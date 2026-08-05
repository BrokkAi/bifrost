//! MCP `report_dead_code_and_unused_abstraction_smells` handler. Composes
//! declaration discovery with bounded graph-backed usage queries to report
//! likely dead code and one-call abstractions while skipping inconclusive
//! cases.

use super::{ReportLines, append_ambiguous_path_notes, resolve_project_files, sanitize_table_cell};
use crate::analyzer::common::language_for_target;
use crate::analyzer::languages::{
    DeadCodeBulkEdges, DeadCodeBulkPreflight, DeadCodeBulkProof, DeadCodeRouting, EdgePassId,
    language_support,
};
use crate::analyzer::usages::ImportGraphCandidateProvider;
use crate::analyzer::usages::inverted_edges::{NodeKey, UsageEdges, UsageNodeKey};
use crate::analyzer::usages::js_ts_graph::{JsTsScopedNodeStatus, JsTsScopedUsageEdges};
use crate::analyzer::usages::{
    CandidateFileProvider, FallbackCandidateProvider, FuzzyResult, TextSearchCandidateProvider,
    UsageAnalyzer, UsageHit, UsageHitKind, UsageHitSurface,
};
use crate::analyzer::{
    CodeUnit, IAnalyzer, Language, ProjectFile, Range, RustAnalyzer, resolve_analyzer,
};
use crate::hash::{HashMap, HashSet};
use crate::path_utils::{AmbiguousPathInput, rel_path_string};
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::LazyLock;

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
    let requested_usage_cap =
        positive_or(params.max_usages_per_symbol, MAX_USAGES_FOR_SMELL as i32) as usize;
    let usage_cap = requested_usage_cap.min(MAX_USAGES_FOR_SMELL);

    let resolved = resolve_project_files(analyzer.project(), params.file_paths);
    let ambiguous_paths = resolved.ambiguous_paths.clone();
    let resolved_file_count = resolved.files.len();
    let input_files: Vec<ProjectFile> = resolved.files.into_iter().take(input_file_cap).collect();
    let mut truncated = resolved.input_truncated || resolved_file_count > input_file_cap;
    let selected_file_ids: HashSet<PathBuf> =
        input_files.iter().map(canonical_file_identity).collect();
    let mut skipped: Vec<String> = Vec::new();

    let candidate_selection = dead_code_candidates(
        analyzer,
        &input_files,
        &params.fq_names,
        &selected_file_ids,
        candidate_cap,
        &mut skipped,
    );
    truncated |= candidate_selection.truncated;
    let mut findings: Vec<DeadCodeFinding> = Vec::new();
    // One bucket per bulk proof, not per language: JavaScript and TypeScript candidates
    // share a proof while Java, Scala and Kotlin do not. A bucket is created on first
    // sight of a language that has a proof, because its routing memo is what makes the
    // whole-workspace facts a per-report cost rather than a per-candidate one.
    let mut buckets: HashMap<EdgePassId, DeadCodeBulkBucket> = HashMap::default();
    for candidate in &candidate_selection.candidates {
        if let Some(proof) = language_support(code_unit_language(candidate))
            .and_then(|support| support.dead_code().bulk)
        {
            let bucket = buckets
                .entry(proof.id())
                .or_insert_with(|| DeadCodeBulkBucket {
                    proof,
                    memo: proof.new_memo(),
                    candidates: Vec::new(),
                });
            if !proof.needs_precise_scan(DeadCodeRouting {
                analyzer,
                candidate,
                file_cap: usage_candidate_file_cap,
                memo: bucket.memo.as_mut(),
            }) {
                bucket.candidates.push(candidate.clone());
                continue;
            }
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
    for id in EdgePassId::ALL {
        let Some(bucket) = buckets.remove(&id) else {
            continue;
        };
        findings.extend(
            prove_bulk_candidates(
                analyzer,
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
    selected_file_ids: &HashSet<PathBuf>,
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
                if !selected_file_ids.is_empty()
                    && !selected_file_ids.contains(&canonical_file_identity(definition.source()))
                {
                    continue;
                }
                if !is_dead_code_candidate(analyzer, &definition) {
                    continue;
                }
                if code_unit_language(&definition) == Language::CSharp
                    && csharp_implicit_entry_point(analyzer, &definition)
                {
                    continue;
                }
                if code_unit_language(&definition) == Language::Cpp
                    && cpp_implicit_entry_point(analyzer, &definition)
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
                if !is_dead_code_candidate(analyzer, &declaration) {
                    continue;
                }
                if code_unit_language(&declaration) == Language::CSharp
                    && csharp_implicit_entry_point(analyzer, &declaration)
                {
                    continue;
                }
                if code_unit_language(&declaration) == Language::Cpp
                    && cpp_implicit_entry_point(analyzer, &declaration)
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
    use super::canonical_file_identity;
    use crate::analyzer::ProjectFile;

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
}

fn is_dead_code_candidate(analyzer: &dyn IAnalyzer, code_unit: &CodeUnit) -> bool {
    if code_unit.is_anonymous() {
        return false;
    }
    let language = code_unit_language(code_unit);
    if code_unit.is_synthetic() && language != Language::Scala {
        return false;
    }
    if language == Language::Go
        && crate::analyzer::usages::go_graph::go_implicit_entry_point(code_unit)
    {
        return false;
    }
    if language == Language::Kotlin && kotlin_implicit_entry_point(analyzer, code_unit) {
        return false;
    }
    if analyzer
        .signature_metadata(code_unit)
        .iter()
        .any(crate::analyzer::SignatureMetadata::is_declaration_only)
    {
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
    analyzer: &dyn IAnalyzer,
    candidate: &CodeUnit,
    usage_candidate_file_cap: usize,
    usage_cap: usize,
    skipped: &mut Vec<String>,
) -> Option<DeadCodeFinding> {
    let language = code_unit_language(candidate);
    let range = analyzer
        .ranges(candidate)
        .into_iter()
        .filter(|range| !range.is_empty())
        .max_by_key(span_lines)?;

    if graph_strategy_for(candidate).is_none() {
        skipped.push(format!(
            "`{}`: {} precise usage strategy is unavailable; evidence is inconclusive",
            candidate.fq_name(),
            language_label(language)
        ));
        return None;
    }

    let query = query_graph_usages(analyzer, candidate, usage_candidate_file_cap, usage_cap)?;

    if query.candidate_files_truncated {
        skipped.push(format!(
            "`{}`: usage candidate files exceeded cap {usage_candidate_file_cap}; evidence is inconclusive",
            candidate.fq_name()
        ));
        return None;
    }

    let (hits, same_owner_count) = match query.result {
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
    analyzer: &dyn IAnalyzer,
    proof: &'static dyn DeadCodeBulkProof,
    candidates: &[CodeUnit],
    usage_candidate_file_cap: usize,
    usage_cap: usize,
    skipped: &mut Vec<String>,
) -> Vec<DeadCodeFinding> {
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
            prove_fqn_candidates(analyzer, &edges, candidates, usage_cap, skipped)
        }
        DeadCodeBulkEdges::Scoped(edges) => {
            prove_scoped_candidates(analyzer, edges, candidates, usage_cap, skipped)
        }
    }
}

fn prove_fqn_candidates(
    analyzer: &dyn IAnalyzer,
    edges: &UsageEdges,
    candidates: &[CodeUnit],
    usage_cap: usize,
    skipped: &mut Vec<String>,
) -> Vec<DeadCodeFinding> {
    let language = code_unit_language(&candidates[0]);
    debug_assert!(
        candidates
            .iter()
            .all(|candidate| code_unit_language(candidate) == language),
        "an fqn-keyed bulk bucket holds exactly one language"
    );
    let declarations_by_fqn = declarations_by_fqn_for_language(analyzer, language);
    let incoming = incoming_usage_by_callee(edges);

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
            if usage.total == 0 && usage.unproven_inbound > 0 {
                skipped.push(format!(
                    "`{candidate_fqn}`: {} structurally matching usage site(s) could not be proven or disproven; evidence is inconclusive",
                    usage.unproven_inbound
                ));
                return None;
            }
            bulk_graph_finding(analyzer, &declarations_by_fqn, candidate, usage)
        })
        .collect()
}

/// Score one bulk-proven candidate.
///
/// Selection by language, but not language dispatch: these are the report's own scoring
/// rules, and they differ in whether a language has a public-surface notion and how it is
/// tested, never in how the usage evidence was gathered.
fn bulk_graph_finding(
    analyzer: &dyn IAnalyzer,
    declarations_by_fqn: &BTreeMap<String, Vec<CodeUnit>>,
    candidate: &CodeUnit,
    usage: GraphIncomingUsage,
) -> Option<DeadCodeFinding> {
    let language = code_unit_language(candidate);
    match language {
        Language::Rust => rust_graph_finding(analyzer, declarations_by_fqn, candidate, usage),
        Language::Java => java_graph_finding(analyzer, declarations_by_fqn, candidate, usage),
        Language::Scala => scala_graph_finding(analyzer, declarations_by_fqn, candidate, usage),
        Language::Go => go_graph_finding(analyzer, declarations_by_fqn, candidate, usage),
        Language::CSharp => csharp_graph_finding(analyzer, declarations_by_fqn, candidate, usage),
        Language::Cpp => cpp_graph_finding(analyzer, declarations_by_fqn, candidate, usage),
        Language::Php => php_graph_finding(analyzer, declarations_by_fqn, candidate, usage),
        Language::Ruby => ruby_graph_finding(analyzer, declarations_by_fqn, candidate, usage),
        Language::Python => graph_finding_for_language(
            analyzer,
            Language::Python,
            declarations_by_fqn,
            candidate,
            usage,
        ),
        Language::JavaScript | Language::TypeScript | Language::Kotlin | Language::None => {
            unreachable!("{language:?} candidates never reach the fqn-keyed bulk proof")
        }
    }
}

#[derive(Clone, Debug, Default)]
struct GraphIncomingUsage {
    total: usize,
    unproven_inbound: usize,
    callers: BTreeMap<String, usize>,
}

/// Fold workspace edges into per-callee inbound usage: each callee's total inbound
/// weight and the per-caller weight. Shared by the Rust and per-language dead-code
/// passes, which differ only in how they build `edges`. Reads weights via
/// [`UsageEdges::edge_weights`], so it never touches per-edge call-site locations.
fn incoming_usage_by_callee(
    edges: &crate::analyzer::usages::inverted_edges::UsageEdges,
) -> BTreeMap<String, GraphIncomingUsage> {
    let mut incoming: BTreeMap<String, GraphIncomingUsage> = BTreeMap::new();
    for (caller, callee, weight) in edges.edge_weights() {
        let usage = incoming.entry(callee.to_string()).or_default();
        usage.total += weight;
        usage.callers.entry(caller.to_string()).or_insert(weight);
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
    let crate::analyzer::usages::inverted_edges::UsageEdgeWeights {
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
            if let Some(total_callsites) = truncated.get(&candidate_key) {
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
            if usage.total == 0 && usage.unproven_inbound > 0 {
                skipped.push(format!(
                    "`{}`: {} structurally matching usage site(s) could not be proven or disproven; evidence is inconclusive",
                    candidate.fq_name(),
                    usage.unproven_inbound
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
    declarations_by_fqn: &BTreeMap<String, Vec<CodeUnit>>,
    candidate: &CodeUnit,
    usage: GraphIncomingUsage,
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
    let is_public = crate::analyzer::is_rust_public_like_declaration(rust, candidate);
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
    public_surface_graph_finding(
        analyzer,
        Language::Java,
        declarations_by_fqn,
        candidate,
        usage,
        java_public_like_declaration(analyzer, candidate),
        "public",
    )
}

fn scala_graph_finding(
    analyzer: &dyn IAnalyzer,
    declarations_by_fqn: &BTreeMap<String, Vec<CodeUnit>>,
    candidate: &CodeUnit,
    usage: GraphIncomingUsage,
) -> Option<DeadCodeFinding> {
    public_surface_graph_finding(
        analyzer,
        Language::Scala,
        declarations_by_fqn,
        candidate,
        usage,
        scala_public_like_declaration(analyzer, candidate),
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
        go_exported_declaration(candidate),
        "exported",
    )
}

fn csharp_graph_finding(
    analyzer: &dyn IAnalyzer,
    declarations_by_fqn: &BTreeMap<String, Vec<CodeUnit>>,
    candidate: &CodeUnit,
    usage: GraphIncomingUsage,
) -> Option<DeadCodeFinding> {
    public_surface_graph_finding(
        analyzer,
        Language::CSharp,
        declarations_by_fqn,
        candidate,
        usage,
        csharp_public_like_declaration(analyzer, candidate),
        "public",
    )
}

fn cpp_graph_finding(
    analyzer: &dyn IAnalyzer,
    declarations_by_fqn: &BTreeMap<String, Vec<CodeUnit>>,
    candidate: &CodeUnit,
    usage: GraphIncomingUsage,
) -> Option<DeadCodeFinding> {
    public_surface_graph_finding(
        analyzer,
        Language::Cpp,
        declarations_by_fqn,
        candidate,
        usage,
        cpp_public_like_declaration(analyzer, candidate),
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

    Some(DeadCodeFinding {
        language: Language::Php,
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
    let score = public_api_graph_score(usage.total, declaration_lines, is_public);
    let confidence = public_api_graph_confidence(usage.total, is_public);
    let evidence = graph_inbound_evidence(&usage);
    let rationale = public_surface_graph_rationale(
        usage.total,
        is_public,
        language_label(language),
        public_label,
    );

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

fn public_api_graph_score(
    total_usage_count: usize,
    declaration_lines: usize,
    is_public: bool,
) -> i32 {
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

fn public_api_graph_confidence(total_usage_count: usize, is_public: bool) -> f64 {
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
    public_surface_graph_rationale(total_usage_count, is_public, "Rust", "public")
}

fn public_surface_graph_rationale(
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
            let defining_owner = analyzer
                .parent_of(candidate)
                .unwrap_or_else(|| candidate.clone());
            let caller_owner = analyzer.parent_of(caller).unwrap_or_else(|| caller.clone());
            caller_owner != defining_owner
        })
        .map(|(_, weight)| *weight)
        .sum()
}

fn java_public_like_declaration(analyzer: &dyn IAnalyzer, candidate: &CodeUnit) -> bool {
    analyzer
        .get_source(candidate, true)
        .is_some_and(|source| contains_java_visibility_modifier(&source, "public"))
}

fn scala_public_like_declaration(analyzer: &dyn IAnalyzer, candidate: &CodeUnit) -> bool {
    let source = analyzer.get_source(candidate, true).unwrap_or_default();
    !contains_java_visibility_modifier(&source, "private")
}

fn csharp_public_like_declaration(analyzer: &dyn IAnalyzer, candidate: &CodeUnit) -> bool {
    let source = analyzer.get_source(candidate, true).unwrap_or_default();
    let header = declaration_header(&source);
    !contains_java_visibility_modifier(header, "private")
}

fn cpp_public_like_declaration(analyzer: &dyn IAnalyzer, candidate: &CodeUnit) -> bool {
    if candidate.is_class() {
        return true;
    }
    let source = analyzer.get_source(candidate, true).unwrap_or_default();
    let header = declaration_header(&source);
    !contains_java_visibility_modifier(header, "static")
}

fn go_exported_declaration(candidate: &CodeUnit) -> bool {
    candidate
        .identifier()
        .chars()
        .next()
        .is_some_and(char::is_uppercase)
}

fn cpp_implicit_entry_point(analyzer: &dyn IAnalyzer, candidate: &CodeUnit) -> bool {
    crate::analyzer::usages::cpp_graph::is_cpp_global_main(analyzer, candidate)
}

fn csharp_implicit_entry_point(analyzer: &dyn IAnalyzer, candidate: &CodeUnit) -> bool {
    if !candidate.is_function() {
        return false;
    }
    csharp_main_entry_point(analyzer, candidate) || csharp_test_entry_point(analyzer, candidate)
}

fn csharp_test_entry_point(analyzer: &dyn IAnalyzer, candidate: &CodeUnit) -> bool {
    let source = analyzer.get_source(candidate, true).unwrap_or_default();
    csharp_source_has_test_attribute(&source)
}

fn csharp_main_entry_point(analyzer: &dyn IAnalyzer, candidate: &CodeUnit) -> bool {
    if candidate.identifier() != "Main" {
        return false;
    }
    let source = analyzer.get_source(candidate, true).unwrap_or_default();
    let header = declaration_header(&source);
    contains_java_visibility_modifier(header, "static")
}

fn csharp_source_has_test_attribute(source: &str) -> bool {
    static TEST_ATTR_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(
            r"\[(?:[A-Za-z_][A-Za-z0-9_.]*\.)?(?:Test|Fact|Theory|TestMethod)(?:Attribute)?(?:\s*\(|\s*\])",
        )
        .expect("valid csharp test regex")
    });
    TEST_ATTR_RE.is_match(source)
}

fn declaration_header(source: &str) -> &str {
    source.split('{').next().unwrap_or(source)
}

fn contains_java_visibility_modifier(source: &str, modifier: &str) -> bool {
    source
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        .any(|token| token == modifier)
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

/// Nine of the twelve languages answer here. Python and C++ are absent by design --
/// they prove their candidates through their bulk proofs -- and their supports keep
/// `DeadCodeSupport::strategy` at `None` so a candidate that does reach this path is
/// still skipped as inconclusive.
fn graph_strategy_for(candidate: &CodeUnit) -> Option<&'static dyn UsageAnalyzer> {
    language_support(code_unit_language(candidate))?
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
