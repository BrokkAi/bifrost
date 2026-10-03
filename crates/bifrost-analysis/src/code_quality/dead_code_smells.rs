//! MCP `report_dead_code_and_unused_abstraction_smells` handler. Composes
//! declaration discovery with bounded graph-backed usage queries to report
//! likely dead code and one-call abstractions while skipping inconclusive
//! cases.

use super::{
    ReportLines, append_ambiguous_path_notes, resolve_project_files,
    resolve_project_files_or_all_analyzed, sanitize_table_cell,
};
use crate::analyzer::common::language_for_target;
use crate::analyzer::languages::{
    DeadCodeBulkEdges, DeadCodeBulkPreflight, DeadCodeBulkProof, DeadCodeRouting, EdgePassId,
    LanguageGraphBackend, NativeWorkspaceGraphProvider, edge_passes, language_support,
};
use crate::analyzer::structural::reference_edges::{EdgeCompleteness, EdgeIncompleteReason};
use crate::analyzer::usages::ImportGraphCandidateProvider;
use crate::analyzer::usages::inverted_edges::{
    JsTsScopedNodeStatus, JsTsScopedUsageEdges, NodeKey, UsageEdges, UsageNodeKey,
};
use crate::analyzer::usages::workspace_graph::{
    SelectedWorkspaceUsageGraphProjectionOutcome, is_graph_declaration,
};
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
    let query_scope = crate::analyzer::AnalyzerQueryScope::new(analyzer);
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

    let candidate_selection = dead_code_candidates(
        analyzer,
        &input_files,
        &params.fq_names,
        &selected_file_ids,
        has_explicit_file_scope,
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
    struct NativeDeadCodeBucket {
        provider: &'static dyn NativeWorkspaceGraphProvider,
        languages: Vec<Language>,
        candidates: Vec<CodeUnit>,
    }
    let graph_passes = edge_passes();
    let mut native_buckets: HashMap<EdgePassId, NativeDeadCodeBucket> = HashMap::default();
    for candidate in &candidate_selection.candidates {
        if language_support(code_unit_language(candidate))
            .is_some_and(|support| support.dead_code_needs_precise_scan(analyzer, candidate))
        {
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
            continue;
        }
        if is_graph_declaration(candidate)
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
        if let Some(proof) = language_support(code_unit_language(candidate))
            .and_then(|support| support.dead_code().bulk)
        {
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
        if let Some(bucket) = native_buckets.remove(&id) {
            findings.extend(
                prove_native_candidates(
                    analyzer,
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
                analyzer,
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
    restrict_to_selected_files: bool,
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
                if restrict_to_selected_files
                    && !selected_file_ids.contains(&canonical_file_identity(definition.source()))
                {
                    continue;
                }
                if !is_dead_code_candidate(analyzer, &definition, skipped) {
                    continue;
                }
                if code_unit_language(&definition) == Language::CSharp
                    && crate::analyzer::usages::csharp_graph::csharp_implicit_entry_point(
                        analyzer,
                        &definition,
                    )
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
                if !is_dead_code_candidate(analyzer, &declaration, skipped) {
                    continue;
                }
                if code_unit_language(&declaration) == Language::CSharp
                    && crate::analyzer::usages::csharp_graph::csharp_implicit_entry_point(
                        analyzer,
                        &declaration,
                    )
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
    use super::{
        PreciseInboundPreflightDecision, canonical_file_identity,
        inbound_usage_inconclusive_reason, precise_inbound_preflight_decision,
    };
    use crate::analyzer::{
        CodeUnit, CodeUnitIndex, GoAnalyzer, Language, OverlayProject, Project, ProjectFile,
    };
    use crate::inline_project::InlineTestProject;
    use std::sync::Arc;

    #[test]
    fn native_bulk_proof_requires_complete_and_proven_exact_inbound_inventory() {
        use crate::CancellationToken;
        use crate::analyzer::languages::{EdgePassId, NativeWorkspaceGraphProvider};
        use crate::analyzer::resolution::ResolutionBatchMetrics;
        use crate::analyzer::structural::reference_edges::{
            EdgeCompleteness, EdgeIncompleteReason,
        };
        use crate::analyzer::usages::workspace_graph::{
            SelectedWorkspaceUsageGraphProjection, SelectedWorkspaceUsageGraphProjectionOutcome,
            UsageEcosystem, WorkspaceUsageCatalog,
        };
        use crate::analyzer::{IAnalyzer, JavaAnalyzer};
        use crate::hash::HashSet;
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
            ) -> crate::analyzer::store::Result<SelectedWorkspaceUsageGraphProjectionOutcome>
            {
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
                    admitted_callers: HashSet::from_iter(admitted_callers.iter().cloned()),
                    unresolved_names: Some(self.unresolved_names.clone()),
                    forward_completeness: self.completeness.clone(),
                    kind_projection_complete: true,
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
        let forward_gap = EdgeCompleteness::Incomplete {
            reasons: vec![EdgeIncompleteReason::ForwardResolutionIncomplete],
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
            // A reason the projection cannot attribute per declaration still
            // disqualifies the whole pass.
            (
                EdgeCompleteness::Incomplete {
                    reasons: vec![EdgeIncompleteReason::ForwardMetadataIncomplete],
                },
                0,
                false,
                0,
            ),
        ] {
            let provider = EmptyNativeInventory {
                completeness,
                unproven,
                unresolved_names: if nominated {
                    BTreeSet::from([candidate.short_name().to_owned()])
                } else {
                    BTreeSet::new()
                },
            };
            let mut skipped = Vec::new();
            let findings = super::prove_native_candidates(
                &analyzer,
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
        use crate::analyzer::JavaAnalyzer;
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
            let usage = super::GraphIncomingUsage {
                total: 1,
                unproven_inbound: 0,
                callers: BTreeMap::from([(
                    super::GraphIncomingCaller::Declaration(caller.clone()),
                    1,
                )]),
            };
            let legacy_names =
                BTreeMap::from([(caller.fq_name(), vec![misleading_name_match.clone()])]);
            assert_eq!(
                super::external_usage_count(&analyzer, &legacy_names, &candidate, &usage),
                external_count
            );
        }
    }

    #[test]
    fn native_rust_dead_code_separates_same_named_impl_members() {
        use crate::analyzer::RustAnalyzer;
        use crate::analyzer::languages::language_support;

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
        let support = language_support(Language::Rust).expect("Rust language support");
        let findings = candidates
            .iter()
            .map(|candidate| {
                assert!(support.dead_code_needs_precise_scan(&analyzer, candidate));
                super::analyze_candidate(&analyzer, candidate, 10, 2, &mut skipped)
                    .expect("complete native precise evidence produces a finding")
            })
            .collect::<Vec<_>>();

        assert!(skipped.is_empty(), "{skipped:?}");
        assert_eq!(findings.len(), 2, "{findings:#?}");
        assert_eq!(findings[0].total_usage_count, 1, "{findings:#?}");
        assert_eq!(findings[1].total_usage_count, 0, "{findings:#?}");
        assert_ne!(findings[0].start_line, findings[1].start_line);
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
        use crate::CancellationToken;
        use crate::analyzer::languages::{
            EdgePassId, LanguageEdgeFailure, NativeWorkspaceGraphProvider,
        };
        use crate::analyzer::usages::workspace_graph::SelectedWorkspaceUsageGraphProjectionOutcome;
        use crate::analyzer::{IAnalyzer, RustAnalyzer};

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
            ) -> crate::analyzer::store::Result<SelectedWorkspaceUsageGraphProjectionOutcome>
            {
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
        let findings = super::prove_native_candidates(
            &analyzer,
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
    fn native_rust_incomplete_inventory_keeps_unused_declaration_indeterminate() {
        use crate::analyzer::RustAnalyzer;
        use crate::analyzer::selected_rust_native_usage_consumer_shadow;
        use crate::analyzer::usages::{FuzzyResult, outcome::GraphUsageOutcome};
        use crate::hash::HashSet;

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
            let finding = super::analyze_candidate_usage_result(
                &analyzer,
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

    fn go_main_candidate(analyzer: &GoAnalyzer, file: &ProjectFile) -> CodeUnit {
        analyzer
            .declarations(file)
            .into_iter()
            .find(|unit| unit.is_function() && unit.identifier() == "main")
            .unwrap_or_else(|| panic!("no Go main declaration in {}", file.rel_path().display()))
    }

    #[test]
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

        assert!(!super::is_dead_code_candidate(
            &analyzer,
            &candidate,
            &mut skipped
        ));
        assert!(skipped.is_empty(), "{skipped:?}");
    }

    #[test]
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

        assert!(super::is_dead_code_candidate(
            &analyzer,
            &candidate,
            &mut skipped
        ));
        assert!(skipped.is_empty(), "{skipped:?}");
    }

    #[test]
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
        assert!(super::is_dead_code_candidate(
            &analyzer,
            &candidate,
            &mut skipped
        ));
        assert!(skipped.is_empty(), "{skipped:?}");
    }

    #[test]
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
        assert!(!super::is_dead_code_candidate(
            &analyzer,
            &candidate,
            &mut skipped
        ));
        assert!(skipped.is_empty(), "{skipped:?}");
    }

    #[test]
    fn go_main_entry_point_with_missing_package_clause_is_inconclusive() {
        let fixture = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.com/missing-clause\n\ngo 1.24\n")
            .file("main.go", "// no package clause\n\nfunc main() {}\n")
            .build();
        let file = fixture.file("main.go");
        let analyzer = GoAnalyzer::new(fixture.project_dyn());
        let candidate = go_main_candidate(&analyzer, &file);
        let mut skipped = Vec::new();

        assert!(!super::is_dead_code_candidate(
            &analyzer,
            &candidate,
            &mut skipped
        ));
        assert_eq!(skipped.len(), 1, "{skipped:?}");
        assert!(
            skipped[0].contains("package clause") && skipped[0].contains("inconclusive"),
            "{skipped:?}"
        );
    }

    #[test]
    fn rust_dead_code_visibility_failure_is_inconclusive_and_retryable() {
        use crate::RustAnalyzer;
        use crate::analyzer::CodeUnitIndex;
        let fixture = crate::inline_project::InlineTestProject::with_language(
            crate::analyzer::Language::Rust,
        )
        .file("src/lib.rs", "pub fn unused() {}\n")
        .build();
        let project = fixture.project_dyn();
        let context =
            crate::analyzer::tree_sitter_analyzer::ephemeral_store_context(project.as_ref())
                .unwrap();
        let store = std::sync::Arc::clone(&context.store);
        let analyzer = RustAnalyzer::new_with_config_store_context(
            project,
            crate::AnalyzerConfig::default(),
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
            super::bulk_graph_finding(
                &analyzer,
                &Default::default(),
                &candidate,
                super::GraphIncomingUsage::default(),
                &mut skipped
            )
            .is_none()
        );
        assert_eq!(skipped.len(), 1);
        assert!(
            skipped[0].contains("Unavailable") && skipped[0].contains("inconclusive"),
            "{skipped:?}"
        );
        analyzer.warm_usage_facts();
        skipped.clear();
        assert!(
            super::bulk_graph_finding(
                &analyzer,
                &Default::default(),
                &candidate,
                super::GraphIncomingUsage::default(),
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
    fn truncated_inbound_usage_is_inconclusive_without_a_workspace_fixture() {
        let total = crate::analyzer::usages::inverted_edges::MAX_CALLSITES + 1;
        let reason = inbound_usage_inconclusive_reason("helpers.helper", Some(total), 0, 1, 0)
            .expect("truncated usage must be inconclusive");

        assert_eq!(
            reason,
            format!(
                "`helpers.helper`: too many workspace inbound call sites ({total}, limit {}); evidence is inconclusive",
                crate::analyzer::usages::inverted_edges::MAX_CALLSITES
            )
        );
    }

    #[test]
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
        match crate::analyzer::usages::go_graph::go_implicit_entry_point(analyzer, code_unit) {
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
    if crate::analyzer::SignatureMetadata::unit_is_declaration_only(
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

    analyze_candidate_usage_result(analyzer, candidate, language, range, query.result, skipped)
}

fn analyze_candidate_usage_result(
    analyzer: &dyn IAnalyzer,
    candidate: &CodeUnit,
    language: Language,
    range: Range,
    result: FuzzyResult,
    skipped: &mut Vec<String>,
) -> Option<DeadCodeFinding> {
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

    let mut findings = Vec::new();

    if !matches!(
        proof.preflight(analyzer),
        DeadCodeBulkPreflight::Ready { files, .. } if files <= usage_candidate_file_cap
    ) {
        for candidate in candidates {
            if let Some(finding) = analyze_candidate(
                analyzer,
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
                analyzer,
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

fn prove_native_candidates(
    analyzer: &dyn IAnalyzer,
    provider: &dyn NativeWorkspaceGraphProvider,
    languages: &[Language],
    candidates: &[CodeUnit],
    usage_candidate_file_cap: usize,
    usage_cap: usize,
    skipped: &mut Vec<String>,
) -> Vec<DeadCodeFinding> {
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
        .filter(|file| languages.contains(&crate::analyzer::common::language_for_file(file)))
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
    // Admission is the analyzed listing: only a published file can contribute
    // an edge, and the preflight above has already reported any that cannot.
    let files = analyzer
        .analyzed_files()
        .into_iter()
        .filter(|file| languages.contains(&crate::analyzer::common::language_for_file(file)))
        .collect::<Vec<_>>();
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
    let generation = analyzer.project().analysis_generation();
    let projection = match provider.project(analyzer, &files, &crate::CancellationToken::default())
    {
        Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Complete(projection)) => Ok(projection),
        // A forward-resolution gap is the one incompleteness this projection
        // attributes per declaration. It says the resolver did not close some
        // reference's target set; such a reference can only *add* an inbound
        // edge, never remove one, and the declarations it can add are the ones
        // its own name reaches, which the projection carries as
        // `unresolved_names`. Every other reason -- a site with no
        // metadata, an owner the route could not classify, a receiver
        // admission it could not decide -- can hide an edge to any
        // declaration, and still disqualifies the whole pass.
        //
        // Without this, one `input.saturating_sub(1)` anywhere in the pass
        // made every candidate inconclusive. Every real workspace contains a
        // call whose receiver the route cannot resolve, so the native bulk
        // bucket abstained on all of them.
        Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Incomplete(projection))
            if projection.kind_projection_complete
                && projection.unresolved_names.is_some()
                && matches!(
                    &projection.forward_completeness,
                    EdgeCompleteness::Incomplete { reasons }
                        if reasons.iter().all(|reason| {
                            reason == &EdgeIncompleteReason::ForwardResolutionIncomplete
                        })
                ) =>
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
    assert_eq!(
        projection.admitted_callers(),
        &files.into_iter().collect::<HashSet<_>>(),
        "native dead-code proof requires exact caller admission"
    );
    let node_indices = projection
        .nodes
        .iter()
        .enumerate()
        .map(|(index, node)| (&node.key.id, index))
        .collect::<HashMap<_, _>>();
    let mut incoming = HashMap::default();
    for candidate in candidates {
        if let Some(&index) = node_indices.get(&candidate.declaration_id()) {
            incoming.insert(index, GraphIncomingUsage::default());
        }
    }
    for edge in &projection.edges {
        let Some(usage) = incoming.get_mut(&edge.to) else {
            continue;
        };
        let count = edge.counts.total();
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
        if projection
            .unresolved_names
            .as_ref()
            .is_some_and(|names| names.contains(candidate.short_name()))
        {
            skipped.push(format!(
                "`{}`: a reference the route could not resolve spells this declaration's name, so an inbound edge to it may be missing; evidence is inconclusive",
                candidate.fq_name()
            ));
            incoming.remove(&index);
            continue;
        }
        let node = &projection.nodes[index];
        let usage = incoming
            .remove(&index)
            .expect("every admitted candidate has an inbound entry");
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
        if let Some(finding) =
            bulk_graph_finding(analyzer, &BTreeMap::new(), candidate, usage, skipped)
        {
            findings.push(finding);
        }
    }
    findings
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
            bulk_graph_finding(analyzer, &declarations_by_fqn, candidate, usage, skipped)
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
            crate::analyzer::usages::inverted_edges::MAX_CALLSITES
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
    analyzer: &dyn IAnalyzer,
    declarations_by_fqn: &BTreeMap<String, Vec<CodeUnit>>,
    candidate: &CodeUnit,
    usage: GraphIncomingUsage,
    skipped: &mut Vec<String>,
) -> Option<DeadCodeFinding> {
    let language = code_unit_language(candidate);
    match language {
        Language::Rust => {
            rust_graph_finding(analyzer, declarations_by_fqn, candidate, usage, skipped)
        }
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
    edges: &crate::analyzer::usages::inverted_edges::UsageEdges,
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
    let is_public = match crate::analyzer::is_rust_public_like_declaration(rust, candidate) {
        Ok(is_public) => is_public,
        Err(error) => {
            skipped.push(format!(
                "`{}`: Rust canonical declaration visibility failed ({error:?}); evidence is inconclusive",
                candidate.fq_name()
            ));
            return None;
        }
    };
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

pub(crate) fn declaration_header(source: &str) -> &str {
    source.split('{').next().unwrap_or(source)
}

pub(crate) fn contains_java_visibility_modifier(source: &str, modifier: &str) -> bool {
    source
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        .any(|token| token == modifier)
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
                let defining_owner = analyzer
                    .parent_of(candidate)
                    .unwrap_or_else(|| candidate.clone());
                let caller_owner = analyzer.parent_of(caller).unwrap_or_else(|| caller.clone());
                caller_owner != defining_owner
            }
        })
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
