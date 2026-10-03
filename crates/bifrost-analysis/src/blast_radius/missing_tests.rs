use super::{
    BlastRadiusCallableSymbol, BlastRadiusEndpoints, CallableChangeTag, FileGraphCompletion,
    build_target_file_dependency_analyzer, changed_callables, collect_target_evidence,
    normalized_path, reverse_reachable_files, target_diff_paths,
};
use crate::CancellationToken;
use crate::analyzer::common::language_for_file;
use crate::analyzer::{
    AnalyzerQueryScope, CodeUnit, DeclarationId, IAnalyzer, ProjectFile, QueryScope, QueryToken,
    test_paths,
};
use crate::diff_analysis::{
    DiffAnalysisOptions, DiffEndpointParams, PreparedDiff, analyze_prepared_symbol_changes,
};
use crate::searchtools::{
    ScanUsagesByLocationParams, ScanUsagesEntry, ScanUsagesExecutionContext,
    ScanUsagesIncompleteReason, ScanUsagesStatus, ScanUsagesTarget,
    scan_usages_by_location_with_context,
};
use crate::searchtools_render::{RenderOptions, RenderText};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[cfg(any(test, feature = "test-support"))]
#[path = "selected_missing_tests.rs"]
mod selected_missing_tests;
#[cfg(any(test, feature = "test-support"))]
pub use selected_missing_tests::{
    SelectedMissingTestsTelemetry, missing_tests_at_root_with_selected_inverse_index,
};

#[derive(Debug, Clone, Default, Deserialize)]
pub struct MissingTestsParams {
    #[serde(default)]
    pub base: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct MissingTestsResult {
    pub endpoints: BlastRadiusEndpoints,
    pub analysis: MissingTestsAnalysis,
    pub missing_functions: Vec<MissingTestFunction>,
    pub indeterminate_functions: Vec<MissingTestFunction>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct MissingTestsAnalysis {
    pub mode: MissingTestsMode,
    pub file_graph_completion: FileGraphCompletion,
    pub exact_usage_completion: FileGraphCompletion,
    pub candidate_function_count: usize,
    pub reached_function_count: usize,
    pub missing_function_count: usize,
    pub indeterminate_function_count: usize,
    pub paths_outside_file_graph: Vec<String>,
    pub unresolved_changed_paths: Vec<String>,
    pub incomplete_reasons: Vec<MissingTestsIncompleteReason>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MissingTestsMode {
    FileImportsThenExactUsages,
    FileGraphNarrowedBindingReachability,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MissingTestsIncompleteReason {
    TargetGraphCancelled,
    CompilationScopeUnresolved,
    UnresolvedChangedPath,
    ChangedFunctionUnresolved,
    UsageCancelled,
    UsageTimeBudget,
    UsageCandidateFiles,
    UsageSourceBytes,
    UsageCallsites,
    UsageResponseBudget,
    UsageResolutionCandidates,
    UsageTargetNotFound,
    UsageTargetAmbiguous,
    UsageAnalysisFailure,
    UsageAnalysisIncomplete,
    UnprovenReferences,
    UsageSiteWithoutEnclosingDeclaration,
    UnresolvedChangedTarget,
    OpenBindingFrontier,
    UnsupportedBindingBoundary,
    UnprovenBindingEdge,
    ReferenceGraphCancelled,
    ReferenceGraphStale,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct MissingTestFunction {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<BlastRadiusCallableSymbol>,
    pub after: BlastRadiusCallableSymbol,
    pub changes: Vec<CallableChangeTag>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub incomplete_reasons: Vec<MissingTestsIncompleteReason>,
}

#[derive(Clone)]
struct CandidateState {
    record: MissingTestFunction,
    reached: bool,
    incomplete_reasons: BTreeSet<MissingTestsIncompleteReason>,
}

#[derive(Default)]
struct ExactNodeOutcome {
    reaches_test_context: bool,
    callers: BTreeMap<DeclarationId, CodeUnit>,
    incomplete_reasons: BTreeSet<MissingTestsIncompleteReason>,
}

struct PreparedMissingTests {
    prepared: PreparedDiff,
    endpoints: BlastRadiusEndpoints,
    paths_outside_file_graph: Vec<String>,
    candidates: Vec<CandidateState>,
}

struct CandidateFileGroup {
    allowed_files: BTreeSet<ProjectFile>,
    candidate_indices: Vec<usize>,
}

/// Find introduced or behavior-changed production functions for which the
/// target snapshot has no complete structured call path from test-context
/// code.
///
/// The file graph is only a coarse prefilter. Exact, location-anchored usage
/// scans run inside each changed file's reverse importer closure and walk
/// enclosing callers until reaching test context. The result is static
/// analyzer evidence, not runtime coverage.
pub fn missing_tests_at_root(
    root: &Path,
    live_target_analyzer: Option<&dyn IAnalyzer>,
    params: MissingTestsParams,
    options: &DiffAnalysisOptions,
    cancellation: &CancellationToken,
) -> Result<MissingTestsResult, String> {
    let mut work = prepare_missing_tests_at_root(root, params, options, cancellation)?;
    if work.candidates.is_empty() {
        return Ok(finish_missing_tests(
            work,
            MissingTestsMode::FileImportsThenExactUsages,
            false,
            false,
            Vec::new(),
        ));
    }

    let target_context =
        build_target_file_dependency_analyzer(&work.prepared, live_target_analyzer)?;
    let target_analyzer = target_context.analyzer();
    let target_evidence = collect_target_evidence(
        target_analyzer,
        &target_diff_paths(&work.prepared),
        cancellation,
    );
    apply_file_graph_incompleteness(&mut work.candidates, &target_evidence);

    if let Some(graph) = target_evidence.graph.as_ref() {
        let exact_scope = AnalyzerQueryScope::with_cancellation(target_analyzer, cancellation);
        let exact_context = ScanUsagesExecutionContext::for_composite_query(cancellation.clone());
        for group in candidate_file_groups(target_analyzer, graph, &mut work.candidates) {
            trace_exact_test_reachability(
                target_analyzer,
                exact_scope.token(),
                &exact_context,
                &group.allowed_files,
                &group.candidate_indices,
                &mut work.candidates,
            );
        }
    }

    let graph_cancelled = target_evidence.graph_cancelled;
    let graph_incomplete = target_evidence.graph_incomplete;
    let unresolved = target_evidence.unresolved;
    Ok(finish_missing_tests(
        work,
        MissingTestsMode::FileImportsThenExactUsages,
        graph_cancelled,
        graph_incomplete,
        unresolved,
    ))
}

fn prepare_missing_tests_at_root(
    root: &Path,
    params: MissingTestsParams,
    options: &DiffAnalysisOptions,
    cancellation: &CancellationToken,
) -> Result<PreparedMissingTests, String> {
    let prepared = PreparedDiff::at_root(
        root,
        DiffEndpointParams {
            base: params.base,
            target: params.target,
        },
        options,
        cancellation,
    )?;
    let endpoints = BlastRadiusEndpoints {
        base: prepared.base.label(),
        target: prepared.target.label(),
    };
    let paths_outside_file_graph = prepared
        .file_changes
        .iter()
        .filter(|change| !change.is_parseable)
        .filter_map(|change| change.path.as_ref().or(change.old_path.as_ref()).cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let symbol_changes = analyze_prepared_symbol_changes(&prepared, false)?.into_symbol_changes();
    let mut candidates = changed_callables(&symbol_changes)
        .into_iter()
        .filter_map(|change| {
            let after = change.after?;
            let actionable = change.changes.iter().any(|tag| {
                matches!(
                    tag,
                    CallableChangeTag::Edited
                        | CallableChangeTag::Introduced
                        | CallableChangeTag::SignatureChanged
                )
            });
            (actionable && !after.in_test_context).then_some(CandidateState {
                record: MissingTestFunction {
                    before: change.before,
                    after,
                    changes: change.changes,
                    incomplete_reasons: Vec::new(),
                },
                reached: false,
                incomplete_reasons: BTreeSet::new(),
            })
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        left.record
            .after
            .path
            .cmp(&right.record.after.path)
            .then_with(|| {
                left.record
                    .after
                    .start_line
                    .cmp(&right.record.after.start_line)
            })
            .then_with(|| left.record.after.fqn.cmp(&right.record.after.fqn))
    });
    Ok(PreparedMissingTests {
        prepared,
        endpoints,
        paths_outside_file_graph,
        candidates,
    })
}

fn apply_file_graph_incompleteness(
    candidates: &mut [CandidateState],
    target_evidence: &super::TargetEvidence,
) {
    let reason = if target_evidence.graph_cancelled {
        Some(MissingTestsIncompleteReason::TargetGraphCancelled)
    } else if target_evidence.graph_incomplete {
        Some(MissingTestsIncompleteReason::CompilationScopeUnresolved)
    } else {
        None
    };
    if let Some(reason) = reason {
        for candidate in candidates {
            candidate.incomplete_reasons.insert(reason);
        }
    }
}

fn candidate_file_groups(
    analyzer: &dyn IAnalyzer,
    graph: &crate::analyzer::usages::workspace_graph::WorkspaceUsageRankingGraph,
    candidates: &mut [CandidateState],
) -> Vec<CandidateFileGroup> {
    let mut grouped_indices = BTreeMap::<String, Vec<usize>>::new();
    for (index, candidate) in candidates.iter().enumerate() {
        grouped_indices
            .entry(candidate.record.after.path.clone())
            .or_default()
            .push(index);
    }
    let mut groups = Vec::with_capacity(grouped_indices.len());
    for (path, candidate_indices) in grouped_indices {
        let Some(seed_file) = analyzer
            .project()
            .file_by_rel_path(Path::new(&path))
            .filter(|file| graph.node_indices_by_file.contains_key(file))
        else {
            for index in candidate_indices {
                candidates[index]
                    .incomplete_reasons
                    .insert(MissingTestsIncompleteReason::UnresolvedChangedPath);
            }
            continue;
        };
        groups.push(CandidateFileGroup {
            allowed_files: reverse_reachable_files(graph, std::iter::once(&seed_file)),
            candidate_indices,
        });
    }
    groups
}

fn finish_missing_tests(
    work: PreparedMissingTests,
    mode: MissingTestsMode,
    graph_cancelled: bool,
    graph_incomplete: bool,
    unresolved_changed_paths: Vec<String>,
) -> MissingTestsResult {
    let PreparedMissingTests {
        prepared: _,
        endpoints,
        paths_outside_file_graph,
        candidates,
    } = work;
    let mut global_reasons = BTreeSet::new();
    if graph_cancelled {
        global_reasons.insert(MissingTestsIncompleteReason::TargetGraphCancelled);
    }
    if graph_incomplete {
        global_reasons.insert(MissingTestsIncompleteReason::CompilationScopeUnresolved);
    }
    if !unresolved_changed_paths.is_empty() {
        global_reasons.insert(MissingTestsIncompleteReason::UnresolvedChangedPath);
    }
    let candidate_function_count = candidates.len();
    let reached_function_count = candidates
        .iter()
        .filter(|candidate| candidate.reached)
        .count();
    let mut missing_functions = Vec::new();
    let mut indeterminate_functions = Vec::new();
    for mut candidate in candidates {
        if candidate.reached {
            continue;
        }
        candidate.record.incomplete_reasons = candidate.incomplete_reasons.into_iter().collect();
        global_reasons.extend(candidate.record.incomplete_reasons.iter().copied());
        if candidate.record.incomplete_reasons.is_empty() {
            missing_functions.push(candidate.record);
        } else {
            indeterminate_functions.push(candidate.record);
        }
    }
    let missing_function_count = missing_functions.len();
    let indeterminate_function_count = indeterminate_functions.len();
    assert_eq!(
        candidate_function_count,
        reached_function_count + missing_function_count + indeterminate_function_count,
        "every missing-tests candidate has exactly one outcome"
    );
    let file_graph_completion =
        if graph_cancelled || graph_incomplete || !unresolved_changed_paths.is_empty() {
            FileGraphCompletion::Incomplete
        } else {
            FileGraphCompletion::Complete
        };
    let exact_usage_completion = if indeterminate_functions.is_empty() {
        FileGraphCompletion::Complete
    } else {
        FileGraphCompletion::Incomplete
    };

    MissingTestsResult {
        endpoints,
        analysis: MissingTestsAnalysis {
            mode,
            file_graph_completion,
            exact_usage_completion,
            candidate_function_count,
            reached_function_count,
            missing_function_count,
            indeterminate_function_count,
            paths_outside_file_graph,
            unresolved_changed_paths,
            incomplete_reasons: global_reasons.into_iter().collect(),
        },
        missing_functions,
        indeterminate_functions,
    }
}

fn trace_exact_test_reachability(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    context: &ScanUsagesExecutionContext,
    allowed_files: &BTreeSet<ProjectFile>,
    candidate_indices: &[usize],
    candidates: &mut [CandidateState],
) {
    let allowed_paths = allowed_files
        .iter()
        .map(|file| normalized_path(file.rel_path()))
        .collect::<Vec<_>>();
    let mut units = BTreeMap::<DeclarationId, CodeUnit>::new();
    let mut pending = BTreeSet::<(usize, DeclarationId)>::new();
    let mut visited = BTreeSet::<(usize, DeclarationId)>::new();
    let mut outcomes = BTreeMap::<DeclarationId, ExactNodeOutcome>::new();

    for &candidate_index in candidate_indices {
        let after = &candidates[candidate_index].record.after;
        let Some(unit) = resolve_changed_function(analyzer, after) else {
            candidates[candidate_index]
                .incomplete_reasons
                .insert(MissingTestsIncompleteReason::ChangedFunctionUnresolved);
            continue;
        };
        let id = unit.declaration_id();
        units.entry(id.clone()).or_insert(unit);
        pending.insert((candidate_index, id));
    }

    while !pending.is_empty() {
        let unscanned_ids = pending
            .iter()
            .map(|(_, id)| id)
            .filter(|id| !outcomes.contains_key(*id))
            .cloned()
            .collect::<BTreeSet<_>>();
        if !unscanned_ids.is_empty() {
            let frontier = unscanned_ids
                .iter()
                .map(|id| units[id].clone())
                .collect::<Vec<_>>();
            let targets = frontier
                .iter()
                .map(|unit| scan_target(analyzer, unit))
                .collect::<Option<Vec<_>>>();
            let Some(targets) = targets else {
                for id in unscanned_ids {
                    let mut outcome = ExactNodeOutcome::default();
                    outcome
                        .incomplete_reasons
                        .insert(MissingTestsIncompleteReason::ChangedFunctionUnresolved);
                    outcomes.insert(id, outcome);
                }
                continue;
            };
            let result = scan_usages_by_location_with_context(
                analyzer,
                token,
                ScanUsagesByLocationParams {
                    targets,
                    include_tests: true,
                    paths: Some(allowed_paths.clone()),
                    include_same_owner: true,
                },
                context,
            );
            assert_eq!(
                frontier.len(),
                result.results.len(),
                "one exact usage result is returned for each frontier declaration"
            );
            for (unit, entry) in frontier.into_iter().zip(result.results) {
                let outcome = exact_node_outcome(analyzer, entry);
                for caller in outcome.callers.values() {
                    units
                        .entry(caller.declaration_id())
                        .or_insert_with(|| caller.clone());
                }
                outcomes.insert(unit.declaration_id(), outcome);
            }
        }

        let current = std::mem::take(&mut pending);
        for (candidate_index, id) in current {
            if candidates[candidate_index].reached || !visited.insert((candidate_index, id.clone()))
            {
                continue;
            }
            let outcome = &outcomes[&id];
            if outcome.reaches_test_context {
                candidates[candidate_index].reached = true;
                continue;
            }
            candidates[candidate_index]
                .incomplete_reasons
                .extend(outcome.incomplete_reasons.iter().copied());
            for caller_id in outcome.callers.keys() {
                if !visited.contains(&(candidate_index, caller_id.clone())) {
                    pending.insert((candidate_index, caller_id.clone()));
                }
            }
        }
    }
}

fn resolve_changed_function(
    analyzer: &dyn IAnalyzer,
    symbol: &BlastRadiusCallableSymbol,
) -> Option<CodeUnit> {
    let file = analyzer
        .project()
        .file_by_rel_path(Path::new(&symbol.path))?;
    analyzer
        .enclosing_code_unit_for_lines(&file, symbol.start_line, symbol.end_line)
        .filter(|unit| unit.is_function() && unit.fq_name() == symbol.fqn)
}

fn scan_target(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> Option<ScanUsagesTarget> {
    let range = analyzer
        .location_ranges(unit)
        .into_iter()
        .min_by_key(|range| (range.start_line, range.start_byte))?;
    Some(ScanUsagesTarget {
        path: normalized_path(unit.source().rel_path()),
        line: range.start_line.max(1),
        column: None,
        symbol: Some(unit.fq_name()),
    })
}

fn exact_node_outcome(analyzer: &dyn IAnalyzer, entry: ScanUsagesEntry) -> ExactNodeOutcome {
    let mut outcome = ExactNodeOutcome::default();
    if !entry.complete {
        outcome.incomplete_reasons.insert(
            entry
                .incomplete_reason
                .map(map_scan_incomplete_reason)
                .unwrap_or(MissingTestsIncompleteReason::UsageAnalysisIncomplete),
        );
    }
    match entry.status {
        ScanUsagesStatus::NotFound => {
            outcome
                .incomplete_reasons
                .insert(MissingTestsIncompleteReason::UsageTargetNotFound);
        }
        ScanUsagesStatus::Ambiguous => {
            outcome
                .incomplete_reasons
                .insert(MissingTestsIncompleteReason::UsageTargetAmbiguous);
        }
        ScanUsagesStatus::Failure => {
            outcome
                .incomplete_reasons
                .insert(MissingTestsIncompleteReason::UsageAnalysisFailure);
        }
        ScanUsagesStatus::TooManyCallsites => {
            outcome
                .incomplete_reasons
                .insert(MissingTestsIncompleteReason::UsageCallsites);
        }
        ScanUsagesStatus::UnverifiedAbsent => {
            outcome
                .incomplete_reasons
                .insert(MissingTestsIncompleteReason::UnprovenReferences);
        }
        ScanUsagesStatus::Found
        | ScanUsagesStatus::VerifiedAbsent
        | ScanUsagesStatus::NoExternalUsages => {}
    }
    if !entry.unproven_files.is_empty() || entry.unproven_hits.is_some_and(|count| count > 0) {
        outcome
            .incomplete_reasons
            .insert(MissingTestsIncompleteReason::UnprovenReferences);
    }

    for group in entry.files.iter().chain(&entry.same_owner_files) {
        let Some(file) = analyzer.project().file_by_rel_path(Path::new(&group.path)) else {
            outcome
                .incomplete_reasons
                .insert(MissingTestsIncompleteReason::UsageSiteWithoutEnclosingDeclaration);
            continue;
        };
        for hit in &group.hits {
            if test_file_context(analyzer, &file) {
                outcome.reaches_test_context = true;
                continue;
            }
            let start_line = hit.line.saturating_sub(1);
            let end_line = hit.end_line.unwrap_or(hit.line).saturating_sub(1);
            let Some(caller) = analyzer.enclosing_code_unit_for_lines(&file, start_line, end_line)
            else {
                outcome
                    .incomplete_reasons
                    .insert(MissingTestsIncompleteReason::UsageSiteWithoutEnclosingDeclaration);
                continue;
            };
            if analyzer.in_test_region(&caller) {
                outcome.reaches_test_context = true;
            } else if caller.is_function() || caller.is_class() {
                outcome.callers.insert(caller.declaration_id(), caller);
            } else {
                outcome
                    .incomplete_reasons
                    .insert(MissingTestsIncompleteReason::UsageSiteWithoutEnclosingDeclaration);
            }
        }
    }
    outcome
}

fn test_file_context(analyzer: &dyn IAnalyzer, file: &ProjectFile) -> bool {
    let path = normalized_path(file.rel_path());
    test_paths::is_test_like_path(&path, language_for_file(file))
        || analyzer.file_is_test_only(file)
}

fn map_scan_incomplete_reason(reason: ScanUsagesIncompleteReason) -> MissingTestsIncompleteReason {
    match reason {
        ScanUsagesIncompleteReason::Cancelled => MissingTestsIncompleteReason::UsageCancelled,
        ScanUsagesIncompleteReason::TimeBudget => MissingTestsIncompleteReason::UsageTimeBudget,
        ScanUsagesIncompleteReason::CandidateFiles => {
            MissingTestsIncompleteReason::UsageCandidateFiles
        }
        ScanUsagesIncompleteReason::SourceBytes => MissingTestsIncompleteReason::UsageSourceBytes,
        ScanUsagesIncompleteReason::Callsites => MissingTestsIncompleteReason::UsageCallsites,
        ScanUsagesIncompleteReason::ResponseBudget => {
            MissingTestsIncompleteReason::UsageResponseBudget
        }
        ScanUsagesIncompleteReason::ResolutionCandidates => {
            MissingTestsIncompleteReason::UsageResolutionCandidates
        }
        // Reachable only if a changed-file path stops naming a workspace file
        // between the graph walk and the usage scan; the generic reason says
        // the usage evidence is short without inventing a schema variant for a
        // selector this caller derives from the workspace itself.
        ScanUsagesIncompleteReason::UnmatchedPaths
        | ScanUsagesIncompleteReason::SemanticAnalysis
        | ScanUsagesIncompleteReason::SourceUnavailable => {
            MissingTestsIncompleteReason::UsageAnalysisIncomplete
        }
    }
}

impl RenderText for MissingTestsResult {
    fn render_text(&self, options: RenderOptions) -> String {
        let (heading, description, traversal_label) = match self.analysis.mode {
            MissingTestsMode::FileImportsThenExactUsages => (
                "# Missing-test candidates (bounded structured usage evidence)",
                "The file graph narrows the search; exact static usage paths determine reachability. This is not runtime coverage.",
                "exact usage traversal",
            ),
            MissingTestsMode::FileGraphNarrowedBindingReachability => (
                "# Missing-test candidates (canonical binding reachability)",
                "The file graph schedules the search; proven canonical binding edges determine reachability. This is not runtime coverage.",
                "binding reachability",
            ),
        };
        let mut lines = vec![
            heading.to_string(),
            String::new(),
            description.to_string(),
            String::new(),
            format!(
                "- Endpoints: `{}` -> `{}`",
                self.endpoints.base, self.endpoints.target
            ),
            format!(
                "- Candidates: {} ({} reached, {} missing, {} indeterminate)",
                self.analysis.candidate_function_count,
                self.analysis.reached_function_count,
                self.analysis.missing_function_count,
                self.analysis.indeterminate_function_count
            ),
            format!(
                "- File graph: `{:?}`; {traversal_label}: `{:?}`",
                self.analysis.file_graph_completion, self.analysis.exact_usage_completion,
            ),
        ];
        if !self.analysis.incomplete_reasons.is_empty() {
            lines.push(format!(
                "- Incomplete reasons: `{:?}`",
                self.analysis.incomplete_reasons
            ));
        }
        render_function_section(
            &mut lines,
            "Functions with no structured path from test context",
            &self.missing_functions,
            options,
        );
        render_function_section(
            &mut lines,
            "Indeterminate functions",
            &self.indeterminate_functions,
            options,
        );
        if self.missing_functions.is_empty() && self.indeterminate_functions.is_empty() {
            lines.push(String::new());
            lines.push("No missing-test candidates found.".to_string());
        }
        lines.join("\n")
    }
}

fn render_function_section(
    lines: &mut Vec<String>,
    heading: &str,
    functions: &[MissingTestFunction],
    options: RenderOptions,
) {
    if functions.is_empty() {
        return;
    }
    lines.push(String::new());
    lines.push(format!("## {heading}"));
    lines.push(String::new());
    for function in functions {
        let location = if options.render_line_numbers {
            format!("{}:{}", function.after.path, function.after.start_line + 1)
        } else {
            function.after.path.clone()
        };
        lines.push(format!(
            "- `{}` at `{}` ({:?}){}",
            function.after.fqn,
            location,
            function.changes,
            if function.incomplete_reasons.is_empty() {
                String::new()
            } else {
                format!("; incomplete: {:?}", function.incomplete_reasons)
            }
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use git2::{IndexAddOption, Repository, Signature};
    use std::fs;

    fn commit_all(repo: &Repository, message: &str) -> git2::Oid {
        let mut index = repo.index().expect("repository index");
        index
            .add_all(["*"], IndexAddOption::DEFAULT, None)
            .expect("stage fixture");
        index.update_all(["*"], None).expect("stage deletions");
        index.write().expect("write fixture index");
        let tree = repo
            .find_tree(index.write_tree().expect("fixture tree oid"))
            .expect("fixture tree");
        let signature = Signature::now("Tester", "tester@example.com").expect("signature");
        let parent = repo
            .head()
            .ok()
            .and_then(|head| head.target())
            .map(|oid| repo.find_commit(oid).expect("fixture parent"));
        let parents = parent.iter().collect::<Vec<_>>();
        repo.commit(
            Some("HEAD"),
            &signature,
            &signature,
            message,
            &tree,
            &parents,
        )
        .expect("fixture commit")
    }

    fn write(root: &Path, path: &str, contents: &str) {
        let target = root.join(path);
        fs::create_dir_all(target.parent().expect("fixture parent")).expect("fixture directory");
        fs::write(target, contents).expect("fixture source");
    }

    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn exact_usage_narrowing_distinguishes_siblings_and_follows_callers() {
        let temp = tempfile::tempdir().expect("temporary repository");
        let root = temp.path();
        write(
            root,
            "Cargo.toml",
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        );
        write(
            root,
            "src/lib.rs",
            "pub mod covered;\npub mod helper;\npub mod uncovered;\npub mod deleted;\npub mod moved;\n",
        );
        write(
            root,
            "src/covered.rs",
            "pub fn direct() -> i32 {\n    1\n}\n\npub fn sibling() -> i32 {\n    1\n}\n\npub fn indirect() -> i32 {\n    1\n}\n",
        );
        write(
            root,
            "src/helper.rs",
            "use crate::covered::indirect;\n\npub fn helper() -> i32 {\n    indirect()\n}\n",
        );
        write(
            root,
            "src/uncovered.rs",
            "pub fn uncovered() -> i32 {\n    1\n}\n",
        );
        write(
            root,
            "src/deleted.rs",
            "pub fn deleted() -> i32 {\n    1\n}\n",
        );
        write(root, "src/moved.rs", "pub fn moved() -> i32 {\n    1\n}\n");
        write(
            root,
            "tests/service.rs",
            "use fixture::covered::direct;\nuse fixture::helper::helper;\n\n#[test]\nfn paths() {\n    let _ = direct();\n    let _ = helper();\n}\n",
        );
        let repo = Repository::init(root).expect("initialize repository");
        commit_all(&repo, "base");

        write(
            root,
            "src/covered.rs",
            "pub fn direct() -> i32 {\n    2\n}\n\npub fn sibling() -> i32 {\n    2\n}\n\npub fn indirect() -> i32 {\n    2\n}\n",
        );
        write(
            root,
            "src/uncovered.rs",
            "pub fn uncovered() -> i32 {\n    2\n}\n\npub fn introduced(input: i32) -> i32 {\n    if input > 0 { input } else { -input }\n}\n",
        );
        write(
            root,
            "src/lib.rs",
            "pub mod covered;\npub mod helper;\npub mod uncovered;\npub mod relocated;\n",
        );
        fs::remove_file(root.join("src/deleted.rs")).expect("delete source");
        fs::rename(root.join("src/moved.rs"), root.join("src/relocated.rs")).expect("move source");
        write(
            root,
            "tests/service.rs",
            "use fixture::covered::direct;\nuse fixture::helper::helper;\n\n#[test]\nfn paths() {\n    let _ = direct();\n    let _ = helper();\n}\n",
        );
        let target = commit_all(&repo, "target");

        let result = missing_tests_at_root(
            root,
            None,
            MissingTestsParams {
                base: None,
                target: Some(target.to_string()),
            },
            &DiffAnalysisOptions::default(),
            &CancellationToken::default(),
        )
        .expect("missing tests");

        assert_eq!(5, result.analysis.candidate_function_count, "{result:#?}");
        assert_eq!(2, result.analysis.reached_function_count);
        assert_eq!(3, result.analysis.missing_function_count);
        assert_eq!(0, result.analysis.indeterminate_function_count);
        assert_eq!(
            FileGraphCompletion::Complete,
            result.analysis.file_graph_completion
        );
        assert_eq!(
            FileGraphCompletion::Complete,
            result.analysis.exact_usage_completion
        );
        let missing = result
            .missing_functions
            .iter()
            .map(|function| function.after.name.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            BTreeSet::from(["introduced", "sibling", "uncovered"]),
            missing
        );
        assert!(
            result
                .missing_functions
                .iter()
                .all(|function| function.after.name != "deleted"
                    && function.after.name != "moved"
                    && function.after.name != "paths")
        );
    }

    #[test]
    fn missing_tests_preserves_library_target_test_context() {
        let temp = tempfile::tempdir().expect("temporary repository");
        let root = temp.path();
        write(
            root,
            "Cargo.toml",
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        );
        write(root, "src/lib.rs", "pub mod changed;\npub mod tests;\n");
        write(
            root,
            "src/changed.rs",
            "pub fn covered() -> i32 {\n    1\n}\n\npub fn uncovered() -> i32 {\n    1\n}\n",
        );
        write(
            root,
            "src/tests/mod.rs",
            "use crate::changed::covered;\n\npub fn witness() -> i32 {\n    covered()\n}\n",
        );
        let repo = Repository::init(root).expect("initialize repository");
        commit_all(&repo, "base");
        write(
            root,
            "src/changed.rs",
            "pub fn covered() -> i32 {\n    2\n}\n\npub fn uncovered() -> i32 {\n    2\n}\n",
        );
        let target = commit_all(&repo, "target");

        let result = missing_tests_at_root(
            root,
            None,
            MissingTestsParams {
                base: None,
                target: Some(target.to_string()),
            },
            &DiffAnalysisOptions::default(),
            &CancellationToken::default(),
        )
        .expect("missing tests");

        assert_eq!(2, result.analysis.candidate_function_count, "{result:#?}");
        assert_eq!(1, result.analysis.reached_function_count, "{result:#?}");
        assert_eq!(1, result.analysis.missing_function_count, "{result:#?}");
        assert_eq!(
            0, result.analysis.indeterminate_function_count,
            "{result:#?}"
        );
    }

    #[test]
    fn cancelled_file_graph_never_claims_a_missing_function() {
        let temp = tempfile::tempdir().expect("temporary repository");
        let root = temp.path();
        write(root, "src/value.py", "def value():\n    return 1\n");
        let repo = Repository::init(root).expect("initialize repository");
        commit_all(&repo, "base");
        write(root, "src/value.py", "def value():\n    return 2\n");
        let target = commit_all(&repo, "target");
        let cancellation = CancellationToken::default();
        cancellation.cancel();

        let result = missing_tests_at_root(
            root,
            None,
            MissingTestsParams {
                base: None,
                target: Some(target.to_string()),
            },
            &DiffAnalysisOptions::default(),
            &cancellation,
        )
        .expect("cancelled missing tests evidence");

        assert!(result.missing_functions.is_empty());
        assert_eq!(1, result.indeterminate_functions.len());
        assert_eq!(
            vec![MissingTestsIncompleteReason::TargetGraphCancelled],
            result.indeterminate_functions[0].incomplete_reasons
        );
    }
}
