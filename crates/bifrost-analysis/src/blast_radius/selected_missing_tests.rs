//! Selected inverse-index implementation of missing-tests analysis.
//!
//! This module owns the canonical selected traversal while the parent module
//! keeps the incumbent file-graph and usage-scan implementation until cutover.

use super::*;
#[cfg(test)]
use crate::analyzer::RustSelectedReferenceIndex;
#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::resolution::{
    FactReferenceEdgeCatalog, FactResolutionSource, SelectedFactResolutionSnapshot,
    SelectedReferenceInverseIndex, SelectedReferenceInverseIndexBuildOutcome,
    build_selected_reference_inverse_index,
};
use crate::analyzer::store::Result as StoreResult;
use crate::analyzer::structural::reference_edges::{
    EdgeCompleteness, EdgeDerivationResult, EdgeIncompleteReason,
};
use crate::analyzer::structural::{EdgeAxis, EdgeProvenance};
use crate::analyzer::usages::{UsageHitKind, UsageHitSurface, UsageProof};
#[cfg(test)]
use crate::analyzer::{Language, RustAnalyzer, resolve_analyzer};
#[cfg(test)]
use crate::analyzer::{
    RustSelectedReverseOutcome, RustSelectedReverseQueries, with_rust_selected_reverse_queries,
};
#[cfg(any(test, feature = "test-support"))]
use crate::diff_analysis::Snapshot;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;

const MAX_MISSING_TESTS_REVERSE_TARGETS_PER_BATCH: usize = 64;

/// Deterministic work counters for one selected `missing_tests` request.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct SelectedMissingTestsTelemetry {
    pub inverse_index_build_attempts: usize,
    pub complete_inverse_index_builds: usize,
    pub incomplete_inverse_index_builds: usize,
    pub cancelled_inverse_index_builds: usize,
    pub stale_inverse_index_builds: usize,
    pub failed_inverse_index_builds: usize,
    pub inverse_index_generation: u64,
    pub inverse_index_targets: usize,
    pub inverse_index_nonempty_targets: usize,
    pub inverse_index_references: usize,
    pub inverse_index_edges: usize,
    pub inverse_index_batches: usize,
    pub frontier_requests: usize,
    pub inverse_index_lookups: usize,
    pub frontier_cache_hits: usize,
    pub uncovered_frontier_lookups: usize,
    pub proven_rows_observed: usize,
    pub unproven_rows_observed: usize,
    pub missing_enclosing_owner_rows: usize,
    pub outside_file_graph_rows: usize,
}

#[derive(Default)]
struct SelectedInverseFrontierCache {
    results: HashMap<CodeUnit, Arc<EdgeDerivationResult>>,
}

trait MissingTestsInverseIndex {
    fn generation(&self) -> u64;
    fn inverse_for(&self, target: &CodeUnit) -> EdgeDerivationResult;
}

/// Fallible, mutable reverse queries used by the selected traversal.
///
/// The provider owns one selected resolution session. A `None` result is an
/// operational stop, not an empty inverse bucket; callers must discard every
/// staged classification when it occurs.
trait MissingTestsInverseQueries {
    fn generation(&self) -> u64;
    fn inverse_for(
        &mut self,
        targets: &[CodeUnit],
    ) -> StoreResult<Option<Vec<EdgeDerivationResult>>>;
}

struct EagerMissingTestsInverseQueries<'a, I> {
    index: &'a I,
}

impl<I: MissingTestsInverseIndex> MissingTestsInverseQueries
    for EagerMissingTestsInverseQueries<'_, I>
{
    fn generation(&self) -> u64 {
        self.index.generation()
    }

    fn inverse_for(
        &mut self,
        targets: &[CodeUnit],
    ) -> StoreResult<Option<Vec<EdgeDerivationResult>>> {
        Ok(Some(
            targets
                .iter()
                .map(|target| self.index.inverse_for(target))
                .collect(),
        ))
    }
}

#[cfg(test)]
struct RustMissingTestsInverseQueries<'a> {
    queries: &'a mut dyn RustSelectedReverseQueries,
    generation: u64,
}

#[cfg(test)]
impl MissingTestsInverseQueries for RustMissingTestsInverseQueries<'_> {
    fn generation(&self) -> u64 {
        self.generation
    }

    fn inverse_for(
        &mut self,
        targets: &[CodeUnit],
    ) -> StoreResult<Option<Vec<EdgeDerivationResult>>> {
        self.queries.inverse_for(targets)
    }
}

#[cfg(test)]
impl MissingTestsInverseIndex for RustSelectedReferenceIndex {
    fn generation(&self) -> u64 {
        RustSelectedReferenceIndex::generation(self)
    }

    fn inverse_for(&self, target: &CodeUnit) -> EdgeDerivationResult {
        RustSelectedReferenceIndex::inverse_for(self, target)
    }
}

#[cfg(any(test, feature = "test-support"))]
impl MissingTestsInverseIndex for SelectedReferenceInverseIndex {
    fn generation(&self) -> u64 {
        SelectedReferenceInverseIndex::generation(self)
    }

    fn inverse_for(&self, target: &CodeUnit) -> EdgeDerivationResult {
        (*SelectedReferenceInverseIndex::inverse_for(self, target)).clone()
    }
}

impl SelectedInverseFrontierCache {
    fn inverse_for_many(
        &mut self,
        queries: &mut dyn MissingTestsInverseQueries,
        targets: &[CodeUnit],
        telemetry: &mut SelectedMissingTestsTelemetry,
    ) -> StoreResult<Option<Vec<Arc<EdgeDerivationResult>>>> {
        telemetry.frontier_requests = telemetry.frontier_requests.saturating_add(targets.len());
        let mut ordered = Vec::with_capacity(targets.len());
        let mut uncached = Vec::new();
        let mut positions = HashMap::<CodeUnit, usize>::default();
        for (position, target) in targets.iter().enumerate() {
            if let Some(result) = self.results.get(target) {
                telemetry.frontier_cache_hits = telemetry.frontier_cache_hits.saturating_add(1);
                ordered.push((target.clone(), Some(Arc::clone(result))));
            } else {
                ordered.push((target.clone(), None));
                uncached.push(target.clone());
            }
            assert!(
                positions.insert(target.clone(), position).is_none(),
                "inverse frontier batches must not repeat targets: {targets:?}"
            );
        }

        if !uncached.is_empty() {
            telemetry.inverse_index_lookups = telemetry
                .inverse_index_lookups
                .saturating_add(uncached.len());
            for chunk in uncached.chunks(MAX_MISSING_TESTS_REVERSE_TARGETS_PER_BATCH) {
                let Some(results) = queries.inverse_for(chunk)? else {
                    return Ok(None);
                };
                assert_eq!(
                    results.len(),
                    chunk.len(),
                    "one inverse result is required for every requested frontier target"
                );
                for (target, result) in chunk.iter().zip(results) {
                    if result_has_incomplete_reason(
                        &result,
                        &EdgeIncompleteReason::InverseIndexTargetUncovered,
                    ) {
                        telemetry.uncovered_frontier_lookups =
                            telemetry.uncovered_frontier_lookups.saturating_add(1);
                    }
                    let result = Arc::new(result);
                    self.results.insert(target.clone(), Arc::clone(&result));
                    let position = positions
                        .get(target)
                        .copied()
                        .expect("every queried frontier target was staged");
                    ordered[position].1 = Some(result);
                }
            }
        }

        Ok(Some(
            ordered
                .into_iter()
                .map(|(_, result)| result.expect("every frontier target is cached"))
                .collect(),
        ))
    }
}

fn result_has_incomplete_reason(
    result: &EdgeDerivationResult,
    expected: &EdgeIncompleteReason,
) -> bool {
    matches!(
        &result.completeness,
        EdgeCompleteness::Incomplete { reasons } if reasons.contains(expected)
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SelectedTraceControl {
    Complete,
    Cancelled,
    Stale,
    Failed(String),
}

/// Run the full `missing_tests` diff, candidate, coarse-file-graph,
/// test-context, partition, and rendering contract with one selected-Java
/// canonical inverse index substituted for repeated usage scans.
///
/// The selected snapshot and catalog must describe the live worktree target.
/// The inverse index is built exactly once inside this operation. It never
/// falls back to `scan_usages`: only proven canonical rows advance the caller
/// BFS, while every stable open or unsupported frontier makes an unreached
/// candidate indeterminate. Cancellation and generation drift discard staged
/// classifications and publish the complete candidate inventory as
/// indeterminate.
#[cfg(any(test, feature = "test-support"))]
#[allow(clippy::too_many_arguments)]
pub fn missing_tests_at_root_with_selected_inverse_index<S>(
    root: &Path,
    live_target_analyzer: &dyn IAnalyzer,
    params: MissingTestsParams,
    options: &DiffAnalysisOptions,
    selected: &SelectedFactResolutionSnapshot<'_, S>,
    catalog: &FactReferenceEdgeCatalog<'_>,
    maximum_batch_size: usize,
    cancellation: &CancellationToken,
    telemetry: &mut SelectedMissingTestsTelemetry,
) -> Result<MissingTestsResult, String>
where
    S: FactResolutionSource,
{
    *telemetry = SelectedMissingTestsTelemetry::default();
    let expected_generation = catalog.generation();
    let mut work = prepare_missing_tests_at_root(root, params, options, cancellation)?;
    if work.prepared.target != Snapshot::Worktree {
        return Err(
            "selected-Java missing_tests requires the live worktree as the target snapshot"
                .to_string(),
        );
    }
    if work.candidates.is_empty() {
        return Ok(finish_missing_tests(
            work,
            MissingTestsMode::FileGraphNarrowedBindingReachability,
            false,
            false,
            Vec::new(),
        ));
    }
    if cancellation.is_cancelled() {
        return Ok(finish_all_indeterminate(
            work,
            MissingTestsMode::FileGraphNarrowedBindingReachability,
            MissingTestsIncompleteReason::TargetGraphCancelled,
            true,
            false,
            Vec::new(),
        ));
    }
    if live_target_analyzer.project().analysis_generation() != expected_generation {
        let mut result = finish_all_indeterminate(
            work,
            MissingTestsMode::FileGraphNarrowedBindingReachability,
            MissingTestsIncompleteReason::ReferenceGraphStale,
            false,
            false,
            Vec::new(),
        );
        result.analysis.file_graph_completion = FileGraphCompletion::Incomplete;
        return Ok(result);
    }

    let target_context =
        build_target_file_dependency_analyzer(&work.prepared, Some(live_target_analyzer))?;
    let target_analyzer = target_context.analyzer();
    let target_evidence = collect_target_evidence(
        target_analyzer,
        &target_diff_paths(&work.prepared),
        cancellation,
    );
    if target_evidence.graph_cancelled || cancellation.is_cancelled() {
        return Ok(finish_all_indeterminate(
            work,
            MissingTestsMode::FileGraphNarrowedBindingReachability,
            MissingTestsIncompleteReason::TargetGraphCancelled,
            true,
            target_evidence.graph_incomplete,
            target_evidence.unresolved,
        ));
    }
    if target_analyzer.project().analysis_generation() != expected_generation {
        return Ok(finish_all_indeterminate(
            work,
            MissingTestsMode::FileGraphNarrowedBindingReachability,
            MissingTestsIncompleteReason::ReferenceGraphStale,
            false,
            target_evidence.graph_incomplete,
            target_evidence.unresolved,
        ));
    }

    telemetry.inverse_index_build_attempts =
        telemetry.inverse_index_build_attempts.saturating_add(1);
    let build_result = build_selected_reference_inverse_index(
        target_analyzer,
        selected,
        catalog,
        maximum_batch_size,
        cancellation,
    );
    if cancellation.is_cancelled() {
        telemetry.cancelled_inverse_index_builds =
            telemetry.cancelled_inverse_index_builds.saturating_add(1);
        return Ok(finish_all_indeterminate(
            work,
            MissingTestsMode::FileGraphNarrowedBindingReachability,
            MissingTestsIncompleteReason::ReferenceGraphCancelled,
            false,
            target_evidence.graph_incomplete,
            target_evidence.unresolved,
        ));
    }
    if target_analyzer.project().analysis_generation() != expected_generation {
        telemetry.stale_inverse_index_builds =
            telemetry.stale_inverse_index_builds.saturating_add(1);
        return Ok(finish_all_indeterminate(
            work,
            MissingTestsMode::FileGraphNarrowedBindingReachability,
            MissingTestsIncompleteReason::ReferenceGraphStale,
            false,
            target_evidence.graph_incomplete,
            target_evidence.unresolved,
        ));
    }
    let build_outcome = match build_result {
        Ok(outcome) => outcome,
        Err(error) => {
            telemetry.failed_inverse_index_builds =
                telemetry.failed_inverse_index_builds.saturating_add(1);
            return Err(error.to_string());
        }
    };
    let index = match build_outcome {
        SelectedReferenceInverseIndexBuildOutcome::Complete(index) => {
            telemetry.complete_inverse_index_builds =
                telemetry.complete_inverse_index_builds.saturating_add(1);
            record_selected_inverse_index(telemetry, &index);
            index
        }
        SelectedReferenceInverseIndexBuildOutcome::Incomplete(index) => {
            telemetry.incomplete_inverse_index_builds =
                telemetry.incomplete_inverse_index_builds.saturating_add(1);
            record_selected_inverse_index(telemetry, &index);
            index
        }
        SelectedReferenceInverseIndexBuildOutcome::Cancelled => {
            telemetry.cancelled_inverse_index_builds =
                telemetry.cancelled_inverse_index_builds.saturating_add(1);
            return Ok(finish_all_indeterminate(
                work,
                MissingTestsMode::FileGraphNarrowedBindingReachability,
                MissingTestsIncompleteReason::ReferenceGraphCancelled,
                false,
                target_evidence.graph_incomplete,
                target_evidence.unresolved,
            ));
        }
        SelectedReferenceInverseIndexBuildOutcome::Stale => {
            telemetry.stale_inverse_index_builds =
                telemetry.stale_inverse_index_builds.saturating_add(1);
            return Ok(finish_all_indeterminate(
                work,
                MissingTestsMode::FileGraphNarrowedBindingReachability,
                MissingTestsIncompleteReason::ReferenceGraphStale,
                false,
                target_evidence.graph_incomplete,
                target_evidence.unresolved,
            ));
        }
    };
    debug_assert_eq!(index.generation(), expected_generation);

    let mut frontier_cache = SelectedInverseFrontierCache::default();
    if let Some(graph) = target_evidence.graph.as_ref() {
        for group in selected_candidate_file_groups(target_analyzer, graph, &mut work.candidates) {
            match trace_selected_test_reachability(
                target_analyzer,
                &index,
                &mut frontier_cache,
                &group.allowed_files,
                &group.candidate_indices,
                &mut work.candidates,
                cancellation,
                telemetry,
            ) {
                SelectedTraceControl::Complete => {}
                SelectedTraceControl::Cancelled => {
                    return Ok(finish_all_indeterminate(
                        work,
                        MissingTestsMode::FileGraphNarrowedBindingReachability,
                        MissingTestsIncompleteReason::ReferenceGraphCancelled,
                        false,
                        target_evidence.graph_incomplete,
                        target_evidence.unresolved,
                    ));
                }
                SelectedTraceControl::Stale => {
                    return Ok(finish_all_indeterminate(
                        work,
                        MissingTestsMode::FileGraphNarrowedBindingReachability,
                        MissingTestsIncompleteReason::ReferenceGraphStale,
                        false,
                        target_evidence.graph_incomplete,
                        target_evidence.unresolved,
                    ));
                }
                SelectedTraceControl::Failed(error) => return Err(error),
            }
        }
    }
    if cancellation.is_cancelled() {
        return Ok(finish_all_indeterminate(
            work,
            MissingTestsMode::FileGraphNarrowedBindingReachability,
            MissingTestsIncompleteReason::ReferenceGraphCancelled,
            false,
            target_evidence.graph_incomplete,
            target_evidence.unresolved,
        ));
    }
    if target_analyzer.project().analysis_generation() != expected_generation {
        return Ok(finish_all_indeterminate(
            work,
            MissingTestsMode::FileGraphNarrowedBindingReachability,
            MissingTestsIncompleteReason::ReferenceGraphStale,
            false,
            target_evidence.graph_incomplete,
            target_evidence.unresolved,
        ));
    }

    let graph_incomplete = target_evidence.graph_incomplete;
    let unresolved = target_evidence.unresolved;
    let candidate_inventory = work
        .candidates
        .iter()
        .map(|candidate| candidate.record.clone())
        .collect::<Vec<_>>();
    let result = finish_missing_tests(
        work,
        MissingTestsMode::FileGraphNarrowedBindingReachability,
        false,
        graph_incomplete,
        unresolved,
    );
    if cancellation.is_cancelled() {
        return Ok(reset_finished_result_all_indeterminate(
            result,
            candidate_inventory,
            MissingTestsIncompleteReason::ReferenceGraphCancelled,
        ));
    }
    if target_analyzer.project().analysis_generation() != expected_generation {
        return Ok(reset_finished_result_all_indeterminate(
            result,
            candidate_inventory,
            MissingTestsIncompleteReason::ReferenceGraphStale,
        ));
    }
    Ok(result)
}

/// Test-only mixed-language diagnostic for the exact #2767 workload. Rust
/// candidates are the only ones allowed through the selected native reverse
/// callback; all other languages retain the incumbent exact usage traversal.
/// The native callback is opened once for every Rust group so its fact session
/// and frontier cache span the complete Rust demand, not one changed file.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn missing_tests_at_root_with_mixed_selected_reverse(
    root: &Path,
    params: MissingTestsParams,
    options: &DiffAnalysisOptions,
    cancellation: &CancellationToken,
    telemetry: &mut SelectedMissingTestsTelemetry,
) -> Result<MissingTestsResult, String> {
    *telemetry = SelectedMissingTestsTelemetry::default();
    let mut work = prepare_missing_tests_at_root(root, params, options, cancellation)?;
    if work.candidates.is_empty() {
        return Ok(finish_missing_tests(
            work,
            MissingTestsMode::FileGraphNarrowedBindingReachability,
            false,
            false,
            Vec::new(),
        ));
    }
    if cancellation.is_cancelled() {
        return Ok(finish_all_indeterminate(
            work,
            MissingTestsMode::FileGraphNarrowedBindingReachability,
            MissingTestsIncompleteReason::TargetGraphCancelled,
            true,
            false,
            Vec::new(),
        ));
    }

    let target_context = build_target_file_dependency_analyzer(&work.prepared, None)?;
    let target_analyzer = target_context.analyzer();
    let expected_generation = target_analyzer.project().analysis_generation();
    let target_evidence = collect_target_evidence(
        target_analyzer,
        &target_diff_paths(&work.prepared),
        cancellation,
    );
    if target_evidence.graph_cancelled || cancellation.is_cancelled() {
        return Ok(finish_all_indeterminate(
            work,
            MissingTestsMode::FileGraphNarrowedBindingReachability,
            MissingTestsIncompleteReason::TargetGraphCancelled,
            true,
            target_evidence.graph_incomplete,
            target_evidence.unresolved,
        ));
    }
    if target_analyzer.project().analysis_generation() != expected_generation {
        return Ok(finish_all_indeterminate(
            work,
            MissingTestsMode::FileGraphNarrowedBindingReachability,
            MissingTestsIncompleteReason::ReferenceGraphStale,
            false,
            target_evidence.graph_incomplete,
            target_evidence.unresolved,
        ));
    }
    let groups = target_evidence
        .graph
        .as_ref()
        .map(|graph| selected_candidate_file_groups(target_analyzer, graph, &mut work.candidates))
        .unwrap_or_default();
    let has_rust_candidates = groups.iter().any(|group| {
        group
            .candidate_indices
            .iter()
            .any(|&index| candidate_is_rust(target_analyzer, &work.candidates[index]))
    });

    if has_rust_candidates {
        let rust = resolve_analyzer::<RustAnalyzer>(target_analyzer).ok_or_else(|| {
            "native Rust diagnostic found Rust candidates without a Rust analyzer".to_string()
        })?;
        let native = with_rust_selected_reverse_queries(rust, cancellation, |queries| {
            let mut provider = RustMissingTestsInverseQueries {
                queries,
                generation: expected_generation,
            };
            let mut frontier_cache = SelectedInverseFrontierCache::default();
            let mut control = SelectedTraceControl::Complete;
            for group in &groups {
                let rust_indices = group
                    .candidate_indices
                    .iter()
                    .copied()
                    .filter(|&index| candidate_is_rust(target_analyzer, &work.candidates[index]))
                    .collect::<Vec<_>>();
                if rust_indices.is_empty() {
                    continue;
                }
                control = trace_selected_test_reachability_with_queries(
                    target_analyzer,
                    &mut provider,
                    &mut frontier_cache,
                    &group.allowed_files,
                    &rust_indices,
                    &mut work.candidates,
                    cancellation,
                    telemetry,
                );
                if !matches!(&control, SelectedTraceControl::Complete) {
                    break;
                }
            }
            Ok(control)
        });
        let control = match native {
            RustSelectedReverseOutcome::Ready(control) => control,
            RustSelectedReverseOutcome::Cancelled => SelectedTraceControl::Cancelled,
            RustSelectedReverseOutcome::Stale(_reason) => SelectedTraceControl::Stale,
            RustSelectedReverseOutcome::Unavailable(reason) => {
                return Err(format!("native Rust missing_tests unavailable: {reason}"));
            }
            RustSelectedReverseOutcome::StoreError(error) => {
                return Err(format!("native Rust missing_tests store error: {error}"));
            }
        };
        match control {
            SelectedTraceControl::Complete => {}
            SelectedTraceControl::Cancelled => {
                return Ok(finish_all_indeterminate(
                    work,
                    MissingTestsMode::FileGraphNarrowedBindingReachability,
                    MissingTestsIncompleteReason::ReferenceGraphCancelled,
                    false,
                    target_evidence.graph_incomplete,
                    target_evidence.unresolved,
                ));
            }
            SelectedTraceControl::Stale => {
                return Ok(finish_all_indeterminate(
                    work,
                    MissingTestsMode::FileGraphNarrowedBindingReachability,
                    MissingTestsIncompleteReason::ReferenceGraphStale,
                    false,
                    target_evidence.graph_incomplete,
                    target_evidence.unresolved,
                ));
            }
            SelectedTraceControl::Failed(error) => return Err(error),
        }
    }

    let exact_scope = AnalyzerQueryScope::with_cancellation(target_analyzer, cancellation);
    let exact_context = ScanUsagesExecutionContext::for_composite_query(cancellation.clone());
    for group in &groups {
        let non_rust_indices = group
            .candidate_indices
            .iter()
            .copied()
            .filter(|&index| !candidate_is_rust(target_analyzer, &work.candidates[index]))
            .collect::<Vec<_>>();
        if non_rust_indices.is_empty() {
            continue;
        }
        trace_exact_test_reachability(
            target_analyzer,
            exact_scope.token(),
            &exact_context,
            &group.allowed_files,
            &non_rust_indices,
            &mut work.candidates,
        );
    }
    if cancellation.is_cancelled() {
        return Ok(finish_all_indeterminate(
            work,
            MissingTestsMode::FileGraphNarrowedBindingReachability,
            MissingTestsIncompleteReason::ReferenceGraphCancelled,
            false,
            target_evidence.graph_incomplete,
            target_evidence.unresolved,
        ));
    }
    if target_analyzer.project().analysis_generation() != expected_generation {
        return Ok(finish_all_indeterminate(
            work,
            MissingTestsMode::FileGraphNarrowedBindingReachability,
            MissingTestsIncompleteReason::ReferenceGraphStale,
            false,
            target_evidence.graph_incomplete,
            target_evidence.unresolved,
        ));
    }
    Ok(finish_missing_tests(
        work,
        MissingTestsMode::FileGraphNarrowedBindingReachability,
        false,
        target_evidence.graph_incomplete,
        target_evidence.unresolved,
    ))
}

fn selected_candidate_file_groups(
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

#[cfg(test)]
fn candidate_is_rust(analyzer: &dyn IAnalyzer, candidate: &CandidateState) -> bool {
    analyzer
        .project()
        .file_by_rel_path(Path::new(&candidate.record.after.path))
        .is_some_and(|file| crate::analyzer::common::language_for_file(&file) == Language::Rust)
}

#[cfg(any(test, feature = "test-support"))]
fn finish_all_indeterminate(
    mut work: PreparedMissingTests,
    mode: MissingTestsMode,
    reason: MissingTestsIncompleteReason,
    graph_cancelled: bool,
    graph_incomplete: bool,
    unresolved_changed_paths: Vec<String>,
) -> MissingTestsResult {
    for candidate in &mut work.candidates {
        candidate.reached = false;
        candidate.incomplete_reasons.clear();
        candidate.incomplete_reasons.insert(reason);
    }
    finish_missing_tests(
        work,
        mode,
        graph_cancelled,
        graph_incomplete,
        unresolved_changed_paths,
    )
}

#[cfg(any(test, feature = "test-support"))]
fn reset_finished_result_all_indeterminate(
    mut result: MissingTestsResult,
    mut candidate_inventory: Vec<MissingTestFunction>,
    reason: MissingTestsIncompleteReason,
) -> MissingTestsResult {
    for candidate in &mut candidate_inventory {
        candidate.incomplete_reasons.clear();
        candidate.incomplete_reasons.push(reason);
    }
    result.analysis.reached_function_count = 0;
    result.analysis.missing_function_count = 0;
    result.analysis.indeterminate_function_count = candidate_inventory.len();
    result.analysis.exact_usage_completion = FileGraphCompletion::Incomplete;
    result.analysis.incomplete_reasons.retain(|reason| {
        matches!(
            reason,
            MissingTestsIncompleteReason::TargetGraphCancelled
                | MissingTestsIncompleteReason::CompilationScopeUnresolved
                | MissingTestsIncompleteReason::UnresolvedChangedPath
        )
    });
    result.analysis.incomplete_reasons.push(reason);
    result.analysis.incomplete_reasons.sort();
    result.analysis.incomplete_reasons.dedup();
    result.missing_functions.clear();
    result.indeterminate_functions = candidate_inventory;
    result
}

#[cfg(any(test, feature = "test-support"))]
fn record_selected_inverse_index(
    telemetry: &mut SelectedMissingTestsTelemetry,
    index: &SelectedReferenceInverseIndex,
) {
    telemetry.inverse_index_generation = index.generation();
    telemetry.inverse_index_targets = index.target_count();
    telemetry.inverse_index_nonempty_targets = index.nonempty_target_count();
    telemetry.inverse_index_references = index.reference_count();
    telemetry.inverse_index_edges = index.edge_count();
    telemetry.inverse_index_batches = index.batch_count();
}

#[allow(clippy::too_many_arguments)]
fn trace_selected_test_reachability_with_queries(
    analyzer: &dyn IAnalyzer,
    queries: &mut dyn MissingTestsInverseQueries,
    cache: &mut SelectedInverseFrontierCache,
    file_graph_scheduling_files: &BTreeSet<ProjectFile>,
    candidate_indices: &[usize],
    candidates: &mut [CandidateState],
    cancellation: &CancellationToken,
    telemetry: &mut SelectedMissingTestsTelemetry,
) -> SelectedTraceControl {
    let mut units = BTreeMap::<DeclarationId, CodeUnit>::new();
    let mut pending = BTreeSet::<(usize, DeclarationId)>::new();
    let mut visited = BTreeSet::<(usize, DeclarationId)>::new();
    let mut outcomes = BTreeMap::<DeclarationId, ExactNodeOutcome>::new();

    let mut roots = BTreeMap::<DeclarationId, (CodeUnit, Vec<usize>)>::new();
    for &candidate_index in candidate_indices {
        let after = &candidates[candidate_index].record.after;
        let Some(unit) = resolve_changed_function(analyzer, after) else {
            candidates[candidate_index]
                .incomplete_reasons
                .insert(MissingTestsIncompleteReason::UnresolvedChangedTarget);
            continue;
        };
        let id = unit.declaration_id();
        roots
            .entry(id)
            .and_modify(|(_, candidates)| candidates.push(candidate_index))
            .or_insert_with(|| (unit, vec![candidate_index]));
    }

    if !roots.is_empty() {
        let root_targets = roots
            .values()
            .map(|(unit, _)| unit.clone())
            .collect::<Vec<_>>();
        let Some(root_results) = (match cache.inverse_for_many(queries, &root_targets, telemetry) {
            Ok(results) => results,
            Err(error) => return SelectedTraceControl::Failed(error.to_string()),
        }) else {
            return if cancellation.is_cancelled() {
                SelectedTraceControl::Cancelled
            } else {
                SelectedTraceControl::Failed(
                    "selected inverse provider became unavailable while resolving changed targets"
                        .to_string(),
                )
            };
        };
        for ((id, (unit, candidate_indices)), result) in roots.into_iter().zip(root_results) {
            units.insert(id.clone(), unit);
            if result_has_incomplete_reason(
                &result,
                &EdgeIncompleteReason::InverseIndexTargetUncovered,
            ) {
                for candidate_index in candidate_indices {
                    candidates[candidate_index]
                        .incomplete_reasons
                        .insert(MissingTestsIncompleteReason::UnresolvedChangedTarget);
                }
                continue;
            }
            for candidate_index in candidate_indices {
                pending.insert((candidate_index, id.clone()));
            }
        }
    }

    while !pending.is_empty() {
        if cancellation.is_cancelled() {
            return SelectedTraceControl::Cancelled;
        }
        if analyzer.project().analysis_generation() != queries.generation() {
            return SelectedTraceControl::Stale;
        }

        let unscanned_ids = pending
            .iter()
            .map(|(_, id)| id)
            .filter(|id| !outcomes.contains_key(*id))
            .cloned()
            .collect::<BTreeSet<_>>();
        let frontier = unscanned_ids
            .iter()
            .map(|id| units[id].clone())
            .collect::<Vec<_>>();
        let Some(results) = (match cache.inverse_for_many(queries, &frontier, telemetry) {
            Ok(results) => results,
            Err(error) => return SelectedTraceControl::Failed(error.to_string()),
        }) else {
            return if cancellation.is_cancelled() {
                SelectedTraceControl::Cancelled
            } else {
                SelectedTraceControl::Failed(
                    "selected inverse provider became unavailable during caller traversal"
                        .to_string(),
                )
            };
        };
        for (id, result) in unscanned_ids.into_iter().zip(results) {
            if cancellation.is_cancelled() {
                return SelectedTraceControl::Cancelled;
            }
            if analyzer.project().analysis_generation() != queries.generation() {
                return SelectedTraceControl::Stale;
            }
            if result.generation != queries.generation() {
                return SelectedTraceControl::Stale;
            }
            assert_eq!(
                result.provenance,
                EdgeProvenance::Inverse,
                "selected inverse index buckets must retain inverse provenance"
            );

            let mut outcome = ExactNodeOutcome::default();
            if result_has_incomplete_reason(
                &result,
                &EdgeIncompleteReason::InverseIndexTargetUncovered,
            ) {
                outcome
                    .incomplete_reasons
                    .insert(MissingTestsIncompleteReason::OpenBindingFrontier);
                outcomes.insert(id, outcome);
                continue;
            }
            if let EdgeCompleteness::Incomplete { reasons } = &result.completeness
                && reasons.contains(&EdgeIncompleteReason::Cancelled)
            {
                return SelectedTraceControl::Cancelled;
            }
            let inverse_covered = result.covers(EdgeAxis::InverseProjection);
            let proof_covered = result.covers(EdgeAxis::ProofAttribution);
            if !inverse_covered || !proof_covered {
                let EdgeCompleteness::Incomplete { reasons } = &result.completeness else {
                    unreachable!("an inverse result with complete required axes was asserted above")
                };
                for reason in reasons {
                    let unsupported = matches!(reason, EdgeIncompleteReason::NoStructuralAdapter)
                        || matches!(
                            reason,
                            EdgeIncompleteReason::AxisUnsupported(
                                EdgeAxis::InverseProjection | EdgeAxis::ProofAttribution
                            )
                        );
                    if unsupported {
                        outcome
                            .incomplete_reasons
                            .insert(MissingTestsIncompleteReason::UnsupportedBindingBoundary);
                        continue;
                    }
                    let reason_completeness = EdgeCompleteness::Incomplete {
                        reasons: vec![reason.clone()],
                    };
                    if !reason_completeness.covers(EdgeAxis::InverseProjection)
                        || !reason_completeness.covers(EdgeAxis::ProofAttribution)
                    {
                        outcome
                            .incomplete_reasons
                            .insert(MissingTestsIncompleteReason::OpenBindingFrontier);
                    }
                }
            }

            for row in &result.edges {
                if cancellation.is_cancelled() {
                    return SelectedTraceControl::Cancelled;
                }
                if analyzer.project().analysis_generation() != queries.generation()
                    || row.generation != queries.generation()
                {
                    return SelectedTraceControl::Stale;
                }
                assert_eq!(row.provenance, EdgeProvenance::Inverse);
                assert_eq!(row.target.declaration_id(), id);
                if !row.included_in(UsageHitSurface::ExternalUsages)
                    && row.usage_kind != UsageHitKind::SelfReceiver
                {
                    continue;
                }
                if row.source_id().as_ref() == Some(&id) {
                    continue;
                }
                if !proof_covered {
                    continue;
                }
                if !file_graph_scheduling_files.contains(&row.site.file) {
                    telemetry.outside_file_graph_rows =
                        telemetry.outside_file_graph_rows.saturating_add(1);
                }
                if row.proof == UsageProof::Unproven {
                    telemetry.unproven_rows_observed =
                        telemetry.unproven_rows_observed.saturating_add(1);
                    outcome
                        .incomplete_reasons
                        .insert(MissingTestsIncompleteReason::UnprovenBindingEdge);
                    continue;
                }
                telemetry.proven_rows_observed = telemetry.proven_rows_observed.saturating_add(1);

                if test_file_context(analyzer, &row.site.file) {
                    outcome.reaches_test_context = true;
                    continue;
                }
                let Some(caller) = row.site.enclosing.as_ref() else {
                    telemetry.missing_enclosing_owner_rows =
                        telemetry.missing_enclosing_owner_rows.saturating_add(1);
                    outcome
                        .incomplete_reasons
                        .insert(MissingTestsIncompleteReason::UnsupportedBindingBoundary);
                    continue;
                };
                if analyzer.in_test_region(caller) {
                    outcome.reaches_test_context = true;
                    continue;
                }
                if !(caller.is_function() || caller.is_class()) {
                    telemetry.missing_enclosing_owner_rows =
                        telemetry.missing_enclosing_owner_rows.saturating_add(1);
                    outcome
                        .incomplete_reasons
                        .insert(MissingTestsIncompleteReason::UnsupportedBindingBoundary);
                    continue;
                }
                outcome
                    .callers
                    .entry(caller.declaration_id())
                    .or_insert_with(|| caller.clone());
            }
            for caller in outcome.callers.values() {
                units
                    .entry(caller.declaration_id())
                    .or_insert_with(|| caller.clone());
            }
            outcomes.insert(id, outcome);
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
    SelectedTraceControl::Complete
}

#[allow(clippy::too_many_arguments)]
fn trace_selected_test_reachability<I: MissingTestsInverseIndex>(
    analyzer: &dyn IAnalyzer,
    index: &I,
    cache: &mut SelectedInverseFrontierCache,
    file_graph_scheduling_files: &BTreeSet<ProjectFile>,
    candidate_indices: &[usize],
    candidates: &mut [CandidateState],
    cancellation: &CancellationToken,
    telemetry: &mut SelectedMissingTestsTelemetry,
) -> SelectedTraceControl {
    let mut queries = EagerMissingTestsInverseQueries { index };
    trace_selected_test_reachability_with_queries(
        analyzer,
        &mut queries,
        cache,
        file_graph_scheduling_files,
        candidate_indices,
        candidates,
        cancellation,
        telemetry,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::Language;
    use crate::analyzer::resolution::{
        BindingFragmentId, FactReferenceEdgeSelectedFragment, PreloadedFactResolutionService,
        SelectedFactResolutionEngine,
    };
    use crate::analyzer::structural::reference_edges::{EdgeSite, ReferenceEdgeRow};
    use crate::analyzer::structural::{OwnerRelation, SiteClass};
    use crate::analyzer::{
        AnalyzerDelegate, CodeUnitIndex, JavaAnalyzer, KotlinAnalyzer, MultiAnalyzer,
        OverlayProject,
    };
    use crate::inline_project::InlineTestProject;
    use git2::{IndexAddOption, Repository, Signature};
    use std::path::PathBuf;

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

    fn java_method(analyzer: &dyn IAnalyzer, name: &str) -> CodeUnit {
        analyzer
            .all_declarations()
            .find(|unit| unit.is_function() && unit.terminal_name() == name)
            .unwrap_or_else(|| panic!("missing Java method {name}"))
    }

    fn candidate_state(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> CandidateState {
        candidate_state_with_language(analyzer, unit, "java")
    }

    fn candidate_state_with_language(
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        language: &str,
    ) -> CandidateState {
        let range = analyzer
            .location_ranges(unit)
            .into_iter()
            .min_by_key(|range| (range.start_line, range.start_byte))
            .expect("an indexed Java method has a primary range");
        CandidateState {
            record: MissingTestFunction {
                before: None,
                after: BlastRadiusCallableSymbol {
                    fqn: unit.fq_name(),
                    name: unit.terminal_name().to_string(),
                    kind: "method".to_string(),
                    signature: unit.signature().unwrap_or_default().to_string(),
                    path: normalized_path(unit.source().rel_path()),
                    start_line: range.start_line,
                    end_line: range.end_line,
                    language: language.to_string(),
                    in_test_context: false,
                },
                changes: vec![CallableChangeTag::Edited],
                incomplete_reasons: Vec::new(),
            },
            reached: false,
            incomplete_reasons: BTreeSet::new(),
        }
    }

    fn selected_row(
        analyzer: &dyn IAnalyzer,
        target: &CodeUnit,
        enclosing: Option<&CodeUnit>,
        proof: UsageProof,
        usage_kind: UsageHitKind,
        generation: u64,
    ) -> ReferenceEdgeRow {
        let site_unit = enclosing.unwrap_or(target);
        let range = analyzer
            .location_ranges(site_unit)
            .into_iter()
            .min_by_key(|range| (range.start_line, range.start_byte))
            .expect("an indexed Java declaration has a primary range");
        ReferenceEdgeRow {
            site: EdgeSite {
                file: site_unit.source().clone(),
                range,
                ast_id: None,
                enclosing: enclosing.cloned(),
            },
            target: target.clone(),
            reference_kind: None,
            proof,
            usage_kind,
            site_class: SiteClass::UseSite,
            owner_relation: if enclosing == Some(target) {
                OwnerRelation::SelfReference
            } else {
                OwnerRelation::External
            },
            provenance: EdgeProvenance::Forward,
            generation,
        }
    }

    fn selected_java_bfs_project() -> (crate::inline_project::BuiltInlineTestProject, JavaAnalyzer)
    {
        let project = InlineTestProject::with_language(Language::Java)
            .file(
                "src/main/java/demo/Service.java",
                "package demo;\nclass Service {\n  int changed() { return 1; }\n  int helper() { return changed(); }\n  int empty() { return 1; }\n  int unproven() { return 1; }\n  int pureLoop() { return pureLoop(); }\n  int nonSelfReceiver() { return 1; }\n  int missingOwner() { return 1; }\n  int intermediateUncovered() { return 1; }\n  int rootUncovered() { return 1; }\n  int openAxis() { return 1; }\n  int ownerAxisOnly() { return 1; }\n  int unsupportedProofAxis() { return 1; }\n  int positiveWins() { return 1; }\n  int cycleA() { return cycleB(); }\n  int cycleB() { return cycleA(); }\n  int ignoredNoise() { return 1; }\n  int overrideTarget() { return 1; }\n}\n",
            )
            .file(
                "src/test/java/demo/ServiceTest.java",
                "package demo;\nclass ServiceTest {\n  void witness() { new Service().helper(); }\n}\n",
            )
            .build();
        let analyzer = JavaAnalyzer::new(project.project_dyn());
        (project, analyzer)
    }

    #[test]
    fn rust_missing_tests_consumer_queries_one_native_frontier_wave_at_a_time() {
        let project = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"missing-tests-rust\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/lib.rs",
                "pub fn changed() {}\npub fn helper() { changed(); }\nmod tests {\n    #[test]\n    fn reaches_test_context() { super::helper(); }\n}\n",
            )
            .build();
        let rust = RustAnalyzer::new(project.project_dyn());
        let changed = rust
            .all_declarations()
            .find(|unit| unit.is_function() && unit.terminal_name() == "changed")
            .expect("Rust changed declaration");
        let mut candidates = vec![candidate_state_with_language(&rust, &changed, "rust")];
        let mut cache = SelectedInverseFrontierCache::default();
        let mut telemetry = SelectedMissingTestsTelemetry::default();
        let cancellation = CancellationToken::new();
        let generation = rust.project().analysis_generation();
        let result = with_rust_selected_reverse_queries(&rust, &cancellation, |queries| {
            let mut provider = RustMissingTestsInverseQueries {
                queries,
                generation,
            };
            let control = trace_selected_test_reachability_with_queries(
                &rust,
                &mut provider,
                &mut cache,
                &BTreeSet::new(),
                &[0],
                &mut candidates,
                &cancellation,
                &mut telemetry,
            );
            assert_eq!(SelectedTraceControl::Complete, control);
            Ok(candidates[0].reached)
        });
        assert!(matches!(result, RustSelectedReverseOutcome::Ready(true)));
        assert!(telemetry.frontier_requests >= 3);
    }

    // R4.6 (#3250): on the native route an unproven reference edge must not
    // advance test reachability, and the candidate it fails to reach must carry
    // an incomplete reason. finish_missing_tests routes an unreached candidate
    // with a reason to indeterminate_functions and one without a reason to
    // missing_functions, so the reason is what separates "no test calls this"
    // from "Bifrost could not tell". Without it an unprovable edge would be
    // published as a confident negative.
    #[test]
    fn rust_missing_tests_keeps_an_unproven_native_edge_indeterminate() {
        let project = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"missing-tests-rust-unproven\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/lib.rs",
                "pub fn changed() {}\npub fn helper() { changed(); }\nmod tests {\n    #[test]\n    fn reaches_test_context() { super::helper(); }\n}\n",
            )
            .build();
        let rust = RustAnalyzer::new(project.project_dyn());
        let declaration = |name: &str| {
            rust.all_declarations()
                .find(|unit| unit.is_function() && unit.terminal_name() == name)
                .unwrap_or_else(|| panic!("missing Rust declaration {name}"))
        };
        let changed = declaration("changed");
        let helper = declaration("helper");
        let generation = rust.project().analysis_generation();
        let index = SelectedReferenceInverseIndex::from_forward_rows_for_test_support(
            generation,
            vec![changed.clone()],
            EdgeCompleteness::Complete,
            1,
            vec![selected_row(
                &rust,
                &changed,
                Some(&helper),
                UsageProof::Unproven,
                UsageHitKind::Reference,
                generation,
            )],
        );
        let mut candidates = vec![candidate_state_with_language(&rust, &changed, "rust")];
        let mut cache = SelectedInverseFrontierCache::default();
        let mut telemetry = SelectedMissingTestsTelemetry::default();

        assert_eq!(
            SelectedTraceControl::Complete,
            trace_selected_test_reachability(
                &rust,
                &index,
                &mut cache,
                &BTreeSet::new(),
                &[0],
                &mut candidates,
                &CancellationToken::new(),
                &mut telemetry,
            )
        );
        assert!(
            !candidates[0].reached,
            "an unproven edge is not a proven path to a test context"
        );
        assert_eq!(
            BTreeSet::from([MissingTestsIncompleteReason::UnprovenBindingEdge]),
            candidates[0].incomplete_reasons,
            "the unreached candidate must say why, so it is reported indeterminate"
        );
        assert_eq!(1, telemetry.unproven_rows_observed);
    }

    #[test]
    fn selected_missing_tests_discards_staged_classification_on_terminal_reverse_query() {
        struct TerminalQueries {
            generation: u64,
        }

        impl MissingTestsInverseQueries for TerminalQueries {
            fn generation(&self) -> u64 {
                self.generation
            }

            fn inverse_for(
                &mut self,
                _targets: &[CodeUnit],
            ) -> StoreResult<Option<Vec<EdgeDerivationResult>>> {
                Ok(None)
            }
        }

        let (_project, analyzer) = selected_java_bfs_project();
        let changed = java_method(&analyzer, "changed");
        let mut candidates = vec![candidate_state(&analyzer, &changed)];
        let generation = analyzer.project().analysis_generation();
        let mut queries = TerminalQueries { generation };
        let mut telemetry = SelectedMissingTestsTelemetry::default();
        let control = trace_selected_test_reachability_with_queries(
            &analyzer,
            &mut queries,
            &mut SelectedInverseFrontierCache::default(),
            &BTreeSet::new(),
            &[0],
            &mut candidates,
            &CancellationToken::new(),
            &mut telemetry,
        );
        assert!(matches!(control, SelectedTraceControl::Failed(_)));
        assert!(!candidates[0].reached);
        assert!(candidates[0].incomplete_reasons.is_empty());
        assert_eq!(1, telemetry.frontier_requests);
    }

    #[test]
    fn selected_inverse_cache_chunks_native_waves_at_the_store_limit() {
        struct RecordingQueries {
            generation: u64,
            batch_sizes: Vec<usize>,
            batch_targets: Vec<Vec<String>>,
        }

        impl MissingTestsInverseQueries for RecordingQueries {
            fn generation(&self) -> u64 {
                self.generation
            }

            fn inverse_for(
                &mut self,
                targets: &[CodeUnit],
            ) -> StoreResult<Option<Vec<EdgeDerivationResult>>> {
                self.batch_sizes.push(targets.len());
                self.batch_targets.push(
                    targets
                        .iter()
                        .map(|target| target.terminal_name().to_string())
                        .collect(),
                );
                Ok(Some(
                    targets
                        .iter()
                        .map(|_| EdgeDerivationResult {
                            edges: Vec::new(),
                            completeness: EdgeCompleteness::Complete,
                            provenance: EdgeProvenance::Inverse,
                            generation: self.generation,
                        })
                        .collect(),
                ))
            }
        }

        let source = (0..65)
            .map(|index| format!("pub fn target_{index}() {{}}\n"))
            .collect::<String>();
        let project = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"reverse-limit\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", source)
            .build();
        let rust = RustAnalyzer::new(project.project_dyn());
        let mut targets = rust
            .all_declarations()
            .filter(|unit| unit.is_function() && unit.terminal_name().starts_with("target_"))
            .collect::<Vec<_>>();
        targets.sort_by_key(|unit| unit.terminal_name().to_string());
        assert_eq!(65, targets.len());

        let generation = rust.project().analysis_generation();
        let mut queries = RecordingQueries {
            generation,
            batch_sizes: Vec::new(),
            batch_targets: Vec::new(),
        };
        let mut cache = SelectedInverseFrontierCache::default();
        let mut telemetry = SelectedMissingTestsTelemetry::default();
        let result = cache
            .inverse_for_many(&mut queries, &targets, &mut telemetry)
            .expect("recording provider succeeds")
            .expect("recording provider is available");
        assert_eq!(65, result.len());
        assert_eq!(vec![64, 1], queries.batch_sizes);
        assert_eq!(
            targets
                .iter()
                .map(|target| target.terminal_name().to_string())
                .collect::<Vec<_>>(),
            queries
                .batch_targets
                .iter()
                .flatten()
                .cloned()
                .collect::<Vec<_>>()
        );
        assert_eq!(65, telemetry.inverse_index_lookups);

        let cached = cache
            .inverse_for_many(&mut queries, &targets, &mut telemetry)
            .expect("cached provider succeeds")
            .expect("cached provider is available");
        assert_eq!(65, cached.len());
        assert_eq!(vec![64, 1], queries.batch_sizes);
        assert_eq!(2, queries.batch_targets.len());
        assert_eq!(65, telemetry.frontier_cache_hits);
    }

    #[test]
    #[ignore = "exact #2767 mixed Rust/Python diagnostic; set BIFROST_MISSING_TESTS_2767_ROOT"]
    fn ignored_exact_2767_mixed_native_missing_tests_diagnostic() {
        let Some(root) = std::env::var_os("BIFROST_MISSING_TESTS_2767_ROOT") else {
            return;
        };
        const TARGET: &str = "57fb66322ce75c1612b7ce5a426e1797d5ba9935";
        let mut telemetry = SelectedMissingTestsTelemetry::default();
        let result = missing_tests_at_root_with_mixed_selected_reverse(
            &PathBuf::from(root),
            MissingTestsParams {
                base: Some(format!("{TARGET}^")),
                target: Some(TARGET.to_string()),
            },
            &DiffAnalysisOptions::default(),
            &CancellationToken::new(),
            &mut telemetry,
        )
        .expect("exact #2767 mixed native missing-tests diagnostic");
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "result": &result,
                "telemetry": telemetry,
            }))
            .expect("diagnostic result serializes")
        );
        assert_eq!(10, result.analysis.candidate_function_count);
        assert_eq!(3, result.analysis.reached_function_count);
        assert_eq!(6, result.analysis.missing_function_count);
        assert_eq!(1, result.analysis.indeterminate_function_count);
    }

    #[test]
    fn selected_inverse_bfs_uses_proven_rows_beyond_the_coarse_file_schedule() {
        let (project, analyzer) = selected_java_bfs_project();
        let changed = java_method(&analyzer, "changed");
        let helper = java_method(&analyzer, "helper");
        let witness = java_method(&analyzer, "witness");
        let empty = java_method(&analyzer, "empty");
        let generation = analyzer.project().analysis_generation();
        let index = SelectedReferenceInverseIndex::from_forward_rows_for_test_support(
            generation,
            vec![changed.clone(), helper.clone(), empty.clone()],
            EdgeCompleteness::Complete,
            2,
            vec![
                selected_row(
                    &analyzer,
                    &changed,
                    Some(&helper),
                    UsageProof::Proven,
                    UsageHitKind::Reference,
                    generation,
                ),
                selected_row(
                    &analyzer,
                    &helper,
                    Some(&witness),
                    UsageProof::Proven,
                    UsageHitKind::Reference,
                    generation,
                ),
            ],
        );
        let mut candidates = vec![
            candidate_state(&analyzer, &changed),
            candidate_state(&analyzer, &empty),
        ];
        let allowed_files = BTreeSet::from([project.file("src/main/java/demo/Service.java")]);
        let mut cache = SelectedInverseFrontierCache::default();
        let mut telemetry = SelectedMissingTestsTelemetry::default();

        assert_eq!(
            SelectedTraceControl::Complete,
            trace_selected_test_reachability(
                &analyzer,
                &index,
                &mut cache,
                &allowed_files,
                &[0, 1],
                &mut candidates,
                &CancellationToken::new(),
                &mut telemetry,
            )
        );
        assert!(candidates[0].reached);
        assert!(!candidates[1].reached);
        assert!(candidates[1].incomplete_reasons.is_empty());
        assert_eq!(2, telemetry.proven_rows_observed);
        assert_eq!(1, telemetry.outside_file_graph_rows);
    }

    #[test]
    fn selected_inverse_bfs_fail_closes_rows_and_uncovered_frontiers() {
        let (_project, analyzer) = selected_java_bfs_project();
        let helper = java_method(&analyzer, "helper");
        let unproven = java_method(&analyzer, "unproven");
        let pure_loop = java_method(&analyzer, "pureLoop");
        let non_self_receiver = java_method(&analyzer, "nonSelfReceiver");
        let missing_owner = java_method(&analyzer, "missingOwner");
        let intermediate_uncovered = java_method(&analyzer, "intermediateUncovered");
        let root_uncovered = java_method(&analyzer, "rootUncovered");
        let generation = analyzer.project().analysis_generation();
        let index = SelectedReferenceInverseIndex::from_forward_rows_for_test_support(
            generation,
            vec![
                unproven.clone(),
                pure_loop.clone(),
                non_self_receiver.clone(),
                missing_owner.clone(),
                intermediate_uncovered.clone(),
            ],
            EdgeCompleteness::Complete,
            5,
            vec![
                selected_row(
                    &analyzer,
                    &unproven,
                    Some(&helper),
                    UsageProof::Unproven,
                    UsageHitKind::Reference,
                    generation,
                ),
                selected_row(
                    &analyzer,
                    &pure_loop,
                    Some(&pure_loop),
                    UsageProof::Unproven,
                    UsageHitKind::SelfReceiver,
                    generation,
                ),
                selected_row(
                    &analyzer,
                    &non_self_receiver,
                    Some(&helper),
                    UsageProof::Unproven,
                    UsageHitKind::SelfReceiver,
                    generation,
                ),
                selected_row(
                    &analyzer,
                    &missing_owner,
                    None,
                    UsageProof::Proven,
                    UsageHitKind::Reference,
                    generation,
                ),
                selected_row(
                    &analyzer,
                    &intermediate_uncovered,
                    Some(&helper),
                    UsageProof::Proven,
                    UsageHitKind::Reference,
                    generation,
                ),
            ],
        );
        let mut candidates = vec![
            candidate_state(&analyzer, &unproven),
            candidate_state(&analyzer, &pure_loop),
            candidate_state(&analyzer, &non_self_receiver),
            candidate_state(&analyzer, &missing_owner),
            candidate_state(&analyzer, &intermediate_uncovered),
            candidate_state(&analyzer, &root_uncovered),
        ];
        let mut cache = SelectedInverseFrontierCache::default();
        let mut telemetry = SelectedMissingTestsTelemetry::default();

        assert_eq!(
            SelectedTraceControl::Complete,
            trace_selected_test_reachability(
                &analyzer,
                &index,
                &mut cache,
                &BTreeSet::new(),
                &[0, 1, 2, 3, 4, 5],
                &mut candidates,
                &CancellationToken::new(),
                &mut telemetry,
            )
        );
        assert_eq!(
            BTreeSet::from([MissingTestsIncompleteReason::UnprovenBindingEdge]),
            candidates[0].incomplete_reasons
        );
        assert!(candidates[1].incomplete_reasons.is_empty());
        assert_eq!(
            BTreeSet::from([MissingTestsIncompleteReason::UnprovenBindingEdge]),
            candidates[2].incomplete_reasons
        );
        assert_eq!(
            BTreeSet::from([MissingTestsIncompleteReason::UnsupportedBindingBoundary]),
            candidates[3].incomplete_reasons
        );
        assert_eq!(
            BTreeSet::from([MissingTestsIncompleteReason::OpenBindingFrontier]),
            candidates[4].incomplete_reasons
        );
        assert_eq!(
            BTreeSet::from([MissingTestsIncompleteReason::UnresolvedChangedTarget]),
            candidates[5].incomplete_reasons
        );
        assert_eq!(2, telemetry.unproven_rows_observed);
        assert_eq!(2, telemetry.proven_rows_observed);
        assert_eq!(1, telemetry.missing_enclosing_owner_rows);
        assert_eq!(2, telemetry.uncovered_frontier_lookups);
    }

    #[test]
    fn selected_inverse_authority_uses_only_inverse_and_proof_axes() {
        let (_project, analyzer) = selected_java_bfs_project();
        let owner_axis_only = java_method(&analyzer, "ownerAxisOnly");
        let open_axis = java_method(&analyzer, "openAxis");
        let unsupported_proof = java_method(&analyzer, "unsupportedProofAxis");
        let generation = analyzer.project().analysis_generation();
        let cases = [
            (
                owner_axis_only,
                EdgeCompleteness::Incomplete {
                    reasons: vec![EdgeIncompleteReason::AxisUnsupported(
                        EdgeAxis::OwnerClassification,
                    )],
                },
                BTreeSet::new(),
            ),
            (
                open_axis,
                EdgeCompleteness::Incomplete {
                    reasons: vec![EdgeIncompleteReason::ForwardResolutionIncomplete],
                },
                BTreeSet::from([MissingTestsIncompleteReason::OpenBindingFrontier]),
            ),
            (
                unsupported_proof,
                EdgeCompleteness::Incomplete {
                    reasons: vec![EdgeIncompleteReason::AxisUnsupported(
                        EdgeAxis::ProofAttribution,
                    )],
                },
                BTreeSet::from([MissingTestsIncompleteReason::UnsupportedBindingBoundary]),
            ),
            (
                java_method(&analyzer, "openAxis"),
                EdgeCompleteness::Incomplete {
                    reasons: vec![
                        EdgeIncompleteReason::AxisUnsupported(EdgeAxis::ProofAttribution),
                        EdgeIncompleteReason::ForwardResolutionIncomplete,
                    ],
                },
                BTreeSet::from([
                    MissingTestsIncompleteReason::OpenBindingFrontier,
                    MissingTestsIncompleteReason::UnsupportedBindingBoundary,
                ]),
            ),
        ];

        for (target, completeness, expected) in cases {
            let index = SelectedReferenceInverseIndex::from_forward_rows_for_test_support(
                generation,
                vec![target.clone()],
                completeness,
                0,
                Vec::new(),
            );
            let mut candidates = vec![candidate_state(&analyzer, &target)];
            assert_eq!(
                SelectedTraceControl::Complete,
                trace_selected_test_reachability(
                    &analyzer,
                    &index,
                    &mut SelectedInverseFrontierCache::default(),
                    &BTreeSet::new(),
                    &[0],
                    &mut candidates,
                    &CancellationToken::new(),
                    &mut SelectedMissingTestsTelemetry::default(),
                )
            );
            assert_eq!(expected, candidates[0].incomplete_reasons);
        }

        let target = java_method(&analyzer, "unsupportedProofAxis");
        let witness = java_method(&analyzer, "witness");
        let index = SelectedReferenceInverseIndex::from_forward_rows_for_test_support(
            generation,
            vec![target.clone()],
            EdgeCompleteness::Incomplete {
                reasons: vec![EdgeIncompleteReason::AxisUnsupported(
                    EdgeAxis::ProofAttribution,
                )],
            },
            1,
            vec![selected_row(
                &analyzer,
                &target,
                Some(&witness),
                UsageProof::Proven,
                UsageHitKind::Reference,
                generation,
            )],
        );
        let mut candidate = vec![candidate_state(&analyzer, &target)];
        assert_eq!(
            SelectedTraceControl::Complete,
            trace_selected_test_reachability(
                &analyzer,
                &index,
                &mut SelectedInverseFrontierCache::default(),
                &BTreeSet::new(),
                &[0],
                &mut candidate,
                &CancellationToken::new(),
                &mut SelectedMissingTestsTelemetry::default(),
            )
        );
        assert!(!candidate[0].reached);
        assert_eq!(
            BTreeSet::from([MissingTestsIncompleteReason::UnsupportedBindingBoundary]),
            candidate[0].incomplete_reasons
        );
    }

    #[test]
    fn selected_inverse_bfs_obeys_branch_cycle_and_usage_surface_laws() {
        let (_project, analyzer) = selected_java_bfs_project();
        let helper = java_method(&analyzer, "helper");
        let witness = java_method(&analyzer, "witness");
        let generation = analyzer.project().analysis_generation();
        let run = |index: &SelectedReferenceInverseIndex, target: &CodeUnit| {
            let mut candidates = vec![candidate_state(&analyzer, target)];
            let mut telemetry = SelectedMissingTestsTelemetry::default();
            assert_eq!(
                SelectedTraceControl::Complete,
                trace_selected_test_reachability(
                    &analyzer,
                    index,
                    &mut SelectedInverseFrontierCache::default(),
                    &BTreeSet::new(),
                    &[0],
                    &mut candidates,
                    &CancellationToken::new(),
                    &mut telemetry,
                )
            );
            (candidates.pop().expect("one candidate"), telemetry)
        };

        let positive_wins = java_method(&analyzer, "positiveWins");
        let positive_index = SelectedReferenceInverseIndex::from_forward_rows_for_test_support(
            generation,
            vec![positive_wins.clone()],
            EdgeCompleteness::Incomplete {
                reasons: vec![EdgeIncompleteReason::ForwardResolutionIncomplete],
            },
            2,
            vec![
                selected_row(
                    &analyzer,
                    &positive_wins,
                    Some(&helper),
                    UsageProof::Unproven,
                    UsageHitKind::Reference,
                    generation,
                ),
                selected_row(
                    &analyzer,
                    &positive_wins,
                    Some(&witness),
                    UsageProof::Proven,
                    UsageHitKind::Reference,
                    generation,
                ),
            ],
        );
        let (positive, _) = run(&positive_index, &positive_wins);
        assert!(positive.reached);
        assert!(positive.incomplete_reasons.is_empty());

        let cycle_a = java_method(&analyzer, "cycleA");
        let cycle_b = java_method(&analyzer, "cycleB");
        let cycle_index = SelectedReferenceInverseIndex::from_forward_rows_for_test_support(
            generation,
            vec![cycle_a.clone(), cycle_b.clone()],
            EdgeCompleteness::Complete,
            2,
            vec![
                selected_row(
                    &analyzer,
                    &cycle_a,
                    Some(&cycle_b),
                    UsageProof::Proven,
                    UsageHitKind::Reference,
                    generation,
                ),
                selected_row(
                    &analyzer,
                    &cycle_b,
                    Some(&cycle_a),
                    UsageProof::Proven,
                    UsageHitKind::Reference,
                    generation,
                ),
            ],
        );
        let (cycle, _) = run(&cycle_index, &cycle_a);
        assert!(!cycle.reached);
        assert!(
            cycle.incomplete_reasons.is_empty(),
            "a closed all-proven cycle is an authoritative missing candidate"
        );

        let ignored_noise = java_method(&analyzer, "ignoredNoise");
        let ignored_index = SelectedReferenceInverseIndex::from_forward_rows_for_test_support(
            generation,
            vec![ignored_noise.clone()],
            EdgeCompleteness::Complete,
            3,
            [
                UsageHitKind::Import,
                UsageHitKind::Reexport,
                UsageHitKind::Definition,
            ]
            .into_iter()
            .map(|kind| {
                selected_row(
                    &analyzer,
                    &ignored_noise,
                    Some(&witness),
                    UsageProof::Proven,
                    kind,
                    generation,
                )
            })
            .collect(),
        );
        let (ignored, ignored_telemetry) = run(&ignored_index, &ignored_noise);
        assert!(!ignored.reached);
        assert!(ignored.incomplete_reasons.is_empty());
        assert_eq!(0, ignored_telemetry.proven_rows_observed);

        let override_target = java_method(&analyzer, "overrideTarget");
        let override_index = SelectedReferenceInverseIndex::from_forward_rows_for_test_support(
            generation,
            vec![override_target.clone()],
            EdgeCompleteness::Complete,
            1,
            vec![selected_row(
                &analyzer,
                &override_target,
                Some(&witness),
                UsageProof::Proven,
                UsageHitKind::OverrideDeclaration,
                generation,
            )],
        );
        let (overridden, _) = run(&override_index, &override_target);
        assert!(overridden.reached);
    }

    #[test]
    fn selected_late_terminal_signal_republishes_the_complete_inventory_only() {
        let (_project, analyzer) = selected_java_bfs_project();
        let first = candidate_state(&analyzer, &java_method(&analyzer, "changed")).record;
        let second = candidate_state(&analyzer, &java_method(&analyzer, "empty")).record;

        for terminal_reason in [
            MissingTestsIncompleteReason::ReferenceGraphCancelled,
            MissingTestsIncompleteReason::ReferenceGraphStale,
        ] {
            let result = MissingTestsResult {
                endpoints: BlastRadiusEndpoints {
                    base: "base".to_string(),
                    target: "worktree".to_string(),
                },
                analysis: MissingTestsAnalysis {
                    mode: MissingTestsMode::FileGraphNarrowedBindingReachability,
                    file_graph_completion: FileGraphCompletion::Incomplete,
                    exact_usage_completion: FileGraphCompletion::Incomplete,
                    candidate_function_count: 2,
                    reached_function_count: 1,
                    missing_function_count: 0,
                    indeterminate_function_count: 1,
                    paths_outside_file_graph: Vec::new(),
                    unresolved_changed_paths: vec!["unknown.java".to_string()],
                    incomplete_reasons: vec![
                        MissingTestsIncompleteReason::CompilationScopeUnresolved,
                        MissingTestsIncompleteReason::OpenBindingFrontier,
                        MissingTestsIncompleteReason::UnprovenBindingEdge,
                    ],
                },
                missing_functions: Vec::new(),
                indeterminate_functions: vec![second.clone()],
            };
            let reset = reset_finished_result_all_indeterminate(
                result,
                vec![first.clone(), second.clone()],
                terminal_reason,
            );
            assert_eq!(0, reset.analysis.reached_function_count);
            assert_eq!(0, reset.analysis.missing_function_count);
            assert_eq!(2, reset.analysis.indeterminate_function_count);
            assert!(reset.missing_functions.is_empty());
            assert_eq!(2, reset.indeterminate_functions.len());
            assert!(
                reset
                    .indeterminate_functions
                    .iter()
                    .all(|candidate| { candidate.incomplete_reasons == vec![terminal_reason] })
            );
            assert_eq!(
                vec![
                    MissingTestsIncompleteReason::CompilationScopeUnresolved,
                    terminal_reason,
                ],
                reset.analysis.incomplete_reasons
            );
        }
    }

    #[test]
    fn selected_missing_tests_rejects_mixed_language_inverse_coverage_without_a_prefix() {
        const BASE_JAVA: &str =
            "package demo;\nclass Service {\n  int changed() { return 1; }\n}\n";
        const TARGET_JAVA: &str =
            "package demo;\nclass Service {\n  int changed() { return 2; }\n}\n";
        let project = InlineTestProject::with_language(Language::Java)
            .file("src/main/java/demo/Service.java", BASE_JAVA)
            .file(
                "src/main/kotlin/demo/Foreign.kt",
                "package demo\nclass Foreign { fun value() = 1 }\n",
            )
            .build();
        let repository = Repository::init(project.root()).expect("initialize mixed repository");
        commit_all(&repository, "base");
        let java_file = project.file("src/main/java/demo/Service.java");
        java_file
            .write(TARGET_JAVA)
            .expect("write changed Java target");

        let java = JavaAnalyzer::new(project.project_dyn());
        let multi = MultiAnalyzer::new(std::collections::BTreeMap::from([
            (
                Language::Java,
                AnalyzerDelegate::Java(JavaAnalyzer::new(project.project_dyn())),
            ),
            (
                Language::Kotlin,
                AnalyzerDelegate::Kotlin(KotlinAnalyzer::new(project.project_dyn())),
            ),
        ]));
        let facts = crate::native_resolution_test_support::parse_java_resolution_facts(
            &java_file,
            TARGET_JAVA,
        );
        let fragment = BindingFragmentId::for_test(b"missing-tests-mixed-language-law");
        let lexical = crate::analyzer::resolution::lower_for_test(fragment, Language::Java, &facts)
            .lexical()
            .clone();
        let typed = crate::analyzer::resolution::lower_for_test(fragment, Language::Java, &facts)
            .typed()
            .clone();
        let service = PreloadedFactResolutionService::from_lowered_fragments(
            [lexical.clone()],
            [typed.clone()],
        );
        let engine = SelectedFactResolutionEngine::new(&service);
        let snapshot = engine
            .snapshot(&CancellationToken::new())
            .expect("the Java selection must snapshot");
        let catalog = FactReferenceEdgeCatalog::from_selected_fragments(
            &java,
            [FactReferenceEdgeSelectedFragment::new(
                java_file,
                TARGET_JAVA,
                &facts,
                &lexical,
                &typed,
                crate::analyzer::resolution::test_shared_names(),
            )],
            &CancellationToken::new(),
        )
        .expect("the Java edge catalog must build")
        .expect("an uncancelled Java edge catalog must publish");
        let mut telemetry = SelectedMissingTestsTelemetry::default();

        let error = missing_tests_at_root_with_selected_inverse_index(
            project.root(),
            &multi,
            MissingTestsParams::default(),
            &DiffAnalysisOptions::default(),
            &snapshot,
            &catalog,
            1,
            &CancellationToken::new(),
            &mut telemetry,
        )
        .expect_err("a Java-only inverse stream cannot certify Kotlin reference sites");
        assert!(
            error.contains("does not cover the complete analyzed workspace"),
            "{error}"
        );
        assert_eq!(1, telemetry.inverse_index_build_attempts);
        assert_eq!(1, telemetry.failed_inverse_index_builds);
        assert_eq!(0, telemetry.frontier_requests);
    }

    #[test]
    fn selected_missing_tests_total_result_covers_empty_cancelled_and_stale_requests() {
        const BASE_JAVA: &str =
            "package demo;\nclass Service {\n  int changed() { return 1; }\n}\n";
        const TARGET_JAVA: &str =
            "package demo;\nclass Service {\n  int changed() { return 2; }\n}\n";
        let project = InlineTestProject::with_language(Language::Java)
            .file("src/main/java/demo/Service.java", BASE_JAVA)
            .build();
        let repository = Repository::init(project.root()).expect("initialize Java repository");
        commit_all(&repository, "base");
        let java_file = project.file("src/main/java/demo/Service.java");
        let overlay = Arc::new(OverlayProject::new(project.project_dyn()));
        let analyzer = JavaAnalyzer::new(overlay.clone());
        let facts = crate::native_resolution_test_support::parse_java_resolution_facts(
            &java_file, BASE_JAVA,
        );
        let fragment = BindingFragmentId::for_test(b"missing-tests-total-result-law");
        let lexical = crate::analyzer::resolution::lower_for_test(fragment, Language::Java, &facts)
            .lexical()
            .clone();
        let typed = crate::analyzer::resolution::lower_for_test(fragment, Language::Java, &facts)
            .typed()
            .clone();
        let service = PreloadedFactResolutionService::from_lowered_fragments(
            [lexical.clone()],
            [typed.clone()],
        );
        let engine = SelectedFactResolutionEngine::new(&service);
        let snapshot = engine
            .snapshot(&CancellationToken::new())
            .expect("the Java selection must snapshot");
        let catalog = FactReferenceEdgeCatalog::from_selected_fragments(
            &analyzer,
            [FactReferenceEdgeSelectedFragment::new(
                java_file.clone(),
                BASE_JAVA,
                &facts,
                &lexical,
                &typed,
                crate::analyzer::resolution::test_shared_names(),
            )],
            &CancellationToken::new(),
        )
        .expect("the Java edge catalog must build")
        .expect("an uncancelled Java edge catalog must publish");
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let mut telemetry = SelectedMissingTestsTelemetry::default();

        let empty = missing_tests_at_root_with_selected_inverse_index(
            project.root(),
            &analyzer,
            MissingTestsParams::default(),
            &DiffAnalysisOptions::default(),
            &snapshot,
            &catalog,
            1,
            &cancellation,
            &mut telemetry,
        )
        .expect("an empty candidate inventory bypasses cancellation");
        assert_eq!(0, empty.analysis.candidate_function_count);
        assert_eq!(
            FileGraphCompletion::Complete,
            empty.analysis.exact_usage_completion
        );
        assert_eq!(0, telemetry.inverse_index_build_attempts);

        java_file
            .write(TARGET_JAVA)
            .expect("write changed Java target");
        let cancelled = missing_tests_at_root_with_selected_inverse_index(
            project.root(),
            &analyzer,
            MissingTestsParams::default(),
            &DiffAnalysisOptions::default(),
            &snapshot,
            &catalog,
            1,
            &cancellation,
            &mut telemetry,
        )
        .expect("pre-cancelled selected missing_tests returns a total result");
        assert_eq!(1, cancelled.analysis.candidate_function_count);
        assert_eq!(0, cancelled.analysis.reached_function_count);
        assert_eq!(0, cancelled.analysis.missing_function_count);
        assert_eq!(1, cancelled.analysis.indeterminate_function_count);
        assert_eq!(
            vec![MissingTestsIncompleteReason::TargetGraphCancelled],
            cancelled.indeterminate_functions[0].incomplete_reasons
        );
        assert_eq!(0, telemetry.inverse_index_build_attempts);

        assert!(overlay.set(java_file.abs_path(), TARGET_JAVA.to_string()));
        let stale = missing_tests_at_root_with_selected_inverse_index(
            project.root(),
            &analyzer,
            MissingTestsParams::default(),
            &DiffAnalysisOptions::default(),
            &snapshot,
            &catalog,
            1,
            &CancellationToken::new(),
            &mut telemetry,
        )
        .expect("a stale selected missing_tests request returns a total result");
        assert_eq!(1, stale.analysis.candidate_function_count);
        assert_eq!(0, stale.analysis.reached_function_count);
        assert_eq!(0, stale.analysis.missing_function_count);
        assert_eq!(1, stale.analysis.indeterminate_function_count);
        assert_eq!(
            vec![MissingTestsIncompleteReason::ReferenceGraphStale],
            stale.indeterminate_functions[0].incomplete_reasons
        );
        assert_eq!(0, telemetry.inverse_index_build_attempts);
    }
}
