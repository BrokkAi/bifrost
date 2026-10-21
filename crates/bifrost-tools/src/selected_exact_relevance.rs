//! Selected canonical exact-usage relevance path.
//!
//! The parent module retains the incumbent import/history and usage-graph
//! ranking implementations until cutover. This module owns only the selected
//! graph producer seam and its exact-ranking adapter.

use crate::relevance::*;

use brokk_bifrost_analysis::analyzer::usages::workspace_graph::canonical_workspace_graph::SelectedWorkspaceUsageRankingBuildOutcome;

/// Observable lifecycle of the selected exact graph used by one full
/// relevance request. This is test-support telemetry, not a production API.
#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SelectedExactUsageGraphLifecycle {
    #[default]
    NotRequested,
    Hit,
    Built,
    UncachedOverBudget,
    Uncached,
    Incomplete,
    Cancelled,
    Stale,
    Error,
}

/// Build and cache observations for the selected exact graph without exposing
/// any graph node or edge representation.
#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SelectedExactRelevanceTelemetry {
    pub build_attempts: usize,
    pub graph_complete: Option<bool>,
    pub lifecycle: SelectedExactUsageGraphLifecycle,
}

/// Run the complete public relevance operation with the selected exact graph
/// producer substituted only at the exact usage-graph cache-miss leader.
///
/// The string seed resolver and result classification remain above this seam
/// in `searchtools::summaries`; calibrated PageRank and history/import fill
/// remain below it in this module. The builder is lazy, so validation and cache
/// hits never construct a selected graph.
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn most_relevant_project_files_with_selected_exact_graph_and_cancellation(
    analyzer: &dyn IAnalyzer,
    seeds: &[(ProjectFile, f64)],
    top_k: usize,
    half_life: Option<f64>,
    cancellation: &CancellationToken,
    telemetry: &mut SelectedExactRelevanceTelemetry,
    build_graph: &mut dyn FnMut(
        &CancellationToken,
    ) -> Result<SelectedWorkspaceUsageRankingBuildOutcome, String>,
) -> Result<MostRelevantProjectFilesOutcome, String> {
    most_relevant_project_files_with_usage_candidates(
        analyzer,
        seeds,
        top_k,
        half_life,
        cancellation,
        |seed_weights, k| {
            related_files_by_selected_usage(
                analyzer,
                seed_weights,
                k,
                cancellation,
                telemetry,
                build_graph,
            )
        },
    )
}

#[cfg(any(test, feature = "test-support"))]
fn related_files_by_selected_usage(
    analyzer: &dyn IAnalyzer,
    seed_weights: &HashMap<ProjectFile, f64>,
    k: usize,
    cancellation: &CancellationToken,
    telemetry: &mut SelectedExactRelevanceTelemetry,
    build_graph: &mut dyn FnMut(
        &CancellationToken,
    ) -> Result<SelectedWorkspaceUsageRankingBuildOutcome, String>,
) -> Result<Cancellable<Vec<FileRelevance>>, String> {
    let selected_ecosystems: BTreeSet<_> = seed_weights
        .keys()
        .map(|file| {
            UsageEcosystem::of(brokk_bifrost_core::analyzer::common::language_for_file(
                file,
            ))
        })
        .collect();
    let supported = selected_ecosystems == BTreeSet::from([UsageEcosystem::Jvm]);
    #[cfg(test)]
    let supported = supported || selected_ecosystems == BTreeSet::from([UsageEcosystem::Rust]);
    if !supported {
        return Err(format!(
            "selected exact relevance requires one supported ecosystem, got {selected_ecosystems:?}"
        ));
    }

    let acquisition = acquire_usage_ranking_graph_from_builder(
        analyzer,
        &selected_ecosystems,
        WorkspaceUsageGraphKind::Exact,
        WorkspaceUsageGraphProducer::SelectedCanonical,
        cancellation,
        || {
            telemetry.build_attempts = telemetry.build_attempts.saturating_add(1);
            let outcome = match build_graph(cancellation) {
                Ok(outcome) => outcome,
                Err(error) => {
                    telemetry.graph_complete = None;
                    telemetry.lifecycle = SelectedExactUsageGraphLifecycle::Error;
                    return Err(error);
                }
            };
            Ok(match outcome {
                SelectedWorkspaceUsageRankingBuildOutcome::Complete(graph) => {
                    telemetry.graph_complete = Some(true);
                    WorkspaceUsageGraphCacheBuildOutcome::Complete(graph.into_ranking_graph())
                }
                SelectedWorkspaceUsageRankingBuildOutcome::Incomplete(graph) => {
                    telemetry.graph_complete = Some(false);
                    WorkspaceUsageGraphCacheBuildOutcome::Incomplete(graph.into_ranking_graph())
                }
                SelectedWorkspaceUsageRankingBuildOutcome::Cancelled => {
                    telemetry.graph_complete = None;
                    telemetry.lifecycle = SelectedExactUsageGraphLifecycle::Cancelled;
                    WorkspaceUsageGraphCacheBuildOutcome::Cancelled
                }
                SelectedWorkspaceUsageRankingBuildOutcome::Stale => {
                    telemetry.graph_complete = None;
                    telemetry.lifecycle = SelectedExactUsageGraphLifecycle::Stale;
                    WorkspaceUsageGraphCacheBuildOutcome::Stale
                }
                SelectedWorkspaceUsageRankingBuildOutcome::Unavailable(reason) => {
                    telemetry.graph_complete = None;
                    telemetry.lifecycle = SelectedExactUsageGraphLifecycle::Error;
                    return Err(reason);
                }
            })
        },
    )?;
    let (ranking_graph, graph_incomplete) = match acquisition {
        UsageGraphAcquisition::Complete(graph, lifecycle) => {
            telemetry.graph_complete = Some(true);
            telemetry.lifecycle = match lifecycle {
                Some(WorkspaceUsageGraphCacheLifecycle::Hit) => {
                    SelectedExactUsageGraphLifecycle::Hit
                }
                Some(WorkspaceUsageGraphCacheLifecycle::Built) => {
                    SelectedExactUsageGraphLifecycle::Built
                }
                Some(WorkspaceUsageGraphCacheLifecycle::UncachedOverBudget) => {
                    SelectedExactUsageGraphLifecycle::UncachedOverBudget
                }
                None => SelectedExactUsageGraphLifecycle::Uncached,
            };
            (graph, false)
        }
        UsageGraphAcquisition::Incomplete(graph) => {
            telemetry.graph_complete = Some(false);
            telemetry.lifecycle = SelectedExactUsageGraphLifecycle::Incomplete;
            (graph, true)
        }
        UsageGraphAcquisition::Cancelled => {
            telemetry.graph_complete = None;
            telemetry.lifecycle = SelectedExactUsageGraphLifecycle::Cancelled;
            return Ok(Cancellable::Cancelled);
        }
        UsageGraphAcquisition::Stale => {
            telemetry.graph_complete = None;
            telemetry.lifecycle = SelectedExactUsageGraphLifecycle::Stale;
            return Err(
                "selected exact relevance observed a stale graph generation twice".to_string(),
            );
        }
    };
    let ranking_graph = if graph_incomplete {
        Cancellable::Incomplete(ranking_graph)
    } else {
        Cancellable::Complete(ranking_graph)
    };
    Ok(rank_usage_graph_with_cancellation(
        ranking_graph,
        seed_weights,
        k,
        cancellation,
    ))
}

/// Run the incumbent calibrated exact-usage ranking over an already-built
/// graph without consulting the production graph cache.
///
/// The selected native-resolution prototype owns graph completeness in its
/// build outcome. Once it has retained a graph, ranking can therefore expose
/// only successful results or cancellation. This adapter deliberately keeps
/// seed normalization, incomplete-node filtering, score bucketing, and
/// deterministic path tie-breaking in the incumbent implementation.
#[cfg(test)]
pub(crate) fn rank_exact_workspace_usage_graph_with_cancellation(
    ranking_graph: &UsageRankingGraph,
    seeds: &[(ProjectFile, f64)],
    k: usize,
    cancellation: &CancellationToken,
) -> Option<Vec<(ProjectFile, f64)>> {
    if cancellation.is_cancelled() {
        return None;
    }
    let seed_weights = seed_weight_map(seeds);
    if cancellation.is_cancelled() {
        return None;
    }
    let ranked = match related_files_by_usage_graph_with_cancellation(
        ranking_graph,
        &seed_weights,
        k,
        UsageReferenceWeights::CALIBRATED,
        cancellation,
    ) {
        Cancellable::Complete(ranked) | Cancellable::Incomplete(ranked) => ranked,
        Cancellable::Cancelled => return None,
    };
    if cancellation.is_cancelled() {
        return None;
    }
    let mut output = Vec::with_capacity(ranked.len());
    for candidate in ranked {
        if cancellation.is_cancelled() {
            return None;
        }
        output.push((candidate.file, candidate.score));
    }
    (!cancellation.is_cancelled()).then_some(output)
}
