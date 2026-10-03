//! Selected canonical exact-usage relevance path.
//!
//! The parent module retains the incumbent import/history and usage-graph
//! ranking implementations until cutover. This module owns only the selected
//! graph producer seam and its exact-ranking adapter.

use super::*;
use crate::analyzer::usages::workspace_graph::SelectedWorkspaceUsageRankingBuildOutcome;

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
        .map(|file| UsageEcosystem::of(crate::analyzer::common::language_for_file(file)))
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
    Ok(
        match related_files_by_usage_graph_with_cancellation(
            &ranking_graph,
            seed_weights,
            k,
            UsageReferenceWeights::CALIBRATED,
            cancellation,
        ) {
            Cancellable::Complete(files) if graph_incomplete => Cancellable::Incomplete(files),
            other => other,
        },
    )
}

/// Run the incumbent calibrated exact-usage ranking over an already-built
/// graph without consulting the production graph cache.
///
/// The selected native-resolution prototype owns graph completeness in its
/// build outcome. Once it has retained a graph, ranking can therefore expose
/// only successful results or cancellation. This adapter deliberately keeps
/// seed normalization, incomplete-node filtering, score bucketing, and
/// deterministic path tie-breaking in the incumbent implementation.
#[cfg(any(test, feature = "test-support"))]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::Language;
    use crate::analyzer::usages::inverted_edges::UsageReferenceCounts;
    use crate::analyzer::usages::workspace_graph::{
        UsageEcosystem, WorkspaceUsageEdge, WorkspaceUsageRankingGraph, WorkspaceUsageRankingNode,
    };
    use crate::hash::HashMap;
    use crate::inline_project::InlineTestProject;

    #[test]
    fn native_rust_relevance_preserves_calibrated_scores_and_complete_cache_authority() {
        use crate::analyzer::RustAnalyzer;
        use crate::analyzer::selected_rust_relevance_graph_shadow;

        // A module mount keeps the token tree unenumerable. A bare
        // `unknown_macro!()` no longer leaves the reference inventory
        // incomplete in item position either, now that an item-position token
        // tree is enumerated for references.
        let opaque = "pub fn opaque() { unknown_macro! { mod generated; } }";
        for hidden_source in ["pub fn unused() {}", opaque] {
            let fixture = InlineTestProject::with_language(Language::Rust)
                .file("Cargo.toml", "[package]\nname = \"rank_shadow\"\nversion = \"0.1.0\"\nedition = \"2024\"\n")
                .file("src/lib.rs", "pub mod z_hot; pub mod a_cold; pub mod hidden;\npub fn caller() {\ncrate::z_hot::target();\ncrate::z_hot::target();\ncrate::a_cold::target();\n}\n")
                .file("src/z_hot.rs", "pub fn target() {}\n")
                .file("src/a_cold.rs", "pub fn target() {}\n")
                .file("src/hidden.rs", hidden_source)
                .file("Foreign.java", "class Foreign {}\n")
                .build();
            let analyzer = RustAnalyzer::new(fixture.project_dyn());
            let cancellation = CancellationToken::new();
            let seed_weights = HashMap::from_iter([(fixture.file("src/lib.rs"), 1.0)]);
            let mixed_seeds = HashMap::from_iter([
                (fixture.file("src/lib.rs"), 1.0),
                (fixture.file("Foreign.java"), 1.0),
            ]);
            let mut mixed_telemetry = SelectedExactRelevanceTelemetry::default();
            assert!(
                related_files_by_selected_usage(
                    &analyzer,
                    &mixed_seeds,
                    2,
                    &cancellation,
                    &mut mixed_telemetry,
                    &mut |_| panic!("mixed ecosystems must not acquire a Rust-only graph"),
                )
                .is_err()
            );
            assert_eq!(mixed_telemetry, SelectedExactRelevanceTelemetry::default());
            let incomplete = hidden_source == opaque;
            let mut total_builds = 0;
            for attempt in 0..2 {
                let mut telemetry = SelectedExactRelevanceTelemetry::default();
                let result = related_files_by_selected_usage(
                    &analyzer,
                    &seed_weights,
                    2,
                    &cancellation,
                    &mut telemetry,
                    &mut |cancellation| {
                        total_builds += 1;
                        selected_rust_relevance_graph_shadow(&analyzer, cancellation)
                    },
                )
                .expect("native Rust relevance shadow must build");
                let ranked = match result {
                    Cancellable::Complete(files) if !incomplete => files,
                    Cancellable::Incomplete(files) if incomplete => files,
                    _ => panic!("ranking must retain native inventory completion"),
                };
                assert_eq!(
                    ranked.iter().map(|row| &row.file).collect::<Vec<_>>(),
                    [
                        &fixture.file("src/z_hot.rs"),
                        &fixture.file("src/a_cold.rs")
                    ]
                );
                // Independent stationary solution: seed mass is 1/(1+alpha),
                // with 2:1 call weights and dangling mass returning to the seed.
                let expected = [
                    2.0 * ALPHA / (3.0 * (1.0 + ALPHA)),
                    ALPHA / (3.0 * (1.0 + ALPHA)),
                ];
                for (row, expected) in ranked.iter().zip(expected) {
                    assert!(
                        (row.score - expected).abs() < 1.0e-5,
                        "{}: score={}, expected={expected}",
                        row.file,
                        row.score
                    );
                }
                assert_eq!(telemetry.graph_complete, Some(!incomplete));
                if incomplete {
                    assert_eq!(
                        telemetry.lifecycle,
                        SelectedExactUsageGraphLifecycle::Incomplete
                    );
                    assert_eq!(telemetry.build_attempts, 1, "partial graph must rebuild");
                } else {
                    assert_eq!(
                        telemetry.lifecycle,
                        if attempt == 0 {
                            SelectedExactUsageGraphLifecycle::Built
                        } else {
                            SelectedExactUsageGraphLifecycle::Hit
                        }
                    );
                    assert_eq!(telemetry.build_attempts, usize::from(attempt == 0));
                }
            }
            assert_eq!(total_builds, if incomplete { 2 } else { 1 });
        }
    }

    #[test]
    fn selected_java_adapter_matches_the_incumbent_calibrated_exact_operation() {
        let project = InlineTestProject::with_language(Language::Java)
            .file("src/Seed.java", "class Seed {}\n")
            .file("src/ZCallTarget.java", "class ZCallTarget {}\n")
            .file("src/AMemberTarget.java", "class AMemberTarget {}\n")
            .build();
        let seed = project.file("src/Seed.java");
        let call_target = project.file("src/ZCallTarget.java");
        let member_target = project.file("src/AMemberTarget.java");
        let mut node_indices_by_file = HashMap::default();
        node_indices_by_file.insert(seed.clone(), vec![0]);
        node_indices_by_file.insert(call_target.clone(), vec![1]);
        node_indices_by_file.insert(member_target.clone(), vec![2]);
        let graph = WorkspaceUsageRankingGraph {
            nodes: vec![
                WorkspaceUsageRankingNode {
                    primary_file: seed.clone(),
                    seed_files: vec![seed.clone()],
                    incomplete: false,
                    contains_tests: None,
                },
                WorkspaceUsageRankingNode {
                    primary_file: call_target.clone(),
                    seed_files: vec![call_target.clone()],
                    incomplete: false,
                    contains_tests: None,
                },
                WorkspaceUsageRankingNode {
                    primary_file: member_target.clone(),
                    seed_files: vec![member_target.clone()],
                    incomplete: false,
                    contains_tests: None,
                },
            ],
            edges: vec![
                WorkspaceUsageEdge {
                    from: 0,
                    to: 1,
                    counts: UsageReferenceCounts {
                        calls: 1,
                        ..UsageReferenceCounts::default()
                    },
                },
                WorkspaceUsageEdge {
                    from: 0,
                    to: 2,
                    counts: UsageReferenceCounts {
                        members: 1,
                        ..UsageReferenceCounts::default()
                    },
                },
            ],
            node_indices_by_file,
            resolved_ecosystems: vec![UsageEcosystem::Jvm],
        };
        let seeds = [(seed.clone(), 0.25), (seed, 0.75)];
        let seed_weights = super::seed_weight_map(&seeds);
        let incumbent = match super::related_files_by_usage_graph_with_cancellation(
            &graph,
            &seed_weights,
            10,
            UsageReferenceWeights::CALIBRATED,
            &crate::CancellationToken::default(),
        ) {
            super::Cancellable::Complete(ranked) => ranked
                .into_iter()
                .map(|candidate| (candidate.file, candidate.score))
                .collect::<Vec<_>>(),
            super::Cancellable::Incomplete(_) => {
                panic!("ranking an already-built graph cannot become incomplete")
            }
            super::Cancellable::Cancelled => panic!("an uncancelled exact ranking must finish"),
        };

        let adapted = super::rank_exact_workspace_usage_graph_with_cancellation(
            &graph,
            &seeds,
            10,
            &crate::CancellationToken::default(),
        )
        .expect("an uncancelled adapted exact ranking must finish");

        assert_eq!(adapted, incumbent);
        assert_eq!(adapted[0].0, call_target);
        assert_eq!(adapted[1].0, member_target);
        assert!(adapted[0].1 > adapted[1].1);
    }
}
