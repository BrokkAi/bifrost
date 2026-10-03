//! Coarse file-level usage graph for interactive relevance ranking.

use super::inverted_edges::UsageReferenceCounts;
use super::workspace_graph::{
    UsageEcosystem, WorkspaceUsageEdge, WorkspaceUsageRankingGraph, WorkspaceUsageRankingNode,
};
use crate::analyzer::capabilities::resolve_imported_files_from_infos;
use crate::analyzer::{IAnalyzer, ProjectFile};
use crate::cancellation::CancellationToken;
use crate::hash::HashMap;
use crate::profiling;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use rayon::prelude::*;
use std::collections::BTreeSet;

pub(crate) enum WorkspaceFileUsageGraphBuildOutcome {
    Complete(WorkspaceUsageRankingGraph),
    Incomplete(WorkspaceUsageRankingGraph),
    Cancelled,
}

/// Build one coarse edge for each structured direct file dependency.
///
/// This graph deliberately stops at file identity. It does not run exact symbol
/// authorization, receiver inference, or macro token-tree recovery. Those
/// relations remain available through `usage_graph_exact` ranking and the
/// public `usage_graph` tool. Besides ordinary imports, providers may contribute
/// dependencies such as Rust's structured external-module declarations.
pub(crate) fn build_workspace_file_usage_graph_with_cancellation(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    selected_ecosystems: &BTreeSet<UsageEcosystem>,
    cancellation: &CancellationToken,
) -> WorkspaceFileUsageGraphBuildOutcome {
    let (files, inventory_complete) = {
        let _scope = profiling::scope("file_usage_graph.files");
        let inventory = analyzer.source_file_inventory();
        let mut files = inventory
            .rows
            .into_iter()
            .filter(|file| {
                selected_ecosystems.contains(&UsageEcosystem::of(
                    crate::analyzer::common::declaration_language_for_file(file),
                ))
            })
            .collect::<Vec<_>>();
        files.sort();
        files.dedup();
        (files, inventory.complete)
    };
    if cancellation.is_cancelled() {
        return WorkspaceFileUsageGraphBuildOutcome::Cancelled;
    }

    let Some(provider) = analyzer.import_analysis_provider() else {
        let contains_tests = files
            .iter()
            .map(|file| (file.clone(), analyzer.contains_tests(file)))
            .collect();
        let indices = files
            .iter()
            .cloned()
            .enumerate()
            .map(|(index, file)| (file, index))
            .collect();
        let adjacency = vec![Vec::new(); files.len()];
        let graph = file_graph(files, indices, adjacency, contains_tests);
        return if inventory_complete {
            WorkspaceFileUsageGraphBuildOutcome::Complete(graph)
        } else {
            WorkspaceFileUsageGraphBuildOutcome::Incomplete(graph)
        };
    };
    let dependency_facts = {
        let _scope = profiling::scope("file_usage_graph.import_facts");
        provider.file_dependency_facts_for_files(&files)
    };
    let import_infos = dependency_facts.as_ref().map(|facts_by_file| {
        facts_by_file
            .iter()
            .map(|(file, facts)| (file.clone(), facts.imports.clone()))
            .collect()
    });
    let import_facts_complete = dependency_facts
        .as_ref()
        .is_none_or(|facts| files.iter().all(|file| facts.contains_key(file)));
    let contains_tests = files
        .iter()
        .filter_map(|file| {
            let contains_tests = match dependency_facts.as_ref() {
                Some(facts) => facts.get(file)?.contains_tests,
                None => None,
            }
            .unwrap_or_else(|| analyzer.contains_tests(file));
            Some((file.clone(), contains_tests))
        })
        .collect();
    if cancellation.is_cancelled() {
        return WorkspaceFileUsageGraphBuildOutcome::Cancelled;
    }

    // Optional prefetch implementations may hydrate their whole input set.
    // A partial authoritative batch must not invite catch-up for missing files.
    if inventory_complete && import_facts_complete {
        let _scope = profiling::scope("file_usage_graph.prefetch_targets");
        provider.prefetch_file_dependency_targets(&files, import_infos.as_ref(), cancellation);
    }
    if cancellation.is_cancelled() {
        return WorkspaceFileUsageGraphBuildOutcome::Cancelled;
    }

    let additional_dependencies = {
        let _scope = profiling::scope("file_usage_graph.additional_dependencies");
        provider.additional_direct_file_dependencies(&files, cancellation)
    };
    let additional_dependencies = match additional_dependencies {
        Some(dependencies) => dependencies,
        None if cancellation.is_cancelled() => {
            return WorkspaceFileUsageGraphBuildOutcome::Cancelled;
        }
        None => crate::analyzer::AdditionalFileDependencies::incomplete(HashMap::default()),
    };
    let additional_dependencies_complete = additional_dependencies.complete;
    if cancellation.is_cancelled() {
        return WorkspaceFileUsageGraphBuildOutcome::Cancelled;
    }

    let indices: HashMap<_, _> = files
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, file)| (file, index))
        .collect();
    let adjacency = {
        let _scope = profiling::scope("file_usage_graph.resolve_relations");
        files
            .par_iter()
            .enumerate()
            .map(|(from, file)| {
                if cancellation.is_cancelled() {
                    return None;
                }
                let mut imported = import_infos.as_ref().map_or_else(
                    || {
                        let imports = provider.import_info_of(token, file);
                        resolve_imported_files_from_infos(provider, file, &imports)
                    },
                    |infos_by_file| {
                        infos_by_file
                            .get(file)
                            .map(|imports| {
                                resolve_imported_files_from_infos(provider, file, imports)
                            })
                            .unwrap_or_default()
                    },
                );
                if let Some(additional) = additional_dependencies.dependencies.get(file) {
                    imported.extend(additional.iter().cloned());
                }
                let mut targets = imported
                    .into_iter()
                    .filter_map(|target| indices.get(&target).copied())
                    .filter(|target| *target != from)
                    .collect::<Vec<_>>();
                targets.sort_unstable();
                targets.dedup();
                Some(targets)
            })
            .collect::<Option<Vec<_>>>()
    };
    let Some(adjacency) = adjacency else {
        return WorkspaceFileUsageGraphBuildOutcome::Cancelled;
    };

    let graph = {
        let _scope = profiling::scope("file_usage_graph.compact");
        file_graph(files, indices, adjacency, contains_tests)
    };
    if inventory_complete && import_facts_complete && additional_dependencies_complete {
        WorkspaceFileUsageGraphBuildOutcome::Complete(graph)
    } else {
        WorkspaceFileUsageGraphBuildOutcome::Incomplete(graph)
    }
}

fn file_graph(
    files: Vec<ProjectFile>,
    indices: HashMap<ProjectFile, usize>,
    adjacency: Vec<Vec<usize>>,
    contains_tests: HashMap<ProjectFile, bool>,
) -> WorkspaceUsageRankingGraph {
    debug_assert_eq!(files.len(), adjacency.len());
    let nodes = files
        .iter()
        .cloned()
        .map(|file| {
            let contains_tests = contains_tests.get(&file).copied();
            WorkspaceUsageRankingNode {
                contains_tests,
                primary_file: file.clone(),
                seed_files: vec![file],
                incomplete: contains_tests.is_none(),
            }
        })
        .collect();
    let node_indices_by_file = indices
        .iter()
        .map(|(file, index)| (file.clone(), vec![*index]))
        .collect();
    let edge_count = adjacency.iter().map(Vec::len).sum();
    let mut edges = Vec::with_capacity(edge_count);
    for (from, targets) in adjacency.into_iter().enumerate() {
        edges.extend(targets.into_iter().map(|to| WorkspaceUsageEdge {
            from,
            to,
            counts: UsageReferenceCounts {
                other: 1,
                ..UsageReferenceCounts::default()
            },
        }));
    }
    WorkspaceUsageRankingGraph {
        nodes,
        edges,
        node_indices_by_file,
        #[cfg(test)]
        resolved_ecosystems: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn file(path: &str) -> ProjectFile {
        ProjectFile::new(
            std::env::current_dir().expect("test working directory must be available"),
            path,
        )
    }

    #[test]
    fn coarse_graph_is_deterministic_and_deduplicates_file_edges() {
        let a = file("a.rs");
        let b = file("b.rs");
        let c = file("c.rs");
        let files = vec![a.clone(), b.clone(), c.clone()];
        let indices = files
            .iter()
            .cloned()
            .enumerate()
            .map(|(index, file)| (file, index))
            .collect();
        let contains_tests = [(c.clone(), true)].into_iter().collect();
        let graph = file_graph(
            files,
            indices,
            vec![vec![1], vec![2], Vec::new()],
            contains_tests,
        );

        assert_eq!(3, graph.nodes.len());
        assert_eq!(2, graph.edges.len());
        assert_eq!((0, 1), (graph.edges[0].from, graph.edges[0].to));
        assert_eq!((1, 2), (graph.edges[1].from, graph.edges[1].to));
        assert!(graph.edges.iter().all(|edge| edge.counts.other == 1));
        assert_eq!(Some(true), graph.nodes[2].contains_tests);
    }
}

#[cfg(test)]
#[path = "file_usage_graph_tests.rs"]
mod contract_tests;
