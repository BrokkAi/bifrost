//! Coarse file-level usage graph for interactive relevance ranking.

use super::inverted_edges::UsageReferenceCounts;
use super::workspace_graph::{
    UsageEcosystem, WorkspaceUsageEdge, WorkspaceUsageRankingGraph, WorkspaceUsageRankingNode,
};
use crate::analyzer::capabilities::resolve_imported_files_from_infos;
use crate::analyzer::{IAnalyzer, ProjectFile};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, HashSet};
use crate::profiling;
use rayon::prelude::*;
use std::collections::BTreeSet;

pub(crate) enum WorkspaceFileUsageGraphBuildOutcome {
    Complete(WorkspaceUsageRankingGraph),
    Cancelled,
}

/// Build one coarse edge for each structured direct file import.
///
/// This graph deliberately stops at file identity. It does not run exact symbol
/// authorization, receiver inference, or macro token-tree recovery. Those
/// relations remain available through `usage_graph_exact` ranking and the
/// public `usage_graph` tool.
pub(crate) fn build_workspace_file_usage_graph_with_cancellation(
    analyzer: &dyn IAnalyzer,
    selected_ecosystems: &BTreeSet<UsageEcosystem>,
    cancellation: &CancellationToken,
) -> WorkspaceFileUsageGraphBuildOutcome {
    let files = {
        let _scope = profiling::scope("file_usage_graph.files");
        let mut files = analyzer
            .analyzed_files()
            .into_iter()
            .filter(|file| {
                selected_ecosystems.contains(&UsageEcosystem::of(
                    crate::analyzer::common::language_for_file(file),
                ))
            })
            .collect::<Vec<_>>();
        files.sort();
        files.dedup();
        files
    };
    if cancellation.is_cancelled() {
        return WorkspaceFileUsageGraphBuildOutcome::Cancelled;
    }

    let Some(provider) = analyzer.import_analysis_provider() else {
        return WorkspaceFileUsageGraphBuildOutcome::Complete(file_graph(files, Vec::new()));
    };
    let import_infos = {
        let _scope = profiling::scope("file_usage_graph.import_facts");
        provider.import_infos_for_files(&files)
    };
    if cancellation.is_cancelled() {
        return WorkspaceFileUsageGraphBuildOutcome::Cancelled;
    }

    let relations = {
        let _scope = profiling::scope("file_usage_graph.resolve_relations");
        let file_set: HashSet<_> = files.iter().cloned().collect();
        files
            .par_iter()
            .map(|file| {
                if cancellation.is_cancelled() {
                    return None;
                }
                let imported = import_infos.as_ref().map_or_else(
                    || {
                        let imports = provider.import_info_of(file);
                        resolve_imported_files_from_infos(provider, file, &imports)
                    },
                    |infos_by_file| {
                        let owned_imports;
                        let imports = if let Some(imports) = infos_by_file.get(file) {
                            imports.as_slice()
                        } else {
                            owned_imports = provider.import_info_of(file);
                            &owned_imports
                        };
                        resolve_imported_files_from_infos(provider, file, imports)
                    },
                );
                Some(
                    imported
                        .into_iter()
                        .filter(|target| target != file && file_set.contains(target))
                        .map(|target| (file.clone(), target))
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<Option<Vec<_>>>()
    };
    let Some(relations) = relations else {
        return WorkspaceFileUsageGraphBuildOutcome::Cancelled;
    };
    let relations = relations.into_iter().flatten().collect();

    let graph = {
        let _scope = profiling::scope("file_usage_graph.compact");
        file_graph(files, relations)
    };
    WorkspaceFileUsageGraphBuildOutcome::Complete(graph)
}

fn file_graph(
    files: Vec<ProjectFile>,
    relations: Vec<(ProjectFile, ProjectFile)>,
) -> WorkspaceUsageRankingGraph {
    let indices: HashMap<_, _> = files
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, file)| (file, index))
        .collect();
    let nodes = files
        .iter()
        .cloned()
        .map(|file| WorkspaceUsageRankingNode {
            primary_file: file.clone(),
            seed_files: vec![file],
            incomplete: false,
        })
        .collect();
    let node_indices_by_file = indices
        .iter()
        .map(|(file, index)| (file.clone(), vec![*index]))
        .collect();
    let mut pairs = BTreeSet::new();
    for (source, target) in relations {
        let (Some(from), Some(to)) = (indices.get(&source), indices.get(&target)) else {
            continue;
        };
        if from != to {
            pairs.insert((*from, *to));
        }
    }
    let edges = pairs
        .into_iter()
        .map(|(from, to)| WorkspaceUsageEdge {
            from,
            to,
            counts: UsageReferenceCounts {
                other: 1,
                ..UsageReferenceCounts::default()
            },
        })
        .collect();
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
    use std::path::PathBuf;

    fn file(path: &str) -> ProjectFile {
        ProjectFile::new(PathBuf::from("/workspace"), path)
    }

    #[test]
    fn coarse_graph_is_deterministic_and_deduplicates_file_edges() {
        let a = file("a.rs");
        let b = file("b.rs");
        let c = file("c.rs");
        let graph = file_graph(
            vec![a.clone(), b.clone(), c.clone()],
            vec![
                (a.clone(), b.clone()),
                (a.clone(), b.clone()),
                (a.clone(), a),
                (b, c),
            ],
        );

        assert_eq!(3, graph.nodes.len());
        assert_eq!(2, graph.edges.len());
        assert_eq!((0, 1), (graph.edges[0].from, graph.edges[0].to));
        assert_eq!((1, 2), (graph.edges[1].from, graph.edges[1].to));
        assert!(graph.edges.iter().all(|edge| edge.counts.other == 1));
    }
}
