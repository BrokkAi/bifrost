use crate::analyzer::usages::inverted_edges::UsageReferenceCounts;
use crate::analyzer::usages::workspace_graph::{
    WorkspaceUsageCatalog, WorkspaceUsageGraph, build_workspace_usage_graph,
};
use crate::analyzer::{CodeUnit, IAnalyzer, ProjectFile};
use crate::compact_graph::CompactDirectedGraph;
use crate::hash::{HashMap, HashSet};
use crate::profiling;
use git2::{Oid, Repository};
use moka::sync::Cache;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

const ALPHA: f64 = 0.85;
const CONVERGENCE_EPSILON: f64 = 1.0e-6;
const SCORE_BUCKET_SCALE: f64 = 1.0e9;
const MAX_ITERS: usize = 75;
/// The numerical baseline uses the current fixed-iteration PageRank solver.
/// Allowing a small tolerance keeps the test portable across supported CPUs.
#[cfg(test)]
const PAGE_RANK_SCORE_TOLERANCE: f64 = 1.0e-6;
const IMPORT_DEPTH: usize = 2;
const COMMITS_TO_PROCESS: usize = 1_000;
pub(crate) const DEFAULT_RECENCY_HALF_LIFE: f64 = 250.0;
const NATIVE_RENAME_THRESHOLD: u16 = 50;
const NATIVE_RENAME_TOKEN_OVERLAP_THRESHOLD: f64 = 0.90;
const COMMIT_CHANGE_CACHE_MAX_ENTRIES: u64 = 50_000;
static GIT_COMMITS_SCANNED: AtomicUsize = AtomicUsize::new(0);
static GIT_COMMITS_WITH_CHURN: AtomicUsize = AtomicUsize::new(0);
static GIT_STATUS_ADDED: AtomicUsize = AtomicUsize::new(0);
static GIT_STATUS_DELETED: AtomicUsize = AtomicUsize::new(0);
static GIT_STATUS_RENAMED: AtomicUsize = AtomicUsize::new(0);
static GIT_STATUS_COPIED: AtomicUsize = AtomicUsize::new(0);
static GIT_NATIVE_RENAME_CANDIDATES: AtomicUsize = AtomicUsize::new(0);
static GIT_FIND_SIMILAR_MICROS: AtomicU64 = AtomicU64::new(0);

fn reset_git_counters() {
    GIT_COMMITS_SCANNED.store(0, Ordering::Relaxed);
    GIT_COMMITS_WITH_CHURN.store(0, Ordering::Relaxed);
    GIT_STATUS_ADDED.store(0, Ordering::Relaxed);
    GIT_STATUS_DELETED.store(0, Ordering::Relaxed);
    GIT_STATUS_RENAMED.store(0, Ordering::Relaxed);
    GIT_STATUS_COPIED.store(0, Ordering::Relaxed);
    GIT_NATIVE_RENAME_CANDIDATES.store(0, Ordering::Relaxed);
    GIT_FIND_SIMILAR_MICROS.store(0, Ordering::Relaxed);
}

fn git_counters_note() -> String {
    format!(
        concat!(
            "git-counters commits_scanned={} commits_with_churn={} ",
            "A={} D={} R={} C={} native_rename_candidates={} ",
            "find_similar_ms={:.1}"
        ),
        GIT_COMMITS_SCANNED.load(Ordering::Relaxed),
        GIT_COMMITS_WITH_CHURN.load(Ordering::Relaxed),
        GIT_STATUS_ADDED.load(Ordering::Relaxed),
        GIT_STATUS_DELETED.load(Ordering::Relaxed),
        GIT_STATUS_RENAMED.load(Ordering::Relaxed),
        GIT_STATUS_COPIED.load(Ordering::Relaxed),
        GIT_NATIVE_RENAME_CANDIDATES.load(Ordering::Relaxed),
        GIT_FIND_SIMILAR_MICROS.load(Ordering::Relaxed) as f64 / 1000.0
    )
}

fn note_git_counters() {
    if !profiling::enabled() {
        return;
    }
    profiling::note(git_counters_note());
}

#[derive(Debug, Clone, PartialEq)]
struct FileRelevance {
    file: ProjectFile,
    score: f64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MostRelevantFilesRankingMode {
    #[default]
    HistoryImports,
    UsageGraph,
}

#[derive(Clone, Copy, Debug)]
struct UsageReferenceWeights {
    calls: f64,
    members: f64,
    types: f64,
    other: f64,
}

struct UsageRankingGraph {
    graph: WorkspaceUsageGraph,
    node_indices_by_file: HashMap<ProjectFile, Vec<usize>>,
}

impl UsageReferenceWeights {
    #[cfg(test)]
    const UNIFORM: Self = Self {
        calls: 1.0,
        members: 1.0,
        types: 1.0,
        other: 1.0,
    };

    // Calibrated against deterministic git co-change retrieval on eight
    // repositories spanning Python, TypeScript, PHP, Java, Go, C++, and Rust.
    // The deliberately subtle bias improved the macro average without the Go
    // regression caused by more aggressive call-first profiles.
    const CALIBRATED: Self = Self {
        calls: 1.5,
        members: 1.25,
        types: 1.0,
        other: 0.875,
    };

    fn combine(self, counts: UsageReferenceCounts) -> f64 {
        f64::from(counts.calls) * self.calls
            + f64::from(counts.members) * self.members
            + f64::from(counts.types) * self.types
            + f64::from(counts.other) * self.other
    }
}

pub(crate) fn most_relevant_project_files(
    analyzer: &dyn IAnalyzer,
    seeds: &[(ProjectFile, f64)],
    top_k: usize,
) -> Vec<ProjectFile> {
    most_relevant_project_files_with_half_life(
        analyzer,
        seeds,
        top_k,
        Some(DEFAULT_RECENCY_HALF_LIFE),
    )
}

pub(crate) fn most_relevant_project_files_with_half_life(
    analyzer: &dyn IAnalyzer,
    seeds: &[(ProjectFile, f64)],
    top_k: usize,
    half_life: Option<f64>,
) -> Vec<ProjectFile> {
    let _scope = profiling::scope("relevance::most_relevant_project_files");
    if top_k == 0 {
        return Vec::new();
    }

    let seed_weights = seed_weight_map(seeds);
    if seed_weights.is_empty() {
        return Vec::new();
    }

    let excluded: HashSet<_> = seed_weights.keys().cloned().collect();
    let mut results = Vec::new();
    let mut seen = HashSet::default();

    {
        let _scope = profiling::scope("relevance::git");
        for candidate in
            related_files_by_git(analyzer, &seed_weights, top_k, half_life).unwrap_or_default()
        {
            if append_candidate(&mut results, &mut seen, &excluded, candidate.file, top_k) {
                return results;
            }
        }
    }

    {
        let _scope = profiling::scope("relevance::imports");
        for candidate in related_files_by_imports(analyzer, &seed_weights, top_k, false) {
            if append_candidate(&mut results, &mut seen, &excluded, candidate.file, top_k) {
                return results;
            }
        }
    }

    results
}

pub(crate) fn most_relevant_project_files_with_ranking_mode(
    analyzer: &dyn IAnalyzer,
    seeds: &[(ProjectFile, f64)],
    top_k: usize,
    half_life: Option<f64>,
    ranking_mode: MostRelevantFilesRankingMode,
) -> Vec<ProjectFile> {
    let _scope = profiling::scope("relevance::most_relevant_project_files_with_ranking_mode");
    if ranking_mode == MostRelevantFilesRankingMode::HistoryImports {
        return most_relevant_project_files_with_half_life(analyzer, seeds, top_k, half_life);
    }
    if top_k == 0 {
        return Vec::new();
    }

    let seed_weights = seed_weight_map(seeds);
    if seed_weights.is_empty() {
        return Vec::new();
    }
    let excluded: HashSet<_> = seed_weights.keys().cloned().collect();
    let mut results = Vec::new();
    let mut seen = HashSet::default();

    for candidate in related_files_by_usage(analyzer, &seed_weights, top_k) {
        if append_candidate(&mut results, &mut seen, &excluded, candidate.file, top_k) {
            return results;
        }
    }

    for candidate in most_relevant_project_files_with_half_life(analyzer, seeds, top_k, half_life) {
        if append_candidate(&mut results, &mut seen, &excluded, candidate, top_k) {
            break;
        }
    }
    results
}

fn related_files_by_usage(
    analyzer: &dyn IAnalyzer,
    seed_weights: &HashMap<ProjectFile, f64>,
    k: usize,
) -> Vec<FileRelevance> {
    let _scope = profiling::scope("relevance::related_files_by_usage");
    if k == 0 {
        return Vec::new();
    }

    let ranking_graph = build_usage_ranking_graph(analyzer);
    related_files_by_usage_graph(
        &ranking_graph,
        seed_weights,
        k,
        UsageReferenceWeights::CALIBRATED,
    )
}

fn build_usage_ranking_graph(analyzer: &dyn IAnalyzer) -> UsageRankingGraph {
    let catalog = {
        let _scope = profiling::scope("relevance::usage_graph_catalog");
        WorkspaceUsageCatalog::build(analyzer)
    };
    let mut node_indices_by_file: HashMap<ProjectFile, Vec<usize>> = HashMap::default();
    for (index, node) in catalog.nodes.iter().enumerate() {
        for file in &node.declaration_files {
            node_indices_by_file
                .entry(file.clone())
                .or_default()
                .push(index);
        }
    }

    let graph = {
        let _scope = profiling::scope("relevance::usage_graph_construction");
        build_workspace_usage_graph(analyzer, catalog)
    };
    UsageRankingGraph {
        graph,
        node_indices_by_file,
    }
}

fn related_files_by_usage_graph(
    ranking_graph: &UsageRankingGraph,
    seed_weights: &HashMap<ProjectFile, f64>,
    k: usize,
    weights: UsageReferenceWeights,
) -> Vec<FileRelevance> {
    if k == 0 {
        return Vec::new();
    }
    let graph = &ranking_graph.graph;
    let mut teleport = vec![0.0; graph.nodes.len()];
    for (file, weight) in seed_weights.iter().filter(|(_, weight)| **weight > 0.0) {
        let Some(indices) = ranking_graph.node_indices_by_file.get(file) else {
            continue;
        };
        if indices.is_empty() {
            continue;
        }
        let per_node = *weight / indices.len() as f64;
        for index in indices {
            teleport[*index] += per_node;
        }
    }
    if teleport.iter().all(|weight| *weight <= 0.0) {
        return Vec::new();
    }

    if graph.edges.is_empty() {
        return Vec::new();
    }
    if profiling::enabled() {
        let unproven_inbound: usize = graph.nodes.iter().map(|node| node.unproven_inbound).sum();
        profiling::note(format!(
            "usage-graph nodes={} edges={} unproven_inbound={unproven_inbound}",
            graph.nodes.len(),
            graph.edges.len()
        ));
    }
    let mut outgoing = vec![Vec::new(); graph.nodes.len()];
    for edge in &graph.edges {
        outgoing[edge.from].push((edge.to, weights.combine(edge.counts)));
    }
    for neighbors in &mut outgoing {
        neighbors.sort_by_key(|(target, _)| *target);
    }

    let scores = {
        let _scope = profiling::scope("relevance::usage_graph_page_rank");
        weighted_page_rank(&outgoing, &teleport)
    };
    let excluded: HashSet<_> = seed_weights.keys().collect();
    let mut file_scores: HashMap<ProjectFile, f64> = HashMap::default();
    {
        let _scope = profiling::scope("relevance::usage_graph_file_aggregation");
        for (node, score) in graph.nodes.iter().zip(scores) {
            if node.truncated_inbound.is_some() || excluded.contains(node.primary.source()) {
                continue;
            }
            *file_scores
                .entry(node.primary.source().clone())
                .or_insert(0.0) += score;
        }
    }

    let mut ranked: Vec<_> = file_scores
        .into_iter()
        .filter(|(_, score)| *score > 0.0)
        .map(|(file, score)| FileRelevance { file, score })
        .collect();
    ranked.sort_by(compare_file_relevance);
    ranked.truncate(k);
    ranked
}

pub(crate) fn most_important_project_files(
    analyzer: &dyn IAnalyzer,
    candidates: &[ProjectFile],
    top_k: usize,
) -> Vec<ProjectFile> {
    let _scope = profiling::scope("relevance::most_important_project_files");
    if top_k == 0 || candidates.is_empty() {
        return Vec::new();
    }

    let Some(repo) = GitProjectContext::discover(analyzer.project().root()) else {
        return Vec::new();
    };
    let candidate_set: HashSet<_> = candidates.iter().cloned().collect();
    if !candidate_set
        .iter()
        .any(|file| repo.is_tracked_in_head(file))
    {
        return Vec::new();
    }

    let Ok(changes) = repo.recent_commit_changes(COMMITS_TO_PROCESS) else {
        return Vec::new();
    };
    if changes.is_empty() {
        return Vec::new();
    }

    let mut scores: HashMap<ProjectFile, f64> = HashMap::default();
    let mut canonicalizer = RenameCanonicalizer::default();
    for (index, change) in changes.into_iter().enumerate() {
        canonicalizer.record_renames(&change.renames);
        let age_weight = commit_age_weight(index, Some(DEFAULT_RECENCY_HALF_LIFE));
        for path in change.paths {
            let canonical = canonicalizer.canonicalize(&path);
            let Some(file) = repo.repo_path_to_project_file(&canonical) else {
                continue;
            };
            if candidate_set.contains(&file) {
                *scores.entry(file).or_insert(0.0) += age_weight;
            }
        }
    }

    let mut ranked = scores
        .into_iter()
        .map(|(file, score)| FileRelevance { file, score })
        .collect::<Vec<_>>();
    ranked.sort_by(compare_file_relevance);
    ranked.truncate(top_k);
    ranked.into_iter().map(|item| item.file).collect()
}

fn commit_age_weight(index: usize, half_life: Option<f64>) -> f64 {
    match half_life {
        None => 1.0,
        Some(half_life) => 2f64.powf(-((index as f64) / half_life)),
    }
}

fn append_candidate(
    results: &mut Vec<ProjectFile>,
    seen: &mut HashSet<ProjectFile>,
    excluded: &HashSet<ProjectFile>,
    candidate: ProjectFile,
    top_k: usize,
) -> bool {
    if excluded.contains(&candidate) || !seen.insert(candidate.clone()) {
        return false;
    }

    results.push(candidate);
    results.len() >= top_k
}

fn seed_weight_map(seeds: &[(ProjectFile, f64)]) -> HashMap<ProjectFile, f64> {
    let mut weights = HashMap::default();
    for (seed, weight) in seeds.iter().filter(|(seed, _)| seed.exists()) {
        *weights.entry(seed.clone()).or_insert(0.0) += *weight;
    }
    weights
}

#[derive(Debug, Default)]
struct ImportGraphBuilder {
    nodes: Vec<ProjectFile>,
    index_by_file: HashMap<ProjectFile, u32>,
    edges: HashSet<(u32, u32)>,
}

impl ImportGraphBuilder {
    fn insert_node(&mut self, file: ProjectFile) -> bool {
        if self.index_by_file.contains_key(&file) {
            return false;
        }
        let id = u32::try_from(self.nodes.len()).expect("import graph nodes must fit in a u32");
        self.nodes.push(file.clone());
        self.index_by_file.insert(file, id);
        true
    }

    fn insert_edge(&mut self, source: &ProjectFile, target: &ProjectFile) {
        let source = self.index_by_file[source];
        let target = self.index_by_file[target];
        self.edges.insert((source, target));
    }

    fn finish(mut self) -> CompactDirectedGraph<ProjectFile> {
        let mut ordered = self.nodes.into_iter().enumerate().collect::<Vec<_>>();
        ordered.sort_by(|(_, left), (_, right)| left.cmp(right));
        let mut remap = vec![0_u32; ordered.len()];
        let mut nodes = Vec::with_capacity(ordered.len());
        for (new, (old, file)) in ordered.into_iter().enumerate() {
            remap[old] = new as u32;
            nodes.push(file);
        }
        let edges = self
            .edges
            .drain()
            .map(|(source, target)| (remap[source as usize], remap[target as usize]))
            .collect();
        CompactDirectedGraph::new(nodes, edges)
    }
}

fn related_files_by_imports(
    analyzer: &dyn IAnalyzer,
    seed_weights: &HashMap<ProjectFile, f64>,
    k: usize,
    reversed: bool,
) -> Vec<FileRelevance> {
    let _scope = profiling::scope("relevance::related_files_by_imports");
    if k == 0 {
        return Vec::new();
    }

    let positive_seeds: HashMap<_, _> = seed_weights
        .iter()
        .filter(|(_, weight)| **weight > 0.0)
        .map(|(file, weight)| (file.clone(), *weight))
        .collect();
    if positive_seeds.is_empty() {
        return Vec::new();
    }

    let graph = {
        let _scope = profiling::scope("relevance::build_import_graph");
        build_import_graph(analyzer, &positive_seeds)
    };
    if profiling::enabled() {
        profiling::note(format!(
            "compact-import-graph nodes={} edges={}",
            graph.nodes().len(),
            graph.edge_count()
        ));
    }
    if graph.nodes().is_empty() {
        return Vec::new();
    }

    let total_seed_weight: f64 = positive_seeds.values().sum();
    if total_seed_weight <= 0.0 {
        return Vec::new();
    }

    let mut teleport = vec![0.0; graph.nodes().len()];
    for (file, weight) in &positive_seeds {
        if let Some(index) = graph.node_id(file) {
            teleport[index as usize] = *weight / total_seed_weight;
        }
    }

    let rank = weighted_page_rank(
        &CompactImportAdjacency {
            graph: &graph,
            reversed,
        },
        &teleport,
    );

    let seed_files: HashSet<_> = positive_seeds.keys().cloned().collect();
    let mut ranked = graph
        .nodes()
        .iter()
        .cloned()
        .enumerate()
        .filter_map(|(index, file)| {
            if seed_files.contains(&file) || rank[index] <= 0.0 {
                return None;
            }
            Some(FileRelevance {
                file,
                score: rank[index],
            })
        })
        .collect::<Vec<_>>();
    ranked.sort_by(compare_file_relevance);
    ranked.truncate(k);
    ranked
}

struct CompactImportAdjacency<'a> {
    graph: &'a CompactDirectedGraph<ProjectFile>,
    reversed: bool,
}

impl WeightedAdjacency for CompactImportAdjacency<'_> {
    fn node_count(&self) -> usize {
        self.graph.nodes().len()
    }

    fn for_each_edge<F>(&self, source: usize, mut visit: F)
    where
        F: FnMut(usize, f64),
    {
        let neighbors = if self.reversed {
            self.graph.incoming(source as u32)
        } else {
            self.graph.outgoing(source as u32)
        };
        for target in neighbors {
            visit(*target as usize, 1.0);
        }
    }
}

trait WeightedAdjacency {
    fn node_count(&self) -> usize;

    fn for_each_edge<F>(&self, source: usize, visit: F)
    where
        F: FnMut(usize, f64);
}

impl WeightedAdjacency for [Vec<(usize, f64)>] {
    fn node_count(&self) -> usize {
        self.len()
    }

    fn for_each_edge<F>(&self, source: usize, mut visit: F)
    where
        F: FnMut(usize, f64),
    {
        for &(target, weight) in &self[source] {
            visit(target, weight);
        }
    }
}

impl WeightedAdjacency for Vec<Vec<(usize, f64)>> {
    fn node_count(&self) -> usize {
        self.as_slice().node_count()
    }

    fn for_each_edge<F>(&self, source: usize, visit: F)
    where
        F: FnMut(usize, f64),
    {
        self.as_slice().for_each_edge(source, visit);
    }
}

impl<const N: usize> WeightedAdjacency for [Vec<(usize, f64)>; N] {
    fn node_count(&self) -> usize {
        N
    }

    fn for_each_edge<F>(&self, source: usize, visit: F)
    where
        F: FnMut(usize, f64),
    {
        self.as_slice().for_each_edge(source, visit);
    }
}

/// Run weighted PageRank over a dense, caller-supplied node order.
///
/// Each outgoing entry is `(target_index, positive_weight)`. Transition mass is
/// divided by the source's total outgoing weight. A non-empty `teleport` vector
/// is normalized before use; an empty vector selects uniform teleportation,
/// which is the ordinary global-centrality form of PageRank. Dangling mass is
/// redistributed through the same teleport vector so personalized rank remains
/// anchored to its seeds.
fn weighted_page_rank<G>(outgoing: &G, teleport: &[f64]) -> Vec<f64>
where
    G: WeightedAdjacency + ?Sized,
{
    let node_count = outgoing.node_count();
    if node_count == 0 {
        return Vec::new();
    }
    assert!(
        teleport.is_empty() || teleport.len() == node_count,
        "teleport vector must be empty or match the graph node count"
    );

    let normalized_teleport = if teleport.is_empty() {
        vec![1.0 / node_count as f64; node_count]
    } else {
        let total = teleport
            .iter()
            .copied()
            .filter(|weight| weight.is_finite() && *weight > 0.0)
            .sum::<f64>();
        if total <= 0.0 {
            vec![1.0 / node_count as f64; node_count]
        } else {
            teleport
                .iter()
                .map(|weight| {
                    if weight.is_finite() && *weight > 0.0 {
                        *weight / total
                    } else {
                        0.0
                    }
                })
                .collect()
        }
    };
    // Avoid a separate initialization rule: PageRank starts from the same
    // distribution it teleports to, preserving the previous personalized path.
    let mut rank = normalized_teleport.clone();
    let mut next = vec![0.0; node_count];
    let outgoing_weight = (0..node_count)
        .map(|source| {
            let mut total = 0.0;
            outgoing.for_each_edge(source, |_, weight| {
                if weight.is_finite() && weight > 0.0 {
                    total += weight;
                }
            });
            total
        })
        .collect::<Vec<_>>();

    for _ in 0..MAX_ITERS {
        for (index, teleport_weight) in normalized_teleport.iter().enumerate() {
            next[index] = (1.0 - ALPHA) * teleport_weight;
        }

        let mut dangling_mass = 0.0;
        for source in 0..node_count {
            let total_weight = outgoing_weight[source];
            if total_weight <= 0.0 {
                dangling_mass += rank[source];
                continue;
            }

            let source_mass = ALPHA * rank[source] / total_weight;
            outgoing.for_each_edge(source, |target, weight| {
                if target < node_count && weight.is_finite() && weight > 0.0 {
                    next[target] += source_mass * weight;
                }
            });
        }

        if dangling_mass.abs() > 1.0e-10 {
            let redistributed = ALPHA * dangling_mass;
            for (index, teleport_weight) in normalized_teleport.iter().enumerate() {
                next[index] += redistributed * teleport_weight;
            }
        }

        let diff = next
            .iter()
            .zip(&rank)
            .map(|(left, right)| (left - right).abs())
            .sum::<f64>();
        std::mem::swap(&mut rank, &mut next);
        if diff < CONVERGENCE_EPSILON {
            break;
        }
    }

    rank
}

fn build_import_graph(
    analyzer: &dyn IAnalyzer,
    seed_weights: &HashMap<ProjectFile, f64>,
) -> CompactDirectedGraph<ProjectFile> {
    let _scope = profiling::scope("relevance::build_import_graph");
    let mut graph = ImportGraphBuilder::default();
    let mut import_cache = HashMap::default();
    let mut reverse_cache = HashMap::default();
    let mut frontier: VecDeque<_> = seed_weights.keys().cloned().collect();
    let mut expanded_nodes = 0usize;
    let mut forward_edges = 0usize;
    let mut reverse_edges = 0usize;
    let mut import_lookup_ms = 0.0;
    let mut reverse_lookup_ms = 0.0;
    let mut depth = 0usize;

    for seed in seed_weights.keys() {
        graph.insert_node(seed.clone());
    }

    for _ in 0..IMPORT_DEPTH {
        if frontier.is_empty() {
            break;
        }
        depth += 1;
        let frontier_len = frontier.len();

        let mut next = VecDeque::new();
        while let Some(file) = frontier.pop_front() {
            expanded_nodes += 1;
            if profiling::enabled() {
                profiling::note(format!(
                    "relevance::build_import_graph expand file={}",
                    normalized_rel_path(&file)
                ));
            }

            if profiling::enabled() {
                profiling::note(format!(
                    "relevance::build_import_graph import_start file={}",
                    normalized_rel_path(&file)
                ));
            }
            let import_started = Instant::now();
            let imported = imported_files_for(analyzer, &file, &mut import_cache);
            let import_elapsed_ms = import_started.elapsed().as_secs_f64() * 1000.0;
            import_lookup_ms += import_elapsed_ms;
            if profiling::enabled() && (import_elapsed_ms >= 100.0 || imported.len() >= 100) {
                profiling::note(format!(
                    "relevance::build_import_graph import file={} imported={} elapsed_ms={:.1}",
                    normalized_rel_path(&file),
                    imported.len(),
                    import_elapsed_ms
                ));
            }
            for target in imported {
                if graph.insert_node(target.clone()) {
                    next.push_back(target.clone());
                }
                graph.insert_edge(&file, &target);
                forward_edges += 1;
            }

            if profiling::enabled() {
                profiling::note(format!(
                    "relevance::build_import_graph reverse_start file={}",
                    normalized_rel_path(&file)
                ));
            }
            let reverse_started = Instant::now();
            let referencing = referencing_files_for(analyzer, &file, &mut reverse_cache);
            let reverse_elapsed_ms = reverse_started.elapsed().as_secs_f64() * 1000.0;
            reverse_lookup_ms += reverse_elapsed_ms;
            if profiling::enabled() && (reverse_elapsed_ms >= 100.0 || referencing.len() >= 100) {
                profiling::note(format!(
                    "relevance::build_import_graph reverse file={} referencing={} elapsed_ms={:.1}",
                    normalized_rel_path(&file),
                    referencing.len(),
                    reverse_elapsed_ms
                ));
            }
            for source in referencing {
                if graph.insert_node(source.clone()) {
                    next.push_back(source.clone());
                }
                graph.insert_edge(&source, &file);
                reverse_edges += 1;
            }
        }
        if profiling::enabled() {
            profiling::note(format!(
                "relevance::build_import_graph depth={} frontier={} expanded_nodes={} forward_edges={} reverse_edges={} import_lookup_ms={:.1} reverse_lookup_ms={:.1}",
                depth,
                frontier_len,
                expanded_nodes,
                forward_edges,
                reverse_edges,
                import_lookup_ms,
                reverse_lookup_ms
            ));
        }
        frontier = next;
    }

    graph.finish()
}

fn imported_files_for(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    cache: &mut HashMap<ProjectFile, BTreeSet<ProjectFile>>,
) -> BTreeSet<ProjectFile> {
    if let Some(cached) = cache.get(file) {
        return cached.clone();
    }

    let mut resolved = BTreeSet::new();
    if let Some(provider) = analyzer.import_analysis_provider() {
        let imported_units = provider.imported_code_units_of(file);
        if !imported_units.is_empty() {
            resolved.extend(
                imported_units
                    .into_iter()
                    .map(|code_unit| code_unit.source().clone()),
            );
        }
    }

    if resolved.is_empty() {
        for import in analyzer.import_statements(file) {
            let before = resolved.len();
            let definitions: Vec<_> = analyzer.definitions(&import).collect();
            add_definitions_to_files(definitions.iter(), &mut resolved);
            if resolved.len() == before {
                let matches = analyzer.search_definitions(&import, true);
                add_definitions_to_files(matches.iter(), &mut resolved);
            }
        }
    }

    cache.insert(file.clone(), resolved.clone());
    resolved
}

fn add_definitions_to_files<'a>(
    definitions: impl IntoIterator<Item = &'a CodeUnit>,
    out: &mut BTreeSet<ProjectFile>,
) {
    out.extend(
        definitions
            .into_iter()
            .map(|code_unit| code_unit.source().clone()),
    );
}

fn referencing_files_for(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    cache: &mut HashMap<ProjectFile, BTreeSet<ProjectFile>>,
) -> BTreeSet<ProjectFile> {
    if let Some(cached) = cache.get(file) {
        return cached.clone();
    }

    let resolved: BTreeSet<ProjectFile> = analyzer
        .import_analysis_provider()
        .map(|provider| provider.referencing_files_of(file).into_iter().collect())
        .unwrap_or_default();
    cache.insert(file.clone(), resolved.clone());
    resolved
}

/// Shared Git-relevance contract for bifrost and Brokk.
///
/// Keep this behavior in sync with Brokk's `GitDistance.getRelatedFiles`. The parity harness depends on
/// these choices matching, not merely being "close enough":
/// - walk the recent commit window in topology-preserving time order so canonicalization never sees an older
///   pre-rename commit before the later rename edge that should rewrite it
/// - use native Git rename detection only, with a 50% similarity threshold and no extra add/delete continuation
///   inference layered on top. If Git does not label an edge as `Renamed`, this scorer treats the old/new paths as
///   unrelated for lineage purposes
/// - canonicalization follows only those native rename labels that actually replace the old path with the new path
///   across the commit boundary; if both paths survive across that boundary, treat the change as ordinary path churn
///   instead of lineage
/// - accepted native rename labels also pass one cheap synchronizer shared with Brokk: compact filename stems must
///   match and the directly compared old/new blobs must retain near-exact token overlap. This keeps libgit2/JGit
///   aligned on borderline rename scores without reintroducing add/delete continuation scoring
/// - copy/split history is intentionally not recovered by custom blob-similarity heuristics
/// - when `half_life` is set, apply the same exponential `2^(-index/half_life)` age weight to
///   both seed mass and joint mass so the seed->target conditional remains a proper conditional;
///   keep document frequency / IDF unweighted because it measures corpus-wide commonness rather
///   than recency-biased affinity
/// - treat near-equal scores as ties using a relative epsilon of `1e-9 * max(1, |score|)` and break them by
///   normalized path so ordering is stable across platforms and implementations
///
/// If any of those rules change here, change Brokk in the same way and rerun the external parity fixtures.
fn related_files_by_git(
    analyzer: &dyn IAnalyzer,
    seed_weights: &HashMap<ProjectFile, f64>,
    k: usize,
    half_life: Option<f64>,
) -> Result<Vec<FileRelevance>, git2::Error> {
    let _scope = profiling::scope("relevance::related_files_by_git");
    reset_git_counters();
    if k == 0 || seed_weights.is_empty() {
        return Ok(Vec::new());
    }

    let Some(repo) = ({
        let _scope = profiling::scope("relevance::git.discover");
        GitProjectContext::discover(analyzer.project().root())
    }) else {
        return Ok(Vec::new());
    };
    if !seed_weights
        .keys()
        .any(|seed| repo.is_tracked_in_head(seed))
    {
        return Ok(Vec::new());
    }

    let changes = {
        let _scope = profiling::scope("relevance::git.recent_commit_changes");
        repo.recent_commit_changes(COMMITS_TO_PROCESS)
            .map_err(|err| git2::Error::from_str(&err))?
    };
    if changes.is_empty() {
        return Ok(Vec::new());
    }

    let mut file_doc_freq: HashMap<ProjectFile, usize> = HashMap::default();
    let mut joint_mass: HashMap<(ProjectFile, ProjectFile), f64> = HashMap::default();
    let mut seed_mass: HashMap<ProjectFile, f64> = HashMap::default();
    let mut canonicalizer = RenameCanonicalizer::default();
    let find_commit_ms = 0.0;
    let change_ms = 0.0;
    let mut canonicalize_ms = 0.0;
    let mut processed_commits = 0usize;

    let baseline_commit_count = changes.len() as f64;
    {
        let _scope = profiling::scope("relevance::git.score_commits");
        for (index, change) in changes.into_iter().enumerate() {
            let started = Instant::now();
            canonicalizer.record_renames(&change.renames);
            let changed_files: BTreeSet<_> = change
                .paths
                .iter()
                .map(|path| canonicalizer.canonicalize(path))
                .filter_map(|path| repo.repo_path_to_project_file(&path))
                .collect();
            canonicalize_ms += started.elapsed().as_secs_f64() * 1000.0;
            processed_commits += 1;
            if profiling::enabled() && processed_commits.is_multiple_of(5) {
                profiling::note(format!(
                    "relevance::git.score_commits progress processed_commits={} find_commit_ms={:.1} change_ms={:.1} canonicalize_ms={:.1} {}",
                    processed_commits,
                    find_commit_ms,
                    change_ms,
                    canonicalize_ms,
                    git_counters_note()
                ));
            }
            if changed_files.is_empty() {
                continue;
            }

            for file in &changed_files {
                *file_doc_freq.entry(file.clone()).or_insert(0) += 1;
            }

            let seeds_in_commit: Vec<_> = changed_files
                .iter()
                .filter(|file| seed_weights.contains_key(*file))
                .cloned()
                .collect();
            if seeds_in_commit.is_empty() {
                continue;
            }

            let commit_weight = commit_age_weight(index, half_life);
            for seed in &seeds_in_commit {
                *seed_mass.entry(seed.clone()).or_insert(0.0) += commit_weight;
            }

            let commit_pair_mass = commit_weight / changed_files.len() as f64;
            for seed in &seeds_in_commit {
                for target in &changed_files {
                    if seed_weights.contains_key(target) {
                        continue;
                    }
                    *joint_mass
                        .entry((seed.clone(), target.clone()))
                        .or_insert(0.0) += commit_pair_mass;
                }
            }
        }
    }
    if profiling::enabled() {
        profiling::note(format!(
            "relevance::git.score_commits processed_commits={processed_commits} find_commit_ms={find_commit_ms:.1} change_ms={change_ms:.1} canonicalize_ms={canonicalize_ms:.1}"
        ));
    }
    note_git_counters();

    if joint_mass.is_empty() {
        return Ok(Vec::new());
    }

    let mut scores = HashMap::default();
    for ((seed, target), joint) in joint_mass {
        let seed_denom = seed_mass.get(&seed).copied().unwrap_or(0.0);
        if seed_denom <= 0.0 {
            continue;
        }

        let conditional = joint / seed_denom;
        let target_doc_freq = file_doc_freq.get(&target).copied().unwrap_or(0).max(1) as f64;
        // Keep document frequency unweighted: IDF measures how globally common a file is
        // across the commit corpus, not how recent its affinity is to the seed set.
        let idf = (1.0 + baseline_commit_count / target_doc_freq).ln();
        let seed_weight = seed_weights.get(&seed).copied().unwrap_or(0.0);
        let contribution = seed_weight * conditional * idf;
        if contribution.is_finite() && contribution != 0.0 {
            *scores.entry(target).or_insert(0.0) += contribution;
        }
    }

    let mut ranked = scores
        .into_iter()
        .map(|(file, score)| FileRelevance { file, score })
        .collect::<Vec<_>>();
    ranked.sort_by(compare_file_relevance);
    ranked.truncate(k);
    Ok(ranked)
}

struct GitProjectContext {
    repo: Repository,
    repo_root: PathBuf,
    project_root: PathBuf,
    repo_prefix: PathBuf,
}

struct RepoCommitChangeCache {
    commits: Cache<Oid, Arc<CommitChange>>,
    fill_lock: Mutex<()>,
    fill_commits_scanned: AtomicUsize,
}

impl RepoCommitChangeCache {
    fn new(max_entries: u64) -> Self {
        Self {
            commits: Cache::builder().max_capacity(max_entries.max(1)).build(),
            fill_lock: Mutex::new(()),
            fill_commits_scanned: AtomicUsize::new(0),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MissingCommitRange {
    start: usize,
    end: usize,
}

fn repo_commit_change_caches() -> &'static Mutex<HashMap<PathBuf, Arc<RepoCommitChangeCache>>> {
    static CACHES: OnceLock<Mutex<HashMap<PathBuf, Arc<RepoCommitChangeCache>>>> = OnceLock::new();
    CACHES.get_or_init(|| Mutex::new(HashMap::default()))
}

fn repo_commit_change_cache(repo_root: &Path) -> Arc<RepoCommitChangeCache> {
    let mut caches = repo_commit_change_caches()
        .lock()
        .expect("repo cache mutex");
    caches
        .entry(repo_root.to_path_buf())
        .or_insert_with(|| Arc::new(RepoCommitChangeCache::new(COMMIT_CHANGE_CACHE_MAX_ENTRIES)))
        .clone()
}

#[cfg(test)]
fn clear_repo_commit_change_cache_for_root(repo_root: &Path) {
    let mut caches = repo_commit_change_caches()
        .lock()
        .expect("repo cache mutex");
    caches.remove(repo_root);
}

impl GitProjectContext {
    fn discover(project_root: &Path) -> Option<Self> {
        // Keep the caller's project_root as-given so ProjectFiles we build from
        // git output compare equal to ProjectFiles supplied by the analyzer.
        // Canonicalize only for repo discovery / prefix computation, since on
        // macOS temp dirs come in via /var -> /private/var symlinks.
        let project_root = project_root.to_path_buf();
        let canonical_project = project_root.canonicalize().ok()?;
        let repo = Repository::discover(&canonical_project).ok()?;
        let repo_root = repo.workdir()?.canonicalize().ok()?;
        if !canonical_project.starts_with(&repo_root) {
            return None;
        }

        let repo_prefix = canonical_project
            .strip_prefix(&repo_root)
            .ok()?
            .to_path_buf();
        Some(Self {
            repo,
            repo_root,
            project_root,
            repo_prefix,
        })
    }

    fn is_tracked_in_head(&self, file: &ProjectFile) -> bool {
        let repo_rel = self.project_rel_to_repo_rel(file.rel_path());
        self.repo
            .head()
            .ok()
            .and_then(|head| head.peel_to_tree().ok())
            .and_then(|tree| tree.get_path(&repo_rel).ok())
            .is_some()
    }

    fn recent_commit_changes(&self, limit: usize) -> Result<Vec<CommitChange>, String> {
        let cache = repo_commit_change_cache(&self.repo_root);
        self.recent_commit_changes_with_cache(limit, &cache)
    }

    fn recent_commit_changes_with_cache(
        &self,
        limit: usize,
        cache: &RepoCommitChangeCache,
    ) -> Result<Vec<CommitChange>, String> {
        let ordered_oids = self.recent_commit_oids(limit)?;
        if ordered_oids.is_empty() {
            return Ok(Vec::new());
        }

        self.fill_missing_commit_ranges(&ordered_oids, cache)?;
        cache.commits.run_pending_tasks();
        self.collect_cached_commit_changes(&ordered_oids, cache)
    }

    #[cfg(test)]
    fn recent_commit_changes_uncached(&self, limit: usize) -> Result<Vec<CommitChange>, String> {
        self.run_git_log_command(limit, None)
    }

    fn recent_commit_oids(&self, limit: usize) -> Result<Vec<Oid>, String> {
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.repo_root)
            .arg("rev-list")
            .arg("--topo-order")
            .arg("--first-parent")
            .arg("-n")
            .arg(limit.to_string())
            .arg("HEAD")
            .output()
            .map_err(|err| format!("failed to run git rev-list: {err}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "git rev-list exited with {}: {stderr}",
                output.status
            ));
        }

        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                Oid::from_str(line).map_err(|err| format!("invalid rev-list oid `{line}`: {err}"))
            })
            .collect()
    }

    fn fill_missing_commit_ranges(
        &self,
        ordered_oids: &[Oid],
        cache: &RepoCommitChangeCache,
    ) -> Result<(), String> {
        let mut missing_ranges = missing_commit_ranges(ordered_oids, &cache.commits);
        if missing_ranges.is_empty() {
            return Ok(());
        }

        let _guard = cache.fill_lock.lock().expect("repo fill mutex");
        missing_ranges = missing_commit_ranges(ordered_oids, &cache.commits);
        for range in missing_ranges {
            self.populate_commit_range(ordered_oids, range, cache)?;
        }

        Ok(())
    }

    fn populate_commit_range(
        &self,
        ordered_oids: &[Oid],
        range: MissingCommitRange,
        cache: &RepoCommitChangeCache,
    ) -> Result<(), String> {
        let newest = ordered_oids[range.start];
        let oldest = ordered_oids[range.end];
        let range_len = range.end - range.start + 1;
        let changes = self.run_git_log_command(range_len, Some((newest, oldest)))?;
        cache
            .fill_commits_scanned
            .fetch_add(changes.len(), Ordering::Relaxed);

        for change in changes {
            cache.commits.insert(change.id, Arc::new(change));
        }

        Ok(())
    }

    fn collect_cached_commit_changes(
        &self,
        ordered_oids: &[Oid],
        cache: &RepoCommitChangeCache,
    ) -> Result<Vec<CommitChange>, String> {
        let mut changes = Vec::with_capacity(ordered_oids.len());
        for oid in ordered_oids {
            let Some(change) = cache.commits.get(oid) else {
                return Err(format!("missing cached commit change for {}", oid));
            };
            changes.push((*change).clone());
        }
        Ok(changes)
    }

    fn run_git_log_command(
        &self,
        limit: usize,
        range: Option<(Oid, Oid)>,
    ) -> Result<Vec<CommitChange>, String> {
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.repo_root)
            .arg("log")
            .arg("--topo-order")
            .arg("--first-parent")
            .arg("--no-color")
            // Merge diffs against the first parent only. `-m` with
            // `--first-parent` is the documented pre-2.31 spelling of
            // `--diff-merges=first-parent`; using it keeps the command
            // working on older git (the flag alone aborts with
            // "unrecognized argument" there, silently emptying results).
            .arg("-m")
            .arg(format!("-M{NATIVE_RENAME_THRESHOLD}"))
            .arg("--name-status")
            .arg("-z")
            .arg("--format=format:%x1e%H")
            .arg("-n")
            .arg(limit.to_string())
            .args(match range {
                Some((newest, oldest)) => {
                    let parent = self.first_parent_oid(oldest);
                    let mut args = Vec::with_capacity(2);
                    if parent.is_none() {
                        args.push("--root".to_string());
                    }
                    args.push(match parent {
                        Some(parent) => format!("{parent}..{newest}"),
                        None => newest.to_string(),
                    });
                    args
                }
                None => vec!["--root".to_string()],
            })
            .output()
            .map_err(|err| format!("failed to run git log: {err}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("git log exited with {}: {stderr}", output.status));
        }

        Ok(self.parse_git_log_name_status(&output.stdout))
    }

    fn first_parent_oid(&self, oid: Oid) -> Option<Oid> {
        self.repo.find_commit(oid).ok()?.parent_ids().next()
    }

    fn parse_git_log_name_status(&self, output: &[u8]) -> Vec<CommitChange> {
        output
            .split(|byte| *byte == 0x1e)
            .filter_map(|record| self.parse_git_log_record(record))
            .collect()
    }

    fn parse_git_log_record(&self, mut record: &[u8]) -> Option<CommitChange> {
        while matches!(record.first(), Some(b'\0' | b'\n' | b'\r')) {
            record = &record[1..];
        }
        if record.len() < 40 {
            return None;
        }

        let oid_text = std::str::from_utf8(&record[..40]).ok()?;
        let oid = Oid::from_str(oid_text).ok()?;
        GIT_COMMITS_SCANNED.fetch_add(1, Ordering::Relaxed);

        let mut rest = &record[40..];
        while matches!(rest.first(), Some(b'\0' | b'\n' | b'\r')) {
            rest = &rest[1..];
        }

        let mut paths = Vec::new();
        let mut renames = Vec::new();
        let mut commit_has_churn = false;
        let mut tokens = rest
            .split(|byte| *byte == b'\0')
            .filter(|token| !token.is_empty());

        while let Some(status_token) = tokens.next() {
            let status_token = strip_git_log_token_prefix(status_token);
            if status_token.is_empty() {
                continue;
            }
            match status_token[0] {
                b'A' => {
                    if let Some(path) = tokens.next().map(pathbuf_from_git_log_token) {
                        commit_has_churn = true;
                        GIT_STATUS_ADDED.fetch_add(1, Ordering::Relaxed);
                        paths.push(path);
                    }
                }
                b'C' => {
                    let _old_path = tokens.next();
                    if let Some(path) = tokens.next().map(pathbuf_from_git_log_token) {
                        commit_has_churn = true;
                        GIT_STATUS_COPIED.fetch_add(1, Ordering::Relaxed);
                        paths.push(path);
                    }
                }
                b'D' => {
                    if let Some(path) = tokens.next().map(pathbuf_from_git_log_token) {
                        commit_has_churn = true;
                        GIT_STATUS_DELETED.fetch_add(1, Ordering::Relaxed);
                        paths.push(path);
                    }
                }
                b'M' | b'T' => {
                    if let Some(path) = tokens.next().map(pathbuf_from_git_log_token) {
                        paths.push(path);
                    }
                }
                b'R' => {
                    let Some(old_path) = tokens.next().map(pathbuf_from_git_log_token) else {
                        continue;
                    };
                    let Some(new_path) = tokens.next().map(pathbuf_from_git_log_token) else {
                        continue;
                    };
                    commit_has_churn = true;
                    GIT_STATUS_RENAMED.fetch_add(1, Ordering::Relaxed);
                    GIT_NATIVE_RENAME_CANDIDATES.fetch_add(1, Ordering::Relaxed);
                    if self.native_rename_paths_are_safe(oid, &old_path, &new_path) {
                        paths.push(new_path.clone());
                        renames.push((old_path, new_path));
                    } else {
                        paths.push(old_path);
                        paths.push(new_path);
                    }
                }
                _ => {
                    let _ = tokens.next();
                }
            }
        }

        if commit_has_churn {
            GIT_COMMITS_WITH_CHURN.fetch_add(1, Ordering::Relaxed);
        }

        Some(CommitChange {
            id: oid,
            paths,
            renames,
        })
    }

    fn repo_path_to_project_file(&self, repo_rel: &Path) -> Option<ProjectFile> {
        let project_rel = if self.repo_prefix.as_os_str().is_empty() {
            repo_rel.to_path_buf()
        } else {
            repo_rel.strip_prefix(&self.repo_prefix).ok()?.to_path_buf()
        };
        let file = ProjectFile::new(self.project_root.clone(), project_rel);
        file.exists().then_some(file)
    }

    fn project_rel_to_repo_rel(&self, project_rel: &Path) -> PathBuf {
        if self.repo_prefix.as_os_str().is_empty() {
            project_rel.to_path_buf()
        } else {
            self.repo_prefix.join(project_rel)
        }
    }

    fn native_rename_paths_are_safe(&self, oid: Oid, old_path: &Path, new_path: &Path) -> bool {
        let Some((parent_tree, current_tree)) = self.commit_parent_and_current_trees(oid) else {
            return false;
        };
        native_rename_replaces_path(Some(&parent_tree), &current_tree, old_path, new_path)
            && native_rename_path_keys_match(old_path, new_path)
            && tree_path_token_overlap_ratio(
                &self.repo,
                &parent_tree,
                &current_tree,
                old_path,
                new_path,
            )
            .is_some_and(|ratio| ratio >= NATIVE_RENAME_TOKEN_OVERLAP_THRESHOLD)
    }

    fn commit_parent_and_current_trees(
        &self,
        oid: Oid,
    ) -> Option<(git2::Tree<'_>, git2::Tree<'_>)> {
        let commit = self.repo.find_commit(oid).ok()?;
        if commit.parent_count() == 0 {
            return None;
        }
        let parent_tree = commit.parent(0).ok()?.tree().ok()?;
        let current_tree = commit.tree().ok()?;
        Some((parent_tree, current_tree))
    }
}

fn missing_commit_ranges(
    ordered_oids: &[Oid],
    cache: &Cache<Oid, Arc<CommitChange>>,
) -> Vec<MissingCommitRange> {
    let mut ranges = Vec::new();
    let mut current_start = None;

    for (index, oid) in ordered_oids.iter().enumerate() {
        if cache.get(oid).is_some() {
            if let Some(start) = current_start.take() {
                ranges.push(MissingCommitRange {
                    start,
                    end: index - 1,
                });
            }
            continue;
        }

        current_start.get_or_insert(index);
    }

    if let Some(start) = current_start {
        ranges.push(MissingCommitRange {
            start,
            end: ordered_oids.len() - 1,
        });
    }

    ranges
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CommitChange {
    #[allow(dead_code)]
    id: Oid,
    paths: Vec<PathBuf>,
    renames: Vec<(PathBuf, PathBuf)>,
}

fn native_rename_replaces_path(
    parent_tree: Option<&git2::Tree<'_>>,
    current_tree: &git2::Tree<'_>,
    old_path: &Path,
    new_path: &Path,
) -> bool {
    let old_survives = current_tree.get_path(old_path).is_ok();
    let new_preexisted = parent_tree.is_some_and(|tree| tree.get_path(new_path).is_ok());
    !old_survives && !new_preexisted
}

fn native_rename_path_keys_match(old_path: &Path, new_path: &Path) -> bool {
    let old_key = compact_stem_key(old_path);
    let new_key = compact_stem_key(new_path);
    !old_key.is_empty() && old_key == new_key
}

fn tree_path_token_overlap_ratio(
    repo: &Repository,
    parent_tree: &git2::Tree<'_>,
    current_tree: &git2::Tree<'_>,
    old_path: &Path,
    new_path: &Path,
) -> Option<f64> {
    let old_blob = parent_tree
        .get_path(old_path)
        .ok()?
        .to_object(repo)
        .ok()?
        .peel_to_blob()
        .ok()?;
    let new_blob = current_tree
        .get_path(new_path)
        .ok()?
        .to_object(repo)
        .ok()?
        .peel_to_blob()
        .ok()?;
    blob_token_overlap_ratio(&old_blob, &new_blob)
}

fn blob_token_overlap_ratio(old_blob: &git2::Blob<'_>, new_blob: &git2::Blob<'_>) -> Option<f64> {
    let old_tokens = blob_token_set(old_blob);
    let new_tokens = blob_token_set(new_blob);
    let max_tokens = old_tokens.len().max(new_tokens.len());
    if max_tokens == 0 {
        return Some(1.0);
    }
    let overlap = old_tokens.intersection(&new_tokens).count();
    Some(overlap as f64 / max_tokens as f64)
}

fn strip_git_log_token_prefix(mut token: &[u8]) -> &[u8] {
    while matches!(token.first(), Some(b'\0' | b'\n' | b'\r')) {
        token = &token[1..];
    }
    token
}

fn pathbuf_from_git_log_token(token: &[u8]) -> PathBuf {
    PathBuf::from(String::from_utf8_lossy(strip_git_log_token_prefix(token)).into_owned())
}

fn blob_token_set(blob: &git2::Blob<'_>) -> HashSet<String> {
    String::from_utf8_lossy(blob.content())
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(|token| token.to_ascii_lowercase())
        .collect()
}

fn compact_stem_key(path: &Path) -> String {
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return String::new();
    };
    let stem = file_name
        .rsplit_once('.')
        .map(|(stem, _)| stem)
        .unwrap_or(file_name);
    stem.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

#[derive(Default)]
struct RenameCanonicalizer {
    repo_rel_map: HashMap<PathBuf, PathBuf>,
}

impl RenameCanonicalizer {
    fn record_renames(&mut self, renames: &[(PathBuf, PathBuf)]) {
        for (old_path, new_path) in renames {
            let canonical_new = self.canonicalize(new_path);
            self.repo_rel_map.insert(old_path.clone(), canonical_new);
        }
    }

    fn canonicalize(&self, path: &Path) -> PathBuf {
        let mut current = path.to_path_buf();
        let mut seen = HashSet::default();
        while seen.insert(current.clone()) {
            let Some(next) = self.repo_rel_map.get(&current) else {
                break;
            };
            current = next.clone();
        }
        current
    }
}

fn normalized_rel_path(file: &ProjectFile) -> String {
    file.rel_path()
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase()
}

fn score_bucket(score: f64) -> i64 {
    (score * SCORE_BUCKET_SCALE).round() as i64
}

fn compare_file_relevance(left: &FileRelevance, right: &FileRelevance) -> std::cmp::Ordering {
    score_bucket(right.score)
        .cmp(&score_bucket(left.score))
        .then_with(|| normalized_rel_path(&left.file).cmp(&normalized_rel_path(&right.file)))
}

#[cfg(test)]
mod weight_benchmark;

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_RECENCY_HALF_LIFE, FileRelevance, GitProjectContext, RepoCommitChangeCache,
        UsageReferenceWeights, clear_repo_commit_change_cache_for_root, commit_age_weight,
        most_relevant_project_files_with_half_life, related_files_by_git, related_files_by_imports,
        repo_commit_change_cache, weighted_page_rank,
    };
    use crate::analyzer::usages::inverted_edges::UsageReferenceCounts;
    use crate::analyzer::{
        AnalyzerDelegate, JavaAnalyzer, Language, MultiAnalyzer, ProjectFile, PythonAnalyzer,
        TestProject,
    };
    use crate::hash::HashMap;
    use git2::{Repository, Signature};
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use std::time::Instant;
    use tempfile::TempDir;

    fn write_file(root: &Path, rel_path: &str, contents: &str) -> ProjectFile {
        let file = ProjectFile::new(root.to_path_buf(), rel_path);
        file.write(contents).unwrap();
        file
    }

    fn hash_map<K, V, const N: usize>(entries: [(K, V); N]) -> HashMap<K, V>
    where
        K: Eq + std::hash::Hash,
    {
        entries.into_iter().collect()
    }

    #[test]
    fn near_tie_scores_sort_by_normalized_path_name() {
        let temp = TempDir::new().unwrap();
        let left = write_file(temp.path(), "Zed.java", "class Zed {}");
        let right = write_file(temp.path(), "Alpha.java", "class Alpha {}");

        let ordering = super::compare_file_relevance(
            &super::FileRelevance {
                file: left,
                score: 1.0,
            },
            &super::FileRelevance {
                file: right,
                score: 1.0 + 5.0e-10,
            },
        );

        assert_eq!(std::cmp::Ordering::Greater, ordering);
    }

    #[test]
    fn score_bucket_order_is_transitive_for_near_tie_chain() {
        let temp = TempDir::new().unwrap();
        let alpha = write_file(temp.path(), "Alpha.java", "class Alpha {}");
        let beta = write_file(temp.path(), "Beta.java", "class Beta {}");
        let zed = write_file(temp.path(), "Zed.java", "class Zed {}");
        let mut ranked = [
            super::FileRelevance {
                file: zed,
                score: 1.0 + 1.4e-10,
            },
            super::FileRelevance {
                file: beta,
                score: 1.0 + 0.9e-10,
            },
            super::FileRelevance {
                file: alpha,
                score: 1.0,
            },
        ];

        ranked.sort_by(super::compare_file_relevance);

        let paths = ranked
            .iter()
            .map(|item| item.file.rel_path().to_string_lossy().to_string())
            .collect::<Vec<_>>();
        assert_eq!(vec!["Alpha.java", "Beta.java", "Zed.java"], paths);
    }

    fn java_analyzer(root: &Path) -> JavaAnalyzer {
        JavaAnalyzer::from_project(TestProject::new(root.to_path_buf(), Language::Java))
    }

    fn commit_paths(repo: &Repository, message: &str, add: &[&str], remove: &[&str]) {
        let mut index = repo.index().unwrap();
        for path in remove {
            index.remove_path(Path::new(path)).unwrap();
        }
        for path in add {
            index.add_path(Path::new(path)).unwrap();
        }
        index.write().unwrap();

        let tree_id = index.write_tree().unwrap();
        let tree = repo.find_tree(tree_id).unwrap();
        let signature = Signature::now("Test User", "test@example.com").unwrap();
        let parent = repo
            .head()
            .ok()
            .and_then(|head| head.target())
            .and_then(|oid| repo.find_commit(oid).ok());
        let parents = parent.iter().collect::<Vec<_>>();
        repo.commit(
            Some("HEAD"),
            &signature,
            &signature,
            message,
            &tree,
            &parents,
        )
        .unwrap();
    }

    fn commit_paths_at(
        repo: &Repository,
        message: &str,
        add: &[&str],
        remove: &[&str],
        seconds: i64,
    ) {
        let mut index = repo.index().unwrap();
        for path in remove {
            index.remove_path(Path::new(path)).unwrap();
        }
        for path in add {
            index.add_path(Path::new(path)).unwrap();
        }
        index.write().unwrap();

        let tree_id = index.write_tree().unwrap();
        let tree = repo.find_tree(tree_id).unwrap();
        let signature = Signature::new(
            "Test User",
            "test@example.com",
            &git2::Time::new(seconds, 0),
        )
        .unwrap();
        let parent = repo
            .head()
            .ok()
            .and_then(|head| head.target())
            .and_then(|oid| repo.find_commit(oid).ok());
        let parents = parent.iter().collect::<Vec<_>>();
        repo.commit(
            Some("HEAD"),
            &signature,
            &signature,
            message,
            &tree,
            &parents,
        )
        .unwrap();
    }

    fn git_context(root: &Path) -> GitProjectContext {
        GitProjectContext::discover(root).expect("git project context")
    }

    fn file_by_name<'a>(result: &'a [FileRelevance], file_name: &str) -> Option<&'a FileRelevance> {
        result.iter().find(|entry| {
            entry
                .file
                .rel_path()
                .file_name()
                .and_then(|value| value.to_str())
                == Some(file_name)
        })
    }

    #[test]
    fn seeds_exclude_self_and_rank_imported_neighbors_higher_reversed_false() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let a = write_file(
            root,
            "test/A.java",
            "package test; import test.B; public class A { public void a() {} }",
        );
        let b = write_file(
            root,
            "test/B.java",
            "package test; import test.C; public class B { public void b() {} }",
        );
        let c = write_file(
            root,
            "test/C.java",
            "package test; public class C { public void c() {} }",
        );
        write_file(
            root,
            "test/D.java",
            "package test; public class D { public void d() {} }",
        );

        let analyzer = java_analyzer(root);
        let results = related_files_by_imports(&analyzer, &hash_map([(a.clone(), 1.0)]), 10, false);

        assert!(results.iter().all(|result| result.file != a));
        assert!(results.len() >= 2);
        let top_two = results
            .iter()
            .take(2)
            .map(|entry| entry.file.clone())
            .collect::<Vec<_>>();
        assert!(top_two.contains(&b));
        assert!(top_two.contains(&c));
    }

    #[test]
    fn relative_ranking_of_hub_node() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let hub = write_file(root, "test/Hub.java", "package test; public class Hub {}");
        let leaf = write_file(
            root,
            "test/Leaf1.java",
            "package test; import test.Hub; public class Leaf1 {}",
        );
        write_file(
            root,
            "test/Leaf2.java",
            "package test; import test.Hub; public class Leaf2 {}",
        );
        write_file(
            root,
            "test/Leaf3.java",
            "package test; import test.Hub; public class Leaf3 {}",
        );
        write_file(
            root,
            "test/Leaf4.java",
            "package test; import test.Hub; public class Leaf4 {}",
        );

        let analyzer = java_analyzer(root);
        let results = related_files_by_imports(&analyzer, &hash_map([(leaf, 1.0)]), 10, false);

        assert_eq!(Some(&hub), results.first().map(|entry| &entry.file));
    }

    #[test]
    fn rank_flows_through_chain_but_not_beyond_import_depth() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let a = write_file(
            root,
            "test/A.java",
            "package test; import test.B; public class A {}",
        );
        let b = write_file(
            root,
            "test/B.java",
            "package test; import test.C; public class B {}",
        );
        let c = write_file(
            root,
            "test/C.java",
            "package test; import test.D; public class C {}",
        );
        let d = write_file(root, "test/D.java", "package test; public class D {}");

        let analyzer = java_analyzer(root);
        let results = related_files_by_imports(&analyzer, &hash_map([(a, 1.0)]), 10, false);
        let result_files = results
            .iter()
            .map(|entry| entry.file.clone())
            .collect::<Vec<_>>();

        let index_b = result_files.iter().position(|file| file == &b).unwrap();
        let index_c = result_files.iter().position(|file| file == &c).unwrap();
        assert!(result_files.contains(&b));
        assert!(result_files.contains(&c));
        assert!(!result_files.contains(&d));
        assert!(index_b < index_c);
    }

    #[test]
    fn page_rank_handles_circular_imports() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let a = write_file(
            root,
            "test/A.java",
            "package test; import test.B; public class A {}",
        );
        let b = write_file(
            root,
            "test/B.java",
            "package test; import test.C; public class B {}",
        );
        let c = write_file(
            root,
            "test/C.java",
            "package test; import test.A; public class C {}",
        );

        let analyzer = java_analyzer(root);
        let results = related_files_by_imports(&analyzer, &hash_map([(a.clone(), 1.0)]), 10, false);
        let result_files = results
            .iter()
            .map(|entry| entry.file.clone())
            .collect::<Vec<_>>();

        assert!(!result_files.contains(&a));
        assert!(result_files.contains(&b));
        assert!(result_files.contains(&c));
        assert!(
            results
                .iter()
                .all(|entry| entry.score > 0.0 && entry.score < 1.0)
        );
    }

    #[test]
    fn weighted_page_rank_supports_uniform_global_centrality() {
        let scores = weighted_page_rank(&[vec![(1, 1.0)], Vec::new()], &[]);

        assert_eq!(scores.len(), 2);
        assert!((scores.iter().sum::<f64>() - 1.0).abs() < 1.0e-6);
        assert!(scores[1] > scores[0], "scores: {scores:?}");
    }

    #[test]
    fn weighted_page_rank_uses_edge_weights() {
        let scores = weighted_page_rank(
            &[vec![(1, 1.0), (2, 3.0)], Vec::new(), Vec::new()],
            &[1.0, 0.0, 0.0],
        );

        assert!(scores[2] > scores[1], "scores: {scores:?}");
        assert!((scores.iter().sum::<f64>() - 1.0).abs() < 1.0e-6);
    }

    #[test]
    fn calibrated_usage_weights_apply_a_subtle_behavioral_preference() {
        let weights = UsageReferenceWeights::CALIBRATED;
        let call = weights.combine(UsageReferenceCounts {
            calls: 1,
            ..UsageReferenceCounts::default()
        });
        let member = weights.combine(UsageReferenceCounts {
            members: 1,
            ..UsageReferenceCounts::default()
        });
        let type_reference = weights.combine(UsageReferenceCounts {
            types: 1,
            ..UsageReferenceCounts::default()
        });
        let other = weights.combine(UsageReferenceCounts {
            other: 1,
            ..UsageReferenceCounts::default()
        });
        assert!(call > member && member > type_reference && type_reference > other);

        let scores = weighted_page_rank(
            &[
                vec![(1, call), (2, member), (3, type_reference), (4, other)],
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ],
            &[1.0, 0.0, 0.0, 0.0, 0.0],
        );
        assert!(scores[1] > scores[2]);
        assert!(scores[2] > scores[3]);
        assert!(scores[3] > scores[4]);
    }

    #[test]
    fn weighted_page_rank_returns_dangling_mass_to_personalized_seeds() {
        let scores = weighted_page_rank(&[vec![(1, 1.0)], Vec::new()], &[2.0, 0.0]);

        assert!(scores[0] > 0.0 && scores[1] > 0.0, "scores: {scores:?}");
        assert!((scores.iter().sum::<f64>() - 1.0).abs() < 1.0e-6);
    }

    #[test]
    fn weighted_page_rank_converges_deterministically_on_a_cycle() {
        let outgoing = [vec![(1, 1.0)], vec![(2, 1.0)], vec![(0, 1.0)]];
        let first = weighted_page_rank(&outgoing, &[3.0, 1.0, 0.0]);
        let second = weighted_page_rank(&outgoing, &[3.0, 1.0, 0.0]);

        assert_eq!(first, second);
        assert!((first.iter().sum::<f64>() - 1.0).abs() < 1.0e-6);
        assert!(first.iter().all(|score| score.is_finite() && *score > 0.0));
    }

    #[test]
    fn no_project_imports_are_handled_gracefully() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let a = write_file(
            root,
            "test/A.java",
            "package test; import java.util.List; public class A { List<String> list; }",
        );
        write_file(
            root,
            "test/B.java",
            "package test; import java.util.Map; public class B { Map<String, String> map; }",
        );

        let analyzer = java_analyzer(root);
        let results = related_files_by_imports(&analyzer, &hash_map([(a.clone(), 1.0)]), 10, false);

        assert!(results.iter().all(|entry| entry.file != a));
        assert!(results.is_empty());
    }

    #[test]
    fn reverse_import_traversal_finds_importers() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let importer = write_file(
            root,
            "test/Importer.java",
            "package test; import test.Imported; public class Importer {}",
        );
        let imported = write_file(
            root,
            "test/Imported.java",
            "package test; public class Imported {}",
        );

        let analyzer = java_analyzer(root);
        let results = related_files_by_imports(&analyzer, &hash_map([(imported, 1.0)]), 10, true);

        assert!(results.iter().any(|entry| entry.file == importer));
    }

    #[test]
    fn directionality_of_reversed_flag_matches_brokk() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let upstream = write_file(
            root,
            "test/Upstream.java",
            "package test; public class Upstream {}",
        );
        let middle = write_file(
            root,
            "test/Middle.java",
            "package test; import test.Upstream; public class Middle {}",
        );
        let downstream = write_file(
            root,
            "test/Downstream.java",
            "package test; import test.Middle; public class Downstream {}",
        );

        let analyzer = java_analyzer(root);
        let forward =
            related_files_by_imports(&analyzer, &hash_map([(middle.clone(), 1.0)]), 10, false);
        let reverse = related_files_by_imports(&analyzer, &hash_map([(middle, 1.0)]), 10, true);

        assert!(forward.iter().any(|entry| entry.file == upstream));
        assert!(!forward.iter().any(|entry| entry.file == downstream));
        assert!(reverse.iter().any(|entry| entry.file == downstream));
        assert!(!reverse.iter().any(|entry| entry.file == upstream));
    }

    #[test]
    fn multi_analyzer_with_multiple_languages_uses_correct_delegates() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let java_source = write_file(
            root,
            "test/Source.java",
            "package test; import test.Target; public class Source {}",
        );
        let java_target = write_file(
            root,
            "test/Target.java",
            "package test; public class Target {}",
        );
        let py_source = write_file(
            root,
            "py_source.py",
            "from other_module import other_fn\n\ndef py_source_fn():\n    other_fn()\n",
        );
        let py_target = write_file(root, "other_module.py", "def other_fn():\n    pass\n");

        let project = TestProject::new(root.to_path_buf(), Language::Java);
        let multi = MultiAnalyzer::new(BTreeMap::from([
            (
                Language::Java,
                AnalyzerDelegate::Java(JavaAnalyzer::from_project(project.clone())),
            ),
            (
                Language::Python,
                AnalyzerDelegate::Python(PythonAnalyzer::from_project(project)),
            ),
        ]));

        let java_results =
            related_files_by_imports(&multi, &hash_map([(java_source, 1.0)]), 10, false);
        assert!(java_results.iter().any(|entry| entry.file == java_target));
        assert!(!java_results.iter().any(|entry| entry.file == py_target));

        let py_results = related_files_by_imports(&multi, &hash_map([(py_source, 1.0)]), 10, false);
        assert!(py_results.iter().any(|entry| entry.file == py_target));
        assert!(!py_results.iter().any(|entry| entry.file == java_target));
    }

    #[test]
    fn stable_scores_exist_for_named_results() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let a = write_file(
            root,
            "test/A.java",
            "package test; import test.B; public class A {}",
        );
        write_file(
            root,
            "test/B.java",
            "package test; import test.C; public class B {}",
        );
        write_file(root, "test/C.java", "package test; public class C {}");

        let analyzer = java_analyzer(root);
        let results = related_files_by_imports(&analyzer, &hash_map([(a, 1.0)]), 10, false);

        let b_score = file_by_name(&results, "B.java")
            .expect("B should be ranked")
            .score;
        let c_score = file_by_name(&results, "C.java")
            .expect("C should be ranked")
            .score;

        // Personalized PageRank over A -> B -> C, with A as the only teleport
        // target. These values deliberately pin the existing fixed-iteration
        // algorithm so storage-only graph changes cannot alter ranking behavior.
        assert!(
            (b_score - 0.330_416_201).abs() <= super::PAGE_RANK_SCORE_TOLERANCE,
            "B score changed: {b_score}"
        );
        assert!(
            (c_score - 0.280_853_771).abs() <= super::PAGE_RANK_SCORE_TOLERANCE,
            "C score changed: {c_score}"
        );
    }

    #[test]
    fn recency_weighted_git_scores_downweight_old_only_targets_against_uniform_scores() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        write_file(root, "Seed.java", "public class Seed { }");
        write_file(root, "OldTarget.java", "public class OldTarget { }");

        let repo = Repository::init(root).unwrap();
        commit_paths(&repo, "initial seed", &["Seed.java"], &[]);
        commit_paths(&repo, "add old target", &["OldTarget.java"], &[]);
        fs::write(
            root.join("Seed.java"),
            "public class Seed { int oldUse() { return 1; } }",
        )
        .unwrap();
        fs::write(
            root.join("OldTarget.java"),
            "public class OldTarget { int value() { return 1; } }",
        )
        .unwrap();
        commit_paths(&repo, "old cochange", &["Seed.java", "OldTarget.java"], &[]);
        fs::write(
            root.join("Seed.java"),
            "public class Seed { int newerOnly() { return 2; } }",
        )
        .unwrap();
        commit_paths(&repo, "seed only recent", &["Seed.java"], &[]);
        for index in 0..30 {
            fs::write(
                root.join("Seed.java"),
                format!("public class Seed {{ int recentOnly{index}() {{ return {index}; }} }}"),
            )
            .unwrap();
            commit_paths(
                &repo,
                &format!("seed only recent {index}"),
                &["Seed.java"],
                &[],
            );
        }

        let analyzer = java_analyzer(root);
        let seed = ProjectFile::new(root.to_path_buf(), "Seed.java");
        let seed_weights = hash_map([(seed, 1.0)]);
        let uniform_scores = related_files_by_git(&analyzer, &seed_weights, 10, None).unwrap();
        let recency_scores =
            related_files_by_git(&analyzer, &seed_weights, 10, Some(10.0)).unwrap();

        let uniform_old = file_by_name(&uniform_scores, "OldTarget.java")
            .expect("uniform old target score")
            .score;
        let recency_old = file_by_name(&recency_scores, "OldTarget.java")
            .expect("recency old target score")
            .score;

        assert!(recency_old < uniform_old, "{recency_old} !< {uniform_old}");
    }

    #[test]
    fn half_life_none_reproduces_legacy_uniform_scores_exactly() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        write_file(root, "Seed.java", "public class Seed { }");
        write_file(root, "Target.java", "public class Target { }");

        let repo = Repository::init(root).unwrap();
        commit_paths(&repo, "initial seed", &["Seed.java"], &[]);
        commit_paths(&repo, "add target", &["Target.java"], &[]);
        fs::write(
            root.join("Seed.java"),
            "public class Seed { int use() { return 1; } }",
        )
        .unwrap();
        fs::write(
            root.join("Target.java"),
            "public class Target { int value() { return 1; } }",
        )
        .unwrap();
        commit_paths(&repo, "cochange", &["Seed.java", "Target.java"], &[]);
        fs::write(
            root.join("Seed.java"),
            "public class Seed { int useAgain() { return 2; } }",
        )
        .unwrap();
        commit_paths(&repo, "seed only", &["Seed.java"], &[]);

        let analyzer = java_analyzer(root);
        let seed = ProjectFile::new(root.to_path_buf(), "Seed.java");
        let uniform_scores =
            related_files_by_git(&analyzer, &hash_map([(seed, 1.0)]), 10, None).unwrap();

        let target_score = file_by_name(&uniform_scores, "Target.java")
            .expect("uniform target score")
            .score;
        let expected_seed_mass = 3.0;
        let expected_joint_mass = 0.5;
        let expected_conditional = expected_joint_mass / expected_seed_mass;
        let expected_idf = 3.0f64.ln();
        let expected_score = expected_conditional * expected_idf;

        assert!(
            (target_score - expected_score).abs() < 1.0e-12,
            "{target_score} != {expected_score}"
        );
    }

    #[test]
    fn huge_half_life_approximates_uniform_scores() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        write_file(root, "Seed.java", "public class Seed { }");
        write_file(root, "Target.java", "public class Target { }");

        let repo = Repository::init(root).unwrap();
        commit_paths(&repo, "initial seed", &["Seed.java"], &[]);
        commit_paths(&repo, "add target", &["Target.java"], &[]);
        fs::write(
            root.join("Seed.java"),
            "public class Seed { int use() { return 1; } }",
        )
        .unwrap();
        fs::write(
            root.join("Target.java"),
            "public class Target { int value() { return 1; } }",
        )
        .unwrap();
        commit_paths(&repo, "cochange", &["Seed.java", "Target.java"], &[]);
        fs::write(
            root.join("Seed.java"),
            "public class Seed { int useAgain() { return 2; } }",
        )
        .unwrap();
        commit_paths(&repo, "seed only", &["Seed.java"], &[]);

        let analyzer = java_analyzer(root);
        let seed = ProjectFile::new(root.to_path_buf(), "Seed.java");
        let uniform_scores =
            related_files_by_git(&analyzer, &hash_map([(seed.clone(), 1.0)]), 10, None).unwrap();
        let huge_half_life_scores =
            related_files_by_git(&analyzer, &hash_map([(seed, 1.0)]), 10, Some(1.0e9)).unwrap();

        let uniform_target = file_by_name(&uniform_scores, "Target.java")
            .expect("uniform target score")
            .score;
        let huge_target = file_by_name(&huge_half_life_scores, "Target.java")
            .expect("large half-life target score")
            .score;
        assert!((uniform_target - huge_target).abs() < 1.0e-9);
    }

    #[test]
    fn small_half_life_sharpens_recency_preference() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        write_file(root, "Seed.java", "public class Seed { }");
        write_file(root, "OldTarget.java", "public class OldTarget { }");
        write_file(root, "RecentTarget.java", "public class RecentTarget { }");

        let repo = Repository::init(root).unwrap();
        commit_paths(&repo, "initial seed", &["Seed.java"], &[]);
        commit_paths(&repo, "add old target", &["OldTarget.java"], &[]);
        fs::write(
            root.join("Seed.java"),
            "public class Seed { int oldUse() { return 1; } }",
        )
        .unwrap();
        fs::write(
            root.join("OldTarget.java"),
            "public class OldTarget { int value() { return 1; } }",
        )
        .unwrap();
        commit_paths(&repo, "old cochange", &["Seed.java", "OldTarget.java"], &[]);
        commit_paths(&repo, "add recent target", &["RecentTarget.java"], &[]);
        fs::write(
            root.join("Seed.java"),
            "public class Seed { int recentUse() { return 2; } }",
        )
        .unwrap();
        fs::write(
            root.join("RecentTarget.java"),
            "public class RecentTarget { int value() { return 2; } }",
        )
        .unwrap();
        commit_paths(
            &repo,
            "recent cochange",
            &["Seed.java", "RecentTarget.java"],
            &[],
        );

        let analyzer = java_analyzer(root);
        let default_ranked = most_relevant_project_files_with_half_life(
            &analyzer,
            &[(ProjectFile::new(root.to_path_buf(), "Seed.java"), 1.0)],
            2,
            Some(DEFAULT_RECENCY_HALF_LIFE),
        );
        let legacy_ranked = most_relevant_project_files_with_half_life(
            &analyzer,
            &[(ProjectFile::new(root.to_path_buf(), "Seed.java"), 1.0)],
            2,
            None,
        );
        let sharp_ranked = most_relevant_project_files_with_half_life(
            &analyzer,
            &[(ProjectFile::new(root.to_path_buf(), "Seed.java"), 1.0)],
            2,
            Some(1.0),
        );

        assert_eq!(
            "RecentTarget.java",
            default_ranked[0].rel_path().display().to_string()
        );
        assert_eq!(
            "OldTarget.java",
            legacy_ranked[0].rel_path().display().to_string()
        );
        assert_eq!(
            "RecentTarget.java",
            sharp_ranked[0].rel_path().display().to_string()
        );
    }

    #[test]
    fn commit_age_weight_defaults_to_uniform_when_half_life_is_none() {
        assert_eq!(1.0, commit_age_weight(0, None));
        assert_eq!(1.0, commit_age_weight(250, None));
        assert_eq!(1.0, commit_age_weight(1_000, None));
    }

    #[test]
    fn cached_commit_window_matches_uncached_history_with_renames_and_merge_commit() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        write_file(root, "Seed.java", "public class Seed { }");
        fs::create_dir_all(root.join("legacy")).unwrap();
        write_file(
            root,
            "legacy/RenameTarget.java",
            "public class RenameTarget { }",
        );
        write_file(root, "MergeTarget.java", "public class MergeTarget { }");

        let repo = Repository::init(root).unwrap();
        commit_paths(
            &repo,
            "initial",
            &["Seed.java", "legacy/RenameTarget.java", "MergeTarget.java"],
            &[],
        );

        std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["checkout", "-b", "feature"])
            .status()
            .unwrap()
            .success()
            .then_some(())
            .expect("create feature branch");
        fs::write(
            root.join("MergeTarget.java"),
            "public class MergeTarget { int feature() { return 1; } }",
        )
        .unwrap();
        commit_paths(&repo, "feature change", &["MergeTarget.java"], &[]);

        std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["checkout", "-"])
            .status()
            .unwrap()
            .success()
            .then_some(())
            .expect("checkout original branch");
        fs::write(
            root.join("Seed.java"),
            "public class Seed { int main() { return 1; } }",
        )
        .unwrap();
        fs::write(
            root.join("legacy/RenameTarget.java"),
            "public class RenameTarget { int main() { return 1; } }",
        )
        .unwrap();
        commit_paths(
            &repo,
            "main cochange before rename",
            &["Seed.java", "legacy/RenameTarget.java"],
            &[],
        );

        fs::create_dir_all(root.join("modern")).unwrap();
        fs::rename(
            root.join("legacy/RenameTarget.java"),
            root.join("modern/RenameTarget.java"),
        )
        .unwrap();
        commit_paths(
            &repo,
            "rename",
            &["modern/RenameTarget.java"],
            &["legacy/RenameTarget.java"],
        );

        std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args([
                "-c",
                "user.name=Test User",
                "-c",
                "user.email=test@example.com",
                "-c",
                "commit.gpgSign=false",
                "merge",
                "--no-ff",
                "feature",
                "-m",
                "merge feature",
            ])
            .status()
            .unwrap()
            .success()
            .then_some(())
            .expect("merge feature branch");

        let context = git_context(root);
        let uncached = context.recent_commit_changes_uncached(10).unwrap();
        let cache = Arc::new(RepoCommitChangeCache::new(64));
        let cached = context
            .recent_commit_changes_with_cache(10, &cache)
            .unwrap();

        assert_eq!(uncached, cached);
        assert!(cached.iter().any(|change| {
            change.renames.iter().any(|(old_path, new_path)| {
                old_path == Path::new("legacy/RenameTarget.java")
                    && new_path == Path::new("modern/RenameTarget.java")
            })
        }));
        assert!(cached.iter().any(|change| {
            change
                .paths
                .iter()
                .any(|path| path == Path::new("MergeTarget.java"))
        }));
    }

    #[test]
    fn incremental_fill_scans_only_new_commits() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        write_file(root, "Seed.java", "public class Seed { }");
        write_file(root, "Target.java", "public class Target { }");

        let repo = Repository::init(root).unwrap();
        commit_paths_at(&repo, "initial", &["Seed.java", "Target.java"], &[], 1);
        fs::write(
            root.join("Seed.java"),
            "public class Seed { int one() { return 1; } }",
        )
        .unwrap();
        commit_paths_at(&repo, "seed one", &["Seed.java"], &[], 2);
        fs::write(
            root.join("Target.java"),
            "public class Target { int one() { return 1; } }",
        )
        .unwrap();
        commit_paths_at(&repo, "target one", &["Target.java"], &[], 3);

        let context = git_context(root);
        let cache = RepoCommitChangeCache::new(64);

        context
            .recent_commit_changes_with_cache(10, &cache)
            .unwrap();
        assert_eq!(3, cache.fill_commits_scanned.load(Ordering::Relaxed));

        context
            .recent_commit_changes_with_cache(10, &cache)
            .unwrap();
        assert_eq!(3, cache.fill_commits_scanned.load(Ordering::Relaxed));

        fs::write(
            root.join("Seed.java"),
            "public class Seed { int two() { return 2; } }",
        )
        .unwrap();
        commit_paths_at(&repo, "seed two", &["Seed.java"], &[], 4);
        fs::write(
            root.join("Target.java"),
            "public class Target { int two() { return 2; } }",
        )
        .unwrap();
        commit_paths_at(&repo, "target two", &["Target.java"], &[], 5);

        context
            .recent_commit_changes_with_cache(10, &cache)
            .unwrap();
        assert_eq!(5, cache.fill_commits_scanned.load(Ordering::Relaxed));
    }

    #[test]
    fn commit_change_cache_eviction_respects_bound() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        write_file(root, "File.java", "class File {}");

        let repo = Repository::init(root).unwrap();
        commit_paths_at(&repo, "initial", &["File.java"], &[], 1);
        for index in 0..4 {
            fs::write(
                root.join("File.java"),
                format!("class File {{ int value() {{ return {index}; }} }}"),
            )
            .unwrap();
            commit_paths_at(
                &repo,
                &format!("change {index}"),
                &["File.java"],
                &[],
                index + 2,
            );
        }

        let context = git_context(root);
        let cache = RepoCommitChangeCache::new(2);
        let ordered_oids = context.recent_commit_oids(10).unwrap();
        let last_range = super::MissingCommitRange {
            start: ordered_oids.len() - 2,
            end: ordered_oids.len() - 1,
        };
        context
            .populate_commit_range(&ordered_oids, last_range, &cache)
            .unwrap();
        cache.commits.run_pending_tasks();

        assert!(
            cache.commits.entry_count() <= 2,
            "entry count should stay within the configured cap"
        );
    }

    #[test]
    fn repo_commit_change_caches_are_isolated_per_repo_root() {
        let left = TempDir::new().unwrap();
        write_file(left.path(), "Left.java", "class Left {}");
        let _left_repo = Repository::init(left.path()).unwrap();

        let right = TempDir::new().unwrap();
        write_file(right.path(), "Right.java", "class Right {}");
        let _right_repo = Repository::init(right.path()).unwrap();

        let left_cache = repo_commit_change_cache(left.path());
        let left_cache_again = repo_commit_change_cache(left.path());
        let right_cache = repo_commit_change_cache(right.path());

        assert!(Arc::ptr_eq(&left_cache, &left_cache_again));
        assert!(!Arc::ptr_eq(&left_cache, &right_cache));
    }

    #[test]
    #[ignore = "benchmark helper for repeated most_relevant_files calls"]
    fn benchmark_repeat_calls_with_cached_git_history() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        write_file(root, "Seed.java", "public class Seed { }");
        write_file(root, "Target.java", "public class Target { }");
        write_file(root, "Helper.java", "public class Helper { }");

        let repo = Repository::init(root).unwrap();
        commit_paths_at(
            &repo,
            "initial",
            &["Seed.java", "Target.java", "Helper.java"],
            &[],
            1,
        );
        for index in 0..120 {
            fs::write(
                root.join("Seed.java"),
                format!("public class Seed {{ int value{index}() {{ return {index}; }} }}"),
            )
            .unwrap();
            let changed = if index % 3 == 0 {
                vec!["Seed.java", "Target.java"]
            } else {
                vec!["Seed.java", "Helper.java"]
            };
            commit_paths_at(
                &repo,
                &format!("change {index}"),
                &changed,
                &[],
                index as i64 + 2,
            );
        }

        let analyzer = java_analyzer(root);
        let seeds = [(ProjectFile::new(root.to_path_buf(), "Seed.java"), 1.0)];

        clear_repo_commit_change_cache_for_root(root);
        let cold_started = Instant::now();
        for _ in 0..28 {
            clear_repo_commit_change_cache_for_root(root);
            let _ = most_relevant_project_files_with_half_life(
                &analyzer,
                &seeds,
                5,
                Some(DEFAULT_RECENCY_HALF_LIFE),
            );
        }
        let cold_elapsed = cold_started.elapsed();

        clear_repo_commit_change_cache_for_root(root);
        let warm_started = Instant::now();
        for _ in 0..28 {
            let _ = most_relevant_project_files_with_half_life(
                &analyzer,
                &seeds,
                5,
                Some(DEFAULT_RECENCY_HALF_LIFE),
            );
        }
        let warm_elapsed = warm_started.elapsed();

        eprintln!(
            "benchmark_repeat_calls_with_cached_git_history cold_28={:.3}s warm_28={:.3}s",
            cold_elapsed.as_secs_f64(),
            warm_elapsed.as_secs_f64()
        );
    }
}
