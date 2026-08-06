use crate::analyzer::usages::file_usage_graph::{
    WorkspaceFileUsageGraphBuildOutcome, build_workspace_file_usage_graph_with_cancellation,
};
use crate::analyzer::usages::inverted_edges::UsageReferenceCounts;
use crate::analyzer::usages::workspace_graph::{
    UsageEcosystem, WorkspaceUsageCatalog, WorkspaceUsageGraphBuildOutcome,
    WorkspaceUsageRankingGraph as UsageRankingGraph, build_workspace_usage_graph_with_cancellation,
};
use crate::analyzer::usages::workspace_graph_cache::{
    WorkspaceUsageGraphCacheAcquisition, WorkspaceUsageGraphCacheBuildOutcome,
    WorkspaceUsageGraphCacheKey, WorkspaceUsageGraphKind,
};
use crate::analyzer::{CodeUnit, IAnalyzer, ProjectFile};
use crate::cancellation::CancellationToken;
use crate::compact_graph::CompactDirectedGraph;
use crate::hash::{HashMap, HashSet};
use crate::profiling;
use git2::{Oid, Repository};
use moka::sync::Cache;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, VecDeque};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

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
/// How often a pending `git` child is checked against the caller's cancellation
/// token. The wait is otherwise idle, so this only bounds how long an expired
/// request budget keeps a doomed subprocess alive.
const GIT_SUBPROCESS_POLL_INTERVAL: Duration = Duration::from_millis(25);
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
/// Counts `git rev-list` subprocess spawns across the process lifetime (not reset by
/// `reset_git_counters`, unlike the per-call diff counters above). Exists so tests and manual
/// measurement can confirm the HEAD-keyed cache is actually skipping the subprocess on repeat
/// calls with an unchanged HEAD, rather than only inferring it from wall-clock time.
static GIT_REV_LIST_SPAWNS: AtomicUsize = AtomicUsize::new(0);

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
    UsageGraphExact,
}

#[derive(Clone, Copy, Debug)]
struct UsageReferenceWeights {
    calls: f64,
    members: f64,
    types: f64,
    other: f64,
}

pub(crate) enum MostRelevantProjectFilesOutcome {
    Complete(Vec<ProjectFile>),
    /// Ranked without the commit-history leg, which this repository could not
    /// supply within the request. The files are a real ranking from the local
    /// import graph, so the caller returns them and reports the response as
    /// incomplete rather than failing.
    HistoryUnavailable(Vec<ProjectFile>),
    Cancelled,
}

enum Cancellable<T> {
    Complete(T),
    Cancelled,
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

/// Rank files related to `seeds` by git co-change, then by import PageRank.
///
/// The returned status describes the history leg only: the import leg is local
/// and always runs. `HistoryUnavailable` or `Cancelled` therefore still yields a
/// usable ranking, just one the caller must report as incomplete.
pub(crate) fn most_relevant_project_files_with_half_life(
    analyzer: &dyn IAnalyzer,
    seeds: &[(ProjectFile, f64)],
    top_k: usize,
    half_life: Option<f64>,
    cancellation: &CancellationToken,
) -> (Vec<ProjectFile>, HistoryRankingStatus) {
    let _scope = profiling::scope("relevance::most_relevant_project_files");
    if top_k == 0 {
        return (Vec::new(), HistoryRankingStatus::Complete);
    }

    let seed_weights = seed_weight_map(seeds);
    if seed_weights.is_empty() {
        return (Vec::new(), HistoryRankingStatus::Complete);
    }

    let excluded: HashSet<_> = seed_weights.keys().cloned().collect();
    let mut results = Vec::new();
    let mut seen = HashSet::default();

    let history_status = {
        let _scope = profiling::scope("relevance::git");
        let (candidates, history_status) =
            related_files_by_git(analyzer, &seed_weights, top_k, half_life, cancellation)
                .unwrap_or_else(|_| (Vec::new(), HistoryRankingStatus::HistoryUnavailable));
        for candidate in candidates {
            if append_candidate(&mut results, &mut seen, &excluded, candidate.file, top_k) {
                return (results, history_status);
            }
        }
        history_status
    };

    {
        let _scope = profiling::scope("relevance::imports");
        for candidate in related_files_by_imports(analyzer, &seed_weights, top_k, false) {
            if append_candidate(&mut results, &mut seen, &excluded, candidate.file, top_k) {
                return (results, history_status);
            }
        }
    }

    (results, history_status)
}

pub(crate) fn most_relevant_project_files_with_ranking_mode_and_cancellation(
    analyzer: &dyn IAnalyzer,
    seeds: &[(ProjectFile, f64)],
    top_k: usize,
    half_life: Option<f64>,
    ranking_mode: MostRelevantFilesRankingMode,
    cancellation: &CancellationToken,
) -> MostRelevantProjectFilesOutcome {
    let _scope = profiling::scope("relevance::most_relevant_project_files_with_ranking_mode");
    if cancellation.is_cancelled() {
        return MostRelevantProjectFilesOutcome::Cancelled;
    }
    if ranking_mode == MostRelevantFilesRankingMode::HistoryImports {
        let (files, history_status) = most_relevant_project_files_with_half_life(
            analyzer,
            seeds,
            top_k,
            half_life,
            cancellation,
        );
        return match history_status {
            HistoryRankingStatus::Complete => MostRelevantProjectFilesOutcome::Complete(files),
            HistoryRankingStatus::HistoryUnavailable => {
                MostRelevantProjectFilesOutcome::HistoryUnavailable(files)
            }
            HistoryRankingStatus::Cancelled => MostRelevantProjectFilesOutcome::Cancelled,
        };
    }
    if top_k == 0 {
        return MostRelevantProjectFilesOutcome::Complete(Vec::new());
    }

    let seed_weights = seed_weight_map(seeds);
    if seed_weights.is_empty() {
        return MostRelevantProjectFilesOutcome::Complete(Vec::new());
    }
    let excluded: HashSet<_> = seed_weights.keys().cloned().collect();
    let mut results = Vec::new();
    let mut seen = HashSet::default();

    let graph_kind = match ranking_mode {
        MostRelevantFilesRankingMode::UsageGraph => WorkspaceUsageGraphKind::File,
        MostRelevantFilesRankingMode::UsageGraphExact => WorkspaceUsageGraphKind::Exact,
        MostRelevantFilesRankingMode::HistoryImports => unreachable!("handled above"),
    };
    let usage_candidates =
        match related_files_by_usage(analyzer, &seed_weights, top_k, graph_kind, cancellation) {
            Cancellable::Complete(candidates) => candidates,
            Cancellable::Cancelled => return MostRelevantProjectFilesOutcome::Cancelled,
        };
    for candidate in usage_candidates {
        if append_candidate(&mut results, &mut seen, &excluded, candidate.file, top_k) {
            return MostRelevantProjectFilesOutcome::Complete(results);
        }
    }

    if cancellation.is_cancelled() {
        return MostRelevantProjectFilesOutcome::Cancelled;
    }
    let (history_files, history_status) =
        most_relevant_project_files_with_half_life(analyzer, seeds, top_k, half_life, cancellation);
    for candidate in history_files {
        if cancellation.is_cancelled() {
            return MostRelevantProjectFilesOutcome::Cancelled;
        }
        if append_candidate(&mut results, &mut seen, &excluded, candidate, top_k) {
            break;
        }
    }
    match history_status {
        _ if cancellation.is_cancelled() => MostRelevantProjectFilesOutcome::Cancelled,
        HistoryRankingStatus::Complete => MostRelevantProjectFilesOutcome::Complete(results),
        HistoryRankingStatus::HistoryUnavailable => {
            MostRelevantProjectFilesOutcome::HistoryUnavailable(results)
        }
        HistoryRankingStatus::Cancelled => MostRelevantProjectFilesOutcome::Cancelled,
    }
}

fn related_files_by_usage(
    analyzer: &dyn IAnalyzer,
    seed_weights: &HashMap<ProjectFile, f64>,
    k: usize,
    graph_kind: WorkspaceUsageGraphKind,
    cancellation: &CancellationToken,
) -> Cancellable<Vec<FileRelevance>> {
    let _scope = profiling::scope("relevance::related_files_by_usage");
    if k == 0 {
        return Cancellable::Complete(Vec::new());
    }

    let ranking_graph = match build_usage_ranking_graph_with_kind_and_cancellation(
        analyzer,
        seed_weights,
        graph_kind,
        cancellation,
    ) {
        Cancellable::Complete(graph) => graph,
        Cancellable::Cancelled => return Cancellable::Cancelled,
    };
    related_files_by_usage_graph_with_cancellation(
        &ranking_graph,
        seed_weights,
        k,
        UsageReferenceWeights::CALIBRATED,
        cancellation,
    )
}

#[cfg(test)]
fn build_usage_ranking_graph(analyzer: &dyn IAnalyzer) -> Arc<UsageRankingGraph> {
    let catalog = WorkspaceUsageCatalog::build(analyzer);
    let selected_ecosystems = catalog.ecosystems();
    match build_usage_ranking_graph_for_ecosystems_with_cancellation(
        analyzer,
        catalog,
        &selected_ecosystems,
        &CancellationToken::default(),
    ) {
        Cancellable::Complete(graph) => Arc::new(graph),
        Cancellable::Cancelled => {
            unreachable!("default cancellation token cannot cancel usage graph construction")
        }
    }
}

#[cfg(test)]
fn build_usage_ranking_graph_with_cancellation(
    analyzer: &dyn IAnalyzer,
    seed_weights: &HashMap<ProjectFile, f64>,
    cancellation: &CancellationToken,
) -> Cancellable<Arc<UsageRankingGraph>> {
    build_usage_ranking_graph_with_kind_and_cancellation(
        analyzer,
        seed_weights,
        WorkspaceUsageGraphKind::Exact,
        cancellation,
    )
}

fn build_usage_ranking_graph_with_kind_and_cancellation(
    analyzer: &dyn IAnalyzer,
    seed_weights: &HashMap<ProjectFile, f64>,
    graph_kind: WorkspaceUsageGraphKind,
    cancellation: &CancellationToken,
) -> Cancellable<Arc<UsageRankingGraph>> {
    let selected_ecosystems: BTreeSet<_> = seed_weights
        .keys()
        .map(|file| UsageEcosystem::of(crate::analyzer::common::language_for_file(file)))
        .collect();
    if profiling::enabled() {
        profiling::note(format!(
            "usage-graph kind={graph_kind:?} selected_ecosystems={}",
            selected_ecosystems
                .iter()
                .map(|ecosystem| ecosystem.as_str())
                .collect::<Vec<_>>()
                .join(",")
        ));
    }

    let Some(cache) = analyzer
        .snapshot_caches()
        .map(|caches| caches.usage_graphs())
    else {
        return build_usage_ranking_graph_uncached(
            analyzer,
            seed_weights,
            &selected_ecosystems,
            graph_kind,
            cancellation,
        )
        .map(Arc::new);
    };

    for _ in 0..2 {
        let source_generations = analyzer.snapshot_source_generations();
        let key = WorkspaceUsageGraphCacheKey::new(
            graph_kind,
            selected_ecosystems.iter().copied(),
            source_generations.clone(),
        );
        let acquisition = cache.acquire(
            key,
            cancellation,
            || match build_usage_ranking_graph_uncached(
                analyzer,
                seed_weights,
                &selected_ecosystems,
                graph_kind,
                cancellation,
            ) {
                Cancellable::Complete(graph) => {
                    WorkspaceUsageGraphCacheBuildOutcome::Complete(graph)
                }
                Cancellable::Cancelled => WorkspaceUsageGraphCacheBuildOutcome::Cancelled,
            },
            || analyzer.snapshot_generations_match(&source_generations),
        );
        match acquisition {
            WorkspaceUsageGraphCacheAcquisition::Ready {
                graph,
                lifecycle,
                wait,
            } => {
                if profiling::enabled() {
                    profiling::note(format!(
                        "usage-graph cache={lifecycle:?} waits={} wait_ms={:.1}",
                        wait.waits,
                        wait.wait_ns as f64 / 1_000_000.0
                    ));
                }
                return Cancellable::Complete(graph);
            }
            WorkspaceUsageGraphCacheAcquisition::Cancelled => return Cancellable::Cancelled,
            WorkspaceUsageGraphCacheAcquisition::Stale => continue,
        }
    }
    Cancellable::Cancelled
}

impl<T> Cancellable<T> {
    fn map<U>(self, map: impl FnOnce(T) -> U) -> Cancellable<U> {
        match self {
            Self::Complete(value) => Cancellable::Complete(map(value)),
            Self::Cancelled => Cancellable::Cancelled,
        }
    }
}

fn build_usage_ranking_graph_uncached(
    analyzer: &dyn IAnalyzer,
    seed_weights: &HashMap<ProjectFile, f64>,
    selected_ecosystems: &BTreeSet<UsageEcosystem>,
    graph_kind: WorkspaceUsageGraphKind,
    cancellation: &CancellationToken,
) -> Cancellable<UsageRankingGraph> {
    if graph_kind == WorkspaceUsageGraphKind::File {
        let graph_outcome = {
            let _scope = profiling::scope("relevance::file_usage_graph_construction");
            build_workspace_file_usage_graph_with_cancellation(
                analyzer,
                selected_ecosystems,
                cancellation,
            )
        };
        return match graph_outcome {
            WorkspaceFileUsageGraphBuildOutcome::Complete(graph) => Cancellable::Complete(graph),
            WorkspaceFileUsageGraphBuildOutcome::Cancelled => Cancellable::Cancelled,
        };
    }
    let Some(catalog) = ({
        let _scope = profiling::scope("relevance::usage_graph_catalog");
        WorkspaceUsageCatalog::build_with_cancellation(analyzer, cancellation)
    }) else {
        return Cancellable::Cancelled;
    };
    let catalog_ecosystems = catalog.ecosystems_for_files(seed_weights.keys());
    debug_assert!(catalog_ecosystems.is_subset(selected_ecosystems));
    build_usage_ranking_graph_for_ecosystems_with_cancellation(
        analyzer,
        catalog,
        &catalog_ecosystems,
        cancellation,
    )
}

fn build_usage_ranking_graph_for_ecosystems_with_cancellation(
    analyzer: &dyn IAnalyzer,
    catalog: WorkspaceUsageCatalog,
    selected_ecosystems: &BTreeSet<UsageEcosystem>,
    cancellation: &CancellationToken,
) -> Cancellable<UsageRankingGraph> {
    let graph_outcome = {
        let _scope = profiling::scope("relevance::usage_graph_construction");
        build_workspace_usage_graph_with_cancellation(
            analyzer,
            catalog,
            selected_ecosystems,
            cancellation,
        )
    };
    let graph = match graph_outcome {
        WorkspaceUsageGraphBuildOutcome::Complete(graph) => graph,
        WorkspaceUsageGraphBuildOutcome::Cancelled => return Cancellable::Cancelled,
    };
    Cancellable::Complete(UsageRankingGraph::from_exact(graph))
}

#[cfg(test)]
fn related_files_by_usage_graph(
    ranking_graph: &UsageRankingGraph,
    seed_weights: &HashMap<ProjectFile, f64>,
    k: usize,
    weights: UsageReferenceWeights,
) -> Vec<FileRelevance> {
    match related_files_by_usage_graph_with_cancellation(
        ranking_graph,
        seed_weights,
        k,
        weights,
        &CancellationToken::default(),
    ) {
        Cancellable::Complete(files) => files,
        Cancellable::Cancelled => {
            unreachable!("default cancellation token cannot cancel usage ranking")
        }
    }
}

fn related_files_by_usage_graph_with_cancellation(
    ranking_graph: &UsageRankingGraph,
    seed_weights: &HashMap<ProjectFile, f64>,
    k: usize,
    weights: UsageReferenceWeights,
    cancellation: &CancellationToken,
) -> Cancellable<Vec<FileRelevance>> {
    if k == 0 {
        return Cancellable::Complete(Vec::new());
    }
    let mut teleport = vec![0.0; ranking_graph.nodes.len()];
    for (file, weight) in seed_weights.iter().filter(|(_, weight)| **weight > 0.0) {
        if cancellation.is_cancelled() {
            return Cancellable::Cancelled;
        }
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
        return Cancellable::Complete(Vec::new());
    }

    if ranking_graph.edges.is_empty() {
        return Cancellable::Complete(Vec::new());
    }
    if profiling::enabled() {
        profiling::note(format!(
            "usage-graph nodes={} edges={}",
            ranking_graph.nodes.len(),
            ranking_graph.edges.len()
        ));
    }
    let mut outgoing = vec![Vec::new(); ranking_graph.nodes.len()];
    for edge in &ranking_graph.edges {
        if cancellation.is_cancelled() {
            return Cancellable::Cancelled;
        }
        outgoing[edge.from].push((edge.to, weights.combine(edge.counts)));
    }
    for neighbors in &mut outgoing {
        neighbors.sort_by_key(|(target, _)| *target);
    }

    let Some(scores) = ({
        let _scope = profiling::scope("relevance::usage_graph_page_rank");
        weighted_page_rank_with_cancellation(&outgoing, &teleport, cancellation)
    }) else {
        return Cancellable::Cancelled;
    };
    let excluded: HashSet<_> = seed_weights.keys().collect();
    let mut file_scores: HashMap<ProjectFile, f64> = HashMap::default();
    {
        let _scope = profiling::scope("relevance::usage_graph_file_aggregation");
        for (node, score) in ranking_graph.nodes.iter().zip(scores) {
            if cancellation.is_cancelled() {
                return Cancellable::Cancelled;
            }
            if node.incomplete || excluded.contains(&node.primary_file) {
                continue;
            }
            *file_scores.entry(node.primary_file.clone()).or_insert(0.0) += score;
        }
    }

    let mut ranked: Vec<_> = file_scores
        .into_iter()
        .filter(|(_, score)| *score > 0.0)
        .map(|(file, score)| FileRelevance { file, score })
        .collect();
    ranked.sort_by(compare_file_relevance);
    ranked.truncate(k);
    Cancellable::Complete(ranked)
}

/// Outcome of computing commit-history data for relevance ranking on a request that may carry a
/// cancellation token. A cold or otherwise unavailable commit-change cache degrades ranking
/// *quality* (files/symbols are returned unranked by recency) but the candidate set itself stays
/// complete; only a genuine cancellation token firing makes the returned set an incomplete subset.
/// Keeping these as distinct variants (rather than folding both into one `bool`) is the fix for
/// issue #1332: a downstream response builder must never re-guess which condition produced a
/// non-`Complete` result, since "cancelled" and "history unavailable" require different wording
/// and different `truncated` semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HistoryRankingStatus {
    /// Commit-history data was available (or none was needed); ranking used the full window.
    Complete,
    /// A cancellation token fired mid-computation; the returned file set may be an incomplete
    /// subset of the true answer.
    Cancelled,
    /// No cancellation occurred, but the commit-change cache was cold (or the lookup otherwise
    /// failed), so files were returned without recency-weighted ranking. The candidate set is
    /// still complete.
    HistoryUnavailable,
}

pub(crate) fn most_important_project_files(
    analyzer: &dyn IAnalyzer,
    candidates: &[ProjectFile],
    top_k: usize,
) -> Vec<ProjectFile> {
    most_important_project_files_with_cancellation(analyzer, candidates, top_k, None).0
}

pub(crate) fn most_important_project_files_with_cancellation(
    analyzer: &dyn IAnalyzer,
    candidates: &[ProjectFile],
    top_k: usize,
    cancellation: Option<&crate::CancellationToken>,
) -> (Vec<ProjectFile>, HistoryRankingStatus) {
    let _cold_scope = profiling::scope("mcp_cold.git_history_relevance_setup");
    let _scope = profiling::scope("relevance::most_important_project_files");
    if top_k == 0 || candidates.is_empty() {
        return (Vec::new(), HistoryRankingStatus::Complete);
    }

    let Some(repo) = GitProjectContext::discover(analyzer.project().root()) else {
        return (Vec::new(), HistoryRankingStatus::Complete);
    };
    let candidate_set: HashSet<_> = candidates.iter().cloned().collect();
    // Peel HEAD to a tree once for the whole call instead of per candidate: a full scan of an
    // untracked candidate set previously re-resolved `HEAD` and re-peeled to a tree once per file.
    let Some(head_tree) = repo.head_tree() else {
        return (Vec::new(), HistoryRankingStatus::Complete);
    };
    if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
        return (Vec::new(), HistoryRankingStatus::Cancelled);
    }
    if !candidate_set
        .iter()
        .any(|file| repo.is_tracked_in_tree(file, &head_tree))
    {
        return (Vec::new(), HistoryRankingStatus::Complete);
    }

    let (changes, history_status) = if cancellation.is_some() {
        match repo.cached_recent_commit_changes(COMMITS_TO_PROCESS) {
            Ok(Some(changes)) => (changes, HistoryRankingStatus::Complete),
            Ok(None) | Err(_) => (Vec::new(), HistoryRankingStatus::HistoryUnavailable),
        }
    } else {
        let Ok(Some(changes)) =
            repo.recent_commit_changes(COMMITS_TO_PROCESS, &CancellationToken::default())
        else {
            return (Vec::new(), HistoryRankingStatus::Complete);
        };
        (changes, HistoryRankingStatus::Complete)
    };
    if changes.is_empty() {
        return (Vec::new(), history_status);
    }

    let mut scores: HashMap<ProjectFile, f64> = HashMap::default();
    let mut canonicalizer = RenameCanonicalizer::default();
    for (index, change) in changes.into_iter().enumerate() {
        if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
            return (Vec::new(), HistoryRankingStatus::Cancelled);
        }
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
    let final_status = if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
        HistoryRankingStatus::Cancelled
    } else {
        history_status
    };
    (
        ranked.into_iter().map(|item| item.file).collect(),
        final_status,
    )
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
    weighted_page_rank_with_cancellation(outgoing, teleport, &CancellationToken::default())
        .expect("default cancellation token cannot cancel PageRank")
}

fn weighted_page_rank_with_cancellation<G>(
    outgoing: &G,
    teleport: &[f64],
    cancellation: &CancellationToken,
) -> Option<Vec<f64>>
where
    G: WeightedAdjacency + ?Sized,
{
    let node_count = outgoing.node_count();
    if node_count == 0 {
        return Some(Vec::new());
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
            if cancellation.is_cancelled() {
                return None;
            }
            let mut total = 0.0;
            outgoing.for_each_edge(source, |_, weight| {
                if weight.is_finite() && weight > 0.0 {
                    total += weight;
                }
            });
            Some(total)
        })
        .collect::<Option<Vec<_>>>()?;

    for _ in 0..MAX_ITERS {
        if cancellation.is_cancelled() {
            return None;
        }
        for (index, teleport_weight) in normalized_teleport.iter().enumerate() {
            next[index] = (1.0 - ALPHA) * teleport_weight;
        }

        let mut dangling_mass = 0.0;
        for source in 0..node_count {
            if cancellation.is_cancelled() {
                return None;
            }
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

    Some(rank)
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
    cancellation: &CancellationToken,
) -> Result<(Vec<FileRelevance>, HistoryRankingStatus), git2::Error> {
    let _scope = profiling::scope("relevance::related_files_by_git");
    reset_git_counters();
    if k == 0 || seed_weights.is_empty() {
        return Ok((Vec::new(), HistoryRankingStatus::Complete));
    }

    let Some(repo) = ({
        let _scope = profiling::scope("relevance::git.discover");
        GitProjectContext::discover(analyzer.project().root())
    }) else {
        return Ok((Vec::new(), HistoryRankingStatus::Complete));
    };
    // Peel HEAD to a tree once for the whole call rather than once per seed (see the matching
    // comment in `most_important_project_files`).
    let Some(head_tree) = repo.head_tree() else {
        return Ok((Vec::new(), HistoryRankingStatus::Complete));
    };
    if !seed_weights
        .keys()
        .any(|seed| repo.is_tracked_in_tree(seed, &head_tree))
    {
        return Ok((Vec::new(), HistoryRankingStatus::Complete));
    }

    let changes = {
        let _scope = profiling::scope("relevance::git.recent_commit_changes");
        repo.recent_commit_changes_for_request(COMMITS_TO_PROCESS, cancellation)
            .map_err(|err| git2::Error::from_str(&err))?
    };
    let Some(changes) = changes else {
        // No history came back for one of two reasons, and they are not the same
        // answer: the caller's budget killed the walk, or this clone cannot serve
        // the walk locally at all.
        return Ok((
            Vec::new(),
            if cancellation.is_cancelled() {
                HistoryRankingStatus::Cancelled
            } else {
                HistoryRankingStatus::HistoryUnavailable
            },
        ));
    };
    if changes.is_empty() {
        return Ok((Vec::new(), HistoryRankingStatus::Complete));
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
            if cancellation.is_cancelled() {
                return Ok((Vec::new(), HistoryRankingStatus::Cancelled));
            }
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
        return Ok((Vec::new(), HistoryRankingStatus::Complete));
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
    Ok((ranked, HistoryRankingStatus::Complete))
}

struct GitCommandOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// Run a `git` child process, abandoning it if `cancellation` fires first.
///
/// Returns `Ok(None)` when the child was killed because the caller's budget
/// expired. `Command::output` cannot express that: it blocks until the child
/// exits, which is why a request-wide deadline could not interrupt the history
/// walk at all before issue #1373.
///
/// Both pipes are drained on helper threads. `git log --name-status` over a
/// thousand commits writes megabytes, and a child that fills a pipe buffer
/// blocks forever while this loop waits for an exit that can no longer happen.
fn run_git_command_with_cancellation(
    command: &mut Command,
    cancellation: &CancellationToken,
) -> Result<Option<GitCommandOutput>, String> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("failed to run git: {err}"))?;

    let mut stdout_pipe = child.stdout.take().expect("git stdout was piped");
    let mut stderr_pipe = child.stderr.take().expect("git stderr was piped");
    let stdout_reader = std::thread::spawn(move || {
        let mut buffer = Vec::new();
        stdout_pipe.read_to_end(&mut buffer).map(|_| buffer)
    });
    let stderr_reader = std::thread::spawn(move || {
        let mut buffer = Vec::new();
        stderr_pipe.read_to_end(&mut buffer).map(|_| buffer)
    });

    let mut cancelled = false;
    let status = loop {
        match child
            .try_wait()
            .map_err(|err| format!("failed to wait for git: {err}"))?
        {
            Some(status) => break status,
            None => {
                if cancellation.is_cancelled() {
                    match child.kill() {
                        Ok(()) => {}
                        // The child exited between `try_wait` and here. That is
                        // the state the kill was asking for, and the `wait`
                        // below still reaps it.
                        Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {}
                        Err(err) => return Err(format!("failed to stop git: {err}")),
                    }
                    cancelled = true;
                    break child
                        .wait()
                        .map_err(|err| format!("failed to reap git: {err}"))?;
                }
                std::thread::sleep(GIT_SUBPROCESS_POLL_INTERVAL);
            }
        }
    };

    let stdout = stdout_reader
        .join()
        .map_err(|_| "git stdout reader panicked".to_string())?
        .map_err(|err| format!("failed to read git stdout: {err}"))?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| "git stderr reader panicked".to_string())?
        .map_err(|err| format!("failed to read git stderr: {err}"))?;

    if cancelled {
        return Ok(None);
    }
    Ok(Some(GitCommandOutput {
        status,
        stdout,
        stderr,
    }))
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
    /// The ordered recent-commit OID list (topo-order, first-parent, as produced by
    /// `git rev-list -n <limit> HEAD`), keyed by the peeled HEAD commit OID it was computed for.
    /// A cheap libgit2 HEAD-peel (no subprocess) on each call is compared against this key; on a
    /// match the `git rev-list` spawn is skipped entirely. A new commit moves HEAD to a new OID,
    /// which misses the cached key and forces a refill, so the list can never be observed stale.
    recent_oids: Mutex<Option<CachedRecentOids>>,
    /// Counts rev-list refills performed FOR THIS CACHE, so tests can assert cache-hit
    /// behavior deterministically under parallel test execution (the process-global
    /// GIT_REV_LIST_SPAWNS counter is shared across concurrently-running tests and is
    /// observability-only).
    recent_oid_fills: AtomicUsize,
}

struct CachedRecentOids {
    head: Oid,
    oids: Arc<Vec<Oid>>,
    /// True once `oids` is known to hold every first-parent commit reachable from `head` (the
    /// fill that produced it asked `git rev-list` for `limit` commits and got back fewer than
    /// that, so there is nothing left to discover for this HEAD no matter what `limit` is
    /// requested next). Repos with fewer than `COMMITS_TO_PROCESS` total first-parent commits can
    /// never reach `oids.len() >= limit` for the constant the MCP path requests, so without this
    /// flag they were permanently cold on that path (issue #1333) even though a single fill had
    /// already captured all of their history.
    exhausted: bool,
}

impl RepoCommitChangeCache {
    fn new(max_entries: u64) -> Self {
        Self {
            commits: Cache::builder().max_capacity(max_entries.max(1)).build(),
            fill_lock: Mutex::new(()),
            fill_commits_scanned: AtomicUsize::new(0),
            recent_oids: Mutex::new(None),
            recent_oid_fills: AtomicUsize::new(0),
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

/// Discovered repo root cache, keyed by the caller-supplied (uncanonicalized) workspace root.
/// `Repository::discover`'s upward directory walk plus the workdir canonicalize only need to run
/// once per workspace; after that we just `Repository::open` the known path each call, which is
/// cheap (`git2::Repository` is not `Sync`, so we cannot cache the `Repository` handle itself
/// across calls/threads, only the path it lives at).
fn repo_root_cache() -> &'static Mutex<HashMap<PathBuf, PathBuf>> {
    static CACHE: OnceLock<Mutex<HashMap<PathBuf, PathBuf>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::default()))
}

#[cfg(test)]
fn clear_repo_root_cache_for_project(project_root: &Path) {
    repo_root_cache()
        .lock()
        .expect("repo root cache mutex")
        .remove(project_root);
}

impl GitProjectContext {
    fn discover(project_root: &Path) -> Option<Self> {
        // Keep the caller's project_root as-given so ProjectFiles we build from
        // git output compare equal to ProjectFiles supplied by the analyzer.
        // Canonicalize only for repo discovery / prefix computation, since on
        // macOS temp dirs come in via /var -> /private/var symlinks.
        let project_root = project_root.to_path_buf();
        let canonical_project = project_root.canonicalize().ok()?;

        let cached_repo_root = repo_root_cache()
            .lock()
            .expect("repo root cache mutex")
            .get(&project_root)
            .cloned();
        if let Some(cached_repo_root) = cached_repo_root
            && canonical_project.starts_with(&cached_repo_root)
            && let Ok(repo) = Repository::open(&cached_repo_root)
        {
            let repo_prefix = canonical_project
                .strip_prefix(&cached_repo_root)
                .ok()?
                .to_path_buf();
            return Some(Self {
                repo,
                repo_root: cached_repo_root,
                project_root,
                repo_prefix,
            });
        }
        // Cached path missing, out of scope for this project root, or no longer opens as a repo
        // (e.g. `.git` was removed or replaced): fall through to a fresh discover below, which
        // will also refresh the cache entry.

        let repo = Repository::discover(&canonical_project).ok()?;
        let repo_root = repo.workdir()?.canonicalize().ok()?;
        if !canonical_project.starts_with(&repo_root) {
            return None;
        }

        repo_root_cache()
            .lock()
            .expect("repo root cache mutex")
            .insert(project_root.clone(), repo_root.clone());

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

    /// Peel HEAD to its tree once per call. Callers that need to test several candidates for
    /// HEAD-tracked status should hoist this once and reuse it (`is_tracked_in_tree`) rather than
    /// re-resolving `HEAD` and re-peeling per candidate.
    ///
    /// We intentionally stop at this per-call hoist rather than also caching a cross-call
    /// tracked-path set keyed by HEAD OID: callers only ever need the first tracked match
    /// (`Iterator::any`), so the expensive case — no candidate is tracked — still only pays one
    /// HEAD peel plus one `Tree::get_path` (bounded by path depth, not repo size) per candidate;
    /// a full recursive tree walk to materialize every tracked path up front would spend more
    /// work than it saves and would hold an unbounded-by-repo-size path set in memory for
    /// large repos.
    fn head_tree(&self) -> Option<git2::Tree<'_>> {
        self.repo.head().ok()?.peel_to_tree().ok()
    }

    fn is_tracked_in_tree(&self, file: &ProjectFile, tree: &git2::Tree<'_>) -> bool {
        let repo_rel = self.project_rel_to_repo_rel(file.rel_path());
        tree.get_path(&repo_rel).is_ok()
    }

    /// The commit OID HEAD currently resolves to, via libgit2 (no subprocess). `None` for an
    /// unborn HEAD (no commits yet); detached HEAD peels the same as an attached branch.
    fn head_commit_oid(&self) -> Option<Oid> {
        self.repo.head().ok()?.peel_to_commit().ok().map(|c| c.id())
    }

    fn recent_commit_changes(
        &self,
        limit: usize,
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<CommitChange>>, String> {
        let cache = repo_commit_change_cache(&self.repo_root);
        self.recent_commit_changes_with_cache(limit, &cache, cancellation)
    }

    /// Return commit-change history only when both cache layers are already
    /// warm. Interactive cancellable queries use this path so ranking never
    /// starts an uninterruptible Git subprocess; a cold cache is a truthful
    /// incomplete ranking rather than a latency-budget violation.
    ///
    /// "Warm" means the cached OID list either already covers `limit` commits, or (issue #1333)
    /// is known to hold every first-parent commit reachable from `head` because a prior fill
    /// asked for at least `limit` and got back fewer — i.e. the effective warm threshold is
    /// `min(total_commits, limit)`, not `limit` itself. Without the second clause, any repo with
    /// fewer than `limit` total first-parent commits could never satisfy `oids.len() >= limit`
    /// and would report cold forever, even after a fill had captured its entire history.
    fn cached_recent_commit_changes(
        &self,
        limit: usize,
    ) -> Result<Option<Vec<CommitChange>>, String> {
        let cache = repo_commit_change_cache(&self.repo_root);
        let Some(head) = self.head_commit_oid() else {
            return Ok(Some(Vec::new()));
        };
        let ordered_oids = {
            let guard = cache.recent_oids.lock().expect("recent oids mutex");
            let Some(cached) = guard.as_ref().filter(|cached| {
                cached.head == head && (cached.oids.len() >= limit || cached.exhausted)
            }) else {
                return Ok(None);
            };
            cached.oids[..cached.oids.len().min(limit)].to_vec()
        };
        match self.collect_cached_commit_changes(&ordered_oids, &cache) {
            Ok(changes) => Ok(Some(changes)),
            Err(_) => Ok(None),
        }
    }

    /// Recent commit changes for a request that carries a time budget.
    ///
    /// A partial clone of a network remote is served from the warm cache only.
    /// Filling it would make Git fetch absent historical objects from the
    /// promisor remote one at a time, which is unbounded network work that no
    /// interactive budget can usefully cover (issue #1373). Reporting the
    /// history as unavailable lets the caller rank from the local import graph
    /// instead of spending the whole request, and keeps the answer a function
    /// of what this clone stores rather than of how the network behaved. A
    /// partial clone whose promisor remote is a local path is exempt: its lazy
    /// fetches read the source repository on the same filesystem, so the walk
    /// stays disk-bound like any ordinary clone.
    fn recent_commit_changes_for_request(
        &self,
        limit: usize,
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<CommitChange>>, String> {
        if self.has_network_promisor_remote() {
            return self.cached_recent_commit_changes(limit);
        }
        self.recent_commit_changes(limit, cancellation)
    }

    fn recent_commit_changes_with_cache(
        &self,
        limit: usize,
        cache: &RepoCommitChangeCache,
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<CommitChange>>, String> {
        let Some(ordered_oids) = self.recent_commit_oids_cached(limit, cache, cancellation)? else {
            return Ok(None);
        };
        if ordered_oids.is_empty() {
            return Ok(Some(Vec::new()));
        }

        if self
            .fill_missing_commit_ranges(&ordered_oids, cache, cancellation)?
            .is_none()
        {
            return Ok(None);
        }
        cache.commits.run_pending_tasks();
        self.collect_cached_commit_changes(&ordered_oids, cache)
            .map(Some)
    }

    #[cfg(test)]
    fn recent_commit_changes_uncached(&self, limit: usize) -> Result<Vec<CommitChange>, String> {
        Ok(self
            .run_git_log_command(limit, None, &CancellationToken::default())?
            .expect("an uncancelled token cannot interrupt the history walk"))
    }

    /// Returns the ordered recent-commit OID list, reusing the cache entry keyed by the current
    /// peeled HEAD OID when it matches and already covers at least `limit` commits. On a HEAD
    /// change (new commit, checkout, reset, …) or a first/insufficient cache entry, this refills
    /// via `recent_commit_oids` (the `git rev-list` subprocess) and replaces the cached entry.
    fn recent_commit_oids_cached(
        &self,
        limit: usize,
        cache: &RepoCommitChangeCache,
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<Oid>>, String> {
        let Some(head_oid) = self.head_commit_oid() else {
            // Unborn HEAD (or otherwise unresolvable): no stable key to cache against. Fall back
            // to the direct, uncached path, which preserves today's error behavior (git itself
            // fails to resolve "HEAD" for an unborn branch).
            return self.recent_commit_oids(limit, cancellation);
        };

        {
            let guard = cache.recent_oids.lock().expect("recent oids mutex");
            if let Some(cached) = guard.as_ref()
                && cached.head == head_oid
                && (cached.oids.len() >= limit || cached.exhausted)
            {
                return Ok(Some(cached.oids[..cached.oids.len().min(limit)].to_vec()));
            }
        }

        cache.recent_oid_fills.fetch_add(1, Ordering::Relaxed);
        let Some(refilled_oids) = self.recent_commit_oids(limit, cancellation)? else {
            return Ok(None);
        };
        // Fewer OIDs came back than were asked for: `git rev-list` walked first-parent history to
        // its root and stopped there, so this list is known-complete for `head_oid` regardless of
        // what `limit` a later caller requests (see `CachedRecentOids::exhausted`, issue #1333).
        let exhausted = refilled_oids.len() < limit;
        let refilled = Arc::new(refilled_oids);
        *cache.recent_oids.lock().expect("recent oids mutex") = Some(CachedRecentOids {
            head: head_oid,
            oids: Arc::clone(&refilled),
            exhausted,
        });
        Ok(Some((*refilled).clone()))
    }

    fn recent_commit_oids(
        &self,
        limit: usize,
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<Oid>>, String> {
        GIT_REV_LIST_SPAWNS.fetch_add(1, Ordering::Relaxed);
        let mut command = Command::new("git");
        command
            .arg("-C")
            .arg(&self.repo_root)
            .arg("rev-list")
            .arg("--topo-order")
            .arg("--first-parent")
            .arg("-n")
            .arg(limit.to_string())
            .arg("HEAD");

        let Some(output) = run_git_command_with_cancellation(&mut command, cancellation)? else {
            return Ok(None);
        };
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
            .collect::<Result<Vec<_>, _>>()
            .map(Some)
    }

    fn fill_missing_commit_ranges(
        &self,
        ordered_oids: &[Oid],
        cache: &RepoCommitChangeCache,
        cancellation: &CancellationToken,
    ) -> Result<Option<()>, String> {
        let mut missing_ranges = missing_commit_ranges(ordered_oids, &cache.commits);
        if missing_ranges.is_empty() {
            return Ok(Some(()));
        }

        let _guard = cache.fill_lock.lock().expect("repo fill mutex");
        missing_ranges = missing_commit_ranges(ordered_oids, &cache.commits);
        for range in missing_ranges {
            if self
                .populate_commit_range(ordered_oids, range, cache, cancellation)?
                .is_none()
            {
                return Ok(None);
            }
        }

        Ok(Some(()))
    }

    fn populate_commit_range(
        &self,
        ordered_oids: &[Oid],
        range: MissingCommitRange,
        cache: &RepoCommitChangeCache,
        cancellation: &CancellationToken,
    ) -> Result<Option<()>, String> {
        let newest = ordered_oids[range.start];
        let oldest = ordered_oids[range.end];
        let range_len = range.end - range.start + 1;
        let Some(changes) =
            self.run_git_log_command(range_len, Some((newest, oldest)), cancellation)?
        else {
            return Ok(None);
        };
        cache
            .fill_commits_scanned
            .fetch_add(changes.len(), Ordering::Relaxed);

        for change in changes {
            cache.commits.insert(change.id, Arc::new(change));
        }

        Ok(Some(()))
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
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<CommitChange>>, String> {
        let mut command = Command::new("git");
        command
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
            });

        let Some(output) = run_git_command_with_cancellation(&mut command, cancellation)? else {
            return Ok(None);
        };
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("git log exited with {}: {stderr}", output.status));
        }

        Ok(Some(self.parse_git_log_name_status(&output.stdout)))
    }

    fn first_parent_oid(&self, oid: Oid) -> Option<Oid> {
        self.repo.find_commit(oid).ok()?.parent_ids().next()
    }

    /// Whether this repository resolves missing objects through a promisor
    /// remote reached over the network, i.e. it is a partial clone such as
    /// `git clone --filter=blob:none` of a network URL.
    ///
    /// The distinction decides whether walking recent history is local work.
    /// In an ordinary clone every historical object is on disk and the walk is
    /// disk-bound and bounded by repository size. In a partial clone of a
    /// network remote the same walk makes Git fetch each absent object it
    /// needs from the remote, one round trip at a time, so its cost is set by
    /// network latency and the number of missing objects rather than by
    /// anything the caller can see. Issue #1373 measured that difference as
    /// 1.2s versus 8m18s over the same thousand commits.
    ///
    /// A promisor remote whose URL is a local path (`file://` or a filesystem
    /// path, as the benchmark harness writes when it blobless-clones a local
    /// fixture) does not count: its lazy fetches read the source repository on
    /// the same filesystem, so the walk remains disk-bound and the honest
    /// answer is the history itself, not `HistoryUnavailable`.
    fn has_network_promisor_remote(&self) -> bool {
        let config = self
            .repo
            .config()
            .expect("an opened repository exposes its configuration");
        let remotes = self
            .repo
            .remotes()
            .expect("an opened repository lists its remotes");
        remotes.iter().flatten().any(|remote| {
            config
                .get_bool(&format!("remote.{remote}.promisor"))
                .unwrap_or(false)
                && !Self::remote_url_is_local(&config, remote)
        })
    }

    /// Whether a remote's URL names the local filesystem. Git's local
    /// transports are `file://` URLs and plain paths (absolute, or explicitly
    /// relative with `./`/`../`). An scp-style `host:path` or any scheme URL
    /// is network; a missing URL keeps the conservative network assumption.
    fn remote_url_is_local(config: &git2::Config, remote: &str) -> bool {
        let Ok(url) = config.get_string(&format!("remote.{remote}.url")) else {
            return false;
        };
        url.starts_with("file://")
            || Path::new(&url).is_absolute()
            || url.starts_with("./")
            || url.starts_with("../")
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
        UsageReferenceWeights, clear_repo_commit_change_cache_for_root,
        clear_repo_root_cache_for_project, commit_age_weight, most_important_project_files,
        most_relevant_project_files_with_half_life, related_files_by_git, related_files_by_imports,
        repo_commit_change_cache, repo_root_cache, weighted_page_rank,
    };
    use crate::analyzer::usages::inverted_edges::UsageReferenceCounts;
    use crate::analyzer::{
        AnalyzerDelegate, JavaAnalyzer, Language, MultiAnalyzer, ProjectFile, PythonAnalyzer,
        RustAnalyzer, TestProject,
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
    fn issue_1304_weighted_page_rank_stops_on_cancellation() {
        let cancellation = crate::CancellationToken::cancel_after_checks_for_test(2);

        let scores = super::weighted_page_rank_with_cancellation(
            &[vec![(1, 1.0)], vec![(0, 1.0)]],
            &[1.0, 0.0],
            &cancellation,
        );

        assert!(scores.is_none());
    }

    #[test]
    fn issue_1304_cancelled_usage_graph_is_a_typed_outcome() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let seed = write_file(
            root,
            "test/Seed.java",
            "package test; public class Seed { void run() { Target.work(); } }",
        );
        write_file(
            root,
            "test/Target.java",
            "package test; public class Target { static void work() {} }",
        );
        let analyzer = java_analyzer(root);
        let cancellation = crate::CancellationToken::cancel_after_checks_for_test(3);

        let outcome = super::most_relevant_project_files_with_ranking_mode_and_cancellation(
            &analyzer,
            &[(seed, 1.0)],
            1,
            Some(DEFAULT_RECENCY_HALF_LIFE),
            super::MostRelevantFilesRankingMode::UsageGraph,
            &cancellation,
        );

        assert!(matches!(
            outcome,
            super::MostRelevantProjectFilesOutcome::Cancelled
        ));
    }

    #[test]
    fn issue_1304_seed_ecosystem_pruning_preserves_exact_ranking() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let rust_seed = write_file(
            root,
            "src/caller.rs",
            "use crate::target::target;\npub fn seed() { target(); }\n",
        );
        write_file(root, "src/lib.rs", "pub mod caller;\npub mod target;\n");
        let rust_target = write_file(
            root,
            "src/target.rs",
            "pub fn target() { leaf(); }\npub fn leaf() {}\n",
        );
        write_file(
            root,
            "py_source.py",
            "from py_target import target\n\ndef source():\n    target()\n",
        );
        write_file(root, "py_target.py", "def target():\n    pass\n");

        let project = TestProject::new(root.to_path_buf(), Language::Rust);
        let analyzer = MultiAnalyzer::new(BTreeMap::from([
            (
                Language::Python,
                AnalyzerDelegate::Python(PythonAnalyzer::from_project(project.clone())),
            ),
            (
                Language::Rust,
                AnalyzerDelegate::Rust(RustAnalyzer::from_project(project)),
            ),
        ]));
        let seed_weights = hash_map([(rust_seed.clone(), 1.0)]);

        let selected_graph = match super::build_usage_ranking_graph_with_cancellation(
            &analyzer,
            &seed_weights,
            &crate::CancellationToken::default(),
        ) {
            super::Cancellable::Complete(graph) => graph,
            super::Cancellable::Cancelled => panic!("uncancelled selected graph build"),
        };
        let warm_graph = match super::build_usage_ranking_graph_with_cancellation(
            &analyzer,
            &seed_weights,
            &crate::CancellationToken::default(),
        ) {
            super::Cancellable::Complete(graph) => graph,
            super::Cancellable::Cancelled => panic!("uncancelled warm graph acquisition"),
        };
        assert!(Arc::ptr_eq(&selected_graph, &warm_graph));
        let all_graph = super::build_usage_ranking_graph(&analyzer);

        assert_eq!(
            vec![crate::analyzer::usages::workspace_graph::UsageEcosystem::Rust],
            selected_graph.resolved_ecosystems
        );
        assert!(
            all_graph
                .resolved_ecosystems
                .contains(&crate::analyzer::usages::workspace_graph::UsageEcosystem::Python)
        );
        let selected = super::related_files_by_usage_graph(
            &selected_graph,
            &seed_weights,
            10,
            UsageReferenceWeights::CALIBRATED,
        );
        let all = super::related_files_by_usage_graph(
            &all_graph,
            &seed_weights,
            10,
            UsageReferenceWeights::CALIBRATED,
        );

        assert_eq!(all, selected);
        assert!(
            selected
                .iter()
                .any(|candidate| candidate.file == rust_target)
        );
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
        let uncancelled = crate::CancellationToken::default();
        let (uniform_scores, _) =
            related_files_by_git(&analyzer, &seed_weights, 10, None, &uncancelled).unwrap();
        let (recency_scores, _) =
            related_files_by_git(&analyzer, &seed_weights, 10, Some(10.0), &uncancelled).unwrap();

        let uniform_old = file_by_name(&uniform_scores, "OldTarget.java")
            .expect("uniform old target score")
            .score;
        let recency_old = file_by_name(&recency_scores, "OldTarget.java")
            .expect("recency old target score")
            .score;

        assert!(recency_old < uniform_old, "{recency_old} !< {uniform_old}");
    }

    /// Build a repository whose `Seed.java` and `Target.java` co-change, so the
    /// git leg has a co-change edge to find (or to be seen not looking for).
    fn cochanging_seed_and_target_repo(root: &Path) -> Repository {
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
        repo
    }

    /// A partial clone must not start a history fill for a request that carries a
    /// budget: the walk would make Git refetch absent objects from the promisor
    /// remote one round trip at a time (1.2s versus 8m18s on the corpus in
    /// issue #1373). The truthful answer is that history is unavailable.
    #[test]
    fn issue_1373_partial_clone_reports_history_unavailable_without_filling() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let repo = cochanging_seed_and_target_repo(root);
        // The marker `git clone --filter=blob:none` writes for its promisor remote.
        repo.remote("origin", "https://example.invalid/repo.git")
            .unwrap();
        repo.config()
            .unwrap()
            .set_bool("remote.origin.promisor", true)
            .unwrap();

        clear_repo_commit_change_cache_for_root(root);
        let analyzer = java_analyzer(root);
        let seed = ProjectFile::new(root.to_path_buf(), "Seed.java");
        let (candidates, status) = related_files_by_git(
            &analyzer,
            &hash_map([(seed, 1.0)]),
            10,
            Some(DEFAULT_RECENCY_HALF_LIFE),
            &crate::CancellationToken::default(),
        )
        .unwrap();

        assert_eq!(super::HistoryRankingStatus::HistoryUnavailable, status);
        assert!(candidates.is_empty(), "{candidates:?}");
        // Nothing was fetched or scanned: the cold cache was reported, not filled.
        let cache = repo_commit_change_cache(root);
        assert_eq!(0, cache.fill_commits_scanned.load(Ordering::Relaxed));
        assert_eq!(0, cache.recent_oid_fills.load(Ordering::Relaxed));
    }

    /// A promisor remote that is a local path keeps the history walk: lazy
    /// fetches from it are filesystem reads, not the unbounded network work
    /// the #1373 guard exists for. This is exactly the clone the benchmark
    /// harness produces when it blobless-clones a local fixture repository.
    #[test]
    fn local_promisor_partial_clone_still_ranks_by_commit_history() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let repo = cochanging_seed_and_target_repo(root);
        repo.remote("origin", &root.display().to_string()).unwrap();
        repo.config()
            .unwrap()
            .set_bool("remote.origin.promisor", true)
            .unwrap();

        clear_repo_commit_change_cache_for_root(root);
        let analyzer = java_analyzer(root);
        let seed = ProjectFile::new(root.to_path_buf(), "Seed.java");
        let (candidates, status) = related_files_by_git(
            &analyzer,
            &hash_map([(seed, 1.0)]),
            10,
            Some(DEFAULT_RECENCY_HALF_LIFE),
            &crate::CancellationToken::default(),
        )
        .unwrap();

        assert_eq!(super::HistoryRankingStatus::Complete, status);
        assert!(
            file_by_name(&candidates, "Target.java").is_some(),
            "{candidates:?}"
        );
    }

    /// The partial-clone rule keys off the clone, so an ordinary repository keeps
    /// filling its history and ranking at full quality.
    #[test]
    fn issue_1373_ordinary_clone_still_ranks_by_commit_history() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        cochanging_seed_and_target_repo(root);

        clear_repo_commit_change_cache_for_root(root);
        let analyzer = java_analyzer(root);
        let seed = ProjectFile::new(root.to_path_buf(), "Seed.java");
        let (candidates, status) = related_files_by_git(
            &analyzer,
            &hash_map([(seed, 1.0)]),
            10,
            Some(DEFAULT_RECENCY_HALF_LIFE),
            &crate::CancellationToken::default(),
        )
        .unwrap();

        assert_eq!(super::HistoryRankingStatus::Complete, status);
        assert!(
            file_by_name(&candidates, "Target.java").is_some(),
            "{candidates:?}"
        );
    }

    /// The history leg is cancellable end to end. Before issue #1373 the walk ran
    /// inside a blocking `Command::output`, so a request-wide deadline could not
    /// stop it and the tool blew its budget instead of reporting the interruption.
    #[test]
    fn issue_1373_cancelled_request_stops_the_history_walk() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        cochanging_seed_and_target_repo(root);

        clear_repo_commit_change_cache_for_root(root);
        let analyzer = java_analyzer(root);
        let seed = ProjectFile::new(root.to_path_buf(), "Seed.java");
        let cancelled = crate::CancellationToken::default();
        cancelled.cancel();
        let (candidates, status) = related_files_by_git(
            &analyzer,
            &hash_map([(seed, 1.0)]),
            10,
            Some(DEFAULT_RECENCY_HALF_LIFE),
            &cancelled,
        )
        .unwrap();

        assert_eq!(super::HistoryRankingStatus::Cancelled, status);
        assert!(candidates.is_empty(), "{candidates:?}");
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
        let (uniform_scores, _) = related_files_by_git(
            &analyzer,
            &hash_map([(seed, 1.0)]),
            10,
            None,
            &crate::CancellationToken::default(),
        )
        .unwrap();

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
        let (uniform_scores, _) = related_files_by_git(
            &analyzer,
            &hash_map([(seed.clone(), 1.0)]),
            10,
            None,
            &crate::CancellationToken::default(),
        )
        .unwrap();
        let (huge_half_life_scores, _) = related_files_by_git(
            &analyzer,
            &hash_map([(seed, 1.0)]),
            10,
            Some(1.0e9),
            &crate::CancellationToken::default(),
        )
        .unwrap();

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
        let (default_ranked, _) = most_relevant_project_files_with_half_life(
            &analyzer,
            &[(ProjectFile::new(root.to_path_buf(), "Seed.java"), 1.0)],
            2,
            Some(DEFAULT_RECENCY_HALF_LIFE),
            &crate::CancellationToken::default(),
        );
        let (legacy_ranked, _) = most_relevant_project_files_with_half_life(
            &analyzer,
            &[(ProjectFile::new(root.to_path_buf(), "Seed.java"), 1.0)],
            2,
            None,
            &crate::CancellationToken::default(),
        );
        let (sharp_ranked, _) = most_relevant_project_files_with_half_life(
            &analyzer,
            &[(ProjectFile::new(root.to_path_buf(), "Seed.java"), 1.0)],
            2,
            Some(1.0),
            &crate::CancellationToken::default(),
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
            .recent_commit_changes_with_cache(10, &cache, &crate::CancellationToken::default())
            .unwrap()
            .expect("an uncancelled token cannot interrupt the history walk");

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
            .recent_commit_changes_with_cache(10, &cache, &crate::CancellationToken::default())
            .unwrap()
            .expect("an uncancelled token cannot interrupt the history walk");
        assert_eq!(3, cache.fill_commits_scanned.load(Ordering::Relaxed));

        context
            .recent_commit_changes_with_cache(10, &cache, &crate::CancellationToken::default())
            .unwrap()
            .expect("an uncancelled token cannot interrupt the history walk");
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
            .recent_commit_changes_with_cache(10, &cache, &crate::CancellationToken::default())
            .unwrap()
            .expect("an uncancelled token cannot interrupt the history walk");
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
        let ordered_oids = context
            .recent_commit_oids(10, &crate::CancellationToken::default())
            .unwrap()
            .expect("an uncancelled token cannot interrupt the rev-list walk");
        let last_range = super::MissingCommitRange {
            start: ordered_oids.len() - 2,
            end: ordered_oids.len() - 1,
        };
        context
            .populate_commit_range(
                &ordered_oids,
                last_range,
                &cache,
                &crate::CancellationToken::default(),
            )
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
                &crate::CancellationToken::default(),
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
                &crate::CancellationToken::default(),
            );
        }
        let warm_elapsed = warm_started.elapsed();

        eprintln!(
            "benchmark_repeat_calls_with_cached_git_history cold_28={:.3}s warm_28={:.3}s",
            cold_elapsed.as_secs_f64(),
            warm_elapsed.as_secs_f64()
        );
    }

    /// M5 ranking-identity regression: repeating the same call against an unchanged HEAD must
    /// reuse the HEAD-keyed commit-OID cache and repo-root cache added in M5, and produce the
    /// exact same ranking. A regression here would mean the cache is returning a different (or
    /// stale/truncated) commit window than a fresh, uncached run would.
    #[test]
    fn ranking_output_identical_across_repeated_calls_with_warm_git_caches() {
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
        commit_paths_at(&repo, "seed+target", &["Seed.java", "Target.java"], &[], 2);
        commit_paths_at(&repo, "seed+helper", &["Seed.java", "Helper.java"], &[], 3);

        let analyzer = java_analyzer(root);
        let seeds = [(ProjectFile::new(root.to_path_buf(), "Seed.java"), 1.0)];

        clear_repo_commit_change_cache_for_root(root);
        clear_repo_root_cache_for_project(root);

        // First call: cold. Populates both the repo-root cache and the HEAD-keyed commit-OID
        // cache (plus the pre-existing per-commit change cache).
        let (first, _) = most_relevant_project_files_with_half_life(
            &analyzer,
            &seeds,
            5,
            Some(DEFAULT_RECENCY_HALF_LIFE),
            &crate::CancellationToken::default(),
        );
        // Second call: warm. HEAD has not moved, so this must hit every M5 cache.
        let (second, _) = most_relevant_project_files_with_half_life(
            &analyzer,
            &seeds,
            5,
            Some(DEFAULT_RECENCY_HALF_LIFE),
            &crate::CancellationToken::default(),
        );

        assert!(
            !first.is_empty(),
            "fixture should produce a non-empty ranking"
        );
        assert_eq!(
            first, second,
            "cached and re-cached rankings must be identical"
        );
    }

    /// M5 invalidation proof: a new commit moves HEAD to a new OID, which must miss the cached
    /// key and force a refill, so the next call reflects the new commit rather than serving a
    /// stale cached commit-OID list.
    #[test]
    fn most_important_files_reflect_commit_added_after_first_call() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let seed = write_file(root, "Seed.java", "class Seed {}");
        let target = write_file(root, "Target.java", "class Target {}");
        let other = write_file(root, "Other.java", "class Other {}");

        let repo = Repository::init(root).unwrap();
        commit_paths_at(&repo, "seed+target", &["Seed.java", "Target.java"], &[], 1);

        let analyzer = java_analyzer(root);
        let candidates = vec![seed.clone(), target.clone(), other.clone()];

        clear_repo_commit_change_cache_for_root(root);
        clear_repo_root_cache_for_project(root);

        let before = most_important_project_files(&analyzer, &candidates, 3);
        assert!(
            before.contains(&seed) && before.contains(&target),
            "files touched by the only commit so far should rank"
        );
        assert!(
            !before.contains(&other),
            "Other.java has not been committed yet and must not appear"
        );

        // HEAD moves: a brand new commit touches the previously-untouched file. If the OID
        // cache were stale, this call would still see only the first commit.
        fs::write(
            root.join("Other.java"),
            "class Other { int value() { return 1; } }",
        )
        .unwrap();
        commit_paths_at(&repo, "other only", &["Other.java"], &[], 2);

        let after = most_important_project_files(&analyzer, &candidates, 3);
        assert!(
            after.contains(&other),
            "the new commit must be visible on the very next call: {after:?}"
        );
        assert_ne!(before, after);
    }

    /// M5 unit test: `recent_commit_oids_cached` must reuse the cached list (and avoid spawning
    /// `git rev-list` again) when HEAD is unchanged, while still matching what an uncached call
    /// would return.
    #[test]
    fn recent_commit_oids_cached_matches_uncached_and_skips_second_spawn() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        write_file(root, "File.java", "class File {}");
        let repo = Repository::init(root).unwrap();
        commit_paths_at(&repo, "initial", &["File.java"], &[], 1);
        for index in 0..4 {
            fs::write(
                root.join("File.java"),
                format!("class File {{ int v{index}() {{ return {index}; }} }}"),
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
        let uncached = context
            .recent_commit_oids(3, &crate::CancellationToken::default())
            .unwrap()
            .expect("an uncancelled token cannot interrupt the rev-list walk");

        let cache = RepoCommitChangeCache::new(64);
        let cached_first = context
            .recent_commit_oids_cached(3, &cache, &crate::CancellationToken::default())
            .unwrap()
            .expect("an uncancelled token cannot interrupt the rev-list walk");
        assert_eq!(1, cache.recent_oid_fills.load(Ordering::Relaxed));
        assert_eq!(uncached, cached_first);

        // HEAD unchanged: the second call must reuse the cached list without spawning again.
        let cached_second = context
            .recent_commit_oids_cached(3, &cache, &crate::CancellationToken::default())
            .unwrap()
            .expect("an uncancelled token cannot interrupt the rev-list walk");
        assert_eq!(1, cache.recent_oid_fills.load(Ordering::Relaxed));
        assert_eq!(cached_first, cached_second);

        // A smaller limit is served from the same cached entry (a prefix slice), still with no
        // extra spawn.
        let cached_smaller = context
            .recent_commit_oids_cached(2, &cache, &crate::CancellationToken::default())
            .unwrap()
            .expect("an uncancelled token cannot interrupt the rev-list walk");
        assert_eq!(1, cache.recent_oid_fills.load(Ordering::Relaxed));
        assert_eq!(&cached_first[..2], cached_smaller.as_slice());

        // A larger limit than what is cached forces exactly one more refill.
        let cached_larger = context
            .recent_commit_oids_cached(5, &cache, &crate::CancellationToken::default())
            .unwrap()
            .expect("an uncancelled token cannot interrupt the rev-list walk");
        assert_eq!(2, cache.recent_oid_fills.load(Ordering::Relaxed));
        assert_eq!(5, cached_larger.len());
    }

    #[test]
    fn issue_1228_cancellable_git_ranking_never_spawns_on_a_cold_cache() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        write_file(root, "File.java", "class File {}");
        let repo = Repository::init(root).unwrap();
        commit_paths_at(&repo, "initial", &["File.java"], &[], 1);
        clear_repo_commit_change_cache_for_root(root);
        clear_repo_root_cache_for_project(root);
        let context = git_context(root);

        let cached = context.cached_recent_commit_changes(1).unwrap();

        assert!(cached.is_none());
        // Scoped to this repository's own fill counter rather than the process-wide
        // `GIT_REV_LIST_SPAWNS`: that static is shared with every other test running
        // in parallel, so reading it here measured other tests' subprocesses.
        assert_eq!(
            0,
            repo_commit_change_cache(root)
                .recent_oid_fills
                .load(Ordering::Relaxed)
        );
    }

    /// M5 unit test for the discover repo-root cache's fallback path: a poisoned/stale cache
    /// entry must not be trusted blind. `discover` must detect the failed `Repository::open`,
    /// fall back to a fresh `Repository::discover`, and refresh the cache entry so subsequent
    /// calls take the fast path against the corrected root.
    #[test]
    fn discover_recovers_when_cached_repo_root_is_invalid() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        write_file(root, "File.java", "class File {}");
        let repo = Repository::init(root).unwrap();
        commit_paths_at(&repo, "initial", &["File.java"], &[], 1);

        clear_repo_root_cache_for_project(root);
        repo_root_cache().lock().unwrap().insert(
            root.to_path_buf(),
            Path::new("/nonexistent/bifrost-relevance-test-path").to_path_buf(),
        );

        let context = GitProjectContext::discover(root)
            .expect("fallback discover should still find the real repo");
        assert_eq!(context.repo_root, root.canonicalize().unwrap());

        let cached_after = repo_root_cache().lock().unwrap().get(root).cloned();
        assert_eq!(
            cached_after,
            Some(root.canonicalize().unwrap()),
            "the fallback path must refresh the cache to the corrected root"
        );
    }

    /// A workspace with no `.git` anywhere in its ancestry keeps returning `None`, whether or not
    /// a stale path cache entry is present; the fallback discover must not fabricate a repo.
    #[test]
    fn discover_returns_none_when_no_repo_exists_even_with_stale_cache_entry() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        write_file(root, "File.java", "class File {}");
        let repo = Repository::init(root).unwrap();
        commit_paths_at(&repo, "initial", &["File.java"], &[], 1);
        clear_repo_root_cache_for_project(root);
        assert!(GitProjectContext::discover(root).is_some());

        fs::remove_dir_all(root.join(".git")).unwrap();
        assert!(
            GitProjectContext::discover(root).is_none(),
            "cached-path open failure must fall back to a fresh discover, not a stale success"
        );
    }
}
