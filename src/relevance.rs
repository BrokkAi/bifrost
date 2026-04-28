use crate::analyzer::{CodeUnit, IAnalyzer, ProjectFile};
use crate::hash::{HashMap, HashSet};
use crate::profiling;
use git2::{Oid, Repository};
use std::collections::{BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

const ALPHA: f64 = 0.85;
const CONVERGENCE_EPSILON: f64 = 1.0e-6;
const SCORE_BUCKET_SCALE: f64 = 1.0e9;
const MAX_ITERS: usize = 75;
const IMPORT_DEPTH: usize = 2;
const COMMITS_TO_PROCESS: usize = 1_000;
const NATIVE_RENAME_THRESHOLD: u16 = 50;
const NATIVE_RENAME_TOKEN_OVERLAP_THRESHOLD: f64 = 0.90;
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

pub(crate) fn most_relevant_project_files(
    analyzer: &dyn IAnalyzer,
    seeds: &[ProjectFile],
    top_k: usize,
) -> Vec<ProjectFile> {
    let _scope = profiling::scope("relevance::most_relevant_project_files");
    if top_k == 0 {
        return Vec::new();
    }

    let seed_weights = normalized_seed_weights(seeds);
    if seed_weights.is_empty() {
        return Vec::new();
    }

    let excluded: HashSet<_> = seed_weights.keys().cloned().collect();
    let mut results = Vec::new();
    let mut seen = HashSet::default();

    {
        let _scope = profiling::scope("relevance::git");
        for candidate in related_files_by_git(analyzer, &seed_weights, top_k).unwrap_or_default() {
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
        let age_weight = 1.0 / ((index + 1) as f64);
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

fn normalized_seed_weights(seeds: &[ProjectFile]) -> HashMap<ProjectFile, f64> {
    let mut weights = HashMap::default();
    for seed in seeds.iter().filter(|seed| seed.exists()) {
        *weights.entry(seed.clone()).or_insert(0.0) += 1.0;
    }
    weights
}

#[derive(Debug, Default)]
struct ImportGraph {
    forward: HashMap<ProjectFile, BTreeSet<ProjectFile>>,
    reverse: HashMap<ProjectFile, BTreeSet<ProjectFile>>,
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
    let adjacency = if reversed {
        &graph.reverse
    } else {
        &graph.forward
    };

    let mut nodes: Vec<_> = adjacency.keys().cloned().collect();
    nodes.sort();
    if nodes.is_empty() {
        return Vec::new();
    }

    let index_by_file: HashMap<_, _> = nodes
        .iter()
        .enumerate()
        .map(|(index, file)| (file.clone(), index))
        .collect();

    let total_seed_weight: f64 = positive_seeds.values().sum();
    if total_seed_weight <= 0.0 {
        return Vec::new();
    }

    let mut teleport = vec![0.0; nodes.len()];
    for (file, weight) in &positive_seeds {
        if let Some(index) = index_by_file.get(file) {
            teleport[*index] = *weight / total_seed_weight;
        }
    }

    let mut neighbors = vec![Vec::new(); nodes.len()];
    let mut out_degree = vec![0usize; nodes.len()];
    for (index, file) in nodes.iter().enumerate() {
        let outs = adjacency.get(file).cloned().unwrap_or_default();
        let mut out_indices = outs
            .into_iter()
            .filter_map(|neighbor| index_by_file.get(&neighbor).copied())
            .collect::<Vec<_>>();
        out_indices.sort_unstable();
        out_degree[index] = out_indices.len();
        neighbors[index] = out_indices;
    }

    let mut rank = teleport.clone();
    let mut next = vec![0.0; nodes.len()];
    for _ in 0..MAX_ITERS {
        for (index, teleport_weight) in teleport.iter().enumerate() {
            next[index] = (1.0 - ALPHA) * teleport_weight;
        }

        let mut dangling_mass = 0.0;
        for index in 0..nodes.len() {
            if out_degree[index] == 0 {
                dangling_mass += rank[index];
                continue;
            }

            let share = ALPHA * rank[index] / out_degree[index] as f64;
            for neighbor in &neighbors[index] {
                next[*neighbor] += share;
            }
        }

        if dangling_mass.abs() > 1.0e-10 {
            let add = ALPHA * dangling_mass;
            for (index, teleport_weight) in teleport.iter().enumerate() {
                next[index] += add * teleport_weight;
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

    let seed_files: HashSet<_> = positive_seeds.keys().cloned().collect();
    let mut ranked = nodes
        .into_iter()
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

fn build_import_graph(
    analyzer: &dyn IAnalyzer,
    seed_weights: &HashMap<ProjectFile, f64>,
) -> ImportGraph {
    let _scope = profiling::scope("relevance::build_import_graph");
    let mut graph = ImportGraph::default();
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
        graph.forward.entry(seed.clone()).or_default();
        graph.reverse.entry(seed.clone()).or_default();
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
                if !graph.forward.contains_key(&target) {
                    graph.forward.entry(target.clone()).or_default();
                    graph.reverse.entry(target.clone()).or_default();
                    next.push_back(target.clone());
                }
                graph
                    .forward
                    .entry(file.clone())
                    .or_default()
                    .insert(target.clone());
                forward_edges += 1;
                graph
                    .reverse
                    .entry(target)
                    .or_default()
                    .insert(file.clone());
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
                if !graph.forward.contains_key(&source) {
                    graph.forward.entry(source.clone()).or_default();
                    graph.reverse.entry(source.clone()).or_default();
                    next.push_back(source.clone());
                }
                graph
                    .forward
                    .entry(source.clone())
                    .or_default()
                    .insert(file.clone());
                reverse_edges += 1;
                graph
                    .reverse
                    .entry(file.clone())
                    .or_default()
                    .insert(source);
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

    graph
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
            add_definitions_to_files(analyzer.definitions(import), &mut resolved);
            if resolved.len() == before {
                let matches = analyzer.search_definitions(import, true);
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
/// - treat near-equal scores as ties using a relative epsilon of `1e-9 * max(1, |score|)` and break them by
///   normalized path so ordering is stable across platforms and implementations
///
/// If any of those rules change here, change Brokk in the same way and rerun the external parity fixtures.
fn related_files_by_git(
    analyzer: &dyn IAnalyzer,
    seed_weights: &HashMap<ProjectFile, f64>,
    k: usize,
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
    let mut seed_commit_count: HashMap<ProjectFile, usize> = HashMap::default();
    let mut canonicalizer = RenameCanonicalizer::default();
    let find_commit_ms = 0.0;
    let change_ms = 0.0;
    let mut canonicalize_ms = 0.0;
    let mut processed_commits = 0usize;

    let baseline_commit_count = changes.len() as f64;
    {
        let _scope = profiling::scope("relevance::git.score_commits");
        for change in changes {
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

            for seed in &seeds_in_commit {
                *seed_commit_count.entry(seed.clone()).or_insert(0) += 1;
            }

            let commit_pair_mass = 1.0 / changed_files.len() as f64;
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
        let seed_denom = seed_commit_count.get(&seed).copied().unwrap_or(0);
        if seed_denom == 0 {
            continue;
        }

        let conditional = joint / seed_denom as f64;
        let target_doc_freq = file_doc_freq.get(&target).copied().unwrap_or(0).max(1) as f64;
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
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.repo_root)
            .arg("log")
            .arg("--topo-order")
            .arg("--no-color")
            .arg("--diff-merges=first-parent")
            .arg("--root")
            .arg(format!("-M{NATIVE_RENAME_THRESHOLD}"))
            .arg("--name-status")
            .arg("-z")
            .arg("--format=format:%x1e%H")
            .arg("-n")
            .arg(limit.to_string())
            .output()
            .map_err(|err| format!("failed to run git log: {err}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("git log exited with {}: {stderr}", output.status));
        }

        Ok(self.parse_git_log_name_status(&output.stdout))
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

#[derive(Clone, Debug)]
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
mod tests {
    use super::{FileRelevance, related_files_by_imports};
    use crate::analyzer::{
        AnalyzerConfig, AnalyzerDelegate, FilesystemProject, JavaAnalyzer, Language, MultiAnalyzer,
        ProjectFile, PythonAnalyzer, TestProject, WorkspaceAnalyzer,
    };
    use crate::hash::{HashMap, HashSet};
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
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

    fn workspace_analyzer(root: &Path) -> WorkspaceAnalyzer {
        let project = Arc::new(FilesystemProject::new(root).unwrap());
        WorkspaceAnalyzer::build(project, AnalyzerConfig::default())
    }

    fn change_by_id(context: &super::GitProjectContext, oid: git2::Oid) -> super::CommitChange {
        context
            .recent_commit_changes(super::COMMITS_TO_PROCESS)
            .unwrap()
            .into_iter()
            .find(|change| change.id == oid)
            .unwrap_or_else(|| panic!("commit {oid} not found in native git log window"))
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
    #[ignore = "diagnostic"]
    fn debug_git_scores_for_plume_merge_gitlibrary_seed() {
        let workspace = workspace_analyzer(Path::new("/home/jonathan/Projects/plume-merge"));
        let seed = ProjectFile::new(
            workspace.analyzer().project().root().to_path_buf(),
            "src/main/java/org/plumelib/merging/GitLibrary.java",
        );
        let results =
            super::related_files_by_git(workspace.analyzer(), &hash_map([(seed, 1.0)]), 25)
                .unwrap();
        for entry in results {
            eprintln!("{:.15} {}", entry.score, entry.file.rel_path().display());
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_git_scores_for_plume_merge_pair() {
        let workspace = workspace_analyzer(Path::new("/home/jonathan/Projects/plume-merge"));
        let root = workspace.analyzer().project().root().to_path_buf();
        let seeds = hash_map([
            (
                ProjectFile::new(
                    root.clone(),
                    "src/main/java/org/plumelib/merging/AdjacentDynamicProgramming.java",
                ),
                1.0,
            ),
            (
                ProjectFile::new(root, "src/test/resources/AnnotationsTest1Base.java"),
                1.0,
            ),
        ]);
        let results = super::related_files_by_git(workspace.analyzer(), &seeds, 25).unwrap();
        for entry in results {
            eprintln!("{:.15} {}", entry.score, entry.file.rel_path().display());
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_vector_similarity_query_result_struct_rankers() {
        let workspace = workspace_analyzer(Path::new("/home/jonathan/Projects/VectorSimilarity"));
        let root = workspace.analyzer().project().root().to_path_buf();
        let seed = ProjectFile::new(root.clone(), "src/VecSim/query_result_struct.cpp");
        let targets = [
            ProjectFile::new(root.clone(), "tests/unit/test_bruteforce.cpp"),
            ProjectFile::new(root.clone(), "src/VecSim/vec_sim.cpp"),
            ProjectFile::new(root.clone(), "src/VecSim/vec_sim.h"),
            ProjectFile::new(root.clone(), "src/python_bindings/bindings.cpp"),
            ProjectFile::new(root.clone(), "tests/flow/test_bruteforce.py"),
            ProjectFile::new(
                root.clone(),
                "tests/benchmark/spaces_benchmarks/bm_spaces_class_fp32.cpp",
            ),
            ProjectFile::new(root.clone(), "src/VecSim/utils/arr_cpp.h"),
            ProjectFile::new(root.clone(), "src/VecSim/algorithms/hnsw/hnsw.h"),
            ProjectFile::new(
                root.clone(),
                "src/VecSim/algorithms/brute_force/brute_force_multi.h",
            ),
            ProjectFile::new(root.clone(), "src/VecSim/spaces/IP/IP_AVX512_FP32.cpp"),
            ProjectFile::new(root.clone(), "src/VecSim/spaces/L2_space.h"),
            ProjectFile::new(
                root.clone(),
                "src/VecSim/index_factories/brute_force_factory.cpp",
            ),
            ProjectFile::new(
                root.clone(),
                "tests/benchmark/spaces_benchmarks/bm_spaces_class_definitions.h",
            ),
        ];

        let git = super::related_files_by_git(
            workspace.analyzer(),
            &hash_map([(seed.clone(), 1.0)]),
            100,
        )
        .unwrap();
        println!("git top 100");
        for entry in &git {
            if targets.contains(&entry.file) {
                println!(
                    "  target git {:.15} {}",
                    entry.score,
                    entry.file.rel_path().display()
                );
            }
        }

        let imports = super::related_files_by_imports(
            workspace.analyzer(),
            &hash_map([(seed, 1.0)]),
            100,
            false,
        );
        println!("imports top 100");
        for entry in &imports {
            if targets.contains(&entry.file) {
                println!(
                    "  target import {:.15} {}",
                    entry.score,
                    entry.file.rel_path().display()
                );
            }
        }
        for target in &targets {
            let git_index = git.iter().position(|entry| entry.file == *target);
            let import_index = imports.iter().position(|entry| entry.file == *target);
            println!(
                "target {} git_rank={:?} import_rank={:?}",
                target.rel_path().display(),
                git_index.map(|index| index + 1),
                import_index.map(|index| index + 1)
            );
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_vector_similarity_query_result_struct_git_commits() {
        let workspace = workspace_analyzer(Path::new("/home/jonathan/Projects/VectorSimilarity"));
        let root = workspace.analyzer().project().root().to_path_buf();
        let seed = ProjectFile::new(root.clone(), "src/VecSim/query_result_struct.cpp");
        let fp32 = ProjectFile::new(
            root.clone(),
            "tests/benchmark/spaces_benchmarks/bm_spaces_class_fp32.cpp",
        );
        let test_bruteforce = ProjectFile::new(root.clone(), "tests/unit/test_bruteforce.cpp");
        let vec_sim_cpp = ProjectFile::new(root.clone(), "src/VecSim/vec_sim.cpp");
        let vec_sim_h = ProjectFile::new(root.clone(), "src/VecSim/vec_sim.h");
        let bindings = ProjectFile::new(root.clone(), "src/python_bindings/bindings.cpp");
        let flow_test = ProjectFile::new(root.clone(), "tests/flow/test_bruteforce.py");
        let definitions = ProjectFile::new(
            root.clone(),
            "tests/benchmark/spaces_benchmarks/bm_spaces_class_definitions.h",
        );
        let brute_force_factory = ProjectFile::new(
            root.clone(),
            "src/VecSim/index_factories/brute_force_factory.cpp",
        );
        let l2_space = ProjectFile::new(root, "src/VecSim/spaces/L2_space.h");

        let repo =
            super::GitProjectContext::discover(workspace.analyzer().project().root()).unwrap();
        let commit_ids = repo
            .recent_commit_changes(super::COMMITS_TO_PROCESS)
            .unwrap();
        let mut canonicalizer = super::RenameCanonicalizer::default();
        for change in &commit_ids {
            canonicalizer.record_renames(&change.renames);

            let changed_files = change
                .paths
                .iter()
                .map(|path| canonicalizer.canonicalize(path))
                .filter_map(|repo_rel| repo.repo_path_to_project_file(&repo_rel))
                .collect::<Vec<_>>();
            if changed_files.contains(&seed)
                && (changed_files.contains(&fp32)
                    || changed_files.contains(&definitions)
                    || changed_files.contains(&brute_force_factory)
                    || changed_files.contains(&l2_space)
                    || changed_files.contains(&test_bruteforce)
                    || changed_files.contains(&vec_sim_cpp)
                    || changed_files.contains(&vec_sim_h)
                    || changed_files.contains(&bindings)
                    || changed_files.contains(&flow_test))
            {
                eprintln!("commit {} size={}", change.id, changed_files.len());
                for file in &changed_files {
                    if *file == seed
                        || *file == fp32
                        || *file == definitions
                        || *file == brute_force_factory
                        || *file == l2_space
                        || *file == test_bruteforce
                        || *file == vec_sim_cpp
                        || *file == vec_sim_h
                        || *file == bindings
                        || *file == flow_test
                    {
                        eprintln!("  {}", file.rel_path().display());
                    }
                }
            }
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_vector_similarity_query_result_struct_git_scores() {
        let workspace = workspace_analyzer(Path::new("/home/jonathan/Projects/VectorSimilarity"));
        let context =
            super::GitProjectContext::discover(workspace.analyzer().project().root()).unwrap();
        let root = workspace.analyzer().project().root().to_path_buf();
        let seed = ProjectFile::new(root.clone(), "src/VecSim/query_result_struct.cpp");
        let targets = [
            ProjectFile::new(root.clone(), "tests/unit/test_bruteforce.cpp"),
            ProjectFile::new(root.clone(), "src/VecSim/vec_sim.cpp"),
            ProjectFile::new(root.clone(), "src/VecSim/vec_sim.h"),
            ProjectFile::new(root.clone(), "src/python_bindings/bindings.cpp"),
            ProjectFile::new(root.clone(), "tests/flow/test_bruteforce.py"),
            ProjectFile::new(root.clone(), "src/VecSim/utils/arr_cpp.h"),
            ProjectFile::new(root.clone(), "src/VecSim/algorithms/hnsw/hnsw.h"),
            ProjectFile::new(root.clone(), "src/VecSim/memory/vecsim_malloc.cpp"),
            ProjectFile::new(root.clone(), "src/VecSim/spaces/L2/L2.cpp"),
            ProjectFile::new(root.clone(), "src/VecSim/spaces/L2/L2.h"),
            ProjectFile::new(root.clone(), "src/VecSim/spaces/IP/IP_AVX512_FP32.cpp"),
            ProjectFile::new(root.clone(), "src/VecSim/spaces/L2_space.h"),
            ProjectFile::new(root, "src/VecSim/index_factories/brute_force_factory.cpp"),
        ];

        let commits = context
            .recent_commit_changes(super::COMMITS_TO_PROCESS)
            .unwrap();
        let baseline_commit_count = commits.len() as f64;
        let mut file_doc_freq: HashMap<ProjectFile, usize> = HashMap::default();
        let mut joint_mass: HashMap<ProjectFile, f64> = HashMap::default();
        let mut seed_commit_count = 0usize;
        let mut canonicalizer = super::RenameCanonicalizer::default();

        for change in &commits {
            canonicalizer.record_renames(&change.renames);
            let changed_files = change
                .paths
                .iter()
                .map(|path| canonicalizer.canonicalize(path))
                .filter_map(|path| context.repo_path_to_project_file(&path))
                .collect::<BTreeSet<_>>();
            if changed_files.is_empty() {
                continue;
            }

            for path in &changed_files {
                *file_doc_freq.entry(path.clone()).or_insert(0) += 1;
            }

            if !changed_files.contains(&seed) {
                continue;
            }
            seed_commit_count += 1;
            let commit_pair_mass = 1.0 / changed_files.len() as f64;
            for target in &targets {
                if changed_files.contains(target) {
                    *joint_mass.entry(target.clone()).or_insert(0.0) += commit_pair_mass;
                }
            }
        }

        for target in &targets {
            let df = file_doc_freq.get(target).copied().unwrap_or(0).max(1) as f64;
            let joint = joint_mass.get(target).copied().unwrap_or(0.0);
            let conditional = if seed_commit_count == 0 {
                0.0
            } else {
                joint / seed_commit_count as f64
            };
            let idf = (1.0 + baseline_commit_count / df).ln();
            let score = conditional * idf;
            eprintln!(
                "{} df={} seed_den={} joint={:.15} conditional={:.15} idf={:.15} score={:.15}",
                target.rel_path().display(),
                file_doc_freq.get(target).copied().unwrap_or(0),
                seed_commit_count,
                joint,
                conditional,
                idf,
                score
            );
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_vector_similarity_problematic_commit_renames() {
        let workspace = workspace_analyzer(Path::new("/home/jonathan/Projects/VectorSimilarity"));
        let repo =
            super::GitProjectContext::discover(workspace.analyzer().project().root()).unwrap();
        let oid = git2::Oid::from_str("493c78d1ef6035c27067137f3ab02d280f67cac2").unwrap();
        let change = change_by_id(&repo, oid);
        eprintln!("renames:");
        for (old_path, new_path) in &change.renames {
            eprintln!("  {} -> {}", old_path.display(), new_path.display());
        }
        eprintln!("paths:");
        for path in &change.paths {
            if path.to_string_lossy().contains("version")
                || path.to_string_lossy().contains("bm_spaces_class")
            {
                eprintln!("  {}", path.display());
            }
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_vector_similarity_l2_move_commit_renames() {
        let workspace = workspace_analyzer(Path::new("/home/jonathan/Projects/VectorSimilarity"));
        let repo =
            super::GitProjectContext::discover(workspace.analyzer().project().root()).unwrap();
        let oid = git2::Oid::from_str("17985eda88a0fa9da910d346aa0f3656f419f2b5").unwrap();
        let change = change_by_id(&repo, oid);
        eprintln!("renames:");
        for (old_path, new_path) in &change.renames {
            eprintln!("  {} -> {}", old_path.display(), new_path.display());
        }
        eprintln!("paths:");
        for path in &change.paths {
            if path.to_string_lossy().contains("L2")
                || path.to_string_lossy().contains("internal_product")
            {
                eprintln!("  {}", path.display());
            }
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_vector_similarity_bruteforce_move_commit_renames() {
        let workspace = workspace_analyzer(Path::new("/home/jonathan/Projects/VectorSimilarity"));
        let repo =
            super::GitProjectContext::discover(workspace.analyzer().project().root()).unwrap();
        let oid = git2::Oid::from_str("e2f3da57fe43ce500f58e4dbe5291e35ada31bee").unwrap();
        let change = change_by_id(&repo, oid);
        eprintln!("renames:");
        for (old_path, new_path) in &change.renames {
            eprintln!("  {} -> {}", old_path.display(), new_path.display());
        }
        eprintln!("paths:");
        for path in &change.paths {
            if path.to_string_lossy().contains("brute_force_factory")
                || path.to_string_lossy().contains("index_factories")
            {
                eprintln!("  {}", path.display());
            }
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_git_scores_for_axios_eslintrc_seed() {
        let workspace = workspace_analyzer(Path::new("/home/jonathan/Projects/axios"));
        let seed = ProjectFile::new(
            workspace.analyzer().project().root().to_path_buf(),
            ".eslintrc.cjs",
        );
        let results =
            super::related_files_by_git(workspace.analyzer(), &hash_map([(seed, 1.0)]), 25)
                .unwrap();
        for entry in results {
            eprintln!("{:.15} {}", entry.score, entry.file.rel_path().display());
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_git_scores_for_autogen_program_seed() {
        let workspace = workspace_analyzer(Path::new(
            "/home/jonathan/Projects/brokkbench/clones/microsoft__autogen",
        ));
        let seed = ProjectFile::new(
            workspace.analyzer().project().root().to_path_buf(),
            "dotnet/samples/AgentChat/AutoGen.Anthropic.Sample/Program.cs",
        );
        let results =
            super::related_files_by_git(workspace.analyzer(), &hash_map([(seed, 1.0)]), 25)
                .unwrap();
        for entry in results {
            eprintln!("{:.15} {}", entry.score, entry.file.rel_path().display());
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_git_scores_for_autogen_checker_seed() {
        let workspace = workspace_analyzer(Path::new(
            "/home/jonathan/Projects/brokkbench/clones/microsoft__autogen",
        ));
        let seed = ProjectFile::new(
            workspace.analyzer().project().root().to_path_buf(),
            "dotnet/samples/GettingStarted/Checker.cs",
        );
        let results =
            super::related_files_by_git(workspace.analyzer(), &hash_map([(seed, 1.0)]), 30)
                .unwrap();
        for entry in results {
            eprintln!("{:.15} {}", entry.score, entry.file.rel_path().display());
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_git_scores_for_autogen_hello_ai_agents_program_seed() {
        let workspace = workspace_analyzer(Path::new(
            "/home/jonathan/Projects/brokkbench/clones/microsoft__autogen",
        ));
        let seed = ProjectFile::new(
            workspace.analyzer().project().root().to_path_buf(),
            "dotnet/samples/Hello/HelloAIAgents/Program.cs",
        );
        let results =
            super::related_files_by_git(workspace.analyzer(), &hash_map([(seed, 1.0)]), 40)
                .unwrap();
        for entry in results {
            eprintln!("{:.15} {}", entry.score, entry.file.rel_path().display());
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_git_scores_for_autogen_hello_agent_program_seed() {
        let workspace = workspace_analyzer(Path::new(
            "/home/jonathan/Projects/brokkbench/clones/microsoft__autogen",
        ));
        let seed = ProjectFile::new(
            workspace.analyzer().project().root().to_path_buf(),
            "dotnet/samples/Hello/HelloAgent/Program.cs",
        );
        let results =
            super::related_files_by_git(workspace.analyzer(), &hash_map([(seed, 1.0)]), 100)
                .unwrap();
        for entry in results {
            eprintln!("{:.15} {}", entry.score, entry.file.rel_path().display());
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_import_scores_for_autogen_hello_ai_agents_program_seed() {
        let workspace = workspace_analyzer(Path::new(
            "/home/jonathan/Projects/brokkbench/clones/microsoft__autogen",
        ));
        let seed = ProjectFile::new(
            workspace.analyzer().project().root().to_path_buf(),
            "dotnet/samples/Hello/HelloAIAgents/Program.cs",
        );
        let results = super::related_files_by_imports(
            workspace.analyzer(),
            &hash_map([(seed, 1.0)]),
            40,
            false,
        );
        for entry in results {
            eprintln!("{:.15} {}", entry.score, entry.file.rel_path().display());
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_import_scores_for_autogen_checker_seed() {
        let workspace = workspace_analyzer(Path::new(
            "/home/jonathan/Projects/brokkbench/clones/microsoft__autogen",
        ));
        let seed = ProjectFile::new(
            workspace.analyzer().project().root().to_path_buf(),
            "dotnet/samples/GettingStarted/Checker.cs",
        );
        let results = super::related_files_by_imports(
            workspace.analyzer(),
            &hash_map([(seed, 1.0)]),
            100,
            false,
        );
        for entry in &results {
            let path = entry.file.rel_path();
            if path
                == Path::new(
                    "dotnet/samples/AgentChat/AutoGen.Anthropic.Sample/Anthropic_Agent_With_Prompt_Caching.cs",
                )
                || path
                    == Path::new(
                        "dotnet/samples/AgentChat/AutoGen.Anthropic.Sample/AutoGen.Anthropic.Sample.csproj",
                    )
            {
                println!(
                    "target {:.15} {}",
                    entry.score,
                    entry.file.rel_path().display()
                );
            }
        }
        for entry in results {
            println!("{:.15} {}", entry.score, entry.file.rel_path().display());
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_git_scores_for_autogen_topicid_and_inmemoryruntime_pair() {
        let workspace = workspace_analyzer(Path::new(
            "/home/jonathan/Projects/brokkbench/clones/microsoft__autogen",
        ));
        let root = workspace.analyzer().project().root().to_path_buf();
        let topic_id = ProjectFile::new(
            root.clone(),
            "dotnet/src/Microsoft.AutoGen/Contracts/TopicId.cs",
        );
        let inmemory = ProjectFile::new(
            root,
            "dotnet/test/Microsoft.AutoGen.Integration.Tests/InMemoryRuntimeIntegrationTests.cs",
        );
        let results = super::related_files_by_git(
            workspace.analyzer(),
            &hash_map([(topic_id, 1.0), (inmemory, 1.0)]),
            100,
        )
        .unwrap();
        for entry in results {
            eprintln!("{:.15} {}", entry.score, entry.file.rel_path().display());
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_import_scores_for_autogen_topicid_and_inmemoryruntime_pair() {
        let workspace = workspace_analyzer(Path::new(
            "/home/jonathan/Projects/brokkbench/clones/microsoft__autogen",
        ));
        let root = workspace.analyzer().project().root().to_path_buf();
        let topic_id = ProjectFile::new(
            root.clone(),
            "dotnet/src/Microsoft.AutoGen/Contracts/TopicId.cs",
        );
        let inmemory = ProjectFile::new(
            root,
            "dotnet/test/Microsoft.AutoGen.Integration.Tests/InMemoryRuntimeIntegrationTests.cs",
        );
        let results = super::related_files_by_imports(
            workspace.analyzer(),
            &hash_map([(topic_id, 1.0), (inmemory, 1.0)]),
            100,
            false,
        );
        for entry in results {
            eprintln!("{:.15} {}", entry.score, entry.file.rel_path().display());
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_git_per_seed_terms_for_autogen_topicid_and_inmemoryruntime_pair() {
        let root = Path::new("/home/jonathan/Projects/brokkbench/clones/microsoft__autogen");
        let context = super::GitProjectContext::discover(root).unwrap();
        let topic_id = PathBuf::from("dotnet/src/Microsoft.AutoGen/Contracts/TopicId.cs");
        let inmemory = PathBuf::from(
            "dotnet/test/Microsoft.AutoGen.Integration.Tests/InMemoryRuntimeIntegrationTests.cs",
        );
        let seeds = [topic_id.clone(), inmemory.clone()];
        let targets = [
            PathBuf::from("dotnet/AutoGen.sln"),
            PathBuf::from("dotnet/src/Microsoft.AutoGen/Contracts/KVStringParseHelper.cs"),
            PathBuf::from("dotnet/src/Microsoft.AutoGen/Contracts/IAgentRuntime.cs"),
            PathBuf::from("dotnet/src/Microsoft.AutoGen/Contracts/IHandle.cs"),
            PathBuf::from(
                "dotnet/src/Microsoft.AutoGen/Agents/IOAgent/ConsoleAgent/IHandleConsole.cs",
            ),
            PathBuf::from("dotnet/src/Microsoft.AutoGen/Core/AgentsApp.cs"),
            PathBuf::from("dotnet/test/Microsoft.AutoGen.Core.Tests/InProcessRuntimeTests.cs"),
        ];

        let commits = context
            .recent_commit_changes(super::COMMITS_TO_PROCESS)
            .unwrap();
        let baseline_commit_count = commits.len() as f64;
        let mut file_doc_freq: HashMap<PathBuf, usize> = HashMap::default();
        let mut joint_mass: HashMap<(PathBuf, PathBuf), f64> = HashMap::default();
        let mut seed_commit_count: HashMap<PathBuf, usize> = HashMap::default();
        let mut canonicalizer = super::RenameCanonicalizer::default();

        for change in &commits {
            let changed_files = change
                .paths
                .iter()
                .map(|path| canonicalizer.canonicalize(path))
                .filter_map(|path| context.repo_path_to_project_file(&path))
                .map(|file| file.rel_path().to_path_buf())
                .collect::<BTreeSet<_>>();
            canonicalizer.record_renames(&change.renames);
            if changed_files.is_empty() {
                continue;
            }

            for path in &changed_files {
                *file_doc_freq.entry(path.clone()).or_insert(0) += 1;
            }

            let seeds_in_commit = seeds
                .iter()
                .filter(|seed| changed_files.contains(*seed))
                .cloned()
                .collect::<Vec<_>>();
            if seeds_in_commit.is_empty() {
                continue;
            }

            for seed in &seeds_in_commit {
                *seed_commit_count.entry(seed.clone()).or_insert(0) += 1;
            }

            let commit_pair_mass = 1.0 / changed_files.len() as f64;
            for seed in &seeds_in_commit {
                for target in &targets {
                    if changed_files.contains(target) {
                        *joint_mass
                            .entry((seed.clone(), target.clone()))
                            .or_insert(0.0) += commit_pair_mass;
                    }
                }
            }
        }

        for target in &targets {
            let df = file_doc_freq.get(target).copied().unwrap_or(0).max(1) as f64;
            let idf = (1.0 + baseline_commit_count / df).ln();
            eprintln!(
                "target={} df={} idf={:.15}",
                target.display(),
                df as usize,
                idf
            );
            let mut total = 0.0;
            for seed in &seeds {
                let joint = joint_mass
                    .get(&(seed.clone(), target.clone()))
                    .copied()
                    .unwrap_or(0.0);
                let seed_denom = seed_commit_count.get(seed).copied().unwrap_or(0);
                let conditional = if seed_denom == 0 {
                    0.0
                } else {
                    joint / seed_denom as f64
                };
                let contribution = conditional * idf;
                total += contribution;
                eprintln!(
                    "  seed={} seed_den={} joint={:.15} conditional={:.15} contribution={:.15}",
                    seed.display(),
                    seed_denom,
                    joint,
                    conditional,
                    contribution
                );
            }
            eprintln!("  total={:.15}", total);
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_git_contributing_commits_for_autogen_topicid_and_inmemoryruntime_pair() {
        let root = Path::new("/home/jonathan/Projects/brokkbench/clones/microsoft__autogen");
        let context = super::GitProjectContext::discover(root).unwrap();
        let topic_id = PathBuf::from("dotnet/src/Microsoft.AutoGen/Contracts/TopicId.cs");
        let inmemory = PathBuf::from(
            "dotnet/test/Microsoft.AutoGen.Integration.Tests/InMemoryRuntimeIntegrationTests.cs",
        );
        let pairs = [
            (
                topic_id.clone(),
                PathBuf::from("dotnet/src/Microsoft.AutoGen/Contracts/KVStringParseHelper.cs"),
            ),
            (inmemory.clone(), PathBuf::from("dotnet/AutoGen.sln")),
        ];

        let commits = context
            .recent_commit_changes(super::COMMITS_TO_PROCESS)
            .unwrap();
        let mut canonicalizer = super::RenameCanonicalizer::default();
        for change in &commits {
            let changed_files = change
                .paths
                .iter()
                .map(|path| canonicalizer.canonicalize(path))
                .filter_map(|path| context.repo_path_to_project_file(&path))
                .map(|file| file.rel_path().to_path_buf())
                .collect::<BTreeSet<_>>();
            canonicalizer.record_renames(&change.renames);
            if changed_files.is_empty() {
                continue;
            }

            for (seed, target) in &pairs {
                if changed_files.contains(seed) && changed_files.contains(target) {
                    eprintln!(
                        "pair {} -> {} commit={} size={}",
                        seed.display(),
                        target.display(),
                        change.id,
                        changed_files.len()
                    );
                }
            }
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_changed_files_for_autogen_pair_commits() {
        let root = Path::new("/home/jonathan/Projects/brokkbench/clones/microsoft__autogen");
        let context = super::GitProjectContext::discover(root).unwrap();
        let interesting = BTreeSet::from([
            git2::Oid::from_str("b16b94feb8bd89ef07c14fc7f34419490924b993").unwrap(),
            git2::Oid::from_str("1a789dfcc44dc2f90b2bf2805a78a4e4f4112c4a").unwrap(),
            git2::Oid::from_str("0100201dd41111473f8624cbf1ab1c2a926f8c93").unwrap(),
            git2::Oid::from_str("7d01bc61368d912460e28daf8ea2edb228bfde24").unwrap(),
            git2::Oid::from_str("ff7f863e739cd0339f54d460d2be8a79bcdd0231").unwrap(),
        ]);

        let commits = context
            .recent_commit_changes(super::COMMITS_TO_PROCESS)
            .unwrap();
        let mut canonicalizer = super::RenameCanonicalizer::default();
        for change in &commits {
            let changed_files = change
                .paths
                .iter()
                .map(|path| canonicalizer.canonicalize(path))
                .filter_map(|path| context.repo_path_to_project_file(&path))
                .map(|file| file.rel_path().to_path_buf())
                .collect::<BTreeSet<_>>();
            canonicalizer.record_renames(&change.renames);
            if interesting.contains(&change.id) {
                eprintln!("commit={} size={}", change.id, changed_files.len());
                for path in changed_files {
                    eprintln!("  {}", path.display());
                }
            }
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_autogen_inprocess_runtime_counted_paths() {
        let root = Path::new("/home/jonathan/Projects/brokkbench/clones/microsoft__autogen");
        let context = super::GitProjectContext::discover(root).unwrap();
        let target =
            PathBuf::from("dotnet/test/Microsoft.AutoGen.Core.Tests/InProcessRuntimeTests.cs");
        let interesting = git2::Oid::from_str("b16b94feb8bd89ef07c14fc7f34419490924b993").unwrap();

        let commits = context
            .recent_commit_changes(super::COMMITS_TO_PROCESS)
            .unwrap();
        let mut canonicalizer = super::RenameCanonicalizer::default();
        for change in &commits {
            if change.id == interesting {
                for path in &change.paths {
                    let canonical = canonicalizer.canonicalize(path);
                    if canonical == target {
                        eprintln!("{} -> {}", path.display(), canonical.display());
                    }
                }
                eprintln!("renames:");
                for (old_path, new_path) in &change.renames {
                    eprintln!("  {} -> {}", old_path.display(), new_path.display());
                }
            }
            canonicalizer.record_renames(&change.renames);
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_autogen_checker_git_stats() {
        let root = Path::new("/home/jonathan/Projects/brokkbench/clones/microsoft__autogen");
        let context = super::GitProjectContext::discover(root).unwrap();
        let seed = PathBuf::from("dotnet/samples/GettingStarted/Checker.cs");
        let docfx = PathBuf::from("docs/dotnet/docfx.json");
        let agent_metadata =
            PathBuf::from("dotnet/src/Microsoft.AutoGen/Contracts/AgentMetadata.cs");

        let commits = context
            .recent_commit_changes(super::COMMITS_TO_PROCESS)
            .unwrap();
        let mut file_doc_freq: HashMap<PathBuf, usize> = HashMap::default();
        let mut joint_mass: HashMap<PathBuf, f64> = HashMap::default();
        let mut seed_commit_count = 0usize;
        let mut canonicalizer = super::RenameCanonicalizer::default();

        for change in &commits {
            let changed_files = change
                .paths
                .iter()
                .map(|path| canonicalizer.canonicalize(path))
                .collect::<BTreeSet<_>>();
            canonicalizer.record_renames(&change.renames);
            if changed_files.is_empty() {
                continue;
            }

            for path in &changed_files {
                *file_doc_freq.entry(path.clone()).or_insert(0) += 1;
            }

            if !changed_files.contains(&seed) {
                continue;
            }
            seed_commit_count += 1;
            let commit_pair_mass = 1.0 / changed_files.len() as f64;
            for target in [&docfx, &agent_metadata] {
                if changed_files.contains(target) {
                    *joint_mass.entry(target.clone()).or_insert(0.0) += commit_pair_mass;
                    eprintln!(
                        "{} shared {} size={}",
                        change.id,
                        target.display(),
                        changed_files.len()
                    );
                }
            }
        }

        for target in [&docfx, &agent_metadata] {
            eprintln!(
                "{} df={} seed_den={} joint={:.15}",
                target.display(),
                file_doc_freq.get(target).copied().unwrap_or(0),
                seed_commit_count,
                joint_mass.get(target).copied().unwrap_or(0.0)
            );
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_autogen_checker_anthropic_git_terms() {
        let root = Path::new("/home/jonathan/Projects/brokkbench/clones/microsoft__autogen");
        let context = super::GitProjectContext::discover(root).unwrap();
        let seed = PathBuf::from("dotnet/samples/GettingStarted/Checker.cs");
        let targets = [
            PathBuf::from(
                "dotnet/samples/AgentChat/AutoGen.Anthropic.Sample/Anthropic_Agent_With_Prompt_Caching.cs",
            ),
            PathBuf::from(
                "dotnet/samples/AgentChat/AutoGen.Anthropic.Sample/AutoGen.Anthropic.Sample.csproj",
            ),
        ];

        let commits = context
            .recent_commit_changes(super::COMMITS_TO_PROCESS)
            .unwrap();
        let baseline_commit_count = commits.len() as f64;
        let mut file_doc_freq: HashMap<PathBuf, usize> = HashMap::default();
        let mut joint_mass: HashMap<PathBuf, f64> = HashMap::default();
        let mut seed_commit_count = 0usize;
        let mut canonicalizer = super::RenameCanonicalizer::default();

        for change in &commits {
            let changed_files = change
                .paths
                .iter()
                .map(|path| canonicalizer.canonicalize(path))
                .collect::<BTreeSet<_>>();
            canonicalizer.record_renames(&change.renames);
            if changed_files.is_empty() {
                continue;
            }

            for path in &changed_files {
                *file_doc_freq.entry(path.clone()).or_insert(0) += 1;
            }

            if !changed_files.contains(&seed) {
                continue;
            }
            seed_commit_count += 1;
            let commit_pair_mass = 1.0 / changed_files.len() as f64;
            for target in &targets {
                if changed_files.contains(target) {
                    *joint_mass.entry(target.clone()).or_insert(0.0) += commit_pair_mass;
                }
            }
        }

        for target in &targets {
            let df = file_doc_freq.get(target).copied().unwrap_or(0).max(1) as f64;
            let joint = joint_mass.get(target).copied().unwrap_or(0.0);
            let conditional = if seed_commit_count == 0 {
                0.0
            } else {
                joint / seed_commit_count as f64
            };
            let idf = (1.0 + baseline_commit_count / df).ln();
            let score = conditional * idf;
            println!(
                "{} df={} seed_den={} joint={:.15} conditional={:.15} idf={:.15} score={:.15}",
                target.display(),
                df as usize,
                seed_commit_count,
                joint,
                conditional,
                idf,
                score
            );
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_autogen_hello_ai_agents_git_stats() {
        let root = Path::new("/home/jonathan/Projects/brokkbench/clones/microsoft__autogen");
        let context = super::GitProjectContext::discover(root).unwrap();
        let seed = PathBuf::from("dotnet/samples/Hello/HelloAIAgents/Program.cs");
        let add_subscription = PathBuf::from(
            "dotnet/src/Microsoft.AutoGen/RuntimeGateway.Grpc/Services/Orleans/Surrogates/AddSubscriptionRequestSurrogate.cs",
        );
        let agent_host = PathBuf::from(
            "dotnet/src/Microsoft.AutoGen/AgentHost/Microsoft.AutoGen.AgentHost.csproj",
        );

        let commits = context
            .recent_commit_changes(super::COMMITS_TO_PROCESS)
            .unwrap();
        let mut file_doc_freq: HashMap<PathBuf, usize> = HashMap::default();
        let mut joint_mass: HashMap<PathBuf, f64> = HashMap::default();
        let mut seed_commit_count = 0usize;
        let mut canonicalizer = super::RenameCanonicalizer::default();

        for change in &commits {
            let changed_files = change
                .paths
                .iter()
                .map(|path| canonicalizer.canonicalize(path))
                .collect::<BTreeSet<_>>();
            canonicalizer.record_renames(&change.renames);
            if changed_files.is_empty() {
                continue;
            }

            for path in &changed_files {
                *file_doc_freq.entry(path.clone()).or_insert(0) += 1;
            }

            if !changed_files.contains(&seed) {
                continue;
            }
            seed_commit_count += 1;
            let commit_pair_mass = 1.0 / changed_files.len() as f64;
            for target in [&add_subscription, &agent_host] {
                if changed_files.contains(target) {
                    *joint_mass.entry(target.clone()).or_insert(0.0) += commit_pair_mass;
                    eprintln!(
                        "{} shared {} size={}",
                        change.id,
                        target.display(),
                        changed_files.len()
                    );
                }
            }
        }

        for target in [&add_subscription, &agent_host] {
            eprintln!(
                "{} df={} seed_den={} joint={:.15}",
                target.display(),
                file_doc_freq.get(target).copied().unwrap_or(0),
                seed_commit_count,
                joint_mass.get(target).copied().unwrap_or(0.0)
            );
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_autogen_hello_ai_agents_contested_git_terms() {
        let root = Path::new("/home/jonathan/Projects/brokkbench/clones/microsoft__autogen");
        let context = super::GitProjectContext::discover(root).unwrap();
        let seed = PathBuf::from("dotnet/samples/Hello/HelloAIAgents/Program.cs");
        let targets = [
            PathBuf::from("dotnet/samples/Hello/HelloAgent/appsettings.json"),
            PathBuf::from("dotnet/src/Microsoft.AutoGen/AgentHost/appsettings.json"),
            PathBuf::from(
                "dotnet/src/Microsoft.AutoGen/Agents/IOAgent/ConsoleAgent/IHandleConsole.cs",
            ),
            PathBuf::from(
                "python/samples/core_xlang_hello_python_agent/protos/agent_events_pb2.py",
            ),
            PathBuf::from(
                "dotnet/samples/dev-team/DevTeam.ServiceDefaults/DevTeam.ServiceDefaults.csproj",
            ),
            PathBuf::from(
                "dotnet/test/Microsoft.AutoGen.Integration.Tests/HelloAppHostIntegrationTests.cs",
            ),
            PathBuf::from("dotnet/samples/dev-team/DevTeam.Backend/Program.cs"),
            PathBuf::from(
                "dotnet/test/Microsoft.AutoGen.Core.Tests/Microsoft.AutoGen.Core.Tests.csproj",
            ),
        ];

        let commits = context
            .recent_commit_changes(super::COMMITS_TO_PROCESS)
            .unwrap();
        let baseline_commit_count = commits.len() as f64;
        let mut file_doc_freq: HashMap<PathBuf, usize> = HashMap::default();
        let mut joint_mass: HashMap<PathBuf, f64> = HashMap::default();
        let mut seed_commit_count = 0usize;
        let mut canonicalizer = super::RenameCanonicalizer::default();

        for change in &commits {
            let changed_files = change
                .paths
                .iter()
                .map(|path| canonicalizer.canonicalize(path))
                .collect::<BTreeSet<_>>();
            canonicalizer.record_renames(&change.renames);
            if changed_files.is_empty() {
                continue;
            }

            for path in &changed_files {
                *file_doc_freq.entry(path.clone()).or_insert(0) += 1;
            }

            if !changed_files.contains(&seed) {
                continue;
            }
            seed_commit_count += 1;
            let commit_pair_mass = 1.0 / changed_files.len() as f64;
            for target in &targets {
                if changed_files.contains(target) {
                    *joint_mass.entry(target.clone()).or_insert(0.0) += commit_pair_mass;
                }
            }
        }

        for target in &targets {
            let df = file_doc_freq.get(target).copied().unwrap_or(0).max(1) as f64;
            let joint = joint_mass.get(target).copied().unwrap_or(0.0);
            let conditional = if seed_commit_count == 0 {
                0.0
            } else {
                joint / seed_commit_count as f64
            };
            let idf = (1.0 + baseline_commit_count / df).ln();
            let score = conditional * idf;
            eprintln!(
                "{} df={} seed_den={} joint={:.15} conditional={:.15} idf={:.15} score={:.15}",
                target.display(),
                file_doc_freq.get(target).copied().unwrap_or(0),
                seed_commit_count,
                joint,
                conditional,
                idf,
                score
            );
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_autogen_hello_agent_contested_git_terms() {
        let root = Path::new("/home/jonathan/Projects/brokkbench/clones/microsoft__autogen");
        let context = super::GitProjectContext::discover(root).unwrap();
        let seed = PathBuf::from("dotnet/samples/Hello/HelloAgent/Program.cs");
        let targets = [
            PathBuf::from(
                "dotnet/test/Microsoft.AutoGen.Integration.Tests.AppHosts/InMemoryTests.AppHost/InMemoryTests.AppHost.csproj",
            ),
            PathBuf::from(
                "dotnet/src/Microsoft.AutoGen/RuntimeGateway.Grpc/Services/Orleans/Surrogates/AnySurrogate.cs",
            ),
            PathBuf::from(
                "dotnet/src/Microsoft.AutoGen/RuntimeGateway.Grpc/Services/Orleans/Surrogates/AgentIdSurrogate.cs",
            ),
            PathBuf::from(
                "dotnet/src/Microsoft.AutoGen/RuntimeGateway.Grpc/Services/Orleans/Surrogates/RpcRequestSurrogate.cs",
            ),
            PathBuf::from(
                "dotnet/src/Microsoft.AutoGen/RuntimeGateway.Grpc/Services/Orleans/Surrogates/SubscriptionSurrogate.cs",
            ),
        ];

        let commits = context
            .recent_commit_changes(super::COMMITS_TO_PROCESS)
            .unwrap();
        let baseline_commit_count = commits.len() as f64;
        let mut file_doc_freq: HashMap<PathBuf, usize> = HashMap::default();
        let mut joint_mass: HashMap<PathBuf, f64> = HashMap::default();
        let mut seed_commit_count = 0usize;
        let mut canonicalizer = super::RenameCanonicalizer::default();

        for change in &commits {
            let changed_files = change
                .paths
                .iter()
                .map(|path| canonicalizer.canonicalize(path))
                .collect::<BTreeSet<_>>();
            canonicalizer.record_renames(&change.renames);
            if changed_files.is_empty() {
                continue;
            }

            for path in &changed_files {
                *file_doc_freq.entry(path.clone()).or_insert(0) += 1;
            }

            if !changed_files.contains(&seed) {
                continue;
            }
            seed_commit_count += 1;
            let commit_pair_mass = 1.0 / changed_files.len() as f64;
            for target in &targets {
                if changed_files.contains(target) {
                    *joint_mass.entry(target.clone()).or_insert(0.0) += commit_pair_mass;
                }
            }
        }

        for target in &targets {
            let df = file_doc_freq.get(target).copied().unwrap_or(0).max(1) as f64;
            let joint = joint_mass.get(target).copied().unwrap_or(0.0);
            let conditional = if seed_commit_count == 0 {
                0.0
            } else {
                joint / seed_commit_count as f64
            };
            let idf = (1.0 + baseline_commit_count / df).ln();
            let score = conditional * idf;
            eprintln!(
                "{} df={} seed_den={} joint={:.15} conditional={:.15} idf={:.15} score={:.15}",
                target.display(),
                file_doc_freq.get(target).copied().unwrap_or(0),
                seed_commit_count,
                joint,
                conditional,
                idf,
                score
            );
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_autogen_agent_host_counted_commits() {
        let root = Path::new("/home/jonathan/Projects/brokkbench/clones/microsoft__autogen");
        let context = super::GitProjectContext::discover(root).unwrap();
        let commits = context
            .recent_commit_changes(super::COMMITS_TO_PROCESS)
            .unwrap();
        let target = PathBuf::from(
            "dotnet/src/Microsoft.AutoGen/AgentHost/Microsoft.AutoGen.AgentHost.csproj",
        );
        let mut canonicalizer = super::RenameCanonicalizer::default();

        for change in commits {
            let changed = change
                .paths
                .iter()
                .map(|path| canonicalizer.canonicalize(path))
                .collect::<BTreeSet<_>>();
            canonicalizer.record_renames(&change.renames);
            if changed.contains(&target) {
                eprintln!("{}", change.id);
            }
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_autogen_agent_host_counted_paths() {
        let root = Path::new("/home/jonathan/Projects/brokkbench/clones/microsoft__autogen");
        let context = super::GitProjectContext::discover(root).unwrap();
        let commits = context
            .recent_commit_changes(super::COMMITS_TO_PROCESS)
            .unwrap();
        let target = PathBuf::from(
            "dotnet/src/Microsoft.AutoGen/AgentHost/Microsoft.AutoGen.AgentHost.csproj",
        );
        let interesting = [
            git2::Oid::from_str("c169df8b7b98687442ea6bbd7eb4efc7c4010610").unwrap(),
            git2::Oid::from_str("6a9c14715b04de653b16a2d1376461e710b80179").unwrap(),
        ]
        .into_iter()
        .collect::<HashSet<_>>();
        let mut canonicalizer = super::RenameCanonicalizer::default();

        for change in commits {
            let original_paths = change.paths.clone();
            let changed = change
                .paths
                .iter()
                .map(|path| canonicalizer.canonicalize(path))
                .collect::<BTreeSet<_>>();
            canonicalizer.record_renames(&change.renames);
            if interesting.contains(&change.id) && changed.contains(&target) {
                eprintln!("commit {}", change.id);
                for path in original_paths {
                    let canonical = canonicalizer.canonicalize(&path);
                    if canonical == target {
                        eprintln!("  {} -> {}", path.display(), canonical.display());
                    }
                }
            }
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_autogen_service_defaults_counted_paths() {
        let root = Path::new("/home/jonathan/Projects/brokkbench/clones/microsoft__autogen");
        let context = super::GitProjectContext::discover(root).unwrap();
        let target = PathBuf::from(
            "dotnet/samples/dev-team/DevTeam.ServiceDefaults/DevTeam.ServiceDefaults.csproj",
        );

        let commits = context
            .recent_commit_changes(super::COMMITS_TO_PROCESS)
            .unwrap();
        let mut canonicalizer = super::RenameCanonicalizer::default();
        for change in &commits {
            let mut counted = BTreeSet::new();
            for path in &change.paths {
                let canonical = canonicalizer.canonicalize(path);
                if canonical == target {
                    counted.insert(path);
                }
            }
            canonicalizer.record_renames(&change.renames);
            if !counted.is_empty() {
                eprintln!("{} {:?}", change.id, counted);
            }
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_autogen_agent_host_appsettings_counted_paths() {
        let root = Path::new("/home/jonathan/Projects/brokkbench/clones/microsoft__autogen");
        let context = super::GitProjectContext::discover(root).unwrap();
        let target = PathBuf::from("dotnet/src/Microsoft.AutoGen/AgentHost/appsettings.json");

        let commits = context
            .recent_commit_changes(super::COMMITS_TO_PROCESS)
            .unwrap();
        let mut canonicalizer = super::RenameCanonicalizer::default();
        for change in &commits {
            let mut counted = BTreeSet::new();
            for path in &change.paths {
                let canonical = canonicalizer.canonicalize(path);
                if canonical == target {
                    counted.insert(path);
                }
            }
            canonicalizer.record_renames(&change.renames);
            if !counted.is_empty() {
                eprintln!("{} {:?}", change.id, counted);
            }
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_autogen_checker_doc_canonicalized_commits() {
        let root = Path::new("/home/jonathan/Projects/brokkbench/clones/microsoft__autogen");
        let context = super::GitProjectContext::discover(root).unwrap();
        let commit_ids = context
            .recent_commit_changes(super::COMMITS_TO_PROCESS)
            .unwrap();
        let mut canonicalizer = super::RenameCanonicalizer::default();
        for change in commit_ids {
            let canonicalized = change
                .paths
                .iter()
                .map(|path| canonicalizer.canonicalize(path))
                .filter(|path| {
                    let path = path.to_string_lossy();
                    path.ends_with("tutorial.md") || path.ends_with("protobuf-message-types.md")
                })
                .collect::<BTreeSet<_>>();
            if !canonicalized.is_empty() {
                eprintln!("{} {:?}", change.id, canonicalized);
            }
            canonicalizer.record_renames(&change.renames);
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_git_scores_for_plume_imports_test2_goal_seed() {
        let workspace = workspace_analyzer(Path::new("/home/jonathan/Projects/plume-merge"));
        let seed = ProjectFile::new(
            workspace.analyzer().project().root().to_path_buf(),
            "src/test/resources/ImportsTest2Goal.java",
        );
        let results =
            super::related_files_by_git(workspace.analyzer(), &hash_map([(seed, 1.0)]), 100)
                .unwrap();
        for entry in results {
            eprintln!("{:.15} {}", entry.score, entry.file.rel_path().display());
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_git_scores_for_plume_imports_test8_base_seed() {
        let workspace = workspace_analyzer(Path::new("/home/jonathan/Projects/plume-merge"));
        let seed = ProjectFile::new(
            workspace.analyzer().project().root().to_path_buf(),
            "src/test/resources/ImportsTest8Base.java",
        );
        let results =
            super::related_files_by_git(workspace.analyzer(), &hash_map([(seed, 1.0)]), 100)
                .unwrap();
        for entry in results {
            eprintln!("{:.15} {}", entry.score, entry.file.rel_path().display());
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_import_resolution_for_plume_imports_test8_base_seed() {
        let workspace = workspace_analyzer(Path::new("/home/jonathan/Projects/plume-merge"));
        let seed = ProjectFile::new(
            workspace.analyzer().project().root().to_path_buf(),
            "src/test/resources/ImportsTest8Base.java",
        );
        let provider = workspace.analyzer().import_analysis_provider().unwrap();
        for code_unit in provider.imported_code_units_of(&seed) {
            eprintln!("{}", code_unit.source().rel_path().display());
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_definitions_for_plume_boolean_column() {
        let workspace = workspace_analyzer(Path::new("/home/jonathan/Projects/plume-merge"));
        for code_unit in workspace
            .analyzer()
            .definitions("tech.tablesaw.api.BooleanColumn")
        {
            eprintln!("{}", code_unit.source().rel_path().display());
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_git_rename_detection_for_external_repos() {
        let autogen_root =
            Path::new("/home/jonathan/Projects/brokkbench/clones/microsoft__autogen");
        let autogen = super::GitProjectContext::discover(autogen_root).unwrap();
        let autogen_change = change_by_id(
            &autogen,
            git2::Oid::from_str("850377c74a10e9d493de6dea1ed706333e05d146").unwrap(),
        );
        eprintln!("autogen renames: {:?}", autogen_change.renames);
        let mut autogen_canon = super::RenameCanonicalizer::default();
        autogen_canon.record_renames(&autogen_change.renames);
        eprintln!(
            "autogen canonical old path -> {}",
            autogen_canon
                .canonicalize(Path::new(
                    "dotnet/samples/AutoGen.Anthropic.Samples/Create_Anthropic_Agent.cs"
                ))
                .display()
        );

        let plume_root = Path::new("/home/jonathan/Projects/plume-merge");
        let plume = super::GitProjectContext::discover(plume_root).unwrap();
        let plume_change = change_by_id(
            &plume,
            git2::Oid::from_str("891e8540ab8a90195e231d1d9fdeed4e05ff044f").unwrap(),
        );
        eprintln!("plume renames: {:?}", plume_change.renames);
        let mut plume_canon = super::RenameCanonicalizer::default();
        plume_canon.record_renames(&plume_change.renames);
        eprintln!(
            "plume canonical old path -> {}",
            plume_canon
                .canonicalize(Path::new(
                    "src/main/java/name/fraser/neil/plaintext/DmpLibrary.java"
                ))
                .display()
        );
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

        assert!(file_by_name(&results, "B.java").is_some());
        assert!(file_by_name(&results, "C.java").is_some());
    }
}
