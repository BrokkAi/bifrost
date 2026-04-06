use crate::analyzer::{CodeUnit, IAnalyzer, ProjectFile};
use crate::profiling;
use git2::{DiffFindOptions, Oid, Repository, Sort};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

const ALPHA: f64 = 0.85;
const CONVERGENCE_EPSILON: f64 = 1.0e-6;
const SCORE_TIE_EPSILON: f64 = 1.0e-9;
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

    let excluded: BTreeSet<_> = seed_weights.keys().cloned().collect();
    let mut results = Vec::new();
    let mut seen = BTreeSet::new();

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

fn append_candidate(
    results: &mut Vec<ProjectFile>,
    seen: &mut BTreeSet<ProjectFile>,
    excluded: &BTreeSet<ProjectFile>,
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
    let mut weights = HashMap::new();
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
    let mut graph = ImportGraph::default();
    let mut import_cache = HashMap::new();
    let mut reverse_cache = HashMap::new();
    let mut frontier: VecDeque<_> = seed_weights.keys().cloned().collect();

    for seed in seed_weights.keys() {
        graph.forward.entry(seed.clone()).or_default();
        graph.reverse.entry(seed.clone()).or_default();
    }

    for _ in 0..IMPORT_DEPTH {
        if frontier.is_empty() {
            break;
        }

        let mut next = VecDeque::new();
        while let Some(file) = frontier.pop_front() {
            for target in imported_files_for(analyzer, &file, &mut import_cache) {
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
                graph
                    .reverse
                    .entry(target)
                    .or_default()
                    .insert(file.clone());
            }

            for source in referencing_files_for(analyzer, &file, &mut reverse_cache) {
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
                graph
                    .reverse
                    .entry(file.clone())
                    .or_default()
                    .insert(source);
            }
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
        for import in analyzer.import_statements_of(file) {
            let before = resolved.len();
            add_definitions_to_files(analyzer.get_definitions(&import), &mut resolved);
            if resolved.len() == before {
                add_definitions_to_files(analyzer.search_definitions(&import, true), &mut resolved);
            }
        }
    }

    cache.insert(file.clone(), resolved.clone());
    resolved
}

fn add_definitions_to_files(
    definitions: impl IntoIterator<Item = CodeUnit>,
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

    let resolved = analyzer
        .import_analysis_provider()
        .map(|provider| provider.referencing_files_of(file))
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
/// - native rename labels still pass cheap sanity checks before they become lineage edges: the compact stem key
///   (lowercased stem with separators removed) must match, and the directly compared old/new blobs must still have
///   near-exact token overlap, so libgit/JGit false positives become add+delete rather than rewritten history
/// - canonicalization follows only those accepted native rename labels; copy/split history is intentionally not
///   recovered by custom blob-similarity heuristics
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

    let commits = {
        let _scope = profiling::scope("relevance::git.recent_commit_ids");
        repo.recent_commit_ids(COMMITS_TO_PROCESS)?
    };
    if commits.is_empty() {
        return Ok(Vec::new());
    }

    let mut file_doc_freq: HashMap<ProjectFile, usize> = HashMap::new();
    let mut joint_mass: HashMap<(ProjectFile, ProjectFile), f64> = HashMap::new();
    let mut seed_commit_count: HashMap<ProjectFile, usize> = HashMap::new();
    let mut canonicalizer = RenameCanonicalizer::default();
    let mut find_commit_ms = 0.0;
    let mut change_ms = 0.0;
    let mut canonicalize_ms = 0.0;
    let mut processed_commits = 0usize;

    let baseline_commit_count = commits.len() as f64;
    {
        let _scope = profiling::scope("relevance::git.score_commits");
        for oid in &commits {
            let started = Instant::now();
            let commit = repo.repo.find_commit(*oid)?;
            find_commit_ms += started.elapsed().as_secs_f64() * 1000.0;

            let started = Instant::now();
            let change = repo.changed_repo_paths_for_commit(&commit)?;
            change_ms += started.elapsed().as_secs_f64() * 1000.0;

            let started = Instant::now();
            canonicalizer.record_renames(&change.renames);
            let changed_files: BTreeSet<_> = change
                .paths
                .into_iter()
                .map(|path| canonicalizer.canonicalize(&path))
                .filter_map(|path| repo.repo_path_to_project_file(&path))
                .collect();
            canonicalize_ms += started.elapsed().as_secs_f64() * 1000.0;
            processed_commits += 1;
            if profiling::enabled() && processed_commits % 5 == 0 {
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

    let mut scores = HashMap::new();
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
    project_root: PathBuf,
    repo_prefix: PathBuf,
}

impl GitProjectContext {
    fn discover(project_root: &Path) -> Option<Self> {
        let project_root = project_root.canonicalize().ok()?;
        let repo = Repository::discover(&project_root).ok()?;
        let repo_root = repo.workdir()?.canonicalize().ok()?;
        if !project_root.starts_with(&repo_root) {
            return None;
        }

        let repo_prefix = project_root.strip_prefix(&repo_root).ok()?.to_path_buf();
        Some(Self {
            repo,
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

    fn recent_commit_ids(&self, limit: usize) -> Result<Vec<Oid>, git2::Error> {
        let mut walk = match self.repo.revwalk() {
            Ok(walk) => walk,
            Err(err) => return Err(err),
        };
        if walk.push_head().is_err() {
            return Ok(Vec::new());
        }
        let _ = walk.set_sorting(Sort::TOPOLOGICAL | Sort::TIME);

        let mut commits = Vec::new();
        for oid in walk.take(limit) {
            commits.push(oid?);
        }
        Ok(commits)
    }

    fn changed_repo_paths_for_commit(
        &self,
        commit: &git2::Commit<'_>,
    ) -> Result<CommitChange, git2::Error> {
        GIT_COMMITS_SCANNED.fetch_add(1, Ordering::Relaxed);
        let current_tree = commit.tree()?;
        let parent_tree = if commit.parent_count() > 0 {
            Some(commit.parent(0)?.tree()?)
        } else {
            None
        };

        let mut diff =
            self.repo
                .diff_tree_to_tree(parent_tree.as_ref(), Some(&current_tree), None)?;

        let mut find_options = DiffFindOptions::new();
        find_options.renames(true);
        find_options.rename_threshold(NATIVE_RENAME_THRESHOLD);
        find_options.dont_ignore_whitespace(true);
        let find_similar_started = Instant::now();
        diff.find_similar(Some(&mut find_options))?;
        GIT_FIND_SIMILAR_MICROS.fetch_add(
            find_similar_started.elapsed().as_micros() as u64,
            Ordering::Relaxed,
        );

        let mut paths = Vec::new();
        let mut renames = Vec::new();
        let mut commit_has_churn = false;
        for delta in diff.deltas() {
            match delta.status() {
                git2::Delta::Added | git2::Delta::Copied | git2::Delta::Modified => {
                    if let Some(path) = delta.new_file().path() {
                        paths.push(path.to_path_buf());
                        if delta.status() == git2::Delta::Added {
                            commit_has_churn = true;
                            GIT_STATUS_ADDED.fetch_add(1, Ordering::Relaxed);
                        } else if delta.status() == git2::Delta::Copied {
                            commit_has_churn = true;
                            GIT_STATUS_COPIED.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                git2::Delta::Deleted => {
                    if let Some(path) = delta.old_file().path() {
                        commit_has_churn = true;
                        GIT_STATUS_DELETED.fetch_add(1, Ordering::Relaxed);
                        paths.push(path.to_path_buf());
                    }
                }
                git2::Delta::Renamed => {
                    commit_has_churn = true;
                    GIT_STATUS_RENAMED.fetch_add(1, Ordering::Relaxed);
                    if let (Some(old_path), Some(new_path)) =
                        (delta.old_file().path(), delta.new_file().path())
                    {
                        GIT_NATIVE_RENAME_CANDIDATES.fetch_add(1, Ordering::Relaxed);
                        let old_path = old_path.to_path_buf();
                        let new_path = new_path.to_path_buf();
                        if native_rename_delta_is_safe(&self.repo, &delta, &old_path, &new_path) {
                            paths.push(new_path.clone());
                            renames.push((old_path, new_path));
                        } else {
                            paths.push(old_path);
                            paths.push(new_path);
                        }
                    }
                }
                _ => {}
            }
        }
        if commit_has_churn {
            GIT_COMMITS_WITH_CHURN.fetch_add(1, Ordering::Relaxed);
        }

        Ok(CommitChange { paths, renames })
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
}

struct CommitChange {
    paths: Vec<PathBuf>,
    renames: Vec<(PathBuf, PathBuf)>,
}

fn native_rename_delta_is_safe(
    repo: &Repository,
    delta: &git2::DiffDelta<'_>,
    old_path: &Path,
    new_path: &Path,
) -> bool {
    native_rename_path_keys_match(old_path, new_path)
        && native_rename_token_overlap_ratio(repo, delta)
            .is_some_and(|ratio| ratio >= NATIVE_RENAME_TOKEN_OVERLAP_THRESHOLD)
}

fn native_rename_path_keys_match(old_path: &Path, new_path: &Path) -> bool {
    let old_key = compact_stem_key(old_path);
    let new_key = compact_stem_key(new_path);
    !old_key.is_empty() && old_key == new_key
}

fn native_rename_token_overlap_ratio(
    repo: &Repository,
    delta: &git2::DiffDelta<'_>,
) -> Option<f64> {
    let old_blob = repo.find_blob(delta.old_file().id()).ok()?;
    let new_blob = repo.find_blob(delta.new_file().id()).ok()?;
    let old_tokens = blob_token_set(&old_blob);
    let new_tokens = blob_token_set(&new_blob);
    let max_tokens = old_tokens.len().max(new_tokens.len());
    if max_tokens == 0 {
        return Some(1.0);
    }
    let overlap = old_tokens.intersection(&new_tokens).count();
    Some(overlap as f64 / max_tokens as f64)
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
        let mut seen = HashSet::new();
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

fn compare_file_relevance(left: &FileRelevance, right: &FileRelevance) -> std::cmp::Ordering {
    let score_gap = right.score - left.score;
    let score_scale = 1.0_f64.max(left.score.abs()).max(right.score.abs());
    if score_gap.abs() <= SCORE_TIE_EPSILON * score_scale {
        normalized_rel_path(&left.file).cmp(&normalized_rel_path(&right.file))
    } else {
        right
            .score
            .partial_cmp(&left.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| normalized_rel_path(&left.file).cmp(&normalized_rel_path(&right.file)))
    }
}

#[cfg(test)]
mod tests {
    use super::{FileRelevance, related_files_by_imports};
    use crate::analyzer::{
        AnalyzerConfig, AnalyzerDelegate, FilesystemProject, JavaAnalyzer, Language,
        MultiAnalyzer, ProjectFile, PythonAnalyzer, TestProject, WorkspaceAnalyzer,
    };
    use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use tempfile::TempDir;

    fn write_file(root: &Path, rel_path: &str, contents: &str) -> ProjectFile {
        let file = ProjectFile::new(root.to_path_buf(), rel_path);
        file.write(contents).unwrap();
        file
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

    fn java_analyzer(root: &Path) -> JavaAnalyzer {
        JavaAnalyzer::from_project(TestProject::new(root.to_path_buf(), Language::Java))
    }

    fn workspace_analyzer(root: &Path) -> WorkspaceAnalyzer {
        let project = Arc::new(FilesystemProject::new(root).unwrap());
        WorkspaceAnalyzer::build(project, AnalyzerConfig::default())
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
            super::related_files_by_git(workspace.analyzer(), &HashMap::from([(seed, 1.0)]), 25)
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
        let seeds = HashMap::from([
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
            ProjectFile::new(
                root.clone(),
                "src/VecSim/utils/arr_cpp.h",
            ),
            ProjectFile::new(
                root.clone(),
                "src/VecSim/algorithms/hnsw/hnsw.h",
            ),
            ProjectFile::new(
                root.clone(),
                "src/VecSim/algorithms/brute_force/brute_force_multi.h",
            ),
            ProjectFile::new(
                root.clone(),
                "src/VecSim/spaces/IP/IP_AVX512_FP32.cpp",
            ),
            ProjectFile::new(
                root.clone(),
                "src/VecSim/spaces/L2_space.h",
            ),
            ProjectFile::new(
                root.clone(),
                "src/VecSim/index_factories/brute_force_factory.cpp",
            ),
            ProjectFile::new(
                root.clone(),
                "tests/benchmark/spaces_benchmarks/bm_spaces_class_definitions.h",
            ),
        ];

        let git = super::related_files_by_git(workspace.analyzer(), &HashMap::from([(seed.clone(), 1.0)]), 100)
            .unwrap();
        println!("git top 100");
        for entry in &git {
            if targets.iter().any(|target| *target == entry.file) {
                println!("  target git {:.15} {}", entry.score, entry.file.rel_path().display());
            }
        }

        let imports =
            super::related_files_by_imports(workspace.analyzer(), &HashMap::from([(seed, 1.0)]), 100, false);
        println!("imports top 100");
        for entry in &imports {
            if targets.iter().any(|target| *target == entry.file) {
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

        let repo = super::GitProjectContext::discover(workspace.analyzer().project().root()).unwrap();
        let commit_ids = repo.recent_commit_ids(super::COMMITS_TO_PROCESS).unwrap();
        let mut canonicalizer = super::RenameCanonicalizer::default();
        for oid in &commit_ids {
            let commit = repo.repo.find_commit(*oid).unwrap();
            let change = repo.changed_repo_paths_for_commit(&commit).unwrap();
            canonicalizer.record_renames(&change.renames);

            let changed_files = change
                .paths
                .iter()
                .map(|path| canonicalizer.canonicalize(path))
                .filter_map(|repo_rel| repo.repo_path_to_project_file(&repo_rel))
                .collect::<Vec<_>>();
            if changed_files.contains(&seed) {
                if changed_files.contains(&fp32)
                    || changed_files.contains(&definitions)
                    || changed_files.contains(&brute_force_factory)
                    || changed_files.contains(&l2_space)
                    || changed_files.contains(&test_bruteforce)
                    || changed_files.contains(&vec_sim_cpp)
                    || changed_files.contains(&vec_sim_h)
                    || changed_files.contains(&bindings)
                    || changed_files.contains(&flow_test)
                {
                    eprintln!("commit {} size={}", oid, changed_files.len());
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
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_vector_similarity_query_result_struct_git_scores() {
        let workspace = workspace_analyzer(Path::new("/home/jonathan/Projects/VectorSimilarity"));
        let context = super::GitProjectContext::discover(workspace.analyzer().project().root()).unwrap();
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

        let commits = context.recent_commit_ids(super::COMMITS_TO_PROCESS).unwrap();
        let baseline_commit_count = commits.len() as f64;
        let mut file_doc_freq: HashMap<ProjectFile, usize> = HashMap::new();
        let mut joint_mass: HashMap<ProjectFile, f64> = HashMap::new();
        let mut seed_commit_count = 0usize;
        let mut canonicalizer = super::RenameCanonicalizer::default();

        for oid in &commits {
            let commit = context.repo.find_commit(*oid).unwrap();
            let change = context.changed_repo_paths_for_commit(&commit).unwrap();
            canonicalizer.record_renames(&change.renames);
            let changed_files = change
                .paths
                .into_iter()
                .map(|path| canonicalizer.canonicalize(&path))
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
        let repo = super::GitProjectContext::discover(workspace.analyzer().project().root()).unwrap();
        let oid = git2::Oid::from_str("493c78d1ef6035c27067137f3ab02d280f67cac2").unwrap();
        let commit = repo.repo.find_commit(oid).unwrap();
        let change = repo.changed_repo_paths_for_commit(&commit).unwrap();
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
        let repo = super::GitProjectContext::discover(workspace.analyzer().project().root()).unwrap();
        let oid = git2::Oid::from_str("17985eda88a0fa9da910d346aa0f3656f419f2b5").unwrap();
        let commit = repo.repo.find_commit(oid).unwrap();
        let change = repo.changed_repo_paths_for_commit(&commit).unwrap();
        eprintln!("renames:");
        for (old_path, new_path) in &change.renames {
            eprintln!("  {} -> {}", old_path.display(), new_path.display());
        }
        eprintln!("paths:");
        for path in &change.paths {
            if path.to_string_lossy().contains("L2") || path.to_string_lossy().contains("internal_product") {
                eprintln!("  {}", path.display());
            }
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_vector_similarity_bruteforce_move_commit_renames() {
        let workspace = workspace_analyzer(Path::new("/home/jonathan/Projects/VectorSimilarity"));
        let repo = super::GitProjectContext::discover(workspace.analyzer().project().root()).unwrap();
        let oid = git2::Oid::from_str("e2f3da57fe43ce500f58e4dbe5291e35ada31bee").unwrap();
        let commit = repo.repo.find_commit(oid).unwrap();
        let change = repo.changed_repo_paths_for_commit(&commit).unwrap();
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
            super::related_files_by_git(workspace.analyzer(), &HashMap::from([(seed, 1.0)]), 25)
                .unwrap();
        for entry in results {
            eprintln!("{:.15} {}", entry.score, entry.file.rel_path().display());
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_git_scores_for_autogen_program_seed() {
        let workspace =
            workspace_analyzer(Path::new("/home/jonathan/Projects/brokkbench/clones/microsoft__autogen"));
        let seed = ProjectFile::new(
            workspace.analyzer().project().root().to_path_buf(),
            "dotnet/samples/AgentChat/AutoGen.Anthropic.Sample/Program.cs",
        );
        let results =
            super::related_files_by_git(workspace.analyzer(), &HashMap::from([(seed, 1.0)]), 25)
                .unwrap();
        for entry in results {
            eprintln!("{:.15} {}", entry.score, entry.file.rel_path().display());
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_git_scores_for_autogen_checker_seed() {
        let workspace =
            workspace_analyzer(Path::new("/home/jonathan/Projects/brokkbench/clones/microsoft__autogen"));
        let seed = ProjectFile::new(
            workspace.analyzer().project().root().to_path_buf(),
            "dotnet/samples/GettingStarted/Checker.cs",
        );
        let results =
            super::related_files_by_git(workspace.analyzer(), &HashMap::from([(seed, 1.0)]), 30)
                .unwrap();
        for entry in results {
            eprintln!("{:.15} {}", entry.score, entry.file.rel_path().display());
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_git_scores_for_autogen_hello_ai_agents_program_seed() {
        let workspace =
            workspace_analyzer(Path::new("/home/jonathan/Projects/brokkbench/clones/microsoft__autogen"));
        let seed = ProjectFile::new(
            workspace.analyzer().project().root().to_path_buf(),
            "dotnet/samples/Hello/HelloAIAgents/Program.cs",
        );
        let results =
            super::related_files_by_git(workspace.analyzer(), &HashMap::from([(seed, 1.0)]), 40)
                .unwrap();
        for entry in results {
            eprintln!("{:.15} {}", entry.score, entry.file.rel_path().display());
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_git_scores_for_autogen_hello_agent_program_seed() {
        let workspace =
            workspace_analyzer(Path::new("/home/jonathan/Projects/brokkbench/clones/microsoft__autogen"));
        let seed = ProjectFile::new(
            workspace.analyzer().project().root().to_path_buf(),
            "dotnet/samples/Hello/HelloAgent/Program.cs",
        );
        let results =
            super::related_files_by_git(workspace.analyzer(), &HashMap::from([(seed, 1.0)]), 100)
                .unwrap();
        for entry in results {
            eprintln!("{:.15} {}", entry.score, entry.file.rel_path().display());
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_import_scores_for_autogen_hello_ai_agents_program_seed() {
        let workspace =
            workspace_analyzer(Path::new("/home/jonathan/Projects/brokkbench/clones/microsoft__autogen"));
        let seed = ProjectFile::new(
            workspace.analyzer().project().root().to_path_buf(),
            "dotnet/samples/Hello/HelloAIAgents/Program.cs",
        );
        let results =
            super::related_files_by_imports(workspace.analyzer(), &HashMap::from([(seed, 1.0)]), 40, false);
        for entry in results {
            eprintln!("{:.15} {}", entry.score, entry.file.rel_path().display());
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_import_scores_for_autogen_checker_seed() {
        let workspace =
            workspace_analyzer(Path::new("/home/jonathan/Projects/brokkbench/clones/microsoft__autogen"));
        let seed = ProjectFile::new(
            workspace.analyzer().project().root().to_path_buf(),
            "dotnet/samples/GettingStarted/Checker.cs",
        );
        let results =
            super::related_files_by_imports(workspace.analyzer(), &HashMap::from([(seed, 1.0)]), 100, false);
        for entry in &results {
            let path = entry.file.rel_path();
            if path == Path::new(
                "dotnet/samples/AgentChat/AutoGen.Anthropic.Sample/Anthropic_Agent_With_Prompt_Caching.cs",
            ) || path
                == Path::new("dotnet/samples/AgentChat/AutoGen.Anthropic.Sample/AutoGen.Anthropic.Sample.csproj")
            {
                println!("target {:.15} {}", entry.score, entry.file.rel_path().display());
            }
        }
        for entry in results {
            println!("{:.15} {}", entry.score, entry.file.rel_path().display());
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_git_scores_for_autogen_topicid_and_inmemoryruntime_pair() {
        let workspace =
            workspace_analyzer(Path::new("/home/jonathan/Projects/brokkbench/clones/microsoft__autogen"));
        let root = workspace.analyzer().project().root().to_path_buf();
        let topic_id = ProjectFile::new(root.clone(), "dotnet/src/Microsoft.AutoGen/Contracts/TopicId.cs");
        let inmemory = ProjectFile::new(
            root,
            "dotnet/test/Microsoft.AutoGen.Integration.Tests/InMemoryRuntimeIntegrationTests.cs",
        );
        let results = super::related_files_by_git(
            workspace.analyzer(),
            &HashMap::from([(topic_id, 1.0), (inmemory, 1.0)]),
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
        let workspace =
            workspace_analyzer(Path::new("/home/jonathan/Projects/brokkbench/clones/microsoft__autogen"));
        let root = workspace.analyzer().project().root().to_path_buf();
        let topic_id = ProjectFile::new(root.clone(), "dotnet/src/Microsoft.AutoGen/Contracts/TopicId.cs");
        let inmemory = ProjectFile::new(
            root,
            "dotnet/test/Microsoft.AutoGen.Integration.Tests/InMemoryRuntimeIntegrationTests.cs",
        );
        let results = super::related_files_by_imports(
            workspace.analyzer(),
            &HashMap::from([(topic_id, 1.0), (inmemory, 1.0)]),
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
            PathBuf::from("dotnet/src/Microsoft.AutoGen/Agents/IOAgent/ConsoleAgent/IHandleConsole.cs"),
            PathBuf::from("dotnet/src/Microsoft.AutoGen/Core/AgentsApp.cs"),
            PathBuf::from("dotnet/test/Microsoft.AutoGen.Core.Tests/InProcessRuntimeTests.cs"),
        ];

        let commits = context.recent_commit_ids(super::COMMITS_TO_PROCESS).unwrap();
        let baseline_commit_count = commits.len() as f64;
        let mut file_doc_freq: HashMap<PathBuf, usize> = HashMap::new();
        let mut joint_mass: HashMap<(PathBuf, PathBuf), f64> = HashMap::new();
        let mut seed_commit_count: HashMap<PathBuf, usize> = HashMap::new();
        let mut canonicalizer = super::RenameCanonicalizer::default();

        for oid in &commits {
            let commit = context.repo.find_commit(*oid).unwrap();
            let change = context.changed_repo_paths_for_commit(&commit).unwrap();
            let changed_files = change
                .paths
                .into_iter()
                .map(|path| canonicalizer.canonicalize(&path))
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
            eprintln!("target={} df={} idf={:.15}", target.display(), df as usize, idf);
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
            (
                inmemory.clone(),
                PathBuf::from("dotnet/AutoGen.sln"),
            ),
        ];

        let commits = context.recent_commit_ids(super::COMMITS_TO_PROCESS).unwrap();
        let mut canonicalizer = super::RenameCanonicalizer::default();
        for oid in &commits {
            let commit = context.repo.find_commit(*oid).unwrap();
            let change = context.changed_repo_paths_for_commit(&commit).unwrap();
            let changed_files = change
                .paths
                .into_iter()
                .map(|path| canonicalizer.canonicalize(&path))
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
                        commit.id(),
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

        let commits = context.recent_commit_ids(super::COMMITS_TO_PROCESS).unwrap();
        let mut canonicalizer = super::RenameCanonicalizer::default();
        for oid in &commits {
            let commit = context.repo.find_commit(*oid).unwrap();
            let change = context.changed_repo_paths_for_commit(&commit).unwrap();
            let changed_files = change
                .paths
                .into_iter()
                .map(|path| canonicalizer.canonicalize(&path))
                .filter_map(|path| context.repo_path_to_project_file(&path))
                .map(|file| file.rel_path().to_path_buf())
                .collect::<BTreeSet<_>>();
            canonicalizer.record_renames(&change.renames);
            if interesting.contains(oid) {
                eprintln!("commit={} size={}", commit.id(), changed_files.len());
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
        let target = PathBuf::from("dotnet/test/Microsoft.AutoGen.Core.Tests/InProcessRuntimeTests.cs");
        let interesting = git2::Oid::from_str("b16b94feb8bd89ef07c14fc7f34419490924b993").unwrap();

        let commits = context.recent_commit_ids(super::COMMITS_TO_PROCESS).unwrap();
        let mut canonicalizer = super::RenameCanonicalizer::default();
        for oid in &commits {
            let commit = context.repo.find_commit(*oid).unwrap();
            let change = context.changed_repo_paths_for_commit(&commit).unwrap();
            if *oid == interesting {
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

        let commits = context.recent_commit_ids(super::COMMITS_TO_PROCESS).unwrap();
        let mut file_doc_freq: HashMap<PathBuf, usize> = HashMap::new();
        let mut joint_mass: HashMap<PathBuf, f64> = HashMap::new();
        let mut seed_commit_count = 0usize;
        let mut canonicalizer = super::RenameCanonicalizer::default();

        for oid in &commits {
            let commit = context.repo.find_commit(*oid).unwrap();
            let change = context.changed_repo_paths_for_commit(&commit).unwrap();
            let changed_files = change
                .paths
                .into_iter()
                .map(|path| canonicalizer.canonicalize(&path))
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
                        commit.id(),
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

        let commits = context.recent_commit_ids(super::COMMITS_TO_PROCESS).unwrap();
        let baseline_commit_count = commits.len() as f64;
        let mut file_doc_freq: HashMap<PathBuf, usize> = HashMap::new();
        let mut joint_mass: HashMap<PathBuf, f64> = HashMap::new();
        let mut seed_commit_count = 0usize;
        let mut canonicalizer = super::RenameCanonicalizer::default();

        for oid in &commits {
            let commit = context.repo.find_commit(*oid).unwrap();
            let change = context.changed_repo_paths_for_commit(&commit).unwrap();
            let changed_files = change
                .paths
                .into_iter()
                .map(|path| canonicalizer.canonicalize(&path))
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
        let agent_host =
            PathBuf::from("dotnet/src/Microsoft.AutoGen/AgentHost/Microsoft.AutoGen.AgentHost.csproj");

        let commits = context.recent_commit_ids(super::COMMITS_TO_PROCESS).unwrap();
        let mut file_doc_freq: HashMap<PathBuf, usize> = HashMap::new();
        let mut joint_mass: HashMap<PathBuf, f64> = HashMap::new();
        let mut seed_commit_count = 0usize;
        let mut canonicalizer = super::RenameCanonicalizer::default();

        for oid in &commits {
            let commit = context.repo.find_commit(*oid).unwrap();
            let change = context.changed_repo_paths_for_commit(&commit).unwrap();
            let changed_files = change
                .paths
                .into_iter()
                .map(|path| canonicalizer.canonicalize(&path))
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
                        commit.id(),
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
            PathBuf::from("dotnet/src/Microsoft.AutoGen/Agents/IOAgent/ConsoleAgent/IHandleConsole.cs"),
            PathBuf::from("python/samples/core_xlang_hello_python_agent/protos/agent_events_pb2.py"),
            PathBuf::from("dotnet/samples/dev-team/DevTeam.ServiceDefaults/DevTeam.ServiceDefaults.csproj"),
            PathBuf::from("dotnet/test/Microsoft.AutoGen.Integration.Tests/HelloAppHostIntegrationTests.cs"),
            PathBuf::from("dotnet/samples/dev-team/DevTeam.Backend/Program.cs"),
            PathBuf::from("dotnet/test/Microsoft.AutoGen.Core.Tests/Microsoft.AutoGen.Core.Tests.csproj"),
        ];

        let commits = context.recent_commit_ids(super::COMMITS_TO_PROCESS).unwrap();
        let baseline_commit_count = commits.len() as f64;
        let mut file_doc_freq: HashMap<PathBuf, usize> = HashMap::new();
        let mut joint_mass: HashMap<PathBuf, f64> = HashMap::new();
        let mut seed_commit_count = 0usize;
        let mut canonicalizer = super::RenameCanonicalizer::default();

        for oid in &commits {
            let commit = context.repo.find_commit(*oid).unwrap();
            let change = context.changed_repo_paths_for_commit(&commit).unwrap();
            let changed_files = change
                .paths
                .into_iter()
                .map(|path| canonicalizer.canonicalize(&path))
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

        let commits = context.recent_commit_ids(super::COMMITS_TO_PROCESS).unwrap();
        let baseline_commit_count = commits.len() as f64;
        let mut file_doc_freq: HashMap<PathBuf, usize> = HashMap::new();
        let mut joint_mass: HashMap<PathBuf, f64> = HashMap::new();
        let mut seed_commit_count = 0usize;
        let mut canonicalizer = super::RenameCanonicalizer::default();

        for oid in &commits {
            let commit = context.repo.find_commit(*oid).unwrap();
            let change = context.changed_repo_paths_for_commit(&commit).unwrap();
            let changed_files = change
                .paths
                .into_iter()
                .map(|path| canonicalizer.canonicalize(&path))
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
    fn autogen_add_subscription_follow_history_counts_runtime_gateway_rename() {
        let root = Path::new("/home/jonathan/Projects/brokkbench/clones/microsoft__autogen");
        if !root.is_dir() {
            eprintln!("skipping autogen rename regression: repo not present");
            return;
        }

        let context = super::GitProjectContext::discover(root).unwrap();
        let commits = context.recent_commit_ids(super::COMMITS_TO_PROCESS).unwrap();
        let target = PathBuf::from(
            "dotnet/src/Microsoft.AutoGen/RuntimeGateway.Grpc/Services/Orleans/Surrogates/AddSubscriptionRequestSurrogate.cs",
        );
        let mut canonicalizer = super::RenameCanonicalizer::default();
        let mut doc_freq = 0usize;

        for oid in commits {
            let commit = context.repo.find_commit(oid).unwrap();
            let change = context.changed_repo_paths_for_commit(&commit).unwrap();
            let changed = change
                .paths
                .into_iter()
                .map(|path| canonicalizer.canonicalize(&path))
                .collect::<BTreeSet<_>>();
            canonicalizer.record_renames(&change.renames);
            if changed.contains(&target) {
                doc_freq += 1;
            }
        }

        assert_eq!(3, doc_freq);
    }

    #[test]
    fn native_rename_sanity_accepts_installation_doc_rename() {
        assert!(super::native_rename_path_keys_match(
            Path::new("docs/dotnet/user-guide/core-user-guide/installation.md"),
            Path::new("docs/dotnet/core/installation.md"),
        ));
    }

    #[test]
    fn native_rename_sanity_accepts_agent_host_casing_rename() {
        assert!(super::native_rename_path_keys_match(
            Path::new("dotnet/src/Microsoft.AutoGen/AgentHost/Microsoft.Autogen.AgentHost.csproj"),
            Path::new("dotnet/src/Microsoft.AutoGen/AgentHost/Microsoft.AutoGen.AgentHost.csproj"),
        ));
    }

    #[test]
    fn native_rename_sanity_rejects_agent_runtime_to_inprocess() {
        assert!(!super::native_rename_path_keys_match(
            Path::new("dotnet/test/Microsoft.AutoGen.Core.Tests/AgentRuntimeTests.cs"),
            Path::new("dotnet/test/Microsoft.AutoGen.Core.Tests/InProcessRuntimeTests.cs"),
        ));
    }

    #[test]
    fn native_rename_sanity_rejects_anthropic_samples_pluralization() {
        assert!(!super::native_rename_path_keys_match(
            Path::new("dotnet/samples/AutoGen.Anthropic.Samples/AutoGen.Anthropic.Samples.csproj"),
            Path::new("dotnet/samples/AgentChat/AutoGen.Anthropic.Sample/AutoGen.Anthropic.Sample.csproj"),
        ));
    }

    #[test]
    fn native_rename_sanity_rejects_vector_similarity_definitions_suffix() {
        assert!(!super::native_rename_path_keys_match(
            Path::new("tests/benchmark/bm_spaces_class.cpp"),
            Path::new("tests/benchmark/spaces_benchmarks/bm_spaces_class_definitions.h"),
        ));
    }

    #[test]
    fn native_rename_sanity_rejects_vector_similarity_bruteforce_factory_move() {
        let root = Path::new("/home/jonathan/Projects/VectorSimilarity");
        if !root.is_dir() {
            eprintln!("skipping vectorsim rename threshold regression: repo not present");
            return;
        }

        let context = super::GitProjectContext::discover(root).unwrap();
        let oid = git2::Oid::from_str("e2f3da57fe43ce500f58e4dbe5291e35ada31bee").unwrap();
        let commit = context.repo.find_commit(oid).unwrap();
        let change = context.changed_repo_paths_for_commit(&commit).unwrap();

        assert!(
            !change.renames.iter().any(|(old_path, new_path)| {
                old_path == Path::new("src/VecSim/algorithms/brute_force/brute_force_factory.cpp")
                    && new_path == Path::new("src/VecSim/index_factories/brute_force_factory.cpp")
            }),
            "native rename should be rejected by the shared stem-only guard"
        );
        assert!(change.paths.contains(&PathBuf::from(
            "src/VecSim/algorithms/brute_force/brute_force_factory.cpp"
        )));
        assert!(change
            .paths
            .contains(&PathBuf::from("src/VecSim/index_factories/brute_force_factory.cpp")));
    }

    #[test]
    fn autogen_agent_host_follow_history_counts_case_rename() {
        let root = Path::new("/home/jonathan/Projects/brokkbench/clones/microsoft__autogen");
        if !root.is_dir() {
            eprintln!("skipping autogen rename regression: repo not present");
            return;
        }

        let context = super::GitProjectContext::discover(root).unwrap();
        let commits = context.recent_commit_ids(super::COMMITS_TO_PROCESS).unwrap();
        let target =
            PathBuf::from("dotnet/src/Microsoft.AutoGen/AgentHost/Microsoft.AutoGen.AgentHost.csproj");
        let mut canonicalizer = super::RenameCanonicalizer::default();
        let mut doc_freq = 0usize;

        for oid in commits {
            let commit = context.repo.find_commit(oid).unwrap();
            let change = context.changed_repo_paths_for_commit(&commit).unwrap();
            let changed = change
                .paths
                .into_iter()
                .map(|path| canonicalizer.canonicalize(&path))
                .collect::<BTreeSet<_>>();
            canonicalizer.record_renames(&change.renames);
            if changed.contains(&target) {
                doc_freq += 1;
            }
        }

        assert_eq!(4, doc_freq);
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_autogen_agent_host_counted_commits() {
        let root = Path::new("/home/jonathan/Projects/brokkbench/clones/microsoft__autogen");
        let context = super::GitProjectContext::discover(root).unwrap();
        let commits = context.recent_commit_ids(super::COMMITS_TO_PROCESS).unwrap();
        let target =
            PathBuf::from("dotnet/src/Microsoft.AutoGen/AgentHost/Microsoft.AutoGen.AgentHost.csproj");
        let mut canonicalizer = super::RenameCanonicalizer::default();

        for oid in commits {
            let commit = context.repo.find_commit(oid).unwrap();
            let change = context.changed_repo_paths_for_commit(&commit).unwrap();
            let changed = change
                .paths
                .into_iter()
                .map(|path| canonicalizer.canonicalize(&path))
                .collect::<BTreeSet<_>>();
            canonicalizer.record_renames(&change.renames);
            if changed.contains(&target) {
                eprintln!("{}", commit.id());
            }
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_autogen_agent_host_counted_paths() {
        let root = Path::new("/home/jonathan/Projects/brokkbench/clones/microsoft__autogen");
        let context = super::GitProjectContext::discover(root).unwrap();
        let commits = context.recent_commit_ids(super::COMMITS_TO_PROCESS).unwrap();
        let target =
            PathBuf::from("dotnet/src/Microsoft.AutoGen/AgentHost/Microsoft.AutoGen.AgentHost.csproj");
        let interesting = [
            git2::Oid::from_str("c169df8b7b98687442ea6bbd7eb4efc7c4010610").unwrap(),
            git2::Oid::from_str("6a9c14715b04de653b16a2d1376461e710b80179").unwrap(),
        ]
        .into_iter()
        .collect::<HashSet<_>>();
        let mut canonicalizer = super::RenameCanonicalizer::default();

        for oid in commits {
            let commit = context.repo.find_commit(oid).unwrap();
            let change = context.changed_repo_paths_for_commit(&commit).unwrap();
            let original_paths = change.paths.clone();
            let changed = change
                .paths
                .into_iter()
                .map(|path| canonicalizer.canonicalize(&path))
                .collect::<BTreeSet<_>>();
            canonicalizer.record_renames(&change.renames);
            if interesting.contains(&oid) && changed.contains(&target) {
                eprintln!("commit {}", oid);
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
        let target =
            PathBuf::from("dotnet/samples/dev-team/DevTeam.ServiceDefaults/DevTeam.ServiceDefaults.csproj");

        let commits = context.recent_commit_ids(super::COMMITS_TO_PROCESS).unwrap();
        let mut canonicalizer = super::RenameCanonicalizer::default();
        for oid in &commits {
            let commit = context.repo.find_commit(*oid).unwrap();
            let change = context.changed_repo_paths_for_commit(&commit).unwrap();
            let mut counted = BTreeSet::new();
            for path in change.paths {
                let canonical = canonicalizer.canonicalize(&path);
                if canonical == target {
                    counted.insert(path);
                }
            }
            canonicalizer.record_renames(&change.renames);
            if !counted.is_empty() {
                eprintln!("{} {:?}", commit.id(), counted);
            }
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_autogen_agent_host_appsettings_counted_paths() {
        let root = Path::new("/home/jonathan/Projects/brokkbench/clones/microsoft__autogen");
        let context = super::GitProjectContext::discover(root).unwrap();
        let target = PathBuf::from("dotnet/src/Microsoft.AutoGen/AgentHost/appsettings.json");

        let commits = context.recent_commit_ids(super::COMMITS_TO_PROCESS).unwrap();
        let mut canonicalizer = super::RenameCanonicalizer::default();
        for oid in &commits {
            let commit = context.repo.find_commit(*oid).unwrap();
            let change = context.changed_repo_paths_for_commit(&commit).unwrap();
            let mut counted = BTreeSet::new();
            for path in change.paths {
                let canonical = canonicalizer.canonicalize(&path);
                if canonical == target {
                    counted.insert(path);
                }
            }
            canonicalizer.record_renames(&change.renames);
            if !counted.is_empty() {
                eprintln!("{} {:?}", commit.id(), counted);
            }
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_autogen_checker_doc_canonicalized_commits() {
        let root = Path::new("/home/jonathan/Projects/brokkbench/clones/microsoft__autogen");
        let context = super::GitProjectContext::discover(root).unwrap();
        let commit_ids = context.recent_commit_ids(super::COMMITS_TO_PROCESS).unwrap();
        let mut canonicalizer = super::RenameCanonicalizer::default();
        for oid in commit_ids {
            let commit = context.repo.find_commit(oid).unwrap();
            let change = context.changed_repo_paths_for_commit(&commit).unwrap();
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
                eprintln!("{} {:?}", commit.id(), canonicalized);
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
            super::related_files_by_git(workspace.analyzer(), &HashMap::from([(seed, 1.0)]), 100)
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
            super::related_files_by_git(workspace.analyzer(), &HashMap::from([(seed, 1.0)]), 100)
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
            .get_definitions("tech.tablesaw.api.BooleanColumn")
        {
            eprintln!("{}", code_unit.source().rel_path().display());
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn debug_git_rename_detection_for_external_repos() {
        let autogen_root = Path::new("/home/jonathan/Projects/brokkbench/clones/microsoft__autogen");
        let autogen = super::GitProjectContext::discover(autogen_root).unwrap();
        let autogen_commit = autogen
            .repo
            .find_commit(git2::Oid::from_str("850377c74a10e9d493de6dea1ed706333e05d146").unwrap())
            .unwrap();
        let autogen_change = autogen.changed_repo_paths_for_commit(&autogen_commit).unwrap();
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
        let plume_commit = plume
            .repo
            .find_commit(git2::Oid::from_str("891e8540ab8a90195e231d1d9fdeed4e05ff044f").unwrap())
            .unwrap();
        let plume_change = plume.changed_repo_paths_for_commit(&plume_commit).unwrap();
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
    fn autogen_large_rename_commit_detects_agent_metadata_move() {
        let root = Path::new("/home/jonathan/Projects/brokkbench/clones/microsoft__autogen");
        if !root.is_dir() {
            eprintln!("skipping autogen rename regression: repo not present");
            return;
        }

        let context = super::GitProjectContext::discover(root).unwrap();
        let commit = context
            .repo
            .find_commit(git2::Oid::from_str(
                "b16b94feb8bd89ef07c14fc7f34419490924b993",
            )
            .unwrap())
            .unwrap();
        let change = context.changed_repo_paths_for_commit(&commit).unwrap();
        let expected = (
            PathBuf::from("dotnet/src/Microsoft.AutoGen/Contracts/PythonEquiv/AgentMetadata.cs"),
            PathBuf::from("dotnet/src/Microsoft.AutoGen/Contracts/AgentMetadata.cs"),
        );

        assert!(
            change.renames.contains(&expected),
            "{:?}",
            change.renames
        );
    }

    #[test]
    fn autogen_agent_metadata_follow_history_counts_python_equiv_commits() {
        let root = Path::new("/home/jonathan/Projects/brokkbench/clones/microsoft__autogen");
        if !root.is_dir() {
            eprintln!("skipping autogen rename regression: repo not present");
            return;
        }

        let context = super::GitProjectContext::discover(root).unwrap();
        let commits = context.recent_commit_ids(super::COMMITS_TO_PROCESS).unwrap();
        let target = PathBuf::from("dotnet/src/Microsoft.AutoGen/Contracts/AgentMetadata.cs");
        let mut canonicalizer = super::RenameCanonicalizer::default();
        let mut doc_freq = 0usize;

        for oid in commits {
            let commit = context.repo.find_commit(oid).unwrap();
            let change = context.changed_repo_paths_for_commit(&commit).unwrap();
            let changed = change
                .paths
                .into_iter()
                .map(|path| canonicalizer.canonicalize(&path))
                .collect::<BTreeSet<_>>();
            canonicalizer.record_renames(&change.renames);
            if changed.contains(&target) {
                doc_freq += 1;
            }
        }

        assert_eq!(5, doc_freq);
    }

    #[test]
    fn autogen_agent_runtime_tests_do_not_follow_to_inprocess_runtime_tests() {
        let root = Path::new("/home/jonathan/Projects/brokkbench/clones/microsoft__autogen");
        if !root.is_dir() {
            eprintln!("skipping autogen rename regression: repo not present");
            return;
        }

        let context = super::GitProjectContext::discover(root).unwrap();
        let commits = context.recent_commit_ids(super::COMMITS_TO_PROCESS).unwrap();
        let old_path =
            PathBuf::from("dotnet/test/Microsoft.AutoGen.Core.Tests/AgentRuntimeTests.cs");
        let expected = old_path.clone();
        let mut canonicalizer = super::RenameCanonicalizer::default();

        for oid in commits {
            let commit = context.repo.find_commit(oid).unwrap();
            if commit.id()
                == git2::Oid::from_str("b16b94feb8bd89ef07c14fc7f34419490924b993").unwrap()
            {
                assert_eq!(expected, canonicalizer.canonicalize(&old_path));
                return;
            }
            let change = context.changed_repo_paths_for_commit(&commit).unwrap();
            canonicalizer.record_renames(&change.renames);
        }

        panic!("autogen baseline window did not include target commit");
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
        let results =
            related_files_by_imports(&analyzer, &HashMap::from([(a.clone(), 1.0)]), 10, false);

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
        let results = related_files_by_imports(&analyzer, &HashMap::from([(leaf, 1.0)]), 10, false);

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
        let results = related_files_by_imports(&analyzer, &HashMap::from([(a, 1.0)]), 10, false);
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
        let results =
            related_files_by_imports(&analyzer, &HashMap::from([(a.clone(), 1.0)]), 10, false);
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
        let results =
            related_files_by_imports(&analyzer, &HashMap::from([(a.clone(), 1.0)]), 10, false);

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
        let results =
            related_files_by_imports(&analyzer, &HashMap::from([(imported, 1.0)]), 10, true);

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
        let forward = related_files_by_imports(
            &analyzer,
            &HashMap::from([(middle.clone(), 1.0)]),
            10,
            false,
        );
        let reverse =
            related_files_by_imports(&analyzer, &HashMap::from([(middle, 1.0)]), 10, true);

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
            related_files_by_imports(&multi, &HashMap::from([(java_source, 1.0)]), 10, false);
        assert!(java_results.iter().any(|entry| entry.file == java_target));
        assert!(!java_results.iter().any(|entry| entry.file == py_target));

        let py_results =
            related_files_by_imports(&multi, &HashMap::from([(py_source, 1.0)]), 10, false);
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
        let results = related_files_by_imports(&analyzer, &HashMap::from([(a, 1.0)]), 10, false);

        assert!(file_by_name(&results, "B.java").is_some());
        assert!(file_by_name(&results, "C.java").is_some());
    }

}
