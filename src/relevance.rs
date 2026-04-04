use crate::analyzer::{CodeUnit, IAnalyzer, ProjectFile};
use git2::{DiffFindOptions, Oid, Repository, Sort};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

const ALPHA: f64 = 0.85;
const CONVERGENCE_EPSILON: f64 = 1.0e-6;
const MAX_ITERS: usize = 75;
const IMPORT_DEPTH: usize = 2;
const COMMITS_TO_PROCESS: usize = 1_000;

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

    for candidate in related_files_by_git(analyzer, &seed_weights, top_k).unwrap_or_default() {
        if append_candidate(&mut results, &mut seen, &excluded, candidate.file, top_k) {
            return results;
        }
    }

    for candidate in related_files_by_imports(analyzer, &seed_weights, top_k, false) {
        if append_candidate(&mut results, &mut seen, &excluded, candidate.file, top_k) {
            return results;
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

    let graph = build_import_graph(analyzer, &positive_seeds);
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
    ranked.sort_by(|left, right| {
        right
            .score
            .partial_cmp(&left.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| normalized_rel_path(&left.file).cmp(&normalized_rel_path(&right.file)))
    });
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

fn related_files_by_git(
    analyzer: &dyn IAnalyzer,
    seed_weights: &HashMap<ProjectFile, f64>,
    k: usize,
) -> Result<Vec<FileRelevance>, git2::Error> {
    if k == 0 || seed_weights.is_empty() {
        return Ok(Vec::new());
    }

    let Some(repo) = GitProjectContext::discover(analyzer.project().root()) else {
        return Ok(Vec::new());
    };
    if !seed_weights
        .keys()
        .any(|seed| repo.is_tracked_in_head(seed))
    {
        return Ok(Vec::new());
    }

    let commits = repo.recent_commit_ids(COMMITS_TO_PROCESS)?;
    if commits.is_empty() {
        return Ok(Vec::new());
    }

    let mut file_doc_freq: HashMap<ProjectFile, usize> = HashMap::new();
    let mut joint_mass: HashMap<(ProjectFile, ProjectFile), f64> = HashMap::new();
    let mut seed_commit_count: HashMap<ProjectFile, usize> = HashMap::new();
    let mut canonicalizer = RenameCanonicalizer::default();

    let baseline_commit_count = commits.len() as f64;
    for oid in &commits {
        let commit = repo.repo.find_commit(*oid)?;
        let change = repo.changed_repo_paths_for_commit(&commit)?;

        let changed_files: BTreeSet<_> = change
            .paths
            .into_iter()
            .map(|path| canonicalizer.canonicalize(&path))
            .filter_map(|path| repo.repo_path_to_project_file(&path))
            .collect();
        canonicalizer.record_renames(&change.renames);
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
    ranked.sort_by(|left, right| {
        right
            .score
            .partial_cmp(&left.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| normalized_rel_path(&left.file).cmp(&normalized_rel_path(&right.file)))
    });
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
        let _ = walk.set_sorting(Sort::TIME);

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
        let current_tree = commit.tree()?;
        let parent_tree = if commit.parent_count() > 0 {
            Some(commit.parent(0)?.tree()?)
        } else {
            None
        };

        let mut diff =
            self.repo
                .diff_tree_to_tree(parent_tree.as_ref(), Some(&current_tree), None)?;
        let mut raw_dir_change_counts = RawDirChangeCounts::default();
        for delta in diff.deltas() {
            match delta.status() {
                git2::Delta::Added | git2::Delta::Copied => {
                    if let Some(path) = delta.new_file().path() {
                        raw_dir_change_counts.record_add(path);
                    }
                }
                git2::Delta::Deleted => {
                    if let Some(path) = delta.old_file().path() {
                        raw_dir_change_counts.record_delete(path);
                    }
                }
                _ => {}
            }
        }

        let mut find_options = DiffFindOptions::new();
        find_options.renames(true);
        diff.find_similar(Some(&mut find_options))?;

        let mut paths = Vec::new();
        let mut renames = Vec::new();
        for delta in diff.deltas() {
            match delta.status() {
                git2::Delta::Added
                | git2::Delta::Copied
                | git2::Delta::Modified
                | git2::Delta::Renamed => {
                    if let Some(path) = delta.new_file().path() {
                        paths.push(path.to_path_buf());
                    }
                }
                git2::Delta::Deleted => {
                    if let Some(path) = delta.old_file().path() {
                        paths.push(path.to_path_buf());
                    }
                }
                _ => {}
            }

            if delta.status() == git2::Delta::Renamed {
                if let (Some(old_path), Some(new_path)) =
                    (delta.old_file().path(), delta.new_file().path())
                {
                    if raw_dir_change_counts.is_unambiguous_rename(old_path, new_path) {
                        renames.push((old_path.to_path_buf(), new_path.to_path_buf()));
                    }
                }
            }
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

#[derive(Default)]
struct RawDirChangeCounts {
    adds_by_dir: HashMap<PathBuf, usize>,
    deletes_by_dir: HashMap<PathBuf, usize>,
}

impl RawDirChangeCounts {
    fn record_add(&mut self, path: &Path) {
        *self.adds_by_dir.entry(parent_dir(path)).or_insert(0) += 1;
    }

    fn record_delete(&mut self, path: &Path) {
        *self.deletes_by_dir.entry(parent_dir(path)).or_insert(0) += 1;
    }

    fn is_unambiguous_rename(&self, old_path: &Path, new_path: &Path) -> bool {
        let old_dir = parent_dir(old_path);
        let new_dir = parent_dir(new_path);
        if old_dir != new_dir {
            return true;
        }

        self.adds_by_dir.get(&old_dir).copied().unwrap_or(0)
            == self.deletes_by_dir.get(&old_dir).copied().unwrap_or(0)
    }
}

fn parent_dir(path: &Path) -> PathBuf {
    path.parent().map(Path::to_path_buf).unwrap_or_default()
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

#[cfg(test)]
mod tests {
    use super::{FileRelevance, related_files_by_imports};
    use crate::analyzer::{
        AnalyzerDelegate, JavaAnalyzer, Language, MultiAnalyzer, ProjectFile, PythonAnalyzer,
        TestProject,
    };
    use std::collections::{BTreeMap, HashMap};
    use std::path::Path;
    use tempfile::TempDir;

    fn write_file(root: &Path, rel_path: &str, contents: &str) -> ProjectFile {
        let file = ProjectFile::new(root.to_path_buf(), rel_path);
        file.write(contents).unwrap();
        file
    }

    fn java_analyzer(root: &Path) -> JavaAnalyzer {
        JavaAnalyzer::from_project(TestProject::new(root.to_path_buf(), Language::Java))
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
