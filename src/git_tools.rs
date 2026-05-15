use crate::analyzer::IAnalyzer;
use git2::{Commit, Diff, DiffOptions, Patch, Repository, Sort};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const DEFAULT_LOG_LIMIT: usize = 50;
const DEFAULT_SEARCH_LIMIT: usize = 50;
const DEFAULT_DIFF_MAX_FILES: usize = 10;
const DEFAULT_DIFF_LINES_PER_FILE: usize = 1000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchGitCommitMessagesParams {
    pub pattern: String,
    #[serde(default = "default_search_limit")]
    pub limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetGitLogParams {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default = "default_log_limit")]
    pub limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetCommitDiffParams {
    pub revision: String,
    #[serde(default = "default_diff_max_files")]
    pub max_files: usize,
    #[serde(default = "default_diff_lines_per_file")]
    pub lines_per_file: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchGitCommitMessagesResult {
    pub matches: Vec<CommitSummary>,
    pub truncated: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GetGitLogResult {
    pub commits: Vec<CommitSummary>,
    pub truncated: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CommitSummary {
    pub short_hash: String,
    pub full_hash: String,
    pub summary: String,
    pub author: String,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct GetCommitDiffResult {
    pub revision: String,
    pub diff: String,
    pub files_total: usize,
    pub files_included: usize,
    pub truncated: bool,
    pub error: Option<String>,
}

pub fn search_git_commit_messages(
    analyzer: &dyn IAnalyzer,
    params: SearchGitCommitMessagesParams,
) -> SearchGitCommitMessagesResult {
    let regex = match Regex::new(params.pattern.trim()) {
        Ok(re) => re,
        Err(err) => {
            return SearchGitCommitMessagesResult {
                matches: Vec::new(),
                truncated: false,
                error: Some(format!("invalid regex: {err}")),
            };
        }
    };

    let context = match GitContext::open(analyzer.project().root()) {
        Ok(ctx) => ctx,
        Err(err) => {
            return SearchGitCommitMessagesResult {
                matches: Vec::new(),
                truncated: false,
                error: Some(err),
            };
        }
    };

    let limit = params.limit.max(1);
    let mut matches = Vec::new();
    let mut truncated = false;

    let walker = match context.revwalk_head() {
        Ok(w) => w,
        Err(err) => {
            return SearchGitCommitMessagesResult {
                matches,
                truncated,
                error: Some(err),
            };
        }
    };

    for oid in walker.flatten() {
        let Ok(commit) = context.repo.find_commit(oid) else {
            continue;
        };
        let message = commit.message().unwrap_or("");
        if !regex.is_match(message) {
            continue;
        }
        if matches.len() >= limit {
            truncated = true;
            break;
        }
        matches.push(summarize_commit(&commit));
    }

    SearchGitCommitMessagesResult {
        matches,
        truncated,
        error: None,
    }
}

pub fn get_git_log(analyzer: &dyn IAnalyzer, params: GetGitLogParams) -> GetGitLogResult {
    let context = match GitContext::open(analyzer.project().root()) {
        Ok(ctx) => ctx,
        Err(err) => {
            return GetGitLogResult {
                commits: Vec::new(),
                truncated: false,
                error: Some(err),
            };
        }
    };

    let limit = params.limit.max(1);
    let filter_path = params
        .path
        .as_deref()
        .map(|raw| raw.trim().replace('\\', "/"))
        .filter(|s| !s.is_empty())
        .map(|rel| context.project_rel_to_repo_rel(Path::new(&rel)));

    let walker = match context.revwalk_head() {
        Ok(w) => w,
        Err(err) => {
            return GetGitLogResult {
                commits: Vec::new(),
                truncated: false,
                error: Some(err),
            };
        }
    };

    let mut commits = Vec::new();
    let mut truncated = false;

    for oid in walker.flatten() {
        let Ok(commit) = context.repo.find_commit(oid) else {
            continue;
        };
        if let Some(path) = filter_path.as_deref()
            && !commit_touches_path(&context.repo, &commit, path)
        {
            continue;
        }
        if commits.len() >= limit {
            truncated = true;
            break;
        }
        commits.push(summarize_commit(&commit));
    }

    GetGitLogResult {
        commits,
        truncated,
        error: None,
    }
}

pub fn get_commit_diff(
    analyzer: &dyn IAnalyzer,
    params: GetCommitDiffParams,
) -> GetCommitDiffResult {
    let revision = params.revision.trim().to_string();
    let context = match GitContext::open(analyzer.project().root()) {
        Ok(ctx) => ctx,
        Err(err) => {
            return GetCommitDiffResult {
                revision,
                diff: String::new(),
                files_total: 0,
                files_included: 0,
                truncated: false,
                error: Some(err),
            };
        }
    };

    let object = match context.repo.revparse_single(&revision) {
        Ok(obj) => obj,
        Err(err) => {
            return GetCommitDiffResult {
                revision,
                diff: String::new(),
                files_total: 0,
                files_included: 0,
                truncated: false,
                error: Some(format!("unable to resolve revision: {err}")),
            };
        }
    };

    let commit = match object.peel_to_commit() {
        Ok(c) => c,
        Err(err) => {
            return GetCommitDiffResult {
                revision,
                diff: String::new(),
                files_total: 0,
                files_included: 0,
                truncated: false,
                error: Some(format!("not a commit: {err}")),
            };
        }
    };

    let current_tree = match commit.tree() {
        Ok(t) => t,
        Err(err) => {
            return GetCommitDiffResult {
                revision,
                diff: String::new(),
                files_total: 0,
                files_included: 0,
                truncated: false,
                error: Some(format!("commit tree missing: {err}")),
            };
        }
    };

    let parent_tree = if commit.parent_count() == 0 {
        None
    } else {
        match commit.parent(0).and_then(|p| p.tree()) {
            Ok(t) => Some(t),
            Err(err) => {
                return GetCommitDiffResult {
                    revision,
                    diff: String::new(),
                    files_total: 0,
                    files_included: 0,
                    truncated: false,
                    error: Some(format!("parent tree missing: {err}")),
                };
            }
        }
    };

    let mut diff_opts = DiffOptions::new();
    diff_opts.include_untracked(false);
    let mut diff = match context.repo.diff_tree_to_tree(
        parent_tree.as_ref(),
        Some(&current_tree),
        Some(&mut diff_opts),
    ) {
        Ok(d) => d,
        Err(err) => {
            return GetCommitDiffResult {
                revision,
                diff: String::new(),
                files_total: 0,
                files_included: 0,
                truncated: false,
                error: Some(format!("diff failed: {err}")),
            };
        }
    };

    let max_files = params.max_files.max(1);
    let lines_per_file = params.lines_per_file.max(1);
    let formatted = format_diff(&mut diff, max_files, lines_per_file);

    GetCommitDiffResult {
        revision,
        diff: formatted.text,
        files_total: formatted.files_total,
        files_included: formatted.files_included,
        truncated: formatted.truncated,
        error: None,
    }
}

struct GitContext {
    repo: Repository,
    repo_root: PathBuf,
    project_root: PathBuf,
}

impl GitContext {
    fn open(project_root: &Path) -> Result<Self, String> {
        let canonical = project_root
            .canonicalize()
            .map_err(|err| format!("cannot canonicalize project root: {err}"))?;
        let repo = Repository::discover(&canonical)
            .map_err(|err| format!("not a git repository: {err}"))?;
        let workdir = repo
            .workdir()
            .ok_or_else(|| "git repository has no working directory".to_string())?
            .to_path_buf();
        let repo_root = workdir
            .canonicalize()
            .map_err(|err| format!("cannot canonicalize repo root: {err}"))?;
        Ok(Self {
            repo,
            repo_root,
            project_root: canonical,
        })
    }

    fn revwalk_head(&self) -> Result<git2::Revwalk<'_>, String> {
        let mut walker = self
            .repo
            .revwalk()
            .map_err(|err| format!("revwalk init failed: {err}"))?;
        walker
            .set_sorting(Sort::TIME)
            .map_err(|err| format!("revwalk sort failed: {err}"))?;
        walker
            .push_head()
            .map_err(|err| format!("revwalk push_head failed: {err}"))?;
        Ok(walker)
    }

    fn project_rel_to_repo_rel(&self, project_rel: &Path) -> PathBuf {
        match self.project_root.strip_prefix(&self.repo_root) {
            Ok(prefix) if !prefix.as_os_str().is_empty() => prefix.join(project_rel),
            _ => project_rel.to_path_buf(),
        }
    }
}

fn summarize_commit(commit: &Commit<'_>) -> CommitSummary {
    let id = commit.id();
    let full_hash = id.to_string();
    let short_hash = full_hash.chars().take(7).collect::<String>();
    let summary = commit.summary().unwrap_or("").to_string();
    let author = commit
        .author()
        .name()
        .map(|s| s.to_string())
        .unwrap_or_default();
    CommitSummary {
        short_hash,
        full_hash,
        summary,
        author,
        timestamp: commit.time().seconds(),
    }
}

fn commit_touches_path(repo: &Repository, commit: &Commit<'_>, path: &Path) -> bool {
    let Ok(current_tree) = commit.tree() else {
        return false;
    };
    let parent_tree = if commit.parent_count() == 0 {
        None
    } else {
        commit.parent(0).and_then(|p| p.tree()).ok()
    };

    let mut diff_opts = DiffOptions::new();
    diff_opts.pathspec(path);
    let Ok(diff) = repo.diff_tree_to_tree(
        parent_tree.as_ref(),
        Some(&current_tree),
        Some(&mut diff_opts),
    ) else {
        return false;
    };

    diff.deltas().len() > 0
}

struct FormattedDiff {
    text: String,
    files_total: usize,
    files_included: usize,
    truncated: bool,
}

fn format_diff(diff: &mut Diff<'_>, max_files: usize, lines_per_file: usize) -> FormattedDiff {
    let files_total = diff.deltas().len();
    let files_included = files_total.min(max_files);
    let mut truncated_overall = files_total > max_files;
    let mut output = String::new();

    for idx in 0..files_included {
        let mut patch = match Patch::from_diff(diff, idx) {
            Ok(Some(p)) => p,
            _ => continue,
        };
        let buf = match patch.to_buf() {
            Ok(b) => b,
            Err(_) => continue,
        };
        let text = std::str::from_utf8(&buf).unwrap_or("");
        let mut file_truncated = false;
        for (line_count, line) in text.split_inclusive('\n').enumerate() {
            if line_count >= lines_per_file {
                file_truncated = true;
                break;
            }
            output.push_str(line);
        }
        if file_truncated {
            truncated_overall = true;
            output.push_str(&format!(
                "... [truncated at {lines_per_file} lines for this file]\n"
            ));
        }
    }

    if files_total > files_included {
        truncated_overall = true;
        output.push_str(&format!(
            "... [{} additional file(s) omitted; max_files={}]\n",
            files_total - files_included,
            max_files
        ));
    }

    FormattedDiff {
        text: output,
        files_total,
        files_included,
        truncated: truncated_overall,
    }
}

fn default_search_limit() -> usize {
    DEFAULT_SEARCH_LIMIT
}

fn default_log_limit() -> usize {
    DEFAULT_LOG_LIMIT
}

fn default_diff_max_files() -> usize {
    DEFAULT_DIFF_MAX_FILES
}

fn default_diff_lines_per_file() -> usize {
    DEFAULT_DIFF_LINES_PER_FILE
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{
        AnalyzerConfig, FilesystemProject, Project, WorkspaceAnalyzer,
    };
    use git2::{Repository, Signature};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use tempfile::TempDir;

    struct GitFixture {
        _temp: TempDir,
        repo_path: PathBuf,
        analyzer: WorkspaceAnalyzer,
    }

    impl GitFixture {
        fn new() -> Self {
            let temp = TempDir::new().expect("tempdir");
            let repo_path = temp.path().canonicalize().expect("canonicalize tempdir");
            Repository::init(&repo_path).expect("git init");
            let project: Arc<dyn Project> = Arc::new(
                FilesystemProject::new(repo_path.clone()).expect("project"),
            );
            let analyzer = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
            Self {
                _temp: temp,
                repo_path,
                analyzer,
            }
        }

        fn commit(&self, message: &str, files: &[(&str, &str)]) -> git2::Oid {
            for (rel, content) in files {
                let abs = self.repo_path.join(rel);
                if let Some(parent) = abs.parent() {
                    fs::create_dir_all(parent).expect("mkdir");
                }
                fs::write(&abs, content).expect("write");
            }
            let repo = Repository::open(&self.repo_path).expect("open repo");
            let mut index = repo.index().expect("index");
            for (rel, _) in files {
                index.add_path(Path::new(rel)).expect("add path");
            }
            index.write().expect("write index");
            let tree_oid = index.write_tree().expect("write tree");
            let tree = repo.find_tree(tree_oid).expect("find tree");
            let sig = Signature::now("Tester", "test@example.com").expect("sig");
            let parents: Vec<git2::Commit> = match repo.head() {
                Ok(head) => match head.peel_to_commit() {
                    Ok(parent) => vec![parent],
                    Err(_) => Vec::new(),
                },
                Err(_) => Vec::new(),
            };
            let parent_refs: Vec<&git2::Commit> = parents.iter().collect();
            repo.commit(Some("HEAD"), &sig, &sig, message, &tree, &parent_refs)
                .expect("commit")
        }
    }

    #[test]
    fn search_git_commit_messages_returns_matching_commits() {
        let fix = GitFixture::new();
        fix.commit("Initial: scaffold", &[("a.txt", "1")]);
        fix.commit("Fix: tighten parser", &[("a.txt", "2")]);
        fix.commit("Docs: README", &[("a.txt", "3")]);

        let result = search_git_commit_messages(
            fix.analyzer.analyzer(),
            SearchGitCommitMessagesParams {
                pattern: "(?i)^fix".to_string(),
                limit: 10,
            },
        );
        assert!(result.error.is_none(), "error: {:?}", result.error);
        assert_eq!(result.matches.len(), 1);
        assert!(result.matches[0].summary.starts_with("Fix:"));
    }

    #[test]
    fn search_git_commit_messages_reports_invalid_regex() {
        let fix = GitFixture::new();
        fix.commit("Initial", &[("a.txt", "1")]);
        let result = search_git_commit_messages(
            fix.analyzer.analyzer(),
            SearchGitCommitMessagesParams {
                pattern: "[".to_string(),
                limit: 10,
            },
        );
        assert!(result.error.is_some());
    }

    #[test]
    fn get_git_log_filters_by_path() {
        let fix = GitFixture::new();
        fix.commit("c1", &[("a.txt", "1")]);
        fix.commit("c2 touch b", &[("b.txt", "1")]);
        fix.commit("c3 touch a", &[("a.txt", "2")]);

        let result = get_git_log(
            fix.analyzer.analyzer(),
            GetGitLogParams {
                path: Some("b.txt".to_string()),
                limit: 10,
            },
        );
        assert!(result.error.is_none(), "error: {:?}", result.error);
        let summaries: Vec<_> = result.commits.iter().map(|c| c.summary.as_str()).collect();
        assert_eq!(summaries, vec!["c2 touch b"]);
    }

    #[test]
    fn get_git_log_returns_all_when_no_path() {
        let fix = GitFixture::new();
        fix.commit("c1", &[("a.txt", "1")]);
        fix.commit("c2", &[("b.txt", "1")]);
        let result = get_git_log(
            fix.analyzer.analyzer(),
            GetGitLogParams {
                path: None,
                limit: 10,
            },
        );
        assert_eq!(result.commits.len(), 2);
    }

    #[test]
    fn get_commit_diff_handles_root_commit() {
        let fix = GitFixture::new();
        let oid = fix.commit("Initial", &[("a.txt", "alpha\n")]);
        let result = get_commit_diff(
            fix.analyzer.analyzer(),
            GetCommitDiffParams {
                revision: oid.to_string(),
                max_files: 10,
                lines_per_file: 1000,
            },
        );
        assert!(result.error.is_none(), "error: {:?}", result.error);
        assert!(result.diff.contains("alpha"));
        assert_eq!(result.files_total, 1);
    }

    #[test]
    fn get_commit_diff_truncates_when_over_file_limit() {
        let fix = GitFixture::new();
        let oid = fix.commit(
            "Many files",
            &[
                ("a.txt", "a\n"),
                ("b.txt", "b\n"),
                ("c.txt", "c\n"),
            ],
        );
        let result = get_commit_diff(
            fix.analyzer.analyzer(),
            GetCommitDiffParams {
                revision: oid.to_string(),
                max_files: 1,
                lines_per_file: 1000,
            },
        );
        assert!(result.truncated);
        assert_eq!(result.files_total, 3);
        assert_eq!(result.files_included, 1);
    }

    #[test]
    fn get_commit_diff_reports_unknown_revision() {
        let fix = GitFixture::new();
        fix.commit("c1", &[("a.txt", "1")]);
        let result = get_commit_diff(
            fix.analyzer.analyzer(),
            GetCommitDiffParams {
                revision: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
                max_files: 10,
                lines_per_file: 1000,
            },
        );
        assert!(result.error.is_some());
    }
}
