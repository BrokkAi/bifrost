//! MCP `analyze_git_hotspots` handler. Correlates git churn with
//! heuristic cyclomatic complexity per file. Output format mirrors
//! brokk-core's `CodeQualityTools.analyzeGitHotspots` byte-for-byte.

use crate::code_quality::ReportLines;

use crate::code_quality::cyclomatic_complexities_for_file;

use crate::code_quality::sanitize_table_cell;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::ProjectFile;
use chrono::{DateTime, SecondsFormat, Utc};
use git2::{Commit, DiffFindOptions, DiffOptions, Repository, Sort};
use serde::{Deserialize, Serialize};
use std::collections::HashMap as StdHashMap;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DEFAULT_SINCE_DAYS: i32 = 7;
const DEFAULT_MAX_COMMITS: usize = 500;
const DEFAULT_MAX_FILES: usize = 75;
const MAX_COMMITS_HARD_CAP: usize = 5_000;
const MAX_FILES_IN_REPORT_HARD_CAP: usize = 500;
const RENAME_DETECTION_LIMIT: usize = 200;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzeGitHotspotsParams {
    #[serde(default)]
    pub since_days: i32,
    #[serde(default)]
    pub since_iso: String,
    #[serde(default)]
    pub until_iso: String,
    #[serde(default)]
    pub max_commits: i32,
    #[serde(default)]
    pub max_files: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnalyzeGitHotspotsResult {
    pub report: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HotspotCategory {
    Hotspot,
    Abandonware,
    Stable,
    Active,
}

impl HotspotCategory {
    fn as_brokk_str(&self) -> &'static str {
        match self {
            Self::Hotspot => "HOTSPOT",
            Self::Abandonware => "ABANDONWARE",
            Self::Stable => "STABLE",
            Self::Active => "ACTIVE",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthorInfo {
    name: String,
    email: String,
    commits: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileHotspotInfo {
    path: String,
    churn: usize,
    top_authors: Vec<AuthorInfo>,
    complexity: u32,
    category: HotspotCategory,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HotspotReport {
    repository: String,
    analyzed_commits: usize,
    timeframe: String,
    total_unique_files: usize,
    truncated: bool,
    history_errors: Vec<String>,
    files: Vec<FileHotspotInfo>,
}

#[derive(Default)]
struct FileStats {
    churn: usize,
    author_counts: StdHashMap<String, usize>,
    author_names: StdHashMap<String, String>,
}

pub fn analyze_git_hotspots(
    analyzer: &dyn IAnalyzer,
    params: AnalyzeGitHotspotsParams,
) -> AnalyzeGitHotspotsResult {
    let report = match analyze_report(analyzer, params) {
        Ok(report) => format_hotspot_report_markdown(&report),
        Err(message) => message,
    };
    AnalyzeGitHotspotsResult { report }
}

fn analyze_report(
    analyzer: &dyn IAnalyzer,
    params: AnalyzeGitHotspotsParams,
) -> Result<HotspotReport, String> {
    let project_root =
        analyzer.project().root().canonicalize().map_err(|err| {
            format!("Git hotspot analysis requires a readable project root: {err}")
        })?;
    let repo = Repository::open(&project_root)
        .map_err(|err| format!("Git hotspot analysis requires a git repository: {err}"))?;
    let repo_root = repo
        .workdir()
        .ok_or_else(|| {
            "Git hotspot analysis requires a git repository with a working tree.".to_string()
        })?
        .canonicalize()
        .map_err(|err| format!("Git hotspot analysis requires a usable working tree: {err}"))?;

    let since = parse_since(&params.since_iso, params.since_days)?;
    let until = parse_optional_iso(&params.until_iso)?;
    let max_commits = normalize_positive(params.max_commits, DEFAULT_MAX_COMMITS);
    let max_commits = max_commits.min(MAX_COMMITS_HARD_CAP);
    let max_files = normalize_positive(params.max_files, DEFAULT_MAX_FILES);
    let timeframe = format_timeframe(&since, until.as_ref());

    let mut walker = repo
        .revwalk()
        .map_err(|err| format!("Git hotspot analysis requires git history access: {err}"))?;
    walker
        .set_sorting(Sort::TOPOLOGICAL | Sort::TIME)
        .map_err(|err| format!("Git hotspot analysis requires revwalk sorting: {err}"))?;
    if repo.head().ok().and_then(|head| head.target()).is_none() {
        return Ok(HotspotReport {
            repository: project_root.display().to_string(),
            analyzed_commits: 0,
            timeframe,
            total_unique_files: 0,
            truncated: false,
            history_errors: Vec::new(),
            files: Vec::new(),
        });
    }
    walker
        .push_head()
        .map_err(|err| format!("Git hotspot analysis requires HEAD history: {err}"))?;

    let mut stats_by_file: StdHashMap<ProjectFile, FileStats> = StdHashMap::new();
    let mut analyzed_commits = 0usize;
    let mut history_errors = Vec::new();
    let mut commits_truncated = false;

    for (examined_commits, oid) in walker.enumerate() {
        if examined_commits >= max_commits {
            commits_truncated = true;
            break;
        }
        let oid = match oid {
            Ok(oid) => oid,
            Err(err) => {
                history_errors.push(format!("revwalk failed: {err}"));
                break;
            }
        };
        let commit = match repo.find_commit(oid) {
            Ok(commit) => commit,
            Err(err) => {
                history_errors.push(format!("could not read commit {oid}: {err}"));
                continue;
            }
        };
        if !commit_in_window(&commit, &since, until.as_ref()) {
            continue;
        }
        analyzed_commits += 1;
        process_commit(
            &repo,
            &project_root,
            &repo_root,
            &commit,
            &mut stats_by_file,
        )
        .map_err(|err| format!("Git hotspot analysis failed while diffing commit {oid}: {err}"))?;
    }

    let mut candidates = stats_by_file
        .into_iter()
        .filter(|(file, _)| file.exists())
        .collect::<Vec<_>>();
    candidates.sort_by(|(left_file, left_stats), (right_file, right_stats)| {
        right_stats
            .churn
            .cmp(&left_stats.churn)
            .then_with(|| left_file.cmp(right_file))
    });

    let total_unique_files = candidates.len();
    let cap = max_files.min(MAX_FILES_IN_REPORT_HARD_CAP);
    let files_truncated = total_unique_files > cap;
    if files_truncated {
        candidates.truncate(cap);
    }
    let files = candidates
        .into_iter()
        .filter_map(|(file, stats)| create_file_info(analyzer, file, stats))
        .collect();

    Ok(HotspotReport {
        repository: project_root.display().to_string(),
        analyzed_commits,
        timeframe,
        total_unique_files,
        truncated: commits_truncated || files_truncated,
        history_errors,
        files,
    })
}

fn parse_since(since_iso: &str, since_days: i32) -> Result<SystemTime, String> {
    if !since_iso.trim().is_empty() {
        return parse_iso8601_utc(since_iso.trim());
    }
    let days = if since_days > 0 {
        since_days as u64
    } else {
        DEFAULT_SINCE_DAYS as u64
    };
    let delta = Duration::from_secs(days.saturating_mul(24 * 60 * 60));
    SystemTime::now()
        .checked_sub(delta)
        .ok_or_else(|| "since_days underflowed the system clock".to_string())
}

fn parse_optional_iso(raw: &str) -> Result<Option<SystemTime>, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        parse_iso8601_utc(trimmed).map(Some)
    }
}

fn parse_iso8601_utc(raw: &str) -> Result<SystemTime, String> {
    let trimmed = raw.trim();
    DateTime::parse_from_rfc3339(trimmed)
        .map(|parsed| parsed.with_timezone(&Utc).into())
        .map_err(|_| format!("Invalid ISO-8601 instant: {trimmed}"))
}

fn normalize_positive(value: i32, default_value: usize) -> usize {
    if value > 0 {
        value as usize
    } else {
        default_value
    }
}

fn format_timeframe(since: &SystemTime, until: Option<&SystemTime>) -> String {
    let since = system_time_to_iso8601(*since);
    match until {
        Some(until) => format!("since {since} until {}", system_time_to_iso8601(*until)),
        None => format!("since {since}"),
    }
}

fn system_time_to_iso8601(time: SystemTime) -> String {
    DateTime::<Utc>::from(time).to_rfc3339_opts(SecondsFormat::AutoSi, true)
}

fn commit_in_window(commit: &Commit<'_>, since: &SystemTime, until: Option<&SystemTime>) -> bool {
    let seconds = commit.time().seconds();
    let when = if seconds >= 0 {
        UNIX_EPOCH + Duration::from_secs(seconds as u64)
    } else {
        UNIX_EPOCH - Duration::from_secs(seconds.unsigned_abs())
    };
    if when < *since {
        return false;
    }
    if let Some(until) = until
        && when >= *until
    {
        return false;
    }
    true
}

fn process_commit(
    repo: &Repository,
    project_root: &Path,
    repo_root: &Path,
    commit: &Commit<'_>,
    stats_by_file: &mut StdHashMap<ProjectFile, FileStats>,
) -> Result<(), String> {
    let author = commit.author();
    let email = author.email().unwrap_or_default().to_string();
    let name = author.name().unwrap_or_default().to_string();

    let changed_files = changed_project_files_for_commit(
        repo,
        project_root,
        repo_root,
        commit,
        apply_rename_detection_with_fallback,
    )?;

    for project_file in changed_files {
        let stats = stats_by_file.entry(project_file).or_default();
        stats.churn += 1;
        *stats.author_counts.entry(email.clone()).or_insert(0) += 1;
        stats
            .author_names
            .entry(email.clone())
            .or_insert(name.clone());
    }
    Ok(())
}

fn changed_project_files_for_commit<'repo, F>(
    repo: &'repo Repository,
    project_root: &Path,
    repo_root: &Path,
    commit: &Commit<'repo>,
    finalize_diff: F,
) -> Result<Vec<ProjectFile>, String>
where
    F: FnOnce(
        &'repo Repository,
        &Commit<'repo>,
        git2::Diff<'repo>,
    ) -> Result<git2::Diff<'repo>, String>,
{
    let diff = diff_commit_to_parent(repo, commit).map_err(|err| err.message().to_string())?;
    let diff = finalize_diff(repo, commit, diff)?;
    let mut files = Vec::new();
    for delta in diff.deltas() {
        let Some(path) = delta_path(&delta) else {
            continue;
        };
        let Some(project_file) = repo_rel_to_project_file(project_root, repo_root, path) else {
            continue;
        };
        files.push(project_file);
    }
    Ok(files)
}

fn diff_commit_to_parent<'repo>(
    repo: &'repo Repository,
    commit: &Commit<'_>,
) -> Result<git2::Diff<'repo>, git2::Error> {
    let current_tree = commit.tree()?;
    let parent_tree = if commit.parent_count() == 0 {
        None
    } else {
        Some(commit.parent(0)?.tree()?)
    };
    let mut opts = DiffOptions::new();
    opts.include_untracked(false);
    repo.diff_tree_to_tree(parent_tree.as_ref(), Some(&current_tree), Some(&mut opts))
}

fn apply_rename_detection_with_fallback<'repo>(
    repo: &'repo Repository,
    commit: &Commit<'_>,
    diff: git2::Diff<'repo>,
) -> Result<git2::Diff<'repo>, String> {
    let mut original_diff = Some(diff);
    with_rename_detection_fallback(|detect_renames| {
        let mut diff = if detect_renames {
            original_diff
                .take()
                .ok_or_else(|| "rename-detection retry exhausted original diff".to_string())?
        } else {
            diff_commit_to_parent(repo, commit)
                .map_err(|err| format!("diff retry without rename detection failed: {err}"))?
        };
        if detect_renames {
            let mut find_opts = DiffFindOptions::new();
            find_opts.renames(true);
            find_opts.rename_limit(RENAME_DETECTION_LIMIT);
            diff.find_similar(Some(&mut find_opts))
                .map_err(|err| err.message().to_string())?;
        }
        Ok(diff)
    })
}

fn with_rename_detection_fallback<T, F>(mut attempt: F) -> Result<T, String>
where
    F: FnMut(bool) -> Result<T, String>,
{
    match attempt(true) {
        Ok(value) => Ok(value),
        Err(_) => attempt(false),
    }
}

fn delta_path<'a>(delta: &'a git2::DiffDelta<'a>) -> Option<&'a Path> {
    delta
        .new_file()
        .path()
        .filter(|_| !matches!(delta.status(), git2::Delta::Deleted))
        .or_else(|| delta.old_file().path())
}

fn repo_rel_to_project_file(
    project_root: &Path,
    repo_root: &Path,
    repo_rel: &Path,
) -> Option<ProjectFile> {
    let abs = repo_root.join(repo_rel);
    if !abs.exists() {
        return None;
    }
    let rel = abs.strip_prefix(project_root).ok()?;
    Some(ProjectFile::new(
        project_root.to_path_buf(),
        rel.to_path_buf(),
    ))
}

fn create_file_info(
    analyzer: &dyn IAnalyzer,
    file: ProjectFile,
    stats: FileStats,
) -> Option<FileHotspotInfo> {
    if !file.exists() {
        return None;
    }
    let complexity = max_file_complexity(analyzer, &file);
    let category = determine_category(stats.churn, complexity);
    let mut top_authors = stats
        .author_counts
        .into_iter()
        .map(|(email, commits)| AuthorInfo {
            name: stats.author_names.get(&email).cloned().unwrap_or_default(),
            email,
            commits,
        })
        .collect::<Vec<_>>();
    top_authors.sort_by(|left, right| {
        right
            .commits
            .cmp(&left.commits)
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.email.cmp(&right.email))
    });
    top_authors.truncate(5);

    Some(FileHotspotInfo {
        path: file.to_string(),
        churn: stats.churn,
        top_authors,
        complexity,
        category,
    })
}

fn max_file_complexity(analyzer: &dyn IAnalyzer, file: &ProjectFile) -> u32 {
    cyclomatic_complexities_for_file(analyzer, file)
        .into_iter()
        .map(|(_, complexity)| complexity)
        .max()
        .unwrap_or(0)
}

fn determine_category(churn: usize, complexity: u32) -> HotspotCategory {
    let high_churn = churn > 10;
    let high_complexity = complexity > 15;
    match (high_churn, high_complexity) {
        (true, true) => HotspotCategory::Hotspot,
        (false, true) => HotspotCategory::Abandonware,
        (true, false) => HotspotCategory::Active,
        (false, false) => HotspotCategory::Stable,
    }
}

fn format_hotspot_report_markdown(report: &HotspotReport) -> String {
    let mut lines = ReportLines::with_capacity(report.files.len() + 8);
    lines.line("## Git hotspots");
    lines.blank();
    lines.line(format!(
        "- Repository: `{}`",
        sanitize_table_cell(&report.repository)
    ));
    lines.line(format!("- Timeframe: {}", report.timeframe));
    lines.line(format!("- Analyzed commits: {}", report.analyzed_commits));
    lines.line(format!(
        "- Unique files (before cap): {}",
        report.total_unique_files
    ));
    lines.line(format!("- Truncated: {}", report.truncated));
    for error in &report.history_errors {
        lines.line(format!(
            "- History incomplete: {}",
            sanitize_table_cell(error)
        ));
    }
    lines.blank();

    if report.files.is_empty() {
        lines.line("No file hotspots in this window.");
        return lines.build();
    }

    lines.line("| Path | Churn | Complexity | Category | Authors |");
    lines.line("|------|-------|------------|----------|---------|");
    for file in &report.files {
        let authors = file
            .top_authors
            .iter()
            .map(|author| format!("{}({})", author.name, author.commits))
            .collect::<Vec<_>>()
            .join(", ");
        lines.line(format!(
            "| `{}` | {} | {} | {} | {} |",
            sanitize_table_cell(&file.path),
            file.churn,
            file.complexity,
            sanitize_table_cell(file.category.as_brokk_str()),
            sanitize_table_cell(&authors)
        ));
    }
    lines.build()
}

#[cfg(test)]
mod tests {

    use crate::code_quality::git_hotspots::*;

    use brokk_bifrost_analysis::test_support::AnalyzerFixture;
    use brokk_bifrost_test_macros::hardwon;
    use git2::{Repository, Signature};
    use std::fs;
    use std::path::MAIN_SEPARATOR_STR;
    use std::path::Path;

    fn init_repo(root: &Path) -> Repository {
        Repository::init(root).expect("init repo")
    }

    fn commit_paths(
        repo: &Repository,
        message: &str,
        author_name: &str,
        author_email: &str,
        when: &str,
        add: &[&str],
    ) {
        let timestamp = parse_iso8601_utc(when).expect("parse commit time");
        let seconds = timestamp
            .duration_since(UNIX_EPOCH)
            .expect("positive timestamp")
            .as_secs() as i64;
        let signature = Signature::new(author_name, author_email, &git2::Time::new(seconds, 0))
            .expect("signature");
        brokk_bifrost_analysis::test_support::shared_git::commit_paths(
            repo, add, message, &signature,
        );
    }

    fn changed_files_with_simulated_retry<'repo>(
        repo: &'repo Repository,
        root: &Path,
        commit: &Commit<'repo>,
        attempts: &mut Vec<bool>,
    ) -> Result<Vec<ProjectFile>, String> {
        changed_project_files_for_commit(repo, root, root, commit, |repo, commit, diff| {
            let mut original_diff = Some(diff);
            with_rename_detection_fallback(|detect_renames| {
                attempts.push(detect_renames);
                if detect_renames {
                    Err("simulated rename detection failure".to_string())
                } else {
                    original_diff.take();
                    diff_commit_to_parent(repo, commit)
                        .map_err(|err| format!("fallback diff rebuild failed: {err}"))
                }
            })
        })
    }

    fn fixture_with_repo() -> AnalyzerFixture {
        let fixture = AnalyzerFixture::new(&[
            (
                "src/ComplexService.java",
                "public class ComplexService {\n    void hotspot(int x) {\n        if (x > 0) {}\n        if (x > 1) {}\n        if (x > 2) {}\n        if (x > 3) {}\n        if (x > 4) {}\n        if (x > 5) {}\n        if (x > 6) {}\n        if (x > 7) {}\n        if (x > 8) {}\n        if (x > 9) {}\n        if (x > 10) {}\n        if (x > 11) {}\n        if (x > 12) {}\n        if (x > 13) {}\n        if (x > 14) {}\n    }\n}\n",
            ),
            (
                "src/StableService.java",
                "public class StableService {\n    void stable() { int x = 1; }\n}\n",
            ),
            (
                "src/UnusedService.java",
                "public class UnusedService {\n    void oldCode(int x) {\n        if (x > 0) {}\n        if (x > 1) {}\n        if (x > 2) {}\n        if (x > 3) {}\n        if (x > 4) {}\n        if (x > 5) {}\n        if (x > 6) {}\n        if (x > 7) {}\n        if (x > 8) {}\n        if (x > 9) {}\n        if (x > 10) {}\n        if (x > 11) {}\n        if (x > 12) {}\n        if (x > 13) {}\n        if (x > 14) {}\n    }\n}\n",
            ),
        ]);
        let repo = init_repo(&fixture.project_root());
        commit_paths(
            &repo,
            "initial complex",
            "dev0",
            "dev0@example.com",
            "2020-06-01T00:00:00Z",
            &[
                "src/ComplexService.java",
                "src/StableService.java",
                "src/UnusedService.java",
            ],
        );
        for i in 1..15 {
            fs::write(
                fixture.project_root().join("src").join("ComplexService.java"),
                format!(
                    "public class ComplexService {{\n    void hotspot(int x) {{\n        int marker = {i};\n        if (x > 0) {{}}\n        if (x > 1) {{}}\n        if (x > 2) {{}}\n        if (x > 3) {{}}\n        if (x > 4) {{}}\n        if (x > 5) {{}}\n        if (x > 6) {{}}\n        if (x > 7) {{}}\n        if (x > 8) {{}}\n        if (x > 9) {{}}\n        if (x > 10) {{}}\n        if (x > 11) {{}}\n        if (x > 12) {{}}\n        if (x > 13) {{}}\n        if (x > 14) {{}}\n    }}\n}}\n"
                ),
            )
            .expect("rewrite complex");
            commit_paths(
                &repo,
                &format!("complex {i}"),
                &format!("dev{}", i % 3),
                &format!("dev{}@example.com", i % 3),
                &format!("2020-06-{:02}T00:00:00Z", i + 1),
                &["src/ComplexService.java"],
            );
        }
        fixture
    }

    fn rel(rel: &str) -> String {
        rel.replace('/', MAIN_SEPARATOR_STR)
    }

    fn report_for(fixture: &AnalyzerFixture, max_commits: i32, max_files: i32) -> String {
        analyze_git_hotspots(
            fixture.analyzer.analyzer(),
            AnalyzeGitHotspotsParams {
                since_days: 0,
                since_iso: "2020-06-01T00:00:00Z".to_string(),
                until_iso: String::new(),
                max_commits,
                max_files,
            },
        )
        .report
    }

    #[hardwon("969d61d302f9: commit cap hid a cut history")]
    #[test]
    fn commit_cap_reports_a_cut_only_when_more_history_exists() {
        let fixture = fixture_with_repo();
        let cut = report_for(&fixture, 1, 75);
        assert!(cut.contains("- Truncated: true"), "{cut}");
        assert!(cut.contains("- Analyzed commits: 1"), "{cut}");
        let complete = report_for(&fixture, 15, 75);
        assert!(complete.contains("- Truncated: false"), "{complete}");
        assert!(complete.contains("- Analyzed commits: 15"), "{complete}");
    }

    #[hardwon("aae03f4e5a48: equal churn rows depended on hash iteration")]
    #[test]
    fn equal_score_rows_are_repeatable() {
        let fixture = AnalyzerFixture::new(&[
            ("src/A.java", "class A {}\n"),
            ("src/B.java", "class B {}\n"),
        ]);
        let repo = init_repo(&fixture.project_root());
        commit_paths(
            &repo,
            "both",
            "Alice",
            "a@example.com",
            "2020-06-01T00:00:00Z",
            &["src/A.java", "src/B.java"],
        );
        let first = report_for(&fixture, 1, 75);
        assert!(
            first.contains(&format!("| `{}` | 1 |", rel("src/A.java"))),
            "{first}"
        );
        assert!(
            first.contains(&format!("| `{}` | 1 |", rel("src/B.java"))),
            "{first}"
        );
        for _ in 0..16 {
            assert_eq!(report_for(&fixture, 1, 75), first);
        }
    }

    #[hardwon("969d61d302f9: equal author counts depended on hash iteration")]
    #[test]
    fn equal_author_counts_are_repeatable() {
        let fixture = AnalyzerFixture::new(&[("src/A.java", "class A {}\n")]);
        let repo = init_repo(&fixture.project_root());
        commit_paths(
            &repo,
            "a",
            "Alice",
            "a@example.com",
            "2020-06-01T00:00:00Z",
            &["src/A.java"],
        );
        fs::write(
            fixture.project_root().join("src/A.java"),
            "class A { int n; }\n",
        )
        .expect("rewrite");
        commit_paths(
            &repo,
            "b",
            "Bob",
            "b@example.com",
            "2020-06-02T00:00:00Z",
            &["src/A.java"],
        );
        let first = report_for(&fixture, 2, 75);
        assert!(
            first.contains("Alice(1)") && first.contains("Bob(1)"),
            "{first}"
        );
        for _ in 0..16 {
            assert_eq!(report_for(&fixture, 2, 75), first);
        }
    }

    #[test]
    fn hotspot_history_renders_counts_categories_and_limits() {
        let fixture = fixture_with_repo();
        let full = report_for(&fixture, 15, 75);
        assert!(full.contains("- Analyzed commits: 15"), "{full}");
        assert!(full.contains("- Unique files (before cap): 3"), "{full}");
        assert!(
            full.contains(&format!(
                "| `{}` | 15 | 16 | HOTSPOT |",
                rel("src/ComplexService.java")
            )),
            "{full}"
        );
        assert!(
            full.contains(&format!(
                "| `{}` | 1 | 1 | STABLE |",
                rel("src/StableService.java")
            )),
            "{full}"
        );
        assert!(
            full.contains(&format!(
                "| `{}` | 1 | 16 | ABANDONWARE |",
                rel("src/UnusedService.java")
            )),
            "{full}"
        );
        assert!(full.contains("dev0(5)"), "{full}");
        let capped = report_for(&fixture, 15, 1);
        assert!(capped.contains("- Truncated: true"), "{capped}");
        assert_eq!(
            capped
                .lines()
                .filter(|line| line.starts_with("| `"))
                .count(),
            1,
            "{capped}"
        );
        assert!(capped.contains(&rel("src/ComplexService.java")), "{capped}");
        let defaulted = report_for(&fixture, 0, 0);
        assert!(defaulted.contains("- Analyzed commits: 15"), "{defaulted}");
        assert!(
            defaulted.contains("- Unique files (before cap): 3"),
            "{defaulted}"
        );
        assert!(!defaulted.ends_with('\n'), "{defaulted}");
    }

    #[test]
    fn file_complexity_uses_most_complex_method() {
        let source = format!(
            "class Mixed {{ void simple() {{}} void complex(int x) {{\n{}}} }}\n",
            (0..16)
                .map(|n| format!("if (x > {n}) {{}}\n"))
                .collect::<String>()
        );
        let fixture = AnalyzerFixture::new(&[("src/Mixed.java", source.as_str())]);
        let repo = init_repo(&fixture.project_root());
        commit_paths(
            &repo,
            "mixed",
            "Alice",
            "a@example.com",
            "2020-06-01T00:00:00Z",
            &["src/Mixed.java"],
        );
        let report = report_for(&fixture, 1, 75);
        assert!(
            report.contains(&format!(
                "| `{}` | 1 | 17 | ABANDONWARE |",
                rel("src/Mixed.java")
            )),
            "{report}"
        );
    }

    #[test]
    fn time_window_and_iso_inputs_are_honored() {
        let fixture = fixture_with_repo();
        let params = |since: &str, until: &str| AnalyzeGitHotspotsParams {
            since_days: 1,
            since_iso: since.to_string(),
            until_iso: until.to_string(),
            max_commits: 100,
            max_files: 75,
        };
        let at_lower = analyze_git_hotspots(
            fixture.analyzer.analyzer(),
            params("2020-06-01T00:00:00Z", "2020-06-02T00:00:00Z"),
        )
        .report;
        assert!(at_lower.contains("- Analyzed commits: 1"), "{at_lower}");
        assert!(
            at_lower.contains("- Timeframe: since 2020-06-01T00:00:00Z until 2020-06-02T00:00:00Z"),
            "{at_lower}"
        );
        let before_upper = analyze_git_hotspots(
            fixture.analyzer.analyzer(),
            params("2020-06-02T00:00:00Z", "2020-06-03T00:00:00Z"),
        )
        .report;
        assert!(
            before_upper.contains("- Analyzed commits: 1"),
            "{before_upper}"
        );
        let invalid = analyze_git_hotspots(
            fixture.analyzer.analyzer(),
            params("2020-06-01T00:00:00Z", "X"),
        )
        .report;
        assert_eq!(invalid, "Invalid ISO-8601 instant: X");
        let open = analyze_git_hotspots(
            fixture.analyzer.analyzer(),
            params("2020-06-01T00:00:00Z", ""),
        )
        .report;
        assert!(open.contains("- Analyzed commits: 15"), "{open}");
        assert!(
            open.contains("- Timeframe: since 2020-06-01T00:00:00Z\n"),
            "{open}"
        );
    }

    #[test]
    fn renamed_file_keeps_its_history() {
        let fixture = AnalyzerFixture::new(&[("src/Before.java", "class Before { int value; }\n")]);
        let repo = init_repo(&fixture.project_root());
        commit_paths(
            &repo,
            "initial",
            "Alice",
            "a@example.com",
            "2020-06-01T00:00:00Z",
            &["src/Before.java"],
        );
        fs::rename(
            fixture.project_root().join("src/Before.java"),
            fixture.project_root().join("src/After.java"),
        )
        .expect("rename");
        let mut index = repo.index().expect("index");
        index
            .remove_path(Path::new("src/Before.java"))
            .expect("remove old path");
        index.write().expect("index write");
        commit_paths(
            &repo,
            "rename",
            "Bob",
            "b@example.com",
            "2020-06-02T00:00:00Z",
            &["src/After.java"],
        );
        let report = report_for(&fixture, 2, 75);
        assert!(
            report.contains(&format!("| `{}` | 1 |", rel("src/After.java"))),
            "{report}"
        );
        assert!(!report.contains("Before.java"), "{report}");
    }

    #[test]
    fn authors_are_counted_and_ranked_from_commit_history() {
        let fixture =
            AnalyzerFixture::new(&[("src/Authors.java", "class Authors { int n = 0; }\n")]);
        let repo = init_repo(&fixture.project_root());
        for (i, (name, email)) in [
            ("Alice", "a@example.com"),
            ("Bob", "b@example.com"),
            ("Bob", "b@example.com"),
            ("Carol", "c@example.com"),
            ("Dave", "d@example.com"),
            ("Eve", "e@example.com"),
            ("Frank", "f@example.com"),
        ]
        .into_iter()
        .enumerate()
        {
            fs::write(
                fixture.project_root().join("src/Authors.java"),
                format!("class Authors {{ int n = {i}; }}\n"),
            )
            .expect("rewrite");
            commit_paths(
                &repo,
                "change",
                name,
                email,
                &format!("2020-06-{:02}T00:00:00Z", i + 1),
                &["src/Authors.java"],
            );
        }
        let report = report_for(&fixture, 7, 75);
        assert!(report.contains("| 7 |"), "{report}");
        assert!(report.contains("Bob(2)"), "{report}");
        assert_eq!(report.matches("(1)").count(), 4, "{report}");
    }

    #[test]
    fn churn_and_complexity_boundaries_classify_files() {
        let complex = format!(
            "class Boundary {{ void run(int x) {{ {} }} }}\n",
            (0..14)
                .map(|n| format!("if (x == {n}) {{}} "))
                .collect::<String>()
        );
        let fixture = AnalyzerFixture::new(&[
            ("src/Boundary.java", &complex),
            ("src/Active.java", "class Active { int n; }\n"),
        ]);
        let repo = init_repo(&fixture.project_root());
        commit_paths(
            &repo,
            "initial",
            "Alice",
            "a@example.com",
            "2020-06-01T00:00:00Z",
            &["src/Boundary.java", "src/Active.java"],
        );
        for i in 1..11 {
            fs::write(
                fixture.project_root().join("src/Active.java"),
                format!("class Active {{ int n = {i}; }}\n"),
            )
            .expect("rewrite");
            commit_paths(
                &repo,
                "change",
                "Alice",
                "a@example.com",
                &format!("2020-06-{:02}T00:00:00Z", i + 1),
                &["src/Active.java"],
            );
        }
        let report = report_for(&fixture, 11, 75);
        assert!(
            report.contains(&format!("| `{}` | 11 |", rel("src/Active.java"))),
            "{report}"
        );
        assert!(
            report.contains("| 11 | 0 | ACTIVE |") || report.contains("| 11 | 1 | ACTIVE |"),
            "{report}"
        );
        assert!(
            report.contains(&format!(
                "| `{}` | 1 | 15 | STABLE |",
                rel("src/Boundary.java")
            )),
            "{report}"
        );
    }

    #[hardwon("969d61d302f9: revwalk errors silently dropped history")]
    #[test]
    fn broken_history_reports_incompleteness() {
        let fixture = AnalyzerFixture::new(&[("src/A.java", "class A {}\n")]);
        let repo = init_repo(&fixture.project_root());
        commit_paths(
            &repo,
            "initial",
            "Alice",
            "a@example.com",
            "2020-06-01T00:00:00Z",
            &["src/A.java"],
        );
        let mut head = repo.head().expect("head");
        let parent = repo
            .find_commit(head.target().expect("head oid"))
            .expect("commit");
        let raw = format!(
            "tree {}\nparent {}\nparent 1111111111111111111111111111111111111111\nauthor Alice <a@example.com> 1591056000 +0000\ncommitter Alice <a@example.com> 1591056000 +0000\n\nbroken second parent\n",
            parent.tree_id(),
            parent.id()
        );
        let oid = repo
            .odb()
            .expect("odb")
            .write(git2::ObjectType::Commit, raw.as_bytes())
            .expect("write commit");
        head.set_target(oid, "test broken history")
            .expect("move head");
        let report = report_for(&fixture, 10, 75);
        assert!(report.contains("- History incomplete: "), "{report}");
        assert!(
            report.contains("revwalk failed") || report.contains("could not read commit"),
            "{report}"
        );
    }

    #[test]
    fn relative_day_window_and_blank_iso_include_recent_history() {
        let fixture = AnalyzerFixture::new(&[("src/Recent.java", "class Recent {}\n")]);
        let repo = init_repo(&fixture.project_root());
        let when = SystemTime::now() - Duration::from_secs(12 * 60 * 60);
        let iso = system_time_to_iso8601(when);
        commit_paths(
            &repo,
            "recent",
            "Alice",
            "a@example.com",
            &iso,
            &["src/Recent.java"],
        );
        let report = analyze_git_hotspots(
            fixture.analyzer.analyzer(),
            AnalyzeGitHotspotsParams {
                since_days: 1,
                since_iso: "   ".to_string(),
                until_iso: "   ".to_string(),
                max_commits: 1,
                max_files: 1,
            },
        )
        .report;
        assert!(report.contains("- Analyzed commits: 1"), "{report}");
        assert!(report.contains(&rel("src/Recent.java")), "{report}");
    }

    #[test]
    fn merge_churn_uses_first_parent_diff() {
        let fixture = AnalyzerFixture::new(&[
            ("src/A.java", "class A { int n = 0; }\n"),
            ("src/B.java", "class B { int n = 0; }\n"),
        ]);
        let repo = init_repo(&fixture.project_root());
        commit_paths(
            &repo,
            "base",
            "Alice",
            "a@example.com",
            "2020-06-01T00:00:00Z",
            &["src/A.java", "src/B.java"],
        );
        let mut head = repo.head().expect("head");
        let base = repo
            .find_commit(head.target().expect("base oid"))
            .expect("base");
        let signature = Signature::new("Alice", "a@example.com", &git2::Time::new(1591056000, 0))
            .expect("signature");
        let make_commit = |message: &str, parents: &[&Commit<'_>]| {
            let mut index = repo.index().expect("index");
            index.add_path(Path::new("src/A.java")).expect("add A");
            index.add_path(Path::new("src/B.java")).expect("add B");
            index.write().expect("index write");
            let tree = repo
                .find_tree(index.write_tree().expect("tree id"))
                .expect("tree");
            let oid = repo
                .commit(None, &signature, &signature, message, &tree, parents)
                .expect("commit");
            repo.find_commit(oid).expect("find commit")
        };
        fs::write(
            fixture.project_root().join("src/A.java"),
            "class A { int n = 1; }\n",
        )
        .expect("A change");
        let branch_a = make_commit("A branch", &[&base]);
        fs::write(
            fixture.project_root().join("src/A.java"),
            "class A { int n = 0; }\n",
        )
        .expect("restore A");
        fs::write(
            fixture.project_root().join("src/B.java"),
            "class B { int n = 1; }\n",
        )
        .expect("B change");
        let branch_b = make_commit("B branch", &[&base]);
        fs::write(
            fixture.project_root().join("src/A.java"),
            "class A { int n = 1; }\n",
        )
        .expect("merge A");
        let merge = make_commit("merge", &[&branch_a, &branch_b]);
        head.set_target(merge.id(), "merge test")
            .expect("move head");
        let report = report_for(&fixture, 4, 75);
        assert!(
            report.contains(&format!("| `{}` | 2 |", rel("src/A.java"))),
            "{report}"
        );
        assert!(
            report.contains(&format!("| `{}` | 3 |", rel("src/B.java"))),
            "{report}"
        );
    }

    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn accepts_offset_iso_and_formats_utc_timeframe() {
        let fixture = fixture_with_repo();
        let result = analyze_git_hotspots(
            fixture.analyzer.analyzer(),
            AnalyzeGitHotspotsParams {
                since_days: 0,
                since_iso: "2020-06-01T02:30:00+02:30".to_string(),
                until_iso: "2020-06-02T00:00:00.250+00:00".to_string(),
                max_commits: 100,
                max_files: 75,
            },
        );
        assert!(
            result
                .report
                .contains("- Timeframe: since 2020-06-01T00:00:00Z until 2020-06-02T00:00:00.250Z"),
            "{}",
            result.report
        );
    }

    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn invalid_clock_fields_are_rejected() {
        let fixture = fixture_with_repo();
        let result = analyze_git_hotspots(
            fixture.analyzer.analyzer(),
            AnalyzeGitHotspotsParams {
                since_days: 0,
                since_iso: "2020-06-01T25:00:00Z".to_string(),
                until_iso: String::new(),
                max_commits: 100,
                max_files: 75,
            },
        );
        assert_eq!(
            result.report,
            "Invalid ISO-8601 instant: 2020-06-01T25:00:00Z"
        );
    }

    #[test]
    fn commit_window_uses_commit_time_not_author_time() {
        let fixture = AnalyzerFixture::new(&[(
            "src/RebasedService.java",
            "public class RebasedService { void rebased() { if (true) {} } }\n",
        )]);
        let repo = init_repo(&fixture.project_root());

        let mut index = repo.index().expect("repo index");
        index
            .add_path(Path::new("src/RebasedService.java"))
            .expect("add path");
        index.write().expect("index write");
        let tree_id = index.write_tree().expect("write tree");
        let tree = repo.find_tree(tree_id).expect("find tree");
        let author_time = parse_iso8601_utc("2020-01-01T00:00:00Z")
            .expect("author time")
            .duration_since(UNIX_EPOCH)
            .expect("positive author time")
            .as_secs() as i64;
        let commit_time = parse_iso8601_utc("2020-06-05T00:00:00Z")
            .expect("commit time")
            .duration_since(UNIX_EPOCH)
            .expect("positive commit time")
            .as_secs() as i64;
        let author = Signature::new(
            "author",
            "author@example.com",
            &git2::Time::new(author_time, 0),
        )
        .expect("author sig");
        let committer = Signature::new(
            "committer",
            "committer@example.com",
            &git2::Time::new(commit_time, 0),
        )
        .expect("committer sig");
        repo.commit(
            Some("HEAD"),
            &author,
            &committer,
            "rebased commit",
            &tree,
            &[],
        )
        .expect("commit");

        let result = analyze_git_hotspots(
            fixture.analyzer.analyzer(),
            AnalyzeGitHotspotsParams {
                since_days: 0,
                since_iso: "2020-06-01T00:00:00Z".to_string(),
                until_iso: String::new(),
                max_commits: 100,
                max_files: 75,
            },
        );
        assert!(
            result.report.contains("- Analyzed commits: 1"),
            "{}",
            result.report
        );
        assert!(
            result.report.contains(&rel("src/RebasedService.java")),
            "{}",
            result.report
        );
    }

    #[test]
    fn fallback_retry_preserves_report_churn_output() {
        let fixture = AnalyzerFixture::new(&[(
            "src/FallbackService.java",
            "public class FallbackService { void fallback() { if (true) {} } }\n",
        )]);
        let repo = init_repo(&fixture.project_root());
        commit_paths(
            &repo,
            "initial fallback",
            "dev0",
            "dev0@example.com",
            "2020-06-01T00:00:00Z",
            &["src/FallbackService.java"],
        );
        fs::write(
            fixture
                .project_root()
                .join("src")
                .join("FallbackService.java"),
            "public class FallbackService { void fallback() { int marker = 1; if (true) {} } }\n",
        )
        .expect("rewrite fallback");
        commit_paths(
            &repo,
            "update fallback",
            "dev0",
            "dev0@example.com",
            "2020-06-02T00:00:00Z",
            &["src/FallbackService.java"],
        );

        let commit = repo
            .find_commit(repo.head().expect("head").target().expect("head target"))
            .expect("head commit");
        let mut attempts = Vec::new();
        let changed_files = changed_files_with_simulated_retry(
            &repo,
            fixture.project_root().as_path(),
            &commit,
            &mut attempts,
        )
        .expect("fallback succeeds");

        let mut stats_by_file = StdHashMap::new();
        let author = commit.author();
        let email = author.email().unwrap_or_default().to_string();
        let name = author.name().unwrap_or_default().to_string();
        for project_file in changed_files {
            let stats = stats_by_file
                .entry(project_file)
                .or_insert_with(FileStats::default);
            stats.churn += 1;
            *stats.author_counts.entry(email.clone()).or_insert(0) += 1;
            stats
                .author_names
                .entry(email.clone())
                .or_insert_with(|| name.clone());
        }

        let file = ProjectFile::new(
            fixture.project_root(),
            Path::new("src/FallbackService.java"),
        );
        let info = create_file_info(
            fixture.analyzer.analyzer(),
            file.clone(),
            stats_by_file
                .remove(&file)
                .expect("stats for fallback file"),
        )
        .expect("file info");

        assert_eq!(attempts, vec![true, false]);
        assert_eq!(info.churn, 1);
        assert_eq!(info.category, HotspotCategory::Stable);
        assert_eq!(
            info.top_authors,
            vec![AuthorInfo {
                email: "dev0@example.com".to_string(),
                name: "dev0".to_string(),
                commits: 1,
            }]
        );
    }

    #[test]
    fn fallback_retry_disables_rename_detection_and_keeps_changed_file() {
        let fixture = AnalyzerFixture::new(&[(
            "src/FallbackService.java",
            "public class FallbackService { void fallback() { if (true) {} } }\n",
        )]);
        let repo = init_repo(&fixture.project_root());
        commit_paths(
            &repo,
            "initial fallback",
            "dev0",
            "dev0@example.com",
            "2020-06-01T00:00:00Z",
            &["src/FallbackService.java"],
        );

        let commit = repo
            .find_commit(repo.head().expect("head").target().expect("head target"))
            .expect("head commit");
        let mut attempts = Vec::new();
        let changed_files = changed_files_with_simulated_retry(
            &repo,
            fixture.project_root().as_path(),
            &commit,
            &mut attempts,
        )
        .expect("fallback succeeds");

        assert_eq!(attempts, vec![true, false]);
        assert_eq!(
            changed_files,
            vec![ProjectFile::new(
                fixture.project_root(),
                Path::new("src/FallbackService.java")
            )]
        );
    }
}
