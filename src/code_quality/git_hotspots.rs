//! MCP `analyze_git_hotspots` handler. Correlates git churn with
//! heuristic cyclomatic complexity per file. Output format mirrors
//! brokk-core's `CodeQualityTools.analyzeGitHotspots` byte-for-byte.

use super::{ReportLines, cyclomatic_complexity_for, sanitize_table_cell};
use crate::analyzer::{IAnalyzer, ProjectFile};
use chrono::{DateTime, SecondsFormat, Utc};
use git2::{Commit, DiffFindOptions, DiffOptions, Repository, Sort};
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::collections::{HashMap as StdHashMap, VecDeque};
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
    files: Vec<FileHotspotInfo>,
}

#[derive(Default)]
struct FileStats {
    churn: usize,
    author_counts: StdHashMap<String, usize>,
    author_names: StdHashMap<String, String>,
    last_modified_epoch_secs: Option<i64>,
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
            files: Vec::new(),
        });
    }
    walker
        .push_head()
        .map_err(|err| format!("Git hotspot analysis requires HEAD history: {err}"))?;

    let mut stats_by_file: StdHashMap<ProjectFile, FileStats> = StdHashMap::new();
    let mut analyzed_commits = 0usize;

    for (examined_commits, oid) in walker.enumerate() {
        if examined_commits >= max_commits {
            break;
        }
        let Ok(oid) = oid else {
            continue;
        };
        let Ok(commit) = repo.find_commit(oid) else {
            continue;
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
        );
    }

    let mut files = stats_by_file
        .into_iter()
        .filter_map(|(file, stats)| create_file_info(analyzer, file, stats))
        .collect::<Vec<_>>();
    files.sort_by_key(|info| Reverse(info.churn));

    let total_unique_files = files.len();
    let cap = max_files.min(MAX_FILES_IN_REPORT_HARD_CAP);
    let truncated = total_unique_files > cap;
    if truncated {
        files.truncate(cap);
    }

    Ok(HotspotReport {
        repository: project_root.display().to_string(),
        analyzed_commits,
        timeframe,
        total_unique_files,
        truncated,
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
) {
    let author = commit.author();
    let email = author.email().unwrap_or_default().to_string();
    let name = author.name().unwrap_or_default().to_string();
    let commit_secs = author.when().seconds();

    let Ok(mut diff) = diff_commit_to_parent(repo, commit) else {
        return;
    };
    let mut find_opts = DiffFindOptions::new();
    find_opts.renames(true);
    find_opts.rename_limit(RENAME_DETECTION_LIMIT);
    let _ = diff.find_similar(Some(&mut find_opts));

    for delta in diff.deltas() {
        let Some(path) = delta_path(&delta) else {
            continue;
        };
        let Some(project_file) = repo_rel_to_project_file(project_root, repo_root, path) else {
            continue;
        };
        let stats = stats_by_file.entry(project_file).or_default();
        stats.churn += 1;
        *stats.author_counts.entry(email.clone()).or_insert(0) += 1;
        stats
            .author_names
            .entry(email.clone())
            .or_insert(name.clone());
        if stats
            .last_modified_epoch_secs
            .is_none_or(|current| commit_secs > current)
        {
            stats.last_modified_epoch_secs = Some(commit_secs);
        }
    }
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
            commits,
        })
        .collect::<Vec<_>>();
    top_authors.sort_by_key(|author| Reverse(author.commits));
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
    let mut max_complexity = 0u32;
    let mut work = VecDeque::new();
    work.extend(analyzer.get_top_level_declarations(file));
    while let Some(code_unit) = work.pop_front() {
        if code_unit.is_function() {
            max_complexity = max_complexity.max(cyclomatic_complexity_for(analyzer, &code_unit));
        }
        for child in analyzer.get_direct_children(&code_unit) {
            work.push_back(child);
        }
    }
    max_complexity
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
    use super::*;
    use crate::test_support::AnalyzerFixture;
    use git2::{Repository, Signature};
    use std::fs;
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
        let mut index = repo.index().expect("repo index");
        for path in add {
            index.add_path(Path::new(path)).expect("add path");
        }
        index.write().expect("index write");
        let tree_id = index.write_tree().expect("write tree");
        let tree = repo.find_tree(tree_id).expect("find tree");
        let timestamp = parse_iso8601_utc(when).expect("parse commit time");
        let seconds = timestamp
            .duration_since(UNIX_EPOCH)
            .expect("positive timestamp")
            .as_secs() as i64;
        let signature = Signature::new(author_name, author_email, &git2::Time::new(seconds, 0))
            .expect("signature");
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
        .expect("commit");
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

    #[test]
    fn hotspot_report_matches_expected_categories_and_authors() {
        let fixture = fixture_with_repo();
        let result = analyze_git_hotspots(
            fixture.analyzer.analyzer(),
            AnalyzeGitHotspotsParams {
                since_days: 0,
                since_iso: "2020-01-01T00:00:00Z".to_string(),
                until_iso: String::new(),
                max_commits: 100,
                max_files: 75,
            },
        );
        assert!(
            result
                .report
                .starts_with("## Git hotspots\n\n- Repository: `")
        );
        assert!(result.report.contains("- Analyzed commits: 15"));
        assert!(
            result
                .report
                .contains("| `src/ComplexService.java` | 15 | 16 | HOTSPOT |"),
            "{}",
            result.report
        );
        for expected in ["dev0(5)", "dev1(5)", "dev2(5)"] {
            assert!(result.report.contains(expected), "{}", result.report);
        }
        assert!(
            result
                .report
                .contains("| `src/StableService.java` | 1 | 1 | STABLE | dev0(1) |")
        );
        assert!(
            result
                .report
                .contains("| `src/UnusedService.java` | 1 | 16 | ABANDONWARE | dev0(1) |")
        );
    }

    #[test]
    fn max_files_truncates_and_sets_flag() {
        let fixture = fixture_with_repo();
        let result = analyze_git_hotspots(
            fixture.analyzer.analyzer(),
            AnalyzeGitHotspotsParams {
                since_days: 0,
                since_iso: "2020-01-01T00:00:00Z".to_string(),
                until_iso: String::new(),
                max_commits: 100,
                max_files: 2,
            },
        );
        assert!(result.report.contains("- Unique files (before cap): 3"));
        assert!(result.report.contains("- Truncated: true"));
        assert_eq!(
            result.report.matches("| `src/").count(),
            2,
            "{}",
            result.report
        );
    }

    #[test]
    fn until_excludes_later_commits() {
        let fixture = fixture_with_repo();
        let result = analyze_git_hotspots(
            fixture.analyzer.analyzer(),
            AnalyzeGitHotspotsParams {
                since_days: 0,
                since_iso: "2020-01-01T00:00:00Z".to_string(),
                until_iso: "2020-06-03T00:00:00Z".to_string(),
                max_commits: 100,
                max_files: 75,
            },
        );
        assert!(
            result.report.contains("- Analyzed commits: 2"),
            "{}",
            result.report
        );
        assert!(
            result
                .report
                .contains("| `src/ComplexService.java` | 2 | 16 | ABANDONWARE |"),
            "{}",
            result.report
        );
        for expected in ["dev0(1)", "dev1(1)"] {
            assert!(result.report.contains(expected), "{}", result.report);
        }
    }

    #[test]
    fn no_matching_commits_returns_empty_state() {
        let fixture = fixture_with_repo();
        let result = analyze_git_hotspots(
            fixture.analyzer.analyzer(),
            AnalyzeGitHotspotsParams {
                since_days: 0,
                since_iso: "2030-01-01T00:00:00Z".to_string(),
                until_iso: String::new(),
                max_commits: 100,
                max_files: 75,
            },
        );
        assert!(result.report.ends_with("No file hotspots in this window."));
    }

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
            result.report.contains("src/RebasedService.java"),
            "{}",
            result.report
        );
    }
}
