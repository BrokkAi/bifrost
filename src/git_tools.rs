use crate::analyzer::IAnalyzer;
use git2::{Commit, Delta, Diff, DiffFindOptions, DiffOptions, ObjectType, Patch, Repository, Sort};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

const DEFAULT_LOG_LIMIT: usize = 20;
const DEFAULT_SEARCH_LIMIT: usize = 20;
const MAX_LOG_LIMIT: usize = 100;
const MAX_SEARCH_LIMIT: usize = 100;
const DEFAULT_DIFF_MAX_FILES: usize = 10;
const DEFAULT_DIFF_LINES_PER_FILE: usize = 1000;
const MAX_DIFF_FILES: usize = 100;
const MAX_DIFF_LINES_PER_FILE: usize = 5000;
// Matches brokk's PerformanceConstants.MAX_DIFF_LINE_LENGTH_BYTES (50KB):
// hunks containing any single data line longer than this are dropped from
// the diff because they are almost always minified bundles, generated
// fixtures, or binary blobs masquerading as text — none of which are
// useful in the textual diff for downstream consumers.
const MAX_DIFF_LINE_LENGTH_BYTES: usize = 50 * 1024;

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

pub fn search_git_commit_messages(
    analyzer: &dyn IAnalyzer,
    params: SearchGitCommitMessagesParams,
) -> String {
    let pattern = params.pattern.trim();
    if pattern.is_empty() {
        return "Cannot search commit messages: pattern is empty".to_string();
    }
    let regex = match Regex::new(pattern) {
        Ok(re) => re,
        Err(err) => return format!("Error searching commit messages: invalid regex: {err}"),
    };

    let context = match GitContext::open(analyzer.project().root()) {
        Ok(ctx) => ctx,
        Err(err) => return format!("Cannot search commit messages: {err}"),
    };

    let effective_limit = params.limit.clamp(1, MAX_SEARCH_LIMIT);

    let walker = match context.revwalk_head() {
        Ok(w) => w,
        Err(err) => return format!("Error searching commit messages: {err}"),
    };

    let mut matches: Vec<Commit<'_>> = Vec::new();
    let mut truncated = false;

    for oid in walker.flatten() {
        let Ok(commit) = context.repo.find_commit(oid) else {
            continue;
        };
        let message = commit.message().unwrap_or("");
        if !regex.is_match(message) {
            continue;
        }
        if matches.len() >= effective_limit {
            truncated = true;
            break;
        }
        matches.push(commit);
    }

    if matches.is_empty() {
        return format!("No commit messages found matching pattern: {pattern}");
    }

    let mut out = String::new();
    if truncated {
        let _ = writeln!(
            out,
            "### WARNING: Result limit reached (max {effective_limit} commits). Showing first {effective_limit} matching commits. Retrying the same tool call will return the same results.\n"
        );
    }

    for commit in &matches {
        let full_hash = commit.id().to_string();
        let _ = writeln!(out, "<commit id=\"{}\">", escape_xml_attr(&full_hash));
        let _ = writeln!(out, "<message>");
        let message = commit.message().unwrap_or("").trim_end();
        if !message.is_empty() {
            let _ = writeln!(out, "{message}");
        }
        let _ = writeln!(out, "</message>");
        let _ = writeln!(out, "<edited_files>");
        let files = list_files_changed_in_commit(&context.repo, commit);
        for path in &files {
            let _ = writeln!(out, "{path}");
        }
        let _ = writeln!(out, "</edited_files>");
        let _ = writeln!(out, "</commit>");
    }
    out
}

pub fn get_git_log(analyzer: &dyn IAnalyzer, params: GetGitLogParams) -> String {
    let context = match GitContext::open(analyzer.project().root()) {
        Ok(ctx) => ctx,
        Err(err) => return format!("Cannot retrieve git log: {err}"),
    };

    let effective_limit = params.limit.clamp(1, MAX_LOG_LIMIT);
    let trimmed_path = params
        .path
        .as_deref()
        .map(|raw| raw.trim().replace('\\', "/"))
        .filter(|s| !s.is_empty());
    if let Some(raw) = trimmed_path.as_deref()
        && raw.starts_with(':')
    {
        return "Cannot retrieve git log: path filter starts with ':' — pathspec magic is not supported, pass a plain workspace-relative path".to_string();
    }
    let filter_path = trimmed_path
        .clone()
        .map(|rel| context.project_rel_to_repo_rel(Path::new(&rel)));

    // When the filter resolves to a tracked file, walk history rename-aware so
    // entries before a rename are still surfaced and tagged with [RENAMED].
    // For directories or untracked paths fall back to a plain pathspec filter.
    if let Some(repo_rel) = filter_path.as_deref()
        && is_file_in_head(&context.repo, repo_rel)
    {
        return rename_aware_log(
            &context,
            repo_rel,
            trimmed_path.as_deref().unwrap_or(""),
            effective_limit,
        );
    }

    let walker = match context.revwalk_head() {
        Ok(w) => w,
        Err(err) => return format!("Cannot retrieve git log: {err}"),
    };

    let mut commits: Vec<Commit<'_>> = Vec::new();
    for oid in walker.flatten() {
        let Ok(commit) = context.repo.find_commit(oid) else {
            continue;
        };
        if let Some(path) = filter_path.as_deref()
            && !commit_touches_path(&context.repo, &commit, path)
        {
            continue;
        }
        if commits.len() >= effective_limit {
            break;
        }
        commits.push(commit);
    }

    if commits.is_empty() {
        return match trimmed_path.as_deref() {
            Some(p) => format!("No history found for path: {p}"),
            None => "No history found for path: (repo root)".to_string(),
        };
    }

    let mut out = String::new();
    out.push_str("<git_log");
    if let Some(p) = trimmed_path.as_deref() {
        let _ = write!(out, " path=\"{}\"", escape_xml_attr(p));
    }
    out.push_str(">\n");

    for commit in &commits {
        append_log_entry(&mut out, &context.repo, commit, None, None);
    }

    out.push_str("</git_log>");
    out
}

fn is_file_in_head(repo: &Repository, rel: &Path) -> bool {
    let Ok(head_commit) = repo.head().and_then(|h| h.peel_to_commit()) else {
        return false;
    };
    let Ok(tree) = head_commit.tree() else {
        return false;
    };
    tree.get_path(rel)
        .map(|e| e.kind() == Some(ObjectType::Blob))
        .unwrap_or(false)
}

fn rename_aware_log(
    context: &GitContext,
    head_rel: &Path,
    display_path: &str,
    effective_limit: usize,
) -> String {
    let walker = match context.revwalk_head() {
        Ok(w) => w,
        Err(err) => return format!("Cannot retrieve git log: {err}"),
    };

    // `current_target` is the path the file holds at the parent of the
    // commit currently being inspected — i.e. the name we expect to find on
    // the "new" side of the diff for that commit. When the commit renames
    // the file, we follow the old name into ancestors.
    let mut current_target: PathBuf = head_rel.to_path_buf();
    // Collected entries in walked order (newest → oldest). Stored as
    // (commit, currentPath, nextPath) per brokk's naming: currentPath is
    // what the file was called before the commit, nextPath after.
    let mut entries: Vec<(Commit<'_>, PathBuf, PathBuf)> = Vec::new();

    for oid in walker.flatten() {
        let Ok(commit) = context.repo.find_commit(oid) else {
            continue;
        };

        let Ok(current_tree) = commit.tree() else {
            continue;
        };
        let parent_tree = if commit.parent_count() == 0 {
            None
        } else {
            commit.parent(0).and_then(|p| p.tree()).ok()
        };

        let mut opts = DiffOptions::new();
        opts.include_untracked(false);
        let Ok(mut diff) = context.repo.diff_tree_to_tree(
            parent_tree.as_ref(),
            Some(&current_tree),
            Some(&mut opts),
        ) else {
            continue;
        };

        let mut find_opts = DiffFindOptions::new();
        find_opts.renames(true);
        let _ = diff.find_similar(Some(&mut find_opts));

        // Locate a delta whose new-side path equals our current target.
        let mut matched: Option<(PathBuf, PathBuf, bool)> = None;
        for delta in diff.deltas() {
            let Some(new_path) = delta.new_file().path() else {
                continue;
            };
            if new_path == current_target {
                let old_path = delta
                    .old_file()
                    .path()
                    .map(|p| p.to_path_buf())
                    .unwrap_or_else(|| new_path.to_path_buf());
                let is_rename =
                    matches!(delta.status(), Delta::Renamed | Delta::Copied) && old_path != new_path;
                matched = Some((old_path, new_path.to_path_buf(), is_rename));
                break;
            }
        }

        if let Some((old_path, new_path, is_rename)) = matched {
            entries.push((commit, old_path.clone(), new_path));
            if entries.len() >= effective_limit {
                break;
            }
            if is_rename {
                current_target = old_path;
            }
        }
    }

    if entries.is_empty() {
        return format!("No history found for path: {display_path}");
    }

    let mut out = String::new();
    out.push_str("<git_log");
    let _ = write!(out, " path=\"{}\"", escape_xml_attr(display_path));
    out.push_str(">\n");

    for (commit, current_path, next_path) in &entries {
        let current_display = current_path.to_string_lossy();
        let next_display = next_path.to_string_lossy();
        append_log_entry(
            &mut out,
            &context.repo,
            commit,
            Some(&current_display),
            Some(&next_display),
        );
    }

    out.push_str("</git_log>");
    out
}

pub fn get_commit_diff(analyzer: &dyn IAnalyzer, params: GetCommitDiffParams) -> String {
    let revision = params.revision.trim().to_string();
    if !is_safe_revision(&revision) {
        return format!(
            "Error retrieving commit diff for {revision}: revision contains unsupported syntax; pass a hex hash, branch, or tag name"
        );
    }
    let context = match GitContext::open(analyzer.project().root()) {
        Ok(ctx) => ctx,
        Err(err) => return format!("Cannot retrieve commit diff: {err}"),
    };

    let object = match context.repo.revparse_single(&revision) {
        Ok(obj) => obj,
        Err(err) => {
            return format!("Error retrieving commit diff for {revision}: unable to resolve revision: {err}");
        }
    };

    let commit = match object.peel_to_commit() {
        Ok(c) => c,
        Err(err) => {
            return format!("Error retrieving commit diff for {revision}: not a commit: {err}");
        }
    };

    let current_tree = match commit.tree() {
        Ok(t) => t,
        Err(err) => {
            return format!("Error retrieving commit diff for {revision}: commit tree missing: {err}");
        }
    };

    let parent_tree = if commit.parent_count() == 0 {
        None
    } else {
        match commit.parent(0).and_then(|p| p.tree()) {
            Ok(t) => Some(t),
            Err(err) => {
                return format!("Error retrieving commit diff for {revision}: parent tree missing: {err}");
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
            return format!("Error retrieving commit diff for {revision}: diff failed: {err}");
        }
    };

    let max_files = params.max_files.clamp(1, MAX_DIFF_FILES);
    let lines_per_file = params.lines_per_file.clamp(1, MAX_DIFF_LINES_PER_FILE);
    let formatted = format_diff(&mut diff, max_files, lines_per_file);

    let full_hash = commit.id().to_string();
    let short_hash: String = full_hash.chars().take(7).collect();

    let mut out = String::new();
    let _ = write!(
        out,
        "<commit_diff revision=\"{}\" short_hash=\"{}\" files_total=\"{}\" files_included=\"{}\" truncated=\"{}\">\n",
        escape_xml_attr(&revision),
        escape_xml_attr(&short_hash),
        formatted.files_total,
        formatted.files_included,
        formatted.truncated
    );
    out.push_str(&formatted.text);
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str("</commit_diff>");
    out
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
        // Use `Repository::open` (no upward search). `Repository::discover`
        // would walk parents looking for a `.git`, which can quietly attach
        // bifrost to an enclosing repository (e.g. `~/.git`) and leak commit
        // data from outside the workspace. Callers that need git operations
        // on a subdirectory of a repo should activate the repo root first via
        // `activate_workspace`, which normalizes to the nearest enclosing
        // git root.
        let repo = Repository::open(&canonical).map_err(|err| {
            format!(
                "not a git repository at project root ({}): {err}. \
                 If the workspace is a subdirectory of a repository, call \
                 activate_workspace to normalize to the git root.",
                canonical.display()
            )
        })?;
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
        // Topological + time order matches `git log`'s default: descendants
        // always appear before their ancestors, with time as a tie-breaker.
        // Pure time order breaks when sibling commits share a timestamp
        // (test fixtures hit this; tight CI builds occasionally too) and
        // would let rename-following see an ancestor before the child that
        // performs the rename, losing the trail.
        walker
            .set_sorting(Sort::TOPOLOGICAL | Sort::TIME)
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

fn append_log_entry(
    out: &mut String,
    repo: &Repository,
    commit: &Commit<'_>,
    current_path: Option<&str>,
    next_path: Option<&str>,
) {
    let full_hash = commit.id().to_string();
    let short_hash: String = full_hash.chars().take(7).collect();
    let author = commit
        .author()
        .name()
        .map(|s| s.to_string())
        .unwrap_or_default();
    let date = format_iso_date(commit.time().seconds());

    let _ = write!(
        out,
        "<entry hash=\"{}\" author=\"{}\" date=\"{}\"",
        escape_xml_attr(&short_hash),
        escape_xml_attr(&author),
        escape_xml_attr(&date)
    );
    if let Some(p) = current_path {
        let _ = write!(out, " path=\"{}\"", escape_xml_attr(p));
    }
    out.push_str(">\n");

    if let (Some(cur), Some(next)) = (current_path, next_path)
        && cur != next
    {
        let _ = writeln!(out, "[RENAMED] {cur} -> {next}");
    }

    let message = commit.message().unwrap_or("").trim_end();
    if !message.is_empty() {
        let _ = writeln!(out, "{message}");
    }

    let files = list_files_changed_in_commit(repo, commit);
    if !files.is_empty() {
        let names: BTreeSet<&str> = files
            .iter()
            .filter_map(|p| Path::new(p).file_name().and_then(|n| n.to_str()))
            .collect();
        let joined: Vec<&str> = names.into_iter().collect();
        let _ = writeln!(out, "Files: {}", joined.join(", "));
    }

    out.push_str("</entry>\n");
}

fn list_files_changed_in_commit(repo: &Repository, commit: &Commit<'_>) -> Vec<String> {
    let Ok(current_tree) = commit.tree() else {
        return Vec::new();
    };
    let parent_tree = if commit.parent_count() == 0 {
        None
    } else {
        commit.parent(0).and_then(|p| p.tree()).ok()
    };
    let mut opts = DiffOptions::new();
    opts.include_untracked(false);
    let Ok(diff) = repo.diff_tree_to_tree(parent_tree.as_ref(), Some(&current_tree), Some(&mut opts))
    else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for delta in diff.deltas() {
        if let Some(path) = delta.new_file().path().and_then(|p| p.to_str()) {
            out.push(path.to_string());
        } else if let Some(path) = delta.old_file().path().and_then(|p| p.to_str()) {
            out.push(path.to_string());
        }
    }
    out
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

// Reject revparse syntax that triggers expensive walks or non-local lookups.
// `:/regex` walks every reachable commit's message; `@{...}` resolves reflog
// entries or upstream tracking; leading `-` would be parsed as an option-like
// argument by some tools. We confine input to plain hashes, refs, and the
// peel/parent suffixes (`^`, `~`, `^{}`).
fn is_safe_revision(s: &str) -> bool {
    !s.is_empty() && !s.starts_with('-') && !s.contains(':') && !s.contains("@{")
}

fn escape_xml_attr(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\n' | '\r' | '\t' => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

// Format a Unix timestamp as ISO 8601 UTC. Implemented in-crate to avoid
// pulling chrono just for date formatting. Uses Howard Hinnant's
// `civil_from_days` algorithm (proleptic Gregorian). Defined for the full
// i64 range; assumes the input represents seconds since the Unix epoch.
fn format_iso_date(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let secs_of_day = seconds.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let sec = secs_of_day % 60;
    format!("{y:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{sec:02}Z")
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u64; // 0..=146096
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // 0..=399
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // 0..=365
    let mp = (5 * doy + 2) / 153; // 0..=11
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // 1..=31
    let m = if mp < 10 { (mp + 3) as u32 } else { (mp - 9) as u32 }; // 1..=12
    let y = y + if m <= 2 { 1 } else { 0 };
    (y, m, d)
}

struct FormattedDiff {
    text: String,
    files_total: usize,
    files_included: usize,
    truncated: bool,
}

// Ported from brokk's CommitPrompts.preprocessUnifiedDiff so output is
// semantically aligned across both MCP servers.
//
// Behavior:
//  - Each file's hunks are inspected; any hunk containing a data line longer
//    than MAX_DIFF_LINE_LENGTH_BYTES is dropped (minified/generated/binary
//    text). Files whose entire patch is dropped this way are skipped.
//  - Surviving files are ordered by (hunk-count desc, total data-line count
//    desc) so the most-changed files surface first within max_files.
//  - Within each emitted file, hunks are ordered by data-line count desc.
//    Hunks are added until the cumulative file budget would exceed
//    lines_per_file. The largest hunk is always emitted, even if it alone
//    exceeds lines_per_file, so the file is never empty in the output.
//  - File headers are reconstructed as `diff --git a/X b/X` / `--- a/X` /
//    `+++ b/X`, matching brokk. Adds/deletes use `/dev/null` on the
//    missing side.
fn format_diff(diff: &mut Diff<'_>, max_files: usize, lines_per_file: usize) -> FormattedDiff {
    let files_total = diff.deltas().len();
    let mut metrics: Vec<FileMetrics> = (0..files_total)
        .filter_map(|idx| build_file_metrics(diff, idx))
        .collect();

    metrics.sort_by(|a, b| {
        b.hunks
            .len()
            .cmp(&a.hunks.len())
            .then_with(|| b.total_data_lines.cmp(&a.total_data_lines))
    });

    let target = max_files.min(metrics.len());
    let mut truncated = metrics.len() > target;
    let mut output = String::new();
    let mut files_included = 0;

    for fm in metrics.iter().take(target) {
        let _ = writeln!(output, "diff --git {} {}", fm.a_path, fm.b_path);
        let _ = writeln!(output, "--- {}", fm.a_path);
        let _ = writeln!(output, "+++ {}", fm.b_path);

        // Hunks ordered by data-line count desc; ties broken by original
        // file order to keep output stable.
        let mut hunks: Vec<&FileHunk> = fm.hunks.iter().collect();
        hunks.sort_by(|a, b| {
            b.data_line_count
                .cmp(&a.data_line_count)
                .then_with(|| a.original_idx.cmp(&b.original_idx))
        });

        let mut added: usize = 0;
        let mut included_any = false;
        for hunk in &hunks {
            let size = hunk.budget_size();
            if !included_any && size > lines_per_file {
                // Brokk semantics: always include the largest hunk to avoid
                // emitting an empty file. Mark truncated since the budget
                // was overshot.
                emit_hunk(&mut output, hunk);
                truncated = true;
                break;
            }
            if added + size <= lines_per_file {
                emit_hunk(&mut output, hunk);
                added += size;
                included_any = true;
            } else {
                truncated = true;
                break;
            }
        }
        files_included += 1;
    }

    FormattedDiff {
        text: output,
        files_total,
        files_included,
        truncated,
    }
}

struct FileMetrics {
    a_path: String,
    b_path: String,
    hunks: Vec<FileHunk>,
    total_data_lines: usize,
}

struct FileHunk {
    original_idx: usize,
    header: String,
    body: String,
    data_line_count: usize,
}

impl FileHunk {
    // Match brokk's deltaSize: 1 header line + data-line count. Context
    // lines are not part of the budget because brokk's preprocessor strips
    // them; bifrost keeps them in the body (since git-style context is
    // useful to non-LLM consumers), but the budget unit is still data
    // lines so file-budget semantics match brokk.
    fn budget_size(&self) -> usize {
        1 + self.data_line_count
    }
}

fn emit_hunk(out: &mut String, hunk: &FileHunk) {
    out.push_str(&hunk.header);
    if !hunk.header.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&hunk.body);
    if !hunk.body.is_empty() && !hunk.body.ends_with('\n') {
        out.push('\n');
    }
}

fn build_file_metrics(diff: &Diff<'_>, idx: usize) -> Option<FileMetrics> {
    let patch = match Patch::from_diff(diff, idx) {
        Ok(Some(p)) => p,
        _ => return None,
    };
    let delta = patch.delta();
    let (a_path, b_path) = format_ab_paths(&delta);
    let num_hunks = patch.num_hunks();

    let mut hunks: Vec<FileHunk> = Vec::new();
    let mut total_data_lines: usize = 0;

    for h in 0..num_hunks {
        let Ok((hunk_info, _)) = patch.hunk(h) else {
            continue;
        };
        let header = String::from_utf8_lossy(hunk_info.header()).into_owned();
        let n_lines = patch.num_lines_in_hunk(h).unwrap_or(0);

        let mut body = String::new();
        let mut data_lines: usize = 0;
        let mut has_overlong = false;

        for li in 0..n_lines {
            let Ok(line) = patch.line_in_hunk(h, li) else {
                continue;
            };
            let origin = line.origin();
            let content = String::from_utf8_lossy(line.content());
            if content.len() > MAX_DIFF_LINE_LENGTH_BYTES {
                has_overlong = true;
                break;
            }
            // Only emit a leading origin char for the prefixes git uses on
            // diff data lines. Other origins (file/hunk headers, binary
            // markers) shouldn't appear here since we iterate inside a
            // hunk; if they do, write the content verbatim so we don't
            // corrupt the diff.
            match origin {
                ' ' | '+' | '-' => {
                    body.push(origin);
                    body.push_str(&content);
                    if origin == '+' || origin == '-' {
                        data_lines += 1;
                    }
                }
                '<' | '>' => {
                    // "no newline at end of file" markers; reproduce git's
                    // literal `\ No newline at end of file` line so
                    // round-trippers don't choke.
                    body.push_str("\\ No newline at end of file\n");
                }
                _ => {
                    body.push_str(&content);
                }
            }
        }

        if has_overlong {
            continue;
        }
        total_data_lines += data_lines;
        hunks.push(FileHunk {
            original_idx: h,
            header,
            body,
            data_line_count: data_lines,
        });
    }

    if hunks.is_empty() {
        return None;
    }
    Some(FileMetrics {
        a_path,
        b_path,
        hunks,
        total_data_lines,
    })
}

fn format_ab_paths(delta: &git2::DiffDelta<'_>) -> (String, String) {
    let old_path = delta
        .old_file()
        .path()
        .and_then(|p| p.to_str())
        .map(|s| s.to_string());
    let new_path = delta
        .new_file()
        .path()
        .and_then(|p| p.to_str())
        .map(|s| s.to_string());

    let (a_raw, b_raw) = match delta.status() {
        Delta::Added => (None, new_path),
        Delta::Deleted => (old_path, None),
        // Modified, Renamed, Copied, Typechange, etc.: keep both sides.
        _ => (old_path, new_path),
    };

    let a = match a_raw {
        None => "/dev/null".to_string(),
        Some(p) if p.starts_with("a/") => p,
        Some(p) => format!("a/{p}"),
    };
    let b = match b_raw {
        None => "/dev/null".to_string(),
        Some(p) if p.starts_with("b/") => p,
        Some(p) => format!("b/{p}"),
    };
    (a, b)
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
    use crate::analyzer::{AnalyzerConfig, FilesystemProject, Project, WorkspaceAnalyzer};
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
            let project: Arc<dyn Project> =
                Arc::new(FilesystemProject::new(repo_path.clone()).expect("project"));
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

        fn merge_commit(&self, message: &str, parents: &[git2::Oid]) -> git2::Oid {
            let repo = Repository::open(&self.repo_path).expect("open repo");
            let head_commit = repo
                .head()
                .and_then(|h| h.peel_to_commit())
                .expect("head commit");
            let tree = head_commit.tree().expect("tree");
            let sig = Signature::now("Tester", "test@example.com").expect("sig");
            let parent_commits: Vec<git2::Commit> = parents
                .iter()
                .map(|oid| repo.find_commit(*oid).expect("find parent"))
                .collect();
            let parent_refs: Vec<&git2::Commit> = parent_commits.iter().collect();
            repo.commit(Some("HEAD"), &sig, &sig, message, &tree, &parent_refs)
                .expect("merge commit")
        }
    }

    #[test]
    fn search_git_commit_messages_emits_commit_blocks() {
        let fix = GitFixture::new();
        fix.commit("Initial scaffold", &[("a.txt", "1")]);
        fix.commit("Fix: tighten parser", &[("a.txt", "2")]);
        fix.commit("Docs: README", &[("a.txt", "3")]);

        let out = search_git_commit_messages(
            fix.analyzer.analyzer(),
            SearchGitCommitMessagesParams {
                pattern: "(?i)^fix".to_string(),
                limit: 10,
            },
        );
        assert!(out.contains("<commit id=\""), "expected <commit>: {out}");
        assert!(out.contains("<message>"));
        assert!(out.contains("Fix: tighten parser"));
        assert!(out.contains("</message>"));
        assert!(out.contains("<edited_files>"));
        assert!(out.contains("a.txt"));
        assert!(out.contains("</edited_files>"));
        assert!(out.contains("</commit>"));
        // Only one match — no truncation warning.
        assert!(!out.contains("WARNING"));
    }

    #[test]
    fn search_git_commit_messages_reports_invalid_regex() {
        let fix = GitFixture::new();
        fix.commit("Initial", &[("a.txt", "1")]);
        let out = search_git_commit_messages(
            fix.analyzer.analyzer(),
            SearchGitCommitMessagesParams {
                pattern: "[".to_string(),
                limit: 10,
            },
        );
        assert!(out.contains("invalid regex"));
    }

    #[test]
    fn search_git_commit_messages_emits_truncation_warning() {
        let fix = GitFixture::new();
        fix.commit("c1", &[("a.txt", "1")]);
        fix.commit("c2", &[("a.txt", "2")]);
        fix.commit("c3", &[("a.txt", "3")]);
        let out = search_git_commit_messages(
            fix.analyzer.analyzer(),
            SearchGitCommitMessagesParams {
                pattern: ".".to_string(),
                limit: 2,
            },
        );
        assert!(out.starts_with("### WARNING: Result limit reached (max 2 commits)"));
        assert_eq!(out.matches("<commit id=\"").count(), 2);
    }

    #[test]
    fn search_git_commit_messages_no_warning_at_exact_limit() {
        let fix = GitFixture::new();
        fix.commit("c1", &[("a.txt", "1")]);
        fix.commit("c2", &[("a.txt", "2")]);
        let out = search_git_commit_messages(
            fix.analyzer.analyzer(),
            SearchGitCommitMessagesParams {
                pattern: ".".to_string(),
                limit: 2,
            },
        );
        assert!(!out.contains("WARNING"));
        assert_eq!(out.matches("<commit id=\"").count(), 2);
    }

    #[test]
    fn search_git_commit_messages_reports_no_match() {
        let fix = GitFixture::new();
        fix.commit("alpha", &[("a.txt", "1")]);
        let out = search_git_commit_messages(
            fix.analyzer.analyzer(),
            SearchGitCommitMessagesParams {
                pattern: "zzz_no_match".to_string(),
                limit: 10,
            },
        );
        assert!(out.starts_with("No commit messages found"));
    }

    #[test]
    fn get_git_log_filters_by_path() {
        let fix = GitFixture::new();
        fix.commit("create-a", &[("a.txt", "1")]);
        fix.commit("touch-b", &[("b.txt", "1")]);
        fix.commit("touch-a", &[("a.txt", "2")]);

        let out = get_git_log(
            fix.analyzer.analyzer(),
            GetGitLogParams {
                path: Some("b.txt".to_string()),
                limit: 10,
            },
        );
        assert!(out.contains("<git_log path=\"b.txt\">"));
        assert!(out.contains("touch-b"));
        assert!(!out.contains("create-a"));
        assert!(!out.contains("touch-a"));
        assert!(out.contains("</git_log>"));
    }

    #[test]
    fn get_git_log_returns_all_when_no_path() {
        let fix = GitFixture::new();
        fix.commit("c1", &[("a.txt", "1")]);
        fix.commit("c2", &[("b.txt", "1")]);
        let out = get_git_log(
            fix.analyzer.analyzer(),
            GetGitLogParams {
                path: None,
                limit: 10,
            },
        );
        assert!(out.starts_with("<git_log>"));
        assert_eq!(out.matches("<entry ").count(), 2);
    }

    #[test]
    fn get_git_log_follows_renames_on_tracked_file() {
        // Create a.txt, rename to renamed.txt, then modify renamed.txt.
        // History for "renamed.txt" must surface all three commits with a
        // [RENAMED] marker on the rename commit.
        let fix = GitFixture::new();
        fix.commit("create a", &[("a.txt", "line one\n")]);

        // Rename a.txt → renamed.txt: delete the old, add the new with same
        // contents so libgit2 rename detection picks it up via find_similar.
        let repo = Repository::open(&fix.repo_path).expect("open repo");
        std::fs::remove_file(fix.repo_path.join("a.txt")).expect("rm a.txt");
        std::fs::write(fix.repo_path.join("renamed.txt"), "line one\n").expect("write renamed");
        let mut index = repo.index().expect("index");
        index.remove_path(Path::new("a.txt")).expect("remove a.txt");
        index
            .add_path(Path::new("renamed.txt"))
            .expect("add renamed.txt");
        index.write().expect("write index");
        let tree_oid = index.write_tree().expect("write tree");
        let tree = repo.find_tree(tree_oid).expect("tree");
        let sig = git2::Signature::now("Tester", "test@example.com").expect("sig");
        let head_commit = repo
            .head()
            .and_then(|h| h.peel_to_commit())
            .expect("head commit");
        repo.commit(
            Some("HEAD"),
            &sig,
            &sig,
            "rename a.txt to renamed.txt",
            &tree,
            &[&head_commit],
        )
        .expect("rename commit");

        fix.commit("touch renamed", &[("renamed.txt", "line one\nline two\n")]);

        let out = get_git_log(
            fix.analyzer.analyzer(),
            GetGitLogParams {
                path: Some("renamed.txt".to_string()),
                limit: 10,
            },
        );

        assert!(out.contains("<git_log path=\"renamed.txt\">"), "got: {out}");
        // Both the rename commit and the post-rename modify commit are
        // surfaced; the original create-a.txt commit too (under its old
        // name).
        assert!(out.contains("touch renamed"), "got: {out}");
        assert!(out.contains("rename a.txt to renamed.txt"), "got: {out}");
        assert!(out.contains("create a"), "got: {out}");
        assert!(
            out.contains("[RENAMED] a.txt -> renamed.txt"),
            "expected rename marker, got: {out}"
        );
        // Pre-rename commit's path attribute should reference the old name.
        assert!(out.contains("path=\"a.txt\""), "got: {out}");
    }

    #[test]
    fn get_git_log_emits_no_history_for_unknown_path() {
        let fix = GitFixture::new();
        fix.commit("c1", &[("a.txt", "1")]);
        let out = get_git_log(
            fix.analyzer.analyzer(),
            GetGitLogParams {
                path: Some("nonexistent.txt".to_string()),
                limit: 10,
            },
        );
        assert!(out.starts_with("No history found for path: nonexistent.txt"));
    }

    #[test]
    fn get_commit_diff_handles_root_commit() {
        let fix = GitFixture::new();
        let oid = fix.commit("Initial", &[("a.txt", "alpha\n")]);
        let out = get_commit_diff(
            fix.analyzer.analyzer(),
            GetCommitDiffParams {
                revision: oid.to_string(),
                max_files: 10,
                lines_per_file: 1000,
            },
        );
        assert!(out.contains("<commit_diff"));
        assert!(out.contains("files_total=\"1\""));
        assert!(out.contains("files_included=\"1\""));
        assert!(out.contains("alpha"));
        assert!(out.contains("</commit_diff>"));
    }

    #[test]
    fn get_commit_diff_handles_merge_commit() {
        // Branch off root, create two commits on different branches, then
        // merge. `get_commit_diff` must use parent(0) — diff vs first parent —
        // and produce a coherent diff for the merge commit revision.
        let fix = GitFixture::new();
        let root = fix.commit("root", &[("a.txt", "root\n")]);
        let _main = fix.commit("main change", &[("a.txt", "main\n")]);

        // Build a side branch from `root`.
        let repo = Repository::open(&fix.repo_path).expect("open repo");
        let root_commit = repo.find_commit(root).expect("root commit");
        repo.branch("side", &root_commit, false).expect("branch");
        repo.set_head("refs/heads/side").expect("set head");
        repo.checkout_head(Some(git2::build::CheckoutBuilder::new().force()))
            .expect("checkout");
        let _side = fix.commit("side change", &[("b.txt", "side\n")]);

        // Switch back to master.
        repo.set_head("refs/heads/master")
            .or_else(|_| repo.set_head("refs/heads/main"))
            .expect("set head master/main");
        repo.checkout_head(Some(git2::build::CheckoutBuilder::new().force()))
            .expect("checkout master");

        // Build merge commit with master (parent 0) + side (parent 1).
        let master_oid = repo
            .head()
            .and_then(|h| h.peel_to_commit())
            .map(|c| c.id())
            .expect("master oid");
        let side_oid = repo
            .find_branch("side", git2::BranchType::Local)
            .and_then(|b| b.into_reference().peel_to_commit())
            .map(|c| c.id())
            .expect("side oid");
        let merge_oid = fix.merge_commit("merge side", &[master_oid, side_oid]);

        let out = get_commit_diff(
            fix.analyzer.analyzer(),
            GetCommitDiffParams {
                revision: merge_oid.to_string(),
                max_files: 10,
                lines_per_file: 1000,
            },
        );
        assert!(out.contains("<commit_diff"), "got: {out}");
        // The merge's tree equals master's tree (we passed master's tree to
        // merge_commit), so diff vs first parent (master) is empty: zero
        // files included, but no error.
        assert!(out.contains("files_total=\"0\""), "got: {out}");
        assert!(!out.contains("Error retrieving commit diff"));
    }

    #[test]
    fn get_commit_diff_truncates_when_over_file_limit() {
        let fix = GitFixture::new();
        let oid = fix.commit(
            "Many files",
            &[("a.txt", "a\n"), ("b.txt", "b\n"), ("c.txt", "c\n")],
        );
        let out = get_commit_diff(
            fix.analyzer.analyzer(),
            GetCommitDiffParams {
                revision: oid.to_string(),
                max_files: 1,
                lines_per_file: 1000,
            },
        );
        assert!(out.contains("truncated=\"true\""));
        assert!(out.contains("files_total=\"3\""));
        assert!(out.contains("files_included=\"1\""));
    }

    #[test]
    fn get_commit_diff_marks_truncated_when_hunk_exceeds_budget() {
        // The new format_diff (brokk-parity) does not slice hunks at the
        // line budget — it skips hunks that would overshoot, but always
        // includes the largest hunk so the file is never empty. When the
        // largest hunk alone exceeds `lines_per_file`, `truncated=true` is
        // reported even though the hunk's content is emitted in full.
        let mut body = String::new();
        for i in 0..20 {
            body.push_str(&format!("line{i}\n"));
        }
        let fix = GitFixture::new();
        let oid = fix.commit("big file", &[("a.txt", body.as_str())]);
        let out = get_commit_diff(
            fix.analyzer.analyzer(),
            GetCommitDiffParams {
                revision: oid.to_string(),
                max_files: 10,
                lines_per_file: 3,
            },
        );
        assert!(out.contains("truncated=\"true\""), "got: {out}");
        // The single hunk was emitted in full, so all 20 added lines should
        // appear in the diff body.
        assert!(out.contains("+line0"), "got: {out}");
        assert!(out.contains("+line19"), "got: {out}");
    }

    #[test]
    fn get_commit_diff_orders_files_by_change_density() {
        // Three files. After modification, data-line counts are roughly
        // big.txt > mid.txt > small.txt. With max_files=2 the smallest
        // must be excluded.
        let mut big_seed = String::new();
        let mut big_mod = String::new();
        for i in 0..10 {
            let _ = writeln!(big_seed, "old{i}");
            let _ = writeln!(big_mod, "new{i}");
        }
        let fix = GitFixture::new();
        fix.commit(
            "seed",
            &[
                ("big.txt", big_seed.as_str()),
                ("mid.txt", "a\nb\nc\n"),
                ("small.txt", "x\n"),
            ],
        );
        let oid = fix.commit(
            "many changes",
            &[
                ("big.txt", big_mod.as_str()),
                ("mid.txt", "A\nB\nC\n"),
                ("small.txt", "x\n"), // unchanged → not in diff at all
            ],
        );

        let out = get_commit_diff(
            fix.analyzer.analyzer(),
            GetCommitDiffParams {
                revision: oid.to_string(),
                max_files: 1,
                lines_per_file: 1000,
            },
        );
        // Only big.txt and mid.txt changed, so files_total=2. With
        // max_files=1, only the densest (big.txt) is included.
        assert!(out.contains("files_total=\"2\""), "got: {out}");
        assert!(out.contains("files_included=\"1\""), "got: {out}");
        assert!(out.contains("truncated=\"true\""), "got: {out}");
        assert!(out.contains("a/big.txt"), "got: {out}");
        assert!(!out.contains("a/mid.txt"), "got: {out}");
    }

    #[test]
    fn get_commit_diff_drops_files_with_overlong_lines() {
        // A file whose sole hunk contains a >50KB single line is dropped
        // entirely (overlong-line filter, matching brokk's hasOverlongLine).
        // A second normal file in the same commit still surfaces.
        let mut huge = "x".repeat(60 * 1024);
        huge.push('\n');
        let fix = GitFixture::new();
        let oid = fix.commit(
            "two files",
            &[("normal.txt", "hello\n"), ("huge.txt", huge.as_str())],
        );
        let out = get_commit_diff(
            fix.analyzer.analyzer(),
            GetCommitDiffParams {
                revision: oid.to_string(),
                max_files: 10,
                lines_per_file: 1000,
            },
        );
        // files_total reflects the raw git delta count; files_included
        // counts only the patches that survived the overlong-line filter.
        assert!(out.contains("files_total=\"2\""), "got: {out}");
        assert!(out.contains("files_included=\"1\""), "got: {out}");
        assert!(out.contains("b/normal.txt"), "got: {out}");
        assert!(!out.contains("b/huge.txt"), "got: {out}");
    }

    #[test]
    fn get_commit_diff_always_includes_largest_hunk() {
        // A file whose only hunk is larger than `lines_per_file` must still
        // emit that hunk (brokk's "include the largest hunk even if it
        // exceeds the limit" rule), so the file is never empty.
        let mut body = String::new();
        for i in 0..50 {
            let _ = writeln!(body, "line{i}");
        }
        let fix = GitFixture::new();
        let oid = fix.commit("dense", &[("a.txt", body.as_str())]);
        let out = get_commit_diff(
            fix.analyzer.analyzer(),
            GetCommitDiffParams {
                revision: oid.to_string(),
                max_files: 10,
                lines_per_file: 5,
            },
        );
        assert!(out.contains("truncated=\"true\""), "got: {out}");
        assert!(out.contains("+line0"), "got: {out}");
        assert!(out.contains("+line49"), "got: {out}");
    }

    #[test]
    fn get_commit_diff_clamps_oversized_max_files() {
        let fix = GitFixture::new();
        let oid = fix.commit("one file", &[("a.txt", "a\n")]);
        let out = get_commit_diff(
            fix.analyzer.analyzer(),
            GetCommitDiffParams {
                revision: oid.to_string(),
                max_files: usize::MAX,
                lines_per_file: usize::MAX,
            },
        );
        assert!(out.contains("files_total=\"1\""));
        assert!(out.contains("files_included=\"1\""));
    }

    #[test]
    fn get_commit_diff_reports_unknown_revision() {
        let fix = GitFixture::new();
        fix.commit("c1", &[("a.txt", "1")]);
        let out = get_commit_diff(
            fix.analyzer.analyzer(),
            GetCommitDiffParams {
                revision: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
                max_files: 10,
                lines_per_file: 1000,
            },
        );
        assert!(out.starts_with("Error retrieving commit diff"));
    }

    #[test]
    fn get_commit_diff_rejects_unsafe_revspec_syntax() {
        let fix = GitFixture::new();
        fix.commit("c1", &[("a.txt", "1")]);
        for revision in [":/.", "HEAD@{1 year ago}", "-foo"] {
            let out = get_commit_diff(
                fix.analyzer.analyzer(),
                GetCommitDiffParams {
                    revision: revision.to_string(),
                    max_files: 10,
                    lines_per_file: 1000,
                },
            );
            assert!(
                out.starts_with("Error retrieving commit diff"),
                "expected error for revision {revision:?}, got: {out}"
            );
        }
    }

    #[test]
    fn get_git_log_rejects_pathspec_magic() {
        let fix = GitFixture::new();
        fix.commit("c1", &[("a.txt", "1")]);
        fix.commit("c2", &[("b.txt", "2")]);
        for magic in [":(exclude)a.txt", ":!a.txt", ":(glob)**"] {
            let out = get_git_log(
                fix.analyzer.analyzer(),
                GetGitLogParams {
                    path: Some(magic.to_string()),
                    limit: 10,
                },
            );
            assert!(
                out.starts_with("Cannot retrieve git log:"),
                "expected error for {magic:?}, got: {out}"
            );
        }
    }

    #[test]
    fn git_context_refuses_workspace_not_at_repo_root() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().canonicalize().expect("canonicalize tempdir");
        Repository::init(&repo_path).expect("git init");
        let nested = repo_path.join("nested");
        fs::create_dir_all(&nested).expect("mkdir nested");
        let project: Arc<dyn Project> =
            Arc::new(FilesystemProject::new(nested.clone()).expect("project"));
        let workspace = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
        let out = get_git_log(
            workspace.analyzer(),
            GetGitLogParams {
                path: None,
                limit: 10,
            },
        );
        assert!(out.starts_with("Cannot retrieve git log:"), "got: {out}");
    }
}
