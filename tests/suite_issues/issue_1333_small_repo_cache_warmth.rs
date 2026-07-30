//! Issue #1333: the cancellable commit-change cache never warmed for repos with fewer than
//! `COMMITS_TO_PROCESS` (1000) total first-parent commits.
//!
//! `most_important_project_files_with_cancellation` always requests `COMMITS_TO_PROCESS` commits
//! on the MCP (cancellable) path, and before this fix the cache only counted as warm once it held
//! at least that many ordered OIDs for the current HEAD (`tests/suite_issues/issue_1332_search_notes_honesty.rs`'s
//! `warm_history_cache_produces_no_note` pins that large-repo shape). Any repo with fewer total
//! first-parent commits than the constant could never reach `oids.len() >= limit`, so it was
//! *permanently* cold on the MCP path -- even immediately after a CLI-path request had already
//! walked its entire history and filled the cache with everything there is to know. Consequence:
//! every small repo (the common case) permanently reported "ranking unavailable" on MCP-path
//! searches and lost recency weighting, forever, no matter how many warm-up calls preceded it.
//!
//! The fix changes the warm test to `min(total_commits, COMMITS_TO_PROCESS)`: a fill now records
//! whether it returned fewer OIDs than it asked for (`CachedRecentOids::exhausted` in
//! `src/relevance.rs`), meaning `git rev-list` walked first-parent history all the way to its root
//! commit and there is nothing left to discover for that HEAD. A small repo's very first fill sets
//! this flag, so it counts as warm from then on regardless of the constant.
//!
//! This test pins the small-repo warm shape end to end through the public
//! `search_symbols`/`search_symbols_with_cancellation` API, mirroring shape 3
//! (`warm_history_cache_produces_no_note`) from the #1332 suite but with a 5-commit fixture
//! instead of a 1000-commit one. It also re-confirms (by construction, using the same shared
//! per-repo-root cache) that the #1228 never-spawn-on-cold contract is untouched: a genuinely cold
//! cache (never filled) still never spawns `git rev-list` on the cancellable path -- what changed
//! is only that a *filled* small-repo cache now counts as warm, not that cold caches start doing
//! more work.

use crate::common::InlineTestProject;
use brokk_bifrost::{
    CancellationToken, Language, RustAnalyzer,
    searchtools::{SearchSymbolsParams, search_symbols, search_symbols_with_cancellation},
};
use git2::{Oid, Repository, Signature};
use std::path::Path;

/// Comfortably below `COMMITS_TO_PROCESS` (1000): this is the common "small repo" shape the issue
/// is about, not an edge case near the threshold.
const SMALL_REPO_COMMIT_COUNT: usize = 5;

fn rust_symbol_project() -> crate::common::BuiltInlineTestProject {
    InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", "pub fn tracked_target_symbol() {}\n")
        .build()
}

/// Commits the same (unchanged) tree `count` times, so the fixture reaches an arbitrary commit
/// count cheaply -- content never changes, so no index/tree writes are needed per commit, only a
/// new commit object per iteration. Shared technique with the #1332 suite's 1000-commit fixture.
fn commit_same_tree_n_times(repo: &Repository, tracked_file: &str, count: usize) {
    let mut index = repo.index().unwrap();
    index.add_path(Path::new(tracked_file)).unwrap();
    index.write().unwrap();
    let tree_id = index.write_tree().unwrap();
    let tree = repo.find_tree(tree_id).unwrap();
    let signature = Signature::now("Test User", "test@example.com").unwrap();

    let mut parent_oid: Option<Oid> = None;
    for i in 0..count {
        let parent_commit = parent_oid.and_then(|oid| repo.find_commit(oid).ok());
        let parents = parent_commit.iter().collect::<Vec<_>>();
        let oid = repo
            .commit(
                Some("HEAD"),
                &signature,
                &signature,
                &format!("commit {i}"),
                &tree,
                &parents,
            )
            .unwrap();
        parent_oid = Some(oid);
    }
}

fn search_params() -> SearchSymbolsParams {
    SearchSymbolsParams {
        patterns: vec!["tracked_target_symbol".to_string()],
        include_tests: true,
        limit: 100,
    }
}

/// Fail-before/pass-after case: a small repo (well under `COMMITS_TO_PROCESS`) whose commit-change
/// cache is warmed once via the non-cancellable CLI path (mirroring an earlier request against the
/// same workspace, exactly like #1332's warm-cache control). Before the fix, this repo could never
/// reach `oids.len() >= COMMITS_TO_PROCESS` and stayed cold forever, so the follow-up MCP-path
/// (cancellable) request would still emit the "ranking unavailable" disclaimer. After the fix, one
/// fill captures all 5 commits and marks the cache exhausted, so the follow-up request must produce
/// no note at all -- ranking data was genuinely available.
#[test]
fn small_repo_warms_on_first_fill_and_mcp_path_gets_ranking() {
    let project = rust_symbol_project();
    Repository::init(project.root()).unwrap();
    let repo = Repository::open(project.root()).unwrap();
    commit_same_tree_n_times(&repo, "src/lib.rs", SMALL_REPO_COMMIT_COUNT);

    let analyzer = RustAnalyzer::from_project(project.project().clone());

    // Prime the shared, repo-root-keyed commit-change cache via the non-cancellable (CLI) path,
    // exactly as would happen from an earlier request against the same workspace.
    let warmup = search_symbols(&analyzer, search_params());
    assert_eq!(warmup.total_files, 1, "{warmup:#?}");

    let cancellation = CancellationToken::new();
    assert!(!cancellation.is_cancelled(), "token must not be cancelled");
    let search = search_symbols_with_cancellation(&analyzer, search_params(), Some(&cancellation));

    assert!(!search.truncated, "{search:#?}");
    assert_eq!(search.total_files, 1, "{search:#?}");
    assert_eq!(
        search.note, None,
        "a small repo whose complete history was already captured by a prior fill must count as \
         warm and emit no ranking-unavailable note: {search:#?}"
    );
}

/// Companion negative control: on a *fresh* small repo where the cancellable request is the very
/// first request against the repo root (the cache was never filled by anything), the cache must
/// still be cold and the request must still get the honest ranking-unavailable disclaimer -- the
/// fix is about a *filled* small-repo cache counting as warm, not about small repos warming
/// without ever being filled.
#[test]
fn small_repo_stays_cold_without_a_prior_fill() {
    let project = rust_symbol_project();
    Repository::init(project.root()).unwrap();
    let repo = Repository::open(project.root()).unwrap();
    commit_same_tree_n_times(&repo, "src/lib.rs", SMALL_REPO_COMMIT_COUNT);

    let analyzer = RustAnalyzer::from_project(project.project().clone());
    let cancellation = CancellationToken::new();
    assert!(!cancellation.is_cancelled(), "token must not be cancelled");

    let search = search_symbols_with_cancellation(&analyzer, search_params(), Some(&cancellation));

    assert!(!search.truncated, "{search:#?}");
    assert_eq!(search.total_files, 1, "{search:#?}");
    let note = search.note.as_deref().unwrap_or_default();
    assert!(
        note.contains("ranking") && note.contains("complete"),
        "an unfilled cache must still report the honest ranking-unavailable disclaimer: {search:#?}"
    );
}
