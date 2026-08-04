//! Issue #1332: `search_symbols` must not claim a cancellation happened when nothing was
//! cancelled. On the MCP path (a cancellation token is supplied), `most_important_project_files`
//! consults a cold-safe commit-change cache so ranking never spawns an uninterruptible `git`
//! subprocess. Before the fix, a cold cache on that path was folded into the *same* `bool` as a
//! genuine cancellation, so `search_symbols` reported `truncated: true` and the wording "Search
//! was cancelled ... Results are partial" even though the candidate/symbol set was complete and
//! nothing was ever cancelled -- only commit-history *ranking* was unavailable.
//!
//! The fix splits that single bool into `relevance::HistoryRankingStatus` (`Complete` /
//! `Cancelled` / `HistoryUnavailable`) at the source (`most_important_project_files_with_cancellation`)
//! and threads the distinction through `search_symbol_git_tiers` into `search_symbols_with_cancellation`,
//! so the response note is built from the real signal instead of re-guessing it downstream.
//!
//! These tests pin all three shapes end to end through the public `search_symbols_with_cancellation`
//! API: a cold history cache (honest ranking disclaimer, `truncated: false`), a genuine cancellation
//! (unchanged "cancelled ... partial" wording, `truncated: true`), and a warm history cache (no note
//! at all) as a control proving the disclaimer does not fire when ranking data really is available.

use crate::common::InlineTestProject;
use brokk_bifrost::{
    CancellationToken, IAnalyzer, Language, RustAnalyzer,
    searchtools::{SearchSymbolsParams, search_symbols, search_symbols_with_cancellation},
};
use git2::{Oid, Repository, Signature};
use std::path::Path;

/// `most_important_project_files_with_cancellation` requests `COMMITS_TO_PROCESS` (1000) commits
/// on both the cancellable and non-cancellable paths. The cancellable commit-change cache only
/// counts as "warm" once it holds at least that many ordered commit OIDs for the current HEAD, so
/// a repo must actually reach that many commits before a warm-cache shape is reachable through the
/// public API. If `COMMITS_TO_PROCESS` ever changes, this constant must move with it.
const COMMITS_TO_PROCESS: usize = 1000;

fn rust_symbol_project() -> crate::common::BuiltInlineTestProject {
    InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", "pub fn tracked_target_symbol() {}\n")
        .build()
}

/// Commits the same (unchanged) tree `count` times, so the fixture reaches an arbitrary commit
/// count cheaply -- content never changes, so no index/tree writes are needed per commit, only a
/// new commit object per iteration.
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

/// Shape 1: cancellation token supplied (the MCP path) but the commit-change cache is cold (this
/// is the very first request against this repo root, so `cached_recent_commit_changes` has never
/// been primed). Nothing was cancelled -- the token is live and never cancelled -- so the result
/// must be honest: the symbol set is complete (`truncated: false`), and the note must describe
/// degraded *ranking*, not a cancellation that never happened.
#[test]
fn cold_history_cache_yields_honest_ranking_disclaimer_not_cancelled_wording() {
    let project = rust_symbol_project();
    Repository::init(project.root()).unwrap();
    // A single commit is enough to make the file tracked, and far short of
    // `COMMITS_TO_PROCESS`, so the cancellable cache lookup is guaranteed to miss.
    let repo = Repository::open(project.root()).unwrap();
    commit_same_tree_n_times(&repo, "src/lib.rs", 1);

    let analyzer = RustAnalyzer::from_project(project.project().clone());
    let cancellation = CancellationToken::new();
    assert!(!cancellation.is_cancelled(), "token must not be cancelled");

    let search = search_symbols_with_cancellation(&analyzer, search_params(), Some(&cancellation));

    assert!(!search.truncated, "{search:#?}");
    assert_eq!(search.total_files, 1, "{search:#?}");
    assert_eq!(
        search
            .files
            .iter()
            .map(|file| file.path.as_str())
            .collect::<Vec<_>>(),
        vec!["src/lib.rs"],
        "{search:#?}"
    );
    let note = search.note.as_deref().unwrap_or_default();
    assert!(
        note.contains("ranking") && note.contains("complete"),
        "expected an honest ranking-unavailable disclaimer: {search:#?}"
    );
    assert!(
        !note.contains("cancelled") && !note.contains("partial"),
        "a cold cache must never be described as a cancellation: {search:#?}"
    );
}

/// Shape 2: a genuine cancellation token that fired before the request was even dispatched. This
/// must keep today's wording and `truncated: true` -- the fix must not weaken real cancellation
/// reporting while fixing the false-positive case above.
#[test]
fn genuine_cancellation_keeps_cancelled_wording_and_truncated() {
    let project = rust_symbol_project();
    let analyzer = RustAnalyzer::from_project(project.project().clone());
    analyzer
        .test_hooks()
        .reset_full_declaration_scan_count_for_test();
    let cancellation = CancellationToken::new();
    cancellation.cancel();

    let search = search_symbols_with_cancellation(&analyzer, search_params(), Some(&cancellation));

    assert!(search.truncated, "{search:#?}");
    assert_eq!(search.total_files, 0, "{search:#?}");
    assert!(search.files.is_empty(), "{search:#?}");
    let note = search.note.as_deref().unwrap_or_default();
    assert!(
        note.contains("cancelled") && note.contains("partial"),
        "{search:#?}"
    );
    assert!(
        !note.contains("ranking"),
        "a genuine cancellation must not be described as a ranking disclaimer: {search:#?}"
    );
    assert_eq!(
        analyzer.test_hooks().full_declaration_scan_count_for_test(),
        0,
        "a request cancelled before dispatch must not start a persisted scan"
    );
}

/// Shape 3 (control): the commit-change cache is genuinely warm for this repo root -- an earlier,
/// non-cancellable request (the CLI path, mirroring how a real MCP session's cache gets primed by
/// other tool calls against the same workspace) already filled `cached_recent_commit_changes` to
/// at least `COMMITS_TO_PROCESS` entries. A live, uncancelled token on this warm cache must produce
/// no note at all: not the cancellation wording, and not the new ranking disclaimer either, since
/// ranking data really was available this time.
#[test]
fn warm_history_cache_produces_no_note() {
    let project = rust_symbol_project();
    Repository::init(project.root()).unwrap();
    let repo = Repository::open(project.root()).unwrap();
    commit_same_tree_n_times(&repo, "src/lib.rs", COMMITS_TO_PROCESS);

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
        "a warm history cache with a live, uncancelled token must not emit any note: {search:#?}"
    );
}
