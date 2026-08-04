//! Issue #1588: no test may build its workspace on the developer's real cache.
//!
//! A persisted workspace resolves its store through `gitblob::cache_db_path`,
//! which walks up to the primary repository root. A test rooted inside the
//! checkout therefore opens the one database every other Bifrost build on the
//! machine also writes, and inherits its schema: on 2026-08-04 a sibling
//! worktree migrated it one version ahead and 35 unrelated tests failed with
//! `DatabaseTooFarAhead`.
//!
//! `tests/common/scratch_cache.rs` provides the two seams that remove the
//! coupling. These tests prove each of them end to end, so a change that
//! quietly re-binds the repository database fails here rather than silently
//! restoring the shared-state problem.

use std::path::{Path, PathBuf};

use brokk_bifrost::SearchToolsService;
use brokk_bifrost::gitblob::cache_db_path;

use crate::common::{ScratchCacheDir, fixture_corpus};

fn checkout_cache_db() -> PathBuf {
    cache_db_path(Path::new(env!("CARGO_MANIFEST_DIR")))
}

#[test]
fn an_in_process_persisted_workspace_writes_its_corpus_cache() {
    let corpus = fixture_corpus("testcode-java");
    let corpus_cache = cache_db_path(corpus.root());
    assert!(
        corpus_cache.starts_with(corpus.root()),
        "corpus cache {} escaped {}",
        corpus_cache.display(),
        corpus.root().display()
    );
    assert_ne!(corpus_cache, checkout_cache_db());

    let service = SearchToolsService::new_without_semantic_index(corpus.root().to_path_buf())
        .expect("build a persisted service on the corpus");
    let payload = service
        .call_tool_json("get_summaries", r#"{"targets":["A.java"]}"#)
        .expect("get_summaries");
    assert!(payload.contains("A.java"), "payload: {payload}");

    assert!(
        corpus_cache.exists(),
        "a persisted workspace must create its cache at {}",
        corpus_cache.display()
    );
}

#[test]
fn a_spawned_process_writes_the_scratch_cache_it_was_given() {
    let repository_fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");
    assert!(
        cache_db_path(&repository_fixture) == checkout_cache_db(),
        "this test is only meaningful while the fixture resolves the checkout's cache"
    );

    let cache = ScratchCacheDir::new();
    let output = cache
        .command(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(&repository_fixture)
        .arg("--tool")
        .arg("get_summaries")
        .arg("--args")
        .arg(r#"{"targets":["A.java"]}"#)
        .output()
        .expect("run bifrost --tool get_summaries");
    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let written: Vec<String> = std::fs::read_dir(cache.path())
        .expect("read scratch cache dir")
        .map(|entry| {
            entry
                .expect("scratch cache entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert!(
        written.iter().any(|name| name.starts_with("bifrost_cache")),
        "a spawned process rooted in the checkout must write the scratch cache it was given, \
         but {} holds {written:?}",
        cache.path().display()
    );
}
