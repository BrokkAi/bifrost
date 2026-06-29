//! End-to-end semantic_search pipeline test with deterministic fake engines:
//! index build -> vector scan -> grounded bm25 -> co-edit relevance, returned as
//! three independent ranked lists.
#![cfg(feature = "nlp")]

use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use brokk_bifrost::nlp::engine::{Embedder, FakeHashEmbedder};
use brokk_bifrost::nlp::indexer::{EngineProvider, FakeEngineProvider, SemanticIndexer};
use brokk_bifrost::nlp::query::{SemanticSearchParams, SemanticSearchResult, semantic_search};
use brokk_bifrost::{AnalyzerConfig, FilesystemProject, Project, WorkspaceAnalyzer};

fn all_legs_empty(result: &SemanticSearchResult) -> bool {
    result.vector_ranked.is_empty()
        && result.bm25_ranked.is_empty()
        && result.coedit_ranked.is_empty()
}

fn write_java(dir: &Path, name: &str, body: &str) {
    std::fs::write(dir.join(name), body).unwrap();
}

fn snapshot_for(root: &Path) -> Arc<WorkspaceAnalyzer> {
    let project: Arc<dyn Project> = Arc::new(FilesystemProject::new(root.to_path_buf()).unwrap());
    Arc::new(WorkspaceAnalyzer::build(project, AnalyzerConfig::default()))
}

/// Semantic search now requires a git repo (the cache is keyed by blob OID), so
/// every fixture initializes one and commits the files written so far.
fn init_git(dir: &Path) {
    run_git(dir, &["init", "-q"]);
    run_git(dir, &["config", "user.email", "t@example.com"]);
    run_git(dir, &["config", "user.name", "T"]);
    run_git(dir, &["add", "-A"]);
    run_git(dir, &["commit", "-q", "-m", "init"]);
}

fn run_git(dir: &Path, args: &[&str]) {
    let status = std::process::Command::new("git")
        .current_dir(dir)
        .args(args)
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?} failed");
}

struct BlockingEmbedder {
    state: Mutex<BlockingState>,
    entered: Condvar,
    released: Condvar,
}

struct BlockingState {
    in_embed: bool,
    release: bool,
}

impl BlockingEmbedder {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(BlockingState {
                in_embed: false,
                release: false,
            }),
            entered: Condvar::new(),
            released: Condvar::new(),
        })
    }

    fn wait_until_embedding(&self) {
        let mut state = self.state.lock().expect("blocking embedder mutex poisoned");
        while !state.in_embed {
            state = self
                .entered
                .wait(state)
                .expect("blocking embedder mutex poisoned");
        }
    }

    fn release(&self) {
        let mut state = self.state.lock().expect("blocking embedder mutex poisoned");
        state.release = true;
        self.released.notify_all();
    }
}

impl Embedder for BlockingEmbedder {
    fn dim(&self) -> usize {
        1
    }

    fn embed_passages(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, String> {
        let mut state = self.state.lock().expect("blocking embedder mutex poisoned");
        state.in_embed = true;
        self.entered.notify_all();
        while !state.release {
            state = self
                .released
                .wait(state)
                .expect("blocking embedder mutex poisoned");
        }
        Ok(texts.iter().map(|_| vec![1.0]).collect())
    }

    fn embed_query(&self, _text: &str) -> Result<Vec<f32>, String> {
        Ok(vec![1.0])
    }

    fn count_tokens(&self, text: &str) -> usize {
        text.split_whitespace().count()
    }

    fn fingerprint(&self) -> String {
        "semantic-search-blocking-test-embedder:v1".to_string()
    }
}

struct BlockingEngineProvider {
    embedder: Arc<BlockingEmbedder>,
}

impl EngineProvider for BlockingEngineProvider {
    fn embedder(&self) -> Result<Arc<dyn Embedder>, String> {
        Ok(self.embedder.clone())
    }
}

#[test]
fn semantic_search_returns_constituent_rankings() {
    let dir = tempfile::tempdir().unwrap();
    write_java(
        dir.path(),
        "ConfigLoader.java",
        "public class ConfigLoader {\n  public String loadConfig(String path) { return path; }\n}\n",
    );
    write_java(
        dir.path(),
        "HttpClient.java",
        "public class HttpClient {\n  public int fetchUrl(String url) { return url.length(); }\n}\n",
    );
    init_git(dir.path());
    let snapshot = snapshot_for(dir.path());
    let embedder = Arc::new(FakeHashEmbedder::new(16));
    let indexer = SemanticIndexer::start_with_provider(
        dir.path().to_path_buf(),
        snapshot.clone(),
        FakeEngineProvider { embedder },
    );

    let result = semantic_search(
        &snapshot,
        &indexer,
        SemanticSearchParams {
            // "loadConfig" grounds against the repo symbol universe, so the bm25
            // leg surfaces the loadConfig function chunk by fqfn.
            query: "where does loadConfig read the configuration".to_string(),
            k: 2,
        },
    )
    .expect("semantic_search succeeds");

    // The vector leg ranks the function chunks (file-summary chunks excluded).
    assert!(
        !result.vector_ranked.is_empty(),
        "vector leg returns function symbols"
    );
    // The grounded bm25 leg keys on fully-qualified names, so the loadConfig
    // function is recovered by symbol.
    assert!(
        result
            .bm25_ranked
            .iter()
            .any(|row| row.fqfn.contains("loadConfig")),
        "bm25 leg surfaces the loadConfig symbol: {:?}",
        result.bm25_ranked
    );
    indexer.close();
}

#[test]
fn semantic_search_handles_initial_build_race() {
    let dir = tempfile::tempdir().unwrap();
    write_java(
        dir.path(),
        "Greeter.java",
        "public class Greeter {\n  public String greet(String name) { return name; }\n}\n",
    );
    init_git(dir.path());
    let snapshot = snapshot_for(dir.path());
    let embedder = Arc::new(FakeHashEmbedder::new(16));
    let indexer = SemanticIndexer::start_with_provider(
        dir.path().to_path_buf(),
        snapshot.clone(),
        FakeEngineProvider { embedder },
    );

    // Issued immediately after start: must not error while the first build is
    // still racing the query path. Slow Windows runners can legitimately hit
    // the query timeout and return the documented partial-result shape here, so
    // assert the no-error contract first and check ranking after explicit
    // readiness below.
    let _initial_result = semantic_search(
        &snapshot,
        &indexer,
        SemanticSearchParams {
            query: "greet a user by name".to_string(),
            k: 1,
        },
    )
    .expect("query issued during build does not fail");

    indexer.wait_ready(Duration::from_secs(30)).unwrap();
    let result = semantic_search(
        &snapshot,
        &indexer,
        SemanticSearchParams {
            query: "greet a user by name".to_string(),
            k: 1,
        },
    )
    .expect("query after build readiness");
    assert_eq!(
        result.vector_ranked.len(),
        1,
        "the single greet() function chunk is ranked"
    );

    indexer.close();
}

#[test]
fn semantic_search_times_out_and_returns_current_results() {
    let dir = tempfile::tempdir().unwrap();
    write_java(
        dir.path(),
        "Greeter.java",
        "public class Greeter {\n  public String greet(String name) { return name; }\n}\n",
    );
    init_git(dir.path());
    let snapshot = snapshot_for(dir.path());
    let embedder = BlockingEmbedder::new();
    let indexer = SemanticIndexer::start_with_provider(
        dir.path().to_path_buf(),
        snapshot.clone(),
        BlockingEngineProvider {
            embedder: embedder.clone(),
        },
    );
    embedder.wait_until_embedding();

    let result = semantic_search(
        &snapshot,
        &indexer,
        SemanticSearchParams {
            query: "greet a user by name".to_string(),
            k: 1,
        },
    )
    .expect("query should fall back while index build is still running");

    assert!(
        all_legs_empty(&result),
        "no vectors have been committed yet"
    );
    assert!(
        result
            .notes
            .iter()
            .any(|note| note.contains("still building")),
        "notes should explain the fallback: {:?}",
        result.notes
    );

    indexer.close();
    embedder.release();
}

#[test]
fn semantic_index_status_counts_indexed_and_waiting_files() {
    let dir = tempfile::tempdir().unwrap();
    write_java(
        dir.path(),
        "Greeter.java",
        "public class Greeter {\n  public String greet(String name) { return name; }\n}\n",
    );
    init_git(dir.path());
    let snapshot = snapshot_for(dir.path());
    let embedder = Arc::new(FakeHashEmbedder::new(16));
    let indexer = SemanticIndexer::start_with_provider(
        dir.path().to_path_buf(),
        snapshot.clone(),
        FakeEngineProvider { embedder },
    );

    indexer.wait_ready(Duration::from_secs(30)).unwrap();
    let status = indexer.status(&snapshot);
    // Greeter has a file-summary chunk plus the greet() function chunk.
    assert!(
        status.indexed_chunks >= 2,
        "indexed chunks: {}",
        status.indexed_chunks
    );
    assert_eq!(status.pending_batches, 0);
    assert_eq!(status.phase, "ready");
    indexer.close();
}

#[test]
fn revert_reuses_cached_blob_vectors() {
    use std::collections::BTreeSet;

    let dir = tempfile::tempdir().unwrap();
    let original =
        "public class Greeter {\n  public String greet(String name) { return name; }\n}\n";
    let edited = "public class Greeter {\n  public String greet(String name) { return \"hi \" + name; }\n}\n";
    write_java(dir.path(), "Greeter.java", original);
    init_git(dir.path());
    let snapshot = snapshot_for(dir.path());
    let embedder = Arc::new(FakeHashEmbedder::new(16));
    let indexer = SemanticIndexer::start_with_provider(
        dir.path().to_path_buf(),
        snapshot.clone(),
        FakeEngineProvider {
            embedder: embedder.clone(),
        },
    );
    indexer.wait_ready(Duration::from_secs(30)).unwrap();

    let file = snapshot
        .analyzer()
        .analyzed_files()
        .next()
        .cloned()
        .expect("one analyzed file");
    let changed: BTreeSet<_> = [file].into_iter().collect();

    // Edit + commit -> new blob OID -> the new content is embedded.
    write_java(dir.path(), "Greeter.java", edited);
    run_git(dir.path(), &["commit", "-aqm", "edit"]);
    let snapshot2 = Arc::new(snapshot.update(&changed));
    indexer.request_update(snapshot2.clone(), changed.clone());
    indexer.wait_ready(Duration::from_secs(30)).unwrap();
    let after_edit = embedder.texts_embedded();
    assert!(after_edit > 0, "editing embeds the new content");

    // Revert + commit -> original blob OID already materialized -> no re-embed.
    write_java(dir.path(), "Greeter.java", original);
    run_git(dir.path(), &["commit", "-aqm", "revert"]);
    let snapshot3 = Arc::new(snapshot2.update(&changed));
    indexer.request_update(snapshot3, changed);
    indexer.wait_ready(Duration::from_secs(30)).unwrap();
    assert_eq!(
        embedder.texts_embedded(),
        after_edit,
        "reverting to a cached blob must reuse vectors, not re-embed"
    );
    indexer.close();
}

#[test]
fn run_gc_blocking_completes_and_is_repeatable() {
    let dir = tempfile::tempdir().unwrap();
    write_java(
        dir.path(),
        "Greeter.java",
        "public class Greeter {\n  public String greet(String name) { return name; }\n}\n",
    );
    init_git(dir.path());
    let snapshot = snapshot_for(dir.path());
    let embedder = Arc::new(FakeHashEmbedder::new(16));
    let indexer = SemanticIndexer::start_with_provider(
        dir.path().to_path_buf(),
        snapshot.clone(),
        FakeEngineProvider { embedder },
    );
    indexer.wait_ready(Duration::from_secs(30)).unwrap();

    // The forced GC runs on the worker and replies on its own channel; the
    // active worktree's blobs stay live, so a follow-up query still resolves.
    indexer.run_gc_blocking().expect("gc completes");
    indexer.run_gc_blocking().expect("gc is repeatable");

    let result = semantic_search(
        &snapshot,
        &indexer,
        SemanticSearchParams {
            query: "greet a user by name".to_string(),
            k: 1,
        },
    )
    .expect("query after gc");
    assert_eq!(result.vector_ranked.len(), 1, "live blob survives gc");
    indexer.close();
}

#[test]
fn semantic_search_caps_requested_k() {
    let dir = tempfile::tempdir().unwrap();
    write_java(
        dir.path(),
        "Greeter.java",
        "public class Greeter {\n  public String greet(String name) { return name; }\n}\n",
    );
    init_git(dir.path());
    let snapshot = snapshot_for(dir.path());
    let embedder = Arc::new(FakeHashEmbedder::new(16));
    let indexer = SemanticIndexer::start_with_provider(
        dir.path().to_path_buf(),
        snapshot.clone(),
        FakeEngineProvider { embedder },
    );

    indexer.wait_ready(Duration::from_secs(30)).unwrap();
    let result = semantic_search(
        &snapshot,
        &indexer,
        SemanticSearchParams {
            query: "greet a user by name".to_string(),
            k: usize::MAX,
        },
    )
    .expect("oversized k is clamped before internal candidate math");
    assert_eq!(result.vector_ranked.len(), 1);
    indexer.close();
}
