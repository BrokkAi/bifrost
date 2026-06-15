//! End-to-end semantic_search pipeline test with deterministic fake engines:
//! index build -> vector scan -> co-edit blend -> grounded bm25 -> rerank.
#![cfg(feature = "nlp")]

use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use brokk_bifrost::nlp::engine::{Embedder, FakeHashEmbedder, FakeOverlapReranker, Reranker};
use brokk_bifrost::nlp::indexer::{EngineProvider, FakeEngineProvider, SemanticIndexer};
use brokk_bifrost::nlp::query::{SemanticSearchParams, semantic_search};
use brokk_bifrost::{AnalyzerConfig, FilesystemProject, Project, WorkspaceAnalyzer};

fn write_java(dir: &Path, name: &str, body: &str) {
    std::fs::write(dir.join(name), body).unwrap();
}

fn snapshot_for(root: &Path) -> Arc<WorkspaceAnalyzer> {
    let project: Arc<dyn Project> = Arc::new(FilesystemProject::new(root.to_path_buf()).unwrap());
    Arc::new(WorkspaceAnalyzer::build(project, AnalyzerConfig::default()))
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

    fn reranker(&self) -> Result<Arc<dyn Reranker>, String> {
        Ok(Arc::new(FakeOverlapReranker))
    }
}

#[test]
fn semantic_search_returns_hits_with_summaries() {
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
            // "loadConfig" grounds against the repo symbol universe, so the
            // bm25 leg and the fake overlap reranker both favor ConfigLoader.
            query: "where does loadConfig read the configuration".to_string(),
            k: 2,
        },
    )
    .expect("semantic_search succeeds");

    assert!(!result.hits.is_empty());
    let config_hit = result
        .hits
        .iter()
        .find(|hit| hit.path == "ConfigLoader.java")
        .expect("ConfigLoader.java among hits");
    assert!(
        config_hit.summary.contains("class ConfigLoader"),
        "hit carries the file summary: {}",
        config_hit.summary
    );
    indexer.close();
}

#[test]
fn semantic_search_blocks_until_initial_build() {
    let dir = tempfile::tempdir().unwrap();
    write_java(
        dir.path(),
        "Greeter.java",
        "public class Greeter {\n  public String greet(String name) { return name; }\n}\n",
    );
    let snapshot = snapshot_for(dir.path());
    let embedder = Arc::new(FakeHashEmbedder::new(16));
    let indexer = SemanticIndexer::start_with_provider(
        dir.path().to_path_buf(),
        snapshot.clone(),
        FakeEngineProvider { embedder },
    );

    // Issued immediately after start: must not error with "still building".
    let result = semantic_search(
        &snapshot,
        &indexer,
        SemanticSearchParams {
            query: "greet a user by name".to_string(),
            k: 1,
        },
    )
    .expect("query issued during build waits for readiness");
    assert_eq!(result.hits.len(), 1);

    // And the indexer reports ready immediately afterwards.
    indexer.wait_ready(Duration::from_secs(1)).unwrap();
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

    assert!(result.hits.is_empty(), "no vectors have been committed yet");
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
    let snapshot = snapshot_for(dir.path());
    let embedder = Arc::new(FakeHashEmbedder::new(16));
    let indexer = SemanticIndexer::start_with_provider(
        dir.path().to_path_buf(),
        snapshot.clone(),
        FakeEngineProvider { embedder },
    );

    indexer.wait_ready(Duration::from_secs(30)).unwrap();
    let status = indexer.status(&snapshot);
    assert_eq!(status.indexed_files, 1);
    assert_eq!(status.waiting_files, 0);
    assert_eq!(status.pending_batches, 0);
    assert_eq!(status.phase, "ready");

    write_java(
        dir.path(),
        "Greeter.java",
        "public class Greeter {\n  public String greet(String name) { return \"hi\" + name; }\n}\n",
    );
    let status = indexer.status(&snapshot);
    assert_eq!(status.indexed_files, 0);
    assert_eq!(status.waiting_files, 1);
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
            query: "greet a user by name".to_string(),
            k: usize::MAX,
        },
    )
    .expect("oversized k is clamped before internal candidate math");
    assert_eq!(result.hits.len(), 1);
    indexer.close();
}
