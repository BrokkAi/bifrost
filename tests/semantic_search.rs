//! End-to-end semantic_search pipeline test with deterministic fake engines:
//! index build -> vector scan -> co-edit blend -> grounded bm25 -> rerank.
#![cfg(feature = "nlp")]

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use brokk_bifrost::nlp::engine::FakeHashEmbedder;
use brokk_bifrost::nlp::indexer::{FakeEngineProvider, SemanticIndexer};
use brokk_bifrost::nlp::query::{SemanticSearchParams, semantic_search};
use brokk_bifrost::{AnalyzerConfig, FilesystemProject, Project, WorkspaceAnalyzer};

fn write_java(dir: &Path, name: &str, body: &str) {
    std::fs::write(dir.join(name), body).unwrap();
}

fn snapshot_for(root: &Path) -> Arc<WorkspaceAnalyzer> {
    let project: Arc<dyn Project> = Arc::new(FilesystemProject::new(root.to_path_buf()).unwrap());
    Arc::new(WorkspaceAnalyzer::build(project, AnalyzerConfig::default()))
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
