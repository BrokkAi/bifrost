//! Real-model smoke test for semantic_search.
//!
//! Ignored by default: it downloads the granite embedding model from HuggingFace
//! (or honors BIFROST_EMBED_MODEL_DIR) and runs real ONNX inference. Run with:
//!
//! ```bash
//! BIFROST_NLP_MODEL_TESTS=1 cargo test --test nlp_semantic_search_models -- --ignored
//! ```
#![cfg(feature = "nlp")]

use std::path::Path;
use std::sync::Arc;

use brokk_bifrost::nlp::indexer::{DEFAULT_READY_TIMEOUT, SemanticIndexer};
use brokk_bifrost::nlp::query::{SemanticSearchParams, semantic_search};
use brokk_bifrost::{AnalyzerConfig, FilesystemProject, Project, WorkspaceAnalyzer};
use git2::{IndexAddOption, Repository, Signature};

fn write_java(dir: &Path, name: &str, body: &str) {
    std::fs::write(dir.join(name), body).unwrap();
}

#[test]
#[ignore = "downloads and runs the real embedding model"]
fn semantic_search_with_real_models_ranks_expected_file() {
    if std::env::var("BIFROST_NLP_MODEL_TESTS").as_deref() != Ok("1") {
        eprintln!("BIFROST_NLP_MODEL_TESTS != 1; skipping real-model smoke test");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    write_java(
        dir.path(),
        "ConfigLoader.java",
        r#"import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

public class ConfigLoader {
    /** Reads the application settings file from disk at startup. */
    public Properties loadSettings(Path settingsFile) throws Exception {
        Properties properties = new Properties();
        try (var stream = Files.newInputStream(settingsFile)) {
            properties.load(stream);
        }
        return properties;
    }
}
"#,
    );
    write_java(
        dir.path(),
        "HttpFetcher.java",
        r#"import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class HttpFetcher {
    /** Downloads the body of a remote URL with retries. */
    public String fetch(String url) throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder(URI.create(url)).build();
        return client.send(request, HttpResponse.BodyHandlers.ofString()).body();
    }
}
"#,
    );
    write_java(
        dir.path(),
        "MathUtils.java",
        r#"public class MathUtils {
    /** Computes the greatest common divisor of two integers. */
    public static int gcd(int a, int b) {
        while (b != 0) {
            int temp = b;
            b = a % b;
            a = temp;
        }
        return a;
    }
}
"#,
    );

    let repo = Repository::init(dir.path()).unwrap();
    let mut index = repo.index().unwrap();
    index.add_all(["*"], IndexAddOption::DEFAULT, None).unwrap();
    index.write().unwrap();
    let tree_oid = index.write_tree().unwrap();
    let tree = repo.find_tree(tree_oid).unwrap();
    let signature = Signature::now("Bifrost model smoke", "bifrost@example.invalid").unwrap();
    repo.commit(Some("HEAD"), &signature, &signature, "fixture", &tree, &[])
        .unwrap();

    let project: Arc<dyn Project> =
        Arc::new(FilesystemProject::new(dir.path().to_path_buf()).unwrap());
    let snapshot = Arc::new(WorkspaceAnalyzer::build(project, AnalyzerConfig::default()));
    let indexer = SemanticIndexer::start(dir.path().to_path_buf(), snapshot.clone());
    indexer.wait_ready(DEFAULT_READY_TIMEOUT).unwrap();

    let result = semantic_search(
        &snapshot,
        &indexer,
        SemanticSearchParams {
            query: "where are application settings read from disk during startup".to_string(),
            k: 2,
        },
    )
    .expect("semantic_search with real models");

    assert!(
        result.notes.is_empty(),
        "expected no degraded-mode notes: {:?}",
        result.notes
    );
    assert_eq!(result.retrieval_profile, "all-signals");
    assert_eq!(result.requested_leg_counts.vector, 2);
    assert_eq!(result.requested_leg_counts.bm25, 2);
    assert_eq!(result.requested_leg_counts.coedit, 2);
    assert!(result.timings.embedding_service_ms > 0.0);
    assert!(result.timings.total_ms >= result.timings.embedding_service_ms);
    // The dense retriever should rank the settings-reading function first by fqfn.
    assert!(
        result
            .vector_ranked
            .first()
            .is_some_and(|row| row.fqfn.contains("loadSettings")),
        "vector_ranked: {:?}",
        result
            .vector_ranked
            .iter()
            .map(|row| (&row.fqfn, row.score))
            .collect::<Vec<_>>()
    );
    indexer.close();
}
