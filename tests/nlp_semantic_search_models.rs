//! Real-model smoke test for semantic_search.
//!
//! Ignored by default: it downloads the granite embedding model and the gte
//! reranker from HuggingFace (or honors BIFROST_EMBED_MODEL_DIR /
//! BIFROST_RERANK_MODEL_DIR) and runs real ONNX inference. Run with:
//!
//! ```bash
//! BIFROST_NLP_MODEL_TESTS=1 cargo test --test nlp_semantic_search_models -- --ignored
//! ```
#![cfg(feature = "nlp")]

use std::path::Path;
use std::sync::Arc;

use brokk_bifrost::nlp::indexer::SemanticIndexer;
use brokk_bifrost::nlp::query::{SemanticSearchParams, semantic_search};
use brokk_bifrost::{AnalyzerConfig, FilesystemProject, Project, WorkspaceAnalyzer};

fn write_java(dir: &Path, name: &str, body: &str) {
    std::fs::write(dir.join(name), body).unwrap();
}

#[test]
#[ignore = "downloads and runs real embedding/reranking models"]
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

    let project: Arc<dyn Project> =
        Arc::new(FilesystemProject::new(dir.path().to_path_buf()).unwrap());
    let snapshot = Arc::new(WorkspaceAnalyzer::build(project, AnalyzerConfig::default()));
    let indexer = SemanticIndexer::start(dir.path().to_path_buf(), snapshot.clone());

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
    assert_eq!(
        result.hits.first().map(|hit| hit.path.as_str()),
        Some("ConfigLoader.java"),
        "hits: {:?}",
        result
            .hits
            .iter()
            .map(|hit| (&hit.path, hit.score))
            .collect::<Vec<_>>()
    );
    indexer.close();
}
