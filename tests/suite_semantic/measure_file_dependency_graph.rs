//! Reproducible file-dependency benchmark for issue #748.
//!
//! The generated Java workspace has one hub imported by every node plus a
//! configurable ring fanout. That makes both reverse RQL traversal and the
//! seed-induced import PageRank graph exercise the full workspace.

use brokk_bifrost::analyzer::structural::{CodeQuery, execute};
use brokk_bifrost::searchtools::{MostRelevantFilesParams, most_relevant_files};
use brokk_bifrost::{AnalyzerConfig, Language, Project, TestProject, WorkspaceAnalyzer};
use serde::Serialize;
use serde_json::json;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::Instant;
use tempfile::TempDir;

const FILE_COUNT_ENV: &str = "BIFROST_FILE_GRAPH_BENCH_FILES";
const FANOUT_ENV: &str = "BIFROST_FILE_GRAPH_BENCH_FANOUT";
const ITERATIONS_ENV: &str = "BIFROST_FILE_GRAPH_BENCH_ITERATIONS";
const DEFAULT_FILE_COUNT: usize = 800;
const DEFAULT_FANOUT: usize = 4;
const DEFAULT_ITERATIONS: usize = 7;

#[derive(Serialize)]
struct FileDependencyBenchmarkResult {
    format: &'static str,
    bifrost_commit: Option<String>,
    files: usize,
    edges: usize,
    fanout: usize,
    iterations: usize,
    analyzer_build_ms: f64,
    relevance_first_ms: f64,
    relevance_warm_median_ms: f64,
    relevance_results: usize,
    importers_first_ms: f64,
    importers_warm_median_ms: f64,
    importers_results: usize,
    peak_rss_start_bytes: u64,
    peak_rss_after_analyzer_bytes: u64,
    peak_rss_after_relevance_bytes: u64,
    peak_rss_after_importers_bytes: u64,
}

#[cfg(unix)]
fn peak_rss_bytes() -> u64 {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    assert_eq!(rc, 0, "getrusage failed");
    let maxrss = usage.ru_maxrss.max(0) as u64;
    if cfg!(target_os = "macos") {
        maxrss
    } else {
        maxrss * 1024
    }
}

#[cfg(not(unix))]
fn peak_rss_bytes() -> u64 {
    0
}

fn positive_env(name: &str, default: usize, maximum: usize) -> usize {
    match std::env::var(name) {
        Ok(raw) => {
            let value = raw
                .trim()
                .parse::<usize>()
                .unwrap_or_else(|_| panic!("{name} must be a positive integer, got `{raw}`"));
            assert!(
                (1..=maximum).contains(&value),
                "{name} must be between 1 and {maximum}, got {value}"
            );
            value
        }
        Err(_) => default,
    }
}

fn workspace_commit(root: &Path) -> Option<String> {
    Command::new("git")
        .current_dir(root)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|commit| commit.trim().to_owned())
}

fn generate_workspace(root: &Path, file_count: usize, fanout: usize) {
    let package = root.join("bench");
    fs::create_dir(&package).expect("create dependency benchmark package");
    let mut hub = String::from("package bench;\n");
    for file in 0..file_count {
        hub.push_str(&format!("import bench.Node{file:04};\n"));
    }
    hub.push_str("public class Hub {\n");
    for file in 0..file_count {
        hub.push_str(&format!("    Node{file:04} node{file:04};\n"));
    }
    hub.push_str("}\n");
    fs::write(package.join("Hub.java"), hub).expect("write dependency hub");

    for file in 0..file_count {
        let mut source = String::from("package bench;\nimport bench.Hub;\n");
        for offset in 1..=fanout {
            let target = (file + offset) % file_count;
            source.push_str(&format!("import bench.Node{target:04};\n"));
        }
        source.push_str(&format!("public class Node{file:04} {{\n    Hub hub;\n"));
        for offset in 1..=fanout {
            let target = (file + offset) % file_count;
            source.push_str(&format!("    Node{target:04} next{offset};\n"));
        }
        source.push_str("}\n");
        fs::write(package.join(format!("Node{file:04}.java")), source)
            .expect("write dependency node");
    }
}

fn median(values: &mut [f64]) -> f64 {
    values.sort_by(f64::total_cmp);
    let middle = values.len() / 2;
    if values.len().is_multiple_of(2) {
        (values[middle - 1] + values[middle]) / 2.0
    } else {
        values[middle]
    }
}

#[test]
#[ignore = "measure-first file dependency benchmark; run explicitly with --ignored --nocapture"]
fn file_dependency_memory_and_reads() {
    let file_count = positive_env(FILE_COUNT_ENV, DEFAULT_FILE_COUNT, 999);
    let fanout = positive_env(FANOUT_ENV, DEFAULT_FANOUT, 32).min(file_count);
    let iterations = positive_env(ITERATIONS_ENV, DEFAULT_ITERATIONS, 50);
    let temp = TempDir::new().expect("file dependency benchmark temp dir");
    generate_workspace(temp.path(), file_count, fanout);

    let rss_start = peak_rss_bytes();
    let project: Arc<dyn Project> =
        Arc::new(TestProject::new(temp.path().to_path_buf(), Language::Java));
    let analyzer_started = Instant::now();
    let workspace = WorkspaceAnalyzer::build(
        project,
        AnalyzerConfig {
            parallelism: Some(1),
            memo_cache_budget_bytes: Some(2 * 1024 * 1024 * 1024),
            ..AnalyzerConfig::default()
        },
    );
    let analyzer_build_ms = analyzer_started.elapsed().as_secs_f64() * 1_000.0;
    let rss_after_analyzer = peak_rss_bytes();
    let analyzer = workspace.analyzer();

    let relevance_params = MostRelevantFilesParams {
        seed_file_paths: vec!["bench/Hub.java".to_owned()],
        seed_weights: None,
        recency_half_life: None,
        ranking_mode: Default::default(),
        limit: file_count,
    };
    let relevance_started = Instant::now();
    let first_relevance = most_relevant_files(analyzer, relevance_params.clone())
        .expect("rank generated file dependencies");
    let relevance_first_ms = relevance_started.elapsed().as_secs_f64() * 1_000.0;
    assert!(first_relevance.not_found.is_empty());
    assert_eq!(first_relevance.files.len(), file_count);

    let mut relevance_times = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let started = Instant::now();
        let result = most_relevant_files(analyzer, relevance_params.clone())
            .expect("rerank generated file dependencies");
        relevance_times.push(started.elapsed().as_secs_f64() * 1_000.0);
        assert_eq!(result.files.len(), file_count);
        std::hint::black_box(result);
    }
    let relevance_warm_median_ms = median(&mut relevance_times);
    let rss_after_relevance = peak_rss_bytes();

    let importers_query = CodeQuery::from_json(&json!({
        "match": { "kind": "class", "name": "Hub" },
        "steps": [{ "op": "file_of" }, { "op": "importers_of" }],
        "limit": file_count
    }))
    .expect("file dependency query should parse");
    let importers_started = Instant::now();
    let first_importers = execute(analyzer, &importers_query);
    let importers_first_ms = importers_started.elapsed().as_secs_f64() * 1_000.0;
    assert!(
        !first_importers.truncated,
        "{:#?}",
        first_importers.diagnostics
    );
    assert_eq!(first_importers.results.len(), file_count);

    let mut importer_times = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let started = Instant::now();
        let result = execute(analyzer, &importers_query);
        importer_times.push(started.elapsed().as_secs_f64() * 1_000.0);
        assert_eq!(result.results.len(), file_count);
        std::hint::black_box(result);
    }
    let importers_warm_median_ms = median(&mut importer_times);
    let rss_after_importers = peak_rss_bytes();

    let result = FileDependencyBenchmarkResult {
        format: "bifrost_file_dependency_benchmark/v1",
        bifrost_commit: workspace_commit(Path::new(env!("CARGO_MANIFEST_DIR"))),
        files: file_count + 1,
        edges: file_count * (fanout + 2),
        fanout,
        iterations,
        analyzer_build_ms,
        relevance_first_ms,
        relevance_warm_median_ms,
        relevance_results: first_relevance.files.len(),
        importers_first_ms,
        importers_warm_median_ms,
        importers_results: first_importers.results.len(),
        peak_rss_start_bytes: rss_start,
        peak_rss_after_analyzer_bytes: rss_after_analyzer,
        peak_rss_after_relevance_bytes: rss_after_relevance,
        peak_rss_after_importers_bytes: rss_after_importers,
    };
    eprintln!(
        "BIFROST_FILE_DEPENDENCY_BENCHMARK={}",
        serde_json::to_string(&result).expect("serialize file dependency benchmark")
    );
}
