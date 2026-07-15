//! Reproducible weighted usage-relevance graph benchmark for issue #748.
//!
//! This complements the public `usage_graph` RSS harnesses by exercising the
//! exact `WorkspaceUsageGraph` representation consumed by PageRank.

use brokk_bifrost::searchtools::{
    MostRelevantFilesParams, MostRelevantFilesRankingMode, most_relevant_files,
};
use brokk_bifrost::{AnalyzerConfig, Language, Project, TestProject, WorkspaceAnalyzer};
use serde::Serialize;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::Instant;
use tempfile::TempDir;

const MODULE_COUNT_ENV: &str = "BIFROST_USAGE_RELEVANCE_BENCH_MODULES";
const ITERATIONS_ENV: &str = "BIFROST_USAGE_RELEVANCE_BENCH_ITERATIONS";
const DEFAULT_MODULE_COUNT: usize = 500;
const DEFAULT_ITERATIONS: usize = 5;

#[derive(Serialize)]
struct UsageRelevanceBenchmarkResult {
    format: &'static str,
    bifrost_commit: Option<String>,
    modules: usize,
    expected_minimum_nodes: usize,
    expected_edges: usize,
    iterations: usize,
    analyzer_build_ms: f64,
    ranking_first_ms: f64,
    ranking_warm_median_ms: f64,
    ranking_results: usize,
    first_result: String,
    peak_rss_start_bytes: u64,
    peak_rss_after_analyzer_bytes: u64,
    peak_rss_after_first_ranking_bytes: u64,
    peak_rss_after_warm_ranking_bytes: u64,
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

fn generate_workspace(root: &Path, module_count: usize) {
    fs::write(root.join("go.mod"), "module example.com/bench\n\ngo 1.21\n")
        .expect("write usage relevance go.mod");
    let sub_dir = root.join("sub");
    fs::create_dir_all(&sub_dir).expect("create usage relevance helper package");
    let mut sub_source = String::from("package sub\n\n");
    for module in 0..module_count {
        sub_source.push_str(&format!(
            "func Helper{module:05}() string {{\n\treturn \"helper\"\n}}\n\n"
        ));
    }
    fs::write(sub_dir.join("sub.go"), sub_source).expect("write usage relevance helpers");

    for module in 0..module_count {
        let module_dir = root.join(format!("mod_{module:05}"));
        fs::create_dir_all(&module_dir).expect("create usage relevance module");
        let mut source = format!("package mod_{module:05}\n\nimport \"example.com/bench/sub\"\n\n");
        for method in 0..6 {
            source.push_str(&format!(
                "func Mod{module:05}Method{method}(value int) string {{\n\
                 \t_ = value + {method}\n\
                 \treturn sub.Helper{module:05}()\n\
                 }}\n\n"
            ));
        }
        fs::write(module_dir.join("mod.go"), source).expect("write usage relevance module");
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
#[ignore = "measure-first usage relevance benchmark; run explicitly with --ignored --nocapture"]
fn usage_relevance_memory_and_reads() {
    let module_count = positive_env(MODULE_COUNT_ENV, DEFAULT_MODULE_COUNT, 2_000);
    let iterations = positive_env(ITERATIONS_ENV, DEFAULT_ITERATIONS, 20);
    let temp = TempDir::new().expect("usage relevance benchmark temp dir");
    generate_workspace(temp.path(), module_count);

    let rss_start = peak_rss_bytes();
    let project: Arc<dyn Project> =
        Arc::new(TestProject::new(temp.path().to_path_buf(), Language::Go));
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
    let params = MostRelevantFilesParams {
        seed_file_paths: vec!["mod_00000/mod.go".to_owned()],
        seed_weights: None,
        recency_half_life: None,
        ranking_mode: MostRelevantFilesRankingMode::UsageGraph,
        limit: 10,
    };

    let first_started = Instant::now();
    let first = most_relevant_files(analyzer, params.clone())
        .expect("rank generated usage relevance graph");
    let ranking_first_ms = first_started.elapsed().as_secs_f64() * 1_000.0;
    assert!(first.not_found.is_empty());
    assert!(!first.files.is_empty());
    assert_eq!(first.files[0], "sub/sub.go");
    let rss_after_first_ranking = peak_rss_bytes();

    let mut warm_times = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let started = Instant::now();
        let result = most_relevant_files(analyzer, params.clone())
            .expect("rerank generated usage relevance graph");
        warm_times.push(started.elapsed().as_secs_f64() * 1_000.0);
        assert_eq!(result.files, first.files);
        std::hint::black_box(result);
    }
    let ranking_warm_median_ms = median(&mut warm_times);
    let rss_after_warm_ranking = peak_rss_bytes();

    let result = UsageRelevanceBenchmarkResult {
        format: "bifrost_usage_relevance_benchmark/v1",
        bifrost_commit: workspace_commit(Path::new(env!("CARGO_MANIFEST_DIR"))),
        modules: module_count,
        expected_minimum_nodes: module_count * 7,
        expected_edges: module_count * 6,
        iterations,
        analyzer_build_ms,
        ranking_first_ms,
        ranking_warm_median_ms,
        ranking_results: first.files.len(),
        first_result: first.files[0].clone(),
        peak_rss_start_bytes: rss_start,
        peak_rss_after_analyzer_bytes: rss_after_analyzer,
        peak_rss_after_first_ranking_bytes: rss_after_first_ranking,
        peak_rss_after_warm_ranking_bytes: rss_after_warm_ranking,
    };
    eprintln!(
        "BIFROST_USAGE_RELEVANCE_BENCHMARK={}",
        serde_json::to_string(&result).expect("serialize usage relevance benchmark")
    );
}
