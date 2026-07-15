#[path = "usage_graph.rs"]
mod usage_graph;

use brokk_bifrost::SearchToolsService;
use serde::Serialize;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;
use tempfile::TempDir;

const MODULE_COUNT_ENV: &str = "BIFROST_BENCH_MODULE_COUNT";

/// Process peak resident set size in bytes (`getrusage(RUSAGE_SELF).ru_maxrss`).
/// macOS reports bytes; Linux reports kilobytes.
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

/// `getrusage` is Unix-only; this measure-first benchmark is run on macOS/Linux. The
/// stub keeps the file compiling on Windows, where the `#[ignore]`d test never runs.
#[cfg(not(unix))]
fn peak_rss_bytes() -> u64 {
    0
}

fn mb(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

/// Semantic expectations for a generated benchmark workspace.
///
/// These are deliberately not applied to `BIFROST_BENCH_REPO`, whose contents
/// are chosen by the caller and therefore cannot have fixture-specific bounds.
pub struct GeneratedFixtureExpectations {
    pub minimum_nodes: usize,
    pub minimum_edges: usize,
    pub expected_edge_suffixes: (&'static str, &'static str),
}

/// Read the generated fixture's module count from `BIFROST_BENCH_MODULE_COUNT`.
///
/// Leaving the variable unset preserves the benchmark's historical default. A
/// positive integer makes repeatable scale sweeps possible without changing
/// source, for example `BIFROST_BENCH_MODULE_COUNT=500`.
pub fn benchmark_module_count(default: usize) -> usize {
    let count = match std::env::var(MODULE_COUNT_ENV) {
        Ok(value) => value.parse::<usize>().unwrap_or_else(|_| {
            panic!("{MODULE_COUNT_ENV} must be a positive integer, got {value:?}")
        }),
        Err(std::env::VarError::NotPresent) => default,
        Err(error) => panic!("failed to read {MODULE_COUNT_ENV}: {error}"),
    };
    assert!(count > 0, "{MODULE_COUNT_ENV} must be a positive integer");
    count
}

#[derive(Serialize)]
struct UsageGraphBenchmarkResult<'a> {
    format: &'static str,
    label: &'a str,
    fixture: &'static str,
    workspace: String,
    commit: Option<String>,
    module_count: Option<usize>,
    service_build_ms: f64,
    usage_graph_ms: f64,
    nodes: usize,
    edges: usize,
    total_call_site_weight: u64,
    payload_bytes: usize,
    peak_rss_start_bytes: u64,
    peak_rss_after_service_bytes: u64,
    peak_rss_after_usage_graph_bytes: u64,
}

fn workspace_commit(root: &Path) -> Option<String> {
    Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|commit| commit.trim().to_owned())
}

/// Run the shared `usage_graph` peak-RSS benchmark harness.
///
/// Point at a real checkout with `BIFROST_BENCH_REPO=/path/to/repo`; otherwise
/// `generate_fixture` builds a synthetic workspace in a temp directory.
pub fn run_usage_graph_peak_rss_benchmark(
    label: &str,
    generated_module_count: usize,
    generated_fixture_expectations: GeneratedFixtureExpectations,
    generate_fixture: impl FnOnce(&Path),
) {
    let (root, _temp, is_generated_fixture): (PathBuf, Option<TempDir>, bool) =
        match std::env::var("BIFROST_BENCH_REPO") {
            Ok(p) => (PathBuf::from(p), None, false),
            Err(_) => {
                let temp = TempDir::new().expect("temp dir");
                let root = temp.path().to_path_buf();
                generate_fixture(&root);
                (root, Some(temp), true)
            }
        };
    eprintln!("workspace: {}", root.display());

    let rss_start = peak_rss_bytes();
    let service_started = Instant::now();
    let service = SearchToolsService::new_without_semantic_index(root.clone())
        .expect("failed to build searchtools service");
    let service_build_ms = service_started.elapsed().as_secs_f64() * 1000.0;
    let rss_after_build = peak_rss_bytes();

    let graph_started = Instant::now();
    let payload = service
        .call_tool_json("usage_graph", "{}")
        .expect("usage_graph call failed");
    let usage_graph_ms = graph_started.elapsed().as_secs_f64() * 1000.0;
    let rss_after_graph = peak_rss_bytes();

    let graph: Value = serde_json::from_str(&payload).expect("usage_graph returned invalid JSON");
    let node_count = graph["nodes"].as_array().map(|a| a.len()).unwrap_or(0);
    let edges = graph["edges"]
        .as_array()
        .expect("usage_graph result must contain an edges array");
    let edge_count = edges.len();
    let total_call_site_weight = edges
        .iter()
        .map(|edge| {
            edge["weight"]
                .as_u64()
                .expect("usage_graph edge must contain a non-negative integer weight")
        })
        .sum::<u64>();
    // The whole-workspace build is what we are measuring; it ran iff the graph has nodes.
    assert!(
        node_count > 0,
        "usage_graph should resolve nodes across the workspace"
    );
    if is_generated_fixture {
        assert!(
            node_count >= generated_fixture_expectations.minimum_nodes,
            "generated {label} fixture should resolve at least {} nodes, found {node_count}",
            generated_fixture_expectations.minimum_nodes
        );
        assert!(
            edge_count >= generated_fixture_expectations.minimum_edges,
            "generated {label} fixture should resolve at least {} edges, found {edge_count}",
            generated_fixture_expectations.minimum_edges
        );
        let (from_suffix, to_suffix) = generated_fixture_expectations.expected_edge_suffixes;
        let has_expected_edge = usage_graph::find_edge(&graph, from_suffix, to_suffix).is_some();
        assert!(
            has_expected_edge,
            "generated {label} fixture should contain a cross-file edge ending in {from_suffix} -> {to_suffix}; found {edge_count} edges"
        );
    }

    let commit = workspace_commit(&root);
    let fixture = if is_generated_fixture {
        "generated"
    } else {
        "repository"
    };
    eprintln!("\n=== {label} usage_graph benchmark ===");
    eprintln!("fixture: {}", fixture);
    eprintln!("workspace: {}", root.display());
    eprintln!("commit: {}", commit.as_deref().unwrap_or("unavailable"));
    if is_generated_fixture {
        eprintln!("module count: {generated_module_count}");
    }
    eprintln!(
        "nodes: {node_count}, edges: {edge_count}, total call-site weight: {total_call_site_weight}"
    );
    eprintln!("serialized payload: {} bytes", payload.len());
    eprintln!("service build: {:.1} ms", service_build_ms);
    eprintln!("usage_graph: {:.1} ms", usage_graph_ms);
    eprintln!("peak RSS at start:            {:.1} MB", mb(rss_start));
    eprintln!(
        "peak RSS after service build: {:.1} MB",
        mb(rss_after_build)
    );
    eprintln!(
        "peak RSS after usage_graph:   {:.1} MB",
        mb(rss_after_graph)
    );
    eprintln!(
        "usage_graph peak growth:      {:.1} MB\n",
        mb(rss_after_graph.saturating_sub(rss_after_build))
    );
    let result = UsageGraphBenchmarkResult {
        format: "bifrost_usage_graph_benchmark/v1",
        label,
        fixture,
        workspace: root.display().to_string(),
        commit,
        module_count: is_generated_fixture.then_some(generated_module_count),
        service_build_ms,
        usage_graph_ms,
        nodes: node_count,
        edges: edge_count,
        total_call_site_weight,
        payload_bytes: payload.len(),
        peak_rss_start_bytes: rss_start,
        peak_rss_after_service_bytes: rss_after_build,
        peak_rss_after_usage_graph_bytes: rss_after_graph,
    };
    eprintln!(
        "BIFROST_USAGE_GRAPH_BENCHMARK={}",
        serde_json::to_string(&result).expect("serialize benchmark result")
    );
}
