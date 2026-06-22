//! Measure-first peak-RSS benchmark for the Python `usage_graph` build (issue #200, Python slice).
//!
//! The whole-workspace inverted edge build (`build_python_edges`) parses each file on demand
//! and drops its syntax tree, so peak memory is bounded by the worker count rather than the
//! repo size. This benchmark builds a sizeable Python workspace, runs a full `usage_graph`,
//! and reports process peak RSS (`getrusage`) — it guards against a regression back to
//! whole-workspace tree retention.
//!
//! Ignored by default (large fixture, several seconds). Run:
//!   cargo test --test measure_python_usage_graph_memory -- --ignored --nocapture
//!
//! Point at a real checkout with BIFROST_BENCH_REPO=/path/to/repo for the figures in #200
//! (sentry ~2.1 GB, django ~0.75 GB before the cap).

use brokk_bifrost::SearchToolsService;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// File count, sized so the retained syntax trees are a visible fraction of process RSS.
const MODULE_COUNT: usize = 2000;

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

/// Write a Python workspace with enough per-file content that the syntax trees are
/// substantial. Every module imports a shared `Widget` (so `usage_graph` resolves real
/// cross-file edges) and defines a class with several methods.
fn generate_large_python_workspace(root: &Path, module_count: usize) {
    fs::write(
        root.join("widget.py"),
        "class Widget:\n    def render(self) -> str:\n        return \"widget\"\n",
    )
    .expect("write widget.py");

    for module in 0..module_count {
        let mut source = format!("from widget import Widget\n\n\nclass Mod{module:05}:\n");
        for method in 0..6 {
            source.push_str(&format!(
                "    def method{method}(self, value: int) -> str:\n\
                 \x20       widget = Widget()\n\
                 \x20       total = value + {method}\n\
                 \x20       return widget.render() + str(total)\n\n"
            ));
        }
        fs::write(root.join(format!("mod_{module:05}.py")), source).expect("write module");
    }
}

#[test]
#[ignore = "measure-first memory benchmark; run explicitly with --ignored --nocapture"]
fn python_usage_graph_peak_rss() {
    // Point at a real checkout with BIFROST_BENCH_REPO=/path/to/repo; otherwise synth.
    let (root, _temp) = match std::env::var("BIFROST_BENCH_REPO") {
        Ok(p) => (PathBuf::from(p), None),
        Err(_) => {
            let temp = TempDir::new().expect("temp dir");
            let root = temp.path().to_path_buf();
            generate_large_python_workspace(&root, MODULE_COUNT);
            (root, Some(temp))
        }
    };
    eprintln!("workspace: {}", root.display());

    let rss_start = peak_rss_bytes();
    let service = SearchToolsService::new_without_semantic_index(root)
        .expect("failed to build searchtools service");
    let rss_after_build = peak_rss_bytes();

    let payload = service
        .call_tool_json("usage_graph", "{}")
        .expect("usage_graph call failed");
    let rss_after_graph = peak_rss_bytes();

    let graph: Value = serde_json::from_str(&payload).expect("usage_graph returned invalid JSON");
    let node_count = graph["nodes"].as_array().map(|a| a.len()).unwrap_or(0);
    let edge_count = graph["edges"].as_array().map(|a| a.len()).unwrap_or(0);
    // The whole-workspace build is what we are measuring; it ran iff the graph has nodes.
    assert!(
        node_count > 0,
        "usage_graph should resolve nodes across the workspace"
    );

    eprintln!("\n=== Python usage_graph peak RSS ===");
    eprintln!("nodes: {node_count}, edges: {edge_count}");
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
}
