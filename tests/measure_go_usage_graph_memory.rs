//! Measure-first peak-RSS benchmark for the Go `usage_graph` build (issue #200, Go slice).
//!
//! The whole-workspace inverted edge build (`build_go_edges`) parses each file on demand
//! and drops its syntax tree, resolving cross-file references from a tree-free index, so
//! peak memory is bounded by the worker count rather than the repo size. This benchmark
//! builds a sizeable Go workspace, runs a full `usage_graph`, and reports process peak RSS
//! (`getrusage`) — it guards against a regression back to whole-workspace tree retention.
//!
//! Ignored by default (large fixture, several seconds). Run:
//!   cargo test --test measure_go_usage_graph_memory -- --ignored --nocapture
//!
//! Point at a real checkout with BIFROST_BENCH_REPO=/path/to/repo.

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

/// Write a Go workspace with enough per-file content that the syntax trees are
/// substantial. Every module imports a shared `widget` package (so `usage_graph` resolves
/// real cross-file edges) and defines a struct with several methods.
fn generate_large_go_workspace(root: &Path, module_count: usize) {
    fs::write(root.join("go.mod"), "module example.com/bench\n\ngo 1.21\n").expect("write go.mod");

    let widget_dir = root.join("widget");
    fs::create_dir_all(&widget_dir).expect("create widget dir");
    fs::write(
        widget_dir.join("widget.go"),
        "package widget\n\ntype Widget struct{}\n\nfunc (w Widget) Render() string {\n\treturn \"widget\"\n}\n",
    )
    .expect("write widget.go");

    for module in 0..module_count {
        let mut source = format!(
            "package bench\n\nimport \"example.com/bench/widget\"\n\ntype Mod{module:05} struct{{}}\n\n"
        );
        for method in 0..6 {
            source.push_str(&format!(
                "func (m Mod{module:05}) Method{method}(value int) string {{\n\
                 \tw := widget.Widget{{}}\n\
                 \t_ = value + {method}\n\
                 \treturn w.Render()\n\
                 }}\n\n"
            ));
        }
        fs::write(root.join(format!("mod_{module:05}.go")), source).expect("write module");
    }
}

#[test]
#[ignore = "measure-first memory benchmark; run explicitly with --ignored --nocapture"]
fn go_usage_graph_peak_rss() {
    // Point at a real checkout with BIFROST_BENCH_REPO=/path/to/repo; otherwise synth.
    let (root, _temp) = match std::env::var("BIFROST_BENCH_REPO") {
        Ok(p) => (PathBuf::from(p), None),
        Err(_) => {
            let temp = TempDir::new().expect("temp dir");
            let root = temp.path().to_path_buf();
            generate_large_go_workspace(&root, MODULE_COUNT);
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

    eprintln!("\n=== Go usage_graph peak RSS ===");
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
