use brokk_bifrost::SearchToolsService;
use serde_json::Value;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

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

/// Run the shared `usage_graph` peak-RSS benchmark harness.
///
/// Point at a real checkout with `BIFROST_BENCH_REPO=/path/to/repo`; otherwise
/// `generate_fixture` builds a synthetic workspace in a temp directory.
pub fn run_usage_graph_peak_rss_benchmark(label: &str, generate_fixture: impl FnOnce(&Path)) {
    let (root, _temp): (PathBuf, Option<TempDir>) = match std::env::var("BIFROST_BENCH_REPO") {
        Ok(p) => (PathBuf::from(p), None),
        Err(_) => {
            let temp = TempDir::new().expect("temp dir");
            let root = temp.path().to_path_buf();
            generate_fixture(&root);
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

    eprintln!("\n=== {label} usage_graph peak RSS ===");
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
