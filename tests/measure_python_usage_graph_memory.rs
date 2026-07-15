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

#[path = "common/memory_benchmark.rs"]
mod memory_benchmark;

use memory_benchmark::{
    GeneratedFixtureExpectations, benchmark_module_count, run_usage_graph_peak_rss_benchmark,
};
use std::fs;
use std::path::Path;

/// File count, sized so the retained syntax trees are a visible fraction of process RSS.
const MODULE_COUNT: usize = 2000;

/// Write a Python workspace with enough per-file content that the syntax trees are
/// substantial. Every module imports a shared `render` function (so `usage_graph` resolves real
/// cross-file edges) and defines a class with several methods.
fn generate_large_python_workspace(root: &Path, module_count: usize) {
    let mut widget_source = String::new();
    for module in 0..module_count {
        widget_source.push_str(&format!(
            "def render_{module:05}() -> str:\n    return \"widget\"\n\n"
        ));
    }
    fs::write(root.join("widget.py"), widget_source).expect("write widget.py");

    for module in 0..module_count {
        let mut source =
            format!("from widget import render_{module:05}\n\n\nclass Mod{module:05}:\n");
        for method in 0..6 {
            source.push_str(&format!(
                "    def method{method}(self, value: int) -> str:\n\
                 \x20       total = value + {method}\n\
                 \x20       return render_{module:05}() + str(total)\n\n"
            ));
        }
        fs::write(root.join(format!("mod_{module:05}.py")), source).expect("write module");
    }
}

#[test]
#[ignore = "measure-first memory benchmark; run explicitly with --ignored --nocapture"]
fn python_usage_graph_peak_rss() {
    let module_count = benchmark_module_count(MODULE_COUNT);
    run_usage_graph_peak_rss_benchmark(
        "Python",
        module_count,
        GeneratedFixtureExpectations {
            minimum_nodes: module_count,
            minimum_edges: module_count,
            expected_edge_suffixes: ("Mod00000.method0", "widget.render_00000"),
        },
        |root| generate_large_python_workspace(root, module_count),
    );
}
