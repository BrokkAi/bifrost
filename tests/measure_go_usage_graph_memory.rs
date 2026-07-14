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

#[path = "common/memory_benchmark.rs"]
mod memory_benchmark;

use memory_benchmark::{GeneratedFixtureExpectations, run_usage_graph_peak_rss_benchmark};
use std::fs;
use std::path::Path;

/// File count, sized so the retained syntax trees are a visible fraction of process RSS.
const MODULE_COUNT: usize = 2000;

/// Write a Go workspace with enough per-file content that the syntax trees are
/// substantial. Every module imports a shared `sub` package (so `usage_graph` resolves
/// real cross-file edges) and defines several functions.
fn generate_large_go_workspace(root: &Path, module_count: usize) {
    fs::write(root.join("go.mod"), "module example.com/bench\n\ngo 1.21\n").expect("write go.mod");

    let sub_dir = root.join("sub");
    fs::create_dir_all(&sub_dir).expect("create sub dir");
    let mut sub_source = String::from("package sub\n\n");
    for module in 0..module_count {
        sub_source.push_str(&format!(
            "func Helper{module:05}() string {{\n\treturn \"helper\"\n}}\n\n"
        ));
    }
    fs::write(sub_dir.join("sub.go"), sub_source).expect("write sub.go");

    for module in 0..module_count {
        let module_dir = root.join(format!("mod_{module:05}"));
        fs::create_dir_all(&module_dir).expect("create module dir");
        let mut source = format!("package mod_{module:05}\n\nimport \"example.com/bench/sub\"\n\n");
        for method in 0..6 {
            source.push_str(&format!(
                "func Mod{module:05}Method{method}(value int) string {{\n\
                 \t_ = value + {method}\n\
                 \treturn sub.Helper{module:05}()\n\
                 }}\n\n"
            ));
        }
        fs::write(module_dir.join("mod.go"), source).expect("write module");
    }
}

#[test]
#[ignore = "measure-first memory benchmark; run explicitly with --ignored --nocapture"]
fn go_usage_graph_peak_rss() {
    run_usage_graph_peak_rss_benchmark(
        "Go",
        GeneratedFixtureExpectations {
            minimum_nodes: MODULE_COUNT,
            minimum_edges: MODULE_COUNT,
            expected_edge_suffixes: ("Mod00000Method0", "sub.Helper00000"),
        },
        |root| generate_large_go_workspace(root, MODULE_COUNT),
    );
}
