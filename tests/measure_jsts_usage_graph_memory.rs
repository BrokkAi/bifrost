//! Measure-first peak-RSS benchmark for the JS/TS `usage_graph` build (issue #200, TS slice).
//!
//! The whole-workspace inverted edge build (`build_jsts_edges` / `build_jsts_scoped_edges`)
//! parses each file on demand and drops its syntax tree, so peak memory is bounded by the
//! worker count rather than the repo size. This benchmark builds a sizeable TypeScript
//! workspace, runs a full `usage_graph`, and reports process peak RSS (`getrusage`) — it
//! guards against a regression back to whole-workspace tree retention.
//!
//! Ignored by default (large fixture, several seconds). Run:
//!   cargo test --test measure_jsts_usage_graph_memory -- --ignored --nocapture

mod common;

use common::memory_benchmark::run_usage_graph_peak_rss_benchmark;
use std::fs;
use std::path::Path;

/// File count, sized so the retained syntax trees are a visible fraction of process RSS.
const MODULE_COUNT: usize = 2000;

/// Write a TypeScript workspace with enough per-file content that the syntax trees are
/// substantial. Every module imports a shared `Widget` (so `usage_graph` resolves real
/// cross-file edges) and defines a class with several methods.
fn generate_large_ts_workspace(root: &Path, module_count: usize) {
    let core_dir = root.join("core");
    fs::create_dir_all(&core_dir).expect("create core dir");
    fs::write(
        core_dir.join("widget.ts"),
        "export class Widget {\n    render(): string {\n        return \"widget\";\n    }\n}\n",
    )
    .expect("write widget.ts");
    fs::write(
        root.join("index.ts"),
        "export { Widget } from \"./core/widget\";\n",
    )
    .expect("write index.ts");

    for module in 0..module_count {
        let mut source =
            format!("import {{ Widget }} from \"./index\";\n\nexport class Mod{module:05} {{\n");
        for method in 0..6 {
            source.push_str(&format!(
                "    method{method}(input: number): string {{\n\
                 \x20       const widget = new Widget();\n\
                 \x20       const total = input + {method};\n\
                 \x20       return widget.render() + total.toString();\n\
                 \x20   }}\n"
            ));
        }
        source.push_str("}\n");
        fs::write(root.join(format!("mod_{module:05}.ts")), source).expect("write module");
    }
}

#[test]
#[ignore = "measure-first memory benchmark; run explicitly with --ignored --nocapture"]
fn jsts_usage_graph_peak_rss() {
    run_usage_graph_peak_rss_benchmark("JS/TS", |root| {
        generate_large_ts_workspace(root, MODULE_COUNT);
    });
}
