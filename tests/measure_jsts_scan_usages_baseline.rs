//! Measure-first benchmark for the JS/TS `scan_usages` repeated-query cost (issue #191).
//!
//! Without the analyzer-cached resolution index, each `scan_usages` query rebuilds the
//! whole-workspace resolution maps by re-parsing every JS/TS file. This benchmark sizes
//! that cost on a synthesized TypeScript workspace and reports it for two
//! symbol shapes:
//!
//! - **low fan-in** (`Niche`, used by one module): its candidate closure is tiny, so the
//!   per-query cost is dominated by the whole-workspace index rebuild — the exact work the
//!   cache eliminates. This is where the cache wins, and the common case for repeated
//!   `scan_usages` over a stable workspace.
//! - **high fan-in** (`Widget`, used by every module): its candidate closure is the whole
//!   workspace, so the scan re-parses everything regardless of the cache. Included as a
//!   no-regression check — the cache must not make the worst case slower.
//!
//! Ignored by default (it generates a large fixture and runs for several seconds). Run:
//!   cargo test --test measure_jsts_scan_usages_baseline -- --ignored --nocapture

use brokk_bifrost::SearchToolsService;
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::time::Instant;
use tempfile::TempDir;

/// Number of importer modules. Large enough that a whole-workspace re-parse is the
/// dominant cost (the thing the cache removes), not setup noise.
const MODULE_COUNT: usize = 400;
/// Warmup + measured query repetitions.
const WARMUP: usize = 1;
const MEASURED: usize = 5;

/// Write a TypeScript workspace with one high-fan-in symbol (`Widget`, re-exported through
/// a barrel and used by every module) and one low-fan-in symbol (`Niche`, used by a single
/// module).
fn generate_ts_workspace(root: &Path, module_count: usize) {
    let core_dir = root.join("core");
    fs::create_dir_all(&core_dir).expect("create core dir");

    fs::write(
        core_dir.join("widget.ts"),
        "export class Widget {\n    render(): string {\n        return \"widget\";\n    }\n}\n",
    )
    .expect("write widget.ts");

    // Low-fan-in symbol: its own file, imported by exactly one module below.
    fs::write(
        core_dir.join("niche.ts"),
        "export class Niche {\n    tag(): string {\n        return \"niche\";\n    }\n}\n",
    )
    .expect("write niche.ts");

    // Barrel re-export: importers depend on `./index`, not the concrete file, so the
    // resolver must follow the re-export edge from the barrel back to `core/widget.ts`.
    fs::write(
        root.join("index.ts"),
        "export { Widget } from \"./core/widget\";\n",
    )
    .expect("write index.ts");

    for module in 0..module_count {
        let mut source = format!(
            "import {{ Widget }} from \"./index\";\n\
             export function use{module:04}(): string {{\n\
             \x20   const widget = new Widget();\n\
             \x20   return widget.render();\n\
             }}\n"
        );
        // Exactly one module uses Niche, keeping its fan-in at 1.
        if module == 0 {
            source.push_str(
                "import { Niche } from \"./core/niche\";\n\
                 export function useNiche(): string {\n\
                 \x20   return new Niche().tag();\n\
                 }\n",
            );
        }
        fs::write(root.join(format!("mod_{module:04}.ts")), source).expect("write module");
    }
}

fn scan_symbol(service: &SearchToolsService, symbol: &str) -> Value {
    let args = format!(r#"{{"symbols":["{symbol}"],"include_tests":true}}"#);
    let payload = service
        .call_tool_json("scan_usages_by_reference", &args)
        .expect("scan_usages call failed");
    serde_json::from_str(&payload).expect("scan_usages returned invalid JSON")
}

/// Warm up, then time `MEASURED` repeated `scan_usages` queries for `symbol`. Returns
/// `(median_ms, mean_ms)`. Asserts the symbol actually resolves to usages so the timing
/// reflects real resolution work, not an early bail.
fn measure_symbol(
    service: &SearchToolsService,
    symbol: &str,
    expected_min_hits: u64,
) -> (f64, f64) {
    let first = scan_symbol(service, symbol);
    let total_hits = first["results"]
        .as_array()
        .and_then(|results| results.first())
        .and_then(|entry| entry["total_hits"].as_u64())
        .unwrap_or(0);
    assert!(
        total_hits >= expected_min_hits,
        "expected >= {expected_min_hits} {symbol} usages, got {total_hits}: {first}"
    );

    for _ in 0..WARMUP {
        let _ = scan_symbol(service, symbol);
    }

    let mut samples_ms: Vec<f64> = Vec::with_capacity(MEASURED);
    for _ in 0..MEASURED {
        let start = Instant::now();
        let _ = scan_symbol(service, symbol);
        samples_ms.push(start.elapsed().as_secs_f64() * 1000.0);
    }
    samples_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median_ms = samples_ms[samples_ms.len() / 2];
    let mean_ms = samples_ms.iter().sum::<f64>() / samples_ms.len() as f64;
    (median_ms, mean_ms)
}

#[test]
#[ignore = "measure-first benchmark; run explicitly with --ignored --nocapture"]
fn jsts_scan_usages_repeated_query_latency() {
    let temp = TempDir::new().expect("temp dir");
    let root = temp.path().to_path_buf();
    generate_ts_workspace(&root, MODULE_COUNT);

    let build_start = Instant::now();
    let service = SearchToolsService::new_without_semantic_index(root)
        .expect("failed to build searchtools service");
    let build_ms = build_start.elapsed().as_secs_f64() * 1000.0;

    let (niche_median, niche_mean) = measure_symbol(&service, "Niche", 1);
    let (widget_median, widget_mean) = measure_symbol(&service, "Widget", MODULE_COUNT as u64);

    eprintln!("\n=== JS/TS scan_usages repeated-query latency ===");
    eprintln!("modules: {MODULE_COUNT}, workspace build: {build_ms:.1} ms");
    eprintln!(
        "low  fan-in (Niche,  1 usage):          median {niche_median:.1} ms, mean {niche_mean:.1} ms"
    );
    eprintln!(
        "high fan-in (Widget, {MODULE_COUNT} usages):       median {widget_median:.1} ms, mean {widget_mean:.1} ms"
    );
    eprintln!();
}
