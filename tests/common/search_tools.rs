#![allow(dead_code)]

//! Shared `SearchToolsService` call-tool helpers lifted out of ~14 byte-identical
//! (or near-identical) per-test-file copies. Every test binary that includes
//! `tests/common` via `mod common;` gets these for free; not every binary uses
//! every helper, hence the blanket `dead_code` allow above (same convention as
//! `inline_project.rs`).

use super::BuiltInlineTestProject;
use serde_json::Value;
use std::sync::{LazyLock, Mutex};

// A handful of the lifted call sites serialized calls through a private lock
// (e.g. `searchtools_definition_selectors.rs`'s `LOOKUP_LOCK`) while others had
// none at all. Serializing unconditionally is a strict behavioral superset of
// both: it can only add ordering, never change a result, so every retargeted
// call site keeps (or gains) the same safety net.
static CALL_TOOL_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

/// Build a fresh `SearchToolsService` over `project` (no semantic index) and
/// invoke `tool` with the raw JSON `args` string, returning the parsed
/// response.
pub fn call_tool(project: &BuiltInlineTestProject, tool: &str, args: &str) -> Value {
    let _guard = CALL_TOOL_LOCK.lock().expect("call tool lock poisoned");
    let service =
        brokk_bifrost::SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
            .expect("service");
    let payload = service
        .call_tool_json(tool, args)
        .expect("tool call failed");
    serde_json::from_str(&payload).expect("tool returned invalid JSON")
}

/// `get_symbol_sources` for a single `symbol`.
pub fn symbol_sources(project: &BuiltInlineTestProject, symbol: &str) -> Value {
    call_tool(
        project,
        "get_symbol_sources",
        &serde_json::json!({ "symbols": [symbol] }).to_string(),
    )
}

/// The `status` string of the (sole) result of a `get_definitions_by_reference`
/// call for `symbol` used at `context` and resolving to `target`.
pub fn definition_reference_status(
    project: &BuiltInlineTestProject,
    symbol: &str,
    context: &str,
    target: &str,
) -> String {
    let args = serde_json::json!({
        "references": [{ "symbol": symbol, "context": context, "target": target }]
    })
    .to_string();
    let result = call_tool(project, "get_definitions_by_reference", &args);
    result["results"][0]["status"]
        .as_str()
        .unwrap_or_else(|| panic!("expected a status string, got {result}"))
        .to_string()
}

/// The `get_definitions_by_location` result for the first byte of `needle` in
/// `source`, which the caller must have written to `path`.
pub fn definition_at(
    project: &BuiltInlineTestProject,
    path: &str,
    source: &str,
    needle: &str,
) -> Value {
    let start = source
        .find(needle)
        .unwrap_or_else(|| panic!("`{needle}` is not present in {path}"));
    let prefix = &source[..start];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = prefix
        .rsplit_once('\n')
        .map_or(prefix, |(_, current_line)| current_line)
        .chars()
        .count()
        + 1;
    let args = serde_json::json!({"references": [{"path": path, "line": line, "column": column}]})
        .to_string();
    call_tool(project, "get_definitions_by_location", &args)["results"][0].clone()
}

/// Every `file`/`path` reported in a `get_definitions_by_location` result's
/// `definitions` list.
pub fn definition_paths(result: &Value) -> Vec<String> {
    result["definitions"]
        .as_array()
        .map(|definitions| {
            definitions
                .iter()
                .filter_map(|definition| {
                    definition["file"].as_str().or(definition["path"].as_str())
                })
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// The sorted `path`s of every `get_symbol_sources` `sources` entry in `result`.
pub fn sorted_source_paths(result: &Value) -> Vec<String> {
    let mut paths: Vec<String> = result["sources"]
        .as_array()
        .unwrap_or_else(|| panic!("expected `sources` array, got {result}"))
        .iter()
        .map(|source| source["path"].as_str().expect("source path").to_string())
        .collect();
    paths.sort();
    paths
}
