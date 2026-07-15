//! Regression tests for the reference-resolver unification refactor: node
//! identity in `usage_graph` and same-name resolution in `scan_usages`.
//!
//! `usage_graph` once keyed nodes on a bare `fqn` string, so two symbols
//! normalizing to the same fqn collapsed into one node — across files in a
//! module-scoped language, or across languages. Node identity is now
//! `(ecosystem, fqn)`, plus the defining file for module-scoped ecosystems
//! (JS/TS). `scan_usages` reports same-name definitions as selectable
//! candidates, and the inverted path resolves typed-receiver calls the forward
//! path already found.

use brokk_bifrost::SearchToolsService;
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::PathBuf;
use tempfile::TempDir;

fn fixture_root(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn usage_graph(fixture: &str) -> Value {
    // These checked-in fixtures are immutable; keep parallel tests isolated
    // from the parent repository's persisted cache and file watcher.
    let service = SearchToolsService::new_manual_without_semantic_index(fixture_root(fixture))
        .expect("service");
    let payload = service
        .call_tool_json("usage_graph", "{}")
        .expect("usage_graph call failed");
    serde_json::from_str(&payload).expect("usage_graph returned invalid JSON")
}

fn scan_usages_by_reference(fixture: &str, args: &str) -> Value {
    let service = SearchToolsService::new_manual_without_semantic_index(fixture_root(fixture))
        .expect("service");
    let payload = service
        .call_tool_json("scan_usages_by_reference", args)
        .expect("scan_usages_by_reference call failed");
    serde_json::from_str(&payload).expect("scan_usages_by_reference returned invalid JSON")
}

fn most_relevant_files(fixture: &str, seed: &str) -> Value {
    let service = SearchToolsService::new_manual_without_semantic_index(fixture_root(fixture))
        .expect("service");
    let arguments =
        format!(r#"{{"seed_file_paths":[{seed:?}],"ranking_mode":"usage_graph","limit":1}}"#);
    let payload = service
        .call_tool_json("most_relevant_files", &arguments)
        .expect("most_relevant_files call failed");
    serde_json::from_str(&payload).expect("most_relevant_files returned invalid JSON")
}

/// All `(fqn, path)` pairs for nodes whose fqn equals `fqn`.
fn nodes_named(graph: &Value, fqn: &str) -> Vec<String> {
    graph["nodes"]
        .as_array()
        .expect("nodes array")
        .iter()
        .filter(|node| node["fqn"].as_str() == Some(fqn))
        .map(|node| node["path"].as_str().unwrap_or("<no path>").to_string())
        .collect()
}

fn has_edge(graph: &Value, from: &str, to: &str) -> bool {
    graph["edges"]
        .as_array()
        .expect("edges array")
        .iter()
        .any(|e| e["from"].as_str() == Some(from) && e["to"].as_str() == Some(to))
}

// Two files exporting `class Anchor` must be two distinct nodes. The fqn is bare
// (`Anchor`) in JS/TS, so identity includes the file; without it the two classes
// collapse into one node and the second is dropped (orphaning `Anchor.place`).
#[test]
fn same_name_classes_are_distinct_nodes() {
    let graph = usage_graph("usage-graph-ts-samename");
    let anchors = nodes_named(&graph, "Anchor");
    assert_eq!(
        anchors.len(),
        2,
        "expected two distinct `Anchor` class nodes (charts + layout); got {anchors:?}. \
         nodes: {:#}",
        graph["nodes"]
    );
    let paths: BTreeSet<&str> = anchors.iter().map(String::as_str).collect();
    assert!(
        paths.contains("charts/Anchor.ts") && paths.contains("layout/Anchor.ts"),
        "the two `Anchor` nodes must be the charts and layout files; got {paths:?}"
    );
}

// The forward-path face of the same gap: `scan_usages("Anchor")` must surface
// that the name maps to two distinct definitions with selectable
// candidate_targets, so a caller can pick one rather than scan a conflation.
#[test]
fn same_name_classes_are_distinguishable_in_scan_usages() {
    let result = scan_usages_by_reference(
        "usage-graph-ts-samename",
        r#"{"symbols":["Anchor"],"include_tests":true}"#,
    );
    let entry = result["results"]
        .as_array()
        .and_then(|entries| entries.first())
        .filter(|entry| {
            entry["input"].as_str() == Some("Anchor")
                && entry["input_kind"].as_str() == Some("symbol")
                && entry["status"].as_str() == Some("ambiguous")
        });
    let candidates: BTreeSet<String> = entry
        .and_then(|e| e["candidate_targets"].as_array())
        .map(|c| {
            c.iter()
                .filter_map(|t| t.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    assert!(
        candidates.len() >= 2,
        "`Anchor` resolves to two distinct classes (charts + layout); scan_usages must \
         report >=2 distinct, selectable candidate_targets. got {candidates:?}; full: {result:#}"
    );

    // The candidates must be selectable, not just distinct: re-calling with one
    // resolves to exactly that definition (no longer ambiguous) and scans it.
    let chosen = candidates
        .iter()
        .find(|target| target.contains("charts/Anchor.ts"))
        .expect("a candidate_target anchored to charts/Anchor.ts");
    let args = format!(r#"{{"symbols":[{chosen:?}],"include_tests":true}}"#);
    let resolved = scan_usages_by_reference("usage-graph-ts-samename", &args);
    assert!(
        resolved["results"]
            .as_array()
            .map(|entries| entries.iter().all(|entry| entry["status"] != "ambiguous"))
            .unwrap_or(false),
        "re-calling with the selector {chosen:?} must resolve to one definition, \
         not stay ambiguous; got {resolved:#}"
    );
    assert_eq!(
        resolved["summary"]["resolved"].as_u64(),
        Some(1),
        "the anchored selector {chosen:?} must resolve exactly one symbol; got {resolved:#}"
    );
}

// Two modules export `helper`; an importer of each calls it. Each `helper` must
// be a distinct node so the call edges attribute to the right definition.
#[test]
fn same_name_module_exports_are_distinct_nodes() {
    let graph = usage_graph("usage-graph-ts-modres");
    let helpers = nodes_named(&graph, "helper");
    assert_eq!(
        helpers.len(),
        2,
        "expected two distinct `helper` nodes (a.ts + b.ts); got {helpers:?}. nodes: {:#}",
        graph["nodes"]
    );
    // With file-qualified nodes, callsA's call resolves to a.ts's helper and
    // callsB's to b.ts's, so both edges exist.
    assert!(
        has_edge(&graph, "callsA", "helper") && has_edge(&graph, "callsB", "helper"),
        "both importers must have a resolved edge to their helper; edges: {:#}",
        graph["edges"]
    );
}

#[test]
fn usage_relevance_keeps_same_name_module_exports_distinct() {
    let result = most_relevant_files("usage-graph-ts-modres", "c.ts");
    assert_eq!(result["files"], serde_json::json!(["a.ts"]));
}

#[test]
fn usage_relevance_keeps_identical_cross_language_fqns_distinct() {
    let temp = TempDir::new().unwrap();
    std::fs::write(
        temp.path().join("main.go"),
        "package service\nfunc run() int { return helper() }\n",
    )
    .unwrap();
    std::fs::write(
        temp.path().join("z.go"),
        "package service\nfunc helper() int { return 1 }\n",
    )
    .unwrap();
    std::fs::write(
        temp.path().join("service.py"),
        "def helper():\n    return 2\n",
    )
    .unwrap();
    let service = SearchToolsService::new_manual_without_semantic_index(temp.path().to_path_buf())
        .expect("service");
    let payload = service
        .call_tool_json(
            "most_relevant_files",
            r#"{"seed_file_paths":["main.go"],"ranking_mode":"usage_graph","limit":1}"#,
        )
        .expect("most_relevant_files call failed");
    let result: Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(result["files"], serde_json::json!(["z.go"]));
}

// The inverted path must resolve typed receivers like the forward path does:
// `run(s: Service)` calling `s.handle()` yields a `svc.run -> svc.Service.handle`
// edge, not just the `svc.run -> svc.Service` type-annotation edge.
#[test]
fn python_receiver_typed_call_is_an_edge() {
    let graph = usage_graph("usage-graph-python-receiver");
    assert!(
        has_edge(&graph, "svc.run", "svc.Service.handle"),
        "receiver-typed call s.handle() in run(s: Service) must be an edge \
         svc.run -> svc.Service.handle; edges: {:#}",
        graph["edges"]
    );
}

// A Python `service.run` and a Go `service.run` normalize to the same bare fqn;
// node identity must carry the ecosystem so they stay two distinct nodes instead
// of merging (which also contaminated their edge weights). See #187.
#[test]
fn cross_language_same_fqn_is_distinct_nodes() {
    let graph = usage_graph("usage-graph-xlang");
    let runs = nodes_named(&graph, "service.run");
    assert_eq!(
        runs.len(),
        2,
        "Python and Go `service.run` must be two distinct (language-qualified) nodes; \
         got {runs:?} (the Python definition is merged away). nodes: {:#}",
        graph["nodes"]
    );
    let paths: BTreeSet<&str> = runs.iter().map(String::as_str).collect();
    assert!(
        paths.contains("service.go") && paths.contains("service.py"),
        "the two `service.run` nodes must be the Go and Python files; got {paths:?}"
    );
}
