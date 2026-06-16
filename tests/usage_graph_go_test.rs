//! `usage_graph` correctness on a Go fixture, exercising the behaviours the
//! whole-workspace inverted builder fixes relative to the original per-symbol
//! resolver:
//!
//! - **No over-counting of same-named methods.** `Alpha.Channel` and
//!   `Beta.Channel` share a name but never call each other; the per-symbol path
//!   cross-linked such methods into an O(n^2) false-positive cluster (observed on
//!   cockroach's generated `eventpb.*.LoggingChannel` — ~16k bogus edges). The
//!   inverted builder resolves each call to the receiver's actual type, so no edge
//!   appears between them.
//! - **Member calls resolve to the receiver's type**, so cross-file references are
//!   recovered (recall), not just bare-name matches.
//! - **Edge weights aggregate** distinct call sites, and **self-references** are
//!   dropped.

mod common;

use brokk_bifrost::SearchToolsService;
use common::usage_graph::has_edge;
use serde_json::Value;
use std::path::PathBuf;

fn go_usage_graph() -> Value {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("usage-graph-go");
    let service = SearchToolsService::new(root).expect("failed to build searchtools service");
    let payload = service
        .call_tool_json("usage_graph", "{}")
        .expect("usage_graph call failed");
    serde_json::from_str(&payload).expect("usage_graph returned invalid JSON")
}

fn edge_weight(value: &Value, from: &str, to: &str) -> Option<u64> {
    value["edges"]
        .as_array()
        .expect("edges array")
        .iter()
        .find(|edge| edge["from"].as_str() == Some(from) && edge["to"].as_str() == Some(to))
        .and_then(|edge| edge["weight"].as_u64())
}

#[test]
fn cross_package_selector_call_resolves_to_an_edge() {
    let graph = go_usage_graph();
    // `callsCrossPackage` calls `sub.Helper()` through an imported-package
    // selector; the edge must resolve to the callee in the other package.
    assert!(
        has_edge(
            &graph,
            "example.com/app.callsCrossPackage",
            "example.com/app/sub.Helper"
        ),
        "cross-package selector call should produce an edge; edges: {:?}",
        graph["edges"]
    );
}

#[test]
fn member_call_resolves_to_the_receivers_type() {
    let graph = go_usage_graph();
    // `describeAlpha` calls `a.Channel()` where `a` is typed `*Alpha`.
    assert!(
        has_edge(
            &graph,
            "example.com/app.describeAlpha",
            "example.com/app.Alpha.Channel"
        ),
        "member call on a *Alpha receiver should resolve to Alpha.Channel; edges: {:?}",
        graph["edges"]
    );
}

#[test]
fn same_named_methods_are_not_cross_linked() {
    let graph = go_usage_graph();
    // The pathology the inverted builder fixes: Alpha.Channel and Beta.Channel
    // share a method name but never reference each other.
    assert!(
        !has_edge(
            &graph,
            "example.com/app.Alpha.Channel",
            "example.com/app.Beta.Channel"
        ),
        "Alpha.Channel must not link to the unrelated same-named Beta.Channel"
    );
    assert!(
        !has_edge(
            &graph,
            "example.com/app.Beta.Channel",
            "example.com/app.Alpha.Channel"
        ),
        "Beta.Channel must not link to the unrelated same-named Alpha.Channel"
    );
}

#[test]
fn repeated_calls_aggregate_edge_weight() {
    let graph = go_usage_graph();
    // `total` calls `helper` on two distinct lines.
    assert_eq!(
        edge_weight(&graph, "example.com/app.total", "example.com/app.helper"),
        Some(2),
        "two distinct call sites should aggregate to weight 2"
    );
}

#[test]
fn self_reference_produces_no_edge() {
    let graph = go_usage_graph();
    // `recurse` calls itself; a self-reference is not a graph edge.
    assert!(
        !has_edge(&graph, "example.com/app.recurse", "example.com/app.recurse"),
        "self-recursion must not produce a self edge"
    );
}
