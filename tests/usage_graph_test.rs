//! End-to-end coverage for the `usage_graph` tool.
//!
//! These exercise the full service path the Python client uses: resolve the
//! workspace, walk every definition, and serialize the aggregated
//! caller -> callee graph. The fixture (`tests/fixtures/usage-graph-python`)
//! has a deliberately small, known call structure:
//!
//! - `a.helper` is called once from `b.run`, twice from `b.run_twice`, and once
//!   at module level in `b.py` (whose enclosing scope is not a node).
//! - `a.unused` is never called.
//! - `a.recurse` calls itself.

mod common;

use brokk_bifrost::{Language, SearchToolsService};
use common::InlineTestProject;
use common::usage_graph::{
    assert_every_edge_endpoint_is_a_node, find_edge, has_edge, usage_graph_at,
};
use serde_json::Value;
use std::path::PathBuf;

fn fixture_root(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn usage_graph_in(fixture: &str, arguments: &str) -> Value {
    let service = SearchToolsService::new_for_python(fixture_root(fixture))
        .expect("failed to build searchtools service over the fixture");
    let payload = service
        .call_tool_json("usage_graph", arguments)
        .expect("usage_graph call failed");
    serde_json::from_str(&payload).expect("usage_graph returned invalid JSON")
}

fn usage_graph(arguments: &str) -> Value {
    usage_graph_in("usage-graph-python", arguments)
}

#[test]
fn receiver_typing_is_function_scoped_not_class_body() {
    // Regression for the inverted receiver-typing scope: a function-scoped
    // receiver accessed at function level resolves, but the same name accessed at
    // the body level of a nested class must not (matching the per-symbol scan).
    let value = usage_graph_in("usage-graph-python-nested-class", "{}");
    assert!(
        has_edge(&value, "m.outer", "m.Foo.method"),
        "function-level recv.method() should resolve to outer -> Foo.method; edges: {:#}",
        value["edges"]
    );
    let edges_to_method = value["edges"]
        .as_array()
        .expect("edges array")
        .iter()
        .filter(|edge| edge["to"].as_str() == Some("m.Foo.method"))
        .count();
    assert_eq!(
        edges_to_method, 1,
        "only the function-level call should resolve; the class-body access must \
         not add an edge. edges: {:#}",
        value["edges"]
    );
}

fn fqns(value: &Value) -> Vec<String> {
    value["nodes"]
        .as_array()
        .expect("nodes array")
        .iter()
        .map(|node| node["fqn"].as_str().expect("node fqn").to_string())
        .collect()
}

#[test]
fn lists_classes_and_functions_as_nodes() {
    let value = usage_graph("{}");
    let fqns = fqns(&value);

    // Nodes come back in a deterministic, fqn-sorted order so a cached graph
    // does not reshuffle between rebuilds of an unchanged workspace.
    let mut sorted = fqns.clone();
    sorted.sort();
    assert_eq!(fqns, sorted, "nodes should be ordered by fqn");

    assert!(
        fqns.iter().any(|fqn| fqn.ends_with("helper")),
        "nodes: {fqns:?}"
    );
    assert!(
        fqns.iter().any(|fqn| fqn.ends_with("run")),
        "nodes: {fqns:?}"
    );
    assert!(
        fqns.iter().any(|fqn| fqn.ends_with("unused")),
        "nodes: {fqns:?}"
    );

    // Only classes and functions participate in the graph.
    for node in value["nodes"].as_array().expect("nodes array") {
        let kind = node["kind"].as_str().expect("node kind");
        assert!(
            kind == "function" || kind == "class",
            "unexpected node kind {kind} in {node}"
        );
        assert!(
            node["fqn"].as_str().is_some_and(|fqn| !fqn.is_empty()),
            "node missing fqn: {node}"
        );
    }
}

#[test]
fn resolves_cross_file_call_edges_and_aggregates_weight() {
    let value = usage_graph("{}");

    // `b.run` calls `a.helper` once.
    let run_edge = find_edge(&value, "run", "helper").expect("expected run -> helper edge");
    assert_eq!(run_edge["weight"].as_u64(), Some(1), "edge: {run_edge}");

    // `b.run_twice` calls `a.helper` on two separate lines, so the edge weight
    // is the aggregated call-site count, not a single deduplicated reference.
    let twice_edge =
        find_edge(&value, "run_twice", "helper").expect("expected run_twice -> helper edge");
    assert_eq!(twice_edge["weight"].as_u64(), Some(2), "edge: {twice_edge}");
}

#[test]
fn overloaded_callee_collapses_to_one_node_and_one_weighted_edge() {
    // `Lib.pick` has two overloads (int / String) sharing one fully qualified
    // name, called once from `Caller.run`. The overloads must collapse to a
    // single node, and the single call site must yield weight 1 — not one count
    // per overload, which would inflate the edge the consumer ranks on.
    let value = usage_graph_in("usage-graph-overloads-java", "{}");

    let pick_nodes: Vec<&Value> = value["nodes"]
        .as_array()
        .expect("nodes array")
        .iter()
        .filter(|node| {
            node["fqn"]
                .as_str()
                .is_some_and(|fqn| fqn.ends_with("pick"))
        })
        .collect();
    assert_eq!(
        pick_nodes.len(),
        1,
        "overloaded `Lib.pick` must collapse to one node: {pick_nodes:?}"
    );
    // Node metadata is taken from the lowest-located overload (`pick(int)` on
    // line 2), deterministically, not from whichever overload iterates first.
    assert_eq!(
        pick_nodes[0]["start_line"].as_u64(),
        Some(2),
        "node metadata must come from the lowest-located overload: {}",
        pick_nodes[0]
    );

    let edge = find_edge(&value, "run", "pick").expect("expected run -> pick edge");
    assert_eq!(edge["weight"].as_u64(), Some(1), "edge: {edge}");
}

#[test]
fn every_edge_endpoint_is_a_node() {
    // `b.py` calls `a.helper` at module level, whose enclosing scope is not a
    // class or function. That reference must not create an edge from a non-node,
    // so a consumer can load nodes + edges into a graph without phantom nodes.
    assert_every_edge_endpoint_is_a_node(&usage_graph("{}"));
}

#[test]
fn self_recursion_does_not_produce_an_edge() {
    // `a.recurse` calls itself; a self edge does not affect centrality ranking
    // and must be dropped.
    let value = usage_graph("{}");

    assert!(
        !value["edges"]
            .as_array()
            .expect("edges array")
            .iter()
            .any(|edge| edge["from"] == edge["to"]),
        "self references must not appear as edges: {}",
        value["edges"]
    );
}

#[test]
fn locals_shadowing_an_import_do_not_produce_an_edge() {
    // `b.shadowed_param` takes a `helper` parameter and `b.shadowed_local`
    // reassigns `helper`; both call `helper()`, but neither resolves to the
    // imported `a.helper`. The inverted scan must honor Python's function-wide
    // scoping and not emit a false caller -> a.helper edge for either.
    let value = usage_graph("{}");

    assert!(
        find_edge(&value, "shadowed_param", "helper").is_none(),
        "a parameter shadowing the import must not produce an edge: {}",
        value["edges"]
    );
    assert!(
        find_edge(&value, "shadowed_local", "helper").is_none(),
        "a local shadowing the import must not produce an edge: {}",
        value["edges"]
    );
}

#[test]
fn object_sensitive_factory_receiver_resolves_only_constructed_type() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "app.py",
            r#"
class Service:
    @classmethod
    def create(cls) -> Service:
        return Service()

    def run(self):
        pass

class Other:
    def run(self):
        pass

def make_service() -> Service:
    return Service()

class Consumer:
    def via_free_factory(self):
        svc = make_service()
        svc.run()

    def via_static_factory(self):
        svc = Service.create()
        svc.run()
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(&value, "app.Consumer.via_free_factory", "app.Service.run"),
        "free factory receiver should edge only to Service.run: {}",
        value["edges"]
    );
    assert!(
        has_edge(&value, "app.Consumer.via_static_factory", "app.Service.run"),
        "static factory receiver should edge only to Service.run: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "app.Consumer.via_free_factory", "app.Other.run")
            && !has_edge(&value, "app.Consumer.via_static_factory", "app.Other.run"),
        "factory receiver must not fall back to same-name Other.run: {}",
        value["edges"]
    );
}

#[test]
fn ambiguous_factory_receiver_emits_no_partial_edge() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "app.py",
            r#"
class Service:
    def run(self):
        pass

class Other:
    def run(self):
        pass

def make(flag):
    if flag:
        return Service()
    return Other()

class Consumer:
    def ambiguous(self, flag):
        svc = make(flag)
        svc.run()
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    assert!(
        !has_edge(&value, "app.Consumer.ambiguous", "app.Service.run")
            && !has_edge(&value, "app.Consumer.ambiguous", "app.Other.run"),
        "ambiguous factory receiver must not emit partial name-only edges: {}",
        value["edges"]
    );
}
