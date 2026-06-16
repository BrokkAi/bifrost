mod common;

use brokk_bifrost::SearchToolsService;
use common::usage_graph::assert_every_edge_endpoint_is_a_node;
use serde_json::Value;
use std::path::PathBuf;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("usage-graph-java")
}

fn usage_graph() -> Value {
    let service = SearchToolsService::new(fixture_root()).expect("service");
    let payload = service
        .call_tool_json("usage_graph", "{}")
        .expect("usage_graph call failed");
    serde_json::from_str(&payload).expect("invalid JSON")
}

fn find_edge<'a>(value: &'a Value, from_suffix: &str, to: &str) -> Option<&'a Value> {
    value["edges"]
        .as_array()
        .expect("edges array")
        .iter()
        .find(|edge| {
            edge["from"]
                .as_str()
                .is_some_and(|from| from.ends_with(from_suffix))
                && edge["to"].as_str() == Some(to)
        })
}

#[test]
fn resolves_instance_static_and_constructor_calls() {
    let value = usage_graph();

    // `s.run()` where `Service s = new Service()` — the local's type resolves the
    // receiver to `com.example.Service.run`.
    assert!(
        find_edge(&value, "viaInstance", "com.example.Service.run").is_some(),
        "expected viaInstance -> Service.run: {}",
        value["edges"]
    );
    // `Service.helper()` — static call resolves the type directly.
    assert!(
        find_edge(&value, "viaStatic", "com.example.Service.helper").is_some(),
        "expected viaStatic -> Service.helper: {}",
        value["edges"]
    );
    // `new Service()` / `Service` return type resolve to the class node.
    assert!(
        find_edge(&value, "makeService", "com.example.Service").is_some(),
        "expected makeService -> Service: {}",
        value["edges"]
    );
}

#[test]
fn receiver_typing_is_type_based_not_name_based() {
    let value = usage_graph();

    // A `run()` call on a Service-typed parameter resolves (the parameter name
    // shadowing the method is irrelevant — resolution is by receiver type).
    assert!(
        find_edge(&value, "shadowed", "com.example.Service.run").is_some(),
        "expected shadowed -> Service.run: {}",
        value["edges"]
    );
    // The same method name on a Consumer-typed receiver must NOT resolve to
    // Service.run — proving resolution is by receiver type, not method name.
    assert!(
        find_edge(&value, "wrongReceiver", "com.example.Service.run").is_none(),
        "wrongReceiver must not edge to Service.run: {}",
        value["edges"]
    );
}

#[test]
fn unused_member_has_no_incoming_edges_and_no_self_edges() {
    let value = usage_graph();

    assert!(
        !value["edges"]
            .as_array()
            .expect("edges array")
            .iter()
            .any(|edge| edge["to"].as_str() == Some("com.example.Service.unused")),
        "unused method must have no incoming edges: {}",
        value["edges"]
    );
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
fn every_edge_endpoint_is_a_node() {
    assert_every_edge_endpoint_is_a_node(&usage_graph());
}

#[test]
fn nested_class_calls_attribute_to_the_nested_fqn() {
    let value = usage_graph();

    // An unqualified call inside `Outer.Inner` must attribute to the nested
    // class's fqn (`com.example.Outer.Inner.helper`), built from AST nesting —
    // not to a simple-name lookup that could hit a same-named top-level type.
    assert!(
        find_edge(
            &value,
            "com.example.Outer.Inner.compute",
            "com.example.Outer.Inner.helper"
        )
        .is_some(),
        "expected Outer.Inner.compute -> Outer.Inner.helper: {}",
        value["edges"]
    );
}

#[test]
fn untyped_local_named_like_a_type_produces_no_static_edge() {
    let value = usage_graph();

    // `shadowFallback` has an untyped local `Service`; `Service.run()` must not
    // be reinterpreted as a static call resolving to `com.example.Service.run`.
    assert!(
        find_edge(&value, "shadowFallback", "com.example.Service.run").is_none(),
        "an untyped local must not fall back to static type resolution: {}",
        value["edges"]
    );
}
