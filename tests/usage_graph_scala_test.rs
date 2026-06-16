mod common;

use brokk_bifrost::SearchToolsService;
use common::usage_graph::{assert_every_edge_endpoint_is_a_node, has_edge};
use serde_json::Value;
use std::path::PathBuf;

fn usage_graph() -> Value {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("usage-graph-scala");
    let service = SearchToolsService::new(root).expect("service");
    let payload = service
        .call_tool_json("usage_graph", "{}")
        .expect("usage_graph call failed");
    serde_json::from_str(&payload).expect("invalid JSON")
}

#[test]
fn resolves_instance_object_and_unqualified_calls() {
    let value = usage_graph();

    // `s.run()` where `val s = new Service()` — local type resolves the receiver.
    assert!(
        has_edge(
            &value,
            "example.Consumer.viaInstance",
            "example.Service.run"
        ),
        "expected viaInstance -> Service.run: {}",
        value["edges"]
    );
    // `svc.run()` where `svc: Service` — typed parameter resolves the receiver.
    assert!(
        has_edge(&value, "example.Consumer.viaParam", "example.Service.run"),
        "expected viaParam -> Service.run: {}",
        value["edges"]
    );
    // `Helpers.help()` — object method call. The object node keeps its `$`
    // suffix, so the edge target is `example.Helpers$.help`.
    assert!(
        has_edge(
            &value,
            "example.Consumer.viaObject",
            "example.Helpers$.help"
        ),
        "expected viaObject -> Helpers$.help: {}",
        value["edges"]
    );
    // Unqualified `local()` attributes to the enclosing class.
    assert!(
        has_edge(
            &value,
            "example.Consumer.callsLocal",
            "example.Consumer.local"
        ),
        "expected callsLocal -> Consumer.local: {}",
        value["edges"]
    );
}

#[test]
fn type_references_edge_to_the_type_node() {
    let value = usage_graph();

    // `new Service()` (and the `Service` return type) edges to the type node.
    assert!(
        has_edge(&value, "example.Consumer.makeService", "example.Service"),
        "expected makeService -> Service: {}",
        value["edges"]
    );
    assert!(
        has_edge(&value, "example.Consumer.viaInstance", "example.Service"),
        "expected viaInstance -> Service (new Service()): {}",
        value["edges"]
    );
}

#[test]
fn receiver_typing_is_type_based_not_name_based() {
    let value = usage_graph();

    // `other.run()` where `other: Consumer` resolves to `Consumer.run`, which is
    // not a node — so it must NOT edge to `Service.run` despite the member name.
    assert!(
        !has_edge(
            &value,
            "example.Consumer.wrongReceiver",
            "example.Service.run"
        ),
        "wrongReceiver must not edge to Service.run: {}",
        value["edges"]
    );
}

#[test]
fn self_recursion_produces_no_edge_and_unused_has_no_incoming() {
    let value = usage_graph();

    // A method calling itself is not an edge.
    assert!(
        !has_edge(
            &value,
            "example.Consumer.recurse",
            "example.Consumer.recurse"
        ),
        "self-recursion must not be an edge: {}",
        value["edges"]
    );
    assert!(
        !value["edges"]
            .as_array()
            .expect("edges array")
            .iter()
            .any(|edge| edge["from"] == edge["to"]),
        "no self references may appear as edges: {}",
        value["edges"]
    );
    // `Service.unused` is never called.
    assert!(
        !value["edges"]
            .as_array()
            .expect("edges array")
            .iter()
            .any(|edge| edge["to"].as_str() == Some("example.Service.unused")),
        "unused method must have no incoming edges: {}",
        value["edges"]
    );
}

#[test]
fn every_edge_endpoint_is_a_node() {
    assert_every_edge_endpoint_is_a_node(&usage_graph());
}

#[test]
fn scala3_indented_this_and_block_scoping() {
    let value = usage_graph();

    // `this.help()` (Scala's `this` is a plain identifier) attributes to the
    // enclosing class.
    assert!(
        has_edge(
            &value,
            "example.Indented.callsThis",
            "example.Indented.help"
        ),
        "expected callsThis -> Indented.help: {}",
        value["edges"]
    );
    // A `val svc` shadow inside a Scala 3 `indented_block` branch must not leak
    // into the method scope, so the trailing `svc.run()` still resolves to the
    // Service-typed parameter.
    assert!(
        has_edge(
            &value,
            "example.Indented.shadowInBranch",
            "example.Service.run"
        ),
        "indented-block shadow must not leak to the method scope: {}",
        value["edges"]
    );
}
