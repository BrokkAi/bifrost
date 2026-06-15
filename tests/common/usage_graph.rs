//! Shared assertion helpers for the `usage_graph_*` end-to-end tests.

use serde_json::Value;

/// True when an edge with exactly this `from` and `to` exists.
#[allow(dead_code)]
pub fn has_edge(value: &Value, from: &str, to: &str) -> bool {
    value["edges"]
        .as_array()
        .expect("edges array")
        .iter()
        .any(|edge| edge["from"].as_str() == Some(from) && edge["to"].as_str() == Some(to))
}

/// The first edge whose `from`/`to` end with the given suffixes.
#[allow(dead_code)]
pub fn find_edge<'a>(value: &'a Value, from_suffix: &str, to_suffix: &str) -> Option<&'a Value> {
    value["edges"]
        .as_array()
        .expect("edges array")
        .iter()
        .find(|edge| {
            edge["from"]
                .as_str()
                .is_some_and(|from| from.ends_with(from_suffix))
                && edge["to"]
                    .as_str()
                    .is_some_and(|to| to.ends_with(to_suffix))
        })
}

/// Assert every edge endpoint is also a node, so a consumer can load nodes +
/// edges into a graph without phantom nodes.
#[allow(dead_code)]
pub fn assert_every_edge_endpoint_is_a_node(value: &Value) {
    let node_fqns: std::collections::HashSet<&str> = value["nodes"]
        .as_array()
        .expect("nodes array")
        .iter()
        .map(|node| node["fqn"].as_str().expect("node fqn"))
        .collect();
    for edge in value["edges"].as_array().expect("edges array") {
        let from = edge["from"].as_str().expect("edge from");
        let to = edge["to"].as_str().expect("edge to");
        assert!(
            node_fqns.contains(from),
            "edge `from` is not a node: {edge}"
        );
        assert!(node_fqns.contains(to), "edge `to` is not a node: {edge}");
    }
}
