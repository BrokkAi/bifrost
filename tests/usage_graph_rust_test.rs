//! Whole-workspace `usage_graph` over a Rust fixture, exercising the inverted
//! edge builder (`src/analyzer/usages/rust_graph/inverted.rs`).
//!
//! The fixture (`tests/fixtures/usage-graph-rust`) covers the resolution shapes
//! the inverted scan must get right:
//! - a named import (`use crate::util::format_value;`) → `util.format_value`,
//!   with call-site weight aggregation;
//! - a namespace import (`use crate::util;` then `util::format_value(..)`);
//! - an associated function on an imported type (`Config::new()`);
//! - a bare call through a chained/aliased in-crate `pub use` re-export;
//! - self-recursion producing no edge;
//! - a parameter shadowing an import producing no edge.

mod common;

use brokk_bifrost::SearchToolsService;
use common::usage_graph::{assert_every_edge_endpoint_is_a_node, find_edge};
use serde_json::Value;
use std::path::PathBuf;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("usage-graph-rust")
}

fn usage_graph() -> Value {
    let service = SearchToolsService::new(fixture_root())
        .expect("failed to build searchtools service over the fixture");
    let payload = service
        .call_tool_json("usage_graph", "{}")
        .expect("usage_graph call failed");
    serde_json::from_str(&payload).expect("usage_graph returned invalid JSON")
}

#[test]
fn resolves_named_import_calls_and_aggregates_weight() {
    let value = usage_graph();

    // `consumer.run` calls `util.format_value` once. This import
    // (`use crate::util::format_value;`) is classified as a namespace by the
    // binder's snake_case heuristic, so the per-symbol path missed bare calls
    // through it — the inverted scan recovers the edge.
    let run_edge = find_edge(&value, "consumer.run", "util.format_value")
        .expect("expected consumer.run -> util.format_value edge");
    assert_eq!(run_edge["weight"].as_u64(), Some(1), "edge: {run_edge}");

    // Two call sites on separate lines aggregate to weight 2.
    let twice_edge = find_edge(&value, "consumer.run_twice", "util.format_value")
        .expect("expected consumer.run_twice -> util.format_value edge");
    assert_eq!(twice_edge["weight"].as_u64(), Some(2), "edge: {twice_edge}");
}

#[test]
fn resolves_namespace_qualified_and_associated_calls() {
    let value = usage_graph();

    // `util::format_value(..)` via `use crate::util;` (namespace import).
    assert!(
        find_edge(&value, "consumer.via_namespace", "util.format_value").is_some(),
        "expected via_namespace -> util.format_value edge: {}",
        value["edges"]
    );
    // `Config::new()` resolves to the associated function on the imported type.
    assert!(
        find_edge(&value, "consumer.make_config", "util.Config.new").is_some(),
        "expected make_config -> util.Config.new edge: {}",
        value["edges"]
    );
}

#[test]
fn resolves_bare_call_through_in_crate_reexport() {
    let value = usage_graph();

    assert!(
        find_edge(&value, "run_demo", "service.build_service").is_some(),
        "expected run_demo -> service.build_service through chained/aliased pub use: {}",
        value["edges"]
    );
}

#[test]
fn parameter_shadowing_an_import_produces_no_edge() {
    let value = usage_graph();

    // `consumer.shadowed` takes a `format_value` parameter; referencing it must
    // not resolve to the imported `util.format_value`. The forward scan never
    // shadows parameters, so the inverted scan is strictly more precise here.
    assert!(
        find_edge(&value, "consumer.shadowed", "util.format_value").is_none(),
        "a parameter shadowing the import must not produce an edge: {}",
        value["edges"]
    );
}

#[test]
fn shadow_scoping_is_precise() {
    let value = usage_graph();

    // A parameter's *type* annotation must not be shadowed by the parameter
    // binding: `typed_param(config: Config)` still resolves `Config::new()`.
    assert!(
        find_edge(&value, "consumer.typed_param", "util.Config.new").is_some(),
        "a parameter type must not be shadowed by its binding: {}",
        value["edges"]
    );

    // A `let` shadow is local to its function, so `let_shadows` has no edge...
    assert!(
        find_edge(&value, "consumer.let_shadows", "util.format_value").is_none(),
        "a local `let` shadow must suppress the import in its function: {}",
        value["edges"]
    );
    // ...but it must not leak to a sibling, so `run` still resolves the import.
    assert!(
        find_edge(&value, "consumer.run", "util.format_value").is_some(),
        "a `let` shadow must not leak to sibling functions: {}",
        value["edges"]
    );
}

#[test]
fn self_recursion_and_unused_items_produce_no_edges() {
    let value = usage_graph();

    // `consumer.recurse` calls itself; a self edge does not affect ranking.
    assert!(
        find_edge(&value, "consumer.recurse", "consumer.recurse").is_none(),
        "self references must not appear as edges: {}",
        value["edges"]
    );
    // `util.unused` is never called.
    assert!(
        !value["edges"]
            .as_array()
            .expect("edges array")
            .iter()
            .any(|edge| edge["to"].as_str() == Some("util.unused")),
        "unused item must have no incoming edges: {}",
        value["edges"]
    );
}

#[test]
fn every_edge_endpoint_is_a_node() {
    assert_every_edge_endpoint_is_a_node(&usage_graph());
}
