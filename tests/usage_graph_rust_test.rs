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

use brokk_bifrost::{Language, SearchToolsService};
use common::InlineTestProject;
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
fn self_receiver_call_does_not_create_usage_graph_edge() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "src/lib.rs",
            r#"
pub struct Service;

impl Service {
    pub fn target(&self) {}

    pub fn caller(&self) {
        self.target();
    }
}
"#,
        )
        .build();

    let value = common::usage_graph::usage_graph_at(project.root(), "{}");
    assert!(
        find_edge(&value, "Service.caller", "Service.target").is_none(),
        "self-receiver calls must not appear as usage_graph edges: {}",
        value["edges"]
    );
}

#[test]
fn object_sensitive_factory_receiver_resolves_only_constructed_type() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "src/lib.rs",
            r#"
pub struct Service;
pub struct Other;

impl Service {
    pub fn new() -> Self {
        Service
    }

    pub fn run(&self) {}
}

impl Other {
    pub fn run(&self) {}
}

pub fn make_service() -> Service {
    Service::new()
}

pub fn via_free_factory() {
    let service = make_service();
    service.run();
}

pub fn via_associated_factory() {
    let service = Service::new();
    service.run();
}
"#,
        )
        .build();

    let value = common::usage_graph::usage_graph_at(project.root(), "{}");
    assert!(
        find_edge(&value, "via_free_factory", "Service.run").is_some(),
        "free factory receiver should edge only to Service.run: {}",
        value["edges"]
    );
    assert!(
        find_edge(&value, "via_associated_factory", "Service.run").is_some(),
        "associated factory receiver should edge only to Service.run: {}",
        value["edges"]
    );
    assert!(
        find_edge(&value, "via_free_factory", "Other.run").is_none()
            && find_edge(&value, "via_associated_factory", "Other.run").is_none(),
        "factory receiver must not fall back to same-name Other.run: {}",
        value["edges"]
    );
}

#[test]
fn factory_receiver_uses_resolved_callable_not_simple_name() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "src/lib.rs",
            r#"
mod hidden {
    pub struct Service;

    impl Service {
        pub fn run(&self) {}
    }

    pub fn make() -> Service {
        Service
    }
}

mod real {
    pub struct Service;

    impl Service {
        pub fn run(&self) {}
    }

    pub fn make() -> Service {
        Service
    }
}

use real::make;

pub fn caller() {
    let service = make();
    service.run();
}
"#,
        )
        .build();

    let value = common::usage_graph::usage_graph_at(project.root(), "{}");
    assert!(
        find_edge(&value, "caller", "hidden.Service.run").is_none(),
        "bare factory must not use a hidden same-name factory summary: {}",
        value["edges"]
    );
}

#[test]
fn wrapper_self_factory_return_seeds_owner_receiver() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "src/lib.rs",
            r#"
use std::sync::Arc;

pub struct Service;
pub struct Other;

impl Service {
    pub fn new() -> Arc<Self> {
        Arc::new(Service)
    }

    pub fn run(&self) {}
}

impl Other {
    pub fn run(&self) {}
}

pub fn caller() {
    let service = Service::new();
    service.run();
}
"#,
        )
        .build();

    let value = common::usage_graph::usage_graph_at(project.root(), "{}");
    assert!(
        find_edge(&value, "caller", "Service.run").is_some(),
        "Arc<Self> factory return should seed the owner receiver: {}",
        value["edges"]
    );
    assert!(
        find_edge(&value, "caller", "Other.run").is_none(),
        "wrapper self return must not fall back to same-name Other.run: {}",
        value["edges"]
    );
}

#[test]
fn unsupported_trait_object_receiver_emits_no_partial_edge() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "src/lib.rs",
            r#"
pub trait Runner {
    fn run(&self);
}

pub struct Service;
pub struct Other;

impl Service {
    pub fn run(&self) {}
}

impl Other {
    pub fn run(&self) {}
}

pub fn ambiguous(receiver: &dyn Runner) {
    receiver.run();
}
"#,
        )
        .build();

    let value = common::usage_graph::usage_graph_at(project.root(), "{}");
    assert!(
        find_edge(&value, "ambiguous", "Service.run").is_none()
            && find_edge(&value, "ambiguous", "Other.run").is_none(),
        "unsupported trait-object receiver must not emit partial same-name edges: {}",
        value["edges"]
    );
}

#[test]
fn block_local_receiver_shadow_does_not_leak_to_outer_call() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "src/lib.rs",
            r#"
pub struct Service;
pub struct Other;

impl Service {
    pub fn new() -> Self { Service }
    pub fn run(&self) {}
}

impl Other {
    pub fn new() -> Self { Other }
    pub fn run(&self) {}
}

pub fn caller(flag: bool) {
    let service = Other::new();
    if flag {
        let service = Service::new();
        let _ = service;
    }
    service.run();
}
"#,
        )
        .build();

    let value = common::usage_graph::usage_graph_at(project.root(), "{}");
    assert!(
        find_edge(&value, "caller", "Other.run").is_some(),
        "outer receiver should resolve to Other.run: {}",
        value["edges"]
    );
    assert!(
        find_edge(&value, "caller", "Service.run").is_none(),
        "block-local receiver shadow must not leak to the outer call: {}",
        value["edges"]
    );
}

#[test]
fn every_edge_endpoint_is_a_node() {
    assert_every_edge_endpoint_is_a_node(&usage_graph());
}
