mod common;

use brokk_bifrost::Language;
use common::InlineTestProject;
use common::usage_graph::{assert_every_edge_endpoint_is_a_node, has_edge, usage_graph_at};
use serde_json::Value;
use std::path::PathBuf;

fn usage_graph() -> Value {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("usage-graph-scala");
    usage_graph_at(root, "{}")
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

#[test]
fn path_filter_only_emits_matching_scala_callers() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "example/Helpers.scala",
            r#"package example

object Helpers {
  def help(): Int = 1
}
"#,
        )
        .file(
            "example/Kept.scala",
            r#"package example

class Kept {
  def call(): Int = Helpers.help()
}
"#,
        )
        .file(
            "example/Ignored.scala",
            r#"package example

class Ignored {
  def call(): Int = Helpers.help()
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), r#"{"paths":["example/Kept.scala"]}"#);
    assert!(
        has_edge(&value, "example.Kept.call", "example.Helpers$.help"),
        "kept Scala caller should still resolve object callee nodes: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "example.Ignored.call", "example.Helpers$.help"),
        "path-filtered usage_graph must not emit edges from ignored callers: {}",
        value["edges"]
    );
}

#[test]
fn scoped_usage_graph_skips_unrelated_invalid_scala_callers() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "example/Helpers.scala",
            r#"package example

object Helpers {
  def help(): Int = 1
}
"#,
        )
        .file(
            "example/Kept.scala",
            r#"package example

class Kept {
  def call(): Int = Helpers.help()
}
"#,
        )
        .file(
            "broken/Broken.scala",
            r#"package broken

class Broken {
  def nope(
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), r#"{"paths":["example/Kept.scala"]}"#);
    assert!(
        has_edge(&value, "example.Kept.call", "example.Helpers$.help"),
        "filtered Scala edge graph should not require parsing unrelated callers: {}",
        value["edges"]
    );
}

#[test]
fn object_sensitive_factory_receiver_resolves_only_constructed_type() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "example/App.scala",
            r#"package example

class Service {
  def run(): Int = 1
}

class Other {
  def run(): Int = 2
}

object Factory {
  def make(): Service = new Service()
}

class Consumer {
  def viaFactory(): Int = {
    val service = Factory.make()
    service.run()
  }
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(&value, "example.Consumer.viaFactory", "example.Service.run"),
        "factory receiver should edge only to Service.run: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "example.Consumer.viaFactory", "example.Other.run"),
        "factory receiver must not fall back to same-name Other.run: {}",
        value["edges"]
    );
}

#[test]
fn unsupported_trait_receiver_emits_no_partial_edge() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "example/App.scala",
            r#"package example

trait Runner {
  def run(): Int
}

class Service {
  def run(): Int = 1
}

class Other {
  def run(): Int = 2
}

class Consumer {
  def ambiguous(receiver: Runner): Int = receiver.run()
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    assert!(
        !has_edge(&value, "example.Consumer.ambiguous", "example.Service.run")
            && !has_edge(&value, "example.Consumer.ambiguous", "example.Other.run"),
        "unsupported trait receiver must not emit partial same-name edges: {}",
        value["edges"]
    );
}

#[test]
fn overloaded_factory_receiver_emits_no_partial_edge() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "example/App.scala",
            r#"package example

class Service {
  def run(): Int = 1
}

class Other {
  def run(): Int = 2
}

object Factory {
  def make(value: Int): Service = new Service()
  def make(value: String): Other = new Other()
}

class Consumer {
  def caller(): Int = {
    val service = Factory.make(1)
    service.run()
  }
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    assert!(
        !has_edge(&value, "example.Consumer.caller", "example.Service.run")
            && !has_edge(&value, "example.Consumer.caller", "example.Other.run"),
        "overloaded factory receiver must not choose a same-arity return type by traversal order: {}",
        value["edges"]
    );
}
