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
fn path_filter_resolves_imported_extension_methods() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Syntax.scala",
            r#"package app

object Syntax:
  extension (value: String)
    def slug(): String = value.toLowerCase
"#,
        )
        .file(
            "app/Kept.scala",
            r#"package app

object Kept:
  import Syntax.*
  def call(): String = "Hello World".slug()
"#,
        )
        .file(
            "app/Ignored.scala",
            r#"package app

object Ignored:
  import Syntax.*
  def call(): String = "Goodbye".slug()
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), r#"{"paths":["app/Kept.scala"]}"#);
    assert!(
        has_edge(&value, "app.Kept$.call", "app.Syntax$.slug"),
        "path-filtered Scala graph should resolve extension methods imported by scanned files: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "app.Ignored$.call", "app.Syntax$.slug"),
        "path-filtered Scala graph must not emit extension edges from ignored callers: {}",
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
fn trait_method_receivers_and_overrides_emit_structured_edges() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "example/App.scala",
            r#"package example

trait Renderer {
  def render(value: String): String
}

class ConsoleRenderer extends Renderer {
  override def render(value: String): String = value.trim
  def render(): String = "empty"
}

class OtherRenderer {
  def render(value: String): String = value
}

class Consumer {
  def viaTrait(renderer: Renderer, value: String): String = renderer.render(value)
  def viaConcrete(console: ConsoleRenderer, value: String): String = console.render(value)
  def overload(console: ConsoleRenderer): String = console.render()
  def unrelated(other: OtherRenderer, value: String): String = other.render(value)
}

object ConsoleRenderer {
  def default: ConsoleRenderer = new ConsoleRenderer()
}

object App {
  import ConsoleRenderer.{default => renderer}

  def direct(): String = renderer.render("  ok ")
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(
            &value,
            "example.ConsoleRenderer.render",
            "example.Renderer.render"
        ),
        "override declaration should edge to the trait method: {}",
        value["edges"]
    );
    assert!(
        has_edge(
            &value,
            "example.Consumer.viaTrait",
            "example.Renderer.render"
        ),
        "trait-typed receiver should edge to Renderer.render: {}",
        value["edges"]
    );
    assert!(
        has_edge(
            &value,
            "example.Consumer.viaConcrete",
            "example.ConsoleRenderer.render"
        ),
        "concrete receiver should edge to ConsoleRenderer.render: {}",
        value["edges"]
    );
    assert!(
        has_edge(
            &value,
            "example.App$.direct",
            "example.ConsoleRenderer.render"
        ),
        "imported factory alias receiver should edge to ConsoleRenderer.render: {}",
        value["edges"]
    );
    assert!(
        !has_edge(
            &value,
            "example.Consumer.overload",
            "example.Renderer.render"
        ) && !has_edge(
            &value,
            "example.Consumer.unrelated",
            "example.Renderer.render"
        ),
        "overloads and unrelated same-name methods must not edge to the trait method: {}",
        value["edges"]
    );
}

#[test]
fn class_method_overrides_do_not_emit_family_edges() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "exact/App.scala",
            r#"package exact

class Base {
  def run(value: String): String = value
}

class Child extends Base {
  override def run(value: String): String = value.trim
}

class Consumer {
  def viaBase(base: Base, value: String): String = base.run(value)
  def viaChild(child: Child, value: String): String = child.run(value)
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(&value, "exact.Consumer.viaBase", "exact.Base.run"),
        "base-typed receiver should edge to Base.run: {}",
        value["edges"]
    );
    assert!(
        has_edge(&value, "exact.Consumer.viaChild", "exact.Child.run"),
        "child-typed receiver should edge to Child.run: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "exact.Child.run", "exact.Base.run"),
        "ordinary class override should not edge to base method: {}",
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

#[test]
fn factory_return_types_resolve_through_shared_type_index() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "example/App.scala",
            r#"package example

class Service {
  def run(): Int = 1
}

class Noise00
class Noise01
class Noise02
class Noise03
class Noise04
class Noise05
class Noise06
class Noise07
class Noise08
class Noise09
class Noise10
class Noise11
class Noise12
class Noise13
class Noise14
class Noise15

object Factory {
  def makeQualified(): example.Service = new Service()
  def makeLocal(): Service = new Service()
}

class Consumer {
  def viaQualified(): Int = {
    val service = Factory.makeQualified()
    service.run()
  }

  def viaLocal(): Int = {
    val service = Factory.makeLocal()
    service.run()
  }
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(
            &value,
            "example.Consumer.viaQualified",
            "example.Service.run"
        ),
        "fully-qualified factory return type should edge to Service.run: {}",
        value["edges"]
    );
    assert!(
        has_edge(&value, "example.Consumer.viaLocal", "example.Service.run"),
        "same-package factory return type should edge to Service.run: {}",
        value["edges"]
    );
}
