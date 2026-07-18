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
fn usage_graph_resolves_structured_scala_field_chains() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "model/Fields.scala",
            r#"package model
class Leaf(val token: Int) { def read(): Int = token }
class Middle(val leaf: Leaf)
class Base(val inherited: Middle)
class Child extends Base(new Middle(new Leaf(1))) {
  def inheritedBare: Int = inherited.leaf.token
  def inheritedShadow(inherited: other.Middle): Int = inherited.leaf.token
}
object Stable { val middle: Middle = new Middle(new Leaf(2)) }
object Owners { final class State(val leaf: Leaf) }
"#,
        )
        .file(
            "other/Fields.scala",
            "package other\nclass Leaf(val token: Int)\nclass Middle(val leaf: Leaf)\n",
        )
        .file(
            "dup/First.scala",
            "package dup\nclass Owner(val value: Int)\n",
        )
        .file(
            "dup/Second.scala",
            "package dup\nclass Owner(val value: Int)\n",
        )
        .file(
            "app/Use.scala",
            r#"package app
import model.{Child, Middle, Owners, Stable}
object Use {
  def typed(middle: Middle): Int = middle.leaf.read()
  def inherited(child: Child): Int = child.inherited.leaf.read()
  def stable: Int = Stable.middle.leaf.read()
  def nested: Int = { val state = new Owners.State(new model.Leaf(1)); state.leaf.read() }
  def localShadow(middle: other.Middle): Int = middle.leaf.read()
  def ambiguous(owner: dup.Owner): Int = owner.value
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    for caller in [
        "app.Use$.typed",
        "app.Use$.inherited",
        "app.Use$.stable",
        "app.Use$.nested",
    ] {
        assert!(has_edge(&value, caller, "model.Leaf.read"), "{value}");
    }
    assert!(!has_edge(
        &value,
        "model.Child.inheritedShadow",
        "model.Leaf.read"
    ));
    assert!(!has_edge(&value, "app.Use$.localShadow", "model.Leaf.read"));
    assert!(!has_edge(&value, "app.Use$.ambiguous", "dup.Owner.value"));
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
fn ordered_parameter_lists_gate_scala_inverted_callable_edges() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "example/Calls.scala",
            r#"package example

class Api {
  def curried(value: Int)(label: String = "default"): Int = value
  def gathered(prefix: Int = 0)(values: String*): Int = prefix
}

class Consumer(api: Api) {
  def validCurried(): Int = api.curried(1)()
  def invalidFirstList(): Int = api.curried()("missing")
  def invalidSecondList(): Int = api.curried(1)("too", "many")
  def partialUnique(): String => Int = api.curried(1)
  def validDefaultsAndRepeated(): Int = api.gathered()("one", "two")
  def invalidDefaultedList(): Int = api.gathered(1, 2)("one")
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(
            &value,
            "example.Consumer.validCurried",
            "example.Api.curried"
        ),
        "valid ordered call lists should resolve: {}",
        value["edges"]
    );
    assert!(
        has_edge(
            &value,
            "example.Consumer.partialUnique",
            "example.Api.curried"
        ),
        "a unique callable may be structurally unapplied after a valid prefix: {}",
        value["edges"]
    );
    assert!(
        !has_edge(
            &value,
            "example.Consumer.invalidFirstList",
            "example.Api.curried"
        ),
        "invalid first list must not resolve: {}",
        value["edges"]
    );
    assert!(
        !has_edge(
            &value,
            "example.Consumer.invalidSecondList",
            "example.Api.curried"
        ),
        "invalid second list must not resolve: {}",
        value["edges"]
    );
    assert!(
        has_edge(
            &value,
            "example.Consumer.validDefaultsAndRepeated",
            "example.Api.gathered"
        ),
        "defaults and repeated parameters must apply independently per list: {}",
        value["edges"]
    );
    assert!(
        !has_edge(
            &value,
            "example.Consumer.invalidDefaultedList",
            "example.Api.gathered"
        ),
        "an invalid defaulted list must fail closed before the repeated list: {}",
        value["edges"]
    );
}

#[test]
fn scala_inverted_type_edges_preserve_class_and_object_identity_roles() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "example/Token.scala",
            r#"package example

class Token
object Token {
  class Nested
  def unapply(value: (String, String)): Option[(String, String)] = Some(value)
}

class Consumer {
  def classOnly(value: Token): Token = new Token
  def objectBare(): Token.type = Token
  def nestedOwner(): Token.Nested = new Token.Nested
  def extractor(value: String): String = value match {
    case Token(found) => found
    case _ => value
  }
  def infixExtractor(value: (String, String)): String = value match {
    case left Token right => left + right
    case _ => ""
  }
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(&value, "example.Consumer.classOnly", "example.Token"),
        "class type/construction roles should edge to the class: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "example.Consumer.classOnly", "example.Token$"),
        "class-only roles must not edge to the companion object: {}",
        value["edges"]
    );
    for caller in [
        "example.Consumer.objectBare",
        "example.Consumer.nestedOwner",
        "example.Consumer.extractor",
        "example.Consumer.infixExtractor",
    ] {
        assert!(
            has_edge(&value, caller, "example.Token$"),
            "object role in {caller} should edge to the companion object: {}",
            value["edges"]
        );
        assert!(
            !has_edge(&value, caller, "example.Token"),
            "object role in {caller} must not edge to the class: {}",
            value["edges"]
        );
    }
}

#[test]
fn scala_inverted_type_edges_include_mixin_and_infix_type_roles_only() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "model/Roles.scala",
            r#"package model

class Base
trait First
trait InHandler
trait OutHandler
object InHandler

infix abstract class CanEqual[A, B]
object CanEqual
"#,
        )
        .file(
            "app/Use.scala",
            r#"package app

import model.{Base, First, InHandler, OutHandler, CanEqual}

object Use {
  def mixinRole(): Base =
    new Base with First with InHandler with OutHandler {}

  def infixTypeRole[A, B](evidence: A CanEqual B): Unit = ()

  def termObjectRole: Any = InHandler
  def ordinaryInfix(left: String, right: String): String = left CanEqual right
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(&value, "app.Use$.mixinRole", "model.InHandler"),
        "anonymous mixin RHS should edge to the exact trait: {}",
        value["edges"]
    );
    assert!(
        has_edge(&value, "app.Use$.infixTypeRole", "model.CanEqual"),
        "infix_type operator should edge to the exact type constructor: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "app.Use$.termObjectRole", "model.InHandler"),
        "term object role must not edge to its companion trait: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "app.Use$.ordinaryInfix", "model.CanEqual"),
        "ordinary term infix operator must not become a type role: {}",
        value["edges"]
    );
}

#[test]
fn scala_inverted_companion_nested_and_wildcard_object_roles_are_exact() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Owners.scala",
            r#"package app
class Token { def make(): Token = this }
object Token { def make(): Token = new Token }
object Outer {
  def make(): Int = 1
  object Inner { def make(): Int = 2 }
}
object Shared
class Holder { val Shared: Int = 1 }
object Use {
  def companion(): Token = Token.make()
  def nested(): Outer.Inner.type = Outer.Inner
  def nestedCall(): Int = Outer.Inner.make()
  def unqualifiedNested = Inner
  def instanceField(holder: Holder): Int = holder.Shared
}
"#,
        )
        .file("left/Shared.scala", "package left\nobject Shared { def make(): Int = 1 }\n")
        .file("right/Shared.scala", "package right\nobject Shared { def make(): Int = 2 }\n")
        .file(
            "app/Ambiguous.scala",
            "package app\nimport left._\nimport right._\nobject Ambiguous {\n  def bare(): Shared.type = Shared\n  def call(): Int = Shared.make()\n}\n",
        )
        .file(
            "app/Explicit.scala",
            "package app\nimport left.Shared\nimport right._\nobject Explicit { def call(): Int = Shared.make() }\n",
        )
        .build();
    let value = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(&value, "app.Use$.companion", "app.Token$.make"),
        "{}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "app.Use$.companion", "app.Token.make"),
        "{}",
        value["edges"]
    );
    assert!(
        has_edge(&value, "app.Use$.nested", "app.Outer$.Inner$"),
        "{}",
        value["edges"]
    );
    assert!(
        has_edge(&value, "app.Use$.nestedCall", "app.Outer$.Inner$.make"),
        "{}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "app.Use$.nestedCall", "app.Outer$.make"),
        "{}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "app.Use$.unqualifiedNested", "app.Outer$.Inner$"),
        "{}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "app.Use$.instanceField", "app.Shared$"),
        "{}",
        value["edges"]
    );
    for callee in ["left.Shared$", "right.Shared$"] {
        assert!(
            !has_edge(&value, "app.Ambiguous$.bare", callee),
            "{callee}: {}",
            value["edges"]
        );
    }
    for callee in ["left.Shared$.make", "right.Shared$.make"] {
        assert!(
            !has_edge(&value, "app.Ambiguous$.call", callee),
            "{callee}: {}",
            value["edges"]
        );
    }
    assert!(
        has_edge(&value, "app.Explicit$.call", "left.Shared$.make"),
        "{}",
        value["edges"]
    );
}

#[test]
fn scala_inverted_graph_honors_method_and_anonymous_local_import_contexts() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Owner.scala",
            r#"package app
object Owner {
  private class RetryTick
  private object RetryTick
}
"#,
        )
        .file("other/RetryTick.scala", "package other\nobject RetryTick\n")
        .file(
            "app/Consumer.scala",
            r#"package app
class Consumer {
  def methodLocal: Any = {
    import Owner._
    accept(RetryTick)
  }
  def anonymousLocal: Any = new Runnable {
    import Owner._
    def run(): Unit = accept(RetryTick)
  }
  def aliasLocal: Any = {
    import Owner.{RetryTick => AliasTick}
    accept(AliasTick)
  }
  def beforeImport: Any = {
    accept(RetryTick)
    import Owner._
  }
  def siblingScope: Any = {
    { import Owner._; accept(RetryTick) }
    accept(RetryTick)
  }
  def shadowed: Any = {
    import Owner._
    val RetryTick = other.RetryTick
    accept(RetryTick)
  }
  def ambiguous: Any = {
    import Owner._
    import other._
    accept(RetryTick)
  }
  def absent: Any = accept(RetryTick)
  private def accept(value: Any): Any = value
}
"#,
        )
        .build();
    let value = usage_graph_at(project.root(), "{}");

    for caller in [
        "app.Consumer.methodLocal",
        "app.Consumer.anonymousLocal",
        "app.Consumer.aliasLocal",
        "app.Consumer.siblingScope",
    ] {
        assert!(
            has_edge(&value, caller, "app.Owner$.RetryTick$"),
            "{caller} should edge to the exact imported object: {}",
            value["edges"]
        );
        assert!(
            !has_edge(&value, caller, "app.Owner$.RetryTick"),
            "{caller} must not edge to the same-name class: {}",
            value["edges"]
        );
    }
    for caller in [
        "app.Consumer.beforeImport",
        "app.Consumer.shadowed",
        "app.Consumer.ambiguous",
        "app.Consumer.absent",
    ] {
        assert!(
            !has_edge(&value, caller, "app.Owner$.RetryTick$"),
            "{caller} must not see the target object: {}",
            value["edges"]
        );
    }
}

#[test]
fn scala_inverted_applies_compilation_unit_import_precedence() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Shared.scala",
            "package app\nobject Shared { def make(): Int = 0 }\n",
        )
        .file(
            "left/Shared.scala",
            "package left\nobject Shared { def make(): Int = 1 }\n",
        )
        .file(
            "app/WildcardWins.scala",
            "package app\nimport left._\nobject WildcardWins { def call(): Int = Shared.make() }\n",
        )
        .build();
    let value = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(&value, "app.WildcardWins$.call", "left.Shared$.make"),
        "{}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "app.WildcardWins$.call", "app.Shared$.make"),
        "{}",
        value["edges"]
    );

    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "left/Shared.scala",
            "package left\nobject Shared { def make(): Int = 1 }\n",
        )
        .file(
            "app/LocalWins.scala",
            "package app\nimport left.Shared\nobject Shared { def make(): Int = 2 }\nobject LocalWins { def call(): Int = Shared.make() }\n",
        )
        .build();
    let value = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(&value, "app.LocalWins$.call", "app.Shared$.make"),
        "{}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "app.LocalWins$.call", "left.Shared$.make"),
        "{}",
        value["edges"]
    );
}

#[test]
fn scala_inverted_resolves_generic_lexical_constructors_and_stable_paths() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "model/Flags.scala",
            r#"package model
object Flags {
  val Enabled: Int = 1
  case object Nested
}
"#,
        )
        .file(
            "app/Use.scala",
            r#"package app

import model.Flags

object Use {
  class Generic[A](value: A)

  def validGeneric = new Generic[Int](1)
  def wrongGenericArity = new Generic[Int]()
  def localConstructorRoot(Generic: LocalFactory) = new Generic[Int](1)
  def directField: Int = Flags.Enabled
  def stableField(value: Any): Int = value match {
    case Flags.Enabled => 1
    case model.Flags.Enabled => 2
    case _ => 0
  }
  def stableObject(value: Any): Int = value match {
    case Flags.Nested => 1
    case model.Flags.Nested => 2
    case _ => 0
  }
  def localRootIsNotImported(Flags: LocalFlags): Int = Flags.Enabled
  def decoyObject(value: Any): Int = value match {
    case decoy.Flags.Nested => 1
    case _ => 0
  }
}

class LocalFlags { val Enabled: Int = 2 }
class LocalFactory
"#,
        )
        .file(
            "decoy/Flags.scala",
            r#"package decoy
object Flags {
  val Enabled: Int = 2
  case object Nested
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(&value, "app.Use$.validGeneric", "app.Use$.Generic"),
        "{}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "app.Use$.wrongGenericArity", "app.Use$.Generic"),
        "{}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "app.Use$.localConstructorRoot", "app.Use$.Generic"),
        "{}",
        value["edges"]
    );
    assert!(
        has_edge(&value, "app.Use$.stableObject", "model.Flags$.Nested$"),
        "{}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "app.Use$.decoyObject", "model.Flags$.Nested$"),
        "{}",
        value["edges"]
    );
}

#[test]
fn scala_inverted_matches_all_same_file_overloads_and_curried_constructor_lists() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Calls.scala",
            r#"package app
class Api {
  def route(value: Int, label: String): Int = value
  def route(value: Int): Int = value
  def flip(value: Int): Int = value
  def flip(value: Int, label: String): Int = value
}
class Curried(value: Int)(label: String = "default")
class Use(api: Api) {
  def routeOne(): Int = api.route(1)
  def routeTwo(): Int = api.route(1, "two")
  def routeNone(): Int = api.route()
  def routeThree(): Int = api.route(1, "two", "three")
  def routePartial(): Int => Int = api.route
  def flipOne(): Int = api.flip(1)
  def flipTwo(): Int = api.flip(1, "two")
  def flipNone(): Int = api.flip()
  def flipThree(): Int = api.flip(1, "two", "three")
  def flipPartial(): Int => Int = api.flip
  def validConstructor(): Any = new Curried(1)()
  def invalidFirstConstructor(): Any = new Curried()("missing")
  def invalidLaterConstructor(): Any = new Curried(1)("too", "many")
}
"#,
        )
        .build();
    let value = usage_graph_at(project.root(), "{}");
    for (method, valid, invalid) in [
        (
            "route",
            ["app.Use.routeOne", "app.Use.routeTwo"],
            [
                "app.Use.routeNone",
                "app.Use.routeThree",
                "app.Use.routePartial",
            ],
        ),
        (
            "flip",
            ["app.Use.flipOne", "app.Use.flipTwo"],
            [
                "app.Use.flipNone",
                "app.Use.flipThree",
                "app.Use.flipPartial",
            ],
        ),
    ] {
        for caller in valid {
            assert!(
                has_edge(&value, caller, &format!("app.Api.{method}")),
                "{}",
                value["edges"]
            );
        }
        for caller in invalid {
            assert!(
                !has_edge(&value, caller, &format!("app.Api.{method}")),
                "{}",
                value["edges"]
            );
        }
    }
    assert!(
        has_edge(&value, "app.Use.validConstructor", "app.Curried"),
        "{}",
        value["edges"]
    );
    for caller in [
        "app.Use.invalidFirstConstructor",
        "app.Use.invalidLaterConstructor",
    ] {
        assert!(
            !has_edge(&value, caller, "app.Curried"),
            "{}",
            value["edges"]
        );
    }
}

#[test]
fn scala_inverted_keeps_overload_shape_receiver_and_return_facts_aligned() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Aligned.scala",
            r#"package app
class A { def run(): Int = 1 }
class B { def run(): Int = 2 }
object Factory {
  def make(value: Int): A = new A
  def make(value: Int, label: String): B = new B
}
object Extensions {
  extension (value: A) def tag(number: Int): Int = number
  extension (value: B) def tag(number: Int, label: String): Int = number
}
object Use {
  import Extensions._
  def returnA(): Int = Factory.make(1).run()
  def returnB(): Int = Factory.make(1, "b").run()
  def extensionA(value: A): Int = value.tag(1)
  def extensionB(value: B): Int = value.tag(1, "b")
  def wrongShapeA(value: A): Int = value.tag(1, "bad")
  def wrongShapeB(value: B): Int = value.tag(1)
  def unappliedA(value: A) = value.tag
}
"#,
        )
        .build();
    let value = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(&value, "app.Use$.returnA", "app.A.run"),
        "{}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "app.Use$.returnA", "app.B.run"),
        "{}",
        value["edges"]
    );
    assert!(
        has_edge(&value, "app.Use$.returnB", "app.B.run"),
        "{}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "app.Use$.returnB", "app.A.run"),
        "{}",
        value["edges"]
    );
    for caller in ["app.Use$.extensionA", "app.Use$.extensionB"] {
        assert!(
            has_edge(&value, caller, "app.Extensions$.tag"),
            "{caller}: {}",
            value["edges"]
        );
    }
    for caller in [
        "app.Use$.wrongShapeA",
        "app.Use$.wrongShapeB",
        "app.Use$.unappliedA",
    ] {
        assert!(
            !has_edge(&value, caller, "app.Extensions$.tag"),
            "{caller}: {}",
            value["edges"]
        );
    }
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
fn scala_inverted_fails_closed_for_ambiguous_declaration_type_paths() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "A.scala",
            "class A { def run(): Int = 0; class Nested { def run(): Int = 0 } }\n",
        )
        .file(
            "left/A.scala",
            "package left\nclass A { def run(): Int = 1; class Nested { def run(): Int = 1 } }\n",
        )
        .file(
            "right/A.scala",
            "package right\nclass A { def run(): Int = 2; class Nested { def run(): Int = 2 } }\n",
        )
        .file(
            "proven/Service.scala",
            "package proven\nclass Service { def run(): Int = 3 }\n",
        )
        .file(
            "app/AmbiguousReturn.scala",
            r#"package app
import left._
import right._

object Factory {
  def make(): A = ???
  def makeNested(): A.Nested = ???
  def makeProven(): proven.Service = ???
}

object Use {
  def call(): Int = Factory.make().run()
  def nestedCall(): Int = Factory.makeNested().run()
  def provenCall(): Int = Factory.makeProven().run()
}
"#,
        )
        .build();
    let value = usage_graph_at(project.root(), "{}");

    for run_fqn in ["A.run", "left.A.run", "right.A.run"] {
        assert!(
            !has_edge(&value, "app.Use$.call", run_fqn),
            "ambiguous declaration return type must not resolve to {run_fqn}: {}",
            value["edges"]
        );
    }
    for run_fqn in ["A.Nested.run", "left.A.Nested.run", "right.A.Nested.run"] {
        assert!(
            !has_edge(&value, "app.Use$.nestedCall", run_fqn),
            "ambiguous qualified declaration return type must not resolve to {run_fqn}: {}",
            value["edges"]
        );
    }
    assert!(
        has_edge(&value, "app.Use$.provenCall", "proven.Service.run"),
        "a structurally proven package prefix should resolve: {}",
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

#[test]
fn qualified_stable_type_paths_emit_exact_inverse_edges() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "model/Structure.scala",
            r#"package model

object Structure {
  case class Value(value: Int)
  object Deep { class Leaf }
}
"#,
        )
        .file(
            "decoy/Structure.scala",
            r#"package decoy

object Structure {
  case class Value(value: Int)
  object Deep { class Leaf }
}
"#,
        )
        .file(
            "app/Use.scala",
            r#"package app

import model.Structure

object Use {
  def typed: Option[Structure.Value] = None
  def created = new Structure.Value(1)
  def wrongConstructor = new Structure.Value(1, 2)
  def applied = Structure.Value(2)
  def wrongApply = Structure.Value(2, 3)
  def extracted(value: Structure.Value): Int = value match {
    case Structure.Value(number) => number
  }
  def deep: Option[Structure.Deep.Leaf] = None
}
"#,
        )
        .file(
            "app/Alias.scala",
            r#"package app

import model.{Structure as Schema}

object Alias {
  def typed: Option[Schema.Value] = None
  def deep: Option[Schema.Deep.Leaf] = None
}
"#,
        )
        .file(
            "app/PackageRoot.scala",
            r#"package app

object PackageRoot {
  def typed: Option[model.Structure.Value] = None
  def deep: Option[model.Structure.Deep.Leaf] = None
}
"#,
        )
        .file(
            "decoy/Use.scala",
            r#"package decoy

object Use {
  def typed: Option[Structure.Value] = None
  def applied = Structure.Value(3)
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    let target = "model.Structure$.Value";
    for caller in [
        "app.Use$.typed",
        "app.Use$.created",
        "app.Use$.applied",
        "app.Use$.extracted",
        "app.Alias$.typed",
        "app.PackageRoot$.typed",
    ] {
        assert!(
            has_edge(&value, caller, target),
            "expected {caller} -> {target}: {}",
            value["edges"]
        );
    }
    for caller in ["app.Use$.wrongConstructor", "app.Use$.wrongApply"] {
        assert!(
            !has_edge(&value, caller, target),
            "wrong-arity {caller} must not edge to {target}: {}",
            value["edges"]
        );
    }
    assert!(
        !has_edge(&value, "decoy.Use$.typed", target)
            && !has_edge(&value, "decoy.Use$.applied", target),
        "same-name decoy must not edge to {target}: {}",
        value["edges"]
    );

    let leaf = "model.Structure$.Deep$.Leaf";
    for caller in ["app.Use$.deep", "app.Alias$.deep", "app.PackageRoot$.deep"] {
        assert!(
            has_edge(&value, caller, leaf),
            "expected {caller} -> {leaf}: {}",
            value["edges"]
        );
    }
}
