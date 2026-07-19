mod common;

use brokk_bifrost::Language;
use common::{InlineTestProject, call_search_tool_json};
use serde_json::{Value, json};

const APP_SOURCE: &str = r#"package app

object Wrong {
  class expr
  class result
  class kind
  object None
  class String
  class Int { def <(other: Int): Boolean = false }
}

final case class DependencyDescription(kind: Int)

object App {
  def run(expr: String, kind: Int): String = {
    val result: String = expr
    val dependency = DependencyDescription(kind = kind)
    result
  }

  val empty = None
  def less(left: Int): Boolean = left < 2
}
"#;

fn location(source: &str, needle: &str) -> Value {
    let start = source.rfind(needle).expect("reference text");
    location_at(source, start)
}

fn location_at(source: &str, start: usize) -> Value {
    location_in("app/App.scala", source, start)
}

fn location_in(path: &str, source: &str, start: usize) -> Value {
    let prefix = &source[..start];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = prefix
        .rsplit_once('\n')
        .map_or(prefix, |(_, current)| current)
        .chars()
        .count()
        + 1;
    json!({"path": path, "line": line, "column": column})
}

#[test]
fn scala_location_definition_returns_parameters_without_guessing_other_namespaces() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/App.scala", APP_SOURCE)
        .build();
    let references = vec![
        location(APP_SOURCE, "expr\n"),
        location(APP_SOURCE, "kind)\n"),
        location(APP_SOURCE, "result\n"),
        location(APP_SOURCE, "None\n"),
        location(APP_SOURCE, "String, kind"),
        location(APP_SOURCE, "< 2"),
    ];
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({"references": references}).to_string(),
    );

    assert_eq!(
        value["results"].as_array().map(Vec::len),
        Some(6),
        "{value}"
    );
    let results = value["results"].as_array().expect("definition results");
    for (result, name) in [(&results[0], "expr"), (&results[1], "kind")] {
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(result["definitions"][0]["name"], name, "{value}");
        assert_eq!(result["definitions"][0]["kind"], "parameter", "{value}");
        assert!(result["definitions"][0].get("fqn").is_none(), "{value}");
    }
    assert_eq!(results[2]["status"], "no_definition", "{value}");
    assert_eq!(
        results[2]["diagnostics"][0]["kind"], "local_binding",
        "{value}"
    );
    for result in &results[3..] {
        assert_eq!(result["status"], "no_definition", "{value}");
    }
}

#[test]
fn scala_reference_definition_keeps_parameter_a_local_identity() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/App.scala", APP_SOURCE)
        .build();
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_reference",
        &json!({
            "references": [{
                "symbol": "app.App$.run",
                "context": "    val result: String = expr",
                "target": "expr"
            }]
        })
        .to_string(),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
    assert_eq!(
        value["results"][0]["diagnostics"][0]["kind"], "local_binding_requires_location",
        "{value}"
    );
}

#[test]
fn scala_term_namespace_resolves_explicitly_imported_stable_object() {
    let consumer = "package app\nimport terms.None\nobject Consumer { val empty = None }\n";
    let project = InlineTestProject::with_language(Language::Scala)
        .file("terms/None.scala", "package terms\nobject None\n")
        .file(
            "app/Wrong.scala",
            "package app\nobject Wrong { object None }\n",
        )
        .file("app/Consumer.scala", consumer)
        .build();
    let start = consumer.rfind("None").expect("stable object reference");
    let prefix = &consumer[..start];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = prefix
        .rsplit_once('\n')
        .map_or(prefix, |(_, current)| current)
        .chars()
        .count()
        + 1;
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({
            "references": [{"path": "app/Consumer.scala", "line": line, "column": column}]
        })
        .to_string(),
    );

    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "terms.None$",
        "{value}"
    );
}

#[test]
fn scala_location_definition_accepts_inherited_default_argument_call() {
    let source = r#"package app

class Base {
  def doTest(text: String, result: String, settings: String = "default"): Unit = ()
}
class Child extends Base {
  doTest("text", "result")
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/Api.scala", source)
        .build();
    let start = source.rfind("doTest").expect("inherited call");
    let prefix = &source[..start];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = prefix
        .rsplit_once('\n')
        .map_or(prefix, |(_, current)| current)
        .chars()
        .count()
        + 1;
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({
            "references": [{"path": "app/Api.scala", "line": line, "column": column}]
        })
        .to_string(),
    );

    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "app.Base.doTest",
        "{value}"
    );
}

#[test]
fn scala_local_pattern_and_recursive_function_bindings_block_indexed_collisions() {
    let source = r#"package app

object Imported {
  def loop(value: Int): Int = value
  val messages: Int = 99
}

final case class Success(messages: Int)

object Consumer {
  import Imported.{loop, messages}

  def run(result: Success): Int = {
    def loop(value: Int): Int =
      if value == 0 then value else loop(value - 1)

    result match {
      case Success(messages) => loop(messages)
    }
  }
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/App.scala", source)
        .build();
    let references = ["loop(value - 1)", "loop(messages)", "messages)\n"]
        .into_iter()
        .map(|needle| location(source, needle))
        .collect::<Vec<_>>();
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({"references": references}).to_string(),
    );

    for result in value["results"].as_array().expect("definition results") {
        assert_eq!(result["status"], "no_definition", "{value}");
        assert!(result["definitions"].is_null(), "{value}");
        assert_eq!(
            result["diagnostics"][0]["kind"], "local_variable_reference",
            "{value}"
        );
    }
}

#[test]
fn scala_typed_pattern_binding_starts_after_its_type_annotation() {
    let source = r#"package app
import model.{Root => owner}
import model.Other.flag

object Use {
  def sameRootName(input: Any): Any = input match {
    case owner: owner.Nested if owner != null => owner
  }

  def bodyBinding(input: Any): Any = input match {
    case flag: owner.Nested if flag != null => flag
  }

  def priorShadow(input: Any): Any = {
    val owner = new model.Shadow
    input match { case value: owner.Nested => value }
  }
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "model/Root.scala",
            r#"package model
object Root { final class Nested(val id: Int) }
final class Shadow
object Other { val flag: Any = new Object }
"#,
        )
        .file("app/Use.scala", source)
        .build();
    let type_reference =
        source.find("owner.Nested").expect("same-name binder type") + "owner.".len();
    let body_owner =
        source.find("null => owner").expect("same-name binder body") + "null => ".len();
    let guard_flag = source.find("if flag").expect("guard binder reference") + "if ".len();
    let shadowed_type = source.rfind("owner.Nested").expect("prior-shadowed type") + "owner.".len();
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({"references": [
            location_in("app/Use.scala", source, type_reference),
            location_in("app/Use.scala", source, body_owner),
            location_in("app/Use.scala", source, guard_flag),
            location_in("app/Use.scala", source, shadowed_type),
        ]})
        .to_string(),
    );
    let results = value["results"].as_array().expect("definition results");
    assert_eq!(results[0]["status"], "resolved", "{value}");
    assert_eq!(
        results[0]["definitions"][0]["fqn"], "model.Root$.Nested",
        "{value}"
    );
    for result in &results[1..3] {
        assert_eq!(result["status"], "no_definition", "{value}");
        assert_eq!(
            result["diagnostics"][0]["kind"], "local_variable_reference",
            "{value}"
        );
    }
    assert_eq!(results[3]["status"], "no_definition", "{value}");
}

#[test]
fn scala_for_generator_binding_shadows_import_only_after_its_source_expression() {
    let source = r#"package app

import lib.Factory.typeText

object Consumer {
  def run: String =
    for
      typeText <- typeText("source")
      preserved = typeText
    yield typeText
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "lib/Factory.scala",
            "package lib\nobject Factory { def typeText(value: String): String = value }\n",
        )
        .file("app/App.scala", source)
        .build();
    let rhs = source
        .find("typeText(\"source\")")
        .expect("generator source call");
    let subsequent = source
        .find("preserved = typeText")
        .expect("subsequent enumerator")
        + "preserved = ".len();
    let yielded = source.rfind("typeText").expect("yielded generator binding");
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({
            "references": [
                location_at(source, rhs),
                location_at(source, subsequent),
                location_at(source, yielded)
            ]
        })
        .to_string(),
    );

    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "lib.Factory$.typeText",
        "{value}"
    );
    for result in &value["results"].as_array().expect("definition results")[1..] {
        assert_eq!(result["status"], "no_definition", "{value}");
        assert_eq!(result["diagnostics"][0]["kind"], "local_binding", "{value}");
    }
}

#[test]
fn scala_qualified_owner_paths_preserve_nested_and_namespace_identity() {
    let source = r#"package app

class Entry
class Map
class LongMap
class Data

object Outer {
  class Entry
}

object view {
  class Map
}

object mutable {
  class LongMap
}

object Namespace {
  object Cache {
    class Data
  }
  object State {
    val data: Cache.Data = new Cache.Data
  }
}

object Consumer {
  val nested: Outer.Entry = new Outer.Entry
  val mapped: view.Map = new view.Map
  val mutableMap: mutable.LongMap = new mutable.LongMap
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/App.scala", source)
        .build();
    let references = [
        ("Outer.Entry =", "Outer.".len()),
        ("view.Map =", "view.".len()),
        ("mutable.LongMap =", "mutable.".len()),
        ("Cache.Data =", "Cache.".len()),
    ]
    .into_iter()
    .map(|(marker, terminal_offset)| {
        location_at(
            source,
            source.find(marker).expect("unique qualified type") + terminal_offset,
        )
    })
    .collect::<Vec<_>>();
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({"references": references}).to_string(),
    );

    let expected = [
        "app.Outer$.Entry",
        "app.view$.Map",
        "app.mutable$.LongMap",
        "app.Namespace$.Cache$.Data",
    ];
    for (result, expected) in value["results"]
        .as_array()
        .expect("definition results")
        .iter()
        .zip(expected)
    {
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(result["definitions"][0]["fqn"], expected, "{value}");
    }
}

#[test]
fn scala_qualified_constructor_prefers_active_outer_package_over_root_decoy() {
    let source = r#"package scala.collection.immutable
package test

object RedBlackTreeTests {
  val t1 = new RedBlackTree.Tree[Int, String]("value")
  val extracted = t1.value
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "library/RedBlackTree.scala",
            r#"package scala.collection.immutable

object RedBlackTree {
  final class Tree[K, V](val value: V)
}
"#,
        )
        .file(
            "fixtures/RedBlackTree.scala",
            r#"object RedBlackTree {
  final class Tree[K, V](val value: V)
}
"#,
        )
        .file("app/App.scala", source)
        .build();
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({
            "references": [location_at(
                source,
                source.rfind("value").expect("qualified receiver member")
            )]
        })
        .to_string(),
    );

    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"],
        "scala.collection.immutable.RedBlackTree$.Tree.value",
        "{value}"
    );
    assert_eq!(
        value["results"][0]["definitions"][0]["path"], "library/RedBlackTree.scala",
        "{value}"
    );
}

#[test]
fn scala_type_namespace_resolves_imported_and_lexically_enclosing_aliases() {
    let browser = r#"package kyo.browser

import kyo.internal.*

object Browser {
  def first(value: Selector): Selector = value
}
"#;
    let fiber = r#"package kyo

object Fiber {
  object Promise {
    opaque type Unsafe = String
    object Unsafe

    def keep(value: Unsafe): Unsafe = value
    val term = Unsafe
  }
}
"#;
    let yaml = r#"package kyo

object Yaml {
  opaque type DocumentIndex = Int
  object DocumentIndex

  def index(value: DocumentIndex): DocumentIndex = value
}
"#;
    let include = r#"package dotty.tools.dotc.interactive

import scala.collection.*

object Interactive {
  object Include {
    class Set
    val typed: Set = new Set
  }
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "kyo/internal/Selector.scala",
            "package kyo.internal\nopaque type Selector = String\n",
        )
        .file("kyo/Selector.scala", "package kyo\nclass Selector\n")
        .file("kyo/browser/Browser.scala", browser)
        .file("kyo/Fiber.scala", fiber)
        .file("kyo/Yaml.scala", yaml)
        .file(
            "scala/collection/Set.scala",
            "package scala.collection\nclass Set\n",
        )
        .file("dotty/Interactive.scala", include)
        .build();
    let references = vec![
        location_in(
            "kyo/browser/Browser.scala",
            browser,
            browser.find("Selector").expect("first imported alias"),
        ),
        location_in(
            "kyo/browser/Browser.scala",
            browser,
            browser.rfind("Selector").expect("second imported alias"),
        ),
        location_in(
            "kyo/Fiber.scala",
            fiber,
            fiber.rfind("Unsafe = value").expect("return alias"),
        ),
        location_in(
            "kyo/Yaml.scala",
            yaml,
            yaml.rfind("DocumentIndex = value")
                .expect("same-scope alias"),
        ),
        location_in(
            "dotty/Interactive.scala",
            include,
            include.find("Set =").expect("enclosing type"),
        ),
        location_in(
            "dotty/Interactive.scala",
            include,
            include.rfind("Set").expect("enclosing constructor"),
        ),
    ];
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({"references": references}).to_string(),
    );

    let expected = [
        "kyo.internal.Selector",
        "kyo.internal.Selector",
        "kyo.Fiber$.Promise$.Unsafe",
        "kyo.Yaml$.DocumentIndex",
        "dotty.tools.dotc.interactive.Interactive$.Include$.Set",
        "dotty.tools.dotc.interactive.Interactive$.Include$.Set",
    ];
    for (result, expected) in value["results"]
        .as_array()
        .expect("definition results")
        .iter()
        .zip(expected)
    {
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(result["definitions"][0]["fqn"], expected, "{value}");
    }

    let term = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({"references": [location_in(
            "kyo/Fiber.scala",
            fiber,
            fiber.rfind("Unsafe").expect("term companion")
        )]})
        .to_string(),
    );
    assert_eq!(term["results"][0]["status"], "resolved", "{term}");
    assert_eq!(
        term["results"][0]["definitions"][0]["fqn"], "kyo.Fiber$.Promise$.Unsafe$",
        "{term}"
    );
}

#[test]
fn scala_unindexed_local_type_bindings_fail_closed_before_global_types() {
    let source = r#"package app

class Collision
class ParameterCollision

object Consumer {
  def local: Unit = {
    type Collision = String
    val value: Collision = "value"
  }

  def generic[ParameterCollision](value: ParameterCollision): ParameterCollision = value
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/App.scala", source)
        .build();
    let local = source
        .rfind("Collision = \"")
        .expect("local alias reference");
    let parameter = source
        .find("value: ParameterCollision")
        .expect("type parameter reference")
        + "value: ".len();
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({"references": [location_at(source, local), location_at(source, parameter)]})
            .to_string(),
    );

    for result in value["results"].as_array().expect("definition results") {
        assert_eq!(result["status"], "no_definition", "{value}");
        assert_eq!(
            result["diagnostics"][0]["kind"], "local_type_binding",
            "{value}"
        );
    }
}
