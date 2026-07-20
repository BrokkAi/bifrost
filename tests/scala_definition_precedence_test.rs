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
fn scala_explicit_imports_precede_wildcard_terms_for_direct_and_brace_selectors() {
    let direct = r#"package consumers
import org.scalactic._
import org.scalatest.UnquotedString
object Direct { val rendered = UnquotedString("direct") }
"#;
    let brace = r#"package consumers
import org.scalatest.{UnquotedString}
import org.scalactic._
object Brace { val rendered = UnquotedString("brace") }
"#;
    let external = r#"package consumers
import akka.event.Logging._
import org.slf4j.MDC
object External { MDC.put("key", "value") }
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "org/scalactic/UnquotedString.scala",
            "package org.scalactic\nclass UnquotedString\nobject UnquotedString { def apply(value: String): UnquotedString = new UnquotedString }\n",
        )
        .file(
            "org/scalatest/UnquotedString.scala",
            "package org.scalatest\nclass UnquotedString\nobject UnquotedString { def apply(value: String): UnquotedString = new UnquotedString }\n",
        )
        .file(
            "akka/event/Logging.scala",
            "package akka.event\nobject Logging { object MDC { def put(key: String, value: String): Unit = () } }\n",
        )
        .file("consumers/Direct.scala", direct)
        .file("consumers/Brace.scala", brace)
        .file("consumers/External.scala", external)
        .build();
    let references = [
        location_in(
            "consumers/Direct.scala",
            direct,
            direct.rfind("UnquotedString").expect("direct call"),
        ),
        location_in(
            "consumers/Brace.scala",
            brace,
            brace.rfind("UnquotedString").expect("brace call"),
        ),
        location_in(
            "consumers/External.scala",
            external,
            external.rfind("MDC.put").expect("external receiver"),
        ),
    ];
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({"references": references}).to_string(),
    );
    let results = value["results"].as_array().expect("definition results");
    for result in &results[..2] {
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(
            result["definitions"][0]["fqn"], "org.scalatest.UnquotedString$.apply",
            "{value}"
        );
    }
    assert_eq!(
        results[2]["status"], "unresolvable_import_boundary",
        "{value}"
    );
    assert_eq!(
        results[2]["diagnostics"][0]["kind"], "unresolvable_import_boundary",
        "{value}"
    );
}

#[test]
fn scala_parser_proven_term_roles_precede_same_named_type_aliases() {
    let kyo = r#"package kyo

opaque type Maybe[+A] = A | Null
object Maybe {
  def apply[A](value: A): Maybe[A] = value
  opaque type Present[+A] = A
  object Present {
    def apply[A](value: A): Present[A] = value
    def unapply(value: Any): Option[Int] = None
  }
}

opaque type Path = String
object Path { def apply(value: String): Path = value }

object Result {
  opaque type Success[+A] = A
  object Success {
    def apply[A](value: A): Success[A] = value
    def unapply(value: Any): Option[Int] = None
  }
}

"#;
    let dotty = r#"package dotty.tools.dotc.ast

object tpd {
  opaque type New = String
  object New { def unapply(value: Any): Option[Int] = None }
  opaque type Block = String
  object Block { def unapply(value: Any): Option[Int] = None }
}
"#;
    let use_source = r#"package consumer

import kyo.*
import dotty.tools.dotc.ast.tpd.*

object Use {
  val maybe = Maybe(1)
  val path = Path("root")
  val success = Result.Success(1)

  def extract(value: Any): Int = value match {
    case Result.Success(found) => found
    case Maybe.Present(found)  => found
    case New(found)            => found
    case Block(found)          => found
    case _                     => 0
  }
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("kyo/Terms.scala", kyo)
        .file("dotty/tools/dotc/ast/tpd.scala", dotty)
        .file("consumer/Use.scala", use_source)
        .build();
    let at = |needle: &str| {
        location_in(
            "consumer/Use.scala",
            use_source,
            use_source.find(needle).expect("unique term-role reference"),
        )
    };
    let at_terminal = |needle: &str| {
        let start = use_source.find(needle).expect("unique qualified term role");
        location_in(
            "consumer/Use.scala",
            use_source,
            start + needle.rfind('.').expect("qualified term role") + 1,
        )
    };
    let at_last_terminal = |needle: &str| {
        let start = use_source.rfind(needle).expect("qualified extractor role");
        location_in(
            "consumer/Use.scala",
            use_source,
            start + needle.rfind('.').expect("qualified extractor role") + 1,
        )
    };
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({"references": [
            at("Maybe(1)"),
            at("Path(\"root\")"),
            at_terminal("Result.Success(1)"),
            at_last_terminal("Result.Success(found)"),
            at_last_terminal("Maybe.Present(found)"),
            at("New(found)"),
            at("Block(found)"),
        ]})
        .to_string(),
    );
    let results = value["results"].as_array().expect("definition results");
    for (result, expected) in results.iter().zip([
        "kyo.Maybe$.apply",
        "kyo.Path$.apply",
        "kyo.Result$.Success$.apply",
        "kyo.Result$.Success$.unapply",
        "kyo.Maybe$.Present$.unapply",
        "dotty.tools.dotc.ast.tpd$.New$.unapply",
        "dotty.tools.dotc.ast.tpd$.Block$.unapply",
    ]) {
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(result["definitions"][0]["fqn"], expected, "{value}");
    }
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
fn scala_qualified_type_paths_preserve_absolute_and_external_namespaces() {
    let source = r#"package app

object Use {
  val boolean: _root_.scala.Boolean = null
  val integer: _root_.scala.Int = null
  val string: _root_.scala.Predef.String = null
  val double: java.lang.Double = null
  val long: java.lang.Long = null
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "scala/Types.scala",
            "package scala\nclass Boolean\nclass Int\nobject Predef { class String }\n",
        )
        .file("java/lang/Types.scala", "package java.lang\nclass Double\n")
        .file(
            "Decoys.scala",
            "class Boolean\nclass Int\nclass String\nclass Double\nclass Long\n",
        )
        .file("app/Use.scala", source)
        .build();
    let references = [
        ("Boolean =", "scala.Boolean"),
        ("Int =", "scala.Int"),
        ("String =", "scala.Predef$.String"),
        ("Double =", "java.lang.Double"),
        ("Long =", "java.lang.Long"),
    ]
    .into_iter()
    .map(|(needle, _)| location_in("app/Use.scala", source, source.find(needle).unwrap()))
    .collect::<Vec<_>>();
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({"references": references}).to_string(),
    );

    let results = value["results"].as_array().expect("definition results");
    for (result, (_, expected)) in results[..4].iter().zip([
        ("Boolean", "scala.Boolean"),
        ("Int", "scala.Int"),
        ("String", "scala.Predef$.String"),
        ("Double", "java.lang.Double"),
    ]) {
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(result["definitions"][0]["fqn"], expected, "{value}");
    }
    assert_eq!(results[4]["status"], "no_definition", "{value}");
    assert!(results[4]["definitions"].is_null(), "{value}");
}

#[test]
fn scala_qualified_type_resolves_exact_nested_export_target() {
    let fields = r#"package kyo
object Fields {
  object Pin {
    opaque type Pin[+N <: String] = Unit
  }
  export Pin.*
}
"#;
    let source = r#"package app
import kyo.*
object Routes {
  def request[N <: String](using Fields.Pin[N]): Unit = ()
  def response[N <: String](using Fields.Pin[N]): Unit = ()
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("kyo/Fields.scala", fields)
        .file(
            "decoy/Fields.scala",
            "package decoy\nobject Fields { class Pin[N] }\n",
        )
        .file("app/Routes.scala", source)
        .build();
    let references = [
        source.find("Fields.Pin").unwrap(),
        source.rfind("Fields.Pin").unwrap(),
    ]
    .into_iter()
    .map(|start| location_in("app/Routes.scala", source, start + "Fields.".len()))
    .collect::<Vec<_>>();
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({"references": references}).to_string(),
    );

    for result in value["results"].as_array().expect("definition results") {
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(
            result["definitions"][0]["fqn"], "kyo.Fields$.Pin$.Pin",
            "{value}"
        );
    }
}

#[test]
fn scala_exported_type_selectors_preserve_exclusions_renames_and_external_misses() {
    let exports = r#"package library
object Facade {
  object Core {
    class kept
    class hidden
    class original
  }
  export Core.{hidden as _, original as renamed, *}
}
object ExternalFacade {
  export absent.Owner.*
}
"#;
    let source = r#"package app
import library.*
object Use {
  val kept: Facade.kept = null
  val renamed: Facade.renamed = null
  val hidden: Facade.hidden = null
  val external: ExternalFacade.Missing = null
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("library/Exports.scala", exports)
        .file("app/Use.scala", source)
        .build();
    let references = [
        "Facade.kept",
        "Facade.renamed",
        "Facade.hidden",
        "ExternalFacade.Missing",
    ]
    .into_iter()
    .map(|needle| {
        location_in(
            "app/Use.scala",
            source,
            source.find(needle).unwrap() + needle.rfind('.').unwrap() + 1,
        )
    })
    .collect::<Vec<_>>();
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({"references": references}).to_string(),
    );
    let results = value["results"].as_array().expect("definition results");
    for (result, expected) in results[..2].iter().zip([
        "library.Facade$.Core$.kept",
        "library.Facade$.Core$.original",
    ]) {
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(result["definitions"][0]["fqn"], expected, "{value}");
    }
    assert_eq!(results[2]["status"], "no_definition", "{value}");
    assert_eq!(results[3]["status"], "no_definition", "{value}");
    assert_ne!(
        results[3]["diagnostics"][0]["kind"], "unresolved_scala_export",
        "{value}"
    );
}

#[test]
fn scala_implicit_scala_package_type_precedes_unrelated_fixture_type() {
    let source = r#"package scala.quoted
object Expr {
  def fromSeq(seq: Seq[Int]): Unit = ()
  def extract(value: Any): Int = value match {
    case Seq(a, b, c, d, e, f, g) => a
    case _ => 0
  }
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "scala/Seq.scala",
            "package scala\nclass Seq[A]\nobject Seq { def unapplySeq(value: Any): Option[Seq[Int]] = None }\nclass Int\n",
        )
        .file("fixtures/Expr.scala", "object Expr { class Seq[A] }\n")
        .file("scala/quoted/Expr.scala", source)
        .build();
    let references = [
        source
            .find("Seq[Int]")
            .expect("implicit scala package type"),
        source
            .rfind("Seq(a")
            .expect("implicit scala package extractor"),
    ]
    .into_iter()
    .map(|start| location_in("scala/quoted/Expr.scala", source, start))
    .collect::<Vec<_>>();
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({"references": references}).to_string(),
    );

    for (result, expected) in value["results"]
        .as_array()
        .expect("definition results")
        .iter()
        .zip(["scala.Seq", "scala.Seq$.unapplySeq"])
    {
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(result["definitions"][0]["fqn"], expected, "{value}");
    }
}

#[test]
fn scala_same_file_package_types_precede_global_same_named_types() {
    let source = r#"package compat
class A
class B
class C
object Api {
  type AA = A
  def mixed(value: A with B): C = new C
  type Refined = A { type Member <: A }
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("Decoys.scala", "object Z { class A; class C }\n")
        .file("compat/Api.scala", source)
        .build();
    let references = ["= A\n", "value: A", "): C", "= new C", "= A {", "<: A"]
        .into_iter()
        .map(|needle| {
            let start = source.find(needle).expect("same-file type")
                + needle.find(|ch: char| ch.is_ascii_uppercase()).unwrap();
            location_in("compat/Api.scala", source, start)
        })
        .collect::<Vec<_>>();
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({"references": references}).to_string(),
    );
    let expected = [
        "compat.A", "compat.A", "compat.C", "compat.C", "compat.A", "compat.A",
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
fn scala_explicit_member_import_from_typed_local_owner_is_exact() {
    let source = r#"package app
final class Shape(val in: Int, val out: Int)
final class Stage(shape: Shape) {
  import shape.{in, out}
  val inlet = in
  val outlet = out
}
"#;
    let ambiguous = r#"package app
final class Ambiguous(shape: Shape) {
  import shape.{in, out}
  val inlet = in
  val outlet = out
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "replica/app/Shape.scala",
            "package app\nfinal class Shape(val in: Int, val out: Int)\n",
        )
        .file("decoy/out.scala", "package decoy\nobject out\n")
        .file("primary/app/Stage.scala", source)
        .file("consumer/app/Ambiguous.scala", ambiguous)
        .build();
    let references = [
        location_in(
            "primary/app/Stage.scala",
            source,
            source.rfind("= in").unwrap() + 2,
        ),
        location_in(
            "primary/app/Stage.scala",
            source,
            source.rfind("= out").unwrap() + 2,
        ),
        location_in(
            "consumer/app/Ambiguous.scala",
            ambiguous,
            ambiguous.rfind("= in").unwrap() + 2,
        ),
        location_in(
            "consumer/app/Ambiguous.scala",
            ambiguous,
            ambiguous.rfind("= out").unwrap() + 2,
        ),
    ];
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({"references": references}).to_string(),
    );

    let results = value["results"].as_array().expect("definition results");
    for (result, expected) in results[..2].iter().zip(["app.Shape.in", "app.Shape.out"]) {
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(result["definitions"][0]["fqn"], expected, "{value}");
        assert_eq!(
            result["definitions"][0]["path"], "primary/app/Stage.scala",
            "{value}"
        );
    }
    for result in &results[2..] {
        assert_eq!(result["status"], "unresolvable_import_boundary", "{value}");
    }
}

#[test]
fn scala_typed_constructor_field_precedes_same_named_package_object() {
    let source = r#"package app
final class Jobs { def poll(): Int = 1 }
final class BspSession(private val jobs: Jobs) {
  def next: Int = jobs.poll()
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/jobs.scala", "package app\nobject jobs\n")
        .file("app/BspSession.scala", source)
        .build();
    let start = source
        .rfind("jobs.poll")
        .expect("constructor field receiver");
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({"references": [location_in("app/BspSession.scala", source, start)]}).to_string(),
    );

    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["name"], "jobs",
        "{value}"
    );
    assert_eq!(
        value["results"][0]["definitions"][0]["kind"], "parameter",
        "{value}"
    );
    assert!(
        value["results"][0]["definitions"][0].get("fqn").is_none(),
        "{value}"
    );
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
fn scala_focused_qualified_paths_resolve_only_the_selected_prefix() {
    let source = r#"package app

object Structure {
  object Value {
    final case class Record(value: Int)
  }
}

object Outer
trait Box { type Item }
object Cache {
  object internal {
    opaque type Slot = Int
    object Slot { val locked = 1 }
    val held = Slot.locked
  }
}

object Consumer {
  def read(input: Any): Int = input match {
    case Structure.Value.Record(value) => value
  }
  val numeric: scala.math.Numeric.Short.type = scala.math.Numeric.Short
  val boxed: Box#Item = null
  val missing: Outer.Missing = null
}
"#;
    let ambiguous = r#"package consumer

import duplicate.Structure

object Consumer {
  val record = Structure.Value.Record
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/App.scala", source)
        .file(
            "scala/math/Numeric.scala",
            "package scala.math\nobject Numeric { object Short }\n",
        )
        .file(
            "jvm/duplicate/Structure.scala",
            "package duplicate\nobject Structure { object Value { object Record } }\n",
        )
        .file(
            "js/duplicate/Structure.scala",
            "package duplicate\nobject Structure { object Value { object Record } }\n",
        )
        .file("consumer/Consumer.scala", ambiguous)
        .build();
    let path = source
        .find("Structure.Value.Record")
        .expect("qualified path");
    let missing = source
        .find("Outer.Missing")
        .expect("missing qualified path");
    let numeric = source
        .find("scala.math.Numeric.Short")
        .expect("fully qualified singleton path")
        + "scala.math.".len();
    let projected = source.find("Box#Item").expect("projected class path");
    let stable_companion = source
        .find("Slot.locked")
        .expect("stable companion qualifier");
    let ambiguous_path = ambiguous
        .find("Structure.Value.Record")
        .expect("ambiguous qualified path")
        + "Structure.".len();
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({
            "references": [
                location_at(source, path),
                location_at(source, path + "Structure.".len()),
                location_at(source, numeric),
                location_at(source, projected),
                location_at(source, stable_companion),
                location_at(source, missing + "Outer.".len()),
                location_in("consumer/Consumer.scala", ambiguous, ambiguous_path),
            ]
        })
        .to_string(),
    );

    let results = value["results"].as_array().expect("definition results");
    for (result, expected) in results[..5].iter().zip([
        "app.Structure$",
        "app.Structure$.Value$",
        "scala.math.Numeric$",
        "app.Box",
        "app.Cache$.internal$.Slot$",
    ]) {
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(result["definitions"][0]["fqn"], expected, "{value}");
    }
    assert_eq!(results[5]["status"], "no_definition", "{value}");
    assert_eq!(results[6]["status"], "no_definition", "{value}");
}

#[test]
fn scala_owner_qualified_self_type_uses_the_exact_physical_child() {
    let schema = r#"package app

trait Schema[A] {
  type Focused
  def narrow: Schema[A] { type Focused = Schema.this.Focused } = null
}
"#;
    let duplicate = r#"package app

trait Schema[A] {
  type Focused
}
"#;
    let external = r#"package consumer

object Consumer {
  val ambiguous: app.Schema[Int]#Focused = null
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("jvm/app/Schema.scala", schema)
        .file("js/app/Schema.scala", duplicate)
        .file("consumer/Consumer.scala", external)
        .build();
    let self_reference = schema
        .find("Schema.this.Focused")
        .expect("owner-qualified self type")
        + "Schema.this.".len();
    let ambiguous = external.find("Focused").expect("external projected type");
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({
            "references": [
                location_in("jvm/app/Schema.scala", schema, self_reference),
                location_in("consumer/Consumer.scala", external, ambiguous),
            ]
        })
        .to_string(),
    );

    let results = value["results"].as_array().expect("definition results");
    assert_eq!(results[0]["status"], "resolved", "{value}");
    assert_eq!(
        results[0]["definitions"][0]["fqn"], "app.Schema.Focused",
        "{value}"
    );
    assert_eq!(
        results[0]["definitions"][0]["path"], "jvm/app/Schema.scala",
        "{value}"
    );
    assert_eq!(results[1]["status"], "no_definition", "{value}");
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

#[test]
fn scala_forward_lexical_type_namespace_is_exact_order_independent_and_fail_closed() {
    let main = r#"package lexical

class Collision { class Member }

trait Contract {
  type Result = String
  class Inherited
}

class Direct extends Contract {
  val beforeAlias: Result = "ok"
  type Result = Int
  val beforeClass: Factory = null
  class Factory
}

class InheritedUse extends Contract {
  val Result = "term namespace must not block the inherited type"
  val alias: Result = "ok"
  val nested: Inherited = null
}

class Covariant[+Collision] {
  val blocked: Collision = null
  val qualifiedBlocked: Collision.Member = null
}

class LocalBarrier {
  def use: Unit = {
    type Collision = String
    val blocked: Collision = "ok"
    val qualifiedBlocked: Collision.Member = null
  }
}

trait DiamondRoot { class Diamond }
trait DiamondLeft extends DiamondRoot
trait DiamondRight extends DiamondRoot
class DiamondUse extends DiamondLeft with DiamondRight {
  val value: Diamond = null
}

trait Left { class Conflict }
trait Right { class Conflict }
class AmbiguousUse extends Left with Right {
  val value: Conflict = null
}

class TermVsType {
  def select[Collision](Collision: Int): Int = Collision
}
"#;
    let same_jvm = r#"package replica
trait Base { class Exact }
class Local extends Base { val value: Exact = null }
"#;
    let same_js = r#"package replica
trait Base { class Exact }
"#;
    let external = r#"package replica
class External extends Base { val value: Exact = null }
class QualifiedExternal extends replica.Base { val value: Exact = null }
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("lexical/Main.scala", main)
        .file("jvm/replica/Base.scala", same_jvm)
        .file("js/replica/Base.scala", same_js)
        .file(
            "fallback/replica/Exact.scala",
            "package replica\nclass Exact\n",
        )
        .file("external/replica/Use.scala", external)
        .build();
    let location = |source: &str, needle: &str| {
        let marker = source.find(needle).expect("unique lexical type marker");
        let type_offset = needle.find(": ").map_or(0, |colon| colon + 2);
        location_in("lexical/Main.scala", source, marker + type_offset)
    };
    let last_location = |source: &str, needle: &str| {
        let marker = source.rfind(needle).expect("last lexical type marker");
        let type_offset = needle.find(": ").map_or(0, |colon| colon + 2);
        location_in("lexical/Main.scala", source, marker + type_offset)
    };
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({"references": [
            location(main, "Result = \"ok\""),
            location(main, "Factory = null"),
            location(main, "alias: Result"),
            location(main, "nested: Inherited"),
            location(main, "value: Diamond"),
            location_in(
                "jvm/replica/Base.scala",
                same_jvm,
                same_jvm.find("Exact = null").expect("same-file inherited type")
            ),
            location(main, "blocked: Collision"),
            location(main, "qualifiedBlocked: Collision.Member"),
            last_location(main, "val blocked: Collision"),
            last_location(main, "val qualifiedBlocked: Collision.Member"),
            location(main, "value: Conflict"),
            location_in(
                "external/replica/Use.scala",
                external,
                external.find("Exact = null").expect("ambiguous replica type")
            ),
            location_in(
                "external/replica/Use.scala",
                external,
                external.rfind("Exact = null").expect("qualified ambiguous replica type")
            ),
            location(
                main,
                "Collision\n}"
            ),
        ]})
        .to_string(),
    );
    let results = value["results"].as_array().expect("definition results");
    for (index, (fqn, path)) in [
        ("lexical.Direct.Result", "lexical/Main.scala"),
        ("lexical.Direct.Factory", "lexical/Main.scala"),
        ("lexical.Contract.Result", "lexical/Main.scala"),
        ("lexical.Contract.Inherited", "lexical/Main.scala"),
        ("lexical.DiamondRoot.Diamond", "lexical/Main.scala"),
        ("replica.Base.Exact", "jvm/replica/Base.scala"),
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(results[index]["status"], "resolved", "{value}");
        assert_eq!(results[index]["definitions"][0]["fqn"], fqn, "{value}");
        assert_eq!(results[index]["definitions"][0]["path"], path, "{value}");
    }
    for result in &results[6..13] {
        assert_eq!(result["status"], "no_definition", "{value}");
    }
    assert_eq!(results[13]["status"], "resolved", "{value}");
    assert_eq!(
        results[13]["definitions"][0]["name"], "Collision",
        "{value}"
    );
}

#[test]
fn scala_forward_definition_shares_structured_call_list_semantics() {
    let source = r#"package app
trait Context
object Api {
  def block(value: => Int)(using Context): Int = value
  def aligned(using Context)(value: Int)(using Context): Int = value
  def contextualOnly(using Context): Int = 1
  def partial(prefix: String)(line: String): String = prefix + line
  def select(prefix: String)(line: String): String = prefix + line
  def select(left: String, right: String)(line: String): String = left + right + line
  def ambiguous(prefix: String)(line: String): String = prefix + line
  def ambiguous(prefix: Int)(line: String): String = prefix.toString + line
}
object Use {
  import Api.*
  given Context = new Context {}
  def consume(run: String => String): String = run("line")
  def consumeTwo(run: (String, String) => String): String = run("left", "right")
  def blockResult: Int = Api.block {
    val first = 1
    val second = 2
    first + second
  }
  def alignedResult: Int = Api.aligned(1)
  def contextualResult: Int = Api.contextualOnly()
  def partialResult: String = consume(Api.partial("prefix"))
  def selectedPartial: String = consume(Api.select("prefix"))
  def wrongExpected: String = consumeTwo(Api.partial("prefix"))
  // Same-shape overloads remain ambiguous without argument-type evidence.
  def ambiguousPartial: String = consume(Api.ambiguous("prefix"))
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/App.scala", source)
        .build();
    let reference_start = |line: &str, member: &str| {
        source.find(line).expect("unique reference line")
            + line.rfind(member).expect("member on reference line")
    };
    let references = [
        ("def blockResult: Int = Api.block {", "block"),
        ("def alignedResult: Int = Api.aligned(1)", "aligned"),
        (
            "def contextualResult: Int = Api.contextualOnly()",
            "contextualOnly",
        ),
        (
            "def partialResult: String = consume(Api.partial(\"prefix\"))",
            "partial",
        ),
        (
            "def selectedPartial: String = consume(Api.select(\"prefix\"))",
            "select",
        ),
        (
            "def wrongExpected: String = consumeTwo(Api.partial(\"prefix\"))",
            "partial",
        ),
        (
            "def ambiguousPartial: String = consume(Api.ambiguous(\"prefix\"))",
            "ambiguous",
        ),
    ]
    .into_iter()
    .map(|(line, member)| location_at(source, reference_start(line, member)))
    .collect::<Vec<_>>();
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({"references": references}).to_string(),
    );

    let results = value["results"].as_array().expect("definition results");
    for (result, expected) in results[..5].iter().zip([
        "app.Api$.block",
        "app.Api$.aligned",
        "app.Api$.contextualOnly",
        "app.Api$.partial",
        "app.Api$.select",
    ]) {
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(result["definitions"][0]["fqn"], expected, "{value}");
    }
    for result in &results[5..] {
        assert_eq!(result["status"], "no_definition", "{value}");
    }
}

#[test]
fn scala_forward_definition_chains_through_field_factories_and_curried_construction() {
    let weather_source = r#"package app
import model.*
class WeatherRoutes(system: String) {
  private var sharding = ClusterSharding(system)
  def route(): String = {
    val ref = sharding.entityRefFor()
    ref.ask()
  }
  def reset(): EntityRef = {
    sharding = ClusterSharding(system)
    sharding.entityRefFor()
  }
}
"#;
    let layer_source = r#"package app
import model.Graph
object LayerMacros {
  def build(nodes: List[Int]): Int = {
    val graph = Graph(nodes.toSet)(_ < _)
    graph.buildTargets()
  }
}
"#;
    let factory_source = r#"package app
import model.Factories.{ambiguous, make}
import model.Graph
object ImportedFactories {
  def positive(): Int = {
    val graph = make()
    graph.buildTargets()
  }
  def negative(): Int = {
    val uncertain = ambiguous(1)
    uncertain.buildTargets()
  }
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "model/Runtime.scala",
            r#"package model
class EntityRef { def ask(): String = "ok" }
class ClusterSharding { def entityRefFor(): EntityRef = new EntityRef }
object ClusterSharding { def apply(system: String): ClusterSharding = new ClusterSharding }
class Graph { def buildTargets(): Int = 1 }
object Graph { def apply(nodes: Set[Int])(edge: (Int, Int) => Boolean): Graph = new Graph }
object Factories {
  def make(): Graph = new Graph
  def make(value: Int): EntityRef = new EntityRef
  def ambiguous(value: Int): EntityRef = new EntityRef
  def ambiguous(value: String): Graph = new Graph
}
"#,
        )
        .file("app/WeatherRoutes.scala", weather_source)
        .file("app/LayerMacros.scala", layer_source)
        .file("app/ImportedFactories.scala", factory_source)
        .build();
    let reference = |path: &str, source: &str, needle: &str| {
        location_in(path, source, source.find(needle).expect("reference needle"))
    };
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({"references": [
            reference("app/WeatherRoutes.scala", weather_source, "entityRefFor"),
            reference("app/WeatherRoutes.scala", weather_source, "ask()"),
            reference(
                "app/WeatherRoutes.scala",
                weather_source,
                "entityRefFor()\n  }\n}",
            ),
            reference("app/LayerMacros.scala", layer_source, "buildTargets"),
            reference(
                "app/ImportedFactories.scala",
                factory_source,
                "buildTargets()\n  }\n  def negative",
            ),
            location_in(
                "app/ImportedFactories.scala",
                factory_source,
                factory_source
                    .rfind("buildTargets")
                    .expect("negative buildTargets reference"),
            ),
        ]})
        .to_string(),
    );
    let results = value["results"].as_array().expect("definition results");
    for (result, fqn) in results.iter().zip([
        "model.ClusterSharding.entityRefFor",
        "model.EntityRef.ask",
        "model.ClusterSharding.entityRefFor",
        "model.Graph.buildTargets",
        "model.Graph.buildTargets",
    ]) {
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(result["definitions"][0]["fqn"], fqn, "{value}");
    }
    assert_eq!(results[5]["status"], "no_definition", "{value}");
}

#[test]
fn scala_forward_named_arguments_do_not_poison_local_receiver_bindings() {
    let source = r#"package app

class Body { val summary: Int = 1 }
class Other { val summary: Int = 2 }
case class Result(body: Int, short: Int)
class Built(val body: Int, val short: Int)

abstract class Parser {
  protected def makeBody(seed: Int): Body
  protected def makeOther(seed: Int): Other

  final def parse(seed: Int): Int =
    val body = makeBody(seed)
    val result = Result(
      body = body.summary,
      short = body.summary,
    )
    val built = new Built(
      body = body.summary,
      short = body.summary,
    )
    var changing = makeBody(seed)
    changing = makeOther(seed)
    result.short + built.short + changing.summary
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/NamedArguments.scala", source)
        .build();
    let summary_sites = source
        .match_indices("body.summary")
        .map(|(start, _)| start + "body.".len())
        .collect::<Vec<_>>();
    let reassigned_summary =
        source.find("changing.summary").expect("reassigned summary") + "changing.".len();
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({"references": [
            location_in("app/NamedArguments.scala", source, summary_sites[0]),
            location_in("app/NamedArguments.scala", source, summary_sites[1]),
            location_in("app/NamedArguments.scala", source, summary_sites[2]),
            location_in("app/NamedArguments.scala", source, summary_sites[3]),
            location_in("app/NamedArguments.scala", source, reassigned_summary),
        ]})
        .to_string(),
    );
    let results = value["results"].as_array().expect("definition results");
    for result in &results[..4] {
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(
            result["definitions"][0]["fqn"], "app.Body.summary",
            "{value}"
        );
    }
    assert_eq!(results[4]["status"], "resolved", "{value}");
    assert_eq!(
        results[4]["definitions"][0]["fqn"], "app.Other.summary",
        "{value}"
    );
}

#[test]
fn scala_forward_definition_filters_callable_roles_before_overload_shapes() {
    let source = r#"package app
trait Context
trait Marker
trait Contains { infix def contains(value: Int): Boolean = true }
class Roleful(value: Int) extends Contains {
  def this() = this(0)
  def this(text: String, flag: Boolean) = this(text.length)
}
object Roleful { def apply(using Context): Roleful = new Roleful(0) }
object Use {
  given Context = new Context {}
  val primary = new Roleful(1)
  val secondaryZero = new Roleful()
  val secondaryTwo = new Roleful("two", true)
  val wrongNew = new Roleful("wrong", false, 3)
  val companion = Roleful()
  val primaryFallback = Roleful(2)
  val secondaryMustNotBeBare = Roleful("two", true)
  val anonymous = new Marker {}
  val inheritedInfix = primary contains 1
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/App.scala", source)
        .build();
    let at = |line: &str, member: &str| {
        let start = source.find(line).expect("unique reference line");
        location_at(source, start + line.find(member).expect("member on line"))
    };
    let mut references = [
        ("val primary = new Roleful(1)", "Roleful"),
        ("val secondaryZero = new Roleful()", "Roleful"),
        ("val secondaryTwo = new Roleful(\"two\", true)", "Roleful"),
        ("val wrongNew = new Roleful(\"wrong\", false, 3)", "Roleful"),
        ("val companion = Roleful()", "Roleful"),
        ("val primaryFallback = Roleful(2)", "Roleful"),
        (
            "val secondaryMustNotBeBare = Roleful(\"two\", true)",
            "Roleful",
        ),
        ("val anonymous = new Marker {}", "Marker"),
    ]
    .into_iter()
    .map(|(line, member)| at(line, member))
    .collect::<Vec<_>>();
    let infix = source.find("contains 1").expect("unique infix reference");
    references.push(location_at(source, infix));
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({"references": references}).to_string(),
    );
    let results = value["results"].as_array().expect("definition results");
    for index in [0, 1, 2, 5] {
        assert_eq!(results[index]["status"], "resolved", "{value}");
        assert_eq!(
            results[index]["definitions"][0]["fqn"], "app.Roleful.Roleful",
            "{value}"
        );
    }
    for index in [3, 6] {
        assert_eq!(results[index]["status"], "no_definition", "{value}");
    }
    assert_eq!(
        results[4]["definitions"][0]["fqn"], "app.Roleful$.apply",
        "{value}"
    );
    assert_eq!(results[7]["definitions"][0]["fqn"], "app.Marker", "{value}");
    assert_eq!(
        results[8]["definitions"][0]["fqn"], "app.Contains.contains",
        "{value}"
    );
}

#[test]
fn scala_definition_resolves_enclosing_package_and_renamed_object_type_roots() {
    let compound = r#"package akka.stream.javadsl
object Compound {
  def flow: javadsl.Flow[Int, String, Unit] = null
}
"#;
    let sequential = r#"package akka.stream
package javadsl
object Sequential {
  def flow: javadsl.Flow[Int, String, Unit] = null
}
"#;
    let visibility = r#"package akka.stream.javadsl
object Visibility {
  def before: javadsl.Flow[Int, String, Unit] = null
  import decoy.javadsl
  def after: javadsl.Flow[Int, String, Unit] = null
}
"#;
    let tree_set = r#"package scala.collection.immutable
import scala.collection.immutable.{RedBlackTree => RB}
class TreeSet[A] extends RB.SetHelper[A]
"#;
    let wildcard = r#"package akka.stream.javadsl
import decoy.*
object Collision {
  def flow: javadsl.Flow[Int, String, Unit] = null
}
"#;
    let ambiguous = r#"package scala.collection.immutable
import scala.collection.immutable.{RedBlackTree => RB}
import decoy.{RedBlackTree => RB}
class Ambiguous[A] extends RB.SetHelper[A]
"#;
    let duplicate_terminal = r#"package replica
import replica.{Root => Alias}
class Use extends Alias.Tail
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "akka/stream/javadsl/Flow.scala",
            "package akka.stream.javadsl\nclass Flow[In, Out, Mat]\n",
        )
        .file("akka/stream/javadsl/Compound.scala", compound)
        .file("akka/stream/javadsl/Sequential.scala", sequential)
        .file("akka/stream/javadsl/Visibility.scala", visibility)
        .file(
            "scala/collection/immutable/RedBlackTree.scala",
            "package scala.collection.immutable\nobject RedBlackTree { trait SetHelper[A] }\n",
        )
        .file(
            "tests/init/crash/rbtree.scala",
            "package scala.collection.immutable\nobject RedBlackTree { class Tree[A] }\n",
        )
        .file("scala/collection/immutable/TreeSet.scala", tree_set)
        .file(
            "decoy/Roots.scala",
            "package decoy\nobject javadsl { class Flow[In, Out, Mat] }\nobject RedBlackTree { trait SetHelper[A] }\n",
        )
        .file("akka/stream/javadsl/Collision.scala", wildcard)
        .file("scala/collection/immutable/Ambiguous.scala", ambiguous)
        .file(
            "replica/RootOne.scala",
            "package replica\nobject Root { trait Tail }\n",
        )
        .file(
            "replica/RootTwo.scala",
            "package replica\nobject Root { trait Tail }\n",
        )
        .file("replica/Use.scala", duplicate_terminal)
        .build();
    let terminal = |source: &str, needle: &str| {
        source.find(needle).expect("qualified type")
            + needle.rfind('.').expect("qualified root")
            + 1
    };
    let references = [
        location_in(
            "akka/stream/javadsl/Compound.scala",
            compound,
            terminal(compound, "javadsl.Flow"),
        ),
        location_in(
            "akka/stream/javadsl/Sequential.scala",
            sequential,
            terminal(sequential, "javadsl.Flow"),
        ),
        location_in(
            "scala/collection/immutable/TreeSet.scala",
            tree_set,
            terminal(tree_set, "RB.SetHelper"),
        ),
        location_in(
            "akka/stream/javadsl/Visibility.scala",
            visibility,
            terminal(visibility, "javadsl.Flow"),
        ),
        location_in(
            "akka/stream/javadsl/Visibility.scala",
            visibility,
            visibility.rfind("javadsl.Flow").expect("post-import type") + "javadsl.".len(),
        ),
        location_in(
            "akka/stream/javadsl/Collision.scala",
            wildcard,
            terminal(wildcard, "javadsl.Flow"),
        ),
        location_in(
            "scala/collection/immutable/Ambiguous.scala",
            ambiguous,
            terminal(ambiguous, "RB.SetHelper"),
        ),
        location_in(
            "replica/Use.scala",
            duplicate_terminal,
            terminal(duplicate_terminal, "Alias.Tail"),
        ),
    ];
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({"references": references}).to_string(),
    );
    let results = value["results"].as_array().expect("definition results");
    for result in &results[..2] {
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(
            result["definitions"][0]["fqn"], "akka.stream.javadsl.Flow",
            "{value}"
        );
    }
    assert_eq!(results[2]["status"], "resolved", "{value}");
    assert_eq!(
        results[2]["definitions"][0]["fqn"], "scala.collection.immutable.RedBlackTree$.SetHelper",
        "{value}"
    );
    assert_eq!(results[3]["status"], "resolved", "{value}");
    assert_eq!(
        results[3]["definitions"][0]["fqn"], "akka.stream.javadsl.Flow",
        "{value}"
    );
    for index in [4, 5] {
        assert_eq!(results[index]["status"], "resolved", "{value}");
        assert_eq!(
            results[index]["definitions"][0]["fqn"], "decoy.javadsl$.Flow",
            "{value}"
        );
    }
    assert_eq!(results[6]["status"], "no_definition", "{value}");
    assert_eq!(results[7]["status"], "no_definition", "{value}");
}

#[test]
fn scala_forward_resolves_nested_parameter_receiver_declarations_exactly() {
    let clock = r#"package kyo

trait Frame
trait AllowUnsafe

final case class Clock() {
  def nowMonotonic(using Frame): Long = 0L
}

object Clock {
  sealed abstract class Unsafe {
    def nowMonotonic()(using AllowUnsafe): Long
  }

  object Stopwatch {
    final class Unsafe(clock: Clock.Unsafe) {
      def elapsed()(using AllowUnsafe): Long = clock.nowMonotonic()
    }
  }
}
"#;
    let semantic = r#"package dotty.tools.dotc.transform.init
class Context
trait Value {
  def show(using Context): String
}
"#;
    let objects = r#"package dotty.tools.dotc.transform.init
class Objects {
  sealed trait Value {
    def show(using Context): String
  }

  def select(value: Value)(using Context): String = value.show
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("kyo/Clock.scala", clock)
        .file("init/Semantic.scala", semantic)
        .file("init/Objects.scala", objects)
        .build();
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({"references": [
            location_in(
                "kyo/Clock.scala",
                clock,
                clock.rfind("clock.nowMonotonic").expect("nested unsafe receiver")
                    + "clock.".len(),
            ),
            location_in(
                "init/Objects.scala",
                objects,
                objects.rfind("value.show").expect("nested value receiver")
                    + "value.".len(),
            ),
        ]})
        .to_string(),
    );
    let results = value["results"].as_array().expect("definition results");
    for (result, fqn, path) in [
        (
            &results[0],
            "kyo.Clock$.Unsafe.nowMonotonic",
            "kyo/Clock.scala",
        ),
        (
            &results[1],
            "dotty.tools.dotc.transform.init.Objects.Value.show",
            "init/Objects.scala",
        ),
    ] {
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(
            result["definitions"].as_array().map(Vec::len),
            Some(1),
            "{value}"
        );
        assert_eq!(result["definitions"][0]["fqn"], fqn, "{value}");
        assert_eq!(result["definitions"][0]["path"], path, "{value}");
    }
}

#[test]
fn scala_forward_typed_receivers_preserve_physical_identity_and_exact_misses() {
    let replica = |platform: &str| {
        format!(
            r#"package replica
object Api {{
  final class Receiver {{
    def choose(value: Int): Int = value
    def choose(value: Int, extra: Int): Int = value + extra
  }}
  def {platform}Selected(receiver: Receiver): Int = receiver.choose(1)
  def {platform}WrongShape(receiver: Receiver): Int = receiver.choose()
}}
"#
        )
    };
    let jvm = replica("jvm");
    let js = replica("js");
    let native = replica("native");
    let external = r#"package consumer
import replica.Api.Receiver
object External {
  def ambiguous(receiver: Receiver): Int = receiver.choose(1)
}
"#;
    let missing = r#"package missing
object Api {
  final class Receiver
  def probe(receiver: Receiver): Int = receiver.leak(1)
}
"#;
    let sibling = r#"package missing
object Api {
  final class Receiver {
    def leak(value: Int): Int = value
  }
}
"#;
    let extension_control = r#"package extensioncase
class Receiver {
  def choose(value: Int): Int = value
}
object Extensions {
  extension (receiver: Receiver) def choose(): Int = 1
}
object Use {
  import Extensions.*
  def selected(receiver: Receiver): Int = receiver.choose()
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("jvm/replica/Api.scala", &jvm)
        .file("js/replica/Api.scala", &js)
        .file("native/replica/Api.scala", &native)
        .file("consumer/External.scala", external)
        .file("jvm/missing/Api.scala", missing)
        .file("js/missing/Api.scala", sibling)
        .file("extensioncase/Use.scala", extension_control)
        .build();

    let mut references = Vec::new();
    for (path, source) in [
        ("jvm/replica/Api.scala", jvm.as_str()),
        ("js/replica/Api.scala", js.as_str()),
        ("native/replica/Api.scala", native.as_str()),
    ] {
        references.push(location_in(
            path,
            source,
            source
                .find("receiver.choose(1)")
                .expect("exact receiver call")
                + "receiver.".len(),
        ));
        references.push(location_in(
            path,
            source,
            source
                .find("receiver.choose()")
                .expect("wrong-shape exact receiver call")
                + "receiver.".len(),
        ));
    }
    references.push(location_in(
        "consumer/External.scala",
        external,
        external
            .find("receiver.choose")
            .expect("ambiguous logical receiver")
            + "receiver.".len(),
    ));
    references.push(location_in(
        "jvm/missing/Api.scala",
        missing,
        missing.find("receiver.leak").expect("exact missing member") + "receiver.".len(),
    ));
    references.push(location_in(
        "extensioncase/Use.scala",
        extension_control,
        extension_control
            .find("receiver.choose()")
            .expect("applicable extension after direct shape miss")
            + "receiver.".len(),
    ));
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({"references": references}).to_string(),
    );
    let results = value["results"].as_array().expect("definition results");
    for (index, path) in [
        "jvm/replica/Api.scala",
        "js/replica/Api.scala",
        "native/replica/Api.scala",
    ]
    .into_iter()
    .enumerate()
    {
        let selected = &results[index * 2];
        assert_eq!(selected["status"], "resolved", "{value}");
        assert_eq!(
            selected["definitions"].as_array().map(Vec::len),
            Some(1),
            "{value}"
        );
        assert_eq!(selected["definitions"][0]["path"], path, "{value}");
        assert_eq!(
            selected["definitions"][0]["fqn"], "replica.Api$.Receiver.choose",
            "{value}"
        );

        let wrong_shape = &results[index * 2 + 1];
        assert_eq!(wrong_shape["status"], "no_definition", "{value}");
        assert_eq!(
            wrong_shape["diagnostics"][0]["kind"], "no_applicable_scala_callable",
            "{value}"
        );
    }
    assert_eq!(results[6]["status"], "no_definition", "{value}");
    assert_eq!(results[7]["status"], "no_definition", "{value}");
    assert!(
        results[7]["definitions"]
            .as_array()
            .is_none_or(Vec::is_empty),
        "an exact owner miss leaked the sibling physical replica: {value}"
    );
    assert_eq!(results[8]["status"], "resolved", "{value}");
    assert_eq!(
        results[8]["definitions"].as_array().map(Vec::len),
        Some(1),
        "{value}"
    );
    assert_eq!(
        results[8]["definitions"][0]["fqn"], "extensioncase.Extensions$.choose",
        "{value}"
    );
}

#[test]
fn scala_forward_definition_preserves_physical_enclosing_owner_identity() {
    let replica = |platform: &str| {
        format!(
            r#"package replica
class Base {{
  var count: Int = 0
  def ready: Boolean = true
  def overloaded(value: Int): Int = value
  def overloaded(value: String): Int = value.length
  def direct(): Unit = {{
    val read = count // {platform}-direct-read
    count += 1 // {platform}-direct-compound
    count = 2 // {platform}-direct-write
    val method = ready // {platform}-direct-method
    val qualified = this.count // {platform}-this-read
    val qualifiedMethod = this.ready // {platform}-this-method
    val overload = overloaded(1) // {platform}-overload
  }}
}}
class Local extends Base {{
  val inherited = count // {platform}-inherited-field
  val inheritedMethod = ready // {platform}-inherited-method
}}
"#
        )
    };
    let jvm = replica("jvm");
    let js = replica("js");
    let external = r#"package consumer
import replica.Base
class External extends Base {
  val ambiguousField = count
  val ambiguousMethod = ready
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("jvm/replica/Base.scala", &jvm)
        .file("js/replica/Base.scala", &js)
        .file("consumer/External.scala", external)
        .build();

    let reference = |path: &str, source: &str, line_marker: &str, name: &str| {
        let marker = source
            .find(line_marker)
            .expect("unique physical-owner marker");
        let line = source[..marker]
            .rfind('\n')
            .map_or(0, |newline| newline + 1);
        let name = source[line..].find(name).expect("name on marker line");
        location_in(path, source, line + name)
    };
    let mut references = Vec::new();
    for (path, source, platform) in [
        ("jvm/replica/Base.scala", jvm.as_str(), "jvm"),
        ("js/replica/Base.scala", js.as_str(), "js"),
    ] {
        for (suffix, name) in [
            ("direct-read", "count"),
            ("direct-compound", "count"),
            ("direct-write", "count"),
            ("direct-method", "ready"),
            ("this-read", "count"),
            ("this-method", "ready"),
            ("overload", "overloaded"),
            ("inherited-field", "count"),
            ("inherited-method", "ready"),
        ] {
            references.push(reference(
                path,
                source,
                &format!("{platform}-{suffix}"),
                name,
            ));
        }
    }
    references.push(reference(
        "consumer/External.scala",
        external,
        "ambiguousField",
        "count",
    ));
    references.push(reference(
        "consumer/External.scala",
        external,
        "ambiguousMethod",
        "ready",
    ));

    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({"references": references}).to_string(),
    );
    let results = value["results"].as_array().expect("definition results");
    for (platform_index, path) in ["jvm/replica/Base.scala", "js/replica/Base.scala"]
        .into_iter()
        .enumerate()
    {
        for result in &results[platform_index * 9..platform_index * 9 + 9] {
            assert_eq!(result["status"], "resolved", "{value}");
            assert!(
                result["definitions"]
                    .as_array()
                    .is_some_and(|definitions| !definitions.is_empty()),
                "{value}"
            );
            assert!(
                result["definitions"]
                    .as_array()
                    .expect("definitions")
                    .iter()
                    .all(|definition| definition["path"] == path),
                "{value}"
            );
        }
    }
    for result in &results[18..] {
        assert_eq!(result["status"], "no_definition", "{value}");
        assert_eq!(
            result["diagnostics"][0]["kind"], "ambiguous_scala_enclosing_member",
            "{value}"
        );
    }
}

#[test]
fn scala_identifier_type_roles_precede_same_named_term_namespace() {
    let source = r#"package app
class Left
class Right
class Or
object Or
object Use {
  type Combined = Left Or Right
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/Use.scala", source)
        .build();
    let start = source.find(" Or Right").expect("infix type operator") + 1;
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({"references": [location_in("app/Use.scala", source, start)]}).to_string(),
    );

    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "app.Or",
        "{value}"
    );
}

#[test]
fn scala_enclosing_terms_precede_implicit_companions_but_not_local_imports() {
    let source = r#"package app
object Imported { val Short: Int = 2 }
object StdType {
  val Short: Int = 1
  val direct = Short
  def imported: Int = {
    import Imported.Short
    Short
  }
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "scala/Short.scala",
            "package scala\nclass Short\nobject Short\n",
        )
        .file("app/StdType.scala", source)
        .build();
    let references = [
        source.find("direct = Short").expect("direct member") + "direct = ".len(),
        source.rfind("    Short").expect("local import use") + 4,
    ]
    .into_iter()
    .map(|start| location_in("app/StdType.scala", source, start))
    .collect::<Vec<_>>();
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({"references": references}).to_string(),
    );
    let results = value["results"].as_array().expect("definition results");
    for (result, expected) in results
        .iter()
        .zip(["app.StdType$.Short", "app.Imported$.Short"])
    {
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(result["definitions"][0]["fqn"], expected, "{value}");
    }
}

#[test]
fn scala_mixed_class_object_lexical_paths_and_synthetic_extractors_are_exact() {
    let source = r#"package app
object Semantic { class Data }
import Semantic.*

class Objects {
  object Cache { class Data }
  val data: Cache.Data = null
}

object Trees {
  case class New(value: Int)
  def read(value: Any): Int = value match {
    case New(number) => number
    case _ => 0
  }
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/Shapes.scala", source)
        .build();
    let references = [
        source.find("Cache.Data").expect("mixed lexical path") + "Cache.".len(),
        source.find("case New(").expect("synthetic extractor") + "case ".len(),
    ]
    .into_iter()
    .map(|start| location_in("app/Shapes.scala", source, start))
    .collect::<Vec<_>>();
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({"references": references}).to_string(),
    );
    let results = value["results"].as_array().expect("definition results");
    for (result, expected) in results
        .iter()
        .zip(["app.Objects.Cache$.Data", "app.Trees$.New.New"])
    {
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(result["definitions"][0]["fqn"], expected, "{value}");
    }
}

#[test]
fn scala_compiler_intrinsics_reject_fixture_declarations_after_legal_shadows() {
    let intrinsic = r#"package consumer
object Use {
  val any: Any = null
  val nothing: Null = null
  val qualifiedAny: scala.Any = null
  val rootedNull: _root_.scala.Null = null
}
"#;
    let shadow = r#"package shadow
class Any
object Use { val local: Any = null }
"#;
    let explicit = r#"package explicit
import shadow.Any
object Use { val imported: Any = null }
"#;
    let wildcard = r#"package wildcard
import shadow.*
object Use { val imported: Any = null }
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "fixtures/Redefinition.scala",
            "package scala\nclass Any\nclass Null\n",
        )
        .file("consumer/Use.scala", intrinsic)
        .file("shadow/Use.scala", shadow)
        .file("explicit/Use.scala", explicit)
        .file("wildcard/Use.scala", wildcard)
        .build();
    let references = [
        location_in(
            "consumer/Use.scala",
            intrinsic,
            intrinsic.find("Any").unwrap(),
        ),
        location_in(
            "consumer/Use.scala",
            intrinsic,
            intrinsic.find("Null").unwrap(),
        ),
        location_in(
            "consumer/Use.scala",
            intrinsic,
            intrinsic.find("scala.Any").unwrap() + "scala.".len(),
        ),
        location_in(
            "consumer/Use.scala",
            intrinsic,
            intrinsic.find("_root_.scala.Null").unwrap() + "_root_.scala.".len(),
        ),
        location_in("shadow/Use.scala", shadow, shadow.rfind("Any").unwrap()),
        location_in(
            "explicit/Use.scala",
            explicit,
            explicit.rfind("Any").unwrap(),
        ),
        location_in(
            "wildcard/Use.scala",
            wildcard,
            wildcard.rfind("Any").unwrap(),
        ),
    ];
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({"references": references}).to_string(),
    );
    let results = value["results"].as_array().expect("definition results");
    for result in &results[..4] {
        assert_eq!(result["status"], "no_definition", "{value}");
        assert_eq!(
            result["diagnostics"][0]["kind"], "scala_compiler_intrinsic_type",
            "{value}"
        );
    }
    for result in &results[4..] {
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(result["definitions"][0]["fqn"], "shadow.Any", "{value}");
    }
}
