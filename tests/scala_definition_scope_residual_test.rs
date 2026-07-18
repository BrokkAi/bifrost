mod common;

use brokk_bifrost::Language;
use common::{InlineTestProject, call_search_tool_json};
use serde_json::{Value, json};

fn location_at(path: &str, source: &str, start: usize) -> Value {
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
fn same_file_type_precedes_wildcard_but_other_file_package_type_does_not() {
    let local_source = r#"package app
import imported.*
final case class LocalWidget(value: Int)
object LocalConsumer { val value = LocalWidget(1) }
"#;
    let package_source = "package app\nfinal case class PackageWidget(value: Int)\n";
    let imported_source = r#"package imported
final case class LocalWidget(value: Int)
final case class PackageWidget(value: Int)
"#;
    let consumer_source = r#"package app
import imported.*
object PackageConsumer { val value = PackageWidget(1) }
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/Local.scala", local_source)
        .file("app/PackageWidget.scala", package_source)
        .file("app/Consumer.scala", consumer_source)
        .file("imported/Widgets.scala", imported_source)
        .build();
    let references = vec![
        location_at(
            "app/Local.scala",
            local_source,
            local_source.rfind("LocalWidget").expect("local call"),
        ),
        location_at(
            "app/Consumer.scala",
            consumer_source,
            consumer_source
                .rfind("PackageWidget")
                .expect("imported call"),
        ),
    ];
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({"references": references}).to_string(),
    );

    let results = value["results"].as_array().expect("definition results");
    assert_eq!(results[0]["status"], "resolved", "{value}");
    assert_eq!(
        results[0]["definitions"][0]["path"], "app/Local.scala",
        "{value}"
    );
    assert_eq!(results[1]["status"], "resolved", "{value}");
    assert_eq!(
        results[1]["definitions"][0]["path"], "imported/Widgets.scala",
        "{value}"
    );
}

#[test]
fn pattern_declaration_sites_do_not_resolve_indexed_name_collisions() {
    let source = r#"package app

object Collisions {
  def name: Int = 1
  val value: Int = 2
  def tree: Int = 3
}
final case class Box(value: Int)

object Consumer {
  import Collisions.*
  def typed(input: Any): Any = input match { case name: String => name }
  def extracted(input: Any): Any = input match { case Box(value) => value }
  def bare(input: Any): Any = input match { case tree => tree }
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/App.scala", source)
        .build();
    let references = ["case name", "case Box(value", "case tree"]
        .into_iter()
        .map(|marker| {
            let offset = if marker == "case Box(value" {
                "case Box(".len()
            } else {
                "case ".len()
            };
            location_at(
                "app/App.scala",
                source,
                source.find(marker).expect("pattern binding") + offset,
            )
        })
        .collect::<Vec<_>>();
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({"references": references}).to_string(),
    );

    for result in value["results"].as_array().expect("definition results") {
        assert_eq!(result["status"], "no_definition", "{value}");
        assert_eq!(
            result["diagnostics"][0]["kind"], "local_variable_reference",
            "{value}"
        );
    }
}

#[test]
fn wildcard_imported_singleton_apply_precedes_unrelated_type() {
    let consumer = r#"package dotty.tools
package dotc
package typer

import core.*
import Annotations.*
import scala.annotation.*

object Consumer { val annotation = Annotation(1, 2, 3) }
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "dotty/tools/dotc/core/Annotations.scala",
            r#"package dotty.tools.dotc.core
object Annotations {
  abstract class Annotation
  object Annotation {
    def apply(cls: Int, arg: Int, span: Int): Annotation = ???
  }
}
"#,
        )
        .file(
            "scala/annotation/Annotation.scala",
            "package scala.annotation\nabstract class Annotation\n",
        )
        .file("dotty/tools/dotc/typer/Consumer.scala", consumer)
        .build();
    let reference = location_at(
        "dotty/tools/dotc/typer/Consumer.scala",
        consumer,
        consumer.rfind("Annotation").expect("singleton call"),
    );
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({"references": [reference]}).to_string(),
    );

    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["path"], "dotty/tools/dotc/core/Annotations.scala",
        "{value}"
    );
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"],
        "dotty.tools.dotc.core.Annotations$.Annotation$.apply",
        "{value}"
    );
    assert_eq!(
        value["results"][0]["definitions"][0]["kind"], "function",
        "{value}"
    );
}

#[test]
fn wildcard_imported_owner_chain_preserves_ambiguity() {
    let consumer = r#"package app
import a.*
import b.*
import Shared.*
object Consumer { val target = Target() }
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "a/Shared.scala",
            "package a\nobject Shared { object Target { def apply(): Int = 1 } }\n",
        )
        .file(
            "b/Shared.scala",
            "package b\nobject Shared { object Target { def apply(): Int = 2 } }\n",
        )
        .file("app/Consumer.scala", consumer)
        .build();
    let reference = location_at(
        "app/Consumer.scala",
        consumer,
        consumer.rfind("Target").expect("ambiguous singleton call"),
    );
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({"references": [reference]}).to_string(),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
    assert_eq!(
        value["results"][0]["diagnostics"][0]["kind"], "ambiguous_scala_wildcard_import",
        "{value}"
    );
}
