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
    let prefix = &source[..start];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = prefix
        .rsplit_once('\n')
        .map_or(prefix, |(_, current)| current)
        .chars()
        .count()
        + 1;
    json!({"path": "app/App.scala", "line": line, "column": column})
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
