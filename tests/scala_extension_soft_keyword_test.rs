mod common;

use brokk_bifrost::Language;
use common::{InlineTestProject, call_search_tool_json};
use serde_json::{Value, json};

const SCALA2_SOURCE: &str = r#"package app

trait ScalametaCommonEnrichments {
  implicit class XtensionAbsolutePath(filename: String) {
    def extension: String = "json"

    def isJson: Boolean =
      extension == "json"

    def isScalaScript: Boolean =
      filename.endsWith(".sc") && !isWorksheet

    def isWorksheet: Boolean =
      filename.endsWith(".worksheet.sc")
  }
}
"#;

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
fn scala_extension_is_contextual_between_identifier_and_definition() {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_scala::LANGUAGE.into())
        .expect("load Scala grammar");

    let scala2_tree = parser.parse(SCALA2_SOURCE, None).expect("parse Scala 2");
    assert!(
        !scala2_tree.root_node().has_error(),
        "Scala 2 `extension` identifier must parse without recovery:\n{}",
        scala2_tree.root_node().to_sexp()
    );
    let scala2_tree = scala2_tree.root_node().to_sexp();
    assert!(
        scala2_tree.contains("left: (identifier"),
        "`extension` must remain an expression identifier:\n{scala2_tree}"
    );

    let scala3 = r#"object Syntax:
  extension (value: String)
    def twice: String = value + value
"#;
    let scala3_tree = parser.parse(scala3, None).expect("parse Scala 3");
    assert!(
        !scala3_tree.root_node().has_error(),
        "Scala 3 extension definition must remain valid:\n{}",
        scala3_tree.root_node().to_sexp()
    );
    assert!(
        scala3_tree
            .root_node()
            .to_sexp()
            .contains("extension_definition"),
        "Scala 3 syntax must retain its structured extension node"
    );
}

#[test]
fn scala_extension_identifier_preserves_nested_symbol_round_trip() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/Enrichments.scala", SCALA2_SOURCE)
        .build();
    let call_start = SCALA2_SOURCE
        .find("!isWorksheet")
        .expect("isWorksheet call")
        + 1;
    let location = location_at("app/Enrichments.scala", SCALA2_SOURCE, call_start);
    let forward = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({"references": [location]}).to_string(),
    );

    assert_eq!(forward["results"][0]["status"], "resolved", "{forward}");
    let definition = &forward["results"][0]["definitions"][0];
    assert_eq!(
        definition["fqn"], "app.ScalametaCommonEnrichments.XtensionAbsolutePath.isWorksheet",
        "{forward}"
    );

    let inverse = call_search_tool_json(
        project.root(),
        "scan_usages_by_reference",
        &json!({
            "symbols": ["app.ScalametaCommonEnrichments.XtensionAbsolutePath.isWorksheet"],
            "include_tests": true
        })
        .to_string(),
    );
    let usage = &inverse["results"][0];
    assert_eq!(usage["status"], "found", "{inverse}");
    assert!(
        usage["files"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|file| file["hits"].as_array().into_iter().flatten())
            .filter_map(|hit| hit["snippet"].as_str())
            .any(|snippet| snippet.contains("!isWorksheet")),
        "expected exact nested call in inverse results: {inverse}"
    );
}
