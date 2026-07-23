mod common;

use brokk_bifrost::{Language, SearchToolsService, searchtools_render::RenderOptions};
use common::InlineTestProject;
use serde_json::Value;
use std::sync::{LazyLock, Mutex};

static LOOKUP_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

const ISSUE_1016_JOBCTRL: &str = include_str!("fixtures/scala-issue-1016/JobCtrl.scala");
const ISSUE_1068_VCSSPEC: &str = include_str!("fixtures/scala-issue-1068/VCSSpec.scala");

fn scala_class_end_byte(language: tree_sitter::Language, source: &str, name: &str) -> usize {
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("Scala language");
    let tree = parser.parse(source, None).expect("Scala parse tree");
    let mut pending = vec![tree.root_node()];
    while let Some(node) = pending.pop() {
        if node.kind() == "class_definition"
            && node
                .child_by_field_name("name")
                .is_some_and(|child| &source[child.byte_range()] == name)
        {
            return node.end_byte();
        }

        let mut cursor = node.walk();
        pending.extend(node.named_children(&mut cursor));
    }
    panic!("missing Scala class {name}");
}

fn call_tool(project: &common::BuiltInlineTestProject, tool: &str, args: &str) -> Value {
    let _guard = LOOKUP_LOCK.lock().expect("lookup lock poisoned");
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");
    let payload = service
        .call_tool_json(tool, args)
        .expect("tool call failed");
    serde_json::from_str(&payload).expect("tool returned invalid JSON")
}

fn call_tool_payload(project: &common::BuiltInlineTestProject, tool: &str, args: &str) -> Value {
    let _guard = LOOKUP_LOCK.lock().expect("lookup lock poisoned");
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");
    let payload = service
        .call_tool_payload_json(tool, args, RenderOptions::default())
        .expect("tool call failed");
    serde_json::from_str(&payload).expect("tool returned invalid JSON")
}

fn string_array(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("array")
        .iter()
        .map(|item| item.as_str().expect("string").to_string())
        .collect()
}

fn string_value(value: &Value) -> &str {
    value.as_str().expect("string")
}

fn not_found_input(value: &Value) -> &str {
    value["input"].as_str().expect("not_found input")
}

fn not_found_note(value: &Value) -> &str {
    value["note"].as_str().expect("not_found note")
}

fn searched_function_symbols(result: &Value) -> Vec<String> {
    result["files"]
        .as_array()
        .expect("search files")
        .iter()
        .flat_map(|file| file["functions"].as_array().expect("search functions"))
        .map(|function| {
            function["symbol"]
                .as_str()
                .expect("function symbol")
                .to_string()
        })
        .collect()
}

fn searched_symbols(result: &Value) -> Vec<String> {
    const BUCKETS: [&str; 5] = ["classes", "functions", "fields", "modules", "macros"];
    result["files"]
        .as_array()
        .expect("search files")
        .iter()
        .flat_map(|file| {
            BUCKETS.into_iter().flat_map(move |bucket| {
                file[bucket]
                    .as_array()
                    .expect("search symbol bucket")
                    .iter()
            })
        })
        .map(|symbol| {
            symbol["symbol"]
                .as_str()
                .expect("searched symbol")
                .to_string()
        })
        .collect()
}

fn assert_symbol_source_contains(
    project: &common::BuiltInlineTestProject,
    selector: &str,
    expected_source: &str,
) -> Value {
    let search_args =
        serde_json::json!({ "patterns": [selector], "include_tests": true, "limit": 5 })
            .to_string();
    let search = call_tool(project, "search_symbols", &search_args);
    assert!(
        searched_symbols(&search)
            .iter()
            .any(|symbol| symbol == selector),
        "{search}"
    );

    let args = serde_json::json!({ "symbols": [selector] }).to_string();
    let result = call_tool(project, "get_symbol_sources", &args);
    assert_eq!(0, result["not_found"].as_array().unwrap().len(), "{result}");
    assert_eq!(0, result["ambiguous"].as_array().unwrap().len(), "{result}");
    assert_eq!(1, result["sources"].as_array().unwrap().len(), "{result}");
    assert!(
        result["sources"][0]["text"]
            .as_str()
            .expect("source text")
            .contains(expected_source),
        "{result}"
    );
    result
}

#[test]
fn symbol_sources_disambiguates_anonymous_js_default_exports_by_file_selector() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "src/plugin/a/index.js",
            "export default function () {\n  return 'a';\n}\n",
        )
        .file(
            "src/plugin/b/index.js",
            "export default function () {\n  return 'b';\n}\n",
        )
        .build();

    let bare = call_tool(&project, "get_symbol_sources", r#"{"symbols":["default"]}"#);
    assert_eq!(0, bare["sources"].as_array().unwrap().len(), "{bare}");
    assert_eq!(0, bare["not_found"].as_array().unwrap().len(), "{bare}");
    assert_eq!(1, bare["ambiguous"].as_array().unwrap().len(), "{bare}");
    assert_eq!("default", bare["ambiguous"][0]["target"], "{bare}");
    assert_eq!(
        vec![
            "src/plugin/a/index.js#default".to_string(),
            "src/plugin/b/index.js#default".to_string(),
        ],
        string_array(&bare["ambiguous"][0]["matches"]),
        "{bare}"
    );
    let note = string_value(&bare["ambiguous"][0]["note"]);
    assert!(
        note.contains("Ambiguous; re-call with one selector from `matches`"),
        "{bare}"
    );
    assert!(note.contains("src/plugin/a/index.js#default"), "{bare}");

    let anchored = call_tool(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["src/plugin/a/index.js#default"]}"#,
    );
    assert_eq!(
        0,
        anchored["ambiguous"].as_array().unwrap().len(),
        "{anchored}"
    );
    assert_eq!(
        0,
        anchored["not_found"].as_array().unwrap().len(),
        "{anchored}"
    );
    assert_eq!(
        1,
        anchored["sources"].as_array().unwrap().len(),
        "{anchored}"
    );
    assert_eq!(
        "src/plugin/a/index.js", anchored["sources"][0]["path"],
        "{anchored}"
    );
    assert!(
        anchored["sources"][0]["text"]
            .as_str()
            .unwrap()
            .contains("return 'a'"),
        "{anchored}"
    );
}

#[test]
fn symbol_sources_disambiguates_same_named_js_functions_by_file_selector() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file("src/a.js", "export function helper() {\n  return 'a';\n}\n")
        .file("src/b.js", "export function helper() {\n  return 'b';\n}\n")
        .build();

    let bare = call_tool(&project, "get_symbol_sources", r#"{"symbols":["helper"]}"#);
    assert_eq!(0, bare["sources"].as_array().unwrap().len(), "{bare}");
    assert_eq!(1, bare["ambiguous"].as_array().unwrap().len(), "{bare}");
    assert_eq!(
        vec!["src/a.js#helper".to_string(), "src/b.js#helper".to_string()],
        string_array(&bare["ambiguous"][0]["matches"]),
        "{bare}"
    );

    let anchored = call_tool(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["src/b.js#helper"]}"#,
    );
    assert_eq!(
        0,
        anchored["ambiguous"].as_array().unwrap().len(),
        "{anchored}"
    );
    assert_eq!(
        0,
        anchored["not_found"].as_array().unwrap().len(),
        "{anchored}"
    );
    assert_eq!(
        1,
        anchored["sources"].as_array().unwrap().len(),
        "{anchored}"
    );
    assert_eq!("src/b.js", anchored["sources"][0]["path"], "{anchored}");
    assert!(
        anchored["sources"][0]["text"]
            .as_str()
            .unwrap()
            .contains("return 'b'"),
        "{anchored}"
    );
}

#[test]
fn symbol_sources_accepts_path_colon_selector_spellings() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "src/a.js",
            r#"export class Duration {
  get() {
    return 'a';
  }
}
"#,
        )
        .file(
            "src/b.js",
            r#"export class Duration {
  get() {
    return 'b';
  }
}
"#,
        )
        .build();

    for selector in ["src/a.js::Duration.get", "src/a.js:Duration.get"] {
        let result = call_tool(
            &project,
            "get_symbol_sources",
            &format!(r#"{{"symbols":["{selector}"]}}"#),
        );

        assert_eq!(0, result["ambiguous"].as_array().unwrap().len(), "{result}");
        assert_eq!(0, result["not_found"].as_array().unwrap().len(), "{result}");
        assert_eq!(1, result["sources"].as_array().unwrap().len(), "{result}");
        assert_eq!("src/a.js", result["sources"][0]["path"], "{result}");
        assert!(
            result["sources"][0]["text"]
                .as_str()
                .unwrap()
                .contains("return 'a'"),
            "{result}"
        );

        let locations = call_tool(
            &project,
            "get_symbol_locations",
            &serde_json::json!({ "symbols": [selector] }).to_string(),
        );
        assert_eq!(
            0,
            locations["not_found"].as_array().unwrap().len(),
            "{locations}"
        );
        assert_eq!(
            1,
            locations["locations"].as_array().unwrap().len(),
            "{locations}"
        );
    }
}

#[test]
fn symbol_sources_reports_ambiguous_path_colon_selector_anchor() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file("src/a.js", "export function helper() { return 'src'; }\n")
        .file("lib/a.js", "export function helper() { return 'lib'; }\n")
        .build();

    let result = call_tool(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["a.js:helper"]}"#,
    );

    assert_eq!(0, result["sources"].as_array().unwrap().len(), "{result}");
    assert_eq!(0, result["not_found"].as_array().unwrap().len(), "{result}");
    assert_eq!(
        1,
        result["ambiguous_paths"].as_array().unwrap().len(),
        "{result}"
    );
    assert_eq!("a.js", result["ambiguous_paths"][0]["input"], "{result}");
    assert_eq!(
        vec!["lib/a.js".to_string(), "src/a.js".to_string()],
        string_array(&result["ambiguous_paths"][0]["matches"]),
        "{result}"
    );
}

#[test]
fn symbol_sources_preserves_java_overloads_as_one_non_module_scoped_definition() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/pkg/Widget.java",
            r#"package pkg;
class Widget {
    int run(int value) { return value; }
    String run(String value) { return value; }
}
"#,
        )
        .build();

    let result = call_tool(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["pkg.Widget.run"]}"#,
    );
    assert_eq!(0, result["ambiguous"].as_array().unwrap().len(), "{result}");
    assert_eq!(0, result["not_found"].as_array().unwrap().len(), "{result}");
    assert_eq!(2, result["sources"].as_array().unwrap().len(), "{result}");
    assert!(
        result["sources"]
            .as_array()
            .unwrap()
            .iter()
            .any(|source| source["text"].as_str().unwrap().contains("int run")),
        "{result}"
    );
    assert!(
        result["sources"]
            .as_array()
            .unwrap()
            .iter()
            .any(|source| source["text"].as_str().unwrap().contains("String run")),
        "{result}"
    );
}

#[test]
fn symbol_sources_resolves_lombok_generated_accessors_to_backing_fields() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/main/java/example/Statement.java",
            r#"package example;
import lombok.Data;
import lombok.Getter;

@Data
class Statement {
    private final String sqlStatementContext;

    @Getter
    private boolean ready;
}
"#,
        )
        .build();

    for (selector, field) in [
        (
            "example.Statement.getSqlStatementContext",
            "private final String sqlStatementContext;",
        ),
        ("example.Statement.isReady", "private boolean ready;"),
        (
            "src/main/java/example/Statement.java#example.Statement.getSqlStatementContext",
            "private final String sqlStatementContext;",
        ),
    ] {
        let args = serde_json::json!({ "symbols": [selector] }).to_string();
        let result = call_tool(&project, "get_symbol_sources", &args);
        assert_eq!(0, result["not_found"].as_array().unwrap().len(), "{result}");
        assert_eq!(1, result["sources"].as_array().unwrap().len(), "{result}");
        assert!(
            result["sources"][0]["text"]
                .as_str()
                .is_some_and(|source| source.contains(field)),
            "{selector}: {result}"
        );
    }
}

#[test]
fn symbol_sources_does_not_invent_unannotated_java_accessors() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/main/java/example/Statement.java",
            "package example; class Statement { private String sql; }\n",
        )
        .build();

    let result = call_tool(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["example.Statement.getSql"]}"#,
    );

    assert_eq!(0, result["sources"].as_array().unwrap().len(), "{result}");
    assert_eq!(1, result["not_found"].as_array().unwrap().len(), "{result}");
}

#[test]
fn symbol_sources_disambiguates_exact_scala_class_and_companion_selectors() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "org/thp/cortex/dto/v0/Artifact.scala",
            r#"
package org.thp.cortex.dto.v0

class InputArtifact(value: String)
object InputArtifact {
  def writes: String = "writes"
}
"#,
        )
        .build();

    let bare = call_tool(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["org.thp.cortex.dto.v0.InputArtifact"]}"#,
    );
    assert_eq!(1, bare["sources"].as_array().unwrap().len(), "{bare}");
    assert_eq!(0, bare["ambiguous"].as_array().unwrap().len(), "{bare}");
    assert_eq!(0, bare["not_found"].as_array().unwrap().len(), "{bare}");
    assert!(
        bare["sources"][0]["text"]
            .as_str()
            .unwrap()
            .contains("class InputArtifact"),
        "{bare}"
    );

    let companion = call_tool(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["org.thp.cortex.dto.v0.InputArtifact$"]}"#,
    );
    assert_eq!(
        1,
        companion["sources"].as_array().unwrap().len(),
        "{companion}"
    );
    assert_eq!(
        0,
        companion["ambiguous"].as_array().unwrap().len(),
        "{companion}"
    );
    assert_eq!(
        0,
        companion["not_found"].as_array().unwrap().len(),
        "{companion}"
    );
    assert!(
        companion["sources"][0]["presentation"].is_null(),
        "{companion}"
    );
    assert!(
        companion["sources"][0]["text"]
            .as_str()
            .unwrap()
            .contains("object InputArtifact"),
        "{companion}"
    );
    assert!(
        companion["sources"][0]["text"]
            .as_str()
            .unwrap()
            .contains("def writes"),
        "{companion}"
    );
}

#[test]
fn scala_opaque_type_alias_is_a_distinct_source_backed_field_symbol() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "kyo/Fiber.scala",
            r#"package kyo

object Fiber {
  object Promise {
    opaque type Unsafe = String
    object Unsafe
  }
}
"#,
        )
        .build();

    let search = call_tool(
        &project,
        "search_symbols",
        r#"{"patterns":["Fiber.Promise.Unsafe"],"include_tests":true,"limit":5}"#,
    );
    let aliases = search["files"]
        .as_array()
        .expect("search files")
        .iter()
        .flat_map(|file| file["fields"].as_array().expect("field bucket"))
        .filter(|field| field["symbol"] == "kyo.Fiber.Promise.Unsafe")
        .collect::<Vec<_>>();
    assert_eq!(aliases.len(), 1, "{search}");

    let alias = call_tool(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["kyo.Fiber$.Promise$.Unsafe"]}"#,
    );
    assert_eq!(
        alias["sources"].as_array().map(Vec::len),
        Some(1),
        "{alias}"
    );
    assert_eq!(
        alias["ambiguous"].as_array().map(Vec::len),
        Some(0),
        "{alias}"
    );
    assert_eq!(
        alias["not_found"].as_array().map(Vec::len),
        Some(0),
        "{alias}"
    );
    assert_eq!(
        alias["sources"][0]["text"].as_str().map(str::trim),
        Some("opaque type Unsafe = String"),
        "{alias}"
    );

    let companion = call_tool(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["kyo.Fiber$.Promise$.Unsafe$"]}"#,
    );
    assert_eq!(
        companion["sources"].as_array().map(Vec::len),
        Some(1),
        "{companion}"
    );
    assert!(
        companion["sources"][0]["text"]
            .as_str()
            .is_some_and(|text| text.contains("object Unsafe")),
        "{companion}"
    );
}

#[test]
fn symbol_sources_resolves_scala_annotated_class_and_owner_qualified_method() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "org/thp/thehive/controllers/v1/Properties.scala",
            r#"
package org.thp.thehive.controllers.v1

@Singleton
class Properties @Inject() (
    @Named("with-thehive-schema") db: Database
) {
  lazy val metaProperties: PublicProperties = PublicPropertyListBuilder.build
}
"#,
        )
        .file(
            "org/thp/thehive/connector/cortex/services/JobSrv.scala",
            r#"
package org.thp.thehive.connector.cortex.services

@Singleton
class JobSrv @Inject() (
    implicit val db: Database
) extends VertexSrv[Job] {
  val observableJobSrv = new EdgeSrv[ObservableJob, Observable, Job]
  def submit(id: String): Unit = {}
}
"#,
        )
        .build();

    let result = call_tool(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["org.thp.thehive.controllers.v1.Properties","org.thp.thehive.connector.cortex.services.JobSrv.submit"]}"#,
    );

    assert_eq!(0, result["ambiguous"].as_array().unwrap().len(), "{result}");
    assert_eq!(0, result["not_found"].as_array().unwrap().len(), "{result}");
    assert_eq!(2, result["sources"].as_array().unwrap().len(), "{result}");
    assert!(
        result["sources"]
            .as_array()
            .unwrap()
            .iter()
            .any(|source| source["text"]
                .as_str()
                .unwrap()
                .contains("class Properties")),
        "{result}"
    );
    assert!(
        result["sources"]
            .as_array()
            .unwrap()
            .iter()
            .any(|source| source["text"].as_str().unwrap().contains("def submit")),
        "{result}"
    );
}

#[test]
fn issue_1016_scala_annotated_constructor_supports_sources_and_body_reference_context() {
    // This integration binary deliberately links the old published grammar
    // beside Bifrost. Its JobCtrl remains truncated, while the service below
    // must use Bifrost's private, fixed parser symbols and return the body.
    let published_end = scala_class_end_byte(
        tree_sitter_scala::LANGUAGE.into(),
        ISSUE_1016_JOBCTRL,
        "JobCtrl",
    );
    assert!(
        published_end
            < ISSUE_1016_JOBCTRL
                .find("def create")
                .expect("create method"),
        "the coexistence control unexpectedly used Bifrost's fixed parser"
    );

    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "org/thp/thehive/connector/cortex/controllers/v0/JobCtrl.scala",
            ISSUE_1016_JOBCTRL,
        )
        .file(
            "org/thp/thehive/connector/cortex/services/JobSrv.scala",
            r#"package org.thp.thehive.connector.cortex.services

class JobSrv {
  def submit(
      cortexId: String,
      analyzerId: String,
      observable: Any,
      richCase: Any,
      parameters: Any
  ): Unit = ()
}
"#,
        )
        .build();

    let source_result = call_tool(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["org.thp.thehive.connector.cortex.controllers.v0.JobCtrl"]}"#,
    );
    assert_eq!(
        source_result["sources"].as_array().map(Vec::len),
        Some(1),
        "{source_result}"
    );
    assert_eq!(
        source_result["ambiguous"].as_array().map(Vec::len),
        Some(0),
        "{source_result}"
    );
    assert_eq!(
        source_result["not_found"].as_array().map(Vec::len),
        Some(0),
        "{source_result}"
    );
    let source = source_result["sources"][0]["text"]
        .as_str()
        .expect("JobCtrl source text");
    assert!(
        source.contains("override val entrypoint: Entrypoint"),
        "{source}"
    );
    assert!(
        source.contains("def create: Action[AnyContent]"),
        "{source}"
    );
    assert!(source.contains("jobSrv"), "{source}");
    assert!(
        source
            .contains(".submit(cortexId, analyzerId, o, c, parameters.getOrElse(JsObject.empty))"),
        "{source}"
    );
    assert!(!source.contains("class PublicJob"), "{source}");

    let reference_args = serde_json::json!({
        "references": [{
            "symbol": "org.thp.thehive.connector.cortex.controllers.v0.JobCtrl",
            "context": ".submit(cortexId, analyzerId, o, c, parameters.getOrElse(JsObject.empty))",
            "target": "submit"
        }]
    })
    .to_string();
    let reference_result = call_tool(&project, "get_definitions_by_reference", &reference_args);
    let result = &reference_result["results"][0];
    assert_eq!(result["status"], "resolved", "{reference_result}");
    assert!(
        result["definitions"]
            .as_array()
            .is_some_and(|definitions| definitions.iter().any(|definition| {
                definition["fqn"] == "org.thp.thehive.connector.cortex.services.JobSrv.submit"
            })),
        "{reference_result}"
    );
}

#[test]
fn issue_1068_scala_empty_lambda_supports_complete_symbol_source() {
    let published_end = scala_class_end_byte(
        tree_sitter_scala::LANGUAGE.into(),
        ISSUE_1068_VCSSPEC,
        "VCSSpec",
    );
    assert!(
        published_end
            < ISSUE_1068_VCSSPEC
                .find("def after")
                .expect("following method"),
        "the published-parser control unexpectedly retained the full class"
    );

    let project = InlineTestProject::with_language(Language::Scala)
        .file("svsimTests/VCSSpec.scala", ISSUE_1068_VCSSPEC)
        .build();
    let result = call_tool(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["svsimTests.VCSSpec"]}"#,
    );

    assert_eq!(
        result["sources"].as_array().map(Vec::len),
        Some(1),
        "{result}"
    );
    assert_eq!(
        result["not_found"].as_array().map(Vec::len),
        Some(0),
        "{result}"
    );
    let source = result["sources"][0]["text"]
        .as_str()
        .expect("VCSSpec source");
    assert!(source.contains("simulation.run("), "{source}");
    assert!(source.contains("def after(): Int"), "{source}");
    assert!(!source.contains("class FollowingSpec"), "{source}");
}

#[test]
fn summaries_and_ancestors_accept_js_file_anchored_selectors() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "src/a.js",
            r#"class BaseA {}
export class Widget extends BaseA {
  render() {}
}
"#,
        )
        .file(
            "src/b.js",
            r#"class BaseB {}
export class Widget extends BaseB {
  render() {}
}
"#,
        )
        .build();

    let bare_summary = call_tool(&project, "get_summaries", r#"{"targets":["Widget"]}"#);
    assert_eq!(
        0,
        bare_summary["summaries"].as_array().unwrap().len(),
        "{bare_summary}"
    );
    assert_eq!(
        vec!["src/a.js#Widget".to_string(), "src/b.js#Widget".to_string()],
        string_array(&bare_summary["ambiguous"][0]["matches"]),
        "{bare_summary}"
    );
    let summary_note = string_value(&bare_summary["ambiguous"][0]["note"]);
    assert!(
        summary_note.contains("Ambiguous; re-call with one selector from `matches`"),
        "{bare_summary}"
    );
    assert!(summary_note.contains("src/a.js#Widget"), "{bare_summary}");

    let anchored_summary = call_tool(
        &project,
        "get_summaries",
        r#"{"targets":["src/a.js#Widget"]}"#,
    );
    assert_eq!(
        0,
        anchored_summary["ambiguous"].as_array().unwrap().len(),
        "{anchored_summary}"
    );
    assert_eq!(
        1,
        anchored_summary["summaries"].as_array().unwrap().len(),
        "{anchored_summary}"
    );
    assert_eq!(
        "src/a.js", anchored_summary["summaries"][0]["path"],
        "{anchored_summary}"
    );

    let bare_ancestors = call_tool(
        &project,
        "get_symbol_ancestors",
        r#"{"symbols":["Widget"]}"#,
    );
    assert_eq!(
        0,
        bare_ancestors["ancestors"].as_array().unwrap().len(),
        "{bare_ancestors}"
    );
    assert_eq!(
        vec!["src/a.js#Widget".to_string(), "src/b.js#Widget".to_string()],
        string_array(&bare_ancestors["ambiguous"][0]["matches"]),
        "{bare_ancestors}"
    );
    let ancestors_note = string_value(&bare_ancestors["ambiguous"][0]["note"]);
    assert!(
        ancestors_note.contains("Ambiguous; re-call with one selector from `matches`"),
        "{bare_ancestors}"
    );
    assert!(
        ancestors_note.contains("src/a.js#Widget"),
        "{bare_ancestors}"
    );

    let anchored_ancestors = call_tool(
        &project,
        "get_symbol_ancestors",
        r#"{"symbols":["src/b.js#Widget"]}"#,
    );
    assert_eq!(
        0,
        anchored_ancestors["ambiguous"].as_array().unwrap().len(),
        "{anchored_ancestors}"
    );
    assert_eq!(
        1,
        anchored_ancestors["ancestors"].as_array().unwrap().len(),
        "{anchored_ancestors}"
    );
    assert_eq!(
        "Widget", anchored_ancestors["ancestors"][0]["symbol"],
        "{anchored_ancestors}"
    );
    assert_eq!(
        vec!["BaseB".to_string()],
        string_array(&anchored_ancestors["ancestors"][0]["ancestors"]),
        "{anchored_ancestors}"
    );
}

#[test]
fn summaries_route_file_anchored_selector_with_extension_like_symbol_member() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "src/a.js",
            r#"export class styles {
  css() {
    return 'a';
  }
}
"#,
        )
        .file(
            "src/b.js",
            r#"export class styles {
  css() {
    return 'b';
  }
}
"#,
        )
        .build();

    let result = call_tool(
        &project,
        "get_summaries",
        r#"{"targets":["src/a.js#styles.css"]}"#,
    );

    assert_eq!(0, result["ambiguous"].as_array().unwrap().len(), "{result}");
    assert_eq!(0, result["not_found"].as_array().unwrap().len(), "{result}");
    assert_eq!(1, result["summaries"].as_array().unwrap().len(), "{result}");
    assert_eq!("src/a.js", result["summaries"][0]["path"], "{result}");
    assert_eq!("styles.css", result["summaries"][0]["label"], "{result}");
}

#[test]
fn ancestors_batch_returns_valid_class_and_reports_non_type_target() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "src/main.js",
            r#"class Base {}
export class ValidClass extends Base {}
export function someFunction() {}
"#,
        )
        .build();

    let result = call_tool(
        &project,
        "get_symbol_ancestors",
        r#"{"symbols":["ValidClass","someFunction"]}"#,
    );

    assert_eq!(1, result["ancestors"].as_array().unwrap().len(), "{result}");
    assert_eq!("ValidClass", result["ancestors"][0]["symbol"], "{result}");
    assert_eq!(
        vec!["Base".to_string()],
        string_array(&result["ancestors"][0]["ancestors"]),
        "{result}"
    );
    assert_eq!(1, result["not_found"].as_array().unwrap().len(), "{result}");
    assert_eq!(
        "someFunction",
        not_found_input(&result["not_found"][0]),
        "{result}"
    );
    assert_eq!(
        "resolves to a function; get_symbol_ancestors only accepts class/module/type symbols",
        not_found_note(&result["not_found"][0]),
        "{result}"
    );
}

#[test]
fn anchored_selector_wrong_path_reports_anchor_recovery_note() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file("src/a.js", "export class Widget {}\n")
        .build();

    let result = call_tool(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["src/wrong.js#Widget"]}"#,
    );

    assert_eq!(0, result["sources"].as_array().unwrap().len(), "{result}");
    assert_eq!(1, result["not_found"].as_array().unwrap().len(), "{result}");
    assert_eq!(
        "src/wrong.js#Widget",
        not_found_input(&result["not_found"][0]),
        "{result}"
    );
    assert_eq!(
        "`Widget` resolved, but no definition is in `src/wrong.js`; re-call with the bare name to list valid selectors",
        not_found_note(&result["not_found"][0]),
        "{result}"
    );
}

#[test]
fn java_class_without_explicit_constructor_does_not_advertise_constructor_symbol() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/main/java/org/example/EventPublisherTest.java",
            "package org.example;\n\nclass EventPublisherTest {}\n",
        )
        .build();

    let search = call_tool(
        &project,
        "search_symbols",
        r#"{"patterns":["EventPublisherTest"],"include_tests":true,"limit":5}"#,
    );
    assert!(
        !searched_function_symbols(&search)
            .iter()
            .any(|symbol| symbol == "org.example.EventPublisherTest.EventPublisherTest"),
        "{search}"
    );

    let bare = call_tool(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["EventPublisherTest"]}"#,
    );
    assert_eq!(1, bare["sources"].as_array().unwrap().len(), "{bare}");
    assert_eq!(0, bare["not_found"].as_array().unwrap().len(), "{bare}");
    assert_eq!(0, bare["ambiguous"].as_array().unwrap().len(), "{bare}");
    assert_eq!(
        "org.example.EventPublisherTest", bare["sources"][0]["label"],
        "{bare}"
    );
    assert!(bare["sources"][0]["note"].is_null(), "{bare}");
    assert!(
        bare["sources"][0]["text"]
            .as_str()
            .unwrap()
            .contains("class EventPublisherTest {}"),
        "{bare}"
    );
}

#[test]
fn java_package_module_round_trips_through_search_source_and_location_tools() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/main/java/org/example/Thing.java",
            "package org.example;\nclass Thing {}\n",
        )
        .build();

    let source = assert_symbol_source_contains(&project, "org.example", "Thing");
    assert_eq!("file_listing", source["sources"][0]["presentation"]);
    let note = source["sources"][0]["note"].as_str().expect("source note");
    assert!(note.contains("module target"), "{source}");
    assert!(note.contains("get_summaries"), "{source}");
    assert!(
        !source
            .to_string()
            .contains("Module/object lookup returns defining files"),
        "{source}"
    );

    let locations = call_tool(
        &project,
        "get_symbol_locations",
        r#"{"symbols":["org.example"]}"#,
    );
    assert_eq!(0, locations["not_found"].as_array().unwrap().len());
    assert_eq!(1, locations["locations"].as_array().unwrap().len());
    assert_eq!("org.example", locations["locations"][0]["symbol"]);
    assert_eq!(1, locations["locations"][0]["start_line"]);
}

#[test]
fn python_dotted_module_selector_returns_outline_and_guidance() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "pkg/utils.py",
            "CONSTANT = 1\n\ndef normalize(value):\n    return value\n\nclass Helper:\n    pass\n",
        )
        .build();

    let payload = call_tool_payload(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["pkg.utils"]}"#,
    );
    let result = &payload["structured"];
    assert_eq!(
        0,
        result["not_found"].as_array().unwrap().len(),
        "{payload}"
    );
    assert_eq!(
        0,
        result["ambiguous"].as_array().unwrap().len(),
        "{payload}"
    );
    assert_eq!(1, result["sources"].as_array().unwrap().len(), "{payload}");

    let source = &result["sources"][0];
    assert_eq!("file_listing", source["presentation"], "{payload}");
    let text = source["text"].as_str().expect("source text");
    assert!(text.contains("normalize"), "{payload}");
    assert!(text.contains("Helper"), "{payload}");
    let note = source["note"].as_str().expect("source note");
    assert!(note.contains("module target"), "{payload}");
    assert!(note.contains("get_summaries"), "{payload}");
    assert!(
        !payload
            .to_string()
            .contains("Module/object lookup returns defining files"),
        "{payload}"
    );
}

#[test]
fn bare_js_filename_module_selector_returns_outline_and_path_symbol_guidance() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file("tests/unit/components/setup.js", "export const seed = 1;\n")
        .file(
            "tests/unit/components/widget.spec.js",
            "import { seed } from './setup.js';\nexport const subject = 'widget';\nexport function buildsWidget() {\n  return seed + subject.length;\n}\n",
        )
        .build();

    let payload = call_tool_payload(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["widget.spec.js"]}"#,
    );
    let result = &payload["structured"];
    assert_eq!(
        0,
        result["not_found"].as_array().unwrap().len(),
        "{payload}"
    );
    assert_eq!(
        0,
        result["ambiguous"].as_array().unwrap().len(),
        "{payload}"
    );
    assert_eq!(1, result["sources"].as_array().unwrap().len(), "{payload}");

    let source = &result["sources"][0];
    assert_eq!("file_listing", source["presentation"], "{payload}");
    assert!(
        source["text"]
            .as_str()
            .expect("source text")
            .contains("buildsWidget"),
        "{payload}"
    );
    let note = source["note"].as_str().expect("source note");
    assert!(note.contains("path#symbol"), "{payload}");
    assert!(note.contains("get_summaries"), "{payload}");
    assert!(
        !payload
            .to_string()
            .contains("Module/object lookup returns defining files"),
        "{payload}"
    );
}

#[test]
fn dotted_js_filename_selectors_resolve_fields_and_functions_consistently() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "packages/converters/src/utils/bruno-to-postman-translator.js",
            "export const simpleTranslations = {};\nexport const complexTransformations = {};\nexport function processAllTransformations() { return simpleTranslations; }\nexport class Translator { process() { return simpleTranslations; } }\n",
        )
        .build();

    for (selector, expected) in [
        (
            "bruno-to-postman-translator.js.simpleTranslations",
            "simpleTranslations = {}",
        ),
        (
            "bruno-to-postman-translator.js.complexTransformations",
            "complexTransformations = {}",
        ),
        (
            "bruno-to-postman-translator.js.processAllTransformations",
            "function processAllTransformations()",
        ),
        (
            "packages/converters/src/utils/bruno-to-postman-translator.js.Translator.process",
            "process() { return simpleTranslations; }",
        ),
    ] {
        let args = serde_json::json!({ "symbols": [selector] }).to_string();
        let result = call_tool(&project, "get_symbol_sources", &args);
        assert_eq!(0, result["not_found"].as_array().unwrap().len(), "{result}");
        assert_eq!(0, result["ambiguous"].as_array().unwrap().len(), "{result}");
        assert_eq!(1, result["sources"].as_array().unwrap().len(), "{result}");
        assert!(
            result["sources"][0]["text"]
                .as_str()
                .expect("source text")
                .contains(expected),
            "{result}"
        );
    }
}

#[test]
fn csharp_generic_arity_selectors_resolve_indexed_source_names() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "DownloadClientFixtureBase.cs",
            "namespace NzbDrone.Core.Test.Download;\nclass DownloadClientFixtureBase { public void Verify(int value) {} }\nclass DownloadClientFixtureBase<T> { public void Verify(T value) {} public U Convert<U>(T value) { return default(U); } }\n",
        )
        .build();

    for (selector, expected) in [
        (
            "NzbDrone.Core.Test.Download.DownloadClientFixtureBase`1",
            "class DownloadClientFixtureBase<T>",
        ),
        (
            "NzbDrone.Core.Test.Download.DownloadClientFixtureBase`1.Verify",
            "void Verify(T value)",
        ),
        (
            "NzbDrone.Core.Test.Download.DownloadClientFixtureBase`1.Convert``1",
            "U Convert<U>(T value)",
        ),
    ] {
        let result = call_tool(
            &project,
            "get_symbol_sources",
            &serde_json::json!({ "symbols": [selector] }).to_string(),
        );
        assert_eq!(0, result["not_found"].as_array().unwrap().len(), "{result}");
        assert_eq!(0, result["ambiguous"].as_array().unwrap().len(), "{result}");
        assert_eq!(1, result["sources"].as_array().unwrap().len(), "{result}");
        assert!(
            result["sources"][0]["text"]
                .as_str()
                .expect("source text")
                .contains(expected),
            "{result}"
        );
    }
}

// ---------------------------------------------------------------------------
// C/C++ elaborated-type-specifier tag selectors (issue #1019, shape 1)
//
// Agents naturally spell C/C++ type references the way a use site requires
// (`struct git_refdb`, `enum Color`, `union Value`), including through the
// existing `path::symbol`/`path#symbol` selector routes, but Bifrost indexes
// the bare type identifier. `struct git_refdb` must resolve/ambiguate exactly
// like the keyword-free `git_refdb` in every selector shape.
// ---------------------------------------------------------------------------

#[test]
fn c_struct_tag_selectors_resolve_like_their_keyword_free_spelling() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "src/libgit2/refdb.h",
            "struct git_refdb {\n    int backend_flags;\n};\n",
        )
        .file(
            "include/git2/types.h",
            "struct git_refdb {\n    int placeholder;\n};\n",
        )
        .build();

    // Bare `struct git_refdb` must ambiguate exactly like bare `git_refdb`:
    // two same-named top-level tag declarations in different files.
    let tagged = call_tool(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["struct git_refdb"]}"#,
    );
    let bare = call_tool(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["git_refdb"]}"#,
    );
    assert_eq!(0, tagged["not_found"].as_array().unwrap().len(), "{tagged}");
    assert_eq!(
        bare["ambiguous"][0]["matches"], tagged["ambiguous"][0]["matches"],
        "tagged: {tagged}, bare: {bare}"
    );
    assert_eq!(
        2,
        tagged["ambiguous"][0]["matches"].as_array().unwrap().len()
    );

    // `path::struct X` and `path#struct X` must each resolve to the single
    // definition in that file, exactly like the keyword-free anchored form.
    for (selector, keyword_free, expected_snippet) in [
        (
            "src/libgit2/refdb.h::struct git_refdb",
            "src/libgit2/refdb.h::git_refdb",
            "backend_flags",
        ),
        (
            "src/libgit2/refdb.h#struct git_refdb",
            "src/libgit2/refdb.h#git_refdb",
            "backend_flags",
        ),
        (
            "include/git2/types.h::struct git_refdb",
            "include/git2/types.h::git_refdb",
            "placeholder",
        ),
    ] {
        let tagged = call_tool(
            &project,
            "get_symbol_sources",
            &format!(r#"{{"symbols":["{selector}"]}}"#),
        );
        let keyword_free_result = call_tool(
            &project,
            "get_symbol_sources",
            &format!(r#"{{"symbols":["{keyword_free}"]}}"#),
        );
        assert_eq!(0, tagged["not_found"].as_array().unwrap().len(), "{tagged}");
        assert_eq!(1, tagged["sources"].as_array().unwrap().len(), "{tagged}");
        assert_eq!(
            tagged["sources"][0]["text"], keyword_free_result["sources"][0]["text"],
            "selector {selector} must resolve identically to {keyword_free}: {tagged}"
        );
        assert!(
            tagged["sources"][0]["text"]
                .as_str()
                .unwrap()
                .contains(expected_snippet),
            "{tagged}"
        );
    }
}

#[test]
fn c_struct_tag_selector_resolves_like_bare_spelling_via_get_definitions_by_reference() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "src/libgit2/refdb.h",
            "int helper(int value) {\n    return value;\n}\n\nstruct git_refdb {\n    int free_id(int value) {\n        return helper(value);\n    }\n};\n",
        )
        .build();

    for (symbol, keyword_free) in [
        (
            "src/libgit2/refdb.h::struct git_refdb.free_id",
            "src/libgit2/refdb.h::git_refdb.free_id",
        ),
        (
            "src/libgit2/refdb.h#struct git_refdb.free_id",
            "src/libgit2/refdb.h#git_refdb.free_id",
        ),
    ] {
        let tagged = call_tool(
            &project,
            "get_definitions_by_reference",
            &serde_json::json!({
                "references": [{
                    "symbol": symbol,
                    "context": "        return helper(value);",
                    "target": "helper"
                }]
            })
            .to_string(),
        );
        let keyword_free_result = call_tool(
            &project,
            "get_definitions_by_reference",
            &serde_json::json!({
                "references": [{
                    "symbol": keyword_free,
                    "context": "        return helper(value);",
                    "target": "helper"
                }]
            })
            .to_string(),
        );
        let tagged = &tagged["results"][0];
        let keyword_free_result = &keyword_free_result["results"][0];
        assert_eq!("resolved", tagged["status"], "{symbol}: {tagged}");
        assert_eq!(
            "helper", tagged["definitions"][0]["fqn"],
            "{symbol}: {tagged}"
        );
        assert_eq!(
            tagged["status"], keyword_free_result["status"],
            "{symbol} vs {keyword_free}"
        );
        assert_eq!(
            tagged["definitions"], keyword_free_result["definitions"],
            "{symbol} vs {keyword_free}"
        );
    }
}

#[test]
fn cpp_enum_and_union_tag_selectors_resolve_like_their_keyword_free_spelling() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "src/values.hpp",
            "enum Color {\n    Red,\n    Green,\n    Blue,\n};\n\nunion Value {\n    int i;\n    float f;\n};\n",
        )
        .build();

    for (selector, expected_snippet) in [
        ("enum Color", "enum Color"),
        ("src/values.hpp::enum Color", "enum Color"),
        ("src/values.hpp#enum Color", "enum Color"),
        ("union Value", "union Value"),
        ("src/values.hpp::union Value", "union Value"),
        ("src/values.hpp#union Value", "union Value"),
    ] {
        let result = call_tool(
            &project,
            "get_symbol_sources",
            &format!(r#"{{"symbols":["{selector}"]}}"#),
        );
        assert_eq!(
            0,
            result["not_found"].as_array().unwrap().len(),
            "{selector} must resolve: {result}"
        );
        assert_eq!(1, result["sources"].as_array().unwrap().len(), "{result}");
        assert!(
            result["sources"][0]["text"]
                .as_str()
                .unwrap()
                .contains(expected_snippet),
            "{selector}: {result}"
        );
    }
}

#[test]
fn java_package_module_returns_deduped_outline_blocks_for_each_defining_file() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/main/java/org/example/Alpha.java",
            "package org.example;\nclass Alpha {}\n",
        )
        .file(
            "src/main/java/org/example/Beta.java",
            "package org.example;\nclass Beta {}\n",
        )
        .build();

    let result = call_tool(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["org.example"]}"#,
    );
    assert_eq!(0, result["not_found"].as_array().unwrap().len(), "{result}");
    assert_eq!(0, result["ambiguous"].as_array().unwrap().len(), "{result}");
    assert_eq!(2, result["sources"].as_array().unwrap().len(), "{result}");

    let sources = result["sources"].as_array().unwrap();
    let paths = sources
        .iter()
        .map(|source| source["path"].as_str().expect("source path"))
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(2, paths.len(), "{result}");
    assert!(
        sources
            .iter()
            .all(|source| source["presentation"] == "file_listing"),
        "{result}"
    );
    assert!(
        sources
            .iter()
            .any(|source| source["text"].as_str().unwrap().contains("Alpha")),
        "{result}"
    );
    assert!(
        sources
            .iter()
            .any(|source| source["text"].as_str().unwrap().contains("Beta")),
        "{result}"
    );
    assert!(
        sources
            .iter()
            .all(|source| source["note"].as_str().unwrap().contains("get_summaries")),
        "{result}"
    );
}

#[test]
fn scala_primary_constructor_symbol_round_trips_to_class_source() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "src/main/scala/app/Service.scala",
            "package app\n\nclass Service(name: String)\n",
        )
        .build();

    let search = call_tool(
        &project,
        "search_symbols",
        r#"{"patterns":["Service"],"include_tests":true,"limit":5}"#,
    );
    assert!(
        searched_function_symbols(&search)
            .iter()
            .any(|symbol| symbol == "app.Service.Service"),
        "{search}"
    );
    assert_symbol_source_contains(
        &project,
        "app.Service.Service",
        "class Service(name: String)",
    );
}

#[test]
fn cpp_constructor_declaration_symbol_round_trips_to_its_source() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "include/service.h",
            "class Service {\npublic:\n    Service() = default;\n};\n",
        )
        .build();

    let search = call_tool(
        &project,
        "search_symbols",
        r#"{"patterns":["Service"],"include_tests":true,"limit":5}"#,
    );
    assert!(
        searched_function_symbols(&search)
            .iter()
            .any(|symbol| symbol == "Service.Service"),
        "{search}"
    );
    assert_symbol_source_contains(&project, "Service.Service", "Service() = default;");
}

#[test]
fn csharp_metadata_constructor_selectors_resolve_explicit_overloads() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Service.cs",
            "namespace App;\nclass Service {\n  public Service() {}\n  public Service(int value) {}\n}\nclass Plain {}\n",
        )
        .build();

    for selector in ["App.Service.#ctor", "Service.cs#App.Service.#ctor"] {
        let args = serde_json::json!({ "symbols": [selector] }).to_string();
        let result = call_tool(&project, "get_symbol_sources", &args);

        assert_eq!(0, result["not_found"].as_array().unwrap().len(), "{result}");
        assert_eq!(0, result["ambiguous"].as_array().unwrap().len(), "{result}");
        let sources = result["sources"].as_array().unwrap();
        assert_eq!(2, sources.len(), "{result}");
        assert!(
            sources
                .iter()
                .all(|source| source["label"] == "App.Service.Service"),
            "{result}"
        );
        assert!(
            sources
                .iter()
                .any(|source| source["text"] == "public Service() {}"),
            "{result}"
        );
        assert!(
            sources
                .iter()
                .any(|source| source["text"] == "public Service(int value) {}"),
            "{result}"
        );
    }

    let missing = call_tool(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["App.Plain.#ctor"]}"#,
    );
    assert_eq!(0, missing["sources"].as_array().unwrap().len(), "{missing}");
    assert_eq!(
        "App.Plain.#ctor",
        not_found_input(&missing["not_found"][0]),
        "{missing}"
    );
}

#[test]
fn explicit_only_language_constructors_round_trip_without_implicit_symbols() {
    let cases = [
        (
            InlineTestProject::with_language(Language::CSharp)
                .file(
                    "Service.cs",
                    "namespace App { class Service { public Service() {} } class Plain {} }\n",
                )
                .build(),
            "App.Service.Service",
            "public Service() {}",
            "App.Plain.Plain",
        ),
        (
            InlineTestProject::with_language(Language::Python)
                .file(
                    "service.py",
                    "class Service:\n    def __init__(self):\n        pass\n\nclass Plain:\n    pass\n",
                )
                .build(),
            "service.Service.__init__",
            "def __init__(self):",
            "service.Plain.__init__",
        ),
        (
            InlineTestProject::with_language(Language::JavaScript)
                .file(
                    "service.js",
                    "class Service { constructor() {} }\nclass Plain {}\n",
                )
                .build(),
            "Service.constructor",
            "constructor() {}",
            "Plain.constructor",
        ),
        (
            InlineTestProject::with_language(Language::TypeScript)
                .file(
                    "service.ts",
                    "class Service { constructor() {} }\nclass Plain {}\n",
                )
                .build(),
            "Service.constructor",
            "constructor() {}",
            "Plain.constructor",
        ),
        (
            InlineTestProject::with_language(Language::Php)
                .file(
                    "Service.php",
                    "<?php\nnamespace App;\nclass Service { public function __construct() {} }\nclass Plain {}\n",
                )
                .build(),
            "App.Service.__construct",
            "public function __construct() {}",
            "App.Plain.__construct",
        ),
        (
            InlineTestProject::with_language(Language::Ruby)
                .file(
                    "service.rb",
                    "class Service\n  def initialize\n  end\nend\n\nclass Plain\nend\n",
                )
                .build(),
            "Service.initialize",
            "def initialize",
            "Plain.initialize",
        ),
    ];

    for (project, explicit_selector, source, implicit_selector) in cases {
        assert_symbol_source_contains(&project, explicit_selector, source);

        let search = call_tool(
            &project,
            "search_symbols",
            r#"{"patterns":["Plain"],"include_tests":true,"limit":5}"#,
        );
        assert!(
            !searched_function_symbols(&search)
                .iter()
                .any(|symbol| symbol == implicit_selector),
            "{search}"
        );
    }
}

#[test]
fn source_less_synthetic_go_replica_is_not_advertised_by_symbol_search() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "settings.go",
            r#"package main

type prefs struct {
    Config, OldConfig struct {
        NodeID string
    }
}
"#,
        )
        .build();

    let search = call_tool(
        &project,
        "search_symbols",
        r#"{"patterns":["NodeID"],"include_tests":true,"limit":5}"#,
    );
    let fields: Vec<_> = search["files"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|file| file["fields"].as_array().unwrap())
        .map(|field| field["symbol"].as_str().unwrap())
        .collect();
    assert!(fields.contains(&"main.prefs.Config.NodeID"), "{search}");
    assert!(!fields.contains(&"main.prefs.OldConfig.NodeID"), "{search}");
    assert_symbol_source_contains(&project, "main.prefs.Config.NodeID", "NodeID");
}

#[test]
fn go_module_scope_symbol_sources_include_full_declarations() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "decls.go",
            r#"package pkg

type Target string
type Alias = Target

var someVar = SomeCall("arg")
const someConst = ConstCall()

var (
    groupedVar = GroupedCall()
    siblingVar = 1
)
"#,
        )
        .build();

    for (selector, expected) in [
        ("pkg._module_.someVar", r#"var someVar = SomeCall("arg")"#),
        ("pkg._module_.someConst", "const someConst = ConstCall()"),
        ("pkg._module_.Alias", "type Alias = Target"),
    ] {
        let result = assert_symbol_source_contains(&project, selector, expected);
        assert!(
            result["sources"][0]["text"]
                .as_str()
                .expect("source text")
                .contains(expected),
            "{result}"
        );
    }

    let short = call_tool(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["pkg.someVar"]}"#,
    );
    assert_eq!(0, short["not_found"].as_array().unwrap().len(), "{short}");
    assert_eq!(0, short["ambiguous"].as_array().unwrap().len(), "{short}");
    assert_eq!(1, short["sources"].as_array().unwrap().len(), "{short}");
    assert!(
        short["sources"][0]["text"]
            .as_str()
            .expect("source text")
            .contains(r#"var someVar = SomeCall("arg")"#),
        "{short}"
    );

    let grouped = assert_symbol_source_contains(
        &project,
        "pkg._module_.groupedVar",
        "groupedVar = GroupedCall()",
    );
    let text = grouped["sources"][0]["text"].as_str().unwrap();
    assert!(!text.contains("siblingVar"), "{grouped}");
}

#[test]
fn go_module_prefixed_file_paths_resolve_from_nested_module_root() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("lib/go.mod", "module github.com/eko/gocache/lib/v4\n")
        .file(
            "lib/cache/chain.go",
            "package cache\n\ntype Chain struct{}\n",
        )
        .file(
            "lib/cache/chain_test.go",
            "package cache\n\nfunc TestChain() {}\n",
        )
        .build();

    let result = call_tool(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["github.com/eko/gocache/lib/v4/cache/chain.go","github.com/eko/gocache/lib/v4/cache/chain_test.go"]}"#,
    );

    assert_eq!(0, result["not_found"].as_array().unwrap().len(), "{result}");
    assert!(
        result["ambiguous_paths"]
            .as_array()
            .is_none_or(Vec::is_empty),
        "{result}"
    );
    let paths = result["sources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|source| source["path"].as_str().expect("source path"))
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        std::collections::BTreeSet::from(["lib/cache/chain.go", "lib/cache/chain_test.go"]),
        paths,
        "{result}"
    );
}

#[test]
fn go_module_prefixed_file_paths_prefer_the_nested_module() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/root\n")
        .file("child/pkg/value.go", "package pkg\n\nconst Parent = 1\n")
        .file("nested/go.mod", "module example.com/root/child\n")
        .file("nested/pkg/value.go", "package pkg\n\nconst Nested = 1\n")
        .build();

    let result = call_tool(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["example.com/root/child/pkg/value.go"]}"#,
    );

    assert_eq!(0, result["not_found"].as_array().unwrap().len(), "{result}");
    assert_eq!(
        "nested/pkg/value.go",
        result["sources"][0]["path"].as_str().unwrap(),
        "{result}"
    );
}

#[test]
fn duplicate_go_module_paths_report_ambiguous_files() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("first/go.mod", "module example.com/shared\n")
        .file("first/pkg/value.go", "package pkg\n\nconst First = 1\n")
        .file("second/go.mod", "module example.com/shared\n")
        .file("second/pkg/value.go", "package pkg\n\nconst Second = 1\n")
        .build();

    let result = call_tool(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["example.com/shared/pkg/value.go"]}"#,
    );

    assert_eq!(
        serde_json::json!([{
            "input": "example.com/shared/pkg/value.go",
            "matches": ["first/pkg/value.go", "second/pkg/value.go"]
        }]),
        result["ambiguous_paths"],
        "{result}"
    );
}

#[test]
fn go_module_prefixed_file_paths_reject_parent_traversal() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("lib/go.mod", "module example.com/lib\n")
        .file("cache/chain.go", "package cache\n\ntype Chain struct{}\n")
        .build();
    let input = "example.com/lib/../cache/chain.go";

    let result = call_tool(
        &project,
        "get_symbol_sources",
        &serde_json::json!({"symbols": [input]}).to_string(),
    );

    assert_eq!(
        Some(input),
        result["not_found"][0]["input"].as_str(),
        "{result}"
    );
    assert!(result["sources"].as_array().unwrap().is_empty(), "{result}");
}

#[test]
fn go_module_scope_heading_selector_reports_grouping_guidance() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("decls.go", "package pkg\n\nvar someVar = 1\n")
        .build();

    let result = call_tool(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["pkg._module_"]}"#,
    );

    assert_eq!(0, result["sources"].as_array().unwrap().len(), "{result}");
    assert_eq!(1, result["not_found"].as_array().unwrap().len(), "{result}");
    let note = not_found_note(&result["not_found"][0]);
    assert!(note.contains("outline grouping"), "{result}");
    assert!(note.contains("pkg._module_.<name>"), "{result}");
    assert!(note.contains("pkg.<name>"), "{result}");
}

#[test]
fn go_file_anchored_module_scope_heading_keeps_file_selector_guidance() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("decls.go", "package pkg\n\nvar someVar = 1\n")
        .build();

    let result = call_tool(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["decls.go#_module_"]}"#,
    );

    assert_eq!(0, result["sources"].as_array().unwrap().len(), "{result}");
    assert_eq!(1, result["not_found"].as_array().unwrap().len(), "{result}");
    let note = not_found_note(&result["not_found"][0]);
    assert!(
        note.contains("not a symbol selector for existing file"),
        "{result}"
    );
    assert!(!note.contains("no symbol matched"), "{result}");
}

#[test]
fn go_module_scope_infix_skip_preserves_real_ambiguity() {
    let project = InlineTestProject::new()
        .file("go.mod", "module example.com/root\n")
        .file("a/pkg/name.go", "package pkg\n\ntype Name struct{}\n")
        .file("b/pkg/name.go", "package pkg\n\nvar Name = 1\n")
        .build();

    let result = call_tool(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["pkg.Name"]}"#,
    );

    assert_eq!(0, result["sources"].as_array().unwrap().len(), "{result}");
    assert_eq!(0, result["not_found"].as_array().unwrap().len(), "{result}");
    assert_eq!(1, result["ambiguous"].as_array().unwrap().len(), "{result}");
    let matches = string_array(&result["ambiguous"][0]["matches"]);
    assert!(
        matches
            .iter()
            .any(|selector| selector.contains("example.com/root/a/pkg.Name")),
        "{result}"
    );
    assert!(
        matches
            .iter()
            .any(|selector| selector.contains("example.com/root/b/pkg._module_.Name")),
        "{result}"
    );
}

#[test]
fn explicit_java_constructor_selector_returns_constructor_source() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/main/java/org/example/EventPublisherTest.java",
            "package org.example;\n\nclass EventPublisherTest {\n  EventPublisherTest() {}\n}\n",
        )
        .build();

    let exact = assert_symbol_source_contains(
        &project,
        "org.example.EventPublisherTest.EventPublisherTest",
        "EventPublisherTest() {}",
    );

    assert_eq!(0, exact["not_found"].as_array().unwrap().len(), "{exact}");
    assert_eq!(1, exact["sources"].as_array().unwrap().len(), "{exact}");
    assert_eq!(
        "org.example.EventPublisherTest.EventPublisherTest", exact["sources"][0]["label"],
        "{exact}"
    );
    assert!(exact["sources"][0]["note"].is_null(), "{exact}");
    assert_eq!(
        "EventPublisherTest() {}", exact["sources"][0]["text"],
        "{exact}"
    );
}

#[test]
fn unresolvable_symbol_reports_search_symbols_recovery_note() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file("src/a.js", "export class Widget {}\n")
        .build();

    let result = call_tool(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["MissingWidget"]}"#,
    );

    assert_eq!(0, result["sources"].as_array().unwrap().len(), "{result}");
    assert_eq!(1, result["not_found"].as_array().unwrap().len(), "{result}");
    assert_eq!(
        "MissingWidget",
        not_found_input(&result["not_found"][0]),
        "{result}"
    );
    assert!(
        not_found_note(&result["not_found"][0]).contains("search_symbols"),
        "{result}"
    );
}

#[test]
fn line_range_selectors_report_symbol_selector_guidance() {
    let project = InlineTestProject::new()
        .file("src/unix/pipe.c", "int includes_nul(void) { return 0; }\n")
        .file("src/core.ts", "export function core() {\n  return 1;\n}\n")
        .file("src/pkg/Thing.java", "package pkg;\nclass Thing {}\n")
        .build();

    let result = call_tool(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["src/unix/pipe.c:1-32","src/core.ts#1-30","src/core.ts#L1-L79","src/pkg/Thing.java:0"]}"#,
    );

    assert_eq!(0, result["sources"].as_array().unwrap().len(), "{result}");
    let not_found = result["not_found"].as_array().unwrap();
    assert_eq!(4, not_found.len(), "{result}");
    let expected = [
        (
            "src/unix/pipe.c:1-32",
            "`1-32` is a line/range anchor, not a symbol selector. Use get_summaries or `src/unix/pipe.c` as a file target for an outline, or retry as path#symbol with a real symbol name.",
        ),
        (
            "src/core.ts#1-30",
            "`1-30` is a line/range anchor, not a symbol selector. Use get_summaries or `src/core.ts` as a file target for an outline, or retry as path#symbol with a real symbol name.",
        ),
        (
            "src/core.ts#L1-L79",
            "`L1-L79` is a line/range anchor, not a symbol selector. Use get_summaries or `src/core.ts` as a file target for an outline, or retry as path#symbol with a real symbol name.",
        ),
        (
            "src/pkg/Thing.java:0",
            "`0` is a line/range anchor, not a symbol selector. Use get_summaries or `src/pkg/Thing.java` as a file target for an outline, or retry as path#symbol with a real symbol name.",
        ),
    ];
    for (item, (input, note)) in not_found.iter().zip(expected) {
        assert_eq!(input, not_found_input(item), "{result}");
        assert_eq!(note, not_found_note(item), "{result}");
    }
}

#[test]
fn selector_shaped_invalid_inputs_report_specific_recovery_guidance() {
    let project = InlineTestProject::new()
        .file(
            "src/MudBlazor/Components/Tabs/MudTabs.cs",
            "class MudTabs {}\n",
        )
        .file(
            "tests/Tests/ORM/Query/ExprTest.php",
            "<?php class ExprTest {}\n",
        )
        .file(
            "src/plugin/duration/index.js",
            "export function duration() {}\n",
        )
        .file("src/core.ts", "export class ProcessPromise {}\n")
        .file(
            "core-common/src/main/java/org/zalando/nakadi/util/CompressionBodyRequestFilter.java",
            "package org.zalando.nakadi.util;\nclass CompressionBodyRequestFilter {}\n",
        )
        .build();

    let result = call_tool(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["src/MudBlazor/Components/Tabs/MudTabs.cs::line 60","tests/Tests/ORM/Query/ExprTest.php%3A1-12","src/plugin/duration/index.js#index.js","src/core.ts#core.ts.ProcessPromise","core-common/src/main/java/org/zalando/nakadi/util/CompressionBodyRequestFilter#CompressionBodyRequestFilter"]}"#,
    );

    assert_eq!(0, result["sources"].as_array().unwrap().len(), "{result}");
    let not_found = result["not_found"].as_array().unwrap();
    assert_eq!(5, not_found.len(), "{result}");
    let notes: Vec<_> = not_found.iter().map(not_found_note).collect();
    assert!(
        notes[0].contains("`line 60` is a line/range anchor")
            && notes[0].contains("src/MudBlazor/Components/Tabs/MudTabs.cs"),
        "{result}"
    );
    assert!(
        notes[1].contains("URL-encoded line/range anchor")
            && notes[1].contains("ExprTest.php:1-12"),
        "{result}"
    );
    assert!(
        notes[2].contains("not a symbol selector for existing file")
            && notes[2].contains("src/plugin/duration/index.js#<symbol>"),
        "{result}"
    );
    assert_eq!(
        "`core.ts.ProcessPromise` redundantly repeats the file name; retry `src/core.ts#ProcessPromise`",
        notes[3],
        "{result}"
    );
    assert_eq!(
        "`core-common/src/main/java/org/zalando/nakadi/util/CompressionBodyRequestFilter` looks like a source path missing its extension; retry with the canonical workspace symbol `org.zalando.nakadi.util.CompressionBodyRequestFilter`",
        notes[4],
        "{result}"
    );
}

#[test]
fn unsupported_selector_shapes_report_specific_recovery_guidance() {
    let project = InlineTestProject::new()
        .file("src/unix/pipe.c", "int includes_nul(void) { return 0; }\n")
        .file("src/pkg/Thing.java", "package pkg;\nclass Thing {}\n")
        .build();
    let absolute = format!(
        "/opt/work/repo/{}",
        project
            .file("src/pkg/Thing.java")
            .rel_path()
            .to_string_lossy()
            .replace('\\', "/")
    );
    let args = format!(
        r#"{{"symbols":["int uv_pipe_bind2(uv_pipe_t* handle, ...)","includes_nul@src/unix/pipe.c","src/pkg/Thing.java.package_and_imports","{absolute}"]}}"#
    );

    let result = call_tool(&project, "get_symbol_sources", &args);

    assert_eq!(0, result["sources"].as_array().unwrap().len(), "{result}");
    let not_found = result["not_found"].as_array().unwrap();
    assert_eq!(4, not_found.len(), "{result}");
    assert_eq!(
        "int uv_pipe_bind2(uv_pipe_t* handle, ...)",
        not_found_input(&not_found[0]),
        "{result}"
    );
    assert_eq!(
        "signature strings are not supported as symbol selectors; retry with the bare function name `uv_pipe_bind2`",
        not_found_note(&not_found[0]),
        "{result}"
    );
    assert_eq!(
        "includes_nul@src/unix/pipe.c",
        not_found_input(&not_found[1]),
        "{result}"
    );
    assert_eq!(
        "`symbol@path` selectors are not supported; retry with the bare symbol `includes_nul` plus the `paths` parameter `src/unix/pipe.c`, or use `src/unix/pipe.c#includes_nul`",
        not_found_note(&not_found[1]),
        "{result}"
    );
    assert_eq!(
        "src/pkg/Thing.java.package_and_imports",
        not_found_input(&not_found[2]),
        "{result}"
    );
    assert_eq!(
        "`package_and_imports` is not a symbol in `src/pkg/Thing.java`; use `src/pkg/Thing.java` as a file target for an outline, or call get_summaries on `src/pkg/Thing.java`",
        not_found_note(&not_found[2]),
        "{result}"
    );
    assert_eq!(absolute, not_found_input(&not_found[3]), "{result}");
    assert_eq!(
        "this looks like an absolute path; strip the workspace-root prefix and retry `src/pkg/Thing.java`",
        not_found_note(&not_found[3]),
        "{result}"
    );
}

#[test]
fn mixed_symbol_sources_render_recovery_before_source_bodies() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file("src/a.js", "export class Widget {}\n")
        .build();

    let payload = call_tool_payload(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["Widget","MissingWidget"]}"#,
    );

    let rendered = payload["rendered_text"].as_str().expect("rendered text");
    assert!(
        rendered.starts_with(
            "Some requested symbols were unresolved: `MissingWidget` (see recovery guidance below)"
        ),
        "{rendered}"
    );
    assert!(rendered.contains("## Widget"), "{rendered}");
    assert!(
        rendered.contains(
            "- `MissingWidget`: no symbol matched; try search_symbols with a substring or regex pattern"
        ),
        "{rendered}"
    );
    let recovery = rendered.find("## Not found").expect("not-found section");
    let source = rendered.find("## Widget").expect("source body");
    assert!(recovery < source, "{rendered}");
}

// C# generic types are indexed with arity (`CountingCollection`1`) but
// users spell them without it; every natural spelling must still resolve
// (issue #1063).
#[test]
fn csharp_generic_type_resolves_without_arity_spelling() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "src/Primitives/CountingCollection.cs",
            "namespace ScottPlot;\n\npublic class CountingCollection<T> {\n    private readonly List<T> _items = new();\n    public void Add(T item) { _items.Add(item); }\n}\n",
        )
        .file("src/App.cs", "namespace App;\n\npublic class App {\n    public void Run() { var c = new ScottPlot.CountingCollection<int>(); }\n}\n")
        .build();

    for selector in [
        "CountingCollection",
        "ScottPlot.CountingCollection",
        "src/Primitives/CountingCollection.cs#CountingCollection",
        "ScottPlot.CountingCollection.Add",
    ] {
        let result = call_tool(
            &project,
            "get_symbol_sources",
            &format!(r#"{{"symbols":["{selector}"]}}"#),
        );
        assert_eq!(
            0,
            result["not_found"].as_array().unwrap().len(),
            "{selector} must resolve: {result}"
        );
        assert!(
            !result["sources"].as_array().unwrap().is_empty()
                || !result["ambiguous"].as_array().unwrap().is_empty(),
            "{selector} must produce sources or ambiguity: {result}"
        );
    }
}

// ---------------------------------------------------------------------------
// `path#terminal` member resolution (issue #1056)
//
// Resolution used to run globally first and filter to the anchor file after;
// members (whose short names are owner-qualified) were invisible to the
// exact/short-name stages, so any top-level namesake in the workspace
// short-circuited the search and the member reported not_found on the very
// file the selector named. Anchored selectors now resolve within the file
// from the start.
// ---------------------------------------------------------------------------

#[test]
fn anchored_selector_resolves_member_by_terminal_name_despite_global_namesake() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/tools/rename.ts",
            "export class LspRenameDetails {\n  apply(edit: string): string {\n    return edit;\n  }\n}\n",
        )
        .file(
            "src/apply.ts",
            "export function apply(input: string): string {\n  return input;\n}\n",
        )
        .build();

    // The shadowing namesake is what used to short-circuit resolution: the
    // bare name has a top-level candidate, but the anchored selector must
    // reach the member in its own file.
    let anchored = call_tool(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["src/tools/rename.ts#apply"]}"#,
    );
    assert_eq!(
        0,
        anchored["ambiguous"].as_array().unwrap().len(),
        "{anchored}"
    );
    assert_eq!(
        0,
        anchored["not_found"].as_array().unwrap().len(),
        "{anchored}"
    );
    assert_eq!(
        1,
        anchored["sources"].as_array().unwrap().len(),
        "{anchored}"
    );
    assert_eq!(
        "src/tools/rename.ts", anchored["sources"][0]["path"],
        "{anchored}"
    );
    assert!(
        anchored["sources"][0]["text"]
            .as_str()
            .unwrap()
            .contains("apply(edit: string)"),
        "{anchored}"
    );
}

#[test]
fn anchored_selector_reports_ambiguity_between_same_named_members_in_one_file() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/tools/handlers.ts",
            "export class ReadHandler {\n  apply(edit: string): string {\n    return edit;\n  }\n}\n\nexport class WriteHandler {\n  apply(edit: string): string {\n    return edit + edit;\n  }\n}\n",
        )
        .build();

    let anchored = call_tool(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["src/tools/handlers.ts#apply"]}"#,
    );
    assert_eq!(
        0,
        anchored["sources"].as_array().unwrap().len(),
        "{anchored}"
    );
    assert_eq!(
        0,
        anchored["not_found"].as_array().unwrap().len(),
        "{anchored}"
    );
    let matches = string_array(&anchored["ambiguous"][0]["matches"]);
    assert_eq!(
        vec![
            "src/tools/handlers.ts#ReadHandler.apply".to_string(),
            "src/tools/handlers.ts#WriteHandler.apply".to_string(),
        ],
        matches,
        "{anchored}"
    );
}

#[test]
fn anchored_selector_resolves_scala_nested_symbol_despite_global_namesake() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "src/AuditRenderer.scala",
            "object AuditRenderer {\n  case class Job(id: Int)\n}\n",
        )
        .file("src/domain/Job.scala", "case class Job(name: String)\n")
        .build();

    // TheHive shape: a nested declaration addressed by its file and terminal
    // name must resolve even when a top-level namesake exists elsewhere.
    // A case class is two declarations (class + synthetic companion), so the
    // correct anchored outcome is actionable ambiguity naming the nested
    // class — not the not_found the old global-first resolution produced.
    let anchored = call_tool(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["src/AuditRenderer.scala#Job"]}"#,
    );
    assert_eq!(
        0,
        anchored["not_found"].as_array().unwrap().len(),
        "{anchored}"
    );
    let matches = string_array(&anchored["ambiguous"][0]["matches"]);
    assert!(
        matches
            .iter()
            .any(|candidate| candidate == "AuditRenderer$.Job"),
        "{anchored}"
    );
}

// Assert a bare-name lookup on `tool` reports ambiguity for `target` with two
// `path#` selectors and the recovery note. Returns the sorted match selectors.
fn assert_bare_name_ambiguous(
    project: &common::BuiltInlineTestProject,
    tool: &str,
    target: &str,
) -> Vec<String> {
    let field = if tool == "get_summaries" {
        "targets"
    } else {
        "symbols"
    };
    let args = serde_json::json!({ field: [target] }).to_string();
    let result = call_tool(project, tool, &args);
    assert_eq!(
        0,
        result["not_found"].as_array().unwrap().len(),
        "{tool}: {result}"
    );
    assert_eq!(
        1,
        result["ambiguous"].as_array().unwrap().len(),
        "{tool}: {result}"
    );
    assert_eq!(target, result["ambiguous"][0]["target"], "{tool}: {result}");
    let mut matches = string_array(&result["ambiguous"][0]["matches"]);
    assert_eq!(2, matches.len(), "{tool}: {result}");
    assert!(
        matches.iter().all(|selector| selector.contains('#')),
        "every candidate must be a path# selector: {tool}: {result}"
    );
    let note = string_value(&result["ambiguous"][0]["note"]);
    assert!(
        note.contains("Ambiguous; re-call with one selector from `matches`"),
        "{tool}: {result}"
    );
    matches.sort();
    matches
}

// #1057: a bare terminal name whose only exact hit is a top-level namesake must
// not silently win while a same-named member exists. Both symbol-source and
// summary surfaces must report ambiguity with both file-anchored selectors.
#[test]
fn bare_name_with_toplevel_and_member_is_ambiguous_typescript() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "checker/cached-version.ts",
            "export function getCachedVersion() {\n  return 1;\n}\n",
        )
        .file(
            "hook.ts",
            "export class AutoUpdateCheckerDeps {\n  getCachedVersion() {\n    return 2;\n  }\n}\n",
        )
        .file(
            "unique.ts",
            "export function computeUniqueThing() {\n  return 3;\n}\n",
        )
        .build();

    for tool in ["get_symbol_sources", "get_summaries"] {
        let matches = assert_bare_name_ambiguous(&project, tool, "getCachedVersion");
        assert!(
            matches
                .iter()
                .any(|selector| selector.contains("checker/cached-version.ts")),
            "{tool}: {matches:?}"
        );
        assert!(
            matches.iter().any(|selector| selector.contains("hook.ts")),
            "{tool}: {matches:?}"
        );
    }

    // A uniquely-named symbol still resolves cleanly (no over-triggering).
    let unique = call_tool(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["computeUniqueThing"]}"#,
    );
    assert_eq!(0, unique["ambiguous"].as_array().unwrap().len(), "{unique}");
    assert_eq!(0, unique["not_found"].as_array().unwrap().len(), "{unique}");
    assert_eq!(1, unique["sources"].as_array().unwrap().len(), "{unique}");
}

// The same collision spanning two languages must be reported through the
// `MultiAnalyzer` merge of `lookup_candidates_by_identifier`. JavaScript and
// TypeScript are distinct delegates, so a `.js` + `.ts` project genuinely
// exercises the cross-delegate merge; both are module-scoped, so both render
// file-anchored `path#` selectors.
#[test]
fn bare_name_with_toplevel_and_member_is_ambiguous_across_languages() {
    let project = InlineTestProject::new()
        .file(
            "legacy.js",
            "export function getCachedVersion() {\n  return 1;\n}\n",
        )
        .file(
            "hook.ts",
            "export class AutoUpdateCheckerDeps {\n  getCachedVersion() {\n    return 2;\n  }\n}\n",
        )
        .file(
            "unique.ts",
            "export function computeUniqueThing() {\n  return 3;\n}\n",
        )
        .build();

    // Sanity: this project spans two distinct analyzer delegates, so the
    // MultiAnalyzer merge of the new identifier lookup is what produces the set.
    assert!(
        project.languages().contains(&Language::JavaScript)
            && project.languages().contains(&Language::TypeScript),
        "{:?}",
        project.languages()
    );

    for tool in ["get_symbol_sources", "get_summaries"] {
        let matches = assert_bare_name_ambiguous(&project, tool, "getCachedVersion");
        assert!(
            matches
                .iter()
                .any(|selector| selector.contains("legacy.js")),
            "{tool}: {matches:?}"
        );
        assert!(
            matches.iter().any(|selector| selector.contains("hook.ts")),
            "{tool}: {matches:?}"
        );
    }

    let unique = call_tool(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["computeUniqueThing"]}"#,
    );
    assert_eq!(0, unique["ambiguous"].as_array().unwrap().len(), "{unique}");
    assert_eq!(1, unique["sources"].as_array().unwrap().len(), "{unique}");
}

// --- M2: location-aware distinctness for identical-FQN collisions ---------

/// Model the Scala scala-2/scala-3 twin shape: the SAME package + type declared
/// in two files under parallel source trees. Both the bare name and the
/// fully-qualified spelling must report ambiguity listing both `path#fqn`
/// selectors, and `get_summaries` + `get_symbol_sources` must agree on the
/// candidate set (the cross-tool consistency the fuzzer flagged). Before the M2
/// `distinct_definitions` change both twins collapsed to a single group and one
/// file was silently picked.
#[test]
fn symbol_sources_disambiguates_scala_cross_build_twins_by_file_selector() {
    let scala2_path = "core/src/main/scala-2/demo/Widget.scala";
    let scala3_path = "core/src/main/scala-3/demo/Widget.scala";
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            scala2_path,
            r#"package demo

class Widget {
  def value: Int = 2
}
"#,
        )
        .file(
            scala3_path,
            r#"package demo

class Widget {
  def value: Int = 3
}
"#,
        )
        .build();

    let scala2_selector = format!("{scala2_path}#demo.Widget");
    let scala3_selector = format!("{scala3_path}#demo.Widget");
    let expected = vec![scala2_selector.clone(), scala3_selector.clone()];

    // Fully-qualified spelling (2b): resolve_codeunit_exact returns both twins,
    // and distinct_definitions must now split them into two file-anchored
    // candidates.
    let fq = call_tool(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["demo.Widget"]}"#,
    );
    assert_eq!(0, fq["sources"].as_array().unwrap().len(), "{fq}");
    assert_eq!(1, fq["ambiguous"].as_array().unwrap().len(), "{fq}");
    let mut fq_matches = string_array(&fq["ambiguous"][0]["matches"]);
    fq_matches.sort();
    assert_eq!(expected, fq_matches, "{fq}");

    // Bare spelling: M1 gathers both twins by identifier; M2 anchors them.
    let bare = call_tool(&project, "get_symbol_sources", r#"{"symbols":["Widget"]}"#);
    assert_eq!(0, bare["sources"].as_array().unwrap().len(), "{bare}");
    assert_eq!(1, bare["ambiguous"].as_array().unwrap().len(), "{bare}");
    let mut bare_matches = string_array(&bare["ambiguous"][0]["matches"]);
    bare_matches.sort();
    assert_eq!(expected, bare_matches, "{bare}");

    // Cross-tool consistency: get_summaries for the same FQN surfaces the same
    // candidate set, so file A (scala-2) appears in both surfaces rather than a
    // silently different file per tool.
    let summaries = call_tool(&project, "get_summaries", r#"{"targets":["demo.Widget"]}"#);
    assert_eq!(
        0,
        summaries["summaries"].as_array().unwrap().len(),
        "{summaries}"
    );
    assert_eq!(
        1,
        summaries["ambiguous"].as_array().unwrap().len(),
        "{summaries}"
    );
    let mut summary_matches = string_array(&summaries["ambiguous"][0]["matches"]);
    summary_matches.sort();
    assert_eq!(expected, summary_matches, "{summaries}");
    assert!(
        summary_matches.contains(&scala2_selector),
        "get_summaries must surface file A: {summaries}"
    );
    assert!(
        fq_matches.contains(&scala2_selector),
        "get_symbol_sources must surface file A: {fq}"
    );

    // Each anchored selector resolves to exactly its file.
    let anchored = call_tool(
        &project,
        "get_symbol_sources",
        &serde_json::json!({ "symbols": [scala2_selector] }).to_string(),
    );
    assert_eq!(
        0,
        anchored["ambiguous"].as_array().unwrap().len(),
        "{anchored}"
    );
    assert_eq!(
        1,
        anchored["sources"].as_array().unwrap().len(),
        "{anchored}"
    );
    assert_eq!(scala2_path, anchored["sources"][0]["path"], "{anchored}");
    assert!(
        anchored["sources"][0]["text"]
            .as_str()
            .unwrap()
            .contains("Int = 2"),
        "{anchored}"
    );
}

/// No regression: two same-FQN methods declared in ONE file are genuine
/// overloads and must stay a single group (Resolved with both sources, not
/// Ambiguous). This is the same-file counterpart the M2 discriminator must not
/// split.
#[test]
fn symbol_sources_keeps_same_file_scala_overloads_as_one_group() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "demo/Box.scala",
            r#"package demo

class Box {
  def run(value: Int): Int = value
  def run(value: String): String = value
}
"#,
        )
        .build();

    let result = call_tool(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["demo.Box.run"]}"#,
    );
    assert_eq!(0, result["ambiguous"].as_array().unwrap().len(), "{result}");
    assert_eq!(0, result["not_found"].as_array().unwrap().len(), "{result}");
    assert_eq!(2, result["sources"].as_array().unwrap().len(), "{result}");
    assert!(
        result["sources"]
            .as_array()
            .unwrap()
            .iter()
            .any(|source| source["text"].as_str().unwrap().contains("value: Int")),
        "{result}"
    );
    assert!(
        result["sources"]
            .as_array()
            .unwrap()
            .iter()
            .any(|source| source["text"].as_str().unwrap().contains("value: String")),
        "{result}"
    );
}

/// No regression: a unique FQN in a non-module-scoped language (one file) still
/// renders its plain FQN selector and resolves without ambiguity — the M2
/// discriminator anchors only FQNs present in more than one file.
#[test]
fn symbol_sources_keeps_unique_scala_fqn_plain_selector() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "demo/Solo.scala",
            r#"package demo

class Solo {
  def onlyOne: Int = 7
}
"#,
        )
        .build();

    assert_symbol_source_contains(&project, "demo.Solo", "class Solo");
    assert_symbol_source_contains(&project, "demo.Solo.onlyOne", "def onlyOne");
}

#[test]
fn bare_name_ambiguity_includes_arrow_function_consts() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "src/a.tsx",
            "export const Input = (props) => {\n  return <input {...props} />;\n};\n",
        )
        .file(
            "src/b.tsx",
            "export function Input(props) {\n  return <input {...props} />;\n}\n",
        )
        .build();
    let result = call_tool(&project, "get_symbol_sources", r#"{"symbols":["Input"]}"#);
    let matches = string_array(&result["ambiguous"][0]["matches"]);
    assert!(
        matches.iter().any(|m| m.contains("src/a.tsx")),
        "arrow const must be a candidate: {result}"
    );
    assert!(
        matches.iter().any(|m| m.contains("src/b.tsx")),
        "function must be a candidate: {result}"
    );
}

#[test]
fn arrow_const_named_input_indexes_and_resolves() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "examples/V6/customMaskedInputWithController.tsx",
            "import React from 'react';\nimport MaskedInput from 'react-input-mask';\nimport { useForm, Controller } from 'react-hook-form';\n\nimport './styles.css';\n\nexport const clearTel = (tel) => tel.replace(/[^0-9]/g, '');\n\nconst isNotFilledTel = (v) => {\n  const clearedTel = clearTel(v);\n  return clearedTel.length < 11 ? 'Phone number is required.' : undefined;\n};\n\nconst Input = (props) => {\n  const { onChange, ...restProps } = props;\n  return <input {...restProps} onChange={onChange} />;\n};\n\nconst CustomMaskedInput = (props) => {\n  const { value, onChange, name } = props;\n  return (\n    <MaskedInput name={name} value={value} mask=\"+7 (999) 999-99-99\" />\n  );\n};\n",
        )
        .build();
    let result = call_tool(&project, "get_symbol_sources", r#"{"symbols":["Input"]}"#);
    let rendered = format!("{result}");
    assert!(
        result["not_found"].as_array().unwrap().is_empty(),
        "Input must resolve: {rendered}"
    );
    assert!(
        !result["sources"].as_array().unwrap().is_empty()
            || !result["ambiguous"].as_array().unwrap().is_empty(),
        "Input must produce sources or ambiguity: {rendered}"
    );
}

// #1087: `resolution_from_matches` dedups candidates into a `BTreeMap<fq_name,
// CodeUnit>` (one first-inserted representative per fq, see `insert_match`).
// The `len == 1` branch re-expands that single fq bucket back out to every
// declaration sharing it via `matching_definitions`, but the `len > 1`
// ("ambiguous") branch used to skip that step and emit
// `matches.into_values().collect()` directly -- so once a THIRD, differently
// fq'd sibling pushed the map past one entry, every other same-fq bucket
// silently collapsed to its single representative.
//
// Here `Input` is declared as a top-level arrow-function const in two files
// (both fq `"Input"`, package empty) plus a top-level, *exported*,
// *non-function* `const Input = {...}` object literal in a third file. JS/TS
// indexes an exported top-level object literal with "surface shape" twice:
// once as a module-scoped `Field` whose short_name (and therefore fq) is
// file-scoped -- e.g. `hook/UseFormMethods.tsx.Input`, mirroring the real
// `UseFormMethods.tsx`/`forwardRefToPassRefProp.tsx` siblings from the
// upstream react-hook-form repro -- and once more as a plain-named "surface"
// `Field` that itself shares fq `"Input"` with the two function
// declarations. That gives two fq buckets: `"Input"` (3 declarations: both
// functions plus the surface field) and the file-scoped one (1 declaration),
// and the second bucket is what pushes `matches.len()` to 2 and selects the
// buggy branch. Before the fix, the `"Input"` bucket collapsed from 3
// declarations down to whichever was first-inserted, silently dropping the
// other two; after the fix all four declarations across both buckets must be
// listed.
#[test]
fn bare_name_ambiguity_expands_every_same_fq_declaration_once_a_distinct_fq_sibling_exists() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "examples/V6/customMaskedInputWithController.tsx",
            "const Input = (props) => {\n  const { onChange, ...restProps } = props;\n  return <input {...restProps} onChange={onChange} />;\n};\n\nexport { Input };\n",
        )
        .file(
            "examples/V7/anotherMaskedInput.tsx",
            "const Input = (props) => {\n  return <input {...props} />;\n};\n\nexport { Input };\n",
        )
        .file(
            "hook/UseFormMethods.tsx",
            "export const Input = {\n  displayName: 'Input',\n};\n",
        )
        .build();

    let result = call_tool(&project, "get_symbol_sources", r#"{"symbols":["Input"]}"#);
    assert_eq!(0, result["not_found"].as_array().unwrap().len(), "{result}");
    assert_eq!(1, result["ambiguous"].as_array().unwrap().len(), "{result}");
    assert_eq!("Input", result["ambiguous"][0]["target"], "{result}");
    let matches = string_array(&result["ambiguous"][0]["matches"]);
    assert_eq!(
        4,
        matches.len(),
        "expected all four declarations (two same-fq functions, the same-fq \
         surface field, and the distinct-fq file-scoped field), got: {result}"
    );
    assert!(
        matches
            .iter()
            .any(|m| m.contains("examples/V6/customMaskedInputWithController.tsx")),
        "missing first same-fq declaration: {result}"
    );
    assert!(
        matches
            .iter()
            .any(|m| m.contains("examples/V7/anotherMaskedInput.tsx")),
        "missing second same-fq declaration: {result}"
    );
    assert!(
        matches.iter().any(|m| m == "hook/UseFormMethods.tsx#Input"),
        "missing same-fq surface field declaration: {result}"
    );
    assert!(
        matches
            .iter()
            .any(|m| m == "hook/UseFormMethods.tsx#UseFormMethods.tsx.Input"),
        "missing distinct-fq file-scoped field declaration: {result}"
    );
}

// No-regression companion to the above: with only the two same-fq function
// declarations (no third, distinct-fq sibling), `resolution_from_matches`
// takes the `len == 1` branch, which already re-expanded correctly before
// this fix. Both file-anchored candidates must keep showing up.
#[test]
fn bare_name_ambiguity_still_expands_same_fq_declarations_without_a_distinct_fq_sibling() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "examples/V6/customMaskedInputWithController.tsx",
            "const Input = (props) => {\n  const { onChange, ...restProps } = props;\n  return <input {...restProps} onChange={onChange} />;\n};\n\nexport { Input };\n",
        )
        .file(
            "examples/V7/anotherMaskedInput.tsx",
            "const Input = (props) => {\n  return <input {...props} />;\n};\n\nexport { Input };\n",
        )
        .build();

    let result = call_tool(&project, "get_symbol_sources", r#"{"symbols":["Input"]}"#);
    assert_eq!(0, result["not_found"].as_array().unwrap().len(), "{result}");
    assert_eq!(1, result["ambiguous"].as_array().unwrap().len(), "{result}");
    let matches = string_array(&result["ambiguous"][0]["matches"]);
    assert_eq!(2, matches.len(), "{result}");
    assert!(
        matches
            .iter()
            .any(|m| m.contains("examples/V6/customMaskedInputWithController.tsx")),
        "{result}"
    );
    assert!(
        matches
            .iter()
            .any(|m| m.contains("examples/V7/anotherMaskedInput.tsx")),
        "{result}"
    );
}

// No-regression: a uniquely-named symbol must keep resolving cleanly (no
// over-triggering of ambiguity from the expansion added for #1087).
#[test]
fn unique_bare_name_still_resolves_cleanly_after_ambiguity_expansion_fix() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "src/unique.tsx",
            "export const OnlyOneOfMe = (props) => {\n  return <input {...props} />;\n};\n",
        )
        .build();

    let result = call_tool(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["OnlyOneOfMe"]}"#,
    );
    assert_eq!(0, result["not_found"].as_array().unwrap().len(), "{result}");
    assert_eq!(0, result["ambiguous"].as_array().unwrap().len(), "{result}");
    assert_eq!(1, result["sources"].as_array().unwrap().len(), "{result}");
    assert_eq!("src/unique.tsx", result["sources"][0]["path"], "{result}");
}
// #1088: bare identifier resolution must see every unit the fq lookup path
// already resolves. dayjs's ~130 locale files each declare `formats` nested
// under a top-level `locale` object; the sibling TypeScript `ILocale.formats`
// interface member used to win silently with zero ambiguity ever reported,
// because (a) JavaScript's `IAnalyzer::lookup_candidates_by_identifier` never
// delegated to the shared identifier-lookup store query at all (every other
// language wrapper did), and (b) even once wired up, the store query's
// membership excluded `in_definition_lookup`-only units (JS/TS module-surface
// duplicate fields) that the fq lookup path already resolves fine.
//
// This fixture exercises both: `dv.js`/`en.js` mirror dayjs's unexported
// `const locale = {...}; export default locale;` shape (only reachable via
// fix (a)); `alpha.js`/`beta.js` use `export const localeX = {...}`, which
// additionally registers a definition-lookup-only bare `localeX.formats` twin
// alongside the real `alpha.js.localeX.formats` declaration (only reachable
// via fix (b)).
#[test]
fn bare_name_ambiguity_surfaces_definition_lookup_only_locale_fields() {
    let project = InlineTestProject::new()
        .file(
            "types/locale/types.d.ts",
            "declare interface ILocale {\n  name: string\n  formats: Partial<{\n    LT: string\n  }>\n}\nexport default ILocale\n",
        )
        .file(
            "src/locale/dv.js",
            "import dayjs from 'dayjs'\n\nconst locale = {\n  name: 'dv',\n  formats: {\n    LT: 'HH:mm'\n  }\n}\n\ndayjs.locale(locale, null, true)\n\nexport default locale\n",
        )
        .file(
            "src/locale/en.js",
            "import dayjs from 'dayjs'\n\nconst locale = {\n  name: 'en',\n  formats: {\n    LT: 'h:mm A'\n  }\n}\n\ndayjs.locale(locale, null, true)\n\nexport default locale\n",
        )
        .file(
            "src/locale/alpha.js",
            "export const localeAlpha = {\n  name: 'alpha',\n  formats: {\n    LT: 'HH:mm'\n  }\n}\n",
        )
        .file(
            "src/locale/beta.js",
            "export const localeBeta = {\n  name: 'beta',\n  formats: {\n    LT: 'h:mm A'\n  }\n}\n",
        )
        .build();

    let result = call_tool(&project, "get_symbol_sources", r#"{"symbols":["formats"]}"#);
    assert_eq!(0, result["not_found"].as_array().unwrap().len(), "{result}");
    assert_eq!(1, result["ambiguous"].as_array().unwrap().len(), "{result}");
    assert_eq!("formats", result["ambiguous"][0]["target"], "{result}");
    let matches = string_array(&result["ambiguous"][0]["matches"]);

    // The type member, the two unexported locale fields (fix a), and the two
    // exported locale fields plus their definition-lookup-only bare twins
    // (fix b): 1 + 2 + 2*2 = 7.
    assert_eq!(
        7,
        matches.len(),
        "expected the type member, both unexported locale fields, and both \
         exported locale fields' declaration + definition-lookup-only twin, \
         got: {result}"
    );
    for expected in [
        "types/locale/types.d.ts#ILocale.formats",
        "src/locale/dv.js#dv.js.locale.formats",
        "src/locale/en.js#en.js.locale.formats",
        "src/locale/alpha.js#alpha.js.localeAlpha.formats",
        "src/locale/alpha.js#localeAlpha.formats",
        "src/locale/beta.js#beta.js.localeBeta.formats",
        "src/locale/beta.js#localeBeta.formats",
    ] {
        assert!(
            matches.iter().any(|m| m == expected),
            "missing {expected}: {result}"
        );
    }
}

// No-regression companion: the fq spelling of one locale's `formats` field
// must keep resolving to exactly that field (the #1088 root-cause report's
// "though the fq spelling resolves fine" half of the asymmetry).
#[test]
fn fq_spelling_of_locale_field_still_resolves_uniquely() {
    let project = InlineTestProject::new()
        .file(
            "types/locale/types.d.ts",
            "declare interface ILocale {\n  name: string\n  formats: Partial<{\n    LT: string\n  }>\n}\nexport default ILocale\n",
        )
        .file(
            "src/locale/dv.js",
            "import dayjs from 'dayjs'\n\nconst locale = {\n  name: 'dv',\n  formats: {\n    LT: 'HH:mm'\n  }\n}\n\ndayjs.locale(locale, null, true)\n\nexport default locale\n",
        )
        .build();

    let result = call_tool(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["dv.js.locale.formats"]}"#,
    );
    assert_eq!(0, result["not_found"].as_array().unwrap().len(), "{result}");
    assert_eq!(0, result["ambiguous"].as_array().unwrap().len(), "{result}");
    assert_eq!(1, result["sources"].as_array().unwrap().len(), "{result}");
    assert_eq!("src/locale/dv.js", result["sources"][0]["path"], "{result}");
    assert_eq!(
        "dv.js.locale.formats", result["sources"][0]["label"],
        "{result}"
    );
}

// #1088: with far more legitimate candidates than a caller can act on (dayjs
// has ~130), the rendered `matches` list must stay bounded, carry the true
// total, and hint at how to narrow the query. 30 distinct-fq same-identifier
// declarations exceed the 25-candidate cap (src/searchtools/mod.rs's
// `AMBIGUOUS_SYMBOL_MATCH_LIMIT`).
#[test]
fn ambiguous_matches_are_capped_with_a_total_count_note() {
    let mut project = InlineTestProject::new();
    for index in 0..30 {
        project = project.file(
            format!("src/locale/locale{index}.js"),
            format!(
                "const locale = {{\n  name: 'locale{index}',\n  formats: {{\n    LT: 'HH:mm'\n  }}\n}}\n\nexport default locale\n"
            ),
        );
    }
    let project = project.build();

    let result = call_tool(&project, "get_symbol_sources", r#"{"symbols":["formats"]}"#);
    assert_eq!(0, result["not_found"].as_array().unwrap().len(), "{result}");
    assert_eq!(1, result["ambiguous"].as_array().unwrap().len(), "{result}");
    let matches = result["ambiguous"][0]["matches"].as_array().unwrap();
    assert_eq!(25, matches.len(), "{result}");
    assert!(
        matches.iter().all(|m| m.as_str().unwrap().contains('#')),
        "every capped candidate must still be a well-formed path# selector: {result}"
    );
    let note = string_value(&result["ambiguous"][0]["note"]);
    assert!(
        note.contains("30 candidates") && note.contains("showing 25"),
        "note must carry the true total and the shown count: {note}"
    );
    assert!(
        note.contains("refine with path#name or a qualified spelling"),
        "note must hint at how to narrow the query: {note}"
    );
}

// #397 no-listing-leak guard: widening bare-identifier *resolution* must not
// leak definition-lookup-only units into declaration *listing* surfaces.
// `alpha.js`'s exported `export const localeAlpha = {...}` registers both a
// real declaration (`alpha.js.localeAlpha.formats`, visible everywhere) and a
// definition-lookup-only bare twin (`localeAlpha.formats`, resolution-only);
// get_summaries and search_symbols must keep showing only the former.
#[test]
fn definition_lookup_only_locale_fields_do_not_leak_into_listings() {
    let project = InlineTestProject::new()
        .file(
            "src/locale/alpha.js",
            "export const localeAlpha = {\n  name: 'alpha',\n  formats: {\n    LT: 'HH:mm'\n  }\n}\n",
        )
        .build();

    let summary = call_tool(
        &project,
        "get_summaries",
        r#"{"targets":["src/locale/alpha.js"]}"#,
    );
    let elements: Vec<String> = summary["summaries"][0]["elements"]
        .as_array()
        .expect("summary elements")
        .iter()
        .map(|element| element["symbol"].as_str().expect("symbol").to_string())
        .collect();
    assert!(
        !elements
            .iter()
            .any(|symbol| symbol == "localeAlpha.formats"),
        "get_summaries must not list the definition-lookup-only bare twin: {summary}"
    );

    let search = call_tool(&project, "search_symbols", r#"{"patterns":["formats"]}"#);
    let symbols: Vec<String> = search["files"][0]["fields"]
        .as_array()
        .expect("search fields")
        .iter()
        .map(|field| field["symbol"].as_str().expect("symbol").to_string())
        .collect();
    assert!(
        symbols
            .iter()
            .any(|symbol| symbol == "alpha.js.localeAlpha.formats"),
        "search_symbols must still list the real declaration: {search}"
    );
    assert!(
        !symbols.iter().any(|symbol| symbol == "localeAlpha.formats"),
        "search_symbols must not list the definition-lookup-only bare twin: {search}"
    );
}

// ---------------------------------------------------------------------------
// Issue #1075: a bare Rust field name with two indexed candidates (e.g.
// `empty` on both `Repr` and `Settings` in uutils/coreutils' join.rs) must
// ambiguate with candidates and guidance exactly like the anchored spelling,
// never fall through to a note-less, candidate-less `not_found` refusal
// (I5). By the time this issue was filed, #1057/#1087/#1088 had already
// widened bare-name resolution to see identifier-indexed members, so this
// pins the fix as a permanent regression rather than reproducing a live bug.
// ---------------------------------------------------------------------------

fn issue_1075_join_rs_project() -> common::BuiltInlineTestProject {
    InlineTestProject::with_language(Language::Rust)
        .file(
            "src/uu/join/src/join.rs",
            "struct Repr {\n    empty: String,\n}\n\nstruct Settings {\n    empty: Option<String>,\n}\n\nfn unrelated() -> i32 {\n    42\n}\n",
        )
        .build()
}

#[test]
fn issue_1075_bare_rust_field_ambiguates_like_anchored_and_fq_spellings() {
    let project = issue_1075_join_rs_project();

    let bare = call_tool(&project, "get_symbol_sources", r#"{"symbols":["empty"]}"#);
    let anchored = call_tool(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["src/uu/join/src/join.rs#empty"]}"#,
    );

    // Neither spelling may produce an empty refusal: both must ambiguate
    // with the same two candidates and a non-empty corrective note.
    assert_eq!(0, bare["not_found"].as_array().unwrap().len(), "{bare}");
    assert_eq!(1, bare["ambiguous"].as_array().unwrap().len(), "{bare}");
    let bare_matches = string_array(&bare["ambiguous"][0]["matches"]);
    assert_eq!(
        vec![
            "src.uu.join.src.join.Repr.empty".to_string(),
            "src.uu.join.src.join.Settings.empty".to_string(),
        ],
        bare_matches,
        "{bare}"
    );
    assert!(
        !string_value(&bare["ambiguous"][0]["note"]).is_empty(),
        "{bare}"
    );
    assert_eq!(
        bare["ambiguous"][0]["matches"], anchored["ambiguous"][0]["matches"],
        "bare: {bare}, anchored: {anchored}"
    );

    // Each fq selector offered by the ambiguity resolves to its own field.
    for (selector, expected_snippet) in [
        ("src.uu.join.src.join.Repr.empty", "empty: String"),
        (
            "src.uu.join.src.join.Settings.empty",
            "empty: Option<String>",
        ),
    ] {
        let resolved = call_tool(
            &project,
            "get_symbol_sources",
            &serde_json::json!({ "symbols": [selector] }).to_string(),
        );
        assert_eq!(
            0,
            resolved["not_found"].as_array().unwrap().len(),
            "{resolved}"
        );
        assert_eq!(
            0,
            resolved["ambiguous"].as_array().unwrap().len(),
            "{resolved}"
        );
        assert!(
            resolved["sources"][0]["text"]
                .as_str()
                .expect("source text")
                .contains(expected_snippet),
            "{resolved}"
        );
    }
}

#[test]
fn issue_1075_genuinely_unmatched_rust_symbol_still_carries_corrective_note() {
    let project = issue_1075_join_rs_project();

    let result = call_tool(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["totally_unmatched_symbol_xyz"]}"#,
    );
    assert_eq!(0, result["ambiguous"].as_array().unwrap().len(), "{result}");
    assert_eq!(1, result["not_found"].as_array().unwrap().len(), "{result}");
    assert_eq!(
        "totally_unmatched_symbol_xyz",
        not_found_input(&result["not_found"][0]),
        "{result}"
    );
    assert!(
        !not_found_note(&result["not_found"][0]).is_empty(),
        "a not_found response must always carry a corrective note (I5): {result}"
    );
}

#[test]
fn issue_1075_get_definitions_by_reference_agrees_on_bare_and_fq_rust_field_owner() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "src/uu/join/src/join.rs",
            "struct Repr {\n    empty: String,\n}\n\nimpl Repr {\n    fn get_empty(&self) -> &str {\n        &self.empty\n    }\n}\n\nstruct Settings {\n    empty: Option<String>,\n}\n",
        )
        .build();

    // I2: the same (context, target) reference must resolve identically
    // whether the enclosing `symbol` is spelled bare or fully qualified.
    let bare = call_tool(
        &project,
        "get_definitions_by_reference",
        r#"{"references":[{"symbol":"get_empty","context":"&self.empty","target":"empty"}]}"#,
    );
    let fq = call_tool(
        &project,
        "get_definitions_by_reference",
        r#"{"references":[{"symbol":"src.uu.join.src.join.Repr.get_empty","context":"&self.empty","target":"empty"}]}"#,
    );

    for (label, result) in [("bare", &bare), ("fq", &fq)] {
        assert_eq!(
            "resolved", result["results"][0]["status"],
            "{label}: {result}"
        );
        assert_eq!(
            "src.uu.join.src.join.Repr.empty", result["results"][0]["definitions"][0]["fqn"],
            "{label}: {result}"
        );
    }
}
