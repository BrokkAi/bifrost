mod common;

use brokk_bifrost::{Language, SearchToolsService, searchtools_render::RenderOptions};
use common::InlineTestProject;
use serde_json::Value;
use std::sync::{LazyLock, Mutex};

static LOOKUP_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

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
