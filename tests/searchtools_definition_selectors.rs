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
    assert_eq!(
        "file_listing", companion["sources"][0]["presentation"],
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
fn synthetic_java_constructor_selector_returns_declaring_class_source() {
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
    let functions = search["files"][0]["functions"].as_array().unwrap();
    assert!(
        functions
            .iter()
            .any(|hit| hit["symbol"] == "org.example.EventPublisherTest.EventPublisherTest"),
        "{search}"
    );

    let bare = call_tool(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["EventPublisherTest"]}"#,
    );
    assert_eq!(0, bare["sources"].as_array().unwrap().len(), "{bare}");
    assert_eq!(0, bare["not_found"].as_array().unwrap().len(), "{bare}");
    assert_eq!(1, bare["ambiguous"].as_array().unwrap().len(), "{bare}");
    assert_eq!(
        "EventPublisherTest", bare["ambiguous"][0]["target"],
        "{bare}"
    );
    assert_eq!(
        vec![
            "org.example.EventPublisherTest".to_string(),
            "org.example.EventPublisherTest.EventPublisherTest".to_string(),
        ],
        string_array(&bare["ambiguous"][0]["matches"]),
        "{bare}"
    );

    let exact = call_tool(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["org.example.EventPublisherTest.EventPublisherTest"]}"#,
    );

    assert_eq!(0, exact["not_found"].as_array().unwrap().len(), "{exact}");
    assert_eq!(0, exact["ambiguous"].as_array().unwrap().len(), "{exact}");
    assert_eq!(1, exact["sources"].as_array().unwrap().len(), "{exact}");
    assert_eq!(
        "org.example.EventPublisherTest", exact["sources"][0]["label"],
        "{exact}"
    );
    assert_eq!(
        "synthetic Java default constructor; showing declaring class source",
        exact["sources"][0]["note"],
        "{exact}"
    );
    assert!(
        exact["sources"][0]["text"]
            .as_str()
            .unwrap()
            .contains("class EventPublisherTest {}"),
        "{exact}"
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

    let exact = call_tool(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["org.example.EventPublisherTest.EventPublisherTest"]}"#,
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
fn mixed_symbol_sources_render_lead_in_before_unresolved_sections() {
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
            "Resolved 1 of 2 requested symbols; unresolved: `MissingWidget` (see sections below)"
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
}
