mod common;

use brokk_bifrost::{Language, SearchToolsService};
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

fn string_array(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("array")
        .iter()
        .map(|item| item.as_str().expect("string").to_string())
        .collect()
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
