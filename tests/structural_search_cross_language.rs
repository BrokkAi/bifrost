//! Cross-language `search_ast` tests for Java and JS/TS structural adapters
//! (issue #328, ExecPlan milestone 4).

mod common;

use brokk_bifrost::analyzer::structural::{AstQuery, SearchAstOutput, execute};
use brokk_bifrost::{AnalyzerConfig, WorkspaceAnalyzer};
use common::InlineTestProject;
use serde_json::json;

const APP_PY: &str = r#"
def route(path):
    return lambda fn: fn

password = "hunter2"


@route("/run")
def handle_request(code):
    eval(code)
"#;

const APP_JAVA: &str = r#"
package app;

@interface route {
    String value();
}

class App {
    String password = "hunter2";

    @route("/run")
    void handle(String code) {
        eval(code);
    }

    void eval(String code) {}
}
"#;

const APP_JS: &str = r#"
function route(path) {
  return (target, key, descriptor) => descriptor;
}

const password = "hunter2";

class JsController {
  @route("/run")
  handle(code) {
    eval(code);
  }
}
"#;

const APP_TS: &str = r#"
function route(path: string) {
  return (target: unknown, key: string, descriptor: PropertyDescriptor) => descriptor;
}

const password = "hunter2";

class TsController {
  @route("/run")
  handle(code: string) {
    eval(code);
  }
}
"#;

fn run_query(query: serde_json::Value) -> SearchAstOutput {
    let project = InlineTestProject::new()
        .file("python/app.py", APP_PY)
        .file("java/App.java", APP_JAVA)
        .file("javascript/app.js", APP_JS)
        .file("typescript/app.ts", APP_TS)
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = AstQuery::from_json(&query).expect("query should parse");
    execute(workspace.analyzer(), &query)
}

#[test]
fn same_eval_call_query_matches_python_java_javascript_and_typescript() {
    let output = run_query(json!({
        "match": {
            "kind": "call",
            "callee": { "name": "eval" },
            "args": [{ "capture": "code" }]
        },
        "inside": { "kind": "callable", "capture": "fn" }
    }));

    assert!(
        output.diagnostics.is_empty(),
        "all project languages should have structural adapters: {:?}",
        output.diagnostics
    );
    assert_eq!(output.matches.len(), 4);

    let rows: Vec<_> = output
        .matches
        .iter()
        .map(|m| (m.language, m.path.as_str(), m.text.as_str()))
        .collect();
    assert_eq!(
        rows,
        vec![
            ("java", "java/App.java", "eval(code)"),
            ("javascript", "javascript/app.js", "eval(code)"),
            ("typescript", "typescript/app.ts", "eval(code)"),
            ("python", "python/app.py", "eval(code)"),
        ]
    );

    for m in &output.matches {
        assert!(
            m.captures
                .iter()
                .any(|capture| capture.name == "code" && capture.text == "code"),
            "missing argument capture for {m:?}"
        );
        assert!(
            m.captures.iter().any(|capture| capture.name == "fn"),
            "missing enclosing callable capture for {m:?}"
        );
    }
}

#[test]
fn assignment_query_matches_variable_initializers_across_languages() {
    let output = run_query(json!({
        "match": {
            "kind": "assignment",
            "left": { "name": "password" },
            "right": { "kind": "string_literal", "capture": "value" }
        }
    }));

    assert!(output.diagnostics.is_empty());
    assert_eq!(output.matches.len(), 4);
    for m in &output.matches {
        assert_eq!(
            m.captures.len(),
            1,
            "expected only the value capture: {m:?}"
        );
        assert_eq!(m.captures[0].name, "value");
        assert_eq!(m.captures[0].text, r#""hunter2""#);
    }
}

#[test]
fn decorator_query_matches_python_decorators_java_annotations_and_js_ts_decorators() {
    let output = run_query(json!({
        "match": {
            "kind": "callable",
            "not_kind": "lambda",
            "decorators": [{ "name": "route" }]
        }
    }));

    assert!(output.diagnostics.is_empty());
    let rows: Vec<_> = output
        .matches
        .iter()
        .map(|m| (m.language, m.path.as_str(), m.kind))
        .collect();
    assert_eq!(
        rows,
        vec![
            ("java", "java/App.java", "method"),
            ("javascript", "javascript/app.js", "method"),
            ("typescript", "typescript/app.ts", "method"),
            ("python", "python/app.py", "function"),
        ]
    );

    let snippets: Vec<_> = output.matches.iter().map(|m| m.text.as_str()).collect();
    assert_eq!(
        snippets,
        vec![
            "@route(\"/run\")…",
            "@route(\"/run\")…",
            "handle(code: string) {…",
            "def handle_request(code):…",
        ]
    );
}
