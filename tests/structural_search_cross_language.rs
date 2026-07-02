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
empty: str


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
    String empty;

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
let empty;

class JsController {
  constructor() {}

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
let empty: string;
type UserId = string;

class TsController {
  constructor() {}

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

fn run_query_with_files(files: &[(&str, &str)], query: serde_json::Value) -> SearchAstOutput {
    let mut project = InlineTestProject::new();
    for (path, source) in files {
        project = project.file(*path, *source);
    }
    let project = project.build();
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
fn assignment_query_does_not_match_uninitialized_declarations() {
    let output = run_query(json!({
        "match": {
            "kind": "assignment",
            "left": { "name": "empty" }
        }
    }));

    assert!(output.matches.is_empty(), "unexpected matches: {output:?}");
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

#[test]
fn js_ts_constructors_are_refined_and_excluded_from_named_callable_queries() {
    let constructors = run_query(json!({
        "languages": ["javascript", "typescript"],
        "match": { "kind": "constructor" }
    }));
    assert!(constructors.diagnostics.is_empty());
    assert_eq!(constructors.matches.len(), 2);
    assert!(
        constructors
            .matches
            .iter()
            .all(|m| m.kind == "constructor" && m.text.starts_with("constructor")),
        "unexpected constructor matches: {constructors:?}"
    );

    let named_callables = run_query(json!({
        "languages": ["javascript", "typescript"],
        "match": { "kind": "callable", "not_kind": "constructor" }
    }));
    assert!(
        named_callables
            .matches
            .iter()
            .all(|m| !m.text.starts_with("constructor")),
        "constructors should be excluded: {named_callables:?}"
    );
}

#[test]
fn js_ts_class_expressions_and_type_alias_names_are_searchable() {
    let output = run_query_with_files(
        &[
            (
                "javascript/expr.js",
                "const Expr = class {\n  method() {}\n};\n",
            ),
            (
                "typescript/expr.ts",
                "const Expr = class {\n  method(): void {}\n};\ntype UserId = string;\n",
            ),
        ],
        json!({ "match": { "kind": "class" } }),
    );
    assert!(output.diagnostics.is_empty());
    assert_eq!(output.matches.len(), 2);
    assert!(
        output.matches.iter().all(|m| m.text.starts_with("class")),
        "expected class-expression matches: {output:?}"
    );

    let alias = run_query_with_files(
        &[("typescript/alias.ts", "type UserId = string;\n")],
        json!({ "match": { "kind": "declaration", "name": "UserId" } }),
    );
    assert!(alias.diagnostics.is_empty());
    assert_eq!(alias.matches.len(), 1);
    assert_eq!(alias.matches[0].text, "type UserId = string;");
}

#[test]
fn tsx_files_use_the_tsx_grammar_for_structural_search() {
    let output = run_query_with_files(
        &[(
            "typescript/widget.tsx",
            r#"export function Widget({ code }: { code: string }) {
  return <button onClick={() => eval(code)}>Run</button>;
}
"#,
        )],
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "eval" },
                "args": [{ "capture": "code" }]
            },
            "inside": { "kind": "callable", "capture": "fn" }
        }),
    );

    assert!(output.diagnostics.is_empty(), "{:?}", output.diagnostics);
    assert_eq!(output.matches.len(), 1);
    assert_eq!(output.matches[0].path, "typescript/widget.tsx");
    assert_eq!(output.matches[0].text, "eval(code)");
}

#[test]
fn unsupported_role_queries_report_capability_diagnostics() {
    let output = run_query(json!({
        "match": {
            "kind": "call",
            "kwargs": { "shell": { "kind": "boolean_literal" } }
        }
    }));

    assert!(
        output.diagnostics.iter().any(
            |diagnostic| diagnostic.language == "java" && diagnostic.message.contains("kwargs")
        ),
        "expected java kwargs diagnostic: {:?}",
        output.diagnostics
    );
    assert!(
        output
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.language == "javascript"
                && diagnostic.message.contains("kwargs")),
        "expected javascript kwargs diagnostic: {:?}",
        output.diagnostics
    );
    assert!(
        output
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.language == "typescript"
                && diagnostic.message.contains("kwargs")),
        "expected typescript kwargs diagnostic: {:?}",
        output.diagnostics
    );
}
