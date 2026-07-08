//! Cross-language `search_ast` tests for Java and JS/TS structural adapters
//! (issue #328, ExecPlan milestone 4).

mod common;

use brokk_bifrost::analyzer::structural::{AstQuery, SearchAstOutput, execute};
use brokk_bifrost::{AnalyzerConfig, WorkspaceAnalyzer};
use common::InlineTestProject;
use serde_json::json;
use std::collections::BTreeSet;

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
fn remaining_languages_report_missing_structural_adapters_before_issue_527_rollout() {
    let output = run_query_with_files(
        &[
            (
                "go/app.go",
                "package app\n\nfunc audit() {}\nfunc run() { audit() }\n",
            ),
            ("cpp/app.cpp", "void audit() {}\nvoid run() { audit(); }\n"),
            ("rust/lib.rs", "fn audit() {}\nfn run() { audit(); }\n"),
            (
                "php/app.php",
                "<?php\nfunction audit() {}\nfunction run() { audit(); }\n",
            ),
            (
                "scala/App.scala",
                "object App { def audit(): Unit = (); def run(): Unit = audit() }\n",
            ),
            (
                "csharp/App.cs",
                "class App { void audit() {} void run() { audit(); } }\n",
            ),
            ("ruby/app.rb", "def audit; end\ndef run; audit; end\n"),
        ],
        json!({ "match": { "kind": "call", "callee": { "name": "audit" } } }),
    );

    assert!(output.matches.is_empty(), "unexpected matches: {output:?}");

    let diagnostics: BTreeSet<_> = output
        .diagnostics
        .iter()
        .map(|diagnostic| (diagnostic.language, diagnostic.message.as_str()))
        .collect();
    assert_eq!(
        diagnostics,
        BTreeSet::from([
            (
                "go",
                "no structural adapter for go yet; its files were not searched",
            ),
            (
                "cpp",
                "no structural adapter for cpp yet; its files were not searched",
            ),
            (
                "rust",
                "no structural adapter for rust yet; its files were not searched",
            ),
            (
                "php",
                "no structural adapter for php yet; its files were not searched",
            ),
            (
                "scala",
                "no structural adapter for scala yet; its files were not searched",
            ),
            (
                "csharp",
                "no structural adapter for csharp yet; its files were not searched",
            ),
            (
                "ruby",
                "no structural adapter for ruby yet; its files were not searched",
            ),
        ])
    );
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
            ("python", "python/app.py", "eval(code)"),
            ("typescript", "typescript/app.ts", "eval(code)"),
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
            ("python", "python/app.py", "function"),
            ("typescript", "typescript/app.ts", "method"),
        ]
    );

    let snippets: Vec<_> = output.matches.iter().map(|m| m.text.as_str()).collect();
    assert_eq!(
        snippets,
        vec![
            "@route(\"/run\")…",
            "@route(\"/run\")…",
            "def handle_request(code):…",
            "handle(code: string) {…",
        ]
    );
}

#[test]
fn full_detail_reports_decorator_ranges_for_decorated_callables() {
    let output = run_query(json!({
        "match": {
            "kind": "callable",
            "not_kind": "lambda",
            "decorators": [{ "name": "route" }]
        },
        "result_detail": "full"
    }));

    assert_eq!(output.matches.len(), 4);
    for m in &output.matches {
        let node_range = m.node_range.expect("full detail node range");
        assert_eq!(
            m.decorator_ranges.len(),
            1,
            "expected one decorator range for {m:?}"
        );
        let decorated_range = m.decorated_range.expect("decorated range");
        assert!(decorated_range.start_byte <= node_range.start_byte);
        assert!(decorated_range.end_byte >= node_range.end_byte);
        let decorator_range = m.decorator_ranges[0];
        assert!(decorator_range.start_byte < decorator_range.end_byte);
        assert!(decorator_range.start_byte >= decorated_range.start_byte);
        assert!(decorator_range.end_byte <= decorated_range.end_byte);
    }
}

#[test]
fn full_detail_reports_decorator_ranges_for_decorated_classes() {
    let output = run_query_with_files(
        &[
            (
                "python/app.py",
                r#"
def route(path):
    return lambda cls: cls

@route("/class")
class PyController:
    pass
"#,
            ),
            (
                "java/App.java",
                r#"
@interface route {
    String value();
}

@route("/class")
class JavaController {}
"#,
            ),
            (
                "javascript/app.js",
                r#"
function route(path) {
  return target => target;
}

@route("/class")
class JsController {}
"#,
            ),
            (
                "typescript/app.ts",
                r#"
function route(path: string) {
  return (target: unknown) => target;
}

@route("/class")
class TsController {}
"#,
            ),
        ],
        json!({
            "match": {
                "kind": "class",
                "decorators": [{ "name": "route" }]
            },
            "result_detail": "full"
        }),
    );

    assert!(output.diagnostics.is_empty(), "{:?}", output.diagnostics);
    assert_eq!(output.matches.len(), 4);
    let mut languages = output
        .matches
        .iter()
        .map(|m| m.language)
        .collect::<Vec<_>>();
    languages.sort_unstable();
    assert_eq!(
        languages,
        vec!["java", "javascript", "python", "typescript"]
    );
    for m in &output.matches {
        assert_eq!(m.kind, "class");
        assert_eq!(m.decorator_ranges.len(), 1, "{m:?}");
        assert!(m.decorated_range.is_some(), "{m:?}");
        assert!(m.node_range.is_some(), "{m:?}");
    }
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
fn js_ts_import_modules_match_by_unquoted_module_name() {
    let output = run_query_with_files(
        &[
            ("javascript/imports.js", r#"import React from "react";"#),
            (
                "typescript/imports.ts",
                r#"import type { User } from "./types";"#,
            ),
        ],
        json!({
            "languages": ["javascript", "typescript"],
            "match": { "kind": "import", "module": { "name": "react" } }
        }),
    );
    assert!(output.diagnostics.is_empty(), "{:?}", output.diagnostics);
    assert_eq!(output.matches.len(), 1);
    assert_eq!(output.matches[0].path, "javascript/imports.js");
    assert_eq!(output.matches[0].text, r#"import React from "react";"#);

    let relative = run_query_with_files(
        &[(
            "typescript/imports.ts",
            r#"import type { User } from "./types";"#,
        )],
        json!({
            "languages": ["typescript"],
            "match": { "kind": "import", "module": { "name": "./types" } }
        }),
    );
    assert!(
        relative.diagnostics.is_empty(),
        "{:?}",
        relative.diagnostics
    );
    assert_eq!(relative.matches.len(), 1);
    assert_eq!(relative.matches[0].path, "typescript/imports.ts");
}

#[test]
fn java_import_modules_match_by_full_scoped_name() {
    let output = run_query_with_files(
        &[("java/App.java", "import java.util.List;\nclass App {}\n")],
        json!({
            "languages": ["java"],
            "match": { "kind": "import", "module": { "name": "java.util.List" } }
        }),
    );

    assert!(output.diagnostics.is_empty(), "{:?}", output.diagnostics);
    assert_eq!(output.matches.len(), 1);
    assert_eq!(output.matches[0].path, "java/App.java");
    assert_eq!(output.matches[0].text, "import java.util.List;");
}

#[test]
fn member_call_callee_is_terminal_name_and_receiver_carries_object() {
    let output = run_query_with_files(
        &[
            (
                "python/app.py",
                "def run(service, code):\n    service.execute(code)\n",
            ),
            (
                "java/App.java",
                "class App { void run(Service service, String code) { service.execute(code); } }\n",
            ),
            (
                "javascript/app.js",
                "function run(service, code) { service.execute(code); }\n",
            ),
            (
                "typescript/app.ts",
                "function run(service: Service, code: string) { service.execute(code); }\n",
            ),
        ],
        json!({
            "match": {
                "kind": "call",
                "receiver": { "name": "service" },
                "callee": { "kind": "identifier", "name": "execute" }
            }
        }),
    );

    assert!(output.diagnostics.is_empty(), "{:?}", output.diagnostics);
    let rows: Vec<_> = output
        .matches
        .iter()
        .map(|m| (m.language, m.path.as_str(), m.text.as_str()))
        .collect();
    assert_eq!(
        rows,
        vec![
            ("java", "java/App.java", "service.execute(code)"),
            ("javascript", "javascript/app.js", "service.execute(code)"),
            ("python", "python/app.py", "service.execute(code)"),
            ("typescript", "typescript/app.ts", "service.execute(code)"),
        ]
    );
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
