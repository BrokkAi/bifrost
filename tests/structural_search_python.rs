//! End-to-end tests for `query_code` structural queries over Python
//! (issue #328, ExecPlan milestone 2). Queries enter as JSON exactly as the
//! tool receives them; assertions run against the structured output.

mod common;

use brokk_bifrost::AnalyzerConfig;
use brokk_bifrost::analyzer::structural::{CodeQuery, CodeQueryResult, execute};
use brokk_bifrost::{Language, WorkspaceAnalyzer};
use common::InlineTestProject;
use serde_json::json;

const APP_PY: &str = r#"import pickle
import subprocess
from os import path

password = "hunter2"
retries = 3


@app.route("/run")
def handle_request(request):
    code = request.args["q"]
    eval(code)
    subprocess.run(cmd, shell=True)
    return "ok"


class Controller:
    def execute_action(self, cmd):
        eval(cmd)

    def safe(self):
        return 1


def helper():
    data = "static"
    return data


compute = lambda x: x + retries
"#;

fn run_query(query: serde_json::Value) -> CodeQueryResult {
    let project = InlineTestProject::with_language(Language::Python)
        .file("src/app.py", APP_PY)
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&query).expect("query should parse");
    execute(workspace.analyzer(), &query)
}

#[test]
fn finds_eval_calls_with_argument_capture() {
    let output = run_query(json!({
        "match": {
            "kind": "call",
            "callee": { "name": "eval" },
            "args": [{ "capture": "code" }]
        }
    }));

    assert_eq!(output.matches.len(), 2, "expected both eval call sites");
    let first = &output.matches[0];
    assert_eq!(first.path, "src/app.py");
    assert_eq!(first.kind, "call");
    assert_eq!(first.text, "eval(code)");
    assert_eq!(first.captures.len(), 1);
    assert_eq!(first.captures[0].name, "code");
    assert_eq!(first.captures[0].text, "code");
    assert!(first.id.is_none());
    assert!(first.node_range.is_none());
    assert!(first.captures[0].range.is_none());
    assert_eq!(
        first.enclosing_symbol.as_deref(),
        Some("src.app.handle_request")
    );

    let second = &output.matches[1];
    assert_eq!(second.text, "eval(cmd)");
    assert_eq!(
        second.enclosing_symbol.as_deref(),
        Some("src.app.Controller.execute_action")
    );
}

#[test]
fn full_result_detail_includes_stable_ranges_and_capture_kind() {
    let output = run_query(json!({
        "match": {
            "kind": "call",
            "callee": { "name": "eval" },
            "args": [{ "capture": "code" }]
        },
        "result_detail": "full",
        "limit": 1
    }));

    let first = &output.matches[0];
    let id = first.id.as_deref().expect("full detail match id");
    assert!(id.contains("src/app.py:call:"), "{id}");
    let range = first.node_range.expect("full detail node range");
    assert!(range.start_byte < range.end_byte);
    assert_eq!(range.start_line, first.start_line);
    assert_eq!(range.end_line, first.end_line);
    assert!(range.start_column >= 1);
    assert!(range.end_column >= 1);

    let capture = &first.captures[0];
    assert_eq!(capture.kind, Some("identifier"));
    let capture_range = capture.range.expect("full detail capture range");
    assert_eq!(capture_range.start_line, capture.start_line);
    assert!(capture_range.end_line >= capture_range.start_line);
}

#[test]
fn duplicate_capture_names_require_exact_text_equality() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "src/app.py",
            r#"
def run(x, y):
    pair(x, x)
    pair(x, y)
"#,
        )
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "match": {
            "kind": "call",
            "callee": { "name": "pair" },
            "args": [
                { "capture": "same" },
                { "capture": "same" }
            ]
        }
    }))
    .expect("query should parse");
    let output = execute(workspace.analyzer(), &query);

    assert_eq!(output.matches.len(), 1);
    assert_eq!(output.matches[0].text, "pair(x, x)");
    assert_eq!(output.matches[0].captures.len(), 2);
    assert!(
        output.matches[0]
            .captures
            .iter()
            .all(|capture| capture.name == "same" && capture.text == "x")
    );
}

#[test]
fn receiver_and_kwargs_narrow_call_matches() {
    let output = run_query(json!({
        "match": {
            "kind": "call",
            "receiver": { "name": "subprocess" },
            "callee": { "name": "run" },
            "kwargs": { "shell": { "kind": "boolean_literal" } }
        }
    }));

    assert_eq!(output.matches.len(), 1);
    assert_eq!(output.matches[0].text, "subprocess.run(cmd, shell=True)");

    // Same query but requiring a string-literal shell value: no match.
    let output = run_query(json!({
        "match": {
            "kind": "call",
            "callee": { "name": "run" },
            "kwargs": { "shell": { "kind": "string_literal" } }
        }
    }));
    assert!(output.matches.is_empty());
}

#[test]
fn containment_and_negation_scope_matches() {
    let inside_class = run_query(json!({
        "match": { "kind": "call", "callee": { "name": "eval" } },
        "inside": { "kind": "class", "name": { "regex": ".*Controller$" } }
    }));
    assert_eq!(inside_class.matches.len(), 1);
    assert_eq!(
        inside_class.matches[0].enclosing_symbol.as_deref(),
        Some("src.app.Controller.execute_action")
    );

    let outside_class = run_query(json!({
        "match": { "kind": "call", "callee": { "name": "eval" } },
        "not_inside": { "kind": "class" }
    }));
    assert_eq!(outside_class.matches.len(), 1);
    assert_eq!(
        outside_class.matches[0].enclosing_symbol.as_deref(),
        Some("src.app.handle_request")
    );
}

#[test]
fn assignment_of_string_literal_and_kind_hierarchy() {
    let output = run_query(json!({
        "match": {
            "kind": "assignment",
            "left": { "name": "password" },
            "right": { "kind": "string_literal", "capture": "value" }
        }
    }));
    assert_eq!(output.matches.len(), 1);
    assert_eq!(output.matches[0].text, r#"password = "hunter2""#);
    assert_eq!(output.matches[0].captures[0].text, r#""hunter2""#);

    // Subtype-aware: the broad `literal` kind matches both the string and
    // the numeric assignment right-hand sides.
    let broad = run_query(json!({
        "match": { "kind": "assignment", "right": { "kind": "literal" } }
    }));
    assert_eq!(broad.matches.len(), 3, "hunter2, retries, and data");

    // Kind unions: string OR numeric literal on the right, spelled out.
    let union = run_query(json!({
        "match": { "kind": "assignment", "right": { "kind": ["string_literal", "numeric_literal"] } }
    }));
    assert_eq!(union.matches.len(), 3);

    // Exclusion narrows the broad kind: literal-but-not-string leaves only
    // the numeric assignment.
    let subtractive = run_query(json!({
        "match": {
            "kind": "assignment",
            "right": { "kind": "literal", "not_kind": "string_literal" }
        }
    }));
    assert_eq!(subtractive.matches.len(), 1);
    assert_eq!(subtractive.matches[0].text, "retries = 3");
}

#[test]
fn decorated_functions_and_method_kind_refinement() {
    let decorated = run_query(json!({
        "match": { "kind": "function", "decorators": [{ "name": "route" }] }
    }));
    assert_eq!(decorated.matches.len(), 1);
    assert_eq!(
        decorated.matches[0].enclosing_symbol.as_deref(),
        Some("src.app.handle_request")
    );

    // `method` matches only defs directly inside a class; `callable`
    // matches functions, methods, and lambdas alike.
    let methods = run_query(json!({ "match": { "kind": "method" } }));
    assert!(
        methods.diagnostics.is_empty(),
        "method is a Python refined kind and should not warn: {:?}",
        methods.diagnostics
    );
    assert_eq!(methods.matches.len(), 2, "execute_action and safe");

    let callables = run_query(json!({ "match": { "kind": "callable" } }));
    assert_eq!(
        callables.matches.len(),
        5,
        "2 functions + 2 methods + 1 lambda"
    );

    // "All named functions, but not constructors or lambdas": both the
    // subtractive and the union spelling agree.
    let named = run_query(json!({
        "match": { "kind": "callable", "not_kind": ["constructor", "lambda"] }
    }));
    assert_eq!(named.matches.len(), 4, "2 functions + 2 methods");

    let union = run_query(json!({ "match": { "kind": ["function", "method"] } }));
    assert_eq!(union.matches.len(), 4);
}

#[test]
fn imports_match_by_module_name() {
    let output = run_query(json!({
        "match": { "kind": "import", "module": { "name": "pickle" } }
    }));
    assert_eq!(output.matches.len(), 1);
    assert_eq!(output.matches[0].text, "import pickle");

    let from_import = run_query(json!({
        "match": { "kind": "import", "module": { "name": "os" } }
    }));
    assert_eq!(from_import.matches.len(), 1);
    assert_eq!(from_import.matches[0].text, "from os import path");
}

#[test]
fn where_globs_and_limit_scope_the_search() {
    let excluded = run_query(json!({
        "where": ["lib/**/*.py"],
        "match": { "kind": "call" }
    }));
    assert!(excluded.matches.is_empty());

    let limited = run_query(json!({
        "match": { "kind": "call", "callee": { "name": "eval" } },
        "limit": 1
    }));
    assert_eq!(limited.matches.len(), 1);
    assert!(limited.truncated);
}

#[test]
fn broad_call_query_finds_every_call() {
    // The direct kind-table-vs-grammar validation lives in the Python spec's
    // unit tests; this asserts the broad end-to-end shape.
    let output = run_query(json!({ "match": { "kind": "call" } }));
    assert_eq!(
        output.matches.len(),
        4,
        "route decorator call, eval x2, subprocess.run; request.args[...] is a subscript, not a call"
    );
    assert!(output.diagnostics.is_empty());
}
