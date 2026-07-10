//! Cross-language `query_code` tests for Java and JS/TS structural adapters
//! (issue #328, ExecPlan milestone 4).

mod common;

use brokk_bifrost::analyzer::structural::{CodeQuery, CodeQueryResult, execute};
use brokk_bifrost::{AnalyzerConfig, Language, WorkspaceAnalyzer};
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

fn run_query(query: serde_json::Value) -> CodeQueryResult {
    let project = InlineTestProject::new()
        .file("python/app.py", APP_PY)
        .file("java/App.java", APP_JAVA)
        .file("javascript/app.js", APP_JS)
        .file("typescript/app.ts", APP_TS)
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&query).expect("query should parse");
    execute(workspace.analyzer(), &query)
}

fn run_query_with_files(files: &[(&str, &str)], query: serde_json::Value) -> CodeQueryResult {
    let mut project = InlineTestProject::new();
    for (path, source) in files {
        project = project.file(*path, *source);
    }
    let project = project.build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&query).expect("query should parse");
    execute(workspace.analyzer(), &query)
}

#[test]
fn remaining_languages_search_without_unsupported_adapter_diagnostics_during_issue_527_rollout() {
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
            ("ruby/app.rb", "def audit; end\ndef run; audit(); end\n"),
        ],
        json!({ "match": { "kind": "call", "callee": { "name": "audit" } } }),
    );

    let rows: Vec<_> = output
        .matches
        .iter()
        .map(|m| (m.language, m.path.as_str(), m.text.as_str()))
        .collect();
    assert_eq!(
        rows,
        vec![
            ("cpp", "cpp/app.cpp", "audit()"),
            ("csharp", "csharp/App.cs", "audit()"),
            ("go", "go/app.go", "audit()"),
            ("php", "php/app.php", "audit()"),
            ("ruby", "ruby/app.rb", "audit()"),
            ("rust", "rust/lib.rs", "audit()"),
            ("scala", "scala/App.scala", "audit()"),
        ]
    );

    let diagnostics: BTreeSet<_> = output
        .diagnostics
        .iter()
        .map(|diagnostic| (diagnostic.language, diagnostic.message.as_str()))
        .collect();
    assert!(diagnostics.is_empty(), "{diagnostics:?}");
}

#[test]
fn cpp_function_like_macro_invocation_matches_call_callee_query() {
    let output = run_query_with_files(
        &[(
            "cpp/macros.cpp",
            "#define TEST_DECLARE(name) int name\nvoid run() { TEST_DECLARE(value); }\n",
        )],
        json!({
            "languages": ["cpp"],
            "match": { "kind": "call", "callee": { "name": "TEST_DECLARE" } }
        }),
    );

    assert!(output.diagnostics.is_empty(), "{output:?}");
    assert_eq!(1, output.matches.len(), "{output:?}");
    assert_eq!("cpp/macros.cpp", output.matches[0].path);
    assert_eq!("TEST_DECLARE(value)", output.matches[0].text);
}

#[test]
fn shared_call_query_matches_every_analyzable_language_without_adapter_diagnostics() {
    let cases = [
        (
            "java",
            "java/App.java",
            "class App { void audit() {} void run() { audit(); } }\n",
            "audit()",
        ),
        (
            "go",
            "go/app.go",
            "package app\n\nfunc audit() {}\nfunc run() { audit() }\n",
            "audit()",
        ),
        (
            "cpp",
            "cpp/app.cpp",
            "void audit() {}\nvoid run() { audit(); }\n",
            "audit()",
        ),
        (
            "javascript",
            "javascript/app.js",
            "function audit() {}\nfunction run() { audit(); }\n",
            "audit()",
        ),
        (
            "typescript",
            "typescript/app.ts",
            "function audit(): void {}\nfunction run(): void { audit(); }\n",
            "audit()",
        ),
        (
            "python",
            "python/app.py",
            "def audit():\n    pass\n\ndef run():\n    audit()\n",
            "audit()",
        ),
        (
            "rust",
            "rust/lib.rs",
            "fn audit() {}\nfn run() { audit(); }\n",
            "audit()",
        ),
        (
            "php",
            "php/app.php",
            "<?php\nfunction audit() {}\nfunction run() { audit(); }\n",
            "audit()",
        ),
        (
            "scala",
            "scala/App.scala",
            "object App { def audit(): Unit = (); def run(): Unit = audit() }\n",
            "audit()",
        ),
        (
            "csharp",
            "csharp/App.cs",
            "class App { void audit() {} void run() { audit(); } }\n",
            "audit()",
        ),
        (
            "ruby",
            "ruby/app.rb",
            "def audit; end\ndef run; audit(); end\n",
            "audit()",
        ),
    ];
    let files: Vec<_> = cases
        .iter()
        .map(|(_, path, source, _)| (*path, *source))
        .collect();
    let output = run_query_with_files(
        &files,
        json!({ "match": { "kind": "call", "callee": { "name": "audit" } } }),
    );

    assert!(
        output.diagnostics.is_empty(),
        "all analyzable languages should have structural adapters: {:?}",
        output.diagnostics
    );
    assert_eq!(output.matches.len(), Language::ANALYZABLE.len());

    let expected_languages: BTreeSet<_> = Language::ANALYZABLE
        .iter()
        .map(|language| language.config_label())
        .collect();
    let case_languages: BTreeSet<_> = cases.iter().map(|(language, _, _, _)| *language).collect();
    assert_eq!(case_languages, expected_languages);

    let actual_languages: BTreeSet<_> = output.matches.iter().map(|mat| mat.language).collect();
    assert_eq!(actual_languages, expected_languages);

    let expected_rows: BTreeSet<_> = cases
        .iter()
        .map(|(language, path, _, text)| (*language, *path, *text))
        .collect();
    let rows: BTreeSet<_> = output
        .matches
        .iter()
        .map(|mat| (mat.language, mat.path.as_str(), mat.text.as_str()))
        .collect();
    assert_eq!(rows, expected_rows);
}

#[test]
fn go_structural_adapter_matches_normalized_shapes() {
    const GO_APP: &str = r#"
package app

import (
    "fmt"
    "net/http"
)

type Service struct {
    Name string
}

type Alias = Service

const password = "hunter2"
var retries, attempts = 3, 4
var callback = func(value string) string {
    return value
}

func audit(code string) string {
    fmt.Println(code)
    service := Service{Name: "primary"}
    service.Name = "updated"
    return code
}

func (s Service) Run(code string) {
    audit(code)
}
"#;

    let audit = run_query_with_files(
        &[("go/app.go", GO_APP)],
        json!({
            "languages": ["go"],
            "match": {
                "kind": "call",
                "callee": { "name": "audit" },
                "args": [{ "capture": "code" }]
            }
        }),
    );
    assert!(audit.diagnostics.is_empty(), "{:?}", audit.diagnostics);
    assert_eq!(audit.matches.len(), 1);
    assert_eq!(audit.matches[0].text, "audit(code)");
    assert_eq!(audit.matches[0].captures[0].text, "code");

    let assignment = run_query_with_files(
        &[("go/app.go", GO_APP)],
        json!({
            "languages": ["go"],
            "match": {
                "kind": "assignment",
                "left": { "name": "password" },
                "right": { "kind": "string_literal", "capture": "value" }
            }
        }),
    );
    assert!(
        assignment.diagnostics.is_empty(),
        "{:?}",
        assignment.diagnostics
    );
    assert_eq!(assignment.matches.len(), 1);
    assert_eq!(assignment.matches[0].text, r#"password = "hunter2""#);
    assert_eq!(assignment.matches[0].captures[0].text, r#""hunter2""#);

    let multi_assignment = run_query_with_files(
        &[("go/app.go", GO_APP)],
        json!({
            "languages": ["go"],
            "match": {
                "kind": "assignment",
                "left": { "name": "attempts" },
                "right": { "text": { "regex": "^4$" }, "capture": "value" }
            }
        }),
    );
    assert!(
        multi_assignment.diagnostics.is_empty(),
        "{:?}",
        multi_assignment.diagnostics
    );
    assert_eq!(multi_assignment.matches.len(), 1);
    assert_eq!(multi_assignment.matches[0].text, "retries, attempts = 3, 4");
    assert_eq!(multi_assignment.matches[0].captures[0].text, "4");

    let field_access = run_query_with_files(
        &[("go/app.go", GO_APP)],
        json!({
            "languages": ["go"],
            "match": {
                "kind": "field_access",
                "object": { "name": "service" },
                "field": { "name": "Name" }
            }
        }),
    );
    assert!(
        field_access.diagnostics.is_empty(),
        "{:?}",
        field_access.diagnostics
    );
    assert_eq!(field_access.matches.len(), 1);
    assert_eq!(field_access.matches[0].text, "service.Name");

    let import = run_query_with_files(
        &[("go/app.go", GO_APP)],
        json!({
            "languages": ["go"],
            "match": { "kind": "import", "module": { "name": "net/http" } }
        }),
    );
    assert!(import.diagnostics.is_empty(), "{:?}", import.diagnostics);
    assert_eq!(import.matches.len(), 1);
    assert_eq!(import.matches[0].text, "import (…");

    let declarations = run_query_with_files(
        &[("go/app.go", GO_APP)],
        json!({
            "languages": ["go"],
            "match": { "kind": "declaration", "name": { "regex": "^(Service|Alias|audit|Run)$" } }
        }),
    );
    assert!(
        declarations.diagnostics.is_empty(),
        "{:?}",
        declarations.diagnostics
    );
    let declaration_rows: Vec<_> = declarations
        .matches
        .iter()
        .map(|m| (m.kind, m.text.as_str()))
        .collect();
    assert_eq!(
        declaration_rows,
        vec![
            ("class", "Service struct {…"),
            ("declaration", "Alias = Service"),
            ("function", "func audit(code string) string {…"),
            ("method", "func (s Service) Run(code string) {…"),
        ]
    );

    let type_identifier = run_query_with_files(
        &[("go/app.go", GO_APP)],
        json!({
            "languages": ["go"],
            "match": { "kind": "identifier", "name": "Alias" }
        }),
    );
    assert!(
        type_identifier.diagnostics.is_empty(),
        "{:?}",
        type_identifier.diagnostics
    );
    assert!(
        type_identifier.matches.iter().any(|m| m.text == "Alias"),
        "expected Alias type identifier match: {:?}",
        type_identifier.matches
    );

    let lambda = run_query_with_files(
        &[("go/app.go", GO_APP)],
        json!({
            "languages": ["go"],
            "match": { "kind": "lambda", "has": { "kind": "return" } }
        }),
    );
    assert!(lambda.diagnostics.is_empty(), "{:?}", lambda.diagnostics);
    assert_eq!(lambda.matches.len(), 1);
    assert_eq!(lambda.matches[0].text, "func(value string) string {…");

    let unsupported = run_query_with_files(
        &[("go/app.go", GO_APP)],
        json!({
            "languages": ["go"],
            "match": {
                "kind": "call",
                "kwargs": { "shell": { "kind": "boolean_literal" } }
            }
        }),
    );
    assert!(
        unsupported
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.language == "go" && diagnostic.message.contains("kwargs")),
        "expected go kwargs diagnostic: {:?}",
        unsupported.diagnostics
    );
}

#[test]
fn cpp_structural_adapter_matches_normalized_shapes() {
    const CPP_APP: &str = r#"
#include <vector>
#include "service.h"

#include <string>

using Alias = Service;

struct Service {
    std::string Name;

    Service();
    void Run(const std::string& code);
};

Service::Service() {}

void Service::Run(const std::string& code) {
    audit(code);
}

std::string password = "hunter2";
char marker = 'x';
int retries = 3;
auto callback = [](int value) {
    return value;
};

std::string audit(const std::string& code) {
    Service service;
    auto created = new Service();
    Service::Run(code);
    service.Name = "updated";
    return code;
}
"#;

    let audit = run_query_with_files(
        &[("cpp/app.cpp", CPP_APP)],
        json!({
            "languages": ["cpp"],
            "match": {
                "kind": "call",
                "callee": { "name": "audit" },
                "args": [{ "name": "code", "capture": "code" }]
            }
        }),
    );
    assert!(audit.diagnostics.is_empty(), "{:?}", audit.diagnostics);
    assert_eq!(audit.matches.len(), 1);
    assert_eq!(audit.matches[0].text, "audit(code)");
    assert_eq!(audit.matches[0].captures[0].text, "code");

    let scoped_call = run_query_with_files(
        &[("cpp/app.cpp", CPP_APP)],
        json!({
            "languages": ["cpp"],
            "match": {
                "kind": "call",
                "callee": { "name": "Run" },
                "receiver": { "name": "Service" },
                "args": [{ "name": "code" }]
            }
        }),
    );
    assert!(
        scoped_call.diagnostics.is_empty(),
        "{:?}",
        scoped_call.diagnostics
    );
    assert_eq!(scoped_call.matches.len(), 1);
    assert_eq!(scoped_call.matches[0].text, "Service::Run(code)");

    let allocation = run_query_with_files(
        &[("cpp/app.cpp", CPP_APP)],
        json!({
            "languages": ["cpp"],
            "match": {
                "kind": "call",
                "callee": { "name": "Service" }
            }
        }),
    );
    assert!(
        allocation.diagnostics.is_empty(),
        "{:?}",
        allocation.diagnostics
    );
    assert_eq!(allocation.matches.len(), 1);
    assert_eq!(allocation.matches[0].text, "new Service()");

    let assignment = run_query_with_files(
        &[("cpp/app.cpp", CPP_APP)],
        json!({
            "languages": ["cpp"],
            "match": {
                "kind": "assignment",
                "left": { "name": "password" },
                "right": { "kind": "string_literal", "capture": "value" }
            }
        }),
    );
    assert!(
        assignment.diagnostics.is_empty(),
        "{:?}",
        assignment.diagnostics
    );
    assert_eq!(assignment.matches.len(), 1);
    assert_eq!(assignment.matches[0].text, r#"password = "hunter2""#);
    assert_eq!(assignment.matches[0].captures[0].text, r#""hunter2""#);

    let char_literal = run_query_with_files(
        &[("cpp/app.cpp", CPP_APP)],
        json!({
            "languages": ["cpp"],
            "match": { "kind": "string_literal", "text": { "regex": "^'x'$" } }
        }),
    );
    assert!(
        char_literal.diagnostics.is_empty(),
        "{:?}",
        char_literal.diagnostics
    );
    assert_eq!(char_literal.matches.len(), 1);
    assert_eq!(char_literal.matches[0].text, "'x'");

    let field_access = run_query_with_files(
        &[("cpp/app.cpp", CPP_APP)],
        json!({
            "languages": ["cpp"],
            "match": {
                "kind": "field_access",
                "object": { "name": "service" },
                "field": { "name": "Name" }
            }
        }),
    );
    assert!(
        field_access.diagnostics.is_empty(),
        "{:?}",
        field_access.diagnostics
    );
    assert_eq!(field_access.matches.len(), 1);
    assert_eq!(field_access.matches[0].text, "service.Name");

    let import = run_query_with_files(
        &[("cpp/app.cpp", CPP_APP)],
        json!({
            "languages": ["cpp"],
            "match": { "kind": "import", "module": { "name": "vector" } }
        }),
    );
    assert!(import.diagnostics.is_empty(), "{:?}", import.diagnostics);
    assert_eq!(import.matches.len(), 1);
    assert_eq!(import.matches[0].text, "#include <vector>…");

    let declarations = run_query_with_files(
        &[("cpp/app.cpp", CPP_APP)],
        json!({
            "languages": ["cpp"],
            "match": { "kind": "declaration", "name": { "regex": "^(Service|Alias|audit|Run)$" } }
        }),
    );
    assert!(
        declarations.diagnostics.is_empty(),
        "{:?}",
        declarations.diagnostics
    );
    let declaration_rows: Vec<_> = declarations
        .matches
        .iter()
        .map(|m| (m.kind, m.text.as_str()))
        .collect();
    assert_eq!(
        declaration_rows,
        vec![
            ("declaration", "using Alias = Service;"),
            ("class", "struct Service {…"),
            ("constructor", "Service::Service() {}"),
            ("method", "void Service::Run(const std::string& code) {…"),
            ("function", "std::string audit(const std::string& code) {…"),
        ]
    );

    let constructor = run_query_with_files(
        &[("cpp/app.cpp", CPP_APP)],
        json!({
            "languages": ["cpp"],
            "match": { "kind": "constructor", "name": "Service" }
        }),
    );
    assert!(
        constructor.diagnostics.is_empty(),
        "{:?}",
        constructor.diagnostics
    );
    assert_eq!(constructor.matches.len(), 1);
    assert_eq!(constructor.matches[0].text, "Service::Service() {}");

    let lambda = run_query_with_files(
        &[("cpp/app.cpp", CPP_APP)],
        json!({
            "languages": ["cpp"],
            "match": { "kind": "lambda", "has": { "kind": "return" } }
        }),
    );
    assert!(lambda.diagnostics.is_empty(), "{:?}", lambda.diagnostics);
    assert_eq!(lambda.matches.len(), 1);
    assert_eq!(lambda.matches[0].text, "[](int value) {…");

    let unsupported = run_query_with_files(
        &[("cpp/app.cpp", CPP_APP)],
        json!({
            "languages": ["cpp"],
            "match": {
                "kind": "call",
                "kwargs": { "shell": { "kind": "boolean_literal" } }
            }
        }),
    );
    assert!(
        unsupported
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.language == "cpp"
                && diagnostic.message.contains("kwargs")),
        "expected cpp kwargs diagnostic: {:?}",
        unsupported.diagnostics
    );
}

#[test]
fn rust_structural_adapter_matches_normalized_shapes() {
    const RUST_APP: &str = r#"
use std::{fmt, io};

type Alias = Service;

const LIMIT: i32 = -3;
static ENABLED: bool = false;

struct Service {
    name: String,
    count: i32,
}

trait Runner {
    fn execute(&self, code: &str);
}

impl Service {
    fn run(&self, code: &str) -> String {
        audit(code)
    }
}

fn audit(code: &str) -> String {
    let password = "hunter2";
    let flag = true;
    let callback = |value: i32| {
        return value;
    };
    let mut service = Service { name: "primary".to_string(), count: 0 };
    let parsed = parse::<String>(code);
    let parsed_method = code.parse::<String>();
    service.count += 1;
    service.name = "updated".to_string();
    code.to_string()
}

fn parse<T>(value: &str) -> String {
    value.to_string()
}
"#;

    let audit = run_query_with_files(
        &[("rust/lib.rs", RUST_APP)],
        json!({
            "languages": ["rust"],
            "match": {
                "kind": "call",
                "callee": { "name": "audit" },
                "args": [{ "name": "code", "capture": "code" }]
            }
        }),
    );
    assert!(audit.diagnostics.is_empty(), "{:?}", audit.diagnostics);
    assert_eq!(audit.matches.len(), 1);
    assert_eq!(audit.matches[0].text, "audit(code)");
    assert_eq!(audit.matches[0].captures[0].text, "code");

    let method_call = run_query_with_files(
        &[("rust/lib.rs", RUST_APP)],
        json!({
            "languages": ["rust"],
            "match": {
                "kind": "call",
                "callee": { "name": "to_string" },
                "receiver": { "name": "code" }
            }
        }),
    );
    assert!(
        method_call.diagnostics.is_empty(),
        "{:?}",
        method_call.diagnostics
    );
    assert_eq!(method_call.matches.len(), 1);
    assert_eq!(method_call.matches[0].text, "code.to_string()");

    let generic_call = run_query_with_files(
        &[("rust/lib.rs", RUST_APP)],
        json!({
            "languages": ["rust"],
            "match": {
                "kind": "call",
                "callee": { "name": "parse" },
                "args": [{ "name": "code" }]
            }
        }),
    );
    assert!(
        generic_call.diagnostics.is_empty(),
        "{:?}",
        generic_call.diagnostics
    );
    assert_eq!(generic_call.matches.len(), 1);
    assert_eq!(generic_call.matches[0].text, "parse::<String>(code)");

    let assignment = run_query_with_files(
        &[("rust/lib.rs", RUST_APP)],
        json!({
            "languages": ["rust"],
            "match": {
                "kind": "assignment",
                "left": { "name": "password" },
                "right": { "kind": "string_literal", "capture": "value" }
            }
        }),
    );
    assert!(
        assignment.diagnostics.is_empty(),
        "{:?}",
        assignment.diagnostics
    );
    assert_eq!(assignment.matches.len(), 1);
    assert_eq!(assignment.matches[0].text, r#"let password = "hunter2";"#);
    assert_eq!(assignment.matches[0].captures[0].text, r#""hunter2""#);

    let mutable_assignment = run_query_with_files(
        &[("rust/lib.rs", RUST_APP)],
        json!({
            "languages": ["rust"],
            "match": {
                "kind": "assignment",
                "left": { "name": "service" },
                "right": { "text": { "regex": "^Service" }, "capture": "value" }
            }
        }),
    );
    assert!(
        mutable_assignment.diagnostics.is_empty(),
        "{:?}",
        mutable_assignment.diagnostics
    );
    assert_eq!(mutable_assignment.matches.len(), 1);
    assert_eq!(
        mutable_assignment.matches[0].text,
        r#"let mut service = Service { name: "primary".to_string(), count: 0 };"#
    );
    assert_eq!(
        mutable_assignment.matches[0].captures[0].text,
        r#"Service { name: "primary".to_string(), count: 0 }"#
    );

    let const_assignment = run_query_with_files(
        &[("rust/lib.rs", RUST_APP)],
        json!({
            "languages": ["rust"],
            "match": {
                "kind": "assignment",
                "left": { "name": "LIMIT" },
                "right": { "kind": "numeric_literal", "capture": "value" }
            }
        }),
    );
    assert!(
        const_assignment.diagnostics.is_empty(),
        "{:?}",
        const_assignment.diagnostics
    );
    assert_eq!(const_assignment.matches.len(), 1);
    assert_eq!(const_assignment.matches[0].text, "const LIMIT: i32 = -3;");
    assert_eq!(const_assignment.matches[0].captures[0].text, "-3");

    let static_assignment = run_query_with_files(
        &[("rust/lib.rs", RUST_APP)],
        json!({
            "languages": ["rust"],
            "match": {
                "kind": "assignment",
                "left": { "name": "ENABLED" },
                "right": { "kind": "boolean_literal", "capture": "value" }
            }
        }),
    );
    assert!(
        static_assignment.diagnostics.is_empty(),
        "{:?}",
        static_assignment.diagnostics
    );
    assert_eq!(static_assignment.matches.len(), 1);
    assert_eq!(
        static_assignment.matches[0].text,
        "static ENABLED: bool = false;"
    );
    assert_eq!(static_assignment.matches[0].captures[0].text, "false");

    let compound_assignment = run_query_with_files(
        &[("rust/lib.rs", RUST_APP)],
        json!({
            "languages": ["rust"],
            "match": {
                "kind": "assignment",
                "left": { "name": "count" },
                "right": { "kind": "numeric_literal", "capture": "value" }
            }
        }),
    );
    assert!(
        compound_assignment.diagnostics.is_empty(),
        "{:?}",
        compound_assignment.diagnostics
    );
    assert_eq!(compound_assignment.matches.len(), 1);
    assert_eq!(compound_assignment.matches[0].text, "service.count += 1");
    assert_eq!(compound_assignment.matches[0].captures[0].text, "1");

    let boolean_literal = run_query_with_files(
        &[("rust/lib.rs", RUST_APP)],
        json!({
            "languages": ["rust"],
            "match": { "kind": "boolean_literal", "text": { "regex": "^true$" } }
        }),
    );
    assert!(
        boolean_literal.diagnostics.is_empty(),
        "{:?}",
        boolean_literal.diagnostics
    );
    assert_eq!(boolean_literal.matches.len(), 1);
    assert_eq!(boolean_literal.matches[0].text, "true");

    let generic_method_call = run_query_with_files(
        &[("rust/lib.rs", RUST_APP)],
        json!({
            "languages": ["rust"],
            "match": {
                "kind": "call",
                "callee": { "name": "parse" },
                "receiver": { "name": "code" }
            }
        }),
    );
    assert!(
        generic_method_call.diagnostics.is_empty(),
        "{:?}",
        generic_method_call.diagnostics
    );
    assert_eq!(generic_method_call.matches.len(), 1);
    assert_eq!(
        generic_method_call.matches[0].text,
        "code.parse::<String>()"
    );

    let field_access = run_query_with_files(
        &[("rust/lib.rs", RUST_APP)],
        json!({
            "languages": ["rust"],
            "match": {
                "kind": "field_access",
                "object": { "name": "service" },
                "field": { "name": "name" }
            }
        }),
    );
    assert!(
        field_access.diagnostics.is_empty(),
        "{:?}",
        field_access.diagnostics
    );
    assert_eq!(field_access.matches.len(), 1);
    assert_eq!(field_access.matches[0].text, "service.name");

    let import = run_query_with_files(
        &[("rust/lib.rs", RUST_APP)],
        json!({
            "languages": ["rust"],
            "match": { "kind": "import", "module": { "name": "fmt" } }
        }),
    );
    assert!(import.diagnostics.is_empty(), "{:?}", import.diagnostics);
    assert_eq!(import.matches.len(), 1);
    assert_eq!(import.matches[0].text, "use std::{fmt, io};");

    let declarations = run_query_with_files(
        &[("rust/lib.rs", RUST_APP)],
        json!({
            "languages": ["rust"],
            "match": { "kind": "declaration", "name": { "regex": "^(Service|Alias|execute|audit|run|parse)$" } }
        }),
    );
    assert!(
        declarations.diagnostics.is_empty(),
        "{:?}",
        declarations.diagnostics
    );
    let declaration_rows: Vec<_> = declarations
        .matches
        .iter()
        .map(|m| (m.kind, m.text.as_str()))
        .collect();
    assert_eq!(
        declaration_rows,
        vec![
            ("declaration", "type Alias = Service;"),
            ("class", "struct Service {…"),
            ("method", "fn execute(&self, code: &str);"),
            ("method", "fn run(&self, code: &str) -> String {…"),
            ("function", "fn audit(code: &str) -> String {…"),
            ("function", "fn parse<T>(value: &str) -> String {…"),
        ]
    );

    let lambda = run_query_with_files(
        &[("rust/lib.rs", RUST_APP)],
        json!({
            "languages": ["rust"],
            "match": { "kind": "lambda", "has": { "kind": "return" } }
        }),
    );
    assert!(lambda.diagnostics.is_empty(), "{:?}", lambda.diagnostics);
    assert_eq!(lambda.matches.len(), 1);
    assert_eq!(lambda.matches[0].text, "|value: i32| {…");

    let unsupported = run_query_with_files(
        &[("rust/lib.rs", RUST_APP)],
        json!({
            "languages": ["rust"],
            "match": {
                "kind": "call",
                "kwargs": { "shell": { "kind": "boolean_literal" } }
            }
        }),
    );
    assert!(
        unsupported.diagnostics.iter().any(
            |diagnostic| diagnostic.language == "rust" && diagnostic.message.contains("kwargs")
        ),
        "expected rust kwargs diagnostic: {:?}",
        unsupported.diagnostics
    );
}

#[test]
fn php_structural_adapter_matches_normalized_shapes() {
    const PHP_APP: &str = r#"<?php
namespace App;

use App\Support\Formatter;
use App\Support\{Logger, Writer as WriterAlias};

#[Route('/run')]
class Service {
    use Loggable;

    public string $name = "primary";
    public const LIMIT = -3;

    public function __construct() {}

    public function run(string $code): string {
        audit($code);
        audit_named(code: $code);
        $this->name = "updated";
        $formatted = Formatter::format($code);
        $callback = function ($value) {
            return $value;
        };
        return $code;
    }
}

function audit(string $code): string {
    $password = "hunter2";
    $flag = true;
    return $code;
}

function audit_named(string $code): string {
    return $code;
}

$service = new Service();
$limit = Service::LIMIT;
$service->run("input");
"#;

    let audit = run_query_with_files(
        &[("php/app.php", PHP_APP)],
        json!({
            "languages": ["php"],
            "match": {
                "kind": "call",
                "callee": { "name": "audit" },
                "args": [{ "name": "code", "capture": "code" }]
            }
        }),
    );
    assert!(audit.diagnostics.is_empty(), "{:?}", audit.diagnostics);
    assert_eq!(audit.matches.len(), 1);
    assert_eq!(audit.matches[0].text, "audit($code)");
    assert_eq!(audit.matches[0].captures[0].text, "$code");

    let method_call = run_query_with_files(
        &[("php/app.php", PHP_APP)],
        json!({
            "languages": ["php"],
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": { "name": "service" }
            }
        }),
    );
    assert!(
        method_call.diagnostics.is_empty(),
        "{:?}",
        method_call.diagnostics
    );
    assert_eq!(method_call.matches.len(), 1);
    assert_eq!(method_call.matches[0].text, r#"$service->run("input")"#);

    let scoped_call = run_query_with_files(
        &[("php/app.php", PHP_APP)],
        json!({
            "languages": ["php"],
            "match": {
                "kind": "call",
                "callee": { "name": "format" },
                "receiver": { "name": "Formatter" }
            }
        }),
    );
    assert!(
        scoped_call.diagnostics.is_empty(),
        "{:?}",
        scoped_call.diagnostics
    );
    assert_eq!(scoped_call.matches.len(), 1);
    assert_eq!(scoped_call.matches[0].text, "Formatter::format($code)");

    let object_creation = run_query_with_files(
        &[("php/app.php", PHP_APP)],
        json!({
            "languages": ["php"],
            "match": { "kind": "call", "callee": { "name": "Service" } }
        }),
    );
    assert!(
        object_creation.diagnostics.is_empty(),
        "{:?}",
        object_creation.diagnostics
    );
    assert_eq!(object_creation.matches.len(), 1);
    assert_eq!(object_creation.matches[0].text, "new Service()");

    let named_argument = run_query_with_files(
        &[("php/app.php", PHP_APP)],
        json!({
            "languages": ["php"],
            "match": {
                "kind": "call",
                "callee": { "name": "audit_named" },
                "kwargs": {
                    "code": { "name": "code", "capture": "code" }
                }
            }
        }),
    );
    assert!(
        named_argument.diagnostics.is_empty(),
        "{:?}",
        named_argument.diagnostics
    );
    assert_eq!(named_argument.matches.len(), 1);
    assert_eq!(named_argument.matches[0].text, "audit_named(code: $code)");
    assert_eq!(named_argument.matches[0].captures[0].text, "$code");

    let assignment = run_query_with_files(
        &[("php/app.php", PHP_APP)],
        json!({
            "languages": ["php"],
            "match": {
                "kind": "assignment",
                "left": { "name": "password" },
                "right": { "kind": "string_literal", "capture": "value" }
            }
        }),
    );
    assert!(
        assignment.diagnostics.is_empty(),
        "{:?}",
        assignment.diagnostics
    );
    assert_eq!(assignment.matches.len(), 1);
    assert_eq!(assignment.matches[0].text, r#"$password = "hunter2""#);
    assert_eq!(assignment.matches[0].captures[0].text, r#""hunter2""#);

    let property_assignment = run_query_with_files(
        &[("php/app.php", PHP_APP)],
        json!({
            "languages": ["php"],
            "match": {
                "kind": "assignment",
                "left": { "name": "name" },
                "right": { "text": { "regex": "^\"primary\"$" }, "capture": "value" }
            }
        }),
    );
    assert!(
        property_assignment.diagnostics.is_empty(),
        "{:?}",
        property_assignment.diagnostics
    );
    assert_eq!(property_assignment.matches.len(), 1);
    assert_eq!(property_assignment.matches[0].text, r#"$name = "primary""#);
    assert_eq!(
        property_assignment.matches[0].captures[0].text,
        r#""primary""#
    );

    let const_assignment = run_query_with_files(
        &[("php/app.php", PHP_APP)],
        json!({
            "languages": ["php"],
            "match": {
                "kind": "assignment",
                "left": { "name": "LIMIT" },
                "right": { "kind": "numeric_literal", "capture": "value" }
            }
        }),
    );
    assert!(
        const_assignment.diagnostics.is_empty(),
        "{:?}",
        const_assignment.diagnostics
    );
    assert_eq!(const_assignment.matches.len(), 1);
    assert_eq!(const_assignment.matches[0].text, "LIMIT = -3");
    assert_eq!(const_assignment.matches[0].captures[0].text, "-3");

    let boolean_literal = run_query_with_files(
        &[("php/app.php", PHP_APP)],
        json!({
            "languages": ["php"],
            "match": { "kind": "boolean_literal", "text": { "regex": "^true$" } }
        }),
    );
    assert!(
        boolean_literal.diagnostics.is_empty(),
        "{:?}",
        boolean_literal.diagnostics
    );
    assert_eq!(boolean_literal.matches.len(), 1);
    assert_eq!(boolean_literal.matches[0].text, "true");

    let field_access = run_query_with_files(
        &[("php/app.php", PHP_APP)],
        json!({
            "languages": ["php"],
            "match": {
                "kind": "field_access",
                "object": { "name": "this" },
                "field": { "name": "name" }
            }
        }),
    );
    assert!(
        field_access.diagnostics.is_empty(),
        "{:?}",
        field_access.diagnostics
    );
    assert_eq!(field_access.matches.len(), 1);
    assert_eq!(field_access.matches[0].text, "$this->name");

    let static_field_access = run_query_with_files(
        &[("php/app.php", PHP_APP)],
        json!({
            "languages": ["php"],
            "match": {
                "kind": "field_access",
                "object": { "name": "Service" },
                "field": { "name": "LIMIT" }
            }
        }),
    );
    assert!(
        static_field_access.diagnostics.is_empty(),
        "{:?}",
        static_field_access.diagnostics
    );
    assert_eq!(static_field_access.matches.len(), 1);
    assert_eq!(static_field_access.matches[0].text, "Service::LIMIT");

    let import = run_query_with_files(
        &[("php/app.php", PHP_APP)],
        json!({
            "languages": ["php"],
            "match": { "kind": "import", "module": { "name": "Formatter" } }
        }),
    );
    assert!(import.diagnostics.is_empty(), "{:?}", import.diagnostics);
    assert_eq!(import.matches.len(), 1);
    assert_eq!(import.matches[0].text, "use App\\Support\\Formatter;");

    let full_import = run_query_with_files(
        &[("php/app.php", PHP_APP)],
        json!({
            "languages": ["php"],
            "match": { "kind": "import", "module": { "name": "App\\Support\\Formatter" } }
        }),
    );
    assert!(
        full_import.diagnostics.is_empty(),
        "{:?}",
        full_import.diagnostics
    );
    assert_eq!(full_import.matches.len(), 1);
    assert_eq!(full_import.matches[0].text, "use App\\Support\\Formatter;");

    let grouped_import = run_query_with_files(
        &[("php/app.php", PHP_APP)],
        json!({
            "languages": ["php"],
            "match": { "kind": "import", "module": { "name": "Logger" } }
        }),
    );
    assert!(
        grouped_import.diagnostics.is_empty(),
        "{:?}",
        grouped_import.diagnostics
    );
    assert_eq!(grouped_import.matches.len(), 1);
    assert_eq!(
        grouped_import.matches[0].text,
        "use App\\Support\\{Logger, Writer as WriterAlias};"
    );

    let aliased_import = run_query_with_files(
        &[("php/app.php", PHP_APP)],
        json!({
            "languages": ["php"],
            "match": { "kind": "import", "module": { "name": "WriterAlias" } }
        }),
    );
    assert!(
        aliased_import.diagnostics.is_empty(),
        "{:?}",
        aliased_import.diagnostics
    );
    assert_eq!(aliased_import.matches.len(), 1);
    assert_eq!(
        aliased_import.matches[0].text,
        "use App\\Support\\{Logger, Writer as WriterAlias};"
    );

    let shared_import_prefix = run_query_with_files(
        &[("php/app.php", PHP_APP)],
        json!({
            "languages": ["php"],
            "match": { "kind": "import", "module": { "name": "Support" } }
        }),
    );
    assert!(
        shared_import_prefix.diagnostics.is_empty(),
        "{:?}",
        shared_import_prefix.diagnostics
    );
    assert!(
        shared_import_prefix.matches.is_empty(),
        "unexpected shared-prefix import match: {shared_import_prefix:?}"
    );

    let declarations = run_query_with_files(
        &[("php/app.php", PHP_APP)],
        json!({
            "languages": ["php"],
            "match": { "kind": "declaration", "name": { "regex": "^(Service|__construct|run|audit|audit_named)$" } }
        }),
    );
    assert!(
        declarations.diagnostics.is_empty(),
        "{:?}",
        declarations.diagnostics
    );
    let declaration_rows: Vec<_> = declarations
        .matches
        .iter()
        .map(|m| (m.kind, m.text.as_str()))
        .collect();
    assert_eq!(
        declaration_rows,
        vec![
            ("class", "#[Route('/run')]…"),
            ("constructor", "public function __construct() {}"),
            ("method", "public function run(string $code): string {…"),
            ("function", "function audit(string $code): string {…"),
            ("function", "function audit_named(string $code): string {…"),
        ]
    );

    let decorated_class = run_query_with_files(
        &[("php/app.php", PHP_APP)],
        json!({
            "languages": ["php"],
            "match": {
                "kind": "class",
                "decorators": [{ "name": "Route" }]
            }
        }),
    );
    assert!(
        decorated_class.diagnostics.is_empty(),
        "{:?}",
        decorated_class.diagnostics
    );
    assert_eq!(decorated_class.matches.len(), 1);
    assert_eq!(decorated_class.matches[0].text, "#[Route('/run')]…");

    let lambda = run_query_with_files(
        &[("php/app.php", PHP_APP)],
        json!({
            "languages": ["php"],
            "match": { "kind": "lambda", "has": { "kind": "return" } }
        }),
    );
    assert!(lambda.diagnostics.is_empty(), "{:?}", lambda.diagnostics);
    assert_eq!(lambda.matches.len(), 1);
    assert_eq!(lambda.matches[0].text, "function ($value) {…");

    let trait_use_is_not_import = run_query_with_files(
        &[("php/app.php", PHP_APP)],
        json!({
            "languages": ["php"],
            "match": { "kind": "import", "module": { "name": "Loggable" } }
        }),
    );
    assert!(
        trait_use_is_not_import.diagnostics.is_empty(),
        "{:?}",
        trait_use_is_not_import.diagnostics
    );
    assert!(
        trait_use_is_not_import.matches.is_empty(),
        "unexpected trait-use import match: {trait_use_is_not_import:?}"
    );
}

#[test]
fn scala_structural_adapter_matches_normalized_shapes() {
    const SCALA_APP: &str = r#"
package app

import scala.util.Try
import scala.collection.mutable.{ListBuffer, Map as MutableMap}

@deprecated("use Service2", "1.0")
class Service(var name: String) {
    def run(code: String): String = {
        audit(code)
        val password = "hunter2"
        val flag = true
        val callback = (value: String) => {
            return value
        }
        val parsed = parse[String](code)
        this.name = "updated"
        code.toString
    }
}

object App {
    def audit(code: String): String = code
    def auditNamed(code: String): String = code
    def parse[T](value: String): String = value
    val limit = -3
    val service = new Service("primary")
    service.run("input")
    auditNamed(code = "named")
    ListBuffer(1).foreach { value => audit(value.toString) }
    Try(audit("again"))
}
"#;

    let audit = run_query_with_files(
        &[("scala/App.scala", SCALA_APP)],
        json!({
            "languages": ["scala"],
            "match": {
                "kind": "call",
                "callee": { "name": "audit" },
                "args": [{ "name": "code", "capture": "code" }]
            }
        }),
    );
    assert!(audit.diagnostics.is_empty(), "{:?}", audit.diagnostics);
    assert_eq!(audit.matches.len(), 1);
    assert_eq!(audit.matches[0].text, "audit(code)");
    assert_eq!(audit.matches[0].captures[0].text, "code");

    let method_call = run_query_with_files(
        &[("scala/App.scala", SCALA_APP)],
        json!({
            "languages": ["scala"],
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": { "name": "service" }
            }
        }),
    );
    assert!(
        method_call.diagnostics.is_empty(),
        "{:?}",
        method_call.diagnostics
    );
    assert_eq!(method_call.matches.len(), 1);
    assert_eq!(method_call.matches[0].text, r#"service.run("input")"#);

    let generic_call = run_query_with_files(
        &[("scala/App.scala", SCALA_APP)],
        json!({
            "languages": ["scala"],
            "match": {
                "kind": "call",
                "callee": { "name": "parse" },
                "args": [{ "name": "code" }]
            }
        }),
    );
    assert!(
        generic_call.diagnostics.is_empty(),
        "{:?}",
        generic_call.diagnostics
    );
    assert_eq!(generic_call.matches.len(), 1);
    assert_eq!(generic_call.matches[0].text, "parse[String](code)");

    let block_argument = run_query_with_files(
        &[("scala/App.scala", SCALA_APP)],
        json!({
            "languages": ["scala"],
            "match": {
                "kind": "call",
                "callee": { "name": "foreach" },
                "args": [{ "has": { "kind": "call", "callee": { "name": "audit" } } }]
            }
        }),
    );
    assert!(
        block_argument.diagnostics.is_empty(),
        "{:?}",
        block_argument.diagnostics
    );
    assert_eq!(block_argument.matches.len(), 1);
    assert_eq!(
        block_argument.matches[0].text,
        "ListBuffer(1).foreach { value => audit(value.toString) }"
    );

    let named_argument = run_query_with_files(
        &[("scala/App.scala", SCALA_APP)],
        json!({
            "languages": ["scala"],
            "match": {
                "kind": "call",
                "callee": { "name": "auditNamed" },
                "kwargs": {
                    "code": { "kind": "string_literal", "capture": "value" }
                }
            }
        }),
    );
    assert!(
        named_argument.diagnostics.is_empty(),
        "{:?}",
        named_argument.diagnostics
    );
    assert_eq!(named_argument.matches.len(), 1);
    assert_eq!(
        named_argument.matches[0].text,
        r#"auditNamed(code = "named")"#
    );
    assert_eq!(named_argument.matches[0].captures[0].text, r#""named""#);

    let named_argument_is_not_assignment = run_query_with_files(
        &[("scala/App.scala", SCALA_APP)],
        json!({
            "languages": ["scala"],
            "match": {
                "kind": "assignment",
                "left": { "name": "code" },
                "right": { "kind": "string_literal" }
            }
        }),
    );
    assert!(
        named_argument_is_not_assignment.diagnostics.is_empty(),
        "{:?}",
        named_argument_is_not_assignment.diagnostics
    );
    assert!(
        named_argument_is_not_assignment.matches.is_empty(),
        "unexpected named-argument assignment match: {named_argument_is_not_assignment:?}"
    );

    let assignment = run_query_with_files(
        &[("scala/App.scala", SCALA_APP)],
        json!({
            "languages": ["scala"],
            "match": {
                "kind": "assignment",
                "left": { "name": "password" },
                "right": { "kind": "string_literal", "capture": "value" }
            }
        }),
    );
    assert!(
        assignment.diagnostics.is_empty(),
        "{:?}",
        assignment.diagnostics
    );
    assert_eq!(assignment.matches.len(), 1);
    assert_eq!(assignment.matches[0].text, r#"val password = "hunter2""#);
    assert_eq!(assignment.matches[0].captures[0].text, r#""hunter2""#);

    let signed_numeric = run_query_with_files(
        &[("scala/App.scala", SCALA_APP)],
        json!({
            "languages": ["scala"],
            "match": {
                "kind": "assignment",
                "left": { "name": "limit" },
                "right": { "kind": "numeric_literal", "capture": "value" }
            }
        }),
    );
    assert!(
        signed_numeric.diagnostics.is_empty(),
        "{:?}",
        signed_numeric.diagnostics
    );
    assert_eq!(signed_numeric.matches.len(), 1);
    assert_eq!(signed_numeric.matches[0].text, "val limit = -3");
    assert_eq!(signed_numeric.matches[0].captures[0].text, "-3");

    let boolean_literal = run_query_with_files(
        &[("scala/App.scala", SCALA_APP)],
        json!({
            "languages": ["scala"],
            "match": { "kind": "boolean_literal", "text": { "regex": "^true$" } }
        }),
    );
    assert!(
        boolean_literal.diagnostics.is_empty(),
        "{:?}",
        boolean_literal.diagnostics
    );
    assert_eq!(boolean_literal.matches.len(), 1);
    assert_eq!(boolean_literal.matches[0].text, "true");

    let field_access = run_query_with_files(
        &[("scala/App.scala", SCALA_APP)],
        json!({
            "languages": ["scala"],
            "match": {
                "kind": "field_access",
                "object": { "name": "this" },
                "field": { "name": "name" }
            }
        }),
    );
    assert!(
        field_access.diagnostics.is_empty(),
        "{:?}",
        field_access.diagnostics
    );
    assert_eq!(field_access.matches.len(), 1);
    assert_eq!(field_access.matches[0].text, "this.name");

    let import = run_query_with_files(
        &[("scala/App.scala", SCALA_APP)],
        json!({
            "languages": ["scala"],
            "match": { "kind": "import", "module": { "name": "Try" } }
        }),
    );
    assert!(import.diagnostics.is_empty(), "{:?}", import.diagnostics);
    assert_eq!(import.matches.len(), 1);
    assert_eq!(import.matches[0].text, "import scala.util.Try");

    let full_import = run_query_with_files(
        &[("scala/App.scala", SCALA_APP)],
        json!({
            "languages": ["scala"],
            "match": { "kind": "import", "module": { "name": "scala.util.Try" } }
        }),
    );
    assert!(
        full_import.diagnostics.is_empty(),
        "{:?}",
        full_import.diagnostics
    );
    assert_eq!(full_import.matches.len(), 1);
    assert_eq!(full_import.matches[0].text, "import scala.util.Try");

    let grouped_import = run_query_with_files(
        &[("scala/App.scala", SCALA_APP)],
        json!({
            "languages": ["scala"],
            "match": { "kind": "import", "module": { "name": "ListBuffer" } }
        }),
    );
    assert!(
        grouped_import.diagnostics.is_empty(),
        "{:?}",
        grouped_import.diagnostics
    );
    assert_eq!(grouped_import.matches.len(), 1);
    assert_eq!(
        grouped_import.matches[0].text,
        "import scala.collection.mutable.{ListBuffer, Map as MutableMap}"
    );

    let aliased_import = run_query_with_files(
        &[("scala/App.scala", SCALA_APP)],
        json!({
            "languages": ["scala"],
            "match": { "kind": "import", "module": { "name": "MutableMap" } }
        }),
    );
    assert!(
        aliased_import.diagnostics.is_empty(),
        "{:?}",
        aliased_import.diagnostics
    );
    assert_eq!(aliased_import.matches.len(), 1);
    assert_eq!(
        aliased_import.matches[0].text,
        "import scala.collection.mutable.{ListBuffer, Map as MutableMap}"
    );

    let shared_import_prefix = run_query_with_files(
        &[("scala/App.scala", SCALA_APP)],
        json!({
            "languages": ["scala"],
            "match": { "kind": "import", "module": { "name": "collection" } }
        }),
    );
    assert!(
        shared_import_prefix.diagnostics.is_empty(),
        "{:?}",
        shared_import_prefix.diagnostics
    );
    assert!(
        shared_import_prefix.matches.is_empty(),
        "unexpected shared-prefix import match: {shared_import_prefix:?}"
    );

    let declarations = run_query_with_files(
        &[("scala/App.scala", SCALA_APP)],
        json!({
            "languages": ["scala"],
            "match": { "kind": "declaration", "name": { "regex": "^(Service|run|App|audit|parse)$" } }
        }),
    );
    assert!(
        declarations.diagnostics.is_empty(),
        "{:?}",
        declarations.diagnostics
    );
    let declaration_rows: Vec<_> = declarations
        .matches
        .iter()
        .map(|m| (m.kind, m.text.as_str()))
        .collect();
    assert_eq!(
        declaration_rows,
        vec![
            ("class", "@deprecated(\"use Service2\", \"1.0\")…"),
            ("method", "def run(code: String): String = {…"),
            ("class", "object App {…"),
            ("method", "def audit(code: String): String = code"),
            ("method", "def parse[T](value: String): String = value"),
        ]
    );

    let methods = run_query_with_files(
        &[("scala/App.scala", SCALA_APP)],
        json!({
            "languages": ["scala"],
            "match": { "kind": "method", "name": { "regex": "^(run|audit)$" } }
        }),
    );
    assert!(methods.diagnostics.is_empty(), "{:?}", methods.diagnostics);
    let method_rows: Vec<_> = methods.matches.iter().map(|m| m.text.as_str()).collect();
    assert_eq!(
        method_rows,
        vec![
            "def run(code: String): String = {…",
            "def audit(code: String): String = code",
        ]
    );

    let decorated_class = run_query_with_files(
        &[("scala/App.scala", SCALA_APP)],
        json!({
            "languages": ["scala"],
            "match": {
                "kind": "class",
                "decorators": [{ "name": "deprecated" }]
            }
        }),
    );
    assert!(
        decorated_class.diagnostics.is_empty(),
        "{:?}",
        decorated_class.diagnostics
    );
    assert_eq!(decorated_class.matches.len(), 1);
    assert_eq!(
        decorated_class.matches[0].text,
        "@deprecated(\"use Service2\", \"1.0\")…"
    );

    let lambda = run_query_with_files(
        &[("scala/App.scala", SCALA_APP)],
        json!({
            "languages": ["scala"],
            "match": { "kind": "lambda", "has": { "kind": "return" } }
        }),
    );
    assert!(lambda.diagnostics.is_empty(), "{:?}", lambda.diagnostics);
    assert_eq!(lambda.matches.len(), 1);
    assert_eq!(lambda.matches[0].text, "(value: String) => {…");
}

#[test]
fn csharp_structural_adapter_matches_normalized_shapes() {
    const CSHARP_APP: &str = r#"
using System;
using App.Support;
using WriterAlias = App.Support.Writer;

namespace App;

[Route("/run")]
class Service {
    public string Name { get; set; } = "primary";
    private string empty;
    public const int Limit = -3;

    public Service() {}

    public string Run(string code) {
        audit(code);
        AuditNamed(code: code);
        this.Name = "updated";
        var formatted = Formatter.Format(code);
        Func<string, string> callback = value => {
            return value;
        };
        return code;
    }

    public static string audit(string code) {
        string password = "hunter2";
        bool flag = true;
        return code;
    }

    public static string AuditNamed(string code) => code;
    public static string Parse<T>(string value) => value;
}

class AppEntry {
    void Main() {
        var service = new Service();
        service.Run("input");
        service?.Run("optional");
        var optionalName = service?.Name;
        var parsed = Service.Parse<string>("value");
    }
}
"#;

    let audit = run_query_with_files(
        &[("csharp/App.cs", CSHARP_APP)],
        json!({
            "languages": ["csharp"],
            "match": {
                "kind": "call",
                "callee": { "name": "audit" },
                "args": [{ "name": "code", "capture": "code" }]
            }
        }),
    );
    assert!(audit.diagnostics.is_empty(), "{:?}", audit.diagnostics);
    assert_eq!(audit.matches.len(), 1);
    assert_eq!(audit.matches[0].text, "audit(code)");
    assert_eq!(audit.matches[0].captures[0].text, "code");

    let method_call = run_query_with_files(
        &[("csharp/App.cs", CSHARP_APP)],
        json!({
            "languages": ["csharp"],
            "match": {
                "kind": "call",
                "callee": { "name": "Run" },
                "receiver": { "name": "service" },
                "args": [{ "text": { "regex": "^\"input\"$" } }]
            }
        }),
    );
    assert!(
        method_call.diagnostics.is_empty(),
        "{:?}",
        method_call.diagnostics
    );
    assert_eq!(method_call.matches.len(), 1);
    assert_eq!(method_call.matches[0].text, r#"service.Run("input")"#);

    let conditional_method_call = run_query_with_files(
        &[("csharp/App.cs", CSHARP_APP)],
        json!({
            "languages": ["csharp"],
            "match": {
                "kind": "call",
                "callee": { "name": "Run" },
                "receiver": { "name": "service" },
                "args": [{ "text": { "regex": "^\"optional\"$" } }]
            }
        }),
    );
    assert!(
        conditional_method_call.diagnostics.is_empty(),
        "{:?}",
        conditional_method_call.diagnostics
    );
    assert_eq!(conditional_method_call.matches.len(), 1);
    assert_eq!(
        conditional_method_call.matches[0].text,
        r#"service?.Run("optional")"#
    );

    let static_generic_call = run_query_with_files(
        &[("csharp/App.cs", CSHARP_APP)],
        json!({
            "languages": ["csharp"],
            "match": {
                "kind": "call",
                "callee": { "name": "Parse" },
                "receiver": { "name": "Service" }
            }
        }),
    );
    assert!(
        static_generic_call.diagnostics.is_empty(),
        "{:?}",
        static_generic_call.diagnostics
    );
    assert_eq!(static_generic_call.matches.len(), 1);
    assert_eq!(
        static_generic_call.matches[0].text,
        r#"Service.Parse<string>("value")"#
    );

    let object_creation = run_query_with_files(
        &[("csharp/App.cs", CSHARP_APP)],
        json!({
            "languages": ["csharp"],
            "match": { "kind": "call", "callee": { "name": "Service" } }
        }),
    );
    assert!(
        object_creation.diagnostics.is_empty(),
        "{:?}",
        object_creation.diagnostics
    );
    assert_eq!(object_creation.matches.len(), 1);
    assert_eq!(object_creation.matches[0].text, "new Service()");

    let named_argument = run_query_with_files(
        &[("csharp/App.cs", CSHARP_APP)],
        json!({
            "languages": ["csharp"],
            "match": {
                "kind": "call",
                "callee": { "name": "AuditNamed" },
                "kwargs": {
                    "code": { "name": "code", "capture": "code" }
                }
            }
        }),
    );
    assert!(
        named_argument.diagnostics.is_empty(),
        "{:?}",
        named_argument.diagnostics
    );
    assert_eq!(named_argument.matches.len(), 1);
    assert_eq!(named_argument.matches[0].text, "AuditNamed(code: code)");
    assert_eq!(named_argument.matches[0].captures[0].text, "code");

    let assignment = run_query_with_files(
        &[("csharp/App.cs", CSHARP_APP)],
        json!({
            "languages": ["csharp"],
            "match": {
                "kind": "assignment",
                "left": { "name": "password" },
                "right": { "kind": "string_literal", "capture": "value" }
            }
        }),
    );
    assert!(
        assignment.diagnostics.is_empty(),
        "{:?}",
        assignment.diagnostics
    );
    assert_eq!(assignment.matches.len(), 1);
    assert_eq!(assignment.matches[0].text, r#"password = "hunter2""#);
    assert_eq!(assignment.matches[0].captures[0].text, r#""hunter2""#);

    let signed_numeric = run_query_with_files(
        &[("csharp/App.cs", CSHARP_APP)],
        json!({
            "languages": ["csharp"],
            "match": {
                "kind": "assignment",
                "left": { "name": "Limit" },
                "right": { "kind": "numeric_literal", "capture": "value" }
            }
        }),
    );
    assert!(
        signed_numeric.diagnostics.is_empty(),
        "{:?}",
        signed_numeric.diagnostics
    );
    assert_eq!(signed_numeric.matches.len(), 1);
    assert_eq!(signed_numeric.matches[0].text, "Limit = -3");
    assert_eq!(signed_numeric.matches[0].captures[0].text, "-3");

    let uninitialized_field = run_query_with_files(
        &[("csharp/App.cs", CSHARP_APP)],
        json!({
            "languages": ["csharp"],
            "match": { "kind": "assignment", "left": { "name": "empty" } }
        }),
    );
    assert!(
        uninitialized_field.diagnostics.is_empty(),
        "{:?}",
        uninitialized_field.diagnostics
    );
    assert!(
        uninitialized_field.matches.is_empty(),
        "unexpected uninitialized field assignment match: {uninitialized_field:?}"
    );

    let boolean_literal = run_query_with_files(
        &[("csharp/App.cs", CSHARP_APP)],
        json!({
            "languages": ["csharp"],
            "match": { "kind": "boolean_literal", "text": { "regex": "^true$" } }
        }),
    );
    assert!(
        boolean_literal.diagnostics.is_empty(),
        "{:?}",
        boolean_literal.diagnostics
    );
    assert_eq!(boolean_literal.matches.len(), 1);
    assert_eq!(boolean_literal.matches[0].text, "true");

    let field_access = run_query_with_files(
        &[("csharp/App.cs", CSHARP_APP)],
        json!({
            "languages": ["csharp"],
            "match": {
                "kind": "field_access",
                "object": { "text": { "regex": "^this$" } },
                "field": { "name": "Name" }
            }
        }),
    );
    assert!(
        field_access.diagnostics.is_empty(),
        "{:?}",
        field_access.diagnostics
    );
    assert_eq!(field_access.matches.len(), 1);
    assert_eq!(field_access.matches[0].text, "this.Name");

    let conditional_field_access = run_query_with_files(
        &[("csharp/App.cs", CSHARP_APP)],
        json!({
            "languages": ["csharp"],
            "match": {
                "kind": "field_access",
                "object": { "name": "service" },
                "field": { "name": "Name" }
            }
        }),
    );
    assert!(
        conditional_field_access.diagnostics.is_empty(),
        "{:?}",
        conditional_field_access.diagnostics
    );
    assert_eq!(conditional_field_access.matches.len(), 1);
    assert_eq!(conditional_field_access.matches[0].text, "service?.Name");

    let system_import = run_query_with_files(
        &[("csharp/App.cs", CSHARP_APP)],
        json!({
            "languages": ["csharp"],
            "match": { "kind": "import", "module": { "name": "System" } }
        }),
    );
    assert!(
        system_import.diagnostics.is_empty(),
        "{:?}",
        system_import.diagnostics
    );
    assert_eq!(system_import.matches.len(), 1);
    assert_eq!(system_import.matches[0].text, "using System;");

    let import = run_query_with_files(
        &[("csharp/App.cs", CSHARP_APP)],
        json!({
            "languages": ["csharp"],
            "match": { "kind": "import", "module": { "name": "Support" } }
        }),
    );
    assert!(import.diagnostics.is_empty(), "{:?}", import.diagnostics);
    assert_eq!(import.matches.len(), 1);
    assert_eq!(import.matches[0].text, "using App.Support;");

    let full_import = run_query_with_files(
        &[("csharp/App.cs", CSHARP_APP)],
        json!({
            "languages": ["csharp"],
            "match": { "kind": "import", "module": { "name": "App.Support" } }
        }),
    );
    assert!(
        full_import.diagnostics.is_empty(),
        "{:?}",
        full_import.diagnostics
    );
    assert_eq!(full_import.matches.len(), 1);
    assert_eq!(full_import.matches[0].text, "using App.Support;");

    let aliased_import = run_query_with_files(
        &[("csharp/App.cs", CSHARP_APP)],
        json!({
            "languages": ["csharp"],
            "match": { "kind": "import", "module": { "name": "WriterAlias" } }
        }),
    );
    assert!(
        aliased_import.diagnostics.is_empty(),
        "{:?}",
        aliased_import.diagnostics
    );
    assert_eq!(aliased_import.matches.len(), 1);
    assert_eq!(
        aliased_import.matches[0].text,
        "using WriterAlias = App.Support.Writer;"
    );

    let alias_target_terminal = run_query_with_files(
        &[("csharp/App.cs", CSHARP_APP)],
        json!({
            "languages": ["csharp"],
            "match": { "kind": "import", "module": { "name": "Writer" } }
        }),
    );
    assert!(
        alias_target_terminal.diagnostics.is_empty(),
        "{:?}",
        alias_target_terminal.diagnostics
    );
    assert!(
        alias_target_terminal.matches.is_empty(),
        "unexpected aliased target terminal import match: {alias_target_terminal:?}"
    );

    let shared_import_prefix = run_query_with_files(
        &[("csharp/App.cs", CSHARP_APP)],
        json!({
            "languages": ["csharp"],
            "match": { "kind": "import", "module": { "name": "App" } }
        }),
    );
    assert!(
        shared_import_prefix.diagnostics.is_empty(),
        "{:?}",
        shared_import_prefix.diagnostics
    );
    assert!(
        shared_import_prefix.matches.is_empty(),
        "unexpected shared-prefix import match: {shared_import_prefix:?}"
    );

    let declarations = run_query_with_files(
        &[("csharp/App.cs", CSHARP_APP)],
        json!({
            "languages": ["csharp"],
            "match": { "kind": "declaration", "name": { "regex": "^(Service|Run|audit|Name)$" } }
        }),
    );
    assert!(
        declarations.diagnostics.is_empty(),
        "{:?}",
        declarations.diagnostics
    );
    let declaration_rows: Vec<_> = declarations
        .matches
        .iter()
        .map(|m| (m.kind, m.text.as_str()))
        .collect();
    assert_eq!(
        declaration_rows,
        vec![
            ("class", "[Route(\"/run\")]…"),
            (
                "declaration",
                "public string Name { get; set; } = \"primary\";"
            ),
            ("constructor", "public Service() {}"),
            ("method", "public string Run(string code) {…"),
            ("method", "public static string audit(string code) {…"),
        ]
    );

    let decorated_class = run_query_with_files(
        &[("csharp/App.cs", CSHARP_APP)],
        json!({
            "languages": ["csharp"],
            "match": {
                "kind": "class",
                "decorators": [{ "name": "Route" }]
            }
        }),
    );
    assert!(
        decorated_class.diagnostics.is_empty(),
        "{:?}",
        decorated_class.diagnostics
    );
    assert_eq!(decorated_class.matches.len(), 1);
    assert_eq!(decorated_class.matches[0].text, "[Route(\"/run\")]…");

    let lambda = run_query_with_files(
        &[("csharp/App.cs", CSHARP_APP)],
        json!({
            "languages": ["csharp"],
            "match": { "kind": "lambda", "has": { "kind": "return" } }
        }),
    );
    assert!(lambda.diagnostics.is_empty(), "{:?}", lambda.diagnostics);
    assert_eq!(lambda.matches.len(), 1);
    assert_eq!(lambda.matches[0].text, "value => {…");
}

#[test]
fn ruby_structural_adapter_matches_normalized_shapes() {
    const RUBY_APP: &str = r#"
require "app/support"
require "plugins/#{tenant}"

module App
  class Service
    LIMIT = -3

    def run(code)
      audit(code)
      audit_named(code: code)
      password = "hunter2"
      flag = true
      callback = ->(value) {
        return value
      }
      klass = App::Service
      code.to_s
    end

    def self.audit(code)
      code
    end
  end
end

class App::External
end

def helper
  service = App::Service.new("primary")
  service.run("input")
  loader.require("plugin")
end
"#;

    let audit = run_query_with_files(
        &[("ruby/app.rb", RUBY_APP)],
        json!({
            "languages": ["ruby"],
            "match": {
                "kind": "call",
                "callee": { "name": "audit" },
                "args": [{ "name": "code", "capture": "code" }]
            }
        }),
    );
    assert!(audit.diagnostics.is_empty(), "{:?}", audit.diagnostics);
    assert_eq!(audit.matches.len(), 1);
    assert_eq!(audit.matches[0].text, "audit(code)");
    assert_eq!(audit.matches[0].captures[0].text, "code");

    let method_call = run_query_with_files(
        &[("ruby/app.rb", RUBY_APP)],
        json!({
            "languages": ["ruby"],
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": { "name": "service" }
            }
        }),
    );
    assert!(
        method_call.diagnostics.is_empty(),
        "{:?}",
        method_call.diagnostics
    );
    assert_eq!(method_call.matches.len(), 1);
    assert_eq!(method_call.matches[0].text, r#"service.run("input")"#);

    let named_argument = run_query_with_files(
        &[("ruby/app.rb", RUBY_APP)],
        json!({
            "languages": ["ruby"],
            "match": {
                "kind": "call",
                "callee": { "name": "audit_named" },
                "kwargs": {
                    "code": { "name": "code", "capture": "code" }
                }
            }
        }),
    );
    assert!(
        named_argument.diagnostics.is_empty(),
        "{:?}",
        named_argument.diagnostics
    );
    assert_eq!(named_argument.matches.len(), 1);
    assert_eq!(named_argument.matches[0].text, "audit_named(code: code)");
    assert_eq!(named_argument.matches[0].captures[0].text, "code");

    let assignment = run_query_with_files(
        &[("ruby/app.rb", RUBY_APP)],
        json!({
            "languages": ["ruby"],
            "match": {
                "kind": "assignment",
                "left": { "name": "password" },
                "right": { "kind": "string_literal", "capture": "value" }
            }
        }),
    );
    assert!(
        assignment.diagnostics.is_empty(),
        "{:?}",
        assignment.diagnostics
    );
    assert_eq!(assignment.matches.len(), 1);
    assert_eq!(assignment.matches[0].text, r#"password = "hunter2""#);
    assert_eq!(assignment.matches[0].captures[0].text, r#""hunter2""#);

    let signed_numeric = run_query_with_files(
        &[("ruby/app.rb", RUBY_APP)],
        json!({
            "languages": ["ruby"],
            "match": {
                "kind": "assignment",
                "left": { "name": "LIMIT" },
                "right": { "kind": "numeric_literal", "capture": "value" }
            }
        }),
    );
    assert!(
        signed_numeric.diagnostics.is_empty(),
        "{:?}",
        signed_numeric.diagnostics
    );
    assert_eq!(signed_numeric.matches.len(), 1);
    assert_eq!(signed_numeric.matches[0].text, "LIMIT = -3");
    assert_eq!(signed_numeric.matches[0].captures[0].text, "-3");

    let boolean_literal = run_query_with_files(
        &[("ruby/app.rb", RUBY_APP)],
        json!({
            "languages": ["ruby"],
            "match": { "kind": "boolean_literal", "text": { "regex": "^true$" } }
        }),
    );
    assert!(
        boolean_literal.diagnostics.is_empty(),
        "{:?}",
        boolean_literal.diagnostics
    );
    assert_eq!(boolean_literal.matches.len(), 1);
    assert_eq!(boolean_literal.matches[0].text, "true");

    let field_access = run_query_with_files(
        &[("ruby/app.rb", RUBY_APP)],
        json!({
            "languages": ["ruby"],
            "match": {
                "kind": "field_access",
                "object": { "name": "App" },
                "field": { "name": "Service" }
            }
        }),
    );
    assert!(
        field_access.diagnostics.is_empty(),
        "{:?}",
        field_access.diagnostics
    );
    assert_eq!(field_access.matches.len(), 2);
    assert!(
        field_access
            .matches
            .iter()
            .all(|m| m.text == "App::Service")
    );

    let import = run_query_with_files(
        &[("ruby/app.rb", RUBY_APP)],
        json!({
            "languages": ["ruby"],
            "match": { "kind": "import", "module": { "name": "app/support" } }
        }),
    );
    assert!(import.diagnostics.is_empty(), "{:?}", import.diagnostics);
    assert_eq!(import.matches.len(), 1);
    assert_eq!(import.matches[0].text, r#"require "app/support""#);

    let dynamic_import_module = run_query_with_files(
        &[("ruby/app.rb", RUBY_APP)],
        json!({
            "languages": ["ruby"],
            "match": { "kind": "import", "module": { "name": "plugins/" } }
        }),
    );
    assert!(
        dynamic_import_module.diagnostics.is_empty(),
        "{:?}",
        dynamic_import_module.diagnostics
    );
    assert!(
        dynamic_import_module.matches.is_empty(),
        "dynamic require module names should not be exposed as precise module roles: {dynamic_import_module:?}"
    );

    let receiver_require_call = run_query_with_files(
        &[("ruby/app.rb", RUBY_APP)],
        json!({
            "languages": ["ruby"],
            "match": {
                "kind": "call",
                "callee": { "name": "require" },
                "receiver": { "name": "loader" }
            }
        }),
    );
    assert!(
        receiver_require_call.diagnostics.is_empty(),
        "{:?}",
        receiver_require_call.diagnostics
    );
    assert_eq!(receiver_require_call.matches.len(), 1);
    assert_eq!(
        receiver_require_call.matches[0].text,
        r#"loader.require("plugin")"#
    );

    let receiver_require_is_not_import = run_query_with_files(
        &[("ruby/app.rb", RUBY_APP)],
        json!({
            "languages": ["ruby"],
            "match": { "kind": "import", "module": { "name": "plugin" } }
        }),
    );
    assert!(
        receiver_require_is_not_import.diagnostics.is_empty(),
        "{:?}",
        receiver_require_is_not_import.diagnostics
    );
    assert!(
        receiver_require_is_not_import.matches.is_empty(),
        "receiver require calls should not be classified as imports: {receiver_require_is_not_import:?}"
    );

    let qualified_class = run_query_with_files(
        &[("ruby/app.rb", RUBY_APP)],
        json!({
            "languages": ["ruby"],
            "match": { "kind": "class", "name": "External" }
        }),
    );
    assert!(
        qualified_class.diagnostics.is_empty(),
        "{:?}",
        qualified_class.diagnostics
    );
    assert_eq!(qualified_class.matches.len(), 1);
    assert_eq!(qualified_class.matches[0].text, "class App::External…");

    let declarations = run_query_with_files(
        &[("ruby/app.rb", RUBY_APP)],
        json!({
            "languages": ["ruby"],
            "match": { "kind": "declaration", "name": { "regex": "^(App|Service|run|audit|helper)$" } }
        }),
    );
    assert!(
        declarations.diagnostics.is_empty(),
        "{:?}",
        declarations.diagnostics
    );
    let declaration_rows: Vec<_> = declarations
        .matches
        .iter()
        .map(|m| (m.kind, m.text.as_str()))
        .collect();
    assert_eq!(
        declaration_rows,
        vec![
            ("class", "module App…"),
            ("class", "class Service…"),
            ("method", "def run(code)…"),
            ("method", "def self.audit(code)…"),
            ("function", "def helper…"),
        ]
    );

    let lambda = run_query_with_files(
        &[("ruby/app.rb", RUBY_APP)],
        json!({
            "languages": ["ruby"],
            "match": { "kind": "lambda", "has": { "kind": "return" } }
        }),
    );
    assert!(lambda.diagnostics.is_empty(), "{:?}", lambda.diagnostics);
    assert_eq!(lambda.matches.len(), 1);
    assert_eq!(lambda.matches[0].text, "->(value) {…");

    let unsupported_decorator = run_query_with_files(
        &[("ruby/app.rb", RUBY_APP)],
        json!({
            "languages": ["ruby"],
            "match": {
                "kind": "class",
                "decorators": [{ "name": "Route" }]
            }
        }),
    );
    assert!(
        unsupported_decorator
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.language == "ruby"
                && diagnostic.message.contains("decorators")),
        "expected ruby decorator diagnostic: {:?}",
        unsupported_decorator.diagnostics
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
