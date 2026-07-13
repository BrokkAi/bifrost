mod common;

use brokk_bifrost::analyzer::structural::{
    CodeQuery, CodeQueryExecutionLimits, CodeQueryResult, execute, execute_with_limits,
};
use brokk_bifrost::{AnalyzerConfig, WorkspaceAnalyzer};
use common::InlineTestProject;
use serde_json::{Value, json};

fn run(files: &[(&str, &str)], query: Value) -> CodeQueryResult {
    let mut project = InlineTestProject::new();
    for (path, source) in files {
        project = project.file(*path, *source);
    }
    let project = project.build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&query).expect("query should parse");
    execute(workspace.analyzer(), &query)
}

fn serialized(result: &CodeQueryResult) -> Value {
    serde_json::to_value(result).expect("query result should serialize")
}

#[test]
fn enclosing_decl_is_inclusive_and_excludes_file_scope() {
    let files = [(
        "app.py",
        "class Outer:\n    def inner(self):\n        audit()\n\ndef audit():\n    pass\n\naudit()\n",
    )];
    let nested = run(
        &files,
        json!({
            "match": { "kind": "call", "callee": { "name": "audit" } },
            "inside": { "kind": "method", "name": "inner" },
            "steps": [{ "op": "enclosing_decl" }]
        }),
    );
    let nested = serialized(&nested);
    assert_eq!(nested["results"][0]["result_type"], "declaration");
    assert_eq!(nested["results"][0]["kind"], "function");
    assert!(
        nested["results"][0]["fq_name"]
            .as_str()
            .is_some_and(|name| name.ends_with("inner")),
        "{nested}"
    );

    let declaration = run(
        &files,
        json!({
            "match": { "kind": "method", "name": "inner" },
            "steps": [{ "op": "enclosing_decl" }]
        }),
    );
    let declaration = serialized(&declaration);
    assert!(
        declaration["results"][0]["fq_name"]
            .as_str()
            .is_some_and(|name| name.ends_with("inner")),
        "{declaration}"
    );

    let top_level = run(
        &files,
        json!({
            "match": { "kind": "call", "callee": { "name": "audit" } },
            "not_inside": { "kind": "callable" },
            "steps": [{ "op": "enclosing_decl" }]
        }),
    );
    let top_level = serialized(&top_level);
    assert_eq!(
        top_level["results"][0]["result_type"], "declaration",
        "{top_level}"
    );
    assert_ne!(top_level["results"][0]["kind"], "file scope");
}

#[test]
fn full_results_include_stable_terminal_and_provenance_identities() {
    let result = run(
        &[(
            "app.py",
            "class Outer:\n    def inner(self):\n        audit()\n",
        )],
        json!({
            "match": { "kind": "call", "callee": { "name": "audit" } },
            "steps": [{ "op": "enclosing_decl" }],
            "result_detail": "full"
        }),
    );
    let value = serialized(&result);
    let terminal = &value["results"][0];
    assert_eq!(terminal["result_type"], "declaration", "{value}");
    assert!(terminal["id"].is_string(), "{value}");
    assert!(terminal["node_range"].is_object(), "{value}");

    let trace = &terminal["provenance"][0];
    assert_eq!(trace["seed"]["result_type"], "structural_match", "{value}");
    assert!(trace["seed"]["id"].is_string(), "{value}");
    assert!(trace["seed"]["node_range"].is_object(), "{value}");
    assert_eq!(trace["steps"][0]["op"], "enclosing_decl", "{value}");
    assert_eq!(trace["steps"][0]["result"]["id"], terminal["id"], "{value}");
}

#[test]
fn file_of_deduplicates_and_caps_deterministic_provenance() {
    let calls = (0..17)
        .map(|_| "    audit()")
        .collect::<Vec<_>>()
        .join("\n");
    let source = format!("def run():\n{calls}\n");
    let result = run(
        &[("app.py", &source)],
        json!({
            "match": { "kind": "call", "callee": { "name": "audit" } },
            "steps": [{ "op": "file_of" }]
        }),
    );
    let value = serialized(&result);
    assert_eq!(value["results"].as_array().unwrap().len(), 1, "{value}");
    assert_eq!(value["results"][0]["result_type"], "file");
    assert_eq!(value["results"][0]["path"], "app.py");
    assert_eq!(
        value["results"][0]["provenance"].as_array().unwrap().len(),
        16
    );
    assert_eq!(value["results"][0]["provenance_truncated"], true);
}

#[test]
fn ruby_importers_are_direct_and_repeat_for_multiple_hops() {
    let files = [
        ("a.rb", "require_relative 'b'\ndef from_a; end\n"),
        ("b.rb", "require_relative 'c'\ndef from_b; end\n"),
        ("c.rb", "def target; end\n"),
    ];
    let direct = run(
        &files,
        json!({
            "match": { "kind": "function", "name": "target" },
            "steps": [{ "op": "file_of" }, { "op": "importers_of" }]
        }),
    );
    let direct = serialized(&direct);
    assert_eq!(direct["results"].as_array().unwrap().len(), 1, "{direct}");
    assert_eq!(direct["results"][0]["path"], "b.rb");

    let repeated = run(
        &files,
        json!({
            "match": { "kind": "function", "name": "target" },
            "steps": [
                { "op": "file_of" },
                { "op": "importers_of" },
                { "op": "importers_of" }
            ]
        }),
    );
    let repeated = serialized(&repeated);
    assert_eq!(
        repeated["results"].as_array().unwrap().len(),
        1,
        "{repeated}"
    );
    assert_eq!(repeated["results"][0]["path"], "a.rb");
}

#[test]
fn imports_of_is_direct_and_cycles_terminate() {
    let files = [
        ("a.rb", "require_relative 'b'\ndef target; end\n"),
        ("b.rb", "require_relative 'c'\ndef from_b; end\n"),
        ("c.rb", "require_relative 'a'\ndef from_c; end\n"),
    ];
    let result = run(
        &files,
        json!({
            "match": { "kind": "function", "name": "target" },
            "steps": [
                { "op": "file_of" },
                { "op": "imports_of" },
                { "op": "imports_of" },
                { "op": "imports_of" }
            ]
        }),
    );
    let value = serialized(&result);
    assert_eq!(value["results"].as_array().unwrap().len(), 1, "{value}");
    assert_eq!(value["results"][0]["path"], "a.rb");
    assert!(!result.truncated);
}

#[test]
fn unsupported_import_provider_is_diagnostic_not_silent() {
    let result = run(
        &[("app.php", "<?php\nfunction target() {}\n")],
        json!({
            "match": { "kind": "function", "name": "target" },
            "steps": [{ "op": "file_of" }, { "op": "imports_of" }]
        }),
    );
    let value = serialized(&result);
    assert!(value["results"].as_array().unwrap().is_empty(), "{value}");
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.language == "php"
                && diagnostic.message.contains("structured import analysis")),
        "{:?}",
        result.diagnostics
    );
}

#[test]
fn terminal_limit_is_applied_after_file_deduplication() {
    let result = run(
        &[
            ("a.py", "audit()\naudit()\n"),
            ("b.py", "audit()\naudit()\n"),
        ],
        json!({
            "match": { "kind": "call", "callee": { "name": "audit" } },
            "steps": [{ "op": "file_of" }],
            "limit": 1
        }),
    );
    let value = serialized(&result);
    assert_eq!(value["results"].as_array().unwrap().len(), 1, "{value}");
    assert_eq!(value["results"][0]["path"], "a.py");
    assert!(result.truncated);
}

#[test]
fn pipeline_budget_returns_partial_results_with_diagnostic() {
    let project = InlineTestProject::new()
        .file("app.py", "audit()\naudit()\n")
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "match": { "kind": "call", "callee": { "name": "audit" } },
        "steps": [{ "op": "file_of" }]
    }))
    .unwrap();
    let result = execute_with_limits(
        workspace.analyzer(),
        &query,
        CodeQueryExecutionLimits {
            max_pipeline_rows: 3,
            ..CodeQueryExecutionLimits::default()
        },
    );
    assert!(result.truncated);
    assert_eq!(result.results.len(), 1);
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("pipeline budget exhausted")),
        "{:?}",
        result.diagnostics
    );
}
