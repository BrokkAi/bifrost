mod common;

use brokk_bifrost::analyzer::structural::{CodeQuery, execute_workspace};
use brokk_bifrost::{AnalyzerConfig, WorkspaceAnalyzer};
use common::InlineTestProject;
use serde_json::{Value, json};

fn run(path: &str, source: &str, query: Value) -> Value {
    let project = InlineTestProject::new().file(path, source).build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&query).expect("query should parse");
    serde_json::to_value(execute_workspace(&workspace, &query))
        .expect("query result should serialize")
}

fn assert_explicitly_uncertain(report: &Value) {
    let rows = report["results"].as_array().expect("receiver rows");
    assert_eq!(rows.len(), 1, "{report}");
    assert!(
        matches!(
            rows[0]["outcome"].as_str(),
            Some("ambiguous" | "unknown" | "unsupported")
        ),
        "an open language boundary must publish an explicit non-precise outcome: {report}"
    );
}

#[test]
fn go_interface_dispatch_remains_explicitly_uncertain() {
    let report = run(
        "receiver.go",
        r#"package receiver

type Runner interface {
    Run()
}

type Service struct{}
func (Service) Run() {}

func call(runner Runner) {
    runner.Run()
}
"#,
        json!({
            "match": { "kind": "call", "callee": { "name": "Run" } },
            "inside": { "kind": "function", "name": "call" },
            "steps": [{ "op": "member_targets" }]
        }),
    );

    assert_explicitly_uncertain(&report);
}

#[test]
fn php_union_receiver_remains_explicitly_uncertain() {
    let report = run(
        "receiver.php",
        r#"<?php
class Service {
    public function run(): void {}
}

class Other {
    public function run(): void {}
}

function call(Service|Other $receiver): void {
    $receiver->run();
}
"#,
        json!({
            "languages": ["php"],
            "match": { "kind": "call", "callee": { "name": "run" } },
            "inside": { "kind": "function", "name": "call" },
            "steps": [{ "op": "member_targets" }]
        }),
    );

    assert_explicitly_uncertain(&report);
}

#[test]
fn rust_trait_object_dispatch_remains_explicitly_uncertain() {
    let report = run(
        "receiver.rs",
        r#"trait Runner {
    fn run(&self);
}

struct Service;
impl Runner for Service {
    fn run(&self) {}
}

fn call(runner: &dyn Runner) {
    runner.run();
}
"#,
        json!({
            "match": { "kind": "call", "callee": { "name": "run" } },
            "inside": { "kind": "function", "name": "call" },
            "steps": [{ "op": "member_targets" }]
        }),
    );

    assert_explicitly_uncertain(&report);
}
