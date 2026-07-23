mod common;

use brokk_bifrost::analyzer::structural::{CodeQuery, CodeQueryResult, execute_workspace};
use brokk_bifrost::{AnalyzerConfig, WorkspaceAnalyzer};
use common::InlineTestProject;
use serde_json::{Value, json};

fn run(files: &[(&str, &str)], query: Value) -> Value {
    let mut project = InlineTestProject::new();
    for (path, source) in files {
        project = project.file(*path, *source);
    }
    let project = project.build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&query).expect("query should parse");
    let result: CodeQueryResult = execute_workspace(&workspace, &query);
    serde_json::to_value(result).expect("query result should serialize")
}

fn first_row(report: &Value) -> &Value {
    report["results"]
        .as_array()
        .and_then(|rows| rows.first())
        .unwrap_or_else(|| panic!("expected receiver row: {report}"))
}

fn assert_exact_member(report: &Value, suffix: &str) {
    let row = first_row(report);
    assert_ne!(row["outcome"], "unsupported", "{report}");
    assert!(
        row["member_targets"]
            .as_array()
            .is_some_and(|targets| targets.iter().any(|target| {
                target["fq_name"]
                    .as_str()
                    .is_some_and(|name| name.ends_with(suffix))
            })),
        "{report}"
    );
}

#[test]
fn cpp_direct_temporary_receiver_uses_its_constructed_type() {
    let report = run(
        &[(
            "temporary.cpp",
            r#"
struct Service {
    void run() {}
};

struct Other {
    void run() {}
};

void caller() {
    Service{}.run();
}
"#,
        )],
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": { "capture": "receiver" }
            },
            "steps": [{ "op": "member_targets", "capture": "receiver" }]
        }),
    );

    assert_exact_member(&report, "Service.run");
    assert!(
        first_row(&report)["member_targets"]
            .as_array()
            .is_some_and(|targets| targets.iter().all(|target| {
                target["fq_name"]
                    .as_str()
                    .is_none_or(|name| !name.ends_with("Other.run"))
            })),
        "{report}"
    );
}

#[test]
fn php_nullsafe_property_parameter_and_static_receivers_stay_structured() {
    let files = [(
        "scope.php",
        r#"<?php
class Service {
    public function run(): void {}
    public static function make(): Service { return new Service(); }
}

class Holder {
    public function __construct(public Service $service) {}
    public function propertyCall(): void { $this->service->run(); }
}

function parameterCall(?Service $service): void { $service?->run(); }
function staticCall(): void { Service::make()->run(); }
"#,
    )];

    for (owner_kind, owner_name) in [("method", "propertyCall"), ("function", "staticCall")] {
        let report = run(
            &files,
            json!({
                "languages": ["php"],
                "match": { "kind": "call", "callee": { "name": "run" } },
                "inside": { "kind": owner_kind, "name": owner_name },
                "steps": [{ "op": "member_targets" }]
            }),
        );
        assert_exact_member(&report, "Service.run");
    }

    let nullable = run(
        &files,
        json!({
            "languages": ["php"],
            "match": { "kind": "call", "callee": { "name": "run" } },
            "inside": { "kind": "function", "name": "parameterCall" },
            "steps": [{ "op": "member_targets" }]
        }),
    );
    assert_eq!(
        first_row(&nullable)["outcome"],
        "unknown",
        "nullable receiver evidence must stay explicit rather than selecting one union arm: {nullable}"
    );

    let static_receiver = run(
        &files,
        json!({
            "languages": ["php"],
            "match": { "kind": "call", "callee": { "name": "make" } },
            "inside": { "kind": "function", "name": "staticCall" },
            "steps": [{ "op": "receiver_targets" }]
        }),
    );
    let row = first_row(&static_receiver);
    assert_ne!(row["outcome"], "unsupported", "{static_receiver}");
    assert!(
        row["values"]
            .as_array()
            .is_some_and(
                |values| values.iter().any(|value| value["receiver_value_kind"]
                    == "class_or_static_object"
                    && value["declaration"]["fq_name"]
                        .as_str()
                        .is_some_and(|name| name.ends_with("Service")))
            ),
        "{static_receiver}"
    );
}

#[test]
fn python_cls_static_class_and_annotated_parameter_receivers_stay_structured() {
    let files = [(
        "scope.py",
        r#"class Service:
    def run(self) -> None:
        pass

    @classmethod
    def build(cls) -> "Service":
        return Service()

    @classmethod
    def via_cls(cls) -> "Service":
        return cls.build()

    @staticmethod
    def static_build() -> "Service":
        return Service()

def parameter_call(service: Service) -> None:
    service.run()

def class_call() -> None:
    Service.build().run()
    Service.static_build().run()
"#,
    )];

    let parameter = run(
        &files,
        json!({
            "languages": ["python"],
            "match": { "kind": "call", "callee": { "name": "run" } },
            "inside": { "kind": "function", "name": "parameter_call" },
            "steps": [{ "op": "member_targets" }]
        }),
    );
    assert_exact_member(&parameter, "Service.run");

    let cls = run(
        &files,
        json!({
            "languages": ["python"],
            "match": { "kind": "call", "callee": { "name": "build" } },
            "inside": { "kind": "method", "name": "via_cls" },
            "steps": [{ "op": "receiver_targets" }]
        }),
    );
    assert_ne!(first_row(&cls)["outcome"], "unsupported", "{cls}");
    assert!(
        first_row(&cls)["values"].to_string().contains("Service"),
        "{cls}"
    );

    let class_receivers = run(
        &files,
        json!({
            "languages": ["python"],
            "match": {
                "kind": "call",
                "callee": { "capture": "factory" },
                "receiver": { "name": "Service", "capture": "class_receiver" }
            },
            "inside": { "kind": "function", "name": "class_call" },
            "steps": [{ "op": "receiver_targets", "capture": "class_receiver" }]
        }),
    );
    assert!(
        class_receivers["results"]
            .as_array()
            .is_some_and(|rows| rows.len() == 2
                && rows.iter().all(|row| row["outcome"] != "unsupported"
                    && row["values"].to_string().contains("Service"))),
        "{class_receivers}"
    );
}

#[test]
fn ruby_safe_navigation_alias_and_module_object_boundaries_are_explicit() {
    let files = [(
        "scope.rb",
        r#"class Service
  def run
  end
end

module Registry
  def self.run
  end
end

def safe_call(service)
  service&.run
end

def alias_call
  original = Service.new
  copy = original
  copy.run
end

def module_call
  Registry.run
end
"#,
    )];

    let safe = run(
        &files,
        json!({
            "languages": ["ruby"],
            "match": { "kind": "call", "callee": { "name": "run" } },
            "inside": { "kind": "function", "name": "safe_call" },
            "steps": [{ "op": "receiver_targets" }]
        }),
    );
    assert_ne!(first_row(&safe)["outcome"], "unsupported", "{safe}");

    let alias = run(
        &files,
        json!({
            "languages": ["ruby"],
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": { "name": "copy", "capture": "receiver" }
            },
            "inside": { "kind": "function", "name": "alias_call" },
            "steps": [{ "op": "points_to", "capture": "receiver" }]
        }),
    );
    assert_ne!(first_row(&alias)["outcome"], "unsupported", "{alias}");
    assert!(
        first_row(&alias)["values"].to_string().contains("Service"),
        "{alias}"
    );

    let module = run(
        &files,
        json!({
            "languages": ["ruby"],
            "match": { "kind": "call", "callee": { "name": "run" } },
            "inside": { "kind": "function", "name": "module_call" },
            "steps": [{ "op": "member_targets" }]
        }),
    );
    assert_exact_member(&module, "Registry.run");
}
