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

fn row_for_text<'a>(result: &'a Value, text: &str) -> &'a Value {
    result["results"]
        .as_array()
        .expect("receiver result rows")
        .iter()
        .find(|row| row["text"] == text)
        .unwrap_or_else(|| panic!("missing receiver row for {text}: {result}"))
}

fn member_fq_names(row: &Value) -> Vec<&str> {
    row["member_targets"]
        .as_array()
        .map(|targets| {
            targets
                .iter()
                .filter_map(|target| target["fq_name"].as_str())
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn go_builtin_new_and_addressability_select_the_correct_method_sets() {
    let source = r#"package receiver

type Service struct{}
func (Service) ValueOnly() {}
func (*Service) PointerOnly() {}

type Other struct{}
func (Other) ValueOnly() {}
func (*Other) PointerOnly() {}

func MakeValue() Service { return Service{} }

func callAddressable() {
    var addressable Service
    addressable.PointerOnly()
}
func callNewPointer() {
    new(Service).PointerOnly()
}
func callNewValue() {
    new(Service).ValueOnly()
}
func callValueFactory() {
    MakeValue().ValueOnly()
}
func callRejectedPointerFactory() {
    MakeValue().PointerOnly()
}
"#;

    let member_row = |callee: &str, function: &str, receiver: &str| {
        let result = run(
            &[("receiver.go", source)],
            json!({
                "match": {
                    "kind": "call",
                    "callee": { "name": callee },
                    "receiver": { "capture": "receiver" }
                },
                "inside": { "kind": "function", "name": function },
                "steps": [{ "op": "member_targets", "capture": "receiver" }]
            }),
        );
        row_for_text(&result, receiver).clone()
    };

    for (function, receiver) in [
        ("callAddressable", "addressable"),
        ("callNewPointer", "new(Service)"),
    ] {
        let row = member_row("PointerOnly", function, receiver);
        assert_ne!(row["outcome"], "unsupported", "{row}");
        assert_eq!(
            member_fq_names(&row),
            ["receiver.Service.PointerOnly"],
            "{row}"
        );
    }
    let non_addressable = member_row("PointerOnly", "callRejectedPointerFactory", "MakeValue()");
    assert_ne!(non_addressable["outcome"], "precise", "{non_addressable}");
    assert!(
        member_fq_names(&non_addressable)
            .iter()
            .all(|target| *target != "receiver.Service.PointerOnly"),
        "{non_addressable}"
    );

    for (function, receiver) in [
        ("callNewValue", "new(Service)"),
        ("callValueFactory", "MakeValue()"),
    ] {
        let row = member_row("ValueOnly", function, receiver);
        assert_ne!(row["outcome"], "unsupported", "{row}");
        assert_eq!(
            member_fq_names(&row),
            ["receiver.Service.ValueOnly"],
            "{row}"
        );
    }
}

#[test]
fn go_builtin_new_points_to_a_structured_service_value() {
    let result = run(
        &[(
            "receiver.go",
            r#"package receiver

type Service struct{}
func (*Service) Run() {}

func call() {
    new(Service).Run()
}
"#,
        )],
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "Run" },
                "receiver": { "capture": "receiver" }
            },
            "steps": [{ "op": "points_to", "capture": "receiver" }]
        }),
    );

    let row = row_for_text(&result, "new(Service)");
    assert_ne!(row["outcome"], "unsupported", "{row}");
    assert!(row["values"].to_string().contains("Service"), "{row}");
}

#[test]
fn go_member_targets_preserve_promotion_paths_and_precise_data_fields() {
    let result = run(
        &[(
            "receiver.go",
            r#"package receiver

type Shared struct {
    ID string
}

type Left struct {
    Shared
}

type Right struct {
    Shared
}

type Model struct {
    Left
    Right
}

type Service struct {
    ID string
}

func inspect(model Model, service Service) {
    _ = model.ID
    _ = service.ID
}
"#,
        )],
        json!({
            "match": {
                "kind": "field_access",
                "field": { "name": "ID" },
                "object": { "capture": "receiver" }
            },
            "inside": { "kind": "function", "name": "inspect" },
            "steps": [{ "op": "member_targets", "capture": "receiver" }]
        }),
    );

    let promoted = row_for_text(&result, "model");
    assert_eq!(promoted["outcome"], "ambiguous", "{promoted}");
    assert_eq!(
        member_fq_names(promoted),
        ["receiver.Shared.ID"],
        "{promoted}"
    );

    let direct = row_for_text(&result, "service");
    assert_eq!(direct["outcome"], "precise", "{direct}");
    assert_eq!(member_fq_names(direct), ["receiver.Service.ID"], "{direct}");
}

#[test]
fn rust_enum_variant_shapes_resolve_the_exact_enum_member() {
    let result = run(
        &[(
            "receiver.rs",
            r#"enum State {
    Unit,
    Tuple(i32),
    Struct { value: i32 },
}

impl State {
    fn run(&self) {}
}

enum Other {
    Unit,
    Tuple(i32),
    Struct { value: i32 },
}

impl Other {
    fn run(&self) {}
}

fn call() {
    State::Unit.run();
    State::Tuple(1).run();
    (State::Struct { value: 1 }).run();
}
"#,
        )],
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": { "capture": "receiver" }
            },
            "inside": { "kind": "function", "name": "call" },
            "steps": [{ "op": "member_targets", "capture": "receiver" }]
        }),
    );

    for receiver in [
        "State::Unit",
        "State::Tuple(1)",
        "(State::Struct { value: 1 })",
    ] {
        let row = row_for_text(&result, receiver);
        assert_ne!(row["outcome"], "unsupported", "{row}");
        assert_eq!(member_fq_names(row), ["State.run"], "{row}");
    }
}
