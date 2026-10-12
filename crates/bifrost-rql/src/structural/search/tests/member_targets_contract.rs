use super::*;

fn class_declaration_query(class_name: &str) -> CodeQuery {
    CodeQuery::from_json(&json!({
        "where": ["app.ts"],
        "match": { "kind": "class", "name": class_name },
        "steps": [{ "op": "enclosing_decl" }],
        "result_detail": "full"
    }))
    .expect("class declaration query")
}

fn method_declaration_query(class_name: &str) -> CodeQuery {
    CodeQuery::from_json(&json!({
        "where": ["app.ts"],
        "match": { "kind": "method", "name": "run" },
        "inside_decl": { "kind": "class", "name": class_name },
        "steps": [{ "op": "enclosing_decl" }],
        "result_detail": "full"
    }))
    .expect("method declaration query")
}

fn declaration_rows(workspace: &WorkspaceAnalyzer, query: CodeQuery) -> Vec<CodeQueryDeclaration> {
    execute_workspace(
        workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    )
    .results
    .into_iter()
    .filter_map(|item| match item.value {
        CodeQueryResultValue::Declaration { value } => Some(value),
        _ => None,
    })
    .collect()
}

fn class_id(workspace: &WorkspaceAnalyzer, class_name: &str) -> String {
    let rows = declaration_rows(workspace, class_declaration_query(class_name));
    let [class] = rows.as_slice() else {
        panic!("expected one class declaration row, got {rows:#?}")
    };
    assert_eq!(class.kind, "class");
    class.id.clone().expect("class declaration id")
}

fn sole_method_id(workspace: &WorkspaceAnalyzer, class_name: &str) -> String {
    let rows = declaration_rows(workspace, method_declaration_query(class_name));
    let [method] = rows.as_slice() else {
        panic!("expected one method declaration row, got {rows:#?}")
    };
    assert_eq!(method.kind, "method");
    method.id.clone().expect("method declaration id")
}

fn member_targets_query() -> CodeQuery {
    CodeQuery::from_json(&json!({
        "where": ["app.ts"],
        "occurrences": { "role": ["member_position"] },
        "steps": [{ "op": "member_targets" }],
        "result_detail": "full"
    }))
    .expect("member target query")
}

#[test]
fn typescript_member_targets_keep_exact_identity_and_typed_uncertainty() {
    let proven_project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "app.ts",
            r#"class Service { run() {} }
class Other { run() {} }
export function caller() {
  const service = new Service();
  service.run();
}
"#,
        )
        .build();
    let proven_workspace = proven_project.workspace_analyzer(AnalyzerConfig::default());
    let service_id = class_id(&proven_workspace, "Service");
    let service_run_id = sole_method_id(&proven_workspace, "Service");
    let other_id = class_id(&proven_workspace, "Other");
    let other_run_id = sole_method_id(&proven_workspace, "Other");

    let proven = execute_workspace(
        &proven_workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &member_targets_query(),
    );
    assert_eq!(proven.results.len(), 1, "{}", proven.render_text());
    let CodeQueryResultValue::MemberTargetAnalysis { value } = &proven.results[0].value else {
        panic!(
            "expected member target analysis, got {}",
            proven.render_text()
        )
    };
    assert_eq!(value.outcome, "precise", "{value:#?}");
    assert_eq!(value.coverage, "exhaustive", "{value:#?}");
    let [target] = value.member_targets.as_slice() else {
        panic!("expected one member target, got {value:#?}")
    };
    assert_eq!(target.id, service_run_id);
    assert_eq!(target.receiver_id.as_deref(), Some(service_id.as_str()));
    assert!(target.semantic_model.is_none());
    assert!(target.receiver_semantic_model.is_none());
    assert!(target.receiver_proof.is_none());
    assert_eq!(
        target
            .declaration
            .as_ref()
            .and_then(|declaration| declaration.id.as_deref()),
        Some(service_run_id.as_str())
    );
    assert_eq!(
        target
            .receiver_declaration
            .as_ref()
            .and_then(|declaration| declaration.id.as_deref()),
        Some(service_id.as_str())
    );
    assert_ne!(target.id, other_run_id);
    assert_ne!(target.receiver_id.as_deref(), Some(other_id.as_str()));

    let uncertain_project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "app.ts",
            "export function caller(service) { service.run(); }\n",
        )
        .build();
    let uncertain_workspace = uncertain_project.workspace_analyzer(AnalyzerConfig::default());
    let uncertain = execute_workspace(
        &uncertain_workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &member_targets_query(),
    );
    assert_eq!(uncertain.results.len(), 1, "{}", uncertain.render_text());
    let CodeQueryResultValue::MemberTargetAnalysis { value } = &uncertain.results[0].value else {
        panic!(
            "expected typed member target uncertainty, got {}",
            uncertain.render_text()
        )
    };
    assert_eq!(value.outcome, "unknown", "{value:#?}");
    assert_eq!(value.coverage, "unknown", "{value:#?}");
    assert!(value.member_targets.is_empty());
}
