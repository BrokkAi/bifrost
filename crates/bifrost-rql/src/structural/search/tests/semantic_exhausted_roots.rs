//! Structured diagnostics are a public contract independent of their prose.
use super::*;

#[test]
fn semantic_file_refusal_names_the_root_lane_and_charge() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("a.py", "def first():\n    marker()\n")
        .file("b.py", "def second():\n    marker()\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "execution_mode": "profile",
        "match": { "kind": "call", "name": "marker" },
        "steps": [{ "op": "procedure_of" }, { "op": "cfg_entry" }]
    }))
    .unwrap();
    let flow = brokk_bifrost_flow::FlowWorkspaceState::new();
    // Two files fit the exact admission limit.
    let CodeQueryResponse::Profile(admitted) = execute_workspace_request_with_limits(
        &workspace,
        &flow,
        &query,
        CodeQueryExecutionLimits {
            semantic: CodeQuerySemanticLimits {
                max_materialized_files: 2,
                ..Default::default()
            },
            ..Default::default()
        },
    ) else {
        panic!("profile expected")
    };
    assert_eq!(admitted.result.results.len(), 2, "{admitted:#?}");
    assert!(!admitted.work.semantic.budget_exhausted, "{admitted:#?}");
    let CodeQueryResponse::Profile(refused) = execute_workspace_request_with_limits(
        &workspace,
        &flow,
        &query,
        CodeQueryExecutionLimits {
            semantic: CodeQuerySemanticLimits {
                max_materialized_files: 1,
                ..Default::default()
            },
            ..Default::default()
        },
    ) else {
        panic!("profile expected")
    };
    assert_eq!(refused.result.results.len(), 1, "{refused:#?}");
    assert!(refused.work.semantic.budget_exhausted, "{refused:#?}");
    let diagnostic = refused
        .result
        .diagnostics
        .iter()
        .find(|d| d.code == CodeQueryDiagnosticCode::SemanticBudgetExhausted)
        .expect("typed refusal");
    assert_eq!(diagnostic.impact, CodeQueryDiagnosticImpact::Incomplete);
    assert_eq!(diagnostic.exhausted_roots.len(), 1, "{diagnostic:#?}");
    let root = &diagnostic.exhausted_roots[0];
    assert_eq!(root.path, "b.py");
    assert_eq!(root.lane, "semantic/files");
    let charge = root.charge.as_ref().expect("admission charge");
    assert_eq!(charge.attempted, 2);
    assert_eq!(charge.limit, 1);
}
