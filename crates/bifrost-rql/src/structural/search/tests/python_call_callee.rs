use super::*;

#[brokk_bifrost_test_macros::hardwon(
    "#4647: builtin identity selected a same-named call argument as the callee"
)]
#[test]
fn python_builtin_identity_selects_only_the_exact_call_callee() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("main.py", "print(print)\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "languages": ["python"],
        "match": { "kind": "call", "callee": { "name": "print" } },
        "steps": [
            { "op": "occurrences_in" },
            { "op": "python_builtin_identity" },
            {
                "op": "filter",
                "where": [
                    { "field": "relation", "op": "eq", "value": { "enum": "builtin_identity" } },
                    { "field": "outcome", "op": "eq", "value": { "enum": "builtin" } },
                    { "field": "call_callee", "op": "eq", "value": { "boolean": true } }
                ]
            }
        ],
        "limit": 100,
        "result_detail": "full"
    }))
    .expect("typed builtin call-callee query");

    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    let locations: Vec<_> = result
        .results
        .iter()
        .filter_map(|item| match &item.value {
            CodeQueryResultValue::PythonRuleFact { value } => Some((
                value.path.as_str(),
                value.range.start_line,
                value.range.start_column,
                value.target_id.as_deref(),
                value.call_callee,
            )),
            _ => None,
        })
        .collect();
    assert_eq!(
        locations,
        vec![("main.py", 1, 1, Some("builtins.print"), Some(true))]
    );
}
