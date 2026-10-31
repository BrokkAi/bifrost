use super::*;

#[test]
fn branch_evidence_names_the_selected_if_owner() {
    let project = InlineTestProject::new()
        .file("Sample.java", "class Sample { int f(boolean x) { if (x) { return 1; } else if (x) { return 1; } return 0; } }")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let owners = execute_code_query_detailed_eager_index_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &CodeQuery::from_json(&json!({"match":{"kind":"if"},"result_detail":"full"})).unwrap(),
        CodeQueryExecutionLimits::default(),
        None,
    );
    let owner_ids = owners
        .result
        .results
        .iter()
        .map(|item| {
            let CodeQueryResultValue::StructuralMatch { value } = &item.value else {
                panic!("selected if");
            };
            value.ast_id.as_ref().expect("full AST identity")
        })
        .collect::<Vec<_>>();
    assert!(!owner_ids.is_empty());
    let detailed = execute_code_query_detailed_eager_index_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &CodeQuery::from_sexp(
            "(branch-relations :relation [identical-bodies repeated-condition] (if))",
        )
        .unwrap(),
        CodeQueryExecutionLimits::default(),
        None,
    );
    assert!(detailed.evidence.len() >= 2, "{detailed:#?}");
    for evidence in &detailed.evidence {
        let DetailedCodeQueryKey::BranchRelation { id, owner_id, .. } = &evidence.key else {
            panic!("branch evidence");
        };
        assert!(owner_ids.contains(&owner_id), "{evidence:#?}");
        assert_ne!(id, owner_id);
    }
}
