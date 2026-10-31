use super::*;
use crate::cancellation::CancellationToken;

#[test]
fn public_request_honors_exact_file_budget() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("first.py", "def first():\n    pass\n")
        .file("second.py", "def second():\n    pass\n")
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let query = CodeQuery::from_json(&json!({"match": {"kind": "function"}})).unwrap();
    // The caller explicitly admits one file, then both authored files.
    for maximum in [1, 2] {
        let response = execute_request_with_limits(
            &analyzer,
            &query,
            CodeQueryExecutionLimits {
                max_scanned_files: maximum,
                ..CodeQueryExecutionLimits::default()
            },
        );
        let result = response.result().unwrap();
        assert_eq!(result.results.len(), maximum, "{result:?}");
        assert_eq!(result.truncated, maximum == 1, "{result:?}");
    }
}

#[test]
fn eager_execution_preserves_cancellation_and_exact_seed_scope() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("selected.py", "def selected():\n    pass\n")
        .file("sibling.py", "def sibling():\n    pass\n")
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let query = CodeQuery::from_json(&json!({"match": {"kind": "function"}})).unwrap();
    let flow = brokk_bifrost_flow::FlowWorkspaceState::new();
    let files = [
        ProjectFile::new(project.root().to_path_buf(), PathBuf::from("selected.py")),
        ProjectFile::new(project.root().to_path_buf(), PathBuf::from("sibling.py")),
    ];
    let result = execute_code_query_detailed_eager_index_in_scope(
        &analyzer,
        &flow,
        &query,
        CodeQueryExecutionLimits::default(),
        None,
        CodeQueryExecutionScope::for_seed_files(&files[..1], &files),
    )
    .result;
    assert_eq!(result.results.len(), 1, "{result:?}");
    assert!(result.render_text().contains("selected"));
    let token = CancellationToken::new();
    token.cancel();
    let result = execute_code_query_detailed_eager_index(
        &analyzer,
        &flow,
        &query,
        CodeQueryExecutionLimits::default(),
        Some(&token),
    )
    .result;
    assert!(result.results.is_empty(), "{result:?}");
    assert!(!result.diagnostics.is_empty(), "{result:?}");
    let mut session = CodeQueryRowFamilySession::default();
    let result = execute_code_query_detailed_eager_index_with_row_family_session_in_scope(
        &analyzer,
        &flow,
        &query,
        CodeQueryExecutionLimits::default(),
        Some(&token),
        &mut session,
        CodeQueryExecutionScope::whole_workspace(),
    )
    .result;
    assert!(result.results.is_empty(), "{result:?}");
    assert!(!result.diagnostics.is_empty(), "{result:?}");
}

#[test]
fn registered_workspace_request_preserves_cancellation() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("main.py", "def selected():\n    pass\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let flow = brokk_bifrost_flow::FlowWorkspaceState::new();
    let query = CodeQuery::from_json(&json!({"match": {"kind": "function"}})).unwrap();
    for cancelled in [false, true] {
        let token = CancellationToken::new();
        if cancelled {
            token.cancel();
        }
        let response = execute_workspace_request_with_registrations_and_limits(
            &workspace,
            &flow,
            0,
            &ProtocolRegistrationSet::default(),
            &query,
            CodeQueryExecutionLimits::default(),
            Some(&token),
        );
        let result = response.result().unwrap();
        assert_eq!(result.results.len(), usize::from(!cancelled), "{result:?}");
        assert_eq!(result.diagnostics.is_empty(), !cancelled, "{result:?}");
    }
}

#[test]
fn unmaterialized_receiver_family_is_invalid() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("main.py", "def target():\n    pass\ntarget()\n")
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let query = CodeQuery::from_json(&json!({
        "match": {"kind": "call"},
        "steps": [{"op": "call_shape"}, {"op": "call_bindings"}, {
            "op": "resolved_call", "resolves_to": {"stable": "target"},
            "call_proof": "exact", "receiver_type": {
                "assignable_to": {"stable": "receiver"}, "resolved_identities": []
            }
        }]
    }))
    .unwrap();
    let response = execute_request(&analyzer, &query);
    let result = response.result().unwrap();
    assert!(result.results.is_empty(), "{result:?}");
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == CodeQueryDiagnosticCode::InvalidPlan),
        "{result:?}"
    );
}
