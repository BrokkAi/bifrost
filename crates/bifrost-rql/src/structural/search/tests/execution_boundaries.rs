use super::*;
use crate::cancellation::CancellationToken;
use brokk_bifrost_test_macros::hardwon;

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

/// The `member_targets` step charges each declaring file to the scan budget
/// once, however many rows reach it. Seventeen accesses touch seventeen
/// declaring files; then the query returns to the first for another member
/// and repeats a member. The smallest budget that completes the first visits
/// must complete the return trip as well.
#[test]
#[hardwon("#10229: a member-form file was parsed and charged again for every row that reached it")]
fn member_form_step_charges_each_declaring_file_once() {
    const FILES: usize = 17;
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    let mut parameters = Vec::new();
    let mut accesses = Vec::new();
    for index in 0..FILES {
        ProjectFile::new(root.clone(), format!("C{index}.cs"))
            .write(format!("public class C{index} {{ public int P {{ get; set; }} public int Q {{ get; set; }} }}\n"))
            .expect("write declaring file");
        parameters.push(format!("C{index} c{index}"));
        accesses.push(format!("_ = c{index}.P;"));
    }
    ProjectFile::new(root.clone(), "Use.cs")
        .write(format!(
            "public class Use {{ public void Run({}) {{ {} _ = c0.Q; _ = c0.P; }} }}\n",
            parameters.join(", "),
            accesses.join(" ")
        ))
        .expect("write usage");
    let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
        Arc::new(TestProject::new(root, Language::CSharp)),
        AnalyzerConfig::default(),
    )
    .expect("ephemeral workspace should build");
    let completes = |names: &str, rows: usize, max_scanned_files: usize| {
        let query = CodeQuery::from_json(&json!({
            "languages": ["csharp"],
            "match": { "kind": "field_access", "field": { "name": { "regex": names } } },
            "steps": [{ "op": "member_targets", "member_form": ["property"] }]
        }))
        .unwrap();
        let result = execute_workspace_with_limits(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
            CodeQueryExecutionLimits {
                max_scanned_files,
                ..CodeQueryExecutionLimits::default()
            },
        );
        result.results.len() == rows && result.diagnostics.is_empty()
    };
    // More budget never completes less, so the smallest completing budget is a
    // partition point.
    let limits = (1..=4 * FILES).collect::<Vec<_>>();
    let first_visits = limits[limits.partition_point(|&limit| !completes("^P$", FILES + 1, limit))];
    // `^P$` already repeats `c0.P`; `^[PQ]$` adds a second member of the first
    // file, reached after sixteen other files evicted its syntax.
    assert!(completes("^[PQ]$", FILES + 2, first_visits));
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "2fd06a51df9c: registered request failures omitted requested depth completion"
)]
fn registered_failure_depth_status_obeys_consumer_gate() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("lib.rs", "fn root() {}")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    for direction in ["callers", "callees"] {
        let query = CodeQuery::from_sexp(&format!(
            "({direction} :depth 1 (enclosing-decl (language rust (function))))"
        ))
        .unwrap();
        let token = CancellationToken::new();
        token.cancel();
        let response = execute_workspace_request_with_registrations_and_limits(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            0,
            &ProtocolRegistrationSet::default(),
            &query,
            CodeQueryExecutionLimits::default(),
            Some(&token),
        );
        assert_eq!(
            response.result().unwrap().depth_bound_status,
            Some(DepthBoundStatus::Unknown)
        );
        let invalid = CodeQuery::from_json(&json!({"union": [
            {"match": {"kind": "function"}, "steps": [{"op": "enclosing_decl"}, {"op": "callers", "depth": 1}]},
            {"match": {"kind": "function"}, "steps": [{"op": "procedure_of"}, {"op": "typestate", "protocol_ref": "test:missing"}]}
        ]})).unwrap();
        let response = execute_workspace_request_with_registrations_and_limits(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            0,
            &ProtocolRegistrationSet::default(),
            &invalid,
            CodeQueryExecutionLimits::default(),
            None,
        );
        assert_eq!(
            response.result().unwrap().depth_bound_status,
            Some(DepthBoundStatus::Unknown)
        );
        assert!(
            response
                .result()
                .unwrap()
                .diagnostics
                .iter()
                .any(|d| d.code == CodeQueryDiagnosticCode::UnresolvedProtocolReference)
        );
        for enabled in [false, true] {
            for error in [
                QueryAnalysisContextError::Cancelled,
                QueryAnalysisContextError::WorkspaceGenerationMismatch {
                    registered: 1,
                    current: 2,
                },
            ] {
                let result = unexecuted_depth_result(
                    query_analysis_context_error_result(None, error),
                    &query,
                    &CodeQueryExecutionScope::whole_workspace().with_depth_bound_status(enabled),
                );
                assert_eq!(
                    result.depth_bound_status,
                    enabled.then_some(DepthBoundStatus::Unknown)
                );
            }
        }
    }
}
