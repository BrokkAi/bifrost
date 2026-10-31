use super::*;

#[test]
fn scope_sessions_distinguish_cold_derivation_from_reuse() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("example.py", "value = 1\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let file = project.file("example.py");
    let files = [file];
    let query = CodeQuery::from_source("(scopes)").expect("scope query");
    let mut session = CodeQueryRowFamilySession::default();
    for expected_reuses in 0..3 {
        let result = execute_code_query_detailed_eager_index_with_row_family_session_in_scope(
            workspace.analyzer(),
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            &query,
            CodeQueryExecutionLimits::default(),
            None,
            &mut session,
            CodeQueryExecutionScope::for_seed_files(&files, &files),
        );
        assert_eq!(result.result.completion(), CodeQueryCompletion::Complete);
        assert_eq!(result.result.results.len(), 1, "one module scope");
        let stats = session.environment.lock().unwrap().stats();
        assert_eq!((stats.0, stats.1), (1, expected_reuses));
    }
}

#[test]
fn recovered_python_withholds_constant_comparison_proofs() {
    for (suffix, expected_rows) in [("", 1), ("\ndef broken(:\n", 0)] {
        let source = format!("answer = 1 == 1\n{suffix}");
        let (_project, workspace) = inline_project::python_workspace(&[("sample.py", &source)]);
        let query =
            CodeQuery::from_source("(python-comparison-constants (language python (comparison)))")
                .expect("comparison query");
        let result = execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            &query,
        );
        assert_eq!(
            result.results.len(),
            expected_rows,
            "{}",
            result.render_text()
        );
        if suffix.is_empty() {
            assert_eq!(result.completion(), CodeQueryCompletion::Complete);
        } else {
            assert!(
                result
                    .diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.message.contains("recovered syntax")),
                "{}",
                result.render_text()
            );
        }
    }
}
