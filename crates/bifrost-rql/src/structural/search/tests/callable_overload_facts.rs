use super::*;

#[test]
fn overload_constraints_select_only_the_matching_declaration() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "Sample.java",
            "class Sample { public void m(int x) {} private void m(String x) {} }",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    for (constraint, expected) in [
        (":visibility public", "public void m(int x) {}"),
        (":visibility private", "private void m(String x) {}"),
        (r#":parameter-type "int""#, "public void m(int x) {}"),
        (r#":parameter-type "String""#, "private void m(String x) {}"),
    ] {
        let query = CodeQuery::from_sexp(&format!(r#"(method :name "m" {constraint})"#)).unwrap();
        let result = execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        );
        let rendered = result.render_text();
        eprintln!("{constraint}: {rendered}");
        assert_eq!(result.results.len(), 1, "{rendered}");
        assert!(rendered.contains(expected), "{rendered}");
        assert!(result.diagnostics.is_empty(), "{rendered}");
    }
}
