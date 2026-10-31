use super::*;

#[test]
fn failed_swap_range_includes_the_second_assignment() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "sample.go",
            "package sample\nfunc swap(a, b int) int {\n a = b\n b = a\n return a\n}\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_sexp(
        "(assignment-relations :relation [failed-swap] (procedure-of (callable)))",
    )
    .unwrap();
    let result = execute_workspace(&workspace, &Default::default(), &query);
    assert_eq!(result.results.len(), 1, "{result:#?}");
    let CodeQueryResultValue::AssignmentRelation { value } = &result.results[0].value else {
        panic!("swap relation");
    };
    assert_eq!(value.range.start_line, 3);
    assert_eq!(value.range.end_line, 4);
    assert_eq!(value.range.end_column, 7);
}
