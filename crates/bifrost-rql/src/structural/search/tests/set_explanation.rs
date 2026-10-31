use super::*;

#[test]
fn explain_preserves_authored_intersection_and_difference() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "sample.py",
            "def left():\n    pass\ndef right():\n    pass\n",
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    for operator in ["intersect", "except"] {
        let mut query = CodeQuery::from_sexp(&format!(
            "({operator} (function :name \"left\") (function :name \"right\"))"
        ))
        .expect("set query");
        let result = execute(&analyzer, &query);
        assert_eq!(result.results.len(), usize::from(operator == "except"));
        if operator == "except" {
            assert!(result.render_text().contains("def left()"));
        }
        query.execution_mode = CodeQueryExecutionMode::Explain;
        let response = execute_request(&analyzer, &query);
        let wire = serde_json::to_value(response).expect("public explain");
        assert!(
            wire["logical_plan"]["nodes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|node| node["operation"]["op"] == operator),
            "{wire:#}"
        );
    }
}
