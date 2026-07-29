//! Compile-time and behavior coverage for the stable root-crate facade.

#[path = "common/inline_project.rs"]
mod inline_project;

use brokk_bifrost::analyzer::structural::CodeQuery;
use brokk_bifrost::code_intelligence::CodeIntelligenceRuntime;
use brokk_bifrost::searchtools::SearchSymbolsParams;
use brokk_bifrost::{AnalyzerConfig, Language, NavigationOperation, WorkspaceAnalyzer};
use inline_project::InlineTestProject;
use serde_json::json;

#[test]
fn root_facade_preserves_analysis_and_runtime_paths() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("src/app.py", "def run():\n    return 42\n")
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let runtime = CodeIntelligenceRuntime::new(&workspace, None);
    let query = CodeQuery::from_json(&json!({ "match": { "kind": "function" } }))
        .expect("query should parse through the stable facade");

    let response = runtime.execute_query(&query, Default::default());
    assert_eq!(
        response
            .result()
            .expect("ordinary query result")
            .structural_matches()
            .len(),
        1
    );

    let _existing_search_params = SearchSymbolsParams {
        patterns: vec!["run".to_string()],
        include_tests: false,
        limit: 10,
    };
    let _existing_navigation_variant = NavigationOperation::Definition;
}
