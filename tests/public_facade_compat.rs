//! Compile-time and behavior coverage for the stable root-crate facade.

#[path = "common/inline_project.rs"]
mod inline_project;

use brokk_bifrost::analyzer::structural::CodeQuery;
use brokk_bifrost::code_intelligence::CodeIntelligenceRuntime;
use brokk_bifrost::mcp_common::McpRenderOptions;
use brokk_bifrost::mcp_registry::resolve_server_spec_for_render_options;
use brokk_bifrost::searchtools::SearchSymbolsParams;
use brokk_bifrost::{
    AnalyzerConfig, Language, NavigationOperation, SearchToolsService, WorkspaceAnalyzer,
};
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

    let spec =
        resolve_server_spec_for_render_options("extended", McpRenderOptions::default(), false)
            .expect("MCP registry should remain available through the stable facade");
    assert!(
        spec.tool_descriptors
            .iter()
            .any(|descriptor| descriptor["name"] == "most_relevant_files")
    );

    let service =
        SearchToolsService::new_manual_without_semantic_index(project.root().to_path_buf())
            .expect("MCP service should construct through the stable facade");
    let payload = service
        .call_tool_json("find_files_containing", r#"{"patterns":["def run"]}"#)
        .expect("advertised workspace tool should execute");
    assert!(payload.contains("src/app.py"), "{payload}");
}
