use super::*;
use crate::structural::search::units::{CodeQueryExecutionScope, execute_code_query_unit};

#[test]
fn union_units_retain_an_earlier_leafs_physical_truncation() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "app.ts",
            "function first() {}\nfunction second() {}\nfunction third() {}\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let files = workspace.analyzer().analyzed_files();
    let flow = brokk_bifrost_flow::FlowWorkspaceState::default();
    for reverse in [false, true] {
        let broad = json!({"match": {"kind": "function"}});
        let narrow = json!({"match": {"kind": "function", "name": "first"}});
        let leaves = if reverse {
            vec![narrow, broad]
        } else {
            vec![broad, narrow]
        };
        let query = CodeQuery::from_json(&json!({"union": leaves, "limit": 100})).unwrap();
        // The broad leaf has three rows and its physical output budget is two.
        let unit = execute_code_query_unit(
            workspace.analyzer(),
            &flow,
            None,
            &query,
            CodeQueryExecutionLimits {
                max_pipeline_rows: 2,
                ..Default::default()
            },
            None,
            CodeQueryExecutionScope::for_seed_files(&files, &files),
        );
        assert!(!unit.rows.is_empty(), "{unit:?}");
        assert!(unit.truncated, "{unit:?}");
    }
}
