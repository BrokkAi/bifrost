use super::*;
use crate::structural::search::units::{
    CodeQueryExecutionScope, execute_code_query_unit, merge_unit_rows, plan_seed_files,
};

#[test]
fn structural_units_follow_relative_path_string_order() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("a.py", "def sibling():\n    pass\n")
        .file("a/x.py", "def nested():\n    pass\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({"match": {"kind": "function"}, "limit": 1})).unwrap();
    let files = plan_seed_files(&query.plan, &workspace.analyzer().analyzed_files());
    assert_eq!(files, vec![project.file("a.py"), project.file("a/x.py")]);
}

#[test]
fn bounded_unit_output_survives_a_later_complete_unit() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "a.ts",
            "function first() {}\nfunction second() {}\nfunction third() {}\n",
        )
        .file("b.ts", "function last() {}\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    // Authored output limit: the first file exceeds two, the second fits.
    let query = CodeQuery::from_json(&json!({"match": {"kind": "function"}, "limit": 2})).unwrap();
    let files = plan_seed_files(&query.plan, &workspace.analyzer().analyzed_files());
    let flow = brokk_bifrost_flow::FlowWorkspaceState::default();
    let units: Vec<_> = files
        .iter()
        .map(|file| {
            execute_code_query_unit(
                workspace.analyzer(),
                &flow,
                None,
                &query,
                CodeQueryExecutionLimits::default(),
                None,
                CodeQueryExecutionScope::for_seed_files(std::slice::from_ref(file), &files),
            )
        })
        .collect();
    assert_eq!(units.len(), 2);
    assert!(units[0].truncated, "{units:?}");
    assert!(!units[1].truncated, "{units:?}");
    let merged = merge_unit_rows(&query, units);
    assert!(merged.truncated, "{merged:?}");
    assert!(matches!(
        merged.completion(),
        CodeQueryCompletion::Incomplete { .. }
    ));
}
