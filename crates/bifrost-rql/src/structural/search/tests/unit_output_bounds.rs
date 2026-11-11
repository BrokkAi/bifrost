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

#[test]
fn rust_reverse_in_file_matches_workspace_call_sites() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"reverse_frontier\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .file(
            "src/lib.rs",
            "mod first;\nmod second;\npub fn target(value: i32) -> i32 { value }\n",
        )
        .file(
            "src/first.rs",
            "pub fn first() -> i32 { crate::target(1) }\n",
        )
        .file(
            "src/second.rs",
            "pub fn second() -> i32 { crate::target(2) + crate::target(3) }\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "languages": ["rust"],
        "match": {"kind": "callable", "name": "target"},
        "steps": [{"op": "enclosing_decl"}, {"op": "call_sites_to"}],
        "limit": 100
    }))
    .unwrap();
    let flow = brokk_bifrost_flow::FlowWorkspaceState::default();
    let files = workspace.analyzer().analyzed_files();
    let run = |scope| {
        execute_code_query_unit(
            workspace.analyzer(),
            &flow,
            Some(&workspace),
            &query,
            CodeQueryExecutionLimits::default(),
            None,
            scope,
        )
    };
    let whole = run(CodeQueryExecutionScope::whole_workspace());
    assert_eq!(whole.completion, CodeQueryCompletion::Complete, "{whole:?}");
    assert_eq!(whole.rows.len(), 3, "{whole:?}");
    let mut local_rows = Vec::new();
    for file in &files {
        let unit = run(CodeQueryExecutionScope::for_reverse_entered_file(
            file, &files,
        ));
        assert_eq!(unit.completion, whole.completion, "{file:?}: {unit:?}");
        local_rows.extend(unit.rows);
    }
    // Compare the rendered row, detailed evidence and stable dedup key.
    let normalize = |rows: Vec<crate::structural::search::units::UnitRow>| {
        let mut rows: Vec<_> = rows
            .into_iter()
            .map(|row| serde_json::to_string(&row).unwrap())
            .collect();
        rows.sort();
        rows
    };
    // A one-file seed restriction keeps its ordinary meaning: the seeds
    // declared in that file, with their call sites anywhere.
    for file in &files {
        let seeded = run(CodeQueryExecutionScope::for_seed_files(
            std::slice::from_ref(file),
            &files,
        ));
        let expected = if file.rel_path() == std::path::Path::new("src/lib.rs") {
            whole.rows.len()
        } else {
            0
        };
        assert_eq!(seeded.rows.len(), expected, "{file:?}: {seeded:?}");
    }
    assert_eq!(normalize(local_rows), normalize(whole.rows));
}

#[test]
fn rust_reverse_in_file_cap_is_reported_per_entered_file() {
    // Three call sites in two files under an output limit of two. The widened
    // run caps inside its one unit. Per entered file no unit reaches the cap,
    // so the units are complete and the merge holds the complete answer; the
    // root limit applied after the merge then caps it. Which rows a capped
    // answer keeps is not a contract; that it is truncated and incomplete is.
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"reverse_frontier\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .file(
            "src/lib.rs",
            "mod first;\nmod second;\npub fn target(value: i32) -> i32 { value }\n",
        )
        .file(
            "src/first.rs",
            "pub fn first() -> i32 { crate::target(1) }\n",
        )
        .file(
            "src/second.rs",
            "pub fn second() -> i32 { crate::target(2) + crate::target(3) }\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "languages": ["rust"],
        "match": {"kind": "callable", "name": "target"},
        "steps": [{"op": "enclosing_decl"}, {"op": "call_sites_to"}],
        "limit": 2
    }))
    .unwrap();
    let flow = brokk_bifrost_flow::FlowWorkspaceState::default();
    let files = workspace.analyzer().analyzed_files();
    let run = |scope| {
        execute_code_query_unit(
            workspace.analyzer(),
            &flow,
            Some(&workspace),
            &query,
            CodeQueryExecutionLimits::default(),
            None,
            scope,
        )
    };
    let whole = run(CodeQueryExecutionScope::whole_workspace());
    let units: Vec<_> = files
        .iter()
        .map(|file| {
            run(CodeQueryExecutionScope::for_reverse_entered_file(
                file, &files,
            ))
        })
        .collect();
    assert!(whole.truncated, "{whole:?}");
    assert!(matches!(
        whole.completion,
        CodeQueryCompletion::Incomplete { .. }
    ));
    let site_ids = |items: Vec<&crate::structural::search::units::UnitRowItem>| {
        let mut ids: Vec<_> = items
            .into_iter()
            .map(|item| serde_json::to_string(item).unwrap())
            .collect();
        ids.sort();
        ids
    };
    for (file, unit) in files.iter().zip(&units) {
        assert!(!unit.truncated, "{file:?}: {unit:?}");
        assert_eq!(unit.completion, CodeQueryCompletion::Complete, "{file:?}");
    }
    let mut merged = merge_unit_rows(&query, units);
    assert_eq!(merged.items.len(), 3, "{merged:?}");
    assert_eq!(merged.completion(), CodeQueryCompletion::Complete);
    merged.apply_result_limit(query.limit);
    assert!(merged.truncated, "{merged:?}");
    assert!(matches!(
        merged.completion(),
        CodeQueryCompletion::Incomplete { .. }
    ));
    assert_eq!(merged.items.len(), whole.rows.len());
    assert_eq!(
        site_ids(merged.items.iter().collect()),
        site_ids(whole.rows.iter().map(|row| &row.item).collect())
    );
}
