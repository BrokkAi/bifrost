//! Structural seeds over files with syntax that parser error recovery
//! produced (#3777), under both access paths. The posting index has no entry
//! for a node recovery removed, so the indexed path must report the file
//! before it skips it for having no candidates.

use super::*;
use brokk_bifrost_test_macros::hardwon;

fn kotlin_workspace(source: &str) -> (tempfile::TempDir, WorkspaceAnalyzer) {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), "Sample.kt")
        .write(source)
        .expect("write Kotlin source");
    let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
        Arc::new(TestProject::new(root, Language::Kotlin)),
        AnalyzerConfig::default(),
    )
    .expect("ephemeral workspace should build");
    (temp, workspace)
}

/// The completion and row count of a kind selection under scan and indexed
/// access, which must agree.
fn select_kind(workspace: &WorkspaceAnalyzer, kind: &str) -> (CodeQueryCompletion, usize) {
    let query = CodeQuery::from_json(&json!({
        "languages": ["kotlin"],
        "match": { "kind": kind },
    }))
    .expect("kind query");
    let [scan, indexed] = [
        StructuralAccessMode::ScanOnly,
        StructuralAccessMode::IndexedRequired,
    ]
    .map(|mode| {
        let result = execute_code_query_with_access_mode(
            workspace.analyzer(),
            &query,
            CodeQueryExecutionLimits::default(),
            mode,
            false,
        )
        .unwrap_or_else(|_| panic!("{mode:?} access"))
        .result;
        (result.completion(), result.results.len())
    });
    assert_eq!(scan, indexed, "`{kind}` must not depend on the access path");
    scan
}

#[test]
#[hardwon("#3777: syntax recovery that removes a selected node must not report complete")]
fn a_region_inside_a_callable_leaves_a_statement_selection_incomplete() {
    // The ERROR region `if c return true else` swallows the `if`.
    let (_temp, workspace) = kotlin_workspace(
        "fun f(c: Boolean): Boolean {\n    if c return true else return false\n}\n",
    );
    assert_eq!(
        select_kind(&workspace, "if"),
        (
            CodeQueryCompletion::Incomplete {
                codes: vec![CodeQueryDiagnosticCode::RecoveredSyntaxIncomplete],
            },
            0
        )
    );
}

#[test]
#[hardwon("#3777: recovery gaps must stay scoped to the affected structural axis")]
fn a_region_outside_every_callable_hides_expressions_but_not_statements() {
    // The only region is the `+` of a class-body initializer.
    let (_temp, workspace) = kotlin_workspace(
        "class A {\n    val x: Int = 1 +\n}\n\nfun f(c: Boolean): Boolean {\n    if (c) return true\n    return false\n}\n",
    );
    assert_eq!(
        select_kind(&workspace, "if"),
        (CodeQueryCompletion::Complete, 1)
    );
    // An initializer holds expressions, so a literal selection is incomplete
    // and still returns the literals the file does have.
    let (completion, rows) = select_kind(&workspace, "literal");
    assert_eq!(
        completion,
        CodeQueryCompletion::Incomplete {
            codes: vec![CodeQueryDiagnosticCode::RecoveredSyntaxIncomplete],
        }
    );
    assert!(rows > 0);
}

#[test]
#[hardwon("#3777: candidate-only indexing must visit files whose recovery could hide a match")]
fn a_ready_index_still_reports_a_file_whose_recovery_may_hide_the_selection() {
    // Once the snapshot index is ready, a query with explicit languages and
    // no path globs visits only the files that have candidate postings. The
    // swallowed `if` has no posting, so the file has to be visited for its
    // recovered regions instead.
    let (_temp, workspace) = kotlin_workspace(
        "fun f(c: Boolean): Boolean {\n    if c return true else return false\n}\n",
    );
    let query = CodeQuery::from_json(&json!({
        "languages": ["kotlin"],
        "match": { "kind": "if" },
    }))
    .expect("if query");
    for run in ["builds the index", "reuses the ready index"] {
        let detailed = execute_code_query_with_access_mode(
            workspace.analyzer(),
            &query,
            CodeQueryExecutionLimits::default(),
            StructuralAccessMode::IndexedRequired,
            true,
        )
        .expect("indexed access");
        assert_eq!(
            detailed.result.completion(),
            CodeQueryCompletion::Incomplete {
                codes: vec![CodeQueryDiagnosticCode::RecoveredSyntaxIncomplete],
            },
            "{run}: {:?}",
            detailed.result.diagnostics
        );
        if run == "reuses the ready index" {
            let access = &detailed.profile.expect("profile").access_path;
            assert_eq!(access.index_hits, 1, "{run}: {access:?}");
        }
    }
}

#[test]
fn syntax_error_facts_are_selectable_without_recovered_syntax_incomplete() {
    let (_temp, workspace) = kotlin_workspace(
        "fun broken(c: Boolean): Boolean {\n    if c return true else return false\n}\n",
    );
    let (completion, rows) = select_kind(&workspace, "syntax_error");

    assert_eq!(completion, CodeQueryCompletion::Complete);
    assert!(
        rows > 0,
        "a recovered parser span must be a syntax_error fact"
    );
}
