use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::TreeSitterAnalyzer;
use brokk_bifrost_analysis::analyzer::{Language, TestProject};
use brokk_bifrost_jvm_analysis::analyzer::java::adapter::JavaAdapter;
use std::sync::Arc;

#[test]
fn identifier_lookup_does_not_inspect_past_the_row_budget() {
    let temp = tempfile::tempdir().expect("temporary workspace");
    let root = temp.path().canonicalize().expect("absolute workspace root");
    std::fs::write(root.join("A.java"), "package demo; class Twin {}\n")
        .expect("write first declaration");
    std::fs::write(root.join("B.java"), "package other; class Twin {}\n")
        .expect("write second declaration");
    let project = Arc::new(TestProject::new(&root, Language::Java));
    let analyzer = TreeSitterAnalyzer::new(project, JavaAdapter);

    let result = analyzer.lookup_declarations_by_identifier_limited("Twin", 1, || true);
    assert!(!result.complete);
    assert_eq!(result.inspected, 1);
    assert!(result.inspected <= 1);
}

#[test]
fn incomplete_exact_member_lookup_does_not_fall_through_to_normalized_rows() {
    let temp = tempfile::tempdir().expect("temporary workspace");
    let root = temp.path().canonicalize().expect("absolute workspace root");
    std::fs::write(
        root.join("Outer.java"),
        "package demo; class Outer { static class Inner { void run() {} } }\n",
    )
    .expect("write nested declaration");
    let project = Arc::new(TestProject::new(&root, Language::Java));
    let analyzer = TreeSitterAnalyzer::new(project, JavaAdapter);
    let checks = std::cell::Cell::new(0);

    let result =
        analyzer.lookup_members_for_owner_name_limited("demo.Outer$Inner", "run", 10, || {
            checks.set(checks.get() + 1);
            checks.get() > 1
        });
    assert!(!result.complete);
    assert!(result.rows.is_empty());
}
