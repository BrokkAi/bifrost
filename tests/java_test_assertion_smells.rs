use brokk_analyzer::code_quality::{ReportTestAssertionSmellsParams, report_test_assertion_smells};
use brokk_analyzer::{IAnalyzer, JavaAnalyzer, Language, TestProject};
use std::path::{Path, PathBuf};

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java")
}

#[test]
fn java_report_test_assertion_smells_flags_multiple_heuristics() {
    let analyzer = JavaAnalyzer::from_project(TestProject::new(fixture_root(), Language::Java));

    let result = report_test_assertion_smells(
        &analyzer as &dyn IAnalyzer,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["TestAssertionSmells.java".to_string()],
            min_score: 3,
            ..Default::default()
        },
    );

    assert!(
        !result.truncated,
        "unexpected truncation: {}",
        result.report
    );
    assert!(result.report.starts_with("## Test assertion smells"));
    assert!(
        result.report.contains("self-comparison"),
        "{}",
        result.report
    );
    assert!(result.report.contains("no-assertions"), "{}", result.report);
    assert!(
        result.report.contains("anonymous-test-double"),
        "{}",
        result.report
    );
    assert!(
        result.report.contains("constant-truth"),
        "{}",
        result.report
    );
    assert!(
        result.report.contains("TestAssertionSmells.java"),
        "{}",
        result.report
    );
}
