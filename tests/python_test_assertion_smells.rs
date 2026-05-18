use brokk_analyzer::code_quality::{ReportTestAssertionSmellsParams, report_test_assertion_smells};
use brokk_analyzer::{IAnalyzer, Language, PythonAnalyzer};

mod common;

use common::InlineTestProject;

fn python_report(source: &str, params: ReportTestAssertionSmellsParams) -> String {
    let project = InlineTestProject::with_language(Language::Python)
        .file("test_sample.py", source)
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    report_test_assertion_smells(&analyzer as &dyn IAnalyzer, params).report
}

#[test]
fn python_flags_constant_equality() {
    let report = python_report(
        r#"
def test_constants():
    assert 1 == 1
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["test_sample.py".to_string()],
            ..Default::default()
        },
    );

    assert!(report.contains("constant-equality"), "{report}");
}

#[test]
fn python_raises_counts_as_assertion_equivalent() {
    let report = python_report(
        r#"
import pytest

def test_raises():
    with pytest.raises(ValueError):
        raise ValueError("boom")
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["test_sample.py".to_string()],
            ..Default::default()
        },
    );

    assert_eq!("No test assertion smells met minScore 4.", report);
}

#[test]
fn python_mock_verify_counts_as_assertion_equivalent() {
    let report = python_report(
        r#"
from unittest.mock import Mock

def test_verify():
    mock = Mock()
    mock("value")
    mock.assert_called_once_with("value")
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["test_sample.py".to_string()],
            ..Default::default()
        },
    );

    assert_eq!("No test assertion smells met minScore 4.", report);
}

#[test]
fn python_no_assertions_is_reported() {
    let report = python_report(
        r#"
def test_no_assertions():
    run_thing()
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["test_sample.py".to_string()],
            ..Default::default()
        },
    );

    assert!(report.contains("no-assertions"), "{report}");
}

#[test]
fn python_shallow_assertions_are_reported_at_lower_threshold() {
    let report = python_report(
        r#"
def test_shallow():
    value = object()
    assert value is not None
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["test_sample.py".to_string()],
            min_score: 2,
            ..Default::default()
        },
    );

    assert!(report.contains("nullness-only"), "{report}");
    assert!(report.contains("shallow-assertions-only"), "{report}");
}
