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
fn python_flags_self_comparison_assertion() {
    let report = python_report(
        r#"
def test_same_value():
    value = "x"
    assert value == value
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["test_sample.py".to_string()],
            ..Default::default()
        },
    );

    assert!(report.contains("self-comparison"), "{report}");
}

#[test]
fn python_flags_constant_truth_and_constant_equality() {
    let report = python_report(
        r#"
import unittest

class SampleTest(unittest.TestCase):
    def test_constants(self):
        assert True
        self.assertEqual(1, 1)
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["test_sample.py".to_string()],
            ..Default::default()
        },
    );

    assert!(report.contains("constant-truth"), "{report}");
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
fn python_meaningful_assertion_is_not_flagged() {
    let report = python_report(
        r#"
def test_meaningful():
    result = {"name": "expected"}
    assert result["name"] == "expected"
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["test_sample.py".to_string()],
            ..Default::default()
        },
    );

    assert_eq!("No test assertion smells met minScore 4.", report);
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

#[test]
fn non_test_python_file_is_skipped() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "pkg/module.py",
            r#"
def helper():
    assert True
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let report = report_test_assertion_smells(
        &analyzer as &dyn IAnalyzer,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["pkg/module.py".to_string()],
            ..Default::default()
        },
    )
    .report;

    assert_eq!("No test assertion smells met minScore 4.", report);
}

#[test]
fn pytest_fixture_named_like_test_is_skipped() {
    let report = python_report(
        r#"
import pytest

@pytest.fixture
def test_data():
    assert True
    return 1
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["test_sample.py".to_string()],
            ..Default::default()
        },
    );

    assert_eq!("No test assertion smells met minScore 4.", report);
}
