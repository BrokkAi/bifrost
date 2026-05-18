use brokk_analyzer::code_quality::{ReportTestAssertionSmellsParams, report_test_assertion_smells};
use brokk_analyzer::{CSharpAnalyzer, GoAnalyzer, IAnalyzer, Language, RustAnalyzer};

mod common;

use common::InlineTestProject;

fn language_report(
    language: Language,
    path: &str,
    source: &str,
    params: ReportTestAssertionSmellsParams,
) -> String {
    let project = InlineTestProject::with_language(language)
        .file(path, source)
        .build();
    match language {
        Language::CSharp => {
            let analyzer = CSharpAnalyzer::from_project(project.project().clone());
            report_test_assertion_smells(&analyzer as &dyn IAnalyzer, params).report
        }
        Language::Go => {
            let analyzer = GoAnalyzer::from_project(project.project().clone());
            report_test_assertion_smells(&analyzer as &dyn IAnalyzer, params).report
        }
        Language::Rust => {
            let analyzer = RustAnalyzer::from_project(project.project().clone());
            report_test_assertion_smells(&analyzer as &dyn IAnalyzer, params).report
        }
        _ => panic!("unsupported language"),
    }
}

#[test]
fn csharp_flags_constant_equality() {
    let report = language_report(
        Language::CSharp,
        "SampleTests.cs",
        r#"
using Xunit;

public class SampleTests {
    [Fact]
    public void Constants() {
        Assert.Equal(1, 1);
    }
}
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["SampleTests.cs".to_string()],
            ..Default::default()
        },
    );

    assert!(report.contains("constant-equality"), "{report}");
}

#[test]
fn csharp_verify_counts_as_assertion_equivalent() {
    let report = language_report(
        Language::CSharp,
        "SampleTests.cs",
        r#"
using Xunit;

public class SampleTests {
    [Fact]
    public void Verify() {
        mock.Verify(x => x.Run());
    }
}
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["SampleTests.cs".to_string()],
            ..Default::default()
        },
    );

    assert_eq!("No test assertion smells met minScore 4.", report);
}

#[test]
fn go_flags_constant_truth() {
    let report = language_report(
        Language::Go,
        "sample_test.go",
        r#"
package sample

import (
    "testing"
    "github.com/stretchr/testify/assert"
)

func TestTruth(t *testing.T) {
    assert.True(t, true)
}
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["sample_test.go".to_string()],
            ..Default::default()
        },
    );

    assert!(report.contains("constant-truth"), "{report}");
}

#[test]
fn go_mock_expectations_count_as_assertion_equivalent() {
    let report = language_report(
        Language::Go,
        "sample_test.go",
        r#"
package sample

import "testing"

func TestVerify(t *testing.T) {
    mock.AssertExpectations(t)
}
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["sample_test.go".to_string()],
            ..Default::default()
        },
    );

    assert_eq!("No test assertion smells met minScore 4.", report);
}

#[test]
fn rust_flags_self_comparison() {
    let report = language_report(
        Language::Rust,
        "src/lib.rs",
        r#"
#[cfg(test)]
mod tests {
    #[test]
    fn same_value() {
        let value = 1;
        assert_eq!(value, value);
    }
}
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["src/lib.rs".to_string()],
            ..Default::default()
        },
    );

    assert!(report.contains("self-comparison"), "{report}");
}

#[test]
fn rust_meaningful_matches_is_not_flagged() {
    let report = language_report(
        Language::Rust,
        "src/lib.rs",
        r#"
#[cfg(test)]
mod tests {
    #[test]
    fn meaningful() {
        assert!(matches!(Some(1), Some(_)));
    }
}
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["src/lib.rs".to_string()],
            ..Default::default()
        },
    );

    assert_eq!("No test assertion smells met minScore 4.", report);
}
