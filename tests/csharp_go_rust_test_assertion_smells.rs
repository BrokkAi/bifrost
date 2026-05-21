use brokk_bifrost::code_quality::{ReportTestAssertionSmellsParams, report_test_assertion_smells};
use brokk_bifrost::{CSharpAnalyzer, GoAnalyzer, IAnalyzer, Language, RustAnalyzer};

mod common;

use common::InlineTestProject;

fn finding_rows(report: &str) -> Vec<&str> {
    report
        .lines()
        .filter(|line| {
            line.starts_with("| ")
                && !line.starts_with("| Score |")
                && !line.starts_with("|------:")
        })
        .collect()
}

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
fn csharp_flags_self_comparison_assertion() {
    let report = language_report(
        Language::CSharp,
        "SampleTests.cs",
        r#"
using Xunit;

public class SampleTests {
    [Fact]
    public void SameValue() {
        var value = "x";
        Assert.Equal(value, value);
    }
}
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["SampleTests.cs".to_string()],
            ..Default::default()
        },
    );

    assert!(report.contains("self-comparison"), "{report}");
}

#[test]
fn csharp_no_assertions_is_reported() {
    let report = language_report(
        Language::CSharp,
        "SampleTests.cs",
        r#"
using Xunit;

public class SampleTests {
    [Fact]
    public void NoAssertions() {
        var value = 42;
        _ = value;
    }
}
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["SampleTests.cs".to_string()],
            ..Default::default()
        },
    );

    assert!(report.contains("no-assertions"), "{report}");
}

#[test]
fn csharp_nullness_only_is_shallow() {
    let report = language_report(
        Language::CSharp,
        "SampleTests.cs",
        r#"
using Xunit;

public class SampleTests {
    [Fact]
    public void NullnessOnly() {
        object value = new();
        Assert.NotNull(value);
    }
}
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["SampleTests.cs".to_string()],
            min_score: 2,
            ..Default::default()
        },
    );

    assert!(report.contains("nullness-only"), "{report}");
    assert!(report.contains("shallow-assertions-only"), "{report}");
}

#[test]
fn csharp_meaningful_assertion_is_not_flagged() {
    let report = language_report(
        Language::CSharp,
        "SampleTests.cs",
        r#"
using Xunit;

public class SampleTests {
    [Fact]
    public void Meaningful() {
        var result = Name();
        Assert.Equal("expected", result);
    }

    private static string Name() => "expected";
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
fn csharp_non_test_file_is_skipped() {
    let report = language_report(
        Language::CSharp,
        "src/Sample.cs",
        r#"
namespace Example;

public class Sample {
    public void LooksLikeAssertion() {
        Assert.Equal(1, 1);
    }
}
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["src/Sample.cs".to_string()],
            ..Default::default()
        },
    );

    assert_eq!("No test assertion smells met minScore 4.", report);
}

#[test]
fn csharp_weight_tuning_can_suppress_findings() {
    let source = r#"
using Xunit;

public class SampleTests {
    [Fact]
    public void Constant() {
        Assert.True(true);
    }
}
"#;
    let defaults = language_report(
        Language::CSharp,
        "SampleTests.cs",
        source,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["SampleTests.cs".to_string()],
            ..Default::default()
        },
    );
    let tuned = language_report(
        Language::CSharp,
        "SampleTests.cs",
        source,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["SampleTests.cs".to_string()],
            no_assertion_weight: 0,
            tautological_assertion_weight: 0,
            constant_truth_weight: 0,
            constant_equality_weight: 0,
            nullness_only_weight: 0,
            shallow_assertion_only_weight: 0,
            overspecified_literal_weight: 0,
            anonymous_test_double_weight: 0,
            repeated_anonymous_test_double_weight: 0,
            meaningful_assertion_credit: 10,
            meaningful_assertion_credit_cap: 4,
            ..Default::default()
        },
    );

    assert!(defaults.contains("constant-truth"), "{defaults}");
    assert_eq!("No test assertion smells met minScore 4.", tuned);
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
fn go_meaningful_branch_does_not_trigger_no_assertions() {
    let report = language_report(
        Language::Go,
        "pkg/sample_test.go",
        r#"
package sample
import "testing"

func TestMeaningful(t *testing.T) {
    got := "value"
    want := "other"
    if got != want {
        t.Errorf("got %s, want %s", got, want)
    }
}
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["pkg/sample_test.go".to_string()],
            ..Default::default()
        },
    );

    assert!(!report.contains("no-assertions"), "{report}");
}

#[test]
fn go_assertion_count_includes_non_smelly_assertions() {
    let report = language_report(
        Language::Go,
        "pkg/sample_test.go",
        r#"
package sample
import "testing"

func TestMixed(t *testing.T) {
    got := "value"
    want := "other"
    if true == true {
        t.Errorf("tautology")
    }
    if got != want {
        t.Errorf("got %s, want %s", got, want)
    }
}
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["pkg/sample_test.go".to_string()],
            min_score: 4,
            ..Default::default()
        },
    );
    let rows = finding_rows(&report);
    assert_eq!(rows.len(), 1, "{report}");
    assert!(rows[0].contains("`constant-equality`"), "{report}");
    assert!(rows[0].contains("| 2 |"), "{report}");
}

#[test]
fn go_shallow_only_is_not_emitted_when_mixed_with_meaningful_branch() {
    let report = language_report(
        Language::Go,
        "pkg/sample_test.go",
        r#"
package sample
import "testing"

func TestMixedShallowAndMeaningful(t *testing.T) {
    var got *int
    want := "expected"
    actual := "actual"
    if got == nil {
        t.Errorf("got nil")
    }
    if actual != want {
        t.Errorf("want %s, got %s", want, actual)
    }
}
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["pkg/sample_test.go".to_string()],
            min_score: 2,
            ..Default::default()
        },
    );

    assert!(report.contains("nullness-only"), "{report}");
    assert!(!report.contains("shallow-assertions-only"), "{report}");
}

#[test]
fn go_no_assertions_is_reported_when_no_assertion_like_branch_exists() {
    let report = language_report(
        Language::Go,
        "pkg/sample_test.go",
        r#"
package sample
import "testing"

func TestNoAssertionLikeBranch(t *testing.T) {
    value := 42
    _ = value
}
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["pkg/sample_test.go".to_string()],
            ..Default::default()
        },
    );

    assert!(report.contains("no-assertions"), "{report}");
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
fn rust_assertion_count_uses_total_recognized_macros() {
    let literal = "a".repeat(120);
    let source = format!(
        r#"
#[test]
fn mixed_assertions() {{
    let expected = String::from("expected");
    let actual = String::from("actual");
    assert_eq!("{literal}", actual);
    assert_eq!(actual, expected);
}}
"#
    );
    let report = language_report(
        Language::Rust,
        "src/lib.rs",
        &source,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["src/lib.rs".to_string()],
            min_score: 2,
            ..Default::default()
        },
    );
    let rows = finding_rows(&report);
    assert_eq!(rows.len(), 1, "{report}");
    assert!(rows[0].contains("`overspecified-literal`"), "{report}");
    assert!(rows[0].contains("| 2 |"), "{report}");
}

#[test]
fn rust_meaningful_assertion_does_not_trigger_no_assertions() {
    let report = language_report(
        Language::Rust,
        "src/lib.rs",
        r#"
#[test]
fn meaningful_assert() {
    let expected = String::from("x");
    let actual = String::from("x");
    assert_eq!(actual, expected);
}
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["src/lib.rs".to_string()],
            ..Default::default()
        },
    );

    assert!(!report.contains("no-assertions"), "{report}");
}

#[test]
fn rust_shallow_only_not_emitted_when_mixed_with_meaningful_macro() {
    let literal = "a".repeat(120);
    let source = format!(
        r#"
#[test]
fn mixed_shallow_and_meaningful() {{
    let expected = String::from("x");
    let actual = String::from("y");
    assert_eq!("{literal}", actual);
    assert_eq!(actual, expected);
}}
"#
    );
    let report = language_report(
        Language::Rust,
        "src/lib.rs",
        &source,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["src/lib.rs".to_string()],
            min_score: 2,
            ..Default::default()
        },
    );

    assert!(report.contains("overspecified-literal"), "{report}");
    assert!(!report.contains("shallow-assertions-only"), "{report}");
}

#[test]
fn rust_cfg_test_alone_does_not_mark_helper_function_as_test() {
    let report = language_report(
        Language::Rust,
        "src/lib.rs",
        r#"
#[cfg(test)]
mod tests {
    fn helper_like_test_name() {
        assert_eq!(1, 1);
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

#[test]
fn rust_direct_test_attribute_enables_smell_detection() {
    let literal = "a".repeat(120);
    let source = format!(
        r#"
#[test]
fn constant_assertion() {{
    assert_eq!("{literal}", actual());
}}

fn actual() -> String {{
    String::from("x")
}}
"#
    );
    let report = language_report(
        Language::Rust,
        "src/lib.rs",
        &source,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["src/lib.rs".to_string()],
            min_score: 2,
            ..Default::default()
        },
    );

    assert!(report.contains("overspecified-literal"), "{report}");
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
