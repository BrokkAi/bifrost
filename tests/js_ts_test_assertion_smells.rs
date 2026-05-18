use brokk_analyzer::code_quality::{ReportTestAssertionSmellsParams, report_test_assertion_smells};
use brokk_analyzer::{IAnalyzer, JavascriptAnalyzer, Language, TypescriptAnalyzer};

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

fn js_or_ts_report(
    language: Language,
    path: &str,
    source: &str,
    params: ReportTestAssertionSmellsParams,
) -> String {
    let project = InlineTestProject::with_language(language)
        .file(path, source)
        .build();
    let report = match language {
        Language::JavaScript => {
            let analyzer = JavascriptAnalyzer::from_project(project.project().clone());
            report_test_assertion_smells(&analyzer as &dyn IAnalyzer, params)
        }
        Language::TypeScript => {
            let analyzer = TypescriptAnalyzer::from_project(project.project().clone());
            report_test_assertion_smells(&analyzer as &dyn IAnalyzer, params)
        }
        _ => panic!("unsupported language"),
    };
    report.report
}

#[test]
fn javascript_flags_constant_equality_and_truth() {
    let report = js_or_ts_report(
        Language::JavaScript,
        "sample.test.js",
        r#"
        test("constants", () => {
            expect(1).toBe(1);
            expect(true).toBeTruthy();
        });
        "#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["sample.test.js".to_string()],
            ..Default::default()
        },
    );

    let rows = finding_rows(&report);
    assert_eq!(rows.len(), 2, "{report}");
    assert!(rows[0].contains("`constant-equality`"), "{report}");
    assert!(rows[1].contains("`constant-truth`"), "{report}");
}

#[test]
fn javascript_verify_counts_as_assertion_equivalent() {
    let report = js_or_ts_report(
        Language::JavaScript,
        "sample.test.js",
        r#"
        test("verify", () => {
            const spy = { fn: jest.fn() };
            spy.fn("value");
            expect(spy.fn).toHaveBeenCalledWith("value");
        });
        "#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["sample.test.js".to_string()],
            ..Default::default()
        },
    );

    assert_eq!("No test assertion smells met minScore 4.", report);
}

#[test]
fn javascript_no_assertions_is_reported() {
    let report = js_or_ts_report(
        Language::JavaScript,
        "sample.test.js",
        r#"
        test("no assertions", () => {
            runThing();
        });
        "#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["sample.test.js".to_string()],
            ..Default::default()
        },
    );

    assert!(report.contains("no-assertions"), "{report}");
}

#[test]
fn typescript_self_comparison_is_reported() {
    let report = js_or_ts_report(
        Language::TypeScript,
        "sample.test.ts",
        r#"
        test("same value", () => {
            const value = "x";
            expect(value).toEqual(value);
        });
        "#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["sample.test.ts".to_string()],
            ..Default::default()
        },
    );

    assert!(report.contains("self-comparison"), "{report}");
}

#[test]
fn typescript_shallow_assertions_are_reported_at_lower_threshold() {
    let report = js_or_ts_report(
        Language::TypeScript,
        "sample.test.ts",
        r#"
        test("shallow", () => {
            const value = getValue();
            expect(value).toBeDefined();
        });
        "#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["sample.test.ts".to_string()],
            min_score: 2,
            ..Default::default()
        },
    );

    assert!(report.contains("nullness-only"), "{report}");
    assert!(report.contains("shallow-assertions-only"), "{report}");
}
