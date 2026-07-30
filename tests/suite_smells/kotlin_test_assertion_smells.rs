//! Kotlin test-assertion smell detection (issue #1243): a positive finding,
//! threshold suppression at the default minScore, and a negative control.
//! Mirrors `scala_php_test_assertion_smells.rs`'s shape.

use brokk_bifrost::code_quality::{ReportTestAssertionSmellsParams, report_test_assertion_smells};
use brokk_bifrost::{IAnalyzer, KotlinAnalyzer, Language};

use crate::common::InlineTestProject;

fn kotlin_report(path: &str, source: &str, params: ReportTestAssertionSmellsParams) -> String {
    let project = InlineTestProject::with_language(Language::Kotlin)
        .file(path, source)
        .build();
    let analyzer = KotlinAnalyzer::from_project(project.project().clone());
    report_test_assertion_smells(&analyzer as &dyn IAnalyzer, params).report
}

#[test]
fn kotlin_flags_self_comparison_assertion() {
    let report = kotlin_report(
        "SampleTest.kt",
        r#"
        package com.example

        import kotlin.test.assertEquals

        class SampleTest {
            init {
                test("same value") {
                    val value = "x"
                    assertEquals(value, value)
                }
            }
        }
        "#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["SampleTest.kt".to_string()],
            ..Default::default()
        },
    );

    assert!(report.contains("self-comparison"), "{report}");
}

#[test]
fn kotlin_nullness_only_is_suppressed_below_default_threshold_then_surfaces() {
    let source = r#"
    package com.example

    import kotlin.test.assertNotNull

    class SampleTest {
        init {
            test("nullness") {
                val result: Any = Any()
                assertNotNull(result)
            }
        }
    }
    "#;

    let suppressed = kotlin_report(
        "SampleTest.kt",
        source,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["SampleTest.kt".to_string()],
            ..Default::default()
        },
    );
    assert_eq!("No test assertion smells met minScore 4.", suppressed);

    let surfaced = kotlin_report(
        "SampleTest.kt",
        source,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["SampleTest.kt".to_string()],
            min_score: 2,
            ..Default::default()
        },
    );
    assert!(surfaced.contains("nullness-only"), "{surfaced}");
    assert!(surfaced.contains("shallow-assertions-only"), "{surfaced}");
}

#[test]
fn kotlin_meaningful_assertion_is_not_flagged() {
    let report = kotlin_report(
        "SampleTest.kt",
        r#"
        package com.example

        import kotlin.test.assertEquals

        class SampleTest {
            init {
                test("meaningful") {
                    val result = computeResult()
                    assertEquals("expected", result)
                }
            }

            fun computeResult(): String {
                return "expected"
            }
        }
        "#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["SampleTest.kt".to_string()],
            ..Default::default()
        },
    );

    assert_eq!("No test assertion smells met minScore 4.", report);
}
