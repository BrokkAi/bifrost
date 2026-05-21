use brokk_bifrost::code_quality::{ReportTestAssertionSmellsParams, report_test_assertion_smells};
use brokk_bifrost::{IAnalyzer, JavaAnalyzer, Language};
use std::fs;

mod common;

use common::InlineTestProject;

fn java_report(
    source: &str,
    params: ReportTestAssertionSmellsParams,
) -> brokk_bifrost::code_quality::ReportTestAssertionSmellsResult {
    let project = InlineTestProject::with_language(Language::Java)
        .file("com/example/SampleTest.java", source)
        .build();
    let analyzer = JavaAnalyzer::from_project(project.project().clone());
    report_test_assertion_smells(&analyzer as &dyn IAnalyzer, params)
}

fn java_report_for_files(
    files: &[(&str, &str)],
    params: ReportTestAssertionSmellsParams,
) -> brokk_bifrost::code_quality::ReportTestAssertionSmellsResult {
    let project = files
        .iter()
        .fold(
            InlineTestProject::with_language(Language::Java),
            |project, (path, contents)| project.file(*path, *contents),
        )
        .build();
    let analyzer = JavaAnalyzer::from_project(project.project().clone());
    report_test_assertion_smells(&analyzer as &dyn IAnalyzer, params)
}

fn default_params() -> ReportTestAssertionSmellsParams {
    ReportTestAssertionSmellsParams {
        file_paths: vec!["com/example/SampleTest.java".to_string()],
        ..Default::default()
    }
}

fn assert_has_reason(report: &str, reason: &str) {
    assert!(report.contains(reason), "{report}");
}

fn assert_lacks_reason(report: &str, reason: &str) {
    assert!(!report.contains(reason), "{report}");
}

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

#[test]
fn flags_self_comparison_assertion() {
    let report = java_report(
        r#"
        package com.example;
        import org.junit.jupiter.api.Test;
        import static org.junit.jupiter.api.Assertions.assertEquals;

        public class SampleTest {
            @Test
            void sameValue() {
                String value = "x";
                assertEquals(value, value);
            }
        }
        "#,
        default_params(),
    )
    .report;

    assert_has_reason(&report, "self-comparison");
}

#[test]
fn flags_constant_truth_and_constant_equality() {
    let report = java_report(
        r#"
        package com.example;
        import org.junit.jupiter.api.Test;
        import static org.junit.jupiter.api.Assertions.assertEquals;
        import static org.junit.jupiter.api.Assertions.assertTrue;

        public class SampleTest {
            @Test
            void constants() {
                assertTrue(true);
                assertEquals(1, 1);
            }
        }
        "#,
        ReportTestAssertionSmellsParams {
            min_score: 4,
            ..default_params()
        },
    )
    .report;

    assert_has_reason(&report, "constant-truth");
    assert_has_reason(&report, "constant-equality");
}

#[test]
fn flags_test_method_with_no_assertions() {
    let report = java_report(
        r#"
        package com.example;
        import org.junit.jupiter.api.Test;

        public class SampleTest {
            @Test
            void noAssertions() {
                new Service().run();
            }
            static class Service {
                void run() {}
            }
        }
        "#,
        default_params(),
    )
    .report;

    assert_has_reason(&report, "no-assertions");
}

#[test]
fn meaningful_assertion_is_not_flagged_with_default_weights() {
    let report = java_report(
        r#"
        package com.example;
        import org.junit.jupiter.api.Test;
        import static org.junit.jupiter.api.Assertions.assertEquals;

        public class SampleTest {
            @Test
            void meaningful() {
                Result result = new Result("expected");
                assertEquals("expected", result.name());
            }
            record Result(String name) {}
        }
        "#,
        default_params(),
    )
    .report;

    assert_eq!("No test assertion smells met minScore 4.", report);
}

#[test]
fn flags_nullness_only_and_shallow_assertions() {
    let report = java_report(
        r#"
        package com.example;
        import org.junit.jupiter.api.Test;
        import static org.junit.jupiter.api.Assertions.assertNotNull;

        public class SampleTest {
            @Test
            void shallow() {
                Object result = new Object();
                assertNotNull(result);
            }
        }
        "#,
        ReportTestAssertionSmellsParams {
            min_score: 2,
            ..default_params()
        },
    )
    .report;

    assert_has_reason(&report, "nullness-only");
    assert_has_reason(&report, "shallow-assertions-only");
}

#[test]
fn flags_anonymous_test_double() {
    let report = java_report(
        r#"
        package com.example;
        import org.junit.jupiter.api.Test;
        import static org.junit.jupiter.api.Assertions.assertEquals;

        public class SampleTest {
            interface Clock {
                long now();
            }

            @Test
            void anonymousDouble() {
                Clock clock = new Clock() {
                    @Override
                    public long now() {
                        return 42;
                    }
                };
                assertEquals(42, clock.now());
            }
        }
        "#,
        ReportTestAssertionSmellsParams {
            min_score: 3,
            ..default_params()
        },
    )
    .report;

    assert_has_reason(&report, "anonymous-test-double");
}

#[test]
fn repeated_anonymous_test_doubles_score_higher_and_show_reusable_reason() {
    let report = java_report(
        r#"
        package com.example;
        import org.junit.jupiter.api.Test;
        import static org.junit.jupiter.api.Assertions.assertEquals;

        public class SampleTest {
            interface Clock {
                long now();
            }

            @Test
            void first() {
                Clock clock = new Clock() {
                    @Override
                    public long now() {
                        return 42;
                    }
                };
                assertEquals(42, clock.now());
            }

            @Test
            void second() {
                Clock clock = new Clock() {
                    @Override
                    public long now() {
                        return 43;
                    }
                };
                assertEquals(43, clock.now());
            }
        }
        "#,
        default_params(),
    )
    .report;

    let rows = finding_rows(&report);
    assert_eq!(rows.len(), 2, "{report}");
    assert!(
        rows.iter()
            .all(|row| row.contains("| 5 | `anonymous-test-double` | 0 |")),
        "{report}"
    );
    assert!(
        rows.iter()
            .all(|row| row.contains("anonymous-test-double, reusable-test-double-candidate")),
        "{report}"
    );
}

#[test]
fn non_test_java_file_is_skipped() {
    let report = java_report(
        r#"
        package com.example;
        public class Sample {
            void assertLookingName() {
                assertEquals(1, 1);
            }
            void assertEquals(int expected, int actual) {}
        }
        "#,
        default_params(),
    )
    .report;

    assert_eq!("No test assertion smells met minScore 4.", report);
}

#[test]
fn weight_tuning_can_suppress_findings() {
    let source = r#"
        package com.example;
        import org.junit.jupiter.api.Test;
        import static org.junit.jupiter.api.Assertions.assertTrue;

        public class SampleTest {
            @Test
            void constant() {
                assertTrue(true);
            }
        }
    "#;

    let defaults = java_report(source, default_params()).report;
    let tuned = java_report(
        source,
        ReportTestAssertionSmellsParams {
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
            ..default_params()
        },
    )
    .report;

    assert_has_reason(&defaults, "constant-truth");
    assert_eq!("No test assertion smells met minScore 4.", tuned);
}

#[test]
fn flags_assertj_tautologies_and_constants() {
    let report = java_report(
        r#"
        package com.example;
        import org.junit.jupiter.api.Test;
        import static org.assertj.core.api.Assertions.assertThat;

        public class SampleTest {
            @Test
            void assertj() {
                String value = "x";
                assertThat(value).isEqualTo(value);
                assertThat(true).isTrue();
            }
        }
        "#,
        default_params(),
    )
    .report;

    assert_has_reason(&report, "self-comparison");
    assert_has_reason(&report, "constant-truth");
}

#[test]
fn mockito_verify_counts_as_assertion_equivalent() {
    let report = java_report(
        r#"
        package com.example;
        import org.junit.jupiter.api.Test;
        import static org.mockito.Mockito.mock;
        import static org.mockito.Mockito.verify;

        public class SampleTest {
            interface Sink {
                void send(String value);
            }

            @Test
            void verifiesInteraction() {
                Sink sink = mock(Sink.class);
                sink.send("value");
                verify(sink).send("value");
            }
        }
        "#,
        default_params(),
    )
    .report;

    assert_eq!("No test assertion smells met minScore 4.", report);
}

#[test]
fn flags_overspecified_large_literal() {
    let literal = "a".repeat(120);
    let source = format!(
        r#"
        package com.example;
        import org.junit.jupiter.api.Test;
        import static org.junit.jupiter.api.Assertions.assertEquals;

        public class SampleTest {{
            @Test
            void largeLiteral() {{
                assertEquals("{literal}", result());
            }}

            String result() {{
                return "";
            }}
        }}
        "#
    );

    let report = java_report(
        &source,
        ReportTestAssertionSmellsParams {
            min_score: 2,
            ..default_params()
        },
    )
    .report;

    assert_has_reason(&report, "overspecified-literal");
}

#[test]
fn assert_throws_counts_as_assertion_equivalent() {
    let report = java_report(
        r#"
        package com.example;
        import org.junit.jupiter.api.Test;
        import static org.junit.jupiter.api.Assertions.assertThrows;

        public class SampleTest {
            @Test
            void throwsMeaningfully() {
                assertThrows(IllegalArgumentException.class, () -> {
                    throw new IllegalArgumentException("boom");
                });
            }
        }
        "#,
        default_params(),
    )
    .report;

    assert_eq!("No test assertion smells met minScore 4.", report);
}

#[test]
fn junit_trailing_message_does_not_hide_expected_and_actual() {
    let report = java_report(
        r#"
        package com.example;
        import org.junit.jupiter.api.Test;
        import static org.junit.jupiter.api.Assertions.assertEquals;

        public class SampleTest {
            @Test
            void trailingMessage() {
                assertEquals("expected", "expected", "message");
            }
        }
        "#,
        default_params(),
    )
    .report;

    assert_has_reason(&report, "constant-equality");
}

#[test]
fn equal_score_findings_sort_by_assertion_kind_before_source_position() {
    let report = java_report(
        r#"
        package com.example;
        import org.junit.jupiter.api.Test;
        import static org.junit.jupiter.api.Assertions.assertEquals;
        import static org.junit.jupiter.api.Assertions.assertTrue;

        public class SampleTest {
            @Test
            void orderedByKind() {
                assertTrue(true);
                assertEquals(1, 1);
            }
        }
        "#,
        default_params(),
    )
    .report;

    let rows = finding_rows(&report);
    assert_eq!(rows.len(), 2, "{report}");
    assert!(rows[0].contains("`constant-equality`"), "{report}");
    assert!(rows[1].contains("`constant-truth`"), "{report}");
}

#[test]
fn assertj_chained_extraction_counts_as_assertion_equivalent() {
    let report = java_report(
        r#"
        package com.example;
        import org.junit.jupiter.api.Test;
        import static org.assertj.core.api.Assertions.assertThat;

        public class SampleTest {
            @Test
            void chainedAssertJ() {
                Result result = new Result("expected");
                assertThat(result).extracting(Result::name).isEqualTo("expected");
            }
            record Result(String name) {}
        }
        "#,
        default_params(),
    )
    .report;

    assert_eq!("No test assertion smells met minScore 4.", report);
}

#[test]
fn direct_tests_render_report_paths_realistically() {
    let report = java_report(
        r#"
        package com.example;
        import org.junit.jupiter.api.Test;
        import static org.junit.jupiter.api.Assertions.assertEquals;

        public class SampleTest {
            @Test
            void sameValue() {
                String value = "x";
                assertEquals(value, value);
            }
        }
        "#,
        default_params(),
    )
    .report;

    assert_has_reason(&report, "com/example/SampleTest.java");
    assert_lacks_reason(&report, "tests/fixtures/testcode-java");
}

#[test]
fn traversal_paths_are_rejected_without_reading_outside_workspace() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "com/example/SampleTest.java",
            r#"
            package com.example;
            import org.junit.jupiter.api.Test;
            import static org.junit.jupiter.api.Assertions.assertEquals;

            public class SampleTest {
                @Test
                void sameValue() {
                    String value = "x";
                    assertEquals(value, value);
                }
            }
            "#,
        )
        .build();
    let outside = project
        .root()
        .parent()
        .expect("inline project root has parent")
        .join("LeakTest.java");
    fs::write(
        &outside,
        r#"
        import org.junit.jupiter.api.Test;
        import static org.junit.jupiter.api.Assertions.assertEquals;

        public class LeakTest {
            @Test
            void leaked() {
                assertEquals(1, 1);
            }
        }
        "#,
    )
    .expect("write outside fixture");

    let analyzer = JavaAnalyzer::from_project(project.project().clone());
    let result = report_test_assertion_smells(
        &analyzer as &dyn IAnalyzer,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["../LeakTest.java".to_string()],
            ..Default::default()
        },
    );

    assert_eq!(
        "No test assertion smells met minScore 4.", result.report,
        "{}",
        result.report
    );
}

#[test]
fn multi_file_projects_can_target_a_single_test_file() {
    let report = java_report_for_files(
        &[
            (
                "com/example/SampleTest.java",
                r#"
                package com.example;
                import org.junit.jupiter.api.Test;
                import static org.junit.jupiter.api.Assertions.assertEquals;

                public class SampleTest {
                    @Test
                    void sameValue() {
                        String value = "x";
                        assertEquals(value, value);
                    }
                }
                "#,
            ),
            (
                "com/example/Helper.java",
                r#"
                package com.example;
                public class Helper {
                    String value() { return "ok"; }
                }
                "#,
            ),
        ],
        default_params(),
    )
    .report;

    assert_has_reason(&report, "self-comparison");
}
