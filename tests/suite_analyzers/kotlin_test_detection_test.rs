//! Kotlin test detection (issue #1243): JUnit4/5 and kotlin.test annotations,
//! Kotest spec-class supertypes, Kotest/Spek DSL block forms, and the plain
//! non-test negative case. Mirrors `scala_test_detection_test.rs`'s shape.

use crate::common::InlineTestProject;
use brokk_bifrost::{IAnalyzer, KotlinAnalyzer, Language};

fn kotlin_analyzer(
    files: &[(&str, &str)],
) -> (crate::common::BuiltInlineTestProject, KotlinAnalyzer) {
    let mut project = InlineTestProject::with_language(Language::Kotlin);
    for (path, contents) in files {
        project = project.file(*path, *contents);
    }
    let built = project.build();
    let analyzer = KotlinAnalyzer::new(built.project_dyn());
    (built, analyzer)
}

#[test]
fn detects_junit_test_annotation() {
    let (built, analyzer) = kotlin_analyzer(&[(
        "Example.kt",
        r#"
        package example

        import org.junit.jupiter.api.Test

        class Example {
            @Test
            fun itWorks() {
                check(1 + 1 == 2)
            }
        }
        "#,
    )]);
    let file = built.file("Example.kt");
    assert!(analyzer.contains_tests(&file));
}

#[test]
fn detects_kotlin_test_annotation() {
    let (built, analyzer) = kotlin_analyzer(&[(
        "Example.kt",
        r#"
        package example

        import kotlin.test.Test
        import kotlin.test.assertEquals

        class Example {
            @Test
            fun itWorks() {
                assertEquals(2, 1 + 1)
            }
        }
        "#,
    )]);
    let file = built.file("Example.kt");
    assert!(analyzer.contains_tests(&file));
}

#[test]
fn detects_kotest_spec_supertype_form() {
    let (built, analyzer) = kotlin_analyzer(&[(
        "Example.kt",
        r#"
        package example

        class ExampleSpec : StringSpec({
            "adds two numbers" {
                check(1 + 1 == 2)
            }
        })
        "#,
    )]);
    let file = built.file("Example.kt");
    assert!(analyzer.contains_tests(&file));
}

#[test]
fn detects_kotest_dsl_call_form() {
    let (built, analyzer) = kotlin_analyzer(&[(
        "Example.kt",
        r#"
        package example

        class Example {
            init {
                test("adds two numbers") {
                    check(1 + 1 == 2)
                }
            }
        }
        "#,
    )]);
    let file = built.file("Example.kt");
    assert!(analyzer.contains_tests(&file));
}

#[test]
fn detects_kotest_should_block_form() {
    let (built, analyzer) = kotlin_analyzer(&[(
        "Example.kt",
        r#"
        package example

        class Example {
            init {
                "adds two numbers" should {
                    check(1 + 1 == 2)
                }
            }
        }
        "#,
    )]);
    let file = built.file("Example.kt");
    assert!(analyzer.contains_tests(&file));
}

#[test]
fn negative_case_no_markers() {
    let (built, analyzer) = kotlin_analyzer(&[(
        "Example.kt",
        r#"
        package example

        class Example {
            fun add(
                a: Int,
                b: Int,
            ): Int {
                return a + b
            }
        }
        "#,
    )]);
    let file = built.file("Example.kt");
    assert!(!analyzer.contains_tests(&file));
}
