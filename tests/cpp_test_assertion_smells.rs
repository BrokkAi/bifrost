use brokk_bifrost::code_quality::{ReportTestAssertionSmellsParams, report_test_assertion_smells};
use brokk_bifrost::{CppAnalyzer, IAnalyzer, Language};

mod common;

use common::InlineTestProject;

fn cpp_report(path: &str, source: &str, params: ReportTestAssertionSmellsParams) -> String {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(path, source)
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    report_test_assertion_smells(&analyzer as &dyn IAnalyzer, params).report
}

fn cpp_contains_tests(path: &str, source: &str) -> bool {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(path, source)
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    analyzer.contains_tests(&project.file(path))
}

#[test]
fn cpp_contains_tests_is_true_for_gtest_macro_in_non_test_path() {
    assert!(cpp_contains_tests(
        "src/sample.cpp",
        r#"
#include <gtest/gtest.h>

TEST(SampleTest, HasTestMarker) {
    EXPECT_TRUE(true);
}
"#,
    ));
}

#[test]
fn cpp_contains_tests_is_false_without_test_markers() {
    assert!(!cpp_contains_tests(
        "src/sample.cpp",
        r#"
int add(int a, int b) {
    return a + b;
}

void usesIdentifierNamedTEST() {
    int TEST = 1;
    (void)TEST;
}
"#,
    ));
}

#[test]
fn cpp_flags_constant_truth_and_constant_equality_in_gtest() {
    let report = cpp_report(
        "src/sample.cpp",
        r#"
#include <gtest/gtest.h>

TEST(SampleTest, SmellyAssertions) {
    EXPECT_TRUE(true);
    ASSERT_EQ(1, 1);
}
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["src/sample.cpp".to_string()],
            ..Default::default()
        },
    );

    assert!(report.contains("constant-truth"), "{report}");
    assert!(report.contains("constant-equality"), "{report}");
}

#[test]
fn cpp_flags_no_assertions_when_test_has_no_assertion_macros() {
    let report = cpp_report(
        "src/sample.cpp",
        r#"
#include <gtest/gtest.h>

TEST(SampleTest, NoAssertions) {
    int value = 42;
    value++;
}
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["src/sample.cpp".to_string()],
            ..Default::default()
        },
    );

    assert!(report.contains("no-assertions"), "{report}");
}

#[test]
fn cpp_accepts_marker_when_comment_separates_name_and_paren() {
    let report = cpp_report(
        "src/sample.cpp",
        r#"
#include <gtest/gtest.h>

TEST /* comment */ (SampleTest, NoAssertions) {
    int value = 42;
    value++;
}
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["src/sample.cpp".to_string()],
            ..Default::default()
        },
    );

    assert!(report.contains("no-assertions"), "{report}");
}

#[test]
fn cpp_flags_no_assertions_for_catch2_test_case() {
    let report = cpp_report(
        "src/sample.cpp",
        r#"
TEST_CASE("NoAssertions") {
    int value = 42;
    value++;
}
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["src/sample.cpp".to_string()],
            ..Default::default()
        },
    );

    assert!(report.contains("no-assertions"), "{report}");
}

#[test]
fn cpp_flags_no_assertions_for_catch2_scenario() {
    let report = cpp_report(
        "src/sample.cpp",
        r#"
SCENARIO("NoAssertions") {
    int value = 42;
    value++;
}
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["src/sample.cpp".to_string()],
            ..Default::default()
        },
    );

    assert!(report.contains("no-assertions"), "{report}");
}

#[test]
fn cpp_flags_no_assertions_for_boost_test_case() {
    let report = cpp_report(
        "src/sample.cpp",
        r#"
BOOST_AUTO_TEST_CASE(NoAssertions) {
    int value = 42;
    value++;
}
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["src/sample.cpp".to_string()],
            ..Default::default()
        },
    );

    assert!(report.contains("no-assertions"), "{report}");
}

#[test]
fn cpp_flags_no_assertions_for_mstest_method_inside_test_class() {
    let report = cpp_report(
        "src/sample.cpp",
        r#"
TEST_CLASS(SampleTests) {
public:
    TEST_METHOD(NoAssertions) {
        int value = 42;
        value++;
    }
};
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["src/sample.cpp".to_string()],
            ..Default::default()
        },
    );

    assert!(report.contains("no-assertions"), "{report}");
}

#[test]
fn cpp_meaningful_assertion_is_not_flagged_with_default_weights() {
    let report = cpp_report(
        "src/sample.cpp",
        r#"
#include <gtest/gtest.h>

TEST(SampleTest, Meaningful) {
    int got = compute();
    EXPECT_EQ(42, got);
}

int compute() {
    return 42;
}
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["src/sample.cpp".to_string()],
            ..Default::default()
        },
    );

    assert_eq!("No test assertion smells met minScore 4.", report);
}

#[test]
fn cpp_flags_nullness_only_and_shallow_only_for_null_checks() {
    let report = cpp_report(
        "src/sample.cpp",
        r#"
#include <gtest/gtest.h>

int* load() {
    static int value = 1;
    return &value;
}

TEST(SampleTest, NullnessOnly) {
    int* result = load();
    EXPECT_NE(result, nullptr);
}
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["src/sample.cpp".to_string()],
            min_score: 2,
            ..Default::default()
        },
    );

    assert!(report.contains("nullness-only"), "{report}");
    assert!(report.contains("shallow-assertions-only"), "{report}");
}

#[test]
fn cpp_mixed_meaningful_assertion_does_not_emit_shallow_only() {
    let report = cpp_report(
        "src/sample.cpp",
        r#"
#include <gtest/gtest.h>

int compute() {
    return 42;
}

int* load() {
    static int value = 1;
    return &value;
}

TEST(SampleTest, Mixed) {
    int* result = load();
    EXPECT_NE(result, nullptr);
    EXPECT_EQ(42, compute());
}
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["src/sample.cpp".to_string()],
            min_score: 2,
            ..Default::default()
        },
    );

    assert!(report.contains("nullness-only"), "{report}");
    assert!(!report.contains("shallow-assertions-only"), "{report}");
}

#[test]
fn cpp_ignores_standalone_macro_like_identifier_in_non_test_code() {
    let report = cpp_report(
        "src/sample.cpp",
        r#"
int TEST = 0;

void helper() {
    if (TEST > 0) {
        TEST++;
    }
}
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["src/sample.cpp".to_string()],
            ..Default::default()
        },
    );

    assert_eq!("No test assertion smells met minScore 4.", report);
}

#[test]
fn cpp_binds_marker_to_its_own_body_when_nearby_blocks_exist() {
    let report = cpp_report(
        "src/sample.cpp",
        r#"
#include <gtest/gtest.h>

void before() {
    int x = 0;
    (void)x;
}

TEST(SampleTest, BodyAssociation) {
    if (true) {
        int y = 1;
        (void)y;
    }
    EXPECT_TRUE(true);
}

void after() {
    int z = 2;
    (void)z;
}
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["src/sample.cpp".to_string()],
            ..Default::default()
        },
    );

    assert!(report.contains("constant-truth"), "{report}");
    assert!(!report.contains("no-assertions"), "{report}");
}
