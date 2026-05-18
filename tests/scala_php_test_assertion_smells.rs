use brokk_analyzer::code_quality::{ReportTestAssertionSmellsParams, report_test_assertion_smells};
use brokk_analyzer::{IAnalyzer, Language, PhpAnalyzer, ScalaAnalyzer};

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
        Language::Scala => {
            let analyzer = ScalaAnalyzer::from_project(project.project().clone());
            report_test_assertion_smells(&analyzer as &dyn IAnalyzer, params).report
        }
        Language::Php => {
            let analyzer = PhpAnalyzer::from_project(project.project().clone());
            report_test_assertion_smells(&analyzer as &dyn IAnalyzer, params).report
        }
        _ => panic!("unsupported language"),
    }
}

#[test]
fn scala_flags_constant_equality() {
    let report = language_report(
        Language::Scala,
        "SampleSpec.scala",
        r#"
import org.scalatest.wordspec.AnyWordSpec

class SampleSpec extends AnyWordSpec {
  "sample" should "flag constants" in {
    1 shouldBe 1
  }
}
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["SampleSpec.scala".to_string()],
            ..Default::default()
        },
    );

    assert!(report.contains("constant-equality"), "{report}");
}

#[test]
fn scala_throws_counts_as_assertion_equivalent() {
    let report = language_report(
        Language::Scala,
        "SampleSpec.scala",
        r#"
import org.scalatest.wordspec.AnyWordSpec

class SampleSpec extends AnyWordSpec {
  "sample" should "throw" in {
    assertThrows[IllegalArgumentException] {
      throw new IllegalArgumentException("boom")
    }
  }
}
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["SampleSpec.scala".to_string()],
            ..Default::default()
        },
    );

    assert_eq!("No test assertion smells met minScore 4.", report);
}

#[test]
fn php_flags_constant_equality() {
    let report = language_report(
        Language::Php,
        "SampleTest.php",
        r#"
<?php

use PHPUnit\Framework\TestCase;

final class SampleTest extends TestCase
{
    public function testConstants(): void
    {
        $this->assertSame(1, 1);
    }
}
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["SampleTest.php".to_string()],
            ..Default::default()
        },
    );

    assert!(report.contains("constant-equality"), "{report}");
}

#[test]
fn php_expect_exception_counts_as_assertion_equivalent() {
    let report = language_report(
        Language::Php,
        "SampleTest.php",
        r#"
<?php

use PHPUnit\Framework\TestCase;

final class SampleTest extends TestCase
{
    public function testException(): void
    {
        $this->expectException(RuntimeException::class);
        throw new RuntimeException("boom");
    }
}
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["SampleTest.php".to_string()],
            ..Default::default()
        },
    );

    assert_eq!("No test assertion smells met minScore 4.", report);
}
