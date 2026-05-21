use brokk_bifrost::code_quality::{ReportTestAssertionSmellsParams, report_test_assertion_smells};
use brokk_bifrost::{IAnalyzer, Language, PhpAnalyzer, ScalaAnalyzer};

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
fn scala_flags_self_comparison_assertion() {
    let report = language_report(
        Language::Scala,
        "com/example/SampleTest.scala",
        r#"
package com.example

import org.junit.jupiter.api.Assertions.assertEquals
import org.scalatest.funsuite.AnyFunSuite

class SampleTest extends AnyFunSuite {
  test("same value") {
    val value = "x"
    assertEquals(value, value)
  }
}
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["com/example/SampleTest.scala".to_string()],
            ..Default::default()
        },
    );

    assert!(report.contains("self-comparison"), "{report}");
}

#[test]
fn scala_flags_constant_truth_and_constant_equality() {
    let report = language_report(
        Language::Scala,
        "com/example/SampleTest.scala",
        r#"
package com.example

import org.scalatest.funsuite.AnyFunSuite

class SampleTest extends AnyFunSuite {
  test("constants") {
    assert(true)
    assert(1 == 1)
  }
}
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["com/example/SampleTest.scala".to_string()],
            ..Default::default()
        },
    );

    assert!(report.contains("constant-truth"), "{report}");
    assert!(report.contains("constant-equality"), "{report}");
}

#[test]
fn scala_no_assertions_is_reported() {
    let report = language_report(
        Language::Scala,
        "com/example/SampleTest.scala",
        r#"
package com.example

import org.scalatest.funsuite.AnyFunSuite

class SampleTest extends AnyFunSuite {
  test("no assertions") {
    helper()
  }
  def helper(): Int = 1
}
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["com/example/SampleTest.scala".to_string()],
            ..Default::default()
        },
    );

    assert!(report.contains("no-assertions"), "{report}");
}

#[test]
fn scala_meaningful_assertion_is_not_flagged() {
    let report = language_report(
        Language::Scala,
        "com/example/SampleTest.scala",
        r#"
package com.example

import org.scalatest.funsuite.AnyFunSuite

class SampleTest extends AnyFunSuite {
  test("meaningful") {
    val result = Result("expected")
    assert(result.name == "expected")
  }
}

case class Result(name: String)
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["com/example/SampleTest.scala".to_string()],
            ..Default::default()
        },
    );

    assert_eq!("No test assertion smells met minScore 4.", report);
}

#[test]
fn scala_nullness_only_is_shallow() {
    let report = language_report(
        Language::Scala,
        "com/example/SampleTest.scala",
        r#"
package com.example

import org.junit.jupiter.api.Assertions.assertNotNull
import org.scalatest.funsuite.AnyFunSuite

class SampleTest extends AnyFunSuite {
  test("nullness") {
    val result: Object = new Object()
    assertNotNull(result)
  }
}
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["com/example/SampleTest.scala".to_string()],
            min_score: 2,
            ..Default::default()
        },
    );

    assert!(report.contains("nullness-only"), "{report}");
    assert!(report.contains("shallow-assertions-only"), "{report}");
}

#[test]
fn scala_overspecified_literal_is_reported() {
    let report = language_report(
        Language::Scala,
        "com/example/SampleTest.scala",
        r#"
package com.example

import org.scalatest.funsuite.AnyFunSuite

class SampleTest extends AnyFunSuite {
  test("overspecified") {
    val result = "value"
    assert(result == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
  }
}
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["com/example/SampleTest.scala".to_string()],
            min_score: 2,
            ..Default::default()
        },
    );

    assert!(report.contains("overspecified-literal"), "{report}");
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
fn php_no_assertions_is_reported() {
    let report = language_report(
        Language::Php,
        "tests/SampleTest.php",
        r#"
<?php
class SampleTest {
    public function testNoAssertions(): void {
        $value = 42;
        $value++;
    }
}
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["tests/SampleTest.php".to_string()],
            ..Default::default()
        },
    );

    assert!(report.contains("no-assertions"), "{report}");
}

#[test]
fn php_flags_constant_truth_and_constant_equality() {
    let report = language_report(
        Language::Php,
        "tests/SampleTest.php",
        r#"
<?php
class SampleTest {
    public function testConstants(): void {
        $this->assertTrue(true);
        $this->assertEquals(1, 1);
    }
}
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["tests/SampleTest.php".to_string()],
            ..Default::default()
        },
    );

    assert!(report.contains("constant-truth"), "{report}");
    assert!(report.contains("constant-equality"), "{report}");
}

#[test]
fn php_flags_self_comparison_assertion() {
    let report = language_report(
        Language::Php,
        "tests/SampleTest.php",
        r#"
<?php
class SampleTest {
    public function testSelfComparison(): void {
        $value = "x";
        $this->assertSame($value, $value);
    }
}
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["tests/SampleTest.php".to_string()],
            ..Default::default()
        },
    );

    assert!(report.contains("self-comparison"), "{report}");
}

#[test]
fn php_nullness_only_is_shallow() {
    let report = language_report(
        Language::Php,
        "tests/SampleTest.php",
        r#"
<?php
class SampleTest {
    public function testNullnessOnly(): void {
        $value = new \stdClass();
        $this->assertNotNull($value);
    }
}
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["tests/SampleTest.php".to_string()],
            min_score: 2,
            ..Default::default()
        },
    );

    assert!(report.contains("nullness-only"), "{report}");
    assert!(report.contains("shallow-assertions-only"), "{report}");
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

#[test]
fn php_meaningful_test_stays_below_default_threshold() {
    let report = language_report(
        Language::Php,
        "tests/SampleTest.php",
        r#"
<?php
class SampleTest {
    public function testMeaningful(): void {
        $value = "expected";
        $this->assertEquals("expected", $value);
    }
}
"#,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["tests/SampleTest.php".to_string()],
            ..Default::default()
        },
    );

    assert_eq!("No test assertion smells met minScore 4.", report);
}
