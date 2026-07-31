use brokk_bifrost::code_quality::{ReportTestAssertionSmellsParams, report_test_assertion_smells};
use brokk_bifrost::{IAnalyzer, Language, RubyAnalyzer, TestAssertionWeights};

use crate::common::InlineTestProject;

fn ruby_report(source: &str, min_score: i32) -> String {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file("sample_spec.rb", source)
        .build();
    let analyzer = RubyAnalyzer::from_project(project.project().clone());
    report_test_assertion_smells(
        &analyzer as &dyn IAnalyzer,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["sample_spec.rb".to_string()],
            min_score,
            ..Default::default()
        },
    )
    .report
}

#[test]
fn ruby_reports_missing_assertions_for_rspec_and_minitest() {
    let report = ruby_report(
        r#"
RSpec.describe Widget do
  it "runs work" do
    Widget.run
  end
end

class WidgetTest < Minitest::Test
  def test_update
    Widget.update
  end
end
"#,
        4,
    );

    assert!(report.contains("runs work"), "{report}");
    assert!(report.contains("test_update"), "{report}");
    assert_eq!(
        2,
        report.matches("| 5 | `no-assertions`").count(),
        "{report}"
    );
}

#[test]
fn ruby_reports_tautological_assertions_across_frameworks() {
    let report = ruby_report(
        r#"
RSpec.describe Widget do
  it "compares itself" do
    expect(value).to eq(value)
  end

  specify "same object" do
    value.must_same value
  end
end

class WidgetTest < Test::Unit::TestCase
  def test_same_value
    assert_equal value, value
  end
end
"#,
        4,
    );

    assert_eq!(
        3,
        report.matches("| 6 | `self-comparison`").count(),
        "{report}"
    );
}

#[test]
fn ruby_reports_constant_equality_and_truth() {
    let report = ruby_report(
        r#"
class ConstantTest < Minitest::Test
  def test_constants
    assert_equal 1, 2
    assert true
    refute false
  end
end
"#,
        4,
    );

    assert!(report.contains("constant-equality"), "{report}");
    assert_eq!(
        2,
        report.matches("| 4 | `constant-truth`").count(),
        "{report}"
    );
}

#[test]
fn ruby_counts_meaningful_framework_assertions() {
    let report = ruby_report(
        r#"
RSpec.describe Widget do
  it "matches" do
    expect(actual).to eq(expected)
    expect { Widget.run }.to raise_error(WidgetError)
  end
end

class WidgetTest < Minitest::Test
  def test_assertions
    assert_equal expected, actual
    assert_raises(WidgetError) { Widget.run }
    refute value.empty?
    actual.must_equal expected
  end
end
"#,
        4,
    );

    assert_eq!("No test assertion smells met minScore 4.", report);
}

#[test]
fn ruby_reports_nil_only_assertions_at_low_threshold() {
    let report = ruby_report(
        r#"
RSpec.describe Widget do
  it "exists" do
    expect(value).not_to be_nil
  end
end

class WidgetTest < Minitest::Test
  def test_exists
    refute_nil value
  end
end
"#,
        2,
    );

    assert_eq!(
        2,
        report.matches("| 2 | `nullness-only`").count(),
        "{report}"
    );
    assert_eq!(
        2,
        report.matches("| 2 | `shallow-assertions-only`").count(),
        "{report}"
    );
}

#[test]
fn ruby_ignores_assertion_lookalikes_and_outside_helpers() {
    let report = ruby_report(
        r#"
RSpec.describe Widget do
  def helper
    assert_equal expected, actual
  end

  it "needs its own assertion" do
    helper
    object.assert_equal(expected, actual)
    helper.expect(actual).to eq(expected)
    text = "assert_equal actual, actual"
    # assert_equal actual, actual
  end
end
"#,
        4,
    );

    assert!(report.contains("no-assertions"), "{report}");
    assert!(!report.contains("self-comparison"), "{report}");
}

#[test]
fn ruby_pending_rspec_examples_do_not_report_missing_assertions() {
    let report = ruby_report(
        r#"
RSpec.describe Widget do
  it "pending"
  specify("also pending")
end
"#,
        4,
    );

    assert_eq!("No test assertion smells met minScore 4.", report);
}

#[test]
fn ruby_ignores_assertions_in_deferred_callables() {
    let report = ruby_report(
        r#"
RSpec.describe Widget do
  it "needs a direct assertion" do
    proc { assert_equal expected, actual }
    lambda { expect(value).to eq(value) }
    deferred = -> { refute false }
    Proc.new { expect(other).to eq(other) }
    define_singleton_method(:later) { assert true }
    def self.later
      assert_equal value, value
    end
  end
end
"#,
        4,
    );

    assert!(report.contains("no-assertions"), "{report}");
    assert!(!report.contains("self-comparison"), "{report}");
    assert!(!report.contains("constant-truth"), "{report}");
}

#[test]
fn ruby_ignores_receiverless_assertion_lookalikes() {
    let report = ruby_report(
        r#"
class WidgetTest < Minitest::Test
  def test_configuration
    assert_cache_initialized
    refute_configuration_loaded
  end
end
"#,
        4,
    );

    assert!(report.contains("no-assertions"), "{report}");
}

#[test]
fn ruby_reports_oversized_literals_for_equality_forms() {
    let literal = "x".repeat(121);
    let source = format!(
        r#"
RSpec.describe Widget do
  it "uses a large expected value" do
    expect(actual).to eq("{literal}")
  end
end

class WidgetTest < Minitest::Test
  def test_large_values
    assert_equal "{literal}", actual
    actual.must_equal "{literal}"
  end
end
"#
    );
    let report = ruby_report(&source, 2);

    assert_eq!(
        3,
        report.matches("| 2 | `overspecified-literal`").count(),
        "{report}"
    );
    assert!(!report.contains("meaningful-assertion"), "{report}");
}

#[test]
fn ruby_combines_constant_equality_and_oversized_literal_scores() {
    let literal = "x".repeat(121);
    let source = format!(
        "class WidgetTest < Minitest::Test\n  def test_large_constants\n    assert_equal \"{literal}\", \"{literal}\"\n  end\nend\n"
    );
    let report = ruby_report(&source, 2);

    assert!(
        report.contains("| 6 | `overspecified-literal`")
            && report.contains("constant-equality, overspecified-literal"),
        "{report}"
    );
}

#[test]
fn ruby_treats_qualified_rspec_matchers_as_custom() {
    let report = ruby_report(
        r#"
RSpec.describe Widget do
  it "uses custom matchers" do
    expect(value).to helper.eq(value)
    expect(value).to helper.be_nil
  end
end
"#,
        2,
    );

    assert_eq!("No test assertion smells met minScore 2.", report);
}

#[test]
fn ruby_ignores_comments_between_call_arguments() {
    let report = ruby_report(
        r#"
class WidgetTest < Minitest::Test
  def test_value
    assert_equal(
      expected,
      # Explain why the actual value is computed below.
      actual
    )
  end
end
"#,
        4,
    );

    assert_eq!("No test assertion smells met minScore 4.", report);
}

#[test]
fn ruby_bounds_descriptions_and_excerpts() {
    let description = "d".repeat(500);
    let body = "Widget.run; ".repeat(100);
    let source =
        format!("RSpec.describe Widget do\n  it \"{description}\" do\n    {body}\n  end\nend\n");
    let report = ruby_report(&source, 4);

    assert!(report.contains("..."), "{report}");
    assert!(
        report.len() < 1_000,
        "report was not bounded: {}",
        report.len()
    );
}

#[test]
fn ruby_bounds_minitest_method_names() {
    let method_name = format!("test_{}", "m".repeat(500));
    let source = format!(
        "class WidgetTest < Minitest::Test\n  def {method_name}\n    Widget.run\n  end\nend\n"
    );
    let report = ruby_report(&source, 4);

    assert!(report.contains("..."), "{report}");
    assert!(
        report.len() < 1_000,
        "report was not bounded: {}",
        report.len()
    );
}

#[test]
fn ruby_limited_analysis_stops_and_reports_truncation() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
            "sample_spec.rb",
            r#"
RSpec.describe Widget do
  it "has multiple findings" do
    expect(value).to eq(value)
    expect(other).to eq(other)
  end
end
"#,
        )
        .build();
    let analyzer = RubyAnalyzer::from_project(project.project().clone());
    let analysis = analyzer.find_test_assertion_smells_limited(
        &project.file("sample_spec.rb"),
        TestAssertionWeights::defaults(),
        1,
    );

    assert!(analysis.truncated);
    assert!(analysis.findings.is_empty());
}

#[test]
fn ruby_limited_analysis_bounds_assertion_free_ast_traversal() {
    let body = "    Widget.run\n".repeat(12_000);
    let source =
        format!("class WidgetTest < Minitest::Test\n  def test_large_body\n{body}  end\nend\n");
    let project = InlineTestProject::with_language(Language::Ruby)
        .file("sample_test.rb", source)
        .build();
    let analyzer = RubyAnalyzer::from_project(project.project().clone());
    let analysis = analyzer.find_test_assertion_smells_limited(
        &project.file("sample_test.rb"),
        TestAssertionWeights::defaults(),
        1,
    );

    assert!(analysis.truncated);
    assert!(analysis.findings.is_empty());
}

#[test]
fn ruby_incomplete_analysis_does_not_claim_all_assertions_are_shallow() {
    let middle = "    Widget.run\n".repeat(12_000);
    let source = format!(
        "class WidgetTest < Minitest::Test\n  def test_large_body\n    assert_nil value\n{middle}    assert_equal expected, actual\n  end\nend\n"
    );
    let project = InlineTestProject::with_language(Language::Ruby)
        .file("sample_test.rb", source)
        .build();
    let analyzer = RubyAnalyzer::from_project(project.project().clone());
    let analysis = analyzer.find_test_assertion_smells_limited(
        &project.file("sample_test.rb"),
        TestAssertionWeights::defaults(),
        2,
    );

    assert!(analysis.truncated);
    assert!(analysis.findings.is_empty());
}

#[test]
fn ruby_report_does_not_claim_unused_cap_was_truncation() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
            "sample_spec.rb",
            "RSpec.describe Widget do\n  it('bad') { expect(value).to eq(value) }\nend\n",
        )
        .build();
    let analyzer = RubyAnalyzer::from_project(project.project().clone());
    let result = report_test_assertion_smells(
        &analyzer as &dyn IAnalyzer,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["sample_spec.rb".to_string()],
            max_findings: i32::MAX,
            ..Default::default()
        },
    );

    assert!(!result.truncated);
    assert!(!result.report.contains("request or analysis truncated"));
}

#[test]
fn ruby_report_distinguishes_row_truncation_from_analysis_truncation() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
            "sample_spec.rb",
            r#"
RSpec.describe Widget do
  it("one") { expect(one).to eq(one) }
  it("two") { expect(two).to eq(two) }
end
"#,
        )
        .build();
    let analyzer = RubyAnalyzer::from_project(project.project().clone());
    let result = report_test_assertion_smells(
        &analyzer as &dyn IAnalyzer,
        ReportTestAssertionSmellsParams {
            file_paths: vec!["sample_spec.rb".to_string()],
            max_findings: 1,
            ..Default::default()
        },
    );

    assert!(result.truncated);
    assert!(
        result
            .report
            .contains("output truncated; increase maxFindings")
    );
    assert!(
        !result
            .report
            .contains("analysis truncated before completion")
    );
}
