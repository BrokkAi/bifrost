// Test-file detection across RSpec, Minitest, and Test::Unit. Covers ISC-8.

use brokk_bifrost::CodeUnitIndex;
use brokk_bifrost::{IAnalyzer, Language, ProjectFile, RubyAnalyzer, TestProject};

use crate::common::InlineTestProject;

fn analyzer() -> RubyAnalyzer {
    RubyAnalyzer::from_project(TestProject::new(
        std::fs::canonicalize("tests/fixtures/testcode-ruby").unwrap(),
        brokk_bifrost::Language::Ruby,
    ))
}

fn contains_tests(analyzer: &RubyAnalyzer, rel: &str) -> bool {
    analyzer.contains_tests(&ProjectFile::new(
        analyzer.project().root().to_path_buf(),
        rel,
    ))
}

#[test]
fn detects_rspec() {
    assert!(contains_tests(&analyzer(), "testing/calculator_spec.rb"));
}

#[test]
fn detects_minitest() {
    assert!(contains_tests(
        &analyzer(),
        "testing/calculator_minitest.rb"
    ));
}

#[test]
fn detects_test_unit() {
    assert!(contains_tests(
        &analyzer(),
        "testing/calculator_test_unit.rb"
    ));
}

#[test]
fn plain_library_is_not_a_test() {
    assert!(!contains_tests(&analyzer(), "testing/plain_lib.rb"));
}

fn inline_contains_tests(source: &str) -> bool {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file("sample.rb", source)
        .build();
    let analyzer = RubyAnalyzer::from_project(project.project().clone());
    analyzer.contains_tests(&project.file("sample.rb"))
}

#[test]
fn detects_structured_ruby_test_forms() {
    for source in [
        "RSpec.describe Widget do\nend\n",
        "describe Widget do\n  it 'works' do\n  end\nend\n",
        "class WidgetTest < Minitest::Test\nend\n",
        "class WidgetTest < Test::Unit::TestCase\nend\n",
        "def test_widget\nend\n",
        "require 'minitest/autorun'\n",
        "require('spec_helper')\n",
        "require_relative 'test_helper'\n",
        "require_relative('spec_helper')\n",
    ] {
        assert!(inline_contains_tests(source), "missed {source:?}");
    }
}

#[test]
fn ignores_ruby_test_markers_outside_supported_ast_forms() {
    for source in [
        "# RSpec.describe Widget\n",
        "text = \"def test_widget\"\n",
        "builder.it('works') { run }\n",
        "RSpecish.describe Widget do\nend\n",
        "require helper_name\n",
        "require \"minitest/#{mode}\"\n",
        "loader.require_relative('test_helper')\n",
        "class WidgetTest < Other::Minitest::Test\nend\n",
    ] {
        assert!(
            !inline_contains_tests(source),
            "false positive for {source:?}"
        );
    }
}
