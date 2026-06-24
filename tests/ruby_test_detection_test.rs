// Test-file detection across RSpec, Minitest, and Test::Unit. Covers ISC-8.

use brokk_bifrost::{IAnalyzer, ProjectFile, RubyAnalyzer, TestProject};

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
