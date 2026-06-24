use super::*;

/// Heuristic detection of Ruby test files across the common frameworks:
/// RSpec, Minitest, and Test::Unit. Mirrors the source-text approach the other
/// language analyzers use for `contains_tests`.
pub(super) fn ruby_source_contains_tests(source: &str) -> bool {
    source.lines().any(|line| {
        let trimmed = line.trim();
        // RSpec
        trimmed.starts_with("RSpec.describe")
            || trimmed.starts_with("describe ")
            || trimmed.starts_with("context ")
            || trimmed.starts_with("it ")
            || trimmed.starts_with("it(")
            || trimmed.starts_with("specify ")
            // Minitest
            || trimmed.starts_with("def test_")
            || (trimmed.starts_with("class ") && trimmed.contains("Minitest::Test"))
            || (trimmed.starts_with("class ") && trimmed.contains("MiniTest::Test"))
            // Test::Unit
            || (trimmed.starts_with("class ") && trimmed.contains("Test::Unit::TestCase"))
            // shared require markers
            || is_test_require(trimmed)
    })
}

fn is_test_require(line: &str) -> bool {
    if !line.starts_with("require") {
        return false;
    }
    [
        "rspec",
        "spec_helper",
        "minitest",
        "test/unit",
        "test_helper",
    ]
    .iter()
    .any(|marker| line.contains(marker))
}

impl TestDetectionProvider for RubyAnalyzer {}
