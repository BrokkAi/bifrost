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

#[cfg(test)]
mod dispatch_mode_tests {
    use super::*;
    use crate::analyzer::RubyMethodDispatchMode;
    use crate::test_support::AnalyzerFixture;

    fn analyzer_with_source(source: &str) -> (AnalyzerFixture, RubyAnalyzer) {
        let fixture = AnalyzerFixture::new_for_language(Language::Ruby, &[("sample.rb", source)]);
        let analyzer = RubyAnalyzer::from_project(fixture.test_project().clone());
        (fixture, analyzer)
    }

    fn dispatch_mode(analyzer: &RubyAnalyzer, fq_name: &str) -> RubyMethodDispatchMode {
        let method = analyzer
            .definitions(fq_name)
            .next()
            .unwrap_or_else(|| panic!("missing Ruby method {fq_name}"));
        analyzer.method_dispatch_mode(&method)
    }

    #[test]
    fn classifies_plain_instance_method() {
        let (_fixture, analyzer) = analyzer_with_source(
            r#"
class Service
  def call
  end
end
"#,
        );

        assert_eq!(
            dispatch_mode(&analyzer, "Service.call"),
            RubyMethodDispatchMode::Instance
        );
    }

    #[test]
    fn classifies_explicit_self_singleton_method() {
        let (_fixture, analyzer) = analyzer_with_source(
            r#"
class Service
  def self.build
  end
end
"#,
        );

        assert_eq!(
            dispatch_mode(&analyzer, "Service.build"),
            RubyMethodDispatchMode::Singleton
        );
    }

    #[test]
    fn classifies_singleton_class_method() {
        let (_fixture, analyzer) = analyzer_with_source(
            r#"
class Service
  class << self
    def make
    end
  end
end
"#,
        );

        assert_eq!(
            dispatch_mode(&analyzer, "Service.make"),
            RubyMethodDispatchMode::Singleton
        );
    }

    #[test]
    fn classifies_bare_module_function_for_subsequent_method() {
        let (_fixture, analyzer) = analyzer_with_source(
            r#"
module Tools
  module_function

  def format
  end
end
"#,
        );

        assert_eq!(
            dispatch_mode(&analyzer, "Tools.format"),
            RubyMethodDispatchMode::ModuleFunction
        );
    }

    #[test]
    fn classifies_named_module_function_method() {
        let (_fixture, analyzer) = analyzer_with_source(
            r#"
module Tools
  def normalize
  end

  module_function :normalize
end
"#,
        );

        assert_eq!(
            dispatch_mode(&analyzer, "Tools.normalize"),
            RubyMethodDispatchMode::ModuleFunction
        );
    }
}
