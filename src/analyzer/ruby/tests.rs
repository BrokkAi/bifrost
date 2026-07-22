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
mod semantic_identifier_range_tests {
    use super::*;

    fn node_with_text<'tree>(root: Node<'tree>, source: &str, expected: &str) -> Node<'tree> {
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if source.get(node.start_byte()..node.end_byte()) == Some(expected) {
                return node;
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        panic!("missing node for {expected:?}");
    }

    fn selected_text(source: &str, expected_node_text: &str) -> String {
        let tree = parse_ruby_tree(source).expect("parse Ruby range fixture");
        let node = node_with_text(tree.root_node(), source, expected_node_text);
        let range = ruby_semantic_identifier_range(node, source);
        source[range.start_byte..range.end_byte].to_string()
    }

    #[test]
    fn selects_only_static_ruby_symbol_identifier_content() {
        let source = r#"audit
public_send(:audit)
public_send(:"audit")
public_send(:"au#{suffix}dit")
notify("audit")
"#;

        assert_eq!(selected_text(source, "audit"), "audit");
        assert_eq!(selected_text(source, ":audit"), "audit");
        assert_eq!(selected_text(source, ":\"audit\""), "audit");
        assert_eq!(
            selected_text(source, ":\"au#{suffix}dit\""),
            ":\"au#{suffix}dit\""
        );
        assert_eq!(selected_text(source, "\"audit\""), "\"audit\"");
    }
}

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
