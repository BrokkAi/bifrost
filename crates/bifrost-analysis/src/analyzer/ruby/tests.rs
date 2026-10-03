//! Ruby test detection: the analyzer-bound half.
//!
//! The recognizer and the assertion-smell detector are
//! [`brokk_bifrost_ruby::test_detection`]. What stays here is the empty
//! `TestDetectionProvider` marker impl (the trait is analysis-owned) and the two
//! fixture suites that need a real `RubyAnalyzer`.

use super::*;

impl TestDetectionProvider for RubyAnalyzer {}

#[cfg(test)]
mod semantic_identifier_range_tests {
    use super::*;
    use tree_sitter::Node;

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

    fn selected_kind_text(source: &str, expected_kind: &str) -> String {
        let tree = parse_ruby_tree(source).expect("parse Ruby range fixture");
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == expected_kind {
                let range = ruby_semantic_identifier_range(node, source);
                return source[range.start_byte..range.end_byte].to_string();
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        panic!("missing node kind {expected_kind:?}");
    }

    #[test]
    fn selects_only_static_ruby_symbol_identifier_content() {
        let source = r#"audit
public_send(:audit)
public_send(:"audit")
public_send(:"au#{suffix}dit")
notify("audit")
configure(audit: true)
"#;

        assert_eq!(selected_text(source, "audit"), "audit");
        assert_eq!(selected_text(source, ":audit"), "audit");
        assert_eq!(selected_text(source, ":\"audit\""), "audit");
        assert_eq!(
            selected_text(source, ":\"au#{suffix}dit\""),
            ":\"au#{suffix}dit\""
        );
        assert_eq!(selected_text(source, "\"audit\""), "\"audit\"");
        assert_eq!(selected_kind_text(source, "hash_key_symbol"), "audit");
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

    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
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

    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
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

    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
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

    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
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

#[cfg(test)]
mod canonical_source_tests {
    use super::*;
    use crate::analyzer::OverlayProject;
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_ruby::graph_support::RubySource;

    #[test]
    fn ruby_dirty_load_and_autoload_facts_are_isolated_across_a_b_a() {
        let source_a = "module Outer\n  autoload :First, \"first\"\nend\n";
        let source_b = "module Outer\n  autoload :Second, \"second\"\nend\n";
        let fixture = InlineTestProject::with_language(Language::Ruby)
            .file("main.rb", source_a)
            .file("first.rb", "class Outer::First; end\n")
            .file("second.rb", "class Outer::Second; end\n")
            .build();
        let file = fixture.file("main.rb");
        let mut analyzer = RubyAnalyzer::new(fixture.project_dyn());
        analyzer.inner.clear_retained_file_states_for_test();
        assert!(analyzer.canonical_sources_ready());
        assert!(
            analyzer
                .autoload_constant_files()
                .unwrap()
                .contains_key("Outer$First")
        );
        let overlay = Arc::new(OverlayProject::new(fixture.project_dyn()));
        assert!(overlay.set(file.abs_path(), source_b.to_owned()));
        let dirty = analyzer.clone_with_project(Arc::clone(&overlay) as Arc<dyn Project>);
        // Ordinary primary preparation establishes the dirty source authority.
        dirty
            .inner
            .prepare_canonical_source_facts(&file, source_b.to_owned())
            .unwrap();
        let loads = dirty.source_facts(&file).unwrap().loads;
        assert_eq!(
            loads[0].autoload_constant.as_deref().unwrap(),
            ["Outer", "Second"]
        );
        let index = dirty.autoload_constant_files().unwrap();
        assert!(index.contains_key("Outer$Second"));
        assert!(!index.contains_key("Outer$First"));
        assert!(
            analyzer
                .autoload_constant_files()
                .unwrap()
                .contains_key("Outer$First")
        );
        assert!(overlay.set(file.abs_path(), source_a.to_owned()));
        let again = analyzer.clone_with_project(overlay as Arc<dyn Project>);
        assert_eq!(
            again.source_facts(&file).unwrap().loads[0]
                .autoload_constant
                .as_deref()
                .unwrap(),
            ["Outer", "First"]
        );
        let index = again.autoload_constant_files().unwrap();
        assert!(index.contains_key("Outer$First"));
        assert!(!index.contains_key("Outer$Second"));
    }

    #[test]
    fn ruby_cold_missing_publication_does_not_parse_or_cache_failed_autoload() {
        let source = "autoload :Ready, \"ready\"\n";
        let fixture = InlineTestProject::with_language(Language::Ruby)
            .file("main.rb", source)
            .build();
        let file = fixture.file("main.rb");
        let mut analyzer = RubyAnalyzer::new(fixture.project_dyn());
        analyzer.inner.clear_retained_file_states_for_test();
        let oid = git2::Oid::hash_object(git2::ObjectType::Blob, source.as_bytes()).unwrap();
        analyzer
            .inner
            .analyzer_store()
            .mark_parsed_blob_incomplete_for_test(oid, "ruby");
        analyzer.inner.reset_full_hydration_count_for_test();
        assert!(analyzer.source_facts(&file).is_none());
        assert!(analyzer.autoload_constant_files().is_none());
        assert!(!analyzer.canonical_sources_ready());
        let scope = crate::analyzer::AnalyzerQueryScope::new(&analyzer);
        use crate::analyzer::QueryScope;
        assert!(
            analyzer
                .import_info_of_checked(scope.token(), &file)
                .is_none()
        );
        assert!(analyzer.import_info_of(scope.token(), &file).is_empty());
        assert!(analyzer.autoload_constant_files.get().is_none());
        assert_eq!(analyzer.inner.full_hydration_count_for_test(), 0);
        analyzer
            .inner
            .prepare_canonical_source_facts(&file, source.to_owned())
            .unwrap();
        assert!(analyzer.canonical_sources_ready());
        assert!(
            analyzer
                .autoload_constant_files()
                .unwrap()
                .contains_key("Ready")
        );
        assert_eq!(analyzer.inner.full_hydration_count_for_test(), 0);
    }
}

#[cfg(test)]
mod canonical_lookup_tests {
    use super::*;
    use crate::analyzer::usages::get_definition::{BoundedResolution, resolve_ruby_bounded};
    use crate::analyzer::usages::get_type::resolve_ruby_type_bounded;
    use crate::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
    use crate::analyzer::usages::reference_site::ResolvedReferenceSite;
    use crate::inline_project::InlineTestProject;

    #[test]
    fn ruby_edge_build_does_not_publish_missing_inputs_after_a_successful_preflight() {
        let source = "class Ready; end\n";
        let fixture = InlineTestProject::with_language(Language::Ruby)
            .file("main.rb", source)
            .build();
        let mut analyzer = RubyAnalyzer::new(fixture.project_dyn());
        analyzer.inner.clear_retained_file_states_for_test();
        assert!(analyzer.canonical_sources_ready());
        analyzer
            .inner
            .analyzer_store()
            .mark_parsed_blob_incomplete_for_test(
                git2::Oid::hash_object(git2::ObjectType::Blob, source.as_bytes()).unwrap(),
                "ruby",
            );
        analyzer.inner.reset_full_hydration_count_for_test();
        let edges = crate::analyzer::usages::ruby_graph::build_ruby_usage_edges(
            &analyzer,
            &HashSet::default(),
            |_| true,
        );
        assert!(edges.is_none());
        assert_eq!(analyzer.inner.full_hydration_count_for_test(), 0);
    }

    #[test]
    fn ruby_cold_definition_and_type_lookup_report_unavailable_source_authority() {
        let source = "class Ready; end\nReady\n";
        let fixture = InlineTestProject::with_language(Language::Ruby)
            .file("main.rb", source)
            .build();
        let file = fixture.file("main.rb");
        let mut analyzer = RubyAnalyzer::new(fixture.project_dyn());
        analyzer.inner.clear_retained_file_states_for_test();
        analyzer
            .inner
            .analyzer_store()
            .mark_parsed_blob_incomplete_for_test(
                git2::Oid::hash_object(git2::ObjectType::Blob, source.as_bytes()).unwrap(),
                "ruby",
            );
        analyzer.inner.reset_full_hydration_count_for_test();
        let tree = parse_ruby_tree(source).unwrap();
        let start = source.rfind("Ready").unwrap();
        let site = ResolvedReferenceSite {
            path: "main.rb".to_owned(),
            text: "Ready".to_owned(),
            range: Range {
                start_byte: start,
                end_byte: start + 5,
                start_line: 1,
                end_line: 1,
            },
            focus_start_byte: start,
            focus_end_byte: start + 5,
        };
        let BoundedResolution::Complete { value, .. } = resolve_ruby_bounded(
            &analyzer,
            &file,
            source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::default(),
            None,
        ) else {
            panic!("unavailable facts must produce an explicit diagnostic");
        };
        assert!(value.definitions.is_empty());
        assert!(
            value
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.kind == "ruby_source_facts_unavailable")
        );
        let BoundedResolution::Complete { value, .. } = resolve_ruby_type_bounded(
            &analyzer,
            &file,
            source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::default(),
            None,
        ) else {
            panic!("unavailable facts must produce an explicit diagnostic");
        };
        assert!(
            value
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.kind == "ruby_source_facts_unavailable")
        );
        assert_eq!(analyzer.inner.full_hydration_count_for_test(), 0);
    }
}
