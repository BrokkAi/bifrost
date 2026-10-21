#[cfg(test)]
mod ruby_extraction_tests {

    use brokk_bifrost_analysis::analyzer::usages::get_definition::call_sites::call_reference_ranges_in_tree;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::parse_tree_for_language;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::Range;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::call_sites::test_support::byte_range;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::call_sites::test_support::file;
    #[test]
    fn ruby_outgoing_candidates_stop_at_nested_execution_boundaries() {
        let outer = r#"class Outer
  setup()
  around() do
    nested_block()
  end

  class Nested
    nested_class()
  end

  class << self
    nested_singleton()
  end

  BEGIN { begin_only() }
  END { end_only() }

  local_value = 1
  consume(local_value)
  finish()
end"#;
        let source = format!("{outer}\n");
        let file = file("boundaries.rb");
        let tree =
            parse_tree_for_language(&file, Language::Ruby, &source).expect("Ruby syntax tree");

        let names_in = |range: Range| {
            call_reference_ranges_in_tree(&tree, Language::Ruby, &range, 20)
                .into_iter()
                .map(|range| source[range.start_byte..range.end_byte].to_string())
                .collect::<Vec<_>>()
        };

        assert_eq!(
            names_in(byte_range(&source, outer)),
            vec!["setup", "around", "consume", "finish"]
        );
        assert_eq!(
            names_in(byte_range(&source, "do\n    nested_block()\n  end")),
            vec!["nested_block"]
        );
        assert_eq!(
            names_in(byte_range(
                &source,
                "class Nested\n    nested_class()\n  end"
            )),
            vec!["nested_class"]
        );
        assert_eq!(
            names_in(byte_range(
                &source,
                "class << self\n    nested_singleton()\n  end"
            )),
            vec!["nested_singleton"]
        );
        assert_eq!(
            names_in(byte_range(&source, "BEGIN { begin_only() }")),
            vec!["begin_only"]
        );
        assert_eq!(
            names_in(byte_range(&source, "END { end_only() }")),
            vec!["end_only"]
        );
    }
}
