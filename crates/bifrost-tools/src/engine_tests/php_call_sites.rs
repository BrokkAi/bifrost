#[cfg(test)]
mod php_extraction_tests {

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::call_sites::call_reference_range_for_call;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::call_sites::call_reference_ranges_in_tree;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::parse_tree_for_language;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::call_sites::test_support::byte_range;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::call_sites::test_support::file;
    #[test]
    fn exact_php_nullsafe_call_span_uses_the_named_method_field() {
        let source = "<?php\nclass Service { public function run(): void {} }\nfunction caller(Service $service): void { $service?->run(); }\n";
        let file = file("nested.php");
        let tree = parse_tree_for_language(&file, Language::Php, source).expect("PHP syntax tree");

        let run = call_reference_range_for_call(
            &tree,
            Language::Php,
            &byte_range(source, "$service?->run()"),
        )
        .expect("nullsafe method reference");

        assert_eq!(&source[run.start_byte..run.end_byte], "run");
    }

    #[test]
    fn php_nullsafe_receiver_properties_are_not_outgoing_call_candidates() {
        let source =
            "<?php\nfunction caller(Holder $holder): void { $holder?->service?->run(); }\n";
        let file = file("nested.php");
        let tree = parse_tree_for_language(&file, Language::Php, source).expect("PHP syntax tree");
        let call = byte_range(source, "$holder?->service?->run()");

        let references = call_reference_ranges_in_tree(&tree, Language::Php, &call, 10);
        let names = references
            .iter()
            .map(|range| &source[range.start_byte..range.end_byte])
            .collect::<Vec<_>>();

        assert_eq!(names, vec!["run"]);
    }
}
