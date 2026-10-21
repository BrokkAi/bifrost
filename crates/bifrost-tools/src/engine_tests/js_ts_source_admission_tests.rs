#[cfg(test)]
mod js_ts_extraction_root {

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::source_admission_test_support::table;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::BoundedParse;

    use brokk_bifrost_analysis::analyzer::semantic::source_admission::SourceAdmissionRefusal;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::js_ts_source_admission_support::parse;

    use brokk_bifrost_cpp_analysis::analyzer::cpp::adapter::CppAdapter;

    use brokk_bifrost_js_ts_analysis::analyzer::javascript::JavascriptAdapter;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon(
        "#5408: generated numeric data was rejected together with overlong executable syntax"
    )]
    fn numeric_data_admission_preserves_structure_and_explicit_limits() {
        let source = table();
        assert!(
            source
                .lines()
                .any(|line| line.len()
                    > brokk_bifrost_core::analyzer::common::DEFAULT_MAX_LINE_LENGTH)
        );
        let BoundedParse::Complete(tree) = parse(&CppAdapter, &source, None) else {
            panic!("default numeric table must be admitted");
        };
        assert!(
            !tree.root_node().has_error(),
            "{}",
            tree.root_node().to_sexp()
        );
        assert_eq!(tree.root_node().end_byte(), source.len());
        for setting in [Some("invalid"), Some("0"), Some("32768")] {
            assert!(matches!(
                parse(&CppAdapter, &source, setting),
                BoundedParse::Complete(_)
            ));
        }
        assert!(matches!(
            parse(&CppAdapter, &source, Some("16000")),
            BoundedParse::Refused(SourceAdmissionRefusal::StructuralLine { limit: 16000, .. })
        ));
        assert!(matches!(
            parse(&CppAdapter, "int binary;\0", Some("0")),
            BoundedParse::Refused(SourceAdmissionRefusal::Binary)
        ));
        assert!(matches!(
            parse(
                &JavascriptAdapter,
                &format!("const words = [{}];", "1,".repeat(9000)),
                None
            ),
            BoundedParse::Refused(SourceAdmissionRefusal::StructuralLine { .. })
        ));

        let signed = format!(
            "long long values[][900] = {{{{{}}},{{1,2}}}};\n",
            "+0x0123456789abcdef,-0x0123456789abcdef,".repeat(450)
        );
        assert!(matches!(
            parse(&CppAdapter, &signed, None),
            BoundedParse::Complete(_)
        ));

        // Short-line tables must not spend the exception's excluded-node allowance.
        let ordinary_tables = "static int ordinary[] = {1,2,3,4,5,6,7,8};\n".repeat(600);
        assert!(matches!(
            parse(&CppAdapter, &(ordinary_tables + &source), None),
            BoundedParse::Complete(_)
        ));
    }
}
