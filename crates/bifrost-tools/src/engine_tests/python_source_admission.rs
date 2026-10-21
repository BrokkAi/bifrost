#[cfg(test)]
mod python_extraction_tests {

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::BoundedParse;

    use brokk_bifrost_analysis::analyzer::semantic::source_admission::SourceAdmissionRefusal;

    use brokk_bifrost_test_macros::hardwon;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::source_admission_test_support::parse;
    #[test]
    #[hardwon("#5596: generated Python bytes descriptors were rejected by exact syntax admission")]
    fn python_literal_admission_grammar_boundary() {
        let adapter = brokk_bifrost_python_analysis::analyzer::python::PythonAdapter::default();
        let payload = "x".repeat(17_000);
        for literal in [format!("b'{payload}'"), format!("'{payload}' 'suffix'")] {
            let source = format!("DESCRIPTOR = consume({literal})\n");
            let BoundedParse::Complete(tree) = parse(&adapter, &source, None) else {
                panic!("Python literal data must be admitted");
            };
            assert!(!tree.root_node().has_error());
            assert_eq!(tree.root_node().end_byte(), source.len());
            assert!(matches!(
                parse(&adapter, &source, Some("16000")),
                BoundedParse::Refused(SourceAdmissionRefusal::StructuralLine { .. })
            ));
        }
        let source = format!("value = f'{payload}{{replacement}}'\n");
        assert!(matches!(
            parse(&adapter, &source, None),
            BoundedParse::Refused(SourceAdmissionRefusal::StructuralLine { .. })
        ));
    }
}
