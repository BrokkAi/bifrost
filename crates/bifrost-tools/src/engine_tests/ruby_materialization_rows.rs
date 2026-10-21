#[cfg(test)]
mod ruby_extraction_tests {

    use brokk_bifrost_core::analyzer::structural::materialization::GenerationInputClass;

    use brokk_bifrost_core::analyzer::structural::materialization::MaterializationAxis;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::structural::materialization_rows::test_support::Fixture;

    /// A dynamic argument keeps the site visible with an explicitly unknown
    /// generated set: the axis reports incomplete, never an empty answer.
    #[test]
    fn ruby_dynamic_generation_reports_incomplete_not_empty() {
        let fixture = Fixture::new(
            Language::Ruby,
            "dynamic.rb",
            "class Widget\n  attr_reader label.to_sym\nend\n",
        );
        let rows = fixture.rows();

        assert_eq!(rows.sites.len(), 1, "sites: {:?}", rows.sites);
        assert_eq!(rows.sites[0].input, GenerationInputClass::Dynamic);
        assert!(rows.sites[0].generated.is_empty());
        assert!(
            !rows.completeness.covers(MaterializationAxis::GeneratedSets),
            "completeness: {:?}",
            rows.completeness
        );
        assert!(
            rows.completeness
                .covers(MaterializationAxis::GenerationSites),
            "the site itself is a complete answer: {:?}",
            rows.completeness
        );
    }
}
