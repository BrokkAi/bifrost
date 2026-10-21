#[cfg(test)]
mod csharp_extraction_tests {

    use brokk_bifrost_core::analyzer::model::CodeUnit;

    use brokk_bifrost_core::analyzer::structural::routes::RouteHopKind;

    use brokk_bifrost_analysis::analyzer::structural::identity_routes::physical_occurrences;

    use brokk_bifrost_analysis::analyzer::structural::identity_routes::test_support::Fixture;

    use brokk_bifrost_analysis::analyzer::structural::identity_routes::test_support::rows_of_kind;

    use brokk_bifrost_core::analyzer::model::Language;
    #[test]
    fn csharp_partial_parts_group_physically() {
        let fixture = Fixture::new(
            Language::CSharp,
            &[
                (
                    "src/WidgetA.cs",
                    "namespace App;\n\npublic partial class Widget {\n    public void A() {}\n}\n",
                ),
                (
                    "src/WidgetB.cs",
                    "namespace App;\n\npublic partial class Widget {\n    public void B() {}\n}\n",
                ),
            ],
        );
        let analyzer = fixture.analyzer();
        let mut widgets: Vec<CodeUnit> = analyzer
            .all_declarations()
            .filter(|unit| unit.is_class() && unit.fq_name().ends_with("Widget"))
            .collect();
        assert!(!widgets.is_empty(), "no Widget class declarations found");
        let widget = widgets.remove(0);
        let occurrences = physical_occurrences(analyzer, &widget);
        let files: std::collections::BTreeSet<&std::path::Path> = occurrences
            .iter()
            .map(|occurrence| occurrence.file.rel_path())
            .collect();
        assert!(
            files.len() >= 2,
            "expected parts in both files, got occurrences {occurrences:?}"
        );

        // And the partial-part relation rows point across parts.
        let rows = fixture.rows(0);
        let parts = rows_of_kind(&rows, RouteHopKind::PartialPart);
        assert!(
            !parts.is_empty(),
            "expected partial-part rows; rows: {:?}",
            rows.rows
        );
    }
}
