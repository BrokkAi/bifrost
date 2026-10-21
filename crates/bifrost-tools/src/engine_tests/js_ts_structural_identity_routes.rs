#[cfg(test)]
mod js_ts_extraction_tests {

    use brokk_bifrost_analysis::analyzer::structural::identity_routes::RouteEndpoint;

    use brokk_bifrost_core::analyzer::structural::routes::RouteHopKind;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::structural::identity_routes::test_support::Fixture;

    use brokk_bifrost_analysis::analyzer::structural::identity_routes::test_support::rows_of_kind;
    #[test]
    fn js_export_of_imported_name_reaches_the_origin() {
        let fixture = Fixture::new(
            Language::JavaScript,
            &[
                (
                    "index.js",
                    "import { widget } from './widget.js';\nexport { widget };\n",
                ),
                ("widget.js", "export function widget() { return 1; }\n"),
            ],
        );
        let rows = fixture.rows(0);
        let exports = rows_of_kind(&rows, RouteHopKind::Export);
        assert_eq!(exports.len(), 1, "rows: {:?}", rows.rows);
        let RouteEndpoint::Declaration(target) = &exports[0].to else {
            panic!("export target must be a declaration");
        };
        assert_eq!(target.source(), &fixture.files[1]);

        let imports = rows_of_kind(&rows, RouteHopKind::Import);
        assert_eq!(imports.len(), 1, "rows: {:?}", rows.rows);
        let RouteEndpoint::Declaration(imported) = &imports[0].to else {
            panic!("import target must be a declaration");
        };
        assert_eq!(imported.source(), &fixture.files[1]);
    }
}
