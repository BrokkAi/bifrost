#[cfg(test)]
mod js_ts_extraction_tests {

    use brokk_bifrost_analysis::analyzer::structural::qualified_paths::QualifiedPathDerivationOptions;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::structural::qualified_paths::js_ts_tests_support::Fixture;

    use brokk_bifrost_analysis::analyzer::structural::qualified_paths::js_ts_tests_support::path_segments_at;
    #[test]
    fn typescript_qualified_type_chain_with_generics() {
        let fixture = Fixture::new(
            Language::TypeScript,
            "app.ts",
            concat!(
                "namespace api { export namespace types { export type Box<T> = { value: T }; } }\n",
                "let boxed: api.types.Box<string> | null = null;\n",
            ),
        );
        let result = fixture.rows(QualifiedPathDerivationOptions::ROWS_ONLY);

        let segments = path_segments_at(&result, fixture.at("api.types.Box<string>"));
        assert_eq!(
            segments
                .iter()
                .map(|s| (s.text.as_str(), s.generic_arity))
                .collect::<Vec<_>>(),
            [("api", None), ("types", None), ("Box", Some(1))],
        );
    }
}
