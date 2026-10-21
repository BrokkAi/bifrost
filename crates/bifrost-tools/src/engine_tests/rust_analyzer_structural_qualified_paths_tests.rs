#[cfg(test)]
mod rust_departing_tests_tests {

    use brokk_bifrost_analysis::analyzer::structural::qualified_paths::js_ts_tests_support::Fixture;

    use brokk_bifrost_analysis::analyzer::structural::qualified_paths::QualifiedPathDerivationOptions;

    use brokk_bifrost_analysis::analyzer::structural::qualified_paths::js_ts_tests_support::path_segments_at;

    use brokk_bifrost_core::analyzer::model::Language;
    /// A Java import chain is one path: ordered segments, each its own row,
    /// the terminal anchoring the path, and — because Java cannot say whether
    /// a scope segment is a package or a type from the token alone — the
    /// qualifier namespace stated on each scope segment rather than a guessed
    /// `Module` or `Type` (#3064).

    #[test]
    fn rust_path_keywords_and_raw_identifiers_stay_honest_segments() {
        let fixture = Fixture::new(
            Language::Rust,
            "src/lib.rs",
            concat!(
                "pub mod util {\n",
                "    pub struct r#type;\n",
                "}\n",
                "pub fn build() -> crate::util::r#type {\n",
                "    crate::util::r#type\n",
                "}\n",
            ),
        );
        let result = fixture.rows(QualifiedPathDerivationOptions::ROWS_ONLY);

        let segments = path_segments_at(&result, fixture.at("crate::util::r#type {"));
        assert_eq!(
            segments
                .iter()
                .map(|s| (s.text.as_str(), s.node.is_some()))
                .collect::<Vec<_>>(),
            [("crate", false), ("util", true), ("type", true)],
        );
    }
}
