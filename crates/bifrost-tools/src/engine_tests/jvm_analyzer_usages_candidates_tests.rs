#[cfg(test)]
mod jvm_extraction_tests {

    use brokk_bifrost_analysis::IAnalyzer;

    use std::sync::Arc;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_core::analyzer::capabilities::DescendantIndexScope;

    use brokk_bifrost_analysis::analyzer::usages::candidates::find_default_candidates_within;

    use brokk_bifrost_analysis::analyzer::usages::candidates::is_constructor_target;

    use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

    use brokk_bifrost_jvm_analysis::analyzer::KotlinAnalyzer;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::test_support::AnalyzerFixture;
    use brokk_bifrost_test_macros::hardwon;

    /// Constructors do not participate in polymorphic dispatch. Before this
    /// gate, asking for one constructor's usages built Kotlin's complete
    /// descendant index and resolved every unrelated class hierarchy in the
    /// workspace (#1748).
    #[test]
    #[hardwon(
        "#2602: Kotlin constructor candidate lookup avoids scanning workspace descendants when the constructor has a direct type identity"
    )]
    fn kotlin_constructor_candidates_skip_workspace_descendant_resolution() {
        let unrelated_hierarchy = (0..64)
            .map(|index| format!("open class Base{index}\nclass Child{index} : Base{index}()\n"))
            .collect::<String>();
        let fixture = AnalyzerFixture::new_for_language(
            Language::Kotlin,
            &[
                (
                    "DuplicateColumnException.kt",
                    "package api\nclass DuplicateColumnException(message: String) : Exception(message)\n",
                ),
                ("Unrelated.kt", &unrelated_hierarchy),
            ],
        );
        let analyzer = KotlinAnalyzer::new(Arc::new(fixture.test_project().clone()));
        let constructor = analyzer
            .get_all_declarations()
            .into_iter()
            .find(|unit| unit.fq_name() == "api.DuplicateColumnException.DuplicateColumnException")
            .expect("fixture declares the DuplicateColumnException constructor");
        assert!(is_constructor_target(&constructor, &analyzer));

        let cancellation = CancellationToken::default();
        let scope = DescendantIndexScope::whole_workspace(&cancellation);
        analyzer
            .test_hooks()
            .reset_definition_candidates_query_count_for_test();
        let candidates = find_default_candidates_within(&constructor, &analyzer, &scope);
        let definition_queries = analyzer
            .test_hooks()
            .definition_candidates_query_count_for_test();

        assert!(candidates.contains(constructor.source()));
        assert!(
            definition_queries < 8,
            "constructor discovery must not resolve the unrelated workspace hierarchy; got {definition_queries} definition queries"
        );
    }
}
