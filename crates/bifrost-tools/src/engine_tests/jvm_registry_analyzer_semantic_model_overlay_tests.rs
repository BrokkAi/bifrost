#[cfg(test)]
mod jvm_registry_tests {

    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::semantic_model::model::Locator;

    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::semantic_model::overlay::authored_anchor;

    #[cfg(test)]
    use brokk_bifrost_analysis::test_support::AnalyzerFixture;
    #[cfg(test)]
    use brokk_bifrost_core::analyzer::model::Language;
    #[cfg(test)]
    use brokk_bifrost_test_macros::hardwon;
    #[cfg(test)]
    #[test]
    #[hardwon("#2634: unavailable dependency source locations lost their durable model anchor")]
    fn unavailable_dependency_source_uses_a_durable_model_location() {
        let fixture = AnalyzerFixture::new_for_language(
            Language::Java,
            &[("src/Main.java", "package app; class Main {}\n")],
        );
        let locator = Locator::Source {
            path: "java.base/java/util/ArrayList.java".to_string(),
            symbol: Some("java.util.ArrayList".to_string()),
        };

        assert!(
            authored_anchor(
                fixture.analyzer.analyzer(),
                &[],
                &locator,
                "java.util.ArrayList"
            )
            .is_none(),
            "a dependency source outside the indexed workspace and the pack's carried sources cannot be an authored navigation target"
        );
    }
    #[cfg(test)]
    #[test]
    #[hardwon("#2634: carried source locations lost the authored declaration anchor")]
    fn carried_dependency_source_preserves_the_authored_anchor() {
        let fixture = AnalyzerFixture::new_for_language(
            Language::Java,
            &[("src/Main.java", "package app; class Main {}\n")],
        );
        let locator = Locator::Source {
            path: "java.base/java/util/ArrayList.java".to_string(),
            symbol: Some("java.util.ArrayList".to_string()),
        };

        let anchor = authored_anchor(
            fixture.analyzer.analyzer(),
            &["java.base/java/util/ArrayList.java".to_string()],
            &locator,
            "java.util.ArrayList",
        )
        .expect("a carried source stays an authored navigation target");
        assert_eq!(anchor.path, "java.base/java/util/ArrayList.java");
        assert_eq!(anchor.symbol, "java.util.ArrayList");
        assert_eq!(anchor.range.start_line, 0);
        assert_eq!(anchor.range.end_line, 0);
    }
}
