#[cfg(test)]
mod php_extraction_tests {

    use brokk_bifrost_analysis::analyzer::semantic_model::dependency::*;

    use brokk_bifrost_analysis::analyzer::semantic_model::dependency::test_support::HookFixture;

    use brokk_bifrost_analysis::analyzer::semantic_model::dependency::test_support::HookBehavior;

    use brokk_bifrost_analysis::analyzer::semantic_model::dependency::test_support::prepare;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SemanticPackCatalog;

    use brokk_bifrost_semantic::analyzer::semantic_model::catalog::CatalogOptions;
    use semver::Version;
    /// The PHP twin declared under #2374. It reaches the same route: an
    /// artifact-less toolchain coordinate that only an installed pack can
    /// satisfy.
    fn declared_php_dependency() -> ResolvedDependency {
        crate::analyzer::php::dependency_discovery::declared_php_runtime_dependency(
            Version::new(8, 2, 0),
            "composer.json",
            "^8.2",
        )
    }

    #[test]
    fn declared_php_runtime_dependency_reaches_the_hook() {
        let fixture = HookFixture::install(HookBehavior::RecordOnly);
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();

        let outcome = prepare(&catalog, declared_php_dependency());

        assert_eq!(fixture.requests(), vec!["declared:php:php@8.2.0"]);
        assert_eq!(
            brokk_bifrost_analysis::analyzer::semantic_model::dependency::diagnostic_codes(
                &outcome.diagnostics
            ),
            vec![
                "dependency.pack_unavailable",
                "preparation.unaccounted-dependency"
            ]
        );
    }
}
