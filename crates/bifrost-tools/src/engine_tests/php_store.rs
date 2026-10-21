#[cfg(test)]
mod php_extraction_tests {

    use std::sync::Arc;

    use brokk_bifrost_analysis::analyzer::store::epoch;

    use brokk_bifrost_analysis::analyzer::store::test_support::assert_prior_parsed_blob_invalidated;

    use brokk_bifrost_analysis::analyzer::store::test_support::parse_state;

    use brokk_bifrost_core::test_support::write_file;

    use brokk_bifrost_php_analysis::analyzer::php::adapter::PhpAdapter;
    #[test]
    fn php_conditional_free_function_epoch_invalidates_prior_parsed_blobs() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "functions.php",
            "<?php\nnamespace FastRoute;\nif (true) { function route(): void {} }\n",
        );
        let state = Arc::new(parse_state(&PhpAdapter, &file));
        let prior_epoch = epoch::php_epoch_before_conditional_free_function_declarations();
        assert_prior_parsed_blob_invalidated(&PhpAdapter, state.as_ref(), &prior_epoch);
    }

    /// #1713: PHP now records the FQ names a file imports in
    /// `type_identifiers`, and it wrote no row of that family before. A blob
    /// persisted under the prior epoch deserializes as "this file imports
    /// nothing", which is indistinguishable from a file that truly imports
    /// nothing, so the salt is the only thing that retires it.
    #[test]
    fn php_imported_type_names_epoch_invalidates_prior_parsed_blobs() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "RouteCollector.php",
            "<?php\nnamespace FastRoute;\n\nclass RouteCollector {\n    public function __construct(RouteParser $parser) {}\n}\n",
        );
        let state = Arc::new(parse_state(&PhpAdapter, &file));
        assert!(
            state.type_identifiers.contains("FastRoute.RouteParser"),
            "the current walk records the same-namespace import: {:?}",
            state.type_identifiers
        );
        let prior_epoch = epoch::php_epoch_before_imported_type_names();
        assert_prior_parsed_blob_invalidated(&PhpAdapter, state.as_ref(), &prior_epoch);
    }
}
