//! PHP's structural-spec coverage, kept beside the engine it exercises.
//!
//! The spec itself is
//! [`brokk_bifrost_php::structural::PHP_STRUCTURAL_SPEC`]. This assertion runs
//! through `structural::adapter_helpers`, the analysis-owned test support, so it
//! stays on this side of the crate line -- exactly as C#'s, Python's and Rust's
//! did.

#[cfg(test)]
mod structural_spec_tests {
    use brokk_bifrost_php::structural::PHP_KIND_TABLE;

    #[test]
    fn php_kind_table_matches_grammar() {
        crate::analyzer::structural::adapter_helpers::assert_kind_table_matches_grammar(
            tree_sitter_php::LANGUAGE_PHP.into(),
            "tree-sitter-php",
            PHP_KIND_TABLE,
        );
    }
}
