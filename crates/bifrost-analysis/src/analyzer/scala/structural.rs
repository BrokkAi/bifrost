//! Scala's structural-spec coverage, kept beside the engine it exercises.
//!
//! The spec itself is
//! [`brokk_bifrost_jvm::scala::structural::SCALA_STRUCTURAL_SPEC`]. The kind
//! table assertion runs through `structural::adapter_helpers`, the
//! analysis-owned test support, so it stays on this side of the crate line --
//! exactly as Java's, C++'s, C#'s, PHP's, Python's and Rust's did.

#[cfg(test)]
mod structural_spec_tests {
    use brokk_bifrost_jvm::scala::structural::SCALA_KIND_TABLE;

    #[test]
    fn scala_kind_table_matches_grammar() {
        crate::analyzer::structural::adapter_helpers::assert_kind_table_matches_grammar(
            brokk_bifrost_jvm::scala::language::LANGUAGE.into(),
            "tree-sitter-scala",
            SCALA_KIND_TABLE,
        );
    }
}
