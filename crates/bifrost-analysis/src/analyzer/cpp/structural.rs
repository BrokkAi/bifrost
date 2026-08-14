//! C++'s structural-spec coverage, kept beside the engine it exercises.
//!
//! The spec itself is
//! [`brokk_bifrost_cpp::structural::CPP_STRUCTURAL_SPEC`]. This assertion runs
//! through `structural::adapter_helpers`, the analysis-owned test support, so it
//! stays on this side of the crate line -- exactly as C#'s, PHP's, Python's and
//! Rust's did.

#[cfg(test)]
mod structural_spec_tests {
    use brokk_bifrost_cpp::structural::CPP_KIND_TABLE;

    #[test]
    fn cpp_kind_table_matches_grammar() {
        crate::analyzer::structural::adapter_helpers::assert_kind_table_matches_grammar(
            tree_sitter_cpp::LANGUAGE.into(),
            "tree-sitter-cpp",
            CPP_KIND_TABLE,
        );
    }
}
