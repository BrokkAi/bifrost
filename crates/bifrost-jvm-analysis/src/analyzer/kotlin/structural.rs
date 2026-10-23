//! Kotlin's structural-spec coverage, kept beside the engine it exercises.
//!
//! The spec itself is
//! [`brokk_bifrost_jvm::kotlin::structural::KOTLIN_STRUCTURAL_SPEC`]. These
//! assertions run through `structural::adapter_helpers`, the analysis-owned
//! test support, so they stay on this side of the crate line -- exactly as
//! Java's, Scala's, C++'s, C#'s, PHP's, Python's and Rust's did.

#[cfg(test)]
mod structural_spec_tests {

    use brokk_bifrost_core::analyzer::structural::kinds::NormalizedKind;

    use brokk_bifrost_core::analyzer::structural::spec::StructuralSpec;
    use brokk_bifrost_jvm::kotlin::structural::{KOTLIN_KIND_TABLE, KOTLIN_STRUCTURAL_SPEC};

    #[test]
    fn kotlin_kind_table_matches_grammar() {
        brokk_bifrost_core::analyzer::structural::adapter_helpers::assert_kind_table_matches_grammar(
            brokk_bifrost_jvm::kotlin::language::LANGUAGE.into(),
            "tree-sitter-kotlin",
            KOTLIN_KIND_TABLE,
        );
    }

    #[test]
    fn kotlin_advertises_the_kinds_it_refines_into() {
        assert!(KOTLIN_STRUCTURAL_SPEC.supports_kind(NormalizedKind::Method));
        assert!(KOTLIN_STRUCTURAL_SPEC.supports_kind(NormalizedKind::Throw));
        assert!(KOTLIN_STRUCTURAL_SPEC.supports_kind(NormalizedKind::Constructor));
        assert!(KOTLIN_STRUCTURAL_SPEC.supports_kind(NormalizedKind::Callable));
        assert!(KOTLIN_STRUCTURAL_SPEC.supports_kind(NormalizedKind::Declaration));
        assert!(KOTLIN_STRUCTURAL_SPEC.supports_kind(NormalizedKind::Literal));
    }

    #[test]
    fn kotlin_supports_every_role_including_keyword_arguments() {
        use brokk_bifrost_core::analyzer::structural::kinds::Role;
        for &role in brokk_bifrost_core::analyzer::structural::kinds::ALL_ROLES {
            // #2647: the iterable/element roles are refused until the Kotlin
            // adapter extracts them.
            if matches!(role, Role::Iterable | Role::Element) {
                assert!(!KOTLIN_STRUCTURAL_SPEC.supports_role(role));
                continue;
            }
            assert!(
                KOTLIN_STRUCTURAL_SPEC.supports_role(role),
                "Kotlin should model {role:?}"
            );
        }
    }
}
