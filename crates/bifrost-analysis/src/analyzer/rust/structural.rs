//! Rust's structural-spec coverage, kept beside the engine it exercises.
//!
//! The spec itself is [`brokk_bifrost_rust::structural::RUST_STRUCTURAL_SPEC`].
//! These assertions run through `structural::extract`, the analysis-owned fact
//! engine, so the tests stay on this side of the crate line (the Go pilot's
//! structural test tail did the same, in the other direction: it dropped the
//! engine dependency so it could ride along).

#[cfg(test)]
mod structural_spec_tests {
    use crate::analyzer::structural::adapter_helpers::{
        assert_kind_table_matches_grammar, assert_occurrence_role, occurrence_roles_of,
    };
    use crate::analyzer::structural::{OccurrenceRole, StructuralSpec};
    use brokk_bifrost_rust::structural::{RUST_KIND_TABLE, RUST_STRUCTURAL_SPEC};

    /// Raw identifiers are the Rust-specific trap #1473 names: `r#type` is one
    /// `identifier` token in a pattern position, so it must classify as a
    /// binder exactly like any other local, without any prefix stripping.
    #[test]
    fn rust_classifies_raw_identifier_binders_declarations_and_use_trees() {
        let source = concat!(
            "use std::collections::HashMap as Map;\n",
            "\n",
            "struct Widget {\n",
            "    label: String,\n",
            "}\n",
            "\n",
            "impl Widget {\n",
            "    fn render(&self, r#type: Map) -> String {\n",
            "        self.label.clone()\n",
            "    }\n",
            "}\n",
        );
        let found = occurrence_roles_of(
            &RUST_STRUCTURAL_SPEC,
            &tree_sitter_rust::LANGUAGE.into(),
            source,
        );

        let at = |needle: &str| source.find(needle).expect("fixture token");
        assert_occurrence_role(&found, at("std"), OccurrenceRole::PathSegment);
        assert_occurrence_role(&found, at("collections"), OccurrenceRole::PathSegment);
        assert_occurrence_role(&found, at("HashMap"), OccurrenceRole::ImportTarget);
        assert_occurrence_role(&found, at("Map;"), OccurrenceRole::ImportAlias);
        assert_occurrence_role(&found, at("Widget {"), OccurrenceRole::DeclarationName);
        assert_occurrence_role(&found, at("label: String"), OccurrenceRole::DeclarationName);
        assert_occurrence_role(&found, at("String,"), OccurrenceRole::TypeOperand);
        assert_occurrence_role(&found, at("render"), OccurrenceRole::DeclarationName);
        assert_occurrence_role(&found, at("r#type"), OccurrenceRole::Binder);
        assert_occurrence_role(&found, at("Map)"), OccurrenceRole::TypeOperand);
        assert_occurrence_role(&found, at("label.clone"), OccurrenceRole::MemberPosition);
        assert_occurrence_role(&found, at("clone()"), OccurrenceRole::MemberPosition);
    }

    #[test]
    fn rust_emits_only_roles_it_declares_as_supported() {
        let source = "fn f(a: u32) -> u32 { let b = a; b }\n";
        let found = occurrence_roles_of(
            &RUST_STRUCTURAL_SPEC,
            &tree_sitter_rust::LANGUAGE.into(),
            source,
        );
        assert!(!found.is_empty());
        for (_, text, role) in &found {
            assert!(
                RUST_STRUCTURAL_SPEC
                    .occurrence_role_support()
                    .is_supported(*role),
                "rust emitted undeclared role {role:?} for {text:?}"
            );
        }
    }

    #[test]
    fn rust_kind_table_matches_grammar() {
        assert_kind_table_matches_grammar(
            tree_sitter_rust::LANGUAGE.into(),
            "tree-sitter-rust",
            RUST_KIND_TABLE,
        );
    }
}
