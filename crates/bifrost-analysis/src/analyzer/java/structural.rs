//! Java's structural-spec coverage, kept beside the engine it exercises.
//!
//! The spec itself is
//! [`brokk_bifrost_jvm::java::structural::JAVA_STRUCTURAL_SPEC`]. These
//! assertions run through `structural::adapter_helpers`, the analysis-owned
//! test support, so they stay on this side of the crate line -- exactly as
//! C++'s, C#'s, PHP's, Python's and Rust's did.

#[cfg(test)]
mod structural_spec_tests {

    use crate::analyzer::structural::adapter_helpers::{
        assert_occurrence_role, block_facts_of, occurrence_roles_of,
    };
    use brokk_bifrost_core::analyzer::structural::occurrences::OccurrenceRole;
    use brokk_bifrost_core::analyzer::structural::spec::StructuralSpec;
    use brokk_bifrost_jvm::java::structural::{JAVA_KIND_TABLE, JAVA_STRUCTURAL_SPEC};

    /// Java's scope-forming statement lists are `block` and `switch_block`.
    /// The class body is neither: it is a member list, and the declarations in
    /// it are already facts of their own.
    #[test]
    fn java_blocks_and_switch_blocks_become_scope_facts() {
        let source = concat!(
            "class Widget {\n",
            "    void render(int size) {\n",
            "        if (size > 0) {\n",
            "            log(size);\n",
            "        }\n",
            "        switch (size) {\n",
            "            default:\n",
            "                break;\n",
            "        }\n",
            "    }\n",
            "}\n",
        );

        assert_eq!(
            block_facts_of(
                &JAVA_STRUCTURAL_SPEC,
                &tree_sitter_java::LANGUAGE.into(),
                source,
            ),
            vec![
                concat!(
                    "{\n",
                    "        if (size > 0) {\n",
                    "            log(size);\n",
                    "        }\n",
                    "        switch (size) {\n",
                    "            default:\n",
                    "                break;\n",
                    "        }\n",
                    "    }",
                ),
                concat!("{\n", "            log(size);\n", "        }"),
                concat!(
                    "{\n",
                    "            default:\n",
                    "                break;\n",
                    "        }",
                ),
            ]
        );
    }

    /// The four positions #1473 names for Java: a declaration head, a bound
    /// parameter, an annotation operand consumed as a type, and the tail of an
    /// import — each of which a semantic layer has historically mislabelled.
    #[test]
    fn java_classifies_declaration_binder_annotation_and_import_positions() {
        let source = concat!(
            "package com.example.app;\n",
            "import java.util.List;\n",
            "@Deprecated\n",
            "class Widget {\n",
            "    List<String> render(String label) {\n",
            "        return helper.build(label);\n",
            "    }\n",
            "}\n",
        );
        let found = occurrence_roles_of(
            &JAVA_STRUCTURAL_SPEC,
            &tree_sitter_java::LANGUAGE.into(),
            source,
        );

        let at = |needle: &str| source.find(needle).expect("fixture token");
        assert_occurrence_role(&found, at("Widget"), OccurrenceRole::DeclarationName);
        assert_occurrence_role(&found, at("render"), OccurrenceRole::DeclarationName);
        assert_occurrence_role(&found, at("label)"), OccurrenceRole::Binder);
        assert_occurrence_role(&found, at("Deprecated"), OccurrenceRole::TypeOperand);
        assert_occurrence_role(&found, at("List;"), OccurrenceRole::ImportTarget);
        assert_occurrence_role(&found, at("java.util"), OccurrenceRole::PathSegment);
        assert_occurrence_role(&found, at("List<String>"), OccurrenceRole::TypeOperand);
        assert_occurrence_role(&found, at("String label"), OccurrenceRole::TypeOperand);
        assert_occurrence_role(&found, at("helper"), OccurrenceRole::ReceiverPosition);
        assert_occurrence_role(&found, at("build"), OccurrenceRole::MemberPosition);
        assert_occurrence_role(&found, at("label);"), OccurrenceRole::ValueReference);
    }

    /// Support is a declaration, not a description of what happened to be
    /// emitted: every role Java emits must be one it declares.
    #[test]
    fn java_emits_only_roles_it_declares_as_supported() {
        let source = "class A { void f(int b) { c.d(b); } }\n";
        let found = occurrence_roles_of(
            &JAVA_STRUCTURAL_SPEC,
            &tree_sitter_java::LANGUAGE.into(),
            source,
        );
        assert!(!found.is_empty());
        for (_, text, role) in &found {
            assert!(
                JAVA_STRUCTURAL_SPEC
                    .occurrence_role_support()
                    .is_supported(*role),
                "java emitted undeclared role {role:?} for {text:?}"
            );
        }
    }

    #[test]
    fn java_kind_table_matches_grammar() {
        crate::analyzer::structural::adapter_helpers::assert_kind_table_matches_grammar(
            tree_sitter_java::LANGUAGE.into(),
            "tree-sitter-java",
            JAVA_KIND_TABLE,
        );
    }
}
