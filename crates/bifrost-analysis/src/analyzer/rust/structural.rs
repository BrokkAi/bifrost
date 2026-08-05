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
        assert_kind_table_matches_grammar, assert_occurrence_role, block_facts_of,
        occurrence_roles_of,
    };
    use crate::analyzer::structural::{NormalizedKind, OccurrenceRole, Role, StructuralSpec};
    use brokk_bifrost_rust::structural::{RUST_KIND_TABLE, RUST_STRUCTURAL_SPEC};

    /// Every Rust scope-forming statement list is a `block`, whether it is a
    /// function body, a conditional body, or a bare block in expression
    /// position.
    #[test]
    fn rust_blocks_become_scope_facts_wherever_they_appear() {
        let source = concat!(
            "fn demo(flag: bool) {\n",
            "    if flag {\n",
            "        work();\n",
            "    }\n",
            "    let value = { 1 };\n",
            "}\n",
        );

        assert_eq!(
            block_facts_of(
                &RUST_STRUCTURAL_SPEC,
                &tree_sitter_rust::LANGUAGE.into(),
                source,
            ),
            vec![
                concat!(
                    "{\n",
                    "    if flag {\n",
                    "        work();\n",
                    "    }\n",
                    "    let value = { 1 };\n",
                    "}",
                ),
                concat!("{\n", "        work();\n", "    }"),
                "{ 1 }",
            ]
        );
    }

    #[test]
    fn rust_retains_structured_derive_and_field_attribute_facts() {
        let source = concat!(
            "use getset::Getters;\n",
            "#[derive(Getters)]\n",
            "struct Record {\n",
            "    #[get = \"pub\"]\n",
            "    value: String,\n",
            "}\n",
        );
        let facts = crate::analyzer::structural::extract::extract_file_facts(
            &RUST_STRUCTURAL_SPEC,
            &tree_sitter_rust::LANGUAGE.into(),
            source,
        )
        .unwrap();
        let derive = facts
            .nodes()
            .iter()
            .enumerate()
            .find(|(_, node)| {
                node.kind == NormalizedKind::Decorator
                    && node
                        .name
                        .is_some_and(|name| name.text(facts.source()) == "Getters")
            })
            .map(|(index, _)| u32::try_from(index).unwrap())
            .expect("derive path decorator");
        assert_eq!(
            facts
                .role_targets(derive, Role::Module)
                .filter_map(|target| target.name)
                .map(|name| name.text(facts.source()))
                .collect::<Vec<_>>(),
            Vec::<&str>::new()
        );
        assert!(facts.nodes().iter().any(|node| {
            node.kind == NormalizedKind::Decorator
                && node
                    .name
                    .is_some_and(|name| name.text(facts.source()) == "get")
        }));
        let getter = facts
            .nodes()
            .iter()
            .enumerate()
            .find(|(_, node)| {
                node.kind == NormalizedKind::Decorator
                    && node
                        .name
                        .is_some_and(|name| name.text(facts.source()) == "get")
            })
            .map(|(index, _)| u32::try_from(index).unwrap())
            .expect("get attribute");
        assert_eq!(
            facts
                .role_targets(getter, Role::Arg)
                .map(|target| target.span.text(facts.source()))
                .collect::<Vec<_>>(),
            vec!["\"pub\""]
        );
        assert!(facts.nodes().iter().any(|node| {
            node.kind == NormalizedKind::Declaration
                && node
                    .name
                    .is_some_and(|name| name.text(facts.source()) == "value")
        }));
    }

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
