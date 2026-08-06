//! JS/TS structural-spec coverage, kept beside the engine it exercises.
//!
//! The two specs themselves are
//! [`brokk_bifrost_js_ts::structural::JAVASCRIPT_STRUCTURAL_SPEC`] and
//! [`brokk_bifrost_js_ts::structural::TYPESCRIPT_STRUCTURAL_SPEC`]. These
//! assertions run through `structural::adapter_helpers`, the analysis-owned test
//! support, so they stay on this side of the crate line -- exactly as C++'s,
//! C#'s, PHP's, Python's and Rust's did.

#[cfg(test)]
mod structural_spec_tests {
    use brokk_bifrost_js_ts::structural::*;

    use crate::analyzer::structural::adapter_helpers::{
        assert_occurrence_role, block_facts_of, occurrence_roles_of,
    };
    use brokk_bifrost_core::analyzer::structural::occurrences::OccurrenceRole;
    use brokk_bifrost_core::analyzer::structural::spec::StructuralSpec;

    /// The JS/TS scope-forming statement lists are `statement_block` and
    /// `switch_body`; a class body is a member list and stays out.
    #[test]
    fn js_ts_statement_blocks_and_switch_bodies_become_scope_facts() {
        let source = concat!(
            "function demo(flag) {\n",
            "  if (flag) {\n",
            "    work();\n",
            "  }\n",
            "  switch (flag) {\n",
            "    default:\n",
            "      break;\n",
            "  }\n",
            "}\n",
        );

        assert_eq!(
            block_facts_of(
                &JAVASCRIPT_STRUCTURAL_SPEC,
                &tree_sitter_javascript::LANGUAGE.into(),
                source,
            ),
            vec![
                concat!(
                    "{\n",
                    "  if (flag) {\n",
                    "    work();\n",
                    "  }\n",
                    "  switch (flag) {\n",
                    "    default:\n",
                    "      break;\n",
                    "  }\n",
                    "}",
                ),
                concat!("{\n", "    work();\n", "  }"),
                concat!("{\n", "    default:\n", "      break;\n", "  }"),
            ]
        );
    }

    /// The JS/TS trap #1473 names: shorthand `{ alpha }` binds in a pattern and
    /// reads in an expression. The grammar already distinguishes the two
    /// (`shorthand_property_identifier_pattern` vs
    /// `shorthand_property_identifier`), so the classification must never come
    /// down to what the token looks like.
    #[test]
    fn js_ts_separates_destructuring_binders_from_expression_shorthand_reads() {
        let source = concat!(
            "import { readFile as read } from \"fs\";\n",
            "\n",
            "const { alpha, beta: gamma } = source;\n",
            "const payload = { alpha, delta: gamma };\n",
            "\n",
            "function render(label) {\n",
            "  return payload.alpha;\n",
            "}\n",
        );
        let found = occurrence_roles_of(
            &JAVASCRIPT_STRUCTURAL_SPEC,
            &tree_sitter_javascript::LANGUAGE.into(),
            source,
        );

        let at = |needle: &str| source.find(needle).expect("fixture token");
        assert_occurrence_role(&found, at("readFile"), OccurrenceRole::ImportTarget);
        assert_occurrence_role(&found, at("read }"), OccurrenceRole::ImportAlias);
        // `alpha` in the destructuring pattern binds; `alpha` in the object
        // literal three lines down reads the binding it just created.
        assert_occurrence_role(&found, at("alpha, beta"), OccurrenceRole::Binder);
        assert_occurrence_role(&found, at("beta"), OccurrenceRole::LabelOrKey);
        assert_occurrence_role(&found, at("gamma }"), OccurrenceRole::Binder);
        assert_occurrence_role(&found, at("source;"), OccurrenceRole::ValueReference);
        assert_occurrence_role(&found, at("payload ="), OccurrenceRole::Binder);
        assert_occurrence_role(&found, at("alpha, delta"), OccurrenceRole::ValueReference);
        assert_occurrence_role(&found, at("delta"), OccurrenceRole::LabelOrKey);
        assert_occurrence_role(&found, at("gamma };"), OccurrenceRole::ValueReference);
        assert_occurrence_role(&found, at("render"), OccurrenceRole::DeclarationName);
        assert_occurrence_role(&found, at("label)"), OccurrenceRole::Binder);
        assert_occurrence_role(
            &found,
            at("payload.alpha"),
            OccurrenceRole::ReceiverPosition,
        );
        assert_occurrence_role(&found, at("alpha;"), OccurrenceRole::MemberPosition);
    }

    /// TypeScript adds `type_identifier`, whose every position is a type
    /// operand except the declaration heads that introduce it.
    #[test]
    fn typescript_separates_type_declaration_heads_from_type_operands() {
        let source = concat!(
            "interface Widget {\n",
            "  label: string;\n",
            "}\n",
            "\n",
            "function render(widget: Widget): Widget {\n",
            "  return widget;\n",
            "}\n",
        );
        let found = occurrence_roles_of(
            &TYPESCRIPT_STRUCTURAL_SPEC,
            &tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            source,
        );

        let at = |needle: &str| source.find(needle).expect("fixture token");
        assert_occurrence_role(&found, at("Widget {"), OccurrenceRole::DeclarationName);
        assert_occurrence_role(&found, at("label"), OccurrenceRole::DeclarationName);
        assert_occurrence_role(&found, at("widget: Widget"), OccurrenceRole::Binder);
        assert_occurrence_role(&found, at("Widget)"), OccurrenceRole::TypeOperand);
        assert_occurrence_role(
            &found,
            at("Widget {\n  return"),
            OccurrenceRole::TypeOperand,
        );
        assert_occurrence_role(&found, at("widget;"), OccurrenceRole::ValueReference);
    }

    #[test]
    fn js_ts_emits_only_roles_it_declares_as_supported() {
        let source = "const { a } = b; function f(c) { return a.d(c); }\n";
        let found = occurrence_roles_of(
            &JAVASCRIPT_STRUCTURAL_SPEC,
            &tree_sitter_javascript::LANGUAGE.into(),
            source,
        );
        assert!(!found.is_empty());
        for (_, text, role) in &found {
            assert!(
                JAVASCRIPT_STRUCTURAL_SPEC
                    .occurrence_role_support()
                    .is_supported(*role),
                "javascript emitted undeclared role {role:?} for {text:?}"
            );
        }
    }

    #[test]
    fn javascript_kind_table_matches_grammar() {
        crate::analyzer::structural::adapter_helpers::assert_kind_table_matches_grammar(
            tree_sitter_javascript::LANGUAGE.into(),
            "tree-sitter-javascript",
            JS_KIND_TABLE,
        );
    }

    #[test]
    fn typescript_kind_table_matches_grammar() {
        crate::analyzer::structural::adapter_helpers::assert_kind_table_matches_grammar(
            tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            "tree-sitter-typescript",
            TS_KIND_TABLE,
        );
    }

    #[test]
    fn tsx_kind_table_matches_grammar() {
        crate::analyzer::structural::adapter_helpers::assert_kind_table_matches_grammar(
            tree_sitter_typescript::LANGUAGE_TSX.into(),
            "tree-sitter-tsx",
            TS_KIND_TABLE,
        );
    }
}
