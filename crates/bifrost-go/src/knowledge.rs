//! Analyzer-independent language rules.

use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::language_knowledge::GuardConditionSyntax;
use brokk_bifrost_core::analyzer::language_knowledge::LanguageKnowledge;
use brokk_bifrost_core::analyzer::language_knowledge::ParserFlavor;
use brokk_bifrost_core::analyzer::structural::spec::StructuralSpec;

/// Go syntax and static language rules.
pub struct GoKnowledge;

impl LanguageKnowledge for GoKnowledge {
    fn semantic_string_constant_value(&self, payload: &str) -> Option<String> {
        String::from_utf8(crate::build_files::go_string_literal_bytes(payload)?).ok()
    }

    fn declared_type_is_referent_immutable(&self, canonical_type: &str) -> bool {
        matches!(
            canonical_type,
            "string"
                | "bool"
                | "byte"
                | "rune"
                | "int"
                | "int8"
                | "int16"
                | "int32"
                | "int64"
                | "uint"
                | "uint8"
                | "uint16"
                | "uint32"
                | "uint64"
                | "uintptr"
                | "float32"
                | "float64"
                | "complex64"
                | "complex128"
        )
    }

    fn guard_condition_syntax(&self) -> Option<&'static GuardConditionSyntax> {
        Some(&GuardConditionSyntax {
            call_kinds: &["call_expression"],
            parenthesis_kinds: &["parenthesized_expression"],
            parenthesis_field: None,
            negation_kinds: &["unary_expression"],
            operator_field: "operator",
            negation_operator: "!",
            operand_field: "operand",
        })
    }

    fn language(&self) -> Language {
        Language::Go
    }

    fn call_may_apply_value(&self) -> bool {
        true
    }

    fn callable_result_is_applicability_independent(&self) -> bool {
        true
    }

    fn package_separator(&self) -> &'static str {
        "/"
    }

    fn parser_language(&self, _flavor: ParserFlavor) -> tree_sitter::Language {
        tree_sitter_go::LANGUAGE.into()
    }

    fn structural_spec(&self) -> &'static dyn StructuralSpec {
        &crate::structural::GO_STRUCTURAL_SPEC
    }

    fn highlight_query(&self) -> Option<&'static str> {
        Some(tree_sitter_go::HIGHLIGHTS_QUERY)
    }
}
