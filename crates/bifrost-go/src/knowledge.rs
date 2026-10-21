//! Analyzer-independent language rules.

use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::language_knowledge::LanguageKnowledge;
use brokk_bifrost_core::analyzer::language_knowledge::ParserFlavor;
use brokk_bifrost_core::analyzer::structural::spec::StructuralSpec;

/// Go syntax and static language rules.
pub struct GoKnowledge;

impl LanguageKnowledge for GoKnowledge {
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
