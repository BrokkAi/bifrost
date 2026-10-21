//! Analyzer-independent language rules.

use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::language_knowledge::LanguageKnowledge;
use brokk_bifrost_core::analyzer::language_knowledge::ParserFlavor;
use brokk_bifrost_core::analyzer::structural::spec::StructuralSpec;

/// Rust syntax and static language rules.
pub struct RustKnowledge;

impl LanguageKnowledge for RustKnowledge {
    fn unbound_call_passes_receiver_as_argument(&self) -> bool {
        true
    }

    fn generated_items_cannot_shadow_bindings(&self) -> bool {
        true
    }

    fn language(&self) -> Language {
        Language::Rust
    }

    fn qualified_call_separator(&self) -> &'static str {
        "::"
    }

    fn parser_language(&self, _flavor: ParserFlavor) -> tree_sitter::Language {
        tree_sitter_rust::LANGUAGE.into()
    }

    fn structural_spec(&self) -> &'static dyn StructuralSpec {
        &crate::structural::RUST_STRUCTURAL_SPEC
    }

    fn highlight_query(&self) -> Option<&'static str> {
        Some(tree_sitter_rust::HIGHLIGHTS_QUERY)
    }
}
