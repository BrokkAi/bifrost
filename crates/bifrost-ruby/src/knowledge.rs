//! Analyzer-independent language rules.

use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::Range;
use brokk_bifrost_core::analyzer::language_knowledge::LanguageKnowledge;
use brokk_bifrost_core::analyzer::language_knowledge::ParserFlavor;
use brokk_bifrost_core::analyzer::structural::spec::StructuralSpec;

/// Ruby syntax and static language rules.
pub struct RubyKnowledge;

impl LanguageKnowledge for RubyKnowledge {
    fn language(&self) -> Language {
        Language::Ruby
    }

    fn declaration_name_range(&self, node: tree_sitter::Node<'_>, source: &str) -> Range {
        crate::syntax::ruby_semantic_identifier_range(node, source)
    }

    fn symbol_literal_name(&self, node: tree_sitter::Node<'_>, source: &str) -> Option<String> {
        crate::imports::ruby_symbol_name(node, source)
    }

    fn parser_language(&self, _flavor: ParserFlavor) -> tree_sitter::Language {
        tree_sitter_ruby::LANGUAGE.into()
    }

    fn structural_spec(&self) -> &'static dyn StructuralSpec {
        &crate::structural::RUBY_STRUCTURAL_SPEC
    }

    fn highlight_query(&self) -> Option<&'static str> {
        Some(tree_sitter_ruby::HIGHLIGHTS_QUERY)
    }
}
