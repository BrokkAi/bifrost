//! Analyzer-independent language rules.

use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::Range;
use brokk_bifrost_core::analyzer::language_knowledge::LanguageKnowledge;
use brokk_bifrost_core::analyzer::language_knowledge::ParserFlavor;
use brokk_bifrost_core::analyzer::structural::spec::StructuralSpec;

/// Php syntax and static language rules.
pub struct PhpKnowledge;

impl LanguageKnowledge for PhpKnowledge {
    fn language(&self) -> Language {
        Language::Php
    }

    fn declaration_name_range(&self, node: tree_sitter::Node<'_>, _source: &str) -> Range {
        crate::graph::syntax::php_declaration_name_range(node)
    }

    fn parser_language(&self, _flavor: ParserFlavor) -> tree_sitter::Language {
        tree_sitter_php::LANGUAGE_PHP.into()
    }

    fn structural_spec(&self) -> &'static dyn StructuralSpec {
        &crate::structural::PHP_STRUCTURAL_SPEC
    }

    fn highlight_query(&self) -> Option<&'static str> {
        Some(tree_sitter_php::HIGHLIGHTS_QUERY)
    }
}
