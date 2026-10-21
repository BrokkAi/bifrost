//! Analyzer-independent language rules.

use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::language_knowledge::LanguageKnowledge;
use brokk_bifrost_core::analyzer::language_knowledge::ParserFlavor;
use brokk_bifrost_core::analyzer::structural::spec::StructuralSpec;

/// CSharp syntax and static language rules.
pub struct CSharpKnowledge;

impl LanguageKnowledge for CSharpKnowledge {
    fn language(&self) -> Language {
        Language::CSharp
    }

    fn display_symbol_name(&self, symbol: &str) -> String {
        crate::syntax::csharp_normalize_full_name(symbol)
    }

    fn source_identifier<'s>(&self, identifier: &'s str) -> &'s str {
        crate::syntax::strip_csharp_generic_arity(identifier)
    }

    fn alias_name_segment<'s>(&self, segment: &'s str) -> &'s str {
        crate::syntax::csharp_source_name_segment(segment)
    }

    fn parser_language(&self, _flavor: ParserFlavor) -> tree_sitter::Language {
        tree_sitter_c_sharp::LANGUAGE.into()
    }

    fn structural_spec(&self) -> &'static dyn StructuralSpec {
        &crate::structural::CSHARP_STRUCTURAL_SPEC
    }

    fn highlight_query(&self) -> Option<&'static str> {
        Some(tree_sitter_c_sharp::HIGHLIGHTS_QUERY)
    }
}
