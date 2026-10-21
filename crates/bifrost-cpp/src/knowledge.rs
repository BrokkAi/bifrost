//! Analyzer-independent language rules.

use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::language_knowledge::LanguageKnowledge;
use brokk_bifrost_core::analyzer::language_knowledge::ParserFlavor;
use brokk_bifrost_core::analyzer::structural::spec::StructuralSpec;

/// Cpp syntax and static language rules.
pub struct CppKnowledge;

impl LanguageKnowledge for CppKnowledge {
    fn language(&self) -> Language {
        Language::Cpp
    }

    fn skips_local_declaration(&self, node: tree_sitter::Node<'_>, source: &str) -> bool {
        match node.kind() {
            "declaration" => {
                crate::declarations::is_direct_recovered_exported_class_field_declaration(
                    node, source,
                )
            }
            "init_declarator" => node.parent().is_some_and(|declaration| {
                crate::declarations::is_direct_recovered_exported_class_field_declaration(
                    declaration,
                    source,
                )
            }),
            _ => false,
        }
    }

    fn package_separator(&self) -> &'static str {
        "::"
    }

    fn qualified_call_separator(&self) -> &'static str {
        "::"
    }

    fn parser_language(&self, _flavor: ParserFlavor) -> tree_sitter::Language {
        tree_sitter_cpp::LANGUAGE.into()
    }

    fn structural_spec(&self) -> &'static dyn StructuralSpec {
        &crate::structural::CPP_STRUCTURAL_SPEC
    }

    fn highlight_query(&self) -> Option<&'static str> {
        Some(tree_sitter_cpp::HIGHLIGHT_QUERY)
    }
}
