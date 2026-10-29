//! Analyzer-independent language rules.

use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::language_knowledge::LanguageKnowledge;
use brokk_bifrost_core::analyzer::language_knowledge::ParserFlavor;
use brokk_bifrost_core::analyzer::structural::spec::StructuralSpec;

/// CSharp syntax and static language rules.
pub struct CSharpKnowledge;

impl LanguageKnowledge for CSharpKnowledge {
    fn models_compose_from_catalog_rows(&self) -> bool {
        true
    }

    fn declared_type_is_referent_immutable(&self, _canonical_type: &str) -> bool {
        false
    }

    fn field_initializer<'t>(
        &self,
        node: tree_sitter::Node<'t>,
    ) -> Option<(tree_sitter::Node<'t>, tree_sitter::Node<'t>)> {
        if !matches!(node.kind(), "variable_declarator" | "property_declaration") {
            return None;
        }
        // brokk-tree-sitter-c-sharp 0.23.8 grammar.js:792 defines
        // variable_declarator = name [brackets] ('=' expression)?, without
        // an initializer field. Select the named sibling directly after the
        // anonymous '=' AST token, never an arbitrary child after the name.
        // property_declaration (:694) also uses its `value` field for an
        // arrow body; that field alone does not prove an initializer.
        let mut cursor = node.walk();
        let value = node
            .children(&mut cursor)
            .find(|child| !child.is_named() && child.kind() == "=")
            .and_then(|equals| equals.next_named_sibling())
            .or_else(|| node.child_by_field_name("value"))
            .or_else(|| node.child_by_field_name("initializer"))
            .or_else(|| {
                let mut cursor = node.walk();
                node.named_children(&mut cursor)
                    .find(|child| child.kind() == "equals_value_clause")
                    .and_then(|clause| {
                        clause
                            .child_by_field_name("value")
                            .or_else(|| clause.named_child(0))
                    })
            })?;
        if value.kind() == "arrow_expression_clause" {
            return None;
        }
        Some((node.child_by_field_name("name")?, value))
    }

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
