//! Analyzer-independent language rules.

use brokk_bifrost_core::analyzer::CodeUnit;
use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::language_knowledge::LanguageKnowledge;
use brokk_bifrost_core::analyzer::language_knowledge::ParserFlavor;
use brokk_bifrost_core::analyzer::project::Project;
use brokk_bifrost_core::analyzer::structural::spec::StructuralSpec;

/// Javascript syntax and static language rules.
pub struct JavascriptKnowledge;

impl LanguageKnowledge for JavascriptKnowledge {
    fn language(&self) -> Language {
        Language::JavaScript
    }

    fn path_synthetic_module_unit(
        &self,
        _project: &dyn Project,
        file: &ProjectFile,
    ) -> Option<CodeUnit> {
        Some(crate::model::module_code_unit(file))
    }

    /// An `export default ...` statement names its declaration with the `default`
    /// keyword, which both grammars spell as an anonymous token the named-children
    /// search cannot see (#2733).
    fn declaration_name_node<'t>(
        &self,
        declaration: tree_sitter::Node<'t>,
    ) -> Option<tree_sitter::Node<'t>> {
        crate::syntax::js_ts_declaration_name(declaration)
    }

    fn scans_local_declarations_after_focus(&self) -> bool {
        true
    }

    /// `.jsx` retains the TSX grammar and distinct storage identity introduced
    /// by #3322. Standard `.js` uses Brokk's JavaScript grammar, whose #3342
    /// repair admits reserved words in JSX name positions without importing
    /// TSX's ordinary-JavaScript grammar differences.
    fn parser_language(&self, flavor: ParserFlavor) -> tree_sitter::Language {
        match flavor {
            ParserFlavor::Tsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
            ParserFlavor::Default => tree_sitter_javascript::LANGUAGE.into(),
        }
    }

    fn publishes_single_segment_external_owners(&self) -> bool {
        true
    }

    fn structural_spec(&self) -> &'static dyn StructuralSpec {
        &crate::structural::JAVASCRIPT_STRUCTURAL_SPEC
    }

    fn highlight_query(&self) -> Option<&'static str> {
        Some(tree_sitter_javascript::HIGHLIGHT_QUERY)
    }
}

/// Typescript syntax and static language rules.
pub struct TypescriptKnowledge;

impl LanguageKnowledge for TypescriptKnowledge {
    fn language(&self) -> Language {
        Language::TypeScript
    }

    fn path_synthetic_module_unit(
        &self,
        _project: &dyn Project,
        file: &ProjectFile,
    ) -> Option<CodeUnit> {
        Some(crate::model::module_code_unit(file))
    }

    /// `$static` is an internal marker keeping static and instance members distinct in
    /// the index; it is not written in source and not shown to a reader.
    fn display_symbol_name(&self, symbol: &str) -> String {
        symbol.strip_suffix("$static").unwrap_or(symbol).to_string()
    }

    fn source_identifier<'s>(&self, identifier: &'s str) -> &'s str {
        identifier.strip_suffix("$static").unwrap_or(identifier)
    }

    /// Same anonymous `default` keyword as JavaScript: the TS and TSX grammars
    /// share the `export_statement` shape with tree-sitter-javascript (#2733).
    fn declaration_name_node<'t>(
        &self,
        declaration: tree_sitter::Node<'t>,
    ) -> Option<tree_sitter::Node<'t>> {
        crate::syntax::js_ts_declaration_name(declaration)
    }

    fn scans_local_declarations_after_focus(&self) -> bool {
        true
    }

    /// The one language whose grammar depends on the flavor: `.tsx` files parse under
    /// the TSX grammar while sharing the TypeScript adapter and structural spec.
    fn parser_language(&self, flavor: ParserFlavor) -> tree_sitter::Language {
        match flavor {
            ParserFlavor::Tsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
            ParserFlavor::Default => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        }
    }

    fn publishes_single_segment_external_owners(&self) -> bool {
        true
    }

    fn structural_spec(&self) -> &'static dyn StructuralSpec {
        &crate::structural::TYPESCRIPT_STRUCTURAL_SPEC
    }

    fn highlight_query(&self) -> Option<&'static str> {
        Some(tree_sitter_typescript::HIGHLIGHTS_QUERY)
    }
}
