use crate::analyzer::{Language, LanguageAdapter, ProjectFile};
use tree_sitter::{Language as TsLanguage, Tree};

use super::declarations::parse_go_file;
use super::packages::canonical_go_package_name;
use super::tests::go_contains_tests;

#[derive(Debug, Clone, Default)]
pub(crate) struct GoAdapter;

impl LanguageAdapter for GoAdapter {
    fn language(&self) -> Language {
        Language::Go
    }

    fn query_directory(&self) -> &'static str {
        "resources/treesitter/go"
    }

    fn parser_language(&self) -> TsLanguage {
        tree_sitter_go::LANGUAGE.into()
    }

    fn file_extension(&self) -> &'static str {
        "go"
    }

    fn storage_content_qualifier(
        &self,
        _code_unit: &crate::analyzer::CodeUnit,
        content_qualifier: &str,
    ) -> String {
        content_qualifier.to_string()
    }

    fn persisted_content_qualifier_supports_substring_search(&self) -> bool {
        false
    }

    fn storage_file_content_qualifier(&self, content_qualifier: &str) -> String {
        content_qualifier.to_string()
    }

    fn hydrate_content_qualifier(&self, content_qualifier: &str, file: &ProjectFile) -> String {
        canonical_go_package_name(file, content_qualifier)
    }

    fn contains_tests(
        &self,
        _file: &ProjectFile,
        source: &str,
        tree: &Tree,
        _parsed: &crate::analyzer::tree_sitter_analyzer::ParsedFile,
    ) -> bool {
        go_contains_tests(tree.root_node(), source)
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        let trimmed = reference.trim();
        let before_args = trimmed
            .split_once('(')
            .map(|(head, _)| head)
            .unwrap_or(trimmed);
        before_args
            .rsplit_once('.')
            .map(|(receiver, _)| receiver.to_string())
    }

    fn parse_file(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
    ) -> crate::analyzer::tree_sitter_analyzer::ParsedFile {
        parse_go_file(file, source, tree)
    }

    fn structural_spec(&self) -> Option<&'static dyn crate::analyzer::structural::StructuralSpec> {
        Some(&super::structural::GO_STRUCTURAL_SPEC)
    }
}
