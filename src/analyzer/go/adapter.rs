use crate::analyzer::{Language, LanguageAdapter, ProjectFile, StorageLanguageAdapter};
use tree_sitter::{Language as TsLanguage, Parser, Tree};

use super::declarations::{determine_go_package_name, parse_go_file};
use super::packages::canonical_go_package_name;
use super::tests::go_contains_tests;

#[derive(Debug, Clone, Default)]
pub(crate) struct GoAdapter;

impl StorageLanguageAdapter for GoAdapter {
    fn storage_content_qualifier(&self, _code_unit: &crate::analyzer::CodeUnit) -> String {
        String::new()
    }

    fn storage_file_content_qualifier(&self, _package_name: &str) -> String {
        String::new()
    }

    fn hydrate_content_qualifier(&self, _content_qualifier: &str, file: &ProjectFile) -> String {
        let Ok(source) = file.read_to_string() else {
            return String::new();
        };
        let mut parser = Parser::new();
        if parser.set_language(&self.parser_language()).is_err() {
            return String::new();
        }
        let Some(tree) = parser.parse(source.as_str(), None) else {
            return String::new();
        };
        let declared = determine_go_package_name(tree.root_node(), &source);
        canonical_go_package_name(file, &declared)
    }
}

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
