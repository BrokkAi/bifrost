use crate::analyzer::{Language, LanguageAdapter, ProjectFile};
use tree_sitter::{Language as TsLanguage, Tree};

use super::declarations::parse_php_file;
use super::tests::php_contains_tests;

#[derive(Debug, Clone, Default)]
pub(super) struct PhpAdapter;

impl LanguageAdapter for PhpAdapter {
    fn language(&self) -> Language {
        Language::Php
    }

    fn query_directory(&self) -> &'static str {
        "resources/treesitter/php"
    }

    fn parser_language(&self) -> TsLanguage {
        tree_sitter_php::LANGUAGE_PHP.into()
    }

    fn file_extension(&self) -> &'static str {
        "php"
    }

    fn contains_tests(
        &self,
        _file: &ProjectFile,
        source: &str,
        _tree: &Tree,
        parsed: &crate::analyzer::tree_sitter_analyzer::ParsedFile,
    ) -> bool {
        php_contains_tests(source, parsed)
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        let trimmed = reference.trim();
        let before_args = trimmed
            .split_once('(')
            .map(|(head, _)| head)
            .unwrap_or(trimmed);
        before_args
            .rsplit_once("::")
            .or_else(|| before_args.rsplit_once("->"))
            .map(|(receiver, _)| receiver.to_string())
    }

    fn parse_file(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
    ) -> crate::analyzer::tree_sitter_analyzer::ParsedFile {
        parse_php_file(file, source, tree)
    }
}
