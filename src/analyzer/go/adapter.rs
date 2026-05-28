use crate::analyzer::{Language, LanguageAdapter, ProjectFile};
use tree_sitter::{Language as TsLanguage, Tree};

use super::declarations::parse_go_file;
use super::tests::go_contains_tests;

#[derive(Debug, Clone, Default)]
pub(super) struct GoAdapter;

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
}
