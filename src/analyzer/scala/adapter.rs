use crate::analyzer::{Language, LanguageAdapter, ProjectFile};
use tree_sitter::{Language as TsLanguage, Tree};

use super::declarations::parse_scala_file;
use super::tests::scala_contains_tests;

#[derive(Debug, Clone, Default)]
pub(super) struct ScalaAdapter;

impl LanguageAdapter for ScalaAdapter {
    fn language(&self) -> Language {
        Language::Scala
    }

    fn query_directory(&self) -> &'static str {
        "resources/treesitter/scala"
    }

    fn parser_language(&self) -> TsLanguage {
        tree_sitter_scala::LANGUAGE.into()
    }

    fn file_extension(&self) -> &'static str {
        "scala"
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

    fn contains_tests(
        &self,
        _file: &ProjectFile,
        source: &str,
        _tree: &Tree,
        _parsed: &crate::analyzer::tree_sitter_analyzer::ParsedFile,
    ) -> bool {
        scala_contains_tests(source)
    }

    fn parse_file(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
    ) -> crate::analyzer::tree_sitter_analyzer::ParsedFile {
        parse_scala_file(file, source, tree)
    }
}
