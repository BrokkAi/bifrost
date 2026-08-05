//! The `LanguageAdapter` forwarding shell for PHP.
//!
//! Every answer below comes from [`brokk_bifrost_php`]; nothing PHP-specific is
//! left here but the trait impl itself.

use crate::analyzer::cognitive_complexity;
use crate::analyzer::{Language, LanguageAdapter, ProjectFile};
use brokk_bifrost_php::adapter::{
    PHP_COGNITIVE_CONFIG, PHP_FILE_EXTENSION, php_extract_call_receiver,
    php_signature_return_type_text,
};
use brokk_bifrost_php::declarations::parse_php_file;
use brokk_bifrost_php::test_detection::php_contains_tests;
use tree_sitter::Tree;

#[derive(Debug, Clone, Default)]
pub(crate) struct PhpAdapter;

impl LanguageAdapter for PhpAdapter {
    fn language(&self) -> Language {
        Language::Php
    }

    fn query_directory(&self) -> &'static str {
        "resources/treesitter/php"
    }

    fn file_extension(&self) -> &'static str {
        PHP_FILE_EXTENSION
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
        php_extract_call_receiver(reference)
    }

    fn callable_return_type_text<'a>(&self, signature: &'a str) -> Option<&'a str> {
        php_signature_return_type_text(signature)
    }

    fn parse_file(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
    ) -> crate::analyzer::tree_sitter_analyzer::ParsedFile {
        parse_php_file(file, source, tree)
    }

    fn cognitive_complexity_config(&self) -> Option<&'static cognitive_complexity::Config> {
        Some(&PHP_COGNITIVE_CONFIG)
    }
}
