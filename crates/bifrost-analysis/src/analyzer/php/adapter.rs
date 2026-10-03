//! The `LanguageAdapter` forwarding shell for PHP.
//!
//! Every answer below comes from [`brokk_bifrost_php`]; nothing PHP-specific is
//! left here but the trait impl itself.

use crate::analyzer::cognitive_complexity;
use crate::analyzer::{Language, LanguageAdapter, ProjectFile};
use brokk_bifrost_php::adapter::{
    PHP_COGNITIVE_CONFIG, PHP_FILE_EXTENSION, php_extract_call_receiver,
};
use brokk_bifrost_php::declarations::parse_php_file;
use brokk_bifrost_php::queries::PHP_QUERY_DIRECTORY;
use brokk_bifrost_php::test_detection::php_contains_tests;
use tree_sitter::Tree;

#[derive(Debug, Clone, Default)]
pub(crate) struct PhpAdapter;

impl LanguageAdapter for PhpAdapter {
    fn source_fact_storage(&self) -> Option<&'static crate::analyzer::store::SourceFactStorage> {
        Some(&crate::analyzer::php::source_publication::SOURCE_STORAGE)
    }

    fn requires_source_declaration_metadata_bridges(&self) -> bool {
        true
    }

    fn produces_canonical_source_facts(&self) -> bool {
        true
    }

    fn php_source_facts_version(&self) -> Option<i64> {
        Some(brokk_bifrost_core::analyzer::php_facts::PHP_SOURCE_FACTS_VERSION)
    }

    fn language(&self) -> Language {
        Language::Php
    }

    /// Relative to `brokk-bifrost-php`'s crate root: the `.scm` assets moved with
    /// the language knowledge and are embedded there.
    fn query_directory(&self) -> &'static str {
        PHP_QUERY_DIRECTORY
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
