//! The `LanguageAdapter` forwarding shell for Ruby.
//!
//! Every answer below comes from [`brokk_bifrost_ruby`]; nothing Ruby-specific
//! is left here but the trait impl itself.

use super::*;
use crate::analyzer::LanguageAdapter;
use crate::analyzer::cognitive_complexity;
use brokk_bifrost_ruby::adapter::{
    RUBY_COGNITIVE_CONFIG, RUBY_FILE_EXTENSION, parse_ruby_file, ruby_extract_call_receiver,
};
use brokk_bifrost_ruby::queries::RUBY_QUERY_DIRECTORY;
use brokk_bifrost_ruby::test_detection::ruby_contains_tests;
use tree_sitter::Tree;

#[derive(Debug, Clone, Default)]
pub struct RubyAdapter;

impl LanguageAdapter for RubyAdapter {
    fn source_fact_storage(&self) -> Option<&'static crate::analyzer::store::SourceFactStorage> {
        Some(&crate::analyzer::ruby::source_publication::SOURCE_STORAGE)
    }

    fn requires_source_declaration_metadata_bridges(&self) -> bool {
        true
    }

    fn produces_canonical_source_facts(&self) -> bool {
        true
    }

    fn ruby_source_facts_version(&self) -> Option<i64> {
        Some(brokk_bifrost_core::analyzer::ruby_facts::RUBY_SOURCE_FACTS_VERSION)
    }

    fn language(&self) -> Language {
        Language::Ruby
    }

    /// Relative to `brokk-bifrost-ruby`'s crate root: the `.scm` assets moved
    /// with the language knowledge and are embedded there.
    fn query_directory(&self) -> &'static str {
        RUBY_QUERY_DIRECTORY
    }

    fn file_extension(&self) -> &'static str {
        RUBY_FILE_EXTENSION
    }

    fn persist_content_stable_lookup_keys(&self) -> bool {
        true
    }

    /// Ruby's structured declaration identity renders nested constant owners
    /// with `$` (`Billing$Invoice`). It is not client source syntax, but it is
    /// a join in the internal rendered-name compatibility surface and must
    /// expose the terminal identifier for an indexed relational candidate
    /// seek.
    fn lookup_candidate_separators(&self) -> &'static [&'static str] {
        &[".", "::", "$"]
    }

    fn contains_tests(
        &self,
        _file: &ProjectFile,
        source: &str,
        tree: &Tree,
        _parsed: &crate::analyzer::tree_sitter_analyzer::ParsedFile,
    ) -> bool {
        ruby_contains_tests(tree.root_node(), source)
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        ruby_extract_call_receiver(reference)
    }

    fn parse_file(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
    ) -> crate::analyzer::tree_sitter_analyzer::ParsedFile {
        parse_ruby_file(file, source, tree)
    }

    fn cognitive_complexity_config(&self) -> Option<&'static cognitive_complexity::Config> {
        Some(&RUBY_COGNITIVE_CONFIG)
    }
}
