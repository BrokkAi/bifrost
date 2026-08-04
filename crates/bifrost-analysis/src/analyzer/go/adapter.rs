//! The `LanguageAdapter` forwarding shell for Go.
//!
//! Every answer below comes from [`brokk_bifrost_go`]; this file exists only
//! because `LanguageAdapter` and `ParsedFile` are analysis-owned types the Go
//! crate cannot name.

use crate::analyzer::cognitive_complexity;
use crate::analyzer::{Language, LanguageAdapter, ProjectFile};
use brokk_bifrost_go::adapter::{GO_COGNITIVE_CONFIG, GO_FILE_EXTENSION, go_extract_call_receiver};
use brokk_bifrost_go::declarations::go_package_fq;
use brokk_bifrost_go::packages::canonical_go_package_name;
use brokk_bifrost_go::queries::GO_QUERY_DIRECTORY;
use brokk_bifrost_go::test_detection::go_contains_tests;
use tree_sitter::Tree;

use super::declarations::parse_go_file;

#[derive(Debug, Clone, Default)]
pub(crate) struct GoAdapter;

impl LanguageAdapter for GoAdapter {
    fn language(&self) -> Language {
        Language::Go
    }

    /// Relative to `brokk-bifrost-go`'s crate root: the `.scm` assets moved with
    /// the language knowledge and are embedded there.
    fn query_directory(&self) -> &'static str {
        GO_QUERY_DIRECTORY
    }

    fn file_extension(&self) -> &'static str {
        GO_FILE_EXTENSION
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

    fn path_derived_package_fq(
        &self,
        content_qualifier: &str,
        file: &ProjectFile,
    ) -> Option<crate::analyzer::FqName> {
        Some(go_package_fq(&canonical_go_package_name(
            file,
            content_qualifier,
        )))
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
        go_extract_call_receiver(reference)
    }

    fn parse_file(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
    ) -> crate::analyzer::tree_sitter_analyzer::ParsedFile {
        parse_go_file(file, source, tree)
    }

    fn cognitive_complexity_config(&self) -> Option<&'static cognitive_complexity::Config> {
        Some(&GO_COGNITIVE_CONFIG)
    }
}
