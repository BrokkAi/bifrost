//! The `LanguageAdapter` forwarding shell for Rust.
//!
//! Every answer below comes from [`brokk_bifrost_rust`]; this file exists only
//! because `LanguageAdapter` and `ParsedFile` are analysis-owned types the Rust
//! crate cannot name.

use crate::analyzer::cognitive_complexity;
use crate::analyzer::{Language, LanguageAdapter, ProjectFile};
use brokk_bifrost_rust::adapter::{
    RUST_COGNITIVE_CONFIG, RUST_FILE_EXTENSION, rust_extract_call_receiver,
    rust_unit_has_explicit_qualifier,
};
use brokk_bifrost_rust::declarations::{parse_rust_file, rust_file_package_fq, rust_package_name};
use brokk_bifrost_rust::queries::RUST_QUERY_DIRECTORY;
use brokk_bifrost_rust::test_detection::rust_source_contains_tests;
use tree_sitter::Tree;

#[derive(Debug, Clone, Default)]
pub(crate) struct RustAdapter;

impl LanguageAdapter for RustAdapter {
    fn language(&self) -> Language {
        Language::Rust
    }

    /// Relative to `brokk-bifrost-rust`'s crate root: the `.scm` assets moved
    /// with the language knowledge and are embedded there.
    fn query_directory(&self) -> &'static str {
        RUST_QUERY_DIRECTORY
    }

    fn file_extension(&self) -> &'static str {
        RUST_FILE_EXTENSION
    }

    fn storage_content_qualifier(
        &self,
        code_unit: &crate::analyzer::CodeUnit,
        _content_qualifier: &str,
    ) -> String {
        if rust_unit_has_explicit_qualifier(code_unit) {
            code_unit.package_name().to_string()
        } else {
            String::new()
        }
    }

    fn persisted_content_qualifier_supports_substring_search(&self) -> bool {
        false
    }

    fn storage_file_content_qualifier(&self, _package_name: &str) -> String {
        String::new()
    }

    fn hydrate_content_qualifier(&self, content_qualifier: &str, file: &ProjectFile) -> String {
        if content_qualifier.is_empty() {
            rust_package_name(file)
        } else {
            content_qualifier.to_string()
        }
    }

    fn path_derived_package_fq(
        &self,
        content_qualifier: &str,
        file: &ProjectFile,
    ) -> Option<crate::analyzer::FqName> {
        content_qualifier
            .is_empty()
            .then(|| rust_file_package_fq(file))
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        rust_extract_call_receiver(reference)
    }

    fn contains_tests(
        &self,
        _file: &ProjectFile,
        source: &str,
        tree: &Tree,
        _parsed: &crate::analyzer::tree_sitter_analyzer::ParsedFile,
    ) -> bool {
        rust_source_contains_tests(tree.root_node(), source)
    }

    fn parse_file(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
    ) -> crate::analyzer::tree_sitter_analyzer::ParsedFile {
        parse_rust_file(file, source, tree)
    }

    fn cognitive_complexity_config(&self) -> Option<&'static cognitive_complexity::Config> {
        Some(&RUST_COGNITIVE_CONFIG)
    }
}
