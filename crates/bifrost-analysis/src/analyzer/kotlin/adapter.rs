//! The `LanguageAdapter` forwarding shell for Kotlin.
//!
//! Every answer below comes from [`brokk_bifrost_jvm`]; nothing Kotlin-specific
//! is left here but the trait impl itself.

use crate::analyzer::cognitive_complexity;
use crate::analyzer::{Language, LanguageAdapter, ProjectFile, SignatureMetadata};
use brokk_bifrost_jvm::kotlin::adapter::{
    KOTLIN_COGNITIVE_CONFIG, KOTLIN_FILE_EXTENSION, kotlin_extract_call_receiver,
    kotlin_signature_arity, kotlin_signature_return_type,
};
use brokk_bifrost_jvm::kotlin::declarations::parse_kotlin_file;
use brokk_bifrost_jvm::kotlin::test_detection::kotlin_contains_tests;
use brokk_bifrost_jvm::queries::KOTLIN_QUERY_DIRECTORY;
use tree_sitter::Tree;

#[derive(Debug, Clone, Default)]
pub(crate) struct KotlinAdapter;

impl LanguageAdapter for KotlinAdapter {
    fn language(&self) -> Language {
        Language::Kotlin
    }

    /// Relative to `brokk-bifrost-jvm`'s crate root: the `.scm` assets moved
    /// with the vendored grammars and are embedded there.
    fn query_directory(&self) -> &'static str {
        KOTLIN_QUERY_DIRECTORY
    }

    fn file_extension(&self) -> &'static str {
        KOTLIN_FILE_EXTENSION
    }

    fn callable_arity(
        &self,
        signature: &str,
        metadata: Option<&SignatureMetadata>,
    ) -> Option<usize> {
        metadata
            .and_then(SignatureMetadata::callable_arity)
            .map(|arity| arity.total())
            .or_else(|| kotlin_signature_arity(signature))
    }

    fn callable_return_type_text<'a>(&self, signature: &'a str) -> Option<&'a str> {
        kotlin_signature_return_type(signature)
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        kotlin_extract_call_receiver(reference)
    }

    fn contains_tests(
        &self,
        _file: &ProjectFile,
        source: &str,
        tree: &Tree,
        _parsed: &crate::analyzer::tree_sitter_analyzer::ParsedFile,
    ) -> bool {
        kotlin_contains_tests(tree.root_node(), source)
    }

    fn parse_file(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
    ) -> crate::analyzer::tree_sitter_analyzer::ParsedFile {
        parse_kotlin_file(file, source, tree)
    }

    fn cognitive_complexity_config(&self) -> Option<&'static cognitive_complexity::Config> {
        Some(&KOTLIN_COGNITIVE_CONFIG)
    }
}
