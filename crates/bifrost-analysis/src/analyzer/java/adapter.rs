//! The `LanguageAdapter` forwarding shell for Java.
//!
//! Every answer below comes from [`brokk_bifrost_jvm`] except
//! `callable_arity`, which reads only core `SignatureMetadata` and names no
//! Java syntax.

use super::*;
use crate::analyzer::cognitive_complexity;
use crate::analyzer::{LanguageAdapter, SignatureMetadata};
use brokk_bifrost_jvm::java::adapter::{
    JAVA_COGNITIVE_CONFIG, JAVA_FILE_EXTENSION, java_callable_return_type_text,
};
use brokk_bifrost_jvm::java::declarations::{
    extract_java_call_receiver, is_java_anonymous_structure, normalize_java_full_name,
    parse_java_file,
};
use brokk_bifrost_jvm::java::test_detection::java_source_contains_tests;
use brokk_bifrost_jvm::queries::JAVA_QUERY_DIRECTORY;
use tree_sitter::Tree;

#[derive(Debug, Clone, Default)]
pub struct JavaAdapter;

impl LanguageAdapter for JavaAdapter {
    fn language(&self) -> Language {
        Language::Java
    }

    /// Relative to `brokk-bifrost-jvm`'s crate root: the `.scm` assets moved
    /// with the vendored grammars and are embedded there.
    fn query_directory(&self) -> &'static str {
        JAVA_QUERY_DIRECTORY
    }

    fn file_extension(&self) -> &'static str {
        JAVA_FILE_EXTENSION
    }

    fn normalize_full_name(&self, fq_name: &str) -> String {
        normalize_java_full_name(fq_name)
    }

    fn callable_arity(
        &self,
        _signature: &str,
        metadata: Option<&SignatureMetadata>,
    ) -> Option<usize> {
        metadata.map(|metadata| {
            metadata
                .callable_arity()
                .map(|arity| arity.total())
                .unwrap_or_else(|| metadata.parameters().len())
        })
    }

    fn callable_return_type_text<'a>(&self, signature: &'a str) -> Option<&'a str> {
        java_callable_return_type_text(signature)
    }

    fn is_anonymous_structure(&self, fq_name: &str) -> bool {
        is_java_anonymous_structure(fq_name)
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        extract_java_call_receiver(reference)
    }

    fn contains_tests(
        &self,
        _file: &ProjectFile,
        source: &str,
        tree: &Tree,
        _parsed: &crate::analyzer::tree_sitter_analyzer::ParsedFile,
    ) -> bool {
        java_source_contains_tests(tree.root_node(), source)
    }

    fn parse_file(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
    ) -> crate::analyzer::tree_sitter_analyzer::ParsedFile {
        parse_java_file(file, source, tree)
    }

    fn cognitive_complexity_config(&self) -> Option<&'static cognitive_complexity::Config> {
        Some(&JAVA_COGNITIVE_CONFIG)
    }
}
