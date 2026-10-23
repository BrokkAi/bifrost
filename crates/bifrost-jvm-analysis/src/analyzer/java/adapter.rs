//! The `LanguageAdapter` forwarding shell for Java.
//!
//! Every answer below comes from [`brokk_bifrost_jvm`].

use crate::analyzer::java::*;

use brokk_bifrost_analysis::analyzer::cognitive_complexity;

use brokk_bifrost_core::analyzer::fq_name::FqName;

use brokk_bifrost_analysis::analyzer::store::StoreLanguageAdapter;
use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::LanguageAdapter;
use brokk_bifrost_jvm::java::adapter::{JAVA_COGNITIVE_CONFIG, JAVA_FILE_EXTENSION};
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
    /// Relative to `brokk-bifrost-jvm`'s crate root: the `.scm` assets moved
    /// with the vendored grammars and are embedded there.
    fn query_directory(&self) -> &'static str {
        JAVA_QUERY_DIRECTORY
    }

    fn file_extension(&self) -> &'static str {
        JAVA_FILE_EXTENSION
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
        _parsed: &brokk_bifrost_core::analyzer::parsed_file::ParsedFile,
    ) -> bool {
        java_source_contains_tests(tree.root_node(), source)
    }

    fn parse_file(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
    ) -> brokk_bifrost_core::analyzer::parsed_file::ParsedFile {
        parse_java_file(file, source, tree)
    }

    fn cognitive_complexity_config(&self) -> Option<&'static cognitive_complexity::Config> {
        Some(&JAVA_COGNITIVE_CONFIG)
    }
}
impl StoreLanguageAdapter for JavaAdapter {
    fn source_fact_storage(
        &self,
    ) -> Option<&'static brokk_bifrost_analysis::analyzer::store::source_facts::SourceFactStorage>
    {
        Some(&crate::analyzer::java::source_publication::SOURCE_STORAGE)
    }
    fn language(&self) -> Language {
        Language::Java
    }
    fn normalize_full_name(&self, fq_name: &str) -> String {
        normalize_java_full_name(fq_name)
    }
    fn normalize_fq_name(&self, fq_name: &FqName) -> FqName {
        brokk_bifrost_jvm::java::declarations::normalize_java_fq_name(fq_name)
    }
    fn requires_source_declaration_metadata_bridges(&self) -> bool {
        true
    }
    fn produces_canonical_source_facts(&self) -> bool {
        true
    }
    fn declaration_visibility_facts_version(&self) -> Option<i64> {
        Some(brokk_bifrost_core::analyzer::source_facts::SOURCE_DECLARATION_VISIBILITY_VERSION)
    }
    fn java_type_constructor_facts_version(&self) -> Option<i64> {
        Some(1)
    }
    fn java_source_facts_version(&self) -> Option<i64> {
        Some(brokk_bifrost_core::analyzer::java_facts::JAVA_SOURCE_FACTS_VERSION)
    }
}
