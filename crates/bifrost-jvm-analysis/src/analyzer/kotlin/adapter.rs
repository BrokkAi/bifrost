//! The `LanguageAdapter` forwarding shell for Kotlin.
//!
//! Every answer below comes from [`brokk_bifrost_jvm`]; nothing Kotlin-specific
//! is left here but the trait impl itself.

use brokk_bifrost_analysis::analyzer::cognitive_complexity;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_analysis::analyzer::store::StoreLanguageAdapter;
use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::LanguageAdapter;

use brokk_bifrost_core::analyzer::model::ProjectFile;
use brokk_bifrost_jvm::kotlin::adapter::{
    KOTLIN_COGNITIVE_CONFIG, KOTLIN_FILE_EXTENSION, kotlin_extract_call_receiver,
};
use brokk_bifrost_jvm::kotlin::declarations::parse_kotlin_file;
use brokk_bifrost_jvm::kotlin::test_detection::kotlin_contains_tests;
use brokk_bifrost_jvm::queries::KOTLIN_QUERY_DIRECTORY;
use tree_sitter::Tree;

#[derive(Debug, Clone, Default)]
#[doc(hidden)]
pub struct KotlinAdapter;

impl LanguageAdapter for KotlinAdapter {
    /// Relative to `brokk-bifrost-jvm`'s crate root: the `.scm` assets moved
    /// with the vendored grammars and are embedded there.
    fn query_directory(&self) -> &'static str {
        KOTLIN_QUERY_DIRECTORY
    }

    fn file_extension(&self) -> &'static str {
        KOTLIN_FILE_EXTENSION
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        kotlin_extract_call_receiver(reference)
    }

    fn contains_tests(
        &self,
        _file: &ProjectFile,
        source: &str,
        tree: &Tree,
        _parsed: &brokk_bifrost_core::analyzer::parsed_file::ParsedFile,
    ) -> bool {
        kotlin_contains_tests(tree.root_node(), source)
    }

    fn parse_file(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
    ) -> brokk_bifrost_core::analyzer::parsed_file::ParsedFile {
        parse_kotlin_file(file, source, tree)
    }

    fn cognitive_complexity_config(&self) -> Option<&'static cognitive_complexity::Config> {
        Some(&KOTLIN_COGNITIVE_CONFIG)
    }
}
impl StoreLanguageAdapter for KotlinAdapter {
    fn language(&self) -> Language {
        Language::Kotlin
    }
    fn requires_source_declaration_metadata_bridges(&self) -> bool {
        true
    }
    fn produces_canonical_source_facts(&self) -> bool {
        true
    }
}
