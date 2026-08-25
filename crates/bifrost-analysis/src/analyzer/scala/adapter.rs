//! The `LanguageAdapter` forwarding shell for Scala.
//!
//! Every answer below comes from [`brokk_bifrost_jvm`]; nothing Scala-specific
//! is left here but the trait impl itself.

use crate::analyzer::cognitive_complexity;
use crate::analyzer::{CodeUnit, Language, LanguageAdapter, ProjectFile};
use brokk_bifrost_jvm::queries::SCALA_QUERY_DIRECTORY;
use brokk_bifrost_jvm::scala::adapter::{
    SCALA_COGNITIVE_CONFIG, SCALA_FILE_EXTENSION, scala_extract_call_receiver,
    scala_object_encoded_short_name_candidates,
};
use brokk_bifrost_jvm::scala::declarations::parse_scala_file;
use brokk_bifrost_jvm::scala::test_detection::scala_contains_tests;
use brokk_bifrost_jvm::scala::{scala_normalize_full_name, scala_simple_type_name};
use tree_sitter::Tree;

use crate::analyzer::tree_sitter_analyzer::lookup_suffix_candidates;

#[derive(Debug, Clone, Default)]
pub(crate) struct ScalaAdapter;

impl LanguageAdapter for ScalaAdapter {
    fn language(&self) -> Language {
        Language::Scala
    }

    /// Relative to `brokk-bifrost-jvm`'s crate root: the `.scm` assets moved
    /// with the vendored grammars and are embedded there.
    fn query_directory(&self) -> &'static str {
        SCALA_QUERY_DIRECTORY
    }

    fn file_extension(&self) -> &'static str {
        SCALA_FILE_EXTENSION
    }

    fn normalize_full_name(&self, fq_name: &str) -> String {
        scala_normalize_full_name(fq_name)
    }

    fn normalize_fq_name(&self, fq_name: &crate::analyzer::FqName) -> crate::analyzer::FqName {
        brokk_bifrost_jvm::scala::scala_normalize_fq_name(fq_name)
    }

    /// Scala peels on `.` alone: its cons class is named `::`, so a `::` in a
    /// scala spelling is a declaration's own name and never a join.
    fn lookup_candidate_separators(&self) -> &'static [&'static str] {
        &["."]
    }

    fn lookup_candidate_short_names(&self, normalized_fq_name: &str) -> Vec<String> {
        let mut candidates =
            lookup_suffix_candidates(normalized_fq_name, self.lookup_candidate_separators());
        let base_candidates = candidates.clone();
        for candidate in base_candidates {
            candidates.extend(scala_object_encoded_short_name_candidates(&candidate));
        }
        candidates.sort();
        candidates.dedup();
        candidates
    }

    fn simple_type_name(&self, unit: &CodeUnit) -> String {
        scala_simple_type_name(unit)
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        scala_extract_call_receiver(reference)
    }

    fn contains_tests(
        &self,
        _file: &ProjectFile,
        source: &str,
        tree: &Tree,
        _parsed: &crate::analyzer::tree_sitter_analyzer::ParsedFile,
    ) -> bool {
        scala_contains_tests(tree.root_node(), source)
    }

    fn parse_file(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
    ) -> crate::analyzer::tree_sitter_analyzer::ParsedFile {
        parse_scala_file(file, source, tree)
    }

    fn cognitive_complexity_config(&self) -> Option<&'static cognitive_complexity::Config> {
        Some(&SCALA_COGNITIVE_CONFIG)
    }
}
