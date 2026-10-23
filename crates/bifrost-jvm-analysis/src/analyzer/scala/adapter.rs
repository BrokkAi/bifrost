//! The `LanguageAdapter` forwarding shell for Scala.
//!
//! Every answer below comes from [`brokk_bifrost_jvm`]; nothing Scala-specific
//! is left here but the trait impl itself.

use brokk_bifrost_analysis::analyzer::cognitive_complexity;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_analysis::analyzer::store::StoreLanguageAdapter;
use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::LanguageAdapter;

use brokk_bifrost_core::analyzer::model::ProjectFile;
use brokk_bifrost_jvm::queries::SCALA_QUERY_DIRECTORY;
use brokk_bifrost_jvm::scala::adapter::{
    SCALA_COGNITIVE_CONFIG, SCALA_FILE_EXTENSION, scala_extract_call_receiver,
    scala_object_encoded_short_name_candidates,
};
use brokk_bifrost_jvm::scala::declarations::parse_scala_file;
use brokk_bifrost_jvm::scala::test_detection::scala_contains_tests;
use brokk_bifrost_jvm::scala::{scala_normalize_full_name, scala_simple_type_name};
use tree_sitter::Tree;

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::DOT_LOOKUP_CANDIDATE_SEPARATORS;

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::lookup_suffix_candidates;

#[derive(Debug, Clone, Default)]
#[doc(hidden)]
pub struct ScalaAdapter;

impl LanguageAdapter for ScalaAdapter {
    /// Relative to `brokk-bifrost-jvm`'s crate root: the `.scm` assets moved
    /// with the vendored grammars and are embedded there.
    fn query_directory(&self) -> &'static str {
        SCALA_QUERY_DIRECTORY
    }

    fn file_extension(&self) -> &'static str {
        SCALA_FILE_EXTENSION
    }

    /// Scala peels on `.` alone: its cons class is named `::`, so a `::` in a
    /// scala spelling is a declaration's own name and never a join.
    fn lookup_candidate_separators(&self) -> &'static [&'static str] {
        DOT_LOOKUP_CANDIDATE_SEPARATORS
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

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        scala_extract_call_receiver(reference)
    }

    fn contains_tests(
        &self,
        _file: &ProjectFile,
        source: &str,
        tree: &Tree,
        _parsed: &brokk_bifrost_core::analyzer::parsed_file::ParsedFile,
    ) -> bool {
        scala_contains_tests(tree.root_node(), source)
    }

    fn parse_file(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
    ) -> brokk_bifrost_core::analyzer::parsed_file::ParsedFile {
        parse_scala_file(file, source, tree)
    }

    fn cognitive_complexity_config(&self) -> Option<&'static cognitive_complexity::Config> {
        Some(&SCALA_COGNITIVE_CONFIG)
    }
}
impl StoreLanguageAdapter for ScalaAdapter {
    fn source_fact_storage(
        &self,
    ) -> Option<&'static brokk_bifrost_analysis::analyzer::store::source_facts::SourceFactStorage>
    {
        Some(&crate::analyzer::scala::source_publication::SOURCE_STORAGE)
    }
    fn requires_source_declaration_metadata_bridges(&self) -> bool {
        true
    }
    fn produces_canonical_source_facts(&self) -> bool {
        true
    }
    fn scala_source_facts_version(&self) -> Option<i64> {
        Some(brokk_bifrost_core::analyzer::scala_facts::SCALA_SOURCE_FACTS_VERSION)
    }
    fn language(&self) -> Language {
        Language::Scala
    }
    fn normalize_full_name(&self, fq_name: &str) -> String {
        scala_normalize_full_name(fq_name)
    }
    fn normalize_fq_name(
        &self,
        fq_name: &brokk_bifrost_core::analyzer::fq_name::FqName,
    ) -> brokk_bifrost_core::analyzer::fq_name::FqName {
        brokk_bifrost_jvm::scala::scala_normalize_fq_name(fq_name)
    }
    fn simple_type_name(&self, unit: &CodeUnit) -> String {
        scala_simple_type_name(unit)
    }
}
