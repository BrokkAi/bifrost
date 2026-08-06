//! The `LanguageAdapter` forwarding shell for Scala.
//!
//! Every answer below that knows Scala comes from [`brokk_bifrost_jvm`];
//! `simple_type_name` is the one exception, because its terminal-segment
//! splitter still lives beside the usage graph in this crate.

use crate::analyzer::cognitive_complexity;
use crate::analyzer::{CodeUnit, Language, LanguageAdapter, ProjectFile, SignatureMetadata};
use brokk_bifrost_jvm::queries::SCALA_QUERY_DIRECTORY;
use brokk_bifrost_jvm::scala::adapter::{
    SCALA_COGNITIVE_CONFIG, SCALA_FILE_EXTENSION, scala_extract_call_receiver,
    scala_object_encoded_short_name_candidates,
};
use brokk_bifrost_jvm::scala::declarations::parse_scala_file;
use brokk_bifrost_jvm::scala::test_detection::scala_contains_tests;
use brokk_bifrost_jvm::scala::{
    scala_member_signature_arity, scala_normalize_full_name, scala_signature_return_type,
};
use tree_sitter::Tree;

use crate::analyzer::tree_sitter_analyzer::lookup_suffix_candidates;

use super::scala_simple_type_name;

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

    fn lookup_candidate_short_names(&self, normalized_fq_name: &str) -> Vec<String> {
        let mut candidates = lookup_suffix_candidates(normalized_fq_name, &["."]);
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

    fn callable_arity(
        &self,
        signature: &str,
        metadata: Option<&SignatureMetadata>,
    ) -> Option<usize> {
        metadata
            .and_then(SignatureMetadata::callable_arity)
            .map(|arity| arity.total())
            .or_else(|| scala_member_signature_arity(signature))
    }

    fn callable_return_type_text<'a>(&self, signature: &'a str) -> Option<&'a str> {
        scala_signature_return_type(signature)
    }

    fn preferred_type_candidate<'a>(&self, candidates: &'a [CodeUnit]) -> Option<&'a CodeUnit> {
        candidates
            .iter()
            .find(|unit| !unit.short_name().ends_with('$'))
            .or_else(|| candidates.first())
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
