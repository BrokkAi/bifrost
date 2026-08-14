//! The `LanguageAdapter` forwarding shell for C++.
//!
//! Every answer below comes from [`brokk_bifrost_cpp`]; nothing C++-specific is
//! left here but the trait impl itself.

use super::*;
use crate::analyzer::LanguageAdapter;
use crate::analyzer::cognitive_complexity;
use brokk_bifrost_cpp::adapter::{
    CPP_COGNITIVE_CONFIG, CPP_FILE_EXTENSION, cpp_extract_call_receiver, parse_cpp_file,
};
use brokk_bifrost_cpp::imports::included_claimable_files;
use brokk_bifrost_cpp::queries::CPP_QUERY_DIRECTORY;
use brokk_bifrost_cpp::test_detection::cpp_contains_tests;
use tree_sitter::Tree;

#[derive(Debug, Clone, Default)]
pub struct CppAdapter;

impl LanguageAdapter for CppAdapter {
    fn language(&self) -> Language {
        Language::Cpp
    }

    /// Relative to `brokk-bifrost-cpp`'s crate root: the `.scm` assets moved
    /// with the language knowledge and are embedded there.
    fn query_directory(&self) -> &'static str {
        CPP_QUERY_DIRECTORY
    }

    fn file_extension(&self) -> &'static str {
        CPP_FILE_EXTENSION
    }

    fn contains_tests(
        &self,
        _file: &ProjectFile,
        source: &str,
        _tree: &Tree,
        _parsed: &crate::analyzer::tree_sitter_analyzer::ParsedFile,
    ) -> bool {
        cpp_contains_tests(source)
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        cpp_extract_call_receiver(reference)
    }

    fn parse_file(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
    ) -> crate::analyzer::tree_sitter_analyzer::ParsedFile {
        parse_cpp_file(file, source, tree)
    }

    fn cognitive_complexity_config(&self) -> Option<&'static cognitive_complexity::Config> {
        Some(&CPP_COGNITIVE_CONFIG)
    }

    /// C++ is the one language that adopts files by include (#1837): `.inc`
    /// translation-unit fragments (abseil's `absl/.../*.inc`) hold real
    /// declarations but carry an extension no language owns, so nothing would
    /// index them otherwise.
    fn claims_included_files(&self) -> bool {
        true
    }

    fn infer_claimed_files(
        &self,
        sources: &[(ProjectFile, Vec<ImportInfo>)],
        claimable: &BTreeSet<ProjectFile>,
    ) -> HashMap<ProjectFile, BTreeSet<ProjectFile>> {
        included_claimable_files(sources, claimable)
    }
}
