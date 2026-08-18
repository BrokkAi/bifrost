//! The `LanguageAdapter` forwarding shell for C++.
//!
//! Every answer below comes from [`brokk_bifrost_cpp`]; nothing C++-specific is
//! left here but the trait impl itself.

use super::*;
use crate::analyzer::cognitive_complexity;
use crate::analyzer::{LanguageAdapter, LanguageDialect};
use brokk_bifrost_cpp::adapter::{
    CPP_COGNITIVE_CONFIG, CPP_FILE_EXTENSION, cpp_extract_call_receiver, cpp_projections_differ,
    parse_cpp_file, parse_cpp_file_in_dialect,
};
use brokk_bifrost_cpp::imports::included_claimable_files;
use brokk_bifrost_cpp::queries::CPP_QUERY_DIRECTORY;
use brokk_bifrost_cpp::test_detection::cpp_contains_tests;
use tree_sitter::Tree;

/// The cache `lang` key that rows extracted with C semantics live under.
///
/// Shaped like the TypeScript pair (`typescript:ts` / `typescript:tsx`): a
/// language-qualified key, so a `.c` blob and a byte-identical `.cpp` blob
/// cannot collide in `blobs`/`code_units`, which are keyed `(blob_oid, lang)`.
pub(crate) const CPP_C_STORAGE_LANGUAGE_KEY: &str = "cpp:c";

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

    /// C and C++ share one grammar and one adapter, but not one set of scoping
    /// rules: extraction of a `.c` file mints a tag declared inside another
    /// aggregate's member list at the enclosing non-aggregate scope, which a
    /// `.cpp` or `.h` file mints as a nested class. The two projections of one
    /// blob's contents must therefore never share cache rows, and rows are
    /// keyed `(blob_oid, lang)` -- so `.c` gets its own storage language key,
    /// exactly as `.tsx` does against `.ts`.
    ///
    /// Every other case keeps the default answer: the key is derived from the
    /// FILE's own language (not this adapter's) so the cross-adapter row guard
    /// still discriminates, and an include-claimed file with an extension no
    /// language owns (#1837) still lands under this adapter's own key.
    fn storage_language_key_for_file(&self, file: &ProjectFile) -> &'static str {
        if LanguageDialect::for_path(Language::Cpp, file.rel_path()) == LanguageDialect::CppC {
            return CPP_C_STORAGE_LANGUAGE_KEY;
        }
        if crate::analyzer::common::has_unclaimed_extension(file) {
            return Language::Cpp.config_label();
        }
        crate::analyzer::common::language_for_file(file).config_label()
    }

    fn storage_language_keys(&self) -> Vec<(String, tree_sitter::Language)> {
        vec![
            (
                Language::Cpp.config_label().to_string(),
                tree_sitter_cpp::LANGUAGE.into(),
            ),
            (
                CPP_C_STORAGE_LANGUAGE_KEY.to_string(),
                tree_sitter_cpp::LANGUAGE.into(),
            ),
        ]
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

    /// A header's second reading (#1970).
    ///
    /// A translation unit's compilation language is settled by its own
    /// extension, so it has one reading and returns nothing here. Every other
    /// file this adapter analyzes -- `.h`/`.hpp`/`.hh`/`.hxx`, and the
    /// include-claimed fragments of #1837 -- is compiled as part of whatever
    /// translation units include it, and C and C++ disagree about where a tag
    /// declared inside an aggregate member list lives. The C reading is stored
    /// under [`CPP_C_STORAGE_LANGUAGE_KEY`] exactly when it differs, so
    /// "no `cpp:c` rows for this blob" unambiguously means "the C reading is
    /// the C++ reading" and the loader falls back to the `cpp` rows.
    ///
    /// The overwhelming majority of headers declare no tag inside an aggregate
    /// and so store nothing: the second walk runs on the tree the primary walk
    /// already has, and its output is discarded.
    fn additional_projections(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
        primary: &crate::analyzer::tree_sitter_analyzer::ParsedFile,
    ) -> Vec<(
        &'static str,
        crate::analyzer::tree_sitter_analyzer::ParsedFile,
    )> {
        if super::imports::is_cpp_translation_unit(file) {
            return Vec::new();
        }
        let c_projection = parse_cpp_file_in_dialect(file, source, tree, LanguageDialect::CppC);
        if !cpp_projections_differ(primary, &c_projection) {
            return Vec::new();
        }
        vec![(CPP_C_STORAGE_LANGUAGE_KEY, c_projection)]
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
