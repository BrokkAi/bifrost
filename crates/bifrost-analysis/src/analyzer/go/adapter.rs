//! The `LanguageAdapter` forwarding shell for Go.
//!
//! Every answer below comes from [`brokk_bifrost_go`]; this file exists only
//! because `LanguageAdapter` is an analysis-owned trait the Go crate cannot name.

use crate::analyzer::cognitive_complexity;
use crate::analyzer::{Language, LanguageAdapter, ProjectFile};
use brokk_bifrost_go::adapter::{GO_COGNITIVE_CONFIG, GO_FILE_EXTENSION, go_extract_call_receiver};
use brokk_bifrost_go::declarations::{go_package_fq, parse_go_file};
use brokk_bifrost_go::packages::{
    canonical_go_package_name, canonical_go_workspace_package_name, go_module_path_from_source,
    go_vendor_package_alias,
};
use brokk_bifrost_go::parse::go_reparse_grammar_gap;
use brokk_bifrost_go::queries::GO_QUERY_DIRECTORY;
use brokk_bifrost_go::test_detection::go_contains_tests;
use tree_sitter::Tree;

#[derive(Debug, Clone, Default)]
pub(crate) struct GoAdapter;

impl LanguageAdapter for GoAdapter {
    fn source_fact_storage(&self) -> Option<&'static crate::analyzer::store::SourceFactStorage> {
        Some(&crate::analyzer::go::source_publication::SOURCE_STORAGE)
    }

    fn go_source_facts_version(&self) -> Option<i64> {
        Some(brokk_bifrost_core::analyzer::go_facts::GO_SOURCE_FACTS_VERSION)
    }

    fn language(&self) -> Language {
        Language::Go
    }

    /// Relative to `brokk-bifrost-go`'s crate root: the `.scm` assets moved with
    /// the language knowledge and are embedded there.
    fn query_directory(&self) -> &'static str {
        GO_QUERY_DIRECTORY
    }

    fn file_extension(&self) -> &'static str {
        GO_FILE_EXTENSION
    }

    fn reparse_grammar_gap(
        &self,
        source: &str,
        tree: &Tree,
        cancellation: Option<&crate::cancellation::CancellationToken>,
    ) -> Option<Tree> {
        go_reparse_grammar_gap(source, tree, cancellation)
    }

    fn storage_content_qualifier(
        &self,
        _code_unit: &crate::analyzer::CodeUnit,
        content_qualifier: &str,
    ) -> String {
        content_qualifier.to_string()
    }

    fn persisted_content_qualifier_supports_substring_search(&self) -> bool {
        false
    }

    fn storage_file_content_qualifier(&self, content_qualifier: &str) -> String {
        content_qualifier.to_string()
    }

    fn hydrate_content_qualifier(&self, content_qualifier: &str, file: &ProjectFile) -> String {
        canonical_go_package_name(file, content_qualifier)
    }

    /// Go import paths are not enumerable from the path alone: an external test
    /// package appends the declared `_test` suffix to a path-derived base, and a
    /// module-less file folds the declared package name into that base. Either
    /// produces a prefix that neither the path nor the persisted qualifier
    /// contains as a substring, so Go declarations are never dropped by the
    /// symbol-search prefilter.
    fn prefilter_path_package(&self, _file: &ProjectFile) -> Option<String> {
        None
    }

    fn default_package_anchor(&self) -> Option<crate::analyzer::PackageAnchor> {
        Some(crate::analyzer::PackageAnchor::OwnModule { pop: 0 })
    }

    fn workspace_file_package_anchor(&self) -> Option<crate::analyzer::PackageAnchor> {
        Some(crate::analyzer::PackageAnchor::OwnModule { pop: 0 })
    }

    fn has_workspace_package_identity_inputs(&self) -> bool {
        true
    }

    fn workspace_package_identity_input(&self, file: &ProjectFile) -> bool {
        file.rel_path()
            .file_name()
            .is_some_and(|name| name == "go.mod")
    }

    /// Only the `module` directive qualifies declarations: package identity
    /// is the module path joined with the directory below the manifest. A
    /// `require`, `replace`, `go` or `toolchain` edit reaches dependency packs,
    /// which the host reactivates from the changed path itself. A manifest
    /// that names no valid module leaves the inventory incomplete, so it is
    /// compared by content and any edit to it rebuilds.
    fn workspace_package_identity_digest(&self, source: &[u8]) -> Option<[u8; 32]> {
        use brokk_bifrost_core::analyzer::canonical_hash::{hash_domain_bytes, sha256_bytes};
        Some(
            match std::str::from_utf8(source)
                .ok()
                .and_then(go_module_path_from_source)
            {
                Some(module_path) => hash_domain_bytes(b"go.mod module", module_path.as_bytes()),
                None => sha256_bytes(source),
            },
        )
    }

    fn workspace_package_aliases(
        &self,
        file: &ProjectFile,
        canonical: &crate::analyzer::FqName,
    ) -> Vec<crate::analyzer::FqName> {
        go_vendor_package_alias(file, canonical)
            .into_iter()
            .collect()
    }

    /// A Go declaration always sits in its file's own package, so the file's
    /// own module is the only anchor this adapter can place. The declared
    /// `package` clause travels in the content qualifier because the live
    /// import path alone cannot recover a `_test` suffix or the module-less
    /// fallback name.
    fn resolve_package_anchor(
        &self,
        anchor: crate::analyzer::PackageAnchor,
        content_qualifier: &str,
        file: &ProjectFile,
    ) -> Option<crate::analyzer::FqName> {
        match anchor {
            crate::analyzer::PackageAnchor::OwnModule { pop: 0 } => {
                canonical_go_workspace_package_name(file, content_qualifier)
                    .map(|package| go_package_fq(&package))
            }
            _ => None,
        }
    }

    fn contains_tests(
        &self,
        _file: &ProjectFile,
        source: &str,
        tree: &Tree,
        _parsed: &crate::analyzer::tree_sitter_analyzer::ParsedFile,
    ) -> bool {
        go_contains_tests(tree.root_node(), source)
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        go_extract_call_receiver(reference)
    }

    fn parse_file(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
    ) -> crate::analyzer::tree_sitter_analyzer::ParsedFile {
        parse_go_file(file, source, tree)
    }

    fn cognitive_complexity_config(&self) -> Option<&'static cognitive_complexity::Config> {
        Some(&GO_COGNITIVE_CONFIG)
    }

    fn produces_canonical_source_facts(&self) -> bool {
        true
    }
}
