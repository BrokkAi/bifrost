//! The `LanguageAdapter` forwarding shell for Rust.
//!
//! Every answer below comes from [`brokk_bifrost_rust`]; this file exists only
//! because `LanguageAdapter` and `ParsedFile` are analysis-owned types the Rust
//! crate cannot name.

use crate::analyzer::cognitive_complexity;
use crate::analyzer::{Language, LanguageAdapter, PackageAnchor, ProjectFile};
use brokk_bifrost_rust::adapter::{
    RUST_COGNITIVE_CONFIG, RUST_FILE_EXTENSION, rust_extract_call_receiver,
};
use brokk_bifrost_rust::declarations::{
    parse_rust_file, rust_file_package_fq, rust_package_name, rust_semantic_package_fq,
};
use brokk_bifrost_rust::queries::RUST_QUERY_DIRECTORY;
use brokk_bifrost_rust::test_detection::rust_source_contains_tests;
use tree_sitter::Tree;

/// Rust persists every unit's package prefix as an anchor plus a
/// content-stable tail, so `code_units.content_qualifier` is always empty for
/// this language. The SQL package prefilters that read that column
/// (`persisted_package_exists`, `forward_fqn_prefix_exists` in
/// `tree_sitter_analyzer.rs`) therefore cannot see any Rust row and would
/// report a false negative if one were ever asked about a Rust package. No
/// Rust caller reaches them today; a future one must resolve the anchor
/// instead of matching persisted text.
#[derive(Debug, Clone, Default)]
pub(crate) struct RustAdapter;

impl LanguageAdapter for RustAdapter {
    fn language(&self) -> Language {
        Language::Rust
    }

    /// Relative to `brokk-bifrost-rust`'s crate root: the `.scm` assets moved
    /// with the language knowledge and are embedded there.
    fn query_directory(&self) -> &'static str {
        RUST_QUERY_DIRECTORY
    }

    fn file_extension(&self) -> &'static str {
        RUST_FILE_EXTENSION
    }

    fn storage_content_qualifier(
        &self,
        _code_unit: &crate::analyzer::CodeUnit,
        _content_qualifier: &str,
    ) -> String {
        // Every Rust unit carries an effective package anchor (its own, or this
        // adapter's default), so its package prefix is re-derived from the live
        // path at hydration. Baking the path-derived text into the row would
        // make a content-addressed blob unusable at a second mount point. A
        // unit that falls back to a fully persisted name needs no qualifier
        // either: mode FULL restores the complete structured name on its own.
        String::new()
    }

    fn persisted_content_qualifier_supports_substring_search(&self) -> bool {
        false
    }

    fn storage_file_content_qualifier(&self, _package_name: &str) -> String {
        String::new()
    }

    fn hydrate_content_qualifier(&self, content_qualifier: &str, file: &ProjectFile) -> String {
        if content_qualifier.is_empty() {
            rust_package_name(file)
        } else {
            content_qualifier.to_string()
        }
    }

    fn default_package_anchor(&self) -> Option<PackageAnchor> {
        Some(PackageAnchor::OwnModule { pop: 0 })
    }

    fn resolve_package_anchor(
        &self,
        anchor: PackageAnchor,
        _content_qualifier: &str,
        file: &ProjectFile,
    ) -> Option<crate::analyzer::FqName> {
        match anchor {
            PackageAnchor::OwnModule { pop } => {
                let package = rust_file_package_fq(file);
                let keep = package.len().saturating_sub(usize::from(pop));
                Some(package.prefix(keep))
            }
            // An empty crate root (a crate mounted at the repository root) is a
            // legitimate empty prefix, not an absent one: it is what lets an
            // `impl crate::Type` member persist a package-free tail.
            PackageAnchor::CrateRoot => Some(rust_semantic_package_fq(
                &brokk_bifrost_rust::imports::rust_crate_root_package(file),
            )),
        }
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        rust_extract_call_receiver(reference)
    }

    fn contains_tests(
        &self,
        _file: &ProjectFile,
        source: &str,
        tree: &Tree,
        _parsed: &crate::analyzer::tree_sitter_analyzer::ParsedFile,
    ) -> bool {
        rust_source_contains_tests(tree.root_node(), source)
    }

    fn parse_file(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
    ) -> crate::analyzer::tree_sitter_analyzer::ParsedFile {
        parse_rust_file(file, source, tree)
    }

    fn cognitive_complexity_config(&self) -> Option<&'static cognitive_complexity::Config> {
        Some(&RUST_COGNITIVE_CONFIG)
    }
}
