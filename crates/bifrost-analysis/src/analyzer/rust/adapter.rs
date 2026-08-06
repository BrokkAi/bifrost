use crate::analyzer::cognitive_complexity;
use crate::analyzer::{Language, LanguageAdapter, PackageAnchor, ProjectFile};
use std::sync::LazyLock;
use tree_sitter::Tree;

use super::declarations::{
    parse_rust_file, rust_file_package_fq, rust_package_name, rust_semantic_package_fq,
};
use super::tests::rust_source_contains_tests;

static RUST_COGNITIVE_CONFIG: LazyLock<cognitive_complexity::Config> =
    LazyLock::new(|| cognitive_complexity::Config {
        if_types: &["if_expression"],
        loop_types: &["for_expression", "while_expression", "loop_expression"],
        case_types: &["match_arm"],
        binary_types: &["binary_expression"],
        logical_operators: &["&&", "||"],
        jump_types: &["break_expression", "continue_expression"],
        named_function_boundary_types: &["function_item"],
        anonymous_function_types: &["closure_expression"],
        else_clause_types: &["else_clause"],
        default_case_predicate: Some(cognitive_complexity::is_wildcard_case),
        ..cognitive_complexity::Config::empty()
    });

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

    fn query_directory(&self) -> &'static str {
        "resources/treesitter/rust"
    }

    fn file_extension(&self) -> &'static str {
        "rs"
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
                &super::imports::rust_crate_root_package(file),
            )),
        }
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        let trimmed = reference.trim();
        let before_args = trimmed
            .split_once('(')
            .map(|(head, _)| head)
            .unwrap_or(trimmed);
        before_args
            .rsplit_once("::")
            .map(|(receiver, _)| receiver.to_string())
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
