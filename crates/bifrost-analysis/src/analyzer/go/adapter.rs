use crate::analyzer::cognitive_complexity;
use crate::analyzer::{Language, LanguageAdapter, ProjectFile};
use std::sync::LazyLock;
use tree_sitter::Tree;

use super::declarations::{go_package_fq, parse_go_file};
use super::packages::canonical_go_package_name;
use super::tests::go_contains_tests;

static GO_COGNITIVE_CONFIG: LazyLock<cognitive_complexity::Config> =
    LazyLock::new(|| cognitive_complexity::Config {
        if_types: &["if_statement"],
        loop_types: &["for_statement"],
        case_types: &["expression_case", "type_case", "communication_case"],
        default_case_types: &["default_case"],
        binary_types: &["binary_expression"],
        logical_operators: &["&&", "||"],
        jump_types: &["break_statement", "continue_statement"],
        named_function_boundary_types: &["function_declaration", "method_declaration"],
        anonymous_function_types: &["func_literal"],
        else_clause_types: &["else_clause"],
        ..cognitive_complexity::Config::empty()
    });

#[derive(Debug, Clone, Default)]
pub(crate) struct GoAdapter;

impl LanguageAdapter for GoAdapter {
    fn language(&self) -> Language {
        Language::Go
    }

    fn query_directory(&self) -> &'static str {
        "resources/treesitter/go"
    }

    fn file_extension(&self) -> &'static str {
        "go"
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

    fn default_package_anchor(&self) -> Option<crate::analyzer::PackageAnchor> {
        Some(crate::analyzer::PackageAnchor::OwnModule { pop: 0 })
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
            crate::analyzer::PackageAnchor::OwnModule { pop: 0 } => Some(go_package_fq(
                &canonical_go_package_name(file, content_qualifier),
            )),
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
        let trimmed = reference.trim();
        let before_args = trimmed
            .split_once('(')
            .map(|(head, _)| head)
            .unwrap_or(trimmed);
        before_args
            .rsplit_once('.')
            .map(|(receiver, _)| receiver.to_string())
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
}
