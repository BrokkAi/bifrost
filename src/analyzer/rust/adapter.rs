use crate::analyzer::cognitive_complexity;
use crate::analyzer::{Language, LanguageAdapter, ProjectFile};
use std::sync::LazyLock;
use tree_sitter::{Language as TsLanguage, Tree};

use super::declarations::{parse_rust_file, rust_package_name};
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

#[derive(Debug, Clone, Default)]
pub(crate) struct RustAdapter;

impl LanguageAdapter for RustAdapter {
    fn language(&self) -> Language {
        Language::Rust
    }

    fn query_directory(&self) -> &'static str {
        "resources/treesitter/rust"
    }

    fn parser_language(&self) -> TsLanguage {
        tree_sitter_rust::LANGUAGE.into()
    }

    fn file_extension(&self) -> &'static str {
        "rs"
    }

    fn storage_content_qualifier(
        &self,
        _code_unit: &crate::analyzer::CodeUnit,
        _content_qualifier: &str,
    ) -> String {
        String::new()
    }

    fn persisted_content_qualifier_supports_substring_search(&self) -> bool {
        false
    }

    fn storage_file_content_qualifier(&self, _package_name: &str) -> String {
        String::new()
    }

    fn hydrate_content_qualifier(&self, _content_qualifier: &str, file: &ProjectFile) -> String {
        rust_package_name(file)
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

    fn structural_spec(&self) -> Option<&'static dyn crate::analyzer::structural::StructuralSpec> {
        Some(&super::structural::RUST_STRUCTURAL_SPEC)
    }
}
