use super::declarations::{RubyVisitor, collect_ruby_identifiers};
use super::tests::ruby_source_contains_tests;
use super::*;
use crate::analyzer::LanguageAdapter;
use crate::analyzer::cognitive_complexity;
use std::sync::LazyLock;
use tree_sitter::Tree;

/// Tree-sitter node-kind mapping used by the cognitive-complexity scorer for
/// Ruby. Node names are from the tree-sitter-ruby grammar.
static RUBY_COGNITIVE_CONFIG: LazyLock<cognitive_complexity::Config> =
    LazyLock::new(|| cognitive_complexity::Config {
        if_types: &["if", "unless", "if_modifier", "unless_modifier"],
        alternate_if_types: &["elsif"],
        loop_types: &["while", "until", "for", "while_modifier", "until_modifier"],
        catch_types: &["rescue"],
        conditional_types: &["conditional"],
        case_types: &["when", "in_clause"],
        binary_types: &["binary"],
        logical_operators: &["&&", "||", "and", "or"],
        named_function_boundary_types: &["method", "singleton_method"],
        anonymous_function_types: &["block", "do_block", "lambda"],
        ..cognitive_complexity::Config::empty()
    });

#[derive(Debug, Clone, Default)]
pub struct RubyAdapter;

impl LanguageAdapter for RubyAdapter {
    fn language(&self) -> Language {
        Language::Ruby
    }

    fn query_directory(&self) -> &'static str {
        "resources/treesitter/ruby"
    }

    fn file_extension(&self) -> &'static str {
        "rb"
    }

    fn contains_tests(
        &self,
        _file: &ProjectFile,
        source: &str,
        _tree: &Tree,
        _parsed: &crate::analyzer::tree_sitter_analyzer::ParsedFile,
    ) -> bool {
        ruby_source_contains_tests(source)
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        let trimmed = reference.trim();
        let before_args = trimmed
            .split_once('(')
            .map(|(head, _)| head)
            .unwrap_or(trimmed);
        // Ruby receivers are separated by `.` (method) or `::` (namespace).
        if let Some((receiver, _)) = before_args.rsplit_once("::") {
            return Some(receiver.to_string());
        }
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
        let mut parsed = crate::analyzer::tree_sitter_analyzer::ParsedFile::new(String::new());
        let root = tree.root_node();

        collect_ruby_identifiers(root, source, &mut parsed.type_identifiers);

        let mut visitor = RubyVisitor {
            file,
            source,
            parsed: &mut parsed,
        };
        visitor.visit_program(root);

        parsed
    }

    fn cognitive_complexity_config(&self) -> Option<&'static cognitive_complexity::Config> {
        Some(&RUBY_COGNITIVE_CONFIG)
    }
}
