//! The Ruby answers behind `RubyAdapter`.
//!
//! `LanguageAdapter` is analysis-owned, so the trait impl itself stays in
//! `analyzer/ruby/adapter.rs`; every answer it gives comes from here or from
//! [`crate::declarations`] and [`crate::test_detection`].

use crate::declarations::{RubyVisitor, collect_ruby_identifiers};
use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::cognitive_complexity;
use brokk_bifrost_core::analyzer::parsed_file::ParsedFile;
use std::sync::LazyLock;
use tree_sitter::Tree;

pub const RUBY_FILE_EXTENSION: &str = "rb";

/// Tree-sitter node-kind mapping used by the cognitive-complexity scorer for
/// Ruby. Node names are from the tree-sitter-ruby grammar.
pub static RUBY_COGNITIVE_CONFIG: LazyLock<cognitive_complexity::Config> =
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

pub fn ruby_extract_call_receiver(reference: &str) -> Option<String> {
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

pub fn parse_ruby_file(file: &ProjectFile, source: &str, tree: &Tree) -> ParsedFile {
    let mut parsed = ParsedFile::new(String::new());
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
