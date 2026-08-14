//! The C++ answers behind `CppAdapter`.
//!
//! `LanguageAdapter` is analysis-owned, so the trait impl itself stays in
//! `analyzer/cpp/adapter.rs`; every answer it gives comes from here or from
//! [`crate::test_detection`] and [`crate::queries`].

use crate::declarations::{CppVisitor, collect_cpp_identifiers, recover_quoted_includes};
use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::cognitive_complexity;
use brokk_bifrost_core::analyzer::parsed_file::ParsedFile;
use brokk_bifrost_core::hash::HashMap;
use std::sync::LazyLock;
use tree_sitter::{Node, Tree};

/// The file extension `CppAdapter` reports. `Language::Cpp` also covers `.c`,
/// `.cc`, `.cxx` and the header spellings; this is only the canonical one.
pub const CPP_FILE_EXTENSION: &str = "cpp";

/// Tree-sitter node-kind mapping used by the cognitive-complexity scorer for
/// C++. Node names are from the tree-sitter-cpp grammar.
pub static CPP_COGNITIVE_CONFIG: LazyLock<cognitive_complexity::Config> =
    LazyLock::new(|| cognitive_complexity::Config {
        if_types: &["if_statement"],
        loop_types: &["for_statement", "while_statement", "do_statement"],
        catch_types: &["catch_clause"],
        conditional_types: &["conditional_expression"],
        case_types: &["case_statement"],
        binary_types: &["binary_expression"],
        logical_operators: &["&&", "||", "and", "or"],
        jump_types: &["break_statement", "continue_statement"],
        named_function_boundary_types: &["function_definition"],
        anonymous_function_types: &["lambda_expression"],
        else_clause_types: &["else_clause"],
        default_case_predicate: Some(cpp_is_default_case),
        ..cognitive_complexity::Config::empty()
    });

fn cpp_is_default_case(node: Node<'_>, _source: &str) -> bool {
    node.child_by_field_name("value").is_none()
}

pub fn parse_cpp_file(file: &ProjectFile, source: &str, tree: &Tree) -> ParsedFile {
    let mut parsed = ParsedFile::new(String::new());
    let root = tree.root_node();

    collect_cpp_identifiers(root, source, &mut parsed.type_identifiers);

    let mut visitor = CppVisitor {
        file,
        source,
        parsed: &mut parsed,
        recovered_class_sibling_scopes: HashMap::default(),
        consumed_fragment_regions: Vec::new(),
    };
    visitor.visit_container(root, "", None, None, None, Vec::new());
    recover_quoted_includes(source, &mut parsed);

    parsed
}

pub fn cpp_extract_call_receiver(reference: &str) -> Option<String> {
    let trimmed = reference.trim();
    let before_args = trimmed
        .split_once('(')
        .map(|(head, _)| head)
        .unwrap_or(trimmed);
    before_args
        .rsplit_once("::")
        .or_else(|| before_args.rsplit_once('.'))
        .map(|(receiver, _)| receiver.to_string())
}
