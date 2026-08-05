//! The PHP answers behind `PhpAdapter`.
//!
//! `LanguageAdapter` is analysis-owned, so the trait impl itself stays in
//! `analyzer/php/adapter.rs`; every answer it gives comes from here or from
//! [`crate::declarations`] and [`crate::test_detection`].

use brokk_bifrost_core::analyzer::cognitive_complexity;
use std::sync::LazyLock;
use tree_sitter::{Node, Parser};

use crate::declarations::php_declared_type_node;

pub const PHP_FILE_EXTENSION: &str = "php";

/// Tree-sitter node-kind mapping used by the cognitive-complexity scorer for
/// PHP.
pub static PHP_COGNITIVE_CONFIG: LazyLock<cognitive_complexity::Config> =
    LazyLock::new(|| cognitive_complexity::Config {
        if_types: &["if_statement", "else_if_clause"],
        loop_types: &[
            "for_statement",
            "foreach_statement",
            "while_statement",
            "do_statement",
        ],
        catch_types: &["catch_clause"],
        conditional_types: &["conditional_expression"],
        case_types: &["case_statement", "match_condition"],
        default_case_types: &["default_statement", "match_default_expression"],
        binary_types: &["binary_expression"],
        logical_operators: &["&&", "||", "and", "or", "??"],
        jump_types: &["break_statement", "continue_statement"],
        named_function_boundary_types: &["function_definition", "method_declaration"],
        anonymous_function_types: &["anonymous_function", "arrow_function"],
        else_clause_types: &["else_clause"],
        ..cognitive_complexity::Config::empty()
    });

pub fn php_extract_call_receiver(reference: &str) -> Option<String> {
    let trimmed = reference.trim();
    let before_args = trimmed
        .split_once('(')
        .map(|(head, _)| head)
        .unwrap_or(trimmed);
    before_args
        .rsplit_once("::")
        .or_else(|| before_args.rsplit_once("->"))
        .map(|(receiver, _)| receiver.to_string())
}

pub fn php_signature_return_type_text(signature: &str) -> Option<&str> {
    php_wrapped_signature_return_type_text(signature, "<?php\n", "\n").or_else(|| {
        php_wrapped_signature_return_type_text(
            signature,
            "<?php\nclass __BifrostSignature {\n",
            "\n}\n",
        )
    })
}

fn php_wrapped_signature_return_type_text<'a>(
    signature: &'a str,
    prefix: &str,
    suffix: &str,
) -> Option<&'a str> {
    let source = format!("{prefix}{signature}{suffix}");
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
        .ok()?;
    let tree = parser.parse(source.as_str(), None)?;
    let declaration = find_signature_declaration(tree.root_node())?;
    let type_node = php_declared_type_node(declaration)?;
    signature_slice(
        signature,
        prefix.len(),
        type_node.start_byte(),
        type_node.end_byte(),
    )
}

fn find_signature_declaration(root: Node<'_>) -> Option<Node<'_>> {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if matches!(
            node.kind(),
            "function_definition" | "method_declaration" | "property_declaration"
        ) {
            return Some(node);
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
    None
}

fn signature_slice(
    signature: &str,
    offset: usize,
    start_byte: usize,
    end_byte: usize,
) -> Option<&str> {
    let start = start_byte.checked_sub(offset)?;
    let end = end_byte.checked_sub(offset)?;
    signature.get(start..end).map(str::trim)
}
