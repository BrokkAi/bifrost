//! Pure Ruby node helpers shared by the declaration walk, the structural spec,
//! the import binder and both usage-graph scans.
//!
//! These were free functions at the top of `analyzer/ruby/mod.rs`, above the
//! `RubyAnalyzer` struct: nothing here needs an analyzer handle, only a
//! `tree_sitter::Node` and the source text it points into.

use brokk_bifrost_core::analyzer::model::Range;
use tree_sitter::Node;

pub fn single_static_string_content_node(node: Node<'_>) -> Option<Node<'_>> {
    if node.named_child_count() != 1 {
        return None;
    }
    let content = node.named_child(0)?;
    (content.kind() == "string_content").then_some(content)
}

pub fn ruby_call_arguments(node: Node<'_>) -> Vec<Node<'_>> {
    let Some(arguments) = ruby_call_arguments_node(node) else {
        return Vec::new();
    };
    let mut cursor = arguments.walk();
    arguments
        .named_children(&mut cursor)
        .filter(|child| is_runtime_node(child.kind()))
        .collect()
}

pub fn ruby_first_call_argument(node: Node<'_>) -> Option<Node<'_>> {
    let arguments = ruby_call_arguments_node(node)?;
    let mut cursor = arguments.walk();
    arguments
        .named_children(&mut cursor)
        .find(|child| is_runtime_node(child.kind()))
}

fn ruby_call_arguments_node(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("arguments")
}

/// Whether an argument-list child is a runtime value rather than a parameter,
/// comment or symbol-key slot. Also read by the parked Ruby value-semantics
/// lowerer, which enumerates call arguments the same way.
pub fn is_runtime_node(kind: &str) -> bool {
    !matches!(
        kind,
        "comment"
            | "method_parameters"
            | "lambda_parameters"
            | "block_parameters"
            | "block_parameter"
            | "optional_parameter"
            | "keyword_parameter"
            | "splat_parameter"
            | "hash_splat_parameter"
            | "forward_parameter"
            | "destructured_parameter"
            | "exception_variable"
            | "hash_key_symbol"
            | "bare_symbol"
    )
}

/// Returns the source range of the semantic identifier carried by a Ruby symbol.
///
/// Tree-sitter represents an unquoted symbol such as `:audit` as one leaf
/// `simple_symbol` node, so its parser range includes the leading colon. Static
/// quoted symbols have a structured `string_content` child that excludes both
/// the colon and quote delimiters. Other nodes keep their parser range.
pub fn ruby_semantic_identifier_range(node: Node<'_>, source: &str) -> Range {
    let node_range = || Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row,
        end_line: node.end_position().row,
    };

    match node.kind() {
        "simple_symbol" => {
            let text = source.get(node.start_byte()..node.end_byte()).unwrap_or("");
            if text.strip_prefix(':').is_none_or(str::is_empty) {
                return node_range();
            }
            Range {
                start_byte: node.start_byte() + ':'.len_utf8(),
                end_byte: node.end_byte(),
                start_line: node.start_position().row,
                end_line: node.end_position().row,
            }
        }
        "delimited_symbol" => {
            let Some(content) = single_static_string_content_node(node) else {
                return node_range();
            };
            Range {
                start_byte: content.start_byte(),
                end_byte: content.end_byte(),
                start_line: content.start_position().row,
                end_line: content.end_position().row,
            }
        }
        _ => node_range(),
    }
}
