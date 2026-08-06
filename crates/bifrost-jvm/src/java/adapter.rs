//! The Java answers behind `JavaAdapter`.
//!
//! `LanguageAdapter` is analysis-owned, so the trait impl itself stays in
//! `analyzer/java/adapter.rs`; every answer it gives comes from here, from
//! [`crate::java::declarations`] or from [`crate::java::test_detection`].

use brokk_bifrost_core::analyzer::cognitive_complexity;
use std::sync::LazyLock;
use tree_sitter::{Node, Parser};

pub const JAVA_FILE_EXTENSION: &str = "java";

/// Tree-sitter node-kind mapping used by the cognitive-complexity scorer
/// for Java. Mirrors `ai.brokk.analyzer.java.CognitiveComplexityAnalysis`.
pub static JAVA_COGNITIVE_CONFIG: LazyLock<cognitive_complexity::Config> =
    LazyLock::new(|| cognitive_complexity::Config {
        if_types: &["if_statement"],
        loop_types: &[
            "for_statement",
            "enhanced_for_statement",
            "while_statement",
            "do_statement",
        ],
        catch_types: &["catch_clause"],
        conditional_types: &["ternary_expression"],
        case_types: &["switch_label", "switch_rule"],
        binary_types: &["binary_expression"],
        logical_operators: &["&&", "||"],
        jump_types: &["break_statement", "continue_statement"],
        anonymous_function_types: &["lambda_expression"],
        default_case_predicate: Some(java_is_default_switch_label),
        ..cognitive_complexity::Config::empty()
    });

fn java_is_default_switch_label(node: Node<'_>, source: &str) -> bool {
    let Some(text) = source.get(node.start_byte()..node.end_byte()) else {
        return false;
    };
    text.trim_start().starts_with("default")
}

/// The return-type span of a rendered Java member signature, read back out of
/// the signature text by parsing it inside a synthetic class body.
pub fn java_callable_return_type_text(signature: &str) -> Option<&str> {
    let prefix = "class __BifrostSignature { ";
    let source = format!("{prefix}{signature}; }}");
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_java::LANGUAGE.into())
        .ok()?;
    let tree = parser.parse(source.as_str(), None)?;
    let declaration = find_signature_declaration(tree.root_node())?;
    let type_node = declaration.child_by_field_name("type")?;
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
        if matches!(node.kind(), "method_declaration" | "field_declaration") {
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
