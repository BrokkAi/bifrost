//! Token and AST-label normalization for C++ structural-clone candidates.
//!
//! `CloneCandidateData` and `compact_clone_excerpt` are analysis-owned and the
//! declaration source comes from the analyzer, so `analyzer/cpp/clones.rs` keeps
//! the ~12-LOC entry point; everything that knows C++ is here.

use tree_sitter::{Node, Parser};

const CPP_CLONE_AST_IDENTIFIER_TYPES: &[&str] = &[
    "identifier",
    "field_identifier",
    "namespace_identifier",
    "type_identifier",
];
const CPP_CLONE_AST_STRING_TYPES: &[&str] = &["string_literal", "raw_string_literal"];
const CPP_CLONE_AST_NUMBER_TYPES: &[&str] = &["number_literal"];

pub fn cpp_clone_parser() -> Parser {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .expect("failed to load cpp parser");
    parser
}

fn normalize_cpp_clone_leaf_token(node: Node<'_>, source: &str) -> String {
    let kind = node.kind();
    let token = source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or("")
        .trim();
    if token.is_empty() || kind == "comment" {
        return String::new();
    }
    if CPP_CLONE_AST_IDENTIFIER_TYPES.contains(&kind) {
        return "ID".to_string();
    }
    if CPP_CLONE_AST_STRING_TYPES.contains(&kind) {
        return "STR".to_string();
    }
    if CPP_CLONE_AST_NUMBER_TYPES.contains(&kind) {
        return "NUM".to_string();
    }
    if matches!(token, "true" | "false") {
        return "BOOL".to_string();
    }
    if token.chars().count() == 1 && token.chars().all(|ch| !ch.is_alphanumeric()) {
        return format!("OP:{token}");
    }
    format!("T:{kind}")
}

/// The normalized token stream and the joined AST-label signature for one C++
/// declaration body, in a single walk.
pub fn cpp_clone_profile(parser: &mut Parser, source: &str) -> (Vec<String>, String) {
    let Some(tree) = parser.parse(source, None) else {
        return (Vec::new(), String::new());
    };
    let mut normalized_tokens = Vec::new();
    let mut ast_labels = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if cpp_is_ignorable_clone_logging_node(node, source) {
            continue;
        }
        ast_labels.push(normalize_cpp_clone_ast_label(node, source));
        if node.named_child_count() == 0 {
            let token = normalize_cpp_clone_leaf_token(node, source);
            if !token.is_empty() {
                normalized_tokens.push(token);
            }
        }
        for index in (0..node.child_count()).rev() {
            if let Some(child) = node.child(index) {
                stack.push(child);
            }
        }
    }
    (normalized_tokens, ast_labels.join("|"))
}

fn normalize_cpp_clone_ast_label(node: Node<'_>, source: &str) -> String {
    let kind = node.kind();
    let text = source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or("")
        .trim();
    if CPP_CLONE_AST_IDENTIFIER_TYPES.contains(&kind) {
        return "ID".to_string();
    }
    if CPP_CLONE_AST_STRING_TYPES.contains(&kind) {
        return "STR".to_string();
    }
    if CPP_CLONE_AST_NUMBER_TYPES.contains(&kind) {
        return "NUM".to_string();
    }
    if matches!(text, "true" | "false") {
        return "BOOL".to_string();
    }
    format!("N:{kind}")
}

fn cpp_is_ignorable_clone_logging_node(node: Node<'_>, source: &str) -> bool {
    if node.kind() != "expression_statement" {
        return false;
    }
    let text = source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or("")
        .trim();
    text.contains("std::cout")
        || text.contains("std::cerr")
        || text.contains("std::clog")
        || text.starts_with("printf(")
}
