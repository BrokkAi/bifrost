//! Python's clone-detection token and AST-signature normalization.
//!
//! `analyzer/python/clones.rs` in `brokk-bifrost-analysis` keeps the entry
//! point: it reads the declaration's source through the analyzer and assembles
//! the analysis-owned `CloneCandidateData`. Everything that knows what a Python
//! token *is* lives here.

use crate::declarations::parse_python_tree;
use tree_sitter::Node;

const PYTHON_CLONE_AST_IDENTIFIER_TYPES: &[&str] = &["identifier", "keyword_identifier"];
const PYTHON_CLONE_AST_STRING_TYPES: &[&str] = &["string", "string_content", "interpolation"];
const PYTHON_CLONE_AST_NUMBER_TYPES: &[&str] = &["integer", "float"];

pub fn normalized_clone_tokens_python(source: &str) -> Vec<String> {
    let Some(tree) = parse_python_tree(source) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    collect_normalized_leaf_tokens_python(tree.root_node(), source, &mut out);
    out
}

fn collect_normalized_leaf_tokens_python(node: Node<'_>, source: &str, out: &mut Vec<String>) {
    if node.named_child_count() == 0 {
        let token = normalize_python_clone_leaf_token(node, source);
        if !token.is_empty() {
            out.push(token);
        }
    }
    let child_count = node.child_count();
    for index in 0..child_count {
        if let Some(child) = node.child(index) {
            collect_normalized_leaf_tokens_python(child, source, out);
        }
    }
}

fn normalize_python_clone_leaf_token(node: Node<'_>, source: &str) -> String {
    let kind = node.kind();
    let token = source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or("")
        .trim();
    if token.is_empty() || kind == "comment" {
        return String::new();
    }
    if PYTHON_CLONE_AST_IDENTIFIER_TYPES.contains(&kind) {
        return "ID".to_string();
    }
    if PYTHON_CLONE_AST_STRING_TYPES.contains(&kind) {
        return "STR".to_string();
    }
    if PYTHON_CLONE_AST_NUMBER_TYPES.contains(&kind) {
        return "NUM".to_string();
    }
    if kind == "true" || kind == "false" || token == "True" || token == "False" {
        return "BOOL".to_string();
    }
    if token.chars().count() == 1 && token.chars().all(|ch| !ch.is_alphanumeric()) {
        return format!("OP:{token}");
    }
    format!("T:{kind}")
}

pub fn build_python_clone_ast_signature(source: &str) -> String {
    let Some(tree) = parse_python_tree(source) else {
        return String::new();
    };
    let mut labels = Vec::new();
    collect_python_clone_ast_labels(tree.root_node(), source, &mut labels);
    labels.join("|")
}

fn collect_python_clone_ast_labels(node: Node<'_>, source: &str, out: &mut Vec<String>) {
    out.push(normalize_python_clone_ast_label(node, source));
    let child_count = node.child_count();
    for index in 0..child_count {
        if let Some(child) = node.child(index) {
            collect_python_clone_ast_labels(child, source, out);
        }
    }
}

fn normalize_python_clone_ast_label(node: Node<'_>, source: &str) -> String {
    let kind = node.kind();
    let text = source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or("")
        .trim();
    if PYTHON_CLONE_AST_IDENTIFIER_TYPES.contains(&kind) {
        return "ID".to_string();
    }
    if PYTHON_CLONE_AST_STRING_TYPES.contains(&kind) {
        return "STR".to_string();
    }
    if PYTHON_CLONE_AST_NUMBER_TYPES.contains(&kind) {
        return "NUM".to_string();
    }
    if kind == "true" || kind == "false" || text == "True" || text == "False" {
        return "BOOL".to_string();
    }
    format!("N:{kind}")
}
