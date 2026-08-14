//! Scala's structural-clone normalization.
//!
//! Two views of the same declaration source: a leaf-token stream with
//! identifiers and literals collapsed to placeholders, and an AST-label
//! signature over every node. `CloneCandidateData` and the excerpt formatter
//! are analysis-owned, so `analyzer/scala/clones.rs` keeps the candidate
//! builder that reads the declaration off the analyzer.

use tree_sitter::{Node, Parser, Tree};

const SCALA_CLONE_AST_IDENTIFIER_TYPES: &[&str] = &["identifier"];
const SCALA_CLONE_AST_STRING_TYPES: &[&str] = &["string"];
const SCALA_CLONE_AST_NUMBER_TYPES: &[&str] = &["integer_literal", "floating_point_literal"];

pub fn normalized_clone_tokens_scala(source: &str) -> Vec<String> {
    let Some(tree) = parse_scala_tree(source) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    collect_normalized_leaf_tokens_scala(tree.root_node(), source, &mut out);
    out
}

fn collect_normalized_leaf_tokens_scala(node: Node<'_>, source: &str, out: &mut Vec<String>) {
    if node.named_child_count() == 0 {
        let token = normalize_scala_clone_leaf_token(node, source);
        if !token.is_empty() {
            out.push(token);
        }
    }
    let child_count = node.child_count();
    for index in 0..child_count {
        if let Some(child) = node.child(index) {
            collect_normalized_leaf_tokens_scala(child, source, out);
        }
    }
}

fn normalize_scala_clone_leaf_token(node: Node<'_>, source: &str) -> String {
    let kind = node.kind();
    let token = source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or("")
        .trim();
    if token.is_empty() || kind == "comment" {
        return String::new();
    }
    if SCALA_CLONE_AST_IDENTIFIER_TYPES.contains(&kind) {
        return "ID".to_string();
    }
    if SCALA_CLONE_AST_STRING_TYPES.contains(&kind) {
        return "STR".to_string();
    }
    if SCALA_CLONE_AST_NUMBER_TYPES.contains(&kind) {
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

pub fn build_scala_clone_ast_signature(source: &str) -> String {
    let Some(tree) = parse_scala_tree(source) else {
        return String::new();
    };
    let mut labels = Vec::new();
    collect_scala_clone_ast_labels(tree.root_node(), source, &mut labels);
    labels.join("|")
}

fn collect_scala_clone_ast_labels(node: Node<'_>, source: &str, out: &mut Vec<String>) {
    out.push(normalize_scala_clone_ast_label(node, source));
    let child_count = node.child_count();
    for index in 0..child_count {
        if let Some(child) = node.child(index) {
            collect_scala_clone_ast_labels(child, source, out);
        }
    }
}

fn normalize_scala_clone_ast_label(node: Node<'_>, source: &str) -> String {
    let kind = node.kind();
    let text = source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or("")
        .trim();
    if SCALA_CLONE_AST_IDENTIFIER_TYPES.contains(&kind) {
        return "ID".to_string();
    }
    if SCALA_CLONE_AST_STRING_TYPES.contains(&kind) {
        return "STR".to_string();
    }
    if SCALA_CLONE_AST_NUMBER_TYPES.contains(&kind) {
        return "NUM".to_string();
    }
    if matches!(text, "true" | "false") {
        return "BOOL".to_string();
    }
    format!("N:{kind}")
}

fn parse_scala_tree(source: &str) -> Option<Tree> {
    if brokk_bifrost_core::analyzer::common::is_unparseable_source(source) {
        return None;
    }
    let mut parser = Parser::new();
    parser
        .set_language(&crate::scala::language::LANGUAGE.into())
        .expect("failed to load scala parser");
    parser.parse(source, None)
}
