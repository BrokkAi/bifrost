//! Token and AST-label normalization for Java structural-clone candidates.
//!
//! `CloneCandidateData` and `compact_clone_excerpt` are analysis-owned and the
//! declaration source comes from the analyzer, so `analyzer/java/clones.rs`
//! keeps the entry point; everything that knows Java is here. Same split as
//! [`brokk_bifrost_cpp::clones`].

use crate::java::declarations::parse_tree;
use brokk_bifrost_core::analyzer::source_content::SourceContent;
use brokk_bifrost_core::hash::HashSet;
use std::sync::LazyLock;
use tree_sitter::Node;

static CLONE_AST_IDENTIFIER_TYPES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from_iter([
        "identifier",
        "type_identifier",
        "scoped_identifier",
        "scoped_type_identifier",
    ])
});
static CLONE_AST_STRING_TYPES: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| HashSet::from_iter(["string_literal", "character_literal"]));
static CLONE_AST_NUMBER_TYPES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from_iter([
        "decimal_integer_literal",
        "hex_integer_literal",
        "octal_integer_literal",
        "binary_integer_literal",
        "decimal_floating_point_literal",
        "hex_floating_point_literal",
    ])
});
static CLONE_AST_IGNORED_TYPES: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| HashSet::from_iter(["modifiers", "type_parameters"]));

/// The normalized leaf-token stream for `source`.
pub fn normalized_clone_tokens_java(source: &str) -> Vec<String> {
    let Some(tree) = parse_tree(source) else {
        return Vec::new();
    };
    let content = SourceContent::new(source);
    let mut out = Vec::new();
    collect_normalized_leaf_tokens_java(tree.root_node(), &content, &mut out);
    out
}

fn collect_normalized_leaf_tokens_java(
    node: Node<'_>,
    source_content: &SourceContent,
    out: &mut Vec<String>,
) {
    if node.named_child_count() == 0 {
        let token = normalize_java_clone_leaf_token(node, source_content);
        if !token.is_empty() {
            out.push(token);
        }
    }
    let child_count = node.child_count();
    for index in 0..child_count {
        if let Some(child) = node.child(index) {
            collect_normalized_leaf_tokens_java(child, source_content, out);
        }
    }
}

fn normalize_java_clone_leaf_token(node: Node<'_>, source_content: &SourceContent) -> String {
    let kind = node.kind();
    let token = source_content
        .as_str()
        .get(node.start_byte()..node.end_byte())
        .unwrap_or("")
        .trim();
    if token.is_empty() {
        return String::new();
    }
    if CLONE_AST_IDENTIFIER_TYPES.contains(kind) {
        return "ID".to_string();
    }
    if CLONE_AST_STRING_TYPES.contains(kind) {
        return "STR".to_string();
    }
    if CLONE_AST_NUMBER_TYPES.contains(kind) {
        return "NUM".to_string();
    }
    if token == "true" || token == "false" {
        return "BOOL".to_string();
    }
    if token.chars().count() == 1 && token.chars().all(|ch| !ch.is_alphanumeric()) {
        return format!("OP:{token}");
    }
    format!("T:{kind}")
}

/// The `|`-joined AST-label signature for `source`.
pub fn build_java_clone_ast_signature(source: &str) -> String {
    let Some(tree) = parse_tree(source) else {
        return String::new();
    };
    let content = SourceContent::new(source);
    let mut labels = Vec::new();
    collect_java_clone_ast_labels(tree.root_node(), &content, &mut labels);
    labels.join("|")
}

fn collect_java_clone_ast_labels(
    node: Node<'_>,
    source_content: &SourceContent,
    out: &mut Vec<String>,
) {
    out.push(normalize_java_clone_ast_label(node, source_content));
    let child_count = node.child_count();
    for index in 0..child_count {
        if let Some(child) = node.child(index) {
            collect_java_clone_ast_labels(child, source_content, out);
        }
    }
}

fn normalize_java_clone_ast_label(node: Node<'_>, source_content: &SourceContent) -> String {
    let kind = node.kind();
    let text = source_content
        .as_str()
        .get(node.start_byte()..node.end_byte())
        .unwrap_or("")
        .trim();
    if CLONE_AST_IDENTIFIER_TYPES.contains(kind) {
        return "ID".to_string();
    }
    if CLONE_AST_STRING_TYPES.contains(kind) {
        return "STR".to_string();
    }
    if CLONE_AST_NUMBER_TYPES.contains(kind) {
        return "NUM".to_string();
    }
    if kind == "boolean_literal" || text == "true" || text == "false" {
        return "BOOL".to_string();
    }
    if CLONE_AST_IGNORED_TYPES.contains(kind) {
        return "IGN".to_string();
    }
    format!("N:{kind}")
}
