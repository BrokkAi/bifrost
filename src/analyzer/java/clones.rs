use super::*;
use crate::analyzer::SourceContent;
use crate::analyzer::clone_detection::{
    CloneCandidateData, compact_clone_excerpt, compute_ast_refinement_similarity_percent,
};
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

pub(super) fn build_clone_candidate_data(
    analyzer: &JavaAnalyzer,
    code_unit: &CodeUnit,
    weights: CloneSmellWeights,
) -> Option<CloneCandidateData> {
    analyzer
        .get_source(code_unit, false)
        .map(|source| source.trim().to_string())
        .filter(|source| !source.is_empty())
        .and_then(|source| {
            let normalized_tokens = normalized_clone_tokens_java(&source);
            if normalized_tokens.len() < weights.min_normalized_tokens.max(0) as usize {
                return None;
            }
            Some(CloneCandidateData {
                unit: code_unit.clone(),
                normalized_tokens,
                ast_signature: build_java_clone_ast_signature(&source),
                excerpt: compact_clone_excerpt(&source),
            })
        })
}

fn normalized_clone_tokens_java(source: &str) -> Vec<String> {
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

fn build_java_clone_ast_signature(source: &str) -> String {
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

pub(super) fn refine_java_clone_similarity(
    left: &CloneCandidateData,
    right: &CloneCandidateData,
    token_similarity: i32,
    weights: CloneSmellWeights,
) -> i32 {
    if left.ast_signature.is_empty() || right.ast_signature.is_empty() {
        return token_similarity;
    }
    let ast_similarity =
        compute_ast_refinement_similarity_percent(&left.ast_signature, &right.ast_signature);
    if ast_similarity == 0 {
        return token_similarity;
    }
    if ast_similarity < weights.ast_similarity_percent {
        return 0;
    }
    token_similarity.min(ast_similarity)
}
