use super::*;
use crate::analyzer::clone_detection::{
    CloneCandidateData, compact_clone_excerpt, compute_ast_refinement_similarity_percent,
};
use tree_sitter::{Node, Parser, Tree};

pub(super) fn build_clone_candidate_data(
    analyzer: &CppAnalyzer,
    code_unit: &CodeUnit,
    weights: CloneSmellWeights,
) -> Option<CloneCandidateData> {
    analyzer
        .get_source(code_unit, false)
        .map(|source| source.trim().to_string())
        .filter(|source| !source.is_empty())
        .and_then(|source| {
            let normalized_tokens = normalized_clone_tokens_cpp(&source);
            if normalized_tokens.len() < weights.min_normalized_tokens.max(0) as usize {
                return None;
            }
            Some(CloneCandidateData {
                unit: code_unit.clone(),
                normalized_tokens,
                ast_signature: build_cpp_clone_ast_signature(&source),
                excerpt: compact_clone_excerpt(&source),
            })
        })
}
const CPP_CLONE_AST_IDENTIFIER_TYPES: &[&str] = &[
    "identifier",
    "field_identifier",
    "namespace_identifier",
    "type_identifier",
];
const CPP_CLONE_AST_STRING_TYPES: &[&str] = &["string_literal", "raw_string_literal"];
const CPP_CLONE_AST_NUMBER_TYPES: &[&str] = &["number_literal"];

fn normalized_clone_tokens_cpp(source: &str) -> Vec<String> {
    let Some(tree) = parse_cpp_tree(source) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    collect_normalized_leaf_tokens_cpp(tree.root_node(), source, &mut out);
    out
}

fn collect_normalized_leaf_tokens_cpp(node: Node<'_>, source: &str, out: &mut Vec<String>) {
    if cpp_is_ignorable_clone_logging_node(node, source) {
        return;
    }
    if node.named_child_count() == 0 {
        let token = normalize_cpp_clone_leaf_token(node, source);
        if !token.is_empty() {
            out.push(token);
        }
    }
    let child_count = node.child_count();
    for index in 0..child_count {
        if let Some(child) = node.child(index) {
            collect_normalized_leaf_tokens_cpp(child, source, out);
        }
    }
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

fn build_cpp_clone_ast_signature(source: &str) -> String {
    let Some(tree) = parse_cpp_tree(source) else {
        return String::new();
    };
    let mut labels = Vec::new();
    collect_cpp_clone_ast_labels(tree.root_node(), source, &mut labels);
    labels.join("|")
}

fn collect_cpp_clone_ast_labels(node: Node<'_>, source: &str, out: &mut Vec<String>) {
    if cpp_is_ignorable_clone_logging_node(node, source) {
        return;
    }
    out.push(normalize_cpp_clone_ast_label(node, source));
    let child_count = node.child_count();
    for index in 0..child_count {
        if let Some(child) = node.child(index) {
            collect_cpp_clone_ast_labels(child, source, out);
        }
    }
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

pub(super) fn refine_cpp_clone_similarity(
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

fn parse_cpp_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .expect("failed to load cpp parser");
    parser.parse(source, None)
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
