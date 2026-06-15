use crate::CloneSmellWeights;
use crate::analyzer::clone_detection::{
    CloneCandidateData, compact_clone_excerpt, compute_ast_refinement_similarity_percent,
};
use crate::analyzer::{CodeUnit, IAnalyzer};
use tree_sitter::{Node, Parser, Tree};

use super::ScalaAnalyzer;

const SCALA_CLONE_AST_IDENTIFIER_TYPES: &[&str] = &["identifier"];
const SCALA_CLONE_AST_STRING_TYPES: &[&str] = &["string"];
const SCALA_CLONE_AST_NUMBER_TYPES: &[&str] = &["integer_literal", "floating_point_literal"];

fn normalized_clone_tokens_scala(source: &str) -> Vec<String> {
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

fn build_scala_clone_ast_signature(source: &str) -> String {
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

pub(super) fn refine_scala_clone_similarity(
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

fn parse_scala_tree(source: &str) -> Option<Tree> {
    if crate::analyzer::common::is_unparseable_source(source) {
        return None;
    }
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_scala::LANGUAGE.into())
        .expect("failed to load scala parser");
    parser.parse(source, None)
}

pub(super) fn build_scala_clone_candidate_data(
    analyzer: &ScalaAnalyzer,
    code_unit: &CodeUnit,
    weights: CloneSmellWeights,
) -> Option<CloneCandidateData> {
    analyzer
        .get_source(code_unit, false)
        .map(|source| source.trim().to_string())
        .filter(|source| !source.is_empty())
        .and_then(|source| {
            let normalized_tokens = normalized_clone_tokens_scala(&source);
            if normalized_tokens.len() < weights.min_normalized_tokens.max(0) as usize {
                return None;
            }
            Some(CloneCandidateData {
                unit: code_unit.clone(),
                normalized_tokens,
                ast_signature: build_scala_clone_ast_signature(&source),
                excerpt: compact_clone_excerpt(&source),
            })
        })
}
