use crate::CloneSmellWeights;
use crate::analyzer::clone_detection::{
    CloneCandidateData, compact_clone_excerpt, compute_ast_refinement_similarity_percent,
};
use crate::analyzer::{CodeUnit, IAnalyzer};
use tree_sitter::{Node, Parser, Tree};

use super::PhpAnalyzer;

const PHP_CLONE_AST_IDENTIFIER_TYPES: &[&str] = &["name", "variable_name"];
const PHP_CLONE_AST_STRING_TYPES: &[&str] = &["string", "encapsed_string", "string_value"];
const PHP_CLONE_AST_NUMBER_TYPES: &[&str] = &["integer", "float"];

fn normalized_clone_tokens_php(source: &str) -> Vec<String> {
    let parse_source = php_clone_parse_source(source);
    let Some(tree) = parse_php_tree(&parse_source) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    collect_normalized_leaf_tokens_php(tree.root_node(), &parse_source, &mut out);
    out
}

fn collect_normalized_leaf_tokens_php(node: Node<'_>, source: &str, out: &mut Vec<String>) {
    if php_is_ignorable_clone_logging_node(node, source) {
        return;
    }
    if node.named_child_count() == 0 {
        let token = normalize_php_clone_leaf_token(node, source);
        if !token.is_empty() {
            out.push(token);
        }
    }
    let child_count = node.child_count();
    for index in 0..child_count {
        if let Some(child) = node.child(index) {
            collect_normalized_leaf_tokens_php(child, source, out);
        }
    }
}

fn normalize_php_clone_leaf_token(node: Node<'_>, source: &str) -> String {
    let kind = node.kind();
    let token = source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or("")
        .trim();
    if token.is_empty() || kind == "comment" {
        return String::new();
    }
    if PHP_CLONE_AST_IDENTIFIER_TYPES.contains(&kind) {
        return "ID".to_string();
    }
    if PHP_CLONE_AST_STRING_TYPES.contains(&kind) {
        return "STR".to_string();
    }
    if PHP_CLONE_AST_NUMBER_TYPES.contains(&kind) {
        return "NUM".to_string();
    }
    if matches!(kind, "boolean" | "boolean_literal") || matches!(token, "true" | "false") {
        return "BOOL".to_string();
    }
    if matches!(kind, "null" | "null_literal") || token == "null" {
        return "NULL".to_string();
    }
    if token.chars().count() == 1 && token.chars().all(|ch| !ch.is_alphanumeric()) {
        return format!("OP:{token}");
    }
    format!("T:{kind}")
}

fn build_php_clone_ast_signature(source: &str) -> String {
    let parse_source = php_clone_parse_source(source);
    let Some(tree) = parse_php_tree(&parse_source) else {
        return String::new();
    };
    let mut labels = Vec::new();
    collect_php_clone_ast_labels(tree.root_node(), &parse_source, &mut labels);
    labels.join("|")
}

fn collect_php_clone_ast_labels(node: Node<'_>, source: &str, out: &mut Vec<String>) {
    if php_is_ignorable_clone_logging_node(node, source) {
        return;
    }
    out.push(normalize_php_clone_ast_label(node, source));
    let child_count = node.child_count();
    for index in 0..child_count {
        if let Some(child) = node.child(index) {
            collect_php_clone_ast_labels(child, source, out);
        }
    }
}

fn normalize_php_clone_ast_label(node: Node<'_>, source: &str) -> String {
    let kind = node.kind();
    let text = source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or("")
        .trim();
    if PHP_CLONE_AST_IDENTIFIER_TYPES.contains(&kind) {
        return "ID".to_string();
    }
    if PHP_CLONE_AST_STRING_TYPES.contains(&kind) {
        return "STR".to_string();
    }
    if PHP_CLONE_AST_NUMBER_TYPES.contains(&kind) {
        return "NUM".to_string();
    }
    if matches!(kind, "boolean" | "boolean_literal") || matches!(text, "true" | "false") {
        return "BOOL".to_string();
    }
    if matches!(kind, "null" | "null_literal") || text == "null" {
        return "NULL".to_string();
    }
    format!("N:{kind}")
}

pub(super) fn refine_php_clone_similarity(
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

fn parse_php_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
        .expect("failed to load php parser");
    parser.parse(source, None)
}

fn php_clone_parse_source(source: &str) -> String {
    if source.trim_start().starts_with("<?php") {
        source.to_string()
    } else {
        format!("<?php\n{source}")
    }
}

fn php_is_ignorable_clone_logging_node(node: Node<'_>, source: &str) -> bool {
    match node.kind() {
        "expression_statement" | "echo_statement" => {
            let text = source
                .get(node.start_byte()..node.end_byte())
                .unwrap_or("")
                .trim();
            text.starts_with("error_log(")
                || text.starts_with("print(")
                || text.starts_with("echo ")
        }
        _ => false,
    }
}

pub(super) fn build_php_clone_candidate_data(
    analyzer: &PhpAnalyzer,
    code_unit: &CodeUnit,
    weights: CloneSmellWeights,
) -> Option<CloneCandidateData> {
    analyzer
        .get_source(code_unit, false)
        .map(|source| source.trim().to_string())
        .filter(|source| !source.is_empty())
        .and_then(|source| {
            let normalized_tokens = normalized_clone_tokens_php(&source);
            if normalized_tokens.len() < weights.min_normalized_tokens.max(0) as usize {
                return None;
            }
            Some(CloneCandidateData {
                unit: code_unit.clone(),
                normalized_tokens,
                ast_signature: build_php_clone_ast_signature(&source),
                excerpt: compact_clone_excerpt(&source),
            })
        })
}
