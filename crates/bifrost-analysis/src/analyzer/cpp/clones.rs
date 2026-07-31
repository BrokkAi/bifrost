use super::*;
use crate::analyzer::clone_detection::{CloneCandidateData, compact_clone_excerpt};
use tree_sitter::{Node, Parser};

pub(super) fn build_clone_candidate_data(
    analyzer: &CppAnalyzer,
    code_unit: &CodeUnit,
    weights: CloneSmellWeights,
    parser: &mut Parser,
) -> Option<CloneCandidateData> {
    analyzer
        .get_source(code_unit, false)
        .map(|source| source.trim().to_string())
        .filter(|source| !source.is_empty())
        .and_then(|source| {
            let (normalized_tokens, ast_signature) = cpp_clone_profile(parser, &source);
            if normalized_tokens.len() < weights.min_normalized_tokens.max(0) as usize {
                return None;
            }
            Some(CloneCandidateData {
                unit: code_unit.clone(),
                normalized_tokens,
                ast_signature,
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

pub(super) fn cpp_clone_parser() -> Parser {
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

fn cpp_clone_profile(parser: &mut Parser, source: &str) -> (Vec<String>, String) {
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
