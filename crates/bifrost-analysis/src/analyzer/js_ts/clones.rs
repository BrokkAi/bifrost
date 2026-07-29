use crate::analyzer::CloneSmellWeights;
use crate::analyzer::clone_detection::{
    CloneCandidateData, compute_ast_refinement_similarity_percent,
};
use tree_sitter::{Language as TsLanguage, Node, Parser, Tree};

const JS_TS_IDENTIFIER_TYPES: &[&str] = &["identifier", "property_identifier"];
const JS_TS_STRING_TYPES: &[&str] = &["string", "template_string"];
const JS_TS_NUMBER_TYPES: &[&str] = &["number"];
const JS_TS_CLONE_AST_IGNORED_TYPES: &[&str] =
    &["accessibility_modifier", "modifiers", "type_parameters"];

pub(crate) fn normalized_clone_tokens_js_ts(
    source: &str,
    parser_language: TsLanguage,
) -> Vec<String> {
    let Some(tree) = parse_js_ts_tree(source, parser_language) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    collect_normalized_leaf_tokens_js_ts(tree.root_node(), source, &mut out);
    out
}

fn collect_normalized_leaf_tokens_js_ts(node: Node<'_>, source: &str, out: &mut Vec<String>) {
    if node.named_child_count() == 0 {
        let token = normalize_js_ts_clone_leaf_token(node, source);
        if !token.is_empty() {
            out.push(token);
        }
    }
    let child_count = node.child_count();
    for index in 0..child_count {
        if let Some(child) = node.child(index) {
            collect_normalized_leaf_tokens_js_ts(child, source, out);
        }
    }
}

fn normalize_js_ts_clone_leaf_token(node: Node<'_>, source: &str) -> String {
    let kind = node.kind();
    let token = source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or("")
        .trim();
    if token.is_empty() || kind == "comment" {
        return String::new();
    }
    if JS_TS_IDENTIFIER_TYPES.contains(&kind) {
        return "ID".to_string();
    }
    if JS_TS_STRING_TYPES.contains(&kind) {
        return "STR".to_string();
    }
    if JS_TS_NUMBER_TYPES.contains(&kind) {
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

pub(crate) fn build_js_ts_clone_ast_signature(source: &str, parser_language: TsLanguage) -> String {
    let Some(tree) = parse_js_ts_tree(source, parser_language) else {
        return String::new();
    };
    let mut labels = Vec::new();
    collect_js_ts_clone_ast_labels(tree.root_node(), source, &mut labels);
    labels.join("|")
}

fn collect_js_ts_clone_ast_labels(node: Node<'_>, source: &str, out: &mut Vec<String>) {
    out.push(normalize_js_ts_clone_ast_label(node, source));
    let child_count = node.child_count();
    for index in 0..child_count {
        if let Some(child) = node.child(index) {
            collect_js_ts_clone_ast_labels(child, source, out);
        }
    }
}

fn normalize_js_ts_clone_ast_label(node: Node<'_>, source: &str) -> String {
    let kind = node.kind();
    let text = source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or("")
        .trim();
    if JS_TS_IDENTIFIER_TYPES.contains(&kind) {
        return "ID".to_string();
    }
    if JS_TS_STRING_TYPES.contains(&kind) {
        return "STR".to_string();
    }
    if JS_TS_NUMBER_TYPES.contains(&kind) {
        return "NUM".to_string();
    }
    if text == "true" || text == "false" {
        return "BOOL".to_string();
    }
    if JS_TS_CLONE_AST_IGNORED_TYPES.contains(&kind) {
        return "IGN".to_string();
    }
    format!("N:{kind}")
}

pub(crate) fn refine_js_ts_clone_similarity(
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

fn parse_js_ts_tree(source: &str, parser_language: TsLanguage) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&parser_language)
        .expect("failed to set js/ts parser language");
    parser.parse(source, None)
}
