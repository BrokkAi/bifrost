use crate::CloneSmellWeights;
use crate::analyzer::clone_detection::{CloneCandidateData, compact_clone_excerpt};
use crate::analyzer::{CodeUnit, CodeUnitIndex};
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

/// One clone-candidate profile for a JS or TS declaration. The dialect enters
/// only as the grammar the normalizers parse with, so both analyzers call this.
pub(crate) fn build_js_ts_clone_candidate_data(
    index: &dyn CodeUnitIndex,
    code_unit: &CodeUnit,
    weights: CloneSmellWeights,
    parser_language: TsLanguage,
) -> Option<CloneCandidateData> {
    index
        .get_source(code_unit, false)
        .map(|source| source.trim().to_string())
        .filter(|source| !source.is_empty())
        .and_then(|source| {
            let normalized_tokens = normalized_clone_tokens_js_ts(&source, parser_language.clone());
            if normalized_tokens.len() < weights.min_normalized_tokens.max(0) as usize {
                return None;
            }
            Some(CloneCandidateData {
                unit: code_unit.clone(),
                normalized_tokens,
                ast_signature: build_js_ts_clone_ast_signature(&source, parser_language),
                excerpt: compact_clone_excerpt(&source),
            })
        })
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

fn parse_js_ts_tree(source: &str, parser_language: TsLanguage) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&parser_language)
        .expect("failed to set js/ts parser language");
    parser.parse(source, None)
}
