//! Token and AST-label normalization for C++ structural-clone candidates.
//!
//! `CloneCandidateData` and `compact_clone_excerpt` are analysis-owned and the
//! declaration source comes from the analyzer, so `analyzer/cpp/clones.rs` keeps
//! the ~12-LOC entry point; everything that knows C++ is here.

use brokk_bifrost_core::analyzer::tree_walk::push_children_reversed;
use brokk_bifrost_core::clones::{
    CloneNormalizationRules, normalize_clone_ast_label as normalize_cpp_clone_ast_label,
    normalize_clone_leaf_token as normalize_cpp_clone_leaf_token,
};
use tree_sitter::{Node, Parser};

const CPP_CLONE_AST_IDENTIFIER_TYPES: &[&str] = &[
    "identifier",
    "field_identifier",
    "namespace_identifier",
    "type_identifier",
];
const CPP_CLONE_AST_STRING_TYPES: &[&str] = &["string_literal", "raw_string_literal"];
const CPP_CLONE_AST_NUMBER_TYPES: &[&str] = &["number_literal"];
const CPP_CLONE_NORMALIZATION_RULES: CloneNormalizationRules = CloneNormalizationRules {
    identifier_kinds: CPP_CLONE_AST_IDENTIFIER_TYPES,
    string_kinds: CPP_CLONE_AST_STRING_TYPES,
    number_kinds: CPP_CLONE_AST_NUMBER_TYPES,
    boolean_kinds: &[],
    boolean_values: &["true", "false"],
    null_kinds: &[],
    null_values: &[],
    comment_kinds: &["comment"],
    ignored_ast_kinds: &[],
};

pub fn cpp_clone_parser() -> Parser {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .expect("failed to load cpp parser");
    parser
}

/// The normalized token stream and the joined AST-label signature for one C++
/// declaration body, in a single walk.
pub fn cpp_clone_profile(parser: &mut Parser, source: &str) -> (Vec<String>, String) {
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
        ast_labels.push(normalize_cpp_clone_ast_label(
            node,
            source,
            CPP_CLONE_NORMALIZATION_RULES,
        ));
        if node.named_child_count() == 0 {
            let token = normalize_cpp_clone_leaf_token(node, source, CPP_CLONE_NORMALIZATION_RULES);
            if !token.is_empty() {
                normalized_tokens.push(token);
            }
        }
        push_children_reversed(node, &mut stack);
    }
    (normalized_tokens, ast_labels.join("|"))
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
