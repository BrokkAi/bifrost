//! PHP's structural-clone normalization: the token stream and AST-label
//! signature a clone candidate is compared by.
//!
//! `CloneCandidateData` and `compact_clone_excerpt` are analysis-owned and the
//! declaration source comes from the analyzer, so the ~20-line entry point stays
//! in `analyzer/php/clones.rs`. Everything that knows PHP is here.

use crate::aliases::parse_php_tree;
use brokk_bifrost_core::analyzer::tree_walk::{WalkControl, walk_tree_preorder};
use brokk_bifrost_core::clones::{
    CloneNormalizationRules, clone_ast_signature_with_skip,
    normalize_clone_leaf_token as normalize_php_clone_leaf_token,
};
use tree_sitter::Node;

const PHP_CLONE_AST_IDENTIFIER_TYPES: &[&str] = &["name", "variable_name"];
const PHP_CLONE_AST_STRING_TYPES: &[&str] = &["string", "encapsed_string", "string_value"];
const PHP_CLONE_AST_NUMBER_TYPES: &[&str] = &["integer", "float"];
const PHP_CLONE_NORMALIZATION_RULES: CloneNormalizationRules = CloneNormalizationRules {
    identifier_kinds: PHP_CLONE_AST_IDENTIFIER_TYPES,
    string_kinds: PHP_CLONE_AST_STRING_TYPES,
    number_kinds: PHP_CLONE_AST_NUMBER_TYPES,
    boolean_kinds: &["boolean", "boolean_literal"],
    boolean_values: &["true", "false"],
    null_kinds: &["null", "null_literal"],
    null_values: &["null"],
    comment_kinds: &["comment"],
    ignored_ast_kinds: &[],
};

pub fn normalized_clone_tokens_php(source: &str) -> Vec<String> {
    let parse_source = php_clone_parse_source(source);
    let Some(tree) = parse_php_tree(&parse_source) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    collect_normalized_leaf_tokens_php(tree.root_node(), &parse_source, &mut out);
    out
}

fn collect_normalized_leaf_tokens_php(node: Node<'_>, source: &str, out: &mut Vec<String>) {
    walk_tree_preorder(node, true, |node| {
        if php_is_ignorable_clone_logging_node(node, source) {
            return WalkControl::SkipChildren;
        }

        if node.named_child_count() == 0 {
            let token = normalize_php_clone_leaf_token(node, source, PHP_CLONE_NORMALIZATION_RULES);
            if !token.is_empty() {
                out.push(token);
            }
        }
        WalkControl::Continue
    });
}

pub fn build_php_clone_ast_signature(source: &str) -> String {
    let parse_source = php_clone_parse_source(source);
    clone_ast_signature_with_skip(
        parse_php_tree(&parse_source),
        &parse_source,
        PHP_CLONE_NORMALIZATION_RULES,
        php_is_ignorable_clone_logging_node,
    )
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
