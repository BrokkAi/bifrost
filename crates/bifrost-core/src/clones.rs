//! Shared syntax-aware normalization for structural clone candidates.

use crate::analyzer::common::node_source_text_trimmed;
use crate::analyzer::tree_walk::{WalkControl, walk_tree_preorder};
use tree_sitter::{Node, Tree};

/// Language-specific syntax kinds and literal spellings for clone normalization.
///
/// Keep language behavior in these slices so the normalization algorithm stays
/// shared without encoding language modes in the helper API.
#[derive(Debug, Clone, Copy)]
pub struct CloneNormalizationRules {
    pub identifier_kinds: &'static [&'static str],
    pub string_kinds: &'static [&'static str],
    pub number_kinds: &'static [&'static str],
    pub boolean_kinds: &'static [&'static str],
    pub boolean_values: &'static [&'static str],
    pub null_kinds: &'static [&'static str],
    pub null_values: &'static [&'static str],
    pub comment_kinds: &'static [&'static str],
    pub ignored_ast_kinds: &'static [&'static str],
}

/// Build a clone AST signature from a parsed tree and language-specific rules.
/// A failed parse has the same empty signature for every language.
pub fn clone_ast_signature(
    tree: Option<Tree>,
    source: &str,
    rules: CloneNormalizationRules,
) -> String {
    let Some(tree) = tree else {
        return String::new();
    };
    clone_ast_signature_from_root(tree.root_node(), source, rules)
}

/// Build a clone AST signature from an already-parsed root node.
pub fn clone_ast_signature_from_root(
    root: Node<'_>,
    source: &str,
    rules: CloneNormalizationRules,
) -> String {
    clone_ast_signature_with_skip_from_root(root, source, rules, |_, _| false)
}

/// Build a clone AST signature while allowing language-specific subtrees to be
/// omitted from the signature.
pub fn clone_ast_signature_with_skip(
    tree: Option<Tree>,
    source: &str,
    rules: CloneNormalizationRules,
    skip_subtree: impl FnMut(Node<'_>, &str) -> bool,
) -> String {
    let Some(tree) = tree else {
        return String::new();
    };
    clone_ast_signature_with_skip_from_root(tree.root_node(), source, rules, skip_subtree)
}

/// Build a clone AST signature from an already-parsed root node, omitting
/// language-specific subtrees selected by `skip_subtree`.
pub fn clone_ast_signature_with_skip_from_root(
    root: Node<'_>,
    source: &str,
    rules: CloneNormalizationRules,
    mut skip_subtree: impl FnMut(Node<'_>, &str) -> bool,
) -> String {
    let mut labels = Vec::new();
    walk_tree_preorder(root, true, |node| {
        if skip_subtree(node, source) {
            return WalkControl::SkipChildren;
        }
        labels.push(normalize_clone_ast_label(node, source, rules));
        WalkControl::Continue
    });
    labels.join("|")
}

/// Build normalized clone tokens from leaf nodes in a parsed tree.
/// A failed parse has no tokens for every language.
pub fn normalized_clone_tokens(
    tree: Option<Tree>,
    source: &str,
    rules: CloneNormalizationRules,
) -> Vec<String> {
    let Some(tree) = tree else {
        return Vec::new();
    };
    normalized_clone_tokens_from_root(tree.root_node(), source, rules)
}

/// Build normalized clone tokens from an already-parsed root node.
pub fn normalized_clone_tokens_from_root(
    root: Node<'_>,
    source: &str,
    rules: CloneNormalizationRules,
) -> Vec<String> {
    let mut tokens = Vec::new();
    walk_tree_preorder(root, true, |node| {
        if node.named_child_count() == 0 {
            let token = normalize_clone_leaf_token(node, source, rules);
            if !token.is_empty() {
                tokens.push(token);
            }
        }
        WalkControl::Continue
    });
    tokens
}

/// Normalize one syntax-tree leaf into a clone token using `rules`.
pub fn normalize_clone_leaf_token(
    node: Node<'_>,
    source: &str,
    rules: CloneNormalizationRules,
) -> String {
    let kind = node.kind();
    let text = node_source_text_trimmed(node, source);
    if text.is_empty() || rules.comment_kinds.contains(&kind) {
        return String::new();
    }
    if rules.identifier_kinds.contains(&kind) {
        return "ID".to_string();
    }
    if rules.string_kinds.contains(&kind) {
        return "STR".to_string();
    }
    if rules.number_kinds.contains(&kind) {
        return "NUM".to_string();
    }
    if rules.boolean_kinds.contains(&kind) || rules.boolean_values.contains(&text) {
        return "BOOL".to_string();
    }
    if rules.null_kinds.contains(&kind) || rules.null_values.contains(&text) {
        return "NULL".to_string();
    }
    if text.chars().count() == 1 && text.chars().all(|ch| !ch.is_alphanumeric()) {
        return format!("OP:{text}");
    }
    format!("T:{kind}")
}

/// Normalize one syntax-tree node into a clone AST label using `rules`.
pub fn normalize_clone_ast_label(
    node: Node<'_>,
    source: &str,
    rules: CloneNormalizationRules,
) -> String {
    let kind = node.kind();
    let text = node_source_text_trimmed(node, source);
    if rules.identifier_kinds.contains(&kind) {
        return "ID".to_string();
    }
    if rules.string_kinds.contains(&kind) {
        return "STR".to_string();
    }
    if rules.number_kinds.contains(&kind) {
        return "NUM".to_string();
    }
    if rules.boolean_kinds.contains(&kind) || rules.boolean_values.contains(&text) {
        return "BOOL".to_string();
    }
    if rules.null_kinds.contains(&kind) || rules.null_values.contains(&text) {
        return "NULL".to_string();
    }
    if rules.ignored_ast_kinds.contains(&kind) {
        return "IGN".to_string();
    }
    format!("N:{kind}")
}
