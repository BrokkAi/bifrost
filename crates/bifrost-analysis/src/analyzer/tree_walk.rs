//! Shared stack-based (non-recursive) tree-sitter traversal helpers.
//!
//! These exist because recursive AST walks are disallowed for analyzer code that may
//! touch deeply nested trees (see CLAUDE.md's stack-safety rule) — every helper here
//! is an explicit-stack replacement for what would otherwise be a recursive walk.
//! Consolidated from ~25 independent per-language/per-module copies (cross-language
//! duplication survey, Concern 5, Tier 1): visibility (`pub(super)`) was the only
//! reason most of them existed as separate copies rather than calling a shared
//! helper.
//!
//! The preorder family -- `WalkControl`, `walk_tree_preorder`,
//! `walk_named_tree_preorder` and its fallible counterpart -- plus
//! `collect_parse_errors` and `expanded_comment_start` live in
//! [`brokk_bifrost_core::analyzer::tree_walk`] and are re-exported by
//! [`crate::analyzer::tree_sitter_analyzer`], where their callers already reach
//! them. The enter/exit iterative walker joined them there when the Ruby scans
//! moved into `brokk-bifrost-ruby`; java and js_ts reach it at this path. The
//! three direct-child readers -- `named_children`, `first_named_child_of_kind`
//! and `has_token_child` -- followed when Kotlin's declaration walk moved into
//! `brokk-bifrost-jvm`, since a language crate reads its own grammar's child
//! slots with them; the first two are re-exported here for the callers already
//! at this path, and `has_token_child` has no analysis-side caller left. The
//! kind-filtered collector and predicate-based sole-child selector also live
//! in core and are re-exported here for analysis callers.

use tree_sitter::Node;

/// Find the first identifier with exact source text in preorder, including `root`.
#[doc(hidden)]
pub fn find_identifier_node<'tree>(
    root: Node<'tree>,
    source: &str,
    expected: &str,
) -> Option<Node<'tree>> {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "identifier"
            && brokk_bifrost_core::analyzer::common::try_node_source_text(node, source)
                == Some(expected)
        {
            return Some(node);
        }
        stack.extend(
            brokk_bifrost_core::analyzer::tree_walk::named_children_vec(node)
                .into_iter()
                .rev(),
        );
    }
    None
}

#[doc(hidden)]
pub fn body_contains_kind_outside_nested_callables(
    body: Node<'_>,
    target_kind: &str,
    is_callable_kind: fn(&str) -> bool,
) -> bool {
    body_contains_kind_with_children(body, target_kind, |node| {
        brokk_bifrost_core::analyzer::tree_walk::named_children_vec(node)
            .into_iter()
            .filter(move |child| !is_callable_kind(child.kind()))
    })
}

/// Search the body, including its root, through caller-selected scope children.
#[doc(hidden)]
pub fn body_contains_kind_with_children<'tree, Children>(
    body: Node<'tree>,
    target_kind: &str,
    mut children: impl FnMut(Node<'tree>) -> Children,
) -> bool
where
    Children: IntoIterator<Item = Node<'tree>>,
{
    let mut stack = vec![body];
    while let Some(node) = stack.pop() {
        if node.kind() == target_kind {
            return true;
        }
        stack.extend(children(node));
    }
    false
}

#[cfg(test)]
pub(crate) use brokk_bifrost_core::analyzer::tree_walk::{TreeWalkAction, walk_tree_iterative};
pub(crate) use brokk_bifrost_core::analyzer::tree_walk::{
    child_by_field_or_named_child_of_kinds, children_iter, first_named_child_of_kind,
    named_children, named_children_iter, node_for_exact_range, push_children_reversed,
    push_named_children_reversed, single_named_child_matching, subtree_contains,
};

#[doc(hidden)]
pub fn call_arguments(node: Node<'_>) -> Vec<Node<'_>> {
    child_by_field_or_named_child_of_kinds(node, "arguments", &["argument_list"])
        .map(named_children)
        .unwrap_or_default()
}

/// All named descendants of `node` (excluding `node`) whose kind matches,
/// in source-order preorder, using an explicit stack.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn descendants_of_kind<'tree>(node: Node<'tree>, kind: &str) -> Vec<Node<'tree>> {
    let mut out = Vec::new();
    let mut stack: Vec<Node<'tree>> = named_children(node).into_iter().rev().collect();
    while let Some(candidate) = stack.pop() {
        if candidate.kind() == kind {
            out.push(candidate);
        }
        for child in named_children(candidate).into_iter().rev() {
            stack.push(child);
        }
    }
    out
}

/// All named nodes in source-order preorder, including `node` when it matches.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn descendants_or_self_of_kind<'tree>(node: Node<'tree>, kind: &str) -> Vec<Node<'tree>> {
    let mut out = Vec::new();
    if node.kind() == kind {
        out.push(node);
    }
    out.extend(descendants_of_kind(node, kind));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    fn parse(source: &str) -> tree_sitter::Tree {
        brokk_bifrost_rust::lexical_scope::parse_rust_tree(source).expect("parse Rust")
    }

    #[test]
    fn walk_tree_iterative_visits_enter_and_exit_in_nested_order() {
        let tree = parse("fn outer() { fn inner() { let x = 1; } }");
        let root = tree.root_node();
        let mut order: Vec<String> = Vec::new();
        walk_tree_iterative(
            root,
            &mut order,
            |node, order| {
                order.push(format!("enter:{}", node.kind()));
                TreeWalkAction::DescendWithExit
            },
            |order| {
                order.push("exit".to_string());
            },
        );
        // Every enter has a matching exit, and exits are LIFO (nested) relative to
        // their enter.
        assert_eq!(
            order.iter().filter(|entry| **entry == "exit").count(),
            order
                .iter()
                .filter(|entry| entry.starts_with("enter:"))
                .count()
        );
        assert_eq!(order.first().map(String::as_str), Some("enter:source_file"));
        assert_eq!(order.last().map(String::as_str), Some("exit"));
    }

    #[test]
    #[hardwon("#1228: cooperative stop must prevent visiting later siblings")]
    fn issue_1228_walk_tree_iterative_can_stop_cooperatively() {
        let source = "fn first() {} fn stop() {} fn never() {}";
        let tree = parse(source);
        let root = tree.root_node();
        let mut visited: Vec<String> = Vec::new();
        walk_tree_iterative(
            root,
            &mut visited,
            |node, visited| {
                let text = node.utf8_text(source.as_bytes()).unwrap_or_default();
                visited.push(text.to_string());
                if text.starts_with("fn stop") {
                    TreeWalkAction::Stop
                } else {
                    TreeWalkAction::Descend
                }
            },
            |_| {},
        );
        assert!(visited.iter().any(|text| text.starts_with("fn stop")));
        assert!(!visited.iter().any(|text| text.starts_with("fn never")));
    }
}
