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
//! them.

use tree_sitter::Node;

/// What [`walk_tree_iterative`] should do after visiting a node on entry.
pub(crate) enum TreeWalkAction {
    /// Descend into the node's named children; do not call `exit` for this node.
    Descend,
    /// Descend into the node's named children, then call `exit` once all
    /// descendants have been visited.
    DescendWithExit,
    /// Do not descend into this node's children.
    Skip,
    /// Stop the entire traversal immediately without firing pending exits.
    Stop,
}

enum TreeWalkFrame<'tree> {
    Enter(Node<'tree>),
    Exit,
}

/// Iterative (stack-based) enter/exit tree-sitter walk over `root`'s named
/// descendants (root included). `enter` is called on the way down and decides
/// whether to descend and whether an `exit` callback should fire on the way back
/// up (`DescendWithExit`) once all of that node's descendants have been visited.
///
/// Children are visited in source order; `exit` calls nest correctly with
/// `enter`/`exit` pairs from descendants firing before their ancestor's `exit`.
pub(crate) fn walk_tree_iterative<State>(
    root: Node<'_>,
    state: &mut State,
    mut enter: impl FnMut(Node<'_>, &mut State) -> TreeWalkAction,
    mut exit: impl FnMut(&mut State),
) {
    let mut stack = vec![TreeWalkFrame::Enter(root)];
    while let Some(frame) = stack.pop() {
        match frame {
            TreeWalkFrame::Enter(node) => match enter(node, state) {
                TreeWalkAction::Descend => push_named_children(node, &mut stack),
                TreeWalkAction::DescendWithExit => {
                    stack.push(TreeWalkFrame::Exit);
                    push_named_children(node, &mut stack);
                }
                TreeWalkAction::Skip => {}
                TreeWalkAction::Stop => break,
            },
            TreeWalkFrame::Exit => exit(state),
        }
    }
}

fn push_named_children<'tree>(node: Node<'tree>, stack: &mut Vec<TreeWalkFrame<'tree>>) {
    for index in (0..node.named_child_count()).rev() {
        if let Some(child) = node.named_child(index) {
            stack.push(TreeWalkFrame::Enter(child));
        }
    }
}

pub(crate) use brokk_bifrost_core::analyzer::tree_walk::subtree_contains;

/// All descendants of `node` (not including `node` itself) whose `kind()` equals
/// `kind`, in pre-order (a node before its own descendants), iterative (explicit
/// stack) depth-first search.
///
/// Its only current callers are test-only traversal helpers (this module's own
/// unit tests, and `ruby::semantic`'s test-only `descendants_by_kind`). The one
/// production candidate identified by the cross-language duplication survey
/// (`rust::graph_support::named_descendants_of_kind`) performs a *post*-order
/// walk that also matches the root node, which is an observably different
/// contract, so it was deliberately left as its own copy rather than forced
/// through this preorder/exclude-self helper.
#[allow(dead_code)]
pub(crate) fn descendants_of_kind<'tree>(node: Node<'tree>, kind: &str) -> Vec<Node<'tree>> {
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

/// The direct named children of `node`, in source order.
pub(crate) fn named_children<'tree>(node: Node<'tree>) -> Vec<Node<'tree>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

/// The first direct named child of `node` whose kind is `kind`.
///
/// Distinct from a bare "first named child": this selects by kind, which is how
/// declaration walks reach a specific grammar slot (a `class_body`, a
/// `type_identifier`) without assuming child order.
pub(crate) fn first_named_child_of_kind<'tree>(
    node: Node<'tree>,
    kind: &str,
) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == kind)
}

/// Whether `node` has an anonymous (token) child spelled `token`.
///
/// Restricted to anonymous children on purpose: grammars can spell the same
/// text as either a keyword token or a named node, and callers asking this
/// question want the keyword.
pub(crate) fn has_token_child(node: Node<'_>, token: &str) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .any(|child| !child.is_named() && child.kind() == token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    fn parse(source: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set rust language");
        parser.parse(source, None).expect("parse")
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
    fn walk_tree_iterative_skip_prunes_descendants() {
        let tree = parse("fn outer() { let x = 1; }");
        let root = tree.root_node();
        let mut visited: Vec<String> = Vec::new();
        walk_tree_iterative(
            root,
            &mut visited,
            |node, visited| {
                visited.push(node.kind().to_string());
                if node.kind() == "block" {
                    // Prune: the block's children (the let-statement and its
                    // descendants) must never be visited.
                    return TreeWalkAction::Skip;
                }
                TreeWalkAction::Descend
            },
            |_| {},
        );
        assert!(visited.iter().any(|k| k == "block"));
        assert!(!visited.iter().any(|k| k == "let_declaration"));
    }

    #[test]
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

    #[test]
    fn subtree_contains_finds_nested_match() {
        let tree = parse("fn outer() { fn inner() {} }");
        let root = tree.root_node();
        assert!(subtree_contains(root, |node| node.kind() == "function_item"));
        assert!(!subtree_contains(root, |node| node.kind() == "struct_item"));
    }

    #[test]
    fn descendants_of_kind_collects_all_matches_excluding_self() {
        let tree = parse("fn outer() { fn inner() { fn innermost() {} } }");
        let root = tree.root_node();
        let functions = descendants_of_kind(root, "function_item");
        assert_eq!(functions.len(), 3);

        // Querying from a function_item root excludes that node itself.
        let outer = functions[0];
        let nested = descendants_of_kind(outer, "function_item");
        assert_eq!(nested.len(), 2);
    }

    #[test]
    fn named_children_returns_direct_children_in_source_order() {
        let tree = parse("fn outer() {}");
        let root = tree.root_node();
        let children = named_children(root);
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].kind(), "function_item");
    }
}
