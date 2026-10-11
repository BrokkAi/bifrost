use brokk_bifrost_core::analyzer::tree_walk::{WalkControl, walk_named_tree_preorder};
use tree_sitter::Node;

pub(crate) fn contains_test_node<'tree>(
    root: Node<'tree>,
    mut is_test_node: impl FnMut(Node<'tree>) -> bool,
) -> bool {
    let mut found = false;
    walk_named_tree_preorder(root, true, |node| {
        found |= is_test_node(node);
        if found {
            WalkControl::SkipChildren
        } else {
            WalkControl::Continue
        }
    });
    found
}
