use brokk_bifrost_core::analyzer::tree_walk::named_children;
use tree_sitter::Node;

pub(crate) fn compilation_unit(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        if node.kind() == "compilation_unit" {
            return Some(node);
        }
        node = node.parent()?;
    }
}

/// Classify only declarations that introduce a Scala template.
pub(crate) fn template_kind(kind: &str) -> Option<&'static str> {
    match kind {
        "class_definition" => Some("class_definition"),
        "object_definition" => Some("object_definition"),
        "trait_definition" => Some("trait_definition"),
        "enum_definition" => Some("enum_definition"),
        _ => None,
    }
}

/// Find the nearest template strictly above the supplied node.
pub(crate) fn enclosing_template(node: Node<'_>) -> Option<Node<'_>> {
    brokk_bifrost_core::analyzer::structural::adapter_helpers::nearest_ancestor(node, |kind| {
        template_kind(kind).is_some()
    })
}

/// Search root and named descendants in the callers' bounded stack order.
pub(crate) fn subtree_has_kind(node: Node<'_>, kind: &str, budget: usize) -> bool {
    let mut stack = vec![node];
    let mut examined = 0_usize;
    while let Some(current) = stack.pop() {
        examined += 1;
        if examined > budget {
            return false;
        }
        if current.kind() == kind {
            return true;
        }
        stack.extend(named_children(current));
    }
    false
}
