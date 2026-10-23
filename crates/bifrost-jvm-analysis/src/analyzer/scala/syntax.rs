use tree_sitter::Node;

pub(crate) fn compilation_unit(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        if node.kind() == "compilation_unit" {
            return Some(node);
        }
        node = node.parent()?;
    }
}
