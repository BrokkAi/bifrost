use crate::graph::resolver::ReceiverMode;
use tree_sitter::Node;

pub fn is_declaration_constant(node: Node<'_>) -> bool {
    if let Some(parent) = node.parent()
        && matches!(parent.kind(), "class" | "module")
        && parent.child_by_field_name("name") == Some(node)
    {
        return true;
    }
    if is_assignment_left_constant(node) {
        return true;
    }
    false
}

fn is_assignment_left_constant(node: Node<'_>) -> bool {
    let mut topmost = node;
    while let Some(parent) = topmost.parent() {
        if parent.kind() == "assignment" {
            if parent.child_by_field_name("left") != Some(topmost) {
                return false;
            }
            return node == topmost
                || topmost
                    .child_by_field_name("name")
                    .is_some_and(|name| name == node);
        }
        if parent.kind() != "scope_resolution" {
            return false;
        }
        topmost = parent;
    }
    false
}

pub fn method_receiver_mode(
    node: Node<'_>,
    enclosing_receiver_mode: Option<ReceiverMode>,
) -> ReceiverMode {
    if node.kind() == "singleton_method" {
        return ReceiverMode::Class;
    }
    enclosing_receiver_mode.unwrap_or(ReceiverMode::TopLevel)
}

pub fn is_declaration_identifier(node: Node<'_>) -> bool {
    if let Some(parent) = node.parent()
        && matches!(parent.kind(), "method" | "singleton_method" | "assignment")
        && parent.child_by_field_name("name") == Some(node)
    {
        return true;
    }
    if let Some(parent) = node.parent()
        && parent.kind() == "assignment"
        && parent.child_by_field_name("left") == Some(node)
    {
        return true;
    }
    false
}

pub fn is_plain_assignment_left_variable(node: Node<'_>) -> bool {
    if !matches!(node.kind(), "instance_variable" | "class_variable") {
        return false;
    }
    node.parent().is_some_and(|parent| {
        matches!(parent.kind(), "assignment" | "operator_assignment")
            && parent.child_by_field_name("left") == Some(node)
    })
}

pub fn is_call_method_identifier(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "call" && parent.child_by_field_name("method") == Some(node)
    })
}

pub fn is_bare_method_reference_identifier(node: Node<'_>) -> bool {
    node.kind() == "identifier"
        && !is_declaration_identifier(node)
        && !is_call_method_identifier(node)
}

pub fn ruby_call_is_same_owner(node: Node<'_>) -> bool {
    node.child_by_field_name("receiver")
        .is_none_or(|receiver| receiver.kind() == "self")
}

pub fn for_each_ruby_superclass_constant<'tree>(
    node: Node<'tree>,
    mut visit: impl FnMut(Node<'tree>),
) {
    let Some(superclass) = node.child_by_field_name("superclass") else {
        return;
    };
    let mut stack = vec![superclass];
    while let Some(current) = stack.pop() {
        visit(current);
        for index in (0..current.named_child_count()).rev() {
            if let Some(child) = current.named_child(index) {
                stack.push(child);
            }
        }
    }
}

pub fn dynamic_dispatch_target_argument<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<(String, Node<'tree>)> {
    let method = node.child_by_field_name("method")?;
    if !is_dynamic_dispatch_method(method, source) {
        return None;
    }
    let first_argument = crate::syntax::ruby_first_call_argument(node)?;
    symbol_or_string_value(first_argument, source).map(|member| (member, first_argument))
}

pub fn is_dynamic_dispatch_method(method: Node<'_>, source: &str) -> bool {
    matches!(
        node_text(method, source),
        "send" | "__send__" | "public_send"
    )
}

pub fn constant_hit_node(node: Node<'_>) -> Node<'_> {
    if node.kind() == "scope_resolution" {
        node.child_by_field_name("name").unwrap_or(node)
    } else {
        node
    }
}

pub fn symbol_or_string_value(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "simple_symbol" => node_text(node, source).strip_prefix(':').map(str::to_owned),
        "string" | "delimited_symbol" => crate::structural::ruby_string_literal_value(node, source),
        _ => None,
    }
}

pub use brokk_bifrost_core::analyzer::common::node_source_text_trimmed as node_text;

#[cfg(test)]
mod tests {
    use super::*;

    // Ripper distinguishes const_path_field from const_path_ref, def/defs
    // names from vcalls, and var_field from var_ref. This table pins the
    // corresponding released tree-sitter fields at those boundaries.
    #[test]
    fn declaration_and_reference_grammar() {
        let source = "module Owner; end\nOwner::VALUE = 1\nOwner::VALUE\nOther = Owner::VALUE\ndef run; end\ndef self.run; end\n@value = 0\n@@count = 0\n@value\n@@count\nrun\n";
        let tree = crate::declarations::parse_ruby_tree(source).unwrap();
        assert!(!tree.root_node().has_error());
        let mut constants = Vec::new();
        let mut methods = Vec::new();
        let mut variables = Vec::new();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            match node.kind() {
                "constant" => {
                    constants.push((node_text(node, source), is_declaration_constant(node)))
                }
                "identifier" if node_text(node, source) == "run" => {
                    methods.push(is_declaration_identifier(node))
                }
                "instance_variable" | "class_variable" => {
                    variables.push(is_plain_assignment_left_variable(node))
                }
                _ => {}
            }
            for index in (0..node.named_child_count()).rev() {
                stack.push(node.named_child(index).unwrap());
            }
        }
        assert_eq!(
            constants,
            [
                ("Owner", true),
                ("Owner", false),
                ("VALUE", true),
                ("Owner", false),
                ("VALUE", false),
                ("Other", true),
                ("Owner", false),
                ("VALUE", false)
            ]
        );
        assert_eq!(methods, [true, true, false]);
        assert_eq!(variables, [true, true, false, false]);
    }
}
