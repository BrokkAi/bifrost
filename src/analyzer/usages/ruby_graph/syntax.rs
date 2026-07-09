use tree_sitter::Node;

use super::resolver::ReceiverMode;

pub(crate) fn is_declaration_constant(node: Node<'_>) -> bool {
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

pub(crate) fn method_receiver_mode(node: Node<'_>) -> ReceiverMode {
    if node.kind() == "singleton_method" {
        return ReceiverMode::Class;
    }
    let mut parent = node.parent();
    while let Some(current) = parent {
        if current.kind() == "singleton_class" {
            return ReceiverMode::Class;
        }
        if matches!(current.kind(), "class" | "module") {
            break;
        }
        parent = current.parent();
    }
    if has_enclosing_type(node) {
        ReceiverMode::Instance
    } else {
        ReceiverMode::TopLevel
    }
}

fn has_enclosing_type(node: Node<'_>) -> bool {
    let mut parent = node.parent();
    while let Some(current) = parent {
        if matches!(current.kind(), "class" | "module") {
            return true;
        }
        parent = current.parent();
    }
    false
}

pub(crate) fn is_declaration_identifier(node: Node<'_>) -> bool {
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

pub(crate) fn is_plain_assignment_left_variable(node: Node<'_>) -> bool {
    if !matches!(node.kind(), "instance_variable" | "class_variable") {
        return false;
    }
    node.parent().is_some_and(|parent| {
        matches!(parent.kind(), "assignment" | "operator_assignment")
            && parent.child_by_field_name("left") == Some(node)
    })
}

pub(crate) fn is_call_method_identifier(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "call" && parent.child_by_field_name("method") == Some(node)
    })
}

pub(crate) fn dynamic_dispatch_target_argument<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<(String, Node<'tree>)> {
    let method = node.child_by_field_name("method")?;
    if !is_dynamic_dispatch_method(method, source) {
        return None;
    }
    let arguments = node.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    let first_argument = arguments.named_children(&mut cursor).next()?;
    symbol_or_string_value(first_argument, source).map(|member| (member, first_argument))
}

pub(crate) fn is_dynamic_dispatch_method(method: Node<'_>, source: &str) -> bool {
    matches!(
        node_text(method, source),
        "send" | "__send__" | "public_send"
    )
}

pub(super) fn constant_hit_node(node: Node<'_>) -> Node<'_> {
    if node.kind() == "scope_resolution" {
        node.child_by_field_name("name").unwrap_or(node)
    } else {
        node
    }
}

pub(crate) fn symbol_or_string_value(node: Node<'_>, source: &str) -> Option<String> {
    let text = node_text(node, source);
    let stripped = text
        .strip_prefix(':')
        .unwrap_or(text)
        .trim_matches(['"', '\'']);
    (!stripped.is_empty()).then(|| stripped.to_string())
}

pub(crate) fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or("")
        .trim()
}
