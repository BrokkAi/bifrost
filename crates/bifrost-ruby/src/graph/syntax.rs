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

/// The positional parameters of `block` (`{ |a, b| ... }`), in order, when
/// each one is a plain name that binds one yielded value. Optional, splat,
/// keyword, block and destructured parameters, and a trailing comma
/// (`|a,|`, which splats a single yielded array), return `None`. Block-local
/// names after `;` are not parameters.
pub fn block_positional_parameters<'tree>(block: Node<'tree>) -> Option<Vec<Node<'tree>>> {
    let Some(parameters) = block.child_by_field_name("parameters") else {
        return Some(Vec::new());
    };
    let mut names = Vec::new();
    let mut after_comma = false;
    for index in 0..parameters.child_count() {
        let child = parameters.child(index)?;
        match child.kind() {
            "identifier" if child.is_named() => {
                names.push(child);
                after_comma = false;
            }
            "," => after_comma = true,
            ";" => break,
            "|" => {}
            _ => return None,
        }
    }
    (!after_comma).then_some(names)
}

/// The `yield` expressions in `method`'s own body, or `None` when the block
/// passed to `method` can be called some other way: captured by a `&block`
/// parameter, forwarded by `...`, or passed on implicitly by `super`. Nested
/// definitions own their own `yield`s; blocks and lambdas inside the body
/// yield to `method`'s block.
pub fn method_yield_sites<'tree>(method: Node<'tree>) -> Option<Vec<Node<'tree>>> {
    if let Some(parameters) = method.child_by_field_name("parameters") {
        let mut cursor = parameters.walk();
        if parameters
            .named_children(&mut cursor)
            .any(|parameter| matches!(parameter.kind(), "block_parameter" | "forward_parameter"))
        {
            return None;
        }
    }
    let mut yields = Vec::new();
    let mut pending: Vec<_> = method.child_by_field_name("body").into_iter().collect();
    while let Some(node) = pending.pop() {
        match node.kind() {
            "method" | "singleton_method" | "class" | "module" | "singleton_class" => continue,
            "super" => return None,
            "yield" => yields.push(node),
            _ => {}
        }
        let mut cursor = node.walk();
        pending.extend(node.named_children(&mut cursor));
    }
    Some(yields)
}

/// The argument of `yield_node` that binds positional block parameter `index`
/// of `count`, by Ruby's proc argument rules: one parameter takes the first
/// value, and several parameters take one value each, except that a single
/// yielded value splats across them. `None` when the parameter binds `nil`,
/// an element of a splatted value, or an argument whose position the syntax
/// does not fix (`*args`, `**opts`, `&blk`, `key: value`).
pub fn yield_argument_for_block_parameter<'tree>(
    yield_node: Node<'tree>,
    count: usize,
    index: usize,
) -> Option<Node<'tree>> {
    debug_assert!(index < count, "block parameter {index} of {count}");
    let arguments = match yield_node.named_child(0) {
        Some(list) => {
            let mut cursor = list.walk();
            list.named_children(&mut cursor).collect::<Vec<_>>()
        }
        None => Vec::new(),
    };
    if arguments.iter().any(|argument| {
        matches!(
            argument.kind(),
            "splat_argument"
                | "hash_splat_argument"
                | "block_argument"
                | "forward_argument"
                | "pair"
        )
    }) {
        return None;
    }
    if count > 1 && arguments.len() == 1 {
        return None;
    }
    arguments.get(index).copied()
}

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
