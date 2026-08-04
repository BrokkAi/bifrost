//! Small utilities for structural-search language adapters.
//!
//! These helpers are intentionally limited to mechanics that are identical
//! across adapters. Grammar-specific decisions, such as how an expression's
//! terminal name is found, stay in the language adapter.

use super::kinds::Role;
use super::spec::RoleSink;
use tree_sitter::Node;

/// The grammar field name `child` occupies in `parent`, or `None` when the
/// child is unnamed-positional. Occurrence-role classification is written
/// against AST fields, so every adapter needs this exact question answered.
pub fn field_name_in_parent(parent: Node<'_>, child: Node<'_>) -> Option<&'static str> {
    (0..parent.child_count()).find_map(|index| {
        (parent.child(index) == Some(child))
            .then(|| parent.field_name_for_child(index as u32))
            .flatten()
    })
}

/// Whether `child` occupies `parent`'s `field`.
pub fn is_field_of(parent: Node<'_>, child: Node<'_>, field: &str) -> bool {
    field_name_in_parent(parent, child) == Some(field)
}

pub fn first_named_child<'tree>(node: Node<'tree>) -> Option<Node<'tree>> {
    node.named_child(0)
}

pub fn attach_role_with_derived_name<'tree>(
    sink: &mut RoleSink<'_>,
    role: Role,
    target: Node<'tree>,
    name_of: impl FnOnce(Node<'tree>) -> Option<Node<'tree>>,
) {
    sink.role_maybe_named(role, target, name_of(target));
}

pub fn attach_argument_role_with_derived_name<'tree>(
    sink: &mut RoleSink<'_>,
    argument: Node<'tree>,
    name_of: impl FnOnce(Node<'tree>) -> Option<Node<'tree>>,
) {
    sink.argument_maybe_named(
        argument,
        name_of(argument),
        is_spread_argument_node(argument),
    );
}

pub fn is_spread_argument_node(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "spread_element"
            | "splat_argument"
            | "hash_splat_argument"
            | "list_splat"
            | "dictionary_splat"
            | "spread_argument"
            | "variadic_unpacking"
    ) || (node.kind() == "argument"
        && (0..node.named_child_count())
            .filter_map(|index| node.named_child(index))
            .any(|child| child.kind() == "variadic_unpacking"))
}

pub fn attach_positional_argument_roles<'tree, F>(
    sink: &mut RoleSink<'_>,
    arguments: Node<'tree>,
    name_of: F,
) where
    F: Fn(Node<'tree>) -> Option<Node<'tree>> + Copy,
{
    for index in 0..arguments.named_child_count() {
        let Some(argument) = arguments.named_child(index) else {
            continue;
        };
        if !sink.should_continue() {
            break;
        }
        attach_argument_role_with_derived_name(sink, argument, name_of);
    }
}

pub fn attach_terminal_callee<'tree>(
    sink: &mut RoleSink<'_>,
    expression: Node<'tree>,
    terminal_name: Option<Node<'tree>>,
) {
    if let Some(name) = terminal_name {
        if sink.should_continue() {
            sink.role_named(Role::Callee, name, name);
            sink.set_name(name);
        }
    } else {
        sink.role(Role::Callee, expression);
    }
}
