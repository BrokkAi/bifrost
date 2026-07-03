//! Small utilities for structural-search language adapters.
//!
//! These helpers are intentionally limited to mechanics that are identical
//! across adapters. Grammar-specific decisions, such as how an expression's
//! terminal name is found, stay in the language adapter.

#[cfg(test)]
use super::kinds::NormalizedKind;
use super::kinds::Role;
use super::spec::RoleSink;
use tree_sitter::Node;

pub(crate) fn first_named_child<'tree>(node: Node<'tree>) -> Option<Node<'tree>> {
    node.named_child(0)
}

pub(crate) fn attach_role_with_derived_name<'tree>(
    sink: &mut RoleSink<'_>,
    role: Role,
    target: Node<'tree>,
    name_of: impl FnOnce(Node<'tree>) -> Option<Node<'tree>>,
) {
    sink.role_maybe_named(role, target, name_of(target));
}

pub(crate) fn attach_positional_argument_roles<'tree, F>(
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
        attach_role_with_derived_name(sink, Role::Arg, argument, name_of);
    }
}

pub(crate) fn attach_terminal_callee<'tree>(
    sink: &mut RoleSink<'_>,
    expression: Node<'tree>,
    terminal_name: Option<Node<'tree>>,
) {
    if let Some(name) = terminal_name {
        sink.role_named(Role::Callee, name, name);
        sink.set_name(name);
    } else {
        sink.role(Role::Callee, expression);
    }
}

#[cfg(test)]
pub(crate) fn assert_kind_table_matches_grammar(
    grammar: tree_sitter::Language,
    grammar_name: &str,
    table: &[(&str, NormalizedKind)],
) {
    for (name, kind) in table {
        assert_ne!(
            grammar.id_for_node_kind(name, true),
            0,
            "node type {name:?} (mapped to {kind:?}) does not exist in {grammar_name}"
        );
    }
}
