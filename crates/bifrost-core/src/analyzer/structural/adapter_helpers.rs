//! Small utilities for structural-search language adapters.
//!
//! These helpers are intentionally limited to mechanics that are identical
//! across adapters. Grammar-specific decisions, such as how an expression's
//! terminal name is found, stay in the language adapter.

use super::kinds::Role;
use super::spec::RoleSink;
use crate::analyzer::Range;
use tree_sitter::Node;

/// The byte-and-line range of one syntax node, in the same 1-based line
/// convention the facts arena records (see `structural::extract`), so an
/// activation interval an adapter states is directly comparable with a fact's
/// range.
pub fn node_range(node: Node<'_>) -> Range {
    Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row + 1,
        end_line: node.end_position().row + 1,
    }
}

/// The nearest ancestor of `node` (inclusive of its parent chain, exclusive of
/// `node` itself) whose grammar kind `accept` admits.
///
/// Every adapter's binding-activation hook asks the same question -- "which
/// binding form does this token belong to?" -- and answers it by climbing the
/// parent chain, so the climb itself is shared and only the predicate is
/// grammar knowledge.
pub fn nearest_ancestor<'tree>(
    node: Node<'tree>,
    mut accept: impl FnMut(&str) -> bool,
) -> Option<Node<'tree>> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if accept(parent.kind()) {
            return Some(parent);
        }
        current = parent;
    }
    None
}

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

/// Climb from a segment token to the outermost node of the left-nested
/// qualified chain it participates in (`scoped_identifier`,
/// `nested_identifier`, and language equivalents). `None` when the token sits
/// in no chain node at all — a bare identifier is not a path.
pub fn qualified_chain_root<'tree>(
    token: Node<'tree>,
    chain: &[(&str, Option<&str>)],
) -> Option<Node<'tree>> {
    let mut root = token;
    while let Some(parent) = root.parent() {
        if chain.iter().any(|(kind, _)| *kind == parent.kind()) {
            root = parent;
        } else {
            break;
        }
    }
    (root.id() != token.id()).then_some(root)
}

/// The ordered segment tokens of the left-nested chain rooted at `root`.
///
/// `chain` pairs each chain node kind with the field that names its own
/// segment (`scoped_identifier`/`name`, `nested_identifier`/`property`), or
/// `None` for a chain node without fields whose segment is positionally its
/// last named child (Java's `scoped_type_identifier`); the remaining named
/// child is the next outer-to-inner link, ending at the head token. A
/// link wrapped in one of `unwrap_kinds` (Rust's turbofish
/// `generic_type` inside a path) is unwrapped to the type or function it
/// wraps. Reads AST fields only; an unexpected shape yields an empty vector,
/// which the derivation layer reports as an unenumerable chain rather than a
/// partial ordering.
pub fn linear_chain_tokens<'tree>(
    root: Node<'tree>,
    chain: &[(&str, Option<&str>)],
    unwrap_kinds: &[&str],
) -> Vec<Node<'tree>> {
    let mut tokens = Vec::new();
    let mut current = root;
    loop {
        let Some(&(_, name_field)) = chain.iter().find(|(kind, _)| *kind == current.kind()) else {
            tokens.push(current);
            break;
        };
        let Some(name) = chain_name_child(current, name_field) else {
            return Vec::new();
        };
        tokens.push(name);
        let mut scope = None;
        let mut cursor = current.walk();
        for child in current.named_children(&mut cursor) {
            if child.id() != name.id() {
                scope = Some(child);
                break;
            }
        }
        drop(cursor);
        let Some(mut scope) = scope else {
            return Vec::new();
        };
        while unwrap_kinds.contains(&scope.kind()) {
            let mut cursor = scope.walk();
            let inner = scope
                .named_children(&mut cursor)
                .find(|child| child.kind() != "type_arguments");
            match inner {
                Some(inner) => scope = inner,
                None => return Vec::new(),
            }
        }
        current = scope;
    }
    tokens.reverse();
    tokens
}

/// The number of generic (type) arguments the source spells at `token`'s
/// segment position: climb the chain while the token remains the chain's own
/// name field, and when the enclosing node is one of `wrapper_kinds`
/// (`generic_type`, `generic_function`), count the named children of its
/// `type_arguments` child. `None` when the source spells no arguments there.
pub fn spelled_generic_arity(
    token: Node<'_>,
    chain: &[(&str, Option<&str>)],
    wrapper_kinds: &[&str],
) -> Option<u32> {
    let mut anchor = token;
    loop {
        let parent = anchor.parent()?;
        if let Some(&(_, name_field)) = chain.iter().find(|(kind, _)| *kind == parent.kind()) {
            if chain_name_child(parent, name_field).map(|name| name.id()) != Some(anchor.id()) {
                return None;
            }
            anchor = parent;
            continue;
        }
        if !wrapper_kinds.contains(&parent.kind()) {
            return None;
        }
        let mut cursor = parent.walk();
        let arguments = parent
            .named_children(&mut cursor)
            .find(|child| child.kind() == "type_arguments")?;
        let count = arguments.named_child_count();
        return Some(u32::try_from(count).expect("type argument count fits in u32"));
    }
}

/// The child that spells a chain node's own segment: the named field where the
/// grammar has one, otherwise the last named child (the positional convention
/// of field-less chain nodes such as Java's `scoped_type_identifier`).
fn chain_name_child<'tree>(node: Node<'tree>, name_field: Option<&str>) -> Option<Node<'tree>> {
    match name_field {
        Some(field) => node.child_by_field_name(field),
        None => {
            let mut cursor = node.walk();
            node.named_children(&mut cursor).last()
        }
    }
}
