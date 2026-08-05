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

/// The grammar field name `child` occupies in `parent`, or `None` when the
/// child is unnamed-positional. Occurrence-role classification is written
/// against AST fields, so every adapter needs this exact question answered.
pub(crate) fn field_name_in_parent(parent: Node<'_>, child: Node<'_>) -> Option<&'static str> {
    (0..parent.child_count()).find_map(|index| {
        (parent.child(index) == Some(child))
            .then(|| parent.field_name_for_child(index as u32))
            .flatten()
    })
}

/// Whether `child` occupies `parent`'s `field`.
pub(crate) fn is_field_of(parent: Node<'_>, child: Node<'_>, field: &str) -> bool {
    field_name_in_parent(parent, child) == Some(field)
}

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

pub(crate) fn attach_argument_role_with_derived_name<'tree>(
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

pub(crate) fn is_spread_argument_node(node: Node<'_>) -> bool {
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
        if !sink.should_continue() {
            break;
        }
        attach_argument_role_with_derived_name(sink, argument, name_of);
    }
}

pub(crate) fn attach_terminal_callee<'tree>(
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

/// Every occurrence role a spec classifies for `source`, as
/// `(start byte, source text, role)` triples in fact order.
///
/// Occurrence roles are a pure function of the source and the spec, so adapter
/// tests extract facts directly rather than standing up a project: the analyzer
/// and cache layers in between cannot change the answer, and the triples carry
/// enough context to make a failure readable.
#[cfg(test)]
pub(crate) fn occurrence_roles_of<'source>(
    spec: &dyn super::spec::StructuralSpec,
    grammar: &tree_sitter::Language,
    source: &'source str,
) -> Vec<(usize, &'source str, super::occurrences::OccurrenceRole)> {
    let facts = super::extract::extract_file_facts(spec, grammar, source)
        .expect("structural extraction should succeed for the fixture");
    let mut found = Vec::new();
    for id in 0..facts.nodes().len() as u32 {
        let node = facts.node(id);
        for &role in facts.occurrence_roles(id) {
            found.push((
                node.range.start_byte,
                &source[node.range.start_byte..node.range.end_byte],
                role,
            ));
        }
    }
    found
}

/// Assert that the token starting at `needle`'s first occurrence carries
/// exactly `role`, naming every classified token when it does not.
#[cfg(test)]
pub(crate) fn assert_occurrence_role(
    found: &[(usize, &str, super::occurrences::OccurrenceRole)],
    start_byte: usize,
    role: super::occurrences::OccurrenceRole,
) {
    let actual = found
        .iter()
        .filter(|(offset, _, _)| *offset == start_byte)
        .map(|(_, _, role)| *role)
        .collect::<Vec<_>>();
    assert_eq!(
        actual,
        vec![role],
        "expected exactly {role:?} at byte {start_byte}; all classified tokens: {found:?}"
    );
}
