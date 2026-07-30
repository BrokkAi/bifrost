//! Structured reads of the Kotlin syntax tree, shared by every Kotlin consumer.
//!
//! The vendored Kotlin grammar (`crates/bifrost-analysis/vendor/tree-sitter-kotlin`)
//! is field-poor: of everything this module reads, only `function_declaration`
//! and `property_declaration` carry a tree-sitter field (`receiver`). The callee
//! of a call, the member of a navigation, the label of a named argument, and the
//! segments of a dotted type are all recovered *positionally* from named
//! children.
//!
//! Positional reads are easy to get subtly wrong, and wrong in a way that fails
//! silently — a mis-read callee does not error, it just resolves nothing. So they
//! live here once rather than once per consumer. Definition navigation
//! (`crate::analyzer::usages::get_definition::kotlin`, issue #1238) and the usage
//! graphs (`crate::analyzer::usages::kotlin_graph`, issue #1239) both read the
//! grammar through this module, which is also what keeps them from disagreeing
//! about what a given syntax shape means.
//!
//! The shapes, as dumped from the pinned grammar:
//!
//!     Base()              (call_expression (simple_identifier)
//!                            (call_suffix (value_arguments)))
//!     base.greet("x")     (call_expression
//!                            (navigation_expression (simple_identifier)
//!                              (navigation_suffix (simple_identifier)))
//!                            (call_suffix (value_arguments
//!                              (value_argument (string_literal)))))
//!     lib.Base            (user_type (type_identifier) (type_identifier))
//!     lib.Base?           (nullable_type (user_type (type_identifier)
//!                            (type_identifier)) (quest))
//!     foo(name = 1)       (value_argument (simple_identifier) (integer_literal))
//!     import a.b.C as D   (import_header (identifier (simple_identifier)
//!                            (simple_identifier) (simple_identifier))
//!                            (import_alias (type_identifier)))
//!
//! Note in particular that a dotted type name is *one* `user_type` node with one
//! `type_identifier` child per segment, not a nested or scoped node. Nothing here
//! splits source text on `.` or `::` to recover that structure.

use crate::analyzer::Range;
use crate::analyzer::tree_walk::{first_named_child_of_kind, named_children};
use crate::analyzer::usages::reference_site::smallest_named_node_covering;
use tree_sitter::Node;

/// The callee expression of a Kotlin call.
///
/// A `call_expression`'s children are the callee followed by `call_suffix`, and a
/// `constructor_invocation` (a supertype list entry such as `: Base(1)`) spells
/// its callee as the `user_type` it constructs followed by `value_arguments`.
/// Neither names the callee with a field, so the callee is "the first named child
/// that is not the argument suffix".
pub(crate) fn kotlin_callee(call: Node<'_>) -> Option<Node<'_>> {
    named_children(call)
        .into_iter()
        .find(|child| !matches!(child.kind(), "call_suffix" | "value_arguments"))
}

/// The `call_expression` whose callee is `node`, if `node` is a callee at all.
pub(crate) fn kotlin_call_with_callee(node: Node<'_>) -> Option<Node<'_>> {
    let call = node
        .parent()
        .filter(|parent| parent.kind() == "call_expression")?;
    (kotlin_callee(call)?.id() == node.id()).then_some(call)
}

/// The `value_arguments` node a Kotlin call passes its arguments in.
///
/// An ordinary call nests it inside `call_suffix`; a `constructor_invocation`
/// holds it directly.
pub(crate) fn kotlin_value_arguments(call: Node<'_>) -> Option<Node<'_>> {
    if let Some(arguments) = first_named_child_of_kind(call, "value_arguments") {
        return Some(arguments);
    }
    first_named_child_of_kind(call, "call_suffix")
        .and_then(|suffix| first_named_child_of_kind(suffix, "value_arguments"))
}

/// How many arguments a call passes.
///
/// A trailing lambda (`items.forEach { … }`) is an argument even though it sits
/// outside the parentheses, so it counts: without it, every trailing-lambda call
/// would look like it passed one argument too few and would fail to match its own
/// overload.
pub(crate) fn kotlin_call_arity(call: Node<'_>) -> usize {
    let positional = kotlin_value_arguments(call)
        .map(|arguments| {
            named_children(arguments)
                .into_iter()
                .filter(|child| child.kind() == "value_argument")
                .count()
        })
        .unwrap_or(0);
    let trailing = first_named_child_of_kind(call, "call_suffix")
        .is_some_and(|suffix| first_named_child_of_kind(suffix, "annotated_lambda").is_some());
    positional + usize::from(trailing)
}

/// Whether `node` is the *label* of a named argument rather than its value.
///
/// `foo(name = 1)` is `(value_argument (simple_identifier) (integer_literal))`; a
/// positional `foo(name)` is `(value_argument (simple_identifier))`. The label is
/// therefore the first of two or more named children.
pub(crate) fn kotlin_named_argument_label(argument: Node<'_>, node: Node<'_>) -> bool {
    let children = named_children(argument);
    children.len() > 1 && children[0].id() == node.id()
}

/// The receiver expression a `navigation_expression` selects from.
pub(crate) fn kotlin_navigation_receiver(navigation: Node<'_>) -> Option<Node<'_>> {
    named_children(navigation)
        .into_iter()
        .find(|child| child.kind() != "navigation_suffix")
}

/// The `type_identifier` children of a `user_type`, in source order.
///
/// One per dotted segment: `lib.Base` yields the `lib` token then the `Base`
/// token. `type_arguments` are deliberately excluded — a generic argument is a
/// type reference in its own right, reached by walking into it, not a segment of
/// the outer name.
pub(crate) fn kotlin_user_type_segments(user_type: Node<'_>) -> Vec<Node<'_>> {
    named_children(user_type)
        .into_iter()
        .filter(|child| child.kind() == "type_identifier")
        .collect()
}

/// Whether `node` is the name a declaration introduces rather than a reference to
/// something declared elsewhere.
pub(crate) fn kotlin_is_declaration_name(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    let expected_kind = match parent.kind() {
        "class_declaration" | "object_declaration" | "companion_object" | "type_alias"
        | "type_parameter" => "type_identifier",
        "function_declaration"
        | "variable_declaration"
        | "parameter"
        | "class_parameter"
        | "enum_entry"
        | "parameter_with_optional_type" => "simple_identifier",
        _ => return false,
    };
    node.kind() == expected_kind
        && first_named_child_of_kind(parent, expected_kind)
            .is_some_and(|name| name.id() == node.id())
}

/// The `import_header` enclosing `node`, if `node` sits inside an import.
///
/// A focus inside an import can land on the `identifier`'s `simple_identifier`,
/// on the `import_alias`'s `type_identifier`, or on the header itself.
pub(crate) fn kotlin_enclosing_import_header(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = Some(node);
    while let Some(candidate) = current {
        if candidate.kind() == "import_header" {
            return Some(candidate);
        }
        current = candidate.parent();
    }
    None
}

/// The dotted path segments of an `import_header`, in source order.
pub(crate) fn kotlin_import_header_segments(header: Node<'_>) -> Vec<Node<'_>> {
    let Some(path) = first_named_child_of_kind(header, "identifier") else {
        return Vec::new();
    };
    named_children(path)
        .into_iter()
        .filter(|child| child.kind() == "simple_identifier")
        .collect()
}

/// Whether a node kind can appear as the value half of a property declaration.
pub(crate) fn kotlin_is_expression_kind(kind: &str) -> bool {
    matches!(
        kind,
        "call_expression"
            | "navigation_expression"
            | "as_expression"
            | "simple_identifier"
            | "parenthesized_expression"
            | "postfix_expression"
            | "object_literal"
    )
}

/// The declaration node covering `range`.
///
/// The smallest covering node is not always the declaration: an `enum_entry`
/// spans exactly its own name, so its `simple_identifier` child covers the same
/// bytes and would win the smallest-covering walk. Climbing back out to the
/// outermost node with the same span picks the declaration rather than the name
/// inside it.
pub(crate) fn kotlin_declaration_node<'tree>(
    root: Node<'tree>,
    range: &Range,
) -> Option<Node<'tree>> {
    let mut node = smallest_named_node_covering(root, range.start_byte, range.end_byte)?;
    while let Some(parent) = node.parent() {
        if parent.start_byte() != node.start_byte() || parent.end_byte() != node.end_byte() {
            break;
        }
        node = parent;
    }
    Some(node)
}
