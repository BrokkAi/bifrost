//! Pure Rust path and type-node readers shared by both usage-graph scans.
//!
//! These five functions were private to `rust_graph/{extractor,hits}.rs`, which
//! are parked on the definition route's `RustTypeLookupCache` and cannot follow
//! them here. They import nothing from either sibling and belong beside Go's
//! `graph/ast.rs` regardless of when the two scans land, so they moved with the
//! inverted pass and are re-exported at their original paths for the parked
//! callers.

use crate::declarations::RUST_IDENTIFIER_SIGIL;
use crate::usage::RustReferenceNamespace;
use brokk_bifrost_core::analyzer::common::node_ident_text;
use brokk_bifrost_core::analyzer::usages::common::same_node;
use tree_sitter::Node;

pub fn is_rust_declaration_name(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    matches!(
        parent.kind(),
        "function_item"
            | "struct_item"
            | "enum_item"
            | "trait_item"
            | "type_item"
            | "const_item"
            | "static_item"
            | "mod_item"
            | "field_declaration"
            | "enum_variant"
            | "function_signature_item"
    ) && parent.child_by_field_name("name") == Some(node)
}

/// Whether this syntax node is Rust's standalone underscore placeholder.
///
/// Tree-sitter represents `_` as its anonymous `_` token in patterns, as an
/// `identifier` in bindings such as `use Trait as _`, and as a
/// `type_identifier` in inferred type positions. None introduces or names a
/// reference. Identifiers that merely begin with an underscore remain ordinary
/// referenceable names.
pub fn is_rust_non_reference_underscore(node: Node<'_>, source: &str) -> bool {
    node.kind() == "_"
        || (matches!(node.kind(), "identifier" | "type_identifier")
            && simple_node_text(node, source).as_deref() == Some("_"))
}

pub fn rust_reference_namespace(node: Node<'_>) -> RustReferenceNamespace {
    let mut ancestor = Some(node);
    while let Some(current) = ancestor {
        if current.kind() == "macro_invocation"
            && current
                .child_by_field_name("macro")
                .is_some_and(|macro_path| {
                    macro_path.start_byte() <= node.start_byte()
                        && node.end_byte() <= macro_path.end_byte()
                })
        {
            return RustReferenceNamespace::Macro;
        }
        ancestor = current.parent();
    }

    if node.kind() == "type_identifier" && rust_type_identifier_is_call_target(node) {
        return RustReferenceNamespace::Value;
    }
    if matches!(node.kind(), "type_identifier" | "scoped_type_identifier") {
        return RustReferenceNamespace::Type;
    }
    if let Some(parent) = node.parent() {
        if parent.kind() == "scoped_type_identifier" {
            return RustReferenceNamespace::Type;
        }
        if parent.kind() == "scoped_identifier"
            && parent
                .child_by_field_name("path")
                .is_some_and(|path| same_node(path, node))
        {
            return RustReferenceNamespace::PathPrefix;
        }
    }
    RustReferenceNamespace::Value
}

fn rust_type_identifier_is_call_target(node: Node<'_>) -> bool {
    let mut expression = node;
    while let Some(parent) = expression.parent()
        && matches!(parent.kind(), "generic_function" | "generic_type")
    {
        expression = parent;
    }
    expression.parent().is_some_and(|parent| {
        parent.kind() == "call_expression"
            && parent
                .child_by_field_name("function")
                .is_some_and(|function| function.id() == expression.id())
    })
}

pub fn first_generic_type_argument(type_node: Node<'_>) -> Option<Node<'_>> {
    let type_arguments = type_node.child_by_field_name("type_arguments");
    let mut cursor = type_arguments.unwrap_or(type_node).walk();
    type_arguments
        .unwrap_or(type_node)
        .named_children(&mut cursor)
        .filter(|child| is_rust_type_node(*child))
        .find(|child| {
            type_node
                .child_by_field_name("type")
                .is_none_or(|base| !same_node(*child, base))
        })
}

pub fn is_rust_type_node(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "type_identifier"
            | "identifier"
            | "scoped_type_identifier"
            | "scoped_identifier"
            | "generic_type"
            | "reference_type"
            | "pointer_type"
            | "array_type"
            | "slice_type"
            | "tuple_type"
            | "unit_type"
            | "never_type"
    )
}

pub fn type_node_last_segment(type_node: Node<'_>, source: &str) -> Option<String> {
    match type_node.kind() {
        "type_identifier" | "identifier" => simple_node_text(type_node, source),
        "scoped_type_identifier" | "scoped_identifier" => type_node
            .child_by_field_name("name")
            .and_then(|name| simple_node_text(name, source)),
        "generic_type" => type_node
            .child_by_field_name("type")
            .and_then(|base| type_node_last_segment(base, source)),
        _ => None,
    }
}

fn simple_node_text(node: Node<'_>, source: &str) -> Option<String> {
    let text = node_ident_text(node, source, true, &RUST_IDENTIFIER_SIGIL);
    (!text.is_empty()).then(|| text.to_string())
}

pub fn rust_path_segments(mut node: Node<'_>) -> Option<Vec<Node<'_>>> {
    let mut reversed = Vec::new();
    loop {
        match node.kind() {
            "scoped_identifier" | "scoped_type_identifier" => {
                reversed.push(node.child_by_field_name("name")?);
                let Some(path) = node.child_by_field_name("path") else {
                    if node.child(0).is_some_and(|child| child.kind() == "::") {
                        break;
                    }
                    return None;
                };
                node = path;
            }
            "generic_type" => node = node.child_by_field_name("type")?,
            "generic_function" => node = node.child_by_field_name("function")?,
            "identifier" | "type_identifier" | "self" | "super" | "crate" => {
                reversed.push(node);
                break;
            }
            _ => return None,
        }
    }
    reversed.reverse();
    Some(reversed)
}

pub fn rust_path_is_leading_absolute(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent()
        && matches!(
            parent.kind(),
            "scoped_identifier" | "scoped_type_identifier" | "generic_type" | "generic_function"
        )
    {
        node = parent;
    }
    loop {
        match node.kind() {
            "generic_type" => {
                let Some(inner) = node.child_by_field_name("type") else {
                    return false;
                };
                node = inner;
            }
            "generic_function" => {
                let Some(inner) = node.child_by_field_name("function") else {
                    return false;
                };
                node = inner;
            }
            "scoped_identifier" | "scoped_type_identifier" => {
                if let Some(path) = node.child_by_field_name("path") {
                    node = path;
                } else {
                    return node.child(0).is_some_and(|child| child.kind() == "::");
                }
            }
            _ => return false,
        }
    }
}

/// The trait bounds that give a generic type parameter its only type
/// information, read from the enclosing scopes' `type_parameters` list and
/// `where_clause`.
///
/// `Some(bounds)` when `name` is declared as a type parameter of a scope that
/// encloses `reference`; the innermost declaration wins, because an inner type
/// parameter shadows an outer one and any type of the same name. The vector is
/// empty when that parameter carries no trait bound: nothing at all is known
/// about a value of this type, which is not the same as knowing it is some
/// other type. `None` when `name` is not a type parameter here, so it names an
/// ordinary type and resolves like one.
///
/// A returned bound is the bound's own type node (`A`, `a::B`, `A<T>`), with
/// lifetimes, `?Sized` removals, and the `for<'a>` binder stripped, so each
/// resolves exactly like any other written type.
pub fn type_parameter_trait_bounds<'tree>(
    reference: Node<'tree>,
    name: &str,
    source: &str,
) -> Option<Vec<Node<'tree>>> {
    let mut scope = Some(reference);
    while let Some(node) = scope {
        if let Some(parameters) = node.child_by_field_name("type_parameters") {
            let mut cursor = parameters.walk();
            let declaration = parameters.named_children(&mut cursor).find(|parameter| {
                parameter
                    .child_by_field_name("name")
                    .and_then(|declared| simple_node_text(declared, source))
                    .is_some_and(|declared| declared == name)
            });
            if let Some(declaration) = declaration {
                let mut bounds = Vec::new();
                if let Some(inline) = declaration.child_by_field_name("bounds") {
                    push_trait_bounds(inline, &mut bounds);
                }
                push_where_clause_bounds(node, name, source, &mut bounds);
                return Some(bounds);
            }
        }
        scope = node.parent();
    }
    None
}

/// The `where S: A + B` bounds `scope` declares for the type parameter `name`.
fn push_where_clause_bounds<'tree>(
    scope: Node<'tree>,
    name: &str,
    source: &str,
    bounds: &mut Vec<Node<'tree>>,
) {
    let mut scope_cursor = scope.walk();
    let Some(where_clause) = scope
        .named_children(&mut scope_cursor)
        .find(|child| child.kind() == "where_clause")
    else {
        return;
    };
    let mut cursor = where_clause.walk();
    for predicate in where_clause.named_children(&mut cursor) {
        let names_parameter = predicate
            .child_by_field_name("left")
            .filter(|left| matches!(left.kind(), "type_identifier" | "identifier"))
            .and_then(|left| simple_node_text(left, source))
            .is_some_and(|left| left == name);
        if names_parameter && let Some(predicate_bounds) = predicate.child_by_field_name("bounds") {
            push_trait_bounds(predicate_bounds, bounds);
        }
    }
}

/// The type nodes of a `trait_bounds` list, minus everything that bounds a
/// value without naming a type it has: lifetimes and `?Sized` removals.
fn push_trait_bounds<'tree>(trait_bounds: Node<'tree>, bounds: &mut Vec<Node<'tree>>) {
    let mut cursor = trait_bounds.walk();
    for bound in trait_bounds.named_children(&mut cursor) {
        match bound.kind() {
            "lifetime" | "removed_trait_bound" => {}
            "higher_ranked_trait_bound" => {
                if let Some(inner) = bound.child_by_field_name("type") {
                    bounds.push(inner);
                }
            }
            _ => bounds.push(bound),
        }
    }
}
