//! Pure Rust path and type-node readers shared by both usage-graph scans.
//!
//! These five functions were private to `rust_graph/{extractor,hits}.rs`, which
//! are parked on the definition route's `RustTypeLookupCache` and cannot follow
//! them here. They import nothing from either sibling and belong beside Go's
//! `graph/ast.rs` regardless of when the two scans land, so they moved with the
//! inverted pass and are re-exported at their original paths for the parked
//! callers.

use crate::declarations::RUST_IDENTIFIER_SIGIL;
use crate::usage_index::RustReferenceNamespace;
use brokk_bifrost_core::analyzer::common::node_ident_text;
use brokk_bifrost_core::analyzer::usages::common::same_node;
use tree_sitter::Node;

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
