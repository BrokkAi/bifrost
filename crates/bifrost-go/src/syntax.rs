//! Go grammar helpers used by native analysis, diagnostics and definition lookup.
//!
//! Name extraction, binding positions, and selectors are read from Tree-sitter
//! nodes without a workspace graph or scan state.

use crate::shape::{composite_literal_owner_type_for_key, keyed_element_for_key};
pub use brokk_bifrost_core::analyzer::tree_walk::last_named_child;
use brokk_bifrost_core::analyzer::usages::common::{node_text, same_node};
use tree_sitter::Node;

/// Whether `node` (a `parameter_declaration`) is the receiver of a method
/// declaration (`func (f *T) m()`), so its binding is the same-owner receiver.
pub fn is_method_receiver_parameter(node: Node<'_>) -> bool {
    node.parent()
        .filter(|parent| parent.kind() == "parameter_list")
        .and_then(|list| {
            list.parent()
                .filter(|method| method.kind() == "method_declaration")
                .map(|method| method.child_by_field_name("receiver") == Some(list))
        })
        .unwrap_or(false)
}
pub fn parameter_names(node: Node<'_>, source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "identifier" {
            out.push(node_text(child, source).to_string());
        }
    }
    out
}
pub fn declared_names(node: Node<'_>, source: &str) -> Vec<String> {
    match node.kind() {
        "short_var_declaration" => lhs_identifiers(node, source),
        "range_clause" => range_clause_binding_names(node, source),
        _ => Vec::new(),
    }
}

pub fn lhs_identifiers(node: Node<'_>, source: &str) -> Vec<String> {
    lhs_identifier_slots(node, source)
        .into_iter()
        .flatten()
        .collect()
}
pub fn lhs_identifier_slots(node: Node<'_>, source: &str) -> Vec<Option<String>> {
    let Some(left) = node
        .child_by_field_name("left")
        .or_else(|| first_named_child(node))
    else {
        return Vec::new();
    };
    identifier_slots_in_node(left, source)
}
pub fn identifier_slots_in_node(node: Node<'_>, source: &str) -> Vec<Option<String>> {
    if is_identifier_node(node) {
        let text = node_text(node, source);
        return vec![(text != "_").then(|| text.to_string())];
    }
    let mut out = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if is_identifier_node(child) {
            let text = node_text(child, source);
            out.push((text != "_").then(|| text.to_string()));
        }
    }
    out
}
pub fn identifiers_in_node(node: Node<'_>, source: &str) -> Vec<String> {
    if is_identifier_node(node) {
        return vec![node_text(node, source).to_string()];
    }
    let mut out = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if is_identifier_node(child) {
            out.push(node_text(child, source).to_string());
        }
    }
    out
}
/// Whether `node` is one of the clause forms whose `statement_list` owns an
/// implicit Go lexical scope. Keeping this grammar predicate shared prevents
/// the forward, inverted, and reference scans from assigning different scope
/// to expression-switch, type-switch, or select bodies.
pub fn is_clause(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "expression_case" | "type_case" | "communication_case" | "default_case"
    )
}

/// Names introduced for one Go switch/select clause. The caller is responsible
/// for limiting their scope to the clause's `statement_list`.
pub fn clause_binding_names(node: Node<'_>, source: &str) -> Vec<String> {
    let binding_node = match node.kind() {
        "communication_case" => {
            let communication = node.child_by_field_name("communication");
            let Some(receive) = communication.filter(|child| child.kind() == "receive_statement")
            else {
                return Vec::new();
            };
            if !receive_statement_is_short_declaration(receive) {
                return Vec::new();
            }
            receive.child_by_field_name("left")
        }
        "type_case" | "default_case" => node
            .parent()
            .filter(|parent| parent.kind() == "type_switch_statement")
            .and_then(|parent| parent.child_by_field_name("alias")),
        _ => None,
    };
    binding_node
        .map(|binding| {
            identifiers_in_node(binding, source)
                .into_iter()
                .filter(|name| name != "_")
                .collect()
        })
        .unwrap_or_default()
}

pub fn receive_statement_is_short_declaration(node: Node<'_>) -> bool {
    node.kind() == "receive_statement" && has_short_declaration_token(node)
}

pub fn for_each_parameter_declaration<'tree>(
    node: Node<'tree>,
    mut visit: impl FnMut(Node<'tree>),
) {
    let mut cursor = node.walk();
    for parameter in node.named_children(&mut cursor) {
        if matches!(
            parameter.kind(),
            "parameter_declaration" | "variadic_parameter_declaration"
        ) {
            visit(parameter);
        }
    }
}

pub fn range_clause_is_short_declaration(node: Node<'_>) -> bool {
    node.kind() == "range_clause" && has_short_declaration_token(node)
}

pub fn range_clause_binding_names(node: Node<'_>, source: &str) -> Vec<String> {
    if !range_clause_is_short_declaration(node) {
        return Vec::new();
    }
    let Some(left) = node.child_by_field_name("left") else {
        return Vec::new();
    };
    identifiers_in_node(left, source)
        .into_iter()
        .filter(|name| name != "_")
        .collect()
}

fn has_short_declaration_token(node: Node<'_>) -> bool {
    brokk_bifrost_core::analyzer::tree_walk::has_child_of_kind(node, ":=")
}

pub fn is_clause_binding_identifier(node: Node<'_>) -> bool {
    let mut ancestor = node.parent();
    while let Some(current) = ancestor {
        match current.kind() {
            "receive_statement" => {
                return receive_statement_is_short_declaration(current)
                    && current.child_by_field_name("left").is_some_and(|left| {
                        left.start_byte() <= node.start_byte() && node.end_byte() <= left.end_byte()
                    });
            }
            "type_switch_statement" => {
                return current.child_by_field_name("alias").is_some_and(|alias| {
                    alias.start_byte() <= node.start_byte() && node.end_byte() <= alias.end_byte()
                });
            }
            "expression_list" => ancestor = current.parent(),
            _ => return false,
        }
    }
    false
}

pub fn clause_statement_list(node: Node<'_>) -> Option<Node<'_>> {
    brokk_bifrost_core::analyzer::tree_walk::first_named_child_of_kind(node, "statement_list")
}
pub fn is_identifier_node(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "identifier" | "field_identifier" | "type_identifier" | "package_identifier"
    )
}
pub fn selector_parts<'a>(node: Node<'a>, source: &str) -> Option<(String, Node<'a>, Node<'a>)> {
    let qualifier_node = node
        .child_by_field_name("operand")
        .or_else(|| node.child_by_field_name("package"))
        .or_else(|| first_named_child(node))?;
    let field_node = node
        .child_by_field_name("field")
        .or_else(|| node.child_by_field_name("name"))
        .or_else(|| last_named_child(node))?;
    Some((
        node_text(qualifier_node, source).to_string(),
        qualifier_node,
        field_node,
    ))
}
pub fn first_named_child(node: Node<'_>) -> Option<Node<'_>> {
    brokk_bifrost_core::analyzer::tree_walk::first_named_child_matching(node, |child| {
        !child.is_extra()
    })
}
pub fn is_definition_identifier(node: Node<'_>, _source: &str) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if node.kind() == "type_identifier" && is_method_receiver_type(node) {
        return true;
    }
    if is_clause_binding_identifier(node) {
        return true;
    }
    if keyed_element_for_key(node).is_some() {
        return composite_literal_owner_type_for_key(node).is_none_or(|type_node| {
            !matches!(type_node.kind(), "map_type" | "array_type" | "slice_type")
        });
    }
    if parent.kind() == "field_declaration"
        && parent.child_by_field_name("type").is_some_and(|ty| {
            node.start_byte() < ty.start_byte()
                && parent
                    .child_by_field_name("name")
                    .is_none_or(|name| same_node(name, node) || node.end_byte() <= ty.start_byte())
        })
    {
        return true;
    }
    matches!(
        parent.kind(),
        "package_clause"
            | "import_spec"
            | "function_declaration"
            | "method_declaration"
            | "type_spec"
            | "type_alias"
            | "var_spec"
            | "const_spec"
            | "field_declaration"
            | "method_elem"
            | "parameter_declaration"
            | "short_var_declaration"
    ) && node
        .parent()
        .and_then(|parent| parent.child_by_field_name("name"))
        .is_some_and(|name| same_node(name, node))
}
fn method_receiver_parameter_ancestor(node: Node<'_>) -> Option<Node<'_>> {
    // Stop at the first enclosing parameter: only that one can be the receiver.
    brokk_bifrost_core::analyzer::tree_walk::find_ancestor(node, |current| {
        current.kind() == "parameter_declaration"
    })
    .filter(|parameter| is_method_receiver_parameter(*parameter))
}

pub fn is_method_receiver_type(node: Node<'_>) -> bool {
    method_receiver_parameter_ancestor(node)
        .and_then(|receiver| receiver.child_by_field_name("type"))
        .is_some_and(|type_node| {
            type_node.start_byte() <= node.start_byte() && node.end_byte() <= type_node.end_byte()
        })
}
