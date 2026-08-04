//! The Go AST vocabulary both usage-graph scans share.
//!
//! Pure node arithmetic: name extraction, binding slots, selector splitting,
//! type-reference shape, and the sentinel tokens the forward scan seeds into
//! local inference. Nothing here needs a project, an index, or a collector, so
//! the analysis-owned scan drivers and this crate's resolver can both use it.

use crate::graph::resolver::TypeRef;
use brokk_bifrost_core::analyzer::usages::common::{node_text, same_node};
use tree_sitter::Node;

pub const OWNER_TOKEN: &str = "__go_target_owner__";
pub const NON_OWNER_TOKEN: &str = "__go_known_non_target_owner__";
pub const FIELD_OWNER_TOKEN_PREFIX: &str = "__go_field_owner__:";
/// Marks the enclosing method's own receiver variable. Go has no `self`/`this`
/// keyword; a method calls its siblings through its declared receiver variable
/// (`func (s *T) f() { s.g() }`). This token distinguishes that same-owner
/// receiver from another owner-typed local, so `s.g()` is a same-owner site
/// while `other.g()` (a different `*T` value) stays external (#1014 facet B).
pub const SELF_RECEIVER_TOKEN: &str = "__go_self_receiver__";
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
        "var_declaration" => {
            let mut out = Vec::new();
            for_each_var_spec(node, &mut |var_spec| {
                out.extend(declared_names(var_spec, source))
            });
            out
        }
        "var_spec" => var_spec_names(node, source),
        "short_var_declaration" => lhs_identifiers(node, source),
        _ => Vec::new(),
    }
}
pub fn var_spec_names(node: Node<'_>, source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cursor = node.walk();
    for name_node in node.children_by_field_name("name", &mut cursor) {
        let name = node_text(name_node, source);
        if name != "_" {
            out.push(name.to_string());
        }
    }
    out
}
pub fn var_spec_name_slots(node: Node<'_>, source: &str) -> Vec<Option<String>> {
    let mut out = Vec::new();
    let mut cursor = node.walk();
    for name_node in node.children_by_field_name("name", &mut cursor) {
        let name = node_text(name_node, source);
        out.push((name != "_").then(|| name.to_string()));
    }
    out
}
pub fn for_each_var_spec(node: Node<'_>, f: &mut impl FnMut(Node<'_>)) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "var_spec" => f(child),
            "var_spec_list" => for_each_var_spec(child, f),
            _ => {}
        }
    }
}
pub fn lhs_identifiers(node: Node<'_>, source: &str) -> Vec<String> {
    let Some(left) = node
        .child_by_field_name("left")
        .or_else(|| first_named_child(node))
    else {
        return Vec::new();
    };
    identifiers_in_node(left, source)
        .into_iter()
        .filter(|name| name != "_")
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
pub fn rhs_expressions(node: Node<'_>) -> Vec<Node<'_>> {
    let Some(right) = node
        .child_by_field_name("right")
        .or_else(|| last_named_child(node))
    else {
        return Vec::new();
    };
    if right.kind() == "expression_list" {
        let mut cursor = right.walk();
        let children: Vec<_> = right.named_children(&mut cursor).collect();
        if !children.is_empty() {
            return children;
        }
    }
    vec![right]
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
pub fn is_identifier_node(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "identifier" | "field_identifier" | "type_identifier" | "package_identifier"
    )
}
pub fn field_owner_token(field: &str) -> String {
    format!("{FIELD_OWNER_TOKEN_PREFIX}{field}")
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
pub fn receiver_symbol_from_qualifier(qualifier: &str) -> &str {
    qualifier
        .trim()
        .trim_start_matches('(')
        .trim_end_matches(')')
        .trim_start_matches(['*', '&'])
        .trim()
}
pub fn type_ref_from_node(node: Node<'_>, source: &str) -> Option<TypeRef> {
    match node.kind() {
        "type_identifier" | "identifier" => Some(TypeRef {
            qualifier: None,
            name: Some(node_text(node, source).to_string()),
        }),
        "qualified_type" | "selector_expression" => {
            let (qualifier, _qualifier_node, field) = selector_parts(node, source)?;
            Some(TypeRef {
                qualifier: Some(qualifier),
                name: Some(node_text(field, source).to_string()),
            })
        }
        "pointer_type" | "slice_type" | "array_type" | "generic_type" | "parenthesized_type" => {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find_map(|child| type_ref_from_node(child, source))
        }
        _ => None,
    }
}
pub fn first_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).next()
}
pub fn last_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).last()
}
pub fn is_definition_identifier(node: Node<'_>, _source: &str) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if is_method_receiver_type(node) {
        return true;
    }
    if keyed_element_for_key(node).is_some() {
        return composite_literal_owner_type_for_key(node)
            .is_none_or(|type_node| type_node.kind() != "map_type");
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
pub fn is_method_receiver_type(node: Node<'_>) -> bool {
    let mut ancestor = node.parent();
    while let Some(current) = ancestor {
        if current.kind() == "parameter_declaration" {
            return is_method_receiver_parameter(current)
                && current
                    .child_by_field_name("type")
                    .is_some_and(|type_node| {
                        type_node.start_byte() <= node.start_byte()
                            && node.end_byte() <= type_node.end_byte()
                    });
        }
        ancestor = current.parent();
    }
    false
}
/// Return the structured owner type for a keyed composite-literal element.
///
/// An elided value such as `[1]Owner{{Field: value}}` has no type node at the
/// inner literal boundary. Its type is nevertheless explicit in the enclosing
/// array/slice element or map value. Walk through only those AST relationships
/// and peel one container type per elided boundary; do not infer an owner from
/// the field spelling.
pub fn composite_literal_owner_type_for_key(node: Node<'_>) -> Option<Node<'_>> {
    let keyed = keyed_element_for_key(node)?;
    let mut literal = keyed
        .parent()
        .filter(|parent| parent.kind() == "literal_value")?;
    let mut elided_depth = 0usize;

    loop {
        let parent = literal.parent()?;
        match parent.kind() {
            "composite_literal" => {
                let mut owner = parent.child_by_field_name("type")?;
                for _ in 0..elided_depth {
                    owner = go_container_element_or_value_type(owner)?;
                }
                return Some(owner);
            }
            "keyed_element" => {
                let value = parent.child_by_field_name("value")?;
                if !same_node(value, literal) {
                    return None;
                }
                literal = parent
                    .parent()
                    .filter(|ancestor| ancestor.kind() == "literal_value")?;
                elided_depth += 1;
            }
            "literal_value" => {
                literal = parent;
                elided_depth += 1;
            }
            "literal_element" => {
                let container = parent.parent()?;
                literal = match container.kind() {
                    "keyed_element" => {
                        let value = container.child_by_field_name("value")?;
                        if !same_node(value, parent) {
                            return None;
                        }
                        container
                            .parent()
                            .filter(|ancestor| ancestor.kind() == "literal_value")?
                    }
                    "literal_value" => container,
                    _ => return None,
                };
                elided_depth += 1;
            }
            _ => return None,
        }
    }
}
pub fn go_container_element_or_value_type(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "array_type" => node.child_by_field_name("element"),
        "slice_type" => node.named_child(0),
        "map_type" => node.child_by_field_name("value"),
        "pointer_type" | "parenthesized_type" => node
            .named_child(0)
            .and_then(go_container_element_or_value_type),
        _ => None,
    }
}
pub fn keyed_element_for_key(node: Node<'_>) -> Option<Node<'_>> {
    let parent = node.parent()?;
    let keyed = if parent.kind() == "keyed_element" {
        parent
    } else {
        let keyed = parent
            .parent()
            .filter(|ancestor| ancestor.kind() == "keyed_element")?;
        let key = keyed.child_by_field_name("key")?;
        if !same_node(key, parent) {
            return None;
        }
        keyed
    };

    let key = keyed.child_by_field_name("key")?;
    if same_node(key, node) {
        return Some(keyed);
    }
    let mut cursor = key.walk();
    let mut children = key.named_children(&mut cursor);
    children
        .next()
        .filter(|child| same_node(*child, node) && children.next().is_none())
        .map(|_| keyed)
}
