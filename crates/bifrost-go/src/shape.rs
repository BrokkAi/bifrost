//! Go composite literal type-shape helpers.

use crate::syntax::first_named_child;
use brokk_bifrost_core::analyzer::usages::common::same_node;
use tree_sitter::Node;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompositeLiteralContainerStep {
    ElementOrValue,
    MapKey,
}

pub struct CompositeLiteralOwnerPath<'tree> {
    pub type_node: Node<'tree>,
    pub steps: Vec<CompositeLiteralContainerStep>,
}

/// Return the explicit outer type and the structured container path from that
/// type to the keyed element's owner. Unlike
/// [`composite_literal_owner_type_for_key`], this retains unapplied steps when
/// the outer literal names a declared container type whose underlying shape is
/// available only from the declaration index. An elided value such as
/// `[1]Owner{{Field: value}}` has no type node at the inner literal boundary;
/// every returned step comes only from the surrounding array, slice, map key,
/// or map value structure, never from the field spelling.
pub fn composite_literal_owner_path_for_key(
    node: Node<'_>,
) -> Option<CompositeLiteralOwnerPath<'_>> {
    let keyed = keyed_element_for_key(node)?;
    let mut literal = keyed
        .parent()
        .filter(|parent| parent.kind() == "literal_value")?;
    let mut steps = Vec::new();

    loop {
        let parent = literal.parent()?;
        match parent.kind() {
            "composite_literal" => {
                steps.reverse();
                return Some(CompositeLiteralOwnerPath {
                    type_node: parent.child_by_field_name("type")?,
                    steps,
                });
            }
            "keyed_element" => {
                let value = parent.child_by_field_name("value")?;
                let step = if same_node(value, literal) {
                    CompositeLiteralContainerStep::ElementOrValue
                } else if parent
                    .child_by_field_name("key")
                    .is_some_and(|key| same_node(key, literal))
                {
                    CompositeLiteralContainerStep::MapKey
                } else {
                    return None;
                };
                literal = parent
                    .parent()
                    .filter(|ancestor| ancestor.kind() == "literal_value")?;
                steps.push(step);
            }
            "literal_value" => {
                literal = parent;
                steps.push(CompositeLiteralContainerStep::ElementOrValue);
            }
            "literal_element" => {
                let container = parent.parent()?;
                literal = match container.kind() {
                    "keyed_element" => {
                        let value = container.child_by_field_name("value")?;
                        let step = if same_node(value, parent) {
                            CompositeLiteralContainerStep::ElementOrValue
                        } else if container
                            .child_by_field_name("key")
                            .is_some_and(|key| same_node(key, parent))
                        {
                            CompositeLiteralContainerStep::MapKey
                        } else {
                            return None;
                        };
                        steps.push(step);
                        container
                            .parent()
                            .filter(|ancestor| ancestor.kind() == "literal_value")?
                    }
                    "literal_value" => container,
                    _ => return None,
                };
                if parent
                    .parent()
                    .is_some_and(|node| node.kind() == "literal_value")
                {
                    steps.push(CompositeLiteralContainerStep::ElementOrValue);
                }
            }
            _ => return None,
        }
    }
}

pub fn composite_literal_owner_type_for_key(node: Node<'_>) -> Option<Node<'_>> {
    let path = composite_literal_owner_path_for_key(node)?;
    let mut owner = path.type_node;
    for step in path.steps {
        owner = match step {
            CompositeLiteralContainerStep::ElementOrValue => {
                go_container_element_or_value_type(owner)?
            }
            CompositeLiteralContainerStep::MapKey => go_map_key_type(owner)?,
        };
    }
    Some(owner)
}
fn go_map_key_type(node: Node<'_>) -> Option<Node<'_>> {
    go_map_key_type_with_scope(node, || true)
}

/// Find a map key type through pointer and parenthesized type wrappers.
/// `scope_step` charges one step for each inspected type node.
pub fn go_map_key_type_with_scope(
    mut node: Node<'_>,
    mut scope_step: impl FnMut() -> bool,
) -> Option<Node<'_>> {
    loop {
        if !scope_step() {
            return None;
        }
        match node.kind() {
            "map_type" => return node.child_by_field_name("key"),
            "pointer_type" | "parenthesized_type" => node = first_named_child(node)?,
            _ => return None,
        }
    }
}
pub fn go_container_element_or_value_type(node: Node<'_>) -> Option<Node<'_>> {
    go_container_element_or_value_type_with_scope(node, || true)
}

/// Find a container element or value type through type wrappers.
/// `scope_step` charges one step for each inspected type node.
pub fn go_container_element_or_value_type_with_scope(
    mut node: Node<'_>,
    mut scope_step: impl FnMut() -> bool,
) -> Option<Node<'_>> {
    loop {
        if !scope_step() {
            return None;
        }
        match node.kind() {
            "array_type" => return node.child_by_field_name("element"),
            "slice_type" => return node.child_by_field_name("element"),
            "map_type" => return node.child_by_field_name("value"),
            "pointer_type" | "parenthesized_type" => node = first_named_child(node)?,
            _ => return None,
        }
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
    brokk_bifrost_core::analyzer::tree_walk::single_named_child_matching(key, |child| {
        !child.is_extra()
    })
    .filter(|only| same_node(*only, node))
    .map(|_| keyed)
}

#[cfg(test)]
mod grammar_boundary_tests {
    use super::*;
    use brokk_bifrost_core::analyzer::usages::common::node_text;

    #[test]
    fn mixed_composite_containers_follow_outer_to_inner_fields() {
        for syntax in [
            "[]map[struct{ F int }]int{{{F:1}:2}}",
            "[]*map[struct{ F int }]int{{{F:1}:2}}",
        ] {
            let source = format!("package p\nvar x = {syntax}\n");
            let mut parser = tree_sitter::Parser::new();
            parser
                .set_language(&tree_sitter_go::LANGUAGE.into())
                .unwrap();
            let tree = parser.parse(&source, None).unwrap();
            assert!(!tree.root_node().has_error());
            let mut stack = vec![tree.root_node()];
            let mut count = 0;
            while let Some(node) = stack.pop() {
                if node.kind() == "identifier" && node_text(node, &source) == "F" {
                    count += 1;
                    let path = composite_literal_owner_path_for_key(node).unwrap();
                    assert_eq!(
                        path.steps,
                        [
                            CompositeLiteralContainerStep::ElementOrValue,
                            CompositeLiteralContainerStep::MapKey
                        ]
                    );
                    let owner = composite_literal_owner_type_for_key(node).unwrap();
                    assert_eq!(node_text(owner, &source), "struct{ F int }");
                }
                stack.extend(node.named_children(&mut node.walk()));
            }
            assert_eq!(count, 1);
        }
    }
}
