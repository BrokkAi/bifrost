use tree_sitter::Node;

/// Node kinds the grammar uses to attach outer attributes to an item or
/// expression. The payload is under a field, while the attributes themselves
/// are grouped under the `attributes` field.
const ATTRIBUTE_WRAPPER_KINDS: [&str; 3] = [
    "declaration_with_attribute",
    "expression_with_attribute",
    "block_expression_with_attribute",
];

/// Follow attribute wrappers to the declaration or expression they carry.
///
/// For any other node, this returns the node unchanged.
pub fn unwrap_attributes(mut node: Node<'_>) -> Node<'_> {
    while ATTRIBUTE_WRAPPER_KINDS.contains(&node.kind()) {
        let Some(child) = node
            .child_by_field_name("declaration")
            .or_else(|| node.child_by_field_name("expression"))
        else {
            break;
        };
        node = child;
    }
    node
}

/// Return the outer `attribute_item`s attached to `node`.
///
/// `node` may be either the wrapper written by the grammar or the item returned
/// by [`unwrap_attributes`]. The grouped `attributes` field is read directly; no
/// ungrouped sibling scan or pre-0.24 fallback is involved. Inline member and
/// parameter groups follow the exact owning list production.
pub fn outer_attributes<'tree>(node: Node<'tree>) -> impl Iterator<Item = Node<'tree>> {
    let attributes = attached_attributes(node);
    RustOuterAttributes {
        attributes,
        index: 0,
    }
}

/// Indexed view over an associated `attributes` group, avoiding allocation in
/// this declaration-walk hot path.
struct RustOuterAttributes<'tree> {
    attributes: Option<Node<'tree>>,
    index: usize,
}

impl<'tree> Iterator for RustOuterAttributes<'tree> {
    type Item = Node<'tree>;

    fn next(&mut self) -> Option<Self::Item> {
        let attributes = self.attributes?;
        while self.index < attributes.child_count() {
            let attribute_item = attributes.child(self.index)?;
            self.index += 1;
            if attribute_item.kind() == "attribute_item" {
                return Some(attribute_item);
            }
        }
        None
    }
}

fn attached_attributes(node: Node<'_>) -> Option<Node<'_>> {
    // A wrapper owns its group. Payload nodes inherit only from the wrapper
    // that names them as its declaration/expression field.
    if ATTRIBUTE_WRAPPER_KINDS.contains(&node.kind()) {
        return node.child_by_field_name("attributes");
    }
    if let Some(parent) = node.parent()
        && ATTRIBUTE_WRAPPER_KINDS.contains(&parent.kind())
        && (parent.child_by_field_name("declaration") == Some(node)
            || parent.child_by_field_name("expression") == Some(node))
    {
        return parent.child_by_field_name("attributes");
    }
    // These productions carry an unnamed attributes child on the owner.
    if matches!(
        node.kind(),
        "enum_variant" | "match_arm" | "field_initializer" | "shorthand_field_initializer"
    ) {
        let mut cursor = node.walk();
        return node
            .named_children(&mut cursor)
            .find(|child| child.kind() == "attributes");
    }
    // Delimited lists put one grouped attribute node before its owned entry.
    // Require the exact list production, and never cross a comma or item.
    let parent = node.parent()?;
    if !matches!(
        parent.kind(),
        "field_declaration_list"
            | "ordered_field_declaration_list"
            | "parameters"
            | "type_parameters"
            | "array_expression"
            | "tuple_expression"
    ) {
        return None;
    }
    let mut previous = node.prev_sibling();
    while let Some(sibling) = previous {
        match sibling.kind() {
            "attributes" => return Some(sibling),
            "line_comment" | "block_comment" => previous = sibling.prev_sibling(),
            _ => return None,
        }
    }
    None
}

/// Whether an `attribute_item`'s path is exactly `expected`.
pub fn attribute_item_has_path(attribute_item: Node<'_>, source: &str, expected: &str) -> bool {
    let Some(attribute) = attribute_item
        .named_child(0)
        .filter(|child| child.kind() == "attribute")
    else {
        return false;
    };
    let Some(path) = attribute.named_child(0) else {
        return false;
    };
    source.get(path.start_byte()..path.end_byte()) == Some(expected)
}

/// Whether `node` has an attached attribute whose path is exactly `expected`.
pub fn item_has_path_attribute(node: Node<'_>, source: &str, expected: &str) -> bool {
    outer_attributes(node)
        .any(|attribute_item| attribute_item_has_path(attribute_item, source, expected))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::{Parser, Tree};

    fn parse(source: &str) -> Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust grammar");
        let tree = parser.parse(source, None).expect("parse Rust source");
        assert!(
            !tree.root_node().has_error(),
            "{}",
            tree.root_node().to_sexp()
        );
        tree
    }

    fn named_descendant<'tree>(root: Node<'tree>, kind: &str) -> Node<'tree> {
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if node.kind() == kind {
                return node;
            }
            let mut cursor = node.walk();
            let children = node.named_children(&mut cursor).collect::<Vec<_>>();
            stack.extend(children.into_iter().rev());
        }
        panic!("expected {kind}")
    }

    fn attribute_paths<'tree>(node: Node<'tree>, source: &str) -> Vec<String> {
        outer_attributes(node)
            .map(|item| {
                let attribute = item.named_child(0).expect("attribute");
                let path = attribute.named_child(0).expect("attribute path");
                source[path.start_byte()..path.end_byte()].to_string()
            })
            .collect()
    }

    #[test]
    fn unwraps_and_reads_declaration_attributes() {
        let source = "#[first] #[cfg(test)] static ITEM: u8 = 0;";
        let tree = parse(source);
        let wrapped = named_descendant(tree.root_node(), "declaration_with_attribute");
        let item = unwrap_attributes(wrapped);
        assert_eq!(item.kind(), "static_item");
        assert_eq!(attribute_paths(item, source), ["first", "cfg"]);
    }

    #[test]
    fn nested_items_receive_only_their_nearest_wrapper_attributes() {
        let source = "#[outer] mod wrapped { #[inner] fn item() {} }";
        let tree = parse(source);
        let root_item = tree.root_node().named_child(0).expect("root item");
        let module = unwrap_attributes(root_item);
        let body = module.child_by_field_name("body").expect("module body");
        let function = body.named_child(0).expect("function");
        assert_eq!(attribute_paths(function, source), ["inner"]);
    }

    #[test]
    fn reads_inline_grouped_member_and_parameter_attributes() {
        let source = "enum E { #[variant] A, B } struct S { #[field] value: u8, clean: u8 } fn function(#[parameter] value: u8, clean: u8) {}";
        let tree = parse(source);
        let variant = named_descendant(tree.root_node(), "enum_variant");
        let parameter = named_descendant(tree.root_node(), "parameter");
        assert_eq!(attribute_paths(variant, source), ["variant"]);
        assert_eq!(attribute_paths(parameter, source), ["parameter"]);
        let field = named_descendant(tree.root_node(), "field_declaration");
        assert_eq!(attribute_paths(field, source), ["field"]);
        for owner in [variant, parameter, field] {
            let mut next = owner.next_named_sibling();
            while let Some(node) = next {
                assert!(
                    outer_attributes(node).next().is_none(),
                    "attributes leaked to {}",
                    node.to_sexp()
                );
                next = node.next_named_sibling();
            }
        }
    }
}
