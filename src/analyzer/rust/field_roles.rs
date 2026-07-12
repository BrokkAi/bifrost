use tree_sitter::Node;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RustStructFieldContainer {
    Literal,
    Pattern,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum RustFieldNameRole<'tree> {
    Reference {
        owner_type: Node<'tree>,
        name: Node<'tree>,
        container: RustStructFieldContainer,
    },
    Declaration {
        name: Node<'tree>,
    },
    Other,
}

pub(crate) fn classify_rust_field_name(mut focused: Node<'_>) -> RustFieldNameRole<'_> {
    loop {
        match focused.kind() {
            "field_declaration" => {
                if let Some(name) = focused.child_by_field_name("name") {
                    return RustFieldNameRole::Declaration { name };
                }
            }
            "field_initializer" | "shorthand_field_initializer" => {
                if let Some(name) = initializer_name(focused)
                    && let Some(container) = enclosing_container(focused, "struct_expression")
                    && let Some(owner_type) = container.child_by_field_name("name")
                {
                    return RustFieldNameRole::Reference {
                        owner_type,
                        name,
                        container: RustStructFieldContainer::Literal,
                    };
                }
            }
            "field_pattern" => {
                if let Some(name) = focused.child_by_field_name("name")
                    && let Some(container) = enclosing_container(focused, "struct_pattern")
                    && let Some(owner_type) = container.child_by_field_name("type")
                {
                    return RustFieldNameRole::Reference {
                        owner_type,
                        name,
                        container: RustStructFieldContainer::Pattern,
                    };
                }
            }
            _ => {}
        }
        let Some(parent) = focused.parent() else {
            return RustFieldNameRole::Other;
        };
        focused = parent;
    }
}

pub(crate) fn rust_is_field_declaration_name(
    focused: Node<'_>,
    start_byte: usize,
    end_byte: usize,
) -> bool {
    matches!(
        classify_rust_field_name(focused),
        RustFieldNameRole::Declaration { name }
            if name.start_byte() == start_byte && name.end_byte() == end_byte
    )
}

pub(crate) fn rust_struct_field_references(
    container: Node<'_>,
) -> Option<(Node<'_>, Vec<Node<'_>>)> {
    let (owner_type, body, child_kind, container_kind) = match container.kind() {
        "struct_expression" => (
            container.child_by_field_name("name")?,
            container.child_by_field_name("body")?,
            None,
            RustStructFieldContainer::Literal,
        ),
        "struct_pattern" => (
            container.child_by_field_name("type")?,
            container,
            Some("field_pattern"),
            RustStructFieldContainer::Pattern,
        ),
        _ => return None,
    };

    let mut cursor = body.walk();
    let names = body
        .named_children(&mut cursor)
        .filter(|child| child_kind.is_none_or(|kind| child.kind() == kind))
        .filter_map(|child| match container_kind {
            RustStructFieldContainer::Literal => initializer_name(child),
            RustStructFieldContainer::Pattern => child.child_by_field_name("name"),
        })
        .collect();
    Some((owner_type, names))
}

fn initializer_name(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "field_initializer" => node.child_by_field_name("field"),
        "shorthand_field_initializer" => node.named_child(0),
        _ => None,
    }
}

fn enclosing_container<'tree>(mut node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    while let Some(parent) = node.parent() {
        if parent.kind() == kind {
            return Some(parent);
        }
        node = parent;
    }
    None
}
