use brokk_bifrost_core::analyzer::tree_walk::find_ancestor;
use tree_sitter::Node;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RustStructFieldContainer {
    Literal,
    Pattern,
}

#[derive(Clone, Copy, Debug)]
pub enum RustFieldNameRole<'tree> {
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

pub fn classify_rust_field_name(mut focused: Node<'_>) -> RustFieldNameRole<'_> {
    loop {
        match focused.kind() {
            "field_declaration" => {
                if let Some(name) = focused.child_by_field_name("name") {
                    return RustFieldNameRole::Declaration { name };
                }
            }
            "field_initializer" | "shorthand_field_initializer" => {
                if let Some(name) = initializer_name(focused)
                    && let Some(container) =
                        find_ancestor(focused, |parent| parent.kind() == "struct_expression")
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
                    && let Some(container) =
                        find_ancestor(focused, |parent| parent.kind() == "struct_pattern")
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

pub fn rust_is_field_declaration_name(
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

fn initializer_name(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "field_initializer" => node.child_by_field_name("field"),
        "shorthand_field_initializer" => node.named_child(0),
        _ => None,
    }
}
