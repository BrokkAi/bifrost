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

/// The role `focused` plays as a struct field NAME, when it is that name.
///
/// Only the name node itself has a role. A node inside a field's value
/// (`Foo { f: Some(x) }`), the field's initializer or declaration node, or any
/// other ancestor is `Other`: it is not a name, and `x` there is an ordinary
/// use of a local. (Walking up through every ancestor used to classify the
/// whole value as a name, which hid locals read inside struct literals from
/// lexical resolution, #11830.)
pub fn classify_rust_field_name(focused: Node<'_>) -> RustFieldNameRole<'_> {
    let Some(owner) = focused.parent() else {
        return RustFieldNameRole::Other;
    };
    match owner.kind() {
        "field_declaration" => {
            if let Some(name) = owner.child_by_field_name("name")
                && name == focused
            {
                return RustFieldNameRole::Declaration { name };
            }
        }
        "field_initializer" | "shorthand_field_initializer" => {
            if let Some(name) = initializer_name(owner)
                && name == focused
                && let Some(container) =
                    find_ancestor(owner, |parent| parent.kind() == "struct_expression")
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
            if let Some(name) = owner.child_by_field_name("name")
                && name == focused
                && let Some(container) =
                    find_ancestor(owner, |parent| parent.kind() == "struct_pattern")
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
    RustFieldNameRole::Other
}

/// Whether `focus` can name a local variable for lexical resolution.
///
/// A field declaration's name and a struct pattern's field name are names, not
/// uses (a pattern's name may bind a local, but that is a declaration, which
/// lexical resolution of a use does not answer). The explicit name of a
/// literal's `field: value` initializer is a field name too. The identifier of
/// a SHORTHAND literal initializer `Foo { x }` means `x: x`: it names the field
/// and also reads the local `x`, so it resolves like any other use.
pub fn rust_focus_resolves_lexically(focus: Node<'_>) -> bool {
    if focus.is_missing() {
        return false;
    }
    match classify_rust_field_name(focus) {
        RustFieldNameRole::Other => true,
        RustFieldNameRole::Declaration { .. } => false,
        RustFieldNameRole::Reference {
            container: RustStructFieldContainer::Pattern,
            ..
        } => false,
        RustFieldNameRole::Reference {
            name,
            container: RustStructFieldContainer::Literal,
            ..
        } => name
            .parent()
            .is_some_and(|owner| owner.kind() == "shorthand_field_initializer"),
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

/// Opaque macro tokens retain punctuation but do not establish expression roles.
/// A dot prefix can be a selector or arbitrary macro syntax.
pub fn rust_token_follows_dot(node: Node<'_>) -> bool {
    if node
        .parent()
        .is_none_or(|parent| parent.kind() != "token_tree")
    {
        return false;
    }
    let mut previous = node.prev_sibling();
    while let Some(token) = previous {
        if !token.is_extra() {
            return token.kind() == ".";
        }
        previous = token.prev_sibling();
    }
    false
}
