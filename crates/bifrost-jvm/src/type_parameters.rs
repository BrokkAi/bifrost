//! JVM grammar rules for lexical type formals and inheritance barriers.
use brokk_bifrost_core::analyzer::Language;
use tree_sitter::Node;

pub(crate) fn is_name(node: Node<'_>, language: Language) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    match language {
        Language::Java => {
            parent.kind() == "type_parameter"
                && crate::java::graph_support::java_type_parameter_name_node(parent) == Some(node)
        }
        Language::Kotlin => {
            parent.kind() == "type_parameter" && {
                let mut cursor = parent.walk();
                parent
                    .named_children(&mut cursor)
                    .find(|child| child.kind() == "type_identifier")
                    == Some(node)
            }
        }
        Language::Scala => {
            matches!(
                parent.kind(),
                "type_parameters" | "covariant_type_parameter" | "contravariant_type_parameter"
            ) && brokk_bifrost_core::analyzer::structural::adapter_helpers::field_name_in_parent(
                parent, node,
            ) == Some("name")
        }
        _ => false,
    }
}

pub(crate) fn owner(node: Node<'_>, language: Language) -> Option<Node<'_>> {
    if !is_name(node, language) {
        return None;
    }
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "class_declaration"
                | "interface_declaration"
                | "record_declaration"
                | "method_declaration"
                | "constructor_declaration"
                | "function_declaration"
                | "class_definition"
                | "trait_definition"
                | "function_definition"
                | "type_definition"
                | "enum_definition"
                | "type_alias"
                | "property_declaration"
                | "extension_definition"
                | "given_definition"
        ) {
            return Some(parent);
        }
        current = parent.parent();
    }
    None
}

fn has_modifier(owner: Node<'_>, modifier: &str) -> bool {
    let mut cursor = owner.walk();
    let mut pending: Vec<_> = owner
        .named_children(&mut cursor)
        .filter(|child| {
            matches!(
                child.kind(),
                "modifiers" | "class_modifier" | "member_modifier"
            )
        })
        .collect();
    while let Some(node) = pending.pop() {
        if node.kind() == modifier {
            return true;
        }
        let mut cursor = node.walk();
        pending.extend(node.children(&mut cursor));
    }
    false
}

pub(crate) fn barrier(owner: Node<'_>, language: Language) -> bool {
    match language {
        Language::Java => {
            if owner.kind() == "static_initializer" {
                return true;
            }
            if matches!(
                owner.kind(),
                "method_declaration"
                    | "field_declaration"
                    | "class_declaration"
                    | "interface_declaration"
                    | "enum_declaration"
                    | "record_declaration"
            ) && has_modifier(owner, "static")
            {
                return true;
            }
            matches!(
                owner.kind(),
                "interface_declaration"
                    | "enum_declaration"
                    | "record_declaration"
                    | "annotation_type_declaration"
            ) || (owner.kind() == "class_declaration"
                && owner.parent().is_some_and(|body| {
                    matches!(
                        body.kind(),
                        "class_body"
                            | "interface_body"
                            | "enum_body"
                            | "enum_body_declarations"
                            | "annotation_type_body"
                    ) && body.parent().is_some_and(|parent| {
                        matches!(
                            parent.kind(),
                            "interface_declaration" | "annotation_type_declaration"
                        )
                    })
                }))
        }
        Language::Kotlin => {
            matches!(owner.kind(), "object_declaration" | "companion_object")
                || (owner.kind() == "class_declaration"
                    && !has_modifier(owner, "inner")
                    && owner.parent().is_some_and(|body| {
                        matches!(body.kind(), "class_body" | "enum_class_body")
                    }))
        }
        _ => false,
    }
}
