//! Shared Java grammar classification for executable fragments.
use super::declarations::java_modifier_keywords;
use brokk_bifrost_core::analyzer::model::ProcedureKind;
use tree_sitter::Node;

pub fn java_callable_shape<'tree>(node: Node<'tree>) -> Option<(ProcedureKind, Node<'tree>, bool)> {
    let has_static = || java_modifier_keywords(node).any(|keyword| keyword == "static");
    match node.kind() {
        "method_declaration" => Some((
            ProcedureKind::Method,
            node.child_by_field_name("body")?,
            has_static(),
        )),
        "constructor_declaration" | "compact_constructor_declaration" => Some((
            ProcedureKind::Constructor,
            node.child_by_field_name("body")?,
            false,
        )),
        "lambda_expression" => Some((
            ProcedureKind::Lambda,
            node.child_by_field_name("body")?,
            false,
        )),
        "static_initializer" => Some((ProcedureKind::Initializer, node.named_child(0)?, true)),
        "block"
            if node
                .parent()
                .is_some_and(|parent| parent.kind() == "class_body") =>
        {
            Some((ProcedureKind::Initializer, node, false))
        }
        "variable_declarator"
            if node.parent().is_some_and(|parent| {
                matches!(parent.kind(), "field_declaration" | "constant_declaration")
            }) =>
        {
            let field = node.parent().expect("guarded field parent");
            Some((
                ProcedureKind::Initializer,
                node.child_by_field_name("value")?,
                field.kind() == "constant_declaration"
                    || java_modifier_keywords(field).any(|keyword| keyword == "static"),
            ))
        }
        "enum_constant" => Some((ProcedureKind::Initializer, node, true)),
        _ => None,
    }
}
