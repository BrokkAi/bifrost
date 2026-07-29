//! Rust structural spec for `query_code`.

use crate::analyzer::Language;
use crate::analyzer::structural::adapter_helpers::{
    attach_positional_argument_roles, attach_role_with_derived_name, attach_terminal_callee,
    first_named_child,
};
use crate::analyzer::structural::{NormalizedKind, Role, RoleSink, StructuralSpec};
use tree_sitter::Node;

#[derive(Debug, Default)]
pub(crate) struct RustStructuralSpec;

pub(crate) static RUST_STRUCTURAL_SPEC: RustStructuralSpec = RustStructuralSpec;

const RUST_KIND_TABLE: &[(&str, NormalizedKind)] = &[
    ("call_expression", NormalizedKind::Call),
    ("field_expression", NormalizedKind::FieldAccess),
    ("function_item", NormalizedKind::Function),
    ("function_signature_item", NormalizedKind::Function),
    ("closure_expression", NormalizedKind::Lambda),
    ("struct_item", NormalizedKind::Class),
    ("enum_item", NormalizedKind::Class),
    ("trait_item", NormalizedKind::Class),
    ("type_item", NormalizedKind::Declaration),
    ("const_item", NormalizedKind::Assignment),
    ("static_item", NormalizedKind::Assignment),
    ("let_declaration", NormalizedKind::Assignment),
    ("assignment_expression", NormalizedKind::Assignment),
    ("compound_assignment_expr", NormalizedKind::Assignment),
    ("use_declaration", NormalizedKind::Import),
    ("identifier", NormalizedKind::Identifier),
    ("field_identifier", NormalizedKind::Identifier),
    ("scoped_identifier", NormalizedKind::Identifier),
    ("type_identifier", NormalizedKind::Identifier),
    ("char_literal", NormalizedKind::StringLiteral),
    ("string_literal", NormalizedKind::StringLiteral),
    ("raw_string_literal", NormalizedKind::StringLiteral),
    ("unary_expression", NormalizedKind::NumericLiteral),
    ("integer_literal", NormalizedKind::NumericLiteral),
    ("float_literal", NormalizedKind::NumericLiteral),
    ("negative_literal", NormalizedKind::NumericLiteral),
    ("boolean_literal", NormalizedKind::BooleanLiteral),
    ("return_expression", NormalizedKind::Return),
    ("if_expression", NormalizedKind::If),
    ("for_expression", NormalizedKind::Loop),
    ("while_expression", NormalizedKind::Loop),
    ("loop_expression", NormalizedKind::Loop),
];

fn expression_name_node<'tree>(expression: Node<'tree>) -> Option<Node<'tree>> {
    let mut current = expression;
    loop {
        match current.kind() {
            "identifier" | "field_identifier" | "type_identifier" | "self" | "super" | "crate" => {
                return Some(current);
            }
            "scoped_identifier" => current = current.child_by_field_name("name")?,
            "generic_function" => current = current.child_by_field_name("function")?,
            "field_expression" => current = current.child_by_field_name("field")?,
            "call_expression" => current = current.child_by_field_name("function")?,
            "mut_pattern" | "ref_pattern" => current = first_named_child(current)?,
            "parenthesized_expression" => current = first_named_child(current)?,
            _ => return None,
        }
    }
}

fn attach_scoped_receiver(sink: &mut RoleSink<'_>, function: Node<'_>) {
    if function.kind() != "scoped_identifier" {
        return;
    }
    if let Some(path) = function.child_by_field_name("path") {
        attach_role_with_derived_name(sink, Role::Receiver, path, expression_name_node);
    }
}

fn call_function_target(mut function: Node<'_>) -> Node<'_> {
    while function.kind() == "generic_function" {
        let Some(inner) = function.child_by_field_name("function") else {
            break;
        };
        function = inner;
    }
    function
}

fn is_numeric_literal_node(node: Node<'_>) -> bool {
    matches!(node.kind(), "integer_literal" | "float_literal")
}

fn is_negative_numeric_unary(node: Node<'_>) -> bool {
    node.kind() == "unary_expression"
        && node.child(0).is_some_and(|operator| operator.kind() == "-")
        && first_named_child(node).is_some_and(is_numeric_literal_node)
}

fn is_inside_negative_numeric_wrapper(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    parent.kind() == "negative_literal" || is_negative_numeric_unary(parent)
}

fn attach_use_module(sink: &mut RoleSink<'_>, node: Node<'_>) {
    match node.kind() {
        "identifier" | "scoped_identifier" | "self" | "super" | "crate" => {
            attach_role_with_derived_name(sink, Role::Module, node, expression_name_node);
        }
        "use_as_clause" => {
            if let Some(alias) = node.child_by_field_name("alias") {
                attach_role_with_derived_name(sink, Role::Module, alias, expression_name_node);
            } else if let Some(first) = first_named_child(node) {
                attach_use_module(sink, first);
            }
        }
        "scoped_use_list" => {
            if let Some(list) = node.child_by_field_name("list") {
                attach_use_module(sink, list);
            }
        }
        _ => {
            for index in 0..node.named_child_count() {
                let Some(child) = node.named_child(index) else {
                    continue;
                };
                attach_use_module(sink, child);
            }
        }
    }
}

fn function_item_is_method(node: Node<'_>) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        match parent.kind() {
            "impl_item" | "trait_item" => return true,
            "function_item" => return false,
            _ => current = parent.parent(),
        }
    }
    false
}

impl StructuralSpec for RustStructuralSpec {
    fn language(&self) -> Language {
        Language::Rust
    }

    fn kind_table(&self) -> &'static [(&'static str, NormalizedKind)] {
        RUST_KIND_TABLE
    }

    fn refine_kind(
        &self,
        node: Node<'_>,
        kind: NormalizedKind,
        _enclosing: Option<NormalizedKind>,
        _source: &str,
    ) -> NormalizedKind {
        if kind == NormalizedKind::Function && function_item_is_method(node) {
            NormalizedKind::Method
        } else {
            kind
        }
    }

    fn should_extract(&self, node: Node<'_>, kind: NormalizedKind) -> bool {
        if kind == NormalizedKind::NumericLiteral {
            if node.kind() == "unary_expression" {
                return is_negative_numeric_unary(node);
            }
            if is_numeric_literal_node(node) && is_inside_negative_numeric_wrapper(node) {
                return false;
            }
        }

        kind != NormalizedKind::Assignment
            || !matches!(
                node.kind(),
                "const_item" | "let_declaration" | "static_item"
            )
            || node.child_by_field_name("value").is_some()
    }

    fn supports_kind(&self, kind: NormalizedKind) -> bool {
        kind == NormalizedKind::Method
            || self
                .kind_table()
                .iter()
                .any(|(_, fact_kind)| fact_kind.satisfies(kind))
    }

    fn supports_role(&self, role: Role) -> bool {
        !matches!(role, Role::Kwarg | Role::Decorator)
    }

    fn extract(&self, node: Node<'_>, kind: NormalizedKind, sink: &mut RoleSink<'_>) {
        match kind {
            NormalizedKind::Call => {
                if let Some(function) = node.child_by_field_name("function") {
                    attach_terminal_callee(sink, function, expression_name_node(function));
                    let target = call_function_target(function);
                    if target.kind() == "field_expression"
                        && let Some(value) = target.child_by_field_name("value")
                    {
                        attach_role_with_derived_name(
                            sink,
                            Role::Receiver,
                            value,
                            expression_name_node,
                        );
                    }
                    attach_scoped_receiver(sink, target);
                }
                if let Some(arguments) = node.child_by_field_name("arguments") {
                    attach_positional_argument_roles(sink, arguments, expression_name_node);
                }
            }
            NormalizedKind::FieldAccess => {
                if let Some(field) = node.child_by_field_name("field") {
                    sink.set_name(field);
                    sink.role_named(Role::Field, field, field);
                }
                if let Some(value) = node.child_by_field_name("value") {
                    attach_role_with_derived_name(sink, Role::Object, value, expression_name_node);
                }
            }
            NormalizedKind::Function
            | NormalizedKind::Method
            | NormalizedKind::Class
            | NormalizedKind::Declaration => {
                if let Some(name) = node.child_by_field_name("name") {
                    sink.set_name(name);
                }
            }
            NormalizedKind::Assignment => match node.kind() {
                "const_item" | "static_item" => {
                    if let Some(name) = node.child_by_field_name("name") {
                        sink.role_named(Role::Left, name, name);
                        sink.set_name(name);
                    }
                    if let Some(value) = node.child_by_field_name("value") {
                        attach_role_with_derived_name(
                            sink,
                            Role::Right,
                            value,
                            expression_name_node,
                        );
                    }
                }
                "let_declaration" => {
                    if let Some(pattern) = node.child_by_field_name("pattern") {
                        attach_role_with_derived_name(
                            sink,
                            Role::Left,
                            pattern,
                            expression_name_node,
                        );
                        if let Some(name) = expression_name_node(pattern) {
                            sink.set_name(name);
                        }
                    }
                    if let Some(value) = node.child_by_field_name("value") {
                        attach_role_with_derived_name(
                            sink,
                            Role::Right,
                            value,
                            expression_name_node,
                        );
                    }
                }
                "assignment_expression" | "compound_assignment_expr" => {
                    if let Some(left) = node.child_by_field_name("left") {
                        attach_role_with_derived_name(sink, Role::Left, left, expression_name_node);
                    }
                    if let Some(right) = node.child_by_field_name("right") {
                        attach_role_with_derived_name(
                            sink,
                            Role::Right,
                            right,
                            expression_name_node,
                        );
                    }
                }
                _ => {}
            },
            NormalizedKind::Import => {
                if let Some(argument) = node.child_by_field_name("argument") {
                    attach_use_module(sink, argument);
                }
            }
            NormalizedKind::Identifier => match expression_name_node(node) {
                Some(name) => sink.set_name(name),
                None => sink.set_name(node),
            },
            _ => {}
        }
    }
}

#[cfg(test)]
mod structural_spec_tests {
    use super::*;

    #[test]
    fn rust_kind_table_matches_grammar() {
        crate::analyzer::structural::adapter_helpers::assert_kind_table_matches_grammar(
            tree_sitter_rust::LANGUAGE.into(),
            "tree-sitter-rust",
            RUST_KIND_TABLE,
        );
    }
}
