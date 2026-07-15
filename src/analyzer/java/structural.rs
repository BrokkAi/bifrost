//! Java structural spec for `query_code`.
//!
//! This maps tree-sitter-java node types to Bifrost's normalized structural
//! vocabulary and extracts role edges from AST fields.

use crate::analyzer::Language;
use crate::analyzer::structural::adapter_helpers::{
    attach_positional_argument_roles, attach_role_with_derived_name, attach_terminal_callee,
    first_named_child,
};
use crate::analyzer::structural::{NormalizedKind, Role, RoleSink, StructuralSpec};
use tree_sitter::Node;

#[derive(Debug, Default)]
pub(crate) struct JavaStructuralSpec;

pub(crate) static JAVA_STRUCTURAL_SPEC: JavaStructuralSpec = JavaStructuralSpec;

const JAVA_KIND_TABLE: &[(&str, NormalizedKind)] = &[
    ("method_invocation", NormalizedKind::Call),
    ("object_creation_expression", NormalizedKind::Call),
    ("field_access", NormalizedKind::FieldAccess),
    ("method_declaration", NormalizedKind::Method),
    ("constructor_declaration", NormalizedKind::Constructor),
    ("lambda_expression", NormalizedKind::Lambda),
    ("class_declaration", NormalizedKind::Class),
    ("interface_declaration", NormalizedKind::Class),
    ("enum_declaration", NormalizedKind::Class),
    ("record_declaration", NormalizedKind::Class),
    ("annotation_type_declaration", NormalizedKind::Class),
    ("variable_declarator", NormalizedKind::Assignment),
    ("assignment_expression", NormalizedKind::Assignment),
    ("import_declaration", NormalizedKind::Import),
    ("identifier", NormalizedKind::Identifier),
    ("type_identifier", NormalizedKind::Identifier),
    ("scoped_identifier", NormalizedKind::Identifier),
    ("scoped_type_identifier", NormalizedKind::Identifier),
    ("string_literal", NormalizedKind::StringLiteral),
    ("decimal_integer_literal", NormalizedKind::NumericLiteral),
    ("hex_integer_literal", NormalizedKind::NumericLiteral),
    ("octal_integer_literal", NormalizedKind::NumericLiteral),
    ("binary_integer_literal", NormalizedKind::NumericLiteral),
    (
        "decimal_floating_point_literal",
        NormalizedKind::NumericLiteral,
    ),
    ("true", NormalizedKind::BooleanLiteral),
    ("false", NormalizedKind::BooleanLiteral),
    ("null_literal", NormalizedKind::NullLiteral),
    ("return_statement", NormalizedKind::Return),
    ("throw_statement", NormalizedKind::Throw),
    ("catch_clause", NormalizedKind::Catch),
    ("if_statement", NormalizedKind::If),
    ("for_statement", NormalizedKind::Loop),
    ("enhanced_for_statement", NormalizedKind::Loop),
    ("while_statement", NormalizedKind::Loop),
    ("do_statement", NormalizedKind::Loop),
    ("annotation", NormalizedKind::Decorator),
    ("marker_annotation", NormalizedKind::Decorator),
];

fn last_named_child(node: Node<'_>) -> Option<Node<'_>> {
    node.named_child_count()
        .checked_sub(1)
        .and_then(|index| node.named_child(index))
}

fn expression_name_node<'tree>(expression: Node<'tree>) -> Option<Node<'tree>> {
    let mut current = expression;
    loop {
        match current.kind() {
            "identifier" | "type_identifier" | "this" | "super" => return Some(current),
            "scoped_identifier" | "scoped_type_identifier" => {
                current = current
                    .child_by_field_name("name")
                    .or_else(|| last_named_child(current))?;
            }
            "generic_type" => current = current.child_by_field_name("type")?,
            "field_access" => current = current.child_by_field_name("field")?,
            "method_invocation" => current = current.child_by_field_name("name")?,
            "object_creation_expression" => current = current.child_by_field_name("type")?,
            "annotation" | "marker_annotation" => current = current.child_by_field_name("name")?,
            _ => return None,
        }
    }
}

fn attach_decorators(sink: &mut RoleSink<'_>, declaration: Node<'_>) {
    for index in 0..declaration.named_child_count() {
        let Some(child) = declaration.named_child(index) else {
            continue;
        };
        if child.kind() != "modifiers" {
            continue;
        }
        for modifier_index in 0..child.named_child_count() {
            let Some(modifier_child) = child.named_child(modifier_index) else {
                continue;
            };
            if matches!(modifier_child.kind(), "annotation" | "marker_annotation") {
                attach_role_with_derived_name(
                    sink,
                    Role::Decorator,
                    modifier_child,
                    expression_name_node,
                );
            }
        }
    }
}

impl StructuralSpec for JavaStructuralSpec {
    fn language(&self) -> Language {
        Language::Java
    }

    fn kind_table(&self) -> &'static [(&'static str, NormalizedKind)] {
        JAVA_KIND_TABLE
    }

    fn should_extract(&self, node: Node<'_>, kind: NormalizedKind) -> bool {
        kind != NormalizedKind::Assignment
            || node.kind() != "variable_declarator"
            || node.child_by_field_name("value").is_some()
    }

    fn supports_role(&self, role: Role) -> bool {
        role != Role::Kwarg
    }

    fn extract(&self, node: Node<'_>, kind: NormalizedKind, sink: &mut RoleSink<'_>) {
        match kind {
            NormalizedKind::Call => {
                match node.kind() {
                    "method_invocation" => {
                        if let Some(name) = node.child_by_field_name("name") {
                            attach_terminal_callee(sink, name, Some(name));
                        }
                        if let Some(object) = node.child_by_field_name("object") {
                            attach_role_with_derived_name(
                                sink,
                                Role::Receiver,
                                object,
                                expression_name_node,
                            );
                        }
                    }
                    "object_creation_expression" => {
                        if let Some(type_node) = node.child_by_field_name("type") {
                            attach_role_with_derived_name(
                                sink,
                                Role::Callee,
                                type_node,
                                expression_name_node,
                            );
                            if let Some(name) = expression_name_node(type_node) {
                                sink.set_name(name);
                            }
                        }
                    }
                    _ => {}
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
                if let Some(object) = node.child_by_field_name("object") {
                    attach_role_with_derived_name(sink, Role::Object, object, expression_name_node);
                }
            }
            NormalizedKind::Method | NormalizedKind::Constructor | NormalizedKind::Class => {
                if let Some(name) = node.child_by_field_name("name") {
                    sink.set_name(name);
                }
                attach_decorators(sink, node);
            }
            NormalizedKind::Assignment => match node.kind() {
                "variable_declarator" => {
                    if let Some(name) = node.child_by_field_name("name") {
                        sink.set_name(name);
                        sink.role_named(Role::Left, name, name);
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
                "assignment_expression" => {
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
                for index in 0..node.named_child_count() {
                    let Some(child) = node.named_child(index) else {
                        continue;
                    };
                    if matches!(
                        child.kind(),
                        "identifier" | "scoped_identifier" | "field_access"
                    ) {
                        sink.role_named(Role::Module, child, child);
                        break;
                    }
                }
            }
            NormalizedKind::Identifier => match node.kind() {
                "scoped_identifier" | "scoped_type_identifier" => {
                    if let Some(name) = node
                        .child_by_field_name("name")
                        .or_else(|| last_named_child(node))
                    {
                        sink.set_name(name);
                    }
                }
                _ => sink.set_name(node),
            },
            NormalizedKind::Decorator => {
                if let Some(name) = expression_name_node(node) {
                    sink.set_name(name);
                }
            }
            NormalizedKind::Lambda => {
                attach_decorators(sink, node);
            }
            _ => {
                if let Some(name) = first_named_child(node).and_then(expression_name_node) {
                    sink.set_name(name);
                }
            }
        }
    }
}

#[cfg(test)]
mod structural_spec_tests {
    use super::*;

    #[test]
    fn java_kind_table_matches_grammar() {
        crate::analyzer::structural::adapter_helpers::assert_kind_table_matches_grammar(
            tree_sitter_java::LANGUAGE.into(),
            "tree-sitter-java",
            JAVA_KIND_TABLE,
        );
    }
}
