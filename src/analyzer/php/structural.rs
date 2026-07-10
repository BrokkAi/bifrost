//! PHP structural spec for `query_code`.

use crate::analyzer::Language;
use crate::analyzer::structural::adapter_helpers::{
    attach_role_with_derived_name, attach_terminal_callee, first_named_child,
};
use crate::analyzer::structural::{NormalizedKind, Role, RoleSink, StructuralSpec};
use tree_sitter::Node;

#[derive(Debug, Default)]
pub(crate) struct PhpStructuralSpec;

pub(crate) static PHP_STRUCTURAL_SPEC: PhpStructuralSpec = PhpStructuralSpec;

const PHP_KIND_TABLE: &[(&str, NormalizedKind)] = &[
    ("function_call_expression", NormalizedKind::Call),
    ("member_call_expression", NormalizedKind::Call),
    ("nullsafe_member_call_expression", NormalizedKind::Call),
    ("scoped_call_expression", NormalizedKind::Call),
    ("object_creation_expression", NormalizedKind::Call),
    ("member_access_expression", NormalizedKind::FieldAccess),
    (
        "nullsafe_member_access_expression",
        NormalizedKind::FieldAccess,
    ),
    (
        "scoped_property_access_expression",
        NormalizedKind::FieldAccess,
    ),
    (
        "class_constant_access_expression",
        NormalizedKind::FieldAccess,
    ),
    ("function_definition", NormalizedKind::Function),
    ("method_declaration", NormalizedKind::Method),
    ("anonymous_function", NormalizedKind::Lambda),
    ("arrow_function", NormalizedKind::Lambda),
    ("class_declaration", NormalizedKind::Class),
    ("interface_declaration", NormalizedKind::Class),
    ("trait_declaration", NormalizedKind::Class),
    ("enum_declaration", NormalizedKind::Class),
    ("property_element", NormalizedKind::Assignment),
    ("const_element", NormalizedKind::Assignment),
    ("assignment_expression", NormalizedKind::Assignment),
    (
        "augmented_assignment_expression",
        NormalizedKind::Assignment,
    ),
    (
        "reference_assignment_expression",
        NormalizedKind::Assignment,
    ),
    ("namespace_use_declaration", NormalizedKind::Import),
    ("attribute", NormalizedKind::Decorator),
    ("name", NormalizedKind::Identifier),
    ("namespace_name", NormalizedKind::Identifier),
    ("qualified_name", NormalizedKind::Identifier),
    ("relative_scope", NormalizedKind::Identifier),
    ("variable_name", NormalizedKind::Identifier),
    ("string", NormalizedKind::StringLiteral),
    ("encapsed_string", NormalizedKind::StringLiteral),
    ("unary_op_expression", NormalizedKind::NumericLiteral),
    ("integer", NormalizedKind::NumericLiteral),
    ("float", NormalizedKind::NumericLiteral),
    ("boolean", NormalizedKind::BooleanLiteral),
    ("null", NormalizedKind::NullLiteral),
    ("return_statement", NormalizedKind::Return),
    ("throw_expression", NormalizedKind::Throw),
    ("catch_clause", NormalizedKind::Catch),
    ("if_statement", NormalizedKind::If),
    ("for_statement", NormalizedKind::Loop),
    ("foreach_statement", NormalizedKind::Loop),
    ("while_statement", NormalizedKind::Loop),
    ("do_statement", NormalizedKind::Loop),
];

fn last_named_child<'tree>(node: Node<'tree>) -> Option<Node<'tree>> {
    (0..node.named_child_count())
        .rev()
        .find_map(|index| node.named_child(index))
}

fn expression_target_node(mut node: Node<'_>) -> Node<'_> {
    while matches!(node.kind(), "expression" | "parenthesized_expression") {
        let Some(child) = first_named_child(node) else {
            break;
        };
        node = child;
    }
    node
}

fn expression_name_node<'tree>(expression: Node<'tree>) -> Option<Node<'tree>> {
    let mut current = expression_target_node(expression);
    loop {
        match current.kind() {
            "name" | "relative_scope" => return Some(current),
            "namespace_name" | "qualified_name" => current = last_named_child(current)?,
            "variable_name" | "named_type" => current = first_named_child(current)?,
            "function_call_expression" => current = current.child_by_field_name("function")?,
            "member_call_expression" | "nullsafe_member_call_expression" => {
                current = current.child_by_field_name("name")?;
            }
            "scoped_call_expression"
            | "member_access_expression"
            | "nullsafe_member_access_expression"
            | "scoped_property_access_expression" => {
                current = current.child_by_field_name("name")?
            }
            "class_constant_access_expression" => current = last_named_child(current)?,
            "object_creation_expression" => current = object_creation_callee(current)?,
            _ => return None,
        }
    }
}

fn is_numeric_literal_node(node: Node<'_>) -> bool {
    matches!(node.kind(), "integer" | "float")
}

fn unary_argument(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("argument")
        .map(expression_target_node)
        .or_else(|| first_named_child(node).map(expression_target_node))
}

fn is_signed_numeric_unary(node: Node<'_>) -> bool {
    node.kind() == "unary_op_expression"
        && node
            .child_by_field_name("operator")
            .is_some_and(|operator| matches!(operator.kind(), "+" | "-"))
        && unary_argument(node).is_some_and(is_numeric_literal_node)
}

fn is_inside_signed_numeric_wrapper(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    is_signed_numeric_unary(parent)
}

fn object_creation_callee(node: Node<'_>) -> Option<Node<'_>> {
    for index in 0..node.named_child_count() {
        let child = node.named_child(index)?;
        if child.kind() == "arguments" {
            continue;
        }
        return Some(child);
    }
    None
}

fn object_creation_arguments(node: Node<'_>) -> Option<Node<'_>> {
    (0..node.named_child_count())
        .filter_map(|index| node.named_child(index))
        .find(|child| child.kind() == "arguments")
}

fn argument_value_node<'tree>(
    argument: Node<'tree>,
    keyword: Option<Node<'tree>>,
) -> Option<Node<'tree>> {
    (0..argument.named_child_count())
        .filter_map(|index| argument.named_child(index))
        .find(|child| {
            keyword.is_none_or(|keyword| child.id() != keyword.id())
                && !matches!(child.kind(), "reference_modifier" | "variadic_unpacking")
        })
        .map(expression_target_node)
}

fn attach_argument_roles(sink: &mut RoleSink<'_>, arguments: Node<'_>) {
    for index in 0..arguments.named_child_count() {
        let Some(argument) = arguments.named_child(index) else {
            continue;
        };
        if argument.kind() != "argument" {
            continue;
        }
        let keyword = argument.child_by_field_name("name");
        if let Some(value) = argument_value_node(argument, keyword) {
            if let Some(keyword) = keyword {
                sink.kwarg(keyword, value);
            } else {
                attach_role_with_derived_name(sink, Role::Arg, value, expression_name_node);
            }
        }
    }
}

fn attach_decorators(sink: &mut RoleSink<'_>, declaration: Node<'_>) {
    let Some(attributes) = declaration.child_by_field_name("attributes") else {
        return;
    };
    let mut stack = vec![attributes];
    while let Some(node) = stack.pop() {
        if node.kind() == "attribute" {
            attach_role_with_derived_name(sink, Role::Decorator, node, expression_name_node);
            continue;
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
}

fn first_child_named_kind<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    (0..node.named_child_count())
        .filter_map(|index| node.named_child(index))
        .find(|child| child.kind() == kind)
}

fn first_child_not_named_kind<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    (0..node.named_child_count())
        .filter_map(|index| node.named_child(index))
        .find(|child| child.kind() != kind)
}

fn last_import_clause_name(node: Node<'_>) -> Option<Node<'_>> {
    (0..node.named_child_count())
        .rev()
        .filter_map(|index| node.named_child(index))
        .find(|child| matches!(child.kind(), "name" | "qualified_name"))
}

fn attach_module_binding(sink: &mut RoleSink<'_>, module: Node<'_>) {
    sink.role_named(Role::Module, module, module);
    if let Some(name) = expression_name_node(module)
        && name.id() != module.id()
    {
        sink.role_named(Role::Module, module, name);
    }
}

fn attach_import_modules(sink: &mut RoleSink<'_>, node: Node<'_>) {
    match node.kind() {
        "namespace_use_clause" => {
            if let Some(module) = node
                .child_by_field_name("alias")
                .or_else(|| last_import_clause_name(node))
            {
                attach_module_binding(sink, module);
            }
        }
        "namespace_use_group" => {
            for index in 0..node.named_child_count() {
                let Some(child) = node.named_child(index) else {
                    continue;
                };
                if child.kind() == "namespace_use_clause" {
                    attach_import_modules(sink, child);
                }
            }
        }
        "namespace_use_declaration" => {
            if let Some(group) = node.child_by_field_name("body") {
                attach_import_modules(sink, group);
                return;
            }
            for index in 0..node.named_child_count() {
                let Some(child) = node.named_child(index) else {
                    continue;
                };
                if child.kind() == "namespace_use_clause" {
                    attach_import_modules(sink, child);
                }
            }
        }
        _ => {}
    }
}

fn const_element_value(node: Node<'_>) -> Option<Node<'_>> {
    first_child_not_named_kind(node, "name").map(expression_target_node)
}

impl StructuralSpec for PhpStructuralSpec {
    fn language(&self) -> Language {
        Language::Php
    }

    fn kind_table(&self) -> &'static [(&'static str, NormalizedKind)] {
        PHP_KIND_TABLE
    }

    fn refine_kind(
        &self,
        node: Node<'_>,
        kind: NormalizedKind,
        _enclosing: Option<NormalizedKind>,
        source: &str,
    ) -> NormalizedKind {
        if kind == NormalizedKind::Method
            && node
                .child_by_field_name("name")
                .and_then(|name| name.utf8_text(source.as_bytes()).ok())
                .is_some_and(|name| name == "__construct")
        {
            NormalizedKind::Constructor
        } else {
            kind
        }
    }

    fn should_extract(&self, node: Node<'_>, kind: NormalizedKind) -> bool {
        if kind == NormalizedKind::NumericLiteral {
            if node.kind() == "unary_op_expression" {
                return is_signed_numeric_unary(node);
            }
            if is_numeric_literal_node(node) && is_inside_signed_numeric_wrapper(node) {
                return false;
            }
        }

        kind != NormalizedKind::Assignment
            || match node.kind() {
                "property_element" => node.child_by_field_name("default_value").is_some(),
                "const_element" => const_element_value(node).is_some(),
                _ => true,
            }
    }

    fn supports_kind(&self, kind: NormalizedKind) -> bool {
        kind == NormalizedKind::Constructor
            || self
                .kind_table()
                .iter()
                .any(|(_, fact_kind)| fact_kind.satisfies(kind))
    }

    fn extract(&self, node: Node<'_>, kind: NormalizedKind, sink: &mut RoleSink<'_>) {
        match kind {
            NormalizedKind::Call => {
                let function = if node.kind() == "object_creation_expression" {
                    object_creation_callee(node)
                } else {
                    node.child_by_field_name("function")
                        .or_else(|| node.child_by_field_name("name"))
                };
                if let Some(function) = function {
                    attach_terminal_callee(sink, function, expression_name_node(function));
                }
                let receiver = match node.kind() {
                    "member_call_expression" | "nullsafe_member_call_expression" => {
                        node.child_by_field_name("object")
                    }
                    "scoped_call_expression" => node.child_by_field_name("scope"),
                    _ => None,
                };
                if let Some(receiver) = receiver {
                    attach_role_with_derived_name(
                        sink,
                        Role::Receiver,
                        receiver,
                        expression_name_node,
                    );
                }
                let arguments = if node.kind() == "object_creation_expression" {
                    object_creation_arguments(node)
                } else {
                    node.child_by_field_name("arguments")
                };
                if let Some(arguments) = arguments {
                    attach_argument_roles(sink, arguments);
                }
            }
            NormalizedKind::FieldAccess => {
                let field = if node.kind() == "class_constant_access_expression" {
                    last_named_child(node)
                } else {
                    node.child_by_field_name("name")
                };
                if let Some(field) = field {
                    attach_role_with_derived_name(sink, Role::Field, field, expression_name_node);
                    if let Some(name) = expression_name_node(field) {
                        sink.set_name(name);
                    }
                }
                let object = if node.kind() == "class_constant_access_expression" {
                    first_named_child(node)
                } else {
                    node.child_by_field_name("object")
                        .or_else(|| node.child_by_field_name("scope"))
                };
                if let Some(object) = object {
                    attach_role_with_derived_name(sink, Role::Object, object, expression_name_node);
                }
            }
            NormalizedKind::Function
            | NormalizedKind::Method
            | NormalizedKind::Constructor
            | NormalizedKind::Class => {
                if let Some(name) = node.child_by_field_name("name") {
                    sink.set_name(name);
                }
                attach_decorators(sink, node);
            }
            NormalizedKind::Lambda => attach_decorators(sink, node),
            NormalizedKind::Assignment => match node.kind() {
                "property_element" => {
                    if let Some(name) = node.child_by_field_name("name") {
                        attach_role_with_derived_name(sink, Role::Left, name, expression_name_node);
                        if let Some(name) = expression_name_node(name) {
                            sink.set_name(name);
                        }
                    }
                    if let Some(value) = node.child_by_field_name("default_value") {
                        let value = expression_target_node(value);
                        attach_role_with_derived_name(
                            sink,
                            Role::Right,
                            value,
                            expression_name_node,
                        );
                    }
                }
                "const_element" => {
                    if let Some(name) = first_child_named_kind(node, "name") {
                        sink.role_named(Role::Left, name, name);
                        sink.set_name(name);
                    }
                    if let Some(value) = const_element_value(node) {
                        attach_role_with_derived_name(
                            sink,
                            Role::Right,
                            value,
                            expression_name_node,
                        );
                    }
                }
                _ => {
                    if let Some(left) = node.child_by_field_name("left") {
                        let left = expression_target_node(left);
                        attach_role_with_derived_name(sink, Role::Left, left, expression_name_node);
                        if let Some(name) = expression_name_node(left) {
                            sink.set_name(name);
                        }
                    }
                    if let Some(right) = node.child_by_field_name("right") {
                        let right = expression_target_node(right);
                        attach_role_with_derived_name(
                            sink,
                            Role::Right,
                            right,
                            expression_name_node,
                        );
                    }
                }
            },
            NormalizedKind::Import => attach_import_modules(sink, node),
            NormalizedKind::Decorator => {
                if let Some(name) = first_named_child(node) {
                    attach_terminal_callee(sink, name, expression_name_node(name));
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
    fn php_kind_table_matches_grammar() {
        crate::analyzer::structural::adapter_helpers::assert_kind_table_matches_grammar(
            tree_sitter_php::LANGUAGE_PHP.into(),
            "tree-sitter-php",
            PHP_KIND_TABLE,
        );
    }
}
