//! C# structural spec for `query_code`.

use crate::analyzer::Language;
use crate::analyzer::csharp_conditional_member_access;
use crate::analyzer::structural::adapter_helpers::{
    attach_role_with_derived_name, attach_terminal_callee, first_named_child,
};
use crate::analyzer::structural::{NormalizedKind, Role, RoleSink, Span, StructuralSpec};
use tree_sitter::Node;

#[derive(Debug, Default)]
pub(crate) struct CSharpStructuralSpec;

pub(crate) static CSHARP_STRUCTURAL_SPEC: CSharpStructuralSpec = CSharpStructuralSpec;

const CSHARP_KIND_TABLE: &[(&str, NormalizedKind)] = &[
    ("invocation_expression", NormalizedKind::Call),
    ("object_creation_expression", NormalizedKind::Call),
    ("member_access_expression", NormalizedKind::FieldAccess),
    ("conditional_access_expression", NormalizedKind::FieldAccess),
    ("method_declaration", NormalizedKind::Method),
    ("constructor_declaration", NormalizedKind::Constructor),
    ("local_function_statement", NormalizedKind::Function),
    ("lambda_expression", NormalizedKind::Lambda),
    ("anonymous_method_expression", NormalizedKind::Lambda),
    ("class_declaration", NormalizedKind::Class),
    ("interface_declaration", NormalizedKind::Class),
    ("struct_declaration", NormalizedKind::Class),
    ("enum_declaration", NormalizedKind::Class),
    ("record_declaration", NormalizedKind::Class),
    ("property_declaration", NormalizedKind::Declaration),
    ("variable_declarator", NormalizedKind::Assignment),
    ("assignment_expression", NormalizedKind::Assignment),
    ("using_directive", NormalizedKind::Import),
    ("attribute", NormalizedKind::Decorator),
    ("identifier", NormalizedKind::Identifier),
    ("generic_name", NormalizedKind::Identifier),
    ("qualified_name", NormalizedKind::Identifier),
    ("alias_qualified_name", NormalizedKind::Identifier),
    ("predefined_type", NormalizedKind::Identifier),
    ("string_literal", NormalizedKind::StringLiteral),
    ("verbatim_string_literal", NormalizedKind::StringLiteral),
    ("raw_string_literal", NormalizedKind::StringLiteral),
    ("character_literal", NormalizedKind::StringLiteral),
    ("prefix_unary_expression", NormalizedKind::NumericLiteral),
    ("integer_literal", NormalizedKind::NumericLiteral),
    ("real_literal", NormalizedKind::NumericLiteral),
    ("boolean_literal", NormalizedKind::BooleanLiteral),
    ("null_literal", NormalizedKind::NullLiteral),
    ("return_statement", NormalizedKind::Return),
    ("throw_statement", NormalizedKind::Throw),
    ("throw_expression", NormalizedKind::Throw),
    ("catch_clause", NormalizedKind::Catch),
    ("if_statement", NormalizedKind::If),
    ("switch_statement", NormalizedKind::If),
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
            "identifier" | "predefined_type" => return Some(current),
            "generic_name" => current = first_named_child(current)?,
            "qualified_name" | "alias_qualified_name" => {
                current = current.child_by_field_name("name")?;
            }
            "invocation_expression" => current = current.child_by_field_name("function")?,
            "object_creation_expression" => current = current.child_by_field_name("type")?,
            "member_access_expression" => current = current.child_by_field_name("name")?,
            "conditional_access_expression" => current = conditional_member_binding(current)?,
            "member_binding_expression" => current = current.child_by_field_name("name")?,
            "argument" | "attribute_argument" => {
                current = first_argument_value(current).map(expression_target_node)?;
            }
            _ => return None,
        }
    }
}

fn is_numeric_literal_node(node: Node<'_>) -> bool {
    matches!(node.kind(), "integer_literal" | "real_literal")
}

fn is_signed_numeric_prefix(node: Node<'_>) -> bool {
    node.kind() == "prefix_unary_expression"
        && last_named_child(node)
            .map(expression_target_node)
            .is_some_and(is_numeric_literal_node)
        && (0..node.child_count())
            .filter_map(|index| node.child(index))
            .any(|child| !child.is_named() && matches!(child.kind(), "+" | "-"))
}

fn is_inside_signed_numeric_wrapper(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    is_signed_numeric_prefix(parent)
}

fn callable_target_node(node: Node<'_>) -> Option<Node<'_>> {
    Some(expression_target_node(node))
}

fn conditional_member_binding(node: Node<'_>) -> Option<Node<'_>> {
    csharp_conditional_member_access(node).map(|access| access.binding)
}

fn first_argument_value(argument: Node<'_>) -> Option<Node<'_>> {
    let keyword = argument.child_by_field_name("name");
    (0..argument.named_child_count())
        .filter_map(|index| argument.named_child(index))
        .find(|child| keyword.is_none_or(|keyword| child.id() != keyword.id()))
}

fn attach_argument_roles(sink: &mut RoleSink<'_>, arguments: Node<'_>) {
    for index in 0..arguments.named_child_count() {
        if !sink.should_continue() {
            break;
        }
        let Some(argument) = arguments.named_child(index) else {
            continue;
        };
        if argument.kind() != "argument" {
            continue;
        }
        let keyword = argument.child_by_field_name("name");
        if let Some(value) = first_argument_value(argument).map(expression_target_node) {
            if let Some(keyword) = keyword {
                sink.kwarg(keyword, value);
            } else {
                attach_role_with_derived_name(sink, Role::Arg, value, expression_name_node);
            }
        }
    }
}

fn attach_decorators(sink: &mut RoleSink<'_>, declaration: Node<'_>) {
    for index in 0..declaration.named_child_count() {
        let Some(child) = declaration.named_child(index) else {
            continue;
        };
        if child.kind() != "attribute_list" {
            continue;
        }
        for attr_index in 0..child.named_child_count() {
            if let Some(attribute) = child.named_child(attr_index)
                && attribute.kind() == "attribute"
            {
                attach_role_with_derived_name(
                    sink,
                    Role::Decorator,
                    attribute,
                    expression_name_node,
                );
            }
        }
    }
}

fn variable_declarator_value(node: Node<'_>) -> Option<Node<'_>> {
    let name = node.child_by_field_name("name");
    (0..node.named_child_count())
        .filter_map(|index| node.named_child(index))
        .find(|child| {
            name.is_none_or(|name| child.id() != name.id())
                && child.kind() != "bracketed_argument_list"
        })
        .map(expression_target_node)
}

fn using_type_node(node: Node<'_>) -> Option<Node<'_>> {
    let alias = node.child_by_field_name("name");
    (0..node.named_child_count())
        .filter_map(|index| node.named_child(index))
        .find(|child| alias.is_none_or(|alias| child.id() != alias.id()))
}

fn span_from(first: Node<'_>, last: Node<'_>) -> Span {
    Span {
        start_byte: first.start_byte(),
        end_byte: last.end_byte(),
    }
}

fn leftmost_name_node(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        match node.kind() {
            "identifier" | "predefined_type" => return Some(node),
            "generic_name" | "qualified_name" | "alias_qualified_name" => {
                node = node
                    .child_by_field_name("qualifier")
                    .or_else(|| node.child_by_field_name("alias"))
                    .or_else(|| first_named_child(node))?;
            }
            _ => return first_named_child(node),
        }
    }
}

fn attach_module_binding(sink: &mut RoleSink<'_>, target: Node<'_>, name: Node<'_>) {
    sink.role_named(Role::Module, target, name);
    if let Some(first) = leftmost_name_node(target)
        && first.id() != name.id()
    {
        sink.role_named_span(Role::Module, target, span_from(first, name));
    }
}

fn attach_import_modules(sink: &mut RoleSink<'_>, node: Node<'_>) {
    if let Some(alias) = node.child_by_field_name("name") {
        sink.role_named(Role::Module, node, alias);
        return;
    }
    if let Some(target) = using_type_node(node)
        && let Some(name) = expression_name_node(target)
    {
        attach_module_binding(sink, target, name);
    }
}

impl StructuralSpec for CSharpStructuralSpec {
    fn language(&self) -> Language {
        Language::CSharp
    }

    fn kind_table(&self) -> &'static [(&'static str, NormalizedKind)] {
        CSHARP_KIND_TABLE
    }

    fn should_extract(&self, node: Node<'_>, kind: NormalizedKind) -> bool {
        if kind == NormalizedKind::FieldAccess && node.kind() == "conditional_access_expression" {
            return conditional_member_binding(node).is_some();
        }

        if kind == NormalizedKind::NumericLiteral {
            if node.kind() == "prefix_unary_expression" {
                return is_signed_numeric_prefix(node);
            }
            if is_numeric_literal_node(node) && is_inside_signed_numeric_wrapper(node) {
                return false;
            }
        }

        kind != NormalizedKind::Assignment
            || node.kind() != "variable_declarator"
            || variable_declarator_value(node).is_some()
    }

    fn extract(&self, node: Node<'_>, kind: NormalizedKind, sink: &mut RoleSink<'_>) {
        match kind {
            NormalizedKind::Call => {
                let function = if node.kind() == "object_creation_expression" {
                    node.child_by_field_name("type")
                } else {
                    node.child_by_field_name("function")
                };
                if let Some(function) = function {
                    attach_terminal_callee(sink, function, expression_name_node(function));
                    if let Some(target) = callable_target_node(function)
                        && target.kind() == "member_access_expression"
                        && let Some(receiver) = target.child_by_field_name("expression")
                    {
                        attach_role_with_derived_name(
                            sink,
                            Role::Receiver,
                            receiver,
                            expression_name_node,
                        );
                    }
                    if let Some(target) = callable_target_node(function)
                        && target.kind() == "conditional_access_expression"
                        && let Some(receiver) = target.child_by_field_name("condition")
                    {
                        attach_role_with_derived_name(
                            sink,
                            Role::Receiver,
                            receiver,
                            expression_name_node,
                        );
                    }
                }
                if let Some(arguments) = node.child_by_field_name("arguments") {
                    attach_argument_roles(sink, arguments);
                }
            }
            NormalizedKind::FieldAccess => {
                let field = if node.kind() == "conditional_access_expression" {
                    conditional_member_binding(node)
                        .and_then(|binding| binding.child_by_field_name("name"))
                } else {
                    node.child_by_field_name("name")
                };
                if let Some(field) = field {
                    attach_role_with_derived_name(sink, Role::Field, field, expression_name_node);
                    if let Some(name) = expression_name_node(field) {
                        sink.set_name(name);
                    }
                }
                let object = if node.kind() == "conditional_access_expression" {
                    node.child_by_field_name("condition")
                } else {
                    node.child_by_field_name("expression")
                };
                if let Some(object) = object {
                    attach_role_with_derived_name(sink, Role::Object, object, expression_name_node);
                }
            }
            NormalizedKind::Function
            | NormalizedKind::Method
            | NormalizedKind::Constructor
            | NormalizedKind::Class
            | NormalizedKind::Declaration => {
                if let Some(name) = node.child_by_field_name("name") {
                    sink.set_name(name);
                }
                attach_decorators(sink, node);
            }
            NormalizedKind::Assignment => match node.kind() {
                "variable_declarator" => {
                    if let Some(name) = node.child_by_field_name("name") {
                        sink.role_named(Role::Left, name, name);
                        sink.set_name(name);
                    }
                    if let Some(value) = variable_declarator_value(node) {
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
                if let Some(name) = node.child_by_field_name("name") {
                    attach_terminal_callee(sink, name, expression_name_node(name).or(Some(name)));
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
    fn csharp_kind_table_matches_grammar() {
        crate::analyzer::structural::adapter_helpers::assert_kind_table_matches_grammar(
            tree_sitter_c_sharp::LANGUAGE.into(),
            "tree-sitter-c-sharp",
            CSHARP_KIND_TABLE,
        );
    }
}
