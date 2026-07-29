//! Go structural spec for `query_code`.

use crate::analyzer::Language;
use crate::analyzer::structural::adapter_helpers::{
    attach_positional_argument_roles, attach_role_with_derived_name, attach_terminal_callee,
    first_named_child,
};
use crate::analyzer::structural::{NormalizedKind, Role, RoleSink, Span, StructuralSpec};
use tree_sitter::Node;

#[derive(Debug, Default)]
pub(crate) struct GoStructuralSpec;

pub(crate) static GO_STRUCTURAL_SPEC: GoStructuralSpec = GoStructuralSpec;

const GO_KIND_TABLE: &[(&str, NormalizedKind)] = &[
    ("call_expression", NormalizedKind::Call),
    ("selector_expression", NormalizedKind::FieldAccess),
    ("function_declaration", NormalizedKind::Function),
    ("method_declaration", NormalizedKind::Method),
    ("func_literal", NormalizedKind::Lambda),
    ("type_spec", NormalizedKind::Class),
    ("type_alias", NormalizedKind::Declaration),
    ("assignment_statement", NormalizedKind::Assignment),
    ("short_var_declaration", NormalizedKind::Assignment),
    ("var_spec", NormalizedKind::Assignment),
    ("const_spec", NormalizedKind::Assignment),
    ("import_declaration", NormalizedKind::Import),
    ("identifier", NormalizedKind::Identifier),
    ("field_identifier", NormalizedKind::Identifier),
    ("package_identifier", NormalizedKind::Identifier),
    ("type_identifier", NormalizedKind::Identifier),
    ("interpreted_string_literal", NormalizedKind::StringLiteral),
    ("raw_string_literal", NormalizedKind::StringLiteral),
    ("int_literal", NormalizedKind::NumericLiteral),
    ("float_literal", NormalizedKind::NumericLiteral),
    ("true", NormalizedKind::BooleanLiteral),
    ("false", NormalizedKind::BooleanLiteral),
    ("nil", NormalizedKind::NullLiteral),
    ("return_statement", NormalizedKind::Return),
    ("if_statement", NormalizedKind::If),
    ("for_statement", NormalizedKind::Loop),
];

fn expression_name_node<'tree>(expression: Node<'tree>) -> Option<Node<'tree>> {
    let mut current = expression;
    loop {
        match current.kind() {
            "identifier" | "field_identifier" | "package_identifier" | "type_identifier" => {
                return Some(current);
            }
            "selector_expression" => current = current.child_by_field_name("field")?,
            "call_expression" => current = current.child_by_field_name("function")?,
            "qualified_type" => current = current.child_by_field_name("name")?,
            "parenthesized_expression" | "expression_list" => current = first_named_child(current)?,
            _ => return None,
        }
    }
}

fn unquoted_go_string_span(node: Node<'_>) -> Option<Span> {
    if !matches!(
        node.kind(),
        "interpreted_string_literal" | "raw_string_literal"
    ) {
        return None;
    }
    let start = node.start_byte().checked_add(1)?;
    let end = node.end_byte().checked_sub(1)?;
    (start <= end).then_some(Span {
        start_byte: start,
        end_byte: end,
    })
}

fn attach_import_spec_module(sink: &mut RoleSink<'_>, import_spec: Node<'_>) {
    if let Some(path) = import_spec.child_by_field_name("path") {
        if let Some(name) = unquoted_go_string_span(path) {
            sink.role_named_span(Role::Module, path, name);
        } else {
            sink.role(Role::Module, path);
        }
    }
}

fn attach_import_modules(sink: &mut RoleSink<'_>, import: Node<'_>) {
    if import.kind() == "import_spec" {
        attach_import_spec_module(sink, import);
        return;
    }

    for index in 0..import.named_child_count() {
        let Some(child) = import.named_child(index) else {
            continue;
        };
        match child.kind() {
            "import_spec" => attach_import_spec_module(sink, child),
            "import_spec_list" => {
                for spec_index in 0..child.named_child_count() {
                    let Some(spec) = child.named_child(spec_index) else {
                        continue;
                    };
                    if spec.kind() == "import_spec" {
                        attach_import_spec_module(sink, spec);
                    }
                }
            }
            _ => {}
        }
    }
}

fn attach_role_target<'tree>(
    sink: &mut RoleSink<'_>,
    role: Role,
    target: Node<'tree>,
    first_name: &mut Option<Node<'tree>>,
) {
    attach_role_with_derived_name(sink, role, target, expression_name_node);
    if first_name.is_none() {
        *first_name = expression_name_node(target);
    }
}

fn attach_role_targets<'tree>(
    sink: &mut RoleSink<'_>,
    role: Role,
    target: Node<'tree>,
) -> Option<Node<'tree>> {
    let mut first_name = None;
    if target.kind() == "expression_list" {
        for index in 0..target.named_child_count() {
            let Some(child) = target.named_child(index) else {
                continue;
            };
            attach_role_target(sink, role, child, &mut first_name);
        }
    } else {
        attach_role_target(sink, role, target, &mut first_name);
    }
    first_name
}

fn attach_name_field_targets<'tree>(
    sink: &mut RoleSink<'_>,
    role: Role,
    node: Node<'tree>,
) -> Option<Node<'tree>> {
    let mut first_name = None;
    let mut cursor = node.walk();
    for name in node.children_by_field_name("name", &mut cursor) {
        if !name.is_named() {
            continue;
        }
        attach_role_target(sink, role, name, &mut first_name);
    }
    first_name
}

fn attach_value_field_targets<'tree>(
    sink: &mut RoleSink<'_>,
    role: Role,
    node: Node<'tree>,
    field: &str,
) -> Option<Node<'tree>> {
    node.child_by_field_name(field)
        .and_then(|target| attach_role_targets(sink, role, target))
}

impl StructuralSpec for GoStructuralSpec {
    fn language(&self) -> Language {
        Language::Go
    }

    fn kind_table(&self) -> &'static [(&'static str, NormalizedKind)] {
        GO_KIND_TABLE
    }

    fn should_extract(&self, node: Node<'_>, kind: NormalizedKind) -> bool {
        kind != NormalizedKind::Assignment
            || !matches!(node.kind(), "var_spec" | "const_spec")
            || node.child_by_field_name("value").is_some()
    }

    fn supports_role(&self, role: Role) -> bool {
        !matches!(role, Role::Kwarg | Role::Decorator)
    }

    fn extract(&self, node: Node<'_>, kind: NormalizedKind, sink: &mut RoleSink<'_>) {
        match kind {
            NormalizedKind::Call => {
                if let Some(function) = node.child_by_field_name("function") {
                    attach_terminal_callee(sink, function, expression_name_node(function));
                    if function.kind() == "selector_expression"
                        && let Some(operand) = function.child_by_field_name("operand")
                    {
                        attach_role_with_derived_name(
                            sink,
                            Role::Receiver,
                            operand,
                            expression_name_node,
                        );
                    }
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
                if let Some(operand) = node.child_by_field_name("operand") {
                    attach_role_with_derived_name(
                        sink,
                        Role::Object,
                        operand,
                        expression_name_node,
                    );
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
            NormalizedKind::Assignment => {
                let first_left_name = match node.kind() {
                    "var_spec" | "const_spec" => attach_name_field_targets(sink, Role::Left, node),
                    _ => attach_value_field_targets(sink, Role::Left, node, "left"),
                };
                if let Some(name) = first_left_name {
                    sink.set_name(name);
                }
                match node.kind() {
                    "var_spec" | "const_spec" => {
                        attach_value_field_targets(sink, Role::Right, node, "value");
                    }
                    _ => {
                        attach_value_field_targets(sink, Role::Right, node, "right");
                    }
                }
            }
            NormalizedKind::Import => attach_import_modules(sink, node),
            NormalizedKind::Identifier => sink.set_name(node),
            _ => {}
        }
    }
}

#[cfg(test)]
mod structural_spec_tests {
    use super::*;

    #[test]
    fn go_kind_table_matches_grammar() {
        crate::analyzer::structural::adapter_helpers::assert_kind_table_matches_grammar(
            tree_sitter_go::LANGUAGE.into(),
            "tree-sitter-go",
            GO_KIND_TABLE,
        );
    }
}
