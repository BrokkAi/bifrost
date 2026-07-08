//! C++ structural spec for `search_ast`.

use crate::analyzer::Language;
use crate::analyzer::structural::adapter_helpers::{
    attach_positional_argument_roles, attach_role_with_derived_name, attach_terminal_callee,
    first_named_child,
};
use crate::analyzer::structural::{NormalizedKind, Role, RoleSink, Span, StructuralSpec};
use tree_sitter::Node;

#[derive(Debug, Default)]
pub(crate) struct CppStructuralSpec;

pub(crate) static CPP_STRUCTURAL_SPEC: CppStructuralSpec = CppStructuralSpec;

const CPP_KIND_TABLE: &[(&str, NormalizedKind)] = &[
    ("call_expression", NormalizedKind::Call),
    ("new_expression", NormalizedKind::Call),
    ("field_expression", NormalizedKind::FieldAccess),
    ("function_definition", NormalizedKind::Function),
    ("lambda_expression", NormalizedKind::Lambda),
    ("class_specifier", NormalizedKind::Class),
    ("struct_specifier", NormalizedKind::Class),
    ("union_specifier", NormalizedKind::Class),
    ("alias_declaration", NormalizedKind::Declaration),
    ("assignment_expression", NormalizedKind::Assignment),
    ("init_declarator", NormalizedKind::Assignment),
    ("preproc_include", NormalizedKind::Import),
    ("identifier", NormalizedKind::Identifier),
    ("field_identifier", NormalizedKind::Identifier),
    ("namespace_identifier", NormalizedKind::Identifier),
    ("qualified_identifier", NormalizedKind::Identifier),
    ("type_identifier", NormalizedKind::Identifier),
    ("template_function", NormalizedKind::Identifier),
    ("template_method", NormalizedKind::Identifier),
    ("template_type", NormalizedKind::Identifier),
    ("dependent_name", NormalizedKind::Identifier),
    ("destructor_name", NormalizedKind::Identifier),
    ("operator_name", NormalizedKind::Identifier),
    ("primitive_type", NormalizedKind::Identifier),
    ("char_literal", NormalizedKind::StringLiteral),
    ("string_literal", NormalizedKind::StringLiteral),
    ("raw_string_literal", NormalizedKind::StringLiteral),
    ("number_literal", NormalizedKind::NumericLiteral),
    ("true", NormalizedKind::BooleanLiteral),
    ("false", NormalizedKind::BooleanLiteral),
    ("null", NormalizedKind::NullLiteral),
    ("return_statement", NormalizedKind::Return),
    ("throw_statement", NormalizedKind::Throw),
    ("catch_clause", NormalizedKind::Catch),
    ("if_statement", NormalizedKind::If),
    ("for_statement", NormalizedKind::Loop),
    ("while_statement", NormalizedKind::Loop),
    ("do_statement", NormalizedKind::Loop),
];

fn last_named_field_child<'tree>(node: Node<'tree>, field: &str) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    node.children_by_field_name(field, &mut cursor)
        .filter(|child| child.is_named())
        .last()
}

fn declarator_name_node<'tree>(declarator: Node<'tree>) -> Option<Node<'tree>> {
    let mut current = declarator;
    loop {
        match current.kind() {
            "identifier"
            | "field_identifier"
            | "namespace_identifier"
            | "type_identifier"
            | "destructor_name"
            | "operator_name"
            | "primitive_type" => return Some(current),
            "qualified_identifier" => current = last_named_field_child(current, "name")?,
            "dependent_name" | "template_function" | "template_method" | "template_type" => {
                current = current.child_by_field_name("name")?;
            }
            "function_declarator"
            | "pointer_declarator"
            | "array_declarator"
            | "init_declarator" => current = current.child_by_field_name("declarator")?,
            "reference_declarator" | "parenthesized_declarator" => {
                current = first_named_child(current)?;
            }
            _ => return None,
        }
    }
}

fn expression_name_node<'tree>(expression: Node<'tree>) -> Option<Node<'tree>> {
    let mut current = expression;
    loop {
        match current.kind() {
            "identifier"
            | "field_identifier"
            | "namespace_identifier"
            | "type_identifier"
            | "destructor_name"
            | "operator_name"
            | "primitive_type"
            | "this" => return Some(current),
            "qualified_identifier" => current = last_named_field_child(current, "name")?,
            "dependent_name" | "template_function" | "template_method" | "template_type" => {
                current = current.child_by_field_name("name")?;
            }
            "field_expression" => current = current.child_by_field_name("field")?,
            "call_expression" => current = current.child_by_field_name("function")?,
            "new_expression" => current = current.child_by_field_name("type")?,
            "parenthesized_expression" => current = first_named_child(current)?,
            _ => return declarator_name_node(current),
        }
    }
}

fn attach_qualified_scope_receiver(sink: &mut RoleSink<'_>, function: Node<'_>) {
    if function.kind() != "qualified_identifier" {
        return;
    }
    if let Some(scope) = function.child_by_field_name("scope") {
        attach_role_with_derived_name(sink, Role::Receiver, scope, expression_name_node);
    }
}

fn qualified_declarator_node(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        if node.kind() == "qualified_identifier" {
            return Some(node);
        }
        node = node
            .child_by_field_name("declarator")
            .or_else(|| node.child_by_field_name("name"))
            .or_else(|| first_named_child(node))?;
    }
}

fn node_text<'source>(node: Node<'_>, source: &'source str) -> Option<&'source str> {
    node.utf8_text(source.as_bytes()).ok()
}

fn scoped_function_definition(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("declarator")
        .and_then(qualified_declarator_node)
        .and_then(|qualified| qualified.child_by_field_name("scope"))
}

fn is_constructor_definition(node: Node<'_>, source: &str) -> bool {
    node.child_by_field_name("declarator")
        .and_then(qualified_declarator_node)
        .and_then(|qualified| {
            Some((
                expression_name_node(qualified.child_by_field_name("scope")?)?,
                expression_name_node(last_named_field_child(qualified, "name")?)?,
            ))
        })
        .is_some_and(|(scope, name)| node_text(scope, source) == node_text(name, source))
}

fn unquoted_include_span(node: Node<'_>) -> Option<Span> {
    if !matches!(node.kind(), "string_literal" | "system_lib_string") {
        return None;
    }
    let start = node.start_byte().checked_add(1)?;
    let end = node.end_byte().checked_sub(1)?;
    (start <= end).then_some(Span {
        start_byte: start,
        end_byte: end,
    })
}

impl StructuralSpec for CppStructuralSpec {
    fn language(&self) -> Language {
        Language::Cpp
    }

    fn kind_table(&self) -> &'static [(&'static str, NormalizedKind)] {
        CPP_KIND_TABLE
    }

    fn refine_kind(
        &self,
        node: Node<'_>,
        kind: NormalizedKind,
        enclosing: Option<NormalizedKind>,
        source: &str,
    ) -> NormalizedKind {
        if kind == NormalizedKind::Function
            && (enclosing == Some(NormalizedKind::Class)
                || scoped_function_definition(node).is_some())
        {
            if is_constructor_definition(node, source) {
                NormalizedKind::Constructor
            } else {
                NormalizedKind::Method
            }
        } else {
            kind
        }
    }

    fn supports_kind(&self, kind: NormalizedKind) -> bool {
        matches!(kind, NormalizedKind::Method | NormalizedKind::Constructor)
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
                let function_field = if node.kind() == "new_expression" {
                    "type"
                } else {
                    "function"
                };
                if let Some(function) = node.child_by_field_name(function_field) {
                    attach_terminal_callee(sink, function, expression_name_node(function));
                    if function.kind() == "field_expression"
                        && let Some(argument) = function.child_by_field_name("argument")
                    {
                        attach_role_with_derived_name(
                            sink,
                            Role::Receiver,
                            argument,
                            expression_name_node,
                        );
                    }
                    attach_qualified_scope_receiver(sink, function);
                }
                if let Some(arguments) = node.child_by_field_name("arguments") {
                    attach_positional_argument_roles(sink, arguments, expression_name_node);
                }
            }
            NormalizedKind::FieldAccess => {
                if let Some(field) = node.child_by_field_name("field") {
                    attach_role_with_derived_name(sink, Role::Field, field, expression_name_node);
                    if let Some(name) = expression_name_node(field) {
                        sink.set_name(name);
                    }
                }
                if let Some(argument) = node.child_by_field_name("argument") {
                    attach_role_with_derived_name(
                        sink,
                        Role::Object,
                        argument,
                        expression_name_node,
                    );
                }
            }
            NormalizedKind::Function | NormalizedKind::Method | NormalizedKind::Constructor => {
                if let Some(name) = node
                    .child_by_field_name("declarator")
                    .and_then(declarator_name_node)
                {
                    sink.set_name(name);
                }
            }
            NormalizedKind::Class | NormalizedKind::Declaration => {
                if let Some(name) = node
                    .child_by_field_name("name")
                    .and_then(declarator_name_node)
                    .or_else(|| node.child_by_field_name("name"))
                {
                    sink.set_name(name);
                }
            }
            NormalizedKind::Assignment => match node.kind() {
                "init_declarator" => {
                    if let Some(declarator) = node.child_by_field_name("declarator") {
                        attach_role_with_derived_name(
                            sink,
                            Role::Left,
                            declarator,
                            declarator_name_node,
                        );
                        if let Some(name) = declarator_name_node(declarator) {
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
                if let Some(path) = node.child_by_field_name("path") {
                    if let Some(name) = unquoted_include_span(path) {
                        sink.role_named_span(Role::Module, path, name);
                    } else {
                        attach_role_with_derived_name(
                            sink,
                            Role::Module,
                            path,
                            expression_name_node,
                        );
                    }
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
    fn cpp_kind_table_matches_grammar() {
        crate::analyzer::structural::adapter_helpers::assert_kind_table_matches_grammar(
            tree_sitter_cpp::LANGUAGE.into(),
            "tree-sitter-cpp",
            CPP_KIND_TABLE,
        );
    }
}
