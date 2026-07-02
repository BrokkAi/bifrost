//! Shared JavaScript/TypeScript structural specs for `search_ast`.

use crate::analyzer::Language;
use crate::analyzer::structural::{NormalizedKind, Role, RoleSink, Span, StructuralSpec};
use tree_sitter::Node;

#[derive(Debug)]
pub(crate) struct JsTsStructuralSpec {
    language: Language,
}

pub(crate) static JAVASCRIPT_STRUCTURAL_SPEC: JsTsStructuralSpec = JsTsStructuralSpec {
    language: Language::JavaScript,
};

pub(crate) static TYPESCRIPT_STRUCTURAL_SPEC: JsTsStructuralSpec = JsTsStructuralSpec {
    language: Language::TypeScript,
};

const JS_KIND_TABLE: &[(&str, NormalizedKind)] = &[
    ("call_expression", NormalizedKind::Call),
    ("new_expression", NormalizedKind::Call),
    ("member_expression", NormalizedKind::FieldAccess),
    ("function_declaration", NormalizedKind::Function),
    ("function_expression", NormalizedKind::Function),
    ("generator_function_declaration", NormalizedKind::Function),
    ("generator_function", NormalizedKind::Function),
    ("method_definition", NormalizedKind::Method),
    ("arrow_function", NormalizedKind::Lambda),
    ("class_declaration", NormalizedKind::Class),
    ("assignment_expression", NormalizedKind::Assignment),
    ("variable_declarator", NormalizedKind::Assignment),
    ("import_statement", NormalizedKind::Import),
    ("identifier", NormalizedKind::Identifier),
    ("property_identifier", NormalizedKind::Identifier),
    ("private_property_identifier", NormalizedKind::Identifier),
    ("shorthand_property_identifier", NormalizedKind::Identifier),
    (
        "shorthand_property_identifier_pattern",
        NormalizedKind::Identifier,
    ),
    ("string", NormalizedKind::StringLiteral),
    ("template_string", NormalizedKind::StringLiteral),
    ("number", NormalizedKind::NumericLiteral),
    ("true", NormalizedKind::BooleanLiteral),
    ("false", NormalizedKind::BooleanLiteral),
    ("null", NormalizedKind::NullLiteral),
    ("return_statement", NormalizedKind::Return),
    ("throw_statement", NormalizedKind::Throw),
    ("catch_clause", NormalizedKind::Catch),
    ("if_statement", NormalizedKind::If),
    ("for_statement", NormalizedKind::Loop),
    ("for_in_statement", NormalizedKind::Loop),
    ("while_statement", NormalizedKind::Loop),
    ("do_statement", NormalizedKind::Loop),
    ("decorator", NormalizedKind::Decorator),
];

const TS_KIND_TABLE: &[(&str, NormalizedKind)] = &[
    ("call_expression", NormalizedKind::Call),
    ("new_expression", NormalizedKind::Call),
    ("member_expression", NormalizedKind::FieldAccess),
    ("function_declaration", NormalizedKind::Function),
    ("function_expression", NormalizedKind::Function),
    ("generator_function_declaration", NormalizedKind::Function),
    ("generator_function", NormalizedKind::Function),
    ("method_definition", NormalizedKind::Method),
    ("arrow_function", NormalizedKind::Lambda),
    ("class_declaration", NormalizedKind::Class),
    ("abstract_class_declaration", NormalizedKind::Class),
    ("interface_declaration", NormalizedKind::Class),
    ("enum_declaration", NormalizedKind::Class),
    ("type_alias_declaration", NormalizedKind::Declaration),
    ("assignment_expression", NormalizedKind::Assignment),
    ("variable_declarator", NormalizedKind::Assignment),
    ("import_statement", NormalizedKind::Import),
    ("identifier", NormalizedKind::Identifier),
    ("property_identifier", NormalizedKind::Identifier),
    ("private_property_identifier", NormalizedKind::Identifier),
    ("shorthand_property_identifier", NormalizedKind::Identifier),
    (
        "shorthand_property_identifier_pattern",
        NormalizedKind::Identifier,
    ),
    ("type_identifier", NormalizedKind::Identifier),
    ("nested_identifier", NormalizedKind::Identifier),
    ("string", NormalizedKind::StringLiteral),
    ("template_string", NormalizedKind::StringLiteral),
    ("number", NormalizedKind::NumericLiteral),
    ("true", NormalizedKind::BooleanLiteral),
    ("false", NormalizedKind::BooleanLiteral),
    ("null", NormalizedKind::NullLiteral),
    ("return_statement", NormalizedKind::Return),
    ("throw_statement", NormalizedKind::Throw),
    ("catch_clause", NormalizedKind::Catch),
    ("if_statement", NormalizedKind::If),
    ("for_statement", NormalizedKind::Loop),
    ("for_in_statement", NormalizedKind::Loop),
    ("while_statement", NormalizedKind::Loop),
    ("do_statement", NormalizedKind::Loop),
    ("decorator", NormalizedKind::Decorator),
];

fn first_named_child(node: Node<'_>) -> Option<Node<'_>> {
    node.named_child(0)
}

fn unquoted_string_span(node: Node<'_>) -> Option<Span> {
    if node.kind() != "string" {
        return None;
    }
    let start = node.start_byte().checked_add(1)?;
    let end = node.end_byte().checked_sub(1)?;
    (start <= end).then_some(Span {
        start_byte: start,
        end_byte: end,
    })
}

fn expression_name_node<'tree>(expression: Node<'tree>) -> Option<Node<'tree>> {
    let mut current = expression;
    loop {
        match current.kind() {
            "identifier"
            | "property_identifier"
            | "private_property_identifier"
            | "shorthand_property_identifier"
            | "shorthand_property_identifier_pattern"
            | "type_identifier" => return Some(current),
            "nested_identifier" | "member_expression" => {
                current = current.child_by_field_name("property")?;
            }
            "call_expression" => current = current.child_by_field_name("function")?,
            "new_expression" => current = current.child_by_field_name("constructor")?,
            "decorator" | "parenthesized_expression" | "non_null_expression" => {
                current = first_named_child(current)?;
            }
            _ => return None,
        }
    }
}

fn attach_named_role(sink: &mut RoleSink<'_>, role: Role, target: Node<'_>) {
    match expression_name_node(target) {
        Some(name) => sink.role_named(role, target, name),
        None => sink.role(role, target),
    }
}

fn attach_argument_roles(sink: &mut RoleSink<'_>, arguments: Node<'_>) {
    if arguments.kind() == "template_string" {
        sink.role(Role::Arg, arguments);
        return;
    }
    for index in 0..arguments.named_child_count() {
        let Some(argument) = arguments.named_child(index) else {
            continue;
        };
        attach_named_role(sink, Role::Arg, argument);
    }
}

fn attach_decorators(sink: &mut RoleSink<'_>, declaration: Node<'_>) {
    for index in 0..declaration.named_child_count() {
        let Some(child) = declaration.named_child(index) else {
            continue;
        };
        if child.kind() == "decorator" {
            attach_named_role(sink, Role::Decorator, child);
        }
    }
    attach_preceding_class_body_decorators(sink, declaration);
}

fn attach_preceding_class_body_decorators(sink: &mut RoleSink<'_>, declaration: Node<'_>) {
    let Some(parent) = declaration.parent() else {
        return;
    };
    if parent.kind() != "class_body" {
        return;
    }
    let mut pending = Vec::new();
    for index in 0..parent.named_child_count() {
        let Some(child) = parent.named_child(index) else {
            continue;
        };
        if child.id() == declaration.id() {
            for decorator in pending {
                attach_named_role(sink, Role::Decorator, decorator);
            }
            return;
        }
        if child.kind() == "decorator" {
            pending.push(child);
        } else {
            pending.clear();
        }
    }
}

impl StructuralSpec for JsTsStructuralSpec {
    fn language(&self) -> Language {
        self.language
    }

    fn kind_table(&self) -> &'static [(&'static str, NormalizedKind)] {
        match self.language {
            Language::JavaScript => JS_KIND_TABLE,
            Language::TypeScript => TS_KIND_TABLE,
            _ => unreachable!("JS/TS structural spec only supports JavaScript and TypeScript"),
        }
    }

    fn extract(&self, node: Node<'_>, kind: NormalizedKind, sink: &mut RoleSink<'_>) {
        match kind {
            NormalizedKind::Call => {
                let callee_field = if node.kind() == "new_expression" {
                    "constructor"
                } else {
                    "function"
                };
                if let Some(function) = node.child_by_field_name(callee_field) {
                    attach_named_role(sink, Role::Callee, function);
                    if let Some(name) = expression_name_node(function) {
                        sink.set_name(name);
                    }
                    if function.kind() == "member_expression"
                        && let Some(object) = function.child_by_field_name("object")
                    {
                        attach_named_role(sink, Role::Receiver, object);
                    }
                }
                if let Some(arguments) = node.child_by_field_name("arguments") {
                    attach_argument_roles(sink, arguments);
                }
            }
            NormalizedKind::FieldAccess => {
                if let Some(property) = node.child_by_field_name("property") {
                    sink.set_name(property);
                    sink.role_named(Role::Field, property, property);
                }
                if let Some(object) = node.child_by_field_name("object") {
                    attach_named_role(sink, Role::Object, object);
                }
            }
            NormalizedKind::Function | NormalizedKind::Method | NormalizedKind::Class => {
                if let Some(name) = node.child_by_field_name("name") {
                    sink.set_name(name);
                }
                attach_decorators(sink, node);
            }
            NormalizedKind::Assignment => match node.kind() {
                "variable_declarator" => {
                    if let Some(name) = node.child_by_field_name("name") {
                        attach_named_role(sink, Role::Left, name);
                        if let Some(name_node) = expression_name_node(name) {
                            sink.set_name(name_node);
                        }
                    }
                    if let Some(value) = node.child_by_field_name("value") {
                        attach_named_role(sink, Role::Right, value);
                    }
                }
                "assignment_expression" => {
                    if let Some(left) = node.child_by_field_name("left") {
                        attach_named_role(sink, Role::Left, left);
                    }
                    if let Some(right) = node.child_by_field_name("right") {
                        attach_named_role(sink, Role::Right, right);
                    }
                }
                _ => {}
            },
            NormalizedKind::Import => {
                if let Some(source) = node.child_by_field_name("source") {
                    if let Some(name) = unquoted_string_span(source) {
                        sink.role_named_span(Role::Module, source, name);
                    } else {
                        attach_named_role(sink, Role::Module, source);
                    }
                }
            }
            NormalizedKind::Identifier => match expression_name_node(node) {
                Some(name) => sink.set_name(name),
                None => sink.set_name(node),
            },
            NormalizedKind::Decorator => {
                if let Some(name) = first_named_child(node).and_then(expression_name_node) {
                    sink.set_name(name);
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod structural_spec_tests {
    use super::*;

    fn assert_kind_table(grammar: tree_sitter::Language, table: &[(&str, NormalizedKind)]) {
        for (name, kind) in table {
            assert_ne!(
                grammar.id_for_node_kind(name, true),
                0,
                "node type {name:?} (mapped to {kind:?}) does not exist in grammar"
            );
        }
    }

    #[test]
    fn javascript_kind_table_matches_grammar() {
        assert_kind_table(tree_sitter_javascript::LANGUAGE.into(), JS_KIND_TABLE);
    }

    #[test]
    fn typescript_kind_table_matches_grammar() {
        assert_kind_table(
            tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            TS_KIND_TABLE,
        );
    }
}
