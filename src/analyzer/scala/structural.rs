//! Scala structural spec for `query_code`.

use crate::analyzer::Language;
use crate::analyzer::structural::adapter_helpers::{
    attach_argument_role_with_derived_name, attach_role_with_derived_name, attach_terminal_callee,
    first_named_child,
};
use crate::analyzer::structural::{NormalizedKind, Role, RoleSink, Span, StructuralSpec};
use tree_sitter::Node;

#[derive(Debug, Default)]
pub(crate) struct ScalaStructuralSpec;

pub(crate) static SCALA_STRUCTURAL_SPEC: ScalaStructuralSpec = ScalaStructuralSpec;

const SCALA_KIND_TABLE: &[(&str, NormalizedKind)] = &[
    ("call_expression", NormalizedKind::Call),
    ("infix_expression", NormalizedKind::Call),
    ("postfix_expression", NormalizedKind::Call),
    ("field_expression", NormalizedKind::FieldAccess),
    ("function_definition", NormalizedKind::Function),
    ("function_declaration", NormalizedKind::Function),
    ("lambda_expression", NormalizedKind::Lambda),
    ("class_definition", NormalizedKind::Class),
    ("object_definition", NormalizedKind::Class),
    ("trait_definition", NormalizedKind::Class),
    ("enum_definition", NormalizedKind::Class),
    ("val_definition", NormalizedKind::Assignment),
    ("var_definition", NormalizedKind::Assignment),
    ("assignment_expression", NormalizedKind::Assignment),
    ("import_declaration", NormalizedKind::Import),
    ("annotation", NormalizedKind::Decorator),
    ("identifier", NormalizedKind::Identifier),
    ("operator_identifier", NormalizedKind::Identifier),
    ("type_identifier", NormalizedKind::Identifier),
    ("stable_type_identifier", NormalizedKind::Identifier),
    ("string", NormalizedKind::StringLiteral),
    (
        "interpolated_string_expression",
        NormalizedKind::StringLiteral,
    ),
    ("character_literal", NormalizedKind::StringLiteral),
    ("prefix_expression", NormalizedKind::NumericLiteral),
    ("integer_literal", NormalizedKind::NumericLiteral),
    ("floating_point_literal", NormalizedKind::NumericLiteral),
    ("boolean_literal", NormalizedKind::BooleanLiteral),
    ("null_literal", NormalizedKind::NullLiteral),
    ("return_expression", NormalizedKind::Return),
    ("throw_expression", NormalizedKind::Throw),
    ("catch_clause", NormalizedKind::Catch),
    ("if_expression", NormalizedKind::If),
    ("for_expression", NormalizedKind::Loop),
    ("while_expression", NormalizedKind::Loop),
    ("do_while_expression", NormalizedKind::Loop),
];

fn last_named_child<'tree>(node: Node<'tree>) -> Option<Node<'tree>> {
    (0..node.named_child_count())
        .rev()
        .find_map(|index| node.named_child(index))
}

fn single_named_child(node: Node<'_>) -> Option<Node<'_>> {
    if node.named_child_count() == 1 {
        node.named_child(0)
    } else {
        None
    }
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
            "identifier" | "operator_identifier" | "type_identifier" => return Some(current),
            "stable_type_identifier" => current = last_named_child(current)?,
            "call_expression" => current = current.child_by_field_name("function")?,
            "generic_function" => current = current.child_by_field_name("function")?,
            "field_expression" => current = current.child_by_field_name("field")?,
            "assignment_expression" => current = current.child_by_field_name("left")?,
            "binding" => current = current.child_by_field_name("name")?,
            _ => return None,
        }
    }
}

fn call_function_node(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "infix_expression" => node.child_by_field_name("operator"),
        "postfix_expression" => (0..node.named_child_count())
            .filter_map(|index| node.named_child(index))
            .rfind(|child| matches!(child.kind(), "identifier" | "operator_identifier")),
        _ => node
            .child_by_field_name("function")
            .map(expression_target_node),
    }
}

fn callable_target_node(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = expression_target_node(node);
    while current.kind() == "generic_function" {
        current = current
            .child_by_field_name("function")
            .map(expression_target_node)?;
    }
    Some(current)
}

fn is_numeric_literal_node(node: Node<'_>) -> bool {
    matches!(node.kind(), "integer_literal" | "floating_point_literal")
}

fn prefix_argument(node: Node<'_>) -> Option<Node<'_>> {
    last_named_child(node).map(expression_target_node)
}

fn is_signed_numeric_prefix(node: Node<'_>) -> bool {
    node.kind() == "prefix_expression"
        && prefix_argument(node).is_some_and(is_numeric_literal_node)
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

fn is_named_argument_assignment(node: Node<'_>) -> bool {
    node.kind() == "assignment_expression"
        && node
            .parent()
            .is_some_and(|parent| parent.kind() == "arguments")
}

fn attach_argument_roles(sink: &mut RoleSink<'_>, arguments: Node<'_>) {
    match arguments.kind() {
        "arguments" => {
            for index in 0..arguments.named_child_count() {
                let Some(argument) = arguments.named_child(index) else {
                    continue;
                };
                let argument = expression_target_node(argument);
                if let Some((keyword, value)) = named_argument_parts(argument) {
                    sink.kwarg(keyword, value);
                } else {
                    attach_argument_role_with_derived_name(sink, argument, expression_name_node);
                }
            }
        }
        "block" | "case_block" => {
            let argument = single_named_child(arguments)
                .map(expression_target_node)
                .unwrap_or(arguments);
            attach_role_with_derived_name(sink, Role::Arg, argument, expression_name_node);
        }
        "colon_argument" => {
            if let Some(argument) = last_named_child(arguments).map(expression_target_node) {
                let argument = single_named_child(argument)
                    .map(expression_target_node)
                    .unwrap_or(argument);
                attach_role_with_derived_name(sink, Role::Arg, argument, expression_name_node);
            }
        }
        _ => {}
    }
}

fn named_argument_parts(argument: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    if argument.kind() != "assignment_expression" {
        return None;
    }
    let keyword = argument
        .child_by_field_name("left")
        .map(expression_target_node)?;
    if !matches!(keyword.kind(), "identifier" | "operator_identifier") {
        return None;
    }
    let value = argument
        .child_by_field_name("right")
        .map(expression_target_node)?;
    Some((keyword, value))
}

fn pattern_name_node<'tree>(pattern: Node<'tree>) -> Option<Node<'tree>> {
    let current = expression_target_node(pattern);
    match current.kind() {
        "identifier" | "operator_identifier" => Some(current),
        "identifiers" => first_named_child(current),
        "binding" => current.child_by_field_name("name"),
        _ => expression_name_node(current).or_else(|| first_named_child(current)),
    }
}

fn attach_decorators(sink: &mut RoleSink<'_>, declaration: Node<'_>) {
    for index in 0..declaration.named_child_count() {
        let Some(child) = declaration.named_child(index) else {
            continue;
        };
        if child.kind() == "annotation" {
            attach_role_with_derived_name(sink, Role::Decorator, child, expression_name_node);
        }
    }
}

fn annotation_name(node: Node<'_>) -> Option<Node<'_>> {
    for index in 0..node.named_child_count() {
        let child = node.named_child(index)?;
        if child.kind() == "arguments" {
            continue;
        }
        return expression_name_node(child).or(Some(child));
    }
    None
}

fn path_field_nodes(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.children_by_field_name("path", &mut cursor)
        .filter(|child| matches!(child.kind(), "identifier" | "operator_identifier"))
        .collect()
}

fn span_from(first: Node<'_>, last: Node<'_>) -> Span {
    Span {
        start_byte: first.start_byte(),
        end_byte: last.end_byte(),
    }
}

fn attach_path_module(sink: &mut RoleSink<'_>, target: Node<'_>, path: &[Node<'_>]) {
    let Some(last) = path.last().copied() else {
        return;
    };
    sink.role_named(Role::Module, target, last);
    if path.len() > 1 {
        sink.role_named_span(Role::Module, target, span_from(path[0], last));
    }
}

fn attach_selector_module(sink: &mut RoleSink<'_>, selector: Node<'_>) {
    match selector.kind() {
        "identifier" | "operator_identifier" => {
            sink.role_named(Role::Module, selector, selector);
        }
        "as_renamed_identifier" | "arrow_renamed_identifier" => {
            let Some(alias) = selector.child_by_field_name("alias") else {
                return;
            };
            if alias.kind() != "wildcard" {
                sink.role_named(Role::Module, selector, alias);
            }
        }
        _ => {}
    }
}

fn attach_import_modules(sink: &mut RoleSink<'_>, node: Node<'_>) {
    let path = path_field_nodes(node);
    let mut has_selectors = false;
    for index in 0..node.named_child_count() {
        let Some(child) = node.named_child(index) else {
            continue;
        };
        match child.kind() {
            "namespace_selectors" => {
                has_selectors = true;
                for selector_index in 0..child.named_child_count() {
                    if let Some(selector) = child.named_child(selector_index) {
                        attach_selector_module(sink, selector);
                    }
                }
            }
            "as_renamed_identifier" | "arrow_renamed_identifier" => {
                has_selectors = true;
                attach_selector_module(sink, child);
            }
            "namespace_wildcard" => has_selectors = true,
            _ => {}
        }
    }
    if !has_selectors {
        attach_path_module(sink, node, &path);
    }
}

impl StructuralSpec for ScalaStructuralSpec {
    fn language(&self) -> Language {
        Language::Scala
    }

    fn kind_table(&self) -> &'static [(&'static str, NormalizedKind)] {
        SCALA_KIND_TABLE
    }

    fn refine_kind(
        &self,
        _node: Node<'_>,
        kind: NormalizedKind,
        enclosing: Option<NormalizedKind>,
        _source: &str,
    ) -> NormalizedKind {
        if kind == NormalizedKind::Function && enclosing == Some(NormalizedKind::Class) {
            NormalizedKind::Method
        } else {
            kind
        }
    }

    fn should_extract(&self, node: Node<'_>, kind: NormalizedKind) -> bool {
        if kind == NormalizedKind::NumericLiteral {
            if node.kind() == "prefix_expression" {
                return is_signed_numeric_prefix(node);
            }
            if is_numeric_literal_node(node) && is_inside_signed_numeric_wrapper(node) {
                return false;
            }
        }

        kind != NormalizedKind::Assignment || !is_named_argument_assignment(node)
    }

    fn supports_kind(&self, kind: NormalizedKind) -> bool {
        kind == NormalizedKind::Method
            || self
                .kind_table()
                .iter()
                .any(|(_, fact_kind)| fact_kind.satisfies(kind))
    }

    fn extract(&self, node: Node<'_>, kind: NormalizedKind, sink: &mut RoleSink<'_>) {
        match kind {
            NormalizedKind::Call => {
                if let Some(function) = call_function_node(node) {
                    attach_terminal_callee(sink, function, expression_name_node(function));
                    if node.kind() == "infix_expression"
                        && let Some(receiver) = node.child_by_field_name("left")
                    {
                        attach_role_with_derived_name(
                            sink,
                            Role::Receiver,
                            receiver,
                            expression_name_node,
                        );
                    }
                    if node.kind() == "postfix_expression"
                        && let Some(receiver) = node.named_child(0)
                        && receiver.end_byte() <= function.start_byte()
                    {
                        attach_role_with_derived_name(
                            sink,
                            Role::Receiver,
                            receiver,
                            expression_name_node,
                        );
                    }
                    if let Some(target) = callable_target_node(function)
                        && target.kind() == "field_expression"
                        && let Some(receiver) = target.child_by_field_name("value")
                    {
                        attach_role_with_derived_name(
                            sink,
                            Role::Receiver,
                            receiver,
                            expression_name_node,
                        );
                    }
                }
                if node.kind() == "infix_expression"
                    && let Some(argument) = node.child_by_field_name("right")
                {
                    attach_argument_role_with_derived_name(sink, argument, expression_name_node);
                }
                if let Some(arguments) = node.child_by_field_name("arguments") {
                    attach_argument_roles(sink, arguments);
                }
            }
            NormalizedKind::FieldAccess => {
                if let Some(field) = node.child_by_field_name("field") {
                    sink.role_named(Role::Field, field, field);
                    sink.set_name(field);
                }
                if let Some(object) = node.child_by_field_name("value") {
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
            NormalizedKind::Assignment => match node.kind() {
                "val_definition" | "var_definition" => {
                    if let Some(pattern) = node.child_by_field_name("pattern") {
                        attach_role_with_derived_name(sink, Role::Left, pattern, pattern_name_node);
                        if let Some(name) = pattern_name_node(pattern) {
                            sink.set_name(name);
                        }
                    }
                    if let Some(value) = node.child_by_field_name("value") {
                        let value = expression_target_node(value);
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
                if let Some(name) = annotation_name(node) {
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
    fn scala_kind_table_matches_grammar() {
        crate::analyzer::structural::adapter_helpers::assert_kind_table_matches_grammar(
            tree_sitter_scala::LANGUAGE.into(),
            "tree-sitter-scala",
            SCALA_KIND_TABLE,
        );
    }
}
