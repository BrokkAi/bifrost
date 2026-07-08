//! Ruby structural spec for `search_ast`.

use crate::analyzer::Language;
use crate::analyzer::structural::adapter_helpers::{
    attach_role_with_derived_name, attach_terminal_callee, first_named_child,
};
use crate::analyzer::structural::{NormalizedKind, Role, RoleSink, Span, StructuralSpec};
use tree_sitter::Node;

#[derive(Debug, Default)]
pub(crate) struct RubyStructuralSpec;

pub(crate) static RUBY_STRUCTURAL_SPEC: RubyStructuralSpec = RubyStructuralSpec;

const RUBY_KIND_TABLE: &[(&str, NormalizedKind)] = &[
    ("call", NormalizedKind::Call),
    ("method", NormalizedKind::Function),
    ("singleton_method", NormalizedKind::Method),
    ("block", NormalizedKind::Lambda),
    ("do_block", NormalizedKind::Lambda),
    ("lambda", NormalizedKind::Lambda),
    ("class", NormalizedKind::Class),
    ("module", NormalizedKind::Class),
    ("assignment", NormalizedKind::Assignment),
    ("operator_assignment", NormalizedKind::Assignment),
    ("scope_resolution", NormalizedKind::FieldAccess),
    ("unary", NormalizedKind::NumericLiteral),
    ("identifier", NormalizedKind::Identifier),
    ("constant", NormalizedKind::Identifier),
    ("instance_variable", NormalizedKind::Identifier),
    ("class_variable", NormalizedKind::Identifier),
    ("global_variable", NormalizedKind::Identifier),
    ("self", NormalizedKind::Identifier),
    ("simple_symbol", NormalizedKind::Identifier),
    ("delimited_symbol", NormalizedKind::Identifier),
    ("hash_key_symbol", NormalizedKind::Identifier),
    ("string", NormalizedKind::StringLiteral),
    ("integer", NormalizedKind::NumericLiteral),
    ("float", NormalizedKind::NumericLiteral),
    ("true", NormalizedKind::BooleanLiteral),
    ("false", NormalizedKind::BooleanLiteral),
    ("nil", NormalizedKind::NullLiteral),
    ("return", NormalizedKind::Return),
    ("rescue", NormalizedKind::Catch),
    ("if", NormalizedKind::If),
    ("unless", NormalizedKind::If),
    ("while", NormalizedKind::Loop),
    ("until", NormalizedKind::Loop),
    ("for", NormalizedKind::Loop),
];

fn expression_target_node(mut node: Node<'_>) -> Node<'_> {
    while matches!(node.kind(), "parenthesized_statements") {
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
            "identifier" | "constant" | "instance_variable" | "class_variable"
            | "global_variable" | "self" | "hash_key_symbol" => return Some(current),
            "simple_symbol" | "delimited_symbol" => return symbol_name_node(current),
            "scope_resolution" => current = current.child_by_field_name("name")?,
            "call" => current = current.child_by_field_name("method")?,
            "pair" => current = current.child_by_field_name("key")?,
            _ => return None,
        }
    }
}

fn symbol_name_node(node: Node<'_>) -> Option<Node<'_>> {
    first_named_child_of_kind(node, "string_content").or(Some(node))
}

fn first_named_child_of_kind<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    (0..node.named_child_count())
        .filter_map(|index| node.named_child(index))
        .find(|child| child.kind() == kind)
}

fn is_numeric_literal_node(node: Node<'_>) -> bool {
    matches!(node.kind(), "integer" | "float")
}

fn is_signed_numeric_unary(node: Node<'_>) -> bool {
    node.kind() == "unary"
        && node
            .child_by_field_name("operator")
            .is_some_and(|operator| matches!(operator.kind(), "+" | "-"))
        && node
            .child_by_field_name("operand")
            .map(expression_target_node)
            .is_some_and(is_numeric_literal_node)
}

fn is_inside_signed_numeric_wrapper(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    is_signed_numeric_unary(parent)
}

fn call_method_node(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("method")
}

fn attach_argument_roles(sink: &mut RoleSink<'_>, arguments: Node<'_>) {
    for index in 0..arguments.named_child_count() {
        let Some(argument) = arguments.named_child(index) else {
            continue;
        };
        if argument.kind() == "pair" {
            if let Some(key) = argument.child_by_field_name("key")
                && let Some(value) = argument
                    .child_by_field_name("value")
                    .map(expression_target_node)
            {
                sink.kwarg(expression_name_node(key).unwrap_or(key), value);
            }
        } else {
            attach_role_with_derived_name(sink, Role::Arg, argument, expression_name_node);
        }
    }
}

fn node_text<'source>(node: Node<'_>, source: &'source str) -> &'source str {
    node.utf8_text(source.as_bytes()).unwrap_or("")
}

fn module_argument_node(node: Node<'_>) -> Option<Node<'_>> {
    let arguments = node.child_by_field_name("arguments")?;
    (0..arguments.named_child_count())
        .filter_map(|index| arguments.named_child(index))
        .find(|argument| argument.kind() == "string")
}

fn is_import_call(node: Node<'_>, source: &str) -> bool {
    if node.child_by_field_name("receiver").is_some() {
        return false;
    }

    let Some(method) = call_method_node(node) else {
        return false;
    };
    matches!(
        node_text(method, source).trim(),
        "require" | "require_relative" | "load" | "autoload"
    ) && module_argument_node(node).is_some()
}

fn static_string_content_node(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() != "string" || node.named_child_count() != 1 {
        return None;
    }
    let content = node.named_child(0)?;
    (content.kind() == "string_content").then_some(content)
}

fn static_string_content_span(node: Node<'_>) -> Option<Span> {
    let content = static_string_content_node(node)?;
    Some(Span {
        start_byte: content.start_byte(),
        end_byte: content.end_byte(),
    })
}

impl StructuralSpec for RubyStructuralSpec {
    fn language(&self) -> Language {
        Language::Ruby
    }

    fn kind_table(&self) -> &'static [(&'static str, NormalizedKind)] {
        RUBY_KIND_TABLE
    }

    fn refine_kind(
        &self,
        node: Node<'_>,
        kind: NormalizedKind,
        enclosing: Option<NormalizedKind>,
        source: &str,
    ) -> NormalizedKind {
        if node.kind() == "call" && is_import_call(node, source) {
            NormalizedKind::Import
        } else if node.kind() == "method"
            && kind == NormalizedKind::Function
            && enclosing == Some(NormalizedKind::Class)
        {
            NormalizedKind::Method
        } else {
            kind
        }
    }

    fn should_extract(&self, node: Node<'_>, kind: NormalizedKind) -> bool {
        if kind == NormalizedKind::Lambda
            && matches!(node.kind(), "block" | "do_block")
            && node
                .parent()
                .is_some_and(|parent| parent.kind() == "lambda")
        {
            return false;
        }

        if kind == NormalizedKind::NumericLiteral {
            if node.kind() == "unary" {
                return is_signed_numeric_unary(node);
            }
            if is_numeric_literal_node(node) && is_inside_signed_numeric_wrapper(node) {
                return false;
            }
        }

        true
    }

    fn supports_kind(&self, kind: NormalizedKind) -> bool {
        kind == NormalizedKind::Import
            || self
                .kind_table()
                .iter()
                .any(|(_, fact_kind)| fact_kind.satisfies(kind))
    }

    fn supports_role(&self, role: Role) -> bool {
        role != Role::Decorator
    }

    fn extract(&self, node: Node<'_>, kind: NormalizedKind, sink: &mut RoleSink<'_>) {
        match kind {
            NormalizedKind::Call => {
                if let Some(method) = call_method_node(node) {
                    attach_terminal_callee(sink, method, expression_name_node(method));
                }
                if let Some(receiver) = node.child_by_field_name("receiver") {
                    attach_role_with_derived_name(
                        sink,
                        Role::Receiver,
                        receiver,
                        expression_name_node,
                    );
                }
                if let Some(arguments) = node.child_by_field_name("arguments") {
                    attach_argument_roles(sink, arguments);
                }
                if let Some(block) = node.child_by_field_name("block") {
                    attach_role_with_derived_name(sink, Role::Arg, block, expression_name_node);
                }
            }
            NormalizedKind::FieldAccess => {
                if let Some(field) = node.child_by_field_name("name") {
                    attach_role_with_derived_name(sink, Role::Field, field, expression_name_node);
                    if let Some(name) = expression_name_node(field) {
                        sink.set_name(name);
                    }
                }
                if let Some(object) = node.child_by_field_name("scope") {
                    attach_role_with_derived_name(sink, Role::Object, object, expression_name_node);
                }
            }
            NormalizedKind::Function
            | NormalizedKind::Method
            | NormalizedKind::Class
            | NormalizedKind::Declaration => {
                if let Some(name) = node.child_by_field_name("name") {
                    sink.set_name(expression_name_node(name).unwrap_or(name));
                }
            }
            NormalizedKind::Assignment => {
                if let Some(left) = node.child_by_field_name("left") {
                    let left = expression_target_node(left);
                    attach_role_with_derived_name(sink, Role::Left, left, expression_name_node);
                    if let Some(name) = expression_name_node(left) {
                        sink.set_name(name);
                    }
                }
                if let Some(right) = node.child_by_field_name("right") {
                    let right = expression_target_node(right);
                    attach_role_with_derived_name(sink, Role::Right, right, expression_name_node);
                }
            }
            NormalizedKind::Import => {
                if let Some(module) = module_argument_node(node)
                    && let Some(name) = static_string_content_span(module)
                {
                    sink.role_named_span(Role::Module, module, name);
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
    fn ruby_kind_table_matches_grammar() {
        crate::analyzer::structural::adapter_helpers::assert_kind_table_matches_grammar(
            tree_sitter_ruby::LANGUAGE.into(),
            "tree-sitter-ruby",
            RUBY_KIND_TABLE,
        );
    }
}
