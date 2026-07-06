use super::resolver::node_text;
use crate::analyzer::usages::local_inference::LocalInferenceEngine;
use crate::analyzer::{CodeUnit, IAnalyzer, PhpAnalyzer, resolve_php_type};
use tree_sitter::{Node, Parser};

const LOCAL_SCOPE_NODES: &[&str] = &[
    "function_definition",
    "method_declaration",
    "anonymous_function",
    "anonymous_function_creation",
    "arrow_function",
];

pub(in crate::analyzer::usages) fn is_local_scope(node: Node<'_>) -> bool {
    LOCAL_SCOPE_NODES.contains(&node.kind())
}

pub(in crate::analyzer::usages) fn seed_parameter_types<F>(
    node: Node<'_>,
    source: &str,
    bindings: &mut LocalInferenceEngine<String>,
    mut resolve_type: F,
) where
    F: FnMut(&str) -> Option<String>,
{
    let Some(parameters) = node.child_by_field_name("parameters") else {
        return;
    };
    let mut cursor = parameters.walk();
    for child in parameters.named_children(&mut cursor) {
        if !matches!(
            child.kind(),
            "simple_parameter" | "property_promotion_parameter"
        ) {
            continue;
        }
        let Some(name_node) = child.child_by_field_name("name") else {
            continue;
        };
        let name = variable_identifier(name_node, source);
        if name.is_empty() {
            continue;
        }
        match child
            .child_by_field_name("type")
            .and_then(|type_node| resolve_type(node_text(type_node, source)))
        {
            Some(fqn) => bindings.seed_symbol(name.to_string(), fqn),
            None => bindings.declare_shadow(name.to_string()),
        }
    }
}

pub(in crate::analyzer::usages) fn assignment_parts(
    node: Node<'_>,
) -> Option<(Node<'_>, Node<'_>)> {
    (node.kind() == "assignment_expression")
        .then(|| {
            node.child_by_field_name("left")
                .zip(node.child_by_field_name("right"))
        })
        .flatten()
}

pub(in crate::analyzer::usages) fn object_creation_type(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| matches!(child.kind(), "name" | "qualified_name"))
}

pub(in crate::analyzer::usages) fn static_member_parts(
    node: Node<'_>,
) -> Option<(Node<'_>, Node<'_>)> {
    let scope = node
        .child_by_field_name("scope")
        .or_else(|| node.child_by_field_name("class"))
        .or_else(|| node.named_child(0))?;
    let name = node
        .child_by_field_name("name")
        .or_else(|| node.child_by_field_name("constant"))
        .or_else(|| node.named_child(1))?;
    Some((scope, name))
}

pub(in crate::analyzer::usages) fn variable_identifier<'a>(
    node: Node<'_>,
    source: &'a str,
) -> &'a str {
    node_text(node, source).trim_start_matches('$')
}

pub(in crate::analyzer::usages) fn literal_member_identifier<'a>(
    node: Node<'_>,
    source: &'a str,
) -> Option<&'a str> {
    (node.kind() == "name").then(|| node_text(node, source))
}

pub(in crate::analyzer::usages) fn static_property_identifier<'a>(
    node: Node<'_>,
    source: &'a str,
) -> Option<&'a str> {
    (node.kind() == "variable_name").then(|| variable_identifier(node, source))
}

pub(in crate::analyzer::usages) fn declared_field_type_fq_name(
    php: &PhpAnalyzer,
    analyzer: &dyn IAnalyzer,
    field: &CodeUnit,
) -> Option<String> {
    if !field.is_field() {
        return None;
    }
    let source = field.source().read_to_string().ok()?;
    let range = analyzer.ranges(field).first()?;
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
        .ok()?;
    let tree = parser.parse(source.as_str(), None)?;
    let declaration = field_declaration_node(tree.root_node(), range.start_byte, range.end_byte)?;
    let type_node = match declaration.kind() {
        "property_promotion_parameter" | "property_declaration" => {
            declaration.child_by_field_name("type")
        }
        "property_element" => declaration
            .parent()
            .and_then(|parent| parent.child_by_field_name("type")),
        _ => None,
    }?;
    let ctx = php.file_context_from_source(field.source(), &source);
    resolve_php_type(node_text(type_node, &source), &ctx)
}

pub(in crate::analyzer::usages) fn declared_callable_return_type_fq_name(
    php: &PhpAnalyzer,
    analyzer: &dyn IAnalyzer,
    callable: &CodeUnit,
) -> Option<String> {
    if !callable.is_function() {
        return None;
    }
    let source = callable.source().read_to_string().ok()?;
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
        .ok()?;
    let tree = parser.parse(source.as_str(), None)?;
    let declaration = declaration_node_for_range(
        tree.root_node(),
        analyzer.ranges(callable),
        &["function_definition", "method_declaration"],
    )?;
    let return_type = declaration.child_by_field_name("return_type")?;
    let raw = node_text(return_type, &source).trim();
    if matches!(raw, "self" | "static") {
        return php.parent_of(callable).map(|owner| owner.fq_name());
    }
    let ctx = php.file_context_from_source(callable.source(), &source);
    resolve_php_type(raw, &ctx)
}

fn field_declaration_node(root: Node<'_>, start: usize, end: usize) -> Option<Node<'_>> {
    let ranges = [crate::analyzer::Range {
        start_byte: start,
        end_byte: end,
        start_line: 0,
        end_line: 0,
    }];
    declaration_node_for_range(
        root,
        &ranges,
        &[
            "property_promotion_parameter",
            "property_declaration",
            "property_element",
        ],
    )
}

fn declaration_node_for_range<'tree>(
    root: Node<'tree>,
    ranges: &[crate::analyzer::Range],
    kinds: &[&str],
) -> Option<Node<'tree>> {
    let start = ranges.iter().map(|range| range.start_byte).min()?;
    let end = ranges.iter().map(|range| range.end_byte).max()?;
    let mut best = None;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.start_byte() > start || node.end_byte() < end {
            continue;
        }
        if kinds.contains(&node.kind()) {
            best = Some(node);
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    best
}
