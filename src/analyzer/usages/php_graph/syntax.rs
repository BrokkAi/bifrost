use super::resolver::node_text;
use crate::analyzer::usages::local_inference::LocalInferenceEngine;
use crate::analyzer::{
    CodeUnit, IAnalyzer, PhpAnalyzer, php_signature_return_type_text, resolve_php_type,
};
use tree_sitter::Node;

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
        .find(|child| matches!(child.kind(), "name" | "qualified_name" | "relative_scope"))
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
    indexed_declared_type_fq_name(analyzer, field)
        .or_else(|| signature_declared_type_fq_name(php, analyzer, field))
}

pub(in crate::analyzer::usages) fn declared_callable_return_type_fq_name(
    php: &PhpAnalyzer,
    analyzer: &dyn IAnalyzer,
    callable: &CodeUnit,
) -> Option<String> {
    if !callable.is_function() {
        return None;
    }
    indexed_declared_type_fq_name(analyzer, callable)
        .or_else(|| signature_declared_type_fq_name(php, analyzer, callable))
}

fn indexed_declared_type_fq_name(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> Option<String> {
    analyzer
        .usage_facts_index()
        .fact_for_declaration(unit)
        .and_then(|facts| facts.return_type_fqn.as_deref())
        .map(str::to_string)
}

fn signature_declared_type_fq_name(
    php: &PhpAnalyzer,
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
) -> Option<String> {
    let signatures = analyzer.signatures(unit);
    let raw = signatures
        .iter()
        .find_map(|signature| php_signature_return_type_text(signature))?;
    if matches!(raw, "self" | "static") {
        return php.parent_of(unit).map(|owner| owner.fq_name());
    }
    let source = unit.source().read_to_string().ok()?;
    let ctx = php.file_context_from_source(unit.source(), &source);
    resolve_php_type(raw, &ctx)
}
