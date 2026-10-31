//! Scala-declared scalar types and literal helpers for semantic analysis.

use brokk_bifrost_jvm::scala::supertypes::scala_type_lookup_segments;

use brokk_bifrost_analysis::analyzer::declared_scalar::DeclaredScalarType;

use brokk_bifrost_analysis::analyzer::declared_scalar::binding_nodes;
use brokk_bifrost_analysis::analyzer::semantic::{ProcedureHandle, SemanticValueKind, ValueId};

use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;
use brokk_bifrost_core::analyzer::tree_walk::subtree_contains;
use brokk_bifrost_core::analyzer::tree_walk::{
    first_named_child_matching, has_child_of_kind as has_direct_token,
};
use brokk_bifrost_jvm::scala::graph::syntax::scala_literal_type_name;
use tree_sitter::Node;

fn scala_literal_node<'tree>(source: &str, mut node: Node<'tree>) -> Option<(Node<'tree>, bool)> {
    let mut negative = false;
    loop {
        match node.kind() {
            "parenthesized_expression" => {
                node = first_named_child_matching(node, |_| true)?;
            }
            "prefix_expression"
                if node
                    .child_by_field_name("operator")
                    .is_some_and(|operator| source.get(operator.byte_range()) == Some("-"))
                    || has_direct_token(node, "-") =>
            {
                negative = !negative;
                node = first_named_child_matching(node, |_| true)?;
            }
            _ => return Some((node, negative)),
        }
    }
}

fn scala_decimal_integer(source: &str, node: Node<'_>) -> Option<(i128, bool)> {
    let (node, negative) = scala_literal_node(source, node)?;
    if node.kind() != "integer_literal" {
        return None;
    }
    let mut text = source.get(node.byte_range())?;
    let long = matches!(text.as_bytes().last(), Some(b'l' | b'L'));
    if long {
        text = &text[..text.len() - 1];
    }
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let magnitude = text.parse::<u128>().ok()?;
    let value = if negative {
        i128::try_from(magnitude)
            .ok()
            .or_else(|| (magnitude == (i128::MAX as u128) + 1).then_some(i128::MIN))?
            .checked_neg()
            .unwrap_or(i128::MIN)
    } else {
        i128::try_from(magnitude).ok()?
    };
    Some((value, long))
}

fn scala_boolean_literal(source: &str, node: Node<'_>) -> Option<bool> {
    let (node, negative) = scala_literal_node(source, node)?;
    if negative || node.kind() != "boolean_literal" {
        return None;
    }
    brokk_bifrost_core::analyzer::structural::adapter_helpers::boolean_literal_value(
        source.get(node.byte_range())?,
    )
}

/// The semantic value kind of a Scala decimal integer or Boolean literal.
/// Parentheses and unary minus are structural literal wrappers; every other
/// expression remains a generic constant so the caller cannot infer a type.
pub(crate) fn scala_scalar_literal_value_kind(
    source: &str,
    node: Node<'_>,
) -> Option<SemanticValueKind> {
    if let Some(value) = scala_boolean_literal(source, node) {
        return Some(SemanticValueKind::Boolean(value));
    }
    let (value, _) = scala_decimal_integer(source, node)?;
    if !(i64::MIN as i128..=i64::MAX as i128).contains(&value) {
        return None;
    }
    Some(if value < 0 {
        SemanticValueKind::SignedInteger(value)
    } else {
        SemanticValueKind::UnsignedInteger(value as u128)
    })
}

/// The scalar type of an integer or Boolean literal, using the shared Scala
/// literal classifier. Integer suffixes select `Long`; unsuffixed literals are
/// `Int`.
pub(crate) fn scala_scalar_type_for_literal(
    source: &str,
    node: Node<'_>,
) -> Option<DeclaredScalarType> {
    let name = scala_literal_type_name(source, node)?;
    match name {
        "Int" | "Long" | "Boolean" => scala_scalar_type_for_primitive_name(name),
        _ => None,
    }
}

/// A Scala declared primitive type supported by the scalar solver. The full
/// type path is required so aliases and user types never acquire primitive
/// operator semantics by name alone.
pub(crate) fn scala_scalar_type_for_type(
    source: &str,
    type_node: Node<'_>,
) -> Option<DeclaredScalarType> {
    if scala_deferred_parameter_type(type_node)
        || subtree_contains(type_node, scala_deferred_parameter_type)
        || type_node.parent().is_some_and(|parent| {
            parent.kind() == "parameter" && subtree_contains(parent, scala_deferred_parameter_type)
        })
    {
        return None;
    }
    let segments = scala_type_lookup_segments(type_node, source);
    let name = match segments
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        [name] | ["scala", name] => *name,
        _ => return None,
    };
    scala_scalar_type_for_primitive_name(name)
}

fn scala_scalar_type_for_primitive_name(name: &str) -> Option<DeclaredScalarType> {
    match name {
        "Int" => Some(DeclaredScalarType::Signed(32)),
        "Long" => Some(DeclaredScalarType::Signed(64)),
        "Short" => Some(DeclaredScalarType::Signed(16)),
        "Byte" => Some(DeclaredScalarType::Signed(8)),
        "Boolean" => Some(DeclaredScalarType::Boolean),
        _ => None,
    }
}

fn scala_deferred_parameter_type(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "by_name_type" | "lazy_parameter_type" | "repeated_parameter_type"
    )
}

/// The scalar type of a Scala `val` or `var`, using only its exact written
/// primitive type or a direct decimal integer/Boolean literal initializer.
pub(crate) fn scala_scalar_type_for_definition(
    source: &str,
    definition: Node<'_>,
) -> Option<DeclaredScalarType> {
    if !matches!(definition.kind(), "val_definition" | "var_definition")
        || subtree_contains(definition, |node| {
            matches!(node.kind(), "lazy_modifier" | "lazy") || has_direct_token(node, "lazy")
        })
    {
        return None;
    }
    definition
        .child_by_field_name("type")
        .and_then(|type_node| scala_scalar_type_for_type(source, type_node))
        .or_else(|| {
            definition
                .child_by_field_name("value")
                .and_then(|value| scala_scalar_type_for_literal(source, value))
        })
}

/// The declared scalar type of each Scala by-value parameter and local whose
/// type is exactly `Int`, `Long`, `Short`, `Byte`, or `Boolean`, or whose
/// initializer is a direct decimal integer or Boolean literal. By-name
/// parameters, lazy values, fields, aliases, and non-literal expressions have
/// no entry.
pub fn scala_declared_scalar_types(
    procedure: &ProcedureHandle,
    prepared: &PreparedSyntaxTree,
) -> Vec<(ValueId, DeclaredScalarType)> {
    let source = prepared.source();
    binding_nodes(procedure, prepared)
        .into_iter()
        .filter_map(|(value, parameter, node)| {
            let scalar_type = if parameter {
                (node.kind() == "parameter")
                    .then(|| node.child_by_field_name("type"))
                    .flatten()
                    .and_then(|type_node| scala_scalar_type_for_type(source, type_node))
            } else {
                (node.kind() == "identifier")
                    .then(|| node.parent())
                    .flatten()
                    .and_then(|definition| scala_scalar_type_for_definition(source, definition))
            }?;
            Some((value, scalar_type))
        })
        .collect()
}
