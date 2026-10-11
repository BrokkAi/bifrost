//! Bounded C and C++ range facts for the direct CodeQL parity slice.
//!
//! The producer reads the prepared tree and only returns facts whose operands
//! and relationships are explicit in that tree. It does not scan source text
//! for patterns or retain a workspace-sized range graph.

use crate::CancellationToken;
use crate::analyzer::structural::provider::StructuralSyntaxLimitedOutcome;
use crate::analyzer::{IAnalyzer, Language, ProjectFile, Range};
use brokk_bifrost_core::analyzer::cpp_facts::{
    CppArrayStorage, CppLoopDirection, CppRangeFact, CppRangeFactOutcome,
};
use brokk_bifrost_core::analyzer::tree_walk::node_range;
use brokk_bifrost_cpp::structural::declarator_name_node;
use tree_sitter::Node;

const MAX_RANGE_SOURCE_BYTES: usize = 1_048_576;

/// Check the exact call range for the `strncpy` size relation.
pub fn bad_strncpy_size(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    call_range: Range,
    cancellation: Option<&CancellationToken>,
) -> CppRangeFactOutcome {
    let Some(prepared) = prepared_cpp(analyzer, file, cancellation) else {
        return CppRangeFactOutcome::Incomplete("cpp_syntax_unavailable");
    };
    let source = prepared.source();
    let root = prepared.tree().root_node();
    let Some(call) = exact_node(root, call_range) else {
        return CppRangeFactOutcome::Incomplete("call_syntax_missing");
    };
    if call.kind() != "call_expression" {
        return CppRangeFactOutcome::NotApplicable;
    }
    let Some(function) = call.child_by_field_name("function") else {
        return CppRangeFactOutcome::Incomplete("call_function_missing");
    };
    if terminal_name(function, source) != Some("strncpy") {
        return CppRangeFactOutcome::NotApplicable;
    }
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return CppRangeFactOutcome::Incomplete("call_arguments_missing");
    };
    let arguments = named_children(arguments);
    if arguments.len() < 3 {
        return CppRangeFactOutcome::Incomplete("strncpy_argument_shape_incomplete");
    }
    let Some(destination) = terminal_name(arguments[0], source) else {
        return CppRangeFactOutcome::Incomplete("destination_operand_unavailable");
    };
    let Some(size_expression) = arguments[2]
        .kind()
        .eq("sizeof_expression")
        .then_some(arguments[2])
    else {
        return CppRangeFactOutcome::NotApplicable;
    };
    let Some(size_operand) = size_expression.child_by_field_name("value") else {
        return CppRangeFactOutcome::Incomplete("sizeof_operand_unavailable");
    };
    let Some(source_name) = terminal_name(size_operand, source) else {
        return CppRangeFactOutcome::Incomplete("source_operand_unavailable");
    };
    let extents = fixed_array_extents(root, source);
    let Some(destination_extent) = extents
        .iter()
        .find_map(|(name, extent, _)| (name == destination).then_some(*extent))
    else {
        return CppRangeFactOutcome::Incomplete("destination_extent_unavailable");
    };
    let Some(source_extent) = extents
        .iter()
        .find_map(|(name, extent, _)| (name == source_name).then_some(*extent))
    else {
        return CppRangeFactOutcome::Incomplete("source_extent_unavailable");
    };
    if source_extent <= destination_extent {
        return CppRangeFactOutcome::NotApplicable;
    }
    CppRangeFactOutcome::Proven(CppRangeFact::BadStrncpySize {
        range: node_range(call),
        destination_extent,
        source_extent,
    })
}

/// Check one exact C/C++ `for_statement` for an update direction opposite to
/// its comparison direction.
pub fn inconsistent_loop_direction(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    loop_range: Range,
    cancellation: Option<&CancellationToken>,
) -> CppRangeFactOutcome {
    let Some(prepared) = prepared_cpp(analyzer, file, cancellation) else {
        return CppRangeFactOutcome::Incomplete("cpp_syntax_unavailable");
    };
    let source = prepared.source();
    let root = prepared.tree().root_node();
    let Some(loop_node) = exact_node(root, loop_range) else {
        return CppRangeFactOutcome::Incomplete("loop_syntax_missing");
    };
    if loop_node.kind() != "for_statement" {
        return CppRangeFactOutcome::NotApplicable;
    }
    let Some(initializer) = loop_node.child_by_field_name("initializer") else {
        return CppRangeFactOutcome::Incomplete("loop_initializer_missing");
    };
    let Some(condition) = loop_node.child_by_field_name("condition") else {
        return CppRangeFactOutcome::Incomplete("loop_condition_missing");
    };
    let Some(update) = loop_node.child_by_field_name("update") else {
        return CppRangeFactOutcome::Incomplete("loop_update_missing");
    };
    let Some(variable) = first_identifier(initializer, source) else {
        return CppRangeFactOutcome::Incomplete("loop_variable_missing");
    };
    let Some((condition_variable, condition_direction)) = comparison_direction(condition, source)
    else {
        return CppRangeFactOutcome::Incomplete("loop_condition_direction_unknown");
    };
    let Some((update_variable, update_direction)) = update_direction(update, source) else {
        return CppRangeFactOutcome::Incomplete("loop_update_direction_unknown");
    };
    if variable != condition_variable || variable != update_variable {
        return CppRangeFactOutcome::NotApplicable;
    }
    if condition_direction == update_direction {
        return CppRangeFactOutcome::NotApplicable;
    }
    CppRangeFactOutcome::Proven(CppRangeFact::InconsistentLoopDirection {
        range: node_range(loop_node),
        condition: condition_direction,
        update: update_direction,
    })
}

/// Check whether a numeric seed is the extent of a fixed array or a vector
/// constructor with the calendar constant 365.
pub fn unsafe_array_for_days_of_the_year(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    seed_range: Range,
    cancellation: Option<&CancellationToken>,
) -> CppRangeFactOutcome {
    let Some(prepared) = prepared_cpp(analyzer, file, cancellation) else {
        return CppRangeFactOutcome::Incomplete("cpp_syntax_unavailable");
    };
    let source = prepared.source();
    let root = prepared.tree().root_node();
    let Some(seed) = exact_node(root, seed_range) else {
        return CppRangeFactOutcome::Incomplete("extent_syntax_missing");
    };
    if seed.kind() != "number_literal" {
        return CppRangeFactOutcome::NotApplicable;
    }
    if numeric_value(seed, source) != Some(365) {
        return CppRangeFactOutcome::NotApplicable;
    }
    for array in nodes(root).filter(|node| node.kind() == "array_declarator") {
        let Some(size) = array.child_by_field_name("size") else {
            continue;
        };
        if size.start_byte() == seed.start_byte() && size.end_byte() == seed.end_byte() {
            return CppRangeFactOutcome::Proven(CppRangeFact::UnsafeArrayExtent {
                range: node_range(seed),
                extent: 365,
                storage: CppArrayStorage::FixedArray,
            });
        }
    }
    for call in nodes(root).filter(|node| node.kind() == "call_expression") {
        let Some(function) = call.child_by_field_name("function") else {
            continue;
        };
        if terminal_name(function, source) != Some("vector") {
            continue;
        }
        let Some(arguments) = call.child_by_field_name("arguments") else {
            continue;
        };
        if named_children(arguments).into_iter().any(|argument| {
            argument.start_byte() == seed.start_byte() && argument.end_byte() == seed.end_byte()
        }) {
            return CppRangeFactOutcome::Proven(CppRangeFact::UnsafeArrayExtent {
                range: node_range(seed),
                extent: 365,
                storage: CppArrayStorage::VectorConstructor,
            });
        }
    }
    for initializer in nodes(root).filter(|node| node.kind() == "init_declarator") {
        let Some(arguments) = initializer.child_by_field_name("value") else {
            continue;
        };
        if arguments.kind() != "argument_list"
            || !named_children(arguments).into_iter().any(|argument| {
                argument.start_byte() == seed.start_byte() && argument.end_byte() == seed.end_byte()
            })
        {
            continue;
        }
        let Some(declaration) = initializer.parent() else {
            continue;
        };
        let Some(type_node) = declaration
            .kind()
            .eq("declaration")
            .then(|| declaration.child_by_field_name("type"))
            .flatten()
        else {
            continue;
        };
        if terminal_name(type_node, source) == Some("vector") {
            return CppRangeFactOutcome::Proven(CppRangeFact::UnsafeArrayExtent {
                range: node_range(seed),
                extent: 365,
                storage: CppArrayStorage::VectorConstructor,
            });
        }
    }
    CppRangeFactOutcome::NotApplicable
}

/// Check one exact call for a direct `ntohl` result used as the third
/// argument of `memcpy`. The caller applies exact library identity selection
/// through the existing call-binding relation before invoking this producer.
pub fn network_to_host_function_as_array_bound(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    call_range: Range,
    cancellation: Option<&CancellationToken>,
) -> CppRangeFactOutcome {
    let Some(prepared) = prepared_cpp(analyzer, file, cancellation) else {
        return CppRangeFactOutcome::Incomplete("cpp_syntax_unavailable");
    };
    let source = prepared.source();
    let root = prepared.tree().root_node();
    let Some(call) = exact_node(root, call_range) else {
        return CppRangeFactOutcome::Incomplete("call_syntax_missing");
    };
    if call.kind() != "call_expression" {
        return CppRangeFactOutcome::NotApplicable;
    }
    let Some(function) = call.child_by_field_name("function") else {
        return CppRangeFactOutcome::Incomplete("call_function_missing");
    };
    if terminal_name(function, source) != Some("ntohl") {
        return CppRangeFactOutcome::NotApplicable;
    }
    let mut ancestor = call;
    while let Some(parent) = ancestor.parent() {
        if parent.kind() == "call_expression" {
            let Some(parent_function) = parent.child_by_field_name("function") else {
                return CppRangeFactOutcome::Incomplete("memcpy_function_missing");
            };
            if terminal_name(parent_function, source) != Some("memcpy") {
                ancestor = parent;
                continue;
            }
            let Some(arguments) = parent.child_by_field_name("arguments") else {
                return CppRangeFactOutcome::Incomplete("memcpy_arguments_missing");
            };
            let arguments = named_children(arguments);
            let Some(bound) = arguments.get(2).copied().map(unwrap_expression) else {
                return CppRangeFactOutcome::Incomplete("memcpy_bound_argument_missing");
            };
            if bound.start_byte() != call.start_byte() || bound.end_byte() != call.end_byte() {
                return CppRangeFactOutcome::NotApplicable;
            }
            return CppRangeFactOutcome::Proven(CppRangeFact::NetworkToHostFunctionAsArrayBound {
                range: node_range(parent),
            });
        }
        ancestor = parent;
    }
    CppRangeFactOutcome::NotApplicable
}

fn prepared_cpp(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    cancellation: Option<&CancellationToken>,
) -> Option<std::sync::Arc<crate::analyzer::tree_sitter_analyzer::PreparedSyntaxTree>> {
    let provider = analyzer
        .structural_fact_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == Language::Cpp)?;
    let outcome = provider.structural_syntax_limited(file, MAX_RANGE_SOURCE_BYTES, cancellation);
    let prepared = match outcome {
        StructuralSyntaxLimitedOutcome::Available(prepared) => prepared.clone_prepared(),
        StructuralSyntaxLimitedOutcome::Exceeded { .. }
        | StructuralSyntaxLimitedOutcome::Cancelled
        | StructuralSyntaxLimitedOutcome::Unavailable => return None,
    };
    Some(prepared)
}

fn exact_node<'tree>(root: Node<'tree>, range: Range) -> Option<Node<'tree>> {
    nodes(root)
        .find(|node| node.start_byte() == range.start_byte && node.end_byte() == range.end_byte)
}

fn nodes<'tree>(root: Node<'tree>) -> impl Iterator<Item = Node<'tree>> {
    let mut stack = vec![root];
    std::iter::from_fn(move || {
        let node = stack.pop()?;
        let mut children = named_children(node);
        let mut reversed = Vec::new();
        while let Some(child) = children.pop() {
            reversed.push(child);
        }
        stack.extend(reversed);
        Some(node)
    })
}

fn named_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

fn first_identifier(node: Node<'_>, source: &str) -> Option<String> {
    nodes(node)
        .find(|node| node.kind() == "identifier")
        .and_then(|node| node.utf8_text(source.as_bytes()).ok())
        .map(ToOwned::to_owned)
}

pub(crate) fn terminal_name<'source>(node: Node<'_>, source: &'source str) -> Option<&'source str> {
    let mut current = node;
    loop {
        match current.kind() {
            "identifier"
            | "field_identifier"
            | "namespace_identifier"
            | "type_identifier"
            | "primitive_type" => return current.utf8_text(source.as_bytes()).ok(),
            "qualified_identifier"
            | "dependent_name"
            | "template_function"
            | "template_method"
            | "template_type" => {
                current = current
                    .child_by_field_name("name")
                    .or_else(|| current.named_child(current.named_child_count().checked_sub(1)?))?;
            }
            "field_expression" => current = current.child_by_field_name("field")?,
            "parenthesized_expression" => current = current.named_child(0)?,
            _ => {
                return declarator_name_node(current)
                    .and_then(|name| name.utf8_text(source.as_bytes()).ok());
            }
        }
    }
}

fn numeric_value(node: Node<'_>, source: &str) -> Option<u64> {
    let text = node.utf8_text(source.as_bytes()).ok()?.trim();
    text.parse().ok()
}

fn unwrap_expression(mut node: Node<'_>) -> Node<'_> {
    loop {
        let next = match node.kind() {
            "cast_expression" => node
                .child_by_field_name("value")
                .or_else(|| node.named_child(1)),
            "parenthesized_expression" => node.named_child(0),
            _ => None,
        };
        let Some(next) = next else {
            return node;
        };
        node = next;
    }
}

fn fixed_array_extents<'tree>(root: Node<'tree>, source: &str) -> Vec<(String, u64, Range)> {
    nodes(root)
        .filter(|node| node.kind() == "array_declarator")
        .filter_map(|array| {
            let size = array.child_by_field_name("size")?;
            let extent = numeric_value(size, source)?;
            let name = declarator_name_node(array)?;
            Some((
                name.utf8_text(source.as_bytes()).ok()?.to_owned(),
                extent,
                node_range(array),
            ))
        })
        .collect()
}

fn comparison_direction(condition: Node<'_>, source: &str) -> Option<(String, CppLoopDirection)> {
    let left = condition.child_by_field_name("left")?;
    let operator = named_or_anonymous_operator(condition, &["<", "<=", ">", ">="])?;
    let variable = terminal_name(left, source)?.to_owned();
    let direction = match operator {
        "<" | "<=" => CppLoopDirection::Increasing,
        ">" | ">=" => CppLoopDirection::Decreasing,
        _ => return None,
    };
    Some((variable, direction))
}

fn update_direction(node: Node<'_>, source: &str) -> Option<(String, CppLoopDirection)> {
    let variable = terminal_name(node.child_by_field_name("argument")?, source)?.to_owned();
    let operator = named_or_anonymous_operator(node, &["++", "--"])?;
    let direction = match operator {
        "++" => CppLoopDirection::Increasing,
        "--" => CppLoopDirection::Decreasing,
        _ => return None,
    };
    Some((variable, direction))
}

fn named_or_anonymous_operator(
    node: Node<'_>,
    operators: &'static [&'static str],
) -> Option<&'static str> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(operator) = operators
            .iter()
            .copied()
            .find(|operator| child.kind() == *operator)
        {
            return Some(operator);
        }
    }
    None
}
