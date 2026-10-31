//! Typed Python string-construction slots used by full and partial SSRF rules.

use super::environment::EnvironmentTraversalCache;
use super::python_format_issues::{
    FormatArguments, PythonFormatSyntaxCache, call_arguments, decoded_string_operand, exact_node,
    unwrap_parentheses,
};
use super::python_rule_facts::{make_row, row_range};
use super::python_variables::PythonInitializerProof;
use super::*;
use crate::analyzer::structural::lexical_environment::EnvironmentFileResult;
use brokk_bifrost_python::decode_python_fstring_literal_segments;
use brokk_bifrost_python::format_string::{
    BraceSelector, parse_brace_format, parse_percent_format,
};
use regex::Regex;
use std::sync::LazyLock;
use tree_sitter::{Node, Tree};

const RELATION: &str = "url_construction";
static CODEQL_FORMAT_PREFIX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^https?://(?:(\{\})|\{([0-9]+)\}|\{([^0-9].*)\}).*$")
        .expect("the fixed CodeQL URL-format pattern is valid")
});

#[derive(Clone)]
struct Slot<'tree> {
    node: Node<'tree>,
    outcome: &'static str,
    prefix: Option<String>,
    reason: Option<&'static str>,
}

/// Expand an exact Python string-construction node into per-slot control facts.
pub(super) fn expansions_for_seed(
    analyzer: &dyn IAnalyzer,
    seed: &SeedMatch,
    environment_cache: &mut EnvironmentTraversalCache,
    syntax_cache: &mut PythonFormatSyntaxCache,
) -> Vec<PipelineExpansion> {
    if seed.language != Language::Python {
        return Vec::new();
    }
    let fact = seed.facts.node(seed.fact_match.node);
    let source = seed.facts.source();
    let Some(tree) = syntax_cache.tree(&seed.file, source) else {
        return Vec::new();
    };
    let Some(node) = exact_node(&tree, fact.range.start_byte, fact.range.end_byte) else {
        return Vec::new();
    };
    match fact.kind {
        NormalizedKind::BinaryExpression => {
            binary_slots(analyzer, seed, node, &tree, environment_cache)
        }
        NormalizedKind::Call => format_call_slots(analyzer, seed, node, &tree, environment_cache),
        NormalizedKind::StringLiteral if node.kind() == "string" => {
            fstring_slots(seed, node, &tree)
        }
        _ => Vec::new(),
    }
}

fn binary_slots(
    analyzer: &dyn IAnalyzer,
    seed: &SeedMatch,
    binary: Node<'_>,
    tree: &Tree,
    environment_cache: &mut EnvironmentTraversalCache,
) -> Vec<PipelineExpansion> {
    if binary.kind() != "binary_operator" || binary.has_error() {
        return Vec::new();
    }
    let source = seed.facts.source();
    let operators = seed
        .facts
        .role_targets(seed.fact_match.node, Role::Operator)
        .collect::<Vec<_>>();
    let [operator] = operators.as_slice() else {
        return Vec::new();
    };
    let Some(operator_text) = source.get(operator.span.start_byte..operator.span.end_byte) else {
        return Vec::new();
    };
    let Some(left) = binary.child_by_field_name("left") else {
        return vec![incomplete_expansion(
            seed,
            binary,
            None,
            "python_url_left_operand_missing",
        )];
    };
    let Some(right) = binary.child_by_field_name("right") else {
        return vec![incomplete_expansion(
            seed,
            binary,
            None,
            "python_url_right_operand_missing",
        )];
    };
    let environment = environment_cache.environment_for(analyzer, &seed.file);
    let initializers =
        environment_cache.python_initializer_proof_for(analyzer, &seed.file, &seed.facts);
    match operator_text {
        "+" => {
            let left = unwrap_parentheses(left);
            let right = unwrap_parentheses(right);
            let prefix = decoded_string_operand(
                left,
                source,
                &seed.facts,
                tree,
                &environment,
                initializers.as_ref(),
            );
            let mut slots = Vec::new();
            match prefix {
                Ok(Some(prefix)) => {
                    slots.push(Slot {
                        node: left,
                        outcome: "full_control",
                        prefix: Some(String::new()),
                        reason: None,
                    });
                    slots.push(Slot {
                        node: right,
                        outcome: if is_scheme_only(&prefix) {
                            "full_control"
                        } else {
                            "partial_control"
                        },
                        prefix: Some(prefix),
                        reason: None,
                    });
                }
                Ok(None) => slots.push(Slot {
                    node: right,
                    outcome: "unknown",
                    prefix: None,
                    reason: Some("python_url_left_prefix_not_string"),
                }),
                Err(reason) => slots.push(Slot {
                    node: right,
                    outcome: "unknown",
                    prefix: None,
                    reason: Some(reason),
                }),
            }
            emit_slots(seed, binary, slots)
        }
        "%" => percent_slots(
            seed,
            binary,
            left,
            right,
            tree,
            &environment,
            initializers.as_ref(),
        ),
        _ => Vec::new(),
    }
}

fn percent_slots(
    seed: &SeedMatch,
    binary: Node<'_>,
    left: Node<'_>,
    right: Node<'_>,
    tree: &Tree,
    environment: &EnvironmentFileResult,
    initializers: Option<&PythonInitializerProof>,
) -> Vec<PipelineExpansion> {
    let source = seed.facts.source();
    let decoded =
        match decoded_string_operand(left, source, &seed.facts, tree, environment, initializers) {
            Ok(Some(value)) => value,
            Ok(None) => {
                return vec![incomplete_expansion(
                    seed,
                    right,
                    None,
                    "python_url_percent_format_not_string",
                )];
            }
            Err(reason) => return vec![incomplete_expansion(seed, right, None, reason)],
        };
    let parsed = parse_percent_format(&decoded);
    if !parsed.complete {
        return vec![incomplete_expansion(
            seed,
            right,
            None,
            "python_url_percent_format_parse_incomplete",
        )];
    }
    let Some(first) = parsed.items.first() else {
        return Vec::new();
    };
    let node = unwrap_parentheses(right);
    let outcome = if codeql_percent_prefix(&decoded) {
        "full_control"
    } else {
        "partial_control"
    };
    emit_slots(
        seed,
        binary,
        vec![Slot {
            node,
            outcome,
            prefix: Some(value_prefix(&decoded, first.source_char)),
            reason: None,
        }],
    )
}

fn format_call_slots(
    analyzer: &dyn IAnalyzer,
    seed: &SeedMatch,
    call: Node<'_>,
    tree: &Tree,
    environment_cache: &mut EnvironmentTraversalCache,
) -> Vec<PipelineExpansion> {
    if call.kind() != "call" || call.has_error() {
        return Vec::new();
    }
    let source = seed.facts.source();
    let Some(function) = call.child_by_field_name("function") else {
        return Vec::new();
    };
    if function.kind() != "attribute"
        || function
            .child_by_field_name("attribute")
            .and_then(|node| node_text(node, source))
            != Some("format")
    {
        return Vec::new();
    }
    let Some(receiver) = function.child_by_field_name("object") else {
        return vec![incomplete_expansion(
            seed,
            call,
            None,
            "python_url_format_receiver_missing",
        )];
    };
    let environment = environment_cache.environment_for(analyzer, &seed.file);
    let initializers =
        environment_cache.python_initializer_proof_for(analyzer, &seed.file, &seed.facts);
    let decoded = match decoded_string_operand(
        receiver,
        source,
        &seed.facts,
        tree,
        &environment,
        initializers.as_ref(),
    ) {
        Ok(Some(value)) => value,
        Ok(None) => {
            return vec![incomplete_expansion(
                seed,
                call,
                None,
                "python_url_format_string_not_literal",
            )];
        }
        Err(reason) => return vec![incomplete_expansion(seed, call, None, reason)],
    };
    let parsed = parse_brace_format(&decoded);
    if !parsed.complete {
        return vec![incomplete_expansion(
            seed,
            call,
            None,
            "python_url_brace_format_parse_incomplete",
        )];
    }
    if parsed.fields.is_empty() {
        return Vec::new();
    }
    let arguments = match call_arguments(call, source) {
        Ok(arguments) if !arguments.positional_open && !arguments.named_open => arguments,
        Ok(_) => {
            return vec![incomplete_expansion(
                seed,
                call,
                None,
                "python_url_format_expanded_arguments",
            )];
        }
        Err(reason) => return vec![incomplete_expansion(seed, call, None, reason)],
    };
    let full_selector = codeql_brace_full_selector(&decoded);
    let mut slots = Vec::new();
    for field in &parsed.fields {
        let Some(argument) = argument_for_selector(&arguments, &field.selector) else {
            return vec![incomplete_expansion(
                seed,
                call,
                Some(value_prefix(&decoded, field.source_char)),
                "python_url_format_argument_mapping_incomplete",
            )];
        };
        slots.push(Slot {
            node: argument,
            outcome: if full_selector.as_ref() == Some(&field.selector) {
                "full_control"
            } else {
                "partial_control"
            },
            prefix: Some(value_prefix(&decoded, field.source_char)),
            reason: None,
        });
    }
    emit_slots(seed, call, coalesce_slots(slots))
}

fn fstring_slots(seed: &SeedMatch, string: Node<'_>, _tree: &Tree) -> Vec<PipelineExpansion> {
    let mut cursor = string.walk();
    let interpolations = string
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "interpolation")
        .collect::<Vec<_>>();
    if interpolations.is_empty() {
        return Vec::new();
    }
    let source = seed.facts.source();
    let literal_segments = match decode_python_fstring_literal_segments(string, source) {
        Ok(segments) => segments,
        Err(reason) => {
            return vec![incomplete_expansion(seed, string, None, reason)];
        }
    };
    if literal_segments.len() != interpolations.len() + 1 {
        return vec![incomplete_expansion(
            seed,
            string,
            literal_segments.first().cloned(),
            "python_url_fstring_segments_incomplete",
        )];
    }
    let scheme_only = literal_segments
        .first()
        .is_some_and(|prefix| is_scheme_only(prefix));
    let mut slots = Vec::with_capacity(interpolations.len());
    let mut prefix = String::new();
    for (index, interpolation) in interpolations.into_iter().enumerate() {
        prefix.push_str(&literal_segments[index]);
        let Some(expression) = interpolation.child_by_field_name("expression") else {
            return vec![incomplete_expansion(
                seed,
                string,
                Some(prefix),
                "python_url_fstring_expression_missing",
            )];
        };
        slots.push(Slot {
            node: expression,
            outcome: if scheme_only && index > 0 {
                "partial_control"
            } else {
                "full_control"
            },
            prefix: Some(prefix.clone()),
            reason: None,
        });
    }
    emit_slots(seed, string, slots)
}

fn argument_for_selector<'tree>(
    arguments: &FormatArguments<'tree>,
    selector: &BraceSelector,
) -> Option<Node<'tree>> {
    match selector {
        BraceSelector::Automatic(index) | BraceSelector::Positional(index) => {
            arguments.positional_nodes.get(*index).copied()
        }
        BraceSelector::Named(name) => arguments.named_nodes.get(name).copied(),
    }
}

fn codeql_brace_full_selector(format: &str) -> Option<BraceSelector> {
    let captures = CODEQL_FORMAT_PREFIX.captures(format)?;
    if captures.get(1).is_some() {
        Some(BraceSelector::Automatic(0))
    } else if let Some(index) = captures.get(2) {
        index.as_str().parse().ok().map(BraceSelector::Positional)
    } else {
        captures
            .get(3)
            .map(|name| BraceSelector::Named(name.as_str().to_owned()))
    }
}

fn codeql_percent_prefix(format: &str) -> bool {
    let scheme_length = if format
        .get(..8)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https://"))
    {
        8
    } else if format
        .get(..7)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("http://"))
    {
        7
    } else {
        return false;
    };
    let Some(after_scheme) = format.get(scheme_length..) else {
        return false;
    };
    after_scheme
        .get(..2)
        .is_some_and(|conversion| conversion.eq_ignore_ascii_case("%s"))
        && after_scheme[2..].chars().all(|character| character != '%')
}

fn is_scheme_only(prefix: &str) -> bool {
    prefix.eq_ignore_ascii_case("http://") || prefix.eq_ignore_ascii_case("https://")
}

fn value_prefix(value: &str, end_char: usize) -> String {
    value.chars().take(end_char).collect()
}

fn coalesce_slots<'tree>(slots: Vec<Slot<'tree>>) -> Vec<Slot<'tree>> {
    let mut result: Vec<Slot<'tree>> = Vec::new();
    for slot in slots {
        if let Some(existing) = result.iter_mut().find(|existing| {
            existing.node.start_byte() == slot.node.start_byte()
                && existing.node.end_byte() == slot.node.end_byte()
        }) {
            if slot.outcome == "full_control" {
                existing.outcome = "full_control";
            }
            continue;
        }
        result.push(slot);
    }
    result
}

fn emit_slots(
    seed: &SeedMatch,
    construction: Node<'_>,
    slots: Vec<Slot<'_>>,
) -> Vec<PipelineExpansion> {
    slots
        .into_iter()
        .enumerate()
        .map(|(index, slot)| {
            let range = slot.node.start_byte()..slot.node.end_byte();
            let display = row_range(seed.facts.source(), range.clone());
            let complete = slot.reason.is_none();
            let mut value = make_row(
                Incompleteness::Content,
                RELATION,
                &seed.file,
                range.clone(),
                display,
                None,
                slot.outcome,
                if complete { "proven" } else { "none" },
                complete,
                slot.reason.map(str::to_owned),
            );
            let mut digest = crate::analyzer::semantic::LengthDelimitedDigest::new(
                b"bifrost.code_query.python_url_construction.v1",
            );
            digest.push(rel_path_string(&seed.file).as_bytes());
            digest.push(&(construction.start_byte() as u64).to_le_bytes());
            digest.push(&(construction.end_byte() as u64).to_le_bytes());
            digest.push(&(range.start as u64).to_le_bytes());
            digest.push(&(range.end as u64).to_le_bytes());
            digest.push(&(index as u64).to_le_bytes());
            value.row.id = digest.finish().to_string();
            value.row.url_prefix = slot.prefix;
            pipeline_expansion(PipelineValue::PythonRuleFact(Box::new(value)))
        })
        .collect()
}

fn incomplete_expansion(
    seed: &SeedMatch,
    node: Node<'_>,
    prefix: Option<String>,
    reason: &'static str,
) -> PipelineExpansion {
    let mut expansions = emit_slots(
        seed,
        node,
        vec![Slot {
            node,
            outcome: "unknown",
            prefix,
            reason: Some(reason),
        }],
    );
    expansions
        .pop()
        .expect("one unknown slot creates one rule fact")
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    node.utf8_text(source.as_bytes()).ok()
}
