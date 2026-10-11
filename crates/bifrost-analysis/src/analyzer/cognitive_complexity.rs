//! Generic cognitive-complexity scorer driven by per-language tree-sitter
//! configuration. Ported from `ai.brokk.analyzer.CognitiveComplexitySupport`
//! in brokk-shared so the bifrost MCP output stays byte-for-byte aligned with
//! brokk-core's `computeCognitiveComplexity` tool.
//!
//! Each language analyzer supplies a [`Config`] that maps tree-sitter node
//! types to the SonarSource cognitive-complexity categories (`if`, loops,
//! catch, ternary, switch case, binary boolean, jumps). The scorer walks the
//! AST iteratively (no recursion to keep deeply nested code safe) and
//! accumulates per-frame nesting, mirroring the reference implementation.

// The `Config` a language declares is plain data -- node-kind tables and
// function-pointer predicates -- so it lives in `brokk-bifrost-core` and is
// re-exported here at its historical path. Only the scorer stays.
use brokk_bifrost_core::analyzer::cognitive_complexity::slice_contains;
pub use brokk_bifrost_core::analyzer::cognitive_complexity::{
    CallableMetrics, CallableMetricsCoverage, CaseIncrementPredicate, Config, DefaultCasePredicate,
    JumpPredicate, NamedFunctionBoundaryPredicate, is_wildcard_case,
};
use brokk_bifrost_core::analyzer::semantic_diagnostics::same_node;
use brokk_bifrost_core::analyzer::tree_walk::{is_comment_kind, node_range};

use crate::analyzer::tree_walk::named_children;
use tree_sitter::Node;

struct Frame<'tree> {
    node: Node<'tree>,
    nesting: u32,
    else_if_continuation: bool,
    root: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WalkMode {
    /// Preserve the historical MCP scorer semantics, including descending into
    /// configured anonymous functions with one extra nesting level.
    Legacy,
    /// Treat every nested callable as a separate owner and retain only the
    /// executable leaves owned by the root callable.
    CallableMetrics,
}

#[derive(Debug, Clone, Copy, Default)]
struct WalkResult {
    complexity: u32,
    max_nesting: u32,
    owned_start_line: Option<usize>,
    owned_end_line: Option<usize>,
}

/// Compute the cognitive complexity of `root` according to `config`.
///
/// `root` should be the tree-sitter node representing the function/method
/// whose complexity is being measured; the scorer walks its subtree.
/// `source` is the full source text of the file, used to disambiguate
/// default/wildcard switch cases and to read the bytes of anonymous
/// logical-operator tokens.
pub fn compute(root: Node<'_>, source: &str, config: &Config) -> u32 {
    walk(root, source, config, WalkMode::Legacy).complexity
}

/// Compute the structured metrics used by the query-local `callable_metrics`
/// relation. Nested named and anonymous callables are ownership boundaries;
/// their bodies are not included in the enclosing callable's complexity,
/// nesting, or owned executable span.
pub fn compute_metrics(root: Node<'_>, source: &str, config: &Config) -> CallableMetrics {
    let body = root.child_by_field_name("body");
    let result = walk(root, source, config, WalkMode::CallableMetrics);
    let Some(body) = body else {
        return CallableMetrics {
            coverage: CallableMetricsCoverage::Incomplete,
            max_nesting: Some(result.max_nesting),
            cognitive_complexity: Some(result.complexity),
            owned_body_span_lines: None,
        };
    };
    let coverage = if root.has_error() || root.is_missing() || body.has_error() || body.is_missing()
    {
        CallableMetricsCoverage::Incomplete
    } else {
        CallableMetricsCoverage::Exact
    };
    let owned_body_span_lines = result
        .owned_start_line
        .zip(result.owned_end_line)
        .map(|(start, end)| end.saturating_sub(start).saturating_add(1) as u32);
    CallableMetrics {
        coverage,
        max_nesting: Some(result.max_nesting),
        cognitive_complexity: Some(result.complexity),
        owned_body_span_lines,
    }
}

fn walk(root: Node<'_>, source: &str, config: &Config, mode: WalkMode) -> WalkResult {
    let mut complexity: u32 = 0;
    let mut max_nesting: u32 = 0;
    let mut owned_start_line: Option<usize> = None;
    let mut owned_end_line: Option<usize> = None;
    let owned_body = root.child_by_field_name("body");
    let mut work: Vec<Frame<'_>> = Vec::new();
    work.push(Frame {
        node: root,
        nesting: 0,
        else_if_continuation: false,
        root: true,
    });

    while let Some(frame) = work.pop() {
        let node = frame.node;
        let kind = node.kind();

        if config.is_any_if(kind) {
            if mode == WalkMode::CallableMetrics {
                max_nesting = max_nesting.max(frame.nesting.saturating_add(1));
            }
            complexity = complexity.saturating_add(if frame.else_if_continuation {
                1
            } else {
                control_flow_increment(frame.nesting)
            });
            push_if_children(&mut work, node, frame.nesting, config);
        } else if slice_contains(config.loop_types, kind)
            || slice_contains(config.catch_types, kind)
            || slice_contains(config.conditional_types, kind)
        {
            if mode == WalkMode::CallableMetrics {
                max_nesting = max_nesting.max(frame.nesting.saturating_add(1));
            }
            complexity = complexity.saturating_add(control_flow_increment(frame.nesting));
            push_named_children(&mut work, node, frame.nesting + 1, false);
        } else if slice_contains(config.case_types, kind) {
            if mode == WalkMode::CallableMetrics {
                max_nesting = max_nesting.max(frame.nesting.saturating_add(1));
            }
            let case_count = config.case_increment_predicate.map_or_else(
                || {
                    u32::from(
                        !config
                            .default_case_predicate
                            .map(|pred| pred(node, source))
                            .unwrap_or(false),
                    )
                },
                |predicate| predicate(node, source),
            );
            complexity = complexity
                .saturating_add(control_flow_increment(frame.nesting).saturating_mul(case_count));
            push_named_children(&mut work, node, frame.nesting + 1, false);
        } else if slice_contains(config.default_case_types, kind) {
            push_named_children(&mut work, node, frame.nesting, false);
        } else if slice_contains(config.binary_types, kind) {
            if !is_nested_in_types(node, config.binary_types) {
                complexity = complexity
                    .saturating_add(logical_operator_sequence_count(node, source, config));
            }
            push_named_children(&mut work, node, frame.nesting, false);
        } else if slice_contains(config.jump_types, kind) {
            if config
                .jump_predicate
                .map_or_else(|| is_labeled_jump(node), |predicate| predicate(node))
            {
                complexity = complexity.saturating_add(1);
            }
            push_named_children(&mut work, node, frame.nesting, false);
        } else {
            let named_boundary = slice_contains(config.named_function_boundary_types, kind)
                || config
                    .named_function_boundary_predicate
                    .map(|pred| pred(node))
                    .unwrap_or(false);
            let anonymous_boundary = slice_contains(config.anonymous_function_types, kind);
            if !frame.root
                && (named_boundary || (mode == WalkMode::CallableMetrics && anonymous_boundary))
            {
                continue;
            }
            if mode == WalkMode::CallableMetrics
                && !frame.root
                && owned_body.is_some_and(|body| {
                    !same_node(node, body)
                        && node.start_byte() >= body.start_byte()
                        && node.end_byte() <= body.end_byte()
                })
                && node.named_child_count() == 0
                && !is_comment_kind(node.kind())
            {
                let range = node_range(node);
                owned_start_line = Some(
                    owned_start_line.map_or(range.start_line, |start| start.min(range.start_line)),
                );
                owned_end_line =
                    Some(owned_end_line.map_or(range.end_line, |end| end.max(range.end_line)));
            }
            let child_nesting = if mode == WalkMode::Legacy
                && slice_contains(config.anonymous_function_types, kind)
            {
                frame.nesting + 1
            } else {
                frame.nesting
            };
            push_named_children(
                &mut work,
                node,
                child_nesting,
                frame.root && !named_boundary,
            );
        }
    }

    debug_assert_eq!(owned_start_line.is_some(), owned_end_line.is_some());
    WalkResult {
        complexity,
        max_nesting,
        owned_start_line,
        owned_end_line,
    }
}

fn push_if_children<'tree>(
    work: &mut Vec<Frame<'tree>>,
    node: Node<'tree>,
    nesting: u32,
    config: &Config,
) {
    let children = named_children(node);
    let alternative = node.child_by_field_name("alternative");
    // Iterate in reverse so children pop in source order from the stack.
    for child in children.into_iter().rev() {
        let kind = child.kind();
        if slice_contains(config.else_clause_types, kind) {
            if let Some(else_if) = direct_named_child_matching(child, |k| config.is_any_if(k)) {
                work.push(Frame {
                    node: else_if,
                    nesting,
                    else_if_continuation: true,
                    root: false,
                });
                push_named_children_except(work, child, Some(else_if), nesting + 1);
            } else {
                work.push(Frame {
                    node: child,
                    nesting: nesting + 1,
                    else_if_continuation: false,
                    root: false,
                });
            }
        } else if config.is_any_if(kind) {
            let else_if_continuation = slice_contains(config.alternate_if_types, kind)
                || alternative.is_some_and(|candidate| candidate == child);
            work.push(Frame {
                node: child,
                nesting: if else_if_continuation {
                    nesting
                } else {
                    nesting + 1
                },
                else_if_continuation,
                root: false,
            });
        } else {
            work.push(Frame {
                node: child,
                nesting: nesting + 1,
                else_if_continuation: false,
                root: false,
            });
        }
    }
}

fn push_named_children<'tree>(
    work: &mut Vec<Frame<'tree>>,
    node: Node<'tree>,
    nesting: u32,
    root: bool,
) {
    brokk_bifrost_core::analyzer::tree_walk::push_named_children_reversed_as(node, work, |child| {
        Frame {
            node: child,
            nesting,
            else_if_continuation: false,
            root,
        }
    });
}

fn push_named_children_except<'tree>(
    work: &mut Vec<Frame<'tree>>,
    node: Node<'tree>,
    except: Option<Node<'tree>>,
    nesting: u32,
) {
    brokk_bifrost_core::analyzer::tree_walk::push_named_children_reversed_where_as(
        node,
        work,
        |child| except.is_none_or(|skip| !same_node(child, skip)),
        |child| Frame {
            node: child,
            nesting,
            else_if_continuation: false,
            root: false,
        },
    );
}

fn control_flow_increment(nesting: u32) -> u32 {
    1 + nesting
}

fn is_nested_in_types(node: Node<'_>, types: &[&str]) -> bool {
    match node.parent() {
        Some(parent) => slice_contains(types, parent.kind()),
        None => false,
    }
}

fn is_labeled_jump(node: Node<'_>) -> bool {
    node.named_child_count() > 0
}

/// Counts logical-operator runs inside a binary expression. Sequences of the
/// same operator (`a && b && c`) collapse to one; alternations (`a && b || c`)
/// count once per distinct adjacent operator. Mirrors brokk-shared exactly.
fn logical_operator_sequence_count(node: Node<'_>, source: &str, config: &Config) -> u32 {
    // Operators are recorded in reverse-source order during the DFS below,
    // then read back in reverse to recover source order. Keep that
    // invariant — flipping the traversal order changes the alternation
    // counting on chains like `a && b || c`.
    let mut operators: Vec<String> = Vec::new();
    let mut work: Vec<Node<'_>> = vec![node];
    while let Some(current) = work.pop() {
        let count = current.child_count();
        for i in (0..count).rev() {
            let Some(child) = current.child(i) else {
                continue;
            };
            let kind = child.kind();
            if slice_contains(config.binary_types, kind) {
                work.push(child);
                continue;
            }
            if slice_contains(config.logical_operators, kind) {
                operators.push(kind.to_string());
                continue;
            }
            if is_logical_operator_token(child, source, config.logical_operators)
                && let Some(text) = source.get(child.start_byte()..child.end_byte())
            {
                operators.push(text.to_string());
            }
        }
    }

    let mut sequences: u32 = 0;
    let mut previous: &str = "";
    for op in operators.iter().rev() {
        if op != previous {
            sequences = sequences.saturating_add(1);
            previous = op.as_str();
        }
    }
    sequences
}

fn is_logical_operator_token(node: Node<'_>, source: &str, operators: &[&str]) -> bool {
    if node.child_count() > 0 {
        return false;
    }
    let byte_length = node.end_byte().saturating_sub(node.start_byte());
    if !(2..=4).contains(&byte_length) {
        return false;
    }
    let Some(text) = source.get(node.start_byte()..node.end_byte()) else {
        return false;
    };
    slice_contains(operators, text)
}

fn direct_named_child_matching<'tree, F>(node: Node<'tree>, pred: F) -> Option<Node<'tree>>
where
    F: Fn(&str) -> bool,
{
    brokk_bifrost_core::analyzer::tree_walk::first_named_child_matching(node, |child| {
        pred(child.kind())
    })
}
