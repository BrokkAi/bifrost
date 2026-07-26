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

use crate::analyzer::tree_walk::named_children;
use tree_sitter::Node;

/// Predicate returning `true` when a switch/match case node is the
/// language's "default"/"wildcard" branch and therefore must not add
/// complexity. Receives the case node and the full source text.
pub type DefaultCasePredicate = fn(Node<'_>, &str) -> bool;

/// Predicate returning `true` when a node should be treated as a named
/// function boundary (i.e. analysis should not descend into it once the
/// scorer has already entered a function). Used for languages where the
/// concrete function-decoration node type varies (e.g. Python's
/// `decorated_definition` wrapping a `function_definition`).
pub type NamedFunctionBoundaryPredicate = fn(Node<'_>) -> bool;

/// Configuration that adapts the generic scorer to a specific language.
///
/// Each `*_types` slice lists the tree-sitter node kinds that map to a
/// SonarSource cognitive-complexity category. Slices use `&'static [&'static
/// str]` rather than a set type because each language declares <= 12 entries
/// per category and the scorer hot loop performs a linear scan per node.
pub struct Config {
    /// Primary `if`-statement node types. Contribute +1+nesting on entry,
    /// or just +1 when the scorer recognizes them as `else if` continuations.
    pub if_types: &'static [&'static str],
    /// Additional node types treated as `if`-like for the `else if` flatten
    /// rule (e.g. Python's `elif_clause`).
    pub alternate_if_types: &'static [&'static str],
    /// Loop node types (`for`, `while`, `do`, `loop`).
    pub loop_types: &'static [&'static str],
    /// Catch/except node types.
    pub catch_types: &'static [&'static str],
    /// Ternary / conditional-expression node types.
    pub conditional_types: &'static [&'static str],
    /// Case-clause node types within a switch/match. Default cases are
    /// filtered out by [`Self::default_case_predicate`] if set.
    pub case_types: &'static [&'static str],
    /// Default-case container node types whose children should be walked
    /// without contributing to the score.
    pub default_case_types: &'static [&'static str],
    /// Binary-expression node types that may contain logical operators.
    pub binary_types: &'static [&'static str],
    /// Logical-operator tokens (`"&&"`, `"||"`, `"and"`, `"or"`...). Compared
    /// both against tree-sitter node kinds (Python exposes `and`/`or` as
    /// named kinds) and against the literal source bytes of anonymous tokens
    /// (Java/Rust expose `&&`/`||` as anonymous tokens).
    pub logical_operators: &'static [&'static str],
    /// Jump node types (`break`, `continue`, `goto`). Only contribute when
    /// they carry a label.
    pub jump_types: &'static [&'static str],
    /// Node types that mark a named (non-anonymous) function boundary —
    /// the scorer enters one such node at the root and refuses to descend
    /// into nested ones.
    pub named_function_boundary_types: &'static [&'static str],
    /// Node types treated as anonymous functions (lambdas, closures): the
    /// scorer descends into them, bumping nesting by one.
    pub anonymous_function_types: &'static [&'static str],
    /// Node types representing `else` clauses; required so that `else if`
    /// is folded into a single increment rather than `else` + `if`.
    pub else_clause_types: &'static [&'static str],
    /// Optional predicate identifying the default branch of a case-like
    /// construct (e.g. Java's `default:`, Rust's `_ =>`).
    pub default_case_predicate: Option<DefaultCasePredicate>,
    /// Optional predicate marking additional named-function-boundary nodes
    /// that cannot be enumerated by kind alone (e.g. Python decorated
    /// functions).
    pub named_function_boundary_predicate: Option<NamedFunctionBoundaryPredicate>,
}

impl Config {
    /// Const constructor producing a no-op config. Language configs override
    /// the relevant slices in their static initializer.
    pub const fn empty() -> Self {
        Self {
            if_types: &[],
            alternate_if_types: &[],
            loop_types: &[],
            catch_types: &[],
            conditional_types: &[],
            case_types: &[],
            default_case_types: &[],
            binary_types: &[],
            logical_operators: &[],
            jump_types: &[],
            named_function_boundary_types: &[],
            anonymous_function_types: &[],
            else_clause_types: &[],
            default_case_predicate: None,
            named_function_boundary_predicate: None,
        }
    }

    fn is_any_if(&self, kind: &str) -> bool {
        slice_contains(self.if_types, kind) || slice_contains(self.alternate_if_types, kind)
    }
}

struct Frame<'tree> {
    node: Node<'tree>,
    nesting: u32,
    else_if_continuation: bool,
    root: bool,
}

/// Compute the cognitive complexity of `root` according to `config`.
///
/// `root` should be the tree-sitter node representing the function/method
/// whose complexity is being measured; the scorer walks its subtree.
/// `source` is the full source text of the file, used to disambiguate
/// default/wildcard switch cases and to read the bytes of anonymous
/// logical-operator tokens.
pub fn compute(root: Node<'_>, source: &str, config: &Config) -> u32 {
    let mut complexity: u32 = 0;
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
            complexity = complexity.saturating_add(control_flow_increment(frame.nesting));
            push_named_children(&mut work, node, frame.nesting + 1, false);
        } else if slice_contains(config.case_types, kind) {
            let is_default = config
                .default_case_predicate
                .map(|pred| pred(node, source))
                .unwrap_or(false);
            if !is_default {
                complexity = complexity.saturating_add(control_flow_increment(frame.nesting));
            }
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
            if is_labeled_jump(node) {
                complexity = complexity.saturating_add(1);
            }
            push_named_children(&mut work, node, frame.nesting, false);
        } else {
            let named_boundary = slice_contains(config.named_function_boundary_types, kind)
                || config
                    .named_function_boundary_predicate
                    .map(|pred| pred(node))
                    .unwrap_or(false);
            if !frame.root && named_boundary {
                continue;
            }
            let child_nesting = if slice_contains(config.anonymous_function_types, kind) {
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

    complexity
}

fn push_if_children<'tree>(
    work: &mut Vec<Frame<'tree>>,
    node: Node<'tree>,
    nesting: u32,
    config: &Config,
) {
    let children = named_children(node);
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
            work.push(Frame {
                node: child,
                nesting,
                else_if_continuation: true,
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
    let children = named_children(node);
    for child in children.into_iter().rev() {
        work.push(Frame {
            node: child,
            nesting,
            else_if_continuation: false,
            root,
        });
    }
}

fn push_named_children_except<'tree>(
    work: &mut Vec<Frame<'tree>>,
    node: Node<'tree>,
    except: Option<Node<'tree>>,
    nesting: u32,
) {
    let children = named_children(node);
    for child in children.into_iter().rev() {
        if let Some(skip) = except
            && same_range(child, skip)
        {
            continue;
        }
        work.push(Frame {
            node: child,
            nesting,
            else_if_continuation: false,
            root: false,
        });
    }
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

/// Helper exposed for language configs (Rust, Scala) whose default-case
/// node is a wildcard pattern. Matches a leading `_` (Rust `_ =>`) or
/// `case _ =>` (Scala).
pub fn is_wildcard_case(node: Node<'_>, source: &str) -> bool {
    let Some(text) = source.get(node.start_byte()..node.end_byte()) else {
        return false;
    };
    let stripped = text.trim_start();
    stripped.starts_with('_') || stripped.starts_with("case _ =>")
}

fn direct_named_child_matching<'tree, F>(node: Node<'tree>, pred: F) -> Option<Node<'tree>>
where
    F: Fn(&str) -> bool,
{
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| pred(child.kind()))
}

fn same_range(a: Node<'_>, b: Node<'_>) -> bool {
    a.start_byte() == b.start_byte() && a.end_byte() == b.end_byte()
}

fn slice_contains(haystack: &[&str], needle: &str) -> bool {
    haystack.contains(&needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    fn rust_config() -> Config {
        // Minimal Rust-flavoured config sufficient for in-module tests; the
        // real config lives next to `RustAdapter`.
        Config {
            if_types: &["if_expression"],
            loop_types: &["for_expression", "while_expression", "loop_expression"],
            case_types: &["match_arm"],
            binary_types: &["binary_expression"],
            logical_operators: &["&&", "||"],
            jump_types: &["break_expression", "continue_expression"],
            named_function_boundary_types: &["function_item"],
            anonymous_function_types: &["closure_expression"],
            else_clause_types: &["else_clause"],
            default_case_predicate: Some(is_wildcard_case),
            ..Config::empty()
        }
    }

    fn parse_rust(source: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        parser.parse(source, None).expect("parse")
    }

    fn find_function<'tree>(root: Node<'tree>, name: &str, source: &str) -> Option<Node<'tree>> {
        if root.kind() == "function_item" {
            let mut cursor = root.walk();
            for child in root.named_children(&mut cursor) {
                if child.kind() == "identifier"
                    && source
                        .get(child.start_byte()..child.end_byte())
                        .map(|t| t == name)
                        .unwrap_or(false)
                {
                    return Some(root);
                }
            }
        }
        let mut cursor = root.walk();
        for child in root.named_children(&mut cursor) {
            if let Some(found) = find_function(child, name, source) {
                return Some(found);
            }
        }
        None
    }

    fn score(source: &str, fn_name: &str) -> u32 {
        let tree = parse_rust(source);
        let node = find_function(tree.root_node(), fn_name, source).expect("function not found");
        compute(node, source, &rust_config())
    }

    #[test]
    fn simple_function_is_zero() {
        assert_eq!(score("fn method() -> i32 { 0 }", "method"), 0);
    }

    #[test]
    fn if_nested_if_and_else_if() {
        let source = "fn method(a: i32, b: i32) -> i32 {\n\
            if a > 0 {\n\
                if b > 0 { return 1; }\n\
            } else if a < 0 {\n\
                return -1;\n\
            }\n\
            0\n\
        }\n";
        assert_eq!(score(source, "method"), 4);
    }

    #[test]
    fn loops_match_logical_and_closure() {
        let source = "fn method(x: i32) -> i32 {\n\
            let f = || { if x > 0 { 1 } else { 0 } };\n\
            'outer: for i in 0..x {\n\
                if x > 0 && i > 0 || i < 10 { break 'outer; }\n\
            }\n\
            while x > 0 { continue; }\n\
            match x { 1 => f(), _ => 0 }\n\
        }\n";
        assert_eq!(score(source, "method"), 10);
    }

    #[test]
    fn deep_nesting_does_not_overflow() {
        let mut source = String::from("fn method(x: i32) -> i32 {\n");
        source.push_str(&"if x > 0 {\n".repeat(120));
        source.push_str("return 1;\n");
        source.push_str(&"}\n".repeat(120));
        source.push_str("0\n}\n");
        assert_eq!(score(&source, "method"), 7_260);
    }
}
