//! Reachable exits of a JavaScript or TypeScript function body.
//!
//! A call ends at a `return`, or returns `undefined` when control reaches the
//! end of the body. A summary of what a call returns must therefore count every
//! reachable exit, not only the `return` expressions (#7239). This walk applies
//! ECMAScript completion rules to the syntax tree: a statement completes
//! normally, or abruptly through `return`, `throw`, `break` or `continue`, and
//! each compound statement combines the completions of its parts.
//!
//! The result over-approximates what can run. A condition is unknown, except
//! that an omitted or literal `true` loop condition never ends its loop. Every
//! `case` and `catch` block can run, and so can every loop body. A listed
//! `return` may never run, but no exit that can run is left out. Nested
//! functions and classes are separate callables, so the walk does not enter
//! them.

use brokk_bifrost_core::analyzer::tree_walk::named_children_iter;
use brokk_bifrost_core::hash::HashMap;
use tree_sitter::Node;

use crate::syntax::slice;
use crate::ts_owners::ts_return_expression;

/// The exits through which a call of one function body returns.
pub(crate) struct FunctionBodyExits<'tree> {
    /// One entry for each `return` that can end the call: the returned
    /// expression, or `None` for `return;`.
    pub(crate) returns: Vec<Option<Node<'tree>>>,
    /// Whether control can reach the end of the body, which returns `undefined`.
    pub(crate) falls_through: bool,
}

/// The reachable exits of `body`, the `statement_block` of a function.
///
/// `None` means the exits are unknown: the body holds a parse error, which can
/// hide a statement or replace part of one (a recovered `for` header reads as
/// `for (;;)`), or a statement this walk does not model. `step` runs once for
/// each statement visited, and its error stops the walk.
pub(crate) fn function_body_exits<'tree, 'src, E>(
    body: Node<'tree>,
    source: &'src str,
    mut step: impl FnMut() -> Result<(), E>,
) -> Result<Option<FunctionBodyExits<'tree>>, E> {
    debug_assert_eq!(body.kind(), "statement_block");
    if body.has_error() {
        return Ok(None);
    }
    let mut completions: HashMap<usize, Completion<'tree, 'src>> = HashMap::default();
    let mut stack = vec![(body, false)];
    while let Some((node, parts_done)) = stack.pop() {
        if parts_done {
            let completion = combine(node, source, &mut completions);
            completions.insert(node.id(), completion);
            continue;
        }
        step()?;
        if !is_modeled(node.kind()) {
            return Ok(None);
        }
        stack.push((node, true));
        stack.extend(parts(node).into_iter().rev().map(|part| (part, false)));
    }
    let body = completions
        .remove(&body.id())
        .expect("the body completes after its parts");
    // A `break` or `continue` whose target is not inside the body is a syntax
    // error.
    if !body.breaks.is_empty() || !body.continues.is_empty() {
        return Ok(None);
    }
    Ok(Some(FunctionBodyExits {
        returns: body.returns,
        falls_through: body.normal,
    }))
}

/// How one statement can complete: `normal` says whether it can complete
/// normally, and the lists hold the abrupt completions that can leave it.
struct Completion<'tree, 'src> {
    normal: bool,
    returns: Vec<Option<Node<'tree>>>,
    /// Targets of the `break`s that leave the statement: `None` is the
    /// innermost loop or `switch`, and `Some` is a label.
    breaks: Vec<Option<&'src str>>,
    /// Targets of the `continue`s that leave the statement: `None` is the
    /// innermost loop, and `Some` is a label.
    continues: Vec<Option<&'src str>>,
}

impl<'tree, 'src> Completion<'tree, 'src> {
    fn normal() -> Self {
        Self {
            normal: true,
            returns: Vec::new(),
            breaks: Vec::new(),
            continues: Vec::new(),
        }
    }

    fn abrupt() -> Self {
        Self {
            normal: false,
            ..Self::normal()
        }
    }

    /// Add the abrupt completions of `part`, which runs inside `self`.
    fn absorb_abrupt(&mut self, mut part: Self) {
        self.returns.append(&mut part.returns);
        self.breaks.append(&mut part.breaks);
        self.continues.append(&mut part.continues);
    }
}

/// Whether the walk knows how a statement of `kind` completes. A statement of
/// another kind could hide an exit.
fn is_modeled(kind: &str) -> bool {
    matches!(
        kind,
        // Compound statements, whose parts the walk visits.
        "statement_block"
            | "if_statement"
            | "for_statement"
            | "for_in_statement"
            | "while_statement"
            | "do_statement"
            | "switch_statement"
            | "switch_case"
            | "switch_default"
            | "try_statement"
            | "labeled_statement"
            | "with_statement"
            // Abrupt completions.
            | "return_statement"
            | "throw_statement"
            | "break_statement"
            | "continue_statement"
            // Statements that complete normally unless they throw. None holds
            // a statement of this function: a nested function or class is a
            // separate callable.
            | "expression_statement"
            | "lexical_declaration"
            | "variable_declaration"
            // Disposal at the end of the block can throw but cannot return.
            | "using_declaration"
            | "empty_statement"
            | "debugger_statement"
            | "function_declaration"
            | "generator_function_declaration"
            | "class_declaration"
            | "abstract_class_declaration"
            | "interface_declaration"
            | "type_alias_declaration"
            | "enum_declaration"
    )
}

/// The statements whose completions make up the completion of `node`, in
/// source order. `combine` reads each part back by the same field.
fn parts(node: Node<'_>) -> Vec<Node<'_>> {
    match node.kind() {
        "statement_block" => statements(node),
        "switch_case" | "switch_default" => {
            let mut cursor = node.walk();
            node.children_by_field_name("body", &mut cursor)
                .filter(|statement| !statement.is_extra())
                .collect()
        }
        "if_statement" => [
            node.child_by_field_name("consequence"),
            alternative_statement(node),
        ]
        .into_iter()
        .flatten()
        .collect(),
        "for_statement" | "for_in_statement" | "while_statement" | "do_statement"
        | "labeled_statement" | "with_statement" => {
            node.child_by_field_name("body").into_iter().collect()
        }
        "switch_statement" => node
            .child_by_field_name("body")
            .map(statements)
            .unwrap_or_default(),
        "try_statement" => [
            node.child_by_field_name("body"),
            clause_body(node, "handler"),
            clause_body(node, "finalizer"),
        ]
        .into_iter()
        .flatten()
        .collect(),
        _ => Vec::new(),
    }
}

/// The completion of `node`, built from the completions of its `parts`.
fn combine<'tree, 'src>(
    node: Node<'tree>,
    source: &'src str,
    completions: &mut HashMap<usize, Completion<'tree, 'src>>,
) -> Completion<'tree, 'src> {
    let mut take = |part: Node<'tree>| {
        completions
            .remove(&part.id())
            .expect("a part completes before the statement that holds it")
    };
    let label = |node: Node<'tree>| {
        node.child_by_field_name("label")
            .map(|label| slice(label, source))
    };
    match node.kind() {
        "return_statement" => Completion {
            returns: vec![ts_return_expression(node)],
            ..Completion::abrupt()
        },
        "throw_statement" => Completion::abrupt(),
        "break_statement" => Completion {
            breaks: vec![label(node)],
            ..Completion::abrupt()
        },
        "continue_statement" => Completion {
            continues: vec![label(node)],
            ..Completion::abrupt()
        },
        "statement_block" | "switch_case" | "switch_default" => {
            let mut sequence = Completion::normal();
            for part in parts(node) {
                let part = take(part);
                // After a part that cannot complete normally, no path reaches
                // the parts that follow it.
                if sequence.normal {
                    sequence.normal = part.normal;
                    sequence.absorb_abrupt(part);
                }
            }
            sequence
        }
        "if_statement" => {
            let mut consequence = node
                .child_by_field_name("consequence")
                .map_or_else(Completion::normal, &mut take);
            // A missing `else` completes normally when the condition is false.
            let alternative =
                alternative_statement(node).map_or_else(Completion::normal, &mut take);
            consequence.normal |= alternative.normal;
            consequence.absorb_abrupt(alternative);
            consequence
        }
        "for_statement" | "for_in_statement" | "while_statement" | "do_statement" => {
            let mut body = node
                .child_by_field_name("body")
                .map_or_else(Completion::normal, &mut take);
            let labels = loop_labels(node, source);
            let targets_loop =
                |target: &Option<&str>| target.is_none_or(|target| labels.contains(&target));
            let breaks = body.breaks.len();
            body.breaks.retain(|target| !targets_loop(target));
            let broke = body.breaks.len() != breaks;
            let continues = body.continues.len();
            body.continues.retain(|target| !targets_loop(target));
            let continued = body.continues.len() != continues;
            let endless = loop_condition_always_true(node);
            body.normal = broke
                || match node.kind() {
                    // The body runs once before the condition is first tested.
                    "do_statement" => (body.normal || continued) && !endless,
                    // The condition, or an empty collection, can end the loop
                    // before the body runs.
                    _ => !endless,
                };
            body
        }
        "labeled_statement" => {
            let mut body = node
                .child_by_field_name("body")
                .map_or_else(Completion::normal, &mut take);
            if let Some(label) = label(node) {
                let breaks = body.breaks.len();
                body.breaks.retain(|target| *target != Some(label));
                body.normal |= body.breaks.len() != breaks;
            }
            body
        }
        "switch_statement" => {
            let cases = parts(node);
            // A value that matches no case skips the body unless a `default`
            // clause catches it.
            let mut normal = !cases.iter().any(|case| case.kind() == "switch_default");
            let mut switch = Completion::abrupt();
            let mut last_case_normal = true;
            for case in cases {
                // Every case can be entered by its label; one that completes
                // normally falls into the next.
                let case = take(case);
                last_case_normal = case.normal;
                switch.absorb_abrupt(case);
            }
            let breaks = switch.breaks.len();
            switch.breaks.retain(Option::is_some);
            normal |= last_case_normal || switch.breaks.len() != breaks;
            switch.normal = normal;
            switch
        }
        "try_statement" => {
            let mut protected = node
                .child_by_field_name("body")
                .map_or_else(Completion::normal, &mut take);
            // Any statement of the `try` block can throw into the `catch` block.
            if let Some(handler) = clause_body(node, "handler") {
                let handler = take(handler);
                protected.normal |= handler.normal;
                protected.absorb_abrupt(handler);
            }
            match clause_body(node, "finalizer").map(&mut take) {
                None => protected,
                // A `finally` block that completes normally keeps the
                // completion of the blocks it guards.
                Some(finalizer) if finalizer.normal => {
                    protected.absorb_abrupt(finalizer);
                    protected
                }
                // One that cannot replaces every completion of the blocks it
                // guards, including a `return`, with its own.
                Some(finalizer) => finalizer,
            }
        }
        "with_statement" => node
            .child_by_field_name("body")
            .map_or_else(Completion::normal, &mut take),
        _ => Completion::normal(),
    }
}

/// The statements directly inside a block or a `switch` body.
fn statements(node: Node<'_>) -> Vec<Node<'_>> {
    named_children_iter(node)
        .filter(|statement| !statement.is_extra())
        .collect()
}

/// The statement of an `if` statement's `else` clause.
fn alternative_statement(node: Node<'_>) -> Option<Node<'_>> {
    let alternative = node.child_by_field_name("alternative")?;
    if alternative.kind() == "else_clause" {
        named_children_iter(alternative).find(|statement| !statement.is_extra())
    } else {
        Some(alternative)
    }
}

/// The block of a `try` statement's `catch` or `finally` clause.
fn clause_body<'tree>(node: Node<'tree>, field: &str) -> Option<Node<'tree>> {
    node.child_by_field_name(field)?.child_by_field_name("body")
}

/// The labels of the labeled statements that wrap a loop directly
/// (`a: b: while (...)`). A `continue` that names one of them continues the
/// loop, and a `break` that names one leaves it.
fn loop_labels<'src>(node: Node<'_>, source: &'src str) -> Vec<&'src str> {
    let mut labels = Vec::new();
    let mut current = node;
    while let Some(parent) = current
        .parent()
        .filter(|parent| parent.kind() == "labeled_statement")
    {
        labels.extend(
            parent
                .child_by_field_name("label")
                .map(|label| slice(label, source)),
        );
        current = parent;
    }
    labels
}

/// Whether only a `break`, `return` or `throw` can end the loop: its
/// condition is omitted (`for (;;)`) or the literal `true`.
fn loop_condition_always_true(node: Node<'_>) -> bool {
    let condition = node.child_by_field_name("condition");
    match node.kind() {
        // The grammar spells an omitted `for` condition as nothing, `;` or an
        // empty statement.
        "for_statement" => condition.is_none_or(|condition| {
            matches!(condition.kind(), ";" | "empty_statement") || is_true_literal(condition)
        }),
        "while_statement" | "do_statement" => condition.is_some_and(is_true_literal),
        _ => false,
    }
}

/// Whether `node` is the literal `true`, possibly parenthesized.
fn is_true_literal(mut node: Node<'_>) -> bool {
    loop {
        match node.kind() {
            "true" => return true,
            "parenthesized_expression" | "expression_statement" => {
                match named_children_iter(node).find(|inner| !inner.is_extra()) {
                    Some(inner) => node = inner,
                    None => return false,
                }
            }
            _ => return false,
        }
    }
}
