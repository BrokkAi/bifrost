//! The Kotlin answers behind `KotlinAdapter`.
//!
//! `LanguageAdapter` is analysis-owned, so the trait impl itself stays in
//! `analyzer/kotlin/adapter.rs`; the answers that know Kotlin come from here or
//! from [`crate::kotlin::declarations`], [`crate::kotlin::test_detection`] and
//! [`crate::queries`].

use brokk_bifrost_core::analyzer::cognitive_complexity;
use brokk_bifrost_core::analyzer::tree_walk::named_children;
use std::sync::LazyLock;
use tree_sitter::Node;

/// The file extension `KotlinAdapter` reports.
pub const KOTLIN_FILE_EXTENSION: &str = "kt";

/// Tree-sitter node-kind mapping used by the cognitive-complexity scorer for
/// Kotlin (#1243). The Kotlin grammar names most control-flow nodes with an
/// `_expression` suffix (`if_expression`, `when_expression`, …) rather than
/// the `_statement` shape other languages use, and folds `break`, `continue`,
/// `return`, and `throw` into one `jump_expression` kind — hence the custom
/// [`kotlin_is_labeled_jump`] predicate rather than the scorer's default
/// "any named child means labeled" heuristic, which would misfire on an
/// ordinary `return value` or `throw value`.
pub static KOTLIN_COGNITIVE_CONFIG: LazyLock<cognitive_complexity::Config> =
    LazyLock::new(|| cognitive_complexity::Config {
        if_types: &["if_expression"],
        loop_types: &["for_statement", "while_statement", "do_while_statement"],
        catch_types: &["catch_block"],
        // Elvis (`?:`) is Kotlin's ternary: a two-way branch, scored the same
        // as a conditional expression in every other language's config.
        conditional_types: &["elvis_expression"],
        // `when_expression` itself never scores; each `when_entry` branch
        // does, unless it is the bare `else ->` arm.
        case_types: &["when_entry"],
        // `&&` and `||` are two distinct node kinds in this grammar (unlike
        // Java's single `binary_expression`), so both are listed; the
        // scorer's sequence-counting walk already recurses through mixed
        // chains of either kind.
        binary_types: &["conjunction_expression", "disjunction_expression"],
        logical_operators: &["&&", "||"],
        jump_types: &["jump_expression"],
        anonymous_function_types: &["lambda_literal"],
        // `else if` is spelled as the outer `if_expression`'s `alternative`
        // field holding a `control_structure_body` that itself wraps the
        // nested `if_expression` — the same wrapper kind an ordinary `else`
        // block or a bodied `if`'s consequence uses. Unwrapping it here is
        // what keeps an `else if` chain flat instead of adding a nesting
        // level per link.
        else_clause_types: &["control_structure_body"],
        default_case_predicate: Some(kotlin_is_default_when_entry),
        jump_predicate: Some(kotlin_is_labeled_jump),
        ..cognitive_complexity::Config::empty()
    });

/// Whether a `when_entry` is the bare `else ->` arm: the grammar gives every
/// other arm at least one `when_condition` child, and reserves the label-free
/// shape for `else`.
fn kotlin_is_default_when_entry(node: Node<'_>, _source: &str) -> bool {
    !named_children(node)
        .into_iter()
        .any(|child| child.kind() == "when_condition")
}

/// Whether a `jump_expression` is a labeled `break@`/`continue@`/`return@`.
///
/// The label is parsed as its own named `label` node (see
/// `_break_at`/`_continue_at`/`_return_at` in the Kotlin grammar), never as
/// part of the value a plain `return`/`throw` carries, so checking for that
/// specific child kind — rather than any named child at all — is what keeps
/// an unlabeled `return value` or `throw value` from being misread as a
/// labeled jump.
fn kotlin_is_labeled_jump(node: Node<'_>) -> bool {
    named_children(node)
        .into_iter()
        .any(|child| child.kind() == "label")
}

/// The receiver spelled before the final `.` of a Kotlin call reference.
pub fn kotlin_extract_call_receiver(reference: &str) -> Option<String> {
    let trimmed = reference.trim();
    let before_args = trimmed
        .split_once('(')
        .map(|(head, _)| head)
        .unwrap_or(trimmed);
    before_args
        .rsplit_once('.')
        .map(|(receiver, _)| receiver.to_string())
}
