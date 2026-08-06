use crate::analyzer::cognitive_complexity;
use crate::analyzer::tree_walk::named_children;
use crate::analyzer::{Language, LanguageAdapter, ProjectFile, SignatureMetadata};
use brokk_bifrost_jvm::queries::KOTLIN_QUERY_DIRECTORY;
use std::sync::LazyLock;
use tree_sitter::{Node, Tree};

use super::declarations::parse_kotlin_file;
use super::tests::kotlin_contains_tests;

/// Tree-sitter node-kind mapping used by the cognitive-complexity scorer for
/// Kotlin (#1243). The vendored grammar names most control-flow nodes with an
/// `_expression` suffix (`if_expression`, `when_expression`, …) rather than
/// the `_statement` shape other languages use, and folds `break`, `continue`,
/// `return`, and `throw` into one `jump_expression` kind — hence the custom
/// [`kotlin_is_labeled_jump`] predicate rather than the scorer's default
/// "any named child means labeled" heuristic, which would misfire on an
/// ordinary `return value` or `throw value`.
static KOTLIN_COGNITIVE_CONFIG: LazyLock<cognitive_complexity::Config> =
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
/// `_break_at`/`_continue_at`/`_return_at` in the vendored grammar), never as
/// part of the value a plain `return`/`throw` carries, so checking for that
/// specific child kind — rather than any named child at all — is what keeps
/// an unlabeled `return value` or `throw value` from being misread as a
/// labeled jump.
fn kotlin_is_labeled_jump(node: Node<'_>) -> bool {
    named_children(node)
        .into_iter()
        .any(|child| child.kind() == "label")
}

#[derive(Debug, Clone, Default)]
pub(crate) struct KotlinAdapter;

impl LanguageAdapter for KotlinAdapter {
    fn language(&self) -> Language {
        Language::Kotlin
    }

    /// Relative to `brokk-bifrost-jvm`'s crate root: the `.scm` assets moved
    /// with the vendored grammars and are embedded there.
    fn query_directory(&self) -> &'static str {
        KOTLIN_QUERY_DIRECTORY
    }

    fn file_extension(&self) -> &'static str {
        "kt"
    }

    fn callable_arity(
        &self,
        signature: &str,
        metadata: Option<&SignatureMetadata>,
    ) -> Option<usize> {
        metadata
            .and_then(SignatureMetadata::callable_arity)
            .map(|arity| arity.total())
            .or_else(|| kotlin_signature_arity(signature))
    }

    fn callable_return_type_text<'a>(&self, signature: &'a str) -> Option<&'a str> {
        // The return type follows the `:` after the *parameter list's* closing
        // paren. `rfind(')')` would land inside the return type itself for a
        // function type (`fun f(): (Int) -> String`), so the list is located by
        // a balanced forward scan.
        let after_parameters = &signature[kotlin_parameter_list_end(signature)?..];
        let (_, return_type) = after_parameters.split_once(':')?;
        let return_type = return_type.trim();
        (!return_type.is_empty()).then_some(return_type)
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        let trimmed = reference.trim();
        let before_args = trimmed
            .split_once('(')
            .map(|(head, _)| head)
            .unwrap_or(trimmed);
        before_args
            .rsplit_once('.')
            .map(|(receiver, _)| receiver.to_string())
    }

    fn contains_tests(
        &self,
        _file: &ProjectFile,
        source: &str,
        tree: &Tree,
        _parsed: &crate::analyzer::tree_sitter_analyzer::ParsedFile,
    ) -> bool {
        kotlin_contains_tests(tree.root_node(), source)
    }

    fn parse_file(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
    ) -> crate::analyzer::tree_sitter_analyzer::ParsedFile {
        parse_kotlin_file(file, source, tree)
    }

    fn cognitive_complexity_config(&self) -> Option<&'static cognitive_complexity::Config> {
        Some(&KOTLIN_COGNITIVE_CONFIG)
    }
}

/// The byte offset just past the callable's parameter list in a rendered
/// signature, or `None` when there is no balanced list.
///
/// The scan starts at the parameter list rather than the first `(` in the
/// string: a signature may open with annotation arguments
/// (`@Suppress("A", "B") fun f(x: Int)`), whose commas belong to the
/// annotation, not the callable.
fn kotlin_parameter_list_end(signature: &str) -> Option<usize> {
    kotlin_scan_parameter_list(signature).map(|(_, end)| end)
}

/// Best-effort arity from a rendered signature when structured metadata is
/// absent: the number of top-level commas in the callable's parameter list.
fn kotlin_signature_arity(signature: &str) -> Option<usize> {
    kotlin_scan_parameter_list(signature).map(|(arity, _)| arity)
}

/// Scan the callable's parameter list, returning `(arity, end_offset)`.
fn kotlin_scan_parameter_list(signature: &str) -> Option<(usize, usize)> {
    let open = kotlin_parameter_list_start(signature)?;
    let mut depth = 0usize;
    let mut arguments = 0usize;
    let mut saw_content = false;
    let mut previous = ' ';
    for (offset, character) in signature[open..].char_indices() {
        match character {
            '(' | '[' | '<' => depth += 1,
            // `->` in a function-type parameter is not a closing bracket.
            '>' if previous == '-' => saw_content = true,
            ')' | ']' | '>' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    let arity = arguments + usize::from(saw_content);
                    return Some((arity, open + offset + character.len_utf8()));
                }
            }
            ',' if depth == 1 => arguments += 1,
            character if !character.is_whitespace() => saw_content = true,
            _ => {}
        }
        previous = character;
    }
    None
}

/// The offset of the `(` that opens the callable's own parameter list,
/// skipping any leading annotation argument lists.
fn kotlin_parameter_list_start(signature: &str) -> Option<usize> {
    let mut search_from = 0usize;
    loop {
        let open = signature[search_from..].find('(')? + search_from;
        // An annotation's arguments are attached directly to an `@name`; the
        // callable's list is the first one that is not.
        let head = signature[..open].trim_end();
        let attached_to_annotation = head
            .rsplit(|character: char| character.is_whitespace())
            .next()
            .is_some_and(|token| token.starts_with('@'));
        if !attached_to_annotation {
            return Some(open);
        }
        let Some(close) = kotlin_balanced_close(signature, open) else {
            return Some(open);
        };
        search_from = close;
    }
}

/// The offset just past the `)` matching the `(` at `open`.
fn kotlin_balanced_close(signature: &str, open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (offset, character) in signature[open..].char_indices() {
        match character {
            '(' => depth += 1,
            ')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(open + offset + character.len_utf8());
                }
            }
            _ => {}
        }
    }
    None
}
