//! The PHP answers behind `PhpAdapter`.
//!
//! `LanguageAdapter` is analysis-owned, so the trait impl itself stays in
//! `analyzer/php/adapter.rs`; every answer it gives comes from here or from
//! [`crate::declarations`] and [`crate::test_detection`].

use brokk_bifrost_core::analyzer::cognitive_complexity;
use std::sync::LazyLock;

pub const PHP_FILE_EXTENSION: &str = "php";

/// Tree-sitter node-kind mapping used by the cognitive-complexity scorer for
/// PHP.
pub static PHP_COGNITIVE_CONFIG: LazyLock<cognitive_complexity::Config> =
    LazyLock::new(|| cognitive_complexity::Config {
        if_types: &["if_statement", "else_if_clause"],
        loop_types: &[
            "for_statement",
            "foreach_statement",
            "while_statement",
            "do_statement",
        ],
        catch_types: &["catch_clause"],
        conditional_types: &["conditional_expression"],
        case_types: &["case_statement", "match_condition"],
        default_case_types: &["default_statement", "match_default_expression"],
        binary_types: &["binary_expression"],
        logical_operators: &["&&", "||", "and", "or", "??"],
        jump_types: &["break_statement", "continue_statement"],
        named_function_boundary_types: &["function_definition", "method_declaration"],
        anonymous_function_types: &["anonymous_function", "arrow_function"],
        else_clause_types: &["else_clause"],
        ..cognitive_complexity::Config::empty()
    });

pub fn php_extract_call_receiver(reference: &str) -> Option<String> {
    let trimmed = reference.trim();
    let before_args = trimmed
        .split_once('(')
        .map(|(head, _)| head)
        .unwrap_or(trimmed);
    before_args
        .rsplit_once("::")
        .or_else(|| before_args.rsplit_once("->"))
        .map(|(receiver, _)| receiver.to_string())
}
