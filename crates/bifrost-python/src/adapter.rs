//! The Python answers behind `PythonAdapter`.
//!
//! `LanguageAdapter` is analysis-owned, so the trait impl itself stays in
//! `analyzer/python/adapter.rs`; every answer it gives comes from here or from
//! [`crate::declarations`]. `synthesize_hydrated_units` is the one exception:
//! it mutates `FileState`, an analysis type, and stays with the shell.

use brokk_bifrost_core::analyzer::cognitive_complexity;
use std::sync::LazyLock;

use crate::declarations::python_is_decorated_function_boundary;

pub const PYTHON_FILE_EXTENSION: &str = "py";

/// Tree-sitter node-kind mapping used by the cognitive-complexity scorer
/// for Python. Mirrors `ai.brokk.analyzer.python.CognitiveComplexityAnalysis`.
pub static PYTHON_COGNITIVE_CONFIG: LazyLock<cognitive_complexity::Config> =
    LazyLock::new(|| cognitive_complexity::Config {
        if_types: &["if_statement"],
        alternate_if_types: &["elif_clause"],
        loop_types: &["for_statement", "while_statement"],
        catch_types: &["except_clause"],
        conditional_types: &["conditional_expression"],
        case_types: &["case_clause"],
        binary_types: &["boolean_operator"],
        logical_operators: &["and", "or"],
        named_function_boundary_types: &["function_definition"],
        anonymous_function_types: &["lambda"],
        named_function_boundary_predicate: Some(python_is_decorated_function_boundary),
        ..cognitive_complexity::Config::empty()
    });

pub fn python_extract_call_receiver(reference: &str) -> Option<String> {
    let trimmed = reference.trim();
    let before_args = trimmed
        .split_once('(')
        .map(|(head, _)| head)
        .unwrap_or(trimmed);
    before_args
        .rsplit_once('.')
        .map(|(receiver, _)| receiver.to_string())
}
