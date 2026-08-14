//! The Scala answers behind `ScalaAdapter`.
//!
//! `LanguageAdapter` is analysis-owned, so the trait impl itself stays in
//! `analyzer/scala/adapter.rs`; the answers that know Scala come from here or
//! from [`crate::scala::declarations`], [`crate::scala::test_detection`] and
//! [`crate::queries`].

use brokk_bifrost_core::analyzer::cognitive_complexity;
use std::sync::LazyLock;

/// The file extension `ScalaAdapter` reports.
pub const SCALA_FILE_EXTENSION: &str = "scala";

/// Tree-sitter node-kind mapping used by the cognitive-complexity scorer for
/// Scala. Node names are from the tree-sitter-scala grammar.
pub static SCALA_COGNITIVE_CONFIG: LazyLock<cognitive_complexity::Config> =
    LazyLock::new(|| cognitive_complexity::Config {
        if_types: &["if_expression"],
        loop_types: &["for_expression", "while_expression", "do_while_expression"],
        case_types: &["case_clause"],
        binary_types: &["infix_expression"],
        logical_operators: &["&&", "||"],
        jump_types: &["break_expression", "continue_expression"],
        named_function_boundary_types: &["function_definition"],
        anonymous_function_types: &["lambda_expression"],
        else_clause_types: &["else_clause"],
        default_case_predicate: Some(cognitive_complexity::is_wildcard_case),
        ..cognitive_complexity::Config::empty()
    });

/// The receiver spelled before the final `.` of a Scala call reference.
pub fn scala_extract_call_receiver(reference: &str) -> Option<String> {
    let trimmed = reference.trim();
    let before_args = trimmed
        .split_once('(')
        .map(|(head, _)| head)
        .unwrap_or(trimmed);
    before_args
        .rsplit_once('.')
        .map(|(receiver, _)| receiver.to_string())
}

/// Every `$`-encoded spelling of a normalized Scala short name.
///
/// Scala compiles an `object` to a class whose own name carries a trailing
/// `$`, so a nested path can encode the marker at any subset of its segments.
/// Enumerating them is exponential in segment count, which is why the walk
/// gives up past [`MAX_OBJECT_ENCODING_SEGMENTS`].
pub fn scala_object_encoded_short_name_candidates(normalized: &str) -> Vec<String> {
    const MAX_OBJECT_ENCODING_SEGMENTS: usize = 8;

    let parts: Vec<_> = normalized
        .split('.')
        .filter(|part| !part.is_empty())
        .collect();
    if parts.is_empty() {
        return Vec::new();
    }
    if parts.len() > MAX_OBJECT_ENCODING_SEGMENTS {
        return Vec::new();
    }

    let variant_count = 1_usize << parts.len();
    let mut out = Vec::new();
    for mask in 1..variant_count {
        let mut encoded = Vec::with_capacity(parts.len());
        for (index, part) in parts.iter().enumerate() {
            if (mask & (1 << index)) != 0 {
                encoded.push(format!("{part}$"));
            } else {
                encoded.push((*part).to_string());
            }
        }
        out.push(encoded.join("."));
    }
    out
}
