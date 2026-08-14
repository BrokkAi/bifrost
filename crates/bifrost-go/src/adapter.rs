//! The Go-language answers behind `brokk-bifrost-analysis`'s `GoAdapter`.
//!
//! Every item here is the language half of one `LanguageAdapter` method (or of
//! the clone-detection syntax profile). The trait impl itself stays in analysis
//! -- it names `ParsedFile` and `Language`-registry types this crate cannot see
//! -- and forwards to these free functions and constants.

use brokk_bifrost_core::analyzer::cognitive_complexity;
use std::sync::LazyLock;

/// Cognitive-complexity node vocabulary for Go.
pub static GO_COGNITIVE_CONFIG: LazyLock<cognitive_complexity::Config> =
    LazyLock::new(|| cognitive_complexity::Config {
        if_types: &["if_statement"],
        loop_types: &["for_statement"],
        case_types: &["expression_case", "type_case", "communication_case"],
        default_case_types: &["default_case"],
        binary_types: &["binary_expression"],
        logical_operators: &["&&", "||"],
        jump_types: &["break_statement", "continue_statement"],
        named_function_boundary_types: &["function_declaration", "method_declaration"],
        anonymous_function_types: &["func_literal"],
        else_clause_types: &["else_clause"],
        ..cognitive_complexity::Config::empty()
    });

/// Source file extension for Go.
pub const GO_FILE_EXTENSION: &str = "go";

/// The receiver of a Go call reference, i.e. everything before the final `.` of
/// the callee path, with any argument list dropped.
pub fn go_extract_call_receiver(reference: &str) -> Option<String> {
    let trimmed = reference.trim();
    let before_args = trimmed
        .split_once('(')
        .map(|(head, _)| head)
        .unwrap_or(trimmed);
    before_args
        .rsplit_once('.')
        .map(|(receiver, _)| receiver.to_string())
}

/// Node kinds that carry a Go clone candidate's body.
pub const GO_CLONE_CANDIDATE_KINDS: &[&str] = &["function_declaration", "method_declaration"];

/// Node kinds whose text is an identifier for clone normalization.
pub const GO_CLONE_IDENTIFIER_KINDS: &[&str] = &[
    "identifier",
    "field_identifier",
    "package_identifier",
    "type_identifier",
];

/// Node kinds holding a Go string literal.
pub const GO_CLONE_STRING_LITERAL_KINDS: &[&str] = &[
    "interpreted_string_literal",
    "raw_string_literal",
    "rune_literal",
];

/// Node kinds holding a Go numeric literal.
pub const GO_CLONE_NUMBER_LITERAL_KINDS: &[&str] =
    &["int_literal", "float_literal", "imaginary_literal"];

/// Node kinds holding a Go comment.
pub const GO_CLONE_COMMENT_KINDS: &[&str] = &["comment"];
