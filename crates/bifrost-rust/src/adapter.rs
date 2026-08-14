//! The Rust-language answers behind `brokk-bifrost-analysis`'s `RustAdapter`.
//!
//! Every item here is the language half of one `LanguageAdapter` method (or of
//! the clone-detection syntax profile). The trait impl itself stays in analysis
//! -- it names `ParsedFile` and `Language`-registry types this crate cannot see
//! -- and forwards to these free functions and constants.

use brokk_bifrost_core::analyzer::CodeUnit;
use brokk_bifrost_core::analyzer::cognitive_complexity;
use std::sync::LazyLock;

use crate::declarations::rust_package_name;

/// Cognitive-complexity node vocabulary for Rust.
pub static RUST_COGNITIVE_CONFIG: LazyLock<cognitive_complexity::Config> =
    LazyLock::new(|| cognitive_complexity::Config {
        if_types: &["if_expression"],
        loop_types: &["for_expression", "while_expression", "loop_expression"],
        case_types: &["match_arm"],
        binary_types: &["binary_expression"],
        logical_operators: &["&&", "||"],
        jump_types: &["break_expression", "continue_expression"],
        named_function_boundary_types: &["function_item"],
        anonymous_function_types: &["closure_expression"],
        else_clause_types: &["else_clause"],
        default_case_predicate: Some(cognitive_complexity::is_wildcard_case),
        ..cognitive_complexity::Config::empty()
    });

/// Source file extension for Rust.
pub const RUST_FILE_EXTENSION: &str = "rs";

/// Node kinds a Rust structural-clone candidate may be rooted at.
pub const RUST_CLONE_CANDIDATE_KINDS: &[&str] = &["function_item"];

/// Node kinds whose text is an identifier for structural-clone normalization.
pub const RUST_CLONE_IDENTIFIER_KINDS: &[&str] = &[
    "identifier",
    "field_identifier",
    "type_identifier",
    "scoped_identifier",
    "scoped_type_identifier",
    "lifetime",
];

/// Node kinds that are string literals for structural-clone normalization.
pub const RUST_CLONE_STRING_LITERAL_KINDS: &[&str] =
    &["string_literal", "raw_string_literal", "char_literal"];

/// Node kinds that are numeric literals for structural-clone normalization.
pub const RUST_CLONE_NUMBER_LITERAL_KINDS: &[&str] = &["integer_literal", "float_literal"];

/// Node kinds that are comments for structural-clone normalization.
pub const RUST_CLONE_COMMENT_KINDS: &[&str] = &["line_comment", "block_comment"];

/// The receiver of a Rust call reference, i.e. everything before the final `::`
/// of the callee path, with any argument list dropped.
pub fn rust_extract_call_receiver(reference: &str) -> Option<String> {
    let trimmed = reference.trim();
    let before_args = trimmed
        .split_once('(')
        .map(|(head, _)| head)
        .unwrap_or(trimmed);
    before_args
        .rsplit_once("::")
        .map(|(receiver, _)| receiver.to_string())
}

/// Whether a declaration's stored package qualifier differs from the one its
/// path alone implies, i.e. whether it has to be persisted at all.
pub fn rust_unit_has_explicit_qualifier(code_unit: &CodeUnit) -> bool {
    code_unit.package_name() != rust_package_name(code_unit.source())
}
