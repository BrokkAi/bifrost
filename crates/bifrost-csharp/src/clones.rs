//! C#'s clone-detection token and AST-signature normalization.
//!
//! `analyzer/csharp/clones.rs` in `brokk-bifrost-analysis` keeps the entry
//! point: it reads the declaration's source through the analyzer and assembles
//! the analysis-owned `CloneCandidateData`. Everything that knows what a C#
//! token *is* lives here.

use brokk_bifrost_core::clones::{
    CloneNormalizationRules, clone_ast_signature, normalized_clone_tokens,
};
use tree_sitter::Tree;

const CSHARP_CLONE_AST_IDENTIFIER_TYPES: &[&str] = &["identifier"];
const CSHARP_CLONE_AST_STRING_TYPES: &[&str] = &["string_literal"];
const CSHARP_CLONE_AST_NUMBER_TYPES: &[&str] = &["integer_literal", "real_literal"];
const CSHARP_CLONE_NORMALIZATION_RULES: CloneNormalizationRules = CloneNormalizationRules {
    identifier_kinds: CSHARP_CLONE_AST_IDENTIFIER_TYPES,
    string_kinds: CSHARP_CLONE_AST_STRING_TYPES,
    number_kinds: CSHARP_CLONE_AST_NUMBER_TYPES,
    boolean_kinds: &[],
    boolean_values: &["true", "false"],
    null_kinds: &[],
    null_values: &[],
    comment_kinds: &["comment"],
    ignored_ast_kinds: &[],
};

pub fn normalized_clone_tokens_csharp(source: &str) -> Vec<String> {
    normalized_clone_tokens(
        parse_csharp_tree(source),
        source,
        CSHARP_CLONE_NORMALIZATION_RULES,
    )
}

pub fn build_csharp_clone_ast_signature(source: &str) -> String {
    clone_ast_signature(
        parse_csharp_tree(source),
        source,
        CSHARP_CLONE_NORMALIZATION_RULES,
    )
}

pub fn parse_csharp_tree(source: &str) -> Option<Tree> {
    crate::preprocessor::parse_csharp(source)
}
