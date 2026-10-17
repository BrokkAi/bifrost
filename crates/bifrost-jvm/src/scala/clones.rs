//! Scala's structural-clone normalization.
//!
//! Two views of the same declaration source: a leaf-token stream with
//! identifiers and literals collapsed to placeholders, and an AST-label
//! signature over every node. `CloneCandidateData` and the excerpt formatter
//! are analysis-owned, so `analyzer/scala/clones.rs` keeps the candidate
//! builder that reads the declaration off the analyzer.

use brokk_bifrost_core::clones::{
    CloneNormalizationRules, clone_ast_signature, normalized_clone_tokens,
};
use tree_sitter::Tree;

const SCALA_CLONE_AST_IDENTIFIER_TYPES: &[&str] = &["identifier"];
const SCALA_CLONE_AST_STRING_TYPES: &[&str] = &["string"];
const SCALA_CLONE_AST_NUMBER_TYPES: &[&str] = &["integer_literal", "floating_point_literal"];
const SCALA_CLONE_NORMALIZATION_RULES: CloneNormalizationRules = CloneNormalizationRules {
    identifier_kinds: SCALA_CLONE_AST_IDENTIFIER_TYPES,
    string_kinds: SCALA_CLONE_AST_STRING_TYPES,
    number_kinds: SCALA_CLONE_AST_NUMBER_TYPES,
    boolean_kinds: &[],
    boolean_values: &["true", "false"],
    null_kinds: &[],
    null_values: &[],
    comment_kinds: &["comment"],
    ignored_ast_kinds: &[],
};

pub fn normalized_clone_tokens_scala(source: &str) -> Vec<String> {
    normalized_clone_tokens(
        parse_scala_tree(source),
        source,
        SCALA_CLONE_NORMALIZATION_RULES,
    )
}

pub fn build_scala_clone_ast_signature(source: &str) -> String {
    clone_ast_signature(
        parse_scala_tree(source),
        source,
        SCALA_CLONE_NORMALIZATION_RULES,
    )
}

fn parse_scala_tree(source: &str) -> Option<Tree> {
    if brokk_bifrost_core::analyzer::common::is_unparseable_source(source) {
        return None;
    }
    crate::scala::language::parse_tree(source).expect("failed to load scala parser")
}
