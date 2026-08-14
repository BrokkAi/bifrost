use super::RustAnalyzer;
use crate::analyzer::clone_detection::{
    CloneCandidateData, CloneSyntaxProfile, build_tree_sitter_clone_candidate_data,
};
use crate::analyzer::{CloneSmellWeights, CodeUnit, Language};
use brokk_bifrost_rust::adapter::{
    RUST_CLONE_CANDIDATE_KINDS, RUST_CLONE_COMMENT_KINDS, RUST_CLONE_IDENTIFIER_KINDS,
    RUST_CLONE_NUMBER_LITERAL_KINDS, RUST_CLONE_STRING_LITERAL_KINDS,
};

const RUST_CLONE_SYNTAX: CloneSyntaxProfile = CloneSyntaxProfile::new(
    Language::Rust,
    RUST_CLONE_CANDIDATE_KINDS,
    RUST_CLONE_IDENTIFIER_KINDS,
    RUST_CLONE_STRING_LITERAL_KINDS,
    RUST_CLONE_NUMBER_LITERAL_KINDS,
    RUST_CLONE_COMMENT_KINDS,
);

pub(super) fn build_rust_clone_candidate_data(
    analyzer: &RustAnalyzer,
    code_unit: &CodeUnit,
    weights: CloneSmellWeights,
) -> Option<CloneCandidateData> {
    build_tree_sitter_clone_candidate_data(analyzer, code_unit, weights, RUST_CLONE_SYNTAX)
}
