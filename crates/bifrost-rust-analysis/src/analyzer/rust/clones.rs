use crate::analyzer::rust::RustAnalyzer;

use brokk_bifrost_analysis::analyzer::clone_detection::CloneCandidateData;

use brokk_bifrost_analysis::analyzer::clone_detection::CloneSyntaxProfile;

use brokk_bifrost_analysis::analyzer::clone_detection::build_tree_sitter_clone_candidate_data;

use brokk_bifrost_core::analyzer::model::CloneSmellWeights;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_core::analyzer::model::Language;
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

pub(crate) fn build_rust_clone_candidate_data(
    analyzer: &RustAnalyzer,
    code_unit: &CodeUnit,
    weights: CloneSmellWeights,
) -> Option<CloneCandidateData> {
    build_tree_sitter_clone_candidate_data(analyzer, code_unit, weights, RUST_CLONE_SYNTAX)
}
