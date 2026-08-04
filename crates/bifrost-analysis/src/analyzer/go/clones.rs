use super::GoAnalyzer;
use crate::analyzer::clone_detection::{
    CloneCandidateData, CloneSyntaxProfile, build_tree_sitter_clone_candidate_data,
};
use crate::analyzer::{CloneSmellWeights, CodeUnit, Language};
use brokk_bifrost_go::adapter::{
    GO_CLONE_CANDIDATE_KINDS, GO_CLONE_COMMENT_KINDS, GO_CLONE_IDENTIFIER_KINDS,
    GO_CLONE_NUMBER_LITERAL_KINDS, GO_CLONE_STRING_LITERAL_KINDS,
};

const GO_CLONE_SYNTAX: CloneSyntaxProfile = CloneSyntaxProfile::new(
    Language::Go,
    GO_CLONE_CANDIDATE_KINDS,
    GO_CLONE_IDENTIFIER_KINDS,
    GO_CLONE_STRING_LITERAL_KINDS,
    GO_CLONE_NUMBER_LITERAL_KINDS,
    GO_CLONE_COMMENT_KINDS,
);

pub(super) fn build_go_clone_candidate_data(
    analyzer: &GoAnalyzer,
    code_unit: &CodeUnit,
    weights: CloneSmellWeights,
) -> Option<CloneCandidateData> {
    build_tree_sitter_clone_candidate_data(analyzer, code_unit, weights, GO_CLONE_SYNTAX)
}
