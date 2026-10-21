use crate::analyzer::go::GoAnalyzer;

use brokk_bifrost_analysis::analyzer::clone_detection::CloneCandidateData;

use brokk_bifrost_analysis::analyzer::clone_detection::CloneSyntaxProfile;

use brokk_bifrost_analysis::analyzer::clone_detection::build_tree_sitter_clone_candidate_data;

use brokk_bifrost_core::analyzer::model::CloneSmellWeights;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_core::analyzer::model::Language;
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

pub(crate) fn build_go_clone_candidate_data(
    analyzer: &GoAnalyzer,
    code_unit: &CodeUnit,
    weights: CloneSmellWeights,
) -> Option<CloneCandidateData> {
    build_tree_sitter_clone_candidate_data(analyzer, code_unit, weights, GO_CLONE_SYNTAX)
}
