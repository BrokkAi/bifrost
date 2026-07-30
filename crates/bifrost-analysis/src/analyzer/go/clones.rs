use super::GoAnalyzer;
use crate::analyzer::clone_detection::{
    CloneCandidateData, CloneSyntaxProfile, build_tree_sitter_clone_candidate_data,
};
use crate::analyzer::{CloneSmellWeights, CodeUnit, Language};

const GO_CLONE_SYNTAX: CloneSyntaxProfile = CloneSyntaxProfile::new(
    Language::Go,
    &["function_declaration", "method_declaration"],
    &[
        "identifier",
        "field_identifier",
        "package_identifier",
        "type_identifier",
    ],
    &[
        "interpreted_string_literal",
        "raw_string_literal",
        "rune_literal",
    ],
    &["int_literal", "float_literal", "imaginary_literal"],
    &["comment"],
);

pub(super) fn build_go_clone_candidate_data(
    analyzer: &GoAnalyzer,
    code_unit: &CodeUnit,
    weights: CloneSmellWeights,
) -> Option<CloneCandidateData> {
    build_tree_sitter_clone_candidate_data(analyzer, code_unit, weights, GO_CLONE_SYNTAX)
}
