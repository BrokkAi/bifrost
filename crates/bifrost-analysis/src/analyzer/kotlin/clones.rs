use super::KotlinAnalyzer;
use crate::analyzer::clone_detection::{
    CloneCandidateData, CloneSyntaxProfile, build_tree_sitter_clone_candidate_data,
};
use crate::analyzer::{CloneSmellWeights, CodeUnit, Language};

const KOTLIN_CLONE_SYNTAX: CloneSyntaxProfile = CloneSyntaxProfile::new(
    Language::Kotlin,
    &["function_declaration"],
    &["simple_identifier", "type_identifier"],
    &[
        "string_literal",
        "string_content",
        "character_literal",
        "character_escape_seq",
    ],
    &[
        "integer_literal",
        "hex_literal",
        "bin_literal",
        "real_literal",
        "long_literal",
        "unsigned_literal",
    ],
    &["line_comment", "multiline_comment"],
);

pub(super) fn build_kotlin_clone_candidate_data(
    analyzer: &KotlinAnalyzer,
    code_unit: &CodeUnit,
    weights: CloneSmellWeights,
) -> Option<CloneCandidateData> {
    build_tree_sitter_clone_candidate_data(analyzer, code_unit, weights, KOTLIN_CLONE_SYNTAX)
}
