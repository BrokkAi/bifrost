use crate::analyzer::kotlin::KotlinAnalyzer;

use brokk_bifrost_analysis::analyzer::clone_detection::CloneCandidateData;

use brokk_bifrost_analysis::analyzer::clone_detection::CloneSyntaxProfile;

use brokk_bifrost_analysis::analyzer::clone_detection::build_tree_sitter_clone_candidate_data;

use brokk_bifrost_core::analyzer::model::CloneSmellWeights;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_core::analyzer::model::Language;

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

pub(crate) fn build_kotlin_clone_candidate_data(
    analyzer: &KotlinAnalyzer,
    code_unit: &CodeUnit,
    weights: CloneSmellWeights,
) -> Option<CloneCandidateData> {
    build_tree_sitter_clone_candidate_data(analyzer, code_unit, weights, KOTLIN_CLONE_SYNTAX)
}
