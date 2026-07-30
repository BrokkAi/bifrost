use super::RustAnalyzer;
use crate::analyzer::clone_detection::{
    CloneCandidateData, CloneSyntaxProfile, build_tree_sitter_clone_candidate_data,
};
use crate::analyzer::{CloneSmellWeights, CodeUnit, Language};

const RUST_CLONE_SYNTAX: CloneSyntaxProfile = CloneSyntaxProfile::new(
    Language::Rust,
    &["function_item"],
    &[
        "identifier",
        "field_identifier",
        "type_identifier",
        "scoped_identifier",
        "scoped_type_identifier",
        "lifetime",
    ],
    &["string_literal", "raw_string_literal", "char_literal"],
    &["integer_literal", "float_literal"],
    &["line_comment", "block_comment"],
);

pub(super) fn build_rust_clone_candidate_data(
    analyzer: &RustAnalyzer,
    code_unit: &CodeUnit,
    weights: CloneSmellWeights,
) -> Option<CloneCandidateData> {
    build_tree_sitter_clone_candidate_data(analyzer, code_unit, weights, RUST_CLONE_SYNTAX)
}
