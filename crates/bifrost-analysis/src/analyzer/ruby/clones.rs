use super::RubyAnalyzer;
use crate::analyzer::clone_detection::{
    CloneCandidateData, CloneSyntaxProfile, build_tree_sitter_clone_candidate_data,
};
use crate::analyzer::{CloneSmellWeights, CodeUnit, Language};

const RUBY_CLONE_SYNTAX: CloneSyntaxProfile = CloneSyntaxProfile::new(
    Language::Ruby,
    &["method", "singleton_method"],
    &[
        "identifier",
        "constant",
        "instance_variable",
        "class_variable",
        "global_variable",
        "simple_symbol",
        "hash_key_symbol",
        "bare_symbol",
    ],
    &["string", "string_content", "heredoc_body", "character"],
    &["integer", "float", "rational", "complex"],
    &["comment"],
);

pub(super) fn build_ruby_clone_candidate_data(
    analyzer: &RubyAnalyzer,
    code_unit: &CodeUnit,
    weights: CloneSmellWeights,
) -> Option<CloneCandidateData> {
    build_tree_sitter_clone_candidate_data(analyzer, code_unit, weights, RUBY_CLONE_SYNTAX)
}
