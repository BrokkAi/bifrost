//! The analysis-side entry point for C++'s structural-clone candidates.
//!
//! `CloneCandidateData` and `compact_clone_excerpt` are analysis-owned and the
//! declaration source comes from the analyzer; the token and AST-label
//! normalization that knows C++ moved to [`brokk_bifrost_cpp::clones`].

use super::*;
use crate::analyzer::clone_detection::{
    CloneCandidateData, build_clone_candidate_data as build_shared_clone_candidate_data,
};
use brokk_bifrost_cpp::clones::cpp_clone_profile;
use tree_sitter::Parser;

pub(super) fn build_clone_candidate_data(
    analyzer: &CppAnalyzer,
    code_unit: &CodeUnit,
    weights: CloneSmellWeights,
    parser: &mut Parser,
) -> Option<CloneCandidateData> {
    build_shared_clone_candidate_data(
        analyzer.get_source(code_unit, false),
        code_unit,
        weights,
        |source, _| Some(cpp_clone_profile(parser, source)),
    )
}
