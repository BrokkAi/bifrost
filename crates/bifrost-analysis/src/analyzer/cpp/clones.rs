//! The analysis-side entry point for C++'s structural-clone candidates.
//!
//! `CloneCandidateData` and `compact_clone_excerpt` are analysis-owned and the
//! declaration source comes from the analyzer; the token and AST-label
//! normalization that knows C++ moved to [`brokk_bifrost_cpp::clones`].

use super::*;
use crate::analyzer::clone_detection::{CloneCandidateData, compact_clone_excerpt};
use brokk_bifrost_cpp::clones::cpp_clone_profile;
use tree_sitter::Parser;

pub(super) fn build_clone_candidate_data(
    analyzer: &CppAnalyzer,
    code_unit: &CodeUnit,
    weights: CloneSmellWeights,
    parser: &mut Parser,
) -> Option<CloneCandidateData> {
    analyzer
        .get_source(code_unit, false)
        .map(|source| source.trim().to_string())
        .filter(|source| !source.is_empty())
        .and_then(|source| {
            let (normalized_tokens, ast_signature) = cpp_clone_profile(parser, &source);
            if normalized_tokens.len() < weights.min_normalized_tokens.max(0) as usize {
                return None;
            }
            Some(CloneCandidateData {
                unit: code_unit.clone(),
                normalized_tokens,
                ast_signature,
                excerpt: compact_clone_excerpt(&source),
            })
        })
}
