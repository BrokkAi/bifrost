//! The analysis-side entry point for C#'s structural-clone candidates.
//!
//! `CloneCandidateData` and `compact_clone_excerpt` are analysis-owned, and the
//! declaration source comes from the analyzer; the token and AST-signature
//! normalization that knows C# moved to [`brokk_bifrost_csharp::clones`].

use crate::CloneSmellWeights;
use crate::analyzer::CodeUnit;
use crate::analyzer::CodeUnitIndex;
use crate::analyzer::clone_detection::{CloneCandidateData, compact_clone_excerpt};
use brokk_bifrost_csharp::clones::{
    build_csharp_clone_ast_signature, normalized_clone_tokens_csharp,
};

use super::CSharpAnalyzer;

pub(super) fn build_csharp_clone_candidate_data(
    analyzer: &CSharpAnalyzer,
    code_unit: &CodeUnit,
    weights: CloneSmellWeights,
) -> Option<CloneCandidateData> {
    analyzer
        .get_source(code_unit, false)
        .map(|source| source.trim().to_string())
        .filter(|source| !source.is_empty())
        .and_then(|source| {
            let normalized_tokens = normalized_clone_tokens_csharp(&source);
            if normalized_tokens.len() < weights.min_normalized_tokens.max(0) as usize {
                return None;
            }
            Some(CloneCandidateData {
                unit: code_unit.clone(),
                normalized_tokens,
                ast_signature: build_csharp_clone_ast_signature(&source),
                excerpt: compact_clone_excerpt(&source),
            })
        })
}
