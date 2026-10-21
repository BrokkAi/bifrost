//! The analysis-side entry point for C#'s structural-clone candidates.
//!
//! `CloneCandidateData` and `compact_clone_excerpt` are analysis-owned, and the
//! declaration source comes from the analyzer; the token and AST-signature
//! normalization that knows C# moved to [`brokk_bifrost_csharp::clones`].

use brokk_bifrost_core::analyzer::model::CloneSmellWeights;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

use brokk_bifrost_analysis::analyzer::clone_detection::CloneCandidateData;

use brokk_bifrost_analysis::analyzer::clone_detection::build_clone_candidate_data;
use brokk_bifrost_csharp::clones::{
    build_csharp_clone_ast_signature, normalized_clone_tokens_csharp,
};

use crate::analyzer::csharp::CSharpAnalyzer;

pub(crate) fn build_csharp_clone_candidate_data(
    analyzer: &CSharpAnalyzer,
    code_unit: &CodeUnit,
    weights: CloneSmellWeights,
) -> Option<CloneCandidateData> {
    build_clone_candidate_data(
        analyzer.get_source(code_unit, false),
        code_unit,
        weights,
        |source, _| {
            Some((
                normalized_clone_tokens_csharp(source),
                build_csharp_clone_ast_signature(source),
            ))
        },
    )
}
