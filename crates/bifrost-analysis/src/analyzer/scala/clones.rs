//! The analysis-side entry point for Scala's structural-clone candidates.
//!
//! `CloneCandidateData` and `compact_clone_excerpt` are analysis-owned and the
//! declaration source comes from the analyzer; the token and AST-label
//! normalization that knows Scala moved to [`brokk_bifrost_jvm::scala::clones`].

use crate::CloneSmellWeights;
use crate::analyzer::CodeUnit;
use crate::analyzer::CodeUnitIndex;
use crate::analyzer::clone_detection::{CloneCandidateData, build_clone_candidate_data};
use brokk_bifrost_jvm::scala::clones::{
    build_scala_clone_ast_signature, normalized_clone_tokens_scala,
};

use super::ScalaAnalyzer;

pub(super) fn build_scala_clone_candidate_data(
    analyzer: &ScalaAnalyzer,
    code_unit: &CodeUnit,
    weights: CloneSmellWeights,
) -> Option<CloneCandidateData> {
    build_clone_candidate_data(
        analyzer.get_source(code_unit, false),
        code_unit,
        weights,
        |source, _| {
            Some((
                normalized_clone_tokens_scala(source),
                build_scala_clone_ast_signature(source),
            ))
        },
    )
}
