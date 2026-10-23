//! The analysis-side entry point for Java's structural-clone candidates.
//!
//! `CloneCandidateData` and `compact_clone_excerpt` are analysis-owned and the
//! declaration source comes from the analyzer; the token and AST-label
//! normalization that knows Java moved to [`brokk_bifrost_jvm::java::clones`].

use crate::analyzer::java::*;

use brokk_bifrost_analysis::analyzer::clone_detection::CloneCandidateData;

use brokk_bifrost_analysis::analyzer::clone_detection::build_clone_candidate_data as build_shared_clone_candidate_data;
use brokk_bifrost_jvm::java::clones::prepare_java_clone;

pub(crate) fn build_clone_candidate_data(
    analyzer: &JavaAnalyzer,
    code_unit: &CodeUnit,
    weights: CloneSmellWeights,
) -> Option<CloneCandidateData> {
    build_shared_clone_candidate_data(
        analyzer.get_source(code_unit, false),
        code_unit,
        weights,
        |source, minimum| {
            let preparation = prepare_java_clone(source, minimum)?;
            Some((preparation.normalized_tokens, preparation.ast_signature))
        },
    )
}
