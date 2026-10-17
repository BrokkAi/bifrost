//! The analysis-side entry point for Python's structural-clone candidates.
//!
//! `CloneCandidateData` and `compact_clone_excerpt` are analysis-owned, and the
//! declaration source comes from the analyzer; the token and AST-signature
//! normalization that knows Python moved to [`brokk_bifrost_python::clones`].

use super::PythonAnalyzer;
use crate::analyzer::clone_detection::{
    CloneCandidateData, build_clone_candidate_data as build_shared_clone_candidate_data,
};
use crate::analyzer::{CloneSmellWeights, CodeUnit, CodeUnitIndex};
use brokk_bifrost_python::clones::prepare_python_clone;

pub(super) fn build_clone_candidate_data(
    analyzer: &PythonAnalyzer,
    code_unit: &CodeUnit,
    weights: CloneSmellWeights,
) -> Option<CloneCandidateData> {
    build_shared_clone_candidate_data(
        analyzer.get_source(code_unit, false),
        code_unit,
        weights,
        |source, minimum| {
            let preparation = prepare_python_clone(source, minimum)?;
            Some((preparation.normalized_tokens, preparation.ast_signature))
        },
    )
}
