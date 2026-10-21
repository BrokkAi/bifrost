//! The analysis-side entry point for PHP's structural-clone candidates.
//!
//! `CloneCandidateData` and `compact_clone_excerpt` are analysis-owned, and the
//! declaration source comes from the analyzer; the token and AST-signature
//! normalization that knows PHP moved to [`brokk_bifrost_php::clones`].

use crate::analyzer::php::PhpAnalyzer;

use brokk_bifrost_core::analyzer::model::CloneSmellWeights;

use brokk_bifrost_analysis::analyzer::clone_detection::CloneCandidateData;

use brokk_bifrost_analysis::analyzer::clone_detection::build_clone_candidate_data;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;
use brokk_bifrost_php::clones::{build_php_clone_ast_signature, normalized_clone_tokens_php};

pub(crate) fn build_php_clone_candidate_data(
    analyzer: &PhpAnalyzer,
    code_unit: &CodeUnit,
    weights: CloneSmellWeights,
) -> Option<CloneCandidateData> {
    build_clone_candidate_data(
        analyzer.get_source(code_unit, false),
        code_unit,
        weights,
        |source, _| {
            Some((
                normalized_clone_tokens_php(source),
                build_php_clone_ast_signature(source),
            ))
        },
    )
}
