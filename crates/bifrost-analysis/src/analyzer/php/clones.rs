//! The analysis-side entry point for PHP's structural-clone candidates.
//!
//! `CloneCandidateData` and `compact_clone_excerpt` are analysis-owned, and the
//! declaration source comes from the analyzer; the token and AST-signature
//! normalization that knows PHP moved to [`brokk_bifrost_php::clones`].

use super::PhpAnalyzer;
use crate::CloneSmellWeights;
use crate::analyzer::clone_detection::{CloneCandidateData, compact_clone_excerpt};
use crate::analyzer::{CodeUnit, CodeUnitIndex};
use brokk_bifrost_php::clones::{build_php_clone_ast_signature, normalized_clone_tokens_php};

pub(super) fn build_php_clone_candidate_data(
    analyzer: &PhpAnalyzer,
    code_unit: &CodeUnit,
    weights: CloneSmellWeights,
) -> Option<CloneCandidateData> {
    analyzer
        .get_source(code_unit, false)
        .map(|source| source.trim().to_string())
        .filter(|source| !source.is_empty())
        .and_then(|source| {
            let normalized_tokens = normalized_clone_tokens_php(&source);
            if normalized_tokens.len() < weights.min_normalized_tokens.max(0) as usize {
                return None;
            }
            Some(CloneCandidateData {
                unit: code_unit.clone(),
                normalized_tokens,
                ast_signature: build_php_clone_ast_signature(&source),
                excerpt: compact_clone_excerpt(&source),
            })
        })
}
