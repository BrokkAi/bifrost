//! The analysis-side entry point for Java's structural-clone candidates.
//!
//! `CloneCandidateData` and `compact_clone_excerpt` are analysis-owned and the
//! declaration source comes from the analyzer; the token and AST-label
//! normalization that knows Java moved to [`brokk_bifrost_jvm::java::clones`].

use super::*;
use crate::analyzer::clone_detection::{CloneCandidateData, compact_clone_excerpt};
use brokk_bifrost_jvm::java::clones::prepare_java_clone;

pub(super) fn build_clone_candidate_data(
    analyzer: &JavaAnalyzer,
    code_unit: &CodeUnit,
    weights: CloneSmellWeights,
) -> Option<CloneCandidateData> {
    let source = analyzer
        .get_source(code_unit, false)
        .map(|source| source.trim().to_string())
        .filter(|source| !source.is_empty());
    let source = source?;

    let preparation = prepare_java_clone(&source, weights.min_normalized_tokens.max(0) as usize);
    let preparation = preparation?;
    Some(CloneCandidateData {
        unit: code_unit.clone(),
        normalized_tokens: preparation.normalized_tokens,
        ast_signature: preparation.ast_signature,
        excerpt: compact_clone_excerpt(&source),
    })
}
