//! The analysis-side entry point for JS/TS structural-clone candidates.
//!
//! `CloneCandidateData` and `compact_clone_excerpt` are analysis-owned and the
//! declaration source comes from the analyzer; the token and AST-label
//! normalization that knows the two grammars moved to
//! [`brokk_bifrost_js_ts::clones`].
//!
//! One function for both dialects: the dialect enters only as the grammar the
//! normalizers parse with, so both analyzers call this.

use crate::analyzer::clone_detection::{CloneCandidateData, build_clone_candidate_data};
use crate::analyzer::{CodeUnit, CodeUnitIndex};
use brokk_bifrost_core::analyzer::model::CloneSmellWeights;
use brokk_bifrost_js_ts::clones::{build_js_ts_clone_ast_signature, normalized_clone_tokens_js_ts};
use tree_sitter::Language as TsLanguage;

pub(crate) fn build_js_ts_clone_candidate_data(
    index: &dyn CodeUnitIndex,
    code_unit: &CodeUnit,
    weights: CloneSmellWeights,
    parser_language: TsLanguage,
) -> Option<CloneCandidateData> {
    build_clone_candidate_data(
        index.get_source(code_unit, false),
        code_unit,
        weights,
        |source, _| {
            Some((
                normalized_clone_tokens_js_ts(source, parser_language.clone()),
                build_js_ts_clone_ast_signature(source, parser_language),
            ))
        },
    )
}
