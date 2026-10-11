use super::results::{CodeQueryDiagnostic, CodeQueryDiagnosticImpact};
use crate::analyzer::Range;

/// Result of one language-owned relation over one source file.
///
/// Language rules may select no ranges while still being unable to prove an
/// exhaustive negative result. Keep those diagnostics beside the ranges so
/// the shared seed executor cannot turn an incomplete relation into a clean
/// empty selection.
#[derive(Default)]
pub(super) struct LanguageRuleMatches {
    pub(super) ranges: Vec<Range>,
    pub(super) diagnostics: Vec<CodeQueryDiagnostic>,
}

impl LanguageRuleMatches {
    pub(super) fn from_ranges(ranges: Vec<Range>) -> Self {
        Self {
            ranges,
            diagnostics: Vec::new(),
        }
    }

    pub(super) fn incomplete(ranges: Vec<Range>, language: &'static str, message: String) -> Self {
        Self {
            ranges,
            diagnostics: vec![CodeQueryDiagnostic {
                code: super::results::CodeQueryDiagnosticCode::UnsupportedStructuralFeature,
                impact: CodeQueryDiagnosticImpact::Incomplete,
                branch: Vec::new(),
                language,
                message,
                exhausted_roots: Vec::new(),
            }],
        }
    }
}
