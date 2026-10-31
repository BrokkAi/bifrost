use super::results::{CodeQueryDiagnostic, CodeQueryDiagnosticImpact};
use crate::analyzer::{ProjectFile, Range};

/// Result of one language-owned relation over one source file.
///
/// Language rules may select no ranges while still being unable to prove an
/// exhaustive negative result. Keep those diagnostics beside the ranges so
/// the shared seed executor cannot turn an incomplete relation into a clean
/// empty selection.
#[derive(Default)]
pub(super) struct LanguageRuleMatches {
    pub(super) matches: Vec<LanguageRuleMatch>,
    pub(super) diagnostics: Vec<CodeQueryDiagnostic>,
}

/// The fact range used to select a language-rule match and its displayed
/// source range. Most rules use the same range for both.
#[derive(Debug, Clone, Copy)]
pub(super) struct LanguageRuleMatch {
    pub(super) select: Range,
    pub(super) report: Range,
}

impl From<Range> for LanguageRuleMatch {
    fn from(range: Range) -> Self {
        Self {
            select: range,
            report: range,
        }
    }
}

/// One place where a language rule could not decide its relation: an
/// unresolved type, an unclassified exception, an unproven method family, or
/// a workspace file whose source the rule could not read.
pub(super) struct UndecidedSite {
    site: String,
    reason: &'static str,
}

impl UndecidedSite {
    pub(super) fn at(range: Range, reason: &'static str) -> Self {
        Self {
            site: format!(
                "lines {}-{} bytes {}..{}",
                range.start_line, range.end_line, range.start_byte, range.end_byte
            ),
            reason,
        }
    }

    pub(super) fn in_file(file: &ProjectFile, reason: &'static str) -> Self {
        Self {
            site: super::rel_path_string(file),
            reason,
        }
    }
}

impl LanguageRuleMatches {
    pub(super) fn from_ranges<T: Into<LanguageRuleMatch>>(ranges: Vec<T>) -> Self {
        Self {
            matches: ranges.into_iter().map(Into::into).collect(),
            diagnostics: Vec::new(),
        }
    }

    pub(super) fn incomplete<T: Into<LanguageRuleMatch>>(
        ranges: Vec<T>,
        language: &'static str,
        message: String,
    ) -> Self {
        Self {
            matches: ranges.into_iter().map(Into::into).collect(),
            diagnostics: vec![CodeQueryDiagnostic::new(CodeQueryDiagnostic {
                incompleteness: brokk_bifrost_rql::Incompleteness::Content,
                related: Vec::new(),
                source: None,
                code: super::results::CodeQueryDiagnosticCode::UnsupportedStructuralFeature,
                impact: CodeQueryDiagnosticImpact::Incomplete,
                branch: Vec::new(),
                language,
                message,
                exhausted_roots: Vec::new(),
                withheld_rows_path: None,
            })],
        }
    }

    /// Combine the ranges a rule proved with the sites it could not decide.
    ///
    /// A rule that cannot decide a site must not report a clean result for
    /// it: once a capability is advertised, an empty selection reads as
    /// "proven absent". Any undecided site therefore makes the whole file
    /// result incomplete, while the proven ranges still flow through.
    pub(super) fn decided<T: Into<LanguageRuleMatch>>(
        ranges: Vec<T>,
        undecided: Vec<UndecidedSite>,
        language: &'static str,
        rule: &'static str,
        file: &ProjectFile,
    ) -> Self {
        let mut matches = ranges.into_iter().map(Into::into).collect::<Vec<_>>();
        matches.sort_unstable_by_key(|matched| (matched.select, matched.report));
        matches.dedup_by_key(|matched| (matched.select, matched.report));
        if undecided.is_empty() {
            return Self {
                matches,
                diagnostics: Vec::new(),
            };
        }
        let sites = undecided
            .iter()
            .map(|site| format!("{}: {}", site.site, site.reason))
            .collect::<Vec<_>>();
        let message = format!(
            "{rule} is incomplete for {}: the relation could not be decided at {sites:?}",
            super::rel_path_string(file),
        );
        Self::incomplete(matches, language, message)
    }
}
