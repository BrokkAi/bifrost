use super::results::{CodeQueryDiagnostic, CodeQueryDiagnosticImpact};
use crate::analyzer::{ProjectFile, Range};
use brokk_bifrost_analysis::analyzer::read_ledger::DerivationExecutionCause;

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
#[derive(Debug, Clone)]
pub(super) struct LanguageRuleMatch {
    pub(super) selected_pattern_source: super::SelectedPatternSourceEvidence,
    pub(super) select: Range,
    pub(super) report: Range,
    /// Why the match is a heuristic guess rather than a structural fact, for
    /// a relation that ranks likely candidates instead of proving one. A
    /// policy finding from such a match is only possible, with this reason.
    pub(super) heuristic: Option<&'static str>,
}

impl From<Range> for LanguageRuleMatch {
    fn from(range: Range) -> Self {
        Self {
            selected_pattern_source: Default::default(),
            select: range,
            report: range,
            heuristic: None,
        }
    }
}

impl LanguageRuleMatch {
    pub(super) fn heuristic(range: Range, reason: &'static str) -> Self {
        Self {
            heuristic: Some(reason),
            ..Self::from(range)
        }
    }
}

/// One place where a language rule could not decide its relation: an
/// unresolved type, an unclassified exception, an unproven method family, or
/// a workspace file whose source the rule could not read.
pub(super) struct UndecidedSite {
    site: String,
    reason: &'static str,
    /// The operational stop behind the reason; `None` for a gap in what the
    /// analysis models (Content).
    cause: Option<DerivationExecutionCause>,
}

impl UndecidedSite {
    pub(super) fn at(range: Range, reason: &'static str) -> Self {
        Self {
            site: range_label(range),
            reason,
            cause: None,
        }
    }

    /// A site that an operational stop (cancellation, a budget, a provider
    /// that could not answer) left undecided.
    pub(super) fn stopped(
        range: Range,
        reason: &'static str,
        cause: DerivationExecutionCause,
    ) -> Self {
        Self {
            site: range_label(range),
            reason,
            cause: Some(cause),
        }
    }

    pub(super) fn in_file(file: &ProjectFile, reason: &'static str) -> Self {
        Self {
            site: super::rel_path_string(file),
            reason,
            cause: None,
        }
    }
}

fn range_label(range: Range) -> String {
    format!(
        "lines {}-{} bytes {}..{}",
        range.start_line, range.end_line, range.start_byte, range.end_byte
    )
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
                has_non_utf8_refusal: false,
                refusal_sites: Default::default(),
                call_relation_facts: None,
                uses_omissions: Vec::new(),
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
                step_index: None,
                step_op: None,
                no_rows_reason: None,
                cause_codes: Vec::new(),
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
        matches.sort_unstable_by_key(|matched| (matched.select, matched.report, matched.heuristic));
        matches.dedup_by(|right, left| {
            if (left.select, left.report, left.heuristic)
                != (right.select, right.report, right.heuristic)
            {
                return false;
            }
            left.selected_pattern_source
                .merge(&right.selected_pattern_source);
            true
        });
        if undecided.is_empty() {
            return Self {
                matches,
                diagnostics: Vec::new(),
            };
        }
        // One diagnostic per cause, so an operational stop is never reported
        // as a content gap or merged with one.
        let mut causes = undecided.iter().map(|site| site.cause).collect::<Vec<_>>();
        causes.sort_unstable();
        causes.dedup();
        let mut result = Self {
            matches,
            diagnostics: Vec::new(),
        };
        for cause in causes {
            let sites = undecided
                .iter()
                .filter(|site| site.cause == cause)
                .map(|site| format!("{}: {}", site.site, site.reason))
                .collect::<Vec<_>>();
            let message = brokk_bifrost_core::bounded_output::bounded_diagnostic_items(
                format_args!(
                    "{rule} is incomplete for {}: the relation could not be decided at {sites:?}",
                    super::rel_path_string(file),
                ),
                format_args!("{rule} is incomplete for {}", super::rel_path_string(file)),
                sites.iter(),
            );
            let mut diagnostics =
                Self::incomplete(Vec::<Range>::new(), language, message).diagnostics;
            if let Some(cause) = cause {
                for diagnostic in &mut diagnostics {
                    diagnostic.incompleteness = super::results::Incompleteness::Operational(cause);
                }
            }
            result.diagnostics.extend(diagnostics);
        }
        result
    }
}

/// Acquire the exact indexed reading instead of parsing source without its configuration.
pub(super) fn selected_syntax(
    analyzer: &dyn crate::analyzer::IAnalyzer,
    file: &ProjectFile,
    source: &str,
) -> Result<
    std::sync::Arc<brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree>,
    LanguageRuleMatches,
> {
    use crate::analyzer::common::language_for_file;
    use brokk_bifrost_analysis::analyzer::structural::provider::StructuralSyntaxLimitedOutcome;
    let language = language_for_file(file);
    let outcome = analyzer
        .structural_fact_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == language)
        .map_or(StructuralSyntaxLimitedOutcome::Unavailable, |provider| {
            provider.structural_syntax_limited(file, source.len(), None)
        });
    let (cause, reason) = match outcome {
        StructuralSyntaxLimitedOutcome::Available(syntax)
            if syntax.prepared().source() == source =>
        {
            return Ok(syntax.clone_prepared());
        }
        StructuralSyntaxLimitedOutcome::Available(_) => (
            DerivationExecutionCause::Snapshot,
            "selected syntax differs from the source snapshot",
        ),
        StructuralSyntaxLimitedOutcome::Exceeded { .. } => (
            DerivationExecutionCause::Budget,
            "selected syntax exceeds the source budget",
        ),
        StructuralSyntaxLimitedOutcome::Cancelled => (
            DerivationExecutionCause::Cancelled,
            "selected syntax acquisition was cancelled",
        ),
        StructuralSyntaxLimitedOutcome::Unavailable => (
            DerivationExecutionCause::Provider,
            "selected syntax is unavailable",
        ),
    };
    // The execution-state diagnostic this pushes carries the dependence into
    // the query's reuse verdict.
    analyzer.mark_execution_dependent();
    let mut result = LanguageRuleMatches::incomplete(
        Vec::<Range>::new(),
        language.config_label(),
        format!("{reason} for {}", super::rel_path_string(file)),
    );
    for diagnostic in &mut result.diagnostics {
        diagnostic.incompleteness = super::results::Incompleteness::Operational(cause);
    }
    Err(result)
}
