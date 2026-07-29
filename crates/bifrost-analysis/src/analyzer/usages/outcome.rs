use crate::analyzer::usages::model::{FuzzyResult, UsageAnalysisDiagnostic};

#[derive(Debug, Clone)]
pub(crate) enum GraphUsageOutcome {
    Resolved(FuzzyResult),
    FallbackSafe(UsageAnalysisDiagnostic),
    #[allow(dead_code)]
    TerminalFailure(UsageAnalysisDiagnostic),
}

impl GraphUsageOutcome {
    pub(crate) fn fallback_safe(
        fq_name: impl Into<String>,
        reason: GraphFailureReason,
        strategy: &'static str,
    ) -> Self {
        Self::FallbackSafe(usage_diagnostic(fq_name, reason, strategy))
    }

    #[allow(dead_code)]
    pub(crate) fn terminal_failure(
        fq_name: impl Into<String>,
        reason: GraphFailureReason,
        strategy: &'static str,
    ) -> Self {
        Self::TerminalFailure(usage_diagnostic(fq_name, reason, strategy))
    }

    pub(crate) fn into_fuzzy_result(self) -> FuzzyResult {
        match self {
            GraphUsageOutcome::Resolved(result) => result,
            GraphUsageOutcome::FallbackSafe(diagnostic)
            | GraphUsageOutcome::TerminalFailure(diagnostic) => FuzzyResult::Failure {
                fq_name: diagnostic.fq_name,
                reason_kind: diagnostic.reason_kind,
                reason: diagnostic.reason,
            },
        }
    }
}

fn usage_diagnostic(
    fq_name: impl Into<String>,
    reason: GraphFailureReason,
    strategy: &'static str,
) -> UsageAnalysisDiagnostic {
    UsageAnalysisDiagnostic {
        fq_name: fq_name.into(),
        strategy: strategy.to_string(),
        reason_kind: reason.kind().to_string(),
        reason: reason.message(strategy),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GraphFailureReason {
    UnsupportedTargetLanguage(&'static str),
    MissingAnalyzerCapability(&'static str),
    UnsupportedTargetShape(&'static str),
    NoGraphSeed(&'static str),
}

impl GraphFailureReason {
    fn kind(self) -> &'static str {
        match self {
            GraphFailureReason::UnsupportedTargetLanguage(_) => "unsupported_target_language",
            GraphFailureReason::MissingAnalyzerCapability(_) => "missing_analyzer_capability",
            GraphFailureReason::UnsupportedTargetShape(_) => "unsupported_target_shape",
            GraphFailureReason::NoGraphSeed(_) => "no_graph_seed",
        }
    }

    fn message(self, strategy: &'static str) -> String {
        let detail = match self {
            GraphFailureReason::UnsupportedTargetLanguage(message)
            | GraphFailureReason::MissingAnalyzerCapability(message)
            | GraphFailureReason::UnsupportedTargetShape(message)
            | GraphFailureReason::NoGraphSeed(message) => message,
        };
        format!("{strategy}: {detail}")
    }
}
