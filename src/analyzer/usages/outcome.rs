use crate::analyzer::usages::model::FuzzyResult;

#[derive(Debug, Clone)]
pub(crate) enum GraphUsageOutcome {
    Resolved(FuzzyResult),
    FallbackSafe {
        fq_name: String,
        reason: String,
    },
    #[allow(dead_code)]
    TerminalFailure {
        fq_name: String,
        reason: String,
    },
}

impl GraphUsageOutcome {
    pub(crate) fn fallback_safe(
        fq_name: impl Into<String>,
        reason: GraphFailureReason,
        strategy: &'static str,
    ) -> Self {
        Self::FallbackSafe {
            fq_name: fq_name.into(),
            reason: reason.message(strategy),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn terminal_failure(
        fq_name: impl Into<String>,
        reason: GraphFailureReason,
        strategy: &'static str,
    ) -> Self {
        Self::TerminalFailure {
            fq_name: fq_name.into(),
            reason: reason.message(strategy),
        }
    }

    pub(crate) fn into_fuzzy_result(self) -> FuzzyResult {
        match self {
            GraphUsageOutcome::Resolved(result) => result,
            GraphUsageOutcome::FallbackSafe { fq_name, reason }
            | GraphUsageOutcome::TerminalFailure { fq_name, reason } => {
                FuzzyResult::Failure { fq_name, reason }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GraphFailureReason {
    UnsupportedTargetLanguage(&'static str),
    MissingAnalyzerCapability(&'static str),
    UnsupportedTargetShape(&'static str),
    NoGraphSeed(&'static str),
    UnsafeInference(&'static str),
}

impl GraphFailureReason {
    fn message(self, strategy: &'static str) -> String {
        let detail = match self {
            GraphFailureReason::UnsupportedTargetLanguage(message)
            | GraphFailureReason::MissingAnalyzerCapability(message)
            | GraphFailureReason::UnsupportedTargetShape(message)
            | GraphFailureReason::NoGraphSeed(message)
            | GraphFailureReason::UnsafeInference(message) => message,
        };
        format!("{strategy}: {detail}")
    }
}
