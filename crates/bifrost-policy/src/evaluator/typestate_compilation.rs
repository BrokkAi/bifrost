use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TypestateCompilationFailure {
    Incomplete {
        reasons: Box<[PolicyIncompleteReason]>,
        message: Box<str>,
        work: PolicyWorkReport,
    },
    Failed {
        reason: PolicyFailureReason,
        message: Box<str>,
        work: PolicyWorkReport,
    },
}

impl TypestateCompilationFailure {
    pub(crate) fn incomplete_many_with_work(
        mut reasons: Vec<PolicyIncompleteReason>,
        message: impl Into<Box<str>>,
        work: PolicyWorkReport,
    ) -> Self {
        reasons.sort();
        reasons.dedup();
        Self::Incomplete {
            reasons: reasons.into_boxed_slice(),
            message: message.into(),
            work,
        }
    }

    pub(crate) fn failed(reason: PolicyFailureReason, message: impl Into<Box<str>>) -> Self {
        Self::Failed {
            reason,
            message: message.into(),
            work: PolicyWorkReport::default(),
        }
    }

    pub(crate) fn failed_with_work(
        reason: PolicyFailureReason,
        message: impl Into<Box<str>>,
        work: PolicyWorkReport,
    ) -> Self {
        Self::Failed {
            reason,
            message: message.into(),
            work,
        }
    }
}
