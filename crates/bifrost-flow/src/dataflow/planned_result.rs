//! Direction-independent results for planned data-flow execution.

use super::{
    DataflowDirectionExecutionMetrics, DataflowDirectionPlan, IcfgInputStatus, SolverTermination,
};

/// Completion evidence shared by every planned data-flow client.
///
/// The three components remain separate so callers can distinguish a partial
/// semantic snapshot, interrupted propagation, and domain-specific
/// incompleteness. In particular, an empty findings slice is a clean negative
/// only when this value is complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PlannedDataflowCompletion {
    input_status: IcfgInputStatus,
    termination: SolverTermination,
    domain_complete: bool,
}

impl PlannedDataflowCompletion {
    pub const fn new(
        input_status: IcfgInputStatus,
        termination: SolverTermination,
        domain_complete: bool,
    ) -> Self {
        Self {
            input_status,
            termination,
            domain_complete,
        }
    }

    pub const fn input_status(self) -> IcfgInputStatus {
        self.input_status
    }

    pub const fn termination(self) -> SolverTermination {
        self.termination
    }

    pub const fn domain_complete(self) -> bool {
        self.domain_complete
    }

    pub const fn is_complete(self) -> bool {
        self.input_status.is_complete() && self.termination.is_fixed_point() && self.domain_complete
    }
}

/// Why a planned result cannot reconstruct a normalized source-to-sink
/// witness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NormalizedWitnessUnavailableReason {
    /// The selected backward snapshot solver does not yet retain normalized
    /// source-to-sink witness relations.
    BackwardSolverUnsupported,
    /// The selected solver supports witnesses, but this query deliberately did
    /// not retain the required witness relations.
    RetentionDisabled,
    /// Witness retention was enabled, but its explicit best-effort limits were
    /// reached before every normalized relation could be retained.
    RetentionTruncated,
}

/// Capability status for normalized witnesses in one planned result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NormalizedWitnessAvailability {
    Available,
    Unavailable(NormalizedWitnessUnavailableReason),
}

impl NormalizedWitnessAvailability {
    pub const fn is_available(self) -> bool {
        matches!(self, Self::Available)
    }

    pub const fn unavailable_reason(self) -> Option<NormalizedWitnessUnavailableReason> {
        match self {
            Self::Available => None,
            Self::Unavailable(reason) => Some(reason),
        }
    }
}

/// One selected data-flow execution with canonical findings and preserved
/// direction-specific evidence.
///
/// `Finding` is the domain's stable, direction-independent observation.
/// `Evidence` is normally an enum whose variants retain the native forward
/// summary or backward snapshot result without coercing one into the other.
#[derive(Debug, Clone)]
pub struct PlannedDataflowResult<Finding, Evidence> {
    execution: DataflowDirectionExecutionMetrics,
    completion: PlannedDataflowCompletion,
    findings: Box<[Finding]>,
    evidence: Evidence,
    witnesses: NormalizedWitnessAvailability,
}

impl<Finding, Evidence> PlannedDataflowResult<Finding, Evidence> {
    pub fn new(
        plan: DataflowDirectionPlan,
        snapshot_work: crate::analyzer::semantic::SemanticWork,
        propagation_work: super::SolverWork,
        completion: PlannedDataflowCompletion,
        findings: impl Into<Box<[Finding]>>,
        evidence: Evidence,
        witnesses: NormalizedWitnessAvailability,
    ) -> Self {
        Self {
            execution: plan.record_work(snapshot_work, propagation_work),
            completion,
            findings: findings.into(),
            evidence,
            witnesses,
        }
    }

    pub const fn execution(&self) -> DataflowDirectionExecutionMetrics {
        self.execution
    }

    pub const fn completion(&self) -> PlannedDataflowCompletion {
        self.completion
    }

    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    pub const fn evidence(&self) -> &Evidence {
        &self.evidence
    }

    pub const fn witnesses(&self) -> NormalizedWitnessAvailability {
        self.witnesses
    }

    pub const fn is_complete(&self) -> bool {
        self.completion.is_complete()
    }

    pub fn into_evidence(self) -> Evidence {
        self.evidence
    }
}

#[cfg(test)]
mod tests {
    use crate::analyzer::semantic::{SemanticBudget, SemanticWork};

    use super::*;

    #[test]
    fn completion_keeps_semantic_budget_exhaustion_typed() {
        let mut limits = SemanticBudget::default().limits();
        limits.procedures = 4;
        let exceeded = SemanticBudget::new(limits)
            .expect("positive budget")
            .check(SemanticWork {
                procedures: 5,
                ..SemanticWork::default()
            })
            .expect_err("procedure budget should be exceeded");
        let completion = PlannedDataflowCompletion::new(
            IcfgInputStatus::ExceededBudget { exceeded },
            SolverTermination::FixedPoint,
            true,
        );

        assert!(!completion.is_complete());
        assert_eq!(completion.input_status().budget_exceeded(), Some(exceeded));
        assert!(completion.termination().is_fixed_point());
        assert!(completion.domain_complete());
    }

    #[test]
    fn completion_keeps_solver_cancellation_typed() {
        let completion = PlannedDataflowCompletion::new(
            IcfgInputStatus::Complete,
            SolverTermination::Cancelled,
            true,
        );

        assert!(!completion.is_complete());
        assert_eq!(completion.termination(), SolverTermination::Cancelled);
    }

    #[test]
    fn witness_unavailability_is_not_an_empty_witness() {
        let availability = NormalizedWitnessAvailability::Unavailable(
            NormalizedWitnessUnavailableReason::BackwardSolverUnsupported,
        );

        assert!(!availability.is_available());
        assert_eq!(
            availability.unavailable_reason(),
            Some(NormalizedWitnessUnavailableReason::BackwardSolverUnsupported)
        );
    }
}
