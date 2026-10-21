//! Shared staging and handle-validation mechanics for workspace oracles.

use crate::analyzer::semantic::EvidenceCompleteness;

use crate::analyzer::semantic::EvidenceHandle;

use crate::analyzer::semantic::EvidenceId;

use crate::analyzer::semantic::OracleContractError;

use crate::analyzer::semantic::ProcedureHandle;

use crate::analyzer::semantic::ProofStatus;

use crate::analyzer::semantic::SemanticArtifactCollector;

use crate::analyzer::semantic::SemanticBudget;

use crate::analyzer::semantic::SemanticBudgetExceeded;

use crate::analyzer::semantic::SemanticCapability;

use crate::analyzer::semantic::SemanticExecutionBudget;

use crate::analyzer::semantic::SemanticProviderError;

use crate::analyzer::semantic::SemanticRequest;

use crate::analyzer::semantic::SemanticWork;

use crate::analyzer::semantic::ValueHandle;

use crate::analyzer::semantic::ValueId;

use brokk_bifrost_core::hash::HashSet;

#[derive(Debug)]
#[doc(hidden)]
pub enum Interruption {
    Budget(SemanticBudgetExceeded),
    Cancelled,
}

#[doc(hidden)]
pub struct WorkStager {
    #[doc(hidden)]
    pub budget: SemanticBudget,
    #[doc(hidden)]
    pub work: SemanticWork,
    execution: Option<SemanticExecutionBudget>,
    artifact_collector: Option<SemanticArtifactCollector>,
}

impl WorkStager {
    #[doc(hidden)]
    pub fn new(request: &SemanticRequest<'_>) -> Self {
        Self {
            budget: request.budget.clone(),
            work: SemanticWork::default(),
            execution: request.execution_budget().cloned(),
            artifact_collector: request.artifact_collector().cloned(),
        }
    }

    #[doc(hidden)]
    pub fn request<'a>(
        &'a mut self,
        cancellation: &'a brokk_bifrost_core::CancellationToken,
    ) -> SemanticRequest<'a> {
        let request = match &self.execution {
            Some(execution) => {
                SemanticRequest::with_execution_budget(&mut self.budget, cancellation, execution)
            }
            None => SemanticRequest::new(&mut self.budget, cancellation),
        };
        match &self.artifact_collector {
            Some(collector) => request.with_artifact_collector(collector),
            None => request,
        }
    }

    #[track_caller]
    #[doc(hidden)]
    pub fn admit(&mut self, work: SemanticWork) -> Result<(), Interruption> {
        let reported = self.work.conservative_add(work);
        if let Err(exceeded) = self.budget.admit(work) {
            self.work = reported;
            return Err(Interruption::Budget(exceeded));
        }
        self.work = reported;
        Ok(())
    }
    #[track_caller]
    #[doc(hidden)]
    pub fn charge_work(&mut self, work: SemanticWork) {
        let reported = self.work.conservative_add(work);
        self.budget.charge_work(work);
        self.work = reported;
    }
}

#[doc(hidden)]
pub fn internal_contract(context: &str, error: OracleContractError) -> SemanticProviderError {
    SemanticProviderError::internal(format!("{context}: {error}"))
}

#[doc(hidden)]
pub fn value_flow_core_capabilities_are_open(procedure: &ProcedureHandle) -> bool {
    let capabilities = procedure.artifact().capabilities();
    [
        SemanticCapability::Values,
        SemanticCapability::Assignments,
        SemanticCapability::Allocations,
        SemanticCapability::LocalFlow,
        SemanticCapability::ParameterFlow,
        SemanticCapability::ReceiverFlow,
        SemanticCapability::ReturnFlow,
    ]
    .into_iter()
    .any(|capability| !capabilities.is_available(capability))
}

#[doc(hidden)]
pub fn evidence_handle(
    procedure: &ProcedureHandle,
    id: EvidenceId,
) -> Result<EvidenceHandle, SemanticProviderError> {
    procedure
        .evidence_handle(id)
        .ok_or_else(|| SemanticProviderError::internal("semantic row has no evidence handle"))
}

#[doc(hidden)]
pub fn dedup_evidence(evidence: impl IntoIterator<Item = EvidenceHandle>) -> Vec<EvidenceHandle> {
    // Handles compare by artifact instance, procedure, and evidence row, so a
    // request-local set gives the same exact members as the former linear
    // membership test without rescanning the retained prefix.
    let mut seen: HashSet<EvidenceHandle> = HashSet::default();
    let mut result = Vec::new();
    for handle in evidence {
        if seen.insert(handle.clone()) {
            result.push(handle);
        }
    }
    result
}

#[doc(hidden)]
pub fn evidence_quality(evidence: &[EvidenceHandle]) -> (ProofStatus, EvidenceCompleteness) {
    let proof = evidence
        .iter()
        .find_map(|handle| {
            let row = handle
                .procedure()
                .semantics()
                .evidence_row(handle.id())
                .expect("evidence handles are validated at construction");
            (!matches!(row.proof, ProofStatus::Proven)).then(|| row.proof.clone())
        })
        .unwrap_or(ProofStatus::Proven);
    let completeness = evidence
        .iter()
        .find_map(|handle| {
            let row = handle
                .procedure()
                .semantics()
                .evidence_row(handle.id())
                .expect("evidence handles are validated at construction");
            (!matches!(row.completeness, EvidenceCompleteness::Complete))
                .then(|| row.completeness.clone())
        })
        .unwrap_or(EvidenceCompleteness::Complete);
    (proof, completeness)
}

#[doc(hidden)]
pub fn value_handle(
    procedure: &ProcedureHandle,
    id: ValueId,
) -> Result<ValueHandle, SemanticProviderError> {
    procedure
        .value_handle(id)
        .ok_or_else(|| SemanticProviderError::internal("semantic effect has a stale value ID"))
}

#[cfg(test)]
mod tests {

    use crate::analyzer::semantic::workspace_oracle::common::*;

    use brokk_bifrost_core::cancellation::CancellationToken;

    #[test]
    fn work_stager_propagates_the_complete_artifact_collector() {
        let collector = SemanticArtifactCollector::new();
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let request =
            SemanticRequest::new(&mut budget, &cancellation).with_artifact_collector(&collector);
        let mut staged = WorkStager::new(&request);
        let nested = staged.request(&cancellation);
        let propagated = nested
            .artifact_collector()
            .expect("staged workspace-oracle requests retain the collector");

        assert!(propagated.shares_state(&collector));
    }
}
