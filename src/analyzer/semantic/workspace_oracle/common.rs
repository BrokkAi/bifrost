//! Shared staging and handle-validation mechanics for workspace oracles.

use crate::analyzer::semantic::{
    EvidenceCompleteness, EvidenceHandle, EvidenceId, OracleContractError, ProcedureHandle,
    ProofStatus, SemanticBudget, SemanticBudgetExceeded, SemanticProviderError, SemanticRequest,
    SemanticWork, ValueHandle, ValueId,
};

#[derive(Debug)]
pub(super) enum Interruption {
    Budget(SemanticBudgetExceeded),
    Cancelled,
}

pub(super) struct WorkStager {
    pub(super) budget: SemanticBudget,
    pub(super) work: SemanticWork,
}

impl WorkStager {
    pub(super) fn new(request: &SemanticRequest<'_>) -> Self {
        Self {
            budget: request.budget.clone(),
            work: SemanticWork::default(),
        }
    }

    pub(super) fn charge(&mut self, work: SemanticWork) -> Result<(), Interruption> {
        let reported = self.work.conservative_add(work);
        if let Err(exceeded) = self.budget.charge(work) {
            self.work = reported;
            return Err(Interruption::Budget(exceeded));
        }
        self.work = reported;
        Ok(())
    }
}

pub(super) fn internal_contract(
    context: &str,
    error: OracleContractError,
) -> SemanticProviderError {
    SemanticProviderError::internal(format!("{context}: {error}"))
}

pub(super) fn evidence_handle(
    procedure: &ProcedureHandle,
    id: EvidenceId,
) -> Result<EvidenceHandle, SemanticProviderError> {
    procedure
        .evidence_handle(id)
        .ok_or_else(|| SemanticProviderError::internal("semantic row has no evidence handle"))
}

pub(super) fn dedup_evidence(
    evidence: impl IntoIterator<Item = EvidenceHandle>,
) -> Vec<EvidenceHandle> {
    let mut result = Vec::new();
    for handle in evidence {
        if !result.contains(&handle) {
            result.push(handle);
        }
    }
    result
}

pub(super) fn evidence_quality(evidence: &[EvidenceHandle]) -> (ProofStatus, EvidenceCompleteness) {
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

pub(super) fn value_handle(
    procedure: &ProcedureHandle,
    id: ValueId,
) -> Result<ValueHandle, SemanticProviderError> {
    procedure
        .value_handle(id)
        .ok_or_else(|| SemanticProviderError::internal("semantic effect has a stale value ID"))
}
