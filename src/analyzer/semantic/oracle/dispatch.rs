use super::super::ids::SemanticLocator;
use super::super::ir::{CallSiteHandle, EvidenceCompleteness, ProcedureHandle, ProofStatus};
use super::error::OracleContractError;
use super::limits::OracleLimits;
use super::model::DispatchBoundaryKind;
use super::relation::{
    CandidateCoverage, OracleRelationHandle, OracleRelationKind, OracleRelationOwner,
    collect_candidate_provenance, validate_retained_relation_arenas,
};

/// One materialized workspace target for an exact semantic call site.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DispatchCandidate {
    pub(crate) target: ProcedureHandle,
    pub(crate) proof: ProofStatus,
    pub(crate) completeness: EvidenceCompleteness,
    pub(crate) provenance: Box<[OracleRelationHandle]>,
    sealed: bool,
}

impl DispatchCandidate {
    /// Create a draft that becomes a candidate-specific query token only
    /// after validation by [`DispatchResult::new`].
    pub fn new<I>(
        target: ProcedureHandle,
        proof: ProofStatus,
        completeness: EvidenceCompleteness,
        provenance: I,
        limits: OracleLimits,
    ) -> Result<Self, OracleContractError>
    where
        I: IntoIterator<Item = OracleRelationHandle>,
    {
        Ok(Self {
            target,
            proof,
            completeness,
            provenance: collect_candidate_provenance(provenance, limits)?,
            sealed: false,
        })
    }

    pub fn target(&self) -> &ProcedureHandle {
        &self.target
    }

    pub fn proof(&self) -> &ProofStatus {
        &self.proof
    }

    pub fn completeness(&self) -> &EvidenceCompleteness {
        &self.completeness
    }

    pub fn provenance(&self) -> &[OracleRelationHandle] {
        &self.provenance
    }

    fn seal(&mut self) {
        self.sealed = true;
    }

    const fn is_sealed(&self) -> bool {
        self.sealed
    }

    pub(super) fn validate_for_call(
        &self,
        call: &CallSiteHandle,
    ) -> Result<(), OracleContractError> {
        if !self.is_sealed() || self.provenance.is_empty() {
            return Err(OracleContractError::InvalidRelationIdentity);
        }
        let owner = OracleRelationOwner::Dispatch(call.clone());
        let first = self.provenance.first();
        let mut seen = std::collections::HashSet::new();
        if self.provenance.iter().any(|relation| {
            relation.owner() != &owner
                || relation.record().kind() != OracleRelationKind::DispatchCandidate
                || !relation
                    .record()
                    .identifies_dispatch_candidate(&self.target)
                || relation.record().evidence().is_empty()
                || first.is_some_and(|first| !first.same_arena(relation))
                || !seen.insert(relation.clone())
        }) {
            return Err(OracleContractError::InvalidRelationIdentity);
        }
        if self.provenance.iter().any(|relation| {
            !relation
                .record()
                .supports_quality(&self.proof, &self.completeness)
        }) {
            return Err(OracleContractError::InvalidRelationQuality);
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DispatchBoundary {
    pub kind: DispatchBoundaryKind,
    pub proof: ProofStatus,
    pub completeness: EvidenceCompleteness,
    pub provenance: Box<[OracleRelationHandle]>,
}

impl DispatchBoundary {
    pub(crate) fn target_locator(&self) -> Option<&SemanticLocator> {
        match &self.kind {
            DispatchBoundaryKind::External(Some(target))
            | DispatchBoundaryKind::Unmaterialized(target)
            | DispatchBoundaryKind::Deferred { target, .. } => Some(target),
            DispatchBoundaryKind::External(None)
            | DispatchBoundaryKind::Unresolved
            | DispatchBoundaryKind::Truncated => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchResult {
    candidates: Box<[DispatchCandidate]>,
    boundaries: Box<[DispatchBoundary]>,
    coverage: CandidateCoverage,
}

impl DispatchResult {
    /// Publish a dispatch answer only after every retained arm has resolvable,
    /// call-scoped provenance from one finite relation arena.
    pub fn new(
        call: &CallSiteHandle,
        candidates: Vec<DispatchCandidate>,
        boundaries: Vec<DispatchBoundary>,
        coverage: CandidateCoverage,
        limits: OracleLimits,
    ) -> Result<Self, OracleContractError> {
        let mut unique_targets = std::collections::HashSet::new();
        if candidates
            .iter()
            .any(|candidate| !unique_targets.insert(candidate.target.clone()))
        {
            return Err(OracleContractError::DuplicateDispatchTarget);
        }
        if candidates.len() > limits.dispatch_targets() {
            return Err(OracleContractError::LimitExceeded {
                dimension: "dispatch_targets",
                limit: limits.dispatch_targets(),
                attempted: candidates.len(),
            });
        }
        let mut result = Self {
            candidates: candidates.into_boxed_slice(),
            boundaries: boundaries.into_boxed_slice(),
            coverage,
        };
        let has_unresolved = result
            .boundaries
            .iter()
            .any(|boundary| matches!(boundary.kind, DispatchBoundaryKind::Unresolved));
        let has_truncated = result
            .boundaries
            .iter()
            .any(|boundary| matches!(boundary.kind, DispatchBoundaryKind::Truncated));
        if (has_unresolved && coverage == CandidateCoverage::Exhaustive)
            || (has_truncated && coverage != CandidateCoverage::Truncated)
        {
            return Err(OracleContractError::InconsistentCoverage);
        }
        result.validate_provenance_for_call(call, false)?;
        validate_retained_relation_arenas(
            result
                .candidates
                .iter()
                .flat_map(|candidate| candidate.provenance.iter())
                .chain(
                    result
                        .boundaries
                        .iter()
                        .flat_map(|boundary| boundary.provenance.iter()),
                ),
            limits,
        )?;
        for candidate in &mut result.candidates {
            candidate.seal();
        }
        Ok(result)
    }

    pub fn candidates(&self) -> &[DispatchCandidate] {
        &self.candidates
    }

    pub fn boundaries(&self) -> &[DispatchBoundary] {
        &self.boundaries
    }

    pub const fn coverage(&self) -> CandidateCoverage {
        self.coverage
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        Box<[DispatchCandidate]>,
        Box<[DispatchBoundary]>,
        CandidateCoverage,
    ) {
        (self.candidates, self.boundaries, self.coverage)
    }

    pub fn validate_for_call(&self, call: &CallSiteHandle) -> Result<(), OracleContractError> {
        self.validate_provenance_for_call(call, true)
    }

    fn first_provenance(&self) -> Option<&OracleRelationHandle> {
        self.candidates
            .iter()
            .flat_map(|candidate| candidate.provenance.iter())
            .chain(
                self.boundaries
                    .iter()
                    .flat_map(|boundary| boundary.provenance.iter()),
            )
            .next()
    }

    fn validate_provenance_for_call(
        &self,
        call: &CallSiteHandle,
        require_sealed_candidates: bool,
    ) -> Result<(), OracleContractError> {
        let owner = OracleRelationOwner::Dispatch(call.clone());
        let first = self.first_provenance();
        if require_sealed_candidates
            && self
                .candidates
                .iter()
                .any(|candidate| !candidate.is_sealed())
        {
            return Err(OracleContractError::InvalidRelationIdentity);
        }
        let mut seen = std::collections::HashSet::new();
        for (relations, kind, proof, completeness) in self
            .candidates
            .iter()
            .map(|candidate| {
                (
                    candidate.provenance.as_ref(),
                    OracleRelationKind::DispatchCandidate,
                    &candidate.proof,
                    &candidate.completeness,
                )
            })
            .chain(self.boundaries.iter().map(|boundary| {
                (
                    boundary.provenance.as_ref(),
                    OracleRelationKind::DispatchBoundary,
                    &boundary.proof,
                    &boundary.completeness,
                )
            }))
        {
            if relations.is_empty()
                || relations.iter().any(|relation| {
                    relation.owner() != &owner
                        || relation.record().kind() != kind
                        || relation.record().evidence().is_empty()
                        || first.is_some_and(|first| !first.same_arena(relation))
                        || !seen.insert(relation.clone())
                })
            {
                return Err(OracleContractError::InvalidRelationIdentity);
            }
            if relations
                .iter()
                .any(|relation| !relation.record().supports_quality(proof, completeness))
            {
                return Err(OracleContractError::InvalidRelationQuality);
            }
        }
        if self.candidates.iter().any(|candidate| {
            candidate.provenance.iter().any(|relation| {
                !relation
                    .record()
                    .identifies_dispatch_candidate(&candidate.target)
            })
        }) {
            return Err(OracleContractError::InvalidRelationIdentity);
        }
        if self.boundaries.iter().any(|boundary| {
            boundary.provenance.iter().any(|relation| {
                !relation
                    .record()
                    .identifies_dispatch_boundary(&boundary.kind)
            })
        }) {
            return Err(OracleContractError::InvalidRelationIdentity);
        }
        Ok(())
    }
}
