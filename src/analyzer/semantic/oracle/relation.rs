use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use super::super::ir::{
    CallSiteHandle, EvidenceCompleteness, EvidenceHandle, ProcedureHandle, ProofStatus,
};
use super::error::OracleContractError;
use super::limits::OracleLimits;
use super::model::{
    AbstractLocation, AbstractObject, AccessPathAtPoint, AliasQuery, DispatchBoundaryKind,
    OracleCallContext, StoreAtPoint, ValueAtPoint,
};

/// A materialization-local identity for one derivation relation.
///
/// These dense IDs are intentionally not persistent keys.  A future summary
/// store must translate them through artifact and source identities rather
/// than serializing the integer alone.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OracleRelationId(u32);

impl OracleRelationId {
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    pub const fn get(self) -> u32 {
        self.0
    }

    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

impl fmt::Display for OracleRelationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// The exact query/materialization scope that owns a finite relation arena.
///
/// Handles from distinct arenas never compare equal, even if their dense IDs
/// match. The structured owner additionally lets proof-producing contracts
/// reject relations from a different call, callee, procedure, or heap
/// observation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum OracleRelationOwner {
    Dispatch(CallSiteHandle),
    ProcedureValueFlow {
        procedure: ProcedureHandle,
        context: OracleCallContext,
    },
    CallBinding {
        call: CallSiteHandle,
        callee: ProcedureHandle,
        context: OracleCallContext,
    },
    PointsTo(Box<ValueAtPoint>),
    Locations(Box<AccessPathAtPoint>),
    Alias(Box<AliasQuery>),
    StrongUpdate(Box<StoreAtPoint>),
}

impl OracleRelationOwner {
    fn accepts_evidence(&self, evidence: &EvidenceHandle) -> bool {
        match self {
            Self::Dispatch(call) => evidence.procedure() == call.procedure(),
            Self::ProcedureValueFlow { procedure, .. } => evidence.procedure() == procedure,
            Self::CallBinding { call, callee, .. } => {
                evidence.procedure() == call.procedure() || evidence.procedure() == callee
            }
            Self::PointsTo(value) => evidence.procedure() == value.point().procedure(),
            Self::Locations(access) => evidence.procedure() == access.point().procedure(),
            Self::Alias(query) => evidence.procedure() == query.left().point().procedure(),
            Self::StrongUpdate(store) => evidence.procedure() == store.store().point().procedure(),
        }
    }
}

/// The language-neutral role of one relation-arena record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OracleRelationKind {
    DispatchCandidate,
    DispatchBoundary,
    ValueFlow,
    CallBinding,
    PointsTo,
    Location,
    Alias,
    Escape,
    LanguageDefined,
}

/// The structured fact identified by one relation record when its role needs
/// more precision than the query-scoped arena owner provides.
///
/// Dispatch shares one arena across every retained arm, so each record names
/// its exact candidate or boundary here. This prevents a valid call-scoped
/// relation from being reused to seal a different arm.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum OracleRelationSubject {
    DispatchCandidate(ProcedureHandle),
    DispatchBoundary(DispatchBoundaryKind),
}

/// One resolvable relation record backed by validated semantic evidence.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OracleRelationRecord {
    kind: OracleRelationKind,
    subject: Option<OracleRelationSubject>,
    evidence: Box<[EvidenceHandle]>,
}

impl OracleRelationRecord {
    pub fn new<I>(
        kind: OracleRelationKind,
        evidence: I,
        limits: OracleLimits,
    ) -> Result<Self, OracleContractError>
    where
        I: IntoIterator<Item = EvidenceHandle>,
    {
        if matches!(
            kind,
            OracleRelationKind::DispatchCandidate | OracleRelationKind::DispatchBoundary
        ) {
            return Err(OracleContractError::InvalidRelationIdentity);
        }
        Self::with_subject(kind, None, evidence, limits)
    }

    pub fn dispatch_candidate<I>(
        target: ProcedureHandle,
        evidence: I,
        limits: OracleLimits,
    ) -> Result<Self, OracleContractError>
    where
        I: IntoIterator<Item = EvidenceHandle>,
    {
        Self::with_subject(
            OracleRelationKind::DispatchCandidate,
            Some(OracleRelationSubject::DispatchCandidate(target)),
            evidence,
            limits,
        )
    }

    pub fn dispatch_boundary<I>(
        boundary: DispatchBoundaryKind,
        evidence: I,
        limits: OracleLimits,
    ) -> Result<Self, OracleContractError>
    where
        I: IntoIterator<Item = EvidenceHandle>,
    {
        Self::with_subject(
            OracleRelationKind::DispatchBoundary,
            Some(OracleRelationSubject::DispatchBoundary(boundary)),
            evidence,
            limits,
        )
    }

    fn with_subject<I>(
        kind: OracleRelationKind,
        subject: Option<OracleRelationSubject>,
        evidence: I,
        limits: OracleLimits,
    ) -> Result<Self, OracleContractError>
    where
        I: IntoIterator<Item = EvidenceHandle>,
    {
        let limit = limits.evidence_handles();
        let evidence = evidence
            .into_iter()
            .take(limit.saturating_add(1))
            .collect::<Vec<_>>();
        if evidence.len() > limit {
            return Err(OracleContractError::LimitExceeded {
                dimension: "evidence_handles",
                limit,
                attempted: evidence.len(),
            });
        }
        Ok(Self {
            kind,
            subject,
            evidence: evidence.into_boxed_slice(),
        })
    }

    pub const fn kind(&self) -> OracleRelationKind {
        self.kind
    }

    pub fn subject(&self) -> Option<&OracleRelationSubject> {
        self.subject.as_ref()
    }

    pub fn evidence(&self) -> &[EvidenceHandle] {
        &self.evidence
    }

    pub fn is_proven(&self) -> bool {
        !self.evidence.is_empty()
            && self.evidence.iter().all(|evidence| {
                let row = evidence
                    .procedure()
                    .semantics()
                    .evidence_row(evidence.id())
                    .expect("evidence handles are validated at construction");
                matches!(row.proof, ProofStatus::Proven)
            })
    }

    pub fn is_complete(&self) -> bool {
        !self.evidence.is_empty()
            && self.evidence.iter().all(|evidence| {
                let row = evidence
                    .procedure()
                    .semantics()
                    .evidence_row(evidence.id())
                    .expect("evidence handles are validated at construction");
                matches!(row.completeness, EvidenceCompleteness::Complete)
            })
    }

    pub fn is_proven_complete(&self) -> bool {
        self.is_proven() && self.is_complete()
    }

    pub(super) fn supports_quality(
        &self,
        proof: &ProofStatus,
        completeness: &EvidenceCompleteness,
    ) -> bool {
        (!matches!(proof, ProofStatus::Proven) || self.is_proven())
            && (!matches!(completeness, EvidenceCompleteness::Complete) || self.is_complete())
    }

    pub(super) fn identifies_dispatch_candidate(&self, target: &ProcedureHandle) -> bool {
        matches!(
            self.subject(),
            Some(OracleRelationSubject::DispatchCandidate(subject)) if subject == target
        )
    }

    pub(super) fn identifies_dispatch_boundary(&self, boundary: &DispatchBoundaryKind) -> bool {
        matches!(
            self.subject(),
            Some(OracleRelationSubject::DispatchBoundary(subject)) if subject == boundary
        )
    }
}

/// One finite, query-scoped arena of relation records.
#[derive(Debug)]
pub struct OracleRelationArena {
    owner: OracleRelationOwner,
    records: Box<[OracleRelationRecord]>,
}

impl OracleRelationArena {
    pub fn new(
        owner: OracleRelationOwner,
        records: Vec<OracleRelationRecord>,
        limits: OracleLimits,
    ) -> Result<Arc<Self>, OracleContractError> {
        if records.len() > limits.provenance_records() {
            return Err(OracleContractError::LimitExceeded {
                dimension: "provenance_records",
                limit: limits.provenance_records(),
                attempted: records.len(),
            });
        }
        let retained_evidence = records.iter().fold(0usize, |total, record| {
            total.saturating_add(record.evidence().len())
        });
        if retained_evidence > limits.evidence_handles() {
            return Err(OracleContractError::LimitExceeded {
                dimension: "evidence_handles",
                limit: limits.evidence_handles(),
                attempted: retained_evidence,
            });
        }
        if records
            .iter()
            .flat_map(OracleRelationRecord::evidence)
            .any(|evidence| !owner.accepts_evidence(evidence))
        {
            return Err(OracleContractError::CrossProcedure);
        }
        Ok(Arc::new(Self {
            owner,
            records: records.into_boxed_slice(),
        }))
    }

    pub fn owner(&self) -> &OracleRelationOwner {
        &self.owner
    }

    pub fn records(&self) -> &[OracleRelationRecord] {
        &self.records
    }

    pub fn handle(self: &Arc<Self>, id: OracleRelationId) -> Option<OracleRelationHandle> {
        self.records.get(id.index())?;
        Some(OracleRelationHandle {
            arena: Arc::clone(self),
            id,
        })
    }
}

/// A validated identity for one record in one exact relation arena.
#[derive(Clone)]
pub struct OracleRelationHandle {
    arena: Arc<OracleRelationArena>,
    id: OracleRelationId,
}

impl OracleRelationHandle {
    pub const fn id(&self) -> OracleRelationId {
        self.id
    }

    pub fn owner(&self) -> &OracleRelationOwner {
        self.arena.owner()
    }

    pub fn record(&self) -> &OracleRelationRecord {
        &self.arena.records[self.id.index()]
    }

    /// Query-local identity used only to total-order retained handles whose
    /// durable owner/row coordinates are otherwise equal.
    pub(crate) fn arena_identity(&self) -> *const () {
        Arc::as_ptr(&self.arena).cast()
    }

    pub(super) fn same_arena(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.arena, &other.arena)
    }
}

impl fmt::Debug for OracleRelationHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OracleRelationHandle")
            .field("owner", self.owner())
            .field("id", &self.id)
            .finish()
    }
}

impl PartialEq for OracleRelationHandle {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.same_arena(other)
    }
}

impl Eq for OracleRelationHandle {}

impl Hash for OracleRelationHandle {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Arc::as_ptr(&self.arena).hash(state);
        self.id.hash(state);
    }
}

/// Total query-local order for retained relation provenance.
///
/// Dense relation IDs are only unique within one arena, so deterministic
/// consumers must include arena identity before comparing IDs.
pub(crate) fn compare_relation_provenance(
    left: &[OracleRelationHandle],
    right: &[OracleRelationHandle],
) -> Ordering {
    left.iter()
        .zip(right)
        .find_map(|(left, right)| {
            let ordering = left
                .arena_identity()
                .cmp(&right.arena_identity())
                .then_with(|| left.id().cmp(&right.id()));
            (!ordering.is_eq()).then_some(ordering)
        })
        .unwrap_or_else(|| left.len().cmp(&right.len()))
}

pub(super) fn validate_retained_relation_arenas<'a>(
    relations: impl IntoIterator<Item = &'a OracleRelationHandle>,
    limits: OracleLimits,
) -> Result<(), OracleContractError> {
    let mut seen = std::collections::HashSet::new();
    let mut provenance_records = 0usize;
    let mut evidence_handles = 0usize;
    for relation in relations {
        let identity = Arc::as_ptr(&relation.arena);
        if !seen.insert(identity) {
            continue;
        }

        provenance_records = provenance_records.saturating_add(relation.arena.records().len());
        if provenance_records > limits.provenance_records() {
            return Err(OracleContractError::LimitExceeded {
                dimension: "provenance_records",
                limit: limits.provenance_records(),
                attempted: provenance_records,
            });
        }

        evidence_handles = relation
            .arena
            .records()
            .iter()
            .map(|record| record.evidence().len())
            .fold(evidence_handles, usize::saturating_add);
        if evidence_handles > limits.evidence_handles() {
            return Err(OracleContractError::LimitExceeded {
                dimension: "evidence_handles",
                limit: limits.evidence_handles(),
                attempted: evidence_handles,
            });
        }
    }
    Ok(())
}

pub(super) fn collect_bounded<T>(
    values: impl IntoIterator<Item = T>,
    limit: usize,
    dimension: &'static str,
) -> Result<Vec<T>, OracleContractError> {
    let values = values
        .into_iter()
        .take(limit.saturating_add(1))
        .collect::<Vec<_>>();
    if values.len() > limit {
        return Err(OracleContractError::LimitExceeded {
            dimension,
            limit,
            attempted: values.len(),
        });
    }
    Ok(values)
}

pub(super) fn collect_candidate_provenance(
    provenance: impl IntoIterator<Item = OracleRelationHandle>,
    limits: OracleLimits,
) -> Result<Box<[OracleRelationHandle]>, OracleContractError> {
    let provenance = collect_bounded(
        provenance,
        limits.provenance_records(),
        "provenance_records",
    )?;
    let mut seen = std::collections::HashSet::new();
    if provenance
        .iter()
        .any(|relation| !seen.insert(relation.clone()))
    {
        return Err(OracleContractError::InvalidRelationIdentity);
    }
    validate_retained_relation_arenas(&provenance, limits)?;
    Ok(provenance.into_boxed_slice())
}

/// Whether a finite candidate set is known to contain every answer.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CandidateCoverage {
    /// The provider proved that no candidate exists outside the returned set.
    Exhaustive,
    /// More candidates may exist, independently of the proof on each returned
    /// candidate.
    #[default]
    Open,
    /// The provider reached a finite bound and omitted candidates.
    Truncated,
}

impl CandidateCoverage {
    pub const fn is_exhaustive(self) -> bool {
        matches!(self, Self::Exhaustive)
    }

    pub const fn is_truncated(self) -> bool {
        matches!(self, Self::Truncated)
    }
}

/// One answer together with its proof quality and finite provenance.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OracleCandidate<T> {
    pub(super) value: T,
    pub(super) proof: ProofStatus,
    pub(super) completeness: EvidenceCompleteness,
    pub(super) provenance: Box<[OracleRelationHandle]>,
}

impl<T> OracleCandidate<T> {
    pub fn new<I>(
        value: T,
        proof: ProofStatus,
        completeness: EvidenceCompleteness,
        provenance: I,
        limits: OracleLimits,
    ) -> Result<Self, OracleContractError>
    where
        I: IntoIterator<Item = OracleRelationHandle>,
    {
        Ok(Self {
            value,
            proof,
            completeness,
            provenance: collect_candidate_provenance(provenance, limits)?,
        })
    }

    pub fn proven<I>(
        value: T,
        provenance: I,
        limits: OracleLimits,
    ) -> Result<Self, OracleContractError>
    where
        I: IntoIterator<Item = OracleRelationHandle>,
    {
        Self::new(
            value,
            ProofStatus::Proven,
            EvidenceCompleteness::Complete,
            provenance,
            limits,
        )
    }

    pub const fn is_proven_complete(&self) -> bool {
        matches!(self.proof, ProofStatus::Proven)
            && matches!(self.completeness, EvidenceCompleteness::Complete)
    }

    pub fn value(&self) -> &T {
        &self.value
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

    pub fn map<U>(self, mapper: impl FnOnce(T) -> U) -> OracleCandidate<U> {
        OracleCandidate {
            value: mapper(self.value),
            proof: self.proof,
            completeness: self.completeness,
            provenance: self.provenance,
        }
    }
}

/// Readable synonym used where the payload is not naturally called a
/// candidate.
pub type EvidenceBacked<T> = OracleCandidate<T>;

/// A finite set whose closure is distinct from per-candidate proof quality.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OracleSet<T> {
    pub(super) candidates: Box<[OracleCandidate<T>]>,
    pub(super) coverage: CandidateCoverage,
}

impl<T> OracleSet<T> {
    fn bounded<I>(candidates: I, mut coverage: CandidateCoverage, limit: usize) -> Self
    where
        I: IntoIterator<Item = OracleCandidate<T>>,
    {
        let mut candidates = candidates
            .into_iter()
            .take(limit.saturating_add(1))
            .collect::<Vec<_>>();
        if candidates.len() > limit {
            candidates.truncate(limit);
            coverage = CandidateCoverage::Truncated;
        }
        Self {
            candidates: candidates.into_boxed_slice(),
            coverage,
        }
    }

    pub fn candidates(&self) -> &[OracleCandidate<T>] {
        &self.candidates
    }

    pub const fn coverage(&self) -> CandidateCoverage {
        self.coverage
    }

    pub const fn is_closed(&self) -> bool {
        self.coverage.is_exhaustive()
    }
}

impl OracleSet<AbstractObject> {
    pub fn bounded_objects<I>(
        candidates: I,
        coverage: CandidateCoverage,
        limits: OracleLimits,
    ) -> Self
    where
        I: IntoIterator<Item = OracleCandidate<AbstractObject>>,
    {
        Self::bounded(candidates, coverage, limits.objects_per_value())
    }
}

impl OracleSet<AbstractLocation> {
    pub fn bounded_locations<I>(
        candidates: I,
        coverage: CandidateCoverage,
        limits: OracleLimits,
    ) -> Self
    where
        I: IntoIterator<Item = OracleCandidate<AbstractLocation>>,
    {
        Self::bounded(candidates, coverage, limits.alias_breadth())
    }
}

pub(super) fn validate_candidate_provenance<T>(
    candidates: &[OracleCandidate<T>],
    owner: &OracleRelationOwner,
    kind: OracleRelationKind,
) -> Result<(), OracleContractError> {
    let first = candidates
        .iter()
        .flat_map(OracleCandidate::provenance)
        .next();
    let mut seen = std::collections::HashSet::new();
    for candidate in candidates {
        if candidate.provenance().is_empty()
            || candidate.provenance().iter().any(|relation| {
                relation.owner() != owner
                    || relation.record().kind() != kind
                    || relation.record().evidence().is_empty()
                    || first.is_some_and(|first| !first.same_arena(relation))
                    || !seen.insert(relation.clone())
            })
        {
            return Err(OracleContractError::InvalidRelationIdentity);
        }
        if candidate.provenance().iter().any(|relation| {
            !relation
                .record()
                .supports_quality(candidate.proof(), candidate.completeness())
        }) {
            return Err(OracleContractError::InvalidRelationQuality);
        }
    }
    Ok(())
}
