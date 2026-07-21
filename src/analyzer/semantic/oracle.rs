//! Language-neutral value, dispatch, and heap-oracle contracts.
//!
//! Oracle answers deliberately separate three independent questions: whether
//! an individual candidate is proven, whether the returned candidate set is
//! closed, and whether an abstract object denotes one runtime object.  A
//! proven candidate in an open set is not a must-answer, and an allocation
//! site is not automatically a singleton object.

use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use super::ids::{MemoryLocationId, SemanticLocator, SemanticRole};
use super::ir::{
    AllocationHandle, ArgumentDomain, CallArgumentExpansion, CallSiteHandle, EvidenceCompleteness,
    EvidenceHandle, FormalMultiplicity, MemoryLocationHandle, MemoryLocationKind, ProcedureHandle,
    ProgramPointHandle, ProofStatus, SemanticArtifact, SemanticEffect, SemanticValueKind,
    ValueHandle,
};
use super::provider::{SemanticOutcome, SemanticProviderError, SemanticRequest};

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

    fn supports_quality(&self, proof: &ProofStatus, completeness: &EvidenceCompleteness) -> bool {
        (!matches!(proof, ProofStatus::Proven) || self.is_proven())
            && (!matches!(completeness, EvidenceCompleteness::Complete) || self.is_complete())
    }

    fn identifies_dispatch_candidate(&self, target: &ProcedureHandle) -> bool {
        matches!(
            self.subject(),
            Some(OracleRelationSubject::DispatchCandidate(subject)) if subject == target
        )
    }

    fn identifies_dispatch_boundary(&self, boundary: &DispatchBoundaryKind) -> bool {
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

    fn same_arena(&self, other: &Self) -> bool {
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

fn validate_retained_relation_arenas<'a>(
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

fn collect_bounded<T>(
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

fn collect_candidate_provenance(
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
    value: T,
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
    provenance: Box<[OracleRelationHandle]>,
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
    candidates: Box<[OracleCandidate<T>]>,
    coverage: CandidateCoverage,
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

/// How many concrete runtime objects one abstract object may denote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectCardinality {
    /// The abstraction is proven to denote exactly one runtime object in this
    /// query context.
    Singleton,
    /// The abstraction intentionally summarizes multiple runtime objects.
    Summary,
    /// The provider cannot establish either property.
    Unknown,
}

/// Public values accepted by [`OracleLimits::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OracleLimitValues {
    pub dispatch_targets: usize,
    pub objects_per_value: usize,
    pub interned_roots: usize,
    pub interned_selectors: usize,
    pub interned_paths: usize,
    pub access_path_length: usize,
    pub alias_breadth: usize,
    pub call_context_depth: usize,
    pub summary_depth: usize,
    pub call_binding_entries: usize,
    pub provenance_records: usize,
    pub evidence_handles: usize,
}

impl OracleLimitValues {
    pub const fn uniform(value: usize) -> Self {
        Self {
            dispatch_targets: value,
            objects_per_value: value,
            interned_roots: value,
            interned_selectors: value,
            interned_paths: value,
            access_path_length: value,
            alias_breadth: value,
            call_context_depth: value,
            summary_depth: value,
            call_binding_entries: value,
            provenance_records: value,
            evidence_handles: value,
        }
    }
}

/// One invalid oracle-limit dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InvalidOracleLimits {
    dimension: &'static str,
}

impl InvalidOracleLimits {
    pub const fn dimension(self) -> &'static str {
        self.dimension
    }
}

impl fmt::Display for InvalidOracleLimits {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "oracle limit `{}` must be positive",
            self.dimension
        )
    }
}

impl std::error::Error for InvalidOracleLimits {}

/// Positive finite bounds shared by dispatch, value-flow, and heap queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OracleLimits {
    values: OracleLimitValues,
}

impl OracleLimits {
    pub fn new(values: OracleLimitValues) -> Result<Self, InvalidOracleLimits> {
        let dimensions = [
            ("dispatch_targets", values.dispatch_targets),
            ("objects_per_value", values.objects_per_value),
            ("interned_roots", values.interned_roots),
            ("interned_selectors", values.interned_selectors),
            ("interned_paths", values.interned_paths),
            ("access_path_length", values.access_path_length),
            ("alias_breadth", values.alias_breadth),
            ("call_context_depth", values.call_context_depth),
            ("summary_depth", values.summary_depth),
            ("call_binding_entries", values.call_binding_entries),
            ("provenance_records", values.provenance_records),
            ("evidence_handles", values.evidence_handles),
        ];
        for (dimension, value) in dimensions {
            if value == 0 {
                return Err(InvalidOracleLimits { dimension });
            }
        }
        Ok(Self { values })
    }

    pub fn uniform(value: usize) -> Result<Self, InvalidOracleLimits> {
        Self::new(OracleLimitValues::uniform(value))
    }

    pub const fn values(self) -> OracleLimitValues {
        self.values
    }

    pub const fn dispatch_targets(self) -> usize {
        self.values.dispatch_targets
    }

    pub const fn objects_per_value(self) -> usize {
        self.values.objects_per_value
    }

    pub const fn interned_roots(self) -> usize {
        self.values.interned_roots
    }

    pub const fn interned_selectors(self) -> usize {
        self.values.interned_selectors
    }

    pub const fn interned_paths(self) -> usize {
        self.values.interned_paths
    }

    pub const fn access_path_length(self) -> usize {
        self.values.access_path_length
    }

    pub const fn alias_breadth(self) -> usize {
        self.values.alias_breadth
    }

    pub const fn call_context_depth(self) -> usize {
        self.values.call_context_depth
    }

    pub const fn summary_depth(self) -> usize {
        self.values.summary_depth
    }

    pub const fn call_binding_entries(self) -> usize {
        self.values.call_binding_entries
    }

    pub const fn provenance_records(self) -> usize {
        self.values.provenance_records
    }

    pub const fn evidence_handles(self) -> usize {
        self.values.evidence_handles
    }
}

impl Default for OracleLimits {
    fn default() -> Self {
        Self::new(OracleLimitValues {
            dispatch_targets: 1_024,
            objects_per_value: 256,
            interned_roots: 100_000,
            interned_selectors: 250_000,
            interned_paths: 250_000,
            access_path_length: 8,
            alias_breadth: 1_024,
            call_context_depth: 2,
            summary_depth: 8,
            call_binding_entries: 4_096,
            provenance_records: 4_096,
            evidence_handles: 4_096,
        })
        .expect("default oracle limits are positive")
    }
}

/// A recent-call suffix retained by a bounded oracle query.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OracleCallContext {
    calls: Box<[CallSiteHandle]>,
    truncated: bool,
}

impl OracleCallContext {
    pub fn bounded(mut calls: Vec<CallSiteHandle>, limits: OracleLimits) -> Self {
        let retained = limits.call_context_depth();
        let truncated = calls.len() > retained;
        if truncated {
            calls.drain(..calls.len() - retained);
        }
        Self {
            calls: calls.into_boxed_slice(),
            truncated,
        }
    }

    pub fn empty() -> Self {
        Self {
            calls: Box::new([]),
            truncated: false,
        }
    }

    pub fn calls(&self) -> &[CallSiteHandle] {
        &self.calls
    }

    pub const fn was_truncated(&self) -> bool {
        self.truncated
    }
}

impl Default for OracleCallContext {
    fn default() -> Self {
        Self::empty()
    }
}

/// Whether an observation sees the state immediately before or after all
/// semantic effects attached to one program point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObservationPhase {
    BeforeEffects,
    AfterEffects,
}

/// Stable symbolic procedure-boundary slots used by summaries and call
/// bindings.  They are deliberately separate from a procedure's temporary
/// value IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProcedurePortKind {
    Receiver,
    Parameter { ordinal: u32 },
    NormalReturn,
    ExceptionalReturn,
    Capture { slot: MemoryLocationId },
}

/// A procedure-scoped boundary slot.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProcedurePortHandle {
    procedure: ProcedureHandle,
    kind: ProcedurePortKind,
}

impl ProcedurePortHandle {
    pub fn new(
        procedure: ProcedureHandle,
        kind: ProcedurePortKind,
    ) -> Result<Self, OracleContractError> {
        match kind {
            ProcedurePortKind::Receiver
                if !procedure
                    .semantics()
                    .values()
                    .iter()
                    .any(|value| value.kind == SemanticValueKind::Receiver) =>
            {
                return Err(OracleContractError::InvalidReceiverPort);
            }
            ProcedurePortKind::Parameter { ordinal }
                if !procedure.semantics().values().iter().any(|value| {
                    matches!(
                        value.kind,
                        SemanticValueKind::Parameter {
                            ordinal: actual,
                            ..
                        } if actual == ordinal
                    )
                }) =>
            {
                return Err(OracleContractError::InvalidParameterOrdinal { ordinal });
            }
            ProcedurePortKind::Capture { slot } => {
                let Some(location) = procedure.semantics().memory_location(slot) else {
                    return Err(OracleContractError::InvalidCaptureSlot { slot });
                };
                if !matches!(location.kind, MemoryLocationKind::Capture { .. }) {
                    return Err(OracleContractError::InvalidCaptureSlot { slot });
                }
            }
            ProcedurePortKind::Receiver
            | ProcedurePortKind::Parameter { .. }
            | ProcedurePortKind::NormalReturn
            | ProcedurePortKind::ExceptionalReturn => {}
        }
        Ok(Self { procedure, kind })
    }

    pub fn receiver(procedure: ProcedureHandle) -> Result<Self, OracleContractError> {
        Self::new(procedure, ProcedurePortKind::Receiver)
    }

    pub fn parameter(
        procedure: ProcedureHandle,
        ordinal: u32,
    ) -> Result<Self, OracleContractError> {
        Self::new(procedure, ProcedurePortKind::Parameter { ordinal })
    }

    pub fn normal_return(procedure: ProcedureHandle) -> Self {
        Self {
            procedure,
            kind: ProcedurePortKind::NormalReturn,
        }
    }

    pub fn exceptional_return(procedure: ProcedureHandle) -> Self {
        Self {
            procedure,
            kind: ProcedurePortKind::ExceptionalReturn,
        }
    }

    pub fn capture(
        procedure: ProcedureHandle,
        slot: MemoryLocationId,
    ) -> Result<Self, OracleContractError> {
        Self::new(procedure, ProcedurePortKind::Capture { slot })
    }

    pub fn procedure(&self) -> &ProcedureHandle {
        &self.procedure
    }

    pub const fn kind(&self) -> ProcedurePortKind {
        self.kind
    }

    pub fn formal_multiplicity(&self) -> Option<&FormalMultiplicity> {
        let ProcedurePortKind::Parameter { ordinal } = self.kind else {
            return None;
        };
        self.procedure
            .semantics()
            .values()
            .iter()
            .find_map(|value| match &value.kind {
                SemanticValueKind::Parameter {
                    ordinal: actual,
                    multiplicity,
                } if *actual == ordinal => Some(multiplicity),
                _ => None,
            })
    }
}

/// A source-facing locator scoped to one exact live semantic artifact.
///
/// The locator remains useful for remapping and display, while `scope`
/// prevents a stale or foreign generation from entering point-sensitive
/// oracle answers as if the locator alone were a live identity.
#[derive(Clone)]
pub struct ScopedSemanticLocator {
    scope: Arc<SemanticArtifact>,
    locator: SemanticLocator,
}

impl ScopedSemanticLocator {
    pub fn new(
        scope: Arc<SemanticArtifact>,
        locator: SemanticLocator,
    ) -> Result<Self, OracleContractError> {
        if scope.key().mount() != locator.mount() {
            return Err(OracleContractError::InvalidSemanticScope);
        }
        Ok(Self { scope, locator })
    }

    pub fn scope(&self) -> &Arc<SemanticArtifact> {
        &self.scope
    }

    pub fn locator(&self) -> &SemanticLocator {
        &self.locator
    }

    fn validate_at(&self, procedure: &ProcedureHandle) -> Result<(), OracleContractError> {
        if Arc::ptr_eq(&self.scope, procedure.artifact()) {
            Ok(())
        } else {
            Err(OracleContractError::InvalidSemanticScope)
        }
    }
}

impl fmt::Debug for ScopedSemanticLocator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScopedSemanticLocator")
            .field("artifact", self.scope.key())
            .field("locator", &self.locator)
            .finish()
    }
}

impl PartialEq for ScopedSemanticLocator {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.scope, &other.scope) && self.locator == other.locator
    }
}

impl Eq for ScopedSemanticLocator {}

impl Hash for ScopedSemanticLocator {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Arc::as_ptr(&self.scope).hash(state);
        self.locator.hash(state);
    }
}

/// A value observed at one precise point and bounded call context.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ValueAtPoint {
    value: ValueHandle,
    point: ProgramPointHandle,
    phase: ObservationPhase,
    context: OracleCallContext,
}

impl ValueAtPoint {
    pub fn new(
        value: ValueHandle,
        point: ProgramPointHandle,
        phase: ObservationPhase,
        context: OracleCallContext,
    ) -> Result<Self, OracleContractError> {
        require_same_procedure(value.procedure(), point.procedure())?;
        Ok(Self {
            value,
            point,
            phase,
            context,
        })
    }

    pub fn value(&self) -> &ValueHandle {
        &self.value
    }

    pub fn point(&self) -> &ProgramPointHandle {
        &self.point
    }

    pub const fn phase(&self) -> ObservationPhase {
        self.phase
    }

    pub fn context(&self) -> &OracleCallContext {
        &self.context
    }
}

/// A symbolic access-path root.  Procedure-owned variants remain scoped by
/// handles; locators are durable declaration identities, not source text.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AccessPathRoot {
    Value(ValueHandle),
    ProcedurePort(ProcedurePortHandle),
    Allocation(AllocationHandle),
    Static(ScopedSemanticLocator),
    LexicalCell(MemoryLocationHandle),
    CaptureSlot(ProcedurePortHandle),
    TypeSummary(ScopedSemanticLocator),
    ModuleObject(ScopedSemanticLocator),
    External(ScopedSemanticLocator),
}

impl AccessPathRoot {
    fn scoped_procedure(&self) -> Option<&ProcedureHandle> {
        match self {
            Self::Value(value) => Some(value.procedure()),
            Self::ProcedurePort(port) | Self::CaptureSlot(port) => Some(port.procedure()),
            Self::Allocation(allocation) => Some(allocation.procedure()),
            Self::LexicalCell(location) => Some(location.procedure()),
            Self::Static(_) | Self::TypeSummary(_) | Self::ModuleObject(_) | Self::External(_) => {
                None
            }
        }
    }

    fn validate_shape(&self) -> Result<(), OracleContractError> {
        match self {
            Self::ProcedurePort(port)
                if matches!(port.kind(), ProcedurePortKind::Capture { .. }) =>
            {
                return Err(OracleContractError::InvalidAccessRoot(
                    "capture ports must use the canonical capture-slot root",
                ));
            }
            Self::LexicalCell(location) => {
                let row = location
                    .procedure()
                    .semantics()
                    .memory_location(location.id())
                    .expect("memory-location handles are validated at construction");
                if !matches!(row.kind, MemoryLocationKind::LexicalCell { .. }) {
                    return Err(OracleContractError::InvalidAccessRoot(
                        "lexical-cell root does not name a lexical-cell location",
                    ));
                }
            }
            Self::CaptureSlot(port)
                if !matches!(port.kind(), ProcedurePortKind::Capture { .. }) =>
            {
                return Err(OracleContractError::InvalidAccessRoot(
                    "capture-slot root does not name a capture port",
                ));
            }
            Self::Static(locator) if locator.locator().role() != SemanticRole::MemoryLocation => {
                return Err(OracleContractError::InvalidAccessRoot(
                    "static roots must name a memory-location locator",
                ));
            }
            Self::Value(_)
            | Self::ProcedurePort(_)
            | Self::Allocation(_)
            | Self::Static(_)
            | Self::CaptureSlot(_)
            | Self::TypeSummary(_)
            | Self::ModuleObject(_)
            | Self::External(_) => {}
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IndexSelector {
    /// An exact index value scoped to the procedure that computes it.
    Exact(ValueHandle),
    /// A structured wildcard used when a precise index cannot be established.
    Any,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AccessSelector {
    Field(ScopedSemanticLocator),
    Index(IndexSelector),
}

/// Whether the retained selectors describe the entire path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccessPathTail {
    Exact,
    /// One or more unknown or omitted selectors remain.
    Summary,
}

/// A bounded root-plus-selector access path.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AccessPath {
    root: AccessPathRoot,
    selectors: Box<[AccessSelector]>,
    tail: AccessPathTail,
}

impl AccessPath {
    /// Retain at most the configured number of selectors.  Truncation always
    /// changes the tail to `Summary`; it never turns a longer path into a
    /// shorter exact path.
    pub fn bounded(
        root: AccessPathRoot,
        mut selectors: Vec<AccessSelector>,
        mut tail: AccessPathTail,
        limits: OracleLimits,
    ) -> Result<Self, OracleContractError> {
        root.validate_shape()?;
        let root_procedure = root.scoped_procedure();
        for selector in &selectors {
            if let AccessSelector::Index(IndexSelector::Exact(index)) = selector
                && let Some(procedure) = root_procedure
            {
                require_same_procedure(index.procedure(), procedure)?;
            }
        }
        if selectors
            .iter()
            .any(|selector| matches!(selector, AccessSelector::Index(IndexSelector::Any)))
        {
            tail = AccessPathTail::Summary;
        }
        if selectors.iter().any(|selector| {
            matches!(
                selector,
                AccessSelector::Field(field)
                    if field.locator().role() != SemanticRole::MemoryLocation
            )
        }) {
            return Err(OracleContractError::InvalidAccessSelector(
                "field selectors must name a memory-location locator",
            ));
        }
        if selectors.len() > limits.access_path_length() {
            selectors.truncate(limits.access_path_length());
            tail = AccessPathTail::Summary;
        }
        Ok(Self {
            root,
            selectors: selectors.into_boxed_slice(),
            tail,
        })
    }

    pub fn exact(
        root: AccessPathRoot,
        selectors: Vec<AccessSelector>,
        limits: OracleLimits,
    ) -> Result<Self, OracleContractError> {
        Self::bounded(root, selectors, AccessPathTail::Exact, limits)
    }

    pub fn root(&self) -> &AccessPathRoot {
        &self.root
    }

    pub fn selectors(&self) -> &[AccessSelector] {
        &self.selectors
    }

    pub const fn tail(&self) -> AccessPathTail {
        self.tail
    }

    pub fn is_exact(&self) -> bool {
        matches!(self.tail, AccessPathTail::Exact)
            && !self
                .selectors
                .iter()
                .any(|selector| matches!(selector, AccessSelector::Index(IndexSelector::Any)))
    }

    fn validate_at(&self, procedure: &ProcedureHandle) -> Result<(), OracleContractError> {
        if let Some(root_procedure) = self.root.scoped_procedure() {
            require_same_procedure(root_procedure, procedure)?;
        }
        for selector in &self.selectors {
            match selector {
                AccessSelector::Field(field) => field.validate_at(procedure)?,
                AccessSelector::Index(IndexSelector::Exact(index)) => {
                    require_same_procedure(index.procedure(), procedure)?;
                }
                AccessSelector::Index(IndexSelector::Any) => {}
            }
        }
        match &self.root {
            AccessPathRoot::Static(locator)
            | AccessPathRoot::TypeSummary(locator)
            | AccessPathRoot::ModuleObject(locator)
            | AccessPathRoot::External(locator) => locator.validate_at(procedure)?,
            AccessPathRoot::Value(_)
            | AccessPathRoot::ProcedurePort(_)
            | AccessPathRoot::Allocation(_)
            | AccessPathRoot::LexicalCell(_)
            | AccessPathRoot::CaptureSlot(_) => {}
        }
        Ok(())
    }
}

/// An access path interpreted at one precise point and call context.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AccessPathAtPoint {
    path: AccessPath,
    point: ProgramPointHandle,
    phase: ObservationPhase,
    context: OracleCallContext,
}

impl AccessPathAtPoint {
    pub fn new(
        path: AccessPath,
        point: ProgramPointHandle,
        phase: ObservationPhase,
        context: OracleCallContext,
    ) -> Result<Self, OracleContractError> {
        path.validate_at(point.procedure())?;
        Ok(Self {
            path,
            point,
            phase,
            context,
        })
    }

    pub fn path(&self) -> &AccessPath {
        &self.path
    }

    pub fn point(&self) -> &ProgramPointHandle {
        &self.point
    }

    pub const fn phase(&self) -> ObservationPhase {
        self.phase
    }

    pub fn context(&self) -> &OracleCallContext {
        &self.context
    }
}

/// The identity component of one abstract object.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AbstractObjectIdentity {
    Value(ValueHandle),
    Allocation(AllocationHandle),
    ProcedurePort(ProcedurePortHandle),
    Static(ScopedSemanticLocator),
    LexicalCell(MemoryLocationHandle),
    CaptureSlot(ProcedurePortHandle),
    TypeSummary(ScopedSemanticLocator),
    ModuleObject(ScopedSemanticLocator),
    External(ScopedSemanticLocator),
}

impl AbstractObjectIdentity {
    fn validate_shape(&self) -> Result<(), OracleContractError> {
        match self {
            Self::ProcedurePort(port)
                if matches!(port.kind(), ProcedurePortKind::Capture { .. }) =>
            {
                Err(OracleContractError::InvalidAccessRoot(
                    "capture ports must use the canonical capture-slot object identity",
                ))
            }
            Self::LexicalCell(location) => {
                let row = location
                    .procedure()
                    .semantics()
                    .memory_location(location.id())
                    .expect("memory-location handles are validated at construction");
                if matches!(row.kind, MemoryLocationKind::LexicalCell { .. }) {
                    Ok(())
                } else {
                    Err(OracleContractError::InvalidAccessRoot(
                        "lexical-cell object identity does not name a lexical-cell location",
                    ))
                }
            }
            Self::CaptureSlot(port)
                if !matches!(port.kind(), ProcedurePortKind::Capture { .. }) =>
            {
                Err(OracleContractError::InvalidAccessRoot(
                    "capture-slot object identity does not name a capture port",
                ))
            }
            Self::Static(locator) if locator.locator().role() != SemanticRole::MemoryLocation => {
                Err(OracleContractError::InvalidAccessRoot(
                    "static object identities must name a memory-location locator",
                ))
            }
            Self::Value(_)
            | Self::Allocation(_)
            | Self::ProcedurePort(_)
            | Self::Static(_)
            | Self::CaptureSlot(_)
            | Self::TypeSummary(_)
            | Self::ModuleObject(_)
            | Self::External(_) => Ok(()),
        }
    }

    fn validate_at(&self, procedure: &ProcedureHandle) -> Result<(), OracleContractError> {
        match self {
            Self::Value(value) => require_same_procedure(value.procedure(), procedure),
            Self::Allocation(allocation) => {
                require_same_procedure(allocation.procedure(), procedure)
            }
            Self::ProcedurePort(port) | Self::CaptureSlot(port) => {
                require_same_procedure(port.procedure(), procedure)
            }
            Self::LexicalCell(location) => require_same_procedure(location.procedure(), procedure),
            Self::Static(locator)
            | Self::TypeSummary(locator)
            | Self::ModuleObject(locator)
            | Self::External(locator) => locator.validate_at(procedure),
        }
    }

    fn matches_root(&self, root: &AccessPathRoot) -> bool {
        matches!(
            (self, root),
            (Self::Value(left), AccessPathRoot::Value(right)) if left == right
        ) || matches!(
            (self, root),
            (Self::Allocation(left), AccessPathRoot::Allocation(right)) if left == right
        ) || matches!(
            (self, root),
            (Self::ProcedurePort(left), AccessPathRoot::ProcedurePort(right)) if left == right
        ) || matches!(
            (self, root),
            (Self::Static(left), AccessPathRoot::Static(right)) if left == right
        ) || matches!(
            (self, root),
            (Self::LexicalCell(left), AccessPathRoot::LexicalCell(right)) if left == right
        ) || matches!(
            (self, root),
            (Self::CaptureSlot(left), AccessPathRoot::CaptureSlot(right)) if left == right
        ) || matches!(
            (self, root),
            (Self::TypeSummary(left), AccessPathRoot::TypeSummary(right)) if left == right
        ) || matches!(
            (self, root),
            (Self::ModuleObject(left), AccessPathRoot::ModuleObject(right)) if left == right
        ) || matches!(
            (self, root),
            (Self::External(left), AccessPathRoot::External(right)) if left == right
        )
    }
}

/// An abstract object candidate.  Cardinality is explicit and never inferred
/// merely from an allocation-site identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AbstractObject {
    identity: AbstractObjectIdentity,
    cardinality: ObjectCardinality,
}

impl AbstractObject {
    pub fn new(
        identity: AbstractObjectIdentity,
        cardinality: ObjectCardinality,
    ) -> Result<Self, OracleContractError> {
        identity.validate_shape()?;
        if matches!(identity, AbstractObjectIdentity::TypeSummary(_))
            && cardinality != ObjectCardinality::Summary
        {
            return Err(OracleContractError::InvalidObjectCardinality(
                "type-summary objects must have summary cardinality",
            ));
        }
        if matches!(identity, AbstractObjectIdentity::External(_))
            && cardinality == ObjectCardinality::Singleton
        {
            return Err(OracleContractError::InvalidObjectCardinality(
                "external objects cannot claim singleton cardinality",
            ));
        }
        Ok(Self {
            identity,
            cardinality,
        })
    }

    pub fn identity(&self) -> &AbstractObjectIdentity {
        &self.identity
    }

    pub const fn cardinality(&self) -> ObjectCardinality {
        self.cardinality
    }

    fn validate_at(&self, procedure: &ProcedureHandle) -> Result<(), OracleContractError> {
        self.identity.validate_at(procedure)
    }
}

/// One abstract addressable location.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AbstractLocation {
    object: AbstractObject,
    path: AccessPath,
}

impl AbstractLocation {
    pub fn new(object: AbstractObject, path: AccessPath) -> Result<Self, OracleContractError> {
        if !object.identity.matches_root(path.root()) {
            return Err(OracleContractError::ObjectPathMismatch);
        }
        Ok(Self { object, path })
    }

    pub fn object(&self) -> &AbstractObject {
        &self.object
    }

    pub fn path(&self) -> &AccessPath {
        &self.path
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValueFlowRelationKind {
    Assignment,
    Parameter,
    Receiver,
    NormalReturn,
    ExceptionalReturn,
    Allocation,
    MemoryLoad,
    MemoryStore,
    Capture,
    LanguageDefined,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ValueFlowEndpoint {
    Value(ValueHandle),
    Port(ProcedurePortHandle),
    Location(Box<AbstractLocation>),
}

impl ValueFlowEndpoint {
    fn validate_at(&self, procedure: &ProcedureHandle) -> Result<(), OracleContractError> {
        match self {
            Self::Value(value) => require_same_procedure(value.procedure(), procedure),
            Self::Port(port) => require_same_procedure(port.procedure(), procedure),
            Self::Location(location) => {
                location.object().validate_at(procedure)?;
                location.path().validate_at(procedure)
            }
        }
    }
}

fn validate_capture_flow(
    procedure: &ProcedureHandle,
    source: &ValueFlowEndpoint,
    target: &ValueFlowEndpoint,
) -> Result<(), OracleContractError> {
    source.validate_at(procedure)?;
    let ValueFlowEndpoint::Port(target) = target else {
        return Err(OracleContractError::CrossProcedure);
    };
    let ProcedurePortKind::Capture { slot } = target.kind() else {
        return Err(OracleContractError::CrossProcedure);
    };
    let child = target.procedure();
    if !Arc::ptr_eq(procedure.artifact(), child.artifact())
        || child.semantics().lexical_parent() != Some(procedure.id())
    {
        return Err(OracleContractError::CrossProcedure);
    }

    let matches_source = |captured: super::ir::CaptureSource| match (captured, source) {
        (super::ir::CaptureSource::Value(expected), ValueFlowEndpoint::Value(actual)) => {
            actual.id() == expected
        }
        (super::ir::CaptureSource::Location(expected), ValueFlowEndpoint::Location(actual)) => {
            matches!(
                actual.object().identity(),
                AbstractObjectIdentity::LexicalCell(location) if location.id() == expected
            )
        }
        (super::ir::CaptureSource::Value(_), _) | (super::ir::CaptureSource::Location(_), _) => {
            false
        }
    };
    if !procedure.semantics().captures().iter().any(|capture| {
        capture.target == child.id()
            && capture.destination == slot
            && matches_source(capture.captured)
    }) {
        return Err(OracleContractError::InvalidRelationIdentity);
    }
    Ok(())
}

/// One materialized value-flow relation.  Relation IDs provide stable identity
/// inside this oracle materialization without imposing any weight algebra.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ValueFlowRelation {
    pub id: OracleRelationHandle,
    pub kind: ValueFlowRelationKind,
    pub source: ValueFlowEndpoint,
    pub target: ValueFlowEndpoint,
    pub proof: ProofStatus,
    pub completeness: EvidenceCompleteness,
}

impl ValueFlowRelation {
    pub const fn is_proven_complete(&self) -> bool {
        matches!(self.proof, ProofStatus::Proven)
            && matches!(self.completeness, EvidenceCompleteness::Complete)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ValueFlowSnapshot {
    procedure: ProcedureHandle,
    context: OracleCallContext,
    relations: Box<[ValueFlowRelation]>,
    coverage: CandidateCoverage,
}

impl ValueFlowSnapshot {
    pub fn new(
        procedure: ProcedureHandle,
        context: OracleCallContext,
        relations: Vec<ValueFlowRelation>,
        coverage: CandidateCoverage,
        limits: OracleLimits,
    ) -> Result<Self, OracleContractError> {
        let owner = OracleRelationOwner::ProcedureValueFlow {
            procedure: procedure.clone(),
            context: context.clone(),
        };
        let mut seen = std::collections::HashSet::new();
        let first = relations.first().map(|relation| &relation.id);
        for relation in &relations {
            if relation.id.owner() != &owner
                || relation.id.record().kind() != OracleRelationKind::ValueFlow
                || relation.id.record().evidence().is_empty()
                || first.is_some_and(|first| !first.same_arena(&relation.id))
                || !seen.insert(relation.id.clone())
            {
                return Err(OracleContractError::InvalidRelationIdentity);
            }
            if !relation
                .id
                .record()
                .supports_quality(&relation.proof, &relation.completeness)
            {
                return Err(OracleContractError::InvalidRelationQuality);
            }
            if relation.kind == ValueFlowRelationKind::Capture {
                validate_capture_flow(&procedure, &relation.source, &relation.target)?;
            } else {
                relation.source.validate_at(&procedure)?;
                relation.target.validate_at(&procedure)?;
            }
        }
        validate_retained_relation_arenas(relations.iter().map(|relation| &relation.id), limits)?;
        Ok(Self {
            procedure,
            context,
            relations: relations.into_boxed_slice(),
            coverage,
        })
    }

    pub fn procedure(&self) -> &ProcedureHandle {
        &self.procedure
    }

    pub fn relations(&self) -> &[ValueFlowRelation] {
        &self.relations
    }

    pub fn context(&self) -> &OracleCallContext {
        &self.context
    }

    pub const fn coverage(&self) -> CandidateCoverage {
        self.coverage
    }
}

/// The caller-side endpoint used by one argument binding.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CallArgumentEndpoint {
    Value(ValueHandle),
    Location {
        value: ValueHandle,
        location: AccessPathAtPoint,
    },
}

impl CallArgumentEndpoint {
    pub fn value(&self) -> &ValueHandle {
        match self {
            Self::Value(value) | Self::Location { value, .. } => value,
        }
    }
}

/// Language-neutral argument passing semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CallPassingMode {
    Value,
    SharedReference,
    MutableReference,
    InputOutputReference,
    OutputReference,
    LanguageDefined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ImplicitArgumentKind {
    Default,
    Implicit,
    LanguageDefined,
}

/// One member contributed by a syntactic call argument. Direct arguments
/// contribute one `Whole` member; spread arguments contribute structured
/// positional, keyword, or language-defined members.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CallArgumentMember {
    Whole,
    Positional(u32),
    Keyword(Box<str>),
    LanguageDefined(Box<str>),
}

/// One retained actual-to-formal mapping inside an argument group.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallArgumentMapping {
    source_index: u32,
    member: CallArgumentMember,
    actual: CallArgumentEndpoint,
    formal: ProcedurePortHandle,
    mode: CallPassingMode,
}

impl CallArgumentMapping {
    pub fn new(
        source_index: u32,
        member: CallArgumentMember,
        actual: CallArgumentEndpoint,
        formal: ProcedurePortHandle,
        mode: CallPassingMode,
    ) -> Self {
        Self {
            source_index,
            member,
            actual,
            formal,
            mode,
        }
    }

    pub const fn source_index(&self) -> u32 {
        self.source_index
    }

    pub fn member(&self) -> &CallArgumentMember {
        &self.member
    }

    pub fn actual(&self) -> &CallArgumentEndpoint {
        &self.actual
    }

    pub fn formal(&self) -> &ProcedurePortHandle {
        &self.formal
    }

    pub const fn mode(&self) -> CallPassingMode {
        self.mode
    }
}

/// Cardinality derived from group coverage and candidate proof. Callers cannot
/// assert an exact cardinality independently of the validated mapping set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArgumentCardinality {
    Exact(usize),
    Between { minimum: usize, maximum: usize },
    AtLeast(usize),
}

/// One evidence-backed group of argument sources and retained mappings.
///
/// The separate closure relation proves that an exhaustive group has no
/// omitted members. Keeping source indices even when no mapping is retained
/// represents an exact empty spread or an open/truncated unknown spread
/// without pretending that the syntactic actual disappeared.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallArgumentGroup {
    closure_relation: OracleRelationHandle,
    sources: Box<[u32]>,
    mappings: Box<[EvidenceBacked<CallArgumentMapping>]>,
    coverage: CandidateCoverage,
}

impl CallArgumentGroup {
    pub fn new<I, M>(
        call: &CallSiteHandle,
        closure_relation: OracleRelationHandle,
        sources: I,
        mappings: M,
        coverage: CandidateCoverage,
        limits: OracleLimits,
    ) -> Result<Self, OracleContractError>
    where
        I: IntoIterator<Item = u32>,
        M: IntoIterator<Item = EvidenceBacked<CallArgumentMapping>>,
    {
        let call_row = call
            .procedure()
            .semantics()
            .call_site(call.id())
            .expect("call-site handles are validated at construction");
        let entry_limit = limits.call_binding_entries();
        let source_limit = entry_limit.min(call_row.arguments.len());
        let sources = sources
            .into_iter()
            .take(source_limit.saturating_add(1))
            .collect::<Vec<_>>();
        if sources.len() > entry_limit {
            return Err(OracleContractError::LimitExceeded {
                dimension: "call_binding_entries",
                limit: entry_limit,
                attempted: sources.len(),
            });
        }
        if sources.len() > call_row.arguments.len() {
            return Err(OracleContractError::InvalidCallBinding(
                "argument group has more sources than the exact call",
            ));
        }
        if sources.is_empty() {
            return Err(OracleContractError::InvalidCallBinding(
                "argument group must name at least one syntactic source",
            ));
        }
        let mut unique_sources = std::collections::HashSet::new();
        if sources.iter().any(|source| !unique_sources.insert(*source)) {
            return Err(OracleContractError::InvalidCallBinding(
                "argument group repeats one syntactic source",
            ));
        }
        if sources
            .iter()
            .any(|source| call_row.arguments.get(*source as usize).is_none())
        {
            return Err(OracleContractError::InvalidCallBinding(
                "argument group names a source outside the exact call",
            ));
        }
        let remaining = entry_limit.saturating_sub(sources.len());
        let mappings = mappings
            .into_iter()
            .take(remaining.saturating_add(1))
            .collect::<Vec<_>>();
        if mappings.len() > remaining {
            return Err(OracleContractError::LimitExceeded {
                dimension: "call_binding_entries",
                limit: entry_limit,
                attempted: sources.len().saturating_add(mappings.len()),
            });
        }
        let mut unique_members = std::collections::HashSet::new();
        if mappings.iter().any(|mapping| {
            !unique_sources.contains(&mapping.value().source_index)
                || !unique_members
                    .insert((mapping.value().source_index, mapping.value().member.clone()))
        }) {
            return Err(OracleContractError::InvalidCallBinding(
                "argument mapping repeats or names an undeclared source member",
            ));
        }
        validate_retained_relation_arenas(
            std::iter::once(&closure_relation)
                .chain(mappings.iter().flat_map(OracleCandidate::provenance)),
            limits,
        )?;
        Ok(Self {
            closure_relation,
            sources: sources.into_boxed_slice(),
            mappings: mappings.into_boxed_slice(),
            coverage,
        })
    }

    pub fn closure_relation(&self) -> &OracleRelationHandle {
        &self.closure_relation
    }

    pub fn sources(&self) -> &[u32] {
        &self.sources
    }

    pub fn mappings(&self) -> &[EvidenceBacked<CallArgumentMapping>] {
        &self.mappings
    }

    pub const fn coverage(&self) -> CandidateCoverage {
        self.coverage
    }

    pub fn cardinality(&self) -> ArgumentCardinality {
        let proven = self
            .mappings
            .iter()
            .filter(|mapping| matches!(mapping.proof(), ProofStatus::Proven))
            .count();
        match self.coverage {
            CandidateCoverage::Exhaustive if proven == self.mappings.len() => {
                ArgumentCardinality::Exact(proven)
            }
            CandidateCoverage::Exhaustive => ArgumentCardinality::Between {
                minimum: proven,
                maximum: self.mappings.len(),
            },
            CandidateCoverage::Open | CandidateCoverage::Truncated => {
                ArgumentCardinality::AtLeast(proven)
            }
        }
    }
}

/// One candidate-specific caller/callee boundary relation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CallBinding {
    Receiver {
        relation: OracleRelationHandle,
        actual: ValueHandle,
        formal: ProcedurePortHandle,
    },
    ArgumentGroup(CallArgumentGroup),
    ImplicitArgument {
        relation: OracleRelationHandle,
        formal_ordinal: u32,
        source: ValueHandle,
        formal: ProcedurePortHandle,
        kind: ImplicitArgumentKind,
    },
    NormalReturn {
        relation: OracleRelationHandle,
        formal: ProcedurePortHandle,
        result: ValueHandle,
    },
    ExceptionalReturn {
        relation: OracleRelationHandle,
        formal: ProcedurePortHandle,
        result: ValueHandle,
    },
}

/// Actual/formal and return bindings for one exact dispatch candidate.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallBindings {
    call: CallSiteHandle,
    candidate: DispatchCandidate,
    context: OracleCallContext,
    bindings: Box<[CallBinding]>,
    coverage: CandidateCoverage,
}

fn validate_call_binding_relation(
    relation: &OracleRelationHandle,
    owner: &OracleRelationOwner,
    first: &mut Option<OracleRelationHandle>,
    seen: &mut std::collections::HashSet<OracleRelationHandle>,
) -> Result<(), OracleContractError> {
    if relation.owner() != owner
        || relation.record().kind() != OracleRelationKind::CallBinding
        || relation.record().evidence().is_empty()
        || first
            .as_ref()
            .is_some_and(|first| !first.same_arena(relation))
        || !seen.insert(relation.clone())
    {
        return Err(OracleContractError::InvalidRelationIdentity);
    }
    if first.is_none() {
        *first = Some(relation.clone());
    }
    Ok(())
}

fn member_matches_expansion(
    expansion: &CallArgumentExpansion,
    member: &CallArgumentMember,
) -> bool {
    match (expansion, member) {
        (CallArgumentExpansion::Direct(_), CallArgumentMember::Whole) => true,
        (
            CallArgumentExpansion::Spread(ArgumentDomain::Positional),
            CallArgumentMember::Positional(_),
        )
        | (
            CallArgumentExpansion::Spread(ArgumentDomain::Keyword),
            CallArgumentMember::Keyword(_),
        ) => true,
        (
            CallArgumentExpansion::Spread(ArgumentDomain::PositionalOrKeyword),
            CallArgumentMember::Positional(_) | CallArgumentMember::Keyword(_),
        ) => true,
        (
            CallArgumentExpansion::Spread(ArgumentDomain::LanguageDefined(expected)),
            CallArgumentMember::LanguageDefined(actual),
        ) => expected == actual,
        _ => false,
    }
}

fn rest_domain_accepts_mapping(
    rest: &ArgumentDomain,
    expansion: &CallArgumentExpansion,
    member: &CallArgumentMember,
) -> bool {
    let accepts_positional = matches!(
        rest,
        ArgumentDomain::Positional | ArgumentDomain::PositionalOrKeyword
    );
    let accepts_keyword = matches!(
        rest,
        ArgumentDomain::Keyword | ArgumentDomain::PositionalOrKeyword
    );
    match (expansion, member) {
        (CallArgumentExpansion::Direct(ArgumentDomain::Positional), CallArgumentMember::Whole) => {
            accepts_positional
        }
        (CallArgumentExpansion::Direct(ArgumentDomain::Keyword), CallArgumentMember::Whole) => {
            accepts_keyword
        }
        (
            CallArgumentExpansion::Direct(ArgumentDomain::PositionalOrKeyword),
            CallArgumentMember::Whole,
        ) => accepts_positional || accepts_keyword,
        (
            CallArgumentExpansion::Direct(ArgumentDomain::LanguageDefined(actual)),
            CallArgumentMember::Whole,
        )
        | (
            CallArgumentExpansion::Spread(ArgumentDomain::LanguageDefined(actual)),
            CallArgumentMember::LanguageDefined(_),
        ) => matches!(rest, ArgumentDomain::LanguageDefined(expected) if expected == actual),
        (CallArgumentExpansion::Spread(_), CallArgumentMember::Positional(_)) => accepts_positional,
        (CallArgumentExpansion::Spread(_), CallArgumentMember::Keyword(_)) => accepts_keyword,
        _ => false,
    }
}

fn validate_argument_endpoint(
    actual: &CallArgumentEndpoint,
    mode: CallPassingMode,
    caller: &ProcedureHandle,
    call_point: super::ids::ProgramPointId,
    context: &OracleCallContext,
) -> Result<(), OracleContractError> {
    require_same_procedure(actual.value().procedure(), caller)?;
    if let CallArgumentEndpoint::Location { location, .. } = actual {
        require_same_procedure(location.point().procedure(), caller)?;
        if location.point().id() != call_point
            || location.phase() != ObservationPhase::BeforeEffects
            || location.context() != context
        {
            return Err(OracleContractError::InvalidCallBinding(
                "reference argument locations must be observed immediately before the call effects",
            ));
        }
        if !matches!(
            mode,
            CallPassingMode::SharedReference
                | CallPassingMode::MutableReference
                | CallPassingMode::InputOutputReference
                | CallPassingMode::OutputReference
                | CallPassingMode::LanguageDefined
        ) {
            return Err(OracleContractError::InvalidCallBinding(
                "location arguments require a reference-capable passing mode",
            ));
        }
    } else if matches!(
        mode,
        CallPassingMode::MutableReference
            | CallPassingMode::InputOutputReference
            | CallPassingMode::OutputReference
    ) {
        return Err(OracleContractError::InvalidCallBinding(
            "mutable/output argument modes require a caller location",
        ));
    }
    Ok(())
}

impl CallBindings {
    pub fn new<I>(
        call: CallSiteHandle,
        candidate: &DispatchCandidate,
        context: OracleCallContext,
        bindings: I,
        coverage: CandidateCoverage,
        limits: OracleLimits,
    ) -> Result<Self, OracleContractError>
    where
        I: IntoIterator<Item = CallBinding>,
    {
        candidate.validate_for_call(&call)?;
        let bindings = collect_bounded(
            bindings,
            limits.call_binding_entries(),
            "call_binding_entries",
        )?;
        let retained_entries = bindings.iter().fold(bindings.len(), |total, binding| {
            let CallBinding::ArgumentGroup(group) = binding else {
                return total;
            };
            total
                .saturating_add(group.sources().len())
                .saturating_add(group.mappings().len())
        });
        if retained_entries > limits.call_binding_entries() {
            return Err(OracleContractError::LimitExceeded {
                dimension: "call_binding_entries",
                limit: limits.call_binding_entries(),
                attempted: retained_entries,
            });
        }
        let callee = candidate.target().clone();
        let caller = call.procedure();
        let call_row = caller
            .semantics()
            .call_site(call.id())
            .expect("call-site handles are validated at construction");
        let relation_owner = OracleRelationOwner::CallBinding {
            call: call.clone(),
            callee: callee.clone(),
            context: context.clone(),
        };
        let mut relation_ids = std::collections::HashSet::new();
        let mut first_relation = None;
        let mut actual_sources = std::collections::HashSet::new();
        let mut formal_bindings = std::collections::HashSet::new();
        let mut formal_mapping_counts = std::collections::HashMap::<u32, usize>::new();
        let mut implicit_formals = std::collections::HashSet::new();
        let mut has_receiver = false;
        let mut has_normal_return = false;
        let mut has_exceptional_return = false;
        let mut has_open_group = false;
        let mut has_truncated_group = false;
        for binding in &bindings {
            match binding {
                CallBinding::Receiver {
                    relation,
                    actual,
                    formal,
                } => {
                    validate_call_binding_relation(
                        relation,
                        &relation_owner,
                        &mut first_relation,
                        &mut relation_ids,
                    )?;
                    if !relation.record().is_proven_complete() {
                        return Err(OracleContractError::InvalidRelationQuality);
                    }
                    require_same_procedure(actual.procedure(), caller)?;
                    require_same_procedure(formal.procedure(), &callee)?;
                    if call_row.receiver != Some(actual.id())
                        || formal.kind() != ProcedurePortKind::Receiver
                    {
                        return Err(OracleContractError::InvalidCallBinding(
                            "receiver binding does not match the call receiver and callee receiver port",
                        ));
                    }
                    if has_receiver {
                        return Err(OracleContractError::InvalidCallBinding(
                            "call binding contains more than one receiver relation",
                        ));
                    }
                    has_receiver = true;
                }
                CallBinding::ArgumentGroup(group) => {
                    validate_call_binding_relation(
                        group.closure_relation(),
                        &relation_owner,
                        &mut first_relation,
                        &mut relation_ids,
                    )?;
                    if group.coverage().is_exhaustive()
                        && !group.closure_relation().record().is_proven_complete()
                    {
                        return Err(OracleContractError::InvalidRelationQuality);
                    }
                    has_open_group |= group.coverage() == CandidateCoverage::Open;
                    has_truncated_group |= group.coverage().is_truncated();
                    for source_index in group.sources() {
                        let Some(argument) = call_row.arguments.get(*source_index as usize) else {
                            return Err(OracleContractError::InvalidCallBinding(
                                "argument group names a source outside the exact call",
                            ));
                        };
                        if !actual_sources.insert(*source_index) {
                            return Err(OracleContractError::InvalidCallBinding(
                                "one syntactic argument source appears in multiple groups",
                            ));
                        }
                        let has_mapping = group
                            .mappings()
                            .iter()
                            .any(|mapping| mapping.value().source_index == *source_index);
                        if group.coverage().is_exhaustive()
                            && !argument.expansion.is_spread()
                            && !has_mapping
                        {
                            return Err(OracleContractError::InvalidCallBinding(
                                "an exhaustive direct-argument group omits its mapping",
                            ));
                        }
                    }
                    for backed_mapping in group.mappings() {
                        if backed_mapping.provenance().is_empty() {
                            return Err(OracleContractError::InvalidRelationIdentity);
                        }
                        for relation in backed_mapping.provenance() {
                            validate_call_binding_relation(
                                relation,
                                &relation_owner,
                                &mut first_relation,
                                &mut relation_ids,
                            )?;
                            if !relation.record().supports_quality(
                                backed_mapping.proof(),
                                backed_mapping.completeness(),
                            ) {
                                return Err(OracleContractError::InvalidRelationQuality);
                            }
                        }
                        let mapping = backed_mapping.value();
                        let argument = call_row
                            .arguments
                            .get(mapping.source_index as usize)
                            .expect("group sources were validated above");
                        validate_argument_endpoint(
                            &mapping.actual,
                            mapping.mode,
                            caller,
                            call_row.point,
                            &context,
                        )?;
                        require_same_procedure(mapping.formal.procedure(), &callee)?;
                        let ProcedurePortKind::Parameter { ordinal } = mapping.formal.kind() else {
                            return Err(OracleContractError::InvalidCallBinding(
                                "argument mapping does not name a callee parameter port",
                            ));
                        };
                        if argument.value != mapping.actual.value().id()
                            || !member_matches_expansion(&argument.expansion, &mapping.member)
                        {
                            return Err(OracleContractError::InvalidCallBinding(
                                "argument mapping does not match the call source expansion",
                            ));
                        }
                        let multiplicity = mapping
                            .formal
                            .formal_multiplicity()
                            .expect("validated parameter port has multiplicity");
                        if implicit_formals.contains(&ordinal) {
                            return Err(OracleContractError::InvalidCallBinding(
                                "argument mapping conflicts with an implicit formal binding",
                            ));
                        }
                        let count = formal_mapping_counts.entry(ordinal).or_default();
                        match multiplicity {
                            FormalMultiplicity::One if *count > 0 => {
                                return Err(OracleContractError::InvalidCallBinding(
                                    "call binding maps one non-rest formal more than once",
                                ));
                            }
                            FormalMultiplicity::Rest(domain)
                                if !rest_domain_accepts_mapping(
                                    domain,
                                    &argument.expansion,
                                    &mapping.member,
                                ) =>
                            {
                                return Err(OracleContractError::InvalidCallBinding(
                                    "argument member domain is incompatible with the rest formal",
                                ));
                            }
                            FormalMultiplicity::One | FormalMultiplicity::Rest(_) => {}
                        }
                        *count = count.saturating_add(1);
                        formal_bindings.insert(ordinal);
                    }
                }
                CallBinding::ImplicitArgument {
                    relation,
                    formal_ordinal,
                    source,
                    formal,
                    ..
                } => {
                    validate_call_binding_relation(
                        relation,
                        &relation_owner,
                        &mut first_relation,
                        &mut relation_ids,
                    )?;
                    if !relation.record().is_proven_complete() {
                        return Err(OracleContractError::InvalidRelationQuality);
                    }
                    require_same_procedure(formal.procedure(), &callee)?;
                    if source.procedure() != caller && source.procedure() != &callee {
                        return Err(OracleContractError::CrossProcedure);
                    }
                    if formal.kind()
                        != (ProcedurePortKind::Parameter {
                            ordinal: *formal_ordinal,
                        })
                        || formal_bindings.contains(formal_ordinal)
                        || !implicit_formals.insert(*formal_ordinal)
                    {
                        return Err(OracleContractError::InvalidCallBinding(
                            "implicit argument does not name one unbound callee parameter",
                        ));
                    }
                    formal_bindings.insert(*formal_ordinal);
                }
                CallBinding::NormalReturn {
                    relation,
                    formal,
                    result,
                } => {
                    validate_call_binding_relation(
                        relation,
                        &relation_owner,
                        &mut first_relation,
                        &mut relation_ids,
                    )?;
                    if !relation.record().is_proven_complete() {
                        return Err(OracleContractError::InvalidRelationQuality);
                    }
                    require_same_procedure(formal.procedure(), &callee)?;
                    require_same_procedure(result.procedure(), caller)?;
                    if call_row.result != Some(result.id())
                        || formal.kind() != ProcedurePortKind::NormalReturn
                    {
                        return Err(OracleContractError::InvalidCallBinding(
                            "normal-return binding does not match the call result and callee return port",
                        ));
                    }
                    if has_normal_return {
                        return Err(OracleContractError::InvalidCallBinding(
                            "call binding contains more than one normal-return relation",
                        ));
                    }
                    has_normal_return = true;
                }
                CallBinding::ExceptionalReturn {
                    relation,
                    formal,
                    result,
                } => {
                    validate_call_binding_relation(
                        relation,
                        &relation_owner,
                        &mut first_relation,
                        &mut relation_ids,
                    )?;
                    if !relation.record().is_proven_complete() {
                        return Err(OracleContractError::InvalidRelationQuality);
                    }
                    require_same_procedure(formal.procedure(), &callee)?;
                    require_same_procedure(result.procedure(), caller)?;
                    if call_row.thrown != Some(result.id())
                        || formal.kind() != ProcedurePortKind::ExceptionalReturn
                    {
                        return Err(OracleContractError::InvalidCallBinding(
                            "exceptional-return binding does not match the call thrown value and callee exceptional port",
                        ));
                    }
                    if has_exceptional_return {
                        return Err(OracleContractError::InvalidCallBinding(
                            "call binding contains more than one exceptional-return relation",
                        ));
                    }
                    has_exceptional_return = true;
                }
            }
        }
        if has_truncated_group && coverage != CandidateCoverage::Truncated {
            return Err(OracleContractError::InvalidCallBinding(
                "a truncated argument group requires truncated call-binding coverage",
            ));
        }
        if has_open_group && coverage.is_exhaustive() {
            return Err(OracleContractError::InvalidCallBinding(
                "an open argument group cannot support exhaustive call bindings",
            ));
        }
        if coverage.is_exhaustive() {
            let all_actuals_bound =
                (0..call_row.arguments.len()).all(|index| actual_sources.contains(&(index as u32)));
            let all_formals_bound = callee
                .semantics()
                .values()
                .iter()
                .filter_map(|value| match &value.kind {
                    SemanticValueKind::Parameter {
                        ordinal,
                        multiplicity: FormalMultiplicity::One,
                    } => Some(*ordinal),
                    _ => None,
                })
                .all(|ordinal| formal_bindings.contains(&ordinal));
            let receiver_bound = !callee
                .semantics()
                .values()
                .iter()
                .any(|value| value.kind == SemanticValueKind::Receiver)
                || has_receiver;
            let returns_bound = call_row.result.is_none() || has_normal_return;
            let throws_bound = call_row.thrown.is_none() || has_exceptional_return;
            if !all_actuals_bound
                || !all_formals_bound
                || !receiver_bound
                || !returns_bound
                || !throws_bound
            {
                return Err(OracleContractError::InvalidCallBinding(
                    "exhaustive call bindings omit an actual, formal, receiver, or return relation",
                ));
            }
        }
        validate_retained_relation_arenas(
            candidate.provenance().iter().chain(relation_ids.iter()),
            limits,
        )?;
        Ok(Self {
            call,
            candidate: candidate.clone(),
            context,
            bindings: bindings.into_boxed_slice(),
            coverage,
        })
    }

    pub fn call(&self) -> &CallSiteHandle {
        &self.call
    }

    pub fn callee(&self) -> &ProcedureHandle {
        self.candidate.target()
    }

    pub fn candidate(&self) -> &DispatchCandidate {
        &self.candidate
    }

    pub fn bindings(&self) -> &[CallBinding] {
        &self.bindings
    }

    pub fn context(&self) -> &OracleCallContext {
        &self.context
    }

    pub const fn coverage(&self) -> CandidateCoverage {
        self.coverage
    }
}

/// Pairwise alias relation at one observation point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AliasRelation {
    MustAlias,
    MayAlias,
    Disjoint,
}

/// Two access paths compared at one exact observation. Cross-time or
/// cross-context questions require a separate relation rather than silently
/// weakening this point-sensitive alias contract.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AliasQuery {
    left: AccessPathAtPoint,
    right: AccessPathAtPoint,
}

impl AliasQuery {
    pub fn new(
        left: AccessPathAtPoint,
        right: AccessPathAtPoint,
    ) -> Result<Self, OracleContractError> {
        require_same_procedure(left.point().procedure(), right.point().procedure())?;
        if left.point() != right.point()
            || left.phase() != right.phase()
            || left.context() != right.context()
        {
            return Err(OracleContractError::MismatchedObservation);
        }
        Ok(Self { left, right })
    }

    pub fn left(&self) -> &AccessPathAtPoint {
        &self.left
    }

    pub fn right(&self) -> &AccessPathAtPoint {
        &self.right
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PointsToResult {
    query: ValueAtPoint,
    objects: OracleSet<AbstractObject>,
}

impl PointsToResult {
    pub fn new<I>(
        query: ValueAtPoint,
        candidates: I,
        coverage: CandidateCoverage,
        limits: OracleLimits,
    ) -> Result<Self, OracleContractError>
    where
        I: IntoIterator<Item = OracleCandidate<AbstractObject>>,
    {
        let objects = OracleSet::bounded_objects(candidates, coverage, limits);
        validate_candidate_provenance(
            objects.candidates(),
            &OracleRelationOwner::PointsTo(Box::new(query.clone())),
            OracleRelationKind::PointsTo,
        )?;
        for candidate in objects.candidates() {
            candidate.value().validate_at(query.point().procedure())?;
        }
        validate_retained_relation_arenas(
            objects
                .candidates()
                .iter()
                .flat_map(OracleCandidate::provenance),
            limits,
        )?;
        Ok(Self { query, objects })
    }

    pub fn query(&self) -> &ValueAtPoint {
        &self.query
    }

    pub fn objects(&self) -> &OracleSet<AbstractObject> {
        &self.objects
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LocationResult {
    query: AccessPathAtPoint,
    locations: OracleSet<AbstractLocation>,
}

impl LocationResult {
    pub fn new<I>(
        query: AccessPathAtPoint,
        candidates: I,
        coverage: CandidateCoverage,
        limits: OracleLimits,
    ) -> Result<Self, OracleContractError>
    where
        I: IntoIterator<Item = OracleCandidate<AbstractLocation>>,
    {
        let locations = OracleSet::bounded_locations(candidates, coverage, limits);
        validate_candidate_provenance(
            locations.candidates(),
            &OracleRelationOwner::Locations(Box::new(query.clone())),
            OracleRelationKind::Location,
        )?;
        for candidate in locations.candidates() {
            candidate
                .value()
                .object()
                .validate_at(query.point().procedure())?;
            candidate
                .value()
                .path()
                .validate_at(query.point().procedure())?;
        }
        validate_retained_relation_arenas(
            locations
                .candidates()
                .iter()
                .flat_map(OracleCandidate::provenance),
            limits,
        )?;
        Ok(Self { query, locations })
    }

    pub fn query(&self) -> &AccessPathAtPoint {
        &self.query
    }

    pub fn locations(&self) -> &OracleSet<AbstractLocation> {
        &self.locations
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AliasResult {
    query: AliasQuery,
    answer: EvidenceBacked<AliasRelation>,
}

impl AliasResult {
    pub fn new(
        query: AliasQuery,
        answer: EvidenceBacked<AliasRelation>,
        limits: OracleLimits,
    ) -> Result<Self, OracleContractError> {
        validate_candidate_provenance(
            std::slice::from_ref(&answer),
            &OracleRelationOwner::Alias(Box::new(query.clone())),
            OracleRelationKind::Alias,
        )?;
        validate_retained_relation_arenas(answer.provenance(), limits)?;
        Ok(Self { query, answer })
    }

    pub fn query(&self) -> &AliasQuery {
        &self.query
    }

    pub fn answer(&self) -> &EvidenceBacked<AliasRelation> {
        &self.answer
    }
}

fn validate_candidate_provenance<T>(
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

/// Whether the alias analysis proved that no competing location can be
/// updated by the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AliasExclusivity {
    Exclusive,
    PotentialAliases,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EscapeStatus {
    DoesNotEscape,
    MayEscape,
}

/// One exact `MemoryStore` event scoped to its immutable procedure artifact.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MemoryStoreHandle {
    point: ProgramPointHandle,
    event_index: u32,
    location: MemoryLocationHandle,
    value: ValueHandle,
}

impl MemoryStoreHandle {
    pub fn new(point: ProgramPointHandle, event_index: usize) -> Result<Self, OracleContractError> {
        let event = point
            .procedure()
            .semantics()
            .point(point.id())
            .expect("program-point handles are validated at construction")
            .events
            .get(event_index)
            .ok_or(OracleContractError::InvalidStoreEvent)?;
        let SemanticEffect::MemoryStore {
            location, value, ..
        } = &event.effect
        else {
            return Err(OracleContractError::InvalidStoreEvent);
        };
        let location = point
            .procedure()
            .memory_location_handle(*location)
            .expect("validated memory-store events name an existing location");
        let value = point
            .procedure()
            .value_handle(*value)
            .expect("validated memory-store events name an existing value");
        Ok(Self {
            point,
            event_index: u32::try_from(event_index)
                .map_err(|_| OracleContractError::InvalidStoreEvent)?,
            location,
            value,
        })
    }

    pub fn point(&self) -> &ProgramPointHandle {
        &self.point
    }

    pub const fn event_index(&self) -> u32 {
        self.event_index
    }

    pub fn location(&self) -> &MemoryLocationHandle {
        &self.location
    }

    pub fn value(&self) -> &ValueHandle {
        &self.value
    }
}

/// One real semantic store with its address and stored value interpreted at
/// the same pre-effect point, phase, and bounded context.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StoreAtPoint {
    store: MemoryStoreHandle,
    target: AccessPathAtPoint,
    value: ValueAtPoint,
    base: Option<ValueAtPoint>,
}

impl StoreAtPoint {
    pub fn new(
        store: MemoryStoreHandle,
        target: AccessPathAtPoint,
        value: ValueAtPoint,
        base: Option<ValueAtPoint>,
    ) -> Result<Self, OracleContractError> {
        require_same_procedure(target.point.procedure(), value.point.procedure())?;
        require_same_procedure(store.point.procedure(), target.point.procedure())?;
        if target.point != value.point
            || target.point != store.point
            || target.phase != value.phase
            || target.context != value.context
        {
            return Err(OracleContractError::MismatchedObservation);
        }
        if target.phase != ObservationPhase::BeforeEffects || value.value != store.value {
            return Err(OracleContractError::InvalidStoreObservation);
        }
        if let Some(base) = &base {
            require_same_procedure(base.point().procedure(), store.point().procedure())?;
            if base.point() != store.point()
                || base.phase() != ObservationPhase::BeforeEffects
                || base.context() != target.context()
            {
                return Err(OracleContractError::MismatchedObservation);
            }
        }
        if !access_path_matches_memory_location(&target.path, &store.location, base.as_ref()) {
            return Err(OracleContractError::StoreLocationMismatch);
        }
        Ok(Self {
            store,
            target,
            value,
            base,
        })
    }

    pub fn store(&self) -> &MemoryStoreHandle {
        &self.store
    }

    pub fn target(&self) -> &AccessPathAtPoint {
        &self.target
    }

    pub fn value(&self) -> &ValueAtPoint {
        &self.value
    }

    pub fn base(&self) -> Option<&ValueAtPoint> {
        self.base.as_ref()
    }
}

fn access_path_matches_memory_location(
    path: &AccessPath,
    location: &MemoryLocationHandle,
    base: Option<&ValueAtPoint>,
) -> bool {
    let row = location
        .procedure()
        .semantics()
        .memory_location(location.id())
        .expect("memory-location handles are validated at construction");
    match &row.kind {
        MemoryLocationKind::Field {
            base: expected_base,
            member,
        } => base.is_some_and(|base| {
            base.value().id() == *expected_base
                && path.selectors().len() == 1
                && access_root_matches_value(path.root(), base.value())
                && matches!(
                    path.selectors().first(),
                    Some(AccessSelector::Field(field)) if field.locator() == member
                )
        }),
        MemoryLocationKind::Static { member } => {
            base.is_none()
                && path.selectors().is_empty()
                && matches!(
                    path.root(),
                    AccessPathRoot::Static(field) if field.locator() == member
                )
        }
        MemoryLocationKind::Index {
            base: expected_base,
            index,
        } => base.is_some_and(|base| {
            base.value().id() == *expected_base
                && path.selectors().len() == 1
                && access_root_matches_value(path.root(), base.value())
                && (matches!(
                    (index, path.selectors().first()),
                    (Some(expected), Some(AccessSelector::Index(IndexSelector::Exact(actual))))
                        if actual.procedure() == location.procedure() && actual.id() == *expected
                ) || matches!(
                    (index, path.selectors().first()),
                    (None, Some(AccessSelector::Index(IndexSelector::Any)))
                ))
        }),
        MemoryLocationKind::LexicalCell { .. } => {
            base.is_none()
                && path.selectors().is_empty()
                && matches!(
                    path.root(),
                    AccessPathRoot::LexicalCell(actual) if actual == location
                )
        }
        MemoryLocationKind::Capture { .. } => {
            base.is_none()
                && path.selectors().is_empty()
                && matches!(
                    path.root(),
                    AccessPathRoot::CaptureSlot(port)
                        if port.procedure() == location.procedure()
                            && matches!(port.kind(), ProcedurePortKind::Capture { slot } if slot == location.id())
                )
        }
    }
}

fn access_root_matches_value(root: &AccessPathRoot, value: &ValueHandle) -> bool {
    match root {
        AccessPathRoot::Value(actual) => actual == value,
        AccessPathRoot::ProcedurePort(port) => {
            require_same_procedure(port.procedure(), value.procedure()).is_ok()
                && match port.kind() {
                    ProcedurePortKind::Receiver => value
                        .procedure()
                        .semantics()
                        .value(value.id())
                        .is_some_and(|row| row.kind == SemanticValueKind::Receiver),
                    ProcedurePortKind::Parameter { ordinal } => value
                        .procedure()
                        .semantics()
                        .value(value.id())
                        .is_some_and(|row| {
                            matches!(
                                row.kind,
                                SemanticValueKind::Parameter {
                                    ordinal: actual,
                                    ..
                                } if actual == ordinal
                            )
                        }),
                    ProcedurePortKind::NormalReturn
                    | ProcedurePortKind::ExceptionalReturn
                    | ProcedurePortKind::Capture { .. } => false,
                }
        }
        AccessPathRoot::Allocation(allocation) => allocation
            .procedure()
            .semantics()
            .allocation(allocation.id())
            .is_some_and(|row| {
                allocation.procedure() == value.procedure() && row.result == value.id()
            }),
        AccessPathRoot::LexicalCell(location) => location
            .procedure()
            .semantics()
            .memory_location(location.id())
            .is_some_and(|row| {
                location.procedure() == value.procedure()
                    && matches!(row.kind, MemoryLocationKind::LexicalCell { binding } if binding == value.id())
            }),
        AccessPathRoot::Static(_)
        | AccessPathRoot::CaptureSlot(_)
        | AccessPathRoot::TypeSummary(_)
        | AccessPathRoot::ModuleObject(_)
        | AccessPathRoot::External(_) => false,
    }
}

/// Alias-exclusivity evidence tied to one exact store and selected location.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AliasExclusivityWitness {
    store: StoreAtPoint,
    location: AbstractLocation,
    status: AliasExclusivity,
}

impl AliasExclusivityWitness {
    pub fn new(
        store: StoreAtPoint,
        location: AbstractLocation,
        status: AliasExclusivity,
    ) -> Result<Self, OracleContractError> {
        if location.path() != store.target().path() {
            return Err(OracleContractError::StoreLocationMismatch);
        }
        location
            .object()
            .validate_at(store.store().point().procedure())?;
        Ok(Self {
            store,
            location,
            status,
        })
    }

    pub fn store(&self) -> &StoreAtPoint {
        &self.store
    }

    pub fn location(&self) -> &AbstractLocation {
        &self.location
    }

    pub const fn status(&self) -> AliasExclusivity {
        self.status
    }
}

/// Escape evidence tied to one exact store observation and abstract object.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EscapeWitness {
    store: StoreAtPoint,
    object: AbstractObject,
    status: EscapeStatus,
}

impl EscapeWitness {
    pub fn new(
        store: StoreAtPoint,
        object: AbstractObject,
        status: EscapeStatus,
    ) -> Result<Self, OracleContractError> {
        object.validate_at(store.store().point().procedure())?;
        Ok(Self {
            store,
            object,
            status,
        })
    }

    pub fn store(&self) -> &StoreAtPoint {
        &self.store
    }

    pub fn object(&self) -> &AbstractObject {
        &self.object
    }

    pub const fn status(&self) -> EscapeStatus {
        self.status
    }
}

/// A reason a store must use a weak update.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WeakUpdateReason {
    NoLocation,
    MultipleLocations,
    NonExhaustiveLocations,
    TruncatedLocations,
    SummaryPath,
    NoObject,
    MultipleObjects,
    NonExhaustiveObjects,
    TruncatedObjects,
    SummaryObject,
    UnknownObjectCardinality,
    IncompleteAliasEvidence,
    PotentialAliases,
    IncompleteEscapeEvidence,
    EscapingObject,
    UnprovenEvidence,
    MissingProvenance,
    LocationObjectMismatch,
    StoreLocationMismatch,
    AliasSubjectMismatch,
    EscapeSubjectMismatch,
    MismatchedProvenance,
    CrossProcedure,
}

/// Inputs used to determine whether one store has a strong-update proof.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StrongUpdateEvidence {
    locations: OracleSet<AbstractLocation>,
    objects: OracleSet<AbstractObject>,
    alias_exclusivity: EvidenceBacked<AliasExclusivityWitness>,
    escape: EvidenceBacked<EscapeWitness>,
}

impl StrongUpdateEvidence {
    pub fn new(
        locations: OracleSet<AbstractLocation>,
        objects: OracleSet<AbstractObject>,
        alias_exclusivity: EvidenceBacked<AliasExclusivityWitness>,
        escape: EvidenceBacked<EscapeWitness>,
        limits: OracleLimits,
    ) -> Result<Self, OracleContractError> {
        if locations.candidates().len() > limits.alias_breadth() {
            return Err(OracleContractError::LimitExceeded {
                dimension: "alias_breadth",
                limit: limits.alias_breadth(),
                attempted: locations.candidates().len(),
            });
        }
        if objects.candidates().len() > limits.objects_per_value() {
            return Err(OracleContractError::LimitExceeded {
                dimension: "objects_per_value",
                limit: limits.objects_per_value(),
                attempted: objects.candidates().len(),
            });
        }
        validate_retained_relation_arenas(
            locations
                .candidates()
                .iter()
                .flat_map(OracleCandidate::provenance)
                .chain(
                    objects
                        .candidates()
                        .iter()
                        .flat_map(OracleCandidate::provenance),
                )
                .chain(alias_exclusivity.provenance())
                .chain(escape.provenance()),
            limits,
        )?;
        Ok(Self {
            locations,
            objects,
            alias_exclusivity,
            escape,
        })
    }

    pub fn locations(&self) -> &OracleSet<AbstractLocation> {
        &self.locations
    }

    pub fn objects(&self) -> &OracleSet<AbstractObject> {
        &self.objects
    }

    pub fn alias_exclusivity(&self) -> &EvidenceBacked<AliasExclusivityWitness> {
        &self.alias_exclusivity
    }

    pub fn escape(&self) -> &EvidenceBacked<EscapeWitness> {
        &self.escape
    }
}

/// A validated proof that one particular store may replace, rather than join,
/// the previous facts at one abstract location.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StrongUpdateCertificate {
    store: StoreAtPoint,
    location: AbstractLocation,
    provenance: Box<[OracleRelationHandle]>,
}

impl StrongUpdateCertificate {
    pub fn try_new(
        store: StoreAtPoint,
        evidence: StrongUpdateEvidence,
    ) -> Result<Self, StrongUpdateError> {
        let reasons = strong_update_reasons(&store, &evidence);
        if !reasons.is_empty() {
            return Err(StrongUpdateError {
                reasons: reasons.into_boxed_slice(),
            });
        }

        let location_candidate = evidence
            .locations
            .candidates
            .into_vec()
            .into_iter()
            .next()
            .expect("strong-update validation requires one location");
        let object_candidate = evidence
            .objects
            .candidates
            .into_vec()
            .into_iter()
            .next()
            .expect("strong-update validation requires one object");
        let mut provenance = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for relation in location_candidate
            .provenance
            .iter()
            .chain(object_candidate.provenance.iter())
            .chain(evidence.alias_exclusivity.provenance.iter())
            .chain(evidence.escape.provenance.iter())
        {
            if seen.insert(relation.clone()) {
                provenance.push(relation.clone());
            }
        }

        Ok(Self {
            store,
            location: location_candidate.value,
            provenance: provenance.into_boxed_slice(),
        })
    }

    pub fn store(&self) -> &StoreAtPoint {
        &self.store
    }

    pub fn location(&self) -> &AbstractLocation {
        &self.location
    }

    pub fn object(&self) -> &AbstractObject {
        &self.location.object
    }

    pub fn provenance(&self) -> &[OracleRelationHandle] {
        &self.provenance
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StrongUpdateError {
    reasons: Box<[WeakUpdateReason]>,
}

impl StrongUpdateError {
    pub fn reasons(&self) -> &[WeakUpdateReason] {
        &self.reasons
    }
}

impl fmt::Display for StrongUpdateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "strong update is not justified: {:?}",
            self.reasons
        )
    }
}

impl std::error::Error for StrongUpdateError {}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum UpdateEligibility {
    Strong(Box<StrongUpdateCertificate>),
    Weak(Box<[WeakUpdateReason]>),
}

impl UpdateEligibility {
    pub fn evaluate(store: StoreAtPoint, evidence: StrongUpdateEvidence) -> Self {
        match StrongUpdateCertificate::try_new(store, evidence) {
            Ok(certificate) => Self::Strong(Box::new(certificate)),
            Err(error) => Self::Weak(error.reasons),
        }
    }
}

fn strong_update_reasons(
    store: &StoreAtPoint,
    evidence: &StrongUpdateEvidence,
) -> Vec<WeakUpdateReason> {
    let mut reasons = Vec::new();
    match evidence.locations.coverage {
        CandidateCoverage::Exhaustive => {}
        CandidateCoverage::Open => reasons.push(WeakUpdateReason::NonExhaustiveLocations),
        CandidateCoverage::Truncated => reasons.push(WeakUpdateReason::TruncatedLocations),
    }
    match evidence.locations.candidates.len() {
        0 => reasons.push(WeakUpdateReason::NoLocation),
        1 => {}
        _ => reasons.push(WeakUpdateReason::MultipleLocations),
    }
    for candidate in &evidence.locations.candidates {
        if !candidate.is_proven_complete() {
            reasons.push(WeakUpdateReason::UnprovenEvidence);
        }
        if !candidate.value.path().is_exact() {
            reasons.push(WeakUpdateReason::SummaryPath);
        }
        if candidate.value.path() != store.target.path() {
            reasons.push(WeakUpdateReason::StoreLocationMismatch);
        }
        if candidate
            .value
            .path()
            .validate_at(store.target.point.procedure())
            .is_err()
        {
            reasons.push(WeakUpdateReason::CrossProcedure);
        }
    }

    match evidence.objects.coverage {
        CandidateCoverage::Exhaustive => {}
        CandidateCoverage::Open => reasons.push(WeakUpdateReason::NonExhaustiveObjects),
        CandidateCoverage::Truncated => reasons.push(WeakUpdateReason::TruncatedObjects),
    }
    match evidence.objects.candidates.len() {
        0 => reasons.push(WeakUpdateReason::NoObject),
        1 => {}
        _ => reasons.push(WeakUpdateReason::MultipleObjects),
    }
    for candidate in &evidence.objects.candidates {
        if !candidate.is_proven_complete() {
            reasons.push(WeakUpdateReason::UnprovenEvidence);
        }
        match candidate.value.cardinality() {
            ObjectCardinality::Singleton => {}
            ObjectCardinality::Summary => reasons.push(WeakUpdateReason::SummaryObject),
            ObjectCardinality::Unknown => {
                reasons.push(WeakUpdateReason::UnknownObjectCardinality);
            }
        }
    }
    if let (Some(location), Some(object)) = (
        evidence.locations.candidates.first(),
        evidence.objects.candidates.first(),
    ) && location.value.object() != &object.value
    {
        reasons.push(WeakUpdateReason::LocationObjectMismatch);
    }

    if !evidence.alias_exclusivity.is_proven_complete() {
        reasons.push(WeakUpdateReason::IncompleteAliasEvidence);
    }
    if matches!(evidence.alias_exclusivity.proof, ProofStatus::Unproven(_)) {
        reasons.push(WeakUpdateReason::UnprovenEvidence);
    }
    let alias_subject_matches = evidence
        .locations
        .candidates
        .first()
        .is_some_and(|location| {
            evidence.alias_exclusivity.value.store() == store
                && evidence.alias_exclusivity.value.location() == &location.value
        });
    if !alias_subject_matches {
        reasons.push(WeakUpdateReason::AliasSubjectMismatch);
    }
    if evidence.alias_exclusivity.value.status() != AliasExclusivity::Exclusive {
        reasons.push(WeakUpdateReason::PotentialAliases);
    }
    if !evidence.escape.is_proven_complete() {
        reasons.push(WeakUpdateReason::IncompleteEscapeEvidence);
    }
    if matches!(evidence.escape.proof, ProofStatus::Unproven(_)) {
        reasons.push(WeakUpdateReason::UnprovenEvidence);
    }
    let escape_subject_matches = evidence.objects.candidates.first().is_some_and(|object| {
        evidence.escape.value.store() == store && evidence.escape.value.object() == &object.value
    });
    if !escape_subject_matches {
        reasons.push(WeakUpdateReason::EscapeSubjectMismatch);
    }
    if evidence.escape.value.status() != EscapeStatus::DoesNotEscape {
        reasons.push(WeakUpdateReason::EscapingObject);
    }
    if evidence
        .locations
        .candidates
        .iter()
        .any(|candidate| candidate.provenance.is_empty())
        || evidence
            .objects
            .candidates
            .iter()
            .any(|candidate| candidate.provenance.is_empty())
        || evidence.alias_exclusivity.provenance.is_empty()
        || evidence.escape.provenance.is_empty()
    {
        reasons.push(WeakUpdateReason::MissingProvenance);
    }
    let expected_owner = OracleRelationOwner::StrongUpdate(Box::new(store.clone()));
    let provenance_groups = [
        (
            evidence
                .locations
                .candidates
                .first()
                .map_or(&[][..], |candidate| candidate.provenance.as_ref()),
            OracleRelationKind::Location,
        ),
        (
            evidence
                .objects
                .candidates
                .first()
                .map_or(&[][..], |candidate| candidate.provenance.as_ref()),
            OracleRelationKind::PointsTo,
        ),
        (
            evidence.alias_exclusivity.provenance.as_ref(),
            OracleRelationKind::Alias,
        ),
        (
            evidence.escape.provenance.as_ref(),
            OracleRelationKind::Escape,
        ),
    ];
    let first_relation = provenance_groups
        .iter()
        .flat_map(|(relations, _)| relations.iter())
        .next();
    if provenance_groups.iter().any(|(relations, kind)| {
        relations.iter().any(|relation| {
            relation.owner() != &expected_owner
                || relation.record().kind() != *kind
                || relation.record().evidence().is_empty()
                || first_relation.is_some_and(|first| !first.same_arena(relation))
        })
    }) {
        reasons.push(WeakUpdateReason::MismatchedProvenance);
    }
    if provenance_groups.iter().any(|(relations, _)| {
        relations
            .iter()
            .any(|relation| !relation.record().is_proven_complete())
    }) {
        reasons.push(WeakUpdateReason::UnprovenEvidence);
    }

    reasons.sort_unstable_by_key(|reason| *reason as u8);
    reasons.dedup();
    reasons
}

/// One materialized workspace target for an exact semantic call site.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DispatchCandidate {
    pub(crate) target: ProcedureHandle,
    pub(crate) proof: ProofStatus,
    pub(crate) completeness: EvidenceCompleteness,
    pub(crate) provenance: Box<[OracleRelationHandle]>,
    sealed_call: Option<CallSiteHandle>,
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
            sealed_call: None,
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

    fn seal_for_call(&mut self, call: &CallSiteHandle) {
        self.sealed_call = Some(call.clone());
    }

    fn is_sealed_for(&self, call: &CallSiteHandle) -> bool {
        self.sealed_call.as_ref() == Some(call)
    }

    fn validate_for_call(&self, call: &CallSiteHandle) -> Result<(), OracleContractError> {
        if !self.is_sealed_for(call) || self.provenance.is_empty() {
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

/// A dispatch arm that cannot enter a materialized workspace procedure.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DispatchBoundaryKind {
    External(Option<SemanticLocator>),
    Unmaterialized(SemanticLocator),
    Deferred {
        target: SemanticLocator,
        kind: DeferredInvocationKind,
    },
    Unresolved,
    Truncated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeferredInvocationKind {
    Async,
    Generator,
    AsyncGenerator,
    LanguageDefined,
}

impl DeferredInvocationKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Async => "async",
            Self::Generator => "generator",
            Self::AsyncGenerator => "async_generator",
            Self::LanguageDefined => "language_defined",
        }
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
            candidate.seal_for_call(call);
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
                .any(|candidate| !candidate.is_sealed_for(call))
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

/// Location-first whole-program dispatch over one exact semantic call site.
pub trait DispatchOracle {
    fn resolve_call(
        &self,
        call: &CallSiteHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<DispatchResult>, SemanticProviderError>;
}

/// Procedure-local and candidate-specific value-flow answers.
pub trait ValueFlowOracle {
    fn procedure_relations(
        &self,
        procedure: &ProcedureHandle,
        context: &OracleCallContext,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<ValueFlowSnapshot>, SemanticProviderError>;

    fn call_bindings(
        &self,
        call: &CallSiteHandle,
        candidate: &DispatchCandidate,
        context: &OracleCallContext,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<CallBindings>, SemanticProviderError>;
}

/// Point-sensitive abstract-object, location, alias, and update answers.
pub trait HeapOracle {
    fn pointees(
        &self,
        value: &ValueAtPoint,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<PointsToResult>, SemanticProviderError>;

    fn locations(
        &self,
        access: &AccessPathAtPoint,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<LocationResult>, SemanticProviderError>;

    fn alias(
        &self,
        query: &AliasQuery,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<AliasResult>, SemanticProviderError>;

    fn update_eligibility(
        &self,
        store: &StoreAtPoint,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<UpdateEligibility>, SemanticProviderError>;
}

/// A construction-time oracle-contract violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OracleContractError {
    CrossProcedure,
    LimitExceeded {
        dimension: &'static str,
        limit: usize,
        attempted: usize,
    },
    InvalidReceiverPort,
    InvalidParameterOrdinal {
        ordinal: u32,
    },
    InvalidCaptureSlot {
        slot: MemoryLocationId,
    },
    InvalidAccessRoot(&'static str),
    InvalidAccessSelector(&'static str),
    InvalidSemanticScope,
    InvalidObjectCardinality(&'static str),
    ObjectPathMismatch,
    InvalidRelationIdentity,
    InvalidRelationQuality,
    DuplicateDispatchTarget,
    InconsistentCoverage,
    InvalidCallBinding(&'static str),
    InvalidStoreEvent,
    InvalidStoreObservation,
    StoreLocationMismatch,
    MismatchedObservation,
}

impl fmt::Display for OracleContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CrossProcedure => {
                formatter.write_str("oracle handles belong to different procedures")
            }
            Self::LimitExceeded {
                dimension,
                limit,
                attempted,
            } => write!(
                formatter,
                "oracle limit `{dimension}` is {limit}, but the query attempted {attempted} items"
            ),
            Self::InvalidReceiverPort => {
                formatter.write_str("procedure does not publish a receiver port")
            }
            Self::InvalidParameterOrdinal { ordinal } => {
                write!(
                    formatter,
                    "procedure does not publish parameter ordinal {ordinal}"
                )
            }
            Self::InvalidCaptureSlot { slot } => {
                write!(formatter, "memory location {slot} is not a capture slot")
            }
            Self::InvalidAccessRoot(detail)
            | Self::InvalidAccessSelector(detail)
            | Self::InvalidObjectCardinality(detail)
            | Self::InvalidCallBinding(detail) => formatter.write_str(detail),
            Self::InvalidSemanticScope => formatter
                .write_str("semantic locator does not belong to the live oracle artifact scope"),
            Self::ObjectPathMismatch => {
                formatter.write_str("abstract object identity does not match the access-path root")
            }
            Self::InvalidRelationIdentity => formatter
                .write_str("oracle relation does not belong to the required query arena and role"),
            Self::InvalidRelationQuality => formatter.write_str(
                "oracle relation claims stronger proof or completeness than its semantic evidence",
            ),
            Self::DuplicateDispatchTarget => {
                formatter.write_str("dispatch result contains a duplicate procedure target")
            }
            Self::InconsistentCoverage => formatter
                .write_str("dispatch coverage contradicts an unresolved or truncated boundary"),
            Self::InvalidStoreEvent => {
                formatter.write_str("store handle does not name a MemoryStore event")
            }
            Self::InvalidStoreObservation => formatter.write_str(
                "store observation must use the stored value immediately before its effects",
            ),
            Self::StoreLocationMismatch => {
                formatter.write_str("store access path does not match the MemoryStore location")
            }
            Self::MismatchedObservation => formatter
                .write_str("oracle observations must share one point, phase, and call context"),
        }
    }
}

impl std::error::Error for OracleContractError {}

fn require_same_procedure(
    left: &ProcedureHandle,
    right: &ProcedureHandle,
) -> Result<(), OracleContractError> {
    if left == right {
        Ok(())
    } else {
        Err(OracleContractError::CrossProcedure)
    }
}
