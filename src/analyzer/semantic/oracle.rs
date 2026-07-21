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
    AllocationHandle, CallSiteHandle, EvidenceCompleteness, EvidenceHandle, MemoryLocationHandle,
    MemoryLocationKind, ProcedureHandle, ProgramPointHandle, ProofStatus, SemanticArtifact,
    SemanticEffect, SemanticValueKind, ValueHandle,
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

/// One resolvable relation record backed by validated semantic evidence.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OracleRelationRecord {
    kind: OracleRelationKind,
    evidence: Box<[EvidenceHandle]>,
}

impl OracleRelationRecord {
    pub fn new<I>(kind: OracleRelationKind, evidence: I) -> Self
    where
        I: IntoIterator<Item = EvidenceHandle>,
    {
        Self {
            kind,
            evidence: evidence.into_iter().collect::<Vec<_>>().into_boxed_slice(),
        }
    }

    pub const fn kind(&self) -> OracleRelationKind {
        self.kind
    }

    pub fn evidence(&self) -> &[EvidenceHandle] {
        &self.evidence
    }

    pub fn is_proven_complete(&self) -> bool {
        !self.evidence.is_empty()
            && self.evidence.iter().all(|evidence| {
                let row = evidence
                    .procedure()
                    .semantics()
                    .evidence_row(evidence.id())
                    .expect("evidence handles are validated at construction");
                matches!(row.proof, ProofStatus::Proven)
                    && matches!(row.completeness, EvidenceCompleteness::Complete)
            })
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
    ) -> Self
    where
        I: IntoIterator<Item = OracleRelationHandle>,
    {
        Self {
            value,
            proof,
            completeness,
            provenance: provenance
                .into_iter()
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        }
    }

    pub fn proven<I>(value: T, provenance: I) -> Self
    where
        I: IntoIterator<Item = OracleRelationHandle>,
    {
        Self::new(
            value,
            ProofStatus::Proven,
            EvidenceCompleteness::Complete,
            provenance,
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
    pub fn bounded<I>(
        candidates: I,
        mut coverage: CandidateCoverage,
        limits: OracleLimits,
        dimension: OracleSetLimit,
    ) -> Self
    where
        I: IntoIterator<Item = OracleCandidate<T>>,
    {
        let limit = dimension.limit(limits);
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OracleSetLimit {
    ObjectsPerValue,
    AliasBreadth,
}

impl OracleSetLimit {
    const fn limit(self, limits: OracleLimits) -> usize {
        match self {
            Self::ObjectsPerValue => limits.objects_per_value(),
            Self::AliasBreadth => limits.alias_breadth(),
        }
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
    pub provenance_records: usize,
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
            provenance_records: value,
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
            ("provenance_records", values.provenance_records),
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

    pub const fn provenance_records(self) -> usize {
        self.values.provenance_records
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
            provenance_records: 4_096,
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
                if !procedure
                    .semantics()
                    .values()
                    .iter()
                    .any(|value| value.kind == SemanticValueKind::Parameter { ordinal }) =>
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
            if relation.is_proven_complete() && !relation.id.record().is_proven_complete() {
                return Err(OracleContractError::InvalidRelationQuality);
            }
            relation.source.validate_at(&procedure)?;
            relation.target.validate_at(&procedure)?;
        }
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

/// One candidate-specific caller/callee boundary relation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CallBinding {
    Receiver {
        relation: OracleRelationHandle,
        actual: ValueHandle,
        formal: ProcedurePortHandle,
    },
    Argument {
        relation: OracleRelationHandle,
        actual_index: u32,
        formal_ordinal: u32,
        actual: CallArgumentEndpoint,
        formal: ProcedurePortHandle,
        mode: CallPassingMode,
    },
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

impl CallBinding {
    pub fn relation(&self) -> &OracleRelationHandle {
        match self {
            Self::Receiver { relation, .. }
            | Self::Argument { relation, .. }
            | Self::ImplicitArgument { relation, .. }
            | Self::NormalReturn { relation, .. }
            | Self::ExceptionalReturn { relation, .. } => relation,
        }
    }
}

/// Actual/formal and return bindings for one exact dispatch candidate.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallBindings {
    call: CallSiteHandle,
    callee: ProcedureHandle,
    context: OracleCallContext,
    bindings: Box<[CallBinding]>,
    coverage: CandidateCoverage,
}

impl CallBindings {
    pub fn new(
        call: CallSiteHandle,
        callee: ProcedureHandle,
        context: OracleCallContext,
        bindings: Vec<CallBinding>,
        coverage: CandidateCoverage,
    ) -> Result<Self, OracleContractError> {
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
        let mut actual_bindings = std::collections::HashSet::new();
        let mut formal_bindings = std::collections::HashSet::new();
        let mut has_receiver = false;
        let mut has_normal_return = false;
        let mut has_exceptional_return = false;
        let first_relation = bindings.first().map(CallBinding::relation);
        for binding in &bindings {
            let relation = binding.relation();
            if relation.owner() != &relation_owner
                || relation.record().kind() != OracleRelationKind::CallBinding
                || relation.record().evidence().is_empty()
                || !relation.record().is_proven_complete()
                || first_relation.is_some_and(|first| !first.same_arena(relation))
                || !relation_ids.insert(relation.clone())
            {
                return Err(OracleContractError::InvalidRelationIdentity);
            }
            match binding {
                CallBinding::Receiver { actual, formal, .. } => {
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
                CallBinding::Argument {
                    actual_index,
                    formal_ordinal,
                    actual,
                    formal,
                    mode,
                    ..
                } => {
                    let actual_value = actual.value();
                    require_same_procedure(actual_value.procedure(), caller)?;
                    require_same_procedure(formal.procedure(), &callee)?;
                    if call_row.arguments.get(*actual_index as usize) != Some(&actual_value.id())
                        || formal.kind()
                            != (ProcedurePortKind::Parameter {
                                ordinal: *formal_ordinal,
                            })
                    {
                        return Err(OracleContractError::InvalidCallBinding(
                            "argument binding does not match the call argument and callee parameter port",
                        ));
                    }
                    if let CallArgumentEndpoint::Location { location, .. } = actual {
                        require_same_procedure(location.point().procedure(), caller)?;
                        if location.point().id() != call_row.point
                            || location.phase() != ObservationPhase::BeforeEffects
                            || location.context() != &context
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
                    if !actual_bindings.insert(*actual_index) {
                        return Err(OracleContractError::InvalidCallBinding(
                            "call binding maps one actual argument more than once",
                        ));
                    }
                    if !formal_bindings.insert(*formal_ordinal) {
                        return Err(OracleContractError::InvalidCallBinding(
                            "call binding maps one non-variadic formal more than once",
                        ));
                    }
                }
                CallBinding::ImplicitArgument {
                    formal_ordinal,
                    source,
                    formal,
                    ..
                } => {
                    require_same_procedure(formal.procedure(), &callee)?;
                    if source.procedure() != caller && source.procedure() != &callee {
                        return Err(OracleContractError::CrossProcedure);
                    }
                    if formal.kind()
                        != (ProcedurePortKind::Parameter {
                            ordinal: *formal_ordinal,
                        })
                        || !formal_bindings.insert(*formal_ordinal)
                    {
                        return Err(OracleContractError::InvalidCallBinding(
                            "implicit argument does not name one unbound callee parameter",
                        ));
                    }
                }
                CallBinding::NormalReturn { formal, result, .. } => {
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
                CallBinding::ExceptionalReturn { formal, result, .. } => {
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
        if coverage.is_exhaustive() {
            let all_actuals_bound = (0..call_row.arguments.len())
                .all(|index| actual_bindings.contains(&(index as u32)));
            let all_formals_bound = callee
                .semantics()
                .values()
                .iter()
                .filter_map(|value| match value.kind {
                    SemanticValueKind::Parameter { ordinal } => Some(ordinal),
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
        Ok(Self {
            call,
            callee,
            context,
            bindings: bindings.into_boxed_slice(),
            coverage,
        })
    }

    pub fn call(&self) -> &CallSiteHandle {
        &self.call
    }

    pub fn callee(&self) -> &ProcedureHandle {
        &self.callee
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
        let objects = OracleSet::bounded(
            candidates,
            coverage,
            limits,
            OracleSetLimit::ObjectsPerValue,
        );
        validate_candidate_provenance(
            objects.candidates(),
            &OracleRelationOwner::PointsTo(Box::new(query.clone())),
            OracleRelationKind::PointsTo,
        )?;
        for candidate in objects.candidates() {
            candidate.value().validate_at(query.point().procedure())?;
        }
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
        let locations =
            OracleSet::bounded(candidates, coverage, limits, OracleSetLimit::AliasBreadth);
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
    ) -> Result<Self, OracleContractError> {
        validate_candidate_provenance(
            std::slice::from_ref(&answer),
            &OracleRelationOwner::Alias(Box::new(query.clone())),
            OracleRelationKind::Alias,
        )?;
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
                    || (candidate.is_proven_complete() && !relation.record().is_proven_complete())
            })
        {
            return Err(OracleContractError::InvalidRelationIdentity);
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
                            row.kind == (SemanticValueKind::Parameter { ordinal })
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
    ) -> Self {
        Self {
            locations,
            objects,
            alias_exclusivity,
            escape,
        }
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchCandidate {
    pub target: ProcedureHandle,
    pub proof: ProofStatus,
    pub completeness: EvidenceCompleteness,
    pub provenance: Box<[OracleRelationHandle]>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchResult {
    candidates: Box<[DispatchCandidate]>,
    boundaries: Box<[DispatchBoundary]>,
    coverage: CandidateCoverage,
}

impl Default for DispatchResult {
    fn default() -> Self {
        Self {
            candidates: Box::new([]),
            boundaries: Box::new([]),
            coverage: CandidateCoverage::Open,
        }
    }
}

impl DispatchResult {
    /// Publish a dispatch answer only after every retained arm has resolvable,
    /// call-scoped provenance from one finite relation arena.
    pub fn new(
        call: &CallSiteHandle,
        candidates: Vec<DispatchCandidate>,
        boundaries: Vec<DispatchBoundary>,
        coverage: CandidateCoverage,
    ) -> Result<Self, OracleContractError> {
        let result = Self {
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
        result.validate_for_call(call)?;
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
        let owner = OracleRelationOwner::Dispatch(call.clone());
        let first = self
            .candidates
            .iter()
            .flat_map(|candidate| candidate.provenance.iter())
            .chain(
                self.boundaries
                    .iter()
                    .flat_map(|boundary| boundary.provenance.iter()),
            )
            .next();
        let mut seen = std::collections::HashSet::new();
        for (relations, kind, proven_complete) in self
            .candidates
            .iter()
            .map(|candidate| {
                (
                    candidate.provenance.as_ref(),
                    OracleRelationKind::DispatchCandidate,
                    matches!(candidate.proof, ProofStatus::Proven)
                        && matches!(candidate.completeness, EvidenceCompleteness::Complete),
                )
            })
            .chain(self.boundaries.iter().map(|boundary| {
                (
                    boundary.provenance.as_ref(),
                    OracleRelationKind::DispatchBoundary,
                    matches!(boundary.proof, ProofStatus::Proven)
                        && matches!(boundary.completeness, EvidenceCompleteness::Complete),
                )
            }))
        {
            if relations.is_empty()
                || relations.iter().any(|relation| {
                    relation.owner() != &owner
                        || relation.record().kind() != kind
                        || relation.record().evidence().is_empty()
                        || (proven_complete && !relation.record().is_proven_complete())
                        || first.is_some_and(|first| !first.same_arena(relation))
                        || !seen.insert(relation.clone())
                })
            {
                return Err(OracleContractError::InvalidRelationIdentity);
            }
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
                "oracle limit `{dimension}` is {limit}, but the query attempted {attempted} records"
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
            Self::InvalidRelationQuality => formatter
                .write_str("oracle relation claims stronger proof than its semantic evidence"),
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
