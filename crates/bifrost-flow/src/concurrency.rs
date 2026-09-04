//! Spawn-rooted concurrent task slices and exact ordinary-access conflicts.
//!
//! The solver owns task topology and capture-cell identity. Workspace target,
//! heap, and reviewed API-model answers enter through [`ConcurrencyProvider`]
//! so this crate does not depend on an analyzer implementation.

use std::collections::VecDeque;

use crate::analyzer::semantic::{
    AllocationId, CallInvocationMode, CallSiteHandle, CallSiteId, CallableTarget,
    CallableTargetResolution, CaptureSource, ExecutionTiming, IndexedLocationIdentity,
    MemoryAccessKind, MemoryLocationId, MemoryLocationKind, ProcedureHandle, ProgramPointId,
    SemanticEffect, SemanticProviderError, SemanticRequest, SourceMappingId, ValueId,
};
use crate::dataflow::{
    SemanticProcedureSummary, SummaryConcurrencyAccessMode, SummaryConcurrencyAccessPath,
    SummaryConcurrencyAccessSelector, SummaryConcurrencyEffect, SummaryConcurrencyEffectKind,
    SummaryEffectKey, SummaryEventKey, SummaryLocationKey, SummaryPort,
};
use crate::hash::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaskId(u32);

impl TaskId {
    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CanonicalConcurrencyLocation {
    pub identity: Box<str>,
    pub kind: Box<str>,
}

impl CanonicalConcurrencyLocation {
    pub fn new(identity: impl Into<String>, kind: impl Into<String>) -> Self {
        Self {
            identity: identity.into().into_boxed_str(),
            kind: kind.into().into_boxed_str(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConcurrencyObjectCardinality {
    Singleton,
    Multiple,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConcurrencyEscape {
    TaskLocal,
    Published,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConcurrencyOwnership {
    Unique,
    Shared,
    Unknown,
}

/// A bounded heap answer for one source access.
///
/// `exhaustive` says that no unlisted runtime object can be reached. A single
/// candidate is exact only when it is exhaustive and its runtime object has
/// singleton cardinality. Escape and ownership are carried independently:
/// exact object identity does not by itself prove that an object is shared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedConcurrencyLocation {
    candidates: Vec<CanonicalConcurrencyLocation>,
    exhaustive: bool,
    cardinality: ConcurrencyObjectCardinality,
    escape: ConcurrencyEscape,
    ownership: ConcurrencyOwnership,
}

impl ResolvedConcurrencyLocation {
    pub fn new(
        mut candidates: Vec<CanonicalConcurrencyLocation>,
        exhaustive: bool,
        cardinality: ConcurrencyObjectCardinality,
        escape: ConcurrencyEscape,
        ownership: ConcurrencyOwnership,
    ) -> Self {
        candidates.sort_unstable();
        candidates.dedup();
        Self {
            candidates,
            exhaustive,
            cardinality,
            escape,
            ownership,
        }
    }

    pub fn exact(location: CanonicalConcurrencyLocation) -> Self {
        Self::new(
            vec![location],
            true,
            ConcurrencyObjectCardinality::Singleton,
            ConcurrencyEscape::Unknown,
            ConcurrencyOwnership::Unknown,
        )
    }

    pub fn unknown() -> Self {
        Self::new(
            Vec::new(),
            false,
            ConcurrencyObjectCardinality::Unknown,
            ConcurrencyEscape::Unknown,
            ConcurrencyOwnership::Unknown,
        )
    }

    pub fn candidates(&self) -> &[CanonicalConcurrencyLocation] {
        &self.candidates
    }

    pub const fn is_exhaustive(&self) -> bool {
        self.exhaustive
    }

    pub const fn cardinality(&self) -> ConcurrencyObjectCardinality {
        self.cardinality
    }

    pub const fn escape(&self) -> ConcurrencyEscape {
        self.escape
    }

    pub const fn ownership(&self) -> ConcurrencyOwnership {
        self.ownership
    }

    pub fn exact_candidate(&self) -> Option<&CanonicalConcurrencyLocation> {
        (self.exhaustive
            && self.cardinality == ConcurrencyObjectCardinality::Singleton
            && self.candidates.len() == 1)
            .then(|| &self.candidates[0])
    }

    pub fn overlap(&self, other: &Self) -> AccessOverlap {
        if let (Some(first), Some(second)) = (self.exact_candidate(), other.exact_candidate()) {
            return if first == second {
                AccessOverlap::Same(first.clone())
            } else {
                AccessOverlap::Disjoint
            };
        }
        let shared = self
            .candidates
            .iter()
            .find(|candidate| other.candidates.contains(candidate));
        if self.exhaustive && other.exhaustive && shared.is_none() {
            return AccessOverlap::Disjoint;
        }
        AccessOverlap::MayAlias(shared.cloned())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessOverlap {
    Same(CanonicalConcurrencyLocation),
    Disjoint,
    MayAlias(Option<CanonicalConcurrencyLocation>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConcurrencyAnswer<T> {
    Proven(T),
    Open {
        partial: T,
        reasons: Vec<ConcurrencyOpenReason>,
    },
}

impl<T> ConcurrencyAnswer<T> {
    pub fn into_parts(self) -> (T, Vec<ConcurrencyOpenReason>) {
        match self {
            Self::Proven(value) => (value, Vec::new()),
            Self::Open { partial, reasons } => (partial, reasons),
        }
    }

    pub fn map<U>(self, transform: impl FnOnce(T) -> U) -> ConcurrencyAnswer<U> {
        match self {
            Self::Proven(value) => ConcurrencyAnswer::Proven(transform(value)),
            Self::Open { partial, reasons } => ConcurrencyAnswer::Open {
                partial: transform(partial),
                reasons,
            },
        }
    }
}

/// Exact caller facts available while a stable concurrency summary is bound
/// at one call site.
#[derive(Debug, Clone, Default)]
pub struct SummaryConcurrencyBoundaryBinding {
    locations: HashMap<SummaryPort, ConcurrencyAnswer<ResolvedConcurrencyLocation>>,
    integers: HashMap<SummaryPort, i128>,
}

impl SummaryConcurrencyBoundaryBinding {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn bind_location(
        &mut self,
        port: SummaryPort,
        location: ConcurrencyAnswer<ResolvedConcurrencyLocation>,
    ) {
        assert!(
            self.locations.insert(port, location).is_none(),
            "one call boundary binds each summary port once"
        );
    }

    pub fn bind_integer(&mut self, port: SummaryPort, value: i128) {
        assert!(
            self.integers.insert(port, value).is_none(),
            "one call boundary binds each scalar summary port once"
        );
    }

    pub fn location(
        &self,
        port: &SummaryPort,
    ) -> Option<&ConcurrencyAnswer<ResolvedConcurrencyLocation>> {
        self.locations.get(port)
    }

    pub fn integer(&self, port: &SummaryPort) -> Option<i128> {
        self.integers.get(port).copied()
    }
}

/// Instantiate one stable summary access path against exact caller facts.
///
/// Exact field and index selectors preserve boundedness and caller allocation
/// identity. An unbound or wildcard selector remains a structured partial
/// location; it never becomes an exact singleton by spelling coincidence.
pub fn instantiate_summary_access_path(
    path: &SummaryConcurrencyAccessPath,
    binding: &SummaryConcurrencyBoundaryBinding,
) -> ConcurrencyAnswer<ResolvedConcurrencyLocation> {
    let Some(root) = binding.location(path.root()) else {
        return ConcurrencyAnswer::Open {
            partial: ResolvedConcurrencyLocation::unknown(),
            reasons: vec![ConcurrencyOpenReason::UnknownLocation],
        };
    };
    let (mut resolved, mut reasons) = root.clone().into_parts();
    for selector in path.selectors() {
        let (exact_selector, kind) = match selector {
            SummaryConcurrencyAccessSelector::Field(field) => {
                (Some(format!("field:{field}")), "field")
            }
            SummaryConcurrencyAccessSelector::Aggregate => {
                (Some("index:aggregate".to_owned()), "index")
            }
            SummaryConcurrencyAccessSelector::ConstantIndex(index) => {
                (Some(format!("index:{index}")), "index")
            }
            SummaryConcurrencyAccessSelector::Index(port) => binding
                .integer(port)
                .map(|index| format!("index:{index}"))
                .map_or((None, "index"), |selector| (Some(selector), "index")),
            SummaryConcurrencyAccessSelector::AnyIndex => (None, "index"),
        };
        let selector_is_exact = exact_selector.is_some();
        let selector = exact_selector.unwrap_or_else(|| "index:any".to_owned());
        let candidates = resolved
            .candidates()
            .iter()
            .map(|candidate| {
                CanonicalConcurrencyLocation::new(
                    format!("{}/{selector}", candidate.identity),
                    kind,
                )
            })
            .collect();
        resolved = ResolvedConcurrencyLocation::new(
            candidates,
            resolved.is_exhaustive() && selector_is_exact,
            if selector_is_exact {
                resolved.cardinality()
            } else {
                ConcurrencyObjectCardinality::Multiple
            },
            resolved.escape(),
            resolved.ownership(),
        );
        if !selector_is_exact {
            reasons.push(ConcurrencyOpenReason::UnknownLocation);
        }
    }
    if resolved.candidates().is_empty() {
        reasons.push(ConcurrencyOpenReason::UnknownLocation);
    }
    reasons.sort();
    reasons.dedup();
    if reasons.is_empty() {
        ConcurrencyAnswer::Proven(resolved)
    } else {
        ConcurrencyAnswer::Open {
            partial: resolved,
            reasons,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConcurrencyOpenReason {
    UnresolvedTarget,
    AmbiguousTarget,
    UnknownLocation,
    AliasSetTruncated,
    UnknownOwnership,
    AmbiguousSynchronization,
    UnsupportedSynchronization(Box<str>),
    RecursiveExpansion,
    BudgetExhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConcurrencyLockMode {
    Shared,
    Exclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConcurrencyAtomicOperation {
    Load,
    Store,
    ReadModifyWrite,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedConcurrencySubject {
    pub value: ValueId,
    pub canonical: Option<CanonicalConcurrencyLocation>,
    pub reasons: Vec<ConcurrencyOpenReason>,
    pub identity: ConcurrencySubjectIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The structured equivalence relation a reviewed model applies to its subject.
pub enum ConcurrencySubjectIdentity {
    /// Preserve ordinary language value-copy semantics.
    Value,
    /// Follow the shared object or aggregate backing across structured copies.
    Backing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedConcurrencyEffect {
    TaskSpawn {
        targets: Vec<ProcedureHandle>,
        group: Option<ResolvedConcurrencySubject>,
    },
    TaskJoin {
        group: ResolvedConcurrencySubject,
    },
    LockAcquire {
        lock: ResolvedConcurrencySubject,
        mode: ConcurrencyLockMode,
    },
    LockRelease {
        lock: ResolvedConcurrencySubject,
        mode: ConcurrencyLockMode,
    },
    WaitGroupAdd {
        group: ResolvedConcurrencySubject,
        delta: Option<i64>,
    },
    WaitGroupDone {
        group: ResolvedConcurrencySubject,
    },
    WaitGroupWait {
        group: ResolvedConcurrencySubject,
    },
    Atomic {
        location: ResolvedConcurrencySubject,
        operation: ConcurrencyAtomicOperation,
    },
}

/// Exact workspace answers consumed by the task-slice solver.
pub trait ConcurrencyProvider {
    /// A complete stable source summary for `procedure`, when the workspace
    /// has published one under the active behavior and dependency closure.
    /// Absence is distinct from a partial summary: partial summaries are never
    /// admitted to this interface.
    fn complete_summary(&self, _procedure: &ProcedureHandle) -> Option<&SemanticProcedureSummary> {
        None
    }

    /// Whether this provider has already paid the semantic-materialization
    /// cost for procedure bodies in the current request. Production summary
    /// projection lowers whole artifacts, including callback declarations
    /// that are not ordinary call dependencies.
    fn procedure_semantics_precharged(&self, _procedure: &ProcedureHandle) -> bool {
        false
    }

    /// Exact materialized targets retained while projecting a complete
    /// summary closure. Returning `None` means the call must be resolved by
    /// the live provider.
    fn complete_call_targets(
        &self,
        _procedure: &ProcedureHandle,
        _call: CallSiteId,
    ) -> Option<&[ProcedureHandle]> {
        None
    }

    fn resolve_call(
        &self,
        call: &CallSiteHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ConcurrencyAnswer<Vec<ProcedureHandle>>, SemanticProviderError>;

    fn modeled_effects(
        &self,
        call: &CallSiteHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ConcurrencyAnswer<Vec<ResolvedConcurrencyEffect>>, SemanticProviderError>;

    /// Whether any active reviewed model can contribute concurrency effects
    /// at this exact call occurrence. Providers should answer from already
    /// retained target/declaration facts; `true` is the conservative default.
    fn may_have_modeled_effects(&self, _call: &CallSiteHandle) -> bool {
        true
    }

    fn canonical_location(
        &self,
        procedure: &ProcedureHandle,
        point: ProgramPointId,
        location: MemoryLocationId,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ConcurrencyAnswer<Option<CanonicalConcurrencyLocation>>, SemanticProviderError>;

    fn resolved_location(
        &self,
        procedure: &ProcedureHandle,
        point: ProgramPointId,
        location: MemoryLocationId,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ConcurrencyAnswer<ResolvedConcurrencyLocation>, SemanticProviderError> {
        self.canonical_location(procedure, point, location, request)
            .map(|answer| {
                answer.map(|location| {
                    location.map_or_else(
                        ResolvedConcurrencyLocation::unknown,
                        ResolvedConcurrencyLocation::exact,
                    )
                })
            })
    }

    fn canonical_value(
        &self,
        procedure: &ProcedureHandle,
        point: ProgramPointId,
        value: ValueId,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ConcurrencyAnswer<Option<CanonicalConcurrencyLocation>>, SemanticProviderError>;

    fn resolved_value(
        &self,
        procedure: &ProcedureHandle,
        point: ProgramPointId,
        value: ValueId,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ConcurrencyAnswer<ResolvedConcurrencyLocation>, SemanticProviderError> {
        self.canonical_value(procedure, point, value, request)
            .map(|answer| {
                answer.map(|location| {
                    location.map_or_else(
                        ResolvedConcurrencyLocation::unknown,
                        ResolvedConcurrencyLocation::exact,
                    )
                })
            })
    }

    fn canonical_allocation(
        &self,
        _procedure: &ProcedureHandle,
        _allocation: AllocationId,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<ConcurrencyAnswer<Option<CanonicalConcurrencyLocation>>, SemanticProviderError>
    {
        Ok(ConcurrencyAnswer::Open {
            partial: None,
            reasons: vec![ConcurrencyOpenReason::UnknownLocation],
        })
    }

    fn resolved_allocation(
        &self,
        procedure: &ProcedureHandle,
        allocation: AllocationId,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ConcurrencyAnswer<ResolvedConcurrencyLocation>, SemanticProviderError> {
        self.canonical_allocation(procedure, allocation, request)
            .map(|answer| {
                answer.map(|location| {
                    location.map_or_else(
                        ResolvedConcurrencyLocation::unknown,
                        ResolvedConcurrencyLocation::exact,
                    )
                })
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConcurrentAccessMode {
    Read,
    Write,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConcurrentTaskRelation {
    ParentChild,
    Siblings,
    Nested,
    Repeated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConcurrentOrdering {
    Unordered,
    HappensBefore,
    Open,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConcurrentProtection {
    Unprotected,
    CompatibleLock,
    AtomicOnly,
    Open,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConcurrentAccessSite {
    pub task: TaskId,
    pub procedure: ProcedureHandle,
    pub point: ProgramPointId,
    pub source: SourceMappingId,
    pub mode: ConcurrentAccessMode,
    pub access_kind: MemoryAccessKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConcurrentAccessConflict {
    pub location: CanonicalConcurrencyLocation,
    pub first: ConcurrentAccessSite,
    pub second: ConcurrentAccessSite,
    pub task_relation: ConcurrentTaskRelation,
    pub ordering: ConcurrentOrdering,
    pub protection: ConcurrentProtection,
    pub proven: bool,
    pub exhaustive: bool,
    pub reasons: Vec<ConcurrencyOpenReason>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConcurrentAccessReport {
    pub conflicts: Vec<ConcurrentAccessConflict>,
    pub reasons: Vec<ConcurrencyOpenReason>,
}

#[derive(Debug, Clone)]
struct Task {
    parent: Option<TaskId>,
    entry_procedure: Option<ProcedureHandle>,
    spawn_procedure: Option<ProcedureHandle>,
    spawn_call: Option<CallSiteId>,
    group: Option<ResolvedConcurrencySubject>,
    repeated: bool,
    repetitions_serialized: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ContextKey {
    task: TaskId,
    procedure: ProcedureHandle,
}

#[derive(Debug, Clone)]
struct SynchronousCall {
    caller: ContextKey,
    point: ProgramPointId,
    target: ContextKey,
}

#[derive(Debug, Clone)]
struct Access {
    site: ConcurrentAccessSite,
    local_location: Option<LocalLocation>,
    canonical: Option<CanonicalConcurrencyLocation>,
    resolved_location: ResolvedConcurrencyLocation,
    index_alias_domain: Option<IndexAliasDomain>,
    field_alias_domain: Option<FieldAliasDomain>,
    local_identity: bool,
    reasons: Vec<ConcurrencyOpenReason>,
    atomic: bool,
}

#[derive(Debug, Clone)]
struct PendingSummaryAccess {
    context: ContextKey,
    effect: SummaryConcurrencyEffect,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IndexAliasDomain {
    base: CanonicalConcurrencyLocation,
    identity: IndexedLocationIdentity,
    constant_index: Option<u128>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FieldAliasDomain {
    base: Option<CanonicalConcurrencyLocation>,
    member: crate::analyzer::semantic::SemanticLocator,
}

struct CanonicalizedAccess {
    canonical: Option<CanonicalConcurrencyLocation>,
    resolved_location: ResolvedConcurrencyLocation,
    reasons: Vec<ConcurrencyOpenReason>,
    index_alias_domain: Option<IndexAliasDomain>,
    field_alias_domain: Option<FieldAliasDomain>,
}

#[derive(Debug, Clone)]
struct PendingIntrinsicSynchronization {
    task: TaskId,
    procedure: ProcedureHandle,
    point: ProgramPointId,
    operation: crate::analyzer::semantic::SynchronizationOperation,
    subject: ValueId,
}

#[derive(Debug, Clone)]
struct IntrinsicSynchronization {
    task: TaskId,
    procedure: ProcedureHandle,
    point: ProgramPointId,
    operation: crate::analyzer::semantic::SynchronizationOperation,
    subject: Option<CanonicalConcurrencyLocation>,
    fresh_allocation: bool,
    root_input: bool,
    reasons: Vec<ConcurrencyOpenReason>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct LocalLocation {
    task: TaskId,
    procedure: ProcedureHandle,
    location: MemoryLocationId,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum LocalSynchronizationSubject {
    Value {
        task: TaskId,
        procedure: ProcedureHandle,
        value: ValueId,
    },
    Location(LocalLocation),
}

#[derive(Debug, Default)]
struct SynchronizationSubjectClasses {
    parent: HashMap<LocalSynchronizationSubject, LocalSynchronizationSubject>,
    formal_bindings: HashMap<LocalSynchronizationSubject, LocalSynchronizationSubject>,
    formal_binding_reasons: HashMap<LocalSynchronizationSubject, Vec<ConcurrencyOpenReason>>,
    backing_parent: HashMap<LocalSynchronizationSubject, LocalSynchronizationSubject>,
    backing_formal_bindings: HashMap<LocalSynchronizationSubject, LocalSynchronizationSubject>,
    backing_ambiguous: Vec<(LocalSynchronizationSubject, LocalSynchronizationSubject)>,
    backing_field_origins: Vec<BackingFieldOrigin>,
    canonical_values: HashMap<LocalSynchronizationSubject, CanonicalConcurrencyLocation>,
    ambiguous: Vec<LocalSynchronizationSubject>,
    captured_values: Vec<LocalSynchronizationSubject>,
    captured_locations: Vec<LocalSynchronizationSubject>,
    modeled_values: Vec<LocalSynchronizationSubject>,
    fresh_allocations: Vec<LocalSynchronizationSubject>,
    value_assignments: HashMap<LocalSynchronizationSubject, usize>,
    location_stores: HashMap<LocalLocation, usize>,
    backing_location_stores: HashMap<LocalLocation, Vec<LocalSynchronizationSubject>>,
    backing_binding_locations: Vec<(LocalLocation, LocalSynchronizationSubject)>,
}

#[derive(Debug, Clone)]
struct BackingFieldOrigin {
    result: LocalSynchronizationSubject,
    base: LocalSynchronizationSubject,
    member: crate::analyzer::semantic::SemanticLocator,
}

impl SynchronizationSubjectClasses {
    fn root(&mut self, subject: LocalSynchronizationSubject) -> LocalSynchronizationSubject {
        let mut cursor = subject;
        let mut path = Vec::new();
        while let Some(parent) = self.parent.get(&cursor).cloned() {
            path.push(cursor);
            cursor = parent;
        }
        for item in path {
            self.parent.insert(item, cursor.clone());
        }
        cursor
    }

    fn union(&mut self, left: LocalSynchronizationSubject, right: LocalSynchronizationSubject) {
        let left = self.root(left);
        let right = self.root(right);
        if left != right {
            self.parent.insert(right, left);
        }
    }

    fn backing_root(
        &mut self,
        subject: LocalSynchronizationSubject,
    ) -> LocalSynchronizationSubject {
        let mut cursor = subject;
        let mut path = Vec::new();
        while let Some(parent) = self.backing_parent.get(&cursor).cloned() {
            path.push(cursor);
            cursor = parent;
        }
        for item in path {
            self.backing_parent.insert(item, cursor.clone());
        }
        cursor
    }

    fn union_backing(
        &mut self,
        left: LocalSynchronizationSubject,
        right: LocalSynchronizationSubject,
    ) {
        let left = self.backing_root(left);
        let right = self.backing_root(right);
        if left != right {
            self.backing_parent.insert(right, left);
        }
    }

    fn bind_backing_formal(
        &mut self,
        formal: LocalSynchronizationSubject,
        actual: LocalSynchronizationSubject,
    ) {
        if let Some(previous) = self.backing_formal_bindings.get(&formal).cloned()
            && self.backing_root(previous.clone()) != self.backing_root(actual.clone())
        {
            self.backing_ambiguous.push((previous, actual));
            return;
        }
        self.backing_formal_bindings
            .insert(formal.clone(), actual.clone());
        self.union_backing(actual, formal);
    }

    fn note_backing_field_load(
        &mut self,
        result: LocalSynchronizationSubject,
        base: LocalSynchronizationSubject,
        member: crate::analyzer::semantic::SemanticLocator,
    ) {
        self.backing_field_origins.push(BackingFieldOrigin {
            result,
            base,
            member,
        });
    }

    fn mark_captured_value(&mut self, subject: LocalSynchronizationSubject) {
        self.captured_values.push(subject);
    }

    fn mark_captured_location(&mut self, subject: LocalSynchronizationSubject) {
        self.captured_locations.push(subject);
    }

    fn mark_modeled_value(&mut self, subject: LocalSynchronizationSubject) {
        self.modeled_values.push(subject);
    }

    fn mark_fresh_allocation(&mut self, subject: LocalSynchronizationSubject) {
        self.fresh_allocations.push(subject);
    }

    fn contains_fresh_allocation(&mut self, subject: LocalSynchronizationSubject) -> bool {
        let root = self.root(subject);
        let allocations = self.fresh_allocations.clone();
        allocations
            .into_iter()
            .any(|candidate| self.root(candidate) == root)
    }

    fn note_value_assignment(&mut self, subject: LocalSynchronizationSubject) {
        *self.value_assignments.entry(subject).or_default() += 1;
    }

    fn bind_formal(
        &mut self,
        formal: LocalSynchronizationSubject,
        actual: LocalSynchronizationSubject,
    ) {
        if let Some(previous) = self.formal_bindings.get(&formal).cloned()
            && self.root(previous.clone()) != self.root(actual.clone())
        {
            self.ambiguous.extend([formal, previous, actual]);
            return;
        }
        self.formal_bindings.insert(formal.clone(), actual.clone());
        self.union(actual, formal);
    }

    fn note_formal_binding_reasons(
        &mut self,
        formal: LocalSynchronizationSubject,
        mut reasons: Vec<ConcurrencyOpenReason>,
    ) {
        assert!(
            !reasons.is_empty(),
            "an open formal binding names its reasons"
        );
        let retained = self.formal_binding_reasons.entry(formal).or_default();
        retained.append(&mut reasons);
        retained.sort();
        retained.dedup();
    }

    fn formal_binding_reasons(
        &mut self,
        subject: LocalSynchronizationSubject,
    ) -> Vec<ConcurrencyOpenReason> {
        let root = self.root(subject);
        let bindings = self.formal_binding_reasons.clone();
        let mut reasons = bindings
            .into_iter()
            .filter(|(formal, _)| self.root(formal.clone()) == root)
            .flat_map(|(_, reasons)| reasons)
            .collect::<Vec<_>>();
        reasons.sort();
        reasons.dedup();
        reasons
    }

    fn bind_canonical_value(
        &mut self,
        subject: LocalSynchronizationSubject,
        canonical: CanonicalConcurrencyLocation,
    ) {
        if let Some(previous) = self.canonical_values.get(&subject)
            && previous != &canonical
        {
            self.ambiguous.push(subject);
            return;
        }
        self.canonical_values.insert(subject, canonical);
    }

    fn equivalent_values(
        &mut self,
        subject: LocalSynchronizationSubject,
    ) -> Vec<(TaskId, ProcedureHandle, ValueId)> {
        let root = self.root(subject.clone());
        let candidates = self
            .parent
            .keys()
            .chain(self.parent.values())
            .cloned()
            .chain(std::iter::once(subject))
            .collect::<HashSet<_>>();
        candidates
            .into_iter()
            .filter(|candidate| self.root(candidate.clone()) == root)
            .filter_map(|candidate| match candidate {
                LocalSynchronizationSubject::Value {
                    task,
                    procedure,
                    value,
                } => Some((task, procedure, value)),
                LocalSynchronizationSubject::Location(_) => None,
            })
            .collect()
    }

    fn contains_formal_binding(&mut self, subject: LocalSynchronizationSubject) -> bool {
        let root = self.root(subject);
        let formals = self.formal_bindings.keys().cloned().collect::<Vec<_>>();
        formals
            .into_iter()
            .any(|candidate| self.root(candidate) == root)
    }

    fn note_location_store(&mut self, location: LocalLocation) {
        *self.location_stores.entry(location).or_default() += 1;
    }

    fn note_backing_location_store(
        &mut self,
        location: LocalLocation,
        value: LocalSynchronizationSubject,
    ) {
        self.backing_location_stores
            .entry(location)
            .or_default()
            .push(value);
    }

    fn note_backing_binding_location(
        &mut self,
        location: LocalLocation,
        binding: LocalSynchronizationSubject,
    ) {
        self.backing_binding_locations.push((location, binding));
    }

    fn connect_stable_backing_stores(&mut self) {
        let stores = std::mem::take(&mut self.backing_location_stores);
        for (location, values) in stores {
            let [value] = values.as_slice() else {
                continue;
            };
            self.union_backing(
                LocalSynchronizationSubject::Location(location),
                value.clone(),
            );
        }
        let bindings = std::mem::take(&mut self.backing_binding_locations);
        for (location, binding) in bindings {
            if self.location_stores.get(&location).copied().unwrap_or(0) != 0 {
                continue;
            }
            self.union_backing(LocalSynchronizationSubject::Location(location), binding);
        }
    }

    fn canonical_capture_identity(
        &mut self,
        subject: LocalSynchronizationSubject,
    ) -> Option<CanonicalConcurrencyLocation> {
        let root = self.root(subject.clone());
        if let Some(canonical) = self.bound_canonical_identity(subject) {
            return Some(canonical);
        }
        let captured = self.captured_values.clone();
        let captured_value = captured
            .into_iter()
            .any(|candidate| self.root(candidate) == root);
        let captured_locations = self.captured_locations.clone();
        let captured_location = captured_locations
            .into_iter()
            .any(|candidate| self.root(candidate) == root);
        let location_stores = self.location_stores.clone();
        let stores = location_stores
            .into_iter()
            .filter(|(location, _)| {
                self.root(LocalSynchronizationSubject::Location(location.clone())) == root
            })
            .map(|(_, count)| count)
            .sum::<usize>();
        if !captured_value && !(captured_location && stores == 1) {
            return None;
        }
        if let LocalSynchronizationSubject::Location(location) = &root {
            return Some(canonical_local_location(location));
        }
        Some(CanonicalConcurrencyLocation::new(
            format!("captured-value:{root:?}"),
            "object",
        ))
    }

    /// Recover the identity of a map or slice backing store from structured
    /// value flow, field loads, call-boundary copies, and exact captures.
    ///
    /// This is intentionally separate from ordinary object equivalence. A Go
    /// value-receiver call copies the receiver's direct fields, but map and
    /// slice descriptors inside that copy still name the same backing store.
    /// Indexed aggregate accesses and reviewed receiver effects on the
    /// addressed object consume this identity.
    fn canonical_backing_identity(
        &mut self,
        subject: LocalSynchronizationSubject,
    ) -> Option<CanonicalConcurrencyLocation> {
        let mut cursor = self.backing_root(subject);
        let mut fields = Vec::new();
        let mut visited = HashSet::default();
        loop {
            if !visited.insert(cursor.clone()) {
                return None;
            }
            let ambiguous = self.backing_ambiguous.clone();
            if ambiguous.into_iter().any(|(left, right)| {
                let left = self.backing_root(left);
                let right = self.backing_root(right);
                left != right && (left == cursor || right == cursor)
            }) {
                return None;
            }

            let canonical_values = self.canonical_values.clone();
            let mut canonicals = canonical_values
                .into_iter()
                .filter_map(|(candidate, value)| {
                    (self.backing_root(candidate) == cursor).then_some(value)
                });
            let base = if let Some(canonical) = canonicals.next() {
                if canonicals.any(|candidate| candidate != canonical) {
                    return None;
                }
                Some(canonical)
            } else {
                let captured_values = self.captured_values.clone();
                let captured_value = captured_values
                    .into_iter()
                    .any(|candidate| self.backing_root(candidate) == cursor);
                let captured_locations = self.captured_locations.clone();
                let captured_location = captured_locations
                    .into_iter()
                    .any(|candidate| self.backing_root(candidate) == cursor);
                if captured_value || captured_location {
                    Some(match &cursor {
                        LocalSynchronizationSubject::Location(location) => {
                            canonical_local_location(location)
                        }
                        LocalSynchronizationSubject::Value { .. } => {
                            CanonicalConcurrencyLocation::new(
                                format!("captured-backing:{cursor:?}"),
                                "object",
                            )
                        }
                    })
                } else if self
                    .backing_formal_bindings
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
                    .into_iter()
                    .any(|formal| self.backing_root(formal) == cursor)
                {
                    Some(match &cursor {
                        LocalSynchronizationSubject::Location(location) => {
                            canonical_local_location(location)
                        }
                        LocalSynchronizationSubject::Value { .. } => {
                            CanonicalConcurrencyLocation::new(
                                format!("bound-backing:{cursor:?}"),
                                "object",
                            )
                        }
                    })
                } else {
                    None
                }
            };
            if let Some(mut base) = base {
                for member in fields.iter().rev() {
                    base = CanonicalConcurrencyLocation::new(
                        format!("{}/{}", base.identity, field_selector(member)),
                        "object",
                    );
                }
                return Some(base);
            }

            let origins = self.backing_field_origins.clone();
            let mut origin: Option<BackingFieldOrigin> = None;
            for candidate in origins {
                if self.backing_root(candidate.result.clone()) != cursor {
                    continue;
                }
                if let Some(existing) = origin.as_ref()
                    && (self.backing_root(candidate.base.clone())
                        != self.backing_root(existing.base.clone())
                        || candidate.member != existing.member)
                {
                    return None;
                }
                origin.get_or_insert(candidate);
            }
            let origin = origin?;
            fields.push(origin.member);
            cursor = self.backing_root(origin.base);
        }
    }

    fn stable_modeled_identity(
        &mut self,
        subject: LocalSynchronizationSubject,
    ) -> Option<CanonicalConcurrencyLocation> {
        let root = self.root(subject);
        let modeled = self.modeled_values.clone();
        let modeled_count = modeled
            .into_iter()
            .filter(|candidate| self.root(candidate.clone()) == root)
            .collect::<HashSet<_>>()
            .len();
        let assignments = self.value_assignments.clone();
        let assignment_count = assignments
            .into_iter()
            .filter(|(candidate, _)| self.root(candidate.clone()) == root)
            .map(|(_, count)| count)
            .sum::<usize>();
        if modeled_count > 1 && assignment_count <= 1 {
            return Some(CanonicalConcurrencyLocation::new(
                format!("modeled-value:{root:?}"),
                "local_equivalence",
            ));
        }
        None
    }

    fn bound_canonical_identity(
        &mut self,
        subject: LocalSynchronizationSubject,
    ) -> Option<CanonicalConcurrencyLocation> {
        let root = self.root(subject);
        let ambiguous = self.ambiguous.clone();
        if ambiguous
            .into_iter()
            .any(|candidate| self.root(candidate) == root)
        {
            return None;
        }
        let canonical_values = self.canonical_values.clone();
        let mut canonicals = canonical_values
            .into_iter()
            .filter_map(|(candidate, canonical)| {
                (self.root(candidate) == root).then_some(canonical)
            });
        if let Some(canonical) = canonicals.next() {
            if canonicals.any(|candidate| candidate != canonical) {
                return None;
            }
            return Some(canonical);
        }
        None
    }
}

#[derive(Debug, Default)]
struct LocationClasses {
    parent: HashMap<LocalLocation, LocalLocation>,
}

impl LocationClasses {
    fn root(&mut self, location: LocalLocation) -> LocalLocation {
        let mut cursor = location.clone();
        let mut path = Vec::new();
        while let Some(parent) = self.parent.get(&cursor).cloned() {
            path.push(cursor);
            cursor = parent;
        }
        for item in path {
            self.parent.insert(item, cursor.clone());
        }
        cursor
    }

    fn union(&mut self, left: LocalLocation, right: LocalLocation) {
        let left = self.root(left);
        let right = self.root(right);
        if left != right {
            self.parent.insert(right, left);
        }
    }
}

/// Build one bounded task slice and return exact conflicts plus scoped open
/// candidates. The existing semantic request owns cancellation and all work
/// limits; each retained procedure/event/call/location is charged to its
/// corresponding shared dimension.
pub fn concurrent_access_conflicts(
    provider: &impl ConcurrencyProvider,
    root: &ProcedureHandle,
    request: &mut SemanticRequest<'_>,
) -> Result<ConcurrentAccessReport, SemanticProviderError> {
    let mut tasks = vec![Task {
        parent: None,
        entry_procedure: Some(root.clone()),
        spawn_procedure: None,
        spawn_call: None,
        group: None,
        repeated: false,
        repetitions_serialized: false,
    }];
    let mut queue = VecDeque::from([ContextKey {
        task: TaskId(0),
        procedure: root.clone(),
    }]);
    let mut visited = HashSet::default();
    let mut accesses = Vec::new();
    let mut pending_summary_accesses = Vec::new();
    let mut pending_synchronizations = Vec::new();
    let mut synchronization_subjects = SynchronizationSubjectClasses::default();
    let mut task_local_allocations =
        HashMap::<TaskId, HashSet<CanonicalConcurrencyLocation>>::default();
    let mut classes = LocationClasses::default();
    let mut report = ConcurrentAccessReport::default();
    let mut modeled_by_context =
        HashMap::<ContextKey, Vec<(ProgramPointId, ResolvedConcurrencyEffect)>>::default();
    let mut model_reasons_by_context = HashMap::<ContextKey, Vec<ConcurrencyOpenReason>>::default();
    let mut synchronous_calls = Vec::new();
    let mut synchronous_graph = HashMap::<ContextKey, Vec<ContextKey>>::default();

    while let Some(context) = queue.pop_front() {
        if !visited.insert(context.clone()) {
            continue;
        }
        if request.cancellation.is_cancelled() {
            report.reasons.push(ConcurrencyOpenReason::BudgetExhausted);
            break;
        }
        let semantics = context.procedure.semantics();
        // Projection and the task solver share one SemanticRequest. A
        // complete summary proves that this exact body was already retained
        // and charged while closing the dependency graph. Do not debit the
        // same root or callee rows a second time while reconnecting
        // generation-local identities and source sites to its stable effects.
        let summary_backed = provider.complete_summary(&context.procedure).is_some();
        let replay_summary_accesses = context.procedure != *root && summary_backed;
        if replay_summary_accesses {
            pending_summary_accesses.extend(
                provider
                    .complete_summary(&context.procedure)
                    .expect("summary-backed context retains its complete summary")
                    .effects()
                    .iter()
                    .filter_map(|effect| match effect.key() {
                        SummaryEffectKey::Concurrency(effect)
                            if matches!(
                                effect.kind(),
                                SummaryConcurrencyEffectKind::Access { .. }
                            ) =>
                        {
                            Some(PendingSummaryAccess {
                                context: context.clone(),
                                effect: effect.clone(),
                            })
                        }
                        _ => None,
                    }),
            );
        }
        if !provider.procedure_semantics_precharged(&context.procedure)
            && request
                .budget
                .charge(crate::analyzer::semantic::SemanticWork {
                    procedures: 1,
                    program_points: semantics.points().len(),
                    call_sites: semantics.call_sites().len(),
                    memory_locations: semantics.memory_locations().len(),
                    captures: semantics.captures().len(),
                    events: semantics
                        .points()
                        .iter()
                        .map(|point| point.events.len())
                        .sum(),
                    control_edges: semantics.control_edges().len(),
                    ..crate::analyzer::semantic::SemanticWork::default()
                })
                .is_err()
        {
            report.reasons.push(ConcurrencyOpenReason::BudgetExhausted);
            break;
        }

        let allocation_results = semantics
            .allocations()
            .iter()
            .map(|allocation| allocation.result)
            .collect::<HashSet<_>>();
        for location in semantics.memory_locations() {
            let binding = match location.kind {
                MemoryLocationKind::LexicalCell { binding }
                | MemoryLocationKind::Capture {
                    binding: Some(binding),
                    ..
                } => binding,
                _ => continue,
            };
            synchronization_subjects.note_backing_binding_location(
                LocalLocation {
                    task: context.task,
                    procedure: context.procedure.clone(),
                    location: location.id,
                },
                LocalSynchronizationSubject::Value {
                    task: context.task,
                    procedure: context.procedure.clone(),
                    value: binding,
                },
            );
        }
        for point in semantics.points() {
            for event in &point.events {
                match event.effect {
                    SemanticEffect::Allocation { allocation } => {
                        let allocation = semantics
                            .allocation(allocation)
                            .expect("validated allocation exists");
                        let (resolved, reasons) = provider
                            .resolved_allocation(&context.procedure, allocation.id, request)?
                            .into_parts();
                        if reasons.is_empty()
                            && let Some(canonical) = resolved.exact_candidate().cloned()
                        {
                            let canonical = contextual_allocation_identity(context.task, canonical);
                            task_local_allocations
                                .entry(context.task)
                                .or_default()
                                .insert(canonical.clone());
                            synchronization_subjects.bind_canonical_value(
                                LocalSynchronizationSubject::Value {
                                    task: context.task,
                                    procedure: context.procedure.clone(),
                                    value: allocation.result,
                                },
                                canonical,
                            );
                        }
                        synchronization_subjects.mark_fresh_allocation(
                            LocalSynchronizationSubject::Value {
                                task: context.task,
                                procedure: context.procedure.clone(),
                                value: allocation.result,
                            },
                        );
                        continue;
                    }
                    SemanticEffect::ValueFlow {
                        kind,
                        source,
                        target,
                    } => {
                        let source_subject = LocalSynchronizationSubject::Value {
                            task: context.task,
                            procedure: context.procedure.clone(),
                            value: source,
                        };
                        let target_subject = LocalSynchronizationSubject::Value {
                            task: context.task,
                            procedure: context.procedure.clone(),
                            value: target,
                        };
                        synchronization_subjects
                            .union_backing(source_subject.clone(), target_subject.clone());
                        if let Some(canonical) = synchronization_subjects
                            .canonical_capture_identity(source_subject.clone())
                        {
                            synchronization_subjects
                                .bind_canonical_value(target_subject.clone(), canonical);
                        }
                        if !matches!(
                            kind,
                            crate::analyzer::semantic::ValueFlowKind::Transfer(
                                crate::analyzer::semantic::ValueTransfer {
                                    kind: crate::analyzer::semantic::TransferKind::AggregateCopy,
                                    ..
                                }
                            )
                        ) && binding_location(semantics, target).is_none()
                        {
                            synchronization_subjects.union(source_subject, target_subject);
                        }
                        continue;
                    }
                    SemanticEffect::Assignment { target, value } => {
                        synchronization_subjects.union_backing(
                            LocalSynchronizationSubject::Value {
                                task: context.task,
                                procedure: context.procedure.clone(),
                                value,
                            },
                            LocalSynchronizationSubject::Value {
                                task: context.task,
                                procedure: context.procedure.clone(),
                                value: target,
                            },
                        );
                        synchronization_subjects.note_value_assignment(
                            LocalSynchronizationSubject::Value {
                                task: context.task,
                                procedure: context.procedure.clone(),
                                value: target,
                            },
                        );
                        if allocation_results.contains(&value) {
                            synchronization_subjects.union(
                                LocalSynchronizationSubject::Value {
                                    task: context.task,
                                    procedure: context.procedure.clone(),
                                    value,
                                },
                                LocalSynchronizationSubject::Value {
                                    task: context.task,
                                    procedure: context.procedure.clone(),
                                    value: target,
                                },
                            );
                            continue;
                        }
                        let Some(target_row) = semantics.value(target) else {
                            unreachable!("validated assignment target exists");
                        };
                        let (crate::analyzer::semantic::SemanticValueKind::Address, Some(location)) =
                            (&target_row.kind, binding_location(semantics, value))
                        else {
                            continue;
                        };
                        synchronization_subjects.union(
                            LocalSynchronizationSubject::Location(LocalLocation {
                                task: context.task,
                                procedure: context.procedure.clone(),
                                location,
                            }),
                            LocalSynchronizationSubject::Value {
                                task: context.task,
                                procedure: context.procedure.clone(),
                                value: target,
                            },
                        );
                        continue;
                    }
                    SemanticEffect::MemoryStore {
                        location, value, ..
                    } => {
                        let local_location = LocalLocation {
                            task: context.task,
                            procedure: context.procedure.clone(),
                            location,
                        };
                        synchronization_subjects.note_location_store(local_location.clone());
                        if !matches!(
                            semantics
                                .memory_location(location)
                                .expect("validated memory store location exists")
                                .kind,
                            MemoryLocationKind::Index { .. }
                        ) {
                            synchronization_subjects.note_backing_location_store(
                                local_location,
                                LocalSynchronizationSubject::Value {
                                    task: context.task,
                                    procedure: context.procedure.clone(),
                                    value,
                                },
                            );
                        }
                    }
                    _ => {}
                }
                if let SemanticEffect::Synchronization { operation, subject } = event.effect {
                    pending_synchronizations.push(PendingIntrinsicSynchronization {
                        task: context.task,
                        procedure: context.procedure.clone(),
                        point: point.id,
                        operation,
                        subject,
                    });
                    continue;
                }
                let (location, mode, access_kind) = match event.effect {
                    SemanticEffect::MemoryLoad {
                        location,
                        result,
                        kind,
                    } => {
                        synchronization_subjects.union_backing(
                            LocalSynchronizationSubject::Location(LocalLocation {
                                task: context.task,
                                procedure: context.procedure.clone(),
                                location,
                            }),
                            LocalSynchronizationSubject::Value {
                                task: context.task,
                                procedure: context.procedure.clone(),
                                value: result,
                            },
                        );
                        if let MemoryLocationKind::Field { base, member } = &semantics
                            .memory_location(location)
                            .expect("validated memory load location exists")
                            .kind
                        {
                            synchronization_subjects.note_backing_field_load(
                                LocalSynchronizationSubject::Value {
                                    task: context.task,
                                    procedure: context.procedure.clone(),
                                    value: result,
                                },
                                LocalSynchronizationSubject::Value {
                                    task: context.task,
                                    procedure: context.procedure.clone(),
                                    value: *base,
                                },
                                member.clone(),
                            );
                        }
                        synchronization_subjects.union(
                            LocalSynchronizationSubject::Location(LocalLocation {
                                task: context.task,
                                procedure: context.procedure.clone(),
                                location,
                            }),
                            LocalSynchronizationSubject::Value {
                                task: context.task,
                                procedure: context.procedure.clone(),
                                value: result,
                            },
                        );
                        (location, ConcurrentAccessMode::Read, kind)
                    }
                    SemanticEffect::MemoryStore { location, kind, .. } => {
                        (location, ConcurrentAccessMode::Write, kind)
                    }
                    _ => continue,
                };
                if replay_summary_accesses {
                    continue;
                }
                let CanonicalizedAccess {
                    canonical,
                    resolved_location,
                    reasons,
                    index_alias_domain,
                    field_alias_domain,
                } = canonicalize_access(provider, &context, point.id, location, request)?;
                let local_identity = matches!(
                    semantics
                        .memory_location(location)
                        .expect("validated access location exists")
                        .kind,
                    MemoryLocationKind::LexicalCell { .. } | MemoryLocationKind::Capture { .. }
                );
                accesses.push(Access {
                    site: ConcurrentAccessSite {
                        task: context.task,
                        procedure: context.procedure.clone(),
                        point: point.id,
                        source: event.source,
                        mode,
                        access_kind,
                    },
                    local_location: Some(LocalLocation {
                        task: context.task,
                        procedure: context.procedure.clone(),
                        location,
                    }),
                    canonical,
                    resolved_location,
                    index_alias_domain,
                    field_alias_domain,
                    local_identity,
                    reasons,
                    atomic: false,
                });
            }
        }

        for call in semantics.call_sites() {
            let call_handle = context
                .procedure
                .call_site_handle(call.id)
                .expect("validated call belongs to its procedure");
            let (effects, reasons) = if provider.may_have_modeled_effects(&call_handle) {
                provider
                    .modeled_effects(&call_handle, request)?
                    .into_parts()
            } else {
                (Vec::new(), Vec::new())
            };
            let model_resolution_reasons = reasons
                .into_iter()
                .filter(|reason| {
                    matches!(
                        reason,
                        ConcurrencyOpenReason::UnresolvedTarget
                            | ConcurrencyOpenReason::AmbiguousTarget
                            | ConcurrencyOpenReason::UnsupportedSynchronization(_)
                            | ConcurrencyOpenReason::BudgetExhausted
                    )
                })
                .collect::<Vec<_>>();
            report
                .reasons
                .extend(model_resolution_reasons.iter().cloned());
            model_reasons_by_context
                .entry(context.clone())
                .or_default()
                .extend(model_resolution_reasons);
            modeled_by_context
                .entry(context.clone())
                .or_default()
                .extend(effects.iter().cloned().map(|effect| (call.point, effect)));
            let detached = call.invocation_mode == CallInvocationMode::Detached
                && call.execution_timing == ExecutionTiming::DifferentTask;
            let modeled_spawns = effects.iter().filter_map(|effect| match effect {
                ResolvedConcurrencyEffect::TaskSpawn { targets, group } => {
                    Some((targets.clone(), group.clone(), false))
                }
                _ => None,
            });
            let direct_targets = if detached {
                let (targets, reasons) =
                    resolve_targets(provider, &context.procedure, call.id, request)?.into_parts();
                report.reasons.extend(reasons);
                Some((targets, None, true))
            } else {
                None
            };
            for (targets, group, bind_invocation) in
                direct_targets.into_iter().chain(modeled_spawns)
            {
                for target in targets {
                    let child = TaskId(u32::try_from(tasks.len()).map_err(|_| {
                        SemanticProviderError::internal("concurrency task count exceeds u32")
                    })?);
                    let repeated = point_is_cyclic(semantics, call.point);
                    tasks.push(Task {
                        parent: Some(context.task),
                        entry_procedure: Some(target.clone()),
                        spawn_procedure: Some(context.procedure.clone()),
                        spawn_call: Some(call.id),
                        group: group.clone(),
                        repeated,
                        repetitions_serialized: false,
                    });
                    union_capture_locations(
                        &mut classes,
                        &mut synchronization_subjects,
                        &context,
                        child,
                        &target,
                        call.callee,
                    );
                    if bind_invocation {
                        bind_call_inputs(
                            &mut synchronization_subjects,
                            &context,
                            call,
                            child,
                            &target,
                            true,
                            provider,
                            request,
                        )?;
                    }
                    queue.push_back(ContextKey {
                        task: child,
                        procedure: target,
                    });
                }
            }

            if !detached {
                let (targets, reasons) =
                    resolve_targets(provider, &context.procedure, call.id, request)?.into_parts();
                let exact_target = reasons.is_empty() && targets.len() == 1;
                report.reasons.extend(reasons);
                for target in targets {
                    union_capture_locations(
                        &mut classes,
                        &mut synchronization_subjects,
                        &context,
                        context.task,
                        &target,
                        call.callee,
                    );
                    bind_call_inputs(
                        &mut synchronization_subjects,
                        &context,
                        call,
                        context.task,
                        &target,
                        false,
                        provider,
                        request,
                    )?;
                    let target_context = ContextKey {
                        task: context.task,
                        procedure: target,
                    };
                    if context_reaches(&synchronous_graph, &target_context, &context) {
                        let summarized_cycle = provider
                            .complete_summary(&context.procedure)
                            .zip(provider.complete_summary(&target_context.procedure))
                            .is_some_and(|(caller, callee)| {
                                caller.recursive_group().is_some()
                                    && caller.recursive_group() == callee.recursive_group()
                            });
                        if !summarized_cycle {
                            report
                                .reasons
                                .push(ConcurrencyOpenReason::RecursiveExpansion);
                        }
                        continue;
                    }
                    synchronous_graph
                        .entry(context.clone())
                        .or_default()
                        .push(target_context.clone());
                    if exact_target {
                        synchronous_calls.push(SynchronousCall {
                            caller: context.clone(),
                            point: call.point,
                            target: target_context.clone(),
                        });
                    }
                    queue.push_back(target_context);
                }
            }
        }
    }
    synchronization_subjects.connect_stable_backing_stores();
    resolve_modeled_subjects(
        &mut synchronization_subjects,
        &mut modeled_by_context,
        &mut tasks,
    );
    append_summary_accesses(
        &mut synchronization_subjects,
        pending_summary_accesses,
        &mut accesses,
    );
    canonicalize_bound_accesses(&mut synchronization_subjects, &mut accesses);
    for access in &mut accesses {
        let context = ContextKey {
            task: access.site.task,
            procedure: access.site.procedure.clone(),
        };
        if let Some(reasons) = model_reasons_by_context.get(&context) {
            access.reasons.extend(reasons.iter().cloned());
            access.reasons.sort();
            access.reasons.dedup();
        }
    }
    associate_wait_group_tasks(&mut tasks, &modeled_by_context, &synchronous_calls);
    append_atomic_accesses(&modeled_by_context, &mut accesses);
    let entry_locks = must_entry_locks(&modeled_by_context, &synchronous_calls);
    let lock_states = must_lock_states(&accesses, &modeled_by_context, &entry_locks);
    let synchronizations = resolve_intrinsic_synchronizations(
        provider,
        &mut synchronization_subjects,
        pending_synchronizations,
        &task_local_allocations,
        request,
    )?;

    compare_accesses(
        &tasks,
        &mut classes,
        AccessComparisonEvidence {
            modeled: &modeled_by_context,
            lock_states: &lock_states,
            synchronizations: &synchronizations,
            task_local_allocations: &task_local_allocations,
        },
        accesses,
        &mut report,
    );
    report.reasons.sort();
    report.reasons.dedup();
    Ok(report)
}

fn context_reaches(
    graph: &HashMap<ContextKey, Vec<ContextKey>>,
    origin: &ContextKey,
    target: &ContextKey,
) -> bool {
    let mut queue = VecDeque::from([origin.clone()]);
    let mut visited = HashSet::default();
    visited.insert(origin.clone());
    while let Some(context) = queue.pop_front() {
        if &context == target {
            return true;
        }
        for successor in graph.get(&context).into_iter().flatten() {
            if visited.insert(successor.clone()) {
                queue.push_back(successor.clone());
            }
        }
    }
    false
}

fn binding_location(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    binding: ValueId,
) -> Option<MemoryLocationId> {
    let mut matching = semantics.memory_locations().iter().filter_map(|location| {
        matches!(
            location.kind,
            MemoryLocationKind::LexicalCell { binding: candidate }
                | MemoryLocationKind::Capture {
                    binding: Some(candidate),
                    ..
                } if candidate == binding
        )
        .then_some(location.id)
    });
    let location = matching.next()?;
    assert!(
        matching.next().is_none(),
        "one semantic binding cannot own multiple local memory cells"
    );
    Some(location)
}

fn associate_wait_group_tasks(
    tasks: &mut [Task],
    modeled: &HashMap<ContextKey, Vec<(ProgramPointId, ResolvedConcurrencyEffect)>>,
    synchronous_calls: &[SynchronousCall],
) {
    #[derive(Debug, Clone)]
    struct Completion {
        task: TaskId,
        parent: TaskId,
        spawn_procedure: ProcedureHandle,
        spawn_point: ProgramPointId,
        group: ResolvedConcurrencySubject,
    }

    let completion_effects = must_completion_effects(modeled, synchronous_calls);
    let mut completions = Vec::new();
    for (index, task) in tasks.iter().enumerate().skip(1) {
        if task.group.is_some() {
            continue;
        }
        let (Some(parent), Some(entry), Some(spawn_procedure), Some(spawn_call)) = (
            task.parent,
            task.entry_procedure.as_ref(),
            task.spawn_procedure.as_ref(),
            task.spawn_call,
        ) else {
            continue;
        };
        let context = ContextKey {
            task: TaskId(u32::try_from(index).expect("task indices fit their validated IDs")),
            procedure: entry.clone(),
        };
        let Some(done) = completion_effects.get(&context) else {
            continue;
        };
        if done.len() != 1 {
            continue;
        }
        let group = done
            .values()
            .next()
            .expect("one completion effect was retained");
        let spawn_point = spawn_procedure
            .semantics()
            .call_site(spawn_call)
            .expect("task spawn call belongs to its procedure")
            .point;
        completions.push(Completion {
            task: context.task,
            parent,
            spawn_procedure: spawn_procedure.clone(),
            spawn_point,
            group: (*group).clone(),
        });
    }

    let mut groups = HashMap::<CanonicalConcurrencyLocation, Vec<Completion>>::default();
    for completion in completions {
        groups
            .entry(
                exact_subject(&completion.group)
                    .expect("completion groups were filtered to exact subjects")
                    .clone(),
            )
            .or_default()
            .push(completion);
    }
    for (canonical, completions) in groups {
        let parent = completions[0].parent;
        let spawn_procedure = completions[0].spawn_procedure.clone();
        let structurally_one_phase = completions.iter().all(|completion| {
            completion.parent == parent && completion.spawn_procedure == spawn_procedure
        });
        let context = ContextKey {
            task: parent,
            procedure: spawn_procedure.clone(),
        };
        let effects = modeled.get(&context).map(Vec::as_slice).unwrap_or_default();
        let adds = effects
            .iter()
            .filter_map(|(point, effect)| match effect {
                ResolvedConcurrencyEffect::WaitGroupAdd { group, delta }
                    if exact_subject(group) == Some(&canonical) =>
                {
                    Some((*point, *delta))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        let waits = effects
            .iter()
            .filter_map(|(point, effect)| match effect {
                ResolvedConcurrencyEffect::WaitGroupWait { group }
                    if exact_subject(group) == Some(&canonical) =>
                {
                    Some(*point)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        let exact_count = adds
            .iter()
            .try_fold(0_i64, |count, (_, delta)| {
                delta.and_then(|delta| (delta > 0).then_some(count + delta))
            })
            .is_some_and(|count| usize::try_from(count).ok() == Some(completions.len()));
        let exact_phase = structurally_one_phase
            && exact_count
            && waits.len() == 1
            && completions.iter().all(|completion| {
                adds.iter()
                    .all(|(add, _)| point_dominates(&spawn_procedure, *add, completion.spawn_point))
                    && point_dominates(&spawn_procedure, completion.spawn_point, waits[0])
            });
        for completion in completions {
            let task = &mut tasks[completion.task.0 as usize];
            task.repetitions_serialized = task.repeated
                && exact_phase
                && all_recurrences_cross_points(
                    &spawn_procedure,
                    completion.spawn_point,
                    &[waits[0]],
                );
            let mut group = completion.group;
            if !exact_phase {
                group
                    .reasons
                    .push(ConcurrencyOpenReason::AmbiguousSynchronization);
                group.reasons.sort();
                group.reasons.dedup();
            }
            task.group = Some(group);
        }
    }

    // When the parent phase is exact but child completion discovery is not,
    // retain the only structurally possible group as open. This prevents a
    // resolver gap at `Done` from becoming a proven race while preserving the
    // access pair and its synchronization uncertainty for review.
    for task in tasks.iter_mut().skip(1) {
        if task.group.is_some() {
            continue;
        }
        let (Some(parent), Some(spawn_procedure), Some(spawn_call)) =
            (task.parent, task.spawn_procedure.as_ref(), task.spawn_call)
        else {
            continue;
        };
        let spawn = spawn_procedure
            .semantics()
            .call_site(spawn_call)
            .expect("task spawn call belongs to its procedure")
            .point;
        let context = ContextKey {
            task: parent,
            procedure: spawn_procedure.clone(),
        };
        let Some(effects) = modeled.get(&context) else {
            continue;
        };
        let mut candidates =
            HashMap::<CanonicalConcurrencyLocation, ResolvedConcurrencySubject>::default();
        for (_, effect) in effects {
            let ResolvedConcurrencyEffect::WaitGroupAdd { group, .. } = effect else {
                continue;
            };
            let Some(canonical) = exact_subject(group) else {
                continue;
            };
            let has_add = effects.iter().any(|(point, effect)| {
                matches!(
                    effect,
                    ResolvedConcurrencyEffect::WaitGroupAdd { group, .. }
                        if exact_subject(group) == Some(canonical)
                            && point_dominates(spawn_procedure, *point, spawn)
                )
            });
            let has_wait = effects.iter().any(|(point, effect)| {
                matches!(
                    effect,
                    ResolvedConcurrencyEffect::WaitGroupWait { group }
                        if exact_subject(group) == Some(canonical)
                            && point_dominates(spawn_procedure, spawn, *point)
                )
            });
            if has_add && has_wait {
                candidates.insert(canonical.clone(), group.clone());
            }
        }
        if candidates.len() == 1 {
            let mut group = candidates
                .into_values()
                .next()
                .expect("one ambiguous WaitGroup candidate was retained");
            group
                .reasons
                .push(ConcurrencyOpenReason::AmbiguousSynchronization);
            task.group = Some(group);
        }
    }
}

fn must_completion_effects(
    modeled: &HashMap<ContextKey, Vec<(ProgramPointId, ResolvedConcurrencyEffect)>>,
    synchronous_calls: &[SynchronousCall],
) -> HashMap<ContextKey, HashMap<(ProcedureHandle, ProgramPointId), ResolvedConcurrencySubject>> {
    let mut summaries = HashMap::default();
    for (context, effects) in modeled {
        let summary = summaries
            .entry(context.clone())
            .or_insert_with(HashMap::default);
        for (point, effect) in effects {
            let ResolvedConcurrencyEffect::WaitGroupDone { group } = effect else {
                continue;
            };
            if exact_subject(group).is_some()
                && point_dominates(
                    &context.procedure,
                    *point,
                    context.procedure.semantics().normal_exit_point(),
                )
            {
                summary.insert((context.procedure.clone(), *point), group.clone());
            }
        }
    }
    loop {
        let mut changed = false;
        for edge in synchronous_calls {
            if !point_dominates(
                &edge.caller.procedure,
                edge.point,
                edge.caller.procedure.semantics().normal_exit_point(),
            ) {
                continue;
            }
            let propagated = summaries.get(&edge.target).cloned().unwrap_or_default();
            let caller = summaries
                .entry(edge.caller.clone())
                .or_insert_with(HashMap::default);
            for (effect, group) in propagated {
                changed |= caller.insert(effect, group).is_none();
            }
        }
        if !changed {
            break;
        }
    }
    summaries
}

fn resolve_modeled_subjects(
    classes: &mut SynchronizationSubjectClasses,
    modeled: &mut HashMap<ContextKey, Vec<(ProgramPointId, ResolvedConcurrencyEffect)>>,
    tasks: &mut [Task],
) {
    for (context, effects) in modeled.iter() {
        for (_, effect) in effects {
            for subject in modeled_effect_subjects(effect) {
                classes.mark_modeled_value(LocalSynchronizationSubject::Value {
                    task: context.task,
                    procedure: context.procedure.clone(),
                    value: subject.value,
                });
            }
        }
    }
    for (context, effects) in modeled {
        for (_, effect) in effects {
            for subject in modeled_effect_subjects_mut(effect) {
                resolve_modeled_subject(classes, context, subject);
            }
        }
    }
    for task in tasks.iter_mut().skip(1) {
        let (Some(parent), Some(procedure), Some(group)) = (
            task.parent,
            task.spawn_procedure.clone(),
            task.group.as_mut(),
        ) else {
            continue;
        };
        resolve_modeled_subject(
            classes,
            &ContextKey {
                task: parent,
                procedure,
            },
            group,
        );
    }
}

fn modeled_effect_subjects(effect: &ResolvedConcurrencyEffect) -> Vec<&ResolvedConcurrencySubject> {
    match effect {
        ResolvedConcurrencyEffect::TaskSpawn { group, .. } => group.iter().collect(),
        ResolvedConcurrencyEffect::TaskJoin { group }
        | ResolvedConcurrencyEffect::WaitGroupAdd { group, .. }
        | ResolvedConcurrencyEffect::WaitGroupDone { group }
        | ResolvedConcurrencyEffect::WaitGroupWait { group } => vec![group],
        ResolvedConcurrencyEffect::LockAcquire { lock, .. }
        | ResolvedConcurrencyEffect::LockRelease { lock, .. } => vec![lock],
        ResolvedConcurrencyEffect::Atomic { location, .. } => vec![location],
    }
}

fn modeled_effect_subjects_mut(
    effect: &mut ResolvedConcurrencyEffect,
) -> Vec<&mut ResolvedConcurrencySubject> {
    match effect {
        ResolvedConcurrencyEffect::TaskSpawn { group, .. } => group.iter_mut().collect(),
        ResolvedConcurrencyEffect::TaskJoin { group }
        | ResolvedConcurrencyEffect::WaitGroupAdd { group, .. }
        | ResolvedConcurrencyEffect::WaitGroupDone { group }
        | ResolvedConcurrencyEffect::WaitGroupWait { group } => vec![group],
        ResolvedConcurrencyEffect::LockAcquire { lock, .. }
        | ResolvedConcurrencyEffect::LockRelease { lock, .. } => vec![lock],
        ResolvedConcurrencyEffect::Atomic { location, .. } => vec![location],
    }
}

fn resolve_modeled_subject(
    classes: &mut SynchronizationSubjectClasses,
    context: &ContextKey,
    subject: &mut ResolvedConcurrencySubject,
) {
    let local = LocalSynchronizationSubject::Value {
        task: context.task,
        procedure: context.procedure.clone(),
        value: subject.value,
    };
    let canonical = match subject.identity {
        ConcurrencySubjectIdentity::Value => classes.canonical_capture_identity(local.clone()),
        ConcurrencySubjectIdentity::Backing => classes.canonical_backing_identity(local.clone()),
    };
    if let Some(canonical) = canonical {
        subject.canonical = Some(canonical);
        subject.reasons.clear();
    } else if let Some(canonical) =
        classes.stable_modeled_identity(LocalSynchronizationSubject::Value {
            task: context.task,
            procedure: context.procedure.clone(),
            value: subject.value,
        })
    {
        subject.canonical = Some(canonical);
        if subject.reasons.is_empty() {
            subject.reasons.push(ConcurrencyOpenReason::UnknownLocation);
        }
    }
}

fn append_atomic_accesses(
    modeled: &HashMap<ContextKey, Vec<(ProgramPointId, ResolvedConcurrencyEffect)>>,
    accesses: &mut Vec<Access>,
) {
    for (context, effects) in modeled {
        for (point, effect) in effects {
            let ResolvedConcurrencyEffect::Atomic {
                location,
                operation,
            } = effect
            else {
                continue;
            };
            let Some(canonical) = location.canonical.clone() else {
                continue;
            };
            let call = context
                .procedure
                .semantics()
                .call_sites()
                .iter()
                .find(|call| call.point == *point)
                .expect("a modeled atomic effect belongs to its source call");
            accesses.push(Access {
                site: ConcurrentAccessSite {
                    task: context.task,
                    procedure: context.procedure.clone(),
                    point: *point,
                    source: call.source,
                    mode: match operation {
                        ConcurrencyAtomicOperation::Load => ConcurrentAccessMode::Read,
                        ConcurrencyAtomicOperation::Store
                        | ConcurrencyAtomicOperation::ReadModifyWrite => {
                            ConcurrentAccessMode::Write
                        }
                    },
                    access_kind: MemoryAccessKind::Field,
                },
                local_location: Some(LocalLocation {
                    task: context.task,
                    procedure: context.procedure.clone(),
                    location: MemoryLocationId::new(u32::MAX),
                }),
                canonical: Some(canonical.clone()),
                resolved_location: ResolvedConcurrencyLocation::exact(canonical),
                index_alias_domain: None,
                field_alias_domain: None,
                local_identity: false,
                reasons: location.reasons.clone(),
                atomic: true,
            });
        }
    }
}

fn resolve_targets(
    provider: &impl ConcurrencyProvider,
    procedure: &ProcedureHandle,
    call: CallSiteId,
    request: &mut SemanticRequest<'_>,
) -> Result<ConcurrencyAnswer<Vec<ProcedureHandle>>, SemanticProviderError> {
    if let Some(targets) = provider.complete_call_targets(procedure, call) {
        return Ok(ConcurrencyAnswer::Proven(targets.to_vec()));
    }
    let row = procedure
        .semantics()
        .call_site(call)
        .expect("validated call belongs to its procedure");
    if let CallableTargetResolution::Proven(CallableTarget::Local(target)) = row.declared_targets {
        return Ok(ConcurrencyAnswer::Proven(vec![
            procedure
                .artifact()
                .procedure_handle(target)
                .expect("validated local target belongs to its artifact"),
        ]));
    }
    let handle = procedure
        .call_site_handle(call)
        .expect("validated call belongs to its procedure");
    provider.resolve_call(&handle, request)
}

fn canonicalize_access(
    provider: &impl ConcurrencyProvider,
    context: &ContextKey,
    point: ProgramPointId,
    location: MemoryLocationId,
    request: &mut SemanticRequest<'_>,
) -> Result<CanonicalizedAccess, SemanticProviderError> {
    let row = context
        .procedure
        .semantics()
        .memory_location(location)
        .expect("validated access location exists");
    match &row.kind {
        MemoryLocationKind::Static { member } => {
            let canonical =
                CanonicalConcurrencyLocation::new(format!("static:{member:?}"), "static");
            Ok(CanonicalizedAccess {
                canonical: Some(canonical.clone()),
                resolved_location: ResolvedConcurrencyLocation::exact(canonical),
                reasons: Vec::new(),
                index_alias_domain: None,
                field_alias_domain: None,
            })
        }
        MemoryLocationKind::LexicalCell { .. } | MemoryLocationKind::Capture { .. } => {
            Ok(CanonicalizedAccess {
                canonical: None,
                resolved_location: ResolvedConcurrencyLocation::unknown(),
                reasons: Vec::new(),
                index_alias_domain: None,
                field_alias_domain: None,
            })
        }
        MemoryLocationKind::Field { base, member } => {
            let (mut resolved_location, mut reasons) = provider
                .resolved_location(&context.procedure, point, location, request)?
                .into_parts();
            let mut canonical = resolved_location.exact_candidate().cloned();
            let (base_location, base_reasons) = provider
                .resolved_value(&context.procedure, point, *base, request)?
                .into_parts();
            let base = base_location.exact_candidate().cloned();
            if base_reasons.is_empty()
                && let Some(base) = base.as_ref()
            {
                let exact = exact_field_location(base, member);
                canonical = Some(exact.clone());
                resolved_location = ResolvedConcurrencyLocation::exact(exact);
                reasons.clear();
            } else {
                reasons.extend(base_reasons);
            }
            if canonical.is_none() {
                reasons.push(ConcurrencyOpenReason::UnknownLocation);
            }
            reasons.sort();
            reasons.dedup();
            Ok(CanonicalizedAccess {
                canonical,
                resolved_location,
                reasons,
                index_alias_domain: None,
                field_alias_domain: Some(FieldAliasDomain {
                    base,
                    member: member.clone(),
                }),
            })
        }
        MemoryLocationKind::Index {
            base,
            identity,
            constant_index,
            ..
        } => {
            let (mut resolved_location, mut reasons) = provider
                .resolved_location(&context.procedure, point, location, request)?
                .into_parts();
            let mut canonical = resolved_location.exact_candidate().cloned();
            let (base_location, base_reasons) = provider
                .resolved_value(&context.procedure, point, *base, request)?
                .into_parts();
            let base = base_location.exact_candidate().cloned();
            let base_is_exact = base_reasons.is_empty();
            let domain = base.map(|base| IndexAliasDomain {
                base,
                identity: *identity,
                constant_index: *constant_index,
            });
            if base_is_exact && let Some(exact) = domain.as_ref().and_then(exact_index_location) {
                canonical = Some(exact.clone());
                resolved_location = ResolvedConcurrencyLocation::exact(exact);
                reasons.clear();
            } else {
                reasons.extend(base_reasons);
            }
            if canonical.is_none() && domain.is_some() {
                reasons.push(ConcurrencyOpenReason::UnknownLocation);
            }
            reasons.sort();
            reasons.dedup();
            Ok(CanonicalizedAccess {
                canonical,
                resolved_location,
                reasons,
                index_alias_domain: domain,
                field_alias_domain: None,
            })
        }
    }
}

fn exact_field_location(
    base: &CanonicalConcurrencyLocation,
    member: &crate::analyzer::semantic::SemanticLocator,
) -> CanonicalConcurrencyLocation {
    CanonicalConcurrencyLocation::new(
        format!("{}/{}", base.identity, field_selector(member)),
        "field",
    )
}

fn field_selector(member: &crate::analyzer::semantic::SemanticLocator) -> String {
    format!("field:{}", SummaryLocationKey::from_locator(member))
}

fn exact_index_location(domain: &IndexAliasDomain) -> Option<CanonicalConcurrencyLocation> {
    let selector = match (domain.identity, domain.constant_index) {
        (IndexedLocationIdentity::Aggregate, _) => "aggregate".to_owned(),
        (IndexedLocationIdentity::Element, Some(index)) => index.to_string(),
        (IndexedLocationIdentity::Element, None) => return None,
    };
    Some(CanonicalConcurrencyLocation::new(
        format!("{}/index:{selector}", domain.base.identity),
        "index",
    ))
}

fn canonicalize_bound_accesses(
    classes: &mut SynchronizationSubjectClasses,
    accesses: &mut [Access],
) {
    for access in accesses {
        let Some(local_location) = access.local_location.as_ref() else {
            continue;
        };
        let row = access
            .site
            .procedure
            .semantics()
            .memory_location(local_location.location)
            .expect("validated concurrent access location exists");
        let (base, selector, indexed) = match &row.kind {
            MemoryLocationKind::Field { base, member } => {
                (*base, Some(field_selector(member)), None)
            }
            MemoryLocationKind::Index {
                base,
                constant_index,
                identity,
                ..
            } => {
                let selector = match (identity, constant_index) {
                    (IndexedLocationIdentity::Aggregate, _) => Some("index:aggregate".to_owned()),
                    (IndexedLocationIdentity::Element, Some(index)) => {
                        Some(format!("index:{index}"))
                    }
                    (IndexedLocationIdentity::Element, None) => None,
                };
                (*base, selector, Some((*identity, *constant_index)))
            }
            _ => continue,
        };
        let local_base = LocalSynchronizationSubject::Value {
            task: access.site.task,
            procedure: access.site.procedure.clone(),
            value: base,
        };
        let contains_formal = classes.contains_formal_binding(local_base.clone());
        let base = match &row.kind {
            MemoryLocationKind::Index { .. } => classes
                .canonical_backing_identity(local_base.clone())
                .or_else(|| classes.canonical_capture_identity(local_base)),
            _ => classes.canonical_capture_identity(local_base),
        };
        let Some(base) = base else {
            if contains_formal {
                access.canonical = None;
                access.resolved_location = ResolvedConcurrencyLocation::unknown();
                access.reasons.push(ConcurrencyOpenReason::UnknownLocation);
                access.reasons.sort();
                access.reasons.dedup();
                if let MemoryLocationKind::Field { member, .. } = &row.kind {
                    access.field_alias_domain = Some(FieldAliasDomain {
                        base: None,
                        member: member.clone(),
                    });
                }
                access.index_alias_domain = None;
            }
            continue;
        };
        if let MemoryLocationKind::Field { member, .. } = &row.kind {
            access.field_alias_domain = Some(FieldAliasDomain {
                base: Some(base.clone()),
                member: member.clone(),
            });
        }
        if let Some((identity, constant_index)) = indexed {
            access.index_alias_domain = Some(IndexAliasDomain {
                base: base.clone(),
                identity,
                constant_index,
            });
        }
        if let Some(selector) = selector {
            let canonical = CanonicalConcurrencyLocation::new(
                format!("{}/{selector}", base.identity),
                row.kind.label(),
            );
            access.canonical = Some(canonical.clone());
            access.resolved_location = ResolvedConcurrencyLocation::exact(canonical);
            access.reasons.clear();
        } else {
            access.canonical = None;
            access.resolved_location = ResolvedConcurrencyLocation::unknown();
            access.reasons = vec![ConcurrencyOpenReason::UnknownLocation];
        }
    }
}

fn append_summary_accesses(
    classes: &mut SynchronizationSubjectClasses,
    pending: Vec<PendingSummaryAccess>,
    accesses: &mut Vec<Access>,
) {
    for pending in pending {
        let SummaryConcurrencyEffectKind::Access { location, mode, .. } = pending.effect.kind()
        else {
            unreachable!("pending summary accesses contain only access effects");
        };
        let mut binding = SummaryConcurrencyBoundaryBinding::new();
        bind_summary_access_root(classes, &pending.context, location, &mut binding);
        let (resolved_location, reasons) =
            instantiate_summary_access_path(location, &binding).into_parts();
        let witness = pending
            .effect
            .witness()
            .expect("production access summaries retain a source witness");
        let (point, source, memory_location) = pending
            .context
            .procedure
            .semantics()
            .points()
            .iter()
            .flat_map(|point| point.events.iter().map(move |event| (point.id, event)))
            .enumerate()
            .find_map(|(ordinal, (point, event))| {
                let memory_location = match (&event.effect, mode) {
                    (
                        SemanticEffect::MemoryLoad { location, .. },
                        SummaryConcurrencyAccessMode::Read,
                    )
                    | (
                        SemanticEffect::MemoryStore { location, .. },
                        SummaryConcurrencyAccessMode::Write,
                    ) => *location,
                    _ => return None,
                };
                let mapping = pending
                    .context
                    .procedure
                    .semantics()
                    .source_mapping(event.source)
                    .expect("validated event retains its source mapping");
                let event_key = SummaryEventKey::from_concurrency_source(&mapping.locator, ordinal);
                (event_key == pending.effect.event()).then(|| {
                    let span = mapping.locator.anchor().span();
                    debug_assert_eq!(span.start_byte(), witness.start_byte());
                    debug_assert_eq!(span.end_byte(), witness.end_byte());
                    (point, event.source, memory_location)
                })
            })
            .expect("a complete summary witness names one live semantic event");
        let local_location = LocalLocation {
            task: pending.context.task,
            procedure: pending.context.procedure.clone(),
            location: memory_location,
        };
        let memory_location = pending
            .context
            .procedure
            .semantics()
            .memory_location(memory_location)
            .expect("summary witness access retains its live memory location");
        let local_identity = matches!(
            memory_location.kind,
            MemoryLocationKind::LexicalCell { .. } | MemoryLocationKind::Capture { .. }
        );
        let field_alias_domain = match &memory_location.kind {
            MemoryLocationKind::Field { member, .. } => Some(FieldAliasDomain {
                base: None,
                member: member.clone(),
            }),
            _ => None,
        };
        let canonical = (!local_identity)
            .then(|| resolved_location.exact_candidate().cloned())
            .flatten();
        let retain_boundary_location = canonical.is_some()
            && location.selectors().iter().any(|selector| {
                matches!(
                    selector,
                    SummaryConcurrencyAccessSelector::Aggregate
                        | SummaryConcurrencyAccessSelector::ConstantIndex(_)
                        | SummaryConcurrencyAccessSelector::Index(_)
                        | SummaryConcurrencyAccessSelector::AnyIndex
                )
            });
        let resolved_location = if local_identity {
            ResolvedConcurrencyLocation::unknown()
        } else {
            resolved_location
        };
        let reasons = if local_identity || retain_boundary_location {
            Vec::new()
        } else {
            reasons
        };
        let access_kind = match location.selectors().last() {
            Some(SummaryConcurrencyAccessSelector::Field(_)) => MemoryAccessKind::Field,
            Some(
                SummaryConcurrencyAccessSelector::Aggregate
                | SummaryConcurrencyAccessSelector::ConstantIndex(_)
                | SummaryConcurrencyAccessSelector::Index(_)
                | SummaryConcurrencyAccessSelector::AnyIndex,
            ) => MemoryAccessKind::Index,
            None => match location.root() {
                SummaryPort::Capture(_) => MemoryAccessKind::Capture,
                SummaryPort::Heap(_) => MemoryAccessKind::Static,
                _ => MemoryAccessKind::Field,
            },
        };
        accesses.push(Access {
            site: ConcurrentAccessSite {
                task: pending.context.task,
                procedure: pending.context.procedure,
                point,
                source,
                mode: match mode {
                    SummaryConcurrencyAccessMode::Read => ConcurrentAccessMode::Read,
                    SummaryConcurrencyAccessMode::Write => ConcurrentAccessMode::Write,
                },
                access_kind,
            },
            // An exact boundary-instantiated summary path is already
            // canonical. Keep its live location only when the path stayed
            // open (or names a local cell) so structured live analysis can
            // still refine it. Replaying an exact boundary path through its
            // local alias would discard stable selectors such as
            // receiver-field/aggregate.
            local_location: (!retain_boundary_location).then_some(local_location),
            canonical,
            resolved_location,
            index_alias_domain: None,
            field_alias_domain,
            local_identity,
            reasons,
            atomic: false,
        });
    }
}

fn bind_summary_access_root(
    classes: &mut SynchronizationSubjectClasses,
    context: &ContextKey,
    path: &SummaryConcurrencyAccessPath,
    binding: &mut SummaryConcurrencyBoundaryBinding,
) {
    let port = path.root();
    let subject = match port {
        SummaryPort::Receiver => context
            .procedure
            .semantics()
            .values()
            .iter()
            .find(|value| {
                matches!(
                    value.kind,
                    crate::analyzer::semantic::SemanticValueKind::Receiver { .. }
                )
            })
            .map(|value| LocalSynchronizationSubject::Value {
                task: context.task,
                procedure: context.procedure.clone(),
                value: value.id,
            }),
        SummaryPort::Parameter(ordinal) => context
            .procedure
            .semantics()
            .values()
            .iter()
            .find(|value| {
                matches!(
                    value.kind,
                    crate::analyzer::semantic::SemanticValueKind::Parameter {
                        ordinal: candidate,
                        ..
                    } if candidate == *ordinal
                )
            })
            .map(|value| LocalSynchronizationSubject::Value {
                task: context.task,
                procedure: context.procedure.clone(),
                value: value.id,
            }),
        SummaryPort::Capture(key) => context
            .procedure
            .semantics()
            .memory_locations()
            .iter()
            .find(|location| {
                matches!(location.kind, MemoryLocationKind::Capture { .. })
                    && context
                        .procedure
                        .semantics()
                        .source_mapping(location.source)
                        .is_some_and(|mapping| {
                            SummaryLocationKey::from_locator(&mapping.locator) == *key
                        })
            })
            .map(|location| {
                LocalSynchronizationSubject::Location(LocalLocation {
                    task: context.task,
                    procedure: context.procedure.clone(),
                    location: location.id,
                })
            }),
        SummaryPort::Heap(key) => {
            binding.bind_location(
                port.clone(),
                ConcurrencyAnswer::Proven(ResolvedConcurrencyLocation::exact(
                    CanonicalConcurrencyLocation::new(format!("heap:{key}"), "static"),
                )),
            );
            return;
        }
        SummaryPort::NormalReturn
        | SummaryPort::IndexedNormalReturn(_)
        | SummaryPort::ExceptionalReturn => None,
    };
    let uses_backing_identity = path.selectors().iter().any(|selector| {
        matches!(
            selector,
            SummaryConcurrencyAccessSelector::Aggregate
                | SummaryConcurrencyAccessSelector::ConstantIndex(_)
                | SummaryConcurrencyAccessSelector::Index(_)
                | SummaryConcurrencyAccessSelector::AnyIndex
        )
    });
    let mut reasons = subject
        .as_ref()
        .map(|subject| classes.formal_binding_reasons(subject.clone()))
        .unwrap_or_default();
    let location = subject.and_then(|subject| {
        if uses_backing_identity {
            classes
                .canonical_backing_identity(subject.clone())
                .or_else(|| classes.canonical_capture_identity(subject))
        } else {
            classes.canonical_capture_identity(subject)
        }
    });
    let location = if let Some(location) = location {
        let partial = ResolvedConcurrencyLocation::exact(location);
        if reasons.is_empty() {
            ConcurrencyAnswer::Proven(partial)
        } else {
            ConcurrencyAnswer::Open { partial, reasons }
        }
    } else {
        reasons.push(ConcurrencyOpenReason::UnknownLocation);
        reasons.sort();
        reasons.dedup();
        ConcurrencyAnswer::Open {
            partial: ResolvedConcurrencyLocation::unknown(),
            reasons,
        }
    };
    binding.bind_location(port.clone(), location);
}

fn union_capture_locations(
    classes: &mut LocationClasses,
    synchronization_subjects: &mut SynchronizationSubjectClasses,
    parent: &ContextKey,
    child_task: TaskId,
    child: &ProcedureHandle,
    _callable: ValueId,
) {
    // A local procedure ID identifies one lexical declaration. Its capture
    // rows are the environment slots for every evaluation of that declaration;
    // the spawn call's proven local target therefore selects them exactly even
    // when transparent callable-value assignments give the call a different
    // procedure-local `ValueId` than the creation event.
    for capture in parent
        .procedure
        .semantics()
        .captures()
        .iter()
        .filter(|capture| capture.target == child.id())
    {
        match capture.captured {
            CaptureSource::Location(source) => {
                let parent_location = LocalLocation {
                    task: parent.task,
                    procedure: parent.procedure.clone(),
                    location: source,
                };
                let child_location = LocalLocation {
                    task: child_task,
                    procedure: child.clone(),
                    location: capture.destination,
                };
                classes.union(parent_location.clone(), child_location.clone());
                let parent_subject = LocalSynchronizationSubject::Location(parent_location);
                synchronization_subjects.union(
                    parent_subject.clone(),
                    LocalSynchronizationSubject::Location(child_location),
                );
                synchronization_subjects.union_backing(
                    parent_subject.clone(),
                    LocalSynchronizationSubject::Location(LocalLocation {
                        task: child_task,
                        procedure: child.clone(),
                        location: capture.destination,
                    }),
                );
                synchronization_subjects.mark_captured_location(parent_subject);
            }
            CaptureSource::Value(source) => {
                let source = LocalSynchronizationSubject::Value {
                    task: parent.task,
                    procedure: parent.procedure.clone(),
                    value: source,
                };
                synchronization_subjects.union(
                    source.clone(),
                    LocalSynchronizationSubject::Location(LocalLocation {
                        task: child_task,
                        procedure: child.clone(),
                        location: capture.destination,
                    }),
                );
                synchronization_subjects.union_backing(
                    source.clone(),
                    LocalSynchronizationSubject::Location(LocalLocation {
                        task: child_task,
                        procedure: child.clone(),
                        location: capture.destination,
                    }),
                );
                synchronization_subjects.mark_captured_value(source);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn bind_call_inputs(
    classes: &mut SynchronizationSubjectClasses,
    caller: &ContextKey,
    call: &crate::analyzer::semantic::SemanticCallSite,
    target_task: TaskId,
    target: &ProcedureHandle,
    task_transfer: bool,
    provider: &impl ConcurrencyProvider,
    request: &mut SemanticRequest<'_>,
) -> Result<(), SemanticProviderError> {
    for formal in target.semantics().values() {
        let actual = match formal.kind {
            crate::analyzer::semantic::SemanticValueKind::Parameter { ordinal, .. } => call
                .arguments
                .get(usize::try_from(ordinal).expect("Go parameter ordinals fit usize"))
                .map(|argument| argument.value),
            crate::analyzer::semantic::SemanticValueKind::Receiver { dispatch: true } => {
                call.receiver
            }
            _ => None,
        };
        let Some(actual_value) = actual else {
            continue;
        };
        let actual = LocalSynchronizationSubject::Value {
            task: caller.task,
            procedure: caller.procedure.clone(),
            value: actual_value,
        };
        let formal_value = formal.id;
        let formal = LocalSynchronizationSubject::Value {
            task: target_task,
            procedure: target.clone(),
            value: formal_value,
        };
        classes.bind_backing_formal(formal.clone(), actual.clone());
        let mut binding_reasons = Vec::new();
        let canonicals = if let Some(canonical) = classes.bound_canonical_identity(actual.clone()) {
            vec![canonical]
        } else {
            let mut canonicals = Vec::new();
            for (task, procedure, value) in classes.equivalent_values(actual.clone()) {
                if task != caller.task || procedure != caller.procedure {
                    continue;
                }
                let (resolved, reasons) = provider
                    .resolved_value(&procedure, call.point, value, request)?
                    .into_parts();
                binding_reasons.extend(reasons);
                if binding_reasons.is_empty()
                    && let Some(canonical) = resolved.exact_candidate().cloned()
                    && !canonicals.contains(&canonical)
                {
                    canonicals.push(canonical);
                }
            }
            canonicals
        };
        binding_reasons.sort();
        binding_reasons.dedup();
        if !binding_reasons.is_empty() {
            classes.note_formal_binding_reasons(formal, binding_reasons);
            continue;
        }
        let [canonical] = canonicals.as_slice() else {
            // Go copies ordinary argument and receiver values. Only a proven
            // runtime object identity may cross this call boundary; equating
            // an otherwise identity-less aggregate with its formal would
            // conflate distinct struct copies in separate task instances.
            binding_reasons.push(ConcurrencyOpenReason::UnknownLocation);
            classes.note_formal_binding_reasons(formal, binding_reasons);
            continue;
        };
        classes.bind_canonical_value(actual.clone(), canonical.clone());
        if task_transfer {
            classes.mark_captured_value(actual.clone());
        }
        classes.bind_formal(formal, actual);
    }
    Ok(())
}

fn resolve_intrinsic_synchronizations(
    provider: &impl ConcurrencyProvider,
    classes: &mut SynchronizationSubjectClasses,
    pending: Vec<PendingIntrinsicSynchronization>,
    task_local_allocations: &HashMap<TaskId, HashSet<CanonicalConcurrencyLocation>>,
    request: &mut SemanticRequest<'_>,
) -> Result<Vec<IntrinsicSynchronization>, SemanticProviderError> {
    let mut resolved = Vec::new();
    for event in pending {
        let local = LocalSynchronizationSubject::Value {
            task: event.task,
            procedure: event.procedure.clone(),
            value: event.subject,
        };
        let (subject, reasons) =
            if let Some(subject) = classes.canonical_capture_identity(local.clone()) {
                (Some(subject), Vec::new())
            } else {
                provider
                    .canonical_value(&event.procedure, event.point, event.subject, request)?
                    .into_parts()
            };
        let fresh_allocation = classes.contains_fresh_allocation(local.clone())
            || subject.as_ref().is_some_and(|subject| {
                task_local_allocations
                    .values()
                    .any(|allocations| allocations.contains(subject))
            });
        let root_input = subject.is_none()
            && classes
                .equivalent_values(local)
                .into_iter()
                .any(|(task, procedure, value)| {
                    task == TaskId(0)
                        && procedure.semantics().value(value).is_some_and(|value| {
                            matches!(
                                value.kind,
                                crate::analyzer::semantic::SemanticValueKind::Parameter { .. }
                                    | crate::analyzer::semantic::SemanticValueKind::Receiver { .. }
                            ) || matches!(
                                &value.kind,
                                crate::analyzer::semantic::SemanticValueKind::LanguageDefined(
                                    kind
                                ) if kind.as_ref() == "go.context_done_formal_channel"
                            )
                        })
                });
        resolved.push(IntrinsicSynchronization {
            task: event.task,
            procedure: event.procedure,
            point: event.point,
            operation: event.operation,
            subject,
            fresh_allocation,
            root_input,
            reasons,
        });
    }
    Ok(resolved)
}

fn point_is_cyclic(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    point: ProgramPointId,
) -> bool {
    let mut queue = VecDeque::from([point]);
    let mut visited = HashSet::default();
    while let Some(current) = queue.pop_front() {
        for (_, successor) in
            crate::analyzer::semantic::cfg_algorithms::DenseBidirectionalGraph::successors(
                semantics, current,
            )
        {
            if successor == point && current != point {
                return true;
            }
            if visited.insert(successor) {
                queue.push_back(successor);
            }
        }
    }
    false
}

fn all_recurrences_cross_points(
    procedure: &ProcedureHandle,
    origin: ProgramPointId,
    required: &[ProgramPointId],
) -> bool {
    if required.is_empty() {
        return false;
    }
    let mut queue = VecDeque::new();
    let mut visited = HashSet::default();
    for (_, edge) in procedure.semantics().successor_edges(origin) {
        let successor = edge.target_point;
        if required.contains(&successor) {
            continue;
        }
        if successor == origin {
            return false;
        }
        if visited.insert(successor) {
            queue.push_back(successor);
        }
    }
    while let Some(point) = queue.pop_front() {
        for (_, edge) in procedure.semantics().successor_edges(point) {
            let successor = edge.target_point;
            if required.contains(&successor) {
                continue;
            }
            if successor == origin {
                return false;
            }
            if visited.insert(successor) {
                queue.push_back(successor);
            }
        }
    }
    true
}

struct AccessComparisonEvidence<'a> {
    modeled: &'a HashMap<ContextKey, Vec<(ProgramPointId, ResolvedConcurrencyEffect)>>,
    lock_states: &'a HashMap<ContextKey, HashMap<ProgramPointId, MustLockSet>>,
    synchronizations: &'a [IntrinsicSynchronization],
    task_local_allocations: &'a HashMap<TaskId, HashSet<CanonicalConcurrencyLocation>>,
}

fn compare_accesses(
    tasks: &[Task],
    classes: &mut LocationClasses,
    evidence: AccessComparisonEvidence<'_>,
    mut accesses: Vec<Access>,
    report: &mut ConcurrentAccessReport,
) {
    let AccessComparisonEvidence {
        modeled,
        lock_states,
        synchronizations,
        task_local_allocations,
    } = evidence;
    for access in &mut accesses {
        if access.canonical.is_none()
            && access.local_identity
            && let Some(local_location) = access.local_location.as_ref()
        {
            let root = classes.root(local_location.clone());
            let canonical = canonical_local_location(&root);
            access.canonical = Some(canonical.clone());
            access.resolved_location = ResolvedConcurrencyLocation::exact(canonical);
        }
    }
    for first_index in 0..accesses.len() {
        for second_index in first_index + 1..accesses.len() {
            let first = &accesses[first_index];
            let second = &accesses[second_index];
            if first.site.task == second.site.task
                || (first.site.mode == ConcurrentAccessMode::Read
                    && second.site.mode == ConcurrentAccessMode::Read)
            {
                continue;
            }
            let overlap = access_location_overlap(first, second);
            if overlap == AccessOverlap::Disjoint {
                continue;
            }
            if !tasks_may_parallel(tasks, first, second) {
                continue;
            }
            let (location, alias_open) = match overlap {
                AccessOverlap::Same(location) => (location, false),
                AccessOverlap::MayAlias(Some(location)) => (location, true),
                AccessOverlap::MayAlias(None) => continue,
                AccessOverlap::Disjoint => unreachable!("disjoint accesses were skipped"),
            };
            let relation = task_relation(tasks, first.site.task, second.site.task);
            let (ordering, ordering_reasons) =
                ordering(tasks, first, second, modeled, synchronizations);
            let protection = if first.atomic && second.atomic {
                ConcurrentProtection::AtomicOnly
            } else {
                compatible_lock_protection(first, second, lock_states)
            };
            let mut reasons = first.reasons.clone();
            reasons.extend(second.reasons.iter().cloned());
            reasons.extend(ordering_reasons);
            if alias_open {
                reasons.push(ConcurrencyOpenReason::UnknownLocation);
            }
            if protection == ConcurrentProtection::Open {
                reasons.push(ConcurrencyOpenReason::AmbiguousSynchronization);
            }
            reasons.sort();
            reasons.dedup();
            let proven = reasons.is_empty()
                && ordering != ConcurrentOrdering::Open
                && protection != ConcurrentProtection::Open;
            report.conflicts.push(ConcurrentAccessConflict {
                location,
                first: first.site.clone(),
                second: second.site.clone(),
                task_relation: relation,
                ordering,
                protection,
                proven,
                exhaustive: reasons.is_empty(),
                reasons,
            });
        }
    }

    // One spawn in a loop represents distinct runtime child instances. Only a
    // location rooted outside that child task (or a provider-canonical heap
    // location) is shared across those instances.
    for access in &accesses {
        if !tasks[access.site.task.0 as usize].repeated
            || tasks[access.site.task.0 as usize].repetitions_serialized
            || access.site.mode != ConcurrentAccessMode::Write
            || access.atomic
        {
            continue;
        }
        let root = access
            .local_location
            .as_ref()
            .map(|location| classes.root(location.clone()));
        let task_local_allocation = access_base(access).is_some_and(|base| {
            task_local_allocations
                .get(&access.site.task)
                .is_some_and(|allocations| allocations.contains(base))
        });
        if access.canonical.is_none()
            || (access.local_identity
                && root
                    .as_ref()
                    .is_some_and(|root| root.task == access.site.task))
            || task_local_allocation
        {
            continue;
        }
        let mut reasons = access.reasons.clone();
        if let Some(group) = &tasks[access.site.task.0 as usize].group {
            reasons.extend(group.reasons.iter().cloned());
        }
        reasons.sort();
        reasons.dedup();
        report.conflicts.push(ConcurrentAccessConflict {
            location: access.canonical.clone().expect("canonicalized above"),
            first: access.site.clone(),
            second: access.site.clone(),
            task_relation: ConcurrentTaskRelation::Repeated,
            ordering: ConcurrentOrdering::Unordered,
            protection: ConcurrentProtection::Unprotected,
            proven: reasons.is_empty(),
            exhaustive: reasons.is_empty(),
            reasons,
        });
    }
}

fn access_base(access: &Access) -> Option<&CanonicalConcurrencyLocation> {
    access
        .field_alias_domain
        .as_ref()
        .and_then(|domain| domain.base.as_ref())
        .or_else(|| {
            access
                .index_alias_domain
                .as_ref()
                .map(|domain| &domain.base)
        })
}

fn contextual_allocation_identity(
    task: TaskId,
    canonical: CanonicalConcurrencyLocation,
) -> CanonicalConcurrencyLocation {
    CanonicalConcurrencyLocation::new(
        format!(
            "task:{}/{identity}",
            task.get(),
            identity = canonical.identity
        ),
        canonical.kind,
    )
}

fn access_location_overlap(first: &Access, second: &Access) -> AccessOverlap {
    if let (Some(first), Some(second)) = (&first.canonical, &second.canonical)
        && first == second
    {
        return AccessOverlap::Same(first.clone());
    }
    if let (Some(first), Some(second)) = (
        first.index_alias_domain.as_ref(),
        second.index_alias_domain.as_ref(),
    ) {
        if first.base != second.base {
            return AccessOverlap::Disjoint;
        }
        match (first.identity, second.identity) {
            (IndexedLocationIdentity::Aggregate, IndexedLocationIdentity::Aggregate) => {
                return exact_index_location(first)
                    .map_or(AccessOverlap::Disjoint, AccessOverlap::Same);
            }
            (IndexedLocationIdentity::Element, IndexedLocationIdentity::Element) => {
                if let (Some(first_index), Some(second_index)) =
                    (first.constant_index, second.constant_index)
                {
                    return if first_index == second_index {
                        exact_index_location(first)
                            .map_or(AccessOverlap::Disjoint, AccessOverlap::Same)
                    } else {
                        AccessOverlap::Disjoint
                    };
                }
            }
            (IndexedLocationIdentity::Aggregate, IndexedLocationIdentity::Element)
            | (IndexedLocationIdentity::Element, IndexedLocationIdentity::Aggregate) => {}
        }
        return AccessOverlap::MayAlias(Some(CanonicalConcurrencyLocation::new(
            format!("{}/index:open", first.base.identity),
            "index",
        )));
    }
    let (Some(first), Some(second)) = (
        first.field_alias_domain.as_ref(),
        second.field_alias_domain.as_ref(),
    ) else {
        return first.resolved_location.overlap(&second.resolved_location);
    };
    if first.member.path() != second.member.path()
        || first.member.anchor() != second.member.anchor()
    {
        return AccessOverlap::Disjoint;
    }
    match (&first.base, &second.base) {
        (Some(first_base), Some(second_base)) if first_base == second_base => {
            AccessOverlap::Same(exact_field_location(first_base, &first.member))
        }
        (Some(_), Some(_)) => AccessOverlap::Disjoint,
        (None, None) | (None, Some(_)) | (Some(_), None) => {
            AccessOverlap::MayAlias(Some(CanonicalConcurrencyLocation::new(
                format!(
                    "field:open:{:?}:{:?}",
                    first.member.path(),
                    first.member.anchor()
                ),
                "field",
            )))
        }
    }
}

/// The canonical identity of one procedure-local memory location.
///
/// The procedure is named by its mount-free wire id, not by the
/// `SemanticArtifactKey` its durable key folds: this string is rendered as a
/// conflict row's `location_id`, which the shipped data-race policy groups by
/// and whose group key becomes the finding's identity. A mount-bearing
/// spelling would make every finding of a `--diff-base` run new, because the
/// base is exported to a temporary root.
fn canonical_local_location(location: &LocalLocation) -> CanonicalConcurrencyLocation {
    CanonicalConcurrencyLocation::new(
        format!(
            "local:{}:{}:{}",
            location.task.get(),
            crate::flow_state::procedure_wire_id(&location.procedure),
            location.location.get()
        ),
        location
            .procedure
            .semantics()
            .memory_location(location.location)
            .expect("canonical local location belongs to its procedure")
            .kind
            .label(),
    )
}

fn tasks_may_parallel(tasks: &[Task], first: &Access, second: &Access) -> bool {
    let first_task = &tasks[first.site.task.0 as usize];
    let second_task = &tasks[second.site.task.0 as usize];
    let parent_child = |parent: &Access, child_task: &Task| {
        if child_task.parent != Some(parent.site.task)
            || child_task.spawn_procedure.as_ref() != Some(&parent.site.procedure)
        {
            return None;
        }
        let spawn = child_task
            .spawn_call
            .and_then(|call| parent.site.procedure.semantics().call_site(call))?
            .point;
        Some(
            point_dominates(&parent.site.procedure, parent.site.point, spawn)
                || point_reaches(&parent.site.procedure, spawn, parent.site.point),
        )
    };
    if let Some(answer) = parent_child(first, second_task) {
        return answer;
    }
    if let Some(answer) = parent_child(second, first_task) {
        return answer;
    }
    if first_task.parent == second_task.parent
        && first_task.spawn_procedure == second_task.spawn_procedure
        && let (Some(procedure), Some(first_call), Some(second_call)) = (
            first_task.spawn_procedure.as_ref(),
            first_task.spawn_call,
            second_task.spawn_call,
        )
    {
        let first_spawn = procedure
            .semantics()
            .call_site(first_call)
            .expect("spawn call belongs to its procedure")
            .point;
        let second_spawn = procedure
            .semantics()
            .call_site(second_call)
            .expect("spawn call belongs to its procedure")
            .point;
        return first_spawn == second_spawn
            || point_reaches(procedure, first_spawn, second_spawn)
            || point_reaches(procedure, second_spawn, first_spawn);
    }
    true
}

fn task_relation(tasks: &[Task], first: TaskId, second: TaskId) -> ConcurrentTaskRelation {
    if tasks[first.0 as usize].repeated || tasks[second.0 as usize].repeated {
        return ConcurrentTaskRelation::Repeated;
    }
    if tasks[first.0 as usize].parent == Some(second)
        || tasks[second.0 as usize].parent == Some(first)
    {
        return ConcurrentTaskRelation::ParentChild;
    }
    if tasks[first.0 as usize].parent == tasks[second.0 as usize].parent {
        return ConcurrentTaskRelation::Siblings;
    }
    ConcurrentTaskRelation::Nested
}

fn ordering(
    tasks: &[Task],
    first: &Access,
    second: &Access,
    modeled: &HashMap<ContextKey, Vec<(ProgramPointId, ResolvedConcurrencyEffect)>>,
    synchronizations: &[IntrinsicSynchronization],
) -> (ConcurrentOrdering, Vec<ConcurrencyOpenReason>) {
    if access_before_spawn(tasks, first, second) || access_before_spawn(tasks, second, first) {
        return (ConcurrentOrdering::HappensBefore, Vec::new());
    }
    let forward_join = joined_before_access(tasks, first, second, modeled);
    let reverse_join = joined_before_access(tasks, second, first, modeled);
    if matches!(forward_join, ConcurrencyAnswer::Proven(true))
        || matches!(reverse_join, ConcurrencyAnswer::Proven(true))
    {
        return (ConcurrentOrdering::HappensBefore, Vec::new());
    }
    let forward = synchronized_before_access(first, second, synchronizations);
    let reverse = synchronized_before_access(second, first, synchronizations);
    if matches!(forward, ConcurrencyAnswer::Proven(true))
        || matches!(reverse, ConcurrencyAnswer::Proven(true))
    {
        return (ConcurrentOrdering::HappensBefore, Vec::new());
    }
    let mut reasons = Vec::new();
    for answer in [forward_join, reverse_join] {
        if let ConcurrencyAnswer::Open {
            reasons: open_reasons,
            ..
        } = answer
        {
            reasons.extend(open_reasons);
        }
    }
    if let ConcurrencyAnswer::Open {
        reasons: open_reasons,
        ..
    } = forward
    {
        reasons.extend(open_reasons);
    }
    if let ConcurrencyAnswer::Open {
        reasons: open_reasons,
        ..
    } = reverse
    {
        reasons.extend(open_reasons);
    }
    reasons.sort();
    reasons.dedup();
    if reasons.is_empty() {
        (ConcurrentOrdering::Unordered, reasons)
    } else {
        (ConcurrentOrdering::Open, reasons)
    }
}

fn synchronized_before_access(
    before: &Access,
    after: &Access,
    synchronizations: &[IntrinsicSynchronization],
) -> ConcurrencyAnswer<bool> {
    let senders = synchronizations
        .iter()
        .filter(|event| {
            event.task == before.site.task
                && event.procedure == before.site.procedure
                && matches!(
                    event.operation,
                    crate::analyzer::semantic::SynchronizationOperation::ChannelSend
                        | crate::analyzer::semantic::SynchronizationOperation::ChannelClose
                )
                && (event.point == before.site.point
                    || point_reaches(&before.site.procedure, before.site.point, event.point))
        })
        .collect::<Vec<_>>();
    let receivers = synchronizations
        .iter()
        .filter(|event| {
            event.task == after.site.task
                && event.procedure == after.site.procedure
                && event.operation
                    == crate::analyzer::semantic::SynchronizationOperation::ChannelReceive
        })
        .collect::<Vec<_>>();
    for sender in &senders {
        let Some(subject) = sender.subject.as_ref() else {
            continue;
        };
        let matching_sends = senders
            .iter()
            .filter_map(|send| (send.subject.as_ref() == Some(subject)).then_some(send.point))
            .collect::<HashSet<_>>();
        if !all_exit_paths_cross_points(&before.site.procedure, before.site.point, &matching_sends)
        {
            continue;
        }
        let matching_receives = receivers
            .iter()
            .filter_map(|receive| {
                (receive.subject.as_ref() == Some(subject)).then_some(receive.point)
            })
            .collect::<HashSet<_>>();
        if all_paths_cross_points(&after.site.procedure, after.site.point, &matching_receives) {
            return ConcurrencyAnswer::Proven(true);
        }
    }
    let possibly_ambiguous = senders.iter().any(|send| {
        let possibly_matching_sends = senders
            .iter()
            .filter_map(|candidate| {
                synchronization_subjects_may_match(send, candidate).then_some(candidate.point)
            })
            .collect::<HashSet<_>>();
        if !all_exit_paths_cross_points(
            &before.site.procedure,
            before.site.point,
            &possibly_matching_sends,
        ) {
            return false;
        }
        let possibly_matching = receivers
            .iter()
            .filter_map(|receive| {
                synchronization_subjects_may_match(send, receive).then_some(receive.point)
            })
            .collect::<HashSet<_>>();
        let identity_is_ambiguous = receivers.iter().any(|receive| {
            (send.subject.is_none() || receive.subject.is_none())
                && possibly_matching.contains(&receive.point)
        });
        identity_is_ambiguous
            && all_paths_cross_points(&after.site.procedure, after.site.point, &possibly_matching)
    });
    if !possibly_ambiguous {
        return ConcurrencyAnswer::Proven(false);
    }
    let mut reasons = senders
        .iter()
        .chain(&receivers)
        .flat_map(|event| event.reasons.iter().cloned())
        .collect::<Vec<_>>();
    if reasons.is_empty() {
        reasons.push(ConcurrencyOpenReason::AmbiguousSynchronization);
    }
    reasons.sort();
    reasons.dedup();
    ConcurrencyAnswer::Open {
        partial: false,
        reasons,
    }
}

fn synchronization_subjects_may_match(
    first: &IntrinsicSynchronization,
    second: &IntrinsicSynchronization,
) -> bool {
    if first.fresh_allocation && second.root_input || second.fresh_allocation && first.root_input {
        return false;
    }
    match (&first.subject, &second.subject) {
        (Some(first), Some(second)) => first == second,
        (None, _) | (_, None) => true,
    }
}

fn all_paths_cross_points(
    procedure: &ProcedureHandle,
    target: ProgramPointId,
    required: &HashSet<ProgramPointId>,
) -> bool {
    if required.is_empty() {
        return false;
    }
    let entry = procedure.semantics().entry_point();
    if target == entry || !point_reaches(procedure, entry, target) {
        return false;
    }
    if required.contains(&entry) {
        return true;
    }
    let mut queue = VecDeque::from([entry]);
    let mut visited = HashSet::default();
    visited.insert(entry);
    while let Some(point) = queue.pop_front() {
        for (_, edge) in procedure.semantics().successor_edges(point) {
            let successor = edge.target_point;
            if required.contains(&successor) {
                continue;
            }
            if successor == target {
                return false;
            }
            if visited.insert(successor) {
                queue.push_back(successor);
            }
        }
    }
    true
}

fn all_exit_paths_cross_points(
    procedure: &ProcedureHandle,
    origin: ProgramPointId,
    required: &HashSet<ProgramPointId>,
) -> bool {
    if required.is_empty() {
        return false;
    }
    if required.contains(&origin) {
        return true;
    }
    let semantics = procedure.semantics();
    let exits = [
        semantics.normal_exit_point(),
        semantics.exceptional_exit_point(),
    ];
    if exits.contains(&origin) {
        return false;
    }
    let mut queue = VecDeque::from([origin]);
    let mut visited = HashSet::default();
    visited.insert(origin);
    while let Some(point) = queue.pop_front() {
        for (_, edge) in semantics.successor_edges(point) {
            let successor = edge.target_point;
            if required.contains(&successor) {
                continue;
            }
            if exits.contains(&successor) {
                return false;
            }
            if visited.insert(successor) {
                queue.push_back(successor);
            }
        }
    }
    true
}

fn access_before_spawn(tasks: &[Task], parent: &Access, child: &Access) -> bool {
    let mut descendant = child.site.task;
    loop {
        let task = &tasks[descendant.0 as usize];
        let Some(owner) = task.parent else {
            return false;
        };
        if owner == parent.site.task {
            if task.spawn_procedure.as_ref() != Some(&parent.site.procedure) {
                return false;
            }
            let Some(spawn_call) = task.spawn_call else {
                return false;
            };
            let spawn = parent
                .site
                .procedure
                .semantics()
                .call_site(spawn_call)
                .expect("task spawn call belongs to its procedure")
                .point;
            return point_dominates(&parent.site.procedure, parent.site.point, spawn);
        }
        descendant = owner;
    }
}

fn joined_before_access(
    tasks: &[Task],
    child: &Access,
    parent: &Access,
    modeled: &HashMap<ContextKey, Vec<(ProgramPointId, ResolvedConcurrencyEffect)>>,
) -> ConcurrencyAnswer<bool> {
    let task = &tasks[child.site.task.0 as usize];
    if task.parent != Some(parent.site.task) {
        return ConcurrencyAnswer::Proven(false);
    }
    let Some(task_group) = task.group.as_ref() else {
        return ConcurrencyAnswer::Proven(false);
    };
    let context = ContextKey {
        task: parent.site.task,
        procedure: parent.site.procedure.clone(),
    };
    let Some(effects) = modeled.get(&context) else {
        return ConcurrencyAnswer::Proven(false);
    };
    let joins = effects
        .iter()
        .filter_map(|(point, effect)| {
            let group = match effect {
                ResolvedConcurrencyEffect::TaskJoin { group }
                | ResolvedConcurrencyEffect::WaitGroupWait { group } => group,
                _ => return None,
            };
            point_dominates(&parent.site.procedure, *point, parent.site.point).then_some(group)
        })
        .collect::<Vec<_>>();
    if joins.iter().any(|group| {
        group.canonical.is_some()
            && group.canonical == task_group.canonical
            && group
                .reasons
                .iter()
                .all(|reason| *reason == ConcurrencyOpenReason::UnknownLocation)
            && task_group
                .reasons
                .iter()
                .all(|reason| *reason == ConcurrencyOpenReason::UnknownLocation)
    }) {
        return ConcurrencyAnswer::Proven(true);
    }
    let possibly_matching = joins.iter().any(|group| {
        !group.reasons.is_empty()
            || !task_group.reasons.is_empty()
            || group.canonical.is_none()
            || task_group.canonical.is_none()
            || group.canonical == task_group.canonical
    });
    if !possibly_matching {
        return ConcurrencyAnswer::Proven(false);
    }
    let mut reasons = task_group.reasons.clone();
    reasons.extend(joins.iter().flat_map(|group| group.reasons.iter().cloned()));
    if reasons.is_empty() {
        reasons.push(ConcurrencyOpenReason::AmbiguousSynchronization);
    }
    reasons.sort();
    reasons.dedup();
    ConcurrencyAnswer::Open {
        partial: false,
        reasons,
    }
}

fn compatible_lock_protection(
    first: &Access,
    second: &Access,
    lock_states: &HashMap<ContextKey, HashMap<ProgramPointId, MustLockSet>>,
) -> ConcurrentProtection {
    let first_locks = must_locks_at(first, lock_states);
    let second_locks = must_locks_at(second, lock_states);
    for (lock, first_mode) in &first_locks.exact {
        let Some(second_mode) = second_locks.exact.get(lock) else {
            continue;
        };
        if *first_mode == ConcurrencyLockMode::Exclusive
            || *second_mode == ConcurrencyLockMode::Exclusive
        {
            return ConcurrentProtection::CompatibleLock;
        }
    }
    let first_modes = first_locks.exact.values().chain(first_locks.open.values());
    let second_modes = second_locks
        .exact
        .values()
        .chain(second_locks.open.values())
        .collect::<Vec<_>>();
    if first_modes.into_iter().any(|first_mode| {
        second_modes.iter().any(|second_mode| {
            (*first_mode == ConcurrencyLockMode::Exclusive
                || **second_mode == ConcurrencyLockMode::Exclusive)
                && (!first_locks.open.is_empty() || !second_locks.open.is_empty())
        })
    }) {
        return ConcurrentProtection::Open;
    }
    ConcurrentProtection::Unprotected
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct OpenLockIdentity {
    value: ValueId,
    canonical: Option<CanonicalConcurrencyLocation>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct MustLockSet {
    exact: HashMap<CanonicalConcurrencyLocation, ConcurrencyLockMode>,
    open: HashMap<OpenLockIdentity, ConcurrencyLockMode>,
}

impl MustLockSet {
    fn intersect_with(&mut self, other: &Self) {
        self.exact
            .retain(|lock, mode| other.exact.get(lock) == Some(mode));
        self.open
            .retain(|lock, mode| other.open.get(lock) == Some(mode));
    }
}

fn must_entry_locks(
    modeled: &HashMap<ContextKey, Vec<(ProgramPointId, ResolvedConcurrencyEffect)>>,
    synchronous_calls: &[SynchronousCall],
) -> HashMap<ContextKey, MustLockSet> {
    let targets = synchronous_calls
        .iter()
        .map(|call| call.target.clone())
        .collect::<HashSet<_>>();
    let mut roots = modeled
        .keys()
        .cloned()
        .chain(synchronous_calls.iter().map(|call| call.caller.clone()))
        .filter(|context| !targets.contains(context))
        .collect::<HashSet<_>>();
    if roots.is_empty() {
        roots.extend(targets.iter().cloned());
    }
    let mut entries = roots
        .iter()
        .cloned()
        .map(|context| (context, MustLockSet::default()))
        .collect::<HashMap<_, _>>();
    let mut queue = roots.into_iter().collect::<VecDeque<_>>();
    while let Some(context) = queue.pop_front() {
        let entry = entries
            .get(&context)
            .cloned()
            .expect("queued context retains an entry lock set");
        let effects = modeled.get(&context).map(Vec::as_slice).unwrap_or(&[]);
        for call in synchronous_calls
            .iter()
            .filter(|call| call.caller == context)
        {
            let candidate = must_locks_by_point(&context.procedure, effects, entry.clone())
                .remove(&call.point)
                .unwrap_or_default();
            match entries.entry(call.target.clone()) {
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(candidate);
                    queue.push_back(call.target.clone());
                }
                std::collections::hash_map::Entry::Occupied(mut entry) => {
                    let previous = entry.get().clone();
                    entry.get_mut().intersect_with(&candidate);
                    if entry.get() != &previous {
                        queue.push_back(call.target.clone());
                    }
                }
            }
        }
    }
    entries
}

fn must_lock_states(
    accesses: &[Access],
    modeled: &HashMap<ContextKey, Vec<(ProgramPointId, ResolvedConcurrencyEffect)>>,
    entry_locks: &HashMap<ContextKey, MustLockSet>,
) -> HashMap<ContextKey, HashMap<ProgramPointId, MustLockSet>> {
    accesses
        .iter()
        .map(|access| ContextKey {
            task: access.site.task,
            procedure: access.site.procedure.clone(),
        })
        .collect::<HashSet<_>>()
        .into_iter()
        .map(|context| {
            let effects = modeled.get(&context).map(Vec::as_slice).unwrap_or(&[]);
            let entry = entry_locks.get(&context).cloned().unwrap_or_default();
            let states = must_locks_by_point(&context.procedure, effects, entry);
            (context, states)
        })
        .collect()
}

fn must_locks_at<'a>(
    access: &Access,
    lock_states: &'a HashMap<ContextKey, HashMap<ProgramPointId, MustLockSet>>,
) -> &'a MustLockSet {
    let context = ContextKey {
        task: access.site.task,
        procedure: access.site.procedure.clone(),
    };
    lock_states
        .get(&context)
        .and_then(|states| states.get(&access.site.point))
        .expect("every compared access has a precomputed must-lock state")
}

fn must_locks_by_point(
    procedure: &ProcedureHandle,
    effects: &[(ProgramPointId, ResolvedConcurrencyEffect)],
    entry: MustLockSet,
) -> HashMap<ProgramPointId, MustLockSet> {
    let semantics = procedure.semantics();
    let mut incoming = HashMap::<ProgramPointId, Option<MustLockSet>>::default();
    for point in semantics.points() {
        incoming.insert(point.id, None);
    }
    incoming.insert(semantics.entry_point(), Some(entry));

    // Must facts form a descending finite lattice. Starting non-entry points
    // at top (`None`) and intersecting predecessor outputs reaches the exact
    // locks held on every path, including loops, without depending on call-row
    // storage order.
    let mut changed = true;
    while changed {
        changed = false;
        for point in semantics.points() {
            if point.id == semantics.entry_point() {
                continue;
            }
            let predecessors = semantics
                .predecessor_edges(point.id)
                .map(|(_, edge)| edge.source_point)
                .collect::<Vec<_>>();
            if predecessors.is_empty() {
                continue;
            }
            let mut candidate: Option<MustLockSet> = None;
            for predecessor in predecessors {
                let Some(mut state) = incoming.get(&predecessor).cloned().flatten() else {
                    // `None` is lattice top, not an empty lock set. Ignoring it
                    // lets an entry predecessor initialize a loop header; when
                    // the backedge becomes reachable its facts can only shrink
                    // the intersection toward the greatest fixed point.
                    continue;
                };
                apply_lock_effects_at(predecessor, effects, &mut state);
                candidate = Some(match candidate {
                    None => state,
                    Some(mut intersection) => {
                        intersection.intersect_with(&state);
                        intersection
                    }
                });
            }
            if incoming.get(&point.id) != Some(&candidate) {
                incoming.insert(point.id, candidate);
                changed = true;
            }
        }
    }
    incoming
        .into_iter()
        .map(|(point, locks)| (point, locks.unwrap_or_default()))
        .collect()
}

fn apply_lock_effects_at(
    point: ProgramPointId,
    effects: &[(ProgramPointId, ResolvedConcurrencyEffect)],
    locks: &mut MustLockSet,
) {
    for (_, effect) in effects
        .iter()
        .filter(|(effect_point, _)| *effect_point == point)
    {
        match effect {
            ResolvedConcurrencyEffect::LockAcquire { lock, mode } => {
                if let Some(lock) = exact_subject(lock) {
                    locks.exact.insert(lock.clone(), *mode);
                } else {
                    locks.open.insert(
                        OpenLockIdentity {
                            value: lock.value,
                            canonical: lock.canonical.clone(),
                        },
                        *mode,
                    );
                }
            }
            ResolvedConcurrencyEffect::LockRelease { lock, .. } => {
                if let Some(lock) = exact_subject(lock) {
                    locks.exact.remove(lock);
                } else {
                    locks.open.remove(&OpenLockIdentity {
                        value: lock.value,
                        canonical: lock.canonical.clone(),
                    });
                }
            }
            _ => {}
        }
    }
}

fn exact_subject(subject: &ResolvedConcurrencySubject) -> Option<&CanonicalConcurrencyLocation> {
    subject
        .reasons
        .is_empty()
        .then_some(subject.canonical.as_ref())
        .flatten()
}

fn point_dominates(
    procedure: &ProcedureHandle,
    candidate: ProgramPointId,
    target: ProgramPointId,
) -> bool {
    use crate::analyzer::semantic::cfg_algorithms::{
        CfgAlgorithmBudget, CfgAlgorithmRequest, dominators,
    };
    let cancellation = crate::cancellation::CancellationToken::default();
    let mut budget = CfgAlgorithmBudget::default();
    let mut request = CfgAlgorithmRequest::new(&mut budget, &cancellation);
    dominators(
        procedure.semantics(),
        procedure.semantics().entry_point(),
        &mut request,
    )
    .is_ok_and(|dominators| dominators.dominates(procedure.semantics(), candidate, target))
}

fn point_reaches(
    procedure: &ProcedureHandle,
    origin: ProgramPointId,
    target: ProgramPointId,
) -> bool {
    let mut queue = VecDeque::from([origin]);
    let mut visited = HashSet::default();
    visited.insert(origin);
    while let Some(point) = queue.pop_front() {
        for edge in procedure.semantics().successor_edges(point) {
            let successor = edge.1.target_point;
            if successor == target {
                return true;
            }
            if visited.insert(successor) {
                queue.push_back(successor);
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::analyzer::semantic::{
        ProcedureId, ProcedureKind, SemanticArtifact, SemanticBudget, SemanticWork,
    };
    use crate::analyzer::{AnalyzerConfig, Language, ProjectFile, WorkspaceAnalyzer};
    use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};

    fn exact_boundary_location(identity: &str) -> ConcurrencyAnswer<ResolvedConcurrencyLocation> {
        ConcurrencyAnswer::Proven(ResolvedConcurrencyLocation::exact(
            CanonicalConcurrencyLocation::new(identity, "object"),
        ))
    }

    #[test]
    fn summary_access_paths_preserve_caller_allocation_identity() {
        let parameter = SummaryPort::Parameter(0);
        let path = SummaryConcurrencyAccessPath::port(parameter.clone());
        let mut first_call = SummaryConcurrencyBoundaryBinding::new();
        first_call.bind_location(
            parameter.clone(),
            exact_boundary_location("allocation:first"),
        );
        let mut second_call = SummaryConcurrencyBoundaryBinding::new();
        second_call.bind_location(
            parameter.clone(),
            exact_boundary_location("allocation:second"),
        );
        let mut shared_call = SummaryConcurrencyBoundaryBinding::new();
        shared_call.bind_location(parameter, exact_boundary_location("allocation:first"));

        let first = instantiate_summary_access_path(&path, &first_call)
            .into_parts()
            .0;
        let second = instantiate_summary_access_path(&path, &second_call)
            .into_parts()
            .0;
        let shared = instantiate_summary_access_path(&path, &shared_call)
            .into_parts()
            .0;
        assert_eq!(first.overlap(&second), AccessOverlap::Disjoint);
        assert!(matches!(first.overlap(&shared), AccessOverlap::Same(_)));
    }

    #[test]
    fn summary_access_path_selectors_are_structured_and_fail_open() {
        let object = SummaryPort::Parameter(0);
        let index = SummaryPort::Parameter(1);
        let field = crate::dataflow::SummaryLocationKey::hash_bytes(b"field.value");
        let field_path = SummaryConcurrencyAccessPath::new(
            object.clone(),
            vec![SummaryConcurrencyAccessSelector::Field(field)],
        );
        let other_field_path = SummaryConcurrencyAccessPath::new(
            object.clone(),
            vec![SummaryConcurrencyAccessSelector::Field(
                crate::dataflow::SummaryLocationKey::hash_bytes(b"field.other"),
            )],
        );
        let dynamic_index_path = SummaryConcurrencyAccessPath::new(
            object.clone(),
            vec![SummaryConcurrencyAccessSelector::Index(index.clone())],
        );
        let constant_index_path = SummaryConcurrencyAccessPath::new(
            object.clone(),
            vec![SummaryConcurrencyAccessSelector::ConstantIndex(7)],
        );
        let mut exact = SummaryConcurrencyBoundaryBinding::new();
        exact.bind_location(object.clone(), exact_boundary_location("allocation:shared"));
        exact.bind_integer(index, 7);

        let field_location = instantiate_summary_access_path(&field_path, &exact)
            .into_parts()
            .0;
        let other_field_location = instantiate_summary_access_path(&other_field_path, &exact)
            .into_parts()
            .0;
        let dynamic_index = instantiate_summary_access_path(&dynamic_index_path, &exact)
            .into_parts()
            .0;
        let constant_index = instantiate_summary_access_path(&constant_index_path, &exact)
            .into_parts()
            .0;
        assert_eq!(
            field_location.overlap(&other_field_location),
            AccessOverlap::Disjoint
        );
        assert!(matches!(
            dynamic_index.overlap(&constant_index),
            AccessOverlap::Same(_)
        ));

        let mut unknown = SummaryConcurrencyBoundaryBinding::new();
        unknown.bind_location(object, exact_boundary_location("allocation:shared"));
        let (partial, reasons) =
            instantiate_summary_access_path(&dynamic_index_path, &unknown).into_parts();
        assert!(!partial.is_exhaustive());
        assert_eq!(
            partial.cardinality(),
            ConcurrencyObjectCardinality::Multiple
        );
        assert_eq!(reasons, vec![ConcurrencyOpenReason::UnknownLocation]);
    }

    struct LocalProvider;

    impl ConcurrencyProvider for LocalProvider {
        fn resolve_call(
            &self,
            _call: &CallSiteHandle,
            _request: &mut SemanticRequest<'_>,
        ) -> Result<ConcurrencyAnswer<Vec<ProcedureHandle>>, SemanticProviderError> {
            Ok(ConcurrencyAnswer::Open {
                partial: Vec::new(),
                reasons: vec![ConcurrencyOpenReason::UnresolvedTarget],
            })
        }

        fn modeled_effects(
            &self,
            _call: &CallSiteHandle,
            _request: &mut SemanticRequest<'_>,
        ) -> Result<ConcurrencyAnswer<Vec<ResolvedConcurrencyEffect>>, SemanticProviderError>
        {
            Ok(ConcurrencyAnswer::Proven(Vec::new()))
        }

        fn canonical_location(
            &self,
            _procedure: &ProcedureHandle,
            _point: ProgramPointId,
            _location: MemoryLocationId,
            _request: &mut SemanticRequest<'_>,
        ) -> Result<ConcurrencyAnswer<Option<CanonicalConcurrencyLocation>>, SemanticProviderError>
        {
            Ok(ConcurrencyAnswer::Open {
                partial: None,
                reasons: vec![ConcurrencyOpenReason::UnknownLocation],
            })
        }

        fn canonical_value(
            &self,
            _procedure: &ProcedureHandle,
            _point: ProgramPointId,
            _value: ValueId,
            _request: &mut SemanticRequest<'_>,
        ) -> Result<ConcurrencyAnswer<Option<CanonicalConcurrencyLocation>>, SemanticProviderError>
        {
            Ok(ConcurrencyAnswer::Open {
                partial: None,
                reasons: vec![ConcurrencyOpenReason::UnknownLocation],
            })
        }
    }

    struct OpenModelProvider;

    impl ConcurrencyProvider for OpenModelProvider {
        fn resolve_call(
            &self,
            call: &CallSiteHandle,
            request: &mut SemanticRequest<'_>,
        ) -> Result<ConcurrencyAnswer<Vec<ProcedureHandle>>, SemanticProviderError> {
            LocalProvider.resolve_call(call, request)
        }

        fn modeled_effects(
            &self,
            _call: &CallSiteHandle,
            _request: &mut SemanticRequest<'_>,
        ) -> Result<ConcurrencyAnswer<Vec<ResolvedConcurrencyEffect>>, SemanticProviderError>
        {
            Ok(ConcurrencyAnswer::Open {
                partial: Vec::new(),
                reasons: vec![ConcurrencyOpenReason::UnresolvedTarget],
            })
        }

        fn canonical_location(
            &self,
            procedure: &ProcedureHandle,
            point: ProgramPointId,
            location: MemoryLocationId,
            request: &mut SemanticRequest<'_>,
        ) -> Result<ConcurrencyAnswer<Option<CanonicalConcurrencyLocation>>, SemanticProviderError>
        {
            LocalProvider.canonical_location(procedure, point, location, request)
        }

        fn canonical_value(
            &self,
            procedure: &ProcedureHandle,
            point: ProgramPointId,
            value: ValueId,
            request: &mut SemanticRequest<'_>,
        ) -> Result<ConcurrencyAnswer<Option<CanonicalConcurrencyLocation>>, SemanticProviderError>
        {
            LocalProvider.canonical_value(procedure, point, value, request)
        }
    }

    struct SelfCallProvider;

    impl ConcurrencyProvider for SelfCallProvider {
        fn resolve_call(
            &self,
            call: &CallSiteHandle,
            _request: &mut SemanticRequest<'_>,
        ) -> Result<ConcurrencyAnswer<Vec<ProcedureHandle>>, SemanticProviderError> {
            Ok(ConcurrencyAnswer::Proven(vec![call.procedure().clone()]))
        }

        fn modeled_effects(
            &self,
            call: &CallSiteHandle,
            request: &mut SemanticRequest<'_>,
        ) -> Result<ConcurrencyAnswer<Vec<ResolvedConcurrencyEffect>>, SemanticProviderError>
        {
            LocalProvider.modeled_effects(call, request)
        }

        fn canonical_location(
            &self,
            procedure: &ProcedureHandle,
            point: ProgramPointId,
            location: MemoryLocationId,
            request: &mut SemanticRequest<'_>,
        ) -> Result<ConcurrencyAnswer<Option<CanonicalConcurrencyLocation>>, SemanticProviderError>
        {
            LocalProvider.canonical_location(procedure, point, location, request)
        }

        fn canonical_value(
            &self,
            procedure: &ProcedureHandle,
            point: ProgramPointId,
            value: ValueId,
            request: &mut SemanticRequest<'_>,
        ) -> Result<ConcurrencyAnswer<Option<CanonicalConcurrencyLocation>>, SemanticProviderError>
        {
            LocalProvider.canonical_value(procedure, point, value, request)
        }
    }

    struct Fixture {
        _project: BuiltInlineTestProject,
        workspace: WorkspaceAnalyzer,
        file: ProjectFile,
    }

    impl Fixture {
        fn new(source: &str) -> Self {
            let project = InlineTestProject::with_language(Language::Go)
                .file("main.go", source)
                .build();
            let file = project.file("main.go");
            let workspace = project.workspace_analyzer(AnalyzerConfig::default());
            Self {
                _project: project,
                workspace,
                file,
            }
        }

        fn artifact(&self) -> Arc<SemanticArtifact> {
            let cancellation = crate::cancellation::CancellationToken::default();
            let mut budget = SemanticBudget::default();
            let outcome = self
                .workspace
                .materialize_program_semantics(
                    &self.file,
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .expect("Go semantics materialize");
            Arc::clone(
                outcome
                    .available_value()
                    .expect("Go semantics are available"),
            )
        }

        fn analyze(&self) -> ConcurrentAccessReport {
            self.analyze_with(&LocalProvider)
        }

        fn analyze_with(&self, provider: &impl ConcurrencyProvider) -> ConcurrentAccessReport {
            let artifact = self.artifact();
            let root = artifact
                .procedures()
                .iter()
                .find(|procedure| {
                    procedure.kind() == ProcedureKind::Function
                        && procedure.lexical_parent().is_none()
                })
                .and_then(|procedure| artifact.procedure_handle(procedure.id()))
                .expect("fixture has one top-level function");
            let cancellation = crate::cancellation::CancellationToken::default();
            let mut budget = SemanticBudget::new(SemanticWork::default_limits()).unwrap();
            concurrent_access_conflicts(
                provider,
                &root,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .unwrap()
        }
    }

    #[test]
    fn unresolved_task_model_opens_the_retained_conflict() {
        let fixture = Fixture::new(
            r#"package sample

func race() int {
    value := 0
    go func() {
        value = 1
        unresolved()
    }()
    return value
}

func unresolved() {}
"#,
        );
        let report = fixture.analyze_with(&OpenModelProvider);
        assert!(
            report.conflicts.iter().any(|conflict| {
                !conflict.proven && conflict.reasons == [ConcurrencyOpenReason::UnresolvedTarget]
            }),
            "report: {report:#?}"
        );
    }

    #[test]
    fn stable_local_model_subjects_share_identity_but_reassignment_stays_open() {
        let fixture = Fixture::new(
            r#"package sample

func root() {}
"#,
        );
        let artifact = fixture.artifact();
        let procedure = artifact
            .procedure_handle(ProcedureId::new(0))
            .expect("fixture root procedure");
        let first = LocalSynchronizationSubject::Value {
            task: TaskId(0),
            procedure: procedure.clone(),
            value: ValueId::new(0),
        };
        let second = LocalSynchronizationSubject::Value {
            task: TaskId(0),
            procedure,
            value: ValueId::new(1),
        };

        let mut stable = SynchronizationSubjectClasses::default();
        stable.union(first.clone(), second.clone());
        stable.mark_modeled_value(first.clone());
        stable.mark_modeled_value(second.clone());
        stable.note_value_assignment(first.clone());
        assert!(
            stable.stable_modeled_identity(second.clone()).is_some(),
            "one stable local value may identify repeated modeled operations"
        );

        stable.note_value_assignment(second.clone());
        assert!(
            stable.stable_modeled_identity(first).is_none(),
            "a reassigned local cannot identify modeled operations across time"
        );
    }

    #[test]
    fn later_exact_backing_merge_discharges_earlier_formal_ambiguity() {
        let fixture = Fixture::new(
            r#"package sample

func root() {}
"#,
        );
        let artifact = fixture.artifact();
        let procedure = artifact
            .procedure_handle(ProcedureId::new(0))
            .expect("fixture root procedure");
        let subject = |value| LocalSynchronizationSubject::Value {
            task: TaskId(0),
            procedure: procedure.clone(),
            value: ValueId::new(value),
        };
        let formal = subject(0);
        let first = subject(1);
        let second = subject(2);
        let mut classes = SynchronizationSubjectClasses::default();

        classes.bind_backing_formal(formal.clone(), first.clone());
        classes.bind_backing_formal(formal.clone(), second.clone());
        classes.mark_captured_value(first.clone());
        assert!(
            classes.canonical_backing_identity(formal.clone()).is_none(),
            "distinct actuals keep the formal backing identity open"
        );

        classes.union_backing(first, second);
        assert!(
            classes.canonical_backing_identity(formal).is_some(),
            "a later exact capture or call edge discharges the stale ambiguity"
        );
    }

    #[test]
    fn synchronous_callees_inherit_only_common_caller_locks() {
        let fixture = Fixture::new(
            r#"package sample

func helper() {}
func locked() { helper() }
func unlocked() { helper() }
"#,
        );
        let artifact = fixture.artifact();
        let procedure = |name| {
            artifact
                .procedures()
                .iter()
                .find(|procedure| {
                    procedure
                        .locator()
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some(name)
                })
                .and_then(|procedure| artifact.procedure_handle(procedure.id()))
                .expect("fixture procedure")
        };
        let helper = procedure("helper");
        let locked = procedure("locked");
        let unlocked = procedure("unlocked");
        let helper_context = ContextKey {
            task: TaskId(0),
            procedure: helper,
        };
        let locked_context = ContextKey {
            task: TaskId(0),
            procedure: locked.clone(),
        };
        let unlocked_context = ContextKey {
            task: TaskId(0),
            procedure: unlocked.clone(),
        };
        let lock = CanonicalConcurrencyLocation::new("lock:shared", "object");
        let mut modeled = HashMap::default();
        modeled.insert(
            locked_context.clone(),
            vec![(
                locked.semantics().entry_point(),
                ResolvedConcurrencyEffect::LockAcquire {
                    lock: ResolvedConcurrencySubject {
                        value: ValueId::new(0),
                        canonical: Some(lock.clone()),
                        reasons: Vec::new(),
                        identity: ConcurrencySubjectIdentity::Value,
                    },
                    mode: ConcurrencyLockMode::Exclusive,
                },
            )],
        );
        let call = |caller: ContextKey| SynchronousCall {
            point: caller.procedure.semantics().call_sites()[0].point,
            caller,
            target: helper_context.clone(),
        };

        let locked_only = must_entry_locks(&modeled, &[call(locked_context.clone())]);
        assert_eq!(
            locked_only
                .get(&helper_context)
                .and_then(|locks| locks.exact.get(&lock)),
            Some(&ConcurrencyLockMode::Exclusive),
            "an exact synchronous callee inherits its caller's must-held lock"
        );

        let mixed = must_entry_locks(&modeled, &[call(locked_context), call(unlocked_context)]);
        assert!(
            mixed
                .get(&helper_context)
                .is_some_and(|locks| locks.exact.is_empty()),
            "a lock absent from one call path is not a callee must-lock"
        );
    }

    #[test]
    fn map_range_and_element_store_share_captured_backing_identity() {
        let report = Fixture::new(
            r#"package sample

func root(values map[int]int) {
    go func() {
        for range values {}
    }()
    values[0] = 1
}
"#,
        )
        .analyze();
        assert!(
            report.conflicts.iter().any(|conflict| {
                conflict.proven
                    && conflict.first.access_kind == MemoryAccessKind::Index
                    && conflict.second.access_kind == MemoryAccessKind::Index
            }),
            "report: {report:#?}"
        );
    }

    #[test]
    fn shared_callees_deduplicate_without_looking_recursive() {
        let report = Fixture::new(
            r#"package sample

func root() {
    helper()
    helper()
}

func helper() {}
"#,
        )
        .analyze();
        assert!(
            !report
                .reasons
                .contains(&ConcurrencyOpenReason::RecursiveExpansion),
            "report: {report:#?}"
        );
    }

    #[test]
    fn recursive_synchronous_expansion_remains_typed_open() {
        let fixture = Fixture::new(
            r#"package sample

func recursive() {
    recursive()
}
"#,
        );
        let report = fixture.analyze_with(&SelfCallProvider);
        assert!(
            report
                .reasons
                .contains(&ConcurrencyOpenReason::RecursiveExpansion),
            "report: {report:#?}"
        );
    }

    #[test]
    fn mutable_capture_write_races_with_parent_read_after_spawn() {
        let report = Fixture::new(
            r#"package sample

func race() int {
    value := 0
    go func() { value = 1 }()
    return value
}
"#,
        )
        .analyze();
        assert!(
            report.conflicts.iter().any(|conflict| {
                conflict.proven
                    && conflict.task_relation == ConcurrentTaskRelation::ParentChild
                    && conflict.ordering == ConcurrentOrdering::Unordered
            }),
            "report: {report:#?}"
        );
    }

    #[test]
    fn parent_accesses_before_spawn_are_happens_before() {
        let report = Fixture::new(
            r#"package sample

func ordered() {
    value := 0
    _ = value
    go func() { value = 1 }()
}
"#,
        )
        .analyze();
        assert!(
            report.conflicts.iter().any(|relation| relation.proven
                && relation.ordering == ConcurrentOrdering::HappensBefore),
            "report: {report:#?}"
        );
        assert!(
            report.conflicts.iter().all(|relation| {
                relation.ordering != ConcurrentOrdering::Unordered
                    || relation.protection != ConcurrentProtection::Unprotected
            }),
            "report: {report:#?}"
        );
    }

    #[test]
    fn sibling_and_nested_tasks_share_the_relayed_cell() {
        let siblings = Fixture::new(
            r#"package sample

func siblings() {
    value := 0
    go func() { value = 1 }()
    go func() { _ = value }()
}
"#,
        )
        .analyze();
        assert!(
            siblings.conflicts.iter().any(|conflict| {
                conflict.proven && conflict.task_relation == ConcurrentTaskRelation::Siblings
            }),
            "siblings: {siblings:#?}"
        );

        let nested = Fixture::new(
            r#"package sample

func nested() int {
    value := 0
    go func() {
        go func() { value = 1 }()
    }()
    return value
}
"#,
        )
        .analyze();
        assert!(
            nested.conflicts.iter().any(|conflict| {
                conflict.proven && conflict.task_relation == ConcurrentTaskRelation::Nested
            }),
            "nested: {nested:#?}"
        );
    }

    #[test]
    fn loop_spawn_instances_conflict_but_exclusive_spawns_do_not() {
        let repeated = Fixture::new(
            r#"package sample

func repeated() {
    value := 0
    for index := 0; index < 2; index++ {
        go func() { value++ }()
    }
}
"#,
        )
        .analyze();
        assert!(
            repeated.conflicts.iter().any(|conflict| {
                conflict.proven && conflict.task_relation == ConcurrentTaskRelation::Repeated
            }),
            "repeated: {repeated:#?}"
        );

        let exclusive = Fixture::new(
            r#"package sample

func exclusive(flag bool) {
    value := 0
    if flag {
        go func() { value = 1 }()
    } else {
        go func() { value = 2 }()
    }
}
"#,
        )
        .analyze();
        assert!(
            exclusive
                .conflicts
                .iter()
                .all(|relation| relation.ordering == ConcurrentOrdering::HappensBefore),
            "exclusive: {exclusive:#?}"
        );
    }

    #[test]
    fn bounded_location_domain_distinguishes_same_disjoint_and_may_alias() {
        let first = CanonicalConcurrencyLocation::new("heap:first", "object");
        let second = CanonicalConcurrencyLocation::new("heap:second", "object");
        let exact_first = ResolvedConcurrencyLocation::exact(first.clone());
        let exact_second = ResolvedConcurrencyLocation::exact(second.clone());
        assert_eq!(
            exact_first.overlap(&ResolvedConcurrencyLocation::exact(first.clone())),
            AccessOverlap::Same(first.clone())
        );
        assert_eq!(exact_first.overlap(&exact_second), AccessOverlap::Disjoint);

        let finite = ResolvedConcurrencyLocation::new(
            vec![first.clone(), second],
            true,
            ConcurrencyObjectCardinality::Multiple,
            ConcurrencyEscape::Published,
            ConcurrencyOwnership::Shared,
        );
        assert_eq!(
            exact_first.overlap(&finite),
            AccessOverlap::MayAlias(Some(first))
        );
    }

    #[test]
    fn non_exhaustive_disjoint_candidates_remain_may_alias() {
        let first = ResolvedConcurrencyLocation::new(
            vec![CanonicalConcurrencyLocation::new("heap:first", "object")],
            false,
            ConcurrencyObjectCardinality::Unknown,
            ConcurrencyEscape::Unknown,
            ConcurrencyOwnership::Unknown,
        );
        let second = ResolvedConcurrencyLocation::exact(CanonicalConcurrencyLocation::new(
            "heap:second",
            "object",
        ));
        assert_eq!(first.overlap(&second), AccessOverlap::MayAlias(None));
    }

    #[test]
    fn candidate_order_and_duplicates_do_not_change_location_identity() {
        let first = CanonicalConcurrencyLocation::new("heap:first", "object");
        let second = CanonicalConcurrencyLocation::new("heap:second", "object");
        let location = ResolvedConcurrencyLocation::new(
            vec![second.clone(), first.clone(), second],
            true,
            ConcurrencyObjectCardinality::Multiple,
            ConcurrencyEscape::Unknown,
            ConcurrencyOwnership::Unknown,
        );
        assert_eq!(
            location.candidates(),
            &[
                first,
                CanonicalConcurrencyLocation::new("heap:second", "object")
            ]
        );
        assert_eq!(location.exact_candidate(), None);
    }
}
