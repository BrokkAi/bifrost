//! Spawn-rooted concurrent task slices and exact ordinary-access conflicts.
//!
//! The solver owns task topology and capture-cell identity. Workspace target,
//! heap, and reviewed API-model answers enter through [`ConcurrencyProvider`]
//! so this crate does not depend on an analyzer implementation.

use std::collections::VecDeque;
use std::collections::hash_map::Entry;

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

/// One procedure activation in this bounded solve, independently of its task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InvocationId(u32);

impl InvocationId {
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

/// Creation evidence for a storage family within one bounded solve. An
/// invocation ID uniquely scopes its procedure-local allocation and cell IDs.
/// Repetition changes the number of objects, not the family that creates them.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ConcurrencyStorageFamily {
    Allocation {
        invocation: InvocationId,
        allocation: AllocationId,
    },
    LexicalCell {
        invocation: InvocationId,
        location: MemoryLocationId,
    },
    Static(CanonicalConcurrencyLocation),
}

/// A bounded heap answer for one source access.
///
/// `exhaustive` says that no unlisted runtime object can be reached. A single
/// candidate is exact only when it is exhaustive and its runtime object has
/// singleton cardinality. Escape and ownership are carried independently:
/// exact object identity does not by itself prove that an object is shared.
/// Distinct candidate names do not establish disjointness. That additionally
/// requires independently created storage roots, or a structural field/index
/// separation at the access comparison boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedConcurrencyLocation {
    candidates: Vec<CanonicalConcurrencyLocation>,
    exhaustive: bool,
    cardinality: ConcurrencyObjectCardinality,
    escape: ConcurrencyEscape,
    ownership: ConcurrencyOwnership,
    /// Independently created storage containing these locations. Symbolic
    /// referent names can prove equality without proving distinct storage.
    independent_storage: Option<ConcurrencyStorageFamily>,
    storage_path: Vec<SummaryConcurrencyAccessSelector>,
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
            independent_storage: None,
            storage_path: Vec::new(),
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

    /// Name storage whose creation proves it independent of other roots.
    /// This must not be used for an unbound reference or a loaded payload.
    fn independent(
        location: CanonicalConcurrencyLocation,
        family: ConcurrencyStorageFamily,
    ) -> Self {
        let mut resolved = Self::exact(location);
        resolved.independent_storage = Some(family);
        resolved
    }

    fn storage_is_disjoint(&self, other: &Self) -> bool {
        let (Some(first), Some(second)) = (&self.independent_storage, &other.independent_storage)
        else {
            return false;
        };
        if first != second {
            return true;
        }
        for (first, second) in self.storage_path.iter().zip(&other.storage_path) {
            if first == second {
                continue;
            }
            // A prefix can contain its sublocation. Only the first differing
            // pair of known field or element selectors proves separation.
            return matches!(
                (first, second),
                (
                    SummaryConcurrencyAccessSelector::Field(_),
                    SummaryConcurrencyAccessSelector::Field(_)
                ) | (
                    SummaryConcurrencyAccessSelector::Property(_),
                    SummaryConcurrencyAccessSelector::Property(_)
                ) | (
                    SummaryConcurrencyAccessSelector::ConstantIndex(_),
                    SummaryConcurrencyAccessSelector::ConstantIndex(_)
                )
            );
        }
        false
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
        if let (Some(first), Some(second)) = (self.exact_candidate(), other.exact_candidate())
            && first == second
        {
            return AccessOverlap::Same(first.clone());
        }
        let shared = self
            .candidates
            .iter()
            .find(|candidate| other.candidates.contains(candidate));
        if shared.is_none() && self.storage_is_disjoint(other) {
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
            SummaryConcurrencyAccessSelector::Property(property) => {
                (Some(format!("property:{property}")), "property")
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
        let rendered_selector = exact_selector.unwrap_or_else(|| "index:any".to_owned());
        let candidates = resolved
            .candidates()
            .iter()
            .map(|candidate| {
                CanonicalConcurrencyLocation::new(
                    format!("{}/{rendered_selector}", candidate.identity),
                    kind,
                )
            })
            .collect();
        resolved.storage_path.push(match selector {
            SummaryConcurrencyAccessSelector::Index(port) => binding.integer(port).map_or(
                SummaryConcurrencyAccessSelector::AnyIndex,
                SummaryConcurrencyAccessSelector::ConstantIndex,
            ),
            selector => selector.clone(),
        });
        resolved.candidates = candidates;
        resolved.exhaustive &= selector_is_exact;
        if !selector_is_exact {
            resolved.cardinality = ConcurrencyObjectCardinality::Multiple;
        }
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
    /// A producer walked this procedure and recorded that it did not model
    /// one of its memory accesses, naming the capability it fell short of.
    ///
    /// Go's lowering says so for a store through a pointer dereference, a
    /// multi-target assignment, and a dynamic index. An answer that omits an
    /// access nobody modelled is not a clean answer, it is an unasked
    /// question, and reporting it as an unknown *location* would name the
    /// wrong thing: the location is not unknown, it was never formed.
    UnmodeledMemory(Box<str>),
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

/// The field declaration one member locator stands for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedMemberDeclaration {
    /// The declaration's fully qualified name.
    pub name: String,
    /// Whether this locator anchors at that declaration rather than at a use
    /// of it. Only a declaration-anchored locator can stand for the field
    /// wherever it is reached.
    pub is_declaration_site: bool,
    /// The selected declaration is a function or method, rather than storage
    /// holding a callable value. Only exact declaration evidence may set this.
    pub is_callable: bool,
}

/// Exact workspace answers consumed by the task-slice solver.
pub trait ConcurrencyProvider {
    /// Number of storage instances a lexical binding can create within one
    /// procedure invocation. This describes the cell, not a pointer it holds.
    /// A loop-body declaration can create multiple cells even though the IR
    /// gives the declaration one identity. Missing lifetime facts stay open.
    fn lexical_cell_cardinality(
        &self,
        _procedure: &ProcedureHandle,
        _binding: ValueId,
    ) -> ConcurrencyObjectCardinality {
        ConcurrencyObjectCardinality::Unknown
    }

    /// The field declaration one member locator stands for, when the consumer
    /// can name it.
    ///
    /// A producer resolves a field only where it can type the receiver, so a
    /// capture inside a spawned closure keeps a per-procedure identity while
    /// the parent uses the declaration. The two then describe one field
    /// differently and their accesses are declared disjoint, silently.
    ///
    /// Abstaining keeps the producer's identity, which is the previous
    /// behavior, so a provider that cannot resolve declarations is unaffected.
    fn resolved_member_identity(
        &self,
        _member: &crate::analyzer::semantic::SemanticLocator,
    ) -> Option<ResolvedMemberDeclaration> {
        None
    }

    /// Positive value/reference semantics of a producer allocation. Unknown
    /// metadata must not be interpreted as evidence of inline storage.
    /// Only a reference result may retain the allocation's identity when
    /// stored in a local; an inline value copy creates distinct storage.
    fn allocation_binds_by_reference(
        &self,
        _procedure: &ProcedureHandle,
        _allocation: AllocationId,
    ) -> Option<bool> {
        None
    }

    /// Whether a loaded field carries a reference to separate storage.
    /// `Some(false)` proves inline value storage; absent metadata stays unknown.
    ///
    /// A copy of a struct copies its direct fields, so a write to one cannot
    /// reach the original. A pointer field inside that copy still addresses
    /// one object, so a write through it does, and refusing both alike turns
    /// a real race into silence.
    fn member_binds_by_reference(
        &self,
        _member: &crate::analyzer::semantic::SemanticLocator,
    ) -> Option<bool> {
        None
    }

    /// Whether binding this callee's receiver preserves the caller's object
    /// identity.
    ///
    /// Most languages pass a receiver by reference, so a callee's field write
    /// reaches the caller's object. Go copies it: a pointer receiver copies
    /// the pointer and still reaches the object, a value receiver copies the
    /// fields and cannot. Answering `true` for a value receiver reports the
    /// callee's write as racing the caller's read, which is a false positive.
    ///
    /// The default is `true` because passing by reference is the common case;
    /// a provider overrides it only for a language that copies.
    fn receiver_binds_by_reference(&self, _procedure: &ProcedureHandle) -> bool {
        true
    }

    /// Whether binding this callee's parameter preserves the caller's object
    /// identity, when the declaration says so either way.
    ///
    /// `None` means no declared type was recorded for that ordinal, which is
    /// the common case for a language whose adapter does not publish
    /// parameter types; the binding then keeps its previous behavior.
    /// `Some(false)` is a proof that the callee writes a copy, so the
    /// caller's object must not cross, and `Some(true)` names the caller's
    /// object the way the caller's own accesses name it.
    fn parameter_binding(&self, _procedure: &ProcedureHandle, _ordinal: u32) -> Option<bool> {
        None
    }

    /// Whether one declared normal result preserves the returned object's
    /// identity. Only positive reference evidence permits result binding;
    /// inline copies and unavailable metadata never imply an alias.
    fn result_binds_by_reference(
        &self,
        _procedure: &ProcedureHandle,
        _ordinal: u32,
    ) -> Option<bool> {
        None
    }

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
    pub invocation: InvocationId,
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
    entry_invocation: InvocationId,
    spawn_procedure: Option<ProcedureHandle>,
    spawn_invocation: Option<InvocationId>,
    spawn_call: Option<CallSiteId>,
    group: Option<ResolvedConcurrencySubject>,
    // Manual Done orders only effects before this event, unlike a reviewed
    // task join whose completion is the child's return.
    completion: Option<(InvocationId, ProgramPointId)>,
    repetition: Option<InvocationId>,
    repetitions_serialized: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ContextKey {
    task: TaskId,
    invocation: InvocationId,
    procedure: ProcedureHandle,
}

#[derive(Debug)]
struct Invocation {
    context: ContextKey,
    caller: Option<(InvocationId, CallSiteId)>,
    // The innermost repeating call that produces this activation. Keeping
    // its scope distinguishes fresh objects per call from shared inputs.
    repetition: Option<InvocationId>,
}

#[derive(Debug, Default)]
struct Invocations {
    entries: Vec<Invocation>,
}

impl Invocations {
    fn push(
        &mut self,
        task: TaskId,
        procedure: ProcedureHandle,
        caller: Option<(InvocationId, CallSiteId)>,
    ) -> ContextKey {
        let invocation = InvocationId(
            u32::try_from(self.entries.len()).expect("bounded invocation IDs fit u32"),
        );
        let context = ContextKey {
            task,
            invocation,
            procedure,
        };
        let repetition = caller.and_then(|(parent, call)| {
            let parent = &self.entries[parent.0 as usize];
            let semantics = parent.context.procedure.semantics();
            let point = semantics
                .call_site(call)
                .expect("invocation caller owns its call site")
                .point;
            if point_is_cyclic(semantics, point) {
                Some(invocation)
            } else {
                parent.repetition
            }
        });
        self.entries.push(Invocation {
            context: context.clone(),
            caller,
            repetition,
        });
        context
    }

    fn contains(&self, ancestor: InvocationId, mut descendant: InvocationId) -> bool {
        loop {
            if ancestor == descendant {
                return true;
            }
            let Some((parent, _)) = self.entries[descendant.0 as usize].caller else {
                return false;
            };
            descendant = parent;
        }
    }

    fn recursively_calls(&self, caller: InvocationId, target: &ProcedureHandle) -> bool {
        let task = self.entries[caller.0 as usize].context.task;
        let mut current = caller;
        loop {
            let entry = &self.entries[current.0 as usize];
            if entry.context.task != task {
                return false;
            }
            if entry.context.procedure == *target {
                return true;
            }
            let Some((parent, _)) = entry.caller else {
                return false;
            };
            current = parent;
        }
    }

    fn ancestry_points(
        &self,
        origin: InvocationId,
        origin_point: ProgramPointId,
    ) -> HashMap<InvocationId, ProgramPointId> {
        let task = self.entries[origin.0 as usize].context.task;
        let mut ancestors = HashMap::default();
        let mut current = origin;
        let mut point = origin_point;
        loop {
            let entry = &self.entries[current.0 as usize];
            ancestors.insert(current, point);
            let Some((parent, call)) = entry.caller else {
                break;
            };
            let caller = &self.entries[parent.0 as usize].context;
            if caller.task != task {
                break;
            }
            point = caller
                .procedure
                .semantics()
                .call_site(call)
                .expect("invocation caller owns its call site")
                .point;
            current = parent;
        }
        ancestors
    }

    /// Project two sites onto their common synchronous caller. Distinct
    /// activations of the same procedure meet at their caller's call sites.
    fn common_points(
        &self,
        first: InvocationId,
        first_point: ProgramPointId,
        second: InvocationId,
        second_point: ProgramPointId,
    ) -> Option<(&ContextKey, ProgramPointId, ProgramPointId)> {
        let task = self.entries[first.0 as usize].context.task;
        if self.entries[second.0 as usize].context.task != task {
            return None;
        }
        let ancestors = self.ancestry_points(first, first_point);
        let mut current = second;
        let mut point = second_point;
        loop {
            let entry = &self.entries[current.0 as usize];
            if let Some(first_point) = ancestors.get(&current) {
                return Some((&entry.context, *first_point, point));
            }
            let (parent, call) = entry.caller?;
            let caller = &self.entries[parent.0 as usize].context;
            if caller.task != task {
                return None;
            }
            point = caller
                .procedure
                .semantics()
                .call_site(call)
                .expect("invocation caller owns its call site")
                .point;
            current = parent;
        }
    }

    /// A synchronization inside a callee can order later caller work only
    /// when every returning path passes through it. Lift that obligation
    /// through each synchronous call until reaching the target's ancestry.
    fn required_points_before(
        &self,
        source: InvocationId,
        required: HashSet<ProgramPointId>,
        target: InvocationId,
        target_point: ProgramPointId,
    ) -> bool {
        let ancestors = self.ancestry_points(target, target_point);
        let mut common = source;
        loop {
            if let Some(target) = ancestors.get(&common) {
                return self
                    .required_points_in(source, required, common)
                    .is_some_and(|required| {
                        !required.contains(target)
                            && all_paths_cross_points(
                                &self.entries[common.0 as usize].context.procedure,
                                *target,
                                &required,
                            )
                    });
            }
            let Some((parent, _)) = self.entries[common.0 as usize].caller else {
                return false;
            };
            common = parent;
        }
    }

    /// Lift a mandatory event to a particular synchronous caller. A call
    /// point represents the event only if every normal return crosses it.
    fn required_points_in(
        &self,
        mut source: InvocationId,
        mut required: HashSet<ProgramPointId>,
        target: InvocationId,
    ) -> Option<HashSet<ProgramPointId>> {
        let task = self.entries[target.0 as usize].context.task;
        loop {
            let entry = &self.entries[source.0 as usize];
            if entry.context.task != task || required.is_empty() {
                return None;
            }
            if source == target {
                return Some(required);
            }
            if !all_paths_cross_points(
                &entry.context.procedure,
                entry.context.procedure.semantics().normal_exit_point(),
                &required,
            ) {
                return None;
            }
            let (parent, call) = entry.caller?;
            let caller = &self.entries[parent.0 as usize].context;
            let point = caller
                .procedure
                .semantics()
                .call_site(call)
                .expect("invocation caller owns its call site")
                .point;
            required = HashSet::from_iter([point]);
            source = parent;
        }
    }
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
    storage_origin: Option<CanonicalConcurrencyLocation>,
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
    /// The field declaration both sides stand for, when the consumer named it.
    ///
    /// `member` agrees only where both producers could type the receiver.
    /// `None` keeps the previous anchor comparison.
    declaration: Option<String>,
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
    invocation: InvocationId,
    procedure: ProcedureHandle,
    point: ProgramPointId,
    operation: crate::analyzer::semantic::SynchronizationOperation,
    subject: ValueId,
}

#[derive(Debug, Clone)]
struct IntrinsicSynchronization {
    task: TaskId,
    invocation: InvocationId,
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
    invocation: InvocationId,
    procedure: ProcedureHandle,
    location: MemoryLocationId,
}

/// The locator that stands for one field, and the rank that chose it.
#[derive(Debug)]
struct CanonicalMember {
    /// Ranks a declaration-anchored locator ahead of every use of the field,
    /// then the lowest locator key, so the choice never depends on the order
    /// the members were visited in.
    ///
    /// The declaration comes first because it is what a producer stores
    /// wherever it could type the receiver, and so what a reusable summary's
    /// own field selector already digests. Where no side could type the field
    /// -- two closures that each capture `p` and reach `p.mu` -- there is no
    /// declaration to prefer and any single choice unifies them.
    rank: (bool, (String, u32, u32)),
    locator: crate::analyzer::semantic::SemanticLocator,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum LocalSynchronizationSubject {
    Value {
        task: TaskId,
        invocation: InvocationId,
        procedure: ProcedureHandle,
        value: ValueId,
    },
    Location(LocalLocation),
}

/// Identity projection retains the bounded object answer and the allocation
/// whose inline storage it addresses. Following a reference payload discards
/// the container's lifetime; the payload needs its own allocation evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ConcurrencyIdentityFact {
    resolved: ResolvedConcurrencyLocation,
    storage_origin: Option<CanonicalConcurrencyLocation>,
}

impl ConcurrencyIdentityFact {
    fn allocation(
        canonical: CanonicalConcurrencyLocation,
        invocation: InvocationId,
        allocation: AllocationId,
    ) -> Self {
        Self {
            resolved: ResolvedConcurrencyLocation::independent(
                canonical.clone(),
                ConcurrencyStorageFamily::Allocation {
                    invocation,
                    allocation,
                },
            ),
            storage_origin: Some(canonical),
        }
    }

    fn canonical(&self) -> &CanonicalConcurrencyLocation {
        assert_eq!(self.resolved.candidates.len(), 1);
        &self.resolved.candidates[0]
    }

    fn project(&mut self, selector: SummaryConcurrencyAccessSelector, kind: &str) {
        let rendered = match &selector {
            SummaryConcurrencyAccessSelector::Field(field) => format!("field:{field}"),
            SummaryConcurrencyAccessSelector::Property(property) => {
                format!("property:{property}")
            }
            SummaryConcurrencyAccessSelector::Aggregate => "index:aggregate".to_owned(),
            SummaryConcurrencyAccessSelector::ConstantIndex(index) => format!("index:{index}"),
            _ => unreachable!("an exact projection requires a resolved selector"),
        };
        self.resolved.storage_path.push(selector);
        for candidate in &mut self.resolved.candidates {
            *candidate = CanonicalConcurrencyLocation::new(
                format!("{}/{rendered}", candidate.identity),
                kind,
            );
        }
    }

    fn reasons(&self) -> Vec<ConcurrencyOpenReason> {
        if self.resolved.exact_candidate().is_some() {
            Vec::new()
        } else {
            vec![ConcurrencyOpenReason::UnknownLocation]
        }
    }
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
    canonical_values: HashMap<LocalSynchronizationSubject, ConcurrencyIdentityFact>,
    identity_reasons: Vec<ConcurrencyOpenReason>,
    ambiguous: Vec<LocalSynchronizationSubject>,
    captured_values: Vec<LocalSynchronizationSubject>,
    captured_locations: Vec<LocalSynchronizationSubject>,
    modeled_values: Vec<LocalSynchronizationSubject>,
    /// Member locators whose field is declared as a pointer, so a chain
    /// through them survives a copy of the struct that holds them.
    reference_members: HashMap<(String, u32, u32), bool>,
    callable_members: HashSet<(String, u32, u32)>,
    cell_cardinalities: HashMap<LocalSynchronizationSubject, ConcurrencyObjectCardinality>,
    inline_cells: HashSet<LocalLocation>,
    /// Allocations are singleton within one activation, but a repeated
    /// activation can produce distinct containers holding shared or fresh
    /// reference payloads. A payload cannot inherit either lifetime claim.
    repeated_allocations: HashSet<CanonicalConcurrencyLocation>,
    /// The declaration each member locator names.
    member_declarations: HashMap<(String, u32, u32), String>,
    /// The one locator chosen to stand for each named field.
    ///
    /// A producer resolves a field only where it can type the receiver, so one
    /// field is denoted by its declaration at one use and by the use itself at
    /// another. Every site renders a field step by digesting a locator, and
    /// that digest folds the source anchor, so those two spell one field
    /// differently: their accesses are declared disjoint, and the two
    /// acquisitions of one lock stop matching, which reports the guarded write
    /// as a race. Composing every occurrence from one locator is what gives
    /// one field one name.
    declaration_locators: HashMap<String, CanonicalMember>,
    fresh_allocations: Vec<LocalSynchronizationSubject>,
    multiple_allocations: Vec<LocalSynchronizationSubject>,
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
        canonical: ConcurrencyIdentityFact,
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
    ) -> Vec<(TaskId, InvocationId, ProcedureHandle, ValueId)> {
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
                    invocation,
                    procedure,
                    value,
                } => Some((task, invocation, procedure, value)),
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

    fn canonical_modeled_identity(
        &mut self,
        context: &ContextKey,
        subject: &ResolvedConcurrencySubject,
    ) -> Option<ConcurrencyIdentityFact> {
        let local = LocalSynchronizationSubject::Value {
            task: context.task,
            invocation: context.invocation,
            procedure: context.procedure.clone(),
            value: subject.value,
        };
        match subject.identity {
            ConcurrencySubjectIdentity::Value => self.canonical_capture_identity(local),
            ConcurrencySubjectIdentity::Backing => self.canonical_backing_identity(local),
        }
    }

    fn canonical_capture_identity(
        &mut self,
        subject: LocalSynchronizationSubject,
    ) -> Option<ConcurrencyIdentityFact> {
        let root = self.root(subject.clone());
        match self.bound_canonical_identity(subject) {
            ConcurrencyAnswer::Proven(Some(canonical)) => {
                return Some(canonical);
            }
            ConcurrencyAnswer::Open { reasons, .. } => {
                self.identity_reasons.extend(reasons);
                return None;
            }
            ConcurrencyAnswer::Proven(None) => {}
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
        let cardinality = self.capture_cardinality(&root);
        if let LocalSynchronizationSubject::Location(location) = &root {
            let mut fact = Self::storage_identity(canonical_local_location(location), cardinality);
            if self.inline_cells.contains(location) {
                fact.resolved.independent_storage = Some(ConcurrencyStorageFamily::LexicalCell {
                    invocation: location.invocation,
                    location: location.location,
                });
            }
            return Some(fact);
        }
        let canonical =
            CanonicalConcurrencyLocation::new(format!("captured-value:{root:?}"), "object");
        Some(Self::storage_identity(canonical, cardinality))
    }

    fn capture_cardinality(
        &mut self,
        root: &LocalSynchronizationSubject,
    ) -> ConcurrencyObjectCardinality {
        let mut facts = self
            .cell_cardinalities
            .clone()
            .into_iter()
            .collect::<Vec<_>>();
        facts.extend(
            self.multiple_allocations
                .iter()
                .cloned()
                .map(|subject| (subject, ConcurrencyObjectCardinality::Multiple)),
        );
        facts
            .into_iter()
            .filter_map(|(subject, cardinality)| {
                (self.root(subject) == *root).then_some(cardinality)
            })
            .max()
            .unwrap_or(ConcurrencyObjectCardinality::Unknown)
    }

    fn backing_cardinality(
        &mut self,
        root: &LocalSynchronizationSubject,
    ) -> ConcurrencyObjectCardinality {
        let mut facts = self
            .cell_cardinalities
            .clone()
            .into_iter()
            .collect::<Vec<_>>();
        facts.extend(
            self.multiple_allocations
                .iter()
                .cloned()
                .map(|subject| (subject, ConcurrencyObjectCardinality::Multiple)),
        );
        facts
            .into_iter()
            .filter_map(|(subject, cardinality)| {
                (self.backing_root(subject) == *root).then_some(cardinality)
            })
            .max()
            .unwrap_or(ConcurrencyObjectCardinality::Unknown)
    }

    fn storage_identity(
        canonical: CanonicalConcurrencyLocation,
        cardinality: ConcurrencyObjectCardinality,
    ) -> ConcurrencyIdentityFact {
        ConcurrencyIdentityFact {
            resolved: ResolvedConcurrencyLocation::new(
                vec![canonical],
                cardinality != ConcurrencyObjectCardinality::Unknown,
                cardinality,
                ConcurrencyEscape::Unknown,
                ConcurrencyOwnership::Unknown,
            ),
            storage_origin: None,
        }
    }

    fn member_reference_binding(
        &self,
        member: &crate::analyzer::semantic::SemanticLocator,
    ) -> Option<bool> {
        self.reference_members
            .get(&member_locator_key(self.canonical_member(member)))
            .or_else(|| self.reference_members.get(&member_locator_key(member)))
            .copied()
    }

    fn leave_inline_storage(&self, fact: &mut ConcurrencyIdentityFact) {
        if fact
            .storage_origin
            .as_ref()
            .is_some_and(|origin| self.repeated_allocations.contains(origin))
        {
            fact.resolved.cardinality = ConcurrencyObjectCardinality::Unknown;
            fact.resolved.exhaustive = false;
        }
        fact.storage_origin = None;
        fact.resolved.independent_storage = None;
    }

    fn project_loaded_field(
        &self,
        fact: &mut ConcurrencyIdentityFact,
        member: &crate::analyzer::semantic::SemanticLocator,
    ) {
        // Only a proven inline field inherits the container's allocation
        // lifetime. Unknown types are not evidence of inline storage.
        if self.member_reference_binding(member) != Some(false) {
            self.leave_inline_storage(fact);
        }
        fact.project(
            SummaryConcurrencyAccessSelector::Field(SummaryLocationKey::from_locator(
                self.canonical_member(member),
            )),
            "object",
        );
    }

    /// The locator that stands for the field a member locator names.
    ///
    /// Answers the member itself where no declaration-anchored locator was
    /// observed, which is what a member no consumer can resolve gets, and is
    /// the naming every site already used.
    fn canonical_member<'a>(
        &'a self,
        member: &'a crate::analyzer::semantic::SemanticLocator,
    ) -> &'a crate::analyzer::semantic::SemanticLocator {
        self.member_declarations
            .get(&member_locator_key(member))
            .and_then(|name| self.declaration_locators.get(name))
            .map_or(member, |canonical| &canonical.locator)
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
    ) -> Option<ConcurrencyIdentityFact> {
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
                    let canonical = match &cursor {
                        LocalSynchronizationSubject::Location(location) => {
                            canonical_local_location(location)
                        }
                        LocalSynchronizationSubject::Value { .. } => {
                            CanonicalConcurrencyLocation::new(
                                format!("captured-backing:{cursor:?}"),
                                "object",
                            )
                        }
                    };
                    Some(Self::storage_identity(
                        canonical,
                        self.backing_cardinality(&cursor),
                    ))
                } else if self
                    .backing_formal_bindings
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
                    .into_iter()
                    .any(|formal| self.backing_root(formal) == cursor)
                {
                    let canonical = match &cursor {
                        LocalSynchronizationSubject::Location(location) => {
                            canonical_local_location(location)
                        }
                        LocalSynchronizationSubject::Value { .. } => {
                            CanonicalConcurrencyLocation::new(
                                format!("bound-backing:{cursor:?}"),
                                "object",
                            )
                        }
                    };
                    Some(Self::storage_identity(
                        canonical,
                        self.backing_cardinality(&cursor),
                    ))
                } else {
                    None
                }
            };
            if let Some(mut base) = base {
                for member in fields.iter().rev() {
                    self.project_loaded_field(&mut base, member);
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

    /// Name a value loaded out of another value's field, by composing the
    /// chain it was loaded through.
    ///
    /// A field load's result is neither captured nor freshly allocated, so it
    /// has no identity of its own, and an access based on it can never pair
    /// with anything. This walks back to a value that does have an identity
    /// and appends each field step, which is what
    /// [`Self::canonical_backing_identity`] already does for an indexed
    /// aggregate.
    ///
    /// It walks the ordinary equivalence classes rather than the backing
    /// ones, and that difference is the point. Backing identity deliberately
    /// crosses a copy, because a map or slice descriptor inside a copied
    /// struct still names one backing store. A direct field does not survive
    /// a copy, so composing over the backing classes equates a field of a
    /// value receiver's copy with the caller's own field, which was measured
    /// to prove a race Go cannot have. The ordinary classes carry only the
    /// bindings that preserve object identity, which is what the receiver and
    /// parameter rules decide.
    fn canonical_field_chain_identity(
        &mut self,
        subject: LocalSynchronizationSubject,
    ) -> Option<ConcurrencyIdentityFact> {
        let mut cursor = self.root(subject);
        let mut fields = Vec::new();
        let mut visited = HashSet::default();
        loop {
            if !visited.insert(cursor.clone()) {
                return None;
            }
            // A chain that has crossed a pointer field addresses one object
            // even where the struct holding that field was copied, which is
            // exactly what the backing classes model. Without this a value
            // receiver writing `o.in.n` through a pointer field reports
            // nothing, though it does race.
            let crossed_pointer = fields
                .iter()
                .any(|member| self.member_reference_binding(member) == Some(true));
            let named = self.canonical_capture_identity(cursor.clone()).or_else(|| {
                crossed_pointer
                    .then(|| self.canonical_backing_identity(cursor.clone()))
                    .flatten()
            });
            if let Some(mut base) = named {
                for member in fields.iter().rev() {
                    // Name an inner step exactly as the outermost step is
                    // named. Without this the chain composes the locator's
                    // own digest, which differs between the declaration the
                    // caller anchors at and the use the callee anchors at, so
                    // `b.tx.stats.CursorCount` agreed on its first and last
                    // steps and disagreed in the middle.
                    self.project_loaded_field(&mut base, member);
                }
                return Some(base);
            }
            // The recorded origins describe every field load, not only those
            // that reach a backing store, so one record serves both walks.
            let origins = self.backing_field_origins.clone();
            let mut origin: Option<BackingFieldOrigin> = None;
            for candidate in origins {
                if self.root(candidate.result.clone()) != cursor {
                    continue;
                }
                if let Some(existing) = origin.as_ref()
                    && (self.root(candidate.base.clone()) != self.root(existing.base.clone())
                        || candidate.member != existing.member)
                {
                    return None;
                }
                origin.get_or_insert(candidate);
            }
            let origin = origin?;
            fields.push(origin.member);
            cursor = self.root(origin.base);
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
    ) -> ConcurrencyAnswer<Option<ConcurrencyIdentityFact>> {
        let root = self.root(subject);
        let ambiguous = self.ambiguous.clone();
        if ambiguous
            .into_iter()
            .any(|candidate| self.root(candidate) == root)
        {
            return ConcurrencyAnswer::Open {
                partial: None,
                reasons: vec![ConcurrencyOpenReason::UnknownLocation],
            };
        }
        let canonical_values = self.canonical_values.clone();
        let mut canonicals = canonical_values
            .into_iter()
            .filter_map(|(candidate, canonical)| {
                (self.root(candidate) == root).then_some(canonical)
            });
        if let Some(canonical) = canonicals.next() {
            if canonicals.any(|candidate| candidate != canonical) {
                return ConcurrencyAnswer::Open {
                    partial: None,
                    reasons: vec![ConcurrencyOpenReason::UnknownLocation],
                };
            }
            return ConcurrencyAnswer::Proven(Some(canonical));
        }
        ConcurrencyAnswer::Proven(None)
    }
}

#[derive(Debug, Default)]
struct LocationClasses {
    parent: HashMap<LocalLocation, LocalLocation>,
    /// Destinations populated by a value snapshot, rather than references to
    /// an owner's lexical cell. Their environment instances are not modeled
    /// as singleton storage, but their storage family is known.
    value_captures: HashSet<LocalLocation>,
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
    let mut invocations = Invocations::default();
    let root_context = invocations.push(TaskId(0), root.clone(), None);
    let mut tasks = vec![Task {
        parent: None,
        entry_procedure: Some(root.clone()),
        entry_invocation: root_context.invocation,
        spawn_procedure: None,
        spawn_invocation: None,
        spawn_call: None,
        group: None,
        completion: None,
        repetition: None,
        repetitions_serialized: false,
    }];
    let mut queue = VecDeque::from([root_context]);
    let mut visited = HashSet::default();
    let mut accesses = Vec::new();
    let mut pending_summary_accesses = Vec::new();
    let mut pending_synchronizations = Vec::new();
    let mut synchronization_subjects = SynchronizationSubjectClasses::default();
    // The procedure a callable-valued value denotes, per context. A callee
    // named by a parameter is chosen by the caller, so lowering cannot resolve
    // it; the binding that supplies the parameter can, and the producer
    // records the flow from that binding to the callable value.
    // Allocation identities that name a reference rather than a value. Only
    // these may be carried onto the cell that stores them, because copying a
    // reference keeps one object while copying a value makes a second.
    let mut reference_allocations = HashSet::<CanonicalConcurrencyLocation>::default();
    let mut inline_allocations = HashSet::<CanonicalConcurrencyLocation>::default();
    let mut callable_values =
        HashMap::<(TaskId, InvocationId, ProcedureHandle, ValueId), ProcedureHandle>::default();
    let mut task_local_allocations =
        HashMap::<TaskId, HashSet<CanonicalConcurrencyLocation>>::default();
    let mut allocation_origins =
        HashMap::<CanonicalConcurrencyLocation, AllocationOrigin>::default();
    let mut classes = LocationClasses::default();
    // The formal each lexical cell was bound with, for the cells whose body
    // never assigns them. Kept apart from `location_stores` so that a cell the
    // body does assign keeps counting only its own writes.
    let mut formal_bound_cells = HashMap::<LocalLocation, LocalSynchronizationSubject>::default();
    let mut report = ConcurrentAccessReport::default();
    let mut modeled_by_context =
        HashMap::<ContextKey, Vec<(ProgramPointId, ResolvedConcurrencyEffect)>>::default();
    let mut model_reasons_by_context = HashMap::<ContextKey, Vec<ConcurrencyOpenReason>>::default();
    let mut synchronous_calls = Vec::new();
    let mut binding_cardinalities = HashMap::default();

    while let Some(context) = queue.pop_front() {
        if !visited.insert(context.clone()) {
            continue;
        }
        if request.cancellation.is_cancelled() {
            report.reasons.push(ConcurrencyOpenReason::BudgetExhausted);
            break;
        }
        let semantics = context.procedure.semantics();
        // Materialization can be precharged, but activation-specific replay
        // is new retained work even when the body or summary is reused.
        if request
            .budget
            .charge(crate::analyzer::semantic::SemanticWork {
                nested_entries: 1
                    + semantics.values().len()
                    + semantics.memory_locations().len()
                    + semantics
                        .points()
                        .iter()
                        .map(|point| point.events.len())
                        .sum::<usize>(),
                ..crate::analyzer::semantic::SemanticWork::default()
            })
            .is_err()
        {
            report.reasons.push(ConcurrencyOpenReason::BudgetExhausted);
            break;
        }
        // A closure that captures a parameter or receiver makes the producer
        // hold it in a lexical cell, and where the body never assigns that
        // formal the cell's only write is the call that bound it. A binding
        // is not a body statement, so no `MemoryStore` reports it and the
        // cell was left with no recorded store at all: it never joined the
        // formal's class, carried no identity, and every access reaching
        // through it resolved to nothing -- silently, because a location with
        // no name is not a gap any step can report.
        //
        // Record the binding separately rather than as a store. Counting it
        // as one would make a cell the body *does* assign look written twice
        // and lose the identity it already had, which was measured: cache2go
        // stopped reporting its own race.
        for location in semantics.memory_locations() {
            let binding = match location.kind {
                MemoryLocationKind::LexicalCell { binding }
                | MemoryLocationKind::Capture {
                    binding: Some(binding),
                    ..
                } => binding,
                _ => continue,
            };
            let Some(bound) = semantics.value(binding) else {
                continue;
            };
            if !matches!(
                bound.kind,
                crate::analyzer::semantic::SemanticValueKind::Parameter { .. }
                    | crate::analyzer::semantic::SemanticValueKind::Receiver { .. }
            ) {
                continue;
            }
            let cell = LocalLocation {
                task: context.task,
                invocation: context.invocation,
                procedure: context.procedure.clone(),
                location: location.id,
            };
            formal_bound_cells.insert(
                cell,
                LocalSynchronizationSubject::Value {
                    task: context.task,
                    invocation: context.invocation,
                    procedure: context.procedure.clone(),
                    value: binding,
                },
            );
        }
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

        // A producer that walked this body and could not model one of its
        // memory accesses says so here. Omitting the access it never formed
        // and still calling the answer clean is the false clean this analysis
        // exists to avoid, so the gap becomes an open reason.
        for gap in semantics.gaps() {
            // `Assignments` is the capability Go falls short of when it says
            // "indirect assignment write is not yet lowered", which is the
            // write this analysis would otherwise omit in silence.
            //
            // Both halves of the test are needed, and each near miss is
            // instructive. The memory capabilities look apt but are not: a
            // mutex-protected fixture with no indirect write carries a
            // `FieldMemory` gap saying a field's struct declaration identity
            // is unresolved, which is about naming a field rather than
            // omitting a write, and admitting it opened four correct answers.
            // `HeapWrite` alone is not enough either, because the
            // `ConcurrentSpawn` gap every goroutine carries claims it too.
            // Within `Assignments` it is exactly the right question: the
            // indirect write gap is `subject=value` and claims a heap write,
            // while the multi-target assignment gap beside it is
            // `subject=point` and claims none. `a, b := 0, 0` is ordinary Go,
            // so opening on that would open nearly every real answer.
            if gap.capability == crate::analyzer::semantic::SemanticCapability::Assignments
                && gap
                    .impacts
                    .contains(crate::analyzer::semantic::SemanticGapImpact::HeapWrite)
            {
                report.reasons.push(ConcurrencyOpenReason::UnmodeledMemory(
                    gap.capability.label().into(),
                ));
            }
        }

        let allocation_cyclic_points = if semantics.allocations().is_empty() {
            Some(HashSet::default())
        } else if semantics.gaps().iter().any(|gap| {
            gap.capability == crate::analyzer::semantic::SemanticCapability::NormalControlFlow
        }) {
            None
        } else if request
            .budget
            .charge(crate::analyzer::semantic::SemanticWork {
                program_points: semantics.points().len(),
                control_edges: semantics.control_edges().len(),
                ..crate::analyzer::semantic::SemanticWork::default()
            })
            .is_err()
        {
            report.reasons.push(ConcurrencyOpenReason::BudgetExhausted);
            None
        } else {
            use crate::analyzer::semantic::cfg_algorithms::{
                CfgAlgorithmBudget, CfgAlgorithmError, CfgAlgorithmRequest, loop_regions,
            };
            let mut budget = CfgAlgorithmBudget::default();
            match loop_regions(
                semantics,
                &mut CfgAlgorithmRequest::new(&mut budget, request.cancellation),
            ) {
                Ok(regions) => Some(
                    regions
                        .regions
                        .into_iter()
                        .flat_map(|region| region.members)
                        .collect::<HashSet<_>>(),
                ),
                Err(CfgAlgorithmError::Cancelled { .. }) => {
                    report.reasons.push(ConcurrencyOpenReason::BudgetExhausted);
                    None
                }
                Err(CfgAlgorithmError::ExceededBudget(_)) => {
                    report.reasons.push(ConcurrencyOpenReason::BudgetExhausted);
                    None
                }
                Err(CfgAlgorithmError::InvalidNode(_)) => {
                    unreachable!("validated allocation CFG contains only owned points")
                }
            }
        };

        let allocation_results = semantics
            .allocations()
            .iter()
            .map(|allocation| allocation.result)
            .collect::<HashSet<_>>();
        let aggregate_copies = semantics
            .points()
            .iter()
            .flat_map(|point| point.events.iter())
            .filter_map(|event| match event.effect {
                SemanticEffect::ValueFlow {
                    kind:
                        crate::analyzer::semantic::ValueFlowKind::Transfer(
                            crate::analyzer::semantic::ValueTransfer {
                                kind: crate::analyzer::semantic::TransferKind::AggregateCopy,
                                ..
                            },
                        ),
                    source,
                    target,
                } => Some((source, target)),
                _ => None,
            })
            .collect::<HashSet<_>>();
        let capture_bindings = semantics
            .memory_locations()
            .iter()
            .filter_map(|location| match location.kind {
                MemoryLocationKind::Capture { binding, .. } => binding,
                _ => None,
            })
            .collect::<HashSet<_>>();
        for value in semantics.values() {
            // A capture proxy is a use of its owner's binding, not a fresh
            // declaration whose lifetime the provider can classify here.
            if capture_bindings.contains(&value.id) {
                continue;
            }
            if !matches!(
                value.kind,
                crate::analyzer::semantic::SemanticValueKind::Local
                    | crate::analyzer::semantic::SemanticValueKind::Parameter { .. }
                    | crate::analyzer::semantic::SemanticValueKind::Receiver { .. }
            ) {
                continue;
            }
            let cardinality = *binding_cardinalities
                .entry((context.procedure.clone(), value.id))
                .or_insert_with(|| provider.lexical_cell_cardinality(&context.procedure, value.id));
            synchronization_subjects.cell_cardinalities.insert(
                LocalSynchronizationSubject::Value {
                    task: context.task,
                    invocation: context.invocation,
                    procedure: context.procedure.clone(),
                    value: value.id,
                },
                cardinality,
            );
        }
        for location in semantics.memory_locations() {
            let binding = match location.kind {
                MemoryLocationKind::LexicalCell { binding }
                | MemoryLocationKind::Capture {
                    binding: Some(binding),
                    ..
                } => binding,
                _ => continue,
            };
            if matches!(location.kind, MemoryLocationKind::LexicalCell { .. }) {
                let cardinality = *binding_cardinalities
                    .entry((context.procedure.clone(), binding))
                    .or_insert_with(|| {
                        provider.lexical_cell_cardinality(&context.procedure, binding)
                    });
                for subject in [
                    LocalSynchronizationSubject::Location(LocalLocation {
                        task: context.task,
                        invocation: context.invocation,
                        procedure: context.procedure.clone(),
                        location: location.id,
                    }),
                    LocalSynchronizationSubject::Value {
                        task: context.task,
                        invocation: context.invocation,
                        procedure: context.procedure.clone(),
                        value: binding,
                    },
                ] {
                    synchronization_subjects
                        .cell_cardinalities
                        .insert(subject, cardinality);
                }
            }
            synchronization_subjects.note_backing_binding_location(
                LocalLocation {
                    task: context.task,
                    invocation: context.invocation,
                    procedure: context.procedure.clone(),
                    location: location.id,
                },
                LocalSynchronizationSubject::Value {
                    task: context.task,
                    invocation: context.invocation,
                    procedure: context.procedure.clone(),
                    value: binding,
                },
            );
        }
        for point in semantics.points() {
            for event in &point.events {
                match event.effect {
                    SemanticEffect::CallableReference {
                        result,
                        ref callable,
                    }
                    | SemanticEffect::CallableCreation {
                        result,
                        ref callable,
                    } => {
                        if let CallableTargetResolution::Proven(CallableTarget::Local(target)) =
                            callable.targets
                            && let Some(handle) =
                                context.procedure.artifact().procedure_handle(target)
                        {
                            callable_values.insert(
                                (
                                    context.task,
                                    context.invocation,
                                    context.procedure.clone(),
                                    result,
                                ),
                                handle,
                            );
                        }
                    }
                    SemanticEffect::Allocation { allocation } => {
                        let allocation = semantics
                            .allocation(allocation)
                            .expect("validated allocation exists");
                        // Allocation is an explicit creation event, not a
                        // pointee guess. Heap queries can be incomplete because
                        // of unrelated accesses elsewhere in this procedure;
                        // that does not erase this event's storage family.
                        let canonical = contextual_allocation_identity(
                            context.task,
                            context.invocation,
                            CanonicalConcurrencyLocation::new(
                                format!(
                                    "allocation:{}:{}",
                                    crate::flow_state::procedure_wire_id(&context.procedure),
                                    allocation.id.get()
                                ),
                                "object",
                            ),
                        );
                        let cardinality = allocation_cyclic_points.as_ref().map_or(
                            ConcurrencyObjectCardinality::Unknown,
                            |points| {
                                if points.contains(&allocation.point) {
                                    ConcurrencyObjectCardinality::Multiple
                                } else {
                                    ConcurrencyObjectCardinality::Singleton
                                }
                            },
                        );
                        if cardinality == ConcurrencyObjectCardinality::Multiple {
                            synchronization_subjects.multiple_allocations.push(
                                LocalSynchronizationSubject::Value {
                                    task: context.task,
                                    invocation: context.invocation,
                                    procedure: context.procedure.clone(),
                                    value: allocation.result,
                                },
                            );
                        }
                        if invocations.entries[context.invocation.0 as usize]
                            .repetition
                            .is_some()
                            || cardinality != ConcurrencyObjectCardinality::Singleton
                        {
                            synchronization_subjects
                                .repeated_allocations
                                .insert(canonical.clone());
                        }
                        match provider
                            .allocation_binds_by_reference(&context.procedure, allocation.id)
                        {
                            Some(true) => {
                                reference_allocations.insert(canonical.clone());
                            }
                            Some(false) => {
                                inline_allocations.insert(canonical.clone());
                            }
                            None => {}
                        }
                        task_local_allocations
                            .entry(context.task)
                            .or_default()
                            .insert(canonical.clone());
                        allocation_origins.insert(
                            canonical.clone(),
                            AllocationOrigin {
                                invocation: context.invocation,
                                point: point.id,
                            },
                        );
                        let mut fact = ConcurrencyIdentityFact::allocation(
                            canonical,
                            context.invocation,
                            allocation.id,
                        );
                        fact.resolved.cardinality = cardinality;
                        fact.resolved.exhaustive =
                            cardinality != ConcurrencyObjectCardinality::Unknown;
                        synchronization_subjects.bind_canonical_value(
                            LocalSynchronizationSubject::Value {
                                task: context.task,
                                invocation: context.invocation,
                                procedure: context.procedure.clone(),
                                value: allocation.result,
                            },
                            fact,
                        );
                        synchronization_subjects.mark_fresh_allocation(
                            LocalSynchronizationSubject::Value {
                                task: context.task,
                                invocation: context.invocation,
                                procedure: context.procedure.clone(),
                                value: allocation.result,
                            },
                        );
                        continue;
                    }
                    SemanticEffect::ValueFlow { source, target, .. } => {
                        let source_subject = LocalSynchronizationSubject::Value {
                            task: context.task,
                            invocation: context.invocation,
                            procedure: context.procedure.clone(),
                            value: source,
                        };
                        let target_subject = LocalSynchronizationSubject::Value {
                            task: context.task,
                            invocation: context.invocation,
                            procedure: context.procedure.clone(),
                            value: target,
                        };
                        if let Some(callable) = callable_values
                            .get(&(
                                context.task,
                                context.invocation,
                                context.procedure.clone(),
                                source,
                            ))
                            .cloned()
                        {
                            callable_values.insert(
                                (
                                    context.task,
                                    context.invocation,
                                    context.procedure.clone(),
                                    target,
                                ),
                                callable,
                            );
                        }
                        if !aggregate_copies.contains(&(source, target)) {
                            synchronization_subjects
                                .union_backing(source_subject.clone(), target_subject.clone());
                            if let ConcurrencyAnswer::Proven(Some(canonical)) =
                                synchronization_subjects
                                    .bound_canonical_identity(source_subject.clone())
                            {
                                synchronization_subjects
                                    .bind_canonical_value(target_subject.clone(), canonical);
                            }
                            if binding_location(semantics, target).is_none() {
                                synchronization_subjects.union(source_subject, target_subject);
                            }
                        }
                        continue;
                    }
                    SemanticEffect::Assignment { target, value } => {
                        let copies_storage = aggregate_copies.contains(&(value, target));
                        if !copies_storage {
                            synchronization_subjects.union_backing(
                                LocalSynchronizationSubject::Value {
                                    task: context.task,
                                    invocation: context.invocation,
                                    procedure: context.procedure.clone(),
                                    value,
                                },
                                LocalSynchronizationSubject::Value {
                                    task: context.task,
                                    invocation: context.invocation,
                                    procedure: context.procedure.clone(),
                                    value: target,
                                },
                            );
                        }
                        synchronization_subjects.note_value_assignment(
                            LocalSynchronizationSubject::Value {
                                task: context.task,
                                invocation: context.invocation,
                                procedure: context.procedure.clone(),
                                value: target,
                            },
                        );
                        if allocation_results.contains(&value) && !copies_storage {
                            synchronization_subjects.union(
                                LocalSynchronizationSubject::Value {
                                    task: context.task,
                                    invocation: context.invocation,
                                    procedure: context.procedure.clone(),
                                    value,
                                },
                                LocalSynchronizationSubject::Value {
                                    task: context.task,
                                    invocation: context.invocation,
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
                                invocation: context.invocation,
                                procedure: context.procedure.clone(),
                                location,
                            }),
                            LocalSynchronizationSubject::Value {
                                task: context.task,
                                invocation: context.invocation,
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
                            invocation: context.invocation,
                            procedure: context.procedure.clone(),
                            location,
                        };
                        synchronization_subjects.note_location_store(local_location.clone());
                        // The cell receives a *copy* of this value, not the
                        // value's own storage, so it must not inherit its
                        // backing. `b := a` on a Go array stores `a` into
                        // `b`'s cell while the copy duplicates the elements,
                        // and connecting the cell to `a`'s backing made `a[0]`
                        // and `b[0]` one location.
                        let stores_a_copy =
                            aggregate_copies.iter().any(|(source, _)| *source == value);
                        if stores_a_copy
                            && matches!(
                                semantics
                                    .memory_location(location)
                                    .expect("validated store location exists")
                                    .kind,
                                MemoryLocationKind::LexicalCell { .. }
                            )
                        {
                            synchronization_subjects
                                .inline_cells
                                .insert(local_location.clone());
                        }
                        if !stores_a_copy
                            && !matches!(
                                semantics
                                    .memory_location(location)
                                    .expect("validated memory store location exists")
                                    .kind,
                                MemoryLocationKind::Index { .. }
                            )
                        {
                            synchronization_subjects.note_backing_location_store(
                                local_location,
                                LocalSynchronizationSubject::Value {
                                    task: context.task,
                                    invocation: context.invocation,
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
                        invocation: context.invocation,
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
                                invocation: context.invocation,
                                procedure: context.procedure.clone(),
                                location,
                            }),
                            LocalSynchronizationSubject::Value {
                                task: context.task,
                                invocation: context.invocation,
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
                                    invocation: context.invocation,
                                    procedure: context.procedure.clone(),
                                    value: result,
                                },
                                LocalSynchronizationSubject::Value {
                                    task: context.task,
                                    invocation: context.invocation,
                                    procedure: context.procedure.clone(),
                                    value: *base,
                                },
                                member.clone(),
                            );
                        }
                        synchronization_subjects.union(
                            LocalSynchronizationSubject::Location(LocalLocation {
                                task: context.task,
                                invocation: context.invocation,
                                procedure: context.procedure.clone(),
                                location,
                            }),
                            LocalSynchronizationSubject::Value {
                                task: context.task,
                                invocation: context.invocation,
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
                        invocation: context.invocation,
                        procedure: context.procedure.clone(),
                        point: point.id,
                        source: event.source,
                        mode,
                        access_kind,
                    },
                    local_location: Some(LocalLocation {
                        task: context.task,
                        invocation: context.invocation,
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
                    storage_origin: None,
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
                let (targets, reasons) = resolve_targets(
                    provider,
                    context.task,
                    context.invocation,
                    &context.procedure,
                    call.id,
                    &callable_values,
                    request,
                )?
                .into_parts();
                report.reasons.extend(reasons);
                Some((targets, None, true))
            } else {
                None
            };
            let mut spawned_any_task = false;
            for (targets, group, bind_invocation) in
                direct_targets.into_iter().chain(modeled_spawns)
            {
                for target in targets {
                    spawned_any_task = true;
                    let child = TaskId(u32::try_from(tasks.len()).map_err(|_| {
                        SemanticProviderError::internal("concurrency task count exceeds u32")
                    })?);
                    // A task spawned by a task that repeats repeats with it,
                    // whatever its own spawn site looks like. Without this,
                    // `for { go check() }` where `check` itself spawns the
                    // body leaves the grandchild believing it runs once, so
                    // its write is never compared against itself and the race
                    // is reported as nothing at all -- silently, since a task
                    // that runs once has no gap to declare. This is bbolt's
                    // own shape.
                    let target_context = invocations.push(
                        child,
                        target.clone(),
                        Some((context.invocation, call.id)),
                    );
                    tasks.push(Task {
                        parent: Some(context.task),
                        entry_procedure: Some(target.clone()),
                        entry_invocation: target_context.invocation,
                        spawn_procedure: Some(context.procedure.clone()),
                        spawn_invocation: Some(context.invocation),
                        spawn_call: Some(call.id),
                        group: group.clone(),
                        completion: None,
                        repetition: invocations.entries[target_context.invocation.0 as usize]
                            .repetition,
                        repetitions_serialized: false,
                    });
                    union_capture_locations(
                        &mut classes,
                        &mut synchronization_subjects,
                        &context,
                        child,
                        target_context.invocation,
                        &target,
                        call.callee,
                    );
                    if bind_invocation {
                        bind_call_inputs(
                            &mut synchronization_subjects,
                            &mut callable_values,
                            &context,
                            call,
                            child,
                            target_context.invocation,
                            &target,
                            true,
                            provider,
                            request,
                        )?;
                    }
                    queue.push_back(target_context);
                }
            }
            // A spawn always runs a body. Reaching none means the body was not
            // found, not that there is nothing to analyze, and the difference
            // matters: an unreported empty spawn leaves the parent's accesses
            // with nothing to compare against, so a real race reads as a clean
            // and complete run. An ordinary call may legitimately reach no body
            // -- a reviewed external is described by its effects -- which is
            // why only the detached case claims this.
            if detached && !spawned_any_task {
                report.reasons.push(ConcurrencyOpenReason::UnresolvedTarget);
            }

            if !detached {
                let (targets, reasons) = resolve_targets(
                    provider,
                    context.task,
                    context.invocation,
                    &context.procedure,
                    call.id,
                    &callable_values,
                    request,
                )?
                .into_parts();
                let exact_target = reasons.is_empty() && targets.len() == 1;
                report.reasons.extend(reasons);
                for target in targets {
                    // Bind through an edge only where the edge is analyzed.
                    // A back edge is skipped just below, and binding through
                    // it first gave the callee's formal a second actual from
                    // a call the solver never expanded. The formal then had
                    // two conflicting actuals and lost its identity, which
                    // discarded the one instantiation that *was* analyzed and
                    // correctly bound, so a write in a procedure the
                    // recursion passes through -- `checkBucket` calling
                    // `ForEachBucket`, whose callback calls `checkBucket` --
                    // was reported as nothing.
                    //
                    // Skipping the binding loses nothing the analysis had:
                    // the deeper instantiation is not expanded either, so it
                    // contributes no accesses to misattribute, and
                    // `RecursiveExpansion` already says it was not analyzed.
                    if invocations.recursively_calls(context.invocation, &target) {
                        let summarized_cycle = provider
                            .complete_summary(&context.procedure)
                            .zip(provider.complete_summary(&target))
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
                    let target_context = invocations.push(
                        context.task,
                        target.clone(),
                        Some((context.invocation, call.id)),
                    );
                    union_capture_locations(
                        &mut classes,
                        &mut synchronization_subjects,
                        &context,
                        context.task,
                        target_context.invocation,
                        &target,
                        call.callee,
                    );
                    bind_call_inputs(
                        &mut synchronization_subjects,
                        &mut callable_values,
                        &context,
                        call,
                        context.task,
                        target_context.invocation,
                        &target,
                        false,
                        provider,
                        request,
                    )?;
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
    // Name every field a load walked before anything composes an identity out
    // of one. A lock taken through `p.mu` is a field load and never an
    // access, and the subject resolution below is where its identity is
    // composed, so naming after that step left its two acquisitions carrying
    // use-site digests that cannot match and so protected nothing.
    let loaded_members = synchronization_subjects
        .backing_field_origins
        .iter()
        .map(|origin| origin.member.clone())
        .collect::<Vec<_>>();
    name_member_declarations(&mut synchronization_subjects, provider, loaded_members);
    // A cell written once holds one object for its whole life. Where that
    // object is a reference with a proven identity, the cell may answer with
    // it, which is what makes a capture of the cell and a direct read of the
    // value agree. Without this the parent reaches the object as a value and
    // names the allocation while the closure reaches it through the cell and
    // names the cell, and the pair is declared disjoint.
    // A formal's cell that the body never writes holds exactly what the call
    // bound, which is the same "written once" the loop below relies on; it is
    // simply written by the binding rather than by a statement.
    //
    // Both ways the body can write it disqualify the cell, and each was
    // measured to matter. A store to the cell means the ordinary rule already
    // counts the writes, and counting the binding as another would make a
    // cell that was named look written twice: cache2go stopped reporting its
    // own race that way. An `Assignment` to the formal is the case the
    // producer lowers as value flow rather than a cell store, so the cell
    // carries no store at all while the body has still replaced what it
    // holds; naming it from the binding then reports a write to a fresh
    // task-local object as a write to the caller's.
    let written_once = synchronization_subjects
        .location_stores
        .iter()
        .filter(|(_, count)| **count == 1)
        .map(|(location, _)| (location.clone(), None))
        .chain(
            formal_bound_cells
                .iter()
                .filter(|(cell, formal)| {
                    !synchronization_subjects.location_stores.contains_key(*cell)
                        && !synchronization_subjects
                            .value_assignments
                            .contains_key(*formal)
                })
                .map(|(cell, formal)| (cell.clone(), Some(formal.clone()))),
        )
        .collect::<Vec<_>>();
    propagate_reference_results(
        &mut synchronization_subjects,
        &invocations,
        &tasks,
        &synchronous_calls,
        &written_once,
        &reference_allocations,
        provider,
        request,
    );
    for (location, bound_formal) in written_once {
        let stored = match bound_formal {
            Some(formal) => Some(formal),
            None => synchronization_subjects
                .backing_location_stores
                .get(&location)
                .and_then(|values| match values.as_slice() {
                    [value] => Some(value.clone()),
                    _ => None,
                }),
        };
        let Some(stored) = stored else {
            continue;
        };
        let ConcurrencyAnswer::Proven(Some(canonical)) =
            synchronization_subjects.bound_canonical_identity(stored)
        else {
            continue;
        };
        if inline_allocations.contains(canonical.canonical()) {
            synchronization_subjects.inline_cells.insert(location);
            continue;
        }
        if !reference_allocations.contains(canonical.canonical()) {
            continue;
        }
        synchronization_subjects
            .bind_canonical_value(LocalSynchronizationSubject::Location(location), canonical);
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
    // A field store records no load origin, so the accesses carry members the
    // first pass could not see. Everything that composes them runs after
    // this point.
    let accessed_members = accesses
        .iter()
        .filter_map(|access| {
            let local = access.local_location.as_ref()?;
            let row = access
                .site
                .procedure
                .semantics()
                .memory_location(local.location)?;
            match &row.kind {
                MemoryLocationKind::Field { member, .. } => Some(member.clone()),
                _ => None,
            }
        })
        .collect::<Vec<_>>();
    name_member_declarations(&mut synchronization_subjects, provider, accessed_members);
    // Selecting a proven method declaration evaluates its receiver, but does
    // not read a field containing the method. Keep function-valued fields:
    // their selected declaration is storage even if the value is a method.
    accesses.retain(|access| {
        access.site.mode != ConcurrentAccessMode::Read
            || access.field_alias_domain.as_ref().is_none_or(|domain| {
                !synchronization_subjects
                    .callable_members
                    .contains(&member_locator_key(&domain.member))
            })
    });
    canonicalize_bound_accesses(&mut synchronization_subjects, &mut accesses);
    for access in &mut accesses {
        let context = ContextKey {
            task: access.site.task,
            invocation: access.site.invocation,
            procedure: access.site.procedure.clone(),
        };
        if let Some(reasons) = model_reasons_by_context.get(&context) {
            access.reasons.extend(reasons.iter().cloned());
            access.reasons.sort();
            access.reasons.dedup();
        }
    }
    associate_wait_group_tasks(&mut tasks, &modeled_by_context, &synchronous_calls);
    append_atomic_accesses(
        &mut synchronization_subjects,
        &modeled_by_context,
        &mut accesses,
    );
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
        provider,
        &tasks,
        &mut classes,
        AccessComparisonEvidence {
            invocations: &invocations,
            modeled: &modeled_by_context,
            lock_states: &lock_states,
            synchronizations: &synchronizations,
            task_local_allocations: &task_local_allocations,
            allocation_origins: &allocation_origins,
        },
        accesses,
        &mut report,
    );
    // Conflicting identities cannot become a complete empty answer merely
    // because no canonical location survived to produce a conflict pair.
    report
        .reasons
        .extend(synchronization_subjects.identity_reasons);
    report.reasons.sort();
    report.reasons.dedup();
    Ok(report)
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

#[derive(Debug, Clone)]
struct ReferenceIdentityUse {
    subject: LocalSynchronizationSubject,
    invocation: InvocationId,
    point: ProgramPointId,
    event: usize,
}

/// A pending equation is not an alias edge. Every source must already have
/// the same full creation fact before the destination receives a snapshot.
/// None retains an unsupported producer as a dependency blocker.
struct PendingReferenceIdentity {
    destination: LocalSynchronizationSubject,
    sources: Option<Vec<ReferenceIdentityUse>>,
}

#[allow(clippy::too_many_arguments)]
fn propagate_reference_results(
    classes: &mut SynchronizationSubjectClasses,
    invocations: &Invocations,
    tasks: &[Task],
    calls: &[SynchronousCall],
    cells: &[(LocalLocation, Option<LocalSynchronizationSubject>)],
    reference_allocations: &HashSet<CanonicalConcurrencyLocation>,
    provider: &impl ConcurrencyProvider,
    request: &mut SemanticRequest<'_>,
) {
    let exact_calls = calls
        .iter()
        .map(|call| {
            let (_, id) = invocations.entries[call.target.invocation.0 as usize]
                .caller
                .expect("synchronous activation has its caller");
            ((call.caller.invocation, id), &call.target)
        })
        .collect::<HashMap<_, _>>();
    let mut pending = Vec::new();
    let mut has_reference_result = false;
    for entry in &invocations.entries {
        let context = &entry.context;
        let semantics = context.procedure.semantics();
        for call in semantics.call_sites() {
            for (ordinal, value) in call.normal_result_values().enumerate() {
                // Builtin allocations already have their own creation proof.
                if semantics
                    .allocations()
                    .iter()
                    .any(|allocation| allocation.result == value)
                {
                    continue;
                }
                let sources = exact_calls
                    .get(&(context.invocation, call.id))
                    .and_then(|target| {
                        let ordinal =
                            u32::try_from(ordinal).expect("semantic result ordinal fits u32");
                        if provider.result_binds_by_reference(&target.procedure, ordinal)
                            != Some(true)
                            || call.normal_continuation.target().is_none()
                            || !reference_evidence_is_complete(semantics, call.evidence)
                            || !reference_control_is_complete(&context.procedure)
                            || !matches!(
                                call.execution_timing,
                                ExecutionTiming::SameEvaluation | ExecutionTiming::SameInvocation
                            )
                        {
                            return None;
                        }
                        has_reference_result = true;
                        let body = target.procedure.semantics();
                        if request.cancellation.is_cancelled()
                            || request
                                .budget
                                .charge(crate::analyzer::semantic::SemanticWork {
                                    program_points: body.points().len(),
                                    control_edges: body.control_edges().len(),
                                    nested_entries: body
                                        .points()
                                        .iter()
                                        .map(|point| point.events.len())
                                        .sum(),
                                    ..crate::analyzer::semantic::SemanticWork::default()
                                })
                                .is_err()
                        {
                            classes
                                .identity_reasons
                                .push(ConcurrencyOpenReason::BudgetExhausted);
                            return None;
                        }
                        reference_result_sources(target, ordinal)
                    });
                pending.push(PendingReferenceIdentity {
                    destination: LocalSynchronizationSubject::Value {
                        task: context.task,
                        invocation: context.invocation,
                        procedure: context.procedure.clone(),
                        value,
                    },
                    sources,
                });
            }
        }
    }
    if !has_reference_result {
        return;
    }
    for (formal, actual) in &classes.backing_formal_bindings {
        if classes.formal_bindings.contains_key(formal) {
            continue;
        }
        let LocalSynchronizationSubject::Value {
            invocation,
            procedure,
            value,
            ..
        } = formal
        else {
            unreachable!("a formal binding has a semantic value");
        };
        let reference = match procedure
            .semantics()
            .value(*value)
            .expect("owned formal")
            .kind
        {
            crate::analyzer::semantic::SemanticValueKind::Parameter { ordinal, .. } => {
                provider.parameter_binding(procedure, ordinal) == Some(true)
            }
            crate::analyzer::semantic::SemanticValueKind::Receiver { dispatch: true } => {
                provider.receiver_binds_by_reference(procedure)
            }
            _ => false,
        };
        if !reference {
            continue;
        }
        let (caller, call) = invocations.entries[invocation.0 as usize]
            .caller
            .expect("bound formal has a caller");
        let point = invocations.entries[caller.0 as usize]
            .context
            .procedure
            .semantics()
            .call_site(call)
            .expect("owned call")
            .point;
        let event = invocations.entries[caller.0 as usize].context.procedure.semantics()
            .point(point).expect("owned call point").events.iter()
            .position(|event| matches!(event.effect, SemanticEffect::Invoke { call_site } if call_site == call))
            .expect("validated call has its invocation event");
        pending.push(PendingReferenceIdentity {
            destination: formal.clone(),
            sources: Some(vec![ReferenceIdentityUse {
                subject: actual.clone(),
                invocation: caller,
                point,
                event,
            }]),
        });
    }
    for (location, formal) in cells {
        let semantics = location.procedure.semantics();
        let stored = formal.clone().map(|formal| (formal, semantics.entry_point(), 0)).or_else(|| {
            let [stored] = classes.backing_location_stores.get(location)?.as_slice() else { return None; };
            let (point, event) = semantics.points().iter().find_map(|point| point.events.iter().position(|event| {
                matches!(event.effect, SemanticEffect::MemoryStore { location: target, .. } if target == location.location)
            }).map(|event| (point.id, event)))?;
            Some((stored.clone(), point, event))
        });
        if let Some((stored, point, event)) = stored {
            pending.push(PendingReferenceIdentity {
                destination: LocalSynchronizationSubject::Location(location.clone()),
                sources: Some(vec![ReferenceIdentityUse {
                    subject: stored,
                    invocation: location.invocation,
                    point,
                    event,
                }]),
            });
        }
    }
    // No new equality edges are introduced here, so the dependency roots
    // remain fixed throughout convergence. An unsupported producer remains
    // pending and blocks any snapshot that could acquire its later value.
    let roots = pending
        .iter()
        .map(|item| classes.root(item.destination.clone()))
        .collect::<Vec<_>>();
    let mut active = vec![true; pending.len()];
    let mut stability = HashMap::default();
    loop {
        if request.cancellation.is_cancelled()
            || request
                .budget
                .charge(crate::analyzer::semantic::SemanticWork {
                    nested_entries: pending.len(),
                    ..crate::analyzer::semantic::SemanticWork::default()
                })
                .is_err()
        {
            classes
                .identity_reasons
                .push(ConcurrencyOpenReason::BudgetExhausted);
            return;
        }
        let mut changed = false;
        for (index, item) in pending.iter().enumerate() {
            if !active[index] {
                continue;
            }
            let Some(sources) = &item.sources else {
                continue;
            };
            if sources.is_empty() {
                continue;
            }
            let mut facts = Vec::new();
            for source in sources {
                let root = classes.root(source.subject.clone());
                if roots.iter().enumerate().any(|(other, destination)| {
                    other != index && active[other] && *destination == root
                }) {
                    break;
                }
                let stable = *stability
                    .entry((root, source.invocation, source.point, source.event))
                    .or_insert_with(|| {
                        reference_source_is_stable(classes, invocations, tasks, source, request)
                    });
                if !stable {
                    break;
                }
                let ConcurrencyAnswer::Proven(Some(fact)) =
                    classes.bound_canonical_identity(source.subject.clone())
                else {
                    break;
                };
                if !reference_allocations.contains(fact.canonical())
                    || fact.storage_origin.as_ref() != Some(fact.canonical())
                {
                    break;
                }
                facts.push(fact);
            }
            if facts.len() != sources.len() || facts.iter().any(|fact| *fact != facts[0]) {
                continue;
            }
            classes.bind_canonical_value(item.destination.clone(), facts.remove(0));
            classes.formal_binding_reasons.remove(&item.destination);
            active[index] = false;
            changed = true;
        }
        if !changed {
            break;
        }
    }
}

fn reference_result_sources(
    context: &ContextKey,
    ordinal: u32,
) -> Option<Vec<ReferenceIdentityUse>> {
    use crate::analyzer::semantic::{SemanticCapability, SemanticValueKind, ValueFlowKind};

    let semantics = context.procedure.semantics();
    if !reference_control_is_complete(&context.procedure)
        || semantics
            .gaps()
            .iter()
            .any(|gap| gap.capability == SemanticCapability::ReturnFlow)
    {
        return None;
    }
    let mut sources = Vec::new();
    let mut terminals = HashSet::default();
    for point in semantics.points() {
        if !point
            .events
            .iter()
            .any(|event| matches!(event.effect, SemanticEffect::ProcedureReturn { .. }))
            || !point_reaches(&context.procedure, semantics.entry_point(), point.id)
            || !point_reaches(&context.procedure, point.id, semantics.normal_exit_point())
        {
            continue;
        }
        // Named results are mutable storage observed after cleanup. Their
        // pre-cleanup IndexedReturn operands are not the returned values.
        if point.events.iter().any(|event| {
            matches!(
                event.effect,
                SemanticEffect::Assignment { .. } | SemanticEffect::MemoryStore { .. }
            ) || (matches!(event.effect, SemanticEffect::ProcedureReturn { .. })
                && !reference_evidence_is_complete(semantics, event.evidence))
        }) {
            return None;
        }
        let mut matching = point.events.iter().enumerate().filter_map(|(position, event)| {
            let SemanticEffect::ValueFlow { kind, source, target } = event.effect else {
                return None;
            };
            if semantics.value(target).expect("owned return target").kind != SemanticValueKind::Return {
                return None;
            }
            let matches_ordinal = match kind {
                ValueFlowKind::Return => ordinal == 0 && point.events.iter().any(|event| {
                    matches!(event.effect, SemanticEffect::ProcedureReturn { value: Some(value) } if value == target)
                }),
                ValueFlowKind::IndexedReturn { ordinal: index } => index == ordinal,
                _ => false,
            };
            matches_ordinal.then_some((source, event.evidence, position))
        });
        let (source, evidence, event) = matching.next()?;
        if matching.next().is_some() {
            return None;
        }
        if !reference_evidence_is_complete(semantics, evidence) {
            return None;
        }
        terminals.insert(point.id);
        sources.push(ReferenceIdentityUse {
            subject: LocalSynchronizationSubject::Value {
                task: context.task,
                invocation: context.invocation,
                procedure: context.procedure.clone(),
                value: source,
            },
            invocation: context.invocation,
            point: point.id,
            event,
        });
    }
    all_paths_cross_points(
        &context.procedure,
        semantics.normal_exit_point(),
        &terminals,
    )
    .then_some(sources)
}

fn reference_evidence_is_complete(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    evidence: crate::analyzer::semantic::EvidenceId,
) -> bool {
    use crate::analyzer::semantic::{EvidenceCompleteness, ProofStatus};
    let evidence = semantics
        .evidence_row(evidence)
        .expect("validated evidence exists");
    evidence.proof == ProofStatus::Proven && evidence.completeness == EvidenceCompleteness::Complete
}

fn reference_control_is_complete(procedure: &ProcedureHandle) -> bool {
    use crate::analyzer::semantic::{
        SemanticCapability, SemanticGapDischarge, SemanticGapImpact, SemanticGapSubject,
    };
    let semantics = procedure.semantics();
    !semantics.gaps().iter().any(|gap| {
        matches!(
            gap.capability,
            SemanticCapability::NormalControlFlow
                | SemanticCapability::NonLocalControl
                | SemanticCapability::NormalCallContinuation
                | SemanticCapability::CleanupControlFlow
                | SemanticCapability::DeferredExecution
                | SemanticCapability::AsyncSuspendResume
                | SemanticCapability::GeneratorSuspension
        ) || gap.discharge == SemanticGapDischarge::ExitOnlyProcedureCompletion
            || (matches!(gap.capability,
                SemanticCapability::ExceptionalControlFlow | SemanticCapability::ExceptionalCallContinuation)
                && gap.discharge != SemanticGapDischarge::NonRejoiningExceptionalExit)
            // A retained call can require workspace target refinement while
            // its evaluation and continuation are already represented. The
            // pending result equation separately requires that exact target;
            // a dispatch-only gap does not invalidate the caller's CFG.
            || (gap.capability == SemanticCapability::Calls
                && (gap.impacts.contains(SemanticGapImpact::CallEvaluation)
                    || !matches!(gap.subject, SemanticGapSubject::CallSite(_))))
    }) && semantics
        .control_edges()
        .iter()
        .all(|edge| reference_evidence_is_complete(semantics, edge.evidence))
}

/// A class used for a new result snapshot must describe an unchanged value,
/// not merely the final contents of a mutable cell. This deliberately refuses
/// mutable bindings until their individual reaching definitions are modeled.
fn reference_source_is_stable(
    classes: &mut SynchronizationSubjectClasses,
    invocations: &Invocations,
    tasks: &[Task],
    source: &ReferenceIdentityUse,
    request: &mut SemanticRequest<'_>,
) -> bool {
    use crate::analyzer::semantic::{SemanticCapability, SemanticGapImpact, SemanticValueKind};

    let root = classes.root(source.subject.clone());
    let mut definitions = Vec::new();
    let mut reads = Vec::new();
    let mut cell_stores = 0;
    for entry in &invocations.entries {
        let context = &entry.context;
        let semantics = context.procedure.semantics();
        let mut values = semantics
            .values()
            .iter()
            .filter_map(|value| {
                let subject = LocalSynchronizationSubject::Value {
                    task: context.task,
                    invocation: context.invocation,
                    procedure: context.procedure.clone(),
                    value: value.id,
                };
                (classes.root(subject) == root).then_some(value.id)
            })
            .collect::<HashSet<_>>();
        let locations = semantics
            .memory_locations()
            .iter()
            .filter_map(|location| {
                let subject = LocalSynchronizationSubject::Location(LocalLocation {
                    task: context.task,
                    invocation: context.invocation,
                    procedure: context.procedure.clone(),
                    location: location.id,
                });
                (classes.root(subject) == root).then_some(location.id)
            })
            .collect::<HashSet<_>>();
        if values.is_empty() && locations.is_empty() {
            continue;
        }
        if request.cancellation.is_cancelled()
            || request
                .budget
                .charge(crate::analyzer::semantic::SemanticWork {
                    nested_entries: semantics.values().len()
                        + semantics
                            .points()
                            .iter()
                            .map(|point| point.events.len())
                            .sum::<usize>(),
                    ..crate::analyzer::semantic::SemanticWork::default()
                })
                .is_err()
        {
            classes
                .identity_reasons
                .push(ConcurrencyOpenReason::BudgetExhausted);
            return false;
        }
        if !reference_control_is_complete(&context.procedure)
            || semantics.gaps().iter().any(|gap| {
                gap.capability == SemanticCapability::Captures
                    || (gap.capability == SemanticCapability::Assignments
                        && gap.impacts.contains(SemanticGapImpact::HeapWrite))
            })
        {
            return false;
        }
        let bindings = values
            .iter()
            .copied()
            .filter(|value| {
                matches!(
                    semantics.value(*value).expect("owned value").kind,
                    SemanticValueKind::Local
                        | SemanticValueKind::Parameter { .. }
                        | SemanticValueKind::Receiver { .. }
                )
            })
            // A load's ordinary class contains the cell and its result, but
            // need not contain the declaration value naming that cell. Follow
            // the structured cell binding before checking hidden capture writes.
            .chain(locations.iter().filter_map(|location| {
                match semantics
                    .memory_location(*location)
                    .expect("owned location")
                    .kind
                {
                    MemoryLocationKind::LexicalCell { binding }
                    | MemoryLocationKind::Capture {
                        binding: Some(binding),
                        ..
                    } => Some(binding),
                    _ => None,
                }
            }))
            .collect::<HashSet<_>>();
        values.extend(bindings.iter().copied());
        if !crate::flow_state::address_alias_values(semantics, &bindings).is_empty() {
            return false;
        }
        for location in &locations {
            if !matches!(
                semantics
                    .memory_location(*location)
                    .expect("owned location")
                    .kind,
                MemoryLocationKind::LexicalCell { .. } | MemoryLocationKind::Capture { .. }
            ) {
                return false;
            }
        }
        for value in &bindings {
            match reference_captures_are_read_only(&context.procedure, *value, request) {
                Ok(true) => {}
                Ok(false) => return false,
                Err(reason) => {
                    classes.identity_reasons.push(reason);
                    return false;
                }
            }
        }
        let mut assignments = HashMap::<ValueId, usize>::default();
        for point in semantics.points() {
            for (position, event) in point.events.iter().enumerate() {
                let relevant = match event.effect {
                    SemanticEffect::Assignment { target, value } => {
                        values.contains(&target) || values.contains(&value)
                    }
                    SemanticEffect::ValueFlow { source, .. } => values.contains(&source),
                    SemanticEffect::MemoryLoad { location, .. }
                    | SemanticEffect::MemoryStore { location, .. } => locations.contains(&location),
                    _ => false,
                };
                if relevant && !reference_evidence_is_complete(semantics, event.evidence) {
                    return false;
                }
                // A creation fact identifies backing storage, but carries no
                // slice-view origin. Copying it across a result would make
                // different views' element zero appear to be the same cell.
                // Keep the route open until result binding retains offsets.
                if relevant
                    && matches!(event.effect,
                    SemanticEffect::ValueFlow {
                        kind: crate::analyzer::semantic::ValueFlowKind::BackingStore { offset }, ..
                    } if !matches!(offset, crate::analyzer::semantic::BackingStoreOffset::Zero | crate::analyzer::semantic::BackingStoreOffset::Constant(0)))
                {
                    return false;
                }
                match event.effect {
                    SemanticEffect::Assignment { target, value } => {
                        if values.contains(&target) {
                            *assignments.entry(target).or_default() += 1;
                            if matches!(
                                semantics.value(target).expect("owned target").kind,
                                SemanticValueKind::Parameter { .. }
                                    | SemanticValueKind::Receiver { .. }
                            ) {
                                return false;
                            }
                            definitions.push((context.invocation, point.id, position));
                        }
                        if values.contains(&value) {
                            reads.push((context.invocation, point.id, position));
                        }
                    }
                    SemanticEffect::MemoryStore { location, .. }
                        if locations.contains(&location) =>
                    {
                        cell_stores += 1;
                        definitions.push((context.invocation, point.id, position));
                    }
                    SemanticEffect::MemoryLoad { location, .. }
                        if locations.contains(&location) =>
                    {
                        reads.push((context.invocation, point.id, position));
                    }
                    SemanticEffect::ValueFlow { source, .. } if values.contains(&source) => {
                        reads.push((context.invocation, point.id, position));
                    }
                    _ => {}
                }
            }
        }
        if assignments.values().any(|count| *count > 1) || cell_stores > 1 {
            return false;
        }
    }
    reads.push((source.invocation, source.point, source.event));
    definitions
        .into_iter()
        .all(|(definition, point, position)| {
            let task = invocations.entries[definition.0 as usize].context.task;
            reads.iter().all(|read| {
                let Some((observer, observation)) =
                    observation_in_task(tasks, invocations, task, (read.0, read.1))
                else {
                    return false;
                };
                (definition == read.0 && point == read.1 && position <= read.2)
                    || invocations.required_points_before(
                        definition,
                        HashSet::from_iter([point]),
                        observer,
                        observation,
                    )
            })
        })
}

/// Inspect lexical capture bodies even when they have not been expanded as
/// calls. An escaped closure can replace its owner's cell without a retained
/// invocation in the current task slice.
fn reference_captures_are_read_only(
    owner: &ProcedureHandle,
    owner_binding: ValueId,
    request: &mut SemanticRequest<'_>,
) -> Result<bool, ConcurrencyOpenReason> {
    use crate::analyzer::semantic::{SemanticCapability, SemanticGapImpact};
    let mut pending = vec![(owner.clone(), owner_binding)];
    let mut visited = HashSet::default();
    while let Some((procedure, binding)) = pending.pop() {
        if !visited.insert((procedure.clone(), binding)) {
            continue;
        }
        let semantics = procedure.semantics();
        if request.cancellation.is_cancelled()
            || request
                .budget
                .charge(crate::analyzer::semantic::SemanticWork {
                    nested_entries: semantics.values().len()
                        + semantics
                            .points()
                            .iter()
                            .map(|point| point.events.len())
                            .sum::<usize>(),
                    ..crate::analyzer::semantic::SemanticWork::default()
                })
                .is_err()
        {
            return Err(ConcurrencyOpenReason::BudgetExhausted);
        }
        let location = binding_location(semantics, binding);
        if (procedure != *owner || binding != owner_binding)
            && (!reference_control_is_complete(&procedure)
                || semantics.gaps().iter().any(|gap| {
                    gap.capability == SemanticCapability::Captures
                        || (gap.capability == SemanticCapability::Assignments
                            && gap.impacts.contains(SemanticGapImpact::HeapWrite))
                })
                || !crate::flow_state::address_alias_values(
                    semantics,
                    &HashSet::from_iter([binding]),
                )
                .is_empty()
                || semantics
                    .points()
                    .iter()
                    .flat_map(|point| &point.events)
                    .any(|event| match event.effect {
                        SemanticEffect::Assignment { target, .. } => target == binding,
                        SemanticEffect::MemoryStore {
                            location: target, ..
                        } => Some(target) == location,
                        _ => false,
                    }))
        {
            return Ok(false);
        }
        for capture in semantics.captures() {
            if !match capture.captured {
                CaptureSource::Value(value) => value == binding,
                CaptureSource::Location(source) => Some(source) == location,
            } {
                continue;
            }
            let Some(target) = procedure.artifact().procedure_handle(capture.target) else {
                return Ok(false);
            };
            let Some(MemoryLocationKind::Capture {
                binding: Some(binding),
                ..
            }) = target
                .semantics()
                .memory_location(capture.destination)
                .map(|location| &location.kind)
            else {
                return Ok(false);
            };
            pending.push((target.clone(), *binding));
        }
    }
    Ok(true)
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
        spawn_invocation: InvocationId,
        spawn_point: ProgramPointId,
        completion: (InvocationId, ProgramPointId),
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
            invocation: task.entry_invocation,
            procedure: entry.clone(),
        };
        let Some(done) = completion_effects.get(&context) else {
            continue;
        };
        if done.len() != 1 {
            continue;
        }
        let (completion, group) = done
            .iter()
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
            spawn_invocation: task
                .spawn_invocation
                .expect("spawned task retains its caller invocation"),
            spawn_point,
            completion: *completion,
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
        let spawn_invocation = completions[0].spawn_invocation;
        let structurally_one_phase = completions.iter().all(|completion| {
            completion.parent == parent
                && completion.spawn_procedure == spawn_procedure
                && completion.spawn_invocation == spawn_invocation
        });
        let context = ContextKey {
            task: parent,
            invocation: spawn_invocation,
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
            let parent_repeats = tasks[completion.parent.0 as usize].repetition.is_some();
            let task = &mut tasks[completion.task.0 as usize];
            task.repetitions_serialized = task.repetition.is_some()
                && !parent_repeats
                && point_is_cyclic(spawn_procedure.semantics(), completion.spawn_point)
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
            task.completion = Some(completion.completion);
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
            invocation: task
                .spawn_invocation
                .expect("spawned task retains its caller invocation"),
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
) -> HashMap<ContextKey, HashMap<(InvocationId, ProgramPointId), ResolvedConcurrencySubject>> {
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
                summary.insert((context.invocation, *point), group.clone());
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
                    invocation: context.invocation,
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
                invocation: task
                    .spawn_invocation
                    .expect("spawned task retains its caller invocation"),
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
    let canonical = classes.canonical_modeled_identity(context, subject);
    if let Some(fact) = canonical {
        subject.reasons = fact.reasons();
        subject.canonical = Some(fact.canonical().clone());
    } else if let Some(canonical) =
        classes.stable_modeled_identity(LocalSynchronizationSubject::Value {
            task: context.task,
            invocation: context.invocation,
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
    classes: &mut SynchronizationSubjectClasses,
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
            let fact = classes.canonical_modeled_identity(context, location);
            let storage_origin = fact.as_ref().and_then(|fact| fact.storage_origin.clone());
            let resolved_location = if let Some(fact) = fact {
                fact.resolved
            } else if location.reasons.is_empty() {
                ResolvedConcurrencyLocation::exact(canonical.clone())
            } else {
                ResolvedConcurrencyLocation::new(
                    vec![canonical.clone()],
                    false,
                    ConcurrencyObjectCardinality::Unknown,
                    ConcurrencyEscape::Unknown,
                    ConcurrencyOwnership::Unknown,
                )
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
                    invocation: context.invocation,
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
                    invocation: context.invocation,
                    procedure: context.procedure.clone(),
                    location: MemoryLocationId::new(u32::MAX),
                }),
                canonical: Some(canonical.clone()),
                resolved_location,
                index_alias_domain: None,
                field_alias_domain: None,
                local_identity: false,
                reasons: location.reasons.clone(),
                atomic: true,
                storage_origin,
            });
        }
    }
}

fn resolve_targets(
    provider: &impl ConcurrencyProvider,
    task: TaskId,
    invocation: InvocationId,
    procedure: &ProcedureHandle,
    call: CallSiteId,
    callable_values: &HashMap<(TaskId, InvocationId, ProcedureHandle, ValueId), ProcedureHandle>,
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
    // A callee the caller supplied resolves through the binding that supplied
    // it. Lowering cannot see that: the value is bound at the call site, one
    // procedure away from the call it decides.
    if let Some(target) = callable_values.get(&(task, invocation, procedure.clone(), row.callee)) {
        return Ok(ConcurrencyAnswer::Proven(vec![target.clone()]));
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
            // A producer that resolved the declaration stored that
            // declaration's own locator, so rendering it is an identity every
            // file agrees on. A producer that could not -- Go's `pkg.Name`
            // through an import, whose declaring file an intra-file adapter
            // must not read -- says so with a gap on the location, and stored a
            // use site instead. Rendering that would claim two occurrences of
            // one variable name different storage. Ask the provider, which can
            // see the workspace, to resolve it.
            // Every static goes to the provider, not only the ones a producer
            // marked unresolved. A file that declares the variable stores the
            // declaration's locator and a file that imports it stores a use
            // site, so canonicalizing the two differently would mean the
            // declaring and importing sides of one variable never meet, which
            // is the whole defect. One resolver answers for both.
            let _ = member;
            let answer =
                provider.canonical_location(&context.procedure, point, location, request)?;
            let proven = matches!(&answer, ConcurrencyAnswer::Proven(_));
            let (canonical, reasons) = match answer {
                ConcurrencyAnswer::Proven(canonical) => (canonical, Vec::new()),
                ConcurrencyAnswer::Open { partial, reasons } => (partial, reasons),
            };
            Ok(match canonical {
                Some(canonical) => CanonicalizedAccess {
                    canonical: Some(canonical.clone()),
                    resolved_location: if proven {
                        ResolvedConcurrencyLocation::independent(
                            canonical.clone(),
                            ConcurrencyStorageFamily::Static(canonical),
                        )
                    } else {
                        ResolvedConcurrencyLocation::new(
                            vec![canonical],
                            false,
                            ConcurrencyObjectCardinality::Unknown,
                            ConcurrencyEscape::Unknown,
                            ConcurrencyOwnership::Unknown,
                        )
                    },
                    reasons,
                    index_alias_domain: None,
                    field_alias_domain: None,
                },
                None => CanonicalizedAccess {
                    canonical: None,
                    resolved_location: ResolvedConcurrencyLocation::unknown(),
                    reasons: if reasons.is_empty() {
                        vec![ConcurrencyOpenReason::UnknownLocation]
                    } else {
                        reasons
                    },
                    index_alias_domain: None,
                    field_alias_domain: None,
                },
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
                resolved_location = base_location;
                resolved_location.candidates = vec![exact];
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
                    declaration: None,
                    member: member.clone(),
                }),
            })
        }
        MemoryLocationKind::Property { base, key } => {
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
                let exact = CanonicalConcurrencyLocation::new(
                    format!("{}/property:{key}", base.identity),
                    "property",
                );
                canonical = Some(exact.clone());
                resolved_location = base_location;
                resolved_location.candidates = vec![exact];
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
                field_alias_domain: None,
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
                resolved_location = base_location;
                resolved_location.candidates = vec![exact];
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
        format!("{}/{}", base.identity, field_step_selector(member)),
        "field",
    )
}

/// The file and span that identify one member locator across occurrences.
fn member_locator_key(member: &crate::analyzer::semantic::SemanticLocator) -> (String, u32, u32) {
    let span = member.anchor().span();
    (
        member.path().as_str().to_owned(),
        span.start_byte(),
        span.end_byte(),
    )
}

/// Name one field step inside a composed location identity.
///
/// Every site that folds a field into an identity renders it through here,
/// including the selectors a reusable summary carries, so one field has one
/// spelling. The spelling digests a locator, which makes the *choice* of
/// locator the thing that has to agree; `canonical_member` makes that choice.
pub fn field_step_selector(member: &crate::analyzer::semantic::SemanticLocator) -> String {
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

/// Resolve the declaration behind each member locator, so that every field has
/// one name before anything composes an identity out of it.
///
/// This runs twice, because the members become known on either side of
/// modeled-subject resolution: a field load is recorded during the event walk,
/// while a field store is only visible on the accesses it produced.
fn name_member_declarations(
    classes: &mut SynchronizationSubjectClasses,
    provider: &impl ConcurrencyProvider,
    members: impl IntoIterator<Item = crate::analyzer::semantic::SemanticLocator>,
) {
    for member in members {
        let key = member_locator_key(&member);
        if let Some(declaration) = provider.resolved_member_identity(&member) {
            if declaration.is_callable {
                classes.callable_members.insert(key.clone());
            }
            let candidate = CanonicalMember {
                rank: (!declaration.is_declaration_site, key.clone()),
                locator: member.clone(),
            };
            match classes.declaration_locators.entry(declaration.name.clone()) {
                Entry::Occupied(mut chosen) => {
                    if candidate.rank < chosen.get().rank {
                        chosen.insert(candidate);
                    }
                }
                Entry::Vacant(slot) => {
                    slot.insert(candidate);
                }
            }
            classes
                .member_declarations
                .insert(key.clone(), declaration.name);
        }
        if let Some(reference) = provider.member_binds_by_reference(&member) {
            classes.reference_members.insert(key, reference);
        }
    }
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
        let declaration = match &row.kind {
            MemoryLocationKind::Field { member, .. } => classes
                .member_declarations
                .get(&member_locator_key(member))
                .cloned(),
            _ => None,
        };
        let (base, selector, indexed) = match &row.kind {
            MemoryLocationKind::Field { base, member } => {
                // The selector buckets accesses before the overlap gate sees
                // them, so it has to agree about one field too.
                let selector = SummaryConcurrencyAccessSelector::Field(
                    SummaryLocationKey::from_locator(classes.canonical_member(member)),
                );
                (*base, Some(selector), None)
            }
            MemoryLocationKind::Property { base, key } => (
                *base,
                Some(SummaryConcurrencyAccessSelector::Property(key.clone())),
                None,
            ),
            MemoryLocationKind::Index {
                base,
                constant_index,
                identity,
                ..
            } => {
                let selector = match (identity, constant_index) {
                    (IndexedLocationIdentity::Aggregate, _) => {
                        Some(SummaryConcurrencyAccessSelector::Aggregate)
                    }
                    (IndexedLocationIdentity::Element, Some(index)) => i128::try_from(*index)
                        .ok()
                        .map(SummaryConcurrencyAccessSelector::ConstantIndex),
                    (IndexedLocationIdentity::Element, None) => None,
                };
                (*base, selector, Some((*identity, *constant_index)))
            }
            _ => continue,
        };
        let local_base = LocalSynchronizationSubject::Value {
            task: access.site.task,
            invocation: access.site.invocation,
            procedure: access.site.procedure.clone(),
            value: base,
        };
        let contains_formal = classes.contains_formal_binding(local_base.clone());
        let backing_root = classes.backing_root(local_base.clone());
        let multiple_allocations = classes.multiple_allocations.clone();
        let multiple_instances = multiple_allocations
            .into_iter()
            .any(|allocation| classes.backing_root(allocation) == backing_root);
        let base = match &row.kind {
            MemoryLocationKind::Index { .. } => classes
                .canonical_backing_identity(local_base.clone())
                .or_else(|| classes.canonical_capture_identity(local_base)),
            // A field loaded from another field is neither captured nor
            // freshly allocated, so it has no identity of its own and can
            // only be named by the chain it was loaded through. Trying this
            // only after the capture identity keeps every location that
            // resolves today resolving to the same name, so it can add a base
            // where there was none and cannot change one that existed.
            _ => classes
                .canonical_capture_identity(local_base.clone())
                .or_else(|| classes.canonical_field_chain_identity(local_base)),
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
                        declaration: declaration.clone(),
                        member: member.clone(),
                    });
                }
                access.index_alias_domain = None;
            }
            continue;
        };
        if let MemoryLocationKind::Field { member, .. } = &row.kind {
            access.field_alias_domain = Some(FieldAliasDomain {
                base: Some(base.canonical().clone()),
                declaration: declaration.clone(),
                member: classes.canonical_member(member).clone(),
            });
        }
        if let Some((identity, constant_index)) = indexed {
            access.index_alias_domain = Some(IndexAliasDomain {
                base: base.canonical().clone(),
                identity,
                constant_index,
            });
        }
        if let Some(selector) = selector {
            let mut fact = base;
            fact.project(selector, row.kind.label());
            access.canonical = Some(fact.canonical().clone());
            access.reasons = fact.reasons();
            access.storage_origin = fact.storage_origin;
            access.resolved_location = fact.resolved;
            if multiple_instances {
                // A capture can name the stored pointer while the allocation
                // producer explicitly reports multiple runtime objects. Keep
                // that cardinality instead of upgrading the capture name to
                // a singleton object shared by every iteration.
                access.resolved_location.cardinality = ConcurrencyObjectCardinality::Multiple;
                access.reasons.push(ConcurrencyOpenReason::UnknownLocation);
            }
        } else {
            access.canonical = None;
            access.storage_origin = base.storage_origin;
            access.resolved_location = base.resolved;
            access.resolved_location.candidates.clear();
            access
                .resolved_location
                .storage_path
                .push(SummaryConcurrencyAccessSelector::AnyIndex);
            access.resolved_location.exhaustive = false;
            access.resolved_location.cardinality = ConcurrencyObjectCardinality::Multiple;
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
        let storage_origin =
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
            invocation: pending.context.invocation,
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
                declaration: None,
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
                        | SummaryConcurrencyAccessSelector::Property(_)
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
            Some(SummaryConcurrencyAccessSelector::Property(_)) => MemoryAccessKind::Property,
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
                invocation: pending.context.invocation,
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
            storage_origin,
        });
    }
}

fn bind_summary_access_root(
    classes: &mut SynchronizationSubjectClasses,
    context: &ContextKey,
    path: &SummaryConcurrencyAccessPath,
    binding: &mut SummaryConcurrencyBoundaryBinding,
) -> Option<CanonicalConcurrencyLocation> {
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
                invocation: context.invocation,
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
                invocation: context.invocation,
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
                    invocation: context.invocation,
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
            return None;
        }
        SummaryPort::NormalReturn
        | SummaryPort::IndexedNormalReturn(_)
        | SummaryPort::ExceptionalReturn => None,
    };
    let uses_backing_identity = path.selectors().iter().any(|selector| {
        matches!(
            selector,
            SummaryConcurrencyAccessSelector::Aggregate
                | SummaryConcurrencyAccessSelector::Property(_)
                | SummaryConcurrencyAccessSelector::ConstantIndex(_)
                | SummaryConcurrencyAccessSelector::Index(_)
                | SummaryConcurrencyAccessSelector::AnyIndex
        )
    });
    let mut reasons = subject
        .as_ref()
        .map(|subject| classes.formal_binding_reasons(subject.clone()))
        .unwrap_or_default();
    let mut location = subject.and_then(|subject| {
        if uses_backing_identity {
            classes
                .canonical_backing_identity(subject.clone())
                .or_else(|| classes.canonical_capture_identity(subject))
        } else {
            classes.canonical_capture_identity(subject)
        }
    });
    if let Some(fact) = location.as_mut()
        && !path
            .selectors()
            .iter()
            .rev()
            .skip(1)
            .all(|selector| match selector {
                // The last selector addresses storage itself. Earlier selectors
                // load intermediate values, which need an inline-storage proof.
                SummaryConcurrencyAccessSelector::Field(field) => {
                    classes.backing_field_origins.iter().any(|origin| {
                        SummaryLocationKey::from_locator(classes.canonical_member(&origin.member))
                            == *field
                            && classes.member_reference_binding(&origin.member) == Some(false)
                    })
                }
                _ => false,
            })
    {
        classes.leave_inline_storage(fact);
    }
    let storage_origin = location
        .as_ref()
        .and_then(|fact| fact.storage_origin.clone());
    let location = if let Some(location) = location {
        reasons.extend(location.reasons());
        let partial = location.resolved;
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
    storage_origin
}

fn union_capture_locations(
    classes: &mut LocationClasses,
    synchronization_subjects: &mut SynchronizationSubjectClasses,
    parent: &ContextKey,
    child_task: TaskId,
    child_invocation: InvocationId,
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
                    invocation: parent.invocation,
                    procedure: parent.procedure.clone(),
                    location: source,
                };
                let child_location = LocalLocation {
                    task: child_task,
                    invocation: child_invocation,
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
                        invocation: child_invocation,
                        procedure: child.clone(),
                        location: capture.destination,
                    }),
                );
                synchronization_subjects.mark_captured_location(parent_subject);
            }
            CaptureSource::Value(source) => {
                if matches!(
                    capture.mode,
                    crate::analyzer::semantic::CaptureMode::Value
                        | crate::analyzer::semantic::CaptureMode::Move
                        | crate::analyzer::semantic::CaptureMode::Receiver
                ) {
                    classes.value_captures.insert(LocalLocation {
                        task: child_task,
                        invocation: child_invocation,
                        procedure: child.clone(),
                        location: capture.destination,
                    });
                }
                let source = LocalSynchronizationSubject::Value {
                    task: parent.task,
                    invocation: parent.invocation,
                    procedure: parent.procedure.clone(),
                    value: source,
                };
                synchronization_subjects.union(
                    source.clone(),
                    LocalSynchronizationSubject::Location(LocalLocation {
                        task: child_task,
                        invocation: child_invocation,
                        procedure: child.clone(),
                        location: capture.destination,
                    }),
                );
                synchronization_subjects.union_backing(
                    source.clone(),
                    LocalSynchronizationSubject::Location(LocalLocation {
                        task: child_task,
                        invocation: child_invocation,
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
    callable_values: &mut HashMap<
        (TaskId, InvocationId, ProcedureHandle, ValueId),
        ProcedureHandle,
    >,
    caller: &ContextKey,
    call: &crate::analyzer::semantic::SemanticCallSite,
    target_task: TaskId,
    target_invocation: InvocationId,
    target: &ProcedureHandle,
    task_transfer: bool,
    provider: &impl ConcurrencyProvider,
    request: &mut SemanticRequest<'_>,
) -> Result<(), SemanticProviderError> {
    for formal in target.semantics().values() {
        let dispatch_receiver = matches!(
            formal.kind,
            crate::analyzer::semantic::SemanticValueKind::Receiver { dispatch: true }
        );
        let parameter_ordinal = match formal.kind {
            crate::analyzer::semantic::SemanticValueKind::Parameter { ordinal, .. } => {
                Some(ordinal)
            }
            _ => None,
        };
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
            invocation: caller.invocation,
            procedure: caller.procedure.clone(),
            value: actual_value,
        };
        let formal_value = formal.id;
        // Carry the callable the actual denotes, so a call on this formal can
        // resolve the body it reaches. This is the callable counterpart of the
        // object identity the rest of this loop carries.
        if let Some(callable) = callable_values
            .get(&(
                caller.task,
                caller.invocation,
                caller.procedure.clone(),
                actual_value,
            ))
            .cloned()
        {
            callable_values.insert(
                (target_task, target_invocation, target.clone(), formal_value),
                callable,
            );
        }
        let formal = LocalSynchronizationSubject::Value {
            task: target_task,
            invocation: target_invocation,
            procedure: target.clone(),
            value: formal_value,
        };
        let formal_cell = binding_location(target.semantics(), formal_value);
        let reassigned = target.semantics().points().iter().any(|point| {
            point.events.iter().any(|event| match event.effect {
                SemanticEffect::Assignment { target, .. } => target == formal_value,
                SemanticEffect::MemoryStore { location, .. } => Some(location) == formal_cell,
                _ => false,
            })
        });
        if reassigned {
            // Entry identity cannot describe every use of a mutable formal.
            // In particular, an unsupported replacement result contributes no
            // competing identity to invalidate an eager or deferred binding.
            // Keep the missing reaching-definition evidence explicit before
            // either ordinary or backing-store equivalence can cross the call.
            classes
                .note_formal_binding_reasons(formal, vec![ConcurrencyOpenReason::UnknownLocation]);
            continue;
        }
        classes.bind_backing_formal(formal.clone(), actual.clone());
        // A pointer receiver copies the pointer, so the callee's field
        // accesses reach the caller's object. Name that object exactly as the
        // caller's own field accesses name it, which is what the overlap gate
        // compares. `canonical_capture_identity` prefers a proven runtime
        // identity and otherwise issues a capture identity, and it issues one
        // only for a cell stored once, so the name cannot outlive the binding
        // it stands for.
        if dispatch_receiver && !provider.receiver_binds_by_reference(target) {
            // The callee writes a copy of the receiver's fields, so nothing
            // it writes reaches the caller's object. No identity crosses.
            classes
                .note_formal_binding_reasons(formal, vec![ConcurrencyOpenReason::UnknownLocation]);
            continue;
        }
        // Go copies an argument, so a parameter answers the same question a
        // receiver does. A pointer parameter copies the pointer and still
        // reaches the caller's object; a value parameter copies the fields
        // and cannot, and binding one reported the callee's write on its own
        // copy as racing the caller's read.
        if let Some(ordinal) = parameter_ordinal {
            match provider.parameter_binding(target, ordinal) {
                Some(false) => {
                    classes.note_formal_binding_reasons(
                        formal,
                        vec![ConcurrencyOpenReason::UnknownLocation],
                    );
                    continue;
                }
                Some(true) if classes.canonical_capture_identity(actual.clone()).is_some() => {
                    if task_transfer {
                        classes.mark_captured_value(actual.clone());
                    }
                    classes.bind_formal(formal, actual);
                    continue;
                }
                // Missing type metadata or capture identity still requires a
                // proven runtime identity before crossing the call boundary.
                Some(true) | None => {}
            }
        }
        // A receiver that does bind by reference must name the caller's
        // object exactly as the caller's own field accesses name it, since
        // that is what the overlap gate compares. `canonical_capture_identity`
        // prefers a proven runtime identity and otherwise issues a capture
        // identity, and it issues one only for a cell stored once, so the
        // name cannot outlive the binding it stands for.
        if dispatch_receiver && classes.canonical_capture_identity(actual.clone()).is_some() {
            if task_transfer {
                classes.mark_captured_value(actual.clone());
            }
            classes.bind_formal(formal, actual);
            continue;
        }
        let (bound, mut binding_reasons) = classes
            .bound_canonical_identity(actual.clone())
            .into_parts();
        let canonicals = if let Some(canonical) = bound {
            vec![canonical]
        } else {
            let mut canonicals = Vec::new();
            for (task, invocation, procedure, value) in classes.equivalent_values(actual.clone()) {
                if task != caller.task
                    || invocation != caller.invocation
                    || procedure != caller.procedure
                {
                    continue;
                }
                let (resolved, reasons) = provider
                    .resolved_value(&procedure, call.point, value, request)?
                    .into_parts();
                binding_reasons.extend(reasons);
                if binding_reasons.is_empty() && resolved.exact_candidate().is_some() {
                    let fact = ConcurrencyIdentityFact {
                        resolved,
                        storage_origin: None,
                    };
                    if !canonicals.contains(&fact) {
                        canonicals.push(fact);
                    }
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
            invocation: event.invocation,
            procedure: event.procedure.clone(),
            value: event.subject,
        };
        let (subject, reasons) =
            if let Some(subject) = classes.canonical_capture_identity(local.clone()) {
                (Some(subject.canonical().clone()), subject.reasons())
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
                .any(|(task, _, procedure, value)| {
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
            invocation: event.invocation,
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
            if successor == point {
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

#[derive(Debug, Clone, Copy)]
struct AllocationOrigin {
    invocation: InvocationId,
    point: ProgramPointId,
}

struct AccessComparisonEvidence<'a> {
    invocations: &'a Invocations,
    modeled: &'a HashMap<ContextKey, Vec<(ProgramPointId, ResolvedConcurrencyEffect)>>,
    lock_states: &'a HashMap<ContextKey, HashMap<ProgramPointId, MustLockSet>>,
    synchronizations: &'a [IntrinsicSynchronization],
    task_local_allocations: &'a HashMap<TaskId, HashSet<CanonicalConcurrencyLocation>>,
    allocation_origins: &'a HashMap<CanonicalConcurrencyLocation, AllocationOrigin>,
}

fn compare_accesses(
    provider: &impl ConcurrencyProvider,
    tasks: &[Task],
    classes: &mut LocationClasses,
    evidence: AccessComparisonEvidence<'_>,
    mut accesses: Vec<Access>,
    report: &mut ConcurrentAccessReport,
) {
    let AccessComparisonEvidence {
        invocations,
        modeled,
        lock_states,
        synchronizations,
        task_local_allocations,
        allocation_origins,
    } = evidence;
    let mut receivers = HashMap::<InvocationId, Vec<&IntrinsicSynchronization>>::default();
    for event in synchronizations {
        if event.operation == crate::analyzer::semantic::SynchronizationOperation::ChannelReceive {
            receivers.entry(event.invocation).or_default().push(event);
        }
    }
    let mut channel_barriers = ChannelCompletionBarriers {
        synchronizations,
        receivers,
        sites: HashMap::default(),
        remaining_entries: accesses.len() + synchronizations.len(),
    };
    let mut cell_cardinalities = HashMap::default();
    for access in &mut accesses {
        if let Some(local_location) = &mut access.local_location {
            *local_location = classes.root(local_location.clone());
            if access.canonical.is_none() && access.local_identity {
                let canonical = canonical_local_location(local_location);
                access.canonical = Some(canonical.clone());
                access.resolved_location = ResolvedConcurrencyLocation::independent(
                    canonical,
                    ConcurrencyStorageFamily::LexicalCell {
                        invocation: local_location.invocation,
                        location: local_location.location,
                    },
                );
            }
            if access.local_identity {
                let cardinality = *cell_cardinalities
                    .entry(local_location.clone())
                    .or_insert_with(|| {
                        let semantics = local_location.procedure.semantics();
                        match semantics
                            .memory_location(local_location.location)
                            .expect("validated lexical cell exists")
                            .kind
                        {
                            MemoryLocationKind::LexicalCell { binding } => provider
                                .lexical_cell_cardinality(&local_location.procedure, binding),
                            MemoryLocationKind::Capture { .. }
                                if classes.value_captures.contains(local_location) =>
                            {
                                ConcurrencyObjectCardinality::Multiple
                            }
                            // An unbound capture does not establish its owner's
                            // cell lifetime merely by naming that capture.
                            _ => ConcurrencyObjectCardinality::Unknown,
                        }
                    });
                access.resolved_location.cardinality = cardinality;
                if cardinality != ConcurrencyObjectCardinality::Singleton {
                    access.reasons.push(ConcurrencyOpenReason::UnknownLocation);
                }
                if cardinality == ConcurrencyObjectCardinality::Unknown {
                    access.resolved_location.exhaustive = false;
                    // An unresolved capture owner may never obtain a common
                    // candidate with another access. Preserve the gap even
                    // when no conflict row can be constructed for it.
                    report.reasons.push(ConcurrencyOpenReason::UnknownLocation);
                }
            }
        }
    }
    for first_index in 0..accesses.len() {
        for second_index in first_index + 1..accesses.len() {
            let first = &accesses[first_index];
            let second = &accesses[second_index];
            if (first.site.task == second.site.task
                && !(shared_across_task_instances(
                    tasks,
                    invocations,
                    first,
                    task_local_allocations,
                    allocation_origins,
                ) || shared_across_task_instances(
                    tasks,
                    invocations,
                    second,
                    task_local_allocations,
                    allocation_origins,
                )))
                || (first.site.mode == ConcurrentAccessMode::Read
                    && second.site.mode == ConcurrentAccessMode::Read)
            {
                continue;
            }
            let overlap = access_location_overlap(first, second);
            if overlap == AccessOverlap::Disjoint {
                continue;
            }
            // An unnamed pair can only retain the report-level location gap;
            // even a proven ordering cannot produce a named relation for it.
            // Once that gap is retained, repeating this pair's ordering work
            // cannot change the result. Named partial relations still follow
            // the ordinary comparison below.
            if overlap == AccessOverlap::MayAlias(None)
                && report
                    .reasons
                    .contains(&ConcurrencyOpenReason::UnknownLocation)
            {
                continue;
            }
            if !tasks_may_parallel(tasks, invocations, first, second, allocation_origins) {
                continue;
            }
            let relation = task_relation(tasks, first.site.task, second.site.task);
            let (ordering, ordering_reasons) = ordering(
                tasks,
                invocations,
                first,
                second,
                modeled,
                &mut channel_barriers,
                allocation_origins,
            );
            let protection = if first.atomic && second.atomic {
                ConcurrentProtection::AtomicOnly
            } else {
                compatible_lock_protection(first, second, lock_states)
            };
            let (location, alias_open) = match overlap {
                AccessOverlap::Same(location) => (location, false),
                AccessOverlap::MayAlias(Some(location)) => (location, true),
                AccessOverlap::MayAlias(None) => {
                    // A proven ordering or common protection makes this pair
                    // safe regardless of whether the references alias.
                    if (ordering == ConcurrentOrdering::HappensBefore
                        && ordering_reasons.is_empty())
                        || matches!(
                            protection,
                            ConcurrentProtection::CompatibleLock | ConcurrentProtection::AtomicOnly
                        )
                    {
                        continue;
                    }
                    report.reasons.push(ConcurrencyOpenReason::UnknownLocation);
                    continue;
                }
                AccessOverlap::Disjoint => unreachable!("disjoint accesses were skipped"),
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

    // Compare one static access with itself across runtime task instances.
    // Distinct static sites in the same repeated task are compared above.
    for access in &accesses {
        if access.site.mode != ConcurrentAccessMode::Write
            || access.atomic
            || !shared_across_task_instances(
                tasks,
                invocations,
                access,
                task_local_allocations,
                allocation_origins,
            )
        {
            continue;
        }
        let mut reasons = access.reasons.clone();
        match repetition_orders_access(tasks, invocations, access, modeled, &mut channel_barriers) {
            ConcurrencyAnswer::Proven(true) => continue,
            ConcurrencyAnswer::Open { reasons: open, .. } => reasons.extend(open),
            ConcurrencyAnswer::Proven(false) => {}
        }
        // Two runtime instances of one repeated spawn reach this write holding
        // whatever locks the body holds there, so the access is compared
        // against itself. Computing this rather than asserting `Unprotected`
        // matters: a body that takes a lock before its write is protected
        // against its own repetition exactly as it is against a sibling.
        let protection = if access.atomic {
            ConcurrentProtection::AtomicOnly
        } else {
            compatible_lock_protection(access, access, lock_states)
        };
        if let Some(group) = &tasks[access.site.task.0 as usize].group {
            reasons.extend(group.reasons.iter().cloned());
        }
        if protection == ConcurrentProtection::Open {
            reasons.push(ConcurrencyOpenReason::AmbiguousSynchronization);
        }
        let Some(location) = access.canonical.clone() else {
            // An unresolved element still participates in repeated execution.
            // Without ordering or common protection, retain the gap instead
            // of inventing an element identity or silently dropping the write.
            if protection != ConcurrentProtection::CompatibleLock {
                report.reasons.extend(reasons);
                report.reasons.push(ConcurrencyOpenReason::UnknownLocation);
            }
            continue;
        };
        reasons.sort();
        reasons.dedup();
        report.conflicts.push(ConcurrentAccessConflict {
            location,
            first: access.site.clone(),
            second: access.site.clone(),
            task_relation: ConcurrentTaskRelation::Repeated,
            ordering: ConcurrentOrdering::Unordered,
            protection,
            proven: reasons.is_empty() && protection != ConcurrentProtection::Open,
            exhaustive: reasons.is_empty(),
            reasons,
        });
    }
}

/// Whether this route can overlap itself across repeated task instances.
/// Unknown identity remains eligible. A creation-local route can exclude its
/// own repetition, but cannot exclude a pair with a different unresolved route
/// that might reach a published object. Such a pair needs both routes local.
fn shared_across_task_instances(
    tasks: &[Task],
    invocations: &Invocations,
    access: &Access,
    task_local_allocations: &HashMap<TaskId, HashSet<CanonicalConcurrencyLocation>>,
    allocation_origins: &HashMap<CanonicalConcurrencyLocation, AllocationOrigin>,
) -> bool {
    let task = &tasks[access.site.task.0 as usize];
    if task.repetition.is_none()
        || (access.local_identity
            && access
                .local_location
                .as_ref()
                .is_some_and(|root| root.task == access.site.task))
        || access_base(access).is_some_and(|base| {
            task_local_allocations
                .get(&access.site.task)
                .is_some_and(|allocations| allocations.contains(base))
        })
    {
        return false;
    }
    !access_base(access)
        .and_then(|base| allocation_origins.get(base))
        .is_some_and(|birth| {
            let repetition = invocations.entries[birth.invocation.0 as usize].repetition;
            repetition.is_some()
                && repetition == task.repetition
                && invocations.contains(birth.invocation, task.entry_invocation)
        })
}

fn repetition_orders_access(
    tasks: &[Task],
    invocations: &Invocations,
    access: &Access,
    modeled: &HashMap<ContextKey, Vec<(ProgramPointId, ResolvedConcurrencyEffect)>>,
    channel_barriers: &mut ChannelCompletionBarriers<'_>,
) -> ConcurrencyAnswer<bool> {
    let task = &tasks[access.site.task.0 as usize];
    let mut reasons = Vec::new();
    if task.repetitions_serialized {
        match completion_orders_access(tasks, invocations, access) {
            ConcurrencyAnswer::Proven(true) => return ConcurrencyAnswer::Proven(true),
            ConcurrencyAnswer::Open { reasons: open, .. } => reasons.extend(open),
            ConcurrencyAnswer::Proven(false) => {}
        }
    }
    let repetition = task
        .repetition
        .expect("only repeated tasks have a repetition ordering obligation");
    let repeated = &invocations.entries[repetition.0 as usize];
    let synchronous_repetition = repeated.caller.is_some_and(|(caller, _)| {
        invocations.entries[caller.0 as usize].context.task == repeated.context.task
    });
    if synchronous_repetition && tasks[repeated.context.task.0 as usize].repetition.is_none() {
        let after = (
            repetition,
            repeated.context.procedure.semantics().normal_exit_point(),
        );
        let channel =
            synchronized_before_point(tasks, invocations, access, after, channel_barriers);
        let group = joined_before_point(tasks, invocations, access, after, modeled);
        if matches!(channel, ConcurrencyAnswer::Proven(true))
            || matches!(group, ConcurrencyAnswer::Proven(true))
        {
            return ConcurrencyAnswer::Proven(true);
        }
        for answer in [channel, group] {
            if let ConcurrencyAnswer::Open { reasons: open, .. } = answer {
                reasons.extend(open);
            }
        }
    }
    if let Some(group) = &task.group {
        reasons.extend(group.reasons.iter().cloned());
    }
    if reasons.is_empty() {
        ConcurrencyAnswer::Proven(false)
    } else {
        reasons.sort();
        reasons.dedup();
        ConcurrencyAnswer::Open {
            partial: false,
            reasons,
        }
    }
}

fn access_base(access: &Access) -> Option<&CanonicalConcurrencyLocation> {
    if let Some(origin) = &access.storage_origin {
        return Some(origin);
    }
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
    invocation: InvocationId,
    canonical: CanonicalConcurrencyLocation,
) -> CanonicalConcurrencyLocation {
    CanonicalConcurrencyLocation::new(
        format!(
            "task:{}/invocation:{}/{identity}",
            task.get(),
            invocation.get(),
            identity = canonical.identity
        ),
        canonical.kind,
    )
}

fn access_location_overlap(first: &Access, second: &Access) -> AccessOverlap {
    if first.local_identity && second.local_identity {
        // A declaration shared by two captures can describe several runtime
        // cells. Equal source identities alone do not prove the same storage.
        return first.resolved_location.overlap(&second.resolved_location);
    }
    if let (Some(first_location), Some(second_location)) = (&first.canonical, &second.canonical)
        && first_location == second_location
    {
        return if first.resolved_location.exact_candidate() == Some(first_location)
            && second.resolved_location.exact_candidate() == Some(second_location)
        {
            AccessOverlap::Same(first_location.clone())
        } else {
            AccessOverlap::MayAlias(Some(first_location.clone()))
        };
    }
    if first
        .resolved_location
        .storage_is_disjoint(&second.resolved_location)
    {
        return AccessOverlap::Disjoint;
    }
    let exact = first.resolved_location.exact_candidate().is_some()
        && second.resolved_location.exact_candidate().is_some();
    if let (Some(first), Some(second)) = (
        first.index_alias_domain.as_ref(),
        second.index_alias_domain.as_ref(),
    ) {
        if first.base != second.base {
            return AccessOverlap::MayAlias(None);
        }
        match (first.identity, second.identity) {
            (IndexedLocationIdentity::Aggregate, IndexedLocationIdentity::Aggregate) => {
                return exact_index_location(first).map_or(
                    AccessOverlap::MayAlias(None),
                    |location| {
                        if exact {
                            AccessOverlap::Same(location)
                        } else {
                            AccessOverlap::MayAlias(Some(location))
                        }
                    },
                );
            }
            (IndexedLocationIdentity::Element, IndexedLocationIdentity::Element) => {
                if let (Some(first_index), Some(second_index)) =
                    (first.constant_index, second.constant_index)
                {
                    return if first_index == second_index {
                        exact_index_location(first).map_or(
                            AccessOverlap::MayAlias(None),
                            |location| {
                                if exact {
                                    AccessOverlap::Same(location)
                                } else {
                                    AccessOverlap::MayAlias(Some(location))
                                }
                            },
                        )
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
    // `member` agrees only where both producers could type the receiver. A
    // capture inside a spawned closure cannot, so it anchors at the use while
    // the parent anchors at the declaration, and comparing anchors alone calls
    // a real race disjoint. A named declaration is the same from either side.
    let same_member = match (&first.declaration, &second.declaration) {
        (Some(first_declaration), Some(second_declaration)) => {
            first_declaration == second_declaration
        }
        _ => {
            first.member.path() == second.member.path()
                && first.member.anchor() == second.member.anchor()
        }
    };
    if !same_member {
        return AccessOverlap::Disjoint;
    }
    match (&first.base, &second.base) {
        (Some(first_base), Some(second_base)) if first_base == second_base => {
            let location = exact_field_location(first_base, &first.member);
            if exact {
                AccessOverlap::Same(location)
            } else {
                AccessOverlap::MayAlias(Some(location))
            }
        }
        (Some(_), Some(_)) => AccessOverlap::MayAlias(None),
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
            "local:{}:{}:{}:{}",
            location.task.get(),
            location.invocation.get(),
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

fn access_is_local_to_invocation(
    invocations: &Invocations,
    allocation_origins: &HashMap<CanonicalConcurrencyLocation, AllocationOrigin>,
    access: &Access,
    ancestor: InvocationId,
) -> bool {
    let birth = if access.local_identity {
        access.local_location.as_ref().and_then(|root| {
            matches!(
                root.procedure
                    .semantics()
                    .memory_location(root.location)
                    .expect("local root belongs to its procedure")
                    .kind,
                MemoryLocationKind::LexicalCell { .. }
            )
            .then_some(root.invocation)
        })
    } else {
        access_base(access)
            .and_then(|base| allocation_origins.get(base))
            .map(|origin| origin.invocation)
    };
    birth.is_some_and(|birth| {
        invocations.contains(ancestor, birth) && invocations.contains(birth, access.site.invocation)
    })
}

fn tasks_may_parallel(
    tasks: &[Task],
    invocations: &Invocations,
    first: &Access,
    second: &Access,
    allocation_origins: &HashMap<CanonicalConcurrencyLocation, AllocationOrigin>,
) -> bool {
    let first_task = &tasks[first.site.task.0 as usize];
    let second_task = &tasks[second.site.task.0 as usize];
    let parent_child = |parent: &Access, child: &Access, child_task: &Task| {
        if child_task.parent != Some(parent.site.task) {
            return None;
        }
        let spawn_invocation = child_task.spawn_invocation?;
        let spawn_procedure = child_task.spawn_procedure.as_ref()?;
        let spawn = child_task
            .spawn_call
            .and_then(|call| spawn_procedure.semantics().call_site(call))?
            .point;
        let (context, parent_point, spawn) = invocations.common_points(
            parent.site.invocation,
            parent.site.point,
            spawn_invocation,
            spawn,
        )?;
        let procedure = &context.procedure;
        let fresh_in_common = access_is_local_to_invocation(
            invocations,
            allocation_origins,
            parent,
            context.invocation,
        ) && access_is_local_to_invocation(
            invocations,
            allocation_origins,
            child,
            context.invocation,
        );
        Some(
            (invocations.entries[context.invocation.0 as usize]
                .repetition
                .is_some()
                && !fresh_in_common)
                || parent_point == spawn
                || point_reaches(procedure, parent_point, spawn)
                || point_reaches(procedure, spawn, parent_point),
        )
    };
    if let Some(answer) = parent_child(first, second, second_task) {
        return answer;
    }
    if let Some(answer) = parent_child(second, first, first_task) {
        return answer;
    }
    if first_task.parent == second_task.parent
        && let (
            Some(first_procedure),
            Some(second_procedure),
            Some(first_call),
            Some(second_call),
            Some(first_invocation),
            Some(second_invocation),
        ) = (
            first_task.spawn_procedure.as_ref(),
            second_task.spawn_procedure.as_ref(),
            first_task.spawn_call,
            second_task.spawn_call,
            first_task.spawn_invocation,
            second_task.spawn_invocation,
        )
    {
        let first_spawn = first_procedure
            .semantics()
            .call_site(first_call)
            .expect("spawn call belongs to its procedure")
            .point;
        let second_spawn = second_procedure
            .semantics()
            .call_site(second_call)
            .expect("spawn call belongs to its procedure")
            .point;
        let Some((context, first_spawn, second_spawn)) = invocations.common_points(
            first_invocation,
            first_spawn,
            second_invocation,
            second_spawn,
        ) else {
            return true;
        };
        let procedure = &context.procedure;
        let fresh_in_common = access_is_local_to_invocation(
            invocations,
            allocation_origins,
            first,
            context.invocation,
        ) && access_is_local_to_invocation(
            invocations,
            allocation_origins,
            second,
            context.invocation,
        );
        return (invocations.entries[context.invocation.0 as usize]
            .repetition
            .is_some()
            && !fresh_in_common)
            || first_spawn == second_spawn
            || point_reaches(procedure, first_spawn, second_spawn)
            || point_reaches(procedure, second_spawn, first_spawn);
    }
    true
}

fn task_relation(tasks: &[Task], first: TaskId, second: TaskId) -> ConcurrentTaskRelation {
    if tasks[first.0 as usize].repetition.is_some() || tasks[second.0 as usize].repetition.is_some()
    {
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

#[allow(clippy::too_many_arguments)]
fn ordering(
    tasks: &[Task],
    invocations: &Invocations,
    first: &Access,
    second: &Access,
    modeled: &HashMap<ContextKey, Vec<(ProgramPointId, ResolvedConcurrencyEffect)>>,
    channel_barriers: &mut ChannelCompletionBarriers<'_>,
    allocation_origins: &HashMap<CanonicalConcurrencyLocation, AllocationOrigin>,
) -> (ConcurrentOrdering, Vec<ConcurrencyOpenReason>) {
    if first.site.task == second.site.task {
        let first = repetition_orders_access(tasks, invocations, first, modeled, channel_barriers);
        let second =
            repetition_orders_access(tasks, invocations, second, modeled, channel_barriers);
        if matches!(first, ConcurrencyAnswer::Proven(true))
            && matches!(second, ConcurrencyAnswer::Proven(true))
        {
            return (ConcurrentOrdering::HappensBefore, Vec::new());
        }
        let mut reasons = Vec::new();
        for answer in [first, second] {
            if let ConcurrencyAnswer::Open { reasons: open, .. } = answer {
                reasons.extend(open);
            }
        }
        return if reasons.is_empty() {
            (ConcurrentOrdering::Unordered, reasons)
        } else {
            reasons.sort();
            reasons.dedup();
            (ConcurrentOrdering::Open, reasons)
        };
    }
    let mut ancestors = HashSet::default();
    let mut current = Some(first.site.task);
    while let Some(task) = current {
        ancestors.insert(task);
        current = tasks[task.0 as usize].parent;
    }
    let mut common = second.site.task;
    while !ancestors.contains(&common) {
        common = tasks[common.0 as usize]
            .parent
            .expect("tasks share the solve root");
    }
    let common = &tasks[common.0 as usize];
    let ordered = if common.repetition.is_some()
        && !(access_is_local_to_invocation(
            invocations,
            allocation_origins,
            first,
            common.entry_invocation,
        ) && access_is_local_to_invocation(
            invocations,
            allocation_origins,
            second,
            common.entry_invocation,
        )) {
        // A local wait orders one parent activation. It does not join the
        // other runtime parents represented by this same task. Keep an
        // attempted local proof open until that outer boundary is covered.
        (
            ConcurrentOrdering::Open,
            vec![ConcurrencyOpenReason::AmbiguousSynchronization],
        )
    } else {
        (ConcurrentOrdering::HappensBefore, Vec::new())
    };
    let mut recurrence_reasons = Vec::new();
    for (parent, child) in [(first, second), (second, first)] {
        if let Some(recurrences) =
            access_before_spawn(tasks, invocations, parent, child, allocation_origins)
        {
            let barriers = channel_barriers.for_access(child);
            let joins = join_completion_barriers(tasks, invocations, child, modeled);
            let mut complete = true;
            for (invocation, point) in recurrences {
                let matching = barriers
                    .iter()
                    .chain(&joins)
                    .filter(|barrier| barrier.between_recurrences(invocations, invocation, point))
                    .collect::<Vec<_>>();
                if !matching.iter().any(|barrier| barrier.reasons.is_empty()) {
                    complete = false;
                    if parent.local_identity {
                        // The retained lexical cell identifies a declaration,
                        // but does not yet state whether its storage is created
                        // anew by this loop (as with a loop-body declaration).
                        recurrence_reasons.push(ConcurrencyOpenReason::UnknownLocation);
                    }
                    // One allocation site may denote a fresh object on each
                    // recurrence. Until object-instance correspondence is
                    // known, site equality cannot prove a cross-iteration race.
                    if access_base(parent)
                        .and_then(|base| allocation_origins.get(base))
                        .is_some_and(|birth| {
                            invocations
                                .ancestry_points(birth.invocation, birth.point)
                                .get(&invocation)
                                .is_some_and(|birth_point| {
                                    let procedure = &invocations.entries[invocation.0 as usize]
                                        .context
                                        .procedure;
                                    point_is_cyclic(procedure.semantics(), *birth_point)
                                        && (*birth_point == point
                                            || (point_reaches(procedure, point, *birth_point)
                                                && point_reaches(procedure, *birth_point, point)))
                                })
                        })
                    {
                        recurrence_reasons.push(ConcurrencyOpenReason::UnknownLocation);
                    }
                    recurrence_reasons.extend(
                        matching
                            .iter()
                            .flat_map(|barrier| barrier.reasons.iter().cloned()),
                    );
                }
            }
            if complete {
                return ordered;
            }
        }
    }
    let forward_join = joined_before_point(
        tasks,
        invocations,
        first,
        (second.site.invocation, second.site.point),
        modeled,
    );
    let reverse_join = joined_before_point(
        tasks,
        invocations,
        second,
        (first.site.invocation, first.site.point),
        modeled,
    );
    if matches!(forward_join, ConcurrencyAnswer::Proven(true))
        || matches!(reverse_join, ConcurrencyAnswer::Proven(true))
    {
        return ordered;
    }
    let forward = synchronized_before_point(
        tasks,
        invocations,
        first,
        (second.site.invocation, second.site.point),
        channel_barriers,
    );
    let reverse = synchronized_before_point(
        tasks,
        invocations,
        second,
        (first.site.invocation, first.site.point),
        channel_barriers,
    );
    if matches!(forward, ConcurrencyAnswer::Proven(true))
        || matches!(reverse, ConcurrencyAnswer::Proven(true))
    {
        return ordered;
    }
    let mut reasons = recurrence_reasons;
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

/// Points at which an access has completed, as observed by one synchronous
/// invocation. Uncertain identity or completion stays attached to the points.
#[derive(Clone)]
struct CompletionBarrier {
    invocation: InvocationId,
    points: HashSet<ProgramPointId>,
    reasons: Vec<ConcurrencyOpenReason>,
}

impl CompletionBarrier {
    fn before(
        &self,
        tasks: &[Task],
        invocations: &Invocations,
        after: (InvocationId, ProgramPointId),
    ) -> bool {
        let task = invocations.entries[self.invocation.0 as usize].context.task;
        observation_in_task(tasks, invocations, task, after).is_some_and(|(target, point)| {
            invocations.required_points_before(self.invocation, self.points.clone(), target, point)
        })
    }

    fn between_recurrences(
        &self,
        invocations: &Invocations,
        invocation: InvocationId,
        point: ProgramPointId,
    ) -> bool {
        let procedure = &invocations.entries[invocation.0 as usize].context.procedure;
        assert!(point_is_cyclic(procedure.semantics(), point));
        invocations
            .required_points_in(self.invocation, self.points.clone(), invocation)
            .is_some_and(|points| {
                // A lifted call point can itself contain the mandatory wait.
                points.contains(&point)
                    || all_recurrences_cross_points(
                        procedure,
                        point,
                        &points.into_iter().collect::<Vec<_>>(),
                    )
            })
    }
}

fn completed_before_point(
    tasks: &[Task],
    invocations: &Invocations,
    barriers: &[CompletionBarrier],
    after: (InvocationId, ProgramPointId),
) -> ConcurrencyAnswer<bool> {
    let mut reasons = Vec::new();
    for barrier in barriers {
        if barrier.before(tasks, invocations, after) {
            if barrier.reasons.is_empty() {
                return ConcurrencyAnswer::Proven(true);
            }
            reasons.extend(barrier.reasons.iter().cloned());
        }
    }
    if reasons.is_empty() {
        ConcurrencyAnswer::Proven(false)
    } else {
        reasons.sort();
        reasons.dedup();
        ConcurrencyAnswer::Open {
            partial: false,
            reasons,
        }
    }
}

fn synchronized_before_point(
    tasks: &[Task],
    invocations: &Invocations,
    before: &Access,
    after: (InvocationId, ProgramPointId),
    channel_barriers: &mut ChannelCompletionBarriers<'_>,
) -> ConcurrencyAnswer<bool> {
    completed_before_point(
        tasks,
        invocations,
        channel_barriers.for_access(before).as_ref(),
        after,
    )
}

/// Channel completion depends on the access site and the solve's fixed
/// synchronization inventory, independently of the access paired with it.
/// Invocation IDs keep repeated calls to the same procedure separate. This
/// cache is discarded with the solve, so no source or summary generation can
/// reuse facts from an earlier query.
struct ChannelCompletionBarriers<'a> {
    synchronizations: &'a [IntrinsicSynchronization],
    receivers: HashMap<InvocationId, Vec<&'a IntrinsicSynchronization>>,
    sites: HashMap<(InvocationId, ProgramPointId), Vec<CompletionBarrier>>,
    // Count keys, barriers, points and reasons. Retained cache entries stay
    // linear in the already retained input. A miss recomputes the same answer;
    // cache capacity never changes proof or coverage.
    remaining_entries: usize,
}

impl ChannelCompletionBarriers<'_> {
    fn for_access(&mut self, access: &Access) -> std::borrow::Cow<'_, [CompletionBarrier]> {
        match self
            .sites
            .entry((access.site.invocation, access.site.point))
        {
            Entry::Occupied(entry) => std::borrow::Cow::Borrowed(entry.into_mut()),
            Entry::Vacant(entry) => {
                let barriers =
                    channel_completion_barriers(access, self.synchronizations, &self.receivers);
                let weight = 1 + barriers
                    .iter()
                    .map(|barrier| 1 + barrier.points.len() + barrier.reasons.len())
                    .sum::<usize>();
                if weight > self.remaining_entries {
                    return std::borrow::Cow::Owned(barriers);
                }
                self.remaining_entries -= weight;
                std::borrow::Cow::Borrowed(entry.insert(barriers))
            }
        }
    }
}

fn channel_completion_barriers(
    before: &Access,
    synchronizations: &[IntrinsicSynchronization],
    receivers: &HashMap<InvocationId, Vec<&IntrinsicSynchronization>>,
) -> Vec<CompletionBarrier> {
    let senders = synchronizations
        .iter()
        .filter(|event| {
            event.task == before.site.task
                && event.invocation == before.site.invocation
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
    let mut barriers = Vec::new();
    let mut represented_senders = HashSet::default();
    for sender in &senders {
        // Equal configurations produce equal barriers. Keep every original
        // sender in the point-set computations below: dropping its point
        // would change which paths prove mandatory completion.
        if !represented_senders.insert((
            sender.subject.as_ref(),
            sender.point == before.site.point,
            sender.fresh_allocation,
            sender.root_input,
            sender.reasons.as_slice(),
        )) {
            continue;
        }
        if let Some(subject) = sender.subject.as_ref() {
            let matching_sends = senders
                .iter()
                .filter_map(|send| {
                    (send.subject.as_ref() == Some(subject) && send.point != before.site.point)
                        .then_some(send.point)
                })
                .collect::<HashSet<_>>();
            if all_exit_paths_cross_points(
                &before.site.procedure,
                before.site.point,
                &matching_sends,
            ) {
                for (invocation, receivers) in receivers {
                    let points = receivers
                        .iter()
                        .filter_map(|receive| {
                            (receive.subject.as_ref() == Some(subject)).then_some(receive.point)
                        })
                        .collect::<HashSet<_>>();
                    if !points.is_empty() {
                        barriers.push(CompletionBarrier {
                            invocation: *invocation,
                            points,
                            reasons: Vec::new(),
                        });
                    }
                }
            }
        }
        let possibly_matching_sends = senders
            .iter()
            .filter_map(|candidate| {
                synchronization_subjects_may_match(sender, candidate).then_some(candidate.point)
            })
            .collect::<HashSet<_>>();
        if !all_exit_paths_cross_points(
            &before.site.procedure,
            before.site.point,
            &possibly_matching_sends,
        ) {
            continue;
        }
        for (invocation, receivers) in receivers {
            let possible = receivers
                .iter()
                .filter(|receive| synchronization_subjects_may_match(sender, receive))
                .collect::<Vec<_>>();
            if possible.is_empty()
                || (sender.point != before.site.point
                    && !possible
                        .iter()
                        .any(|receive| sender.subject.is_none() || receive.subject.is_none()))
            {
                continue;
            }
            let mut reasons = sender.reasons.clone();
            reasons.extend(
                possible
                    .iter()
                    .flat_map(|receive| receive.reasons.iter().cloned()),
            );
            if reasons.is_empty() {
                reasons.push(ConcurrencyOpenReason::AmbiguousSynchronization);
            }
            barriers.push(CompletionBarrier {
                invocation: *invocation,
                points: possible.iter().map(|receive| receive.point).collect(),
                reasons,
            });
        }
    }
    barriers
}

/// Observe an access in an ancestor task at the spawn that leads to it.
/// Ordering before that spawn also orders before the descendant access.
fn observation_in_task(
    tasks: &[Task],
    invocations: &Invocations,
    observer: TaskId,
    site: (InvocationId, ProgramPointId),
) -> Option<(InvocationId, ProgramPointId)> {
    let (invocation, _) = site;
    let task = invocations.entries[invocation.0 as usize].context.task;
    if observer == task {
        return Some(site);
    }
    let mut descendant = task;
    loop {
        let task = &tasks[descendant.0 as usize];
        let parent = task.parent?;
        if parent == observer {
            let invocation = task.spawn_invocation?;
            let point = task
                .spawn_procedure
                .as_ref()?
                .semantics()
                .call_site(task.spawn_call?)
                .expect("spawn belongs to its caller")
                .point;
            return Some((invocation, point));
        }
        descendant = parent;
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

fn access_before_spawn(
    tasks: &[Task],
    invocations: &Invocations,
    parent: &Access,
    child: &Access,
    allocation_origins: &HashMap<CanonicalConcurrencyLocation, AllocationOrigin>,
) -> Option<Vec<(InvocationId, ProgramPointId)>> {
    let mut descendant = child.site.task;
    loop {
        let task = &tasks[descendant.0 as usize];
        let owner = task.parent?;
        if owner == parent.site.task {
            let (Some(spawn_call), Some(spawn_procedure), Some(spawn_invocation)) = (
                task.spawn_call,
                task.spawn_procedure.as_ref(),
                task.spawn_invocation,
            ) else {
                return None;
            };
            let spawn = spawn_procedure
                .semantics()
                .call_site(spawn_call)
                .expect("task spawn call belongs to its procedure")
                .point;
            let (context, parent_point, spawn) = invocations.common_points(
                parent.site.invocation,
                parent.site.point,
                spawn_invocation,
                spawn,
            )?;
            let procedure = &context.procedure;
            if parent_point == spawn || !point_dominates(procedure, parent_point, spawn) {
                return None;
            }
            // The parent itself can denote concurrent runtime tasks. Only
            // storage born inside that parent can use its local precedence
            // to order all accesses to the object.
            let parent_task = &tasks[parent.site.task.0 as usize];
            if parent_task.repetition.is_some()
                && !(access_is_local_to_invocation(
                    invocations,
                    allocation_origins,
                    parent,
                    parent_task.entry_invocation,
                ) && access_is_local_to_invocation(
                    invocations,
                    allocation_origins,
                    child,
                    parent_task.entry_invocation,
                ))
            {
                return None;
            }
            let parent_points =
                invocations.ancestry_points(parent.site.invocation, parent.site.point);
            let spawn_points = invocations.ancestry_points(
                spawn_invocation,
                spawn_procedure
                    .semantics()
                    .call_site(spawn_call)
                    .expect("spawn belongs to its caller")
                    .point,
            );
            let mut recurrences = Vec::new();
            for (invocation, parent_point) in parent_points {
                let Some(spawn_point) = spawn_points.get(&invocation) else {
                    continue;
                };
                let procedure = &invocations.entries[invocation.0 as usize].context.procedure;
                if point_is_cyclic(procedure.semantics(), parent_point)
                    && (parent_point == *spawn_point
                        || point_reaches(procedure, *spawn_point, parent_point))
                {
                    recurrences.push((invocation, parent_point));
                }
            }
            return Some(recurrences);
        }
        descendant = owner;
    }
}

/// A manual completion event does not cover later writes in the same task.
/// Require ordering within the shared synchronous caller; an unresolved
/// position remains open instead of turning a possible join into a race.
fn completion_orders_access(
    tasks: &[Task],
    invocations: &Invocations,
    access: &Access,
) -> ConcurrencyAnswer<bool> {
    let Some((completion, completion_point)) = tasks[access.site.task.0 as usize].completion else {
        return ConcurrencyAnswer::Proven(true);
    };
    if let Some((context, access_point, completion_point)) = invocations.common_points(
        access.site.invocation,
        access.site.point,
        completion,
        completion_point,
    ) && access_point != completion_point
    {
        let procedure = &context.procedure;
        if point_dominates(procedure, access_point, completion_point)
            && !point_reaches(procedure, completion_point, access_point)
        {
            return ConcurrencyAnswer::Proven(true);
        }
        if point_dominates(procedure, completion_point, access_point)
            && !point_reaches(procedure, access_point, completion_point)
        {
            return ConcurrencyAnswer::Proven(false);
        }
    }
    ConcurrencyAnswer::Open {
        partial: false,
        reasons: vec![ConcurrencyOpenReason::AmbiguousSynchronization],
    }
}

fn joined_before_point(
    tasks: &[Task],
    invocations: &Invocations,
    child: &Access,
    after: (InvocationId, ProgramPointId),
    modeled: &HashMap<ContextKey, Vec<(ProgramPointId, ResolvedConcurrencyEffect)>>,
) -> ConcurrencyAnswer<bool> {
    completed_before_point(
        tasks,
        invocations,
        &join_completion_barriers(tasks, invocations, child, modeled),
        after,
    )
}

fn join_completion_barriers(
    tasks: &[Task],
    invocations: &Invocations,
    child: &Access,
    modeled: &HashMap<ContextKey, Vec<(ProgramPointId, ResolvedConcurrencyEffect)>>,
) -> Vec<CompletionBarrier> {
    let task = &tasks[child.site.task.0 as usize];
    let (Some(parent), Some(task_group)) = (task.parent, task.group.as_ref()) else {
        return Vec::new();
    };
    let completion_reasons = match completion_orders_access(tasks, invocations, child) {
        ConcurrencyAnswer::Proven(false) => return Vec::new(),
        ConcurrencyAnswer::Proven(true) => Vec::new(),
        ConcurrencyAnswer::Open { reasons, .. } => reasons,
    };
    let mut barriers = Vec::new();
    for (context, effects) in modeled {
        if context.task != parent {
            continue;
        }
        let joins = effects
            .iter()
            .filter_map(|(point, effect)| {
                let group = match effect {
                    ResolvedConcurrencyEffect::TaskJoin { group }
                    | ResolvedConcurrencyEffect::WaitGroupWait { group } => group,
                    _ => return None,
                };
                Some((*point, group))
            })
            .collect::<Vec<_>>();
        let exact = joins
            .iter()
            .filter_map(|(point, group)| {
                (group.canonical.is_some()
                    && group.canonical == task_group.canonical
                    && group
                        .reasons
                        .iter()
                        .chain(&task_group.reasons)
                        .all(|reason| *reason == ConcurrencyOpenReason::UnknownLocation))
                .then_some(*point)
            })
            .collect::<HashSet<_>>();
        if !exact.is_empty() {
            barriers.push(CompletionBarrier {
                invocation: context.invocation,
                points: exact,
                reasons: completion_reasons.clone(),
            });
        }
        let possible = joins
            .iter()
            .filter_map(|(point, group)| {
                (!group.reasons.is_empty()
                    || !task_group.reasons.is_empty()
                    || group.canonical.is_none()
                    || task_group.canonical.is_none()
                    || group.canonical == task_group.canonical)
                    .then_some(*point)
            })
            .collect::<HashSet<_>>();
        if !possible.is_empty() {
            let mut reasons = completion_reasons.clone();
            reasons.extend(task_group.reasons.iter().cloned());
            reasons.extend(
                joins
                    .iter()
                    .flat_map(|(_, group)| group.reasons.iter().cloned()),
            );
            reasons.push(ConcurrencyOpenReason::AmbiguousSynchronization);
            barriers.push(CompletionBarrier {
                invocation: context.invocation,
                points: possible,
                reasons,
            });
        }
    }
    barriers
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
            invocation: access.site.invocation,
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
        invocation: access.site.invocation,
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

    fn exact_boundary_location(
        identity: &str,
        allocation: u32,
    ) -> ConcurrencyAnswer<ResolvedConcurrencyLocation> {
        let canonical = CanonicalConcurrencyLocation::new(identity, "object");
        ConcurrencyAnswer::Proven(ResolvedConcurrencyLocation::independent(
            canonical,
            ConcurrencyStorageFamily::Allocation {
                invocation: InvocationId(0),
                allocation: AllocationId::new(allocation),
            },
        ))
    }

    #[test]
    fn summary_access_paths_preserve_caller_allocation_identity() {
        let parameter = SummaryPort::Parameter(0);
        let path = SummaryConcurrencyAccessPath::port(parameter.clone());
        let mut first_call = SummaryConcurrencyBoundaryBinding::new();
        first_call.bind_location(
            parameter.clone(),
            exact_boundary_location("allocation:first", 0),
        );
        let mut second_call = SummaryConcurrencyBoundaryBinding::new();
        second_call.bind_location(
            parameter.clone(),
            exact_boundary_location("allocation:second", 1),
        );
        let mut shared_call = SummaryConcurrencyBoundaryBinding::new();
        shared_call.bind_location(parameter, exact_boundary_location("allocation:first", 0));

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
        exact.bind_location(
            object.clone(),
            exact_boundary_location("allocation:shared", 0),
        );
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
        unknown.bind_location(object, exact_boundary_location("allocation:shared", 0));
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
        fn lexical_cell_cardinality(
            &self,
            _procedure: &ProcedureHandle,
            _binding: ValueId,
        ) -> ConcurrencyObjectCardinality {
            // These task-topology fixtures declare their captured cells once
            // outside loops. The workspace provider's declaration facts are
            // exercised by paired fresh/shared RQL integration tests.
            ConcurrencyObjectCardinality::Singleton
        }

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
        fn lexical_cell_cardinality(
            &self,
            procedure: &ProcedureHandle,
            binding: ValueId,
        ) -> ConcurrencyObjectCardinality {
            LocalProvider.lexical_cell_cardinality(procedure, binding)
        }

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
            invocation: InvocationId(0),
            procedure: procedure.clone(),
            value: ValueId::new(0),
        };
        let second = LocalSynchronizationSubject::Value {
            task: TaskId(0),
            invocation: InvocationId(0),
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
    fn captured_identity_preserves_conflicting_binding_evidence() {
        let fixture = Fixture::new("package sample\nfunc root() {}\n");
        let artifact = fixture.artifact();
        let procedure = artifact
            .procedure_handle(ProcedureId::new(0))
            .expect("fixture root procedure");
        let subject = |value| LocalSynchronizationSubject::Value {
            task: TaskId(0),
            invocation: InvocationId(0),
            procedure: procedure.clone(),
            value: ValueId::new(value),
        };
        let first = subject(0);
        let second = subject(1);
        let allocation = CanonicalConcurrencyLocation::new("allocation:first", "object");
        for reverse in [false, true] {
            let mut classes = SynchronizationSubjectClasses::default();
            classes.mark_captured_value(first.clone());
            assert!(classes.canonical_capture_identity(first.clone()).is_some());
            classes.bind_canonical_value(
                first.clone(),
                ConcurrencyIdentityFact::allocation(
                    allocation.clone(),
                    InvocationId(0),
                    AllocationId::new(0),
                ),
            );
            assert_eq!(
                classes
                    .canonical_capture_identity(first.clone())
                    .map(|fact| fact.canonical().clone()),
                Some(allocation.clone())
            );
            classes.bind_canonical_value(
                second.clone(),
                ConcurrencyIdentityFact::allocation(
                    CanonicalConcurrencyLocation::new("allocation:second", "object"),
                    InvocationId(0),
                    AllocationId::new(1),
                ),
            );
            if reverse {
                classes.union(second.clone(), first.clone());
            } else {
                classes.union(first.clone(), second.clone());
            }
            assert!(
                classes.canonical_capture_identity(first.clone()).is_none(),
                "capture membership cannot override conflicting allocations"
            );
        }
        let mut classes = SynchronizationSubjectClasses::default();
        classes.mark_captured_value(first.clone());
        classes.bind_canonical_value(
            first.clone(),
            ConcurrencyIdentityFact::allocation(allocation, InvocationId(0), AllocationId::new(0)),
        );
        classes.bind_canonical_value(
            first.clone(),
            ConcurrencyIdentityFact::allocation(
                CanonicalConcurrencyLocation::new("allocation:replacement", "object"),
                InvocationId(0),
                AllocationId::new(1),
            ),
        );
        assert!(
            classes.canonical_capture_identity(first).is_none(),
            "a conflicting rebinding cannot fall back to the retained old identity"
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
            invocation: InvocationId(0),
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
            invocation: InvocationId(0),
            procedure: helper,
        };
        let locked_context = ContextKey {
            task: TaskId(0),
            invocation: InvocationId(0),
            procedure: locked.clone(),
        };
        let unlocked_context = ContextKey {
            task: TaskId(0),
            invocation: InvocationId(0),
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
        let exact_first = ResolvedConcurrencyLocation::independent(
            first.clone(),
            ConcurrencyStorageFamily::Allocation {
                invocation: InvocationId(0),
                allocation: AllocationId::new(0),
            },
        );
        let exact_second = ResolvedConcurrencyLocation::independent(
            second.clone(),
            ConcurrencyStorageFamily::Allocation {
                invocation: InvocationId(0),
                allocation: AllocationId::new(1),
            },
        );
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
    fn symbolic_reference_names_prove_equality_but_not_disjointness() {
        let first = CanonicalConcurrencyLocation::new("parameter:a", "object");
        let second = CanonicalConcurrencyLocation::new("parameter:b", "object");
        let a = ResolvedConcurrencyLocation::exact(first.clone());
        let b = ResolvedConcurrencyLocation::exact(second.clone());
        // Two pointer parameters can receive either one object or two objects.
        // Reusing one stable parameter still proves the same referent.
        assert_eq!(a.overlap(&a), AccessOverlap::Same(first));
        assert_eq!(a.overlap(&b), AccessOverlap::MayAlias(None));
        assert_eq!(b.overlap(&a), AccessOverlap::MayAlias(None));
        let allocation = ResolvedConcurrencyLocation::independent(
            second,
            ConcurrencyStorageFamily::Allocation {
                invocation: InvocationId(0),
                allocation: AllocationId::new(0),
            },
        );
        assert_eq!(a.overlap(&allocation), AccessOverlap::MayAlias(None));
        assert_eq!(allocation.overlap(&a), AccessOverlap::MayAlias(None));
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
