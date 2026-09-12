//! Spawn-rooted concurrent task slices and exact ordinary-access conflicts.
//!
//! The solver owns task topology and capture-cell identity. Workspace target,
//! heap, and reviewed API-model answers enter through [`ConcurrencyProvider`]
//! so this crate does not depend on an analyzer implementation.

mod publication;

use std::collections::VecDeque;
use std::collections::hash_map::Entry;

use crate::analyzer::semantic::{
    AllocationId, CallInvocationMode, CallSiteHandle, CallSiteId, CallableTarget,
    CallableTargetResolution, CaptureSource, ExecutionTiming, IcfgProviderBehaviorIdentity,
    IndexedLocationIdentity, MemoryAccessKind, MemoryLocationId, MemoryLocationKind,
    MemoryValueCopy, ProcedureHandle, ProgramPointId, SemanticEffect, SemanticGap,
    SemanticGapImpact, SemanticProviderError, SemanticRequest, SourceMappingId,
    SynchronizationPayload, SynchronizationPayloadCopy, ValueId,
};
use crate::dataflow::validate_recursive_summary_batch;
use crate::dataflow::{
    SemanticProcedureSummary, SummaryCallSourceWitness, SummaryConcurrencyAccessMode,
    SummaryConcurrencyAccessPath, SummaryConcurrencyAccessSelector, SummaryConcurrencyEffect,
    SummaryConcurrencyEffectKind, SummaryConcurrencyLockMode, SummaryConcurrencyLockOperation,
    SummaryConcurrencySubjectIdentity, SummaryDependencyKey, SummaryEffectKey, SummaryEventKey,
    SummaryLocationKey, SummaryPort,
};
use crate::hash::{HashMap, HashSet};
use crate::scalar_state::{
    ScalarCallEffects, ScalarEntryFact, ScalarFact, ScalarIntegerDomain, ScalarIntegerInterval,
    ScalarIntegerValue, ScalarStateDerivation,
};

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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ConcurrencyStorageFamily {
    Allocation {
        invocation: InvocationId,
        allocation: AllocationId,
    },
    InlineValue {
        invocation: InvocationId,
        value: ValueId,
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
    storage_path: Vec<ConcurrencyStorageSelector>,
}

/// A use-site field name can support equality without proving a different
/// field from another name. Keep declaration evidence in the storage path.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ConcurrencyStorageSelector {
    DeclaredField(SummaryLocationKey),
    UnresolvedField(SummaryLocationKey),
    Property(String),
    ConstantIndex(i128),
    Aggregate,
    AnyIndex,
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
            if matches!(first, ConcurrencyStorageSelector::UnresolvedField(_))
                || matches!(second, ConcurrencyStorageSelector::UnresolvedField(_))
            {
                return false;
            }
            if first == second {
                continue;
            }
            // A prefix can contain its sublocation. Only the first differing
            // pair of known field or element selectors proves separation.
            return matches!(
                (first, second),
                (
                    ConcurrencyStorageSelector::DeclaredField(_),
                    ConcurrencyStorageSelector::DeclaredField(_)
                ) | (
                    ConcurrencyStorageSelector::Property(_),
                    ConcurrencyStorageSelector::Property(_)
                ) | (
                    ConcurrencyStorageSelector::ConstantIndex(_),
                    ConcurrencyStorageSelector::ConstantIndex(_)
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
            SummaryConcurrencyAccessSelector::Property(key) => {
                ConcurrencyStorageSelector::Property(key.to_string())
            }
            SummaryConcurrencyAccessSelector::Field(field) => {
                // Source summaries also retain unresolved use-site locators.
                // The key itself carries no declaration-resolution evidence;
                // live source witnesses can recover that evidence below.
                ConcurrencyStorageSelector::UnresolvedField(*field)
            }
            SummaryConcurrencyAccessSelector::Aggregate => ConcurrencyStorageSelector::Aggregate,
            SummaryConcurrencyAccessSelector::ConstantIndex(index) => {
                ConcurrencyStorageSelector::ConstantIndex(*index)
            }
            SummaryConcurrencyAccessSelector::Index(port) => binding.integer(port).map_or(
                ConcurrencyStorageSelector::AnyIndex,
                ConcurrencyStorageSelector::ConstantIndex,
            ),
            SummaryConcurrencyAccessSelector::AnyIndex => ConcurrencyStorageSelector::AnyIndex,
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
    UnknownPublication,
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

/// Whether one structured semantic gap proves that a source memory access was
/// omitted from the IR consumed by the concurrency solver.
///
/// A heap impact alone is not enough. Go field-declaration and spawn gaps can
/// carry the same broad impact while every actual load or store is present.
/// The assignment capability with a heap write is the producer's exact
/// contract for an indirect write it could not lower.
pub(crate) fn semantic_gap_omits_concurrency_access(gap: &SemanticGap) -> bool {
    gap.capability == crate::analyzer::semantic::SemanticCapability::Assignments
        && gap.impacts.contains(SemanticGapImpact::HeapWrite)
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
        callable: ValueId,
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
    /// Exact behavior identity of the ICFG provider whose active model
    /// snapshot this provider consumes. Production summary projection accepts
    /// modeled effects only when both providers name the same behavior.
    fn summary_behavior_identity(&self) -> Option<IcfgProviderBehaviorIdentity> {
        None
    }

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

    /// Whether this exact fresh allocation remains confined to the task that
    /// executes its procedure through every procedure exit. A positive answer
    /// requires a complete publication inventory; ordinary allocation
    /// freshness or request-local private storage is not sufficient.
    fn allocation_is_task_local(
        &self,
        _procedure: &ProcedureHandle,
        _allocation: AllocationId,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<ConcurrencyAnswer<bool>, SemanticProviderError> {
        Ok(ConcurrencyAnswer::Open {
            partial: false,
            reasons: vec![ConcurrencyOpenReason::UnknownPublication],
        })
    }

    /// Whether indexed entries occupy storage that cannot overlap an ordinary
    /// object field slot. This is a storage-family proof, not an alias claim
    /// about references stored in those entries. Unknown families stay open.
    fn index_uses_separate_associative_storage(
        &self,
        _procedure: &ProcedureHandle,
        _location: MemoryLocationId,
    ) -> bool {
        false
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
    /// `None` means the parameter's binding semantics are unavailable. The
    /// caller's object identity cannot establish how the callee copies it.
    /// `Some(false)` is a proof that the callee writes a copy, so the
    /// caller's object must not cross, and `Some(true)` names the caller's
    /// object the way the caller's own accesses name it.
    fn parameter_binding(&self, _procedure: &ProcedureHandle, _ordinal: u32) -> Option<bool> {
        None
    }

    /// Positive type evidence that binding this parameter copies a descriptor
    /// while preserving the caller's backing storage. Inline aggregate copies
    /// and unavailable metadata must return false.
    fn parameter_preserves_backing(&self, _procedure: &ProcedureHandle, _ordinal: u32) -> bool {
        false
    }

    /// Exact type evidence that this parameter cannot carry a mutable object
    /// or callable reference. Value-copy evidence alone is insufficient.
    fn parameter_is_reference_free(&self, _procedure: &ProcedureHandle, _ordinal: u32) -> bool {
        false
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

    /// Look up modeled effects using the invocation's resolved source targets.
    /// A proven nonempty set names materialized source bodies; a proven empty
    /// set can describe an external boundary and still needs model lookup.
    /// A proven answer closes the effect inventory. Individual subjects may
    /// still carry identity reasons, which the solver refines and retains on
    /// the affected synchronization relation or modeled memory access.
    /// Open answer reasons describe missing effect coverage and are never
    /// erased by resolving a subject's storage identity.
    fn modeled_effects(
        &self,
        call: &CallSiteHandle,
        targets: &ConcurrencyAnswer<Vec<ProcedureHandle>>,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ConcurrencyAnswer<Vec<ResolvedConcurrencyEffect>>, SemanticProviderError>;

    /// Independent, exhaustive model certificate for an external call that
    /// cannot change or publish ordinary heap storage. Synchronization effects
    /// alone never provide this guarantee; missing certificates remain false.
    fn modeled_call_preserves_ordinary_heap(
        &self,
        _call: &CallSiteHandle,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<bool, SemanticProviderError> {
        Ok(false)
    }

    /// Whether this call needs modeled-effect lookup or an open effects
    /// boundary. Providers should answer from retained target/declaration
    /// facts; absent model activation does not close unresolved dispatch.
    /// `true` is the conservative default.
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
    // The caller-owned value whose environment this activation invokes.
    callable: Option<ValueId>,
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
        request: &mut SemanticRequest<'_>,
    ) -> Result<ContextKey, ConcurrencyOpenReason> {
        let invocation = InvocationId(
            u32::try_from(self.entries.len()).expect("bounded invocation IDs fit u32"),
        );
        let context = ContextKey {
            task,
            invocation,
            procedure,
        };
        let repetition = if let Some((parent, call)) = caller {
            let parent = &self.entries[parent.0 as usize];
            let semantics = parent.context.procedure.semantics();
            let point = semantics
                .call_site(call)
                .expect("invocation caller owns its call site")
                .point;
            if point_is_cyclic(semantics, point, request)? {
                Some(invocation)
            } else {
                parent.repetition
            }
        } else {
            None
        };
        let callable = caller.map(|(parent, call)| {
            self.entries[parent.0 as usize]
                .context
                .procedure
                .semantics()
                .call_site(call)
                .expect("owned invocation call")
                .callee
        });
        self.entries.push(Invocation {
            context: context.clone(),
            callable,
            caller,
            repetition,
        });
        Ok(context)
    }

    fn contains(&self, ancestor: InvocationId, descendant: InvocationId) -> bool {
        self.contains_with(ancestor, descendant, || true)
    }

    fn contains_bounded(
        &self,
        ancestor: InvocationId,
        descendant: InvocationId,
        request: &mut SemanticRequest<'_>,
    ) -> Result<bool, ConcurrencyOpenReason> {
        let mut visit_result = Ok(());
        let contains = self.contains_with(ancestor, descendant, || {
            visit_result = charge_concurrency_work(request, 1);
            visit_result.is_ok()
        });
        visit_result?;
        Ok(contains)
    }

    fn contains_with(
        &self,
        ancestor: InvocationId,
        mut descendant: InvocationId,
        mut visit: impl FnMut() -> bool,
    ) -> bool {
        loop {
            if !visit() {
                return false;
            }
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

    // Only an ancestral task-spawn edge closes this expansion. Equal targets
    // in sibling invocations and ordinary synchronous calls are distinct.
    fn repeats_spawn_edge(
        &self,
        caller: InvocationId,
        call: CallSiteId,
        target: &ProcedureHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<bool, ConcurrencyOpenReason> {
        let caller_procedure = &self.entries[caller.0 as usize].context.procedure;
        let mut current = caller;
        loop {
            if request.cancellation.is_cancelled()
                || request
                    .budget
                    .charge(crate::analyzer::semantic::SemanticWork {
                        nested_entries: 1,
                        ..crate::analyzer::semantic::SemanticWork::default()
                    })
                    .is_err()
            {
                return Err(ConcurrencyOpenReason::BudgetExhausted);
            }
            let entry = &self.entries[current.0 as usize];
            let Some((parent, edge)) = entry.caller else {
                return Ok(false);
            };
            let parent_entry = &self.entries[parent.0 as usize];
            if entry.context.task != parent_entry.context.task
                && edge == call
                && parent_entry.context.procedure == *caller_procedure
                && entry.context.procedure == *target
            {
                return Ok(true);
            }
            current = parent;
        }
    }

    fn ancestry_points_bounded(
        &self,
        origin: InvocationId,
        point: ProgramPointId,
        request: &mut SemanticRequest<'_>,
    ) -> Result<HashMap<InvocationId, ProgramPointId>, ConcurrencyOpenReason> {
        self.ancestry_points_with(origin, point, || {
            charge_concurrency_work(request, 1).is_ok()
        })
        .ok_or(ConcurrencyOpenReason::BudgetExhausted)
    }

    fn ancestry_points_with(
        &self,
        origin: InvocationId,
        origin_point: ProgramPointId,
        mut visit: impl FnMut() -> bool,
    ) -> Option<HashMap<InvocationId, ProgramPointId>> {
        let task = self.entries[origin.0 as usize].context.task;
        let mut ancestors = HashMap::default();
        let mut current = origin;
        let mut point = origin_point;
        loop {
            if !visit() {
                return None;
            }
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
        Some(ancestors)
    }

    /// Project two sites onto their common synchronous caller. Distinct
    /// activations of the same procedure meet at their caller's call sites.
    fn common_points_bounded(
        &self,
        first: InvocationId,
        first_point: ProgramPointId,
        second: InvocationId,
        second_point: ProgramPointId,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Option<(&ContextKey, ProgramPointId, ProgramPointId)>, ConcurrencyOpenReason> {
        let mut visit_result = Ok(());
        let points = self.common_points_with(first, first_point, second, second_point, || {
            visit_result = charge_concurrency_work(request, 1);
            visit_result.is_ok()
        });
        visit_result?;
        Ok(points)
    }

    fn common_points_with(
        &self,
        first: InvocationId,
        first_point: ProgramPointId,
        second: InvocationId,
        second_point: ProgramPointId,
        mut visit: impl FnMut() -> bool,
    ) -> Option<(&ContextKey, ProgramPointId, ProgramPointId)> {
        if !visit() {
            return None;
        }
        let task = self.entries[first.0 as usize].context.task;
        if self.entries[second.0 as usize].context.task != task {
            return None;
        }
        let ancestors = self.ancestry_points_with(first, first_point, &mut visit)?;
        let mut current = second;
        let mut point = second_point;
        loop {
            if !visit() {
                return None;
            }
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
        request: &mut SemanticRequest<'_>,
    ) -> Result<bool, ConcurrencyOpenReason> {
        let ancestors = self.ancestry_points_bounded(target, target_point, request)?;
        let mut common = source;
        loop {
            charge_concurrency_work(request, 1)?;
            if let Some(target) = ancestors.get(&common) {
                let Some(required) = self.required_points_in(source, required, common, request)?
                else {
                    return Ok(false);
                };
                return Ok(!required.contains(target)
                    && all_paths_cross_points(
                        &self.entries[common.0 as usize].context.procedure,
                        *target,
                        &required,
                        request,
                    )?);
            }
            let Some((parent, _)) = self.entries[common.0 as usize].caller else {
                return Ok(false);
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
        request: &mut SemanticRequest<'_>,
    ) -> Result<Option<HashSet<ProgramPointId>>, ConcurrencyOpenReason> {
        let task = self.entries[target.0 as usize].context.task;
        loop {
            charge_concurrency_work(request, 1)?;
            let entry = &self.entries[source.0 as usize];
            if entry.context.task != task || required.is_empty() {
                return Ok(None);
            }
            if source == target {
                return Ok(Some(required));
            }
            if !all_paths_cross_points(
                &entry.context.procedure,
                entry.context.procedure.semantics().normal_exit_point(),
                &required,
                request,
            )? {
                return Ok(None);
            }
            let Some((parent, call)) = entry.caller else {
                return Ok(None);
            };
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
struct OpenCallEffects {
    invocation: InvocationId,
    call: CallSiteId,
    point: ProgramPointId,
    reason: ConcurrencyOpenReason,
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
struct PendingSummaryEffect {
    context: ContextKey,
    effect: SummaryConcurrencyEffect,
}

#[derive(Debug, Clone)]
struct PendingSummaryAccess {
    context: ContextKey,
    path: SummaryConcurrencyAccessPath,
    point: ProgramPointId,
    source: SourceMappingId,
    location: MemoryLocationId,
    mode: ConcurrentAccessMode,
    access_kind: MemoryAccessKind,
}

#[derive(Debug, Clone)]
struct OmittedRecursiveCall {
    caller: ContextKey,
    call: CallSiteId,
    target: ProcedureHandle,
    boundary_is_closed: bool,
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
    /// `None` permits equal occurrence locators but cannot prove separation.
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
    payload: Option<SynchronizationPayload>,
    event: usize,
    complete: bool,
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
    storage_family: Option<ConcurrencyStorageFamily>,
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

    fn project(&mut self, selector: ConcurrencyStorageSelector, kind: &str) {
        let rendered = match &selector {
            ConcurrencyStorageSelector::DeclaredField(field)
            | ConcurrencyStorageSelector::UnresolvedField(field) => format!("field:{field}"),
            ConcurrencyStorageSelector::Property(property) => format!("property:{property}"),
            ConcurrencyStorageSelector::Aggregate => "index:aggregate".to_owned(),
            ConcurrencyStorageSelector::ConstantIndex(index) => format!("index:{index}"),
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
    value_copy_formals: HashSet<LocalSynchronizationSubject>,
    backing_ambiguous: Vec<(LocalSynchronizationSubject, LocalSynchronizationSubject)>,
    backing_field_origins: Vec<BackingFieldOrigin>,
    canonical_values: HashMap<LocalSynchronizationSubject, ConcurrencyIdentityFact>,
    identity_reasons: Vec<ConcurrencyOpenReason>,
    ambiguous: Vec<LocalSynchronizationSubject>,
    /// Values whose producer cannot establish an object identity. Stable
    /// cell stores and captures carry this boundary through backing links;
    /// naming the receiving variable cannot manufacture a payload identity.
    opaque_values: Vec<LocalSynchronizationSubject>,
    /// Copying separates storage, but still requires a valid source value.
    /// These directed links propagate uncertainty without creating aliases.
    value_copy_dependencies: Vec<(LocalSynchronizationSubject, LocalSynchronizationSubject)>,
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
        self.value_copy_dependencies
            .push((base.clone(), result.clone()));
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

    fn contains_fresh_backing_allocation(&mut self, subject: LocalSynchronizationSubject) -> bool {
        let root = self.backing_root(subject);
        let allocations = self.fresh_allocations.clone();
        allocations
            .into_iter()
            .any(|candidate| self.backing_root(candidate) == root)
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
            ConcurrencySubjectIdentity::Backing => self
                .canonical_modeled_value_copy_identity(local.clone())
                .or_else(|| self.canonical_backing_identity(local)),
        }
    }

    fn canonical_modeled_value_copy_identity(
        &mut self,
        subject: LocalSynchronizationSubject,
    ) -> Option<ConcurrencyIdentityFact> {
        let mut cursor = self.root(subject);
        let mut visited = HashSet::default();
        let mut fields = Vec::new();
        loop {
            if !visited.insert(cursor.clone()) {
                return None;
            }
            let formals = self.value_copy_formals.clone();
            if formals
                .into_iter()
                .any(|formal| self.root(formal) == cursor)
            {
                let mut base = Self::storage_identity(
                    CanonicalConcurrencyLocation::new(
                        format!("value-copy-formal:{cursor:?}"),
                        "object",
                    ),
                    ConcurrencyObjectCardinality::Singleton,
                );
                for member in fields.iter().rev() {
                    self.project_loaded_field(&mut base, member)?;
                }
                return Some(base);
            }
            let origins = self.backing_field_origins.clone();
            let mut origin: Option<BackingFieldOrigin> = None;
            for candidate in origins {
                if self.root(candidate.result.clone()) != cursor {
                    continue;
                }
                if self.member_reference_binding(&candidate.member) != Some(false) {
                    return None;
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
        // Capturing a loaded pointer gives the binding a name, not the
        // pointer's pointee. Its recorded field origin must still establish
        // the payload (or retain an open boundary).
        let backing_root = self.backing_root(root.clone());
        let field_origins = self.backing_field_origins.clone();
        if field_origins.into_iter().any(|origin| {
            self.member_reference_binding(&origin.member) != Some(false)
                && self.backing_root(origin.result) == backing_root
        }) {
            return None;
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
    ) -> Option<()> {
        // Only a proven inline field inherits the container's allocation
        // lifetime. Unknown types are not evidence of inline storage.
        if self.member_reference_binding(member) != Some(false) {
            if fact.storage_origin.is_some() {
                // Fresh storage has a concrete initialization history. A
                // reference field cannot name a pointee merely because the
                // field slot exists. Proven payloads bind the load result
                // directly and never need this synthetic projection.
                return None;
            }
            self.leave_inline_storage(fact);
        }
        fact.project(self.field_storage_selector(member), "object");
        Some(())
    }

    fn field_storage_selector(
        &self,
        member: &crate::analyzer::semantic::SemanticLocator,
    ) -> ConcurrencyStorageSelector {
        let key = SummaryLocationKey::from_locator(self.canonical_member(member));
        if self
            .member_declarations
            .contains_key(&member_locator_key(member))
        {
            ConcurrencyStorageSelector::DeclaredField(key)
        } else {
            ConcurrencyStorageSelector::UnresolvedField(key)
        }
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
            if self.identity_is_opaque(cursor.clone()) {
                self.identity_reasons
                    .push(ConcurrencyOpenReason::UnknownLocation);
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

            let field_origins = self.backing_field_origins.clone();
            let loaded = field_origins
                .into_iter()
                .any(|origin| self.backing_root(origin.result) == cursor);
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
            } else if loaded {
                None
            } else if let LocalSynchronizationSubject::Location(location) = &cursor
                && self.inline_cells.contains(location)
            {
                let mut fact = Self::storage_identity(
                    canonical_local_location(location),
                    self.backing_cardinality(&cursor),
                );
                fact.resolved.independent_storage = Some(ConcurrencyStorageFamily::LexicalCell {
                    invocation: location.invocation,
                    location: location.location,
                });
                Some(fact)
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
                    self.project_loaded_field(&mut base, member)?;
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
                    self.project_loaded_field(&mut base, member)?;
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
        if self.identity_is_opaque(subject.clone()) {
            return ConcurrencyAnswer::Open {
                partial: None,
                reasons: vec![ConcurrencyOpenReason::UnknownLocation],
            };
        }
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

    fn identity_is_opaque(&mut self, subject: LocalSynchronizationSubject) -> bool {
        if self.opaque_values.is_empty() {
            return false;
        }
        let root = self.backing_root(subject);
        let opaque = self.opaque_values.clone();
        opaque
            .into_iter()
            .any(|candidate| self.backing_root(candidate) == root)
    }

    fn propagate_opaque_values(&mut self, request: &mut SemanticRequest<'_>) -> bool {
        if self.opaque_values.is_empty() {
            return true;
        }
        let dependencies = std::mem::take(&mut self.value_copy_dependencies);
        if request.cancellation.is_cancelled()
            || request
                .budget
                .charge(crate::analyzer::semantic::SemanticWork {
                    nested_entries: dependencies.len() + self.opaque_values.len(),
                    ..crate::analyzer::semantic::SemanticWork::default()
                })
                .is_err()
        {
            return false;
        }
        let mut outgoing = HashMap::<_, Vec<_>>::default();
        for (source, target) in dependencies {
            let source = self.backing_root(source);
            let target = self.backing_root(target);
            outgoing.entry(source).or_default().push(target);
        }
        let mut pending = self.opaque_values.clone();
        let mut visited = HashSet::default();
        while let Some(subject) = pending.pop() {
            if request.cancellation.is_cancelled()
                || request
                    .budget
                    .charge(crate::analyzer::semantic::SemanticWork {
                        nested_entries: 1,
                        ..crate::analyzer::semantic::SemanticWork::default()
                    })
                    .is_err()
            {
                return false;
            }
            let root = self.backing_root(subject);
            if !visited.insert(root.clone()) {
                continue;
            }
            if let Some(targets) = outgoing.remove(&root) {
                pending.extend(targets);
            }
        }
        self.opaque_values = visited.into_iter().collect();
        true
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
    let root_context = invocations
        .push(TaskId(0), root.clone(), None, request)
        .expect("a root invocation has no caller CFG to traverse");
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
    let mut summary_open_publication_storage = HashSet::<ConcurrencyStorageFamily>::default();
    let mut classes = LocationClasses::default();
    // The formal each lexical cell was bound with, for the cells whose body
    // never assigns them. Kept apart from `location_stores` so that a cell the
    // body does assign keeps counting only its own writes.
    let mut formal_bound_cells = HashMap::<LocalLocation, LocalSynchronizationSubject>::default();
    let mut report = ConcurrentAccessReport::default();
    let mut modeled_by_context =
        HashMap::<ContextKey, Vec<(ProgramPointId, ResolvedConcurrencyEffect)>>::default();
    let mut model_reasons_by_task = HashMap::<TaskId, Vec<OpenCallEffects>>::default();
    let mut synchronous_calls = Vec::new();
    let mut binding_cardinalities = HashMap::default();
    let mut omitted_recursive_effects = false;
    let mut omitted_recursive_calls = Vec::new();
    let mut closed_recursive_calls = HashSet::default();
    let mut effect_free_closures = HashMap::default();
    let mut omitted_call_effects = false;
    let mut closed_calls = HashSet::default();
    let mut summary_effect_free_call_targets = HashMap::default();

    while let Some(context) = queue.pop_front() {
        if !visited.insert(context.clone()) {
            continue;
        }
        if request.cancellation.is_cancelled() {
            report.reasons.push(ConcurrencyOpenReason::BudgetExhausted);
            report.reasons.sort();
            report.reasons.dedup();
            return Ok(report);
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
            report.reasons.sort();
            report.reasons.dedup();
            return Ok(report);
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
        let summary = (context.procedure != *root)
            .then(|| provider.complete_summary(&context.procedure))
            .flatten();
        let mut replayed_summary_accesses = HashSet::default();
        let mut replayed_summary_allocations = HashMap::<SummaryEventKey, AllocationId>::default();
        let mut replayed_summary_synchronizations = HashSet::default();
        let mut replayed_summary_modeled_calls = HashMap::default();
        let mut replayed_summary_modeled_events = HashSet::default();
        let mut summary_task_local_allocations = HashSet::<AllocationId>::default();
        let mut summary_call_dependencies =
            HashMap::<CallSiteId, Vec<SummaryDependencyKey>>::default();
        if let Some(summary) = summary {
            for summary_effect in summary.effects() {
                let effect = match summary_effect.key() {
                    SummaryEffectKey::Call {
                        event,
                        callee,
                        witness,
                    } => {
                        if !summary_effect.evidence().is_proven()
                            || !summary_effect.evidence().is_complete()
                        {
                            report.reasons.push(ConcurrencyOpenReason::UnresolvedTarget);
                            continue;
                        }
                        let Some(call) = live_summary_call(&context.procedure, *event, *witness)
                        else {
                            report.reasons.push(ConcurrencyOpenReason::UnresolvedTarget);
                            continue;
                        };
                        let dependencies = summary_call_dependencies.entry(call).or_default();
                        if !dependencies.contains(callee.as_ref()) {
                            dependencies.push(callee.as_ref().clone());
                        }
                        continue;
                    }
                    SummaryEffectKey::Concurrency(effect) => effect,
                    _ => continue,
                };
                match effect.kind() {
                    SummaryConcurrencyEffectKind::Allocation { .. } => {
                        let pending = PendingSummaryEffect {
                            context: context.clone(),
                            effect: effect.clone(),
                        };
                        if effect.execution().timing() != ExecutionTiming::SameEvaluation
                            || !summary_effect.evidence().is_proven()
                            || !summary_effect.evidence().is_complete()
                        {
                            report.reasons.push(ConcurrencyOpenReason::UnknownLocation);
                            continue;
                        }
                        match source_summary_allocation(&pending) {
                            Ok(allocation) => assert!(
                                replayed_summary_allocations
                                    .insert(effect.event(), allocation)
                                    .is_none(),
                                "one stable allocation event is applied once per invocation"
                            ),
                            Err(_) => report.reasons.push(ConcurrencyOpenReason::UnknownLocation),
                        }
                    }
                    SummaryConcurrencyEffectKind::Access { .. } => {
                        let pending = PendingSummaryEffect {
                            context: context.clone(),
                            effect: effect.clone(),
                        };
                        if effect.execution().timing() != ExecutionTiming::SameEvaluation
                            || !summary_effect.evidence().is_proven()
                            || !summary_effect.evidence().is_complete()
                        {
                            report.reasons.push(ConcurrencyOpenReason::UnmodeledMemory(
                                "summary access evidence is unavailable".into(),
                            ));
                            continue;
                        }
                        match source_summary_access(&pending) {
                            Ok(access) => {
                                replayed_summary_accesses.insert(effect.event());
                                pending_summary_accesses.push(access);
                            }
                            Err(reason) => report
                                .reasons
                                .push(ConcurrencyOpenReason::UnmodeledMemory(reason.into())),
                        }
                    }
                    SummaryConcurrencyEffectKind::Synchronize { .. } => {
                        let pending = PendingSummaryEffect {
                            context: context.clone(),
                            effect: effect.clone(),
                        };
                        if effect.execution().timing() != ExecutionTiming::SameEvaluation {
                            report
                                .reasons
                                .push(ConcurrencyOpenReason::UnsupportedSynchronization(
                                    "summary synchronization timing is unavailable".into(),
                                ));
                            continue;
                        }
                        match source_summary_synchronization(&pending) {
                            Ok(synchronization) => {
                                replayed_summary_synchronizations.insert(effect.event());
                                pending_synchronizations.push(synchronization);
                            }
                            Err(reason) => report.reasons.push(
                                ConcurrencyOpenReason::UnsupportedSynchronization(reason.into()),
                            ),
                        }
                    }
                    SummaryConcurrencyEffectKind::Publish { .. } => {
                        let pending = PendingSummaryEffect {
                            context: context.clone(),
                            effect: effect.clone(),
                        };
                        if effect.execution().timing() != ExecutionTiming::SameEvaluation
                            || !summary_effect.evidence().is_proven()
                            || !summary_effect.evidence().is_complete()
                            || source_summary_publication(&pending).is_err()
                        {
                            report
                                .reasons
                                .push(ConcurrencyOpenReason::UnknownPublication);
                        }
                    }
                    SummaryConcurrencyEffectKind::Unpublished { .. } => {
                        let pending = PendingSummaryEffect {
                            context: context.clone(),
                            effect: effect.clone(),
                        };
                        if effect.execution().timing() != ExecutionTiming::SameEvaluation
                            || !summary_effect.evidence().is_proven()
                            || !summary_effect.evidence().is_complete()
                        {
                            report
                                .reasons
                                .push(ConcurrencyOpenReason::UnknownPublication);
                            continue;
                        }
                        match source_summary_unpublished(&pending) {
                            Ok(allocation) => {
                                summary_task_local_allocations.insert(allocation);
                            }
                            Err(_) => report
                                .reasons
                                .push(ConcurrencyOpenReason::UnknownPublication),
                        }
                    }
                    SummaryConcurrencyEffectKind::ModeledCall { effect_count } => {
                        let pending = PendingSummaryEffect {
                            context: context.clone(),
                            effect: effect.clone(),
                        };
                        if effect.execution().timing() != ExecutionTiming::SameEvaluation
                            || !summary_effect.evidence().is_proven()
                            || !summary_effect.evidence().is_complete()
                        {
                            report
                                .reasons
                                .push(ConcurrencyOpenReason::UnsupportedSynchronization(
                                    "summary modeled-call evidence is unavailable".into(),
                                ));
                            continue;
                        }
                        let modeled = summary
                            .effects()
                            .iter()
                            .filter_map(|candidate| match candidate.key() {
                                SummaryEffectKey::Concurrency(candidate_effect)
                                    if candidate_effect.event() == effect.event()
                                        && matches!(
                                            candidate_effect.kind(),
                                            SummaryConcurrencyEffectKind::Lock { .. }
                                                | SummaryConcurrencyEffectKind::Atomic { .. }
                                        ) =>
                                {
                                    Some((candidate_effect, candidate.evidence()))
                                }
                                _ => None,
                            })
                            .collect::<Vec<_>>();
                        if usize::try_from(*effect_count).ok() != Some(modeled.len())
                            || modeled.iter().any(|(_, evidence)| {
                                !evidence.is_proven() || !evidence.is_complete()
                            })
                        {
                            report
                                .reasons
                                .push(ConcurrencyOpenReason::UnsupportedSynchronization(
                                    "summary modeled-call inventory is incomplete".into(),
                                ));
                            continue;
                        }
                        let Ok((call, _)) = source_summary_modeled_call(&pending) else {
                            report
                                .reasons
                                .push(ConcurrencyOpenReason::UnsupportedSynchronization(
                                    "summary modeled-call witness is unavailable".into(),
                                ));
                            continue;
                        };
                        let mut resolved = Vec::with_capacity(modeled.len());
                        let mut valid = true;
                        for (effect, _) in modeled {
                            let pending = PendingSummaryEffect {
                                context: context.clone(),
                                effect: effect.clone(),
                            };
                            match source_summary_modeled_effect(&pending, call) {
                                Ok(effect) => resolved.push(effect),
                                Err(_) => {
                                    valid = false;
                                    break;
                                }
                            }
                        }
                        if !valid {
                            report
                                .reasons
                                .push(ConcurrencyOpenReason::UnsupportedSynchronization(
                                    "summary modeled effect witness is unavailable".into(),
                                ));
                            continue;
                        }
                        assert!(
                            replayed_summary_modeled_calls
                                .insert(call, resolved)
                                .is_none(),
                            "one source call has one modeled inventory certificate"
                        );
                        replayed_summary_modeled_events.insert(effect.event());
                    }
                    SummaryConcurrencyEffectKind::Lock { .. } => {}
                    SummaryConcurrencyEffectKind::Unsupported { protocol }
                        if protocol.as_ref() == "publication-inventory-open" =>
                    {
                        let pending = PendingSummaryEffect {
                            context: context.clone(),
                            effect: effect.clone(),
                        };
                        if effect.execution().timing() != ExecutionTiming::SameEvaluation
                            || !summary_effect.evidence().is_proven()
                            || !summary_effect.evidence().is_complete()
                        {
                            report
                                .reasons
                                .push(ConcurrencyOpenReason::UnknownPublication);
                            continue;
                        }
                        match source_summary_publication_inventory_open(&pending) {
                            Ok(allocation) => {
                                summary_open_publication_storage.insert(
                                    ConcurrencyStorageFamily::Allocation {
                                        invocation: context.invocation,
                                        allocation,
                                    },
                                );
                            }
                            Err(_) => report
                                .reasons
                                .push(ConcurrencyOpenReason::UnknownPublication),
                        }
                    }
                    SummaryConcurrencyEffectKind::Unsupported { protocol }
                        if protocol.starts_with("semantic-gap:") =>
                    {
                        let pending = PendingSummaryEffect {
                            context: context.clone(),
                            effect: effect.clone(),
                        };
                        if effect.execution().timing() != ExecutionTiming::SameEvaluation
                            || !summary_effect.evidence().is_proven()
                            || !summary_effect.evidence().is_complete()
                        {
                            report.reasons.push(ConcurrencyOpenReason::UnmodeledMemory(
                                "summary unsupported evidence is unavailable".into(),
                            ));
                            continue;
                        }
                        match source_summary_gap(&pending) {
                            Ok(capability) => report
                                .reasons
                                .push(ConcurrencyOpenReason::UnmodeledMemory(capability.into())),
                            Err(reason) => report
                                .reasons
                                .push(ConcurrencyOpenReason::UnmodeledMemory(reason.into())),
                        }
                    }
                    _ => continue,
                }
            }
            if summary.effects().iter().any(|effect| {
                matches!(effect.key(), SummaryEffectKey::Concurrency(effect)
                    if matches!(effect.kind(), SummaryConcurrencyEffectKind::Lock { .. } | SummaryConcurrencyEffectKind::Atomic { .. })
                        && !replayed_summary_modeled_events.contains(&effect.event()))
            }) {
                report
                    .reasons
                    .push(ConcurrencyOpenReason::UnsupportedSynchronization(
                        "summary modeled effect inventory is unavailable".into(),
                    ));
            }
            let invalid_task_local_allocation =
                summary_task_local_allocations.iter().any(|allocation| {
                    replayed_summary_allocations
                        .values()
                        .filter(|candidate| *candidate == allocation)
                        .count()
                        != 1
                });
            if invalid_task_local_allocation {
                report
                    .reasons
                    .push(ConcurrencyOpenReason::UnknownPublication);
            }
            summary_task_local_allocations.retain(|allocation| {
                replayed_summary_allocations
                    .values()
                    .filter(|candidate| *candidate == allocation)
                    .count()
                    == 1
            });
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
            report.reasons.sort();
            report.reasons.dedup();
            return Ok(report);
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
            if semantic_gap_omits_concurrency_access(gap) {
                report.reasons.push(ConcurrencyOpenReason::UnmodeledMemory(
                    gap.capability.label().into(),
                ));
            }
        }

        let has_aggregate_copy = semantics
            .points()
            .iter()
            .flat_map(|point| &point.events)
            .any(|event| {
                matches!(
                    event.effect,
                    SemanticEffect::ValueFlow {
                        kind: crate::analyzer::semantic::ValueFlowKind::Transfer(
                            crate::analyzer::semantic::ValueTransfer {
                                kind: crate::analyzer::semantic::TransferKind::AggregateCopy,
                                ..
                            },
                        ),
                        ..
                    }
                )
            });
        let creation_cyclic_points = if semantics.allocations().is_empty() && !has_aggregate_copy {
            Some(HashSet::default())
        } else if semantics.gaps().iter().any(|gap| {
            gap.capability == crate::analyzer::semantic::SemanticCapability::NormalControlFlow
                && gap.discharge
                    != crate::analyzer::semantic::SemanticGapDischarge::RetainedControlTopology
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
            use crate::analyzer::semantic::cfg_algorithms::loop_regions;
            match bounded_cfg_query(request, |request| loop_regions(semantics, request)) {
                Ok(regions) => Some(
                    regions
                        .regions
                        .into_iter()
                        .flat_map(|region| region.members)
                        .collect::<HashSet<_>>(),
                ),
                Err(reason) => {
                    report.reasons.push(reason);
                    None
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
        // Transfers retain value dependence, not implicit storage identity.
        // In particular, an unproven unboxing cannot reinterpret an allocation
        // as the asserted type. A backing-store alternative can select either
        // its input or fresh storage, so it is not an identity equality either.
        // Keep the matching Assignment from bypassing the same boundary, as
        // the heap oracle already does.
        let identity_transfers = semantics
            .points()
            .iter()
            .flat_map(|point| &point.events)
            .filter_map(|event| match event.effect {
                SemanticEffect::ValueFlow {
                    kind:
                        crate::analyzer::semantic::ValueFlowKind::Transfer(_)
                        | crate::analyzer::semantic::ValueFlowKind::BackingStoreAlternative { .. }
                        | crate::analyzer::semantic::ValueFlowKind::LanguageDefined
                        | crate::analyzer::semantic::ValueFlowKind::ReferenceBoxing
                        | crate::analyzer::semantic::ValueFlowKind::ReferenceUnboxing,
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
            if value.kind == crate::analyzer::semantic::SemanticValueKind::Null {
                synchronization_subjects
                    .opaque_values
                    .push(LocalSynchronizationSubject::Value {
                        task: context.task,
                        invocation: context.invocation,
                        procedure: context.procedure.clone(),
                        value: value.id,
                    });
            }
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
        let mut summary_event_ordinal = 0usize;
        for point in semantics.points() {
            for (event_position, event) in point.events.iter().enumerate() {
                let event_ordinal = summary_event_ordinal;
                summary_event_ordinal = summary_event_ordinal.saturating_add(1);
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
                        let event_key = summary_event_key(semantics, event.source, event_ordinal);
                        let allocation = replayed_summary_allocations
                            .remove(&event_key)
                            .unwrap_or(allocation);
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
                        let cardinality = creation_cyclic_points.as_ref().map_or(
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
                        let task_local = if summary.is_some() {
                            summary_task_local_allocations.contains(&allocation.id)
                        } else {
                            match provider.allocation_is_task_local(
                                &context.procedure,
                                allocation.id,
                                request,
                            )? {
                                ConcurrencyAnswer::Proven(task_local) => task_local,
                                ConcurrencyAnswer::Open { reasons, .. } => {
                                    if reasons.contains(&ConcurrencyOpenReason::BudgetExhausted) {
                                        report.reasons.push(ConcurrencyOpenReason::BudgetExhausted);
                                    }
                                    false
                                }
                            }
                        };
                        if task_local {
                            fact.resolved.escape = ConcurrencyEscape::TaskLocal;
                        }
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
                    SemanticEffect::ValueFlow {
                        kind,
                        source,
                        target,
                    } => {
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
                        if matches!(
                            kind,
                            crate::analyzer::semantic::ValueFlowKind::Transfer(
                                crate::analyzer::semantic::ValueTransfer {
                                    kind: crate::analyzer::semantic::TransferKind::AggregateCopy,
                                    ..
                                },
                            )
                        ) {
                            let cardinality = if invocations.entries[context.invocation.0 as usize]
                                .repetition
                                .is_some()
                            {
                                ConcurrencyObjectCardinality::Multiple
                            } else {
                                creation_cyclic_points.as_ref().map_or(
                                    ConcurrencyObjectCardinality::Unknown,
                                    |points| {
                                        if points.contains(&point.id) {
                                            ConcurrencyObjectCardinality::Multiple
                                        } else {
                                            ConcurrencyObjectCardinality::Singleton
                                        }
                                    },
                                )
                            };
                            let canonical = CanonicalConcurrencyLocation::new(
                                format!(
                                    "task:{}/invocation:{}/inline-value:{}:{}",
                                    context.task.get(),
                                    context.invocation.get(),
                                    crate::flow_state::procedure_wire_id(&context.procedure),
                                    target.get(),
                                ),
                                "object",
                            );
                            let mut fact = SynchronizationSubjectClasses::storage_identity(
                                canonical,
                                cardinality,
                            );
                            fact.resolved.independent_storage =
                                Some(ConcurrencyStorageFamily::InlineValue {
                                    invocation: context.invocation,
                                    value: target,
                                });
                            synchronization_subjects
                                .bind_canonical_value(target_subject.clone(), fact);
                        }
                        if kind == crate::analyzer::semantic::ValueFlowKind::LanguageDefined {
                            // Dependence on a value does not preserve its object
                            // identity through an unspecified language operation.
                            // Keep the output opaque without poisoning the input
                            // or claiming a gap for unrelated scalar operations.
                            synchronization_subjects
                                .opaque_values
                                .push(target_subject.clone());
                        }
                        if matches!(
                            kind,
                            crate::analyzer::semantic::ValueFlowKind::Transfer(
                                crate::analyzer::semantic::ValueTransfer {
                                    kind: crate::analyzer::semantic::TransferKind::Unboxing,
                                    ..
                                }
                            )
                        ) {
                            synchronization_subjects
                                .opaque_values
                                .push(target_subject.clone());
                            report.reasons.push(ConcurrencyOpenReason::UnknownLocation);
                        }
                        if let Some(callable) = callable_values
                            .get(&(
                                context.task,
                                context.invocation,
                                context.procedure.clone(),
                                source,
                            ))
                            .cloned()
                            .filter(|_| {
                                matches!(
                                    kind,
                                    crate::analyzer::semantic::ValueFlowKind::Local
                                        | crate::analyzer::semantic::ValueFlowKind::Parameter
                                        | crate::analyzer::semantic::ValueFlowKind::Receiver
                                )
                            })
                            .filter(|_| {
                                reference_source_is_stable(
                                    &mut synchronization_subjects,
                                    &invocations,
                                    &tasks,
                                    &ReferenceIdentityUse {
                                        subject: source_subject.clone(),
                                        invocation: context.invocation,
                                        point: point.id,
                                        event: event_position,
                                    },
                                    request,
                                )
                            })
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
                        if !identity_transfers.contains(&(source, target)) {
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
                        } else {
                            synchronization_subjects
                                .value_copy_dependencies
                                .push((source_subject, target_subject));
                        }
                        continue;
                    }
                    SemanticEffect::Assignment { target, value } => {
                        let blocks_identity = identity_transfers.contains(&(value, target));
                        if !blocks_identity {
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
                        if blocks_identity {
                            continue;
                        }
                        if allocation_results.contains(&value) {
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
                        synchronization_subjects.value_copy_dependencies.push((
                            LocalSynchronizationSubject::Value {
                                task: context.task,
                                invocation: context.invocation,
                                procedure: context.procedure.clone(),
                                value,
                            },
                            LocalSynchronizationSubject::Location(local_location.clone()),
                        ));
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
                if let SemanticEffect::Synchronization {
                    operation,
                    subject,
                    payload,
                } = event.effect
                {
                    let event_key = summary_event_key(semantics, event.source, event_ordinal);
                    if replayed_summary_synchronizations.contains(&event_key) {
                        continue;
                    }
                    pending_synchronizations.push(PendingIntrinsicSynchronization {
                        task: context.task,
                        invocation: context.invocation,
                        procedure: context.procedure.clone(),
                        point: point.id,
                        operation,
                        subject,
                        payload,
                        event: event_position,
                        complete: reference_evidence_is_complete(semantics, event.evidence),
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
                let event_key = summary_event_key(semantics, event.source, event_ordinal);
                if replayed_summary_accesses.contains(&event_key) {
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
        debug_assert!(
            replayed_summary_allocations.is_empty(),
            "every validated source allocation is present in the direct event inventory"
        );

        for call in semantics.call_sites() {
            let call_handle = context
                .procedure
                .call_site_handle(call.id)
                .expect("validated call belongs to its procedure");
            let resolved_targets = resolve_targets(
                provider,
                &mut synchronization_subjects,
                &invocations,
                &tasks,
                context.task,
                context.invocation,
                &context.procedure,
                call.id,
                &callable_values,
                request,
            )?;
            let modeled_answer =
                if let Some(effects) = replayed_summary_modeled_calls.remove(&call.id) {
                    ConcurrencyAnswer::Proven(effects)
                } else if provider.may_have_modeled_effects(&call_handle) {
                    provider.modeled_effects(&call_handle, &resolved_targets, request)?
                } else {
                    ConcurrencyAnswer::Proven(Vec::new())
                };
            let call_effects_closed = matches!(&modeled_answer, ConcurrencyAnswer::Proven(_));
            let (effects, mut model_resolution_reasons) = modeled_answer.into_parts();
            let call_has_no_modeled_effects = effects.is_empty();
            if !call_effects_closed && model_resolution_reasons.is_empty() {
                model_resolution_reasons.push(ConcurrencyOpenReason::UnsupportedSynchronization(
                    "open_call_effects".into(),
                ));
            }
            report
                .reasons
                .extend(model_resolution_reasons.iter().cloned());
            model_reasons_by_task
                .entry(context.task)
                .or_default()
                .extend(
                    model_resolution_reasons
                        .into_iter()
                        .map(|reason| OpenCallEffects {
                            invocation: context.invocation,
                            call: call.id,
                            point: call.point,
                            reason,
                        }),
                );
            modeled_by_context
                .entry(context.clone())
                .or_default()
                .extend(effects.iter().cloned().map(|effect| (call.point, effect)));
            let detached = call.invocation_mode == CallInvocationMode::Detached
                && call.execution_timing == ExecutionTiming::DifferentTask;
            let modeled_spawns = effects.iter().filter_map(|effect| match effect {
                ResolvedConcurrencyEffect::TaskSpawn {
                    callable,
                    targets,
                    group,
                } => Some((targets.clone(), group.clone(), false, *callable)),
                _ => None,
            });
            let (targets, target_reasons) = resolved_targets.into_parts();
            let summary_call_matches = summary_call_dependencies
                .remove(&call.id)
                .map(|dependencies| {
                    let matches = dependencies.iter().all(|dependency| {
                        targets.iter().any(|target| {
                            summary_dependency_matches_target(provider, dependency, target)
                        })
                    }) && targets.iter().all(|target| {
                        dependencies.iter().any(|dependency| {
                            summary_dependency_matches_target(provider, dependency, target)
                        })
                    });
                    if !matches {
                        // Direct resolution still supplies the target for expansion,
                        // but this retained boundary cannot certify that it describes
                        // the same invocation. Keep the mismatch visible rather than
                        // applying another procedure's effects under these actuals.
                        report.reasons.push(ConcurrencyOpenReason::UnresolvedTarget);
                    }
                    matches
                })
                .unwrap_or(true);
            let exact_target = target_reasons.is_empty() && targets.len() == 1;
            if exact_target
                && call_effects_closed
                && call_has_no_modeled_effects
                && summary_call_matches
            {
                assert!(
                    summary_effect_free_call_targets
                        .insert((context.invocation, call.id), targets[0].clone(),)
                        .is_none(),
                    "one invocation processes one semantic call once"
                );
            }
            report.reasons.extend(target_reasons);
            let (direct_targets, synchronous_targets) = if detached {
                (Some((targets, None, true, call.callee)), Vec::new())
            } else {
                (None, targets)
            };
            let mut spawned_any_task = false;
            for (targets, group, bind_invocation, invoked_callable) in
                direct_targets.into_iter().chain(modeled_spawns)
            {
                for target in targets {
                    spawned_any_task = true;
                    match invocations.repeats_spawn_edge(
                        context.invocation,
                        call.id,
                        &target,
                        request,
                    ) {
                        Ok(true) => {
                            // The omitted activation supplies neither bindings nor
                            // a certificate about its heap/synchronization effects.
                            report
                                .reasons
                                .push(ConcurrencyOpenReason::RecursiveExpansion);
                            omitted_recursive_effects = true;
                            omitted_call_effects = true;
                            continue;
                        }
                        Ok(false) => {}
                        Err(reason) => {
                            report.reasons.push(reason);
                            report.reasons.sort();
                            report.reasons.dedup();
                            return Ok(report);
                        }
                    }
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
                    let target_context = match invocations.push(
                        child,
                        target.clone(),
                        Some((context.invocation, call.id)),
                        request,
                    ) {
                        Ok(context) => context,
                        Err(reason) => {
                            report.reasons.push(reason);
                            report.reasons.sort();
                            report.reasons.dedup();
                            return Ok(report);
                        }
                    };
                    invocations.entries[target_context.invocation.0 as usize].callable =
                        Some(invoked_callable);
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
                    if bind_invocation {
                        if exact_target && call_effects_closed {
                            closed_calls.insert((context.invocation, call.id));
                        }
                        bind_call_inputs(
                            &mut synchronization_subjects,
                            &mut callable_values,
                            &invocations,
                            &tasks,
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
                for target in synchronous_targets {
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
                        omitted_call_effects = true;
                        // Membership in one summary component does not replay
                        // the omitted activation's synchronization or accesses.
                        // Only an independently empty effect closure can make
                        // omitting this recursive body irrelevant.
                        let effect_free = match effect_free_closures.entry(target.clone()) {
                            Entry::Occupied(entry) => *entry.get(),
                            Entry::Vacant(entry) => {
                                match source_closure_has_no_effects(provider, &target, request) {
                                    Ok(empty) => *entry.insert(empty),
                                    Err(reason) => {
                                        report.reasons.push(reason);
                                        report.reasons.sort();
                                        report.reasons.dedup();
                                        return Ok(report);
                                    }
                                }
                            }
                        };
                        if !effect_free {
                            omitted_recursive_calls.push(OmittedRecursiveCall {
                                caller: context.clone(),
                                call: call.id,
                                target: target.clone(),
                                boundary_is_closed: exact_target
                                    && call_effects_closed
                                    && call_has_no_modeled_effects
                                    && summary_call_matches,
                            });
                        }
                        continue;
                    }
                    let target_context = match invocations.push(
                        context.task,
                        target.clone(),
                        Some((context.invocation, call.id)),
                        request,
                    ) {
                        Ok(context) => context,
                        Err(reason) => {
                            report.reasons.push(reason);
                            report.reasons.sort();
                            report.reasons.dedup();
                            return Ok(report);
                        }
                    };
                    bind_call_inputs(
                        &mut synchronization_subjects,
                        &mut callable_values,
                        &invocations,
                        &tasks,
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
                        if call_effects_closed {
                            closed_calls.insert((context.invocation, call.id));
                        }
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
    // A forwarded callback executes with the environment created by its
    // producer, which need not be its immediate caller. Recover that exact
    // origin from retained actual/formal and local-copy edges before solving
    // captured cells. A lexical ancestor name alone is never an environment.
    for entry in &invocations.entries {
        if entry
            .context
            .procedure
            .semantics()
            .lexical_parent()
            .is_none()
        {
            continue;
        }
        if let Some((creator, callable)) = retained_callable_creation(
            &mut synchronization_subjects,
            &invocations,
            &tasks,
            entry,
            request,
        ) {
            union_capture_locations(
                &mut classes,
                &mut synchronization_subjects,
                &creator,
                entry.context.task,
                entry.context.invocation,
                &entry.context.procedure,
                callable,
            );
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
    propagate_reference_identities(
        &mut synchronization_subjects,
        &invocations,
        &tasks,
        &synchronous_calls,
        &written_once,
        &reference_allocations,
        &pending_synchronizations,
        &summary_effect_free_call_targets,
        &closed_recursive_calls,
        provider,
        request,
    );
    for (location, bound_formal) in &written_once {
        let stored = match bound_formal {
            Some(formal) => Some(formal.clone()),
            None => synchronization_subjects
                .backing_location_stores
                .get(location)
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
            synchronization_subjects
                .inline_cells
                .insert(location.clone());
            continue;
        }
        if !reference_allocations.contains(canonical.canonical()) {
            continue;
        }
        synchronization_subjects.bind_canonical_value(
            LocalSynchronizationSubject::Location(location.clone()),
            canonical,
        );
    }
    synchronization_subjects.connect_stable_backing_stores();
    if !propagate_memory_payload_identities(
        &mut synchronization_subjects,
        &invocations,
        &tasks,
        &reference_allocations,
        &callable_values,
        provider,
        request,
    )? {
        report.reasons.push(ConcurrencyOpenReason::BudgetExhausted);
        report.reasons.sort();
        report.reasons.dedup();
        return Ok(report);
    }
    if !synchronization_subjects.propagate_opaque_values(request) {
        report.reasons.push(ConcurrencyOpenReason::BudgetExhausted);
        report.reasons.sort();
        report.reasons.dedup();
        return Ok(report);
    }
    for omitted in &omitted_recursive_calls {
        let call = omitted
            .caller
            .procedure
            .semantics()
            .call_site(omitted.call)
            .expect("omitted recursive call belongs to its caller");
        let ancestor = omitted.boundary_is_closed.then(|| {
            recursive_call_preserves_inputs(
                &mut synchronization_subjects,
                &invocations,
                &tasks,
                &omitted.caller,
                call,
                &omitted.target,
                provider,
                request,
            )
        });
        let covered = ancestor.flatten().is_some_and(|ancestor| {
            recursive_access_summaries_cover_call(
                provider,
                &mut synchronization_subjects,
                &invocations,
                &tasks,
                &summary_effect_free_call_targets,
                &omitted.caller,
                call,
                &omitted.target,
                ancestor,
                request,
            )
        });
        if !covered {
            omitted_recursive_effects = true;
            report
                .reasons
                .push(ConcurrencyOpenReason::RecursiveExpansion);
        } else {
            closed_recursive_calls.insert((omitted.caller.invocation, omitted.call));
        }
    }
    if !closed_recursive_calls.is_empty() {
        propagate_reference_identities(
            &mut synchronization_subjects,
            &invocations,
            &tasks,
            &synchronous_calls,
            &written_once,
            &reference_allocations,
            &pending_synchronizations,
            &summary_effect_free_call_targets,
            &closed_recursive_calls,
            provider,
            request,
        );
        synchronization_subjects.connect_stable_backing_stores();
        if !synchronization_subjects.propagate_opaque_values(request) {
            report.reasons.push(ConcurrencyOpenReason::BudgetExhausted);
            report.reasons.sort();
            report.reasons.dedup();
            return Ok(report);
        }
    }
    resolve_modeled_subjects(
        &mut synchronization_subjects,
        &mut modeled_by_context,
        &mut tasks,
    );
    append_summary_accesses(
        provider,
        &mut synchronization_subjects,
        pending_summary_accesses,
        &mut accesses,
        request,
    )?;
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
    canonicalize_bound_accesses(&mut synchronization_subjects, &invocations, &mut accesses);
    if let Err(reason) =
        associate_wait_group_tasks(&mut tasks, &modeled_by_context, &synchronous_calls, request)
    {
        report.reasons.push(reason);
        report.reasons.sort();
        report.reasons.dedup();
        return Ok(report);
    }
    append_atomic_accesses(
        &mut synchronization_subjects,
        &modeled_by_context,
        &mut accesses,
        &mut report,
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

    // Privacy is relative to this fully inventoried slice. An omitted body
    // cannot participate in a non-publication certificate, even when another
    // summary was sufficient to stop ordinary synchronous expansion.
    let mut private_storage = if !omitted_call_effects
        && model_reasons_by_task
            .values()
            .any(|origins| !origins.is_empty())
    {
        match publication::private_storage_in_slice(&invocations, &closed_calls, request) {
            Ok(private) => private,
            Err(reason) => {
                report.reasons.push(reason);
                report.reasons.sort();
                report.reasons.dedup();
                return Ok(report);
            }
        }
    } else {
        None
    };
    if let Some(private_storage) = private_storage.as_mut() {
        for family in &summary_open_publication_storage {
            private_storage.exclude(family);
        }
    }
    let mut private_synchronization_by_task = HashMap::default();
    // CFG topology is immutable across invocations of the same artifact.
    let mut points_before_calls = HashMap::default();
    for access in &mut accesses {
        if let Some(reasons) = model_reasons_by_task.get(&access.site.task) {
            for OpenCallEffects {
                invocation: origin,
                call: call_id,
                point: call,
                reason,
            } in reasons
            {
                debug_assert_eq!(
                    invocations.entries[origin.0 as usize]
                        .context
                        .procedure
                        .semantics()
                        .call_site(*call_id)
                        .expect("retained call-effect origin")
                        .point,
                    *call,
                );
                // Unknown effects can survive a synchronous return or enter a
                // later callee. Compare both sites in their common invocation;
                // source target identity alone does not close body effects.
                let mut exhausted = false;
                let projected = invocations.common_points_with(
                    access.site.invocation,
                    access.site.point,
                    *origin,
                    *call,
                    || {
                        if request.cancellation.is_cancelled()
                            || request
                                .budget
                                .charge(crate::analyzer::semantic::SemanticWork {
                                    nested_entries: 1,
                                    ..crate::analyzer::semantic::SemanticWork::default()
                                })
                                .is_err()
                        {
                            exhausted = true;
                            return false;
                        }
                        true
                    },
                );
                if exhausted {
                    report.reasons.push(ConcurrencyOpenReason::BudgetExhausted);
                    report.reasons.sort();
                    report.reasons.dedup();
                    return Ok(report);
                }
                let precedes = if let Some((context, access_point, call_point)) = projected {
                    let before =
                        match points_before_calls.entry((context.procedure.clone(), call_point)) {
                            Entry::Occupied(entry) => entry.into_mut(),
                            Entry::Vacant(entry) => {
                                match points_strictly_before_call(
                                    &context.procedure,
                                    call_point,
                                    request,
                                ) {
                                    Ok(points) => entry.insert(points),
                                    Err(reason) => {
                                        report.reasons.push(reason);
                                        report.reasons.sort();
                                        report.reasons.dedup();
                                        return Ok(report);
                                    }
                                }
                            }
                        };
                    before.contains(&access_point)
                } else {
                    false
                };
                if !precedes {
                    let private_access = *reason == ConcurrencyOpenReason::UnresolvedTarget
                        && access.resolved_location.exact_candidate().is_some()
                        && access
                            .resolved_location
                            .independent_storage
                            .as_ref()
                            .is_some_and(|family| {
                                private_storage
                                    .as_ref()
                                    .is_some_and(|private| private.contains(family))
                            });
                    let noninterfering = if private_access {
                        match private_synchronization_by_task.entry(access.site.task) {
                            Entry::Occupied(entry) => *entry.get(),
                            Entry::Vacant(entry) => {
                                // An unknown call may synchronize through ambient
                                // state without reaching the accessed cell. Every
                                // opposing task must therefore have closed effects
                                // and synchronize only through unpublished objects.
                                if request.cancellation.is_cancelled()
                                    || request
                                        .budget
                                        .charge(crate::analyzer::semantic::SemanticWork {
                                            nested_entries: model_reasons_by_task.len()
                                                + modeled_by_context.len()
                                                + synchronizations.len(),
                                            ..crate::analyzer::semantic::SemanticWork::default()
                                        })
                                        .is_err()
                                {
                                    report.reasons.push(ConcurrencyOpenReason::BudgetExhausted);
                                    report.reasons.sort();
                                    report.reasons.dedup();
                                    return Ok(report);
                                }
                                let private = private_storage
                                    .as_ref()
                                    .expect("private access has its certificate");
                                let closed =
                                    model_reasons_by_task.iter().all(|(task, origins)| {
                                        *task == access.site.task || origins.is_empty()
                                    }) && modeled_by_context.iter().all(|(context, effects)| {
                                        context.task == access.site.task || effects.is_empty()
                                    }) && synchronizations.iter().all(|sync| {
                                        sync.task == access.site.task
                                            || (sync.fresh_allocation
                                                && sync.reasons.is_empty()
                                                && sync
                                                    .storage_family
                                                    .as_ref()
                                                    .is_some_and(|family| private.contains(family)))
                                    });
                                *entry.insert(closed)
                            }
                        }
                    } else {
                        false
                    };
                    if !noninterfering {
                        access.reasons.push(reason.clone());
                    }
                }
            }
            access.reasons.sort();
            access.reasons.dedup();
        }
    }
    // An omitted activation may participate in synchronization between any
    // retained tasks. Until an effects footprint excludes that possibility,
    // retain candidate pairs without certifying their ordering or completeness.
    if omitted_recursive_effects {
        for access in &mut accesses {
            access
                .reasons
                .push(ConcurrencyOpenReason::RecursiveExpansion);
        }
    }
    compare_accesses(
        &tasks,
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
        request,
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

/// Follow the value actually invoked to one retained closure creation. This
/// preserves creation context across forwarding parameters without identifying
/// different evaluations of a closure declaration with one another.
fn retained_callable_creation(
    classes: &mut SynchronizationSubjectClasses,
    invocations: &Invocations,
    tasks: &[Task],
    invocation: &Invocation,
    request: &mut SemanticRequest<'_>,
) -> Option<(ContextKey, ValueId)> {
    use crate::analyzer::semantic::{SemanticValueKind, ValueFlowKind};
    let (caller, call_id) = invocation.caller?;
    let mut context = invocations.entries[caller.0 as usize].context.clone();
    let call = context.procedure.semantics().call_site(call_id)?;
    let mut value = invocation.callable?;
    let mut point = call.point;
    let mut event = context.procedure.semantics().point(point)?.events.iter()
        .position(|event| matches!(event.effect, SemanticEffect::Invoke { call_site } if call_site == call_id))?;
    let mut visited = HashSet::default();
    loop {
        let semantics = context.procedure.semantics();
        if !visited.insert((context.invocation, value)) {
            return None;
        }
        if request.cancellation.is_cancelled()
            || request
                .budget
                .charge(crate::analyzer::semantic::SemanticWork {
                    nested_entries: semantics
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
        let mut definition = None;
        let mut creation = None;
        for candidate in semantics.points() {
            for (position, row) in candidate.events.iter().enumerate() {
                match &row.effect {
                    SemanticEffect::CallableCreation { result, callable } if *result == value => {
                        if creation.is_some()
                            || !reference_evidence_is_complete(semantics, row.evidence)
                            || !matches!(callable.targets, CallableTargetResolution::Proven(CallableTarget::Local(target))
                                if context.procedure.artifact().procedure_handle(target).as_ref() == Some(&invocation.context.procedure))
                        {
                            return None;
                        }
                        creation = Some((candidate.id, position));
                    }
                    SemanticEffect::Assignment {
                        target,
                        value: source,
                    }
                    | SemanticEffect::ValueFlow {
                        kind:
                            ValueFlowKind::Local | ValueFlowKind::Parameter | ValueFlowKind::Receiver,
                        source,
                        target,
                    } if *target == value => {
                        if !reference_evidence_is_complete(semantics, row.evidence) {
                            return None;
                        }
                        let next = (candidate.id, position, *source);
                        if let Some((existing_point, _, existing_source)) = definition
                            && (existing_point != candidate.id || existing_source != *source)
                        {
                            return None;
                        }
                        definition.get_or_insert(next);
                    }
                    SemanticEffect::ValueFlow { target, .. }
                    | SemanticEffect::MemoryLoad { result: target, .. }
                        if *target == value =>
                    {
                        return None;
                    }
                    _ => {}
                }
            }
        }
        // An immediately invoked creation denotes this exact environment,
        // independently of unrelated operand-order gaps elsewhere in its
        // creator. Forwarded bindings still need full stability evidence.
        let immediate_creation = creation.is_some()
            && semantics.value(value)?.kind == SemanticValueKind::Callable
            && invocation
                .caller
                .is_some_and(|(caller, _)| caller == context.invocation)
            && invocation.callable == Some(value);
        if !immediate_creation
            && !reference_source_is_stable(
                classes,
                invocations,
                tasks,
                &ReferenceIdentityUse {
                    subject: LocalSynchronizationSubject::Value {
                        task: context.task,
                        invocation: context.invocation,
                        procedure: context.procedure.clone(),
                        value,
                    },
                    invocation: context.invocation,
                    point,
                    event,
                },
                request,
            )
        {
            return None;
        }
        if let Some((defined, position)) =
            creation.or(definition.map(|(point, event, _)| (point, event)))
        {
            let precedes = if defined == point {
                position < event
            } else {
                match point_dominates(&context.procedure, defined, point, request) {
                    Ok(before) => before,
                    Err(reason) => {
                        classes.identity_reasons.push(reason);
                        return None;
                    }
                }
            };
            if !precedes {
                return None;
            }
        }
        if let Some((defined, _)) = creation {
            if definition.is_some()
                || (match point_is_cyclic(semantics, defined, request) {
                    Ok(cyclic) => cyclic,
                    Err(reason) => {
                        classes.identity_reasons.push(reason);
                        return None;
                    }
                } && !(invocation
                    .caller
                    .is_some_and(|(caller, _)| caller == context.invocation)
                    && invocation.callable == Some(value)))
                || !invocations.contains(context.invocation, invocation.context.invocation)
            {
                return None;
            }
            return Some((context, value));
        }
        if let Some((defined, position, source)) = definition {
            value = source;
            point = defined;
            event = position;
            continue;
        }
        let SemanticValueKind::Parameter { ordinal, .. } = semantics.value(value)?.kind else {
            return None;
        };
        let activation = &invocations.entries[context.invocation.0 as usize];
        let (parent, call_id) = activation.caller?;
        context = invocations.entries[parent.0 as usize].context.clone();
        let call = context.procedure.semantics().call_site(call_id)?;
        // A direct detached call also evaluates and binds its arguments in
        // the caller. A modeled callback, however, has its own argument
        // contract and cannot borrow the scheduling call's parameter slots.
        let binds_arguments = (call.invocation_mode == CallInvocationMode::Ordinary
            && call.execution_timing.is_synchronous())
            || (call.invocation_mode == CallInvocationMode::Detached
                && call.execution_timing == ExecutionTiming::DifferentTask);
        if !binds_arguments
            || activation.callable != Some(call.callee)
            || !reference_evidence_is_complete(context.procedure.semantics(), call.evidence)
        {
            return None;
        }
        value = call.arguments.get(ordinal as usize)?.value;
        point = call.point;
        event = context.procedure.semantics().point(point)?.events.iter()
            .position(|event| matches!(event.effect, SemanticEffect::Invoke { call_site } if call_site == call_id))?;
    }
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

fn identity_use_precedes(
    source: &ReferenceIdentityUse,
    observation: &ReferenceIdentityUse,
    invocations: &Invocations,
    tasks: &[Task],
    request: &mut SemanticRequest<'_>,
) -> Result<bool, ConcurrencyOpenReason> {
    let task = invocations.entries[source.invocation.0 as usize]
        .context
        .task;
    let Some((observer, observation_point)) = observation_in_task(
        tasks,
        invocations,
        task,
        (observation.invocation, observation.point),
    ) else {
        return Ok(false);
    };
    if source.invocation == observation.invocation && source.point == observation.point {
        return Ok(source.event < observation.event);
    }
    invocations.required_points_before(
        source.invocation,
        HashSet::from_iter([source.point]),
        observer,
        observation_point,
        request,
    )
}

/// A pending equation is not an alias edge. Every source must already have
/// the same full creation fact before the destination receives a snapshot.
/// None retains an unsupported producer as a dependency blocker.
struct PendingReferenceIdentity {
    destination: LocalSynchronizationSubject,
    sources: Option<Vec<ReferenceIdentityUse>>,
}

/// A field slot and the object stored in it are different identities. For a
/// concrete fresh container, require an observed, stable store before naming
/// its reference payload. In particular, an omitted initializer cannot turn
/// a zero-valued pointer into a composed container/field object.
fn propagate_memory_payload_identities(
    classes: &mut SynchronizationSubjectClasses,
    invocations: &Invocations,
    tasks: &[Task],
    reference_allocations: &HashSet<CanonicalConcurrencyLocation>,
    callable_values: &HashMap<(TaskId, InvocationId, ProcedureHandle, ValueId), ProcedureHandle>,
    provider: &impl ConcurrencyProvider,
    request: &mut SemanticRequest<'_>,
) -> Result<bool, SemanticProviderError> {
    use crate::analyzer::semantic::{
        SemanticCapability, SemanticGapDischarge, SemanticGapImpact, SemanticGapSubject,
    };

    let mut has_index_payloads = false;
    for entry in &invocations.entries {
        let locations = entry.context.procedure.semantics().memory_locations();
        if request.cancellation.is_cancelled()
            || request
                .budget
                .charge(crate::analyzer::semantic::SemanticWork {
                    nested_entries: locations.len(),
                    ..crate::analyzer::semantic::SemanticWork::default()
                })
                .is_err()
        {
            classes
                .identity_reasons
                .push(ConcurrencyOpenReason::BudgetExhausted);
            return Ok(false);
        }
        has_index_payloads |= locations.iter().any(|location| {
            matches!(location.kind, MemoryLocationKind::Index { .. })
                && matches!(
                    location.value_copy,
                    MemoryValueCopy::Reference | MemoryValueCopy::BackingStore { .. }
                )
        });
    }
    let field_payloads_are_inline = classes
        .backing_field_origins
        .iter()
        .all(|origin| classes.member_reference_binding(&origin.member) == Some(false));
    if field_payloads_are_inline && !has_index_payloads {
        return Ok(true);
    }
    // Symbolic parameter/receiver paths do not acquire fresh payload facts
    // here. Avoid expanding every call again when this solve has no freshly
    // allocated container to refine.
    let mut has_fresh_container = false;
    for index in 0..classes.backing_field_origins.len() {
        let origin = &classes.backing_field_origins[index];
        if classes.member_reference_binding(&origin.member) == Some(false) {
            continue;
        }
        let base = origin.base.clone();
        if classes
            .canonical_backing_identity(base)
            .is_some_and(|fact| fact.storage_origin.is_some())
        {
            has_fresh_container = true;
            break;
        }
    }
    if !has_fresh_container && !has_index_payloads {
        return Ok(true);
    }
    struct FieldLoad {
        base: ReferenceIdentityUse,
        member: crate::analyzer::semantic::SemanticLocator,
        result: LocalSynchronizationSubject,
    }
    struct FieldStore {
        base: LocalSynchronizationSubject,
        member: crate::analyzer::semantic::SemanticLocator,
        source: ReferenceIdentityUse,
    }
    struct IndexLoad {
        base: ReferenceIdentityUse,
        identity: IndexedLocationIdentity,
        constant_index: u128,
        value_copy: MemoryValueCopy,
        result: LocalSynchronizationSubject,
    }
    struct IndexStore {
        base: ReferenceIdentityUse,
        identity: IndexedLocationIdentity,
        constant_index: Option<u128>,
        value_copy: MemoryValueCopy,
        source: ReferenceIdentityUse,
    }
    struct AggregateCopy {
        source: ReferenceIdentityUse,
        target: ReferenceIdentityUse,
        target_storage: LocalSynchronizationSubject,
    }
    let mut loads = Vec::new();
    let mut stores = Vec::new();
    let mut index_loads = Vec::new();
    let mut index_stores = Vec::new();
    let mut aggregate_copies = Vec::new();
    let mut closed = true;
    let mut recursive_roots = HashSet::default();
    for entry in &invocations.entries {
        let context = &entry.context;
        let semantics = context.procedure.semantics();
        name_member_declarations(
            classes,
            provider,
            semantics
                .memory_locations()
                .iter()
                .filter_map(|location| match &location.kind {
                    MemoryLocationKind::Field { member, .. } => Some(member.clone()),
                    _ => None,
                })
                .chain(
                    semantics
                        .points()
                        .iter()
                        .flat_map(|point| &point.events)
                        .filter_map(|event| match &event.effect {
                            SemanticEffect::AggregateInitializer { selector, .. } => {
                                Some(selector.clone())
                            }
                            _ => None,
                        }),
                ),
        );
        if request.cancellation.is_cancelled()
            || request
                .budget
                .charge(crate::analyzer::semantic::SemanticWork {
                    nested_entries: semantics
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
            return Ok(false);
        }
        // A store inventory is exhaustive only within a closed invocation
        // slice. An unexpanded call without a heap certificate, or a write/alias
        // gap, blocks a payload snapshot. Uncertain loads are still collected.
        closed &= reference_control_is_complete(&context.procedure)
            && !semantics.gaps().iter().any(|gap| {
                // These front-end boundaries are discharged by the exact
                // call/capture closure below, the retained abort topology,
                // or a workspace-resolved field declaration respectively.
                if (gap.capability == SemanticCapability::ConcurrentSpawn
                    && gap.discharge == SemanticGapDischarge::RetainedControlTopology)
                    || (matches!(
                        gap.capability,
                        SemanticCapability::ExceptionalControlFlow
                            | SemanticCapability::ExceptionalCallContinuation
                    ) && gap.discharge == SemanticGapDischarge::NonRejoiningExceptionalExit)
                    || (gap.capability == SemanticCapability::Calls
                        && matches!(gap.subject, SemanticGapSubject::CallSite(_)))
                {
                    return false;
                }
                if gap.capability == SemanticCapability::FieldMemory
                    && let SemanticGapSubject::MemoryLocation(location) = gap.subject
                    && let MemoryLocationKind::Field { member, .. } = &semantics
                        .memory_location(location)
                        .expect("owned gap location")
                        .kind
                    && classes
                        .member_declarations
                        .contains_key(&member_locator_key(member))
                {
                    return false;
                }
                if gap.capability == SemanticCapability::IndexMemory
                    && gap.discharge == SemanticGapDischarge::CanonicalIndexIdentity
                    && let SemanticGapSubject::MemoryLocation(location) = gap.subject
                    && matches!(
                        semantics
                            .memory_location(location)
                            .expect("owned gap location")
                            .kind,
                        MemoryLocationKind::Index {
                            constant_index: Some(_),
                            ..
                        }
                    )
                {
                    return false;
                }
                if gap.capability == SemanticCapability::IndexMemory
                    && let SemanticGapSubject::MemoryLocation(location) = gap.subject
                    && provider.index_uses_separate_associative_storage(&context.procedure, location)
                {
                    // Map entry reads/writes are retained memory events. They
                    // cannot overwrite an ordinary field slot. Loaded references
                    // still need their own identity, and stores of the container
                    // into an entry remain publication boundaries below.
                    return false;
                }
                if gap.capability == SemanticCapability::CallableReferences
                    && let SemanticGapSubject::Value(value) = gap.subject
                    && (semantics.call_sites().iter().any(|call| call.callee == value)
                        || semantics.points().iter().flat_map(|point| &point.events).any(|event| {
                            let SemanticEffect::MemoryLoad { location, result, .. } = event.effect else {
                                return false;
                            };
                            result == value && matches!(&semantics.memory_location(location)
                                .expect("owned load location").kind,
                                MemoryLocationKind::Field { member, .. }
                                    if classes.member_declarations.contains_key(&member_locator_key(member)))
                        }))
                {
                    return false;
                }
                if gap.capability == SemanticCapability::Values
                    && let SemanticGapSubject::Value(aggregate) = gap.subject
                {
                    let mut initializers = semantics.points().iter().flat_map(|point| &point.events)
                        .filter_map(|event| match &event.effect {
                            SemanticEffect::AggregateInitializer { aggregate: owner, selector, .. }
                                if *owner == aggregate => Some(selector),
                            _ => None,
                        }).peekable();
                    if initializers.peek().is_some() && initializers.all(|selector| {
                        classes.member_declarations.contains_key(&member_locator_key(selector))
                            && classes.member_reference_binding(selector) == Some(true)
                    }) {
                        return false;
                    }
                }
                gap.impacts.contains(SemanticGapImpact::HeapWrite)
                    || gap.impacts.contains(SemanticGapImpact::Aliasing)
                    || gap.capability == SemanticCapability::Captures
            });
        for call in semantics.call_sites() {
            // Closure is a prerequisite for every payload proof below. Once
            // an unmodeled boundary defeats it, further dispatch resolution
            // cannot restore it. Still collect loads so their payloads remain
            // opaque instead of silently inheriting container identities.
            if !closed {
                break;
            }
            if semantics.allocations().iter().any(|allocation| {
                call.normal_result_values()
                    .any(|result| result == allocation.result)
            }) {
                continue;
            }
            let handle = context
                .procedure
                .call_site_handle(call.id)
                .expect("owned call");
            if provider.may_have_modeled_effects(&handle)
                && provider.modeled_call_preserves_ordinary_heap(&handle, request)?
            {
                continue;
            }
            let targets = resolve_targets(
                provider,
                classes,
                invocations,
                tasks,
                context.task,
                context.invocation,
                &context.procedure,
                call.id,
                callable_values,
                request,
            )?;
            closed &= reference_evidence_is_complete(semantics, call.evidence)
                && match targets {
                    ConcurrencyAnswer::Proven(targets) => {
                        !targets.is_empty()
                            && targets.iter().all(|target| {
                                if invocations.entries.iter().any(|entry| {
                                    entry.caller == Some((context.invocation, call.id))
                                        && entry.context.procedure == *target
                                }) {
                                    return true;
                                }
                                if let Some(ancestor) = recursive_call_preserves_inputs(
                                    classes,
                                    invocations,
                                    tasks,
                                    context,
                                    call,
                                    target,
                                    provider,
                                    request,
                                ) {
                                    recursive_roots.insert(ancestor);
                                    true
                                } else {
                                    false
                                }
                            })
                    }
                    ConcurrencyAnswer::Open { .. } => false,
                };
        }
        // Uncalled local closures do not execute their bodies. Invoked targets
        // must be retained above; publication of a capturing callable is
        // checked separately before accepting any payload snapshot.
        let subject = |value| LocalSynchronizationSubject::Value {
            task: context.task,
            invocation: context.invocation,
            procedure: context.procedure.clone(),
            value,
        };
        for point in semantics.points() {
            for (position, event) in point.events.iter().enumerate() {
                if let SemanticEffect::AggregateInitializer {
                    aggregate,
                    selector,
                    value,
                } = &event.effect
                {
                    // The producer retained operands at construction completion;
                    // only workspace proof turns a key into reference-field storage.
                    closed &= reference_evidence_is_complete(semantics, event.evidence)
                        && classes
                            .member_declarations
                            .contains_key(&member_locator_key(selector))
                        && classes.member_reference_binding(selector) == Some(true);
                    stores.push(FieldStore {
                        base: subject(*aggregate),
                        member: selector.clone(),
                        source: ReferenceIdentityUse {
                            subject: subject(*value),
                            invocation: context.invocation,
                            point: point.id,
                            event: position,
                        },
                    });
                    continue;
                }
                if let SemanticEffect::ValueFlow {
                    kind:
                        crate::analyzer::semantic::ValueFlowKind::Transfer(
                            crate::analyzer::semantic::ValueTransfer {
                                kind: crate::analyzer::semantic::TransferKind::AggregateCopy,
                                ..
                            },
                        ),
                    source,
                    target,
                } = event.effect
                {
                    let target_storage = binding_location(semantics, target).map_or_else(
                        || subject(target),
                        |location| {
                            LocalSynchronizationSubject::Location(LocalLocation {
                                task: context.task,
                                invocation: context.invocation,
                                procedure: context.procedure.clone(),
                                location,
                            })
                        },
                    );
                    aggregate_copies.push(AggregateCopy {
                        source: ReferenceIdentityUse {
                            subject: subject(source),
                            invocation: context.invocation,
                            point: point.id,
                            event: position,
                        },
                        target: ReferenceIdentityUse {
                            subject: subject(target),
                            invocation: context.invocation,
                            point: point.id,
                            event: position,
                        },
                        target_storage,
                    });
                    continue;
                }
                let location = match event.effect {
                    SemanticEffect::MemoryLoad { location, .. }
                    | SemanticEffect::MemoryStore { location, .. } => location,
                    _ => continue,
                };
                closed &= reference_evidence_is_complete(semantics, event.evidence);
                let location = semantics
                    .memory_location(location)
                    .expect("owned memory location");
                if let MemoryLocationKind::Index {
                    base,
                    identity,
                    constant_index,
                    ..
                } = &location.kind
                {
                    match event.effect {
                        SemanticEffect::MemoryLoad { result, .. }
                            if constant_index.is_some()
                                && matches!(
                                    location.value_copy,
                                    MemoryValueCopy::Reference
                                        | MemoryValueCopy::BackingStore { .. }
                                ) =>
                        {
                            index_loads.push(IndexLoad {
                                base: ReferenceIdentityUse {
                                    subject: subject(*base),
                                    invocation: context.invocation,
                                    point: point.id,
                                    event: position,
                                },
                                identity: *identity,
                                constant_index: constant_index
                                    .expect("guard retains an exact index"),
                                value_copy: location.value_copy,
                                result: subject(result),
                            });
                        }
                        SemanticEffect::MemoryStore { value, .. } => {
                            index_stores.push(IndexStore {
                                base: ReferenceIdentityUse {
                                    subject: subject(*base),
                                    invocation: context.invocation,
                                    point: point.id,
                                    event: position,
                                },
                                identity: *identity,
                                constant_index: *constant_index,
                                value_copy: location.value_copy,
                                source: ReferenceIdentityUse {
                                    subject: subject(value),
                                    invocation: context.invocation,
                                    point: point.id,
                                    event: position,
                                },
                            });
                        }
                        _ => {}
                    }
                    continue;
                }
                let MemoryLocationKind::Field { base, member } = &location.kind else {
                    continue;
                };
                match event.effect {
                    SemanticEffect::MemoryLoad { result, .. } => loads.push(FieldLoad {
                        base: ReferenceIdentityUse {
                            subject: subject(*base),
                            invocation: context.invocation,
                            point: point.id,
                            event: position,
                        },
                        member: member.clone(),
                        result: subject(result),
                    }),
                    SemanticEffect::MemoryStore { value, .. } => stores.push(FieldStore {
                        base: subject(*base),
                        member: member.clone(),
                        source: ReferenceIdentityUse {
                            subject: subject(value),
                            invocation: context.invocation,
                            point: point.id,
                            event: position,
                        },
                    }),
                    _ => unreachable!("only memory events selected"),
                }
            }
        }
    }
    let mut answers = Vec::new();
    for load in loads {
        if request.cancellation.is_cancelled()
            || request
                .budget
                .charge(crate::analyzer::semantic::SemanticWork {
                    nested_entries: 1,
                    ..crate::analyzer::semantic::SemanticWork::default()
                })
                .is_err()
        {
            return Ok(false);
        }
        if classes.member_reference_binding(&load.member) == Some(false) {
            continue;
        }
        let Some(container) = classes.canonical_backing_identity(load.base.subject.clone()) else {
            continue;
        };
        if container.storage_origin.is_none() {
            continue;
        }
        let declaration = classes
            .member_declarations
            .get(&member_locator_key(&load.member))
            .cloned();
        if !closed
            || declaration.is_none()
            || classes.member_reference_binding(&load.member) != Some(true)
        {
            answers.push((load.result, None));
            continue;
        }
        if request
            .budget
            .charge(crate::analyzer::semantic::SemanticWork {
                nested_entries: stores.len(),
                ..crate::analyzer::semantic::SemanticWork::default()
            })
            .is_err()
        {
            return Ok(false);
        }
        let mut matching = Vec::new();
        let mut complete = true;
        for store in &stores {
            let store_declaration = classes
                .member_declarations
                .get(&member_locator_key(&store.member))
                .cloned();
            if declaration
                .as_ref()
                .zip(store_declaration.as_ref())
                .is_some_and(|(a, b)| a != b)
            {
                continue;
            }
            let base = classes.canonical_backing_identity(store.base.clone());
            match base {
                Some(base)
                    if base.canonical() == container.canonical()
                        && declaration == store_declaration =>
                {
                    matching.push(store)
                }
                Some(base)
                    if base.storage_origin.is_some()
                        && base.storage_origin != container.storage_origin => {}
                _ => complete = false,
            }
        }
        let fact = if let [store] = matching.as_slice()
            && complete
            // A site in a recursive activation denotes repeated stores even
            // when the retained template contains it once. Initializers outside
            // that recursive subtree may still establish an invariant payload.
            && !recursive_roots.iter().any(|ancestor| invocations.contains(*ancestor, store.source.invocation))
            && reference_source_is_stable(classes, invocations, tasks, &load.base, request)
            && reference_source_is_stable(classes, invocations, tasks, &store.source, request)
            && field_container_is_unpublished(
                classes,
                invocations,
                callable_values,
                &container,
                request,
            ) {
            let source = &store.source;
            let task = invocations.entries[source.invocation.0 as usize]
                .context
                .task;
            let before = match observation_in_task(
                tasks,
                invocations,
                task,
                (load.base.invocation, load.base.point),
            ) {
                Some((observer, observation)) => {
                    (source.invocation == load.base.invocation
                        && source.point == load.base.point
                        && source.event < load.base.event)
                        || match invocations.required_points_before(
                            source.invocation,
                            HashSet::from_iter([source.point]),
                            observer,
                            observation,
                            request,
                        ) {
                            Ok(before) => before,
                            Err(reason) => {
                                classes.identity_reasons.push(reason);
                                return Ok(false);
                            }
                        }
                }
                None => false,
            };
            match classes.bound_canonical_identity(source.subject.clone()) {
                ConcurrencyAnswer::Proven(Some(fact))
                    if before
                        && reference_allocations.contains(fact.canonical())
                        && !classes.repeated_allocations.contains(fact.canonical())
                        && fact.resolved.exact_candidate().is_some()
                        && fact.storage_origin.as_ref() == Some(fact.canonical()) =>
                {
                    Some(fact)
                }
                _ => None,
            }
        } else {
            None
        };
        answers.push((load.result, fact));
    }
    for (result, fact) in answers {
        if let Some(fact) = fact {
            classes.bind_canonical_value(result, fact);
        } else {
            classes.opaque_values.push(result);
        }
    }

    struct PendingIndexPayload {
        destination: LocalSynchronizationSubject,
        source: Option<ReferenceIdentityUse>,
        value_copy: MemoryValueCopy,
    }
    let index_payload_results = index_loads
        .iter()
        .map(|load| load.result.clone())
        .collect::<HashSet<_>>();
    let mut pending_index_payloads = Vec::with_capacity(index_loads.len());
    for load in index_loads {
        if request.cancellation.is_cancelled()
            || request
                .budget
                .charge(crate::analyzer::semantic::SemanticWork {
                    nested_entries: 1,
                    ..crate::analyzer::semantic::SemanticWork::default()
                })
                .is_err()
        {
            return Ok(false);
        }
        let Some(container) = classes.canonical_backing_identity(load.base.subject.clone()) else {
            pending_index_payloads.push(PendingIndexPayload {
                destination: load.result,
                source: None,
                value_copy: load.value_copy,
            });
            continue;
        };
        if container.resolved.exact_candidate().is_none() || !closed {
            pending_index_payloads.push(PendingIndexPayload {
                destination: load.result,
                source: None,
                value_copy: load.value_copy,
            });
            continue;
        }
        // An aggregate copy defines every destination slot without equating
        // the source and destination aggregate storage. Follow that definition
        // back to one exact stored payload, including chains of array copies.
        // Every other store or copy remains a competing definition.
        let mut current_container = container;
        let mut observation = load.base.clone();
        let mut visited_containers = HashSet::default();
        let source = loop {
            if request.cancellation.is_cancelled()
                || request
                    .budget
                    .charge(crate::analyzer::semantic::SemanticWork {
                        nested_entries: index_stores
                            .len()
                            .saturating_add(aggregate_copies.len())
                            .saturating_add(1),
                        ..crate::analyzer::semantic::SemanticWork::default()
                    })
                    .is_err()
            {
                return Ok(false);
            }
            let fresh = visited_containers.insert(current_container.canonical().clone());
            let stable =
                reference_source_is_stable(classes, invocations, tasks, &observation, request);
            let unpublished = field_container_is_unpublished(
                classes,
                invocations,
                callable_values,
                &current_container,
                request,
            );
            if !fresh || !stable || !unpublished {
                break None;
            }

            let mut matching_stores = Vec::new();
            let mut matching_copies = Vec::new();
            let mut complete = true;
            for store in &index_stores {
                if store.identity != load.identity {
                    continue;
                }
                let base = classes.canonical_backing_identity(store.base.subject.clone());
                match base {
                    Some(base) if base.canonical() == current_container.canonical() => {
                        let Some(index) = store.constant_index else {
                            complete = false;
                            continue;
                        };
                        if index != load.constant_index {
                            continue;
                        }
                        if store.value_copy == load.value_copy {
                            matching_stores.push(store);
                        } else {
                            complete = false;
                        }
                    }
                    Some(base)
                        if base.resolved.exact_candidate().is_some()
                            && base.canonical() != current_container.canonical() => {}
                    _ => complete = false,
                }
            }
            for copy in &aggregate_copies {
                let target = classes.canonical_backing_identity(copy.target_storage.clone());
                match target {
                    Some(target) if target.canonical() == current_container.canonical() => {
                        matching_copies.push(copy)
                    }
                    Some(target)
                        if target.resolved.exact_candidate().is_some()
                            && target.canonical() != current_container.canonical() => {}
                    _ => complete = false,
                }
            }
            if !complete || matching_stores.len() + matching_copies.len() != 1 {
                break None;
            }

            if let [store] = matching_stores.as_slice() {
                let recursive = recursive_roots
                    .iter()
                    .any(|ancestor| invocations.contains(*ancestor, store.source.invocation));
                let base_stable =
                    reference_source_is_stable(classes, invocations, tasks, &store.base, request);
                let source_stable = index_payload_results.contains(&store.source.subject)
                    || reference_source_is_stable(
                        classes,
                        invocations,
                        tasks,
                        &store.source,
                        request,
                    );
                if recursive
                    || !base_stable
                    // A memory-load result is an immutable value snapshot. Its
                    // pending equation proves the exact source; inspecting the
                    // mutable slot associated with that result would reject an
                    // otherwise exact multi-hop payload copy.
                    || !source_stable
                {
                    break None;
                }
                match identity_use_precedes(
                    &store.source,
                    &observation,
                    invocations,
                    tasks,
                    request,
                ) {
                    Ok(true) => break Some(store.source.clone()),
                    Ok(false) => break None,
                    Err(reason) => {
                        classes.identity_reasons.push(reason);
                        return Ok(false);
                    }
                }
            }

            let [copy] = matching_copies.as_slice() else {
                unreachable!("one indexed definition is either a store or an aggregate copy")
            };
            let recursive = recursive_roots.iter().any(|ancestor| {
                invocations.contains(*ancestor, copy.source.invocation)
                    || invocations.contains(*ancestor, copy.target.invocation)
            });
            let source_stable =
                reference_source_is_stable(classes, invocations, tasks, &copy.source, request);
            let target_stable =
                reference_source_is_stable(classes, invocations, tasks, &copy.target, request);
            if recursive || !source_stable || !target_stable {
                break None;
            }
            match identity_use_precedes(&copy.target, &observation, invocations, tasks, request) {
                Ok(true) => {}
                Ok(false) => break None,
                Err(reason) => {
                    classes.identity_reasons.push(reason);
                    return Ok(false);
                }
            }
            let Some(source_container) =
                classes.canonical_backing_identity(copy.source.subject.clone())
            else {
                break None;
            };
            if source_container.resolved.exact_candidate().is_none() {
                break None;
            }
            current_container = source_container;
            observation = copy.source.clone();
        };
        pending_index_payloads.push(PendingIndexPayload {
            destination: load.result,
            source,
            value_copy: load.value_copy,
        });
    }
    let mut active = vec![true; pending_index_payloads.len()];
    loop {
        if request.cancellation.is_cancelled()
            || request
                .budget
                .charge(crate::analyzer::semantic::SemanticWork {
                    nested_entries: pending_index_payloads.len(),
                    ..crate::analyzer::semantic::SemanticWork::default()
                })
                .is_err()
        {
            return Ok(false);
        }
        let mut changed = false;
        for (index, pending) in pending_index_payloads.iter().enumerate() {
            if !active[index] {
                continue;
            }
            let Some(source) = &pending.source else {
                continue;
            };
            match pending.value_copy {
                MemoryValueCopy::Reference => {
                    let ConcurrencyAnswer::Proven(Some(fact)) =
                        classes.bound_canonical_identity(source.subject.clone())
                    else {
                        continue;
                    };
                    if !reference_allocations.contains(fact.canonical())
                        || classes.repeated_allocations.contains(fact.canonical())
                        || fact.storage_origin.as_ref() != Some(fact.canonical())
                        || fact.resolved.exact_candidate().is_none()
                    {
                        continue;
                    }
                    classes.bind_canonical_value(pending.destination.clone(), fact);
                }
                MemoryValueCopy::BackingStore { .. } => {
                    let Some(fact) = classes.canonical_backing_identity(source.subject.clone())
                    else {
                        continue;
                    };
                    if classes.repeated_allocations.contains(fact.canonical())
                        || fact.storage_origin.is_none()
                        || fact.resolved.exact_candidate().is_none()
                    {
                        continue;
                    }
                    classes.union_backing(source.subject.clone(), pending.destination.clone());
                }
                MemoryValueCopy::Value | MemoryValueCopy::Unknown => {
                    unreachable!("only identity-preserving index payloads are pending")
                }
            }
            active[index] = false;
            changed = true;
        }
        if !changed {
            break;
        }
    }
    for (pending, active) in pending_index_payloads.iter().zip(active) {
        if active {
            classes.opaque_values.push(pending.destination.clone());
            classes
                .identity_reasons
                .push(ConcurrencyOpenReason::UnknownLocation);
        }
    }
    Ok(true)
}

/// Reusing a recursive body's write inventory requires invariant reference
/// inputs, not another binding of that body to the skipped call's actuals.
/// Scalar control parameters may differ; aggregate copies and callable
/// environments remain open until their recursive transfer is represented.
#[allow(clippy::too_many_arguments)]
fn recursive_call_preserves_inputs(
    classes: &mut SynchronizationSubjectClasses,
    invocations: &Invocations,
    tasks: &[Task],
    caller: &ContextKey,
    call: &crate::analyzer::semantic::SemanticCallSite,
    target: &ProcedureHandle,
    provider: &impl ConcurrencyProvider,
    request: &mut SemanticRequest<'_>,
) -> Option<InvocationId> {
    use crate::analyzer::semantic::SemanticValueKind;
    enum RecursiveInputIdentity {
        Value,
        Backing,
    }

    if call.invocation_mode != CallInvocationMode::Ordinary
        || !call.execution_timing.is_synchronous()
        || target.semantics().lexical_parent().is_some()
        || !invocations.recursively_calls(caller.invocation, target)
    {
        return None;
    }
    let ancestor = invocations
        .entries
        .iter()
        .rev()
        .find(|entry| {
            entry.context.task == caller.task
                && entry.context.procedure == *target
                && invocations.contains(entry.context.invocation, caller.invocation)
        })
        .expect("a recursive target has a retained ancestor");
    let call_event = caller
        .procedure
        .semantics()
        .point(call.point)
        .expect("owned call point")
        .events
        .iter()
        .position(|event| {
            matches!(event.effect,
            SemanticEffect::Invoke { call_site } if call_site == call.id)
        })?;
    for formal in target.semantics().values() {
        let (actual, identity) = match formal.kind {
            SemanticValueKind::Receiver { dispatch: true } => {
                if !provider.receiver_binds_by_reference(target) {
                    return None;
                }
                (call.receiver?, RecursiveInputIdentity::Value)
            }
            SemanticValueKind::Receiver { dispatch: false } => return None,
            SemanticValueKind::Parameter { ordinal, .. } => {
                if provider.parameter_is_reference_free(target, ordinal) {
                    continue;
                }
                let identity = if provider.parameter_binding(target, ordinal) == Some(true) {
                    RecursiveInputIdentity::Value
                } else if provider.parameter_preserves_backing(target, ordinal) {
                    // Go copies slice, map, and channel descriptors while
                    // preserving their backing object. The ordinary value
                    // identity must not cross, but an exact backing fact can.
                    RecursiveInputIdentity::Backing
                } else {
                    return None;
                };
                (call.arguments.get(ordinal as usize)?.value, identity)
            }
            _ => continue,
        };
        let actual = LocalSynchronizationSubject::Value {
            task: caller.task,
            invocation: caller.invocation,
            procedure: caller.procedure.clone(),
            value: actual,
        };
        if !reference_source_is_stable(
            classes,
            invocations,
            tasks,
            &ReferenceIdentityUse {
                subject: actual.clone(),
                invocation: caller.invocation,
                point: call.point,
                event: call_event,
            },
            request,
        ) {
            return None;
        }
        let formal = LocalSynchronizationSubject::Value {
            task: ancestor.context.task,
            invocation: ancestor.context.invocation,
            procedure: target.clone(),
            value: formal.id,
        };
        let (actual, formal) = match identity {
            RecursiveInputIdentity::Value => {
                let (
                    ConcurrencyAnswer::Proven(Some(actual)),
                    ConcurrencyAnswer::Proven(Some(formal)),
                ) = (
                    classes.bound_canonical_identity(actual),
                    classes.bound_canonical_identity(formal),
                )
                else {
                    return None;
                };
                (actual, formal)
            }
            RecursiveInputIdentity::Backing => (
                classes.canonical_backing_identity(actual)?,
                classes.canonical_backing_identity(formal)?,
            ),
        };
        if actual.resolved.exact_candidate().is_none()
            || actual.canonical() != formal.canonical()
            || actual.storage_origin != formal.storage_origin
        {
            return None;
        }
    }
    Some(ancestor.context.invocation)
}

/// Publication creates aliases outside the retained local/capture equations.
/// Do not certify a field invariant through such an unmodeled route.
fn field_container_is_unpublished(
    classes: &mut SynchronizationSubjectClasses,
    invocations: &Invocations,
    callable_values: &HashMap<(TaskId, InvocationId, ProcedureHandle, ValueId), ProcedureHandle>,
    container: &ConcurrencyIdentityFact,
    request: &mut SemanticRequest<'_>,
) -> bool {
    use crate::analyzer::semantic::ValueFlowKind;
    // Charge the publication inventory when it is actually inspected, after
    // the caller has established the field's closed, unique store relation.
    let inventory_work = callable_values.len()
        + invocations
            .entries
            .iter()
            .map(|entry| {
                let semantics = entry.context.procedure.semantics();
                semantics.values().len()
                    + semantics.captures().len()
                    + semantics
                        .points()
                        .iter()
                        .map(|point| point.events.len())
                        .sum::<usize>()
            })
            .sum::<usize>();
    if request.cancellation.is_cancelled()
        || request
            .budget
            .charge(crate::analyzer::semantic::SemanticWork {
                nested_entries: inventory_work,
                ..crate::analyzer::semantic::SemanticWork::default()
            })
            .is_err()
    {
        classes
            .identity_reasons
            .push(ConcurrencyOpenReason::BudgetExhausted);
        return false;
    }
    // Publication dependence is separate from object equality: an escaping
    // callable exposes the objects and other callables in its environment.
    let mut exposed = HashSet::default();
    let mut edges = Vec::new();
    let mut boundaries = Vec::new();
    let mut callable_roots = HashMap::<ProcedureHandle, LocalSynchronizationSubject>::default();
    for ((task, invocation, procedure, value), target) in callable_values {
        let root = classes.root(LocalSynchronizationSubject::Value {
            task: *task,
            invocation: *invocation,
            procedure: procedure.clone(),
            value: *value,
        });
        if let Some(other) = callable_roots.insert(target.clone(), root.clone()) {
            edges.push((other.clone(), root.clone()));
            edges.push((root, other));
        }
    }
    for entry in &invocations.entries {
        let context = &entry.context;
        let semantics = context.procedure.semantics();
        let subject = |value| LocalSynchronizationSubject::Value {
            task: context.task,
            invocation: context.invocation,
            procedure: context.procedure.clone(),
            value,
        };
        for value in semantics.values() {
            let value = subject(value.id);
            if !classes.identity_is_opaque(value.clone())
                && classes
                    .canonical_backing_identity(value.clone())
                    .is_some_and(|fact| fact.canonical() == container.canonical())
            {
                exposed.insert(classes.root(value));
            }
        }
        for capture in semantics.captures() {
            let captured = match capture.captured {
                CaptureSource::Value(value) => subject(value),
                CaptureSource::Location(location) => {
                    LocalSynchronizationSubject::Location(LocalLocation {
                        task: context.task,
                        invocation: context.invocation,
                        procedure: context.procedure.clone(),
                        location,
                    })
                }
            };
            if !classes.identity_is_opaque(captured.clone())
                && classes
                    .canonical_backing_identity(captured.clone())
                    .is_some_and(|fact| fact.canonical() == container.canonical())
            {
                exposed.insert(classes.root(captured.clone()));
            }
            edges.push((
                classes.root(captured),
                classes.root(subject(capture.callable)),
            ));
        }
        for point in semantics.points() {
            for event in &point.events {
                match event.effect {
                    SemanticEffect::Assignment {
                        value: source,
                        target,
                    }
                    | SemanticEffect::ValueFlow { source, target, .. }
                    | SemanticEffect::AggregateInitializer {
                        value: source,
                        aggregate: target,
                        ..
                    } => {
                        edges.push((classes.root(subject(source)), classes.root(subject(target))));
                    }
                    SemanticEffect::MemoryStore {
                        location, value, ..
                    } => {
                        let cell = LocalSynchronizationSubject::Location(LocalLocation {
                            task: context.task,
                            invocation: context.invocation,
                            procedure: context.procedure.clone(),
                            location,
                        });
                        edges.push((classes.root(subject(value)), classes.root(cell)));
                    }
                    SemanticEffect::MemoryLoad {
                        location, result, ..
                    } => {
                        let cell = LocalSynchronizationSubject::Location(LocalLocation {
                            task: context.task,
                            invocation: context.invocation,
                            procedure: context.procedure.clone(),
                            location,
                        });
                        edges.push((classes.root(cell), classes.root(subject(result))));
                    }
                    _ => {}
                }
                let value = match event.effect {
                    SemanticEffect::MemoryStore {
                        location, value, ..
                    } if !matches!(
                        semantics
                            .memory_location(location)
                            .expect("owned location")
                            .kind,
                        MemoryLocationKind::LexicalCell { .. } | MemoryLocationKind::Capture { .. }
                    ) =>
                    {
                        value
                    }
                    SemanticEffect::ValueFlow { kind, source, .. }
                        if !matches!(
                            kind,
                            ValueFlowKind::Local
                                | ValueFlowKind::Parameter
                                | ValueFlowKind::Receiver
                                | ValueFlowKind::BackingStore { .. }
                                | ValueFlowKind::Transfer(_)
                                | ValueFlowKind::ReferenceBoxing
                                | ValueFlowKind::ReferenceUnboxing
                        ) =>
                    {
                        source
                    }
                    SemanticEffect::ProcedureReturn { value: Some(value) }
                    | SemanticEffect::Throw { value: Some(value) }
                    | SemanticEffect::Synchronization { subject: value, .. } => value,
                    _ => continue,
                };
                boundaries.push(classes.root(subject(value)));
            }
        }
    }
    loop {
        if request.cancellation.is_cancelled()
            || request
                .budget
                .charge(crate::analyzer::semantic::SemanticWork {
                    nested_entries: edges.len() + boundaries.len(),
                    ..crate::analyzer::semantic::SemanticWork::default()
                })
                .is_err()
        {
            classes
                .identity_reasons
                .push(ConcurrencyOpenReason::BudgetExhausted);
            return false;
        }
        if boundaries.iter().any(|value| exposed.contains(value)) {
            return false;
        }
        let mut changed = false;
        for (source, target) in &edges {
            if exposed.contains(source) {
                changed |= exposed.insert(target.clone());
            }
        }
        if !changed {
            return true;
        }
    }
}

/// A channel payload can identify one object only while every use of that
/// channel descriptor remains inside this retained solve. The direct capture
/// case is accepted only when its closure creation feeds one exact retained
/// invocation. One exact source call may copy the descriptor into an unchanged
/// producer-proven backing-preserving formal. Storing or returning the
/// descriptor, or passing it through any other call boundary, leaves transport
/// identity open.
#[allow(clippy::too_many_arguments)]
fn channel_transport_is_retained(
    classes: &mut SynchronizationSubjectClasses,
    invocations: &Invocations,
    tasks: &[Task],
    effect_free_call_targets: &HashMap<(InvocationId, CallSiteId), ProcedureHandle>,
    closed_recursive_calls: &HashSet<(InvocationId, CallSiteId)>,
    channel: LocalSynchronizationSubject,
    provider: &impl ConcurrencyProvider,
    request: &mut SemanticRequest<'_>,
) -> bool {
    use crate::analyzer::semantic::{
        SemanticCapability, SemanticGapDischarge, SemanticGapImpact, SemanticGapSubject,
        ValueFlowKind,
    };

    let root = classes.backing_root(channel);
    let mut values = HashSet::default();
    let mut locations = HashSet::default();
    for entry in &invocations.entries {
        let context = &entry.context;
        let semantics = context.procedure.semantics();
        if request.cancellation.is_cancelled()
            || request
                .budget
                .charge(crate::analyzer::semantic::SemanticWork {
                    nested_entries: semantics.values().len()
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
            classes
                .identity_reasons
                .push(ConcurrencyOpenReason::BudgetExhausted);
            return false;
        }
        for value in semantics.values() {
            let subject = LocalSynchronizationSubject::Value {
                task: context.task,
                invocation: context.invocation,
                procedure: context.procedure.clone(),
                value: value.id,
            };
            if classes.backing_root(subject) == root {
                values.insert((context.invocation, context.procedure.clone(), value.id));
            }
        }
        for location in semantics.memory_locations() {
            let subject = LocalSynchronizationSubject::Location(LocalLocation {
                task: context.task,
                invocation: context.invocation,
                procedure: context.procedure.clone(),
                location: location.id,
            });
            if classes.backing_root(subject) == root {
                locations.insert((context.invocation, context.procedure.clone(), location.id));
            }
        }
    }
    // Captured lexical cells are connected to the descriptor only after the
    // stable-store pass. Recognize the same exact one-source cell here so the
    // escape proof can inspect its retained capture without changing object
    // and cell identity or advancing that later fixed point.
    let stored_cells = classes.backing_location_stores.clone();
    let mut channel_cell_roots = Vec::new();
    for (location, stored) in stored_cells {
        let [stored] = stored.as_slice() else {
            continue;
        };
        if classes.backing_root(stored.clone()) == root {
            channel_cell_roots
                .push(classes.backing_root(LocalSynchronizationSubject::Location(location)));
        }
    }
    if !channel_cell_roots.is_empty() {
        for entry in &invocations.entries {
            let context = &entry.context;
            for location in context.procedure.semantics().memory_locations() {
                let subject = LocalSynchronizationSubject::Location(LocalLocation {
                    task: context.task,
                    invocation: context.invocation,
                    procedure: context.procedure.clone(),
                    location: location.id,
                });
                let location_root = classes.backing_root(subject);
                if channel_cell_roots.contains(&location_root) {
                    locations.insert((context.invocation, context.procedure.clone(), location.id));
                }
            }
        }
    }
    let owns_value = |invocation, procedure: &ProcedureHandle, value| {
        values.contains(&(invocation, procedure.clone(), value))
    };
    let owns_location = |invocation, procedure: &ProcedureHandle, location| {
        locations.contains(&(invocation, procedure.clone(), location))
    };

    for entry in &invocations.entries {
        let context = &entry.context;
        let semantics = context.procedure.semantics();
        for call in semantics.call_sites() {
            let owns = |value| owns_value(context.invocation, &context.procedure, value);
            let channel_arguments = call
                .arguments
                .iter()
                .enumerate()
                .filter(|(_, argument)| owns(argument.value))
                .collect::<Vec<_>>();
            if owns(call.callee)
                || call.receiver.is_some_and(owns)
                || call.normal_result_values().any(owns)
            {
                return false;
            }
            if channel_arguments.is_empty() {
                continue;
            }
            // Passing a channel descriptor into one exact retained source
            // activation does not publish it beyond this solve. The argument
            // must reach a typed descriptor-copy formal whose backing edge is
            // already present. Unknown/modelled calls, ambiguous targets,
            // reassigned formals, and recursive omissions without an exact
            // closure certificate all fail one of these checks and keep
            // transport identity open.
            let retained_execution = match (call.invocation_mode, call.execution_timing) {
                (CallInvocationMode::Ordinary, timing) => timing.is_synchronous(),
                (CallInvocationMode::Detached, ExecutionTiming::DifferentTask) => true,
                _ => false,
            };
            if !reference_evidence_is_complete(semantics, call.evidence) || !retained_execution {
                return false;
            }
            let Some(target) = effect_free_call_targets.get(&(context.invocation, call.id)) else {
                return false;
            };
            let invoked = invocations
                .entries
                .iter()
                .filter(|invocation| invocation.caller == Some((context.invocation, call.id)))
                .collect::<Vec<_>>();
            let invoked = match invoked.as_slice() {
                [invoked] if invoked.context.procedure == *target => Some(*invoked),
                [] if closed_recursive_calls.contains(&(context.invocation, call.id))
                    && *target == context.procedure =>
                {
                    None
                }
                _ => return false,
            };
            for (ordinal, _) in channel_arguments {
                let ordinal = u32::try_from(ordinal).expect("semantic parameter ordinal fits u32");
                if !provider.parameter_preserves_backing(target, ordinal) {
                    return false;
                }
                let formals = target
                    .semantics()
                    .values()
                    .iter()
                    .filter(|value| {
                        matches!(
                            value.kind,
                            crate::analyzer::semantic::SemanticValueKind::Parameter {
                                ordinal: candidate,
                                ..
                            } if candidate == ordinal
                        )
                    })
                    .collect::<Vec<_>>();
                let [formal] = formals.as_slice() else {
                    return false;
                };
                let formal_is_retained = invoked.is_some_and(|invoked| {
                    owns_value(
                        invoked.context.invocation,
                        &invoked.context.procedure,
                        formal.id,
                    )
                }) || invoked.is_none()
                    && owns_value(context.invocation, &context.procedure, formal.id);
                if !formal_is_retained {
                    return false;
                }
            }
        }
        for gap in semantics.gaps() {
            if gap.capability == SemanticCapability::ConcurrentSpawn
                && gap.discharge == SemanticGapDischarge::RetainedControlTopology
            {
                // The exact spawned task and its local continuation are both
                // present in this solve. This gap retains scheduler progress
                // uncertainty but omits no descriptor value flow.
                continue;
            }
            if gap.capability == SemanticCapability::ExceptionalControlFlow
                && gap.discharge == SemanticGapDischarge::NonRejoiningExceptionalExit
            {
                // This operation's successful continuation is retained, and
                // the alternative exits without executing later body code.
                // It cannot introduce a hidden descriptor alias on the route
                // whose synchronization events are being reconciled.
                continue;
            }
            let relevant = match gap.subject {
                SemanticGapSubject::Value(value) => {
                    owns_value(context.invocation, &context.procedure, value)
                }
                SemanticGapSubject::MemoryLocation(location) => {
                    owns_location(context.invocation, &context.procedure, location)
                }
                // A point/procedure-scoped value or alias gap exists because
                // the producer could not name the affected binding. Exact
                // channel retention therefore cannot prove that the omitted
                // route did not copy this descriptor. This is load-bearing
                // for tuple assignments that create a competing sender alias.
                SemanticGapSubject::Point | SemanticGapSubject::Procedure => matches!(
                    gap.capability,
                    SemanticCapability::Assignments
                        | SemanticCapability::Values
                        | SemanticCapability::LocalFlow
                        | SemanticCapability::ParameterFlow
                        | SemanticCapability::Captures
                ),
                SemanticGapSubject::CallSite(_)
                | SemanticGapSubject::CallContinuation { .. }
                | SemanticGapSubject::AsyncContinuation { .. } => false,
                SemanticGapSubject::Capture(_) => true,
            };
            if relevant
                && (gap.impacts.contains(SemanticGapImpact::Aliasing)
                    || gap.impacts.contains(SemanticGapImpact::ValueFlow)
                    || gap.impacts.contains(SemanticGapImpact::HeapWrite))
            {
                return false;
            }
        }
        for point in semantics.points() {
            for event in &point.events {
                let complete = reference_evidence_is_complete(semantics, event.evidence);
                let retained = match &event.effect {
                    SemanticEffect::Assignment { target, value } => {
                        let target = owns_value(context.invocation, &context.procedure, *target);
                        let value = owns_value(context.invocation, &context.procedure, *value);
                        !target && !value || complete && target && value
                    }
                    SemanticEffect::ValueFlow {
                        kind,
                        source,
                        target,
                    } => {
                        let source = owns_value(context.invocation, &context.procedure, *source);
                        let target = owns_value(context.invocation, &context.procedure, *target);
                        !source && !target
                            || complete
                                && source
                                && target
                                && matches!(
                                    kind,
                                    ValueFlowKind::Local
                                        | ValueFlowKind::Parameter
                                        | ValueFlowKind::Receiver
                                )
                    }
                    SemanticEffect::MemoryStore {
                        location, value, ..
                    } => {
                        let location =
                            owns_location(context.invocation, &context.procedure, *location);
                        let value = owns_value(context.invocation, &context.procedure, *value);
                        !location && !value || complete && location && value
                    }
                    SemanticEffect::MemoryLoad {
                        location, result, ..
                    } => {
                        let location =
                            owns_location(context.invocation, &context.procedure, *location);
                        let result = owns_value(context.invocation, &context.procedure, *result);
                        !location && !result || complete && location && result
                    }
                    SemanticEffect::Synchronization {
                        subject, payload, ..
                    } => {
                        let subject = owns_value(context.invocation, &context.procedure, *subject);
                        let transported_channel = match payload {
                            Some(SynchronizationPayload::Send { value, .. }) => {
                                owns_value(context.invocation, &context.procedure, *value)
                            }
                            Some(SynchronizationPayload::Receive { result }) => {
                                owns_value(context.invocation, &context.procedure, *result)
                            }
                            None => false,
                        };
                        !transported_channel && (!subject || complete)
                    }
                    SemanticEffect::AggregateInitializer {
                        aggregate, value, ..
                    } => {
                        !owns_value(context.invocation, &context.procedure, *aggregate)
                            && !owns_value(context.invocation, &context.procedure, *value)
                    }
                    SemanticEffect::ProcedureReturn { value } | SemanticEffect::Throw { value } => {
                        value.is_none_or(|value| {
                            !owns_value(context.invocation, &context.procedure, value)
                        })
                    }
                    SemanticEffect::AsyncSuspend { awaited, .. } => awaited.is_none_or(|value| {
                        !owns_value(context.invocation, &context.procedure, value)
                    }),
                    SemanticEffect::ValueUse { value, .. } => {
                        !owns_value(context.invocation, &context.procedure, *value)
                    }
                    SemanticEffect::Allocation { allocation } => {
                        semantics.allocation(*allocation).is_none_or(|allocation| {
                            !owns_value(context.invocation, &context.procedure, allocation.result)
                                || complete
                        })
                    }
                    SemanticEffect::CallableCreation { result, .. }
                    | SemanticEffect::CallableReference { result, .. } => {
                        !owns_value(context.invocation, &context.procedure, *result)
                    }
                    SemanticEffect::Entry
                    | SemanticEffect::NormalExit
                    | SemanticEffect::ExceptionalExit
                    | SemanticEffect::CaptureBind { .. }
                    | SemanticEffect::Invoke { .. }
                    | SemanticEffect::CallContinuation { .. }
                    | SemanticEffect::AsyncResume { .. }
                    | SemanticEffect::Gap { .. } => true,
                };
                if !retained {
                    return false;
                }
            }
        }
        for capture in semantics.captures() {
            let captured = match capture.captured {
                CaptureSource::Value(value) => {
                    owns_value(context.invocation, &context.procedure, value)
                }
                CaptureSource::Location(location) => {
                    owns_location(context.invocation, &context.procedure, location)
                }
            };
            if !captured {
                continue;
            }
            if !reference_evidence_is_complete(semantics, capture.evidence) {
                return false;
            }
            let calls = semantics
                .call_sites()
                .iter()
                .filter(|call| call.callee == capture.callable)
                .collect::<Vec<_>>();
            let [call] = calls.as_slice() else {
                return false;
            };
            if call.invocation_mode != CallInvocationMode::Detached
                || call.execution_timing != ExecutionTiming::DifferentTask
                || !reference_evidence_is_complete(semantics, call.evidence)
            {
                return false;
            }
            let invoked = invocations
                .entries
                .iter()
                .filter(|invocation| {
                    invocation.caller == Some((context.invocation, call.id))
                        && invocation.context.procedure.id() == capture.target
                })
                .collect::<Vec<_>>();
            let [invoked] = invoked.as_slice() else {
                return false;
            };
            if invoked.repetition.is_some()
                || retained_callable_creation(classes, invocations, tasks, invoked, request)
                    != Some((context.clone(), capture.callable))
            {
                return false;
            }
            for point in semantics.points() {
                for event in &point.events {
                    let escapes = match event.effect {
                        SemanticEffect::Assignment { target, value }
                        | SemanticEffect::ValueFlow {
                            source: value,
                            target,
                            ..
                        } => target == capture.callable || value == capture.callable,
                        SemanticEffect::MemoryStore { value, .. }
                        | SemanticEffect::ProcedureReturn { value: Some(value) }
                        | SemanticEffect::Throw { value: Some(value) } => value == capture.callable,
                        _ => false,
                    };
                    if escapes {
                        return false;
                    }
                }
            }
        }
    }
    true
}

#[allow(clippy::too_many_arguments)]
fn propagate_reference_identities(
    classes: &mut SynchronizationSubjectClasses,
    invocations: &Invocations,
    tasks: &[Task],
    calls: &[SynchronousCall],
    cells: &[(LocalLocation, Option<LocalSynchronizationSubject>)],
    reference_allocations: &HashSet<CanonicalConcurrencyLocation>,
    synchronizations: &[PendingIntrinsicSynchronization],
    effect_free_call_targets: &HashMap<(InvocationId, CallSiteId), ProcedureHandle>,
    closed_recursive_calls: &HashSet<(InvocationId, CallSiteId)>,
    provider: &impl ConcurrencyProvider,
    request: &mut SemanticRequest<'_>,
) {
    use crate::analyzer::semantic::ValueFlowKind;

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
    // A wrapper owns a reference payload, not the referenced object's
    // storage. Pair exact packing and extraction facts through the stable
    // wrapper binding without unioning wrapper and payload identities.
    let mut boxed_payloads = HashMap::<_, Vec<_>>::default();
    let mut extractions = Vec::new();
    for entry in &invocations.entries {
        let context = &entry.context;
        let semantics = context.procedure.semantics();
        if request.cancellation.is_cancelled()
            || request
                .budget
                .charge(crate::analyzer::semantic::SemanticWork {
                    nested_entries: semantics
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
            return;
        }
        let subject = |value| LocalSynchronizationSubject::Value {
            task: context.task,
            invocation: context.invocation,
            procedure: context.procedure.clone(),
            value,
        };
        for point in semantics.points() {
            for (event, row) in point.events.iter().enumerate() {
                let SemanticEffect::ValueFlow {
                    kind,
                    source,
                    target,
                } = row.effect
                else {
                    continue;
                };
                if !matches!(
                    kind,
                    ValueFlowKind::ReferenceBoxing | ValueFlowKind::ReferenceUnboxing
                ) {
                    continue;
                }
                let source = ReferenceIdentityUse {
                    subject: subject(source),
                    invocation: context.invocation,
                    point: point.id,
                    event,
                };
                let target = subject(target);
                if kind == ValueFlowKind::ReferenceBoxing {
                    boxed_payloads
                        .entry(classes.root(target))
                        .or_default()
                        .push(
                            reference_evidence_is_complete(semantics, row.evidence)
                                .then_some(source),
                        );
                } else {
                    extractions.push((
                        target,
                        source,
                        reference_evidence_is_complete(semantics, row.evidence),
                    ));
                }
            }
        }
    }
    // A captured interface may be read through its lexical cell. Follow the
    // cell's one stored value as a producer edge; the interface wrapper does
    // not thereby acquire the payload's object identity.
    let mut wrapper_cells = HashMap::<_, Option<_>>::default();
    for (location, formal) in cells {
        let stored = formal.clone().or_else(|| {
            let [stored] = classes.backing_location_stores.get(location)?.as_slice() else {
                return None;
            };
            Some(stored.clone())
        });
        if let Some(stored) = stored {
            let source = classes.root(stored);
            let target = classes.root(LocalSynchronizationSubject::Location(location.clone()));
            if source == target {
                continue;
            }
            wrapper_cells
                .entry(target)
                .and_modify(|existing| {
                    if existing.as_ref() != Some(&source) {
                        *existing = None;
                    }
                })
                .or_insert(Some(source));
        }
    }
    let mut payload_destinations = HashSet::default();
    for (destination, wrapper, complete) in extractions {
        let mut root = classes.root(wrapper.subject.clone());
        let mut visited = HashSet::default();
        while !boxed_payloads.contains_key(&root) && visited.insert(root.clone()) {
            if request.cancellation.is_cancelled()
                || request
                    .budget
                    .charge(crate::analyzer::semantic::SemanticWork {
                        nested_entries: 1,
                        ..crate::analyzer::semantic::SemanticWork::default()
                    })
                    .is_err()
            {
                classes
                    .identity_reasons
                    .push(ConcurrencyOpenReason::BudgetExhausted);
                return;
            }
            let Some(Some(source)) = wrapper_cells.get(&root) else {
                break;
            };
            root = source.clone();
        }
        let sources = boxed_payloads
            .get(&root)
            .and_then(|sources| match sources.as_slice() {
                [Some(source)] if complete => Some(source.clone()),
                _ => None,
            })
            .filter(|_| !classes.identity_is_opaque(wrapper.subject.clone()))
            .filter(|_| reference_source_is_stable(classes, invocations, tasks, &wrapper, request))
            .map(|source| vec![source]);
        payload_destinations.insert(destination.clone());
        pending.push(PendingReferenceIdentity {
            destination,
            sources,
        });
    }
    // A receive is a must-equal payload only when one exact send can supply
    // it. Multiple sends or receives describe a choice and must never be
    // unioned into this equality relation. Restrict the first transport proof
    // to fresh, nonrepeating channels and direct reference or zero-offset
    // backing-store payloads retained entirely by this invocation/task slice.
    for receive in synchronizations {
        let Some(SynchronizationPayload::Receive { result }) = receive.payload else {
            continue;
        };
        let channel = LocalSynchronizationSubject::Value {
            task: receive.task,
            invocation: receive.invocation,
            procedure: receive.procedure.clone(),
            value: receive.subject,
        };
        let Some(channel_fact) = classes.canonical_backing_identity(channel.clone()) else {
            continue;
        };
        let allocation_nonrepeating = match channel_fact.resolved.independent_storage {
            Some(ConcurrencyStorageFamily::Allocation {
                invocation,
                allocation,
            }) => {
                let owner = &invocations.entries[invocation.0 as usize];
                let allocation = owner
                    .context
                    .procedure
                    .semantics()
                    .allocation(allocation)
                    .expect("identity allocation belongs to its invocation");
                if owner.repetition.is_some() {
                    false
                } else {
                    match point_is_cyclic(
                        owner.context.procedure.semantics(),
                        allocation.point,
                        request,
                    ) {
                        Ok(cyclic) => !cyclic,
                        Err(reason) => {
                            classes.identity_reasons.push(reason);
                            false
                        }
                    }
                }
            }
            _ => false,
        };
        if !receive.complete
            || channel_fact.storage_origin.as_ref() != Some(channel_fact.canonical())
            || !reference_allocations.contains(channel_fact.canonical())
            || !allocation_nonrepeating
            || !classes.contains_fresh_backing_allocation(channel.clone())
            || invocations.entries[receive.invocation.0 as usize]
                .repetition
                .is_some()
        {
            continue;
        }
        let mut sends = Vec::new();
        let mut receives = Vec::new();
        let mut closed_or_incomplete = false;
        for candidate in synchronizations {
            let candidate_channel = LocalSynchronizationSubject::Value {
                task: candidate.task,
                invocation: candidate.invocation,
                procedure: candidate.procedure.clone(),
                value: candidate.subject,
            };
            let Some(candidate_fact) =
                classes.canonical_backing_identity(candidate_channel.clone())
            else {
                continue;
            };
            if candidate_fact.canonical() != channel_fact.canonical() {
                continue;
            }
            if !candidate.complete
                || invocations.entries[candidate.invocation.0 as usize]
                    .repetition
                    .is_some()
            {
                closed_or_incomplete = true;
                continue;
            }
            let cyclic =
                match point_is_cyclic(candidate.procedure.semantics(), candidate.point, request) {
                    Ok(cyclic) => cyclic,
                    Err(reason) => {
                        classes.identity_reasons.push(reason);
                        true
                    }
                };
            if cyclic {
                closed_or_incomplete = true;
                continue;
            }
            match (candidate.operation, candidate.payload) {
                (
                    crate::analyzer::semantic::SynchronizationOperation::ChannelSend,
                    Some(SynchronizationPayload::Send {
                        value,
                        copy: SynchronizationPayloadCopy::Reference,
                    }),
                ) => sends.push((
                    ReferenceIdentityUse {
                        subject: LocalSynchronizationSubject::Value {
                            task: candidate.task,
                            invocation: candidate.invocation,
                            procedure: candidate.procedure.clone(),
                            value,
                        },
                        invocation: candidate.invocation,
                        point: candidate.point,
                        event: candidate.event,
                    },
                    SynchronizationPayloadCopy::Reference,
                )),
                (
                    crate::analyzer::semantic::SynchronizationOperation::ChannelSend,
                    Some(SynchronizationPayload::Send {
                        value,
                        copy: copy @ SynchronizationPayloadCopy::BackingStore { .. },
                    }),
                ) => sends.push((
                    ReferenceIdentityUse {
                        subject: LocalSynchronizationSubject::Value {
                            task: candidate.task,
                            invocation: candidate.invocation,
                            procedure: candidate.procedure.clone(),
                            value,
                        },
                        invocation: candidate.invocation,
                        point: candidate.point,
                        event: candidate.event,
                    },
                    copy,
                )),
                (
                    crate::analyzer::semantic::SynchronizationOperation::ChannelReceive,
                    Some(SynchronizationPayload::Receive { result }),
                ) => receives.push((candidate.invocation, candidate.point, result)),
                _ => closed_or_incomplete = true,
            }
        }
        let [send] = sends.as_slice() else {
            continue;
        };
        let [only_receive] = receives.as_slice() else {
            continue;
        };
        let retained = channel_transport_is_retained(
            classes,
            invocations,
            tasks,
            effect_free_call_targets,
            closed_recursive_calls,
            channel.clone(),
            provider,
            request,
        );
        let stable = reference_source_is_stable(classes, invocations, tasks, &send.0, request);
        if closed_or_incomplete
            || *only_receive != (receive.invocation, receive.point, result)
            || !retained
            || !stable
        {
            continue;
        }
        let destination = LocalSynchronizationSubject::Value {
            task: receive.task,
            invocation: receive.invocation,
            procedure: receive.procedure.clone(),
            value: result,
        };
        match send.1 {
            SynchronizationPayloadCopy::Reference => pending.push(PendingReferenceIdentity {
                destination,
                sources: Some(vec![send.0.clone()]),
            }),
            SynchronizationPayloadCopy::BackingStore { .. } => {
                classes.union_backing(send.0.subject.clone(), destination);
            }
        }
    }
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
                        match reference_result_sources(target, ordinal, request) {
                            Ok(sources) => sources,
                            Err(reason) => {
                                classes.identity_reasons.push(reason);
                                None
                            }
                        }
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
    // Cells can form dependency chains even when no call returns a
    // reference. Solve those chains to a fixed point as well: a single
    // HashMap-order pass can visit a captured alias before its source cell
    // receives the allocation fact.
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
                // A paired reference-boxing fact supplies its own explicit
                // source-type witness, including named aliases the provider
                // has not independently classified. Other equations still
                // require the allocation's provider-authored reference fact.
                if (!reference_allocations.contains(fact.canonical())
                    && !payload_destinations.contains(&item.destination))
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
    for (item, active) in pending.iter().zip(active) {
        if active && payload_destinations.contains(&item.destination) {
            classes.opaque_values.push(item.destination.clone());
            classes
                .identity_reasons
                .push(ConcurrencyOpenReason::UnknownLocation);
        }
    }
}

fn reference_result_sources(
    context: &ContextKey,
    ordinal: u32,
    request: &mut SemanticRequest<'_>,
) -> Result<Option<Vec<ReferenceIdentityUse>>, ConcurrencyOpenReason> {
    use crate::analyzer::semantic::{SemanticCapability, SemanticValueKind, ValueFlowKind};

    let semantics = context.procedure.semantics();
    if !reference_control_is_complete(&context.procedure)
        || semantics
            .gaps()
            .iter()
            .any(|gap| gap.capability == SemanticCapability::ReturnFlow)
    {
        return Ok(None);
    }
    let mut sources = Vec::new();
    let mut terminals = HashSet::default();
    for point in semantics.points() {
        if !point
            .events
            .iter()
            .any(|event| matches!(event.effect, SemanticEffect::ProcedureReturn { .. }))
            || !point_reaches(
                &context.procedure,
                semantics.entry_point(),
                point.id,
                request,
            )?
            || !point_reaches(
                &context.procedure,
                point.id,
                semantics.normal_exit_point(),
                request,
            )?
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
            return Ok(None);
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
        let Some((source, evidence, event)) = matching.next() else {
            return Ok(None);
        };
        if matching.next().is_some() {
            return Ok(None);
        }
        if !reference_evidence_is_complete(semantics, evidence) {
            return Ok(None);
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
    Ok(all_paths_cross_points(
        &context.procedure,
        semantics.normal_exit_point(),
        &terminals,
        request,
    )?
    .then_some(sources))
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
    let semantics = procedure.semantics();
    !semantics.gaps().iter().any(reference_control_gap_is_open)
        && semantics
            .control_edges()
            .iter()
            .all(|edge| reference_evidence_is_complete(semantics, edge.evidence))
}

fn reference_control_gap_is_open(gap: &crate::analyzer::semantic::SemanticGap) -> bool {
    use crate::analyzer::semantic::{
        SemanticCapability, SemanticGapDischarge, SemanticGapImpact, SemanticGapSubject,
    };
    // Blocking can prevent an observation from executing, but cannot
    // change which definitions precede it when it does execute. This
    // producer certificate retains every source-local successor. Its
    // default control impacts remain relevant to progress-sensitive
    // consumers; independent mutation/evaluation gaps are still checked.
    if gap.capability == SemanticCapability::NormalControlFlow
        && gap.discharge == SemanticGapDischarge::RetainedControlTopology
        && gap.subject == SemanticGapSubject::Point
    {
        return false;
    }
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
    let mut dependencies =
        HashMap::<LocalSynchronizationSubject, Vec<LocalSynchronizationSubject>>::default();
    for (formal, actual) in &classes.formal_bindings {
        dependencies
            .entry(actual.clone())
            .or_default()
            .push(formal.clone());
    }
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
        let subject = |value| LocalSynchronizationSubject::Value {
            task: context.task,
            invocation: context.invocation,
            procedure: context.procedure.clone(),
            value,
        };
        let location_subject = |location| {
            LocalSynchronizationSubject::Location(LocalLocation {
                task: context.task,
                invocation: context.invocation,
                procedure: context.procedure.clone(),
                location,
            })
        };
        for capture in semantics.captures() {
            let captured = match capture.captured {
                CaptureSource::Value(value) => subject(value),
                CaptureSource::Location(location) => location_subject(location),
            };
            let Some(target_procedure) = context
                .procedure
                .artifact()
                .procedure_handle(capture.target)
            else {
                return false;
            };
            for target in &invocations.entries {
                if target.context.procedure == target_procedure
                    && invocations.contains(context.invocation, target.context.invocation)
                {
                    dependencies.entry(captured.clone()).or_default().push(
                        LocalSynchronizationSubject::Location(LocalLocation {
                            task: target.context.task,
                            invocation: target.context.invocation,
                            procedure: target.context.procedure.clone(),
                            location: capture.destination,
                        }),
                    );
                }
            }
        }
        let mut assignments = HashMap::<ValueId, usize>::default();
        for point in semantics.points() {
            for (position, event) in point.events.iter().enumerate() {
                let dependency = match event.effect {
                    SemanticEffect::Assignment { target, value } => {
                        Some((subject(value), subject(target)))
                    }
                    SemanticEffect::ValueFlow { source, target, .. } => {
                        Some((subject(source), subject(target)))
                    }
                    SemanticEffect::MemoryLoad {
                        location, result, ..
                    } => Some((location_subject(location), subject(result))),
                    SemanticEffect::MemoryStore {
                        location, value, ..
                    } => Some((subject(value), location_subject(location))),
                    _ => None,
                };
                if let Some((from, to)) = dependency {
                    dependencies.entry(from).or_default().push(to);
                }
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
                    SemanticEffect::ValueFlow {
                        kind: crate::analyzer::semantic::ValueFlowKind::ReferenceBoxing,
                        target,
                        ..
                    } if values.contains(&target) => {
                        definitions.push((subject(target), context.invocation, point.id, position));
                    }
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
                            definitions.push((
                                subject(target),
                                context.invocation,
                                point.id,
                                position,
                            ));
                        }
                        if values.contains(&value) {
                            reads.push((subject(value), context.invocation, point.id, position));
                        }
                    }
                    SemanticEffect::MemoryStore { location, .. }
                        if locations.contains(&location) =>
                    {
                        cell_stores += 1;
                        definitions.push((
                            location_subject(location),
                            context.invocation,
                            point.id,
                            position,
                        ));
                    }
                    SemanticEffect::MemoryLoad { location, .. }
                        if locations.contains(&location) =>
                    {
                        reads.push((
                            location_subject(location),
                            context.invocation,
                            point.id,
                            position,
                        ));
                    }
                    SemanticEffect::ValueFlow { source, .. } if values.contains(&source) => {
                        reads.push((subject(source), context.invocation, point.id, position));
                    }
                    _ => {}
                }
            }
        }
        if assignments.values().any(|count| *count > 1) || cell_stores > 1 {
            return false;
        }
    }
    reads.push((
        source.subject.clone(),
        source.invocation,
        source.point,
        source.event,
    ));
    // Creating another alias does not mutate its source. Check an assignment
    // against reads reachable from its destination, rather than all reads in
    // the final object-equivalence class (some precede this alias's creation).
    for (binding, definition, point, position) in definitions {
        let mut reachable = HashSet::default();
        let mut pending = vec![binding];
        while let Some(value) = pending.pop() {
            if !reachable.insert(value.clone()) {
                continue;
            }
            if request.cancellation.is_cancelled()
                || request
                    .budget
                    .charge(crate::analyzer::semantic::SemanticWork {
                        nested_entries: dependencies.get(&value).map_or(0, Vec::len) + 1,
                        ..crate::analyzer::semantic::SemanticWork::default()
                    })
                    .is_err()
            {
                classes
                    .identity_reasons
                    .push(ConcurrencyOpenReason::BudgetExhausted);
                return false;
            }
            pending.extend(dependencies.get(&value).into_iter().flatten().cloned());
        }
        let task = invocations.entries[definition.0 as usize].context.task;
        for (value, invocation, read_point, read_event) in &reads {
            if !reachable.contains(value) {
                continue;
            }
            let Some((observer, observation)) =
                observation_in_task(tasks, invocations, task, (*invocation, *read_point))
            else {
                return false;
            };
            if !(definition == *invocation && point == *read_point && position <= *read_event)
                && !match invocations.required_points_before(
                    definition,
                    HashSet::from_iter([point]),
                    observer,
                    observation,
                    request,
                ) {
                    Ok(before) => before,
                    Err(reason) => {
                        classes.identity_reasons.push(reason);
                        return false;
                    }
                }
            {
                return false;
            }
        }
    }
    true
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
    request: &mut SemanticRequest<'_>,
) -> Result<(), ConcurrencyOpenReason> {
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

    let completion_effects = must_completion_effects(modeled, synchronous_calls, request)?;
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
        let mut exact_phase = structurally_one_phase && exact_count && waits.len() == 1;
        if exact_phase {
            'phase: for completion in &completions {
                for (add, _) in &adds {
                    if !point_dominates(&spawn_procedure, *add, completion.spawn_point, request)? {
                        exact_phase = false;
                        break 'phase;
                    }
                }
                if !point_dominates(&spawn_procedure, completion.spawn_point, waits[0], request)? {
                    exact_phase = false;
                    break;
                }
            }
        }
        for completion in completions {
            let parent_repeats = tasks[completion.parent.0 as usize].repetition.is_some();
            let task = &mut tasks[completion.task.0 as usize];
            task.repetitions_serialized = task.repetition.is_some()
                && !parent_repeats
                && exact_phase
                && point_is_cyclic(spawn_procedure.semantics(), completion.spawn_point, request)?
                && all_recurrences_cross_points(
                    &spawn_procedure,
                    completion.spawn_point,
                    &HashSet::from_iter([waits[0]]),
                    request,
                )?;
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
            let mut has_add = false;
            let mut has_wait = false;
            for (point, effect) in effects {
                match effect {
                    ResolvedConcurrencyEffect::WaitGroupAdd { group, .. }
                        if !has_add && exact_subject(group) == Some(canonical) =>
                    {
                        has_add = point_dominates(spawn_procedure, *point, spawn, request)?;
                    }
                    ResolvedConcurrencyEffect::WaitGroupWait { group }
                        if !has_wait && exact_subject(group) == Some(canonical) =>
                    {
                        has_wait = point_dominates(spawn_procedure, spawn, *point, request)?;
                    }
                    _ => {}
                }
                if has_add && has_wait {
                    break;
                }
            }
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
    Ok(())
}

type CompletionEffects = HashMap<(InvocationId, ProgramPointId), ResolvedConcurrencySubject>;

fn must_completion_effects(
    modeled: &HashMap<ContextKey, Vec<(ProgramPointId, ResolvedConcurrencyEffect)>>,
    synchronous_calls: &[SynchronousCall],
    request: &mut SemanticRequest<'_>,
) -> Result<HashMap<ContextKey, CompletionEffects>, ConcurrencyOpenReason> {
    let mut summaries = HashMap::default();
    for (context, effects) in modeled {
        charge_concurrency_work(request, 1)?;
        let summary = summaries
            .entry(context.clone())
            .or_insert_with(HashMap::default);
        for (point, effect) in effects {
            charge_concurrency_work(request, 1)?;
            let ResolvedConcurrencyEffect::WaitGroupDone { group } = effect else {
                continue;
            };
            if exact_subject(group).is_some()
                && point_dominates(
                    &context.procedure,
                    *point,
                    context.procedure.semantics().normal_exit_point(),
                    request,
                )?
            {
                summary.insert((context.invocation, *point), group.clone());
            }
        }
    }
    loop {
        let mut changed = false;
        for edge in synchronous_calls {
            charge_concurrency_work(request, 1)?;
            let Some(propagated) = summaries
                .get(&edge.target)
                .filter(|effects| !effects.is_empty())
            else {
                continue;
            };
            if !point_dominates(
                &edge.caller.procedure,
                edge.point,
                edge.caller.procedure.semantics().normal_exit_point(),
                request,
            )? {
                continue;
            }
            charge_concurrency_work(request, propagated.len())?;
            let propagated = propagated.clone();
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
    Ok(summaries)
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
    if subject.canonical.is_none() && subject.reasons.is_empty() {
        subject.reasons.push(ConcurrencyOpenReason::UnknownLocation);
    }
}

fn append_atomic_accesses(
    classes: &mut SynchronizationSubjectClasses,
    modeled: &HashMap<ContextKey, Vec<(ProgramPointId, ResolvedConcurrencyEffect)>>,
    accesses: &mut Vec<Access>,
    report: &mut ConcurrentAccessReport,
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
                // This model contains a memory access whose location cannot
                // be represented. Preserve the gap even when no pair exists.
                report.reasons.extend(location.reasons.iter().cloned());
                report.reasons.push(ConcurrencyOpenReason::UnknownLocation);
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

#[allow(clippy::too_many_arguments)]
fn resolve_targets(
    provider: &impl ConcurrencyProvider,
    classes: &mut SynchronizationSubjectClasses,
    invocations: &Invocations,
    tasks: &[Task],
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
        let event = procedure
            .semantics()
            .point(row.point)
            .expect("owned call point")
            .events
            .iter()
            .position(|event| {
                matches!(event.effect,
                SemanticEffect::Invoke { call_site } if call_site == call)
            })
            .expect("a retained call has an invocation event");
        if reference_source_is_stable(
            classes,
            invocations,
            tasks,
            &ReferenceIdentityUse {
                subject: LocalSynchronizationSubject::Value {
                    task,
                    invocation,
                    procedure: procedure.clone(),
                    value: row.callee,
                },
                invocation,
                point: row.point,
                event,
            },
            request,
        ) {
            return Ok(ConcurrencyAnswer::Proven(vec![target.clone()]));
        }
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

/// Resolve an exact scalar through the analyzed invocation ancestry. Each
/// procedure-local step must be immutable and each call edge must bind the
/// same positional parameter. A root formal or unavailable edge stays open.
fn invocation_scalar_integer(
    invocations: &Invocations,
    mut invocation: InvocationId,
    mut value: ValueId,
) -> Option<u128> {
    let mut visited = HashSet::default();
    let mut offset = ScalarIntegerValue::unsigned(0);
    loop {
        if !visited.insert((invocation, value)) {
            return None;
        }
        let current = invocations.entries.get(invocation.0 as usize)?;
        match crate::typestate::direct_scalar_source(current.context.procedure.semantics(), value)?
        {
            crate::typestate::DirectScalarSource::UnsignedInteger(integer) => {
                let result = ScalarIntegerValue::unsigned(integer).checked_add(offset)?;
                return (!result.negative()).then_some(result.magnitude());
            }
            crate::typestate::DirectScalarSource::IntegerOffset {
                source,
                offset: next,
            } => {
                offset = ScalarIntegerValue::new(next.negative(), next.magnitude())
                    .checked_add(offset)?;
                value = source;
            }
            crate::typestate::DirectScalarSource::Port(SummaryPort::Parameter(ordinal)) => {
                let (parent, call) = current.caller?;
                let caller = invocations.entries.get(parent.0 as usize)?;
                value = caller
                    .context
                    .procedure
                    .semantics()
                    .call_site(call)?
                    .arguments
                    .get(usize::try_from(ordinal).ok()?)?
                    .value;
                invocation = parent;
            }
            crate::typestate::DirectScalarSource::Port(
                SummaryPort::Receiver
                | SummaryPort::NormalReturn
                | SummaryPort::IndexedNormalReturn(_)
                | SummaryPort::ExceptionalReturn
                | SummaryPort::Capture(_)
                | SummaryPort::Heap(_),
            ) => return None,
        }
    }
}

fn exact_scalar_fact(value: u128) -> ScalarFact {
    ScalarFact::Integer(ScalarIntegerInterval::exact(
        ScalarIntegerValue::unsigned(value),
        ScalarIntegerDomain::Mathematical,
    ))
}

fn invocation_scalar_entry_facts(
    invocations: &Invocations,
    invocation: InvocationId,
) -> Vec<ScalarEntryFact> {
    let entry = &invocations.entries[invocation.0 as usize];
    let Some((parent, call)) = entry.caller else {
        return Vec::new();
    };
    let caller = &invocations.entries[parent.0 as usize].context;
    let call = caller
        .procedure
        .semantics()
        .call_site(call)
        .expect("invocation caller owns its call site");
    entry
        .context
        .procedure
        .semantics()
        .values()
        .iter()
        .filter_map(|formal| {
            let crate::analyzer::semantic::SemanticValueKind::Parameter { ordinal, .. } =
                formal.kind
            else {
                return None;
            };
            let actual = call.arguments.get(usize::try_from(ordinal).ok()?)?.value;
            invocation_scalar_integer(invocations, parent, actual).map(|value| ScalarEntryFact {
                target: formal.id,
                fact: exact_scalar_fact(value),
            })
        })
        .collect()
}

fn recursive_scalar_entry_facts(
    target: &ProcedureHandle,
    call: &crate::analyzer::semantic::SemanticCallSite,
    derivation: &ScalarStateDerivation,
) -> Vec<ScalarEntryFact> {
    target
        .semantics()
        .values()
        .iter()
        .filter_map(|formal| {
            let crate::analyzer::semantic::SemanticValueKind::Parameter { ordinal, .. } =
                formal.kind
            else {
                return None;
            };
            let actual = call.arguments.get(usize::try_from(ordinal).ok()?)?.value;
            let ScalarFact::Integer(interval) = derivation.fact_at(call.point, actual) else {
                return None;
            };
            interval.exact_value().map(|value| ScalarEntryFact {
                target: formal.id,
                fact: ScalarFact::Integer(ScalarIntegerInterval::exact(value, interval.domain())),
            })
        })
        .collect()
}

fn scalar_entry_values(
    entry_facts: &[ScalarEntryFact],
) -> Option<Vec<(ValueId, ScalarIntegerValue)>> {
    let mut result = entry_facts
        .iter()
        .map(|entry| {
            let ScalarFact::Integer(interval) = entry.fact else {
                return None;
            };
            Some((entry.target, interval.exact_value()?))
        })
        .collect::<Option<Vec<_>>>()?;
    result.sort_unstable_by_key(|(target, _)| *target);
    Some(result)
}

fn scalar_inputs_strictly_decrease(
    current: &[(ValueId, ScalarIntegerValue)],
    next: &[(ValueId, ScalarIntegerValue)],
) -> bool {
    current.len() == next.len()
        && current
            .iter()
            .zip(next)
            .all(|((current_id, current), (next_id, next))| {
                current_id == next_id && next <= current
            })
        && current
            .iter()
            .zip(next)
            .any(|((_, current), (_, next))| next < current)
}

fn canonicalize_bound_accesses(
    classes: &mut SynchronizationSubjectClasses,
    invocations: &Invocations,
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
        // Field identity does not depend on knowing which object is reached.
        // Retain a resolved declaration even when base binding remains open.
        if let Some(domain) = &mut access.field_alias_domain {
            domain.declaration.clone_from(&declaration);
        }
        let (base, selector, indexed) = match &row.kind {
            MemoryLocationKind::Field { base, member } => {
                // The selector buckets accesses before the overlap gate sees
                // them, so it has to agree about one field too.
                let selector = classes.field_storage_selector(member);
                (*base, Some(selector), None)
            }
            MemoryLocationKind::Property { base, key } => (
                *base,
                Some(ConcurrencyStorageSelector::Property(key.to_string())),
                None,
            ),
            MemoryLocationKind::Index {
                base,
                index,
                constant_index,
                identity,
                ..
            } => {
                let constant_index = (*constant_index).or_else(|| {
                    (*index).and_then(|index| {
                        invocation_scalar_integer(invocations, access.site.invocation, index)
                    })
                });
                let selector = match (identity, constant_index) {
                    (IndexedLocationIdentity::Aggregate, _) => {
                        Some(ConcurrencyStorageSelector::Aggregate)
                    }
                    (IndexedLocationIdentity::Element, Some(index)) => i128::try_from(index)
                        .ok()
                        .map(ConcurrencyStorageSelector::ConstantIndex),
                    (IndexedLocationIdentity::Element, None) => None,
                };
                (*base, selector, Some((*identity, constant_index)))
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
        let opaque = classes.identity_is_opaque(local_base.clone());
        let local_root = classes.root(local_base.clone());
        let origins = classes.backing_field_origins.clone();
        let loaded_base = origins
            .into_iter()
            .any(|origin| classes.root(origin.result) == local_root);
        let backing_root = classes.backing_root(local_base.clone());
        let multiple_allocations = classes.multiple_allocations.clone();
        let multiple_instances = multiple_allocations
            .into_iter()
            .any(|allocation| classes.backing_root(allocation) == backing_root);
        let base = if opaque {
            None
        } else {
            match &row.kind {
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
            }
        };
        let Some(base) = base else {
            if contains_formal || opaque || loaded_base {
                access.canonical = None;
                access.storage_origin = None;
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
                .push(ConcurrencyStorageSelector::AnyIndex);
            access.resolved_location.exhaustive = false;
            access.resolved_location.cardinality = ConcurrencyObjectCardinality::Multiple;
            access.reasons = vec![ConcurrencyOpenReason::UnknownLocation];
        }
    }
}

fn summary_event_key(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    source: SourceMappingId,
    ordinal: usize,
) -> SummaryEventKey {
    let mapping = semantics
        .source_mapping(source)
        .expect("validated semantic event retains its source mapping");
    SummaryEventKey::from_concurrency_source(&mapping.locator, ordinal)
}

pub(crate) fn source_allocation_summary_path(
    procedure: &ProcedureHandle,
    allocation: AllocationId,
) -> SummaryConcurrencyAccessPath {
    let semantics = procedure.semantics();
    let allocation_ordinal = semantics
        .allocations()
        .iter()
        .position(|candidate| candidate.id == allocation)
        .expect("validated allocation belongs to its procedure");
    let allocation = semantics
        .allocation(allocation)
        .expect("validated allocation belongs to its procedure");
    let mapping = semantics
        .source_mapping(allocation.source)
        .expect("validated allocation retains its source mapping");
    SummaryConcurrencyAccessPath::port(SummaryPort::Heap(
        SummaryLocationKey::from_allocation_source(&mapping.locator, allocation_ordinal),
    ))
}

fn live_summary_call(
    procedure: &ProcedureHandle,
    event: SummaryEventKey,
    witness: Option<SummaryCallSourceWitness>,
) -> Option<CallSiteId> {
    let witness = witness?;
    let semantics = procedure.semantics();
    if witness.procedure()
        != crate::dataflow::SummaryProcedureSourceKey::from_locator(semantics.locator())
    {
        return None;
    }
    let mut matching = semantics
        .call_sites()
        .iter()
        .enumerate()
        .filter_map(|(ordinal, call)| {
            let mapping = semantics
                .source_mapping(call.source)
                .expect("validated call retains its source mapping");
            let span = mapping.locator.anchor().span();
            (SummaryEventKey::from_call_source(&mapping.locator, ordinal) == event
                && span.start_byte() == witness.start_byte()
                && span.end_byte() == witness.end_byte())
            .then_some(call.id)
        });
    let call = matching.next()?;
    matching.next().is_none().then_some(call)
}

fn summary_dependency_matches_target(
    provider: &impl ConcurrencyProvider,
    dependency: &SummaryDependencyKey,
    target: &ProcedureHandle,
) -> bool {
    let Some(summary) = provider.complete_summary(target) else {
        return false;
    };
    match dependency {
        SummaryDependencyKey::Complete(key) => summary.key() == key.as_ref(),
        SummaryDependencyKey::Recursive(identity) => summary.key().identity() == identity.as_ref(),
    }
}

/// Certify the finite fixed point for one synchronous recursive access SCC.
/// Every member on the retained activation chain already contributes its
/// source accesses once in this task. Repeating the cycle cannot add a
/// cross-task access or synchronization edge when the back edge restores the
/// ancestor's reference inputs and every member has the same closed summary
/// component and exact effect-free call boundary.
///
/// This deliberately accepts only exact source-backed accesses, proven
/// unpublished allocations, and one internal call per member. Repeated
/// unpublished allocations create distinct activation-local objects and add no
/// cross-task identity. A group may additionally carry reference results whose
/// complete semantic return inventories preserve stable objects or forward the
/// next member's recursive results. Every concrete result base in the component
/// must be the same exact object, and at least one member must supply a base.
/// Published allocations, captures, and generic transfers remain open. One
/// source-backed channel send is accepted only when a scalar path certificate
/// proves that it executes exactly once across the omitted recursive closure.
/// A dynamic index is accepted only when every
/// member forwards the same scalar port unchanged at its SCC edge; a computed
/// or reassigned argument therefore cannot enter the fixed point.
#[allow(clippy::too_many_arguments)]
fn recursive_access_summaries_cover_call(
    provider: &impl ConcurrencyProvider,
    classes: &mut SynchronizationSubjectClasses,
    invocations: &Invocations,
    tasks: &[Task],
    effect_free_call_targets: &HashMap<(InvocationId, CallSiteId), ProcedureHandle>,
    caller: &ContextKey,
    call: &crate::analyzer::semantic::SemanticCallSite,
    target: &ProcedureHandle,
    ancestor: InvocationId,
    request: &mut SemanticRequest<'_>,
) -> bool {
    if call.invocation_mode != CallInvocationMode::Ordinary
        || call.execution_timing != ExecutionTiming::SameEvaluation
    {
        return false;
    }
    let Some(target_summary) = provider.complete_summary(target) else {
        return false;
    };
    let Some(group) = target_summary.recursive_group() else {
        return false;
    };
    let ancestor_context = &invocations.entries[ancestor.0 as usize].context;
    if ancestor_context.procedure != *target || ancestor_context.task != caller.task {
        return false;
    }

    let mut member_contexts = Vec::new();
    let mut cursor = caller.invocation;
    loop {
        let entry = &invocations.entries[cursor.0 as usize];
        if entry.context.task != caller.task {
            return false;
        }
        member_contexts.push(&entry.context);
        if cursor == ancestor {
            break;
        }
        let Some((parent, _)) = entry.caller else {
            return false;
        };
        cursor = parent;
    }

    let mut member_identities = HashSet::default();
    let mut member_summaries = Vec::with_capacity(member_contexts.len());
    for context in &member_contexts {
        let Some(summary) = provider.complete_summary(&context.procedure) else {
            return false;
        };
        if summary.recursive_group() != Some(group)
            || !member_identities.insert(summary.key().identity().clone())
        {
            return false;
        }
        member_summaries.push(summary);
    }
    if member_identities.len() != group.member_count() as usize
        || !validate_recursive_summary_batch(&member_summaries)
            .is_ok_and(|validated| validated.group == group)
    {
        return false;
    }

    let mut dynamic_index_ports = HashSet::default();
    for summary in &member_summaries {
        for effect in summary.effects() {
            let SummaryEffectKey::Concurrency(concurrency) = effect.key() else {
                continue;
            };
            let SummaryConcurrencyEffectKind::Access { location, .. } = concurrency.kind() else {
                continue;
            };
            for selector in location.selectors() {
                if let SummaryConcurrencyAccessSelector::Index(port) = selector {
                    dynamic_index_ports.insert(port.clone());
                }
            }
        }
    }

    let mut access_count = 0_usize;
    let mut private_allocation_count = 0_usize;
    let mut synchronization_count = 0_usize;
    let mut recursive_result_ordinals = None::<Vec<u32>>;
    let mut recursive_result_bases = HashMap::<u32, ConcurrencyIdentityFact>::default();
    let mut saw_no_result = false;
    for context in member_contexts {
        let summary = provider
            .complete_summary(&context.procedure)
            .expect("recursive member summary was collected above");
        if summary.composition_root() != summary.key()
            || !summary.completeness().is_complete()
            || !summary.transfers().is_empty()
            || summary.dependencies().len() != 1
            || !matches!(&summary.dependencies()[0], SummaryDependencyKey::Recursive(identity)
                if member_identities.contains(identity.as_ref()))
        {
            return false;
        }
        let [member_call] = context.procedure.semantics().call_sites() else {
            return false;
        };
        let Some(live_target) = effect_free_call_targets.get(&(context.invocation, member_call.id))
        else {
            return false;
        };
        let Some(live_target_summary) = provider.complete_summary(live_target) else {
            return false;
        };
        let target_group_mismatch = live_target_summary.recursive_group() != Some(group);
        let target_member_missing =
            !member_identities.contains(live_target_summary.key().identity());
        let dynamic_index_mismatch = dynamic_index_ports.iter().any(|port| {
            !recursive_scalar_port_is_invariant(context.procedure.semantics(), member_call, port)
        });
        let source_gaps_open =
            !recursive_access_source_gaps_are_closed(&context.procedure, member_call);
        if target_group_mismatch
            || target_member_missing
            || dynamic_index_mismatch
            || source_gaps_open
        {
            return false;
        }
        let Some(result_transition) = recursive_result_transition(
            provider,
            classes,
            invocations,
            tasks,
            context,
            member_call,
            live_target,
            request,
        ) else {
            return false;
        };
        match &result_transition {
            RecursiveResultTransition::None => {
                if recursive_result_ordinals.is_some() {
                    return false;
                }
                saw_no_result = true;
            }
            RecursiveResultTransition::InvariantReferences { bases } => {
                if saw_no_result {
                    return false;
                }
                let ordinals = bases
                    .iter()
                    .map(|(ordinal, _)| *ordinal)
                    .collect::<Vec<_>>();
                if recursive_result_ordinals
                    .as_ref()
                    .is_some_and(|expected| expected != &ordinals)
                {
                    return false;
                }
                recursive_result_ordinals = Some(ordinals);
                for (ordinal, base) in bases {
                    let Some(base) = base else {
                        continue;
                    };
                    if recursive_result_bases
                        .get(ordinal)
                        .is_some_and(|existing| existing != base)
                    {
                        return false;
                    }
                    recursive_result_bases.insert(*ordinal, base.clone());
                }
            }
        }

        let mut saw_call = false;
        let mut summarized_accesses = HashSet::default();
        let mut summarized_synchronization_events = HashSet::default();
        let mut summarized_synchronizations = Vec::new();
        let mut unpublished_allocations = HashSet::default();
        for effect in summary.effects() {
            let SummaryEffectKey::Concurrency(concurrency) = effect.key() else {
                continue;
            };
            if !matches!(
                concurrency.kind(),
                SummaryConcurrencyEffectKind::Unpublished { .. }
            ) {
                continue;
            }
            let pending = PendingSummaryEffect {
                context: context.clone(),
                effect: concurrency.clone(),
            };
            let Ok(allocation) = source_summary_unpublished(&pending) else {
                return false;
            };
            if concurrency.execution().timing() != ExecutionTiming::SameEvaluation
                || !effect.evidence().is_proven()
                || !effect.evidence().is_complete()
                || !unpublished_allocations.insert(allocation)
            {
                return false;
            }
        }
        let mut summarized_allocations = HashSet::default();
        for effect in summary.effects() {
            if !effect.evidence().is_proven() || !effect.evidence().is_complete() {
                return false;
            }
            match effect.key() {
                SummaryEffectKey::Call {
                    event,
                    callee,
                    witness,
                } => {
                    if saw_call
                        || callee.identity() != live_target_summary.key().identity()
                        || !matches!(callee.as_ref(), SummaryDependencyKey::Recursive(_))
                        || live_summary_call(&context.procedure, *event, *witness)
                            != Some(member_call.id)
                    {
                        return false;
                    }
                    saw_call = true;
                }
                SummaryEffectKey::Concurrency(concurrency) => match concurrency.kind() {
                    SummaryConcurrencyEffectKind::Access {
                        location,
                        must_hold,
                        ..
                    } => {
                        let pending = PendingSummaryEffect {
                            context: context.clone(),
                            effect: concurrency.clone(),
                        };
                        let Ok(source) = source_summary_access(&pending) else {
                            return false;
                        };
                        if concurrency.execution().timing() != ExecutionTiming::SameEvaluation
                            || !must_hold.is_empty()
                            || !matches!(
                                crate::typestate::direct_concurrency_path(
                                    &context.procedure,
                                    source.location,
                                ),
                                crate::typestate::DirectConcurrencyPath::Boundary(source)
                                    if &source == location
                            )
                            || !recursive_access_path_is_invariant(
                                &context.procedure,
                                member_call,
                                location,
                            )
                            || !summarized_accesses.insert(concurrency.event())
                        {
                            return false;
                        }
                    }
                    SummaryConcurrencyEffectKind::Allocation { .. } => {
                        let pending = PendingSummaryEffect {
                            context: context.clone(),
                            effect: concurrency.clone(),
                        };
                        let Ok(allocation) = source_summary_allocation(&pending) else {
                            return false;
                        };
                        if concurrency.execution().timing() != ExecutionTiming::SameEvaluation
                            || !unpublished_allocations.contains(&allocation)
                            || !summarized_allocations.insert(allocation)
                        {
                            return false;
                        }
                    }
                    SummaryConcurrencyEffectKind::Unpublished { .. } => {}
                    SummaryConcurrencyEffectKind::Synchronize { .. } => {
                        let pending = PendingSummaryEffect {
                            context: context.clone(),
                            effect: concurrency.clone(),
                        };
                        let Ok(synchronization) = source_summary_synchronization(&pending) else {
                            return false;
                        };
                        if concurrency.execution().timing() != ExecutionTiming::SameEvaluation
                            || !synchronization.complete
                            || synchronization.operation
                                != crate::analyzer::semantic::SynchronizationOperation::ChannelSend
                            || synchronization.payload.is_none()
                            || !summarized_synchronization_events.insert(concurrency.event())
                        {
                            return false;
                        }
                        summarized_synchronizations.push(synchronization);
                    }
                    _ => return false,
                },
                _ => return false,
            }
        }
        if !summarized_synchronizations.is_empty() {
            if group.member_count() != 1 {
                return false;
            }
            match recursive_synchronization_executes_exactly_once(
                invocations,
                context,
                member_call,
                &summarized_synchronizations,
                request,
            ) {
                Ok(true) => {}
                Ok(false) => return false,
                Err(reason) => {
                    classes.identity_reasons.push(reason);
                    return false;
                }
            }
        }
        if !saw_call
            || summarized_allocations != unpublished_allocations
            || !recursive_access_source_inventory_is_closed(
                &context.procedure,
                member_call,
                &summarized_accesses,
                &summarized_allocations,
                &summarized_synchronization_events,
                &result_transition,
            )
        {
            return false;
        }
        access_count = access_count.saturating_add(summarized_accesses.len());
        private_allocation_count =
            private_allocation_count.saturating_add(summarized_allocations.len());
        synchronization_count =
            synchronization_count.saturating_add(summarized_synchronizations.len());
    }
    (access_count > 0 || private_allocation_count > 0 || synchronization_count > 0)
        && recursive_result_ordinals.as_ref().is_none_or(|ordinals| {
            ordinals
                .iter()
                .all(|ordinal| recursive_result_bases.contains_key(ordinal))
        })
}

fn recursive_synchronization_executes_exactly_once(
    invocations: &Invocations,
    context: &ContextKey,
    recursive_call: &crate::analyzer::semantic::SemanticCallSite,
    synchronizations: &[PendingIntrinsicSynchronization],
    request: &mut SemanticRequest<'_>,
) -> Result<bool, ConcurrencyOpenReason> {
    let [synchronization] = synchronizations else {
        return Ok(false);
    };
    if synchronization.task != context.task
        || synchronization.invocation != context.invocation
        || synchronization.procedure != context.procedure
        || synchronization.operation
            != crate::analyzer::semantic::SynchronizationOperation::ChannelSend
        || synchronization.payload.is_none()
        || point_is_cyclic(context.procedure.semantics(), recursive_call.point, request)?
        || point_is_cyclic(
            context.procedure.semantics(),
            synchronization.point,
            request,
        )?
    {
        return Ok(false);
    }
    let semantics = context.procedure.semantics();
    if !semantics
        .point(synchronization.point)
        .and_then(|point| point.events.get(synchronization.event))
        .is_some_and(|event| {
            matches!(
                event.effect,
                SemanticEffect::Synchronization {
                    operation: crate::analyzer::semantic::SynchronizationOperation::ChannelSend,
                    payload: Some(_),
                    ..
                }
            )
        })
    {
        return Ok(false);
    }

    let mut entry_facts = invocation_scalar_entry_facts(invocations, context.invocation);
    let Some(mut scalar_values) = scalar_entry_values(&entry_facts) else {
        return Ok(false);
    };
    if scalar_values.is_empty() || !scalar_entry_formals_are_immutable(semantics, &entry_facts) {
        return Ok(false);
    }
    let mut visited = HashSet::default();
    loop {
        charge_concurrency_work(request, 1)?;
        if !visited.insert(scalar_values.clone()) {
            return Ok(false);
        }
        let derivation = ScalarStateDerivation::derive_with_entry_facts(
            &context.procedure,
            ScalarCallEffects::default(),
            &entry_facts,
        );
        let recursive = derivation.is_reachable(recursive_call.point);
        let synchronized = derivation.is_reachable(synchronization.point);
        match (recursive, synchronized) {
            (true, false) => {
                if !scalar_paths_cross_point(
                    &context.procedure,
                    &derivation,
                    recursive_call.point,
                    semantics.normal_exit_point(),
                    request,
                )? {
                    return Ok(false);
                }
                let next_entry_facts =
                    recursive_scalar_entry_facts(&context.procedure, recursive_call, &derivation);
                let Some(next_values) = scalar_entry_values(&next_entry_facts) else {
                    return Ok(false);
                };
                if !scalar_inputs_strictly_decrease(&scalar_values, &next_values)
                    || !scalar_entry_formals_are_immutable(semantics, &next_entry_facts)
                {
                    return Ok(false);
                }
                entry_facts = next_entry_facts;
                scalar_values = next_values;
            }
            (false, true) => {
                return scalar_paths_cross_point(
                    &context.procedure,
                    &derivation,
                    synchronization.point,
                    semantics.normal_exit_point(),
                    request,
                );
            }
            (false, false) | (true, true) => return Ok(false),
        }
    }
}

fn scalar_entry_formals_are_immutable(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    entry_facts: &[ScalarEntryFact],
) -> bool {
    let formals = entry_facts
        .iter()
        .map(|entry| entry.target)
        .collect::<HashSet<_>>();
    semantics
        .points()
        .iter()
        .flat_map(|point| &point.events)
        .all(|event| match event.effect {
            SemanticEffect::Assignment { target, .. } => !formals.contains(&target),
            SemanticEffect::MemoryStore { location, .. } => semantics
                .memory_location(location)
                .is_none_or(|location| match location.kind {
                    MemoryLocationKind::LexicalCell { binding }
                    | MemoryLocationKind::Capture {
                        binding: Some(binding),
                        ..
                    } => !formals.contains(&binding),
                    _ => true,
                }),
            _ => true,
        })
}

fn scalar_paths_cross_point(
    procedure: &ProcedureHandle,
    derivation: &ScalarStateDerivation,
    required: ProgramPointId,
    endpoint: ProgramPointId,
    request: &mut SemanticRequest<'_>,
) -> Result<bool, ConcurrencyOpenReason> {
    if !derivation.is_reachable(required) || !derivation.is_reachable(endpoint) {
        return Ok(false);
    }
    let semantics = procedure.semantics();
    let mut pending = VecDeque::from([semantics.entry_point()]);
    let mut visited = HashSet::default();
    while let Some(point) = pending.pop_front() {
        charge_concurrency_work(request, 1)?;
        if point == required || !visited.insert(point) {
            continue;
        }
        if point == endpoint {
            return Ok(false);
        }
        pending.extend(
            semantics
                .successor_edges(point)
                .filter(|(edge, _)| derivation.edge_is_feasible(*edge))
                .map(|(_, edge)| edge.target_point),
        );
    }
    Ok(true)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RecursiveResultTransition {
    None,
    InvariantReferences {
        bases: Vec<(u32, Option<ConcurrencyIdentityFact>)>,
    },
}

/// Prove one member's result transition for the recursive access certificate.
/// The semantic return-flow inventory must be complete, the language provider
/// must say that every result preserves reference identity, and every normal
/// return must be either the next member's same-ordinal recursive result or one
/// stable exact object. The component-level caller requires one concrete base
/// for each ordinal across the group, so a forwarding-only member is valid but
/// an unanchored result equation is not.
#[allow(clippy::too_many_arguments)]
fn recursive_result_transition(
    provider: &impl ConcurrencyProvider,
    classes: &mut SynchronizationSubjectClasses,
    invocations: &Invocations,
    tasks: &[Task],
    context: &ContextKey,
    call: &crate::analyzer::semantic::SemanticCallSite,
    target: &ProcedureHandle,
    request: &mut SemanticRequest<'_>,
) -> Option<RecursiveResultTransition> {
    use crate::analyzer::semantic::ValueFlowKind;

    let semantics = context.procedure.semantics();
    let mut result_ordinals = HashSet::default();
    let mut has_value_return = false;
    for event in semantics.points().iter().flat_map(|point| &point.events) {
        match event.effect {
            SemanticEffect::ValueFlow {
                kind: ValueFlowKind::Return,
                ..
            } => {
                result_ordinals.insert(0_u32);
            }
            SemanticEffect::ValueFlow {
                kind: ValueFlowKind::IndexedReturn { ordinal },
                ..
            } => {
                result_ordinals.insert(ordinal);
            }
            SemanticEffect::ProcedureReturn { value: Some(_) } => has_value_return = true,
            _ => {}
        }
    }
    if result_ordinals.is_empty() {
        return (!has_value_return).then_some(RecursiveResultTransition::None);
    }
    let mut result_ordinals = result_ordinals.into_iter().collect::<Vec<_>>();
    result_ordinals.sort_unstable();
    if result_ordinals
        .iter()
        .copied()
        .ne(0..u32::try_from(result_ordinals.len()).ok()?)
        || call.normal_result_values().count() != result_ordinals.len()
        || call.invocation_mode != CallInvocationMode::Ordinary
        || call.execution_timing != ExecutionTiming::SameEvaluation
        || call.normal_continuation.target().is_none()
        || !reference_evidence_is_complete(semantics, call.evidence)
    {
        return None;
    }
    let mut bases = Vec::with_capacity(result_ordinals.len());
    for ordinal in result_ordinals {
        if provider.result_binds_by_reference(target, ordinal) != Some(true) {
            return None;
        }
        let recursive_result = call.normal_result(usize::try_from(ordinal).ok()?)?;
        let sources = match reference_result_sources(context, ordinal, request) {
            Ok(Some(sources)) if !sources.is_empty() => sources,
            Ok(_) => return None,
            Err(reason) => {
                classes.identity_reasons.push(reason);
                return None;
            }
        };
        let mut base = None::<ConcurrencyIdentityFact>;
        for source in sources {
            let LocalSynchronizationSubject::Value {
                task,
                invocation,
                procedure,
                value,
            } = &source.subject
            else {
                return None;
            };
            if *task != context.task
                || *invocation != context.invocation
                || procedure != &context.procedure
            {
                return None;
            }
            if *value == recursive_result {
                continue;
            }
            if !reference_source_is_stable(classes, invocations, tasks, &source, request) {
                return None;
            }
            let recursive_subject = LocalSynchronizationSubject::Value {
                task: context.task,
                invocation: context.invocation,
                procedure: context.procedure.clone(),
                value: recursive_result,
            };
            if classes.root(source.subject.clone()) == classes.root(recursive_subject) {
                continue;
            }
            let ConcurrencyAnswer::Proven(Some(fact)) =
                classes.bound_canonical_identity(source.subject.clone())
            else {
                return None;
            };
            if fact.resolved.exact_candidate().is_none()
                || fact.storage_origin.as_ref() != Some(fact.canonical())
                || base.as_ref().is_some_and(|existing| existing != &fact)
            {
                return None;
            }
            base = Some(fact);
        }
        bases.push((ordinal, base));
    }
    Some(RecursiveResultTransition::InvariantReferences { bases })
}

fn recursive_access_source_gaps_are_closed(
    target: &ProcedureHandle,
    call: &crate::analyzer::semantic::SemanticCallSite,
) -> bool {
    target
        .semantics()
        .gaps()
        .iter()
        .all(|gap| recursive_access_source_gap_is_closed(target, gap, call))
}

fn recursive_access_source_gap_is_closed(
    target: &ProcedureHandle,
    gap: &crate::analyzer::semantic::SemanticGap,
    call: &crate::analyzer::semantic::SemanticCallSite,
) -> bool {
    use crate::analyzer::semantic::{SemanticCapability, SemanticGapDischarge, SemanticGapSubject};

    match (gap.capability, gap.subject) {
        (
            SemanticCapability::ExceptionalControlFlow
            | SemanticCapability::ExceptionalCallContinuation,
            SemanticGapSubject::Point,
        ) => gap.discharge == SemanticGapDischarge::NonRejoiningExceptionalExit,
        (SemanticCapability::NormalControlFlow, SemanticGapSubject::Point) => {
            gap.discharge == SemanticGapDischarge::RetainedControlTopology
                && target.semantics().point(gap.point).is_some_and(|point| {
                    point.events.iter().any(|event| {
                    matches!(
                        event.effect,
                        SemanticEffect::Synchronization {
                            operation:
                                crate::analyzer::semantic::SynchronizationOperation::ChannelSend,
                            payload: Some(_),
                            ..
                        }
                    )
                })
                })
        }
        (SemanticCapability::Calls, SemanticGapSubject::CallSite(candidate)) => {
            candidate == call.id
        }
        (SemanticCapability::DynamicDispatch, SemanticGapSubject::CallSite(candidate)) => {
            candidate == call.id
        }
        (SemanticCapability::CallableReferences, SemanticGapSubject::Value(candidate)) => {
            candidate == call.callee
        }
        (SemanticCapability::IndexMemory, SemanticGapSubject::MemoryLocation(location)) => {
            matches!(
                crate::typestate::direct_concurrency_path(target, location),
                crate::typestate::DirectConcurrencyPath::Boundary(path)
                    if path.selectors().iter().any(|selector| {
                        matches!(selector, SummaryConcurrencyAccessSelector::Index(_))
                    }) && recursive_access_path_is_invariant(target, call, &path)
            )
        }
        _ => false,
    }
}

fn recursive_access_source_inventory_is_closed(
    target: &ProcedureHandle,
    call: &crate::analyzer::semantic::SemanticCallSite,
    summarized_accesses: &HashSet<SummaryEventKey>,
    summarized_allocations: &HashSet<AllocationId>,
    summarized_synchronizations: &HashSet<SummaryEventKey>,
    result_transition: &RecursiveResultTransition,
) -> bool {
    use crate::analyzer::semantic::{SemanticEffect, ValueFlowKind};

    let semantics = target.semantics();
    semantics
        .points()
        .iter()
        .flat_map(|point| &point.events)
        .enumerate()
        .all(|(ordinal, event)| match event.effect {
            SemanticEffect::MemoryLoad { location, .. }
            | SemanticEffect::MemoryStore { location, .. } => {
                match crate::typestate::direct_concurrency_path(target, location) {
                    crate::typestate::DirectConcurrencyPath::Boundary(_) => summarized_accesses
                        .contains(&summary_event_key(semantics, event.source, ordinal)),
                    crate::typestate::DirectConcurrencyPath::Local => true,
                    crate::typestate::DirectConcurrencyPath::Open => false,
                }
            }
            SemanticEffect::Entry
            | SemanticEffect::NormalExit
            | SemanticEffect::ExceptionalExit
            | SemanticEffect::Assignment { .. }
            | SemanticEffect::ValueUse { .. }
            | SemanticEffect::ProcedureReturn { value: None } => true,
            SemanticEffect::ValueFlow {
                kind: ValueFlowKind::Return | ValueFlowKind::IndexedReturn { .. },
                ..
            }
            | SemanticEffect::ProcedureReturn { value: Some(_) } => {
                matches!(
                    result_transition,
                    RecursiveResultTransition::InvariantReferences { .. }
                )
            }
            SemanticEffect::ValueFlow { .. } => true,
            SemanticEffect::CallableReference { result, .. } => result == call.callee,
            SemanticEffect::Invoke { call_site }
            | SemanticEffect::CallContinuation { call_site, .. } => call_site == call.id,
            SemanticEffect::Gap { gap } => semantics
                .gap(gap)
                .is_some_and(|gap| recursive_access_source_gap_is_closed(target, gap, call)),
            SemanticEffect::Allocation { allocation } => {
                summarized_allocations.contains(&allocation)
            }
            SemanticEffect::Synchronization { .. } => summarized_synchronizations
                .contains(&summary_event_key(semantics, event.source, ordinal)),
            SemanticEffect::AggregateInitializer { .. }
            | SemanticEffect::CallableCreation { .. }
            | SemanticEffect::CaptureBind { .. }
            | SemanticEffect::Throw { .. }
            | SemanticEffect::AsyncSuspend { .. }
            | SemanticEffect::AsyncResume { .. } => false,
        })
}

fn recursive_access_path_is_invariant(
    target: &ProcedureHandle,
    call: &crate::analyzer::semantic::SemanticCallSite,
    path: &SummaryConcurrencyAccessPath,
) -> bool {
    use crate::analyzer::semantic::SemanticValueKind;

    let semantics = target.semantics();
    let boundary_exists = match path.root() {
        SummaryPort::Receiver => semantics
            .values()
            .iter()
            .any(|value| matches!(value.kind, SemanticValueKind::Receiver { dispatch: true })),
        SummaryPort::Parameter(ordinal) => semantics.values().iter().any(|value| {
            matches!(value.kind, SemanticValueKind::Parameter { ordinal: candidate, .. }
                if candidate == *ordinal)
        }),
        SummaryPort::Heap(_) => true,
        SummaryPort::Capture(_)
        | SummaryPort::NormalReturn
        | SummaryPort::IndexedNormalReturn(_)
        | SummaryPort::ExceptionalReturn => false,
    };
    boundary_exists
        && path.selectors().iter().all(|selector| match selector {
            SummaryConcurrencyAccessSelector::Index(port) => {
                recursive_scalar_port_is_invariant(semantics, call, port)
            }
            SummaryConcurrencyAccessSelector::Field(_)
            | SummaryConcurrencyAccessSelector::Property(_)
            | SummaryConcurrencyAccessSelector::Aggregate
            | SummaryConcurrencyAccessSelector::ConstantIndex(_)
            | SummaryConcurrencyAccessSelector::AnyIndex => true,
        })
}

fn recursive_scalar_port_is_invariant(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    call: &crate::analyzer::semantic::SemanticCallSite,
    port: &SummaryPort,
) -> bool {
    use crate::analyzer::semantic::SemanticValueKind;

    match port {
        SummaryPort::Receiver => semantics
            .values()
            .iter()
            .find(|value| matches!(value.kind, SemanticValueKind::Receiver { dispatch: true }))
            .is_some_and(|receiver| call.receiver == Some(receiver.id)),
        SummaryPort::Parameter(ordinal) => semantics
            .values()
            .iter()
            .find(|value| {
                matches!(value.kind, SemanticValueKind::Parameter { ordinal: candidate, .. }
                    if candidate == *ordinal)
            })
            .is_some_and(|formal| {
                call.arguments.get(*ordinal as usize).is_some_and(|actual| {
                    crate::typestate::direct_scalar_summary_port(semantics, actual.value)
                        == Some(SummaryPort::Parameter(*ordinal))
                        && crate::typestate::direct_scalar_summary_port(semantics, formal.id)
                            == Some(SummaryPort::Parameter(*ordinal))
                })
            }),
        SummaryPort::NormalReturn
        | SummaryPort::IndexedNormalReturn(_)
        | SummaryPort::ExceptionalReturn
        | SummaryPort::Capture(_)
        | SummaryPort::Heap(_) => false,
    }
}

fn live_summary_event(
    pending: &PendingSummaryEffect,
) -> Option<(
    ProgramPointId,
    usize,
    crate::analyzer::semantic::SemanticEvent,
)> {
    let witness = pending.effect.witness()?;
    let semantics = pending.context.procedure.semantics();
    if witness.procedure()
        != crate::dataflow::SummaryProcedureSourceKey::from_locator(semantics.locator())
    {
        return None;
    }
    let mut matching = semantics
        .points()
        .iter()
        .flat_map(|point| {
            point
                .events
                .iter()
                .enumerate()
                .map(move |(position, event)| (point.id, position, event))
        })
        .enumerate()
        .filter_map(|(ordinal, (point, position, event))| {
            let mapping = semantics
                .source_mapping(event.source)
                .expect("validated event retains its source mapping");
            let span = mapping.locator.anchor().span();
            (summary_event_key(semantics, event.source, ordinal) == pending.effect.event()
                && span.start_byte() == witness.start_byte()
                && span.end_byte() == witness.end_byte())
            .then(|| (point, position, event.clone()))
        });
    let event = matching.next()?;
    matching.next().is_none().then_some(event)
}

fn source_summary_modeled_call(
    pending: &PendingSummaryEffect,
) -> Result<(CallSiteId, ProgramPointId), &'static str> {
    let SummaryConcurrencyEffectKind::ModeledCall { .. } = pending.effect.kind() else {
        return Err("summary modeled-call certificate has an incompatible kind");
    };
    let Some((point, _, event)) = live_summary_event(pending) else {
        return Err("summary modeled-call witness is unavailable");
    };
    let SemanticEffect::Invoke { call_site } = event.effect else {
        return Err("summary modeled-call witness does not name an invocation");
    };
    let call = pending
        .context
        .procedure
        .semantics()
        .call_site(call_site)
        .ok_or("summary modeled-call invocation is unavailable")?;
    if call.point != point {
        return Err("summary modeled-call point does not match its invocation");
    }
    Ok((call_site, point))
}

fn source_summary_modeled_effect(
    pending: &PendingSummaryEffect,
    expected_call: CallSiteId,
) -> Result<ResolvedConcurrencyEffect, &'static str> {
    let (path, identity) = match pending.effect.kind() {
        SummaryConcurrencyEffectKind::Lock { lock, identity, .. } => (lock, *identity),
        SummaryConcurrencyEffectKind::Atomic { location, .. } => {
            (location, SummaryConcurrencySubjectIdentity::Value)
        }
        _ => return Err("summary modeled effect has an incompatible kind"),
    };
    let Some((point, _, event)) = live_summary_event(pending) else {
        return Err("summary modeled effect witness is unavailable");
    };
    let SemanticEffect::Invoke { call_site } = event.effect else {
        return Err("summary modeled effect witness does not name an invocation");
    };
    if call_site != expected_call {
        return Err("summary modeled effect names another invocation");
    }
    let call = pending
        .context
        .procedure
        .semantics()
        .call_site(call_site)
        .ok_or("summary modeled effect invocation is unavailable")?;
    if call.point != point {
        return Err("summary modeled effect point does not match its invocation");
    }
    let mut values = call
        .receiver
        .into_iter()
        .chain(call.arguments.iter().map(|argument| argument.value))
        .filter(|value| {
            matches!(
                crate::typestate::direct_concurrency_value_path(
                    &pending.context.procedure,
                    *value,
                ),
                crate::typestate::DirectConcurrencyPath::Boundary(ref candidate)
                    if candidate == path
            )
        });
    let value = values
        .next()
        .ok_or("summary modeled effect subject is unavailable")?;
    if values.next().is_some()
        || (identity == SummaryConcurrencySubjectIdentity::Backing && call.receiver != Some(value))
    {
        return Err("summary modeled effect subject is ambiguous");
    }
    let subject = ResolvedConcurrencySubject {
        value,
        canonical: None,
        reasons: Vec::new(),
        identity: match identity {
            SummaryConcurrencySubjectIdentity::Value => ConcurrencySubjectIdentity::Value,
            SummaryConcurrencySubjectIdentity::Backing => ConcurrencySubjectIdentity::Backing,
        },
    };
    Ok(match pending.effect.kind() {
        SummaryConcurrencyEffectKind::Lock {
            operation, mode, ..
        } => {
            let mode = match mode {
                SummaryConcurrencyLockMode::Shared => ConcurrencyLockMode::Shared,
                SummaryConcurrencyLockMode::Exclusive => ConcurrencyLockMode::Exclusive,
            };
            match operation {
                SummaryConcurrencyLockOperation::Acquire => {
                    ResolvedConcurrencyEffect::LockAcquire {
                        lock: subject,
                        mode,
                    }
                }
                SummaryConcurrencyLockOperation::Release => {
                    ResolvedConcurrencyEffect::LockRelease {
                        lock: subject,
                        mode,
                    }
                }
            }
        }
        SummaryConcurrencyEffectKind::Atomic { operation, .. } => {
            ResolvedConcurrencyEffect::Atomic {
                location: subject,
                operation: match operation {
                    crate::dataflow::SummaryConcurrencyAtomicOperation::Load => {
                        ConcurrencyAtomicOperation::Load
                    }
                    crate::dataflow::SummaryConcurrencyAtomicOperation::Store => {
                        ConcurrencyAtomicOperation::Store
                    }
                    crate::dataflow::SummaryConcurrencyAtomicOperation::ReadModifyWrite => {
                        ConcurrencyAtomicOperation::ReadModifyWrite
                    }
                },
            }
        }
        _ => unreachable!("only modeled locks and atomics have a replay subject"),
    })
}

fn source_summary_gap(pending: &PendingSummaryEffect) -> Result<&'static str, &'static str> {
    let SummaryConcurrencyEffectKind::Unsupported { protocol } = pending.effect.kind() else {
        return Err("summary unsupported effect has an incompatible kind");
    };
    let witness = pending
        .effect
        .witness()
        .ok_or("summary unsupported witness is unavailable")?;
    let semantics = pending.context.procedure.semantics();
    if witness.procedure()
        != crate::dataflow::SummaryProcedureSourceKey::from_locator(semantics.locator())
    {
        return Err("summary unsupported witness is unavailable");
    }
    let first_gap_ordinal = semantics
        .points()
        .iter()
        .map(|point| point.events.len())
        .sum::<usize>();
    let mut matching = semantics
        .gaps()
        .iter()
        .enumerate()
        .filter_map(|(index, gap)| {
            let mapping = semantics
                .source_mapping(gap.source)
                .expect("validated semantic gap retains its source mapping");
            let span = mapping.locator.anchor().span();
            (SummaryEventKey::from_concurrency_source(
                &mapping.locator,
                first_gap_ordinal.saturating_add(index),
            ) == pending.effect.event()
                && span.start_byte() == witness.start_byte()
                && span.end_byte() == witness.end_byte())
            .then_some(gap)
        });
    let gap = matching
        .next()
        .ok_or("summary unsupported witness is unavailable")?;
    if matching.next().is_some() {
        return Err("summary unsupported witness is ambiguous");
    }
    if !semantic_gap_omits_concurrency_access(gap) {
        return Err("summary unsupported witness does not omit a memory access");
    }
    let capability = gap.capability.label();
    if protocol.as_ref() != format!("semantic-gap:{capability}") {
        return Err("summary unsupported capability does not match source");
    }
    Ok(capability)
}

fn source_summary_allocation(pending: &PendingSummaryEffect) -> Result<AllocationId, &'static str> {
    let SummaryConcurrencyEffectKind::Allocation { location } = pending.effect.kind() else {
        return Err("summary allocation has an incompatible effect kind");
    };
    let Some((_, _, event)) = live_summary_event(pending) else {
        return Err("summary allocation witness is unavailable");
    };
    let SemanticEffect::Allocation { allocation } = event.effect else {
        return Err("summary allocation witness does not name an allocation");
    };
    if location != &source_allocation_summary_path(&pending.context.procedure, allocation) {
        return Err("summary allocation identity does not match source");
    }
    Ok(allocation)
}

fn source_summary_publication(
    pending: &PendingSummaryEffect,
) -> Result<AllocationId, &'static str> {
    let SummaryConcurrencyEffectKind::Publish { value, destination } = pending.effect.kind() else {
        return Err("summary publication has an incompatible effect kind");
    };
    let Some((point, event_index, _)) = live_summary_event(pending) else {
        return Err("summary publication witness is unavailable");
    };
    let semantics = pending.context.procedure.semantics();
    let expected_destination = crate::typestate::direct_publication_destination(
        &pending.context.procedure,
        point,
        event_index,
        match semantics
            .point(point)
            .and_then(|point| point.events.get(event_index))
            .map(|event| &event.effect)
        {
            Some(SemanticEffect::MemoryStore { .. }) => {
                crate::analyzer::semantic::FreshObjectPublicationKind::MemoryStore
            }
            Some(SemanticEffect::ProcedureReturn { .. } | SemanticEffect::ValueFlow { .. }) => {
                crate::analyzer::semantic::FreshObjectPublicationKind::Return
            }
            Some(SemanticEffect::Throw { .. }) => {
                crate::analyzer::semantic::FreshObjectPublicationKind::Throw
            }
            _ => return Err("summary publication witness is not a supported boundary"),
        },
    )
    .ok_or("summary publication destination is unavailable")?;
    if destination != &expected_destination {
        return Err("summary publication destination does not match source");
    }
    let mut allocations = semantics.allocations().iter().filter_map(|allocation| {
        (&source_allocation_summary_path(&pending.context.procedure, allocation.id) == value)
            .then_some(allocation.id)
    });
    let allocation = allocations
        .next()
        .ok_or("summary publication identity does not match source")?;
    if allocations.next().is_some() {
        return Err("summary publication identity is ambiguous");
    }
    Ok(allocation)
}

fn source_summary_unpublished(
    pending: &PendingSummaryEffect,
) -> Result<AllocationId, &'static str> {
    let SummaryConcurrencyEffectKind::Unpublished { value } = pending.effect.kind() else {
        return Err("summary non-publication has an incompatible effect kind");
    };
    let Some((_, _, event)) = live_summary_event(pending) else {
        return Err("summary non-publication witness is unavailable");
    };
    let SemanticEffect::Allocation { allocation } = event.effect else {
        return Err("summary non-publication witness does not name an allocation");
    };
    if value != &source_allocation_summary_path(&pending.context.procedure, allocation) {
        return Err("summary non-publication identity does not match source");
    }
    Ok(allocation)
}

fn source_summary_publication_inventory_open(
    pending: &PendingSummaryEffect,
) -> Result<AllocationId, &'static str> {
    let SummaryConcurrencyEffectKind::Unsupported { protocol } = pending.effect.kind() else {
        return Err("summary publication inventory has an incompatible effect kind");
    };
    if protocol.as_ref() != "publication-inventory-open" {
        return Err("summary publication inventory has an incompatible protocol");
    }
    let Some((_, _, event)) = live_summary_event(pending) else {
        return Err("summary publication inventory witness is unavailable");
    };
    let SemanticEffect::Allocation { allocation } = event.effect else {
        return Err("summary publication inventory does not name an allocation");
    };
    Ok(allocation)
}

fn source_summary_synchronization(
    pending: &PendingSummaryEffect,
) -> Result<PendingIntrinsicSynchronization, &'static str> {
    let SummaryConcurrencyEffectKind::Synchronize {
        operation: summarized_operation,
        ..
    } = pending.effect.kind()
    else {
        return Err("summary synchronization has an incompatible effect kind");
    };
    let Some((point, event_position, event)) = live_summary_event(pending) else {
        return Err("summary synchronization witness is unavailable");
    };
    let SemanticEffect::Synchronization {
        operation,
        subject,
        payload,
    } = event.effect
    else {
        return Err("summary synchronization witness does not name synchronization");
    };
    if *summarized_operation != operation.into() {
        return Err("summary synchronization operation does not match source");
    }
    let semantics = pending.context.procedure.semantics();
    Ok(PendingIntrinsicSynchronization {
        task: pending.context.task,
        invocation: pending.context.invocation,
        procedure: pending.context.procedure.clone(),
        point,
        operation,
        subject,
        payload,
        event: event_position,
        complete: reference_evidence_is_complete(semantics, event.evidence),
    })
}

fn source_summary_access(
    pending: &PendingSummaryEffect,
) -> Result<PendingSummaryAccess, &'static str> {
    let SummaryConcurrencyEffectKind::Access {
        location: path,
        mode: summarized_mode,
        ..
    } = pending.effect.kind()
    else {
        return Err("summary access has an incompatible effect kind");
    };
    let Some((point, _, event)) = live_summary_event(pending) else {
        return Err("summary access witness is unavailable");
    };
    let (location, mode, access_kind) = match (event.effect, summarized_mode) {
        (SemanticEffect::MemoryLoad { location, kind, .. }, SummaryConcurrencyAccessMode::Read) => {
            (location, ConcurrentAccessMode::Read, kind)
        }
        (
            SemanticEffect::MemoryStore { location, kind, .. },
            SummaryConcurrencyAccessMode::Write,
        ) => (location, ConcurrentAccessMode::Write, kind),
        _ => return Err("summary access mode does not match source"),
    };
    Ok(PendingSummaryAccess {
        context: pending.context.clone(),
        path: path.clone(),
        point,
        source: event.source,
        location,
        mode,
        access_kind,
    })
}

fn summary_access_uses_live_identity(
    provider: &impl ConcurrencyProvider,
    procedure: &ProcedureHandle,
    path: &SummaryConcurrencyAccessPath,
) -> bool {
    match path.root() {
        SummaryPort::Receiver => provider.receiver_binds_by_reference(procedure),
        SummaryPort::Parameter(ordinal) => {
            provider.parameter_binding(procedure, *ordinal) == Some(true)
        }
        SummaryPort::Capture(_) | SummaryPort::Heap(_) => true,
        SummaryPort::NormalReturn
        | SummaryPort::IndexedNormalReturn(_)
        | SummaryPort::ExceptionalReturn => false,
    }
}

fn append_summary_accesses(
    provider: &impl ConcurrencyProvider,
    classes: &mut SynchronizationSubjectClasses,
    pending: Vec<PendingSummaryAccess>,
    accesses: &mut Vec<Access>,
    request: &mut SemanticRequest<'_>,
) -> Result<(), SemanticProviderError> {
    for pending in pending {
        let local_location = LocalLocation {
            task: pending.context.task,
            invocation: pending.context.invocation,
            procedure: pending.context.procedure.clone(),
            location: pending.location,
        };
        let memory_location = pending
            .context
            .procedure
            .semantics()
            .memory_location(pending.location)
            .expect("summary witness access retains its live memory location");
        let local_identity = matches!(
            memory_location.kind,
            MemoryLocationKind::LexicalCell { .. } | MemoryLocationKind::Capture { .. }
        );
        let CanonicalizedAccess {
            canonical,
            resolved_location,
            reasons,
            index_alias_domain,
            field_alias_domain,
        } = if summary_access_uses_live_identity(
            provider,
            &pending.context.procedure,
            &pending.path,
        ) {
            // The stable path selects the exact source effect. Current
            // provider facts still own cross-file declarations and concrete
            // invocation identity, just as they do during direct expansion.
            canonicalize_access(
                provider,
                &pending.context,
                pending.point,
                pending.location,
                request,
            )?
        } else {
            // A value-copy or unavailable formal binding cannot inherit the
            // caller's object. Preserve its formal-boundary uncertainty
            // without asking live resolution to fabricate an alias candidate.
            let mut reasons =
                summary_formal_binding_reasons(classes, &pending.context, pending.path.root());
            if reasons.is_empty() {
                reasons.push(ConcurrencyOpenReason::UnknownLocation);
            }
            CanonicalizedAccess {
                canonical: None,
                resolved_location: ResolvedConcurrencyLocation::unknown(),
                reasons,
                index_alias_domain: None,
                field_alias_domain: match &memory_location.kind {
                    MemoryLocationKind::Field { member, .. } => Some(FieldAliasDomain {
                        declaration: None,
                        base: None,
                        member: member.clone(),
                    }),
                    _ => None,
                },
            }
        };
        accesses.push(Access {
            site: ConcurrentAccessSite {
                task: pending.context.task,
                invocation: pending.context.invocation,
                procedure: pending.context.procedure,
                point: pending.point,
                source: pending.source,
                mode: pending.mode,
                access_kind: pending.access_kind,
            },
            local_location: Some(local_location),
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
    Ok(())
}

fn summary_formal_binding_reasons(
    classes: &mut SynchronizationSubjectClasses,
    context: &ContextKey,
    port: &SummaryPort,
) -> Vec<ConcurrencyOpenReason> {
    let value = match port {
        SummaryPort::Receiver => context.procedure.semantics().values().iter().find(|value| {
            matches!(
                value.kind,
                crate::analyzer::semantic::SemanticValueKind::Receiver { .. }
            )
        }),
        SummaryPort::Parameter(ordinal) => {
            context.procedure.semantics().values().iter().find(|value| {
                matches!(
                    value.kind,
                    crate::analyzer::semantic::SemanticValueKind::Parameter {
                        ordinal: candidate,
                        ..
                    } if candidate == *ordinal
                )
            })
        }
        _ => None,
    };
    value.map_or_else(Vec::new, |value| {
        classes.formal_binding_reasons(LocalSynchronizationSubject::Value {
            task: context.task,
            invocation: context.invocation,
            procedure: context.procedure.clone(),
            value: value.id,
        })
    })
}

fn union_capture_locations(
    classes: &mut LocationClasses,
    synchronization_subjects: &mut SynchronizationSubjectClasses,
    parent: &ContextKey,
    child_task: TaskId,
    child_invocation: InvocationId,
    child: &ProcedureHandle,
    callable: ValueId,
) {
    let Some(environment) = parent
        .procedure
        .semantics()
        .points()
        .iter()
        .flat_map(|point| &point.events)
        .find_map(|event| match &event.effect {
            SemanticEffect::CallableCreation {
                result,
                callable: value,
            } if *result == callable => value.environment,
            _ => None,
        })
    else {
        return;
    };
    for capture in parent
        .procedure
        .semantics()
        .captures()
        .iter()
        .filter(|capture| {
            capture.callable == callable
                && capture.environment == environment
                && parent
                    .procedure
                    .artifact()
                    .procedure_handle(capture.target)
                    .as_ref()
                    == Some(child)
        })
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
    invocations: &Invocations,
    tasks: &[Task],
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
        let parameter_binding =
            parameter_ordinal.and_then(|ordinal| provider.parameter_binding(target, ordinal));
        let parameter_preserves_backing = parameter_ordinal
            .is_some_and(|ordinal| provider.parameter_preserves_backing(target, ordinal));
        let receiver_binding = dispatch_receiver && provider.receiver_binds_by_reference(target);
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
            .filter(|_| {
                let event = caller.procedure.semantics().point(call.point)
                    .expect("owned call point").events.iter().position(|event|
                        matches!(event.effect, SemanticEffect::Invoke { call_site } if call_site == call.id))
                    .expect("a retained call has its invocation event");
                reference_source_is_stable(classes, invocations, tasks,
                    &ReferenceIdentityUse { subject: actual.clone(), invocation: caller.invocation,
                        point: call.point, event }, request)
            })
        {
            callable_values.insert(
                (target_task, target_invocation, target.clone(), formal_value),
                callable,
            );
        }
        if !receiver_binding && parameter_binding != Some(true) && !parameter_preserves_backing {
            classes.value_copy_formals.insert(formal.clone());
        }
        classes.bind_backing_formal(formal.clone(), actual.clone());
        // A pointer receiver copies the pointer, so the callee's field
        // accesses reach the caller's object. Name that object exactly as the
        // caller's own field accesses name it, which is what the overlap gate
        // compares. `canonical_capture_identity` prefers a proven runtime
        // identity and otherwise issues a capture identity, and it issues one
        // only for a cell stored once, so the name cannot outlive the binding
        // it stands for.
        if dispatch_receiver && !receiver_binding {
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
        if parameter_ordinal.is_some() {
            match parameter_binding {
                Some(false) | None => {
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
                // A reference-shaped parameter still needs the identity of
                // the actual object before a snapshot can cross the call.
                Some(true) => {}
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

/// Traverse the exact source dependency closure before certifying that no
/// omitted invocation can contribute memory or synchronization effects. The
/// IR retains typed dispatch gaps even after source targets are resolved, so
/// discharge those gaps from the exact targets rather than summary labels.
fn source_closure_has_no_effects(
    provider: &impl ConcurrencyProvider,
    root: &ProcedureHandle,
    request: &mut SemanticRequest<'_>,
) -> Result<bool, ConcurrencyOpenReason> {
    use crate::analyzer::semantic::{SemanticCapability, SemanticGapSubject, SemanticWork};
    let mut pending = vec![root.clone()];
    let mut visited = HashSet::default();
    while let Some(procedure) = pending.pop() {
        if request.cancellation.is_cancelled() {
            return Err(ConcurrencyOpenReason::BudgetExhausted);
        }
        request
            .budget
            .charge(SemanticWork {
                nested_entries: 1,
                ..SemanticWork::default()
            })
            .map_err(|_| ConcurrencyOpenReason::BudgetExhausted)?;
        if !visited.insert(procedure.clone()) {
            continue;
        }
        if provider.complete_summary(&procedure).is_none()
            || !reference_control_is_complete(&procedure)
        {
            return Ok(false);
        }
        let semantics = procedure.semantics();
        request
            .budget
            .charge(SemanticWork {
                nested_entries: semantics.gaps().len() * (1 + semantics.call_sites().len())
                    + semantics
                        .points()
                        .iter()
                        .map(|point| point.events.len())
                        .sum::<usize>()
                    + semantics.call_sites().len(),
                ..SemanticWork::default()
            })
            .map_err(|_| ConcurrencyOpenReason::BudgetExhausted)?;
        if semantics
            .gaps()
            .iter()
            .any(|gap| match (gap.capability, gap.subject) {
                (SemanticCapability::Calls, SemanticGapSubject::CallSite(_)) => false,
                (SemanticCapability::CallableReferences, SemanticGapSubject::Value(value)) => {
                    !semantics
                        .call_sites()
                        .iter()
                        .any(|call| call.callee == value)
                }
                _ => true,
            })
            || semantics
                .points()
                .iter()
                .flat_map(|point| &point.events)
                .any(|event| {
                    !matches!(
                        event.effect,
                        SemanticEffect::Entry
                            | SemanticEffect::NormalExit
                            | SemanticEffect::ExceptionalExit
                            | SemanticEffect::CallableReference { .. }
                            | SemanticEffect::ValueUse { .. }
                            | SemanticEffect::Invoke { .. }
                            | SemanticEffect::CallContinuation { .. }
                            | SemanticEffect::ProcedureReturn { value: None }
                            | SemanticEffect::Gap { .. }
                    )
                })
        {
            return Ok(false);
        }
        for call in semantics.call_sites() {
            if call.invocation_mode != CallInvocationMode::Ordinary
                || call.execution_timing != ExecutionTiming::SameEvaluation
            {
                return Ok(false);
            }
            let Some(targets) = provider.complete_call_targets(&procedure, call.id) else {
                return Ok(false);
            };
            // No source body at an external boundary does not mean no effects.
            if targets.is_empty() {
                return Ok(false);
            }
            request
                .budget
                .charge(SemanticWork {
                    nested_entries: targets.len(),
                    ..SemanticWork::default()
                })
                .map_err(|_| ConcurrencyOpenReason::BudgetExhausted)?;
            pending.extend(targets.iter().cloned());
        }
    }
    Ok(true)
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
        // Intrinsic synchronization operates on channel state. Passing a
        // channel copies its descriptor but preserves that state, which is
        // represented by the backing binding rather than ordinary value/cell
        // equivalence (the same distinction used by maps and slices).
        let identity = classes.canonical_backing_identity(local.clone());
        let storage_family = identity.as_ref().and_then(|identity| {
            (identity.resolved.exact_candidate().is_some()
                && identity.resolved.storage_path.is_empty())
            .then(|| identity.resolved.independent_storage.clone())
            .flatten()
        });
        let (subject, reasons) = if let Some(subject) = identity {
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
            storage_family,
            root_input,
            reasons,
        });
    }
    Ok(resolved)
}

fn point_is_cyclic(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    point: ProgramPointId,
    request: &mut SemanticRequest<'_>,
) -> Result<bool, ConcurrencyOpenReason> {
    charge_concurrency_work(request, 1)?;
    let mut queue = VecDeque::from([point]);
    let mut visited = HashSet::default();
    while let Some(current) = queue.pop_front() {
        charge_concurrency_work(request, 1)?;
        for (_, successor) in
            crate::analyzer::semantic::cfg_algorithms::DenseBidirectionalGraph::successors(
                semantics, current,
            )
        {
            charge_concurrency_work(request, 1)?;
            if successor == point {
                return Ok(true);
            }
            if visited.insert(successor) {
                queue.push_back(successor);
            }
        }
    }
    Ok(false)
}

fn all_recurrences_cross_points(
    procedure: &ProcedureHandle,
    origin: ProgramPointId,
    required: &HashSet<ProgramPointId>,
    request: &mut SemanticRequest<'_>,
) -> Result<bool, ConcurrencyOpenReason> {
    charge_concurrency_work(request, 1)?;
    if required.is_empty() {
        return Ok(false);
    }
    let mut queue = VecDeque::new();
    let mut visited = HashSet::default();
    for (_, edge) in procedure.semantics().successor_edges(origin) {
        charge_concurrency_work(request, 1)?;
        let successor = edge.target_point;
        if required.contains(&successor) {
            continue;
        }
        if successor == origin {
            return Ok(false);
        }
        if visited.insert(successor) {
            queue.push_back(successor);
        }
    }
    while let Some(point) = queue.pop_front() {
        charge_concurrency_work(request, 1)?;
        for (_, edge) in procedure.semantics().successor_edges(point) {
            charge_concurrency_work(request, 1)?;
            let successor = edge.target_point;
            if required.contains(&successor) {
                continue;
            }
            if successor == origin {
                return Ok(false);
            }
            if visited.insert(successor) {
                queue.push_back(successor);
            }
        }
    }
    Ok(true)
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
    tasks: &[Task],
    evidence: AccessComparisonEvidence<'_>,
    accesses: Vec<Access>,
    report: &mut ConcurrentAccessReport,
    request: &mut SemanticRequest<'_>,
) {
    let AccessComparisonEvidence {
        invocations,
        modeled,
        lock_states,
        synchronizations,
        task_local_allocations,
        allocation_origins,
    } = evidence;
    let synchronization_index = match SynchronizationIndex::build(synchronizations, request) {
        Ok(index) => index,
        Err(reason) => {
            report.reasons.push(reason);
            return;
        }
    };
    let mut channel_barriers = ChannelCompletionBarriers {
        tasks,
        invocations,
        synchronizations: synchronization_index,
        sites: HashMap::default(),
        remaining_entries: accesses.len() + synchronizations.len(),
    };
    let mut control = AccessControlCache::default();
    for first_index in 0..accesses.len() {
        for second_index in first_index + 1..accesses.len() {
            if request.cancellation.is_cancelled() {
                report.reasons.push(ConcurrencyOpenReason::BudgetExhausted);
                return;
            }
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
            match tasks_may_parallel(
                tasks,
                invocations,
                first,
                second,
                allocation_origins,
                &mut control,
                request,
            ) {
                Ok(false) => continue,
                Ok(true) => {}
                Err(reason) => {
                    report.reasons.push(reason);
                    return;
                }
            }
            let relation = task_relation(tasks, first.site.task, second.site.task);
            let (ordering, ordering_reasons) = match ordering(
                tasks,
                invocations,
                first,
                second,
                modeled,
                &mut channel_barriers,
                allocation_origins,
                &mut control,
                request,
            ) {
                Ok(ordering) => ordering,
                Err(reason) => {
                    report.reasons.push(reason);
                    return;
                }
            };
            if ordering_reasons.contains(&ConcurrencyOpenReason::BudgetExhausted) {
                report.reasons.push(ConcurrencyOpenReason::BudgetExhausted);
                return;
            }
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
        if request.cancellation.is_cancelled() {
            report.reasons.push(ConcurrencyOpenReason::BudgetExhausted);
            return;
        }
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
        let repetition = match repetition_orders_access(
            tasks,
            invocations,
            access,
            modeled,
            &mut channel_barriers,
            request,
        ) {
            Ok(repetition) => repetition,
            Err(reason) => {
                report.reasons.push(reason);
                return;
            }
        };
        match repetition {
            ConcurrencyAnswer::Proven(true) => continue,
            ConcurrencyAnswer::Open { reasons: open, .. } => {
                if open.contains(&ConcurrencyOpenReason::BudgetExhausted) {
                    report.reasons.push(ConcurrencyOpenReason::BudgetExhausted);
                    return;
                }
                reasons.extend(open);
            }
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
            && access.local_location.as_ref().is_some_and(|root| {
                // A captured cell retains its creator's lifetime. A
                // repeated helper creates a new cell for each activation,
                // even when the access runs in that helper's child task.
                root.task == access.site.task
                    || (matches!(
                        root.procedure
                            .semantics()
                            .memory_location(root.location)
                            .expect("owned capture root")
                            .kind,
                        MemoryLocationKind::LexicalCell { .. }
                    ) && invocations.entries[root.invocation.0 as usize].repetition
                        == task.repetition
                        && invocations.contains(root.invocation, task.entry_invocation))
            }))
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
    request: &mut SemanticRequest<'_>,
) -> Result<ConcurrencyAnswer<bool>, ConcurrencyOpenReason> {
    let task = &tasks[access.site.task.0 as usize];
    let mut reasons = Vec::new();
    if task.repetitions_serialized {
        match completion_orders_access(tasks, invocations, access, request)? {
            ConcurrencyAnswer::Proven(true) => return Ok(ConcurrencyAnswer::Proven(true)),
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
        let channel = synchronized_before_point(
            tasks,
            invocations,
            access,
            after,
            channel_barriers,
            request,
        )?;
        let group = joined_before_point(tasks, invocations, access, after, modeled, request)?;
        if matches!(channel, ConcurrencyAnswer::Proven(true))
            || matches!(group, ConcurrencyAnswer::Proven(true))
        {
            return Ok(ConcurrencyAnswer::Proven(true));
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
    Ok(if reasons.is_empty() {
        ConcurrencyAnswer::Proven(false)
    } else {
        reasons.sort();
        reasons.dedup();
        ConcurrencyAnswer::Open {
            partial: false,
            reasons,
        }
    })
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
    if first.site.task != second.site.task
        && (first.resolved_location.escape() == ConcurrencyEscape::TaskLocal
            || second.resolved_location.escape() == ConcurrencyEscape::TaskLocal)
    {
        return AccessOverlap::Disjoint;
    }
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
    // Loading a reference-valued element reads the container's pointer slot;
    // a field access through that value reaches the pointed-to object's
    // storage. Those locations cannot overlap even when the inline container
    // has no allocation-backed storage family (for example a captured Go
    // array). Value elements stay open because an aggregate element can
    // contain the field being accessed.
    if (first.field_alias_domain.is_some() && indexed_payload_is_separate_reference(second))
        || (second.field_alias_domain.is_some() && indexed_payload_is_separate_reference(first))
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
        _ if first.member.path() == second.member.path()
            && first.member.anchor() == second.member.anchor() =>
        {
            true
        }
        _ => return AccessOverlap::MayAlias(None),
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

fn indexed_payload_is_separate_reference(access: &Access) -> bool {
    if access.index_alias_domain.is_none() {
        return false;
    }
    let Some(location) = access.local_location.as_ref() else {
        return false;
    };
    matches!(
        location
            .procedure
            .semantics()
            .memory_location(location.location)
            .map(|row| row.value_copy),
        Some(MemoryValueCopy::Reference | MemoryValueCopy::BackingStore { .. })
    )
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

#[derive(Default)]
struct AccessControlCache {
    reachability: HashMap<
        (ProcedureHandle, ProgramPointId),
        (
            crate::analyzer::semantic::cfg_algorithms::Reachability<ProgramPointId>,
            crate::analyzer::semantic::cfg_algorithms::Reachability<ProgramPointId>,
        ),
    >,
    cyclic_points: HashMap<ProcedureHandle, HashSet<ProgramPointId>>,
    dominators: HashMap<
        ProcedureHandle,
        crate::analyzer::semantic::cfg_algorithms::Dominators<ProgramPointId>,
    >,
}

impl AccessControlCache {
    /// Return `(other reaches point, point reaches other)` from one cached pair
    /// of complete CFG traversals centered on `point`.
    fn relation(
        &mut self,
        procedure: &ProcedureHandle,
        point: ProgramPointId,
        other: ProgramPointId,
        request: &mut SemanticRequest<'_>,
    ) -> Result<(bool, bool), ConcurrencyOpenReason> {
        use crate::analyzer::semantic::cfg_algorithms::{
            forward_reachability, reverse_reachability,
        };

        charge_concurrency_work(request, 0)?;
        let key = (procedure.clone(), point);
        if !self.reachability.contains_key(&key) {
            let semantics = procedure.semantics();
            let reachability = bounded_cfg_query(request, |cfg_request| {
                reverse_reachability(semantics, point, cfg_request).and_then(|before| {
                    forward_reachability(semantics, point, cfg_request).map(|after| (before, after))
                })
            })?;
            charge_concurrency_work(request, 1 + 2 * semantics.points().len())?;
            self.reachability.insert(key.clone(), reachability);
        }
        let (before, after) = self
            .reachability
            .get(&key)
            .expect("the call reachability entry was inserted");
        Ok((
            before.contains(procedure.semantics(), other),
            after.contains(procedure.semantics(), other),
        ))
    }

    fn is_cyclic(
        &mut self,
        procedure: &ProcedureHandle,
        point: ProgramPointId,
        request: &mut SemanticRequest<'_>,
    ) -> Result<bool, ConcurrencyOpenReason> {
        charge_concurrency_work(request, 0)?;
        if !self.cyclic_points.contains_key(procedure) {
            use crate::analyzer::semantic::cfg_algorithms::loop_regions;

            let regions = bounded_cfg_query(request, |cfg_request| {
                loop_regions(procedure.semantics(), cfg_request)
            })?;
            let mut points = HashSet::default();
            for member in regions
                .regions
                .into_iter()
                .flat_map(|region| region.members)
            {
                charge_concurrency_work(request, 1)?;
                points.insert(member);
            }
            charge_concurrency_work(request, 1)?;
            self.cyclic_points.insert(procedure.clone(), points);
        }
        Ok(self
            .cyclic_points
            .get(procedure)
            .expect("the cyclic-point entry was inserted")
            .contains(&point))
    }

    fn dominates(
        &mut self,
        procedure: &ProcedureHandle,
        candidate: ProgramPointId,
        target: ProgramPointId,
        request: &mut SemanticRequest<'_>,
    ) -> Result<bool, ConcurrencyOpenReason> {
        charge_concurrency_work(request, 0)?;
        if !self.dominators.contains_key(procedure) {
            use crate::analyzer::semantic::cfg_algorithms::dominators;

            let semantics = procedure.semantics();
            let result = bounded_cfg_query(request, |cfg_request| {
                dominators(semantics, semantics.entry_point(), cfg_request)
            })?;
            charge_concurrency_work(request, 1 + semantics.points().len())?;
            self.dominators.insert(procedure.clone(), result);
        }
        Ok(self
            .dominators
            .get(procedure)
            .expect("the dominator entry was inserted")
            .dominates(procedure.semantics(), candidate, target))
    }
}

fn tasks_may_parallel(
    tasks: &[Task],
    invocations: &Invocations,
    first: &Access,
    second: &Access,
    allocation_origins: &HashMap<CanonicalConcurrencyLocation, AllocationOrigin>,
    control: &mut AccessControlCache,
    request: &mut SemanticRequest<'_>,
) -> Result<bool, ConcurrencyOpenReason> {
    let first_task = &tasks[first.site.task.0 as usize];
    let second_task = &tasks[second.site.task.0 as usize];
    let mut parent_child = |parent: &Access,
                            child: &Access,
                            child_task: &Task|
     -> Result<Option<bool>, ConcurrencyOpenReason> {
        if child_task.parent != Some(parent.site.task) {
            return Ok(None);
        }
        let (Some(spawn_invocation), Some(spawn_procedure)) = (
            child_task.spawn_invocation,
            child_task.spawn_procedure.as_ref(),
        ) else {
            return Ok(None);
        };
        let Some(spawn) = child_task
            .spawn_call
            .and_then(|call| spawn_procedure.semantics().call_site(call))
        else {
            return Ok(None);
        };
        let Some((context, parent_point, spawn)) = invocations.common_points_bounded(
            parent.site.invocation,
            parent.site.point,
            spawn_invocation,
            spawn.point,
            request,
        )?
        else {
            return Ok(None);
        };
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
        let (parent_reaches_spawn, spawn_reaches_parent) =
            control.relation(procedure, spawn, parent_point, request)?;
        Ok(Some(
            (invocations.entries[context.invocation.0 as usize]
                .repetition
                .is_some()
                && !fresh_in_common)
                || parent_point == spawn
                || parent_reaches_spawn
                || spawn_reaches_parent,
        ))
    };
    if let Some(answer) = parent_child(first, second, second_task)? {
        return Ok(answer);
    }
    if let Some(answer) = parent_child(second, first, first_task)? {
        return Ok(answer);
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
        let Some((context, first_spawn, second_spawn)) = invocations.common_points_bounded(
            first_invocation,
            first_spawn,
            second_invocation,
            second_spawn,
            request,
        )?
        else {
            return Ok(true);
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
        let (second_reaches_first, first_reaches_second) =
            control.relation(procedure, first_spawn, second_spawn, request)?;
        return Ok((invocations.entries[context.invocation.0 as usize]
            .repetition
            .is_some()
            && !fresh_in_common)
            || first_spawn == second_spawn
            || first_reaches_second
            || second_reaches_first);
    }
    Ok(true)
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
    control: &mut AccessControlCache,
    request: &mut SemanticRequest<'_>,
) -> Result<(ConcurrentOrdering, Vec<ConcurrencyOpenReason>), ConcurrencyOpenReason> {
    if first.site.task == second.site.task {
        let first = repetition_orders_access(
            tasks,
            invocations,
            first,
            modeled,
            channel_barriers,
            request,
        )?;
        let second = repetition_orders_access(
            tasks,
            invocations,
            second,
            modeled,
            channel_barriers,
            request,
        )?;
        if matches!(first, ConcurrencyAnswer::Proven(true))
            && matches!(second, ConcurrencyAnswer::Proven(true))
        {
            return Ok((ConcurrentOrdering::HappensBefore, Vec::new()));
        }
        let mut reasons = Vec::new();
        for answer in [first, second] {
            if let ConcurrencyAnswer::Open { reasons: open, .. } = answer {
                reasons.extend(open);
            }
        }
        return Ok(if reasons.is_empty() {
            (ConcurrentOrdering::Unordered, reasons)
        } else {
            reasons.sort();
            reasons.dedup();
            (ConcurrentOrdering::Open, reasons)
        });
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
    let mut ordered = if common.repetition.is_some()
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
    // A non-repeated task can repeatedly call a helper that leaves children
    // running. A channel local to that helper orders one activation only.
    // Shared memory needs completion before the helper returns to order
    // accesses from different activations represented by these same sites.
    let first_repetition = tasks[first.site.task.0 as usize].repetition;
    let second_repetition = tasks[second.site.task.0 as usize]
        .repetition
        .filter(|repetition| Some(*repetition) != first_repetition);
    for repetition in first_repetition.into_iter().chain(second_repetition) {
        if ordered.0 == ConcurrentOrdering::Open {
            break;
        }
        if request
            .budget
            .charge(crate::analyzer::semantic::SemanticWork {
                nested_entries: 6 * invocations.entries.len(),
                ..crate::analyzer::semantic::SemanticWork::default()
            })
            .is_err()
        {
            return Err(ConcurrencyOpenReason::BudgetExhausted);
        }
        if !invocations.contains(repetition, first.site.invocation)
            || !invocations.contains(repetition, second.site.invocation)
            || (access_is_local_to_invocation(invocations, allocation_origins, first, repetition)
                && access_is_local_to_invocation(
                    invocations,
                    allocation_origins,
                    second,
                    repetition,
                ))
        {
            continue;
        }
        let repeated = &invocations.entries[repetition.0 as usize].context;
        let exit = (
            repetition,
            repeated.procedure.semantics().normal_exit_point(),
        );
        for access in [first, second] {
            if access.site.task == repeated.task {
                continue;
            }
            let join = joined_before_point(tasks, invocations, access, exit, modeled, request)?;
            if matches!(join, ConcurrencyAnswer::Proven(true)) {
                continue;
            }
            let channel = synchronized_before_point(
                tasks,
                invocations,
                access,
                exit,
                channel_barriers,
                request,
            )?;
            if let ConcurrencyAnswer::Open { reasons, .. } = &channel
                && reasons.contains(&ConcurrencyOpenReason::BudgetExhausted)
            {
                return Err(ConcurrencyOpenReason::BudgetExhausted);
            }
            if matches!(channel, ConcurrencyAnswer::Proven(true)) {
                continue;
            }
            ordered.0 = ConcurrentOrdering::Open;
            ordered
                .1
                .push(ConcurrencyOpenReason::AmbiguousSynchronization);
            for answer in [channel, join] {
                if let ConcurrencyAnswer::Open { reasons, .. } = answer {
                    ordered.1.extend(reasons);
                }
            }
        }
        ordered.1.sort();
        ordered.1.dedup();
    }
    let mut recurrence_reasons = Vec::new();
    for (parent, child) in [(first, second), (second, first)] {
        if let Some(recurrences) = access_before_spawn(
            tasks,
            invocations,
            parent,
            child,
            allocation_origins,
            control,
            request,
        )? {
            let barriers = channel_barriers.for_access(child, request)?;
            let joins = join_completion_barriers(tasks, invocations, child, modeled, request)?;
            let mut complete = true;
            for (invocation, point) in recurrences {
                let mut matching = Vec::new();
                for barrier in barriers.iter().chain(&joins) {
                    if barrier.between_recurrences(invocations, invocation, point, request)? {
                        matching.push(barrier);
                    }
                }
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
                    let birth_point = if let Some(birth) =
                        access_base(parent).and_then(|base| allocation_origins.get(base))
                    {
                        invocations
                            .ancestry_points_bounded(birth.invocation, birth.point, request)?
                            .get(&invocation)
                            .copied()
                    } else {
                        None
                    };
                    let procedure = &invocations.entries[invocation.0 as usize].context.procedure;
                    if let Some(birth_point) = birth_point
                        && point_is_cyclic(procedure.semantics(), birth_point, request)?
                        && (birth_point == point
                            || (point_reaches(procedure, point, birth_point, request)?
                                && point_reaches(procedure, birth_point, point, request)?))
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
                return Ok(ordered);
            }
        }
    }
    let forward_join = joined_before_point(
        tasks,
        invocations,
        first,
        (second.site.invocation, second.site.point),
        modeled,
        request,
    )?;
    let reverse_join = joined_before_point(
        tasks,
        invocations,
        second,
        (first.site.invocation, first.site.point),
        modeled,
        request,
    )?;
    if matches!(forward_join, ConcurrencyAnswer::Proven(true))
        || matches!(reverse_join, ConcurrencyAnswer::Proven(true))
    {
        return Ok(ordered);
    }
    let forward = synchronized_before_point(
        tasks,
        invocations,
        first,
        (second.site.invocation, second.site.point),
        channel_barriers,
        request,
    )?;
    let reverse = synchronized_before_point(
        tasks,
        invocations,
        second,
        (first.site.invocation, first.site.point),
        channel_barriers,
        request,
    )?;
    if matches!(forward, ConcurrencyAnswer::Proven(true))
        || matches!(reverse, ConcurrencyAnswer::Proven(true))
    {
        return Ok(ordered);
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
    Ok(if reasons.is_empty() {
        (ConcurrentOrdering::Unordered, reasons)
    } else {
        (ConcurrentOrdering::Open, reasons)
    })
}

/// Points at which an access has completed, as observed by one synchronous
/// invocation. Uncertain identity or completion stays attached to the points.
/// A repeated invocation describes the corresponding activation; comparing
/// shared-memory accesses across activations needs a separate completion proof.
#[derive(Clone, Debug, PartialEq, Eq)]
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
        request: &mut SemanticRequest<'_>,
    ) -> Result<bool, ConcurrencyOpenReason> {
        let task = invocations.entries[self.invocation.0 as usize].context.task;
        let Some((target, point)) =
            observation_in_task_bounded(tasks, invocations, task, after, request)?
        else {
            return Ok(false);
        };
        charge_concurrency_work(request, self.points.len())?;
        invocations.required_points_before(
            self.invocation,
            self.points.clone(),
            target,
            point,
            request,
        )
    }

    fn between_recurrences(
        &self,
        invocations: &Invocations,
        invocation: InvocationId,
        point: ProgramPointId,
        request: &mut SemanticRequest<'_>,
    ) -> Result<bool, ConcurrencyOpenReason> {
        let procedure = &invocations.entries[invocation.0 as usize].context.procedure;
        assert!(point_is_cyclic(procedure.semantics(), point, request)?);
        charge_concurrency_work(request, self.points.len())?;
        let Some(points) = invocations.required_points_in(
            self.invocation,
            self.points.clone(),
            invocation,
            request,
        )?
        else {
            return Ok(false);
        };
        // A lifted call point can itself contain the mandatory wait.
        Ok(points.contains(&point)
            || all_recurrences_cross_points(procedure, point, &points, request)?)
    }
}

fn completed_before_point(
    tasks: &[Task],
    invocations: &Invocations,
    barriers: &[CompletionBarrier],
    after: (InvocationId, ProgramPointId),
    request: &mut SemanticRequest<'_>,
) -> Result<ConcurrencyAnswer<bool>, ConcurrencyOpenReason> {
    let mut reasons = Vec::new();
    for barrier in barriers {
        if barrier.before(tasks, invocations, after, request)? {
            if barrier.reasons.is_empty() {
                return Ok(ConcurrencyAnswer::Proven(true));
            }
            reasons.extend(barrier.reasons.iter().cloned());
        }
    }
    Ok(if reasons.is_empty() {
        ConcurrencyAnswer::Proven(false)
    } else {
        reasons.sort();
        reasons.dedup();
        ConcurrencyAnswer::Open {
            partial: false,
            reasons,
        }
    })
}

fn synchronized_before_point(
    tasks: &[Task],
    invocations: &Invocations,
    before: &Access,
    after: (InvocationId, ProgramPointId),
    channel_barriers: &mut ChannelCompletionBarriers<'_>,
    request: &mut SemanticRequest<'_>,
) -> Result<ConcurrencyAnswer<bool>, ConcurrencyOpenReason> {
    let barriers = channel_barriers.for_access(before, request)?;
    completed_before_point(tasks, invocations, barriers.as_ref(), after, request)
}

struct SynchronizationIndex<'a> {
    // A flat list is required by the extender. It must inspect every send and
    // close across every subject before filtering candidates for one sender.
    send_closes: Vec<&'a IntrinsicSynchronization>,
    send_closes_by_invocation: HashMap<InvocationId, Vec<&'a IntrinsicSynchronization>>,
    send_closes_by_subject:
        HashMap<CanonicalConcurrencyLocation, Vec<&'a IntrinsicSynchronization>>,
    send_closes_unknown: Vec<&'a IntrinsicSynchronization>,

    receives: Vec<&'a IntrinsicSynchronization>,
    receives_by_subject: HashMap<CanonicalConcurrencyLocation, Vec<&'a IntrinsicSynchronization>>,
    receives_unknown: Vec<&'a IntrinsicSynchronization>,
}

/// Lookup over borrowed index entries. The subject-specific form chains the
/// exact subject bucket with the unknown bucket; those buckets are disjoint.
/// A None subject must use the flat list because every known subject remains a
/// possible match. No fresh/root exclusions are applied here; the caller must
/// still call synchronization_subjects_may_match.
enum SynchronizationCandidates<'index, 'event> {
    All(std::iter::Copied<std::slice::Iter<'index, &'event IntrinsicSynchronization>>),
    SameAndUnknown(
        std::iter::Chain<
            std::iter::Copied<std::slice::Iter<'index, &'event IntrinsicSynchronization>>,
            std::iter::Copied<std::slice::Iter<'index, &'event IntrinsicSynchronization>>,
        >,
    ),
}

impl<'index, 'event> Iterator for SynchronizationCandidates<'index, 'event> {
    type Item = &'event IntrinsicSynchronization;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::All(events) => events.next(),
            Self::SameAndUnknown(events) => events.next(),
        }
    }
}

impl<'a> SynchronizationIndex<'a> {
    fn build(
        synchronizations: &'a [IntrinsicSynchronization],
        request: &mut SemanticRequest<'_>,
    ) -> Result<Self, ConcurrencyOpenReason> {
        let mut index = Self {
            send_closes: Vec::new(),
            send_closes_by_invocation: HashMap::default(),
            send_closes_by_subject: HashMap::default(),
            send_closes_unknown: Vec::new(),
            receives: Vec::new(),
            receives_by_subject: HashMap::default(),
            receives_unknown: Vec::new(),
        };

        for event in synchronizations {
            // Charge each examined input and each retained index entry.
            charge_concurrency_work(request, 1)?;
            match event.operation {
                crate::analyzer::semantic::SynchronizationOperation::ChannelSend
                | crate::analyzer::semantic::SynchronizationOperation::ChannelClose => {
                    // Each retained vector reference is charged separately:
                    // flat list, invocation index, and subject/unknown index.
                    charge_concurrency_work(request, 1)?;
                    index.send_closes.push(event);
                    index.retain_send_close_by_invocation(event, request)?;
                    index.retain_send_close_by_subject(event, request)?;
                }
                crate::analyzer::semantic::SynchronizationOperation::ChannelReceive => {
                    // Each receive is retained in its flat list and exactly
                    // one subject/unknown bucket.
                    charge_concurrency_work(request, 1)?;
                    index.receives.push(event);
                    index.retain_receive_by_subject(event, request)?;
                }
            }
        }
        Ok(index)
    }

    fn retain_send_close_by_invocation(
        &mut self,
        event: &'a IntrinsicSynchronization,
        request: &mut SemanticRequest<'_>,
    ) -> Result<(), ConcurrencyOpenReason> {
        // Retained reference in the invocation bucket.
        charge_concurrency_work(request, 1)?;
        if let Some(events) = self.send_closes_by_invocation.get_mut(&event.invocation) {
            events.push(event);
        } else {
            // The InvocationId key is also retained by this index. It is Copy,
            // so this charge accounts for the map entry without cloning data.
            charge_concurrency_work(request, 1)?;
            self.send_closes_by_invocation
                .insert(event.invocation, vec![event]);
        }
        Ok(())
    }

    fn retain_send_close_by_subject(
        &mut self,
        event: &'a IntrinsicSynchronization,
        request: &mut SemanticRequest<'_>,
    ) -> Result<(), ConcurrencyOpenReason> {
        if let Some(subject) = event.subject.as_ref() {
            // Retained reference in the known-subject bucket.
            charge_concurrency_work(request, 1)?;
            if let Some(events) = self.send_closes_by_subject.get_mut(subject) {
                events.push(event);
            } else {
                // Canonical locations are cloned only as HashMap keys.
                charge_concurrency_work(request, 1)?;
                self.send_closes_by_subject
                    .insert(subject.clone(), vec![event]);
            }
        } else {
            // Unknown-subject events form the explicit wildcard bucket.
            charge_concurrency_work(request, 1)?;
            self.send_closes_unknown.push(event);
        }
        Ok(())
    }

    fn retain_receive_by_subject(
        &mut self,
        event: &'a IntrinsicSynchronization,
        request: &mut SemanticRequest<'_>,
    ) -> Result<(), ConcurrencyOpenReason> {
        if let Some(subject) = event.subject.as_ref() {
            // Retained reference in the known-subject bucket.
            charge_concurrency_work(request, 1)?;
            if let Some(events) = self.receives_by_subject.get_mut(subject) {
                events.push(event);
            } else {
                charge_concurrency_work(request, 1)?;
                self.receives_by_subject
                    .insert(subject.clone(), vec![event]);
            }
        } else {
            // Unknown-subject events form the explicit wildcard bucket.
            charge_concurrency_work(request, 1)?;
            self.receives_unknown.push(event);
        }
        Ok(())
    }

    fn all_send_closes(&self) -> &[&'a IntrinsicSynchronization] {
        &self.send_closes
    }

    fn send_closes_for_invocation(
        &self,
        invocation: InvocationId,
    ) -> &[&'a IntrinsicSynchronization] {
        self.send_closes_by_invocation
            .get(&invocation)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    fn possible_send_closes_for(
        &self,
        event: &IntrinsicSynchronization,
    ) -> SynchronizationCandidates<'_, 'a> {
        match event.subject.as_ref() {
            Some(subject) => {
                let exact = self
                    .send_closes_by_subject
                    .get(subject)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]);
                SynchronizationCandidates::SameAndUnknown(
                    exact
                        .iter()
                        .copied()
                        .chain(self.send_closes_unknown.iter().copied()),
                )
            }
            None => SynchronizationCandidates::All(self.send_closes.iter().copied()),
        }
    }

    fn possible_receives_for(
        &self,
        event: &IntrinsicSynchronization,
    ) -> SynchronizationCandidates<'_, 'a> {
        match event.subject.as_ref() {
            Some(subject) => {
                let exact = self
                    .receives_by_subject
                    .get(subject)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]);
                SynchronizationCandidates::SameAndUnknown(
                    exact
                        .iter()
                        .copied()
                        .chain(self.receives_unknown.iter().copied()),
                )
            }
            None => SynchronizationCandidates::All(self.receives.iter().copied()),
        }
    }
}

/// Channel completion depends on the access site and the solve's fixed
/// synchronization inventory, independently of the access paired with it.
/// Invocation IDs keep repeated calls to the same procedure separate. This
/// cache is discarded with the solve, so no source or summary generation can
/// reuse facts from an earlier query.
struct ChannelCompletionBarriers<'a> {
    tasks: &'a [Task],
    invocations: &'a Invocations,
    synchronizations: SynchronizationIndex<'a>,
    sites: HashMap<(InvocationId, ProgramPointId), Vec<CompletionBarrier>>,
    // Count keys, barriers, points and reasons. Retained cache entries stay
    // linear in the already retained input. A miss recomputes the same answer;
    // cache capacity never changes proof or coverage.
    remaining_entries: usize,
}

impl ChannelCompletionBarriers<'_> {
    fn for_access(
        &mut self,
        access: &Access,
        request: &mut SemanticRequest<'_>,
    ) -> Result<std::borrow::Cow<'_, [CompletionBarrier]>, ConcurrencyOpenReason> {
        if request.cancellation.is_cancelled() {
            return Err(ConcurrencyOpenReason::BudgetExhausted);
        }
        match self
            .sites
            .entry((access.site.invocation, access.site.point))
        {
            Entry::Occupied(entry) => Ok(std::borrow::Cow::Borrowed(entry.into_mut())),
            Entry::Vacant(entry) => {
                let mut barriers = channel_completion_barriers(
                    access,
                    self.invocations,
                    &self.synchronizations,
                    request,
                )?;
                extend_channel_completion_barriers(
                    &mut barriers,
                    self.tasks,
                    self.invocations,
                    &self.synchronizations,
                    request,
                )?;
                let weight = 1 + barriers
                    .iter()
                    .map(|barrier| 1 + barrier.points.len() + barrier.reasons.len())
                    .sum::<usize>();
                if weight > self.remaining_entries {
                    return Ok(std::borrow::Cow::Owned(barriers));
                }
                self.remaining_entries -= weight;
                Ok(std::borrow::Cow::Borrowed(entry.insert(barriers)))
            }
        }
    }
}

/// Group all possible receiver records for one sender before forming point
/// sets. Subject-known and subject-unknown buckets are deliberately merged by
/// invocation, so one receiver invocation gets one barrier with all possible
/// receive points and all corresponding reasons.
fn group_channel_receivers_by_invocation<'a>(
    sender: &IntrinsicSynchronization,
    index: &SynchronizationIndex<'a>,
    request: &mut SemanticRequest<'_>,
) -> Result<HashMap<InvocationId, Vec<&'a IntrinsicSynchronization>>, ConcurrencyOpenReason> {
    let mut grouped: HashMap<InvocationId, Vec<&IntrinsicSynchronization>> = HashMap::default();
    for receive in index.possible_receives_for(sender) {
        // Candidate scan includes both known and unknown subject buckets.
        charge_concurrency_work(request, 1)?;
        if !synchronization_subjects_may_match(sender, receive) {
            continue;
        }
        let invocation = receive.invocation;
        // Retain the borrowed receiver reference in its invocation group.
        charge_concurrency_work(request, 1)?;
        if let Some(candidates) = grouped.get_mut(&invocation) {
            candidates.push(receive);
        } else {
            // The InvocationId key is Copy, but remains a retained index entry.
            charge_concurrency_work(request, 1)?;
            grouped.insert(invocation, vec![receive]);
        }
    }
    Ok(grouped)
}

/// A second compatible signal suffices to disprove uniqueness.
fn channel_has_unique_signal(
    sender: &IntrinsicSynchronization,
    index: &SynchronizationIndex<'_>,
    request: &mut SemanticRequest<'_>,
) -> Result<bool, ConcurrencyOpenReason> {
    let mut count = 0usize;
    for candidate in index.possible_send_closes_for(sender) {
        charge_concurrency_work(request, 1)?;
        if synchronization_subjects_may_match(sender, candidate) {
            count += 1;
            if count == 2 {
                return Ok(false);
            }
        }
    }
    Ok(count == 1)
}

/// Find a signal outside the original sender records. Pointer identity is
/// intentional: the index stores borrowed records, and equal field values do
/// not identify the same source event. The original records include every
/// following sender point retained by the invocation seed.
fn channel_has_competing_signal(
    sender: &IntrinsicSynchronization,
    original_senders: &[&IntrinsicSynchronization],
    index: &SynchronizationIndex<'_>,
    request: &mut SemanticRequest<'_>,
) -> Result<bool, ConcurrencyOpenReason> {
    for candidate in index.possible_send_closes_for(sender) {
        charge_concurrency_work(request, 1)?;
        if !synchronization_subjects_may_match(sender, candidate) {
            continue;
        }
        let mut original = false;
        for following in original_senders {
            charge_concurrency_work(request, 1)?;
            if std::ptr::eq(*following, candidate) {
                original = true;
                break;
            }
        }
        if !original {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Charge and retain one initial barrier. Initial barriers are not antichain
/// filtered here; preserving the existing seed output is part of the channel
/// completion contract.
fn push_initial_channel_barrier(
    barriers: &mut Vec<CompletionBarrier>,
    barrier: CompletionBarrier,
    request: &mut SemanticRequest<'_>,
) -> Result<(), ConcurrencyOpenReason> {
    charge_concurrency_work(request, 1 + barrier.points.len() + barrier.reasons.len())?;
    barriers.push(barrier);
    Ok(())
}

/// Retain an extension barrier after charging the actual antichain comparisons
/// and the retained output. Existing barriers suppress a new barrier exactly
/// when they have the same invocation/points and a subset of its reasons.
fn push_extended_channel_barrier(
    barriers: &mut Vec<CompletionBarrier>,
    barrier: CompletionBarrier,
    request: &mut SemanticRequest<'_>,
) -> Result<(), ConcurrencyOpenReason> {
    for existing in barriers.iter() {
        charge_concurrency_work(request, 1)?;
        if existing.invocation != barrier.invocation
            || existing.points.len() != barrier.points.len()
        {
            continue;
        }
        charge_concurrency_work(request, existing.points.len())?;
        if existing.points != barrier.points {
            continue;
        }
        let mut subset = true;
        for reason in &existing.reasons {
            charge_concurrency_work(request, 1)?;
            let mut found = false;
            for candidate in &barrier.reasons {
                charge_concurrency_work(request, 1)?;
                if reason == candidate {
                    found = true;
                    break;
                }
            }
            if !found {
                subset = false;
                break;
            }
        }
        if subset {
            return Ok(());
        }
    }
    charge_concurrency_work(request, 1 + barrier.points.len() + barrier.reasons.len())?;
    barriers.push(barrier);
    Ok(())
}

fn channel_completion_barriers(
    before: &Access,
    invocations: &Invocations,
    index: &SynchronizationIndex<'_>,
    request: &mut SemanticRequest<'_>,
) -> Result<Vec<CompletionBarrier>, ConcurrencyOpenReason> {
    // Seed the access invocation bucket. Keep every sender record for later
    // mandatory point sets and pointer-identity competitor exclusion; only the
    // configuration representative is deduplicated before expensive CFG work.
    let mut senders = Vec::new();
    for sender in index.send_closes_for_invocation(before.site.invocation) {
        charge_concurrency_work(request, 1)?;
        if sender.task != before.site.task || sender.procedure != before.site.procedure {
            continue;
        }
        let reaches = sender.point == before.site.point
            || point_reaches(
                &before.site.procedure,
                before.site.point,
                sender.point,
                request,
            )?;
        if reaches {
            charge_concurrency_work(request, 1)?;
            senders.push(*sender);
        }
    }

    let mut barriers = Vec::new();
    let mut represented_senders = HashSet::default();
    for sender in &senders {
        // Configuration deduplication occurs before matching-send CFG walks.
        // All sender points remain in `senders`, so mandatory sets still see
        // every following point even when this sender is a duplicate config.
        charge_concurrency_work(request, 1)?;
        let configuration = (
            sender.subject.as_ref(),
            sender.point == before.site.point,
            sender.fresh_allocation,
            sender.root_input,
            sender.reasons.as_slice(),
        );
        if !represented_senders.insert(configuration) {
            continue;
        }

        let mut matching_sends = HashSet::default();
        if let Some(subject) = sender.subject.as_ref() {
            for candidate in &senders {
                charge_concurrency_work(request, 1)?;
                if candidate.subject.as_ref() == Some(subject)
                    && candidate.point != before.site.point
                    && matching_sends.insert(candidate.point)
                {
                    charge_concurrency_work(request, 1)?;
                }
            }
        }

        // This is the earlier-iteration mandatory path. It intentionally
        // retains its exact-subject receiver behavior; unknown receivers do
        // not silently become mandatory points here.
        let mut receiver_groups = None;
        if let Some(subject) = sender.subject.as_ref()
            && all_exit_paths_cross_points(
                &before.site.procedure,
                before.site.point,
                &matching_sends,
                request,
            )?
        {
            let mut earlier_iteration_signal = false;
            for point in &matching_sends {
                charge_concurrency_work(request, 1)?;
                if point_reaches(&before.site.procedure, *point, before.site.point, request)? {
                    earlier_iteration_signal = true;
                    break;
                }
            }
            let competing_signal = channel_has_competing_signal(sender, &senders, index, request)?;
            let groups = group_channel_receivers_by_invocation(sender, index, request)?;
            for (invocation, candidates) in &groups {
                let mut points = HashSet::default();
                let mut receive_reasons = Vec::new();
                for receive in candidates {
                    charge_concurrency_work(request, 1)?;
                    if receive.subject.as_ref() != Some(subject) {
                        continue;
                    }
                    if points.insert(receive.point) {
                        charge_concurrency_work(request, 1)?;
                    }
                    charge_concurrency_work(request, receive.reasons.len())?;
                    receive_reasons.extend(receive.reasons.iter().cloned());
                }
                if points.is_empty() {
                    continue;
                }
                charge_concurrency_work(request, sender.reasons.len())?;
                let mut reasons = sender.reasons.clone();
                reasons.extend(receive_reasons);
                if let Some(repetition) =
                    invocations.entries[sender.invocation.0 as usize].repetition
                    && !channel_is_local_to_repetition(
                        sender,
                        repetition,
                        invocations,
                        &[sender.invocation, *invocation],
                        request,
                    )?
                {
                    reasons.push(ConcurrencyOpenReason::AmbiguousSynchronization);
                }
                if competing_signal || earlier_iteration_signal || !sender.fresh_allocation {
                    reasons.push(ConcurrencyOpenReason::AmbiguousSynchronization);
                }
                charge_concurrency_work(request, reasons.len())?;
                reasons.sort();
                reasons.dedup();
                push_initial_channel_barrier(
                    &mut barriers,
                    CompletionBarrier {
                        invocation: *invocation,
                        points,
                        reasons,
                    },
                    request,
                )?;
            }
            receiver_groups = Some(groups);
        }

        // Keep every possible sender point in this mandatory set. This scan is
        // local to the seeded invocation, while the extender below scans the
        // complete flat signal list across all channels.
        let mut possibly_matching_sends = HashSet::default();
        for candidate in &senders {
            charge_concurrency_work(request, 1)?;
            if synchronization_subjects_may_match(sender, candidate)
                && possibly_matching_sends.insert(candidate.point)
            {
                charge_concurrency_work(request, 1)?;
            }
        }
        if !all_exit_paths_cross_points(
            &before.site.procedure,
            before.site.point,
            &possibly_matching_sends,
            request,
        )? {
            continue;
        }

        let groups = match receiver_groups {
            Some(groups) => groups,
            None => group_channel_receivers_by_invocation(sender, index, request)?,
        };
        for (invocation, candidates) in groups {
            let mut points = HashSet::default();
            let mut receive_reasons = Vec::new();
            let mut has_unknown_candidate = false;
            for receive in candidates {
                charge_concurrency_work(request, 1)?;
                if sender.point != before.site.point
                    && (sender.subject.is_none() || receive.subject.is_none())
                {
                    has_unknown_candidate = true;
                }
                if points.insert(receive.point) {
                    charge_concurrency_work(request, 1)?;
                }
                charge_concurrency_work(request, receive.reasons.len())?;
                receive_reasons.extend(receive.reasons.iter().cloned());
            }
            if points.is_empty() || (sender.point != before.site.point && !has_unknown_candidate) {
                continue;
            }
            charge_concurrency_work(request, sender.reasons.len())?;
            let mut reasons = sender.reasons.clone();
            reasons.extend(receive_reasons);
            if reasons.is_empty() {
                reasons.push(ConcurrencyOpenReason::AmbiguousSynchronization);
            }
            charge_concurrency_work(request, reasons.len())?;
            reasons.sort();
            reasons.dedup();
            push_initial_channel_barrier(
                &mut barriers,
                CompletionBarrier {
                    invocation,
                    points,
                    reasons,
                },
                request,
            )?;
        }
    }
    Ok(barriers)
}

/// Compose retained channel observations to a fixed point. A receive in a
/// relay task can establish completion before that task's next signal; the
/// signal is not limited to the task containing the original memory access.
fn extend_channel_completion_barriers(
    barriers: &mut Vec<CompletionBarrier>,
    tasks: &[Task],
    invocations: &Invocations,
    index: &SynchronizationIndex<'_>,
    request: &mut SemanticRequest<'_>,
) -> Result<(), ConcurrencyOpenReason> {
    let mut next = 0;
    while next < barriers.len() {
        charge_concurrency_work(
            request,
            1 + barriers[next].points.len() + barriers[next].reasons.len(),
        )?;
        let before = barriers[next].clone();
        next += 1;

        // This must remain the flat all-channel list. Subject buckets are used
        // only after selecting this sender to find possible receivers.
        for sender in index.all_send_closes() {
            charge_concurrency_work(request, 1)?;
            if request.cancellation.is_cancelled() {
                return Err(ConcurrencyOpenReason::BudgetExhausted);
            }
            if !before.before(
                tasks,
                invocations,
                (sender.invocation, sender.point),
                request,
            )? {
                continue;
            }

            // Only applicable later signals need their control evidence
            // checked. Stop as soon as one ancestor leaves control open.
            let mut complete_control = true;
            'control: for origin in [before.invocation, sender.invocation] {
                let mut current = Some(origin);
                while let Some(invocation) = current {
                    charge_concurrency_work(request, 1)?;
                    let entry = &invocations.entries[invocation.0 as usize];
                    let semantics = entry.context.procedure.semantics();
                    for gap in semantics.gaps() {
                        charge_concurrency_work(request, 1)?;
                        if reference_control_gap_is_open(gap) {
                            complete_control = false;
                            break 'control;
                        }
                    }
                    for edge in semantics.control_edges() {
                        charge_concurrency_work(request, 1)?;
                        if !reference_evidence_is_complete(semantics, edge.evidence) {
                            complete_control = false;
                            break 'control;
                        }
                    }
                    current = entry.caller.map(|(caller, _)| caller);
                }
            }

            charge_concurrency_work(request, before.reasons.len())?;
            let mut base_reasons = before.reasons.clone();
            charge_concurrency_work(request, sender.reasons.len())?;
            base_reasons.extend(sender.reasons.iter().cloned());

            let unique_signal = sender.subject.is_some()
                && sender.fresh_allocation
                && channel_has_unique_signal(sender, index, request)?;
            let mut ambiguous = !unique_signal || !complete_control;
            if !ambiguous {
                for point in &before.points {
                    charge_concurrency_work(request, 1)?;
                    if point_is_cyclic(
                        invocations.entries[before.invocation.0 as usize]
                            .context
                            .procedure
                            .semantics(),
                        *point,
                        request,
                    )? {
                        ambiguous = true;
                        break;
                    }
                }
            }
            if !ambiguous {
                charge_concurrency_work(request, 1)?;
                ambiguous = point_is_cyclic(sender.procedure.semantics(), sender.point, request)?;
            }
            if ambiguous {
                base_reasons.push(ConcurrencyOpenReason::AmbiguousSynchronization);
            }

            let grouped_receivers = group_channel_receivers_by_invocation(sender, index, request)?;
            for (invocation, candidates) in grouped_receivers {
                charge_concurrency_work(request, 1)?;
                charge_concurrency_work(request, base_reasons.len())?;
                let mut reasons = base_reasons.clone();
                let semantics = invocations.entries[invocation.0 as usize]
                    .context
                    .procedure
                    .semantics();
                let contexts = [before.invocation, sender.invocation, invocation];
                let mut local_to_repetitions = true;
                for context in contexts {
                    charge_concurrency_work(request, 1)?;
                    if let Some(repetition) = invocations.entries[context.0 as usize].repetition
                        && !channel_is_local_to_repetition(
                            sender,
                            repetition,
                            invocations,
                            &contexts,
                            request,
                        )?
                    {
                        local_to_repetitions = false;
                        break;
                    }
                }

                let mut points = HashSet::default();
                let mut candidate_ambiguous = false;
                for receive in candidates {
                    charge_concurrency_work(request, 1)?;
                    if points.insert(receive.point) {
                        charge_concurrency_work(request, 1)?;
                    }
                    charge_concurrency_work(request, receive.reasons.len())?;
                    reasons.extend(receive.reasons.iter().cloned());
                    if receive.subject.is_none()
                        || receive.subject != sender.subject
                        || point_is_cyclic(semantics, receive.point, request)?
                    {
                        candidate_ambiguous = true;
                    }
                }
                if candidate_ambiguous || !local_to_repetitions {
                    reasons.push(ConcurrencyOpenReason::AmbiguousSynchronization);
                }
                charge_concurrency_work(request, reasons.len())?;
                reasons.sort();
                reasons.dedup();
                push_extended_channel_barrier(
                    barriers,
                    CompletionBarrier {
                        invocation,
                        points,
                        reasons,
                    },
                    request,
                )?;
            }
        }
    }
    Ok(())
}

/// Observe an access in an ancestor task at the spawn that leads to it.
/// Ordering before that spawn also orders before the descendant access.
fn observation_in_task(
    tasks: &[Task],
    invocations: &Invocations,
    observer: TaskId,
    site: (InvocationId, ProgramPointId),
) -> Option<(InvocationId, ProgramPointId)> {
    observation_in_task_with(tasks, invocations, observer, site, || true)
}

fn observation_in_task_bounded(
    tasks: &[Task],
    invocations: &Invocations,
    observer: TaskId,
    site: (InvocationId, ProgramPointId),
    request: &mut SemanticRequest<'_>,
) -> Result<Option<(InvocationId, ProgramPointId)>, ConcurrencyOpenReason> {
    let mut visit_result = Ok(());
    let point = observation_in_task_with(tasks, invocations, observer, site, || {
        visit_result = charge_concurrency_work(request, 1);
        visit_result.is_ok()
    });
    visit_result?;
    Ok(point)
}

fn observation_in_task_with(
    tasks: &[Task],
    invocations: &Invocations,
    observer: TaskId,
    site: (InvocationId, ProgramPointId),
    mut visit: impl FnMut() -> bool,
) -> Option<(InvocationId, ProgramPointId)> {
    if !visit() {
        return None;
    }
    let (invocation, _) = site;
    let task = invocations.entries[invocation.0 as usize].context.task;
    if observer == task {
        return Some(site);
    }
    let mut descendant = task;
    loop {
        if !visit() {
            return None;
        }
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

/// Allocation ancestry confines this channel family to a repeated activation.
/// It does not serialize accesses to memory shared by different activations.
fn channel_is_local_to_repetition(
    channel: &IntrinsicSynchronization,
    repetition: InvocationId,
    invocations: &Invocations,
    contexts: &[InvocationId],
    request: &mut SemanticRequest<'_>,
) -> Result<bool, ConcurrencyOpenReason> {
    let Some(ConcurrencyStorageFamily::Allocation {
        invocation: birth, ..
    }) = channel.storage_family.as_ref()
    else {
        return Ok(false);
    };
    if !invocations.contains_bounded(repetition, *birth, request)? {
        return Ok(false);
    }
    for context in contexts {
        if !invocations.contains_bounded(*birth, *context, request)? {
            return Ok(false);
        }
    }
    Ok(true)
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
    request: &mut SemanticRequest<'_>,
) -> Result<bool, ConcurrencyOpenReason> {
    charge_concurrency_work(request, 1)?;
    if required.is_empty() {
        return Ok(false);
    }
    let entry = procedure.semantics().entry_point();
    if target == entry || !point_reaches(procedure, entry, target, request)? {
        return Ok(false);
    }
    if required.contains(&entry) {
        return Ok(true);
    }
    let mut queue = VecDeque::from([entry]);
    let mut visited = HashSet::default();
    visited.insert(entry);
    while let Some(point) = queue.pop_front() {
        charge_concurrency_work(request, 1)?;
        for (_, edge) in procedure.semantics().successor_edges(point) {
            charge_concurrency_work(request, 1)?;
            let successor = edge.target_point;
            if required.contains(&successor) {
                continue;
            }
            if successor == target {
                return Ok(false);
            }
            if visited.insert(successor) {
                queue.push_back(successor);
            }
        }
    }
    Ok(true)
}

fn all_exit_paths_cross_points(
    procedure: &ProcedureHandle,
    origin: ProgramPointId,
    required: &HashSet<ProgramPointId>,
    request: &mut SemanticRequest<'_>,
) -> Result<bool, ConcurrencyOpenReason> {
    charge_concurrency_work(request, 1)?;
    if required.is_empty() {
        return Ok(false);
    }
    if required.contains(&origin) {
        return Ok(true);
    }
    let semantics = procedure.semantics();
    let exits = [
        semantics.normal_exit_point(),
        semantics.exceptional_exit_point(),
    ];
    if exits.contains(&origin) {
        return Ok(false);
    }
    let mut queue = VecDeque::from([origin]);
    let mut visited = HashSet::default();
    visited.insert(origin);
    while let Some(point) = queue.pop_front() {
        charge_concurrency_work(request, 1)?;
        for (_, edge) in semantics.successor_edges(point) {
            charge_concurrency_work(request, 1)?;
            let successor = edge.target_point;
            if required.contains(&successor) {
                continue;
            }
            if exits.contains(&successor) {
                return Ok(false);
            }
            if visited.insert(successor) {
                queue.push_back(successor);
            }
        }
    }
    Ok(true)
}

fn access_before_spawn(
    tasks: &[Task],
    invocations: &Invocations,
    parent: &Access,
    child: &Access,
    allocation_origins: &HashMap<CanonicalConcurrencyLocation, AllocationOrigin>,
    control: &mut AccessControlCache,
    request: &mut SemanticRequest<'_>,
) -> Result<Option<Vec<(InvocationId, ProgramPointId)>>, ConcurrencyOpenReason> {
    let mut descendant = child.site.task;
    loop {
        charge_concurrency_work(request, 1)?;
        let task = &tasks[descendant.0 as usize];
        let Some(owner) = task.parent else {
            return Ok(None);
        };
        if owner == parent.site.task {
            let (Some(spawn_call), Some(spawn_procedure), Some(spawn_invocation)) = (
                task.spawn_call,
                task.spawn_procedure.as_ref(),
                task.spawn_invocation,
            ) else {
                return Ok(None);
            };
            let spawn = spawn_procedure
                .semantics()
                .call_site(spawn_call)
                .expect("task spawn call belongs to its procedure")
                .point;
            let Some((context, parent_point, spawn)) = invocations.common_points_bounded(
                parent.site.invocation,
                parent.site.point,
                spawn_invocation,
                spawn,
                request,
            )?
            else {
                return Ok(None);
            };
            let procedure = &context.procedure;
            let (parent_reaches_spawn, spawn_reaches_parent) =
                control.relation(procedure, spawn, parent_point, request)?;
            // Ordering an observed access does not require that access to
            // execute on every branch. An acyclic conditional store can
            // precede a spawn whenever it occurs, without dominating it.
            // Cyclic precedence still needs the existing dominance and
            // recurrence-barrier proof below.
            if parent_point == spawn
                || !((reference_control_is_complete(procedure)
                    && parent_reaches_spawn
                    && !spawn_reaches_parent)
                    || control.dominates(procedure, parent_point, spawn, request)?)
            {
                return Ok(None);
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
                return Ok(None);
            }
            let parent_points = invocations.ancestry_points_bounded(
                parent.site.invocation,
                parent.site.point,
                request,
            )?;
            let spawn_points = invocations.ancestry_points_bounded(
                spawn_invocation,
                spawn_procedure
                    .semantics()
                    .call_site(spawn_call)
                    .expect("spawn belongs to its caller")
                    .point,
                request,
            )?;
            let mut recurrences = Vec::new();
            for (invocation, parent_point) in parent_points {
                let Some(spawn_point) = spawn_points.get(&invocation) else {
                    continue;
                };
                let procedure = &invocations.entries[invocation.0 as usize].context.procedure;
                let spawn_reaches_parent = if parent_point == *spawn_point {
                    true
                } else {
                    control
                        .relation(procedure, *spawn_point, parent_point, request)?
                        .1
                };
                if control.is_cyclic(procedure, parent_point, request)? && spawn_reaches_parent {
                    recurrences.push((invocation, parent_point));
                }
            }
            return Ok(Some(recurrences));
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
    request: &mut SemanticRequest<'_>,
) -> Result<ConcurrencyAnswer<bool>, ConcurrencyOpenReason> {
    let Some((completion, completion_point)) = tasks[access.site.task.0 as usize].completion else {
        return Ok(ConcurrencyAnswer::Proven(true));
    };
    if let Some((context, access_point, completion_point)) = invocations.common_points_bounded(
        access.site.invocation,
        access.site.point,
        completion,
        completion_point,
        request,
    )? && access_point != completion_point
    {
        let procedure = &context.procedure;
        if point_dominates(procedure, access_point, completion_point, request)?
            && !point_reaches(procedure, completion_point, access_point, request)?
        {
            return Ok(ConcurrencyAnswer::Proven(true));
        }
        if point_dominates(procedure, completion_point, access_point, request)?
            && !point_reaches(procedure, access_point, completion_point, request)?
        {
            return Ok(ConcurrencyAnswer::Proven(false));
        }
    }
    Ok(ConcurrencyAnswer::Open {
        partial: false,
        reasons: vec![ConcurrencyOpenReason::AmbiguousSynchronization],
    })
}

fn joined_before_point(
    tasks: &[Task],
    invocations: &Invocations,
    child: &Access,
    after: (InvocationId, ProgramPointId),
    modeled: &HashMap<ContextKey, Vec<(ProgramPointId, ResolvedConcurrencyEffect)>>,
    request: &mut SemanticRequest<'_>,
) -> Result<ConcurrencyAnswer<bool>, ConcurrencyOpenReason> {
    let barriers = join_completion_barriers(tasks, invocations, child, modeled, request)?;
    completed_before_point(tasks, invocations, &barriers, after, request)
}

fn join_completion_barriers(
    tasks: &[Task],
    invocations: &Invocations,
    child: &Access,
    modeled: &HashMap<ContextKey, Vec<(ProgramPointId, ResolvedConcurrencyEffect)>>,
    request: &mut SemanticRequest<'_>,
) -> Result<Vec<CompletionBarrier>, ConcurrencyOpenReason> {
    let task = &tasks[child.site.task.0 as usize];
    let (Some(parent), Some(task_group)) = (task.parent, task.group.as_ref()) else {
        return Ok(Vec::new());
    };
    let completion_reasons = match completion_orders_access(tasks, invocations, child, request)? {
        ConcurrencyAnswer::Proven(false) => return Ok(Vec::new()),
        ConcurrencyAnswer::Proven(true) => Vec::new(),
        ConcurrencyAnswer::Open { reasons, .. } => reasons,
    };
    let mut barriers = Vec::new();
    for (context, effects) in modeled {
        charge_concurrency_work(request, 1)?;
        if context.task != parent {
            continue;
        }
        charge_concurrency_work(request, effects.len())?;
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
    Ok(barriers)
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

pub(crate) fn point_dominates(
    procedure: &ProcedureHandle,
    candidate: ProgramPointId,
    target: ProgramPointId,
    request: &mut SemanticRequest<'_>,
) -> Result<bool, ConcurrencyOpenReason> {
    use crate::analyzer::semantic::cfg_algorithms::dominators;
    bounded_cfg_query(request, |request| {
        dominators(
            procedure.semantics(),
            procedure.semantics().entry_point(),
            request,
        )
        .map(|dominators| dominators.dominates(procedure.semantics(), candidate, target))
    })
}

/// CFG algorithms use the solve's cancellation token and debit their actual
/// visits, including visits performed before an exhausted or cancelled query.
fn bounded_cfg_query<T>(
    request: &mut SemanticRequest<'_>,
    query: impl FnOnce(
        &mut crate::analyzer::semantic::cfg_algorithms::CfgAlgorithmRequest<'_>,
    ) -> Result<
        T,
        crate::analyzer::semantic::cfg_algorithms::CfgAlgorithmError<ProgramPointId>,
    >,
) -> Result<T, ConcurrencyOpenReason> {
    use crate::analyzer::semantic::SemanticWork;
    use crate::analyzer::semantic::cfg_algorithms::{
        CfgAlgorithmBudget, CfgAlgorithmError, CfgAlgorithmRequest,
    };
    if request.cancellation.is_cancelled() {
        return Err(ConcurrencyOpenReason::BudgetExhausted);
    }
    let mut budget = CfgAlgorithmBudget::uniform(request.budget.remaining().nested_entries / 2);
    let result = query(&mut CfgAlgorithmRequest::new(
        &mut budget,
        request.cancellation,
    ));
    let used = budget.used();
    request
        .budget
        .charge(SemanticWork {
            nested_entries: used.node_visits + used.edge_visits,
            ..SemanticWork::default()
        })
        .expect("CFG visit limits fit the remaining semantic budget");
    if request.cancellation.is_cancelled() {
        return Err(ConcurrencyOpenReason::BudgetExhausted);
    }
    match result {
        Ok(value) => Ok(value),
        Err(CfgAlgorithmError::InvalidNode(node)) => {
            panic!("validated concurrency CFG contains invalid node {node:?}")
        }
        Err(CfgAlgorithmError::Cancelled { .. } | CfgAlgorithmError::ExceededBudget(_)) => {
            Err(ConcurrencyOpenReason::BudgetExhausted)
        }
    }
}

/// Reusable ordering proof for one call in an immutable procedure artifact.
fn points_strictly_before_call(
    procedure: &ProcedureHandle,
    call: ProgramPointId,
    request: &mut SemanticRequest<'_>,
) -> Result<HashSet<ProgramPointId>, ConcurrencyOpenReason> {
    use crate::analyzer::semantic::cfg_algorithms::{forward_reachability, reverse_reachability};
    use crate::analyzer::semantic::{SemanticGapDischarge, SemanticWork, SourceMappingKind};

    if request.cancellation.is_cancelled() {
        return Err(ConcurrencyOpenReason::BudgetExhausted);
    }
    let semantics = procedure.semantics();
    request
        .budget
        .charge(SemanticWork {
            nested_entries: 2 * semantics.gaps().len() + semantics.control_edges().len(),
            ..SemanticWork::default()
        })
        .map_err(|_| ConcurrencyOpenReason::BudgetExhausted)?;
    if semantics.gaps().iter().any(|gap| {
        gap.discharge != SemanticGapDischarge::RetainedEvaluationOrder
            && reference_control_gap_is_open(gap)
    }) || semantics
        .control_edges()
        .iter()
        .any(|edge| !reference_evidence_is_complete(semantics, edge.evidence))
    {
        return Ok(HashSet::default());
    }
    let reorder_regions = semantics
        .gaps()
        .iter()
        .filter(|gap| gap.discharge == SemanticGapDischarge::RetainedEvaluationOrder)
        .collect::<Vec<_>>();
    // Reordering is confined to the producer's expression region. This
    // comparison is independent of the evaluation order within that region
    // only when both endpoints are outside it. Keep the global control check
    // conservative for heap-state consumers, which ask different questions.
    let outside_regions = |point| {
        reorder_regions.iter().all(|gap| {
            if request.cancellation.is_cancelled() || point == gap.point {
                return false;
            }
            let Some(region) = semantics.source_mapping(gap.source) else {
                return false;
            };
            let Some(point) = semantics.point(point) else {
                return false;
            };
            // Events can carry more precise mappings than their enclosing
            // point. Check both so a narrow point mapping cannot hide an
            // access inside an unordered expression.
            std::iter::once(point.source)
                .chain(point.events.iter().map(|event| event.source))
                .all(|source| {
                    if request.cancellation.is_cancelled() {
                        return false;
                    }
                    let Some(endpoint) = semantics.source_mapping(source) else {
                        return false;
                    };
                    if region.kind != SourceMappingKind::Exact
                        || endpoint.kind != SourceMappingKind::Exact
                        || region.locator.path() != endpoint.locator.path()
                        || region.locator.mount() != endpoint.locator.mount()
                    {
                        return false;
                    }
                    let region = region.locator.anchor().span();
                    let endpoint = endpoint.locator.anchor().span();
                    region.start_byte() < region.end_byte()
                        && endpoint.start_byte() < endpoint.end_byte()
                        && (endpoint.end_byte() <= region.start_byte()
                            || region.end_byte() <= endpoint.start_byte())
                })
        })
    };
    request
        .budget
        .charge(SemanticWork {
            nested_entries: reorder_regions.len()
                * (1 + semantics
                    .point(call)
                    .expect("validated call point exists")
                    .events
                    .len()),
            ..SemanticWork::default()
        })
        .map_err(|_| ConcurrencyOpenReason::BudgetExhausted)?;
    let call_outside_regions = outside_regions(call);
    if request.cancellation.is_cancelled() {
        return Err(ConcurrencyOpenReason::BudgetExhausted);
    }
    if !call_outside_regions {
        return Ok(HashSet::default());
    }
    // Account for two dense membership allocations and the final set scan.
    request
        .budget
        .charge(SemanticWork {
            nested_entries: 3 * semantics.points().len(),
            ..SemanticWork::default()
        })
        .map_err(|_| ConcurrencyOpenReason::BudgetExhausted)?;
    let result = bounded_cfg_query(request, |cfg_request| {
        reverse_reachability(semantics, call, cfg_request).and_then(|before| {
            forward_reachability(semantics, call, cfg_request).map(|after| (before, after))
        })
    });
    match result {
        Ok((before, after)) => {
            let mut points = HashSet::default();
            for point in before.iter(semantics) {
                if point == call || after.contains(semantics, point) {
                    continue;
                }
                if request.cancellation.is_cancelled() {
                    return Err(ConcurrencyOpenReason::BudgetExhausted);
                }
                request
                    .budget
                    .charge(SemanticWork {
                        nested_entries: reorder_regions.len()
                            * (1 + semantics
                                .point(point)
                                .expect("validated CFG point exists")
                                .events
                                .len()),
                        ..SemanticWork::default()
                    })
                    .map_err(|_| ConcurrencyOpenReason::BudgetExhausted)?;
                if outside_regions(point) {
                    points.insert(point);
                }
            }
            if request.cancellation.is_cancelled() {
                return Err(ConcurrencyOpenReason::BudgetExhausted);
            }
            Ok(points)
        }
        Err(reason) => Err(reason),
    }
}

fn point_reaches(
    procedure: &ProcedureHandle,
    origin: ProgramPointId,
    target: ProgramPointId,
    request: &mut SemanticRequest<'_>,
) -> Result<bool, ConcurrencyOpenReason> {
    charge_concurrency_work(request, 1)?;
    let mut queue = VecDeque::from([origin]);
    let mut visited = HashSet::default();
    visited.insert(origin);
    while let Some(point) = queue.pop_front() {
        charge_concurrency_work(request, 1)?;
        for edge in procedure.semantics().successor_edges(point) {
            charge_concurrency_work(request, 1)?;
            let successor = edge.1.target_point;
            if successor == target {
                return Ok(true);
            }
            if visited.insert(successor) {
                queue.push_back(successor);
            }
        }
    }
    Ok(false)
}

fn charge_concurrency_work(
    request: &mut SemanticRequest<'_>,
    entries: usize,
) -> Result<(), ConcurrencyOpenReason> {
    if request.cancellation.is_cancelled() {
        return Err(ConcurrencyOpenReason::BudgetExhausted);
    }
    request
        .budget
        .charge(crate::analyzer::semantic::SemanticWork {
            nested_entries: entries,
            ..crate::analyzer::semantic::SemanticWork::default()
        })
        .map_err(|_| ConcurrencyOpenReason::BudgetExhausted)
}

#[cfg(test)]
mod tests {
    #[test]
    fn dominance_uses_the_solve_budget_and_cancellation() {
        let fixture = Fixture::new("package sample\nfunc root() { n := 1; _ = n }\n");
        let artifact = fixture.artifact();
        let procedure = artifact
            .procedure_handle(artifact.procedures()[0].id())
            .unwrap();
        let entry = procedure.semantics().entry_point();
        let exit = procedure.semantics().normal_exit_point();
        let cancellation = crate::cancellation::CancellationToken::default();
        let mut budget = SemanticBudget::default();
        assert!(
            point_dominates(
                &procedure,
                entry,
                exit,
                &mut SemanticRequest::new(&mut budget, &cancellation)
            )
            .unwrap()
        );
        assert!(
            !point_dominates(
                &procedure,
                exit,
                entry,
                &mut SemanticRequest::new(&mut budget, &cancellation)
            )
            .unwrap()
        );
        assert!(
            budget.used().nested_entries > 0,
            "dominance must debit the solve ledger"
        );

        let mut tiny = SemanticBudget::uniform(1).unwrap();
        assert_eq!(
            point_dominates(
                &procedure,
                entry,
                exit,
                &mut SemanticRequest::new(&mut tiny, &cancellation)
            ),
            Err(ConcurrencyOpenReason::BudgetExhausted)
        );

        let cancelled = crate::cancellation::CancellationToken::cancel_after_checks_for_test(1);
        let mut budget = SemanticBudget::default();
        assert_eq!(
            point_dominates(
                &procedure,
                entry,
                exit,
                &mut SemanticRequest::new(&mut budget, &cancelled)
            ),
            Err(ConcurrencyOpenReason::BudgetExhausted)
        );
    }

    #[test]
    fn channel_completion_barriers_are_budget_bounded_and_cancellable() {
        use crate::analyzer::semantic::SynchronizationOperation;

        let fixture = Fixture::new(
            r#"package sample

    func root() {
        a := make(chan struct{})
        b := make(chan struct{})
        close(a)
        <-a
        close(b)
        <-b
    }
    "#,
        );
        let artifact = fixture.artifact();
        let root = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure.kind() == ProcedureKind::Function && procedure.lexical_parent().is_none()
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("fixture root procedure");

        let synchronization_events = root
            .semantics()
            .points()
            .iter()
            .flat_map(|point| {
                point.events.iter().filter_map(move |event| {
                    let SemanticEffect::Synchronization { operation, .. } = event.effect else {
                        return None;
                    };
                    Some((point.id, operation))
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(synchronization_events.len(), 4);
        assert!(matches!(
            synchronization_events[0].1,
            SynchronizationOperation::ChannelClose
        ));
        assert!(matches!(
            synchronization_events[1].1,
            SynchronizationOperation::ChannelReceive
        ));
        assert!(matches!(
            synchronization_events[2].1,
            SynchronizationOperation::ChannelClose
        ));
        assert!(matches!(
            synchronization_events[3].1,
            SynchronizationOperation::ChannelReceive
        ));

        let cancellation = crate::cancellation::CancellationToken::default();
        let mut generous_budget = SemanticBudget::new(SemanticWork::default_limits()).unwrap();
        let mut invocations = Invocations::default();
        let context = invocations
            .push(
                TaskId(0),
                root.clone(),
                None,
                &mut SemanticRequest::new(&mut generous_budget, &cancellation),
            )
            .unwrap();
        let tasks = vec![Task {
            parent: None,
            entry_procedure: Some(root.clone()),
            entry_invocation: context.invocation,
            spawn_procedure: None,
            spawn_invocation: None,
            spawn_call: None,
            group: None,
            completion: None,
            repetition: None,
            repetitions_serialized: false,
        }];
        let channel_a = CanonicalConcurrencyLocation::new("fixture:channel:a", "channel");
        let channel_b = CanonicalConcurrencyLocation::new("fixture:channel:b", "channel");
        let make_sync = |index: usize, subject, fresh_allocation| IntrinsicSynchronization {
            task: context.task,
            invocation: context.invocation,
            procedure: root.clone(),
            point: synchronization_events[index].0,
            operation: synchronization_events[index].1,
            subject: Some(subject),
            fresh_allocation,
            storage_family: None,
            root_input: false,
            reasons: Vec::new(),
        };
        let synchronizations = vec![
            make_sync(0, channel_a.clone(), true),
            make_sync(1, channel_a, false),
            make_sync(2, channel_b.clone(), true),
            make_sync(3, channel_b, false),
        ];
        let index = SynchronizationIndex::build(
            &synchronizations,
            &mut SemanticRequest::new(&mut generous_budget, &cancellation),
        )
        .expect("generous budget indexes the synchronization inventory");
        // Differential oracle: indexed candidates must preserve the complete
        // inventory's matching relation, including unknown and root inputs.
        let mut inventory = synchronizations.clone();
        for event in &synchronizations {
            let mut unknown = event.clone();
            unknown.subject = None;
            inventory.push(unknown);
            let mut root_input = event.clone();
            root_input.subject = None;
            root_input.root_input = true;
            root_input.fresh_allocation = false;
            inventory.push(root_input);
        }
        let oracle_index = SynchronizationIndex::build(
            &inventory,
            &mut SemanticRequest::new(&mut generous_budget, &cancellation),
        )
        .unwrap();
        for event in &inventory {
            let matches = |candidate: &&IntrinsicSynchronization| {
                synchronization_subjects_may_match(event, candidate)
            };
            let indexed_receives = oracle_index
                .possible_receives_for(event)
                .filter(matches)
                .map(std::ptr::from_ref)
                .collect::<HashSet<_>>();
            let expected_receives = inventory
                .iter()
                .filter(|candidate| candidate.operation == SynchronizationOperation::ChannelReceive)
                .filter(matches)
                .map(std::ptr::from_ref)
                .collect::<HashSet<_>>();
            assert_eq!(indexed_receives, expected_receives);
            let indexed_signals = oracle_index
                .possible_send_closes_for(event)
                .filter(matches)
                .map(std::ptr::from_ref)
                .collect::<HashSet<_>>();
            let expected_signals = inventory
                .iter()
                .filter(|candidate| candidate.operation != SynchronizationOperation::ChannelReceive)
                .filter(matches)
                .map(std::ptr::from_ref)
                .collect::<HashSet<_>>();
            assert_eq!(indexed_signals, expected_signals);
        }
        let receive_a = synchronization_events[1].0;
        let receive_b = synchronization_events[3].0;
        let initial_barriers = || {
            vec![CompletionBarrier {
                invocation: context.invocation,
                points: [receive_a].into_iter().collect(),
                reasons: Vec::new(),
            }]
        };

        let mut generous_barriers = initial_barriers();
        extend_channel_completion_barriers(
            &mut generous_barriers,
            &tasks,
            &invocations,
            &index,
            &mut SemanticRequest::new(&mut generous_budget, &cancellation),
        )
        .expect("generous budget reaches the transitive receiver barrier");
        assert!(
            generous_barriers.iter().any(|barrier| {
                barrier.invocation == context.invocation && barrier.points.contains(&receive_b)
            }),
            "transitive receiver barrier missing: {generous_barriers:#?}"
        );

        let mut tiny_budget = SemanticBudget::uniform(1).unwrap();
        let mut tiny_barriers = initial_barriers();
        assert_eq!(
            extend_channel_completion_barriers(
                &mut tiny_barriers,
                &tasks,
                &invocations,
                &index,
                &mut SemanticRequest::new(&mut tiny_budget, &cancellation),
            ),
            Err(ConcurrencyOpenReason::BudgetExhausted)
        );
        assert_eq!(
            tiny_barriers.len(),
            1,
            "failed charge must not grow worklist"
        );

        let cancelled = crate::cancellation::CancellationToken::default();
        cancelled.cancel();
        let mut cancelled_budget = SemanticBudget::new(SemanticWork::default_limits()).unwrap();
        let mut cancelled_barriers = initial_barriers();
        assert_eq!(
            extend_channel_completion_barriers(
                &mut cancelled_barriers,
                &tasks,
                &invocations,
                &index,
                &mut SemanticRequest::new(&mut cancelled_budget, &cancelled),
            ),
            Err(ConcurrencyOpenReason::BudgetExhausted)
        );
        assert_eq!(
            cancelled_barriers.len(),
            1,
            "cancellation must stop before growing worklist"
        );
    }
    struct AtomicReplayProvider {
        modeled_procedure: crate::analyzer::semantic::SemanticLocator,
        unknown_call: CallSiteId,
        unknown_effect_reason: ConcurrencyOpenReason,
        atomic_call: CallSiteId,
        ordinary_procedure: crate::analyzer::semantic::SemanticLocator,
        ordinary_point: ProgramPointId,
        ordinary_location: MemoryLocationId,
        shared: CanonicalConcurrencyLocation,
        atomic_identity: Option<CanonicalConcurrencyLocation>,
    }

    impl AtomicReplayProvider {
        fn is_callback_call(&self, call: &CallSiteHandle, id: CallSiteId) -> bool {
            call.procedure().semantics().locator() == &self.modeled_procedure && call.id() == id
        }
    }

    impl ConcurrencyProvider for AtomicReplayProvider {
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
            if self.is_callback_call(call, self.atomic_call) {
                return Ok(ConcurrencyAnswer::Proven(Vec::new()));
            }
            if self.is_callback_call(call, self.unknown_call) {
                return Ok(ConcurrencyAnswer::Open {
                    partial: Vec::new(),
                    reasons: vec![ConcurrencyOpenReason::UnresolvedTarget],
                });
            }
            LocalProvider.resolve_call(call, request)
        }

        fn modeled_effects(
            &self,
            call: &CallSiteHandle,
            _targets: &ConcurrencyAnswer<Vec<ProcedureHandle>>,
            _request: &mut SemanticRequest<'_>,
        ) -> Result<ConcurrencyAnswer<Vec<ResolvedConcurrencyEffect>>, SemanticProviderError>
        {
            if self.is_callback_call(call, self.atomic_call) {
                let callee = call
                    .procedure()
                    .semantics()
                    .call_site(call.id())
                    .expect("modeled callback call belongs to its procedure")
                    .callee;
                return Ok(ConcurrencyAnswer::Proven(vec![
                    ResolvedConcurrencyEffect::Atomic {
                        location: ResolvedConcurrencySubject {
                            value: callee,
                            canonical: self.atomic_identity.clone(),
                            reasons: Vec::new(),
                            identity: ConcurrencySubjectIdentity::Value,
                        },
                        operation: ConcurrencyAtomicOperation::Store,
                    },
                ]));
            }
            if self.is_callback_call(call, self.unknown_call) {
                return Ok(ConcurrencyAnswer::Open {
                    partial: Vec::new(),
                    reasons: vec![self.unknown_effect_reason.clone()],
                });
            }
            Ok(ConcurrencyAnswer::Proven(Vec::new()))
        }

        fn canonical_location(
            &self,
            procedure: &ProcedureHandle,
            point: ProgramPointId,
            location: MemoryLocationId,
            request: &mut SemanticRequest<'_>,
        ) -> Result<ConcurrencyAnswer<Option<CanonicalConcurrencyLocation>>, SemanticProviderError>
        {
            // This is the synthetic provider contract: the one selected static
            // store is the object named by the modeled atomic Store above.
            if procedure.semantics().locator() == &self.ordinary_procedure
                && point == self.ordinary_point
                && location == self.ordinary_location
            {
                return Ok(ConcurrencyAnswer::Proven(Some(self.shared.clone())));
            }
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

    #[test]
    fn unpublished_storage_requires_retained_method_value_receivers() {
        let fixture = Fixture::new(
            r#"package sample
 type cell struct { n int }
 func (p *cell) write() { p.n = 1 }
 func root() { p := &cell{}; publish(p.write) }
"#,
        );
        let artifact = fixture.artifact();
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure.kind() == ProcedureKind::Function && procedure.lexical_parent().is_none()
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("root function");
        let cancellation = crate::cancellation::CancellationToken::default();
        let mut budget = SemanticBudget::new(SemanticWork::default_limits()).unwrap();
        let mut invocations = Invocations::default();
        invocations
            .push(
                TaskId(0),
                procedure,
                None,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .unwrap();
        assert!(
            publication::private_storage_in_slice(
                &invocations,
                &HashSet::default(),
                &mut SemanticRequest::new(&mut budget, &cancellation)
            )
            .unwrap()
            .is_none(),
            "missing method-value receiver transport must not certify private storage"
        );
    }

    #[test]
    fn replayed_unknown_effects_open_modeled_atomic_store_against_sibling_write() {
        let fixture = Fixture::new(
            r#"package sample

var shared int

func root() {
    go func() {
        unknownEffects()
        modeledStore()
    }()
    go func() {
        shared = 1
    }()
}
"#,
        );
        let artifact = fixture.artifact();
        let modeled_procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure.lexical_parent().is_some() && procedure.call_sites().len() == 2
            })
            .expect("the callback has the unresolved call followed by the modeled atomic call");
        let [unknown, atomic] = modeled_procedure.call_sites() else {
            panic!("callback call contract changed");
        };
        let ordinary = artifact
            .procedures()
            .iter()
            .filter(|procedure| procedure.lexical_parent().is_some())
            .find_map(|procedure| {
                procedure.points().iter().find_map(|point| {
                    point.events.iter().find_map(|event| {
                        let SemanticEffect::MemoryStore { location, .. } = event.effect else {
                            return None;
                        };
                        matches!(
                            procedure
                                .memory_location(location)
                                .expect("ordinary write location exists")
                                .kind,
                            MemoryLocationKind::Static { .. }
                        )
                        .then_some((
                            procedure.locator().clone(),
                            point.id,
                            location,
                        ))
                    })
                })
            })
            .expect("sibling callback has one static shared write");
        let shared = CanonicalConcurrencyLocation::new("synthetic:shared", "object");
        for reason in [
            ConcurrencyOpenReason::UnresolvedTarget,
            ConcurrencyOpenReason::UnknownLocation,
            ConcurrencyOpenReason::UnmodeledMemory("call_effects".into()),
        ] {
            for atomic_identity in [Some(shared.clone()), None] {
                let provider = AtomicReplayProvider {
                    modeled_procedure: modeled_procedure.locator().clone(),
                    unknown_call: unknown.id,
                    unknown_effect_reason: reason.clone(),
                    atomic_call: atomic.id,
                    ordinary_procedure: ordinary.0.clone(),
                    ordinary_point: ordinary.1,
                    ordinary_location: ordinary.2,
                    shared: shared.clone(),
                    atomic_identity: atomic_identity.clone(),
                };
                let root = artifact
                    .procedures()
                    .iter()
                    .find(|procedure| {
                        procedure.kind() == ProcedureKind::Function
                            && procedure.lexical_parent().is_none()
                    })
                    .and_then(|procedure| artifact.procedure_handle(procedure.id()))
                    .expect("fixture root procedure");
                let cancellation = crate::cancellation::CancellationToken::default();
                let mut budget = SemanticBudget::new(SemanticWork::default_limits()).unwrap();
                let report = concurrent_access_conflicts(
                    &provider,
                    &root,
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .unwrap();
                if atomic_identity.is_none() {
                    assert!(
                        report
                            .reasons
                            .contains(&ConcurrencyOpenReason::UnknownLocation),
                        "an unrepresented modeled memory access must not disappear: {report:#?}"
                    );
                    continue;
                }
                let atomic_point = atomic.point;
                let is_atomic = |site: &ConcurrentAccessSite| {
                    site.procedure.semantics().locator() == &provider.modeled_procedure
                        && site.point == atomic_point
                };
                let is_ordinary = |site: &ConcurrentAccessSite| {
                    site.procedure.semantics().locator() == &provider.ordinary_procedure
                        && site.point == provider.ordinary_point
                };
                let conflict = report
                    .conflicts
                    .iter()
                    .find(|conflict| {
                        conflict.location == shared
                            && ((is_atomic(&conflict.first) && is_ordinary(&conflict.second))
                                || (is_ordinary(&conflict.first) && is_atomic(&conflict.second)))
                    })
                    .expect("modeled atomic Store must remain compared with sibling static write");
                assert_eq!(conflict.task_relation, ConcurrentTaskRelation::Siblings);
                assert_eq!(conflict.ordering, ConcurrentOrdering::Unordered);
                assert_eq!(conflict.protection, ConcurrentProtection::Unprotected);
                assert!(!conflict.proven, "report: {report:#?}");
                assert!(!conflict.exhaustive, "report: {report:#?}");
                assert_eq!(conflict.reasons.as_slice(), std::slice::from_ref(&reason));
            }
        }
    }
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
    fn source_summary_call_requires_an_exact_live_occurrence() {
        let fixture =
            Fixture::new("package sample\nfunc helper() {}\nfunc root() { helper(); helper() }\n");
        let artifact = fixture.artifact();
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| procedure.call_sites().len() == 2)
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("fixture root procedure");
        let calls = procedure.semantics().call_sites();
        let mapping = procedure
            .semantics()
            .source_mapping(calls[1].source)
            .expect("second call source mapping");
        let span = mapping.locator.anchor().span();
        let event = SummaryEventKey::from_call_source(&mapping.locator, 1);
        let witness = SummaryCallSourceWitness::new(
            procedure.semantics().locator(),
            span.start_byte(),
            span.end_byte(),
        );
        assert_eq!(
            live_summary_call(&procedure, event, Some(witness)),
            Some(calls[1].id)
        );
        assert_eq!(live_summary_call(&procedure, event, None), None);

        let first_mapping = procedure
            .semantics()
            .source_mapping(calls[0].source)
            .expect("first call source mapping");
        let first_span = first_mapping.locator.anchor().span();
        let first_witness = SummaryCallSourceWitness::new(
            procedure.semantics().locator(),
            first_span.start_byte(),
            first_span.end_byte(),
        );
        assert_eq!(
            live_summary_call(&procedure, event, Some(first_witness)),
            None,
            "an event ordinal cannot bind another source occurrence"
        );
    }

    #[test]
    fn source_summary_gap_requires_an_exact_omitted_access() {
        let fixture = Fixture::new("package sample\nfunc clear(target *error) { *target = nil }\n");
        let artifact = fixture.artifact();
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| procedure.kind() == ProcedureKind::Function)
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("fixture clear procedure");
        let gaps = procedure
            .semantics()
            .gaps()
            .iter()
            .filter(|gap| semantic_gap_omits_concurrency_access(gap))
            .collect::<Vec<_>>();
        let [gap] = gaps.as_slice() else {
            panic!("fixture has one omitted indirect write: {gaps:#?}");
        };
        let mapping = procedure
            .semantics()
            .source_mapping(gap.source)
            .expect("gap source mapping");
        let span = mapping.locator.anchor().span();
        let ordinal = procedure
            .semantics()
            .points()
            .iter()
            .map(|point| point.events.len())
            .sum::<usize>()
            + procedure
                .semantics()
                .gaps()
                .iter()
                .position(|candidate| candidate.id == gap.id)
                .expect("selected gap belongs to procedure");
        let event = SummaryEventKey::from_concurrency_source(&mapping.locator, ordinal);
        let witness = crate::dataflow::SummaryConcurrencySourceWitness::new(
            procedure.semantics().locator(),
            span.start_byte(),
            span.end_byte(),
        );
        let pending = |protocol: &str, witness| PendingSummaryEffect {
            context: ContextKey {
                task: TaskId(0),
                invocation: InvocationId(0),
                procedure: procedure.clone(),
            },
            effect: SummaryConcurrencyEffect::new(
                event,
                SummaryConcurrencyEffectKind::Unsupported {
                    protocol: protocol.into(),
                },
                crate::dataflow::SummaryConcurrencyExecution::new(
                    ExecutionTiming::SameEvaluation,
                    crate::dataflow::SummaryConcurrencyExecutionCardinality::Unknown,
                ),
                witness,
            ),
        };
        assert_eq!(
            source_summary_gap(&pending("semantic-gap:assignments", Some(witness))),
            Ok("assignments")
        );
        assert_eq!(
            source_summary_gap(&pending("semantic-gap:assignments", None)),
            Err("summary unsupported witness is unavailable")
        );
        assert_eq!(
            source_summary_gap(&pending("semantic-gap:field_memory", Some(witness))),
            Err("summary unsupported capability does not match source")
        );
    }

    #[test]
    fn source_summary_allocation_requires_exact_storage_identity() {
        let fixture = Fixture::new(
            "package sample\ntype cell struct { n int }\nfunc makeCell() *cell { return &cell{} }\n",
        );
        let artifact = fixture.artifact();
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| procedure.kind() == ProcedureKind::Function)
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("fixture makeCell procedure");
        let (ordinal, live_event) = procedure
            .semantics()
            .points()
            .iter()
            .flat_map(|point| point.events.iter())
            .enumerate()
            .find(|(_, event)| matches!(event.effect, SemanticEffect::Allocation { .. }))
            .expect("fixture allocation event");
        let SemanticEffect::Allocation { allocation } = live_event.effect else {
            unreachable!("selected event is an allocation");
        };
        let mapping = procedure
            .semantics()
            .source_mapping(live_event.source)
            .expect("allocation source mapping");
        let span = mapping.locator.anchor().span();
        assert_ne!(
            SummaryLocationKey::from_allocation_source(&mapping.locator, 0),
            SummaryLocationKey::from_allocation_source(&mapping.locator, 1),
            "co-located allocation occurrences retain distinct storage keys"
        );
        let event = SummaryEventKey::from_concurrency_source(&mapping.locator, ordinal);
        let witness = crate::dataflow::SummaryConcurrencySourceWitness::new(
            procedure.semantics().locator(),
            span.start_byte(),
            span.end_byte(),
        );
        let pending = |location, witness| PendingSummaryEffect {
            context: ContextKey {
                task: TaskId(0),
                invocation: InvocationId(0),
                procedure: procedure.clone(),
            },
            effect: SummaryConcurrencyEffect::new(
                event,
                SummaryConcurrencyEffectKind::Allocation { location },
                crate::dataflow::SummaryConcurrencyExecution::new(
                    ExecutionTiming::SameEvaluation,
                    crate::dataflow::SummaryConcurrencyExecutionCardinality::Unknown,
                ),
                witness,
            ),
        };
        assert_eq!(
            source_summary_allocation(&pending(
                source_allocation_summary_path(&procedure, allocation),
                Some(witness),
            )),
            Ok(allocation)
        );
        assert_eq!(
            source_summary_allocation(&pending(
                SummaryConcurrencyAccessPath::port(SummaryPort::Heap(
                    SummaryLocationKey::hash_bytes(b"another allocation"),
                )),
                Some(witness),
            )),
            Err("summary allocation identity does not match source")
        );
        assert_eq!(
            source_summary_allocation(&pending(
                source_allocation_summary_path(&procedure, allocation),
                None,
            )),
            Err("summary allocation witness is unavailable")
        );
    }

    #[test]
    fn source_summary_publication_requires_exact_destination() {
        let fixture = Fixture::new(
            "package sample\ntype cell struct { n int }\nfunc makeCell() *cell { return &cell{} }\n",
        );
        let artifact = fixture.artifact();
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| procedure.kind() == ProcedureKind::Function)
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("fixture makeCell procedure");
        let semantics = procedure.semantics();
        let allocation = semantics.allocations()[0].id;
        let (ordinal, point, event_index, event, destination) = semantics
            .points()
            .iter()
            .flat_map(|point| {
                point
                    .events
                    .iter()
                    .enumerate()
                    .map(move |(index, event)| (point.id, index, event))
            })
            .enumerate()
            .find_map(|(ordinal, (point, event_index, event))| {
                let kind = match event.effect {
                    SemanticEffect::ProcedureReturn { .. } | SemanticEffect::ValueFlow { .. } => {
                        crate::analyzer::semantic::FreshObjectPublicationKind::Return
                    }
                    _ => return None,
                };
                crate::typestate::direct_publication_destination(
                    &procedure,
                    point,
                    event_index,
                    kind,
                )
                .filter(|destination| {
                    destination.root() == &SummaryPort::NormalReturn
                        && destination.selectors().is_empty()
                })
                .map(|destination| (ordinal, point, event_index, event, destination))
            })
            .expect("fixture normal-result publication event");
        assert_eq!(
            crate::typestate::direct_publication_destination(
                &procedure,
                point,
                event_index,
                crate::analyzer::semantic::FreshObjectPublicationKind::Return,
            ),
            Some(destination.clone())
        );
        let mapping = semantics
            .source_mapping(event.source)
            .expect("publication source mapping");
        let span = mapping.locator.anchor().span();
        let event = SummaryEventKey::from_concurrency_source(&mapping.locator, ordinal);
        let witness = crate::dataflow::SummaryConcurrencySourceWitness::new(
            semantics.locator(),
            span.start_byte(),
            span.end_byte(),
        );
        let pending = |destination, witness| PendingSummaryEffect {
            context: ContextKey {
                task: TaskId(0),
                invocation: InvocationId(0),
                procedure: procedure.clone(),
            },
            effect: SummaryConcurrencyEffect::new(
                event,
                SummaryConcurrencyEffectKind::Publish {
                    value: source_allocation_summary_path(&procedure, allocation),
                    destination,
                },
                crate::dataflow::SummaryConcurrencyExecution::new(
                    ExecutionTiming::SameEvaluation,
                    crate::dataflow::SummaryConcurrencyExecutionCardinality::Unknown,
                ),
                witness,
            ),
        };
        assert_eq!(
            source_summary_publication(&pending(destination, Some(witness))),
            Ok(allocation)
        );
        assert_eq!(
            source_summary_publication(&pending(
                SummaryConcurrencyAccessPath::port(SummaryPort::ExceptionalReturn),
                Some(witness),
            )),
            Err("summary publication destination does not match source")
        );
        assert_eq!(
            source_summary_publication(&pending(
                SummaryConcurrencyAccessPath::port(SummaryPort::NormalReturn),
                None,
            )),
            Err("summary publication witness is unavailable")
        );

        let (allocation_ordinal, allocation_event) = semantics
            .points()
            .iter()
            .flat_map(|point| point.events.iter())
            .enumerate()
            .find(|(_, event)| matches!(event.effect, SemanticEffect::Allocation { .. }))
            .expect("fixture allocation event");
        let allocation_mapping = semantics
            .source_mapping(allocation_event.source)
            .expect("allocation source mapping");
        let allocation_span = allocation_mapping.locator.anchor().span();
        let open_inventory = PendingSummaryEffect {
            context: ContextKey {
                task: TaskId(0),
                invocation: InvocationId(0),
                procedure: procedure.clone(),
            },
            effect: SummaryConcurrencyEffect::new(
                SummaryEventKey::from_concurrency_source(
                    &allocation_mapping.locator,
                    allocation_ordinal,
                ),
                SummaryConcurrencyEffectKind::Unsupported {
                    protocol: "publication-inventory-open".into(),
                },
                crate::dataflow::SummaryConcurrencyExecution::new(
                    ExecutionTiming::SameEvaluation,
                    crate::dataflow::SummaryConcurrencyExecutionCardinality::Unknown,
                ),
                Some(crate::dataflow::SummaryConcurrencySourceWitness::new(
                    semantics.locator(),
                    allocation_span.start_byte(),
                    allocation_span.end_byte(),
                )),
            ),
        };
        assert_eq!(
            source_summary_publication_inventory_open(&open_inventory),
            Ok(allocation)
        );
    }

    #[test]
    fn source_summary_synchronization_requires_an_exact_live_witness() {
        use crate::dataflow::SummaryConcurrencySynchronizationOperation;

        let fixture = Fixture::new("package sample\nfunc wait(channel chan int) { <-channel }\n");
        let artifact = fixture.artifact();
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| procedure.kind() == ProcedureKind::Function)
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("fixture wait procedure");
        let (ordinal, live_event) = procedure
            .semantics()
            .points()
            .iter()
            .flat_map(|point| point.events.iter())
            .enumerate()
            .find(|(_, event)| matches!(event.effect, SemanticEffect::Synchronization { .. }))
            .expect("fixture receive synchronization");
        let mapping = procedure
            .semantics()
            .source_mapping(live_event.source)
            .expect("synchronization source mapping");
        let span = mapping.locator.anchor().span();
        let effect = |event, operation, witness| PendingSummaryEffect {
            context: ContextKey {
                task: TaskId(0),
                invocation: InvocationId(0),
                procedure: procedure.clone(),
            },
            effect: SummaryConcurrencyEffect::new(
                event,
                SummaryConcurrencyEffectKind::Synchronize {
                    subject: SummaryConcurrencyAccessPath::port(SummaryPort::Parameter(0)),
                    operation,
                },
                crate::dataflow::SummaryConcurrencyExecution::new(
                    ExecutionTiming::SameEvaluation,
                    crate::dataflow::SummaryConcurrencyExecutionCardinality::Unknown,
                ),
                witness,
            ),
        };
        let event = SummaryEventKey::from_concurrency_source(&mapping.locator, ordinal);
        let witness = crate::dataflow::SummaryConcurrencySourceWitness::new(
            procedure.semantics().locator(),
            span.start_byte(),
            span.end_byte(),
        );
        let exact = source_summary_synchronization(&effect(
            event,
            SummaryConcurrencySynchronizationOperation::Acquire,
            Some(witness),
        ))
        .expect("exact receive summary rehydrates its live event");
        let SemanticEffect::Synchronization {
            operation,
            subject,
            payload,
        } = &live_event.effect
        else {
            unreachable!("selected event is synchronization");
        };
        assert_eq!(exact.operation, *operation);
        assert_eq!(exact.subject, *subject);
        assert_eq!(exact.payload.as_ref(), payload.as_ref());
        assert_eq!(exact.event, 0);

        assert_eq!(
            source_summary_synchronization(&effect(
                event,
                SummaryConcurrencySynchronizationOperation::Acquire,
                None,
            ))
            .unwrap_err(),
            "summary synchronization witness is unavailable"
        );
        assert_eq!(
            source_summary_synchronization(&effect(
                SummaryEventKey::hash_bytes(b"wrong event"),
                SummaryConcurrencySynchronizationOperation::Acquire,
                Some(witness),
            ))
            .unwrap_err(),
            "summary synchronization witness is unavailable"
        );
        let wrong_witness = crate::dataflow::SummaryConcurrencySourceWitness::new(
            procedure.semantics().locator(),
            span.start_byte().saturating_add(1),
            span.end_byte(),
        );
        assert_eq!(
            source_summary_synchronization(&effect(
                event,
                SummaryConcurrencySynchronizationOperation::Acquire,
                Some(wrong_witness),
            ))
            .unwrap_err(),
            "summary synchronization witness is unavailable"
        );
        assert_eq!(
            source_summary_synchronization(&effect(
                event,
                SummaryConcurrencySynchronizationOperation::Release,
                Some(witness),
            ))
            .unwrap_err(),
            "summary synchronization operation does not match source"
        );
    }

    #[test]
    fn source_summary_access_requires_an_exact_live_witness() {
        let fixture = Fixture::new(
            "package sample\ntype cell struct { value int }\nfunc write(c *cell) { c.value = 1 }\n",
        );
        let artifact = fixture.artifact();
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| procedure.kind() == ProcedureKind::Function)
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("fixture write procedure");
        let (ordinal, (point, live_event)) = procedure
            .semantics()
            .points()
            .iter()
            .flat_map(|point| point.events.iter().map(move |event| (point.id, event)))
            .enumerate()
            .find(|(_, (_, event))| matches!(event.effect, SemanticEffect::MemoryStore { .. }))
            .expect("fixture field store");
        let mapping = procedure
            .semantics()
            .source_mapping(live_event.source)
            .expect("access source mapping");
        let span = mapping.locator.anchor().span();
        let path = SummaryConcurrencyAccessPath::new(
            SummaryPort::Parameter(0),
            vec![SummaryConcurrencyAccessSelector::Field(
                SummaryLocationKey::hash_bytes(b"cell.value"),
            )],
        );
        let effect = |event, mode, witness| PendingSummaryEffect {
            context: ContextKey {
                task: TaskId(0),
                invocation: InvocationId(0),
                procedure: procedure.clone(),
            },
            effect: SummaryConcurrencyEffect::new(
                event,
                SummaryConcurrencyEffectKind::Access {
                    location: path.clone(),
                    mode,
                    must_hold: Box::default(),
                },
                crate::dataflow::SummaryConcurrencyExecution::new(
                    ExecutionTiming::SameEvaluation,
                    crate::dataflow::SummaryConcurrencyExecutionCardinality::Unknown,
                ),
                witness,
            ),
        };
        let event = SummaryEventKey::from_concurrency_source(&mapping.locator, ordinal);
        let witness = crate::dataflow::SummaryConcurrencySourceWitness::new(
            procedure.semantics().locator(),
            span.start_byte(),
            span.end_byte(),
        );
        let exact = source_summary_access(&effect(
            event,
            SummaryConcurrencyAccessMode::Write,
            Some(witness),
        ))
        .expect("exact access summary rehydrates its live event");
        let SemanticEffect::MemoryStore { location, kind, .. } = &live_event.effect else {
            unreachable!("selected event is a store");
        };
        assert_eq!(exact.point, point);
        assert_eq!(exact.source, live_event.source);
        assert_eq!(exact.location, *location);
        assert_eq!(exact.mode, ConcurrentAccessMode::Write);
        assert_eq!(exact.access_kind, *kind);

        assert_eq!(
            source_summary_access(&effect(event, SummaryConcurrencyAccessMode::Write, None,))
                .unwrap_err(),
            "summary access witness is unavailable"
        );
        assert_eq!(
            source_summary_access(&effect(
                SummaryEventKey::hash_bytes(b"wrong event"),
                SummaryConcurrencyAccessMode::Write,
                Some(witness),
            ))
            .unwrap_err(),
            "summary access witness is unavailable"
        );
        let foreign_fixture = Fixture::new("package sample\nfunc other() {}\n");
        let foreign_artifact = foreign_fixture.artifact();
        let foreign_procedure = foreign_artifact
            .procedures()
            .iter()
            .find(|procedure| procedure.kind() == ProcedureKind::Function)
            .and_then(|procedure| foreign_artifact.procedure_handle(procedure.id()))
            .expect("fixture foreign procedure");
        let wrong_owner_witness = crate::dataflow::SummaryConcurrencySourceWitness::new(
            foreign_procedure.semantics().locator(),
            span.start_byte(),
            span.end_byte(),
        );
        assert_eq!(
            source_summary_access(&effect(
                event,
                SummaryConcurrencyAccessMode::Write,
                Some(wrong_owner_witness),
            ))
            .unwrap_err(),
            "summary access witness is unavailable"
        );
        assert_eq!(
            source_summary_access(&effect(
                event,
                SummaryConcurrencyAccessMode::Read,
                Some(witness),
            ))
            .unwrap_err(),
            "summary access mode does not match source"
        );
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
            AccessOverlap::MayAlias(None),
            "opaque summary field keys alone do not prove different declarations"
        );
        assert!(matches!(
            field_location.overlap(&field_location),
            AccessOverlap::Same(_)
        ));
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
            _targets: &ConcurrencyAnswer<Vec<ProcedureHandle>>,
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

    struct ExternalEffectsProvider {
        worker_effects: ConcurrencyAnswer<Vec<ResolvedConcurrencyEffect>>,
        worker_procedure: ProcedureHandle,
        worker_call: CallSiteId,
        root_procedure: ProcedureHandle,
        root_unknown_call: CallSiteId,
    }

    impl ExternalEffectsProvider {
        fn is_worker_call(&self, call: &CallSiteHandle) -> bool {
            call.procedure() == &self.worker_procedure && call.id() == self.worker_call
        }

        fn is_root_unknown_call(&self, call: &CallSiteHandle) -> bool {
            call.procedure() == &self.root_procedure && call.id() == self.root_unknown_call
        }
    }

    impl ConcurrencyProvider for ExternalEffectsProvider {
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
            if self.is_worker_call(call) {
                // Exact external declaration; target identity does not close effects.
                return Ok(ConcurrencyAnswer::Proven(Vec::new()));
            }
            if self.is_root_unknown_call(call) {
                return Ok(ConcurrencyAnswer::Open {
                    partial: Vec::new(),
                    reasons: vec![ConcurrencyOpenReason::UnresolvedTarget],
                });
            }
            LocalProvider.resolve_call(call, request)
        }

        fn modeled_effects(
            &self,
            call: &CallSiteHandle,
            targets: &ConcurrencyAnswer<Vec<ProcedureHandle>>,
            request: &mut SemanticRequest<'_>,
        ) -> Result<ConcurrencyAnswer<Vec<ResolvedConcurrencyEffect>>, SemanticProviderError>
        {
            if self.is_worker_call(call) {
                return Ok(self.worker_effects.clone());
            }
            if self.is_root_unknown_call(call) {
                return Ok(ConcurrencyAnswer::Open {
                    partial: Vec::new(),
                    reasons: vec![ConcurrencyOpenReason::UnresolvedTarget],
                });
            }
            LocalProvider.modeled_effects(call, targets, request)
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

    #[test]
    fn private_storage_respects_opposing_effect_inventory() {
        let fixture = Fixture::new(
            r#"package sample

    func root() {
        n := 0
        go func() {
            externalWorker()
            n = 1
        }()
        unknownRootEffects()
        n = 2
    }
    "#,
        );
        let artifact = fixture.artifact();
        let root = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure.kind() == ProcedureKind::Function && procedure.lexical_parent().is_none()
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("fixture root procedure");
        let worker = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure.lexical_parent().is_some() && procedure.call_sites().len() == 1
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("fixture spawned closure");
        let worker_call = worker.semantics().call_sites()[0].id;
        let root_unknown_call = root
            .semantics()
            .call_sites()
            .iter()
            .find(|call| call.invocation_mode == CallInvocationMode::Ordinary)
            .expect("fixture root unknown call")
            .id;
        for (worker_effects, expected_proven) in [
            (
                ConcurrencyAnswer::Open {
                    partial: Vec::new(),
                    reasons: vec![ConcurrencyOpenReason::UnresolvedTarget],
                },
                false,
            ),
            (ConcurrencyAnswer::Proven(Vec::new()), true),
        ] {
            let provider = ExternalEffectsProvider {
                worker_effects,
                worker_procedure: worker.clone(),
                worker_call,
                root_procedure: root.clone(),
                root_unknown_call,
            };
            let cancellation = crate::cancellation::CancellationToken::default();
            let mut budget = SemanticBudget::new(SemanticWork::default_limits()).unwrap();
            let report = concurrent_access_conflicts(
                &provider,
                &root,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .unwrap();

            let captured_write_conflict = report.conflicts.iter().find(|conflict| {
                conflict.first.mode == ConcurrentAccessMode::Write
                    && conflict.second.mode == ConcurrentAccessMode::Write
                    && conflict.ordering == ConcurrentOrdering::Unordered
                    && conflict.protection == ConcurrentProtection::Unprotected
                    && conflict.task_relation == ConcurrentTaskRelation::ParentChild
            });
            assert!(
                captured_write_conflict.is_some(),
                "fixture did not retain opposing captured writes: {report:#?}"
            );
            let conflict = captured_write_conflict.expect("checked above");
            assert_eq!(conflict.proven, expected_proven, "{report:#?}");
            assert_eq!(conflict.exhaustive, expected_proven, "{report:#?}");
            let expected_reasons = if expected_proven {
                Vec::new()
            } else {
                vec![ConcurrencyOpenReason::UnresolvedTarget]
            };
            assert_eq!(conflict.reasons, expected_reasons, "{report:#?}");
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
            _targets: &ConcurrencyAnswer<Vec<ProcedureHandle>>,
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
            targets: &ConcurrencyAnswer<Vec<ProcedureHandle>>,
            request: &mut SemanticRequest<'_>,
        ) -> Result<ConcurrencyAnswer<Vec<ResolvedConcurrencyEffect>>, SemanticProviderError>
        {
            LocalProvider.modeled_effects(call, targets, request)
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

    #[test]
    fn cached_call_order_matches_pairwise_reachability() {
        let fixture = Fixture::new(
            r#"
package demo
func f(n int) int {
    total := 0
    for i := 0; i < n; i++ {
        if i == 2 { continue }
        total += i
    }
    if n > 4 { total++ } else { total-- }
    return total
}
"#,
        );
        let artifact = fixture.artifact();
        let procedure = artifact
            .procedure_handle(artifact.procedures()[0].id())
            .unwrap();
        assert!(reference_control_is_complete(&procedure));
        let cancellation = crate::cancellation::CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let mut control = AccessControlCache::default();
        for call in procedure.semantics().points() {
            let before = points_strictly_before_call(
                &procedure,
                call.id,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .unwrap();
            for access in procedure.semantics().points() {
                let access_reaches_call = point_reaches(
                    &procedure,
                    access.id,
                    call.id,
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .unwrap();
                let call_reaches_access = point_reaches(
                    &procedure,
                    call.id,
                    access.id,
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .unwrap();
                let expected = access.id != call.id && access_reaches_call && !call_reaches_access;
                assert_eq!(
                    before.contains(&access.id),
                    expected,
                    "access {:?}, call {:?}",
                    access.id,
                    call.id
                );
                assert_eq!(
                    control
                        .relation(
                            &procedure,
                            call.id,
                            access.id,
                            &mut SemanticRequest::new(&mut budget, &cancellation),
                        )
                        .unwrap(),
                    (
                        access_reaches_call || access.id == call.id,
                        call_reaches_access || access.id == call.id
                    ),
                    "cached relation for access {:?}, call {:?}",
                    access.id,
                    call.id
                );
            }
        }
        for point in procedure.semantics().points() {
            assert_eq!(
                control
                    .is_cyclic(
                        &procedure,
                        point.id,
                        &mut SemanticRequest::new(&mut budget, &cancellation),
                    )
                    .unwrap(),
                point_is_cyclic(
                    procedure.semantics(),
                    point.id,
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .unwrap(),
                "cached cyclic membership for {:?}",
                point.id
            );
            assert_eq!(
                control
                    .dominates(
                        &procedure,
                        procedure.semantics().entry_point(),
                        point.id,
                        &mut SemanticRequest::new(&mut budget, &cancellation),
                    )
                    .unwrap(),
                point_dominates(
                    &procedure,
                    procedure.semantics().entry_point(),
                    point.id,
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .unwrap(),
                "cached dominance for {:?}",
                point.id
            );
        }
        let mut exhausted = SemanticBudget::uniform(1).unwrap();
        assert_eq!(
            points_strictly_before_call(
                &procedure,
                procedure.semantics().entry_point(),
                &mut SemanticRequest::new(&mut exhausted, &cancellation),
            ),
            Err(ConcurrencyOpenReason::BudgetExhausted)
        );
        let cancelled = crate::cancellation::CancellationToken::default();
        cancelled.cancel();
        let mut cancelled_budget = SemanticBudget::default();
        assert_eq!(
            control.relation(
                &procedure,
                procedure.semantics().entry_point(),
                procedure.semantics().normal_exit_point(),
                &mut SemanticRequest::new(&mut cancelled_budget, &cancelled),
            ),
            Err(ConcurrencyOpenReason::BudgetExhausted),
            "a cached control fact must still honor later cancellation"
        );
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
    fn opaque_base_invalidates_provider_identity_without_a_formal_binding() {
        let fixture =
            Fixture::new("package sample\nfunc root() { items := [1]int{}; items[0] = 1 }\n");
        let artifact = fixture.artifact();
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| procedure.kind() == ProcedureKind::Function)
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("fixture function");
        let (point, event, location, base, identity, constant_index) = procedure
            .semantics()
            .points()
            .iter()
            .find_map(|point| {
                point.events.iter().find_map(|event| {
                    let SemanticEffect::MemoryStore { location, .. } = event.effect else {
                        return None;
                    };
                    let MemoryLocationKind::Index {
                        base,
                        identity,
                        constant_index,
                        ..
                    } = procedure.semantics().memory_location(location)?.kind
                    else {
                        return None;
                    };
                    Some((point.id, event, location, base, identity, constant_index))
                })
            })
            .expect("source-backed element store");
        let allocation = procedure
            .semantics()
            .allocations()
            .first()
            .expect("array allocation")
            .id;
        let canonical = CanonicalConcurrencyLocation::new("provider-array-element", "index");
        let mut access = Access {
            site: ConcurrentAccessSite {
                task: TaskId(0),
                invocation: InvocationId(0),
                procedure: procedure.clone(),
                point,
                source: event.source,
                mode: ConcurrentAccessMode::Write,
                access_kind: MemoryAccessKind::Index,
            },
            local_location: Some(LocalLocation {
                task: TaskId(0),
                invocation: InvocationId(0),
                procedure: procedure.clone(),
                location,
            }),
            canonical: Some(canonical.clone()),
            resolved_location: ResolvedConcurrencyLocation::independent(
                canonical.clone(),
                ConcurrencyStorageFamily::Allocation {
                    invocation: InvocationId(0),
                    allocation,
                },
            ),
            index_alias_domain: Some(IndexAliasDomain {
                base: canonical.clone(),
                identity,
                constant_index,
            }),
            field_alias_domain: None,
            local_identity: false,
            reasons: Vec::new(),
            atomic: false,
            storage_origin: Some(canonical.clone()),
        };
        let mut classes = SynchronizationSubjectClasses::default();
        let invocations = Invocations {
            entries: vec![Invocation {
                context: ContextKey {
                    task: TaskId(0),
                    invocation: InvocationId(0),
                    procedure: procedure.clone(),
                },
                callable: None,
                caller: None,
                repetition: None,
            }],
        };
        canonicalize_bound_accesses(
            &mut classes,
            &invocations,
            std::slice::from_mut(&mut access),
        );
        assert_eq!(access.canonical, Some(canonical));
        assert!(access.resolved_location.exact_candidate().is_some());
        assert!(access.reasons.is_empty());

        classes
            .opaque_values
            .push(LocalSynchronizationSubject::Value {
                task: TaskId(0),
                invocation: InvocationId(0),
                procedure,
                value: base,
            });
        canonicalize_bound_accesses(
            &mut classes,
            &invocations,
            std::slice::from_mut(&mut access),
        );
        assert_eq!(access.canonical, None);
        assert!(access.resolved_location.exact_candidate().is_none());
        assert_eq!(access.index_alias_domain, None);
        assert_eq!(access.storage_origin, None);
        assert_eq!(access.reasons, [ConcurrencyOpenReason::UnknownLocation]);
    }

    #[test]
    fn reference_identity_cell_propagation_is_order_invariant_without_results() {
        let fixture = Fixture::new(
            r#"package sample

type cell struct {
    value int
}

func root() {
    first := &cell{}
    second := first
    _ = func() {
        first.value = 1
        second.value = 2
    }
}
"#,
        );
        let artifact = fixture.artifact();
        let root = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure.kind() == ProcedureKind::Function
                    && procedure.lexical_parent().is_none()
                    && procedure
                        .locator()
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some("root")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("fixture root procedure");

        let run = |terminal_first: bool| {
            let cancellation = crate::cancellation::CancellationToken::default();
            let mut budget = SemanticBudget::new(SemanticWork::default_limits()).unwrap();
            let mut invocations = Invocations::default();
            let context = invocations
                .push(
                    TaskId(0),
                    root.clone(),
                    None,
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .unwrap();
            let tasks = vec![Task {
                parent: None,
                entry_procedure: Some(root.clone()),
                entry_invocation: context.invocation,
                spawn_procedure: None,
                spawn_invocation: None,
                spawn_call: None,
                group: None,
                completion: None,
                repetition: None,
                repetitions_serialized: false,
            }];
            let local = |location| LocalLocation {
                task: context.task,
                invocation: context.invocation,
                procedure: root.clone(),
                location,
            };
            let subject = |value| LocalSynchronizationSubject::Value {
                task: context.task,
                invocation: context.invocation,
                procedure: root.clone(),
                value,
            };
            let mut classes = SynchronizationSubjectClasses::default();
            let mut reference_allocations = HashSet::default();
            let mut allocation_fact = None;
            let mut allocation_results = HashSet::default();
            for allocation in root.semantics().allocations() {
                if !matches!(
                    &allocation.kind,
                    crate::analyzer::semantic::AllocationKind::Object
                ) {
                    continue;
                }
                let canonical = contextual_allocation_identity(
                    context.task,
                    context.invocation,
                    CanonicalConcurrencyLocation::new(
                        format!(
                            "allocation:{}:{}",
                            crate::flow_state::procedure_wire_id(&root),
                            allocation.id.get()
                        ),
                        "object",
                    ),
                );
                let fact = ConcurrencyIdentityFact::allocation(
                    canonical.clone(),
                    context.invocation,
                    allocation.id,
                );
                let allocation_subject = subject(allocation.result);
                classes.bind_canonical_value(allocation_subject.clone(), fact.clone());
                classes.mark_fresh_allocation(allocation_subject);
                allocation_results.insert(allocation.result);
                reference_allocations.insert(canonical);
                assert!(
                    allocation_fact.replace(fact).is_none(),
                    "fixture has one real reference allocation"
                );
            }
            let allocation_fact = allocation_fact.expect("fixture allocation");

            let mut store_counts = HashMap::<LocalLocation, usize>::default();
            let mut loaded_values = HashSet::default();
            for point in root.semantics().points() {
                for event in &point.events {
                    match event.effect {
                        SemanticEffect::Assignment { target, value } => {
                            let source = subject(value);
                            let target_subject = subject(target);
                            classes.union_backing(source.clone(), target_subject.clone());
                            classes.note_value_assignment(target_subject.clone());
                            if allocation_results.contains(&value) {
                                classes.union(source, target_subject);
                            }
                        }
                        SemanticEffect::ValueFlow {
                            kind: crate::analyzer::semantic::ValueFlowKind::Local,
                            source,
                            target,
                        } => {
                            let source = subject(source);
                            let target_subject = subject(target);
                            classes.union_backing(source.clone(), target_subject.clone());
                            if let ConcurrencyAnswer::Proven(Some(canonical)) =
                                classes.bound_canonical_identity(source.clone())
                            {
                                classes.bind_canonical_value(target_subject.clone(), canonical);
                            }
                            if binding_location(root.semantics(), target).is_none() {
                                classes.union(source, target_subject);
                            }
                        }
                        SemanticEffect::MemoryLoad {
                            location, result, ..
                        } => {
                            let location = local(location);
                            let result = subject(result);
                            classes.union_backing(
                                LocalSynchronizationSubject::Location(location.clone()),
                                result.clone(),
                            );
                            classes.union(
                                LocalSynchronizationSubject::Location(location),
                                result.clone(),
                            );
                            loaded_values.insert(result);
                        }
                        SemanticEffect::MemoryStore {
                            location, value, ..
                        } => {
                            let location = local(location);
                            *store_counts.entry(location.clone()).or_default() += 1;
                            classes.note_location_store(location.clone());
                            let row = root
                                .semantics()
                                .memory_location(location.location)
                                .expect("store location");
                            if !matches!(&row.kind, MemoryLocationKind::Index { .. }) {
                                classes.note_backing_location_store(location, subject(value));
                            }
                        }
                        _ => {}
                    }
                }
            }
            let cells = store_counts
                .into_iter()
                .filter_map(|(location, count)| {
                    let row = root
                        .semantics()
                        .memory_location(location.location)
                        .expect("cell store location");
                    (count == 1
                        && matches!(
                            &row.kind,
                            MemoryLocationKind::LexicalCell { .. }
                                | MemoryLocationKind::Capture { .. }
                        ))
                    .then_some(location)
                })
                .collect::<Vec<_>>();
            assert_eq!(cells.len(), 2, "cell stores: {cells:#?}");
            let source_cell = cells
                .iter()
                .find(|location| {
                    let Some([stored]) = classes
                        .backing_location_stores
                        .get(*location)
                        .map(Vec::as_slice)
                    else {
                        return false;
                    };
                    matches!(
                        classes.bound_canonical_identity(stored.clone()),
                        ConcurrencyAnswer::Proven(Some(ref fact)) if fact == &allocation_fact
                    )
                })
                .cloned()
                .expect("one cell stores the real allocation");
            let terminal_cell = cells
                .iter()
                .find(|location| {
                    let Some([stored]) = classes
                        .backing_location_stores
                        .get(*location)
                        .map(Vec::as_slice)
                    else {
                        return false;
                    };
                    loaded_values.contains(stored)
                })
                .cloned()
                .expect("one cell stores the loaded source value");
            assert_ne!(source_cell, terminal_cell);
            let cells = if terminal_first {
                vec![(terminal_cell.clone(), None), (source_cell, None)]
            } else {
                vec![(source_cell, None), (terminal_cell.clone(), None)]
            };

            propagate_reference_identities(
                &mut classes,
                &invocations,
                &tasks,
                &[],
                &cells,
                &reference_allocations,
                &[],
                &HashMap::default(),
                &HashSet::default(),
                &LocalProvider,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            );
            let terminal_fact = match classes
                .bound_canonical_identity(LocalSynchronizationSubject::Location(terminal_cell))
            {
                ConcurrencyAnswer::Proven(Some(fact)) => fact,
                answer => panic!("terminal cell receives the propagated allocation: {answer:?}"),
            };
            (terminal_fact, allocation_fact)
        };

        let (first_terminal, first_allocation) = run(false);
        let (second_terminal, second_allocation) = run(true);
        assert_eq!(first_terminal, first_allocation);
        assert_eq!(second_terminal, second_allocation);
        assert_eq!(first_terminal, second_terminal);
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
    fn exhausted_activation_does_not_spend_remaining_budget_on_heap_passes() {
        let fixture = Fixture::new("package sample\nfunc root() { n := 1; _ = n }\n");
        let artifact = fixture.artifact();
        let root = artifact
            .procedure_handle(artifact.procedures()[0].id())
            .unwrap();
        let events = root
            .semantics()
            .points()
            .iter()
            .map(|point| point.events.len())
            .sum();
        assert!(events > 0);
        // Replay needs these events plus values and locations. The smaller
        // heap inventory fits this limit, but must not run after replay fails.
        let mut budget = SemanticBudget::new(SemanticWork {
            nested_entries: events,
            ..SemanticWork::default_limits()
        })
        .unwrap();
        let cancellation = crate::cancellation::CancellationToken::default();
        let report = concurrent_access_conflicts(
            &LocalProvider,
            &root,
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .unwrap();
        assert_eq!(report.reasons, [ConcurrencyOpenReason::BudgetExhausted]);
        assert!(report.conflicts.is_empty());
        assert_eq!(budget.used(), SemanticWork::default());
    }

    #[test]
    fn spawn_recursion_is_ancestral_edge_specific_and_bounded() {
        let fixture = Fixture::new("package sample\nfunc root() { go root(); go root() }\n");
        let artifact = fixture.artifact();
        let root = artifact
            .procedure_handle(artifact.procedures()[0].id())
            .unwrap();
        let calls = root.semantics().call_sites();
        assert_eq!(calls.len(), 2);
        let cancellation = crate::cancellation::CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let mut request = SemanticRequest::new(&mut budget, &cancellation);
        let mut invocations = Invocations::default();
        let parent = invocations
            .push(TaskId(0), root.clone(), None, &mut request)
            .unwrap();
        let first = invocations
            .push(
                TaskId(1),
                root.clone(),
                Some((parent.invocation, calls[0].id)),
                &mut request,
            )
            .unwrap();
        let sibling = invocations
            .push(
                TaskId(2),
                root.clone(),
                Some((parent.invocation, calls[0].id)),
                &mut request,
            )
            .unwrap();
        let synchronous = invocations
            .push(
                TaskId(0),
                root.clone(),
                Some((parent.invocation, calls[0].id)),
                &mut request,
            )
            .unwrap();
        for (caller, call, expected) in [
            (parent.invocation, calls[0].id, false),
            (first.invocation, calls[0].id, true),
            (sibling.invocation, calls[0].id, true),
            (first.invocation, calls[1].id, false),
            (synchronous.invocation, calls[0].id, false),
        ] {
            assert_eq!(
                invocations.repeats_spawn_edge(caller, call, &root, &mut request),
                Ok(expected)
            );
        }
        let mut bounded = SemanticBudget::uniform(1).unwrap();
        assert_eq!(
            invocations.repeats_spawn_edge(
                first.invocation,
                calls[1].id,
                &root,
                &mut SemanticRequest::new(&mut bounded, &cancellation),
            ),
            Err(ConcurrencyOpenReason::BudgetExhausted)
        );
        cancellation.cancel();
        assert_eq!(
            invocations.repeats_spawn_edge(first.invocation, calls[0].id, &root, &mut request,),
            Err(ConcurrencyOpenReason::BudgetExhausted)
        );
    }

    #[test]
    fn recursive_detached_expansion_stops_before_exhausting_budget() {
        let fixture = Fixture::new(
            r#"package sample

func recursive() {
    go recursive()
}
"#,
        );
        let artifact = fixture.artifact();
        let root = artifact
            .procedures()
            .iter()
            .find(|procedure| procedure.kind() == ProcedureKind::Function)
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .unwrap();
        let cancellation = crate::cancellation::CancellationToken::default();
        let mut budget = SemanticBudget::new(SemanticWork {
            nested_entries: 2_000,
            ..SemanticWork::default_limits()
        })
        .unwrap();
        let report = concurrent_access_conflicts(
            &SelfCallProvider,
            &root,
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .unwrap();
        assert_eq!(report.reasons, [ConcurrencyOpenReason::RecursiveExpansion]);
        assert!(budget.remaining().nested_entries > 0);
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
