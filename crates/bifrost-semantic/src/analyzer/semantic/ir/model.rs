use std::fmt;

use crate::analyzer::semantic::capabilities::SemanticCapability;

use crate::analyzer::semantic::ids::AllocationId;

use crate::analyzer::semantic::ids::BlockId;

use crate::analyzer::semantic::ids::CallSiteId;

use crate::analyzer::semantic::ids::CaptureId;

use crate::analyzer::semantic::ids::DeclarationSegmentKind;

use crate::analyzer::semantic::ids::EvidenceId;

use crate::analyzer::semantic::ids::GuardId;

use crate::analyzer::semantic::ids::MemoryLocationId;

use crate::analyzer::semantic::ids::PointerOriginId;

use crate::analyzer::semantic::ids::ProcedureId;

use crate::analyzer::semantic::ids::ProgramPointId;

use crate::analyzer::semantic::ids::SemanticGapId;

use crate::analyzer::semantic::ids::SemanticLocator;

use crate::analyzer::semantic::ids::SourceMappingId;

use crate::analyzer::semantic::ids::StableDigest;

use crate::analyzer::semantic::ids::StructuralNodeIdentity;

use crate::analyzer::semantic::ids::SwitchFactId;

use crate::analyzer::semantic::ids::ValueId;

use crate::analyzer::semantic::provider::SemanticBudgetExceeded;

pub use brokk_bifrost_core::analyzer::model::DispatchExtensibility;

pub const FOOTPRINT_COVERAGE_CONTRACT_VERSION: u32 = 1;

/// The complete set of footprint claims required by contract version 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FootprintClass {
    FormalSlots,
    SignatureAttributesTransforms,
    MemoryWrite,
    MemoryRead,
    PublicationEscape,
    StaticGlobal,
    Capture,
    NestedCall,
    CallTarget,
    NormalExit,
    ExceptionalExit,
    CleanupDropUnwind,
    ConversionInitialization,
    DeferredExecution,
    NestedCallableOwnership,
}

impl FootprintClass {
    pub const ALL: [Self; 15] = [
        Self::FormalSlots,
        Self::SignatureAttributesTransforms,
        Self::MemoryWrite,
        Self::MemoryRead,
        Self::PublicationEscape,
        Self::StaticGlobal,
        Self::Capture,
        Self::NestedCall,
        Self::CallTarget,
        Self::NormalExit,
        Self::ExceptionalExit,
        Self::CleanupDropUnwind,
        Self::ConversionInitialization,
        Self::DeferredExecution,
        Self::NestedCallableOwnership,
    ];

    pub const fn code(self) -> i64 {
        match self {
            Self::FormalSlots => 1,
            Self::SignatureAttributesTransforms => 2,
            Self::MemoryWrite => 3,
            Self::MemoryRead => 4,
            Self::PublicationEscape => 5,
            Self::StaticGlobal => 6,
            Self::Capture => 7,
            Self::NestedCall => 8,
            Self::CallTarget => 9,
            Self::NormalExit => 10,
            Self::ExceptionalExit => 11,
            Self::CleanupDropUnwind => 12,
            Self::ConversionInitialization => 13,
            Self::DeferredExecution => 14,
            Self::NestedCallableOwnership => 15,
        }
    }

    pub fn from_code(code: i64) -> Option<Self> {
        let class = Self::ALL.into_iter().find(|class| class.code() == code)?;
        debug_assert_eq!(class.code(), code);
        Some(class)
    }
}

/// Footprint classes witnessed by the lowered IR rows of a procedure.
pub fn present_footprint_classes(
    parts: &ProcedureSemanticsParts,
) -> std::collections::HashSet<FootprintClass> {
    let mut present = std::collections::HashSet::new();
    for point in &parts.points {
        for event in &point.events {
            match &event.effect {
                SemanticEffect::MemoryStore { .. } => {
                    present.insert(FootprintClass::MemoryWrite);
                    present.insert(FootprintClass::PublicationEscape);
                }
                SemanticEffect::MemoryLoad { .. } => {
                    present.insert(FootprintClass::MemoryRead);
                }
                SemanticEffect::CaptureBind { .. } => {
                    present.insert(FootprintClass::Capture);
                    present.insert(FootprintClass::PublicationEscape);
                }
                // A keyed operand of an aggregate is an initializing write to
                // the aggregate, like a field store.
                SemanticEffect::AggregateInitializer { .. } => {
                    present.insert(FootprintClass::MemoryWrite);
                    present.insert(FootprintClass::PublicationEscape);
                }
                // A multi-value return publishes through indexed flows and
                // carries `ProcedureReturn { value: None }`.
                SemanticEffect::ProcedureReturn { value: Some(_) }
                | SemanticEffect::Throw { value: Some(_) }
                | SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Return | ValueFlowKind::IndexedReturn { .. },
                    ..
                } => {
                    present.insert(FootprintClass::PublicationEscape);
                }
                SemanticEffect::NormalExit => {
                    present.insert(FootprintClass::NormalExit);
                }
                SemanticEffect::ExceptionalExit => {
                    present.insert(FootprintClass::ExceptionalExit);
                }
                _ => {}
            }
        }
    }
    if parts
        .memory_locations
        .iter()
        .any(|location| matches!(location.kind, MemoryLocationKind::Static { .. }))
    {
        present.insert(FootprintClass::StaticGlobal);
    }
    if !parts.captures.is_empty() {
        present.insert(FootprintClass::Capture);
        present.insert(FootprintClass::PublicationEscape);
    }
    if !parts.call_sites.is_empty() {
        present.insert(FootprintClass::NestedCall);
        present.insert(FootprintClass::CallTarget);
    }
    if parts.call_sites.iter().any(|call| {
        matches!(call.invocation_mode, CallInvocationMode::Detached)
            || matches!(
                call.execution_timing,
                ExecutionTiming::SameInvocation
                    | ExecutionTiming::LaterSameTurn
                    | ExecutionTiming::AfterSuspension
                    | ExecutionTiming::DifferentTask
                    | ExecutionTiming::DifferentThread
                    | ExecutionTiming::DeferredCallback
                    | ExecutionTiming::GeneratorResume
                    | ExecutionTiming::CancellationCleanup
            )
    }) {
        present.insert(FootprintClass::DeferredExecution);
    }
    present
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FootprintExclusion {
    NoInstance,
    NoDropGlue,
}

impl FootprintExclusion {
    pub const fn code(self) -> i64 {
        match self {
            Self::NoInstance => 1,
            Self::NoDropGlue => 2,
        }
    }

    pub fn from_code(code: i64) -> Option<Self> {
        let reason = match code {
            1 => Self::NoInstance,
            2 => Self::NoDropGlue,
            _ => return None,
        };
        debug_assert_eq!(reason.code(), code);
        Some(reason)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FootprintRefusal {
    UnclassifiedBranch,
    FormalSlotsUnavailable,
    UnaccountedSourceNode,
    ContradictoryOwnership,
    RelevantGap,
}

impl FootprintRefusal {
    pub const fn code(self) -> i64 {
        match self {
            Self::UnclassifiedBranch => 1,
            Self::FormalSlotsUnavailable => 2,
            Self::UnaccountedSourceNode => 3,
            Self::ContradictoryOwnership => 4,
            Self::RelevantGap => 5,
        }
    }

    pub fn from_code(code: i64) -> Option<Self> {
        let reason = match code {
            1 => Self::UnclassifiedBranch,
            2 => Self::FormalSlotsUnavailable,
            3 => Self::UnaccountedSourceNode,
            4 => Self::ContradictoryOwnership,
            5 => Self::RelevantGap,
            _ => return None,
        };
        debug_assert_eq!(reason.code(), code);
        Some(reason)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FootprintDisposition {
    Represented,
    Excluded(FootprintExclusion),
    Refused(FootprintRefusal),
}

impl FootprintDisposition {
    pub const fn code(self) -> i64 {
        match self {
            Self::Represented => 1,
            Self::Excluded(_) => 2,
            Self::Refused(_) => 3,
        }
    }

    pub fn from_code(code: i64, reason: Option<i64>) -> Option<Self> {
        let disposition = match (code, reason) {
            (1, None) => Self::Represented,
            (2, Some(reason)) => Self::Excluded(FootprintExclusion::from_code(reason)?),
            (3, Some(reason)) => Self::Refused(FootprintRefusal::from_code(reason)?),
            _ => return None,
        };
        debug_assert_eq!(disposition.code(), code);
        Some(disposition)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcedureFootprintCoverage {
    pub contract_version: u32,
    pub boundary: Result<(), FootprintRefusal>,
    pub classes: [FootprintDisposition; 15],
    pub call_target_obligations: Vec<CallTargetObligation>,
}

/// Transient proof about the selected source procedure, independent of the
/// full effect footprint. M2 publishes this as relational coverage rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcedureCallControlCoverage {
    pub source_boundary: Result<(), FootprintRefusal>,
    pub branches: Vec<CallControlBranch>,
    pub call_target_obligations: Vec<CallTargetObligation>,
    pub admission: Result<(), FootprintRefusal>,
}

impl Default for ProcedureCallControlCoverage {
    fn default() -> Self {
        Self {
            source_boundary: Err(FootprintRefusal::UnclassifiedBranch),
            branches: Vec::new(),
            call_target_obligations: Vec::new(),
            admission: Err(FootprintRefusal::UnclassifiedBranch),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallControlKind {
    Syntax,
    ExplicitCall,
    Control,
    InitializationConversion,
    Deferred,
    Callback,
    NestedCallable,
    ImplicitAccess,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallControlDisposition {
    Represented,
    AffirmativelyExcluded(FootprintExclusion),
    Refused(FootprintRefusal),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallControlBranch {
    pub start: usize,
    pub end: usize,
    pub kind: CallControlKind,
    pub disposition: CallControlDisposition,
}

impl ProcedureFootprintCoverage {
    pub fn unclassified() -> Self {
        Self {
            contract_version: FOOTPRINT_COVERAGE_CONTRACT_VERSION,
            boundary: Err(FootprintRefusal::UnclassifiedBranch),
            classes: [FootprintDisposition::Refused(FootprintRefusal::UnclassifiedBranch); 15],
            call_target_obligations: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallTargetObligation {
    pub call: CallSiteId,
    pub gap: SemanticGapId,
    pub impacts: SemanticGapImpacts,
}

type CallGapFactKey = (ProgramPointId, SemanticGapSubject, SemanticCapability);

fn unknown_call_gap_fact(gap: &SemanticGap) -> Option<CallGapFactKey> {
    (gap.kind == SemanticGapKind::Unknown).then_some((gap.point, gap.subject, gap.capability))
}

fn call_gap_pair_keys(call: &SemanticCallSite) -> [CallGapFactKey; 2] {
    [
        (
            call.point,
            SemanticGapSubject::CallSite(call.id),
            SemanticCapability::Calls,
        ),
        (
            call.point,
            SemanticGapSubject::Value(call.callee),
            SemanticCapability::CallableReferences,
        ),
    ]
}

/// Allocation-free lookup for a single query call. Bulk construction uses
/// CallTargetGapIndex with the same keys, avoiding repeated procedure scans.
pub fn call_target_gap_pair<'a>(
    call: &SemanticCallSite,
    gaps: &'a [SemanticGap],
) -> Option<(&'a SemanticGap, &'a SemanticGap)> {
    let unique = |key| {
        let mut matching = gaps
            .iter()
            .filter(|gap| unknown_call_gap_fact(gap) == Some(key));
        let found = matching.next()?;
        matching.next().is_none().then_some(found)
    };
    let [resolution, callable] = call_gap_pair_keys(call);
    Some((unique(resolution)?, unique(callable)?))
}

/// The unresolved-target gap pair of one call site: its unique Unknown Calls
/// gap and its callee's unique Unknown callable-reference gap. A declared
/// discharge is not required here; the obligation stays open until the
/// query-time proof discharges the call. Both coverage writers and the
/// footprint reader apply this pairing.
#[derive(Default)]
pub struct CallTargetGapIndex<'a> {
    facts: brokk_bifrost_core::hash::HashMap<CallGapFactKey, Option<&'a SemanticGap>>,
    callable: brokk_bifrost_core::hash::HashMap<ValueId, Vec<&'a SemanticGap>>,
    dynamic: brokk_bifrost_core::hash::HashMap<CallSiteId, Vec<&'a SemanticGap>>,
}

impl<'a> CallTargetGapIndex<'a> {
    pub fn new(gaps: &'a [SemanticGap]) -> Self {
        let mut index = Self::default();
        for gap in gaps {
            index.insert(gap);
        }
        index
    }

    /// Add one observed gap. Query callers can poll cancellation and admit
    /// temporary residency before inserting, using the same producer predicate.
    pub fn insert(&mut self, gap: &'a SemanticGap) {
        if gap.capability == SemanticCapability::DynamicDispatch
            && let SemanticGapSubject::CallSite(call) = gap.subject
        {
            self.dynamic.entry(call).or_default().push(gap);
        }
        let Some(fact) = unknown_call_gap_fact(gap) else {
            return;
        };
        self.facts
            .entry(fact)
            .and_modify(|previous| *previous = None)
            .or_insert(Some(gap));
        if gap.capability == SemanticCapability::CallableReferences
            && let SemanticGapSubject::Value(value) = gap.subject
        {
            self.callable.entry(value).or_default().push(gap);
        }
    }

    pub fn pair(&self, call: &SemanticCallSite) -> Option<(&'a SemanticGap, &'a SemanticGap)> {
        let [resolution, callable] = call_gap_pair_keys(call);
        Some((
            self.facts.get(&resolution).copied().flatten()?,
            self.facts.get(&callable).copied().flatten()?,
        ))
    }

    pub fn dynamic_gaps(&self, call: CallSiteId) -> &[&'a SemanticGap] {
        self.dynamic.get(&call).map_or(&[], Vec::as_slice)
    }

    pub fn callable_gaps(&self, value: ValueId) -> &[&'a SemanticGap] {
        self.callable.get(&value).map_or(&[], Vec::as_slice)
    }
}

/// A stable category for one validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SemanticIrErrorKind {
    Cancelled,
    ArtifactIdentity,
    ResourceLimit,
    CapabilityContract,
    DenseId,
    OutOfBounds,
    SourceScope,
    LocatorRole,
    DuplicateLocator,
    ParentCycle,
    BlockMembership,
    Boundary,
    ValueFlowContract,
    EventContract,
    ControlFlowContract,
    CallContract,
    CallableContract,
    CaptureContract,
    MemoryContract,
    AsyncContract,
    GapContract,
    DuplicateEdge,
    GuardContract,
    SwitchContract,
    LifecycleContract,
    PointerContract,
}

impl SemanticIrErrorKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Cancelled => "cancelled",
            Self::ArtifactIdentity => "artifact_identity",
            Self::ResourceLimit => "resource_limit",
            Self::CapabilityContract => "capability_contract",
            Self::DenseId => "dense_id",
            Self::OutOfBounds => "out_of_bounds",
            Self::SourceScope => "source_scope",
            Self::LocatorRole => "locator_role",
            Self::DuplicateLocator => "duplicate_locator",
            Self::ParentCycle => "parent_cycle",
            Self::BlockMembership => "block_membership",
            Self::Boundary => "boundary",
            Self::ValueFlowContract => "value_flow_contract",
            Self::EventContract => "event_contract",
            Self::ControlFlowContract => "control_flow_contract",
            Self::CallContract => "call_contract",
            Self::CallableContract => "callable_contract",
            Self::CaptureContract => "capture_contract",
            Self::MemoryContract => "memory_contract",
            Self::AsyncContract => "async_contract",
            Self::GapContract => "gap_contract",
            Self::DuplicateEdge => "duplicate_edge",
            Self::GuardContract => "guard_contract",
            Self::SwitchContract => "switch_contract",
            Self::LifecycleContract => "lifecycle_contract",
            Self::PointerContract => "pointer_contract",
        }
    }
}

/// A construction-time invariant violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticIrError {
    kind: SemanticIrErrorKind,
    procedure: Option<ProcedureId>,
    /// The source construct that violated the invariant: the offending row's
    /// own source mapping when the check has one, otherwise the procedure's
    /// locator. Procedure and row IDs are artifact-local, so without this the
    /// message cannot be traced back to source (#13027).
    source: Option<Box<SemanticLocator>>,
    detail: Box<str>,
}

impl SemanticIrError {
    pub(in crate::analyzer::semantic::ir) fn artifact(
        kind: SemanticIrErrorKind,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            procedure: None,
            source: None,
            detail: detail.into().into_boxed_str(),
        }
    }

    pub(in crate::analyzer::semantic::ir) fn procedure(
        procedure: ProcedureId,
        kind: SemanticIrErrorKind,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            procedure: Some(procedure),
            source: None,
            detail: detail.into().into_boxed_str(),
        }
    }

    /// Name the source construct of this error unless a more specific one is
    /// already attached.
    pub(in crate::analyzer::semantic::ir) fn at_source(
        mut self,
        locator: &SemanticLocator,
    ) -> Self {
        if self.source.is_none() {
            self.source = Some(Box::new(locator.clone()));
        }
        self
    }

    /// Name the source of a procedure-scoped error by the locator of the
    /// procedure it names, when that procedure is one of `procedures`.
    pub(in crate::analyzer::semantic::ir) fn at_procedure_source(
        self,
        procedures: &[ProcedureSemanticsParts],
    ) -> Self {
        match self
            .procedure
            .and_then(|procedure| procedures.get(procedure.index()))
        {
            Some(procedure) => self.at_source(&procedure.locator),
            None => self,
        }
    }

    pub fn source_locator(&self) -> Option<&SemanticLocator> {
        self.source.as_deref()
    }

    pub const fn kind(&self) -> SemanticIrErrorKind {
        self.kind
    }

    pub const fn procedure_id(&self) -> Option<ProcedureId> {
        self.procedure
    }

    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for SemanticIrError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "semantic IR {} error", self.kind.label())?;
        if let Some(procedure) = self.procedure {
            write!(formatter, " in procedure {procedure}")?;
        }
        if let Some(source) = &self.source {
            // Positions are zero-based in the IR; render them one-based. The
            // column counts UTF-8 bytes, so on a line with multi-byte text
            // before the construct it can exceed an editor's column.
            let start = source.anchor().span().start();
            write!(
                formatter,
                " at {}:{}:{} (",
                source.path().as_str(),
                start.line() + 1,
                start.byte_column() + 1
            )?;
            // The path already names the file segment.
            let declarations = source
                .declaration()
                .segments()
                .iter()
                .filter(|segment| segment.kind() != DeclarationSegmentKind::File);
            for (index, segment) in declarations.enumerate() {
                if index > 0 {
                    formatter.write_str(" > ")?;
                }
                let kind = segment.kind().stable_label();
                match segment.name() {
                    Some(name) => write!(formatter, "{kind} {name}")?,
                    None => write!(formatter, "anonymous {kind}")?,
                }
            }
            formatter.write_str(")")?;
        }
        write!(formatter, ": {}", self.detail)
    }
}

impl std::error::Error for SemanticIrError {}
pub use brokk_bifrost_core::analyzer::model::ProcedureKind;

/// Whether a procedure's authored body and signature describe the callable
/// boundary that a call observes.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProcedureCallBoundary {
    /// Calls can be bound to this procedure's receiver, formals, and returns.
    #[default]
    Direct,
    /// A callable transformation may replace the authored boundary.
    Unknown,
}

impl ProcedureCallBoundary {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Unknown => "unknown",
        }
    }
}

/// Whether invoking a callable begins executing its body immediately.
///
/// Some languages publish callable bodies whose invocation only creates a
/// suspended object. Python coroutine and generator functions, JavaScript
/// generators, and Rust async functions are examples. Keeping this separate
/// from `is_async` and `is_generator` avoids incorrectly applying one
/// language's call semantics to another language with the same surface
/// property.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProcedureInvocationKind {
    #[default]
    Immediate,
    Deferred,
    /// PLACEHOLDER persisted discriminant 2; finalize in landing order (#12128).
    /// The body can be analyzed locally, but invoking it only constructs a future.
    DeferredBody,
}

impl ProcedureInvocationKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Immediate => "immediate",
            Self::Deferred => "deferred",
            Self::DeferredBody => "deferred_body",
        }
    }

    pub const fn is_deferred(self) -> bool {
        matches!(self, Self::Deferred | Self::DeferredBody)
    }
}

/// Whether dispatch participates in an ordinary caller-local call operation
/// or starts detached work. This is deliberately orthogonal to
/// [`ExecutionTiming`] and [`ProcedureInvocationKind`]: `Ordinary` preserves
/// caller-local continuations and result transfer but does not claim that an
/// async or generator target body executes synchronously. Detached work may
/// use any timing a language proves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CallInvocationMode {
    Ordinary,
    Detached,
}

impl CallInvocationMode {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ordinary => "ordinary",
            Self::Detached => "detached",
        }
    }
}

/// When the target of a semantic relation is evaluated, relative to the
/// evaluation that triggered it (issue #2446).
///
/// This is the analyzer's one execution-timing vocabulary. It applies both to
/// value-flow relations and to call/effect execution: "lexically inside" is
/// not "executes now", so a producer that has no scheduling evidence must say
/// [`ExecutionTiming::Unknown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExecutionTiming {
    /// Source and target belong to one indivisible program-point evaluation.
    SameEvaluation,
    /// The target runs later in the same synchronous procedure invocation.
    SameInvocation,
    /// The target runs later in the same cooperative scheduler turn.
    LaterSameTurn,
    /// The target runs after its task suspended and resumed.
    AfterSuspension,
    /// The target runs in a different task or goroutine.
    DifferentTask,
    /// The target runs on a different thread.
    DifferentThread,
    /// Another component retains or schedules the target for later execution.
    DeferredCallback,
    /// A consumer resumes a suspended generator or iterator.
    GeneratorResume,
    /// The target runs while an activation unwinds or is cancelled.
    CancellationCleanup,
    /// Available evidence does not establish execution timing.
    Unknown,
}

impl ExecutionTiming {
    /// The stable value domain shared by timing-bearing public facts.
    pub const LABELS: &'static [&'static str] = &[
        "same_evaluation",
        "same_invocation",
        "later_same_turn",
        "after_suspension",
        "different_task",
        "different_thread",
        "deferred_callback",
        "generator_resume",
        "cancellation_cleanup",
        "unknown",
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::SameEvaluation => "same_evaluation",
            Self::SameInvocation => "same_invocation",
            Self::LaterSameTurn => "later_same_turn",
            Self::AfterSuspension => "after_suspension",
            Self::DifferentTask => "different_task",
            Self::DifferentThread => "different_thread",
            Self::DeferredCallback => "deferred_callback",
            Self::GeneratorResume => "generator_resume",
            Self::CancellationCleanup => "cancellation_cleanup",
            Self::Unknown => "unknown",
        }
    }

    /// Whether the target remains in the trigger's synchronous activation.
    pub const fn is_synchronous(self) -> bool {
        matches!(self, Self::SameEvaluation | Self::SameInvocation)
    }

    /// Compose timing across one exact call edge.
    ///
    /// `self` is when the call executes relative to its caller and `nested` is
    /// when a callee effect executes relative to that call. The deliberately
    /// small exact table covers the call modes and declared-effect timings the
    /// current producers emit. Richer combinations fail open as `Unknown`.
    pub const fn compose(self, nested: Self) -> Self {
        match (self, nested) {
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            (Self::SameEvaluation, nested) => nested,
            (outer, Self::SameEvaluation) => outer,
            (Self::SameInvocation, Self::SameInvocation) => Self::SameInvocation,
            (Self::SameInvocation, Self::DifferentTask) => Self::DifferentTask,
            (Self::SameInvocation, Self::DifferentThread) => Self::DifferentThread,
            (Self::SameInvocation, Self::DeferredCallback) => Self::DeferredCallback,
            (Self::DifferentTask, Self::SameInvocation) => Self::DifferentTask,
            (Self::DifferentThread, Self::SameInvocation) => Self::DifferentThread,
            _ => Self::Unknown,
        }
    }

    /// Join independent paths attributing the same effect.
    pub const fn join(self, other: Self) -> Self {
        if self as u8 == other as u8 {
            self
        } else {
            Self::Unknown
        }
    }
}

/// Which value supplies a method receiver when selected through a type.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProcedureReceiverBinding {
    /// The caller passes an instance explicitly when the method is unbound.
    #[default]
    Instance,
    /// The descriptor binds the type object used to select the method.
    Class,
}

impl ProcedureReceiverBinding {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Instance => "instance",
            Self::Class => "class",
        }
    }
}

/// Whether an initializer's normal return can replace the allocated instance.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConstructionReturn {
    /// Return values retain their ordinary transport, including languages
    /// whose constructors can return a replacement object.
    #[default]
    MayReplaceAllocation,
    /// Construction yields the allocation; a direct initializer call still
    /// yields the initializer's own normal return value.
    PreservesAllocation,
}

impl ConstructionReturn {
    pub const fn label(self) -> &'static str {
        match self {
            Self::MayReplaceAllocation => "may_replace_allocation",
            Self::PreservesAllocation => "preserves_allocation",
        }
    }
}

/// Orthogonal properties that should not be encoded in [`ProcedureKind`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcedureProperties {
    pub is_async: bool,
    pub is_generator: bool,
    pub is_static: bool,
    pub is_synthetic: bool,
    pub invocation: ProcedureInvocationKind,
    pub dispatch_extensibility: DispatchExtensibility,
    pub call_boundary: ProcedureCallBoundary,
    pub receiver_binding: ProcedureReceiverBinding,
    pub construction_return: ConstructionReturn,
}

/// The positional or keyword domain accepted or produced at a call boundary.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ArgumentDomain {
    Positional,
    Keyword,
    PositionalOrKeyword,
    LanguageDefined(Box<str>),
}

impl ArgumentDomain {
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Positional => "positional",
            Self::Keyword => "keyword",
            Self::PositionalOrKeyword => "positional_or_keyword",
            Self::LanguageDefined(_) => "language_defined",
        }
    }

    pub(crate) const fn accepts_positional(&self) -> bool {
        matches!(self, Self::Positional | Self::PositionalOrKeyword)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub enum FormalMultiplicity {
    #[default]
    One,
    Rest(ArgumentDomain),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum FormalParameterPassingMode {
    PositionalOnly,
    #[default]
    PositionalOrNamed,
    NamedOnly,
}

impl FormalParameterPassingMode {
    pub const fn accepts_positional(self) -> bool {
        self.argument_domain().accepts_positional()
    }

    pub const fn accepts_named(self) -> bool {
        matches!(self, Self::PositionalOrNamed | Self::NamedOnly)
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::PositionalOnly => "positional_only",
            Self::PositionalOrNamed => "positional_or_named",
            Self::NamedOnly => "named_only",
        }
    }

    const fn argument_domain(self) -> &'static ArgumentDomain {
        match self {
            Self::PositionalOnly => &ArgumentDomain::Positional,
            Self::PositionalOrNamed => &ArgumentDomain::PositionalOrKeyword,
            Self::NamedOnly => &ArgumentDomain::Keyword,
        }
    }
}

impl FormalMultiplicity {
    pub const fn label(&self) -> &'static str {
        match self {
            Self::One => "one",
            Self::Rest(_) => "rest",
        }
    }

    pub const fn is_rest(&self) -> bool {
        matches!(self, Self::Rest(_))
    }
}

/// The declared ownership form of a method's receiver. This declaration is
/// not evidence that a particular call actually borrowed or moved its value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum ReceiverMode {
    #[default]
    Unknown,
    SharedBorrow,
    MutableBorrow,
    Owned,
}

/// The semantic role of a value row.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SemanticValueKind {
    Local,
    Parameter {
        ordinal: u32,
        multiplicity: FormalMultiplicity,
        name: Option<Box<str>>,
        passing_mode: FormalParameterPassingMode,
    },
    /// The value saved when the procedure definition evaluated a default
    /// expression for the non-rest formal at `ordinal`.
    ///
    /// This is a definition-time value carrier. It is not an executable
    /// per-call computation and does not imply a fresh allocation on each
    /// invocation; a call-binding relation selects it only when that formal
    /// is omitted by a call.
    DefaultArgument {
        ordinal: u32,
    },
    /// The procedure's receiver formal. `dispatch` states whether the value
    /// is the object the call dispatches on (`this`/`self`), as opposed to a
    /// passed-in receiver -- a Kotlin or Scala extension receiver -- that
    /// binds like a parameter and is never the caller's own `this`.
    Receiver {
        dispatch: bool,
        mode: ReceiverMode,
    },
    Return,
    Temporary,
    /// A language-level address or reference value derived from another
    /// semantic value. The structured assignment into this value records the
    /// referenced source without conflating ordinary value propagation with
    /// address creation.
    Address,
    /// The language's distinguished null or nil value.
    Null,
    /// A compile-time Boolean value.
    Boolean(bool),
    /// A non-negative compile-time integer magnitude that fits in `u128`.
    UnsignedInteger(u128),
    /// A compile-time integer with a signed payload. Producers must establish
    /// the language's literal and conversion rules before publishing it.
    SignedInteger(i128),
    /// A compile-time finite IEEE 754 binary64 value, as its exact bit
    /// pattern. Producers apply the language's literal rounding, including a
    /// narrower source type such as Java `float`, before publishing it; a
    /// binary32 value widens to binary64 exactly.
    FloatingPoint {
        bits: u64,
    },
    /// A compile-time constant whose payload is not represented structurally.
    Constant,
    /// A language-defined constant key. Equal payloads denote the same
    /// constant; unequal payloads do not prove different values. A payload may
    /// be a literal's spelling or a synthetic label. Obtain its string value
    /// through LanguageKnowledge::semantic_string_constant_value rather than
    /// treating the key as decoded text.
    ConstantString(Box<str>),
    Exception,
    Callable,
    AwaitResult,
    LanguageDefined(Box<str>),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CallArgumentExpansion {
    Unclassified,
    Direct(ArgumentDomain),
    Spread(ArgumentDomain),
}

impl CallArgumentExpansion {
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Unclassified => "unclassified",
            Self::Direct(_) => "direct",
            Self::Spread(_) => "spread",
        }
    }

    pub const fn domain(&self) -> Option<&ArgumentDomain> {
        match self {
            Self::Unclassified => None,
            Self::Direct(domain) | Self::Spread(domain) => Some(domain),
        }
    }

    pub const fn is_spread(&self) -> bool {
        matches!(self, Self::Spread(_))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SemanticCallArgument {
    pub value: ValueId,
    pub expansion: CallArgumentExpansion,
    /// The canonical name written by a direct keyword argument. `None` on a
    /// direct keyword preserves a structured keyword domain whose key is not
    /// statically nameable, such as a Ruby pair with a dynamic key.
    pub keyword: Option<Box<str>>,
}

impl SemanticCallArgument {
    /// Construct a direct argument when structured lowering established that
    /// the source is not a spread and identified its argument domain.
    pub fn direct(value: ValueId, domain: ArgumentDomain) -> Self {
        Self {
            value,
            expansion: CallArgumentExpansion::Direct(domain),
            keyword: None,
        }
    }

    pub fn keyword(value: ValueId, name: impl Into<Box<str>>) -> Self {
        Self {
            value,
            expansion: CallArgumentExpansion::Direct(ArgumentDomain::Keyword),
            keyword: Some(name.into()),
        }
    }

    /// Preserve the pre-v5 contract without manufacturing direct/spread or
    /// positional/keyword semantics. Adapters refine this row only from their
    /// structured syntax.
    pub fn unclassified(value: ValueId) -> Self {
        Self {
            value,
            expansion: CallArgumentExpansion::Unclassified,
            keyword: None,
        }
    }
}

impl From<ValueId> for SemanticCallArgument {
    fn from(value: ValueId) -> Self {
        Self::unclassified(value)
    }
}

impl SemanticValueKind {
    /// Whether this value denotes a local, formal parameter, or receiver binding.
    pub const fn is_binding(&self) -> bool {
        matches!(
            self,
            Self::Local | Self::Parameter { .. } | Self::Receiver { .. }
        )
    }

    pub fn is_language_defined(&self, expected: &str) -> bool {
        matches!(self, Self::LanguageDefined(kind) if kind.as_ref() == expected)
    }

    pub const fn label(&self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Parameter { .. } => "parameter",
            Self::DefaultArgument { .. } => "default_argument",
            Self::Receiver { .. } => "receiver",
            Self::Return => "return",
            Self::Temporary => "temporary",
            Self::Address => "address",
            Self::Null => "null",
            Self::Boolean(_) => "boolean",
            Self::UnsignedInteger(_) => "unsigned_integer",
            Self::SignedInteger(_) => "signed_integer",
            Self::FloatingPoint { .. } => "floating_point",
            Self::Constant => "constant",
            Self::ConstantString(_) => "constant_string",
            Self::Exception => "exception",
            Self::Callable => "callable",
            Self::AwaitResult => "await_result",
            Self::LanguageDefined(_) => "language_defined",
        }
    }

    /// Whether the value carries an integer the IR represents exactly. An
    /// ordered integer guard compares against only such a value, so a
    /// lowering decides from this predicate and the validator enforces it.
    pub const fn is_represented_integer(&self) -> bool {
        matches!(self, Self::UnsignedInteger(_) | Self::SignedInteger(_))
    }

    pub const fn is_constant(&self) -> bool {
        matches!(
            self,
            Self::Null
                | Self::Boolean(_)
                | Self::UnsignedInteger(_)
                | Self::SignedInteger(_)
                | Self::FloatingPoint { .. }
                | Self::Constant
                | Self::ConstantString(_)
        )
    }
}

/// How a value of a static type is represented, from its underlying type and
/// independent of payload identity. A consumer decides from it whether a
/// conversion copies the value or keeps its identity.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum StaticTypeClass {
    /// Not proven: an unresolved or generic type, or a value whose static
    /// type the producer could not follow.
    #[default]
    Unknown = 0,
    Interface = 1,
    Pointer = 2,
    /// A handle whose copies share one referent: a function, map, channel
    /// or slice.
    Reference = 3,
    /// Copied on assignment: a struct, array or basic type.
    Value = 4,
}

/// Where a consumer finds the static type of a value whose class the
/// producer left `Unknown`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StaticTypeOrigin {
    /// The `ordinal`th normal result of `call`; the class is the callee's
    /// declared result class.
    CallResult { call: CallSiteId, ordinal: u32 },
}

/// The actual expression-level borrow emitted by the language adapter.
/// Declaration passing modes do not establish this fact. Missing and old
/// persisted rows are Unknown, including every non-address value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ActualBorrowKind {
    #[default]
    Unknown = 0,
    Shared = 1,
    Mutable = 2,
    Raw = 3,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SemanticValue {
    pub actual_borrow: ActualBorrowKind,
    pub id: ValueId,
    pub kind: SemanticValueKind,
    pub source: SourceMappingId,
    pub evidence: EvidenceId,
    pub static_type_class: StaticTypeClass,
    pub static_type_origin: Option<StaticTypeOrigin>,
}

/// The abstract allocation represented by an allocation-site row.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AllocationKind {
    Object,
    Array,
    /// One fresh backing store whose slice values may share element storage.
    Slice,
    Callable,
    ClosureEnvironment,
    SharedCell,
    LanguageDefined(Box<str>),
}

impl AllocationKind {
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Object => "object",
            Self::Array => "array",
            Self::Slice => "slice",
            Self::Callable => "callable",
            Self::ClosureEnvironment => "closure_environment",
            Self::SharedCell => "shared_cell",
            Self::LanguageDefined(_) => "language_defined",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AllocationSite {
    pub id: AllocationId,
    pub point: ProgramPointId,
    pub result: ValueId,
    pub kind: AllocationKind,
    pub source: SourceMappingId,
    pub evidence: EvidenceId,
}

/// One abstract addressable location.  This does not claim a concrete runtime
/// object identity; later heap oracles can refine it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MemoryLocationKind {
    Field {
        base: ValueId,
        member: SemanticLocator,
    },
    /// A property whose key is known from syntax but has no declaration
    /// locator (for example `process.env.DFB_INPUT`).
    Property {
        base: ValueId,
        key: String,
    },
    Static {
        member: SemanticLocator,
    },
    Index {
        base: ValueId,
        index: Option<ValueId>,
        /// Exact non-negative integer magnitude when the adapter proved one.
        ///
        /// `index` retains the evaluated value and its evidence. This field is
        /// the arithmetic identity used to compose bounded backing-store
        /// views without recovering a number from source text.
        constant_index: Option<u128>,
        identity: IndexedLocationIdentity,
    },
    /// The whole object named by a pointer value. This is not a field of the
    /// pointer value; the address resolves to the storage being read or
    /// written.
    Dereference {
        address: ValueId,
    },
    /// A creator-local mutable cell backing a lexical binding.  This is the
    /// principled source for shared/mutable captures in languages whose
    /// closure conversion boxes locals; it is not an indexed heap access.
    LexicalCell {
        binding: ValueId,
    },
    /// A child-procedure slot populated by one or more capture bindings in
    /// its lexical parent.  The slot does not name one creation site: the
    /// same body slot can be populated at several static creation points and
    /// by many runtime environment instances.
    Capture {
        lexical_parent: ProcedureId,
        binding: Option<ValueId>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IndexedLocationIdentity {
    Element,
    Aggregate,
}

impl IndexedLocationIdentity {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Element => "element",
            Self::Aggregate => "aggregate",
        }
    }
}

impl MemoryLocationKind {
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Field { .. } => "field",
            Self::Property { .. } => "property",
            Self::Static { .. } => "static",
            Self::Index { .. } => "index",
            Self::Dereference { .. } => "dereference",
            Self::LexicalCell { .. } => "lexical_cell",
            Self::Capture { .. } => "capture",
        }
    }

    /// Whether this location's structured identity consumes `value` as its
    /// base, index, or lexical binding.
    pub fn uses_value(&self, value: ValueId) -> bool {
        match self {
            Self::Field { base, .. } => *base == value,
            Self::Property { base, .. } => *base == value,
            Self::Index { base, index, .. } => *base == value || *index == Some(value),
            Self::Dereference { address } => *address == value,
            Self::LexicalCell { binding } => *binding == value,
            Self::Capture { binding, .. } => *binding == Some(value),
            Self::Static { .. } => false,
        }
    }
}

/// How assigning a language value to a memory slot preserves heap identity.
///
/// This fact describes the value held by the slot, independently of the
/// slot's own storage. Consumers must still prove which store reaches a load
/// before applying it. `Unknown` never implies either reference identity or
/// an inline value copy.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemoryValueCopy {
    #[default]
    Unknown,
    /// The stored value has its own inline identity after the copy.
    Value,
    /// The copied value denotes the same referenced runtime object.
    Reference,
    /// The copied descriptor denotes the same indexed backing store.
    BackingStore { identity: IndexedLocationIdentity },
}

impl MemoryValueCopy {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Value => "value",
            Self::Reference => "reference",
            Self::BackingStore { .. } => "backing_store",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MemoryLocation {
    pub id: MemoryLocationId,
    pub kind: MemoryLocationKind,
    pub value_copy: MemoryValueCopy,
    pub source: SourceMappingId,
    pub evidence: EvidenceId,
}

/// How a closure environment obtains one captured binding.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CaptureMode {
    Value,
    Move,
    SharedCell,
    MutableCell,
    Receiver,
    LanguageDefined(Box<str>),
    Unknown,
}

impl CaptureMode {
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Value => "value",
            Self::Move => "move",
            Self::SharedCell => "shared_cell",
            Self::MutableCell => "mutable_cell",
            Self::Receiver => "receiver",
            Self::LanguageDefined(_) => "language_defined",
            Self::Unknown => "unknown",
        }
    }
}

/// The captured entity is deliberately either a value snapshot/move or a
/// shared abstract location.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CaptureSource {
    Value(ValueId),
    Location(MemoryLocationId),
}

impl CaptureSource {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Value(_) => "value",
            Self::Location(_) => "location",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CaptureBinding {
    pub id: CaptureId,
    pub point: ProgramPointId,
    pub callable: ValueId,
    pub target: ProcedureId,
    pub environment: AllocationId,
    pub captured: CaptureSource,
    /// A memory-location ID in `target`, not in the procedure that owns this
    /// binding.  The explicit target scopes this otherwise procedure-local ID.
    pub destination: MemoryLocationId,
    pub mode: CaptureMode,
    pub source: SourceMappingId,
    pub evidence: EvidenceId,
}

/// Exact source identity for an artifact-backed anonymous callable.
///
/// Construction requires the language adapter's fresh source proof. The
/// descriptor identifies a body to materialize; it does not prove invocation
/// or bind one creation's captured environment. No materialized graph is
/// retained by this durable target.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ArtifactCallableTarget {
    identity: Box<crate::analyzer::semantic_model::AnonymousCallableIdentity>,
}

impl ArtifactCallableTarget {
    #[doc(hidden)]
    pub fn from_bound_identity(
        identity: crate::analyzer::semantic_model::AnonymousCallableIdentity,
    ) -> Self {
        Self {
            identity: Box::new(identity),
        }
    }

    pub fn identity(&self) -> &crate::analyzer::semantic_model::AnonymousCallableIdentity {
        &self.identity
    }
}

/// A resolved local body or a durable external declaration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CallableTarget {
    Local(ProcedureId),
    /// A declaration in this artifact whose procedure body was not published
    /// because materialization was incomplete.  This form is legal only in an
    /// explicitly unproven or budget-exceeded candidate set.
    Unmaterialized(SemanticLocator),
    External(SemanticLocator),
    Artifact(ArtifactCallableTarget),
}

impl CallableTarget {
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Local(_) => "local",
            Self::Unmaterialized(_) => "unmaterialized",
            Self::External(_) => "external",
            Self::Artifact(_) => "artifact",
        }
    }
}

/// Resolution and proof are intentionally not collapsed into an optional
/// target.  Partial candidates survive unproven and budget-limited outcomes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CallableTargetResolution {
    Proven(CallableTarget),
    Ambiguous(Box<[CallableTarget]>),
    Unknown,
    Unsupported,
    Unproven(Box<[CallableTarget]>),
    ExceededBudget(Box<[CallableTarget]>),
}

impl CallableTargetResolution {
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Proven(_) => "proven",
            Self::Ambiguous(_) => SemanticGapKind::Ambiguous.label(),
            Self::Unknown => SemanticGapKind::Unknown.label(),
            Self::Unsupported => SemanticGapKind::Unsupported.label(),
            Self::Unproven(_) => SemanticGapKind::Unproven.label(),
            Self::ExceededBudget(_) => SemanticGapKind::ExceededBudget.label(),
        }
    }

    pub fn candidates(&self) -> &[CallableTarget] {
        match self {
            Self::Proven(target) => std::slice::from_ref(target),
            Self::Ambiguous(targets) | Self::Unproven(targets) | Self::ExceededBudget(targets) => {
                targets
            }
            Self::Unknown | Self::Unsupported => &[],
        }
    }
}

/// Callable values distinguish evaluation from invocation and distinguish
/// whether receiver binding happened when the reference was evaluated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CallableReferenceKind {
    Lambda,
    Function,
    BoundMethod,
    UnboundMethod,
    /// A callable selected through a proven imported module namespace. The
    /// qualifier participates in name lookup but is not a bound receiver.
    ModuleQualified {
        qualifier: ValueId,
    },
    /// A member selected through a proven type object. The resolved method's
    /// receiver contract decides whether the qualifier or a written actual
    /// supplies its receiver; the qualifier is not itself a bound receiver.
    TypeQualifiedMethod {
        qualifier: ValueId,
    },
    StaticMethod,
    Constructor,
}

impl CallableReferenceKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Lambda => "lambda",
            Self::Function => "function",
            Self::BoundMethod => "bound_method",
            Self::UnboundMethod => "unbound_method",
            Self::ModuleQualified { .. } => "module_qualified",
            Self::TypeQualifiedMethod { .. } => "type_qualified_method",
            Self::StaticMethod => "static_method",
            Self::Constructor => "constructor",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallableValue {
    pub kind: CallableReferenceKind,
    pub targets: CallableTargetResolution,
    /// Evidence for target resolution, distinct from the event evidence that
    /// establishes evaluation of the callable value.
    pub target_evidence: EvidenceId,
    pub bound_receiver: Option<ValueId>,
    /// Present only when evaluating this callable allocates a capture
    /// environment.  Repeated evaluations can therefore share a body target
    /// while retaining distinct allocation sites.
    pub environment: Option<AllocationId>,
}

impl CallableValue {
    #[doc(hidden)]
    pub fn unknown_target(kind: CallableReferenceKind, target_evidence: EvidenceId) -> Self {
        Self {
            kind,
            targets: CallableTargetResolution::Unknown,
            target_evidence,
            bound_receiver: None,
            environment: None,
        }
    }
}

/// A caller-side receiver fact established at one call site.
///
/// This describes evaluation of the callable value, not whether a resolved
/// target declares a receiver-like formal. In particular, a method selected
/// through a type can require target-specific binding even though the caller
/// did not evaluate a bound receiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CallerReceiverBinding {
    Absent,
    Bound(ValueId),
    ModuleQualified(ValueId),
    TypeQualified(ValueId),
}

/// The intraprocedural destination of one normal, exceptional, or async arm.
///
/// `Absent` is a proven semantic absence, such as the normal arm of a
/// diverging call.  The other non-target variants require a matching
/// [`SemanticGap`] and never license an adapter to fabricate an edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ControlContinuation {
    Target(ProgramPointId),
    Absent,
    Unknown,
    Unsupported,
    Unproven,
    ExceededBudget,
}

impl ControlContinuation {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Target(_) => "target",
            Self::Absent => "absent",
            Self::Unknown => "unknown",
            Self::Unsupported => "unsupported",
            Self::Unproven => "unproven",
            Self::ExceededBudget => "exceeded_budget",
        }
    }

    pub const fn target(self) -> Option<ProgramPointId> {
        match self {
            Self::Target(target) => Some(target),
            Self::Absent
            | Self::Unknown
            | Self::Unsupported
            | Self::Unproven
            | Self::ExceededBudget => None,
        }
    }
}

/// A member invocation whose field-versus-method interpretation requires
/// declaration lookup. The owning call row supplies the exact call occurrence
/// and evaluated receiver value; the member name is not an occurrence key.
///
/// A method binds either an address or a value copy according to its declared
/// receiver and the operand's static pointer depth. A function-valued field is
/// loaded before invocation. An unresolved selection remains open and may
/// write through the receiver; consumers must invalidate the affected place
/// rather than retain its pre-call value. Selecting an interface method never
/// passes the interface variable itself by address.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DeferredMemberSelection {
    pub member: Box<str>,
    /// Storage of the written receiver, when structurally addressable. This
    /// does not itself assert that the call passes that storage by address.
    pub receiver_place: Option<SemanticPlace>,
    /// Pointer indirections in the receiver's static type; None retains an
    /// unknown type rather than guessing a non-pointer receiver.
    pub receiver_pointer_depth: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SemanticCallSite {
    pub id: CallSiteId,
    pub point: ProgramPointId,
    /// Whether this is an ordinary caller-local call operation or a detached
    /// spawn. Target-level async/generator behavior is refined separately.
    pub invocation_mode: CallInvocationMode,
    /// When this invocation executes relative to the source construct that
    /// registered or started it. The call row's source/evidence pair proves
    /// this fact; `Unknown` is never interpreted as synchronous execution.
    pub execution_timing: ExecutionTiming,
    pub callee: ValueId,
    /// The evaluated call receiver, or a module namespace qualifier when the
    /// callable reference is `ModuleQualified`.
    pub receiver: Option<ValueId>,
    /// Deferred field/method selection on this call's evaluated receiver.
    pub member_selection: Option<Box<DeferredMemberSelection>>,
    pub arguments: Box<[SemanticCallArgument]>,
    /// Ordered normal results for a language call that returns more than one
    /// independent value. This is mutually exclusive with `result` and must
    /// contain at least two values when non-empty.
    pub normal_results: Box<[ValueId]>,
    /// The normal result for a call with exactly one result.
    pub result: Option<ValueId>,
    pub thrown: Option<ValueId>,
    /// Targets named or established by local syntax/declaration semantics.
    /// Whole-program receiver and dynamic-dispatch refinement belongs to the
    /// `DispatchOracle` introduced by issue #816.
    pub declared_targets: CallableTargetResolution,
    /// Evidence for the declared/syntactic target set, distinct from evidence
    /// that the call occurrence itself exists.
    pub target_evidence: EvidenceId,
    pub normal_continuation: ControlContinuation,
    pub exceptional_continuation: ControlContinuation,
    pub source: SourceMappingId,
    pub evidence: EvidenceId,
}

impl SemanticCallSite {
    /// Return one normal result by its zero-based language ordinal.
    pub fn normal_result(&self, index: usize) -> Option<ValueId> {
        if self.normal_results.is_empty() {
            (index == 0).then_some(self.result).flatten()
        } else {
            self.normal_results.get(index).copied()
        }
    }

    pub fn normal_result_values(&self) -> impl Iterator<Item = ValueId> + '_ {
        self.normal_results.iter().copied().chain(self.result)
    }

    /// Returns whether `target` consumes one of this call's ordinary results.
    ///
    /// This relation establishes evaluation order without depending on source
    /// ranges: this producer must complete before the consuming call begins.
    pub fn normal_result_is_argument_to(&self, target: &Self) -> bool {
        target.arguments.iter().any(|argument| {
            self.result == Some(argument.value) || self.normal_results.contains(&argument.value)
        })
    }
}

/// The relation represented by a portable source mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceMappingKind {
    Exact,
    Enclosing,
    Synthetic,
}

impl SourceMappingKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Enclosing => "enclosing",
            Self::Synthetic => "synthetic",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SourceMapping {
    pub id: SourceMappingId,
    pub locator: SemanticLocator,
    pub kind: SourceMappingKind,
    /// Exact normalized structural fact identity when this mapping was
    /// produced from a supported structural node. Ordinary mappings retain
    /// `None` rather than inferring identity from their source range.
    pub ast_identity: Option<StructuralNodeIdentity>,
}

/// One producer-attested entry into an executable source statement.
///
/// A statement may have several entries when cleanup is specialized for
/// distinct completions. Its entry point can also be shared with an enclosing
/// statement, so the source mapping names the statement itself rather than
/// inheriting the point's source mapping.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StatementEntrySite {
    pub source: SourceMappingId,
    pub evidence: EvidenceId,
    pub point: ProgramPointId,
}

/// One producer-attested source loop: the point each new iteration re-enters
/// and the entry of the loop body.
///
/// The header is the target of the loop's own repeat: the condition or loop
/// point of a `while` or `for`, and the body entry of a `do`. A labeled loop
/// may share its header with the label. The source mapping names the loop
/// statement itself.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LoopSite {
    pub source: SourceMappingId,
    pub evidence: EvidenceId,
    pub header: ProgramPointId,
    pub body: ProgramPointId,
}

/// Whether the evidence actually establishes the attached fact.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ProofStatus {
    Proven,
    Unproven(Box<str>),
}

impl ProofStatus {
    #[doc(hidden)]
    pub const fn establishes_complete_evidence(&self, completeness: &EvidenceCompleteness) -> bool {
        matches!(self, Self::Proven) && matches!(completeness, EvidenceCompleteness::Complete)
    }

    pub fn retained_heap_bytes(&self) -> usize {
        retained_reason_heap_bytes(match self {
            Self::Proven => None,
            Self::Unproven(reason) => Some(reason),
        })
    }
}

impl ProofStatus {
    /// The value domain the `proof` row fields fed by this status publish
    /// (issue #2515).
    pub const LABELS: &'static [&'static str] = &["proven", "unproven"];

    pub const fn label(&self) -> &'static str {
        match self {
            Self::Proven => "proven",
            Self::Unproven(_) => "unproven",
        }
    }
}

/// Whether evidence covers all semantics at the attached site.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EvidenceCompleteness {
    Complete,
    Partial(Box<str>),
}

impl EvidenceCompleteness {
    pub fn retained_heap_bytes(&self) -> usize {
        retained_reason_heap_bytes(match self {
            Self::Complete => None,
            Self::Partial(reason) => Some(reason),
        })
    }
}

fn retained_reason_heap_bytes(reason: Option<&str>) -> usize {
    reason.map_or(0, str::len)
}

impl EvidenceCompleteness {
    /// The value domain the `completeness` row fields fed by this status
    /// publish (issue #2515).
    pub const LABELS: &'static [&'static str] = &["complete", "partial"];

    pub const fn label(&self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Partial(_) => "partial",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Evidence {
    pub id: EvidenceId,
    pub proof: ProofStatus,
    pub completeness: EvidenceCompleteness,
    pub sources: Box<[SourceMappingId]>,
}

/// A missing-semantic reason.  These states are facts in the artifact, not
/// implicit absence and never permission to synthesize an edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SemanticGapKind {
    Ambiguous,
    Unknown,
    Unsupported,
    Unproven,
    ExceededBudget,
}

impl SemanticGapKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ambiguous => "ambiguous",
            Self::Unknown => "unknown",
            Self::Unsupported => "unsupported",
            Self::Unproven => "unproven",
            Self::ExceededBudget => "exceeded_budget",
        }
    }
}

/// The exact local fact whose semantics are incomplete.
///
/// A subject prevents one broad gap at a program point from silently
/// legitimizing unrelated values, calls, continuations, or capture slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SemanticGapSubject {
    Procedure,
    /// Caller-visible effects of constructing a future, distinct from its body.
    FutureConstruction,
    /// Conversion/polling and output effects of activating a future.
    FutureActivation,
    Point,
    Value(ValueId),
    CleanupOwners(super::CleanupSegment),
    MemoryLocation(MemoryLocationId),
    Capture(CaptureId),
    CallSite(CallSiteId),
    CallContinuation {
        call_site: CallSiteId,
        kind: CallContinuationKind,
    },
    AsyncContinuation {
        suspend: ProgramPointId,
        kind: AsyncResumeKind,
    },
}

/// Stable identity of one borrowed logical member of a compact cleanup gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GapMemberRef {
    pub base_gap_id: SemanticGapId,
    pub owner: ValueId,
}

/// Procedure-local identity of a discharge verdict.
/// Compact rows use Gap only for owner-independent predicates. Owner-specific
/// proofs always use Member and never discharge the other owners.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GapKey {
    Gap(SemanticGapId),
    Member(GapMemberRef),
}

impl GapKey {
    /// An owner-independent stored-gap verdict also covers its logical members.
    /// Only uniform predicates may record a compact row's Gap key; owner proofs
    /// always record Member keys and cannot discharge sibling owners.
    pub fn is_discharged_by(self, mut contains: impl FnMut(Self) -> bool) -> bool {
        contains(self)
            || match self {
                Self::Member(member) => contains(Self::Gap(member.base_gap_id)),
                Self::Gap(_) => false,
            }
    }
}

/// Borrowed logical gap; member identity never allocates a global gap ID.
#[derive(Debug, Clone, Copy)]
pub struct LogicalGapRef<'a> {
    pub base: &'a SemanticGap,
    pub member: Option<GapMemberRef>,
}
impl LogicalGapRef<'_> {
    pub fn key(self) -> GapKey {
        self.member
            .map_or(GapKey::Gap(self.base.id), GapKey::Member)
    }

    pub fn subject(self) -> SemanticGapSubject {
        self.member.map_or(self.base.subject, |member| {
            SemanticGapSubject::Value(member.owner)
        })
    }
}

impl SemanticGapSubject {
    /// Whether the old point/value guard holds for the logical subjects.
    /// Compact rows use the shared ancestry index, without owner postings.
    pub fn is_point_or_value(self, chains: &super::CleanupChains) -> bool {
        match self {
            Self::Point | Self::Value(_) => true,
            Self::CleanupOwners(segment) => chains.has_member_owners(segment),
            _ => false,
        }
    }

    /// Exact value-subject membership without expanding compact owner sets.
    pub fn contains_value(self, chains: &super::CleanupChains, value: ValueId) -> bool {
        match self {
            Self::Value(subject) => subject == value,
            Self::CleanupOwners(segment) => chains.contains_owner(segment, value),
            _ => false,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Procedure => "procedure",
            Self::FutureConstruction => "future_construction",
            Self::FutureActivation => "future_activation",
            Self::Point => "point",
            Self::Value(_) => "value",
            Self::CleanupOwners(_) => "cleanup_owners",
            Self::MemoryLocation(_) => "memory_location",
            Self::Capture(_) => "capture",
            Self::CallSite(_) => "call_site",
            Self::CallContinuation { .. } => "call_continuation",
            Self::AsyncContinuation { .. } => "async_continuation",
        }
    }
}

/// One semantic consumer concern that an explicit gap may invalidate.
///
/// Gap impacts are deliberately independent of language and capability names.
/// Consumers can therefore select only the uncertainty that affects their
/// operation without importing adapter-specific knowledge.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SemanticGapImpact {
    DispatchCoverage,
    CallEvaluation,
    ReturnTransfer,
    ValueFlow,
    HeapRead,
    HeapWrite,
    Aliasing,
}

impl SemanticGapImpact {
    pub const ALL: [Self; 7] = [
        Self::DispatchCoverage,
        Self::CallEvaluation,
        Self::ReturnTransfer,
        Self::ValueFlow,
        Self::HeapRead,
        Self::HeapWrite,
        Self::Aliasing,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::DispatchCoverage => "dispatch_coverage",
            Self::CallEvaluation => "call_evaluation",
            Self::ReturnTransfer => "return_transfer",
            Self::ValueFlow => "value_flow",
            Self::HeapRead => "heap_read",
            Self::HeapWrite => "heap_write",
            Self::Aliasing => "aliasing",
        }
    }

    const fn bit(self) -> u8 {
        1_u8 << (self as u8)
    }
}

/// Compact, deterministically iterable semantic gap impacts.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SemanticGapImpacts(u8);

impl SemanticGapImpacts {
    pub const NONE: Self = Self(0);

    pub(in crate::analyzer::semantic::ir) const VALUE: Self =
        Self::single(SemanticGapImpact::ValueFlow).with(SemanticGapImpact::Aliasing);
    const MEMORY: Self = Self::VALUE
        .with(SemanticGapImpact::HeapRead)
        .with(SemanticGapImpact::HeapWrite);
    const RETURN_TRANSFER: Self = Self::VALUE.with(SemanticGapImpact::ReturnTransfer);
    /// Conservative downstream profile for a represented evaluation whose
    /// timing or multiplicity is unresolved.
    ///
    /// The evaluation still exists in the IR, so this deliberately does not
    /// weaken dispatch coverage or call existence. It does leave produced
    /// values, aliases, heap effects, and return transfer open.
    pub const DEFERRED_EFFECTS: Self = Self::MEMORY.with(SemanticGapImpact::ReturnTransfer);
    pub(in crate::analyzer::semantic::ir) const CONTROL_FLOW: Self = Self::DEFERRED_EFFECTS;
    /// Conservative downstream profile for a represented call whose
    /// caller-side evaluation or transfer is incomplete.
    ///
    /// The represented call may still affect produced values, aliases, heap
    /// reads and writes, return transfer, and caller-side evaluation beyond
    /// what its retained IR events prove.
    pub const CALL_EVALUATION: Self =
        Self::DEFERRED_EFFECTS.with(SemanticGapImpact::CallEvaluation);

    pub const fn single(impact: SemanticGapImpact) -> Self {
        Self(impact.bit())
    }

    #[must_use]
    pub const fn with(self, impact: SemanticGapImpact) -> Self {
        Self(self.0 | impact.bit())
    }

    pub const fn contains(self, impact: SemanticGapImpact) -> bool {
        self.0 & impact.bit() != 0
    }

    pub(crate) const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Derive the conservative cross-language impacts shared by adapter gap
    /// builders. Adapter-specific consequences that cannot be inferred from
    /// the capability and subject must still be attached deliberately.
    pub const fn for_gap(capability: SemanticCapability, subject: SemanticGapSubject) -> Self {
        let capability_impacts = match capability {
            SemanticCapability::Procedures
            | SemanticCapability::BasicBlocks
            | SemanticCapability::ProgramPoints => Self::NONE,
            SemanticCapability::EntryBoundary => Self::VALUE,
            SemanticCapability::NormalExitBoundary
            | SemanticCapability::ExceptionalExitBoundary
            | SemanticCapability::ReturnFlow => Self::RETURN_TRANSFER,
            SemanticCapability::NormalControlFlow
            | SemanticCapability::ExceptionalControlFlow
            | SemanticCapability::CleanupControlFlow
            | SemanticCapability::NonLocalControl
            // An unnormalized guard leaves open which successor executes, so
            // its downstream consequences are the control-flow ones.
            | SemanticCapability::GuardFacts
            | SemanticCapability::SwitchFacts => Self::CONTROL_FLOW,
            SemanticCapability::Assignments
            | SemanticCapability::Values
            | SemanticCapability::LocalFlow
            | SemanticCapability::ParameterFlow => Self::VALUE,
            SemanticCapability::ReceiverFlow => {
                Self::VALUE.with(SemanticGapImpact::DispatchCoverage)
            }
            SemanticCapability::Allocations
            | SemanticCapability::FieldMemory
            | SemanticCapability::StaticMemory
            | SemanticCapability::IndexMemory
            | SemanticCapability::Captures => Self::MEMORY,
            // A call-site-scoped omission leaves call-dependent values and
            // aliases open, but it does not by itself weaken retained target
            // coverage or caller-side evaluation. Broader Calls gaps and
            // callable producer gaps need adapter-authored impacts for any
            // specific downstream consequence. DeferredExecution always
            // leaves evaluation effects open; adapters additionally attach
            // CallEvaluation only when a represented call's caller-side
            // evaluation or transfer is itself incomplete.
            SemanticCapability::Calls => match subject {
                SemanticGapSubject::CallSite(_) => Self::VALUE,
                _ => Self::NONE,
            },
            SemanticCapability::CallableReferences => Self::NONE,
            SemanticCapability::DeferredExecution => Self::DEFERRED_EFFECTS,
            SemanticCapability::ConcurrentSpawn | SemanticCapability::Synchronization => {
                Self::CALL_EVALUATION
            }
            SemanticCapability::DynamicDispatch => {
                Self::single(SemanticGapImpact::DispatchCoverage)
            }
            SemanticCapability::NormalCallContinuation
            | SemanticCapability::ExceptionalCallContinuation
            | SemanticCapability::AsyncSuspendResume
            | SemanticCapability::GeneratorSuspension
            | SemanticCapability::ResourceManagement => Self::CALL_EVALUATION,
        };
        let subject_impacts = match subject {
            SemanticGapSubject::Value(_) | SemanticGapSubject::CleanupOwners(_) => Self::VALUE,
            SemanticGapSubject::MemoryLocation(_) | SemanticGapSubject::Capture(_) => Self::MEMORY,
            SemanticGapSubject::CallContinuation { .. }
            | SemanticGapSubject::AsyncContinuation { .. } => Self::CALL_EVALUATION,
            SemanticGapSubject::FutureConstruction
            | SemanticGapSubject::FutureActivation
            | SemanticGapSubject::Procedure
            | SemanticGapSubject::Point
            | SemanticGapSubject::CallSite(_) => Self::NONE,
        };
        capability_impacts.union(subject_impacts)
    }

    /// A dropped owner identifies the cleanup obligation, not an omitted
    /// transfer of that owner's value. Keep capability-derived consequences.
    pub const fn for_gap_with_discharge(
        capability: SemanticCapability,
        subject: SemanticGapSubject,
        discharge: SemanticGapDischarge,
    ) -> Self {
        let impact_subject = if !matches!(capability, SemanticCapability::ExceptionalControlFlow)
            && matches!(discharge, SemanticGapDischarge::InertDropGlue)
            && matches!(
                subject,
                SemanticGapSubject::Value(_) | SemanticGapSubject::CleanupOwners(_)
            ) {
            SemanticGapSubject::Point
        } else {
            subject
        };
        Self::for_gap(capability, impact_subject)
    }

    /// Iterate in [`SemanticGapImpact::ALL`] order, which is part of the
    /// deterministic semantic rendering contract.
    pub fn iter(self) -> impl Iterator<Item = SemanticGapImpact> {
        SemanticGapImpact::ALL
            .into_iter()
            .filter(move |impact| self.contains(*impact))
    }
}

/// What answers a gap, stated by the adapter that published it.
///
/// `CallResolution` marks a call-site-scoped gap whose question a complete
/// workspace resolution and binding of that call answers -- for example
/// Scala argument-evaluation strictness, which the resolved signature proves
/// because a deferring callee carries its own procedure-level gap that keeps
/// every binding to it open. `RetainedEvaluationOrder` marks an evaluation
/// whose operand order the language leaves open. The producer must map the gap
/// to the whole evaluation; points mapped inside that span form its region. The
/// producer retains every evaluation in the region and chooses one deterministic
/// order. A consumer may discharge the gap only when its answer depends on the
/// set of those evaluations rather than their order, or when the answer lies
/// entirely outside the region. A missing source mapping fails closed.
/// `RetainedControlTopology` marks a
/// point-scoped control gap where every source-local parent normal successor is
/// retained, but feasibility, blocking, termination, or concurrent child
/// execution remains unresolved. On an exceptional-control gap it marks an
/// exception dispatch that retains every handler and the unmatched
/// propagation as successors and runs no user code to select among them. A consumer may discharge it only for a
/// positive proof that depends on the retained parent successor topology, not
/// on liveness, evaluation effects, or spawned work.
/// `CanonicalIndexIdentity` marks a memory-location-scoped index gap where every
/// occurrence names one canonical identity: either one exact value and numeric
/// magnitude for every occurrence of the same literal index, or the one
/// aggregate cell (`Index { index: None, constant_index: None, identity:
/// Aggregate }`) that stands for every element of its base. Consumers such as value flow may
/// discharge the identity question after verifying that structured location
/// and constant value. The marker does not claim that flow state projects
/// indexed properties, so the raw gap remains available to consumers that
/// need that separate capability.
/// `NonRejoiningExceptionalExit` marks an omitted exceptional transfer that
/// cannot resume this procedure's normal evaluation after the gap point and
/// whose exact lowering scope has no already-active handler or cleanup user
/// code. An adapter must leave the discharge as `None` when an omitted abort
/// route can enter such user code. A result-specific selective-dominance proof
/// may ignore the marker only when retained dominance places the gap strictly
/// before every establishment of the exact result being checked, so the
/// omitted route exits before that result exists. An exact normal-continuation
/// proof may also ignore a point- or value-scoped marker that strictly precedes
/// that continuation: reaching the continuation proves the non-rejoining exit
/// was not taken. After proving that one exact guard edge dominates a queried
/// use, a positive result-specific proof may ignore a point- or value-scoped
/// marker when retained reachability proves the marker cannot reach that use;
/// this admits both a strictly later marker and one confined to a sibling arm.
/// The corresponding negative-evidence proof may use the same target-relative
/// fact only to prove control confinement; its caller must supply the arm's
/// reviewed negative meaning. Procedure-scoped markers, predecessors, and
/// cycles remain blocking. Global exceptional flow remains incomplete, and
/// consumers must not treat the marker as a model of the omitted route.
/// `ExitOnlyProcedureCompletion` marks omitted work that can begin only after
/// this procedure has selected an exit and cannot resume its normal body. It
/// covers point-scoped deferred-execution or cleanup-control work whose
/// registration-time evaluations and ordinary successor are retained. It also
/// covers a point- or value-scoped exceptional transfer that can run active
/// cleanup code (Go deferred functions, Rust destructors) before the panicking function returns, including when that
/// cleanup recovers the panic. A result-specific control proof may discharge
/// the marker only relative to an ordinary-body target: either the retained
/// point is in the strict acyclic history of every exact result establishment,
/// or an exact guard projection proves that the point cannot reach that target.
/// In both cases the target must be normal-entry-reachable and outside every
/// retained cleanup, exceptional, or asynchronous region; a shared completion
/// target is not eligible merely because a normal path also reaches it.
/// Procedure-scoped markers, predecessors, and cycles remain blocking. The
/// marker does not enumerate work performed during completion:
/// result-observation and generic control proofs must keep it open. For
/// observation enumeration its point/value subject scopes the triggering
/// transfer only; active completion may observe any captured result.
/// `RebindAtCallOrSuspension` marks a value-scoped `Captures` gap on a local
/// or parameter that this procedure fully establishes, but that a nested
/// callable assigns. That callable can run only during a call or a suspension
/// of this procedure, so the binding keeps its projected value between those
/// points. A consumer may discharge the gap for a proof whose relevant path
/// crosses no call or suspension, or by releasing the binding's value at
/// every call and suspension. An assignment by the callable still establishes
/// the binding, so an initialization proof may discharge it outright.
/// `InertDropGlue` marks a point-scoped omission of implicit destructor calls
/// whose destroyed values are only the procedure's parameters and the values of
/// its `let` bindings, including a temporary a wildcard `let` discards. A
/// consumer may discharge it with a language proof, made against the exact
/// source the procedure was lowered from, that dropping every such value runs no
/// user code. Any value the proof cannot type keeps the gap.
/// A gap without a declared discharge (`None`) stands until the adapter itself
/// lowers the construct.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SemanticGapDischarge {
    #[default]
    None,
    CallResolution,
    RetainedEvaluationOrder,
    RetainedControlTopology,
    CanonicalIndexIdentity,
    /// Missing aggregate/member layout only. An exact field projection may
    /// resolve this obligation with retained initializer/access AST identity,
    /// activated declaration identity and complete state at the queried point.
    /// Other fields and the containing procedure's coverage stay open.
    ExactFieldLayout,
    /// An executable property/index load may be interpreted by a runtime model.
    RuntimeReadBehavior,
    NonRejoiningExceptionalExit,
    ExitOnlyProcedureCompletion,
    /// The adapter modeled every operation effect except the exact impact set
    /// retained by this gap. Consumers may discharge only that partition.
    /// An exact field access may retain declaration/type uncertainty with an
    /// empty impact set; its memory effects are already fully represented.
    ModeledEffectPartition,
    /// A nested callable rebinds the subject binding only at a call or a
    /// suspension of this procedure.
    RebindAtCallOrSuspension,
    /// Every value the omitted drop can destroy is a parameter or a `let`
    /// binding whose drop glue a language proof can show runs no user code.
    /// An exceptional omission retains this marker; control_flow_discharge
    /// interprets its conditional non-rejoining exit proof.
    InertDropGlue,
    /// `NonRejoiningExceptionalExit`, provided the procedure's `InertDropGlue`
    /// proof holds: the evaluation scope's active cleanups destroy only
    /// parameters and `let` bindings, so the abort route runs user code only
    /// if one of those drops does.
    NonRejoiningExceptionalExitAfterInertDrops,
    /// A conversion the lowering kept as a value transfer is a no-user-code
    /// transfer once the language's query-time type proof holds: the
    /// enclosing function's declared return type for Rust's `?`, the
    /// initializer's resolved type for a typed C# local.
    ResidualConversion,
    /// An omitted implicit destructor invocation whose effects remain open.
    /// An analysis that excludes implicit drops may ignore this obligation;
    /// it never certifies inert drop glue or complete cleanup effects.
    /// An exceptional omission retains this marker; control_flow_discharge
    /// interprets its exit-only completion proof.
    ImplicitDropExecution = 14,
    /// Persisted discriminant 15, assigned in landing order after
    /// `ImplicitDropExecution` (#12128).
    /// The producer of this value is withheld. A query can set this obligation
    /// aside only when none of its requested data dependencies uses the value.
    DataDependency = 15,
    /// Only the lexical-parent creation binding is absent in this realization.
    /// A consumer holding an exact creation may discharge this obligation after
    /// proving that its capture rows bind every slot with complete evidence.
    /// This never proves that an unresolved capture prepass found every slot.
    CreatingRealizationBindsCaptures = 16,
}

/// One Go predeclared builtin whose call lowering relies on package-level
/// name resolution finding no same-package declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GoPredeclaredBuiltin {
    Append,
    Cap,
    Clear,
    Close,
    Complex,
    Copy,
    Delete,
    Imag,
    Len,
    Make,
    Max,
    Min,
    New,
    Panic,
    Print,
    Println,
    Real,
    Recover,
}

impl GoPredeclaredBuiltin {
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "append" => Self::Append,
            "cap" => Self::Cap,
            "clear" => Self::Clear,
            "close" => Self::Close,
            "complex" => Self::Complex,
            "copy" => Self::Copy,
            "delete" => Self::Delete,
            "imag" => Self::Imag,
            "len" => Self::Len,
            "make" => Self::Make,
            "max" => Self::Max,
            "min" => Self::Min,
            "new" => Self::New,
            "panic" => Self::Panic,
            "print" => Self::Print,
            "println" => Self::Println,
            "real" => Self::Real,
            "recover" => Self::Recover,
            _ => return None,
        })
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Append => "append",
            Self::Cap => "cap",
            Self::Clear => "clear",
            Self::Close => "close",
            Self::Complex => "complex",
            Self::Copy => "copy",
            Self::Delete => "delete",
            Self::Imag => "imag",
            Self::Len => "len",
            Self::Make => "make",
            Self::Max => "max",
            Self::Min => "min",
            Self::New => "new",
            Self::Panic => "panic",
            Self::Print => "print",
            Self::Println => "println",
            Self::Real => "real",
            Self::Recover => "recover",
        }
    }
}

/// Dispatch obligation attached to the call-target half of a gap pair.
/// Unspecified preserves producers that refine dispatch entirely at query time.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CallTargetDispatch {
    #[default]
    Unspecified,
    Static,
    Special,
    Virtual,
    Interface,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SemanticGap {
    pub id: SemanticGapId,
    pub point: ProgramPointId,
    pub subject: SemanticGapSubject,
    pub capability: SemanticCapability,
    pub impacts: SemanticGapImpacts,
    pub kind: SemanticGapKind,
    /// Required exactly when `kind` is `ExceededBudget`.
    pub budget: Option<SemanticBudgetExceeded>,
    /// The declared structured proof obligation, when this gap is
    /// dischargeable by a downstream consumer.
    pub discharge: SemanticGapDischarge,
    /// Dispatch semantics of the call-target gap; other gaps use Unspecified.
    pub dispatch: CallTargetDispatch,
    pub detail: Box<str>,
    pub source: SourceMappingId,
    pub evidence: EvidenceId,
}

impl SemanticGap {
    /// Whether the omitted work is an implicit destructor invocation, rather
    /// than a generic cleanup, deferred call, or exceptional completion.
    pub const fn is_implicit_drop_omission(&self) -> bool {
        matches!(
            self.discharge,
            SemanticGapDischarge::InertDropGlue | SemanticGapDischarge::ImplicitDropExecution
        )
    }

    /// Interpret an exceptional implicit-drop omission's control-flow proof
    /// without erasing its drop-specific identity for write liveness.
    pub const fn control_flow_discharge(&self) -> SemanticGapDischarge {
        match (self.capability, self.discharge) {
            (SemanticCapability::ExceptionalControlFlow, SemanticGapDischarge::InertDropGlue) => {
                SemanticGapDischarge::NonRejoiningExceptionalExitAfterInertDrops
            }
            (
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapDischarge::ImplicitDropExecution,
            ) => SemanticGapDischarge::ExitOnlyProcedureCompletion,
            _ => self.discharge,
        }
    }

    /// Whether this gap leaves a procedure's return-value transfer incomplete.
    pub fn is_return_transfer_gap(&self) -> bool {
        self.capability == SemanticCapability::Values
            && self.impacts.contains(SemanticGapImpact::ReturnTransfer)
    }
}

/// Whether a producer-authored gap certifies one exact index identity across
/// source occurrences.
///
/// The discharge marker is the producer's cross-occurrence guarantee. The
/// structural checks keep that guarantee scoped to an indexed memory location
/// whose identity is either a retained constant index value or the one
/// aggregate cell (`index: None`, `constant_index: None`, `Aggregate`), and
/// whose exact access remains at the gap point. A dynamic element, rebound,
/// missing, or retargeted access therefore cannot acquire the proof merely by
/// carrying the marker.
#[doc(hidden)]
pub fn gap_certifies_canonical_index_identity(
    gap: &SemanticGap,
    points: &[ProgramPoint],
    memory_locations: &[MemoryLocation],
    values: &[SemanticValue],
) -> bool {
    if gap.discharge != SemanticGapDischarge::CanonicalIndexIdentity
        || gap.capability != SemanticCapability::IndexMemory
        || gap.kind != SemanticGapKind::Unsupported
    {
        return false;
    }
    let SemanticGapSubject::MemoryLocation(location) = gap.subject else {
        return false;
    };
    let Some(MemoryLocation {
        kind:
            MemoryLocationKind::Index {
                index,
                constant_index,
                identity,
                ..
            },
        ..
    }) = memory_locations.get(location.index())
    else {
        return false;
    };
    let names_one_identity = match (index, constant_index, identity) {
        // One exact literal value and magnitude.
        (Some(index), Some(_), _) => values
            .get(index.index())
            .is_some_and(|value| value.kind.is_constant()),
        // The one aggregate cell standing for every element.
        (None, None, IndexedLocationIdentity::Aggregate) => true,
        _ => false,
    };
    names_one_identity
        && points.get(gap.point.index()).is_some_and(|point| {
            point.events.iter().any(|event| {
                matches!(
                    &event.effect,
                    SemanticEffect::MemoryLoad {
                        kind: MemoryAccessKind::Index,
                        location: accessed,
                        ..
                    } | SemanticEffect::MemoryStore {
                        kind: MemoryAccessKind::Index,
                        location: accessed,
                        ..
                    } if *accessed == location
                )
            })
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BackingStoreOffset {
    Zero,
    Constant(u128),
    Value(ValueId),
}

/// How a by-value transfer relates the destination's value and identity to
/// the source.
///
/// Every kind creates a distinct storage/object identity for the target while
/// preserving logical value dependence on the source. No kind implies storage
/// aliasing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransferKind {
    /// The value is duplicated; the source is unaffected.
    Copy,
    /// A whole aggregate value is copied into independent element storage.
    /// Modeling copied element contents is a separate, explicitly incomplete
    /// concern.
    AggregateCopy,
    /// The value (and, where the language defines it, ownership) transfers to
    /// the target and the source stops holding it.
    Move { invalidation: MoveInvalidation },
    /// The target holds a converted form of the source's value.
    Conversion { preservation: ValuePreservation },
    /// The source value is wrapped in an object or interface representation,
    /// separate from the payload's storage. A reference payload remains a
    /// dependence of the wrapper, not an alias of the wrapper. This is the
    /// call-boundary equivalent of `ValueFlowKind::ReferenceBoxing` when the
    /// source is a reference, and also covers boxing primitive/value payloads.
    /// This does not prove freshness or sharing with another boxing operation;
    /// allocation and language runtime caches require independent identity proof.
    Boxing,
    /// The contained value is extracted out of a container object.
    Unboxing,
}

impl TransferKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Copy => "copy",
            Self::AggregateCopy => "aggregate_copy",
            Self::Move { .. } => "move",
            Self::Conversion { .. } => "conversion",
            Self::Boxing => "boxing",
            Self::Unboxing => "unboxing",
        }
    }
}

/// What a move leaves behind in the source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MoveInvalidation {
    /// The source no longer holds the relevant value after the transfer.
    Invalidated,
    /// The language or producer cannot state what the source holds afterward.
    /// The event's evidence must not claim proven, complete knowledge.
    Unknown,
}

impl MoveInvalidation {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Invalidated => "invalidated",
            Self::Unknown => "unknown",
        }
    }
}

/// Whether a conversion preserves the relevant value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValuePreservation {
    /// The target holds the identical value in an identical representation.
    Identity,
    /// The representation changes but the relevant value is preserved.
    Preserving,
    /// The relevant value is not preserved (narrowing, lossy, reinterpreting).
    Changing,
}

impl ValuePreservation {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Preserving => "preserving",
            Self::Changing => "changing",
        }
    }
}

/// The exact operation the language selected to perform a transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransferOperation {
    /// No distinct operation runs (a trivial or bitwise transfer).
    None,
    /// The selected operation is the procedure invoked at this call site. The
    /// call site's dispatch facts carry the exact callable identity; the
    /// transfer does not duplicate it.
    CallSite(CallSiteId),
    /// A shared resolver proved the conversion for one actual/formal argument
    /// pair. The copyable digest is opaque, content-addressed provenance for
    /// that complete conversion witness; it does not identify a callee
    /// invocation and carries no local graph identity.
    CallArgumentConversion(StableDigest),
    /// A language adapter proved that a declared value type and its runtime
    /// carrier differ here, and selected the exact adaptation the platform
    /// runs. The copyable digest is opaque, content-addressed provenance for
    /// that complete witness: the adapting declaration's identity, the member
    /// that carries the value, the direction, and the boundary rule that
    /// forced the adaptation. Kotlin's `@JvmInline` value classes are the
    /// first consumer; nothing about the digest is Kotlin-specific.
    ValueCarrierAdaptation(StableDigest),
    /// An operation runs but was not selected exactly. The event's evidence
    /// must not claim proven, complete knowledge.
    Unknown,
}

/// One signed integer magnitude without a host-width signed cast.
///
/// The representation covers `-u128::MAX` through `u128::MAX`. Negative zero
/// is canonicalized to positive zero at construction so equal offsets have one
/// stable IR representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SignedIntegerMagnitude {
    negative: bool,
    magnitude: u128,
}

impl SignedIntegerMagnitude {
    pub const fn new(negative: bool, magnitude: u128) -> Self {
        Self {
            negative: negative && magnitude != 0,
            magnitude,
        }
    }

    /// Construct the canonical sign-and-magnitude form of an `i128` value.
    pub const fn from_i128(value: i128) -> Self {
        Self::new(value < 0, value.unsigned_abs())
    }

    pub const fn negative(self) -> bool {
        self.negative
    }

    pub const fn magnitude(self) -> u128 {
        self.magnitude
    }
}

impl TransferOperation {
    pub const fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::CallSite(_) => "call_site",
            Self::CallArgumentConversion(_) => "call_argument_conversion",
            Self::ValueCarrierAdaptation(_) => "value_carrier_adaptation",
            Self::Unknown => "unknown",
        }
    }
}

/// One identity-separating by-value transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ValueTransfer {
    pub kind: TransferKind,
    pub operation: TransferOperation,
}

impl ValueTransfer {
    /// Whether the transfer establishes the same runtime class, not merely
    /// numerical value preservation or value dependence.
    pub const fn preserves_runtime_class(self) -> bool {
        matches!(
            self.kind,
            TransferKind::Copy
                | TransferKind::AggregateCopy
                | TransferKind::Move { .. }
                | TransferKind::Conversion {
                    preservation: ValuePreservation::Identity
                }
        )
    }

    /// Whether the destination holds the same member contents as the source at
    /// the moment of the transfer.
    ///
    /// This is a statement about contents, not about storage. Every
    /// `TransferKind` separates storage identity, so a later write through one
    /// side is never visible through the other; a duplicating transfer still
    /// starts the destination out holding what the source held, which is what
    /// lets a member read of the destination observe the source's member. A
    /// boxing or unboxing operation restructures the value instead of
    /// duplicating it, and a changing conversion does not preserve the value at
    /// all, so neither carries the source's members.
    pub const fn preserves_member_contents(self) -> bool {
        matches!(
            self.kind,
            TransferKind::Copy
                | TransferKind::AggregateCopy
                | TransferKind::Move { .. }
                | TransferKind::Conversion {
                    preservation: ValuePreservation::Identity | ValuePreservation::Preserving
                }
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
// Variant order reaches materialization/cache digests through derived Hash.
// Append new variants LAST. `value_flow_hash_stability::encoded_hash_is_stable`
// pins canonical hash bytes and digests in value-flow-kind-hash-v1.txt.
pub enum ValueFlowKind {
    Local,
    /// The target receives the exact logical value selected from a field, but
    /// Copy versus Move and the source place's later state are unresolved.
    /// This is neither an alias nor an identity-separating transfer proof.
    OwnershipUnknown,
    /// The target receives the source's value in a distinct storage/object
    /// identity.
    ///
    /// The producer must emit this immediately after its matching `Assignment`
    /// at the same program point. It overrides that assignment
    /// for identity consumers while remaining ordinary value dependence.
    /// Access-path and heap-origin walks must stop rather than mistake it for
    /// an alias.
    Transfer(ValueTransfer),
    /// `target` denotes the same indexed backing store as `source`. Its start
    /// is zero, an exact non-negative element constant, or a semantic value
    /// evaluated at the slice boundary. A consumer may retain allocation
    /// identity when that value is not exactly refinable, but overlap remains
    /// open.
    ///
    /// This is a storage-identity relation as well as ordinary local value
    /// flow. Languages with by-value arrays must not use it for array copies.
    BackingStore {
        offset: BackingStoreOffset,
    },
    /// `target` is `source` plus one exact signed integer magnitude. This is a
    /// scalar computation, not a heap-identity or runtime-class relation.
    IntegerOffset {
        offset: SignedIntegerMagnitude,
    },
    /// The target uses either the source backing store at `offset` or the
    /// named fresh allocation.  The allocation is a bounded alternative, not
    /// an additional ordinary value-flow edge; consumers must retain both
    /// candidates and keep their completeness partial until runtime choice is
    /// known.
    BackingStoreAlternative {
        offset: BackingStoreOffset,
        allocation: AllocationId,
    },
    Parameter,
    Receiver,
    Return,
    IndexedReturn {
        ordinal: u32,
    },
    /// The source reference value is stored in a distinct interface or
    /// wrapper representation. The wrapper's storage identity is separate
    /// from the referenced payload; this edge preserves ordinary value
    /// dependence without claiming that the two values alias.
    ReferenceBoxing,
    /// A reference payload is extracted from a wrapper after the producer
    /// proved the compatible assertion. The extracted reference may retain
    /// its payload identity, but the wrapper itself remains a separate value.
    ReferenceUnboxing,
    LanguageDefined,
    /// The target copies the source at capture time. Referent identity is
    /// preserved only when a language hook proves a static reference type.
    ByValueCapture,
    /// The target is the address of the source storage. Ordinary value
    /// dependence is transparent, but the operand's pointer identity does
    /// not become the identity of the resulting address.
    AddressOf,
    /// A read through an address. Ordinary value dependence follows the
    /// address, while pointer identity comes from the named storage contents.
    MemoryLoad {
        location: MemoryLocationId,
    },
}

impl ValueFlowKind {
    /// Whether this relation establishes unchanged runtime class identity.
    /// A view can have another class than its backing storage, and an
    /// arbitrary computation need not return the class of any operand.
    pub const fn preserves_runtime_class(self) -> bool {
        match self {
            Self::Transfer(transfer) => transfer.preserves_runtime_class(),
            Self::BackingStore { .. }
            | Self::OwnershipUnknown
            | Self::IntegerOffset { .. }
            | Self::ReferenceBoxing
            | Self::ReferenceUnboxing
            | Self::BackingStoreAlternative { .. }
            | Self::LanguageDefined
            | Self::MemoryLoad { .. }
            | Self::ByValueCapture => false,
            Self::Local
            | Self::AddressOf
            | Self::Parameter
            | Self::Receiver
            | Self::Return
            | Self::IndexedReturn { .. } => true,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::AddressOf => "address_of",
            Self::MemoryLoad { .. } => "pointer_memory_load",
            Self::OwnershipUnknown => "ownership_unknown",
            Self::Transfer(_) => "transfer",
            Self::BackingStore { .. } => "backing_store",
            Self::IntegerOffset { .. } => "integer_offset",
            Self::BackingStoreAlternative { .. } => "backing_store_alternative",
            Self::Parameter => "parameter",
            Self::Receiver => "receiver",
            Self::Return => "return",
            Self::IndexedReturn { .. } => "indexed_return",
            Self::ReferenceBoxing => "reference_boxing",
            Self::ReferenceUnboxing => "reference_unboxing",
            Self::LanguageDefined => "language_defined",
            Self::ByValueCapture => "by_value_capture",
        }
    }
}

/// One reason shared by consumers that need Copy/Move or identity evidence
/// after an exact pattern-value projection. The value relation remains proven.
pub fn ownership_unknown_reason(point: ProgramPointId) -> String {
    format!("ownership of the projected value at {point} is unknown")
}

/// A structured operation on a value or binding without claiming that it
/// flows into the operation's result.
///
/// This is deliberately separate from [`ValueFlowKind`]. For example, an
/// address value is required to dereference memory, but the address itself is
/// not the value loaded from that memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValueUseKind {
    Dereference,
    /// Remove the lexical binding that names this local or parameter.
    Unbind,
}

impl ValueUseKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Dereference => "dereference",
            Self::Unbind => "unbind",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemoryAccessKind {
    Field,
    Property,
    Static,
    Index,
    Dereference,
    LexicalCell,
    Capture,
}

impl MemoryAccessKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Field => "field",
            Self::Property => "property",
            Self::Static => "static",
            Self::Index => "index",
            Self::Dereference => "dereference",
            Self::LexicalCell => "lexical_cell",
            Self::Capture => "capture",
        }
    }
}

/// A language-level synchronization operation whose subject is an exact
/// semantic value. API-backed synchronization is projected separately from
/// reviewed procedure summaries so dense actual-argument IDs do not enter the
/// authored model format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SynchronizationOperation {
    ChannelSend,
    ChannelReceive,
    ChannelClose,
}

impl SynchronizationOperation {
    pub const fn label(self) -> &'static str {
        match self {
            Self::ChannelSend => "channel_send",
            Self::ChannelReceive => "channel_receive",
            Self::ChannelClose => "channel_close",
        }
    }
}

/// The part of a synchronization operation that carries a language value.
///
/// A send records its value independently of whether the language front end
/// can prove how the element copy preserves object identity. A receive records its
/// result independently; a consumer must still pair it with one exact send
/// before relating the two values. Missing payload metadata is an unsupported
/// transport fact, never evidence that no value crossed the operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SynchronizationPayload {
    Send {
        value: ValueId,
        copy: SynchronizationPayloadCopy,
    },
    Receive {
        result: ValueId,
    },
}

/// What is known about identity preservation by a channel element copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SynchronizationPayloadCopy {
    /// The sent value is known, but its transport identity is not proved.
    Unknown,
    /// A pointer or channel descriptor preserves the referenced object.
    Reference,
    /// A container descriptor preserves its backing store. The indexed
    /// identity distinguishes sequence elements from associative aggregates
    /// so a receive can retain the producer-authored location family.
    BackingStore { identity: IndexedLocationIdentity },
}

impl SynchronizationPayloadCopy {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Reference => "reference",
            Self::BackingStore { .. } => "backing_store",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CallContinuationKind {
    Normal,
    Exceptional,
}

impl CallContinuationKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Exceptional => "exceptional",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AsyncResumeKind {
    Normal,
    Exceptional,
}

impl AsyncResumeKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Exceptional => "exceptional",
        }
    }
}

/// One normalized execution effect.  Callable evaluation and invocation are
/// separate variants; only `Invoke` owns a call site.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SemanticEffect {
    Entry,
    NormalExit,
    ExceptionalExit,
    Assignment {
        target: ValueId,
        value: ValueId,
    },
    /// One keyed operand of an aggregate whose layout was unavailable to the
    /// file-local producer.  The selector is the exact source key locator and
    /// `value` is the already-lowered RHS value.  This is an operand relation
    /// only: it does not identify a struct field, map entry, copy, alias, or
    /// storage location.  The fact is emitted at the aggregate expression's
    /// post-child terminal point, after the RHS has been evaluated. A
    /// workspace-aware provider may refine it when the aggregate declaration
    /// is available.
    AggregateInitializer {
        aggregate: ValueId,
        selector: SemanticLocator,
        value: ValueId,
    },
    ValueFlow {
        kind: ValueFlowKind,
        source: ValueId,
        target: ValueId,
    },
    ValueUse {
        kind: ValueUseKind,
        value: ValueId,
    },
    Allocation {
        allocation: AllocationId,
    },
    MemoryLoad {
        kind: MemoryAccessKind,
        location: MemoryLocationId,
        result: ValueId,
    },
    MemoryStore {
        kind: MemoryAccessKind,
        location: MemoryLocationId,
        value: ValueId,
    },
    Synchronization {
        operation: SynchronizationOperation,
        subject: ValueId,
        payload: Option<SynchronizationPayload>,
    },
    CallableCreation {
        result: ValueId,
        callable: CallableValue,
    },
    CallableReference {
        result: ValueId,
        callable: CallableValue,
    },
    CaptureBind {
        capture: CaptureId,
    },
    Invoke {
        call_site: CallSiteId,
    },
    CallContinuation {
        call_site: CallSiteId,
        kind: CallContinuationKind,
    },
    ProcedureReturn {
        value: Option<ValueId>,
    },
    Throw {
        value: Option<ValueId>,
    },
    AsyncSuspend {
        awaited: Option<ValueId>,
        normal_resume: ControlContinuation,
        exceptional_resume: ControlContinuation,
    },
    AsyncResume {
        suspend: ProgramPointId,
        kind: AsyncResumeKind,
        result: Option<ValueId>,
    },
    Gap {
        gap: SemanticGapId,
    },
    /// PLACEHOLDER event discriminant 21; finalize in landing order (#12128).
    /// Other execution may modify every memory location that existing facts do
    /// not prove exclusively owned. Scalar locals and object identities survive.
    MemoryInterference,
}

impl SemanticEffect {
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Entry => "entry",
            Self::NormalExit => "normal_exit",
            Self::ExceptionalExit => "exceptional_exit",
            Self::Assignment { .. } => "assignment",
            Self::AggregateInitializer { .. } => "aggregate_initializer",
            Self::ValueFlow { .. } => "value_flow",
            Self::ValueUse { .. } => "value_use",
            Self::Allocation { .. } => "allocation",
            Self::MemoryLoad { .. } => "memory_load",
            Self::MemoryStore { .. } => "memory_store",
            Self::Synchronization { .. } => "synchronization",
            Self::CallableCreation { .. } => "callable_creation",
            Self::CallableReference { .. } => "callable_reference",
            Self::CaptureBind { .. } => "capture_bind",
            Self::Invoke { .. } => "invoke",
            Self::CallContinuation { .. } => "call_continuation",
            Self::ProcedureReturn { .. } => "procedure_return",
            Self::Throw { .. } => "throw",
            Self::AsyncSuspend { .. } => "async_suspend",
            Self::AsyncResume { .. } => "async_resume",
            Self::Gap { .. } => "gap",
            Self::MemoryInterference => "memory_interference",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SemanticEvent {
    pub effect: SemanticEffect,
    pub source: SourceMappingId,
    pub evidence: EvidenceId,
}

impl SemanticEvent {
    pub const fn new(
        effect: SemanticEffect,
        source: SourceMappingId,
        evidence: EvidenceId,
    ) -> Self {
        Self {
            effect,
            source,
            evidence,
        }
    }
}

/// The identity-separating transfer that immediately overrides one Assignment
/// for identity consumers, when the producer authored one.
///
/// Artifact validation guarantees the matching immediate-successor contract.
/// Consumers use this helper inside event scans they already account for;
/// deriving a second procedure-wide edge table would hide semantic work.
#[doc(hidden)]
pub fn assignment_transfer(
    events: &[SemanticEvent],
    assignment_index: usize,
    source: ValueId,
    target: ValueId,
) -> Option<ValueTransfer> {
    events
        .get(assignment_index + 1)
        .and_then(|event| match event.effect {
            SemanticEffect::ValueFlow {
                kind: ValueFlowKind::Transfer(transfer),
                source: actual_source,
                target: actual_target,
            } if actual_source == source && actual_target == target => Some(transfer),
            _ => None,
        })
}

/// A source binding or projected storage location whose initialization and
/// lifetime can be tracked independently of the value currently stored there.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SemanticPlace {
    /// A local or parameter binding, identified by its exact value locator.
    LocalBinding(SemanticLocator),
    /// A structured projection such as a field or indexed element.
    MemoryLocation(MemoryLocationId),
}

/// Whether a place's destructor has user-visible behavior.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DropBehavior {
    /// The producer proved that dropping this place runs no user destructor.
    Trivial,
    /// A user destructor is selected or its target-resolution frontier is
    /// retained for downstream cleanup analysis.
    Destructor(CallableTargetResolution),
}

/// One explicit or implicit destruction of a place at a program point.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DropFact {
    pub place: SemanticPlace,
    pub point: ProgramPointId,
    pub behavior: DropBehavior,
    pub source: SourceMappingId,
    pub evidence: EvidenceId,
}

/// The initialization state left in a moved place or tracked aggregate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MoveOutState {
    Uninitialized,
    PartiallyInitialized,
    Unknown,
}

/// One place-level initialization transition tied to an existing move transfer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MoveOutFact {
    pub place: SemanticPlace,
    pub point: ProgramPointId,
    pub source_value: ValueId,
    pub target_value: ValueId,
    pub state_after: MoveOutState,
    pub source: SourceMappingId,
    pub evidence: EvidenceId,
}

/// Where one place's storage lifetime ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScopeEndAt {
    Point(ProgramPointId),
    Edge {
        source_point: ProgramPointId,
        target_point: ProgramPointId,
        kind: ControlEdgeKind,
    },
}

/// One exact storage-lifetime end for a local place.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ScopeEndFact {
    pub place: SemanticPlace,
    pub at: ScopeEndAt,
    pub source: SourceMappingId,
    pub evidence: EvidenceId,
}

/// The kind of object named by one abstract pointer origin.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PointerOriginKind {
    StackPlace { place: SemanticPlace },
    Allocation { allocation: AllocationId },
}

/// One procedure-local abstract stack place or allocation identity.
///
/// The dense ID is local to the containing procedure artifact. `kind`, source,
/// and evidence retain the declaration or allocation site that roots it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PointerOrigin {
    pub id: PointerOriginId,
    pub point: ProgramPointId,
    pub kind: PointerOriginKind,
    pub byte_extent: Option<u128>,
    pub source: SourceMappingId,
    pub evidence: EvidenceId,
}

/// Whether a pointer relation has one proven origin or retains alternatives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PointerRelationStrength {
    Must,
    May,
}

impl PointerRelationStrength {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Must => "must",
            Self::May => "may",
        }
    }
}

/// A byte displacement from the beginning of a pointer origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PointerByteOffset {
    Exact(i128),
    Value(ValueId),
    Range { minimum: i128, maximum: i128 },
    Unknown,
}

/// One pointer value may designate one abstract origin at this offset.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PointerAlias {
    pub point: ProgramPointId,
    pub pointer: ValueId,
    pub origin: PointerOriginId,
    pub byte_offset: PointerByteOffset,
    pub strength: PointerRelationStrength,
    pub source: SourceMappingId,
    pub evidence: EvidenceId,
}

/// Whether an indirect operation reads, writes, or both through a pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PointerAccessKind {
    Read,
    Write,
    ReadWrite,
}

impl PointerAccessKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::ReadWrite => "read_write",
        }
    }
}

/// The byte width accessed through a pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PointerAccessWidth {
    Exact(u128),
    ValueTimes { value: ValueId, multiplier: u128 },
    Unknown,
}

/// One source-mapped indirect memory operation through a pointer value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PointerAccess {
    pub point: ProgramPointId,
    pub pointer: ValueId,
    pub kind: PointerAccessKind,
    pub width: PointerAccessWidth,
    pub source: SourceMappingId,
    pub evidence: EvidenceId,
}

/// How a pointer invalidation identifies the allocation whose lifetime ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PointerInvalidationTarget {
    /// Resolve this pointer value to its possible origins at the invalidation.
    Pointer(ValueId),
    /// Name an origin local to the containing procedure artifact.
    Origin(PointerOriginId),
}

/// Why a pointer origin may no longer be accessed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PointerInvalidationCause {
    Deallocated,
    OwnerDropped,
    OwnershipTransferred,
    PossibleReallocation,
}

impl PointerInvalidationCause {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Deallocated => "deallocated",
            Self::OwnerDropped => "owner_dropped",
            Self::OwnershipTransferred => "ownership_transferred",
            Self::PossibleReallocation => "possible_reallocation",
        }
    }
}

/// One event that invalidates or may invalidate an abstract pointer origin.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PointerInvalidation {
    pub point: ProgramPointId,
    pub target: PointerInvalidationTarget,
    pub cause: PointerInvalidationCause,
    pub strength: PointerRelationStrength,
    pub source: SourceMappingId,
    pub evidence: EvidenceId,
}

/// A typed reason why lifecycle support is incomplete at one subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LifecycleIncompleteReason {
    UnsupportedMacroExpansion,
    GenericDropObligation,
    MissingType,
    PartialMove,
    ManuallyDrop,
    ForgottenOwner,
    UnresolvedTraitDispatch,
    UnsupportedCleanup,
    UnknownPanicStrategy,
    AsyncCancellationState,
}

/// A typed reason why pointer-origin or invalidation support is incomplete.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PointerIncompleteReason {
    RawPointerType,
    UnsupportedOperation,
    MissingType,
    UnknownLayout,
    UnknownAllocationExtent,
    AmbiguousOrigin,
    AmbiguousAlias,
    UnresolvedAllocator,
    ExternalEscape,
    OffsetOverflow,
}

/// Domain-qualified reason attached to an explicit incomplete fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SemanticIncompleteReason {
    Lifecycle(LifecycleIncompleteReason),
    Pointer(PointerIncompleteReason),
}

/// The exact procedure-local subject whose semantics remain incomplete.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SemanticIncompleteSubject {
    Procedure,
    Place(SemanticPlace),
    Value(ValueId),
    PointerOrigin(PointerOriginId),
}

/// One machine-readable reason that positive facts do not cover a subject.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SemanticIncompleteFact {
    pub point: ProgramPointId,
    pub subject: SemanticIncompleteSubject,
    pub reason: SemanticIncompleteReason,
    pub source: SourceMappingId,
    pub evidence: EvidenceId,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BasicBlock {
    pub id: BlockId,
    pub points: Box<[ProgramPointId]>,
    pub source: SourceMappingId,
    pub evidence: EvidenceId,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProgramPoint {
    pub id: ProgramPointId,
    pub block: BlockId,
    pub events: Box<[SemanticEvent]>,
    pub source: SourceMappingId,
    pub evidence: EvidenceId,
}

impl ProgramPoint {
    /// Whether this assignment has an adjacent transfer interpretation.
    /// Identity consumers use the marker's row instead of copying through
    /// both rows. Other definitions of the same value are independent.
    pub fn assignment_has_transfer_marker(&self, event_index: usize) -> bool {
        let SemanticEffect::Assignment { target, value } = self.events[event_index].effect else {
            unreachable!("the requested event is an assignment");
        };
        self.events.get(event_index + 1).is_some_and(|next| {
            matches!(next.effect, SemanticEffect::ValueFlow {
                kind: ValueFlowKind::Transfer(_)
                    | ValueFlowKind::BackingStore { .. }
                    | ValueFlowKind::ReferenceBoxing
                    | ValueFlowKind::ReferenceUnboxing
                    | ValueFlowKind::BackingStoreAlternative { .. },
                source,
                target: transferred,
            } if source == value && transferred == target)
        })
    }
}

/// Intraprocedural topology only.  ICFG call-to-entry and exit-to-return
/// edges belong to issue #818 and cannot be represented by these local IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ControlEdgeKind {
    Normal,
    ConditionalTrue,
    ConditionalFalse,
    SwitchCase,
    LoopBack,
    Exceptional,
    Cleanup,
    AsyncNormal,
    AsyncExceptional,
}

impl ControlEdgeKind {
    /// The value domain the `control_edge.edge_kind` row field publishes
    /// (issue #2515).
    pub const LABELS: &'static [&'static str] = &[
        "normal",
        "conditional_true",
        "conditional_false",
        "switch_case",
        "loop_back",
        "exceptional",
        "cleanup",
        "async_normal",
        "async_exceptional",
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::ConditionalTrue => "conditional_true",
            Self::ConditionalFalse => "conditional_false",
            Self::SwitchCase => "switch_case",
            Self::LoopBack => "loop_back",
            Self::Exceptional => "exceptional",
            Self::Cleanup => "cleanup",
            Self::AsyncNormal => "async_normal",
            Self::AsyncExceptional => "async_exceptional",
        }
    }

    pub const fn sort_rank(self) -> u8 {
        match self {
            Self::Normal => 0,
            Self::ConditionalTrue => 1,
            Self::ConditionalFalse => 2,
            Self::SwitchCase => 3,
            Self::LoopBack => 4,
            Self::Exceptional => 5,
            Self::Cleanup => 6,
            Self::AsyncNormal => 7,
            Self::AsyncExceptional => 8,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ControlEdge {
    pub source_point: ProgramPointId,
    pub target_point: ProgramPointId,
    pub kind: ControlEdgeKind,
    pub source: SourceMappingId,
    pub evidence: EvidenceId,
}

/// A stable digest over the shape of a condition a lowerer declined to
/// normalize.
///
/// The only ingredient is the adapter's own structured classification of the
/// condition -- its grammar node kind -- never its source text. Two opaque
/// guards therefore agree exactly when their lowerers classified the syntax the
/// same way, and the IR carries no language-specific vocabulary of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GuardConditionDigest(u64);

impl GuardConditionDigest {
    pub fn from_syntax_kind(kind: &str) -> Self {
        let digest = StableDigest::sha256(kind);
        let mut head = [0_u8; 8];
        head.copy_from_slice(&digest.as_bytes()[..8]);
        Self(u64::from_le_bytes(head))
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    /// Rebuild a digest from the value [`Self::get`] returned, as the
    /// semantic IR row decoder does.
    #[doc(hidden)]
    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }
}

/// The ordered relation between a guard subject and an exact integer constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IntegerComparison {
    LessThan,
    LessThanOrEqual,
    GreaterThan,
    GreaterThanOrEqual,
}

impl IntegerComparison {
    pub const fn label(self) -> &'static str {
        match self {
            Self::LessThan => "less_than",
            Self::LessThanOrEqual => "less_than_or_equal",
            Self::GreaterThan => "greater_than",
            Self::GreaterThanOrEqual => "greater_than_or_equal",
        }
    }

    pub const fn reverse(self) -> Self {
        match self {
            Self::LessThan => Self::GreaterThan,
            Self::LessThanOrEqual => Self::GreaterThanOrEqual,
            Self::GreaterThan => Self::LessThan,
            Self::GreaterThanOrEqual => Self::LessThanOrEqual,
        }
    }

    pub const fn negate(self) -> Self {
        match self {
            Self::LessThan => Self::GreaterThanOrEqual,
            Self::LessThanOrEqual => Self::GreaterThan,
            Self::GreaterThan => Self::LessThanOrEqual,
            Self::GreaterThanOrEqual => Self::LessThan,
        }
    }
}

/// The normalized meaning of one decision point's condition (issue #2443).
///
/// A lowerer publishes a predicate only when its own structured syntax
/// establishes the shape. Anything it represents but cannot normalize is
/// `Opaque`; anything it does not represent at all publishes no row, and the
/// [`SemanticCapability::GuardFacts`] entry in the adapter's capability table
/// is what says which of the two an absent row means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GuardPredicate {
    /// The condition is a compile-time constant.
    ///
    /// Recorded even when lowering folded the dead arm away: the fold is
    /// exactly the evidence no consumer can recover from the frozen CFG, so
    /// destroying it silently is the defect this variant exists to repair.
    ConstantBoolean { value: bool },
    /// The condition compares the subject against the language's null value.
    /// `null_on_true` states which arm a null subject takes.
    NullComparison { null_on_true: bool },
    /// The condition compares the subject against a constant value.
    /// `negated` distinguishes an inequality from an equality.
    ConstantEquality { negated: bool, constant: ValueId },
    /// The subject is ordered relative to one represented integer constant.
    OrderedIntegerComparison {
        relation: IntegerComparison,
        constant: ValueId,
    },
    /// The subject is ordered relative to one represented floating constant
    /// by the language's numeric order, which is false whenever an operand
    /// is NaN. A consumer refines only a subject it already knows to hold a
    /// number; an operand that may convert or dispatch stays unknown.
    OrderedFloatComparison {
        relation: IntegerComparison,
        constant: ValueId,
    },
    /// The condition compares the subject with itself by IEEE equality or a
    /// non-strict order (`x != x`, `x == x`, `x <= x`), which only NaN
    /// decides. `nan_on_true` states which arm a NaN subject takes; every
    /// other number takes the other arm.
    NanComparison { nan_on_true: bool },
    /// The condition tests whether `value` is an instance of one or more
    /// classes denoted by `classes`.
    InstanceOf { value: ValueId, classes: ValueId },
    /// The condition tests whether `value`'s class is exactly one of the
    /// classes denoted by `classes`.
    ///
    /// This is not `InstanceOf` with a narrower reading. A subclass of a named
    /// class satisfies `InstanceOf` and fails this test, so the two disagree on
    /// both arms and one cannot stand in for the other.
    ///
    /// `exact_on_true` carries the comparison's polarity, the way
    /// [`Self::NullComparison`] carries `null_on_true`: `type(x) is C` states
    /// the class on the true arm, and `type(x) is not C` states it on the
    /// false arm. The grammar spells `is not` as one operator token, so the
    /// two are one predicate with two polarities rather than a predicate and
    /// its negation.
    ExactClass {
        value: ValueId,
        classes: ValueId,
        exact_on_true: bool,
    },
    /// The condition tests whether `value` has the member named by `member`.
    HasMember { value: ValueId, member: ValueId },
    /// The condition is `value` itself, read for its truth.
    ///
    /// For an arbitrary value only the true arm carries information, and only
    /// about the language's null value: `None` is falsy and nothing can make
    /// it truthy. A falsy value is not necessarily null. A value a consumer
    /// already knows to be null, a Boolean, an integer, or a float that is
    /// not NaN has the same truthiness in every language that publishes this
    /// predicate, so both arms refine it.
    Truthy { value: ValueId },
    /// The decision is represented, but its condition was not normalizable.
    Opaque { digest: GuardConditionDigest },
    /// A syntactic equality between two exact value reads. Unlike
    /// ConstantEquality this does not assert a scalar or constant operand.
    /// Policy-owned guards may consume it; scalar refinement must not.
    ValueEquality {
        left: ValueId,
        right: ValueId,
        negated: bool,
    },
    /// A syntactic ordered comparison between exact value reads, without a
    /// claim that the operation is an intrinsic integer or floating order.
    ValueOrdering {
        left: ValueId,
        right: ValueId,
        relation: IntegerComparison,
    },
}

impl GuardPredicate {
    /// The value domain the `guard.predicate` row field publishes
    /// (issue #2515), in variant order.
    pub const LABELS: &'static [&'static str] = &[
        "constant_boolean",
        "null_comparison",
        "constant_equality",
        "ordered_integer_comparison",
        "ordered_float_comparison",
        "nan_comparison",
        "instance_of",
        "exact_class",
        "has_member",
        "truthy",
        "opaque",
        "value_equality",
        "value_ordering",
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::ConstantBoolean { .. } => "constant_boolean",
            Self::NullComparison { .. } => "null_comparison",
            Self::ConstantEquality { .. } => "constant_equality",
            Self::OrderedIntegerComparison { .. } => "ordered_integer_comparison",
            Self::OrderedFloatComparison { .. } => "ordered_float_comparison",
            Self::NanComparison { .. } => "nan_comparison",
            Self::InstanceOf { .. } => "instance_of",
            Self::ExactClass { .. } => "exact_class",
            Self::HasMember { .. } => "has_member",
            Self::Truthy { .. } => "truthy",
            Self::Opaque { .. } => "opaque",
            Self::ValueEquality { .. } => "value_equality",
            Self::ValueOrdering { .. } => "value_ordering",
        }
    }

    /// The value the predicate proves the condition always takes, when it
    /// proves one at all.
    pub const fn constant_value(self) -> Option<bool> {
        match self {
            Self::ConstantBoolean { value } => Some(value),
            Self::NullComparison { .. }
            | Self::ConstantEquality { .. }
            | Self::OrderedIntegerComparison { .. }
            | Self::OrderedFloatComparison { .. }
            | Self::NanComparison { .. }
            | Self::InstanceOf { .. }
            | Self::ExactClass { .. }
            | Self::HasMember { .. }
            | Self::Truthy { .. }
            | Self::ValueEquality { .. }
            | Self::ValueOrdering { .. }
            | Self::Opaque { .. } => None,
        }
    }
}

/// One successor arm of a guarded decision, named the way a lowerer knows it.
///
/// Control-edge IDs are assigned when the canonical edge table is sorted at
/// freeze time, so a lowering-time row cannot carry one. The destination and
/// edge kind are what the lowerer chose and are together unique among one
/// point's outgoing edges, which is what makes the freeze-time resolution to a
/// [`ControlEdgeId`] exact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GuardArm {
    pub target_point: ProgramPointId,
    pub kind: ControlEdgeKind,
}

/// One normalized decision-point condition, as construction parts.
///
/// An arm is `None` when the lowerer emitted no edge for it. That is the
/// ordinary shape of a folded constant condition -- `if (false)` has no true
/// arm at all -- and it is the whole reason the predicate has to be recorded
/// separately from the topology.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GuardFactParts {
    pub id: GuardId,
    pub point: ProgramPointId,
    pub subject: Option<ValueId>,
    pub predicate: GuardPredicate,
    pub true_arm: Option<GuardArm>,
    pub false_arm: Option<GuardArm>,
    pub source: SourceMappingId,
    pub evidence: EvidenceId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwitchFactKind {
    Expression,
    Expressionless,
    Type,
}

impl SwitchFactKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Expression => "expression",
            Self::Expressionless => "expressionless",
            Self::Type => "type",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwitchSelectorDomain {
    Boolean,
    Open,
}

impl SwitchSelectorDomain {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Boolean => "boolean",
            Self::Open => "open",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SwitchEdgeParts {
    pub source_point: ProgramPointId,
    pub arm: GuardArm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SwitchCaseFactParts {
    pub value: ValueId,
    pub edge: SwitchEdgeParts,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SwitchFactParts {
    pub id: SwitchFactId,
    pub kind: SwitchFactKind,
    pub point: ProgramPointId,
    pub selector: Option<ValueId>,
    pub selector_domain: SwitchSelectorDomain,
    pub cases: Vec<SwitchCaseFactParts>,
    pub default_edge: Option<SwitchEdgeParts>,
    pub default_present: bool,
    pub source: SourceMappingId,
    pub evidence: EvidenceId,
}

/// The qualified type identity of one call's receiver or associated owner, as
/// the file alone proves it.
///
/// The segments are the qualified path of the receiver's declared type after
/// the language's built-in dereferences, outermost first, resolved through
/// this file's own import bindings when the written name is terminal-only.
/// When the call has no receiver, the segments instead name the associated
/// function's owner. `member` is the method name the call applies; the call
/// site's argument count is the arity. This is a file-local fact: no workspace resolution and
/// no model lookup took part in producing it. A query that reaches the call
/// site applies model contracts (collection flow, deferred factories) from
/// this shape. Before the semantic IR was stored as rows, the Rust lowerer
/// applied those contracts itself during lowering, which made the artifact
/// depend on the active model set and therefore unfit for a blob-keyed row.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallReceiverTypeFact {
    pub call_site: CallSiteId,
    /// At least two segments: a terminal-only name that the file cannot bind
    /// to a qualified path is not a fact. With no call receiver, this is the
    /// associated function's owner identity.
    pub receiver_type: Box<[Box<str>]>,
    pub member: Box<str>,
}

/// Mutable construction parts. Once accepted by
/// [`crate::analyzer::semantic::SemanticArtifact::try_new`],
/// every collection is boxed and only shared immutably.
/// A syntax-derived projection that has no value-flow meaning until selected
/// declaration authority proves the constructor, field, and binding mode.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GuardedPatternProjection {
    /// Dense, deterministic ordinal within the procedure. Virtual event IDs
    /// derive from this ordinal after selected admission.
    pub ordinal: u32,
    pub point: ProgramPointId,
    pub whole_value: ValueId,
    pub binder: ValueId,
    pub pattern_source: SourceMappingId,
    pub binder_source: SourceMappingId,
    /// Exact omitted binding-projection obligation, identified by its ordinal
    /// within this procedure. An unlinked candidate discharges nothing.
    pub gap: Option<SemanticGapId>,
    pub declared_path_len: u8,
    pub path: Box<[PatternProjectionStep]>,
    pub status: PatternProjectionStatus,
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PatternProjectionStep {
    Tuple(u32),
    Named(Box<str>),
    /// An authored model member declaration ID, never a variant display name.
    /// Endpoint paths admit this step; stored guarded-pattern IR rejects it.
    Variant {
        declaration: Box<str>,
    },
    /// The summarized indexed element of an authored endpoint, never stored IR.
    Element,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PatternProjectionStatus {
    Unevaluated,
}

#[derive(Debug, Clone)]
pub struct ProcedureSemanticsParts {
    pub(super) candidate_alternate: Option<Box<CandidateMacroAlternateParts>>,
    /// None means unavailable signature; Some([]) means declared zero results.
    pub declared_result_classes: Option<Box<[StaticTypeClass]>>,
    pub id: ProcedureId,
    pub locator: SemanticLocator,
    /// Query-time source regions this procedure does not lower. Nested
    /// procedures can independently own source inside these holes. These
    /// in-memory ownership facts are not part of the persisted IR row format.
    pub source_range_holes: Vec<crate::analyzer::semantic::SourceSpan>,
    pub lexical_parent: Option<ProcedureId>,
    pub kind: ProcedureKind,
    pub properties: ProcedureProperties,
    /// Per-procedure lowering witness. The source-boundary account is discarded
    /// before this result leaves the lowerer.
    pub footprint_coverage: ProcedureFootprintCoverage,
    pub call_control_coverage: ProcedureCallControlCoverage,
    pub source: SourceMappingId,
    pub evidence: EvidenceId,
    pub values: Vec<SemanticValue>,
    pub allocations: Vec<AllocationSite>,
    pub memory_locations: Vec<MemoryLocation>,
    pub captures: Vec<CaptureBinding>,
    pub call_sites: Vec<SemanticCallSite>,
    pub source_mappings: Vec<SourceMapping>,
    pub statement_entries: Vec<StatementEntrySite>,
    pub loop_sites: Vec<LoopSite>,
    pub evidence_rows: Vec<Evidence>,
    pub gaps: Vec<SemanticGap>,
    pub blocks: Vec<BasicBlock>,
    pub points: Vec<ProgramPoint>,
    pub control_edges: Vec<ControlEdge>,
    pub guard_facts: Vec<GuardFactParts>,
    pub switch_facts: Vec<SwitchFactParts>,
    pub cleanup_chains: super::CleanupChains,
    pub drops: Vec<DropFact>,
    pub move_outs: Vec<MoveOutFact>,
    pub scope_ends: Vec<ScopeEndFact>,
    pub pointer_origins: Vec<PointerOrigin>,
    pub pointer_aliases: Vec<PointerAlias>,
    pub pointer_accesses: Vec<PointerAccess>,
    pub pointer_invalidations: Vec<PointerInvalidation>,
    pub incomplete_facts: Vec<SemanticIncompleteFact>,
    /// Written receiver types of method calls, in increasing call-site order
    /// with at most one fact per call site.
    pub receiver_type_facts: Vec<CallReceiverTypeFact>,
    /// Guarded syntax candidates; these are never active IR effects.
    pub guarded_pattern_projections: Vec<GuardedPatternProjection>,
    /// Go builtin-shaped calls this procedure's file-local lowerer omitted as
    /// runtime calls. Workspace queries validate these names against the
    /// package declaration index.
    pub go_predeclared_builtin_assumptions: Vec<GoPredeclaredBuiltin>,
}

/// A complete alternative, isolated from ordinary executable rows (#10972).
#[derive(Debug, Clone)]
pub(super) struct CandidateMacroAlternateParts {
    pub parts: ProcedureSemanticsParts,
    /// One record per candidate invocation, in canonical order.
    pub candidates: Box<[CandidateRecord]>,
}

/// The byte extent of a candidate invocation in its file. It is only a lookup
/// index inside one blob's artifact: digests, receipts and read keys use the
/// position-free base call identity and never an offset (#11251).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CandidateAnchor {
    pub start_byte: u32,
    pub end_byte: u32,
}

impl CandidateAnchor {
    pub fn of(span: crate::analyzer::semantic::SourceSpan) -> Self {
        Self {
            start_byte: span.start_byte(),
            end_byte: span.end_byte(),
        }
    }

    /// The extent of a call's source mapping in `parts`.
    pub fn of_call(parts: &ProcedureSemanticsParts, call: CallSiteId) -> Option<Self> {
        let call = parts
            .call_sites
            .get(call.index())
            .filter(|site| site.id == call)?;
        let mapping = parts.source_mappings.get(call.source.index())?;
        Some(Self::of(mapping.locator.anchor().span()))
    }

    pub const fn contains(self, inner: Self) -> bool {
        self.start_byte <= inner.start_byte && inner.end_byte <= self.end_byte
    }
}

/// What the alternate does with one candidate invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CandidateRealization {
    /// The alternate lowers the invocation to this runtime call.
    RuntimeCall(CallSiteId),
    /// The alternate lowers the invocation to control flow and values; it has
    /// no call at the anchor.
    Intrinsic,
    /// The alternate keeps the same logical call and proves that the
    /// invocation introduces no items into the lexical scope.
    LexicalNoItemsIntroduced,
}

/// One candidate invocation of a guarded alternate (#11251).
///
/// `base_call` is the base call the invocation replaces. An invocation nested
/// in the operands of an opaque candidate has no base call of its own (the base
/// does not lower the operands); it names the nearest enclosing base candidate
/// call, whose anchor contains this one. Records are ordered by
/// (`base_call`, `anchor`); the ordinal among records sharing a `base_call`
/// completes the position-free identity of a candidate within one procedure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CandidateRecord {
    pub anchor: CandidateAnchor,
    pub base_call: CallSiteId,
    pub realization: CandidateRealization,
}

impl CandidateRecord {
    /// The record of an alternate that keeps `call` as a runtime call replacing
    /// the base call with the same id and anchor.
    pub fn same_call(parts: &ProcedureSemanticsParts, call: CallSiteId) -> Self {
        Self {
            anchor: CandidateAnchor::of_call(parts, call).expect("a call with a source mapping"),
            base_call: call,
            realization: CandidateRealization::RuntimeCall(call),
        }
    }
}

/// The shared validation of an alternate's candidate records, used by lowering
/// and by artifact construction. `Err` names the violated rule.
pub fn validate_candidate_records(
    base: &ProcedureSemanticsParts,
    alternate: &ProcedureSemanticsParts,
    records: &[CandidateRecord],
) -> Result<(), String> {
    validate_candidate_records_with_anchor(
        |call| CandidateAnchor::of_call(base, call),
        alternate,
        records,
    )
}

pub(super) fn validate_candidate_records_with_anchor(
    base_anchor: impl Fn(CallSiteId) -> Option<CandidateAnchor>,
    alternate: &ProcedureSemanticsParts,
    records: &[CandidateRecord],
) -> Result<(), String> {
    if records.is_empty() {
        return Err("an alternate needs at least one candidate record".to_owned());
    }
    let alternate_anchors = (0..alternate.call_sites.len())
        .filter_map(|index| CandidateAnchor::of_call(alternate, CallSiteId::new(index as u32)))
        .collect::<std::collections::HashSet<_>>();
    let mut previous = None;
    let mut alternate_calls = std::collections::HashSet::new();
    for record in records {
        let key = (record.base_call, record.anchor);
        if record.anchor.start_byte >= record.anchor.end_byte {
            return Err(format!("candidate anchor {:?} is empty", record.anchor));
        }
        if previous.is_some_and(|previous| previous >= key) {
            return Err(format!(
                "candidate records are not strictly ordered by (base call, anchor): {record:?}"
            ));
        }
        previous = Some(key);
        let Some(base_anchor) = base_anchor(record.base_call) else {
            return Err(format!(
                "candidate {record:?} has no base call mapping in the base procedure"
            ));
        };
        if !base_anchor.contains(record.anchor) {
            return Err(format!(
                "candidate {record:?} is not inside its base call anchor {base_anchor:?}"
            ));
        }
        match record.realization {
            CandidateRealization::RuntimeCall(call) => {
                if CandidateAnchor::of_call(alternate, call) != Some(record.anchor) {
                    return Err(format!(
                        "runtime-call candidate {record:?} has no alternate call at its anchor"
                    ));
                }
                if !alternate_calls.insert(call) {
                    return Err(format!(
                        "alternate call {call:?} realizes more than one candidate"
                    ));
                }
            }
            CandidateRealization::Intrinsic => {
                if alternate_anchors.contains(&record.anchor) {
                    return Err(format!(
                        "intrinsic candidate {record:?} still has an alternate call at its anchor"
                    ));
                }
                if !alternate.source_mappings.iter().any(|mapping| {
                    CandidateAnchor::of(mapping.locator.anchor().span()) == record.anchor
                }) {
                    return Err(format!(
                        "intrinsic candidate {record:?} has no alternate source mapping at its anchor"
                    ));
                }
            }
            CandidateRealization::LexicalNoItemsIntroduced => {
                if base_anchor != record.anchor || !alternate_anchors.contains(&record.anchor) {
                    return Err(format!(
                        "lexical-guard candidate {record:?} does not keep the same logical call"
                    ));
                }
            }
        }
    }
    Ok(())
}

impl ProcedureSemanticsParts {
    /// Every direct or anchor-derived place destruction, in publication order.
    pub fn logical_drops(&self) -> impl Iterator<Item = LogicalDropFact<'_>> {
        super::artifact::logical_drops(&self.drops, &self.cleanup_chains)
    }

    // The row census includes alternate payloads but not their boxed headers.
    pub(crate) fn retained_layout(&self) -> (usize, usize) {
        let mut headers =
            std::mem::size_of::<Self>().saturating_add(self.cleanup_chains.index_retained_bytes());
        let mut invalidations = self.pointer_invalidations.len();
        if let Some(alternate) = &self.candidate_alternate {
            headers = headers
                .saturating_add(std::mem::size_of::<CandidateMacroAlternateParts>())
                .saturating_add(alternate.parts.cleanup_chains.index_retained_bytes());
            invalidations =
                invalidations.saturating_add(alternate.parts.pointer_invalidations.len());
        }
        (headers, invalidations)
    }

    /// Split a completed demand reconstruction into a shared native base
    /// and the single requested alternate. Nothing partial is published.
    #[doc(hidden)]
    pub fn take_candidate_macro_alternate_parts(
        &mut self,
    ) -> Option<(Self, Box<[CandidateRecord]>)> {
        self.candidate_alternate
            .take()
            .map(|alternate| (alternate.parts, alternate.candidates))
    }

    /// Isolated parts for the guarded publication encoder.
    #[doc(hidden)]
    pub fn candidate_macro_alternate_parts(&self) -> Option<(&Self, &[CandidateRecord])> {
        self.candidate_alternate
            .as_ref()
            .map(|alternate| (&alternate.parts, alternate.candidates.as_ref()))
    }

    /// Attach an alternative for later validated artifact construction.
    pub fn attach_candidate_macro_alternate(
        &mut self,
        alternate: ProcedureSemanticsParts,
        candidates: Box<[CandidateRecord]>,
    ) {
        assert!(self.candidate_alternate.is_none());
        assert!(alternate.candidate_alternate.is_none());
        assert_eq!(self.id, alternate.id);
        assert_eq!(self.locator, alternate.locator);
        if let Err(violation) = validate_candidate_records(self, &alternate, &candidates) {
            panic!("invalid candidate records for {:?}: {violation}", self.id);
        }
        self.candidate_alternate = Some(Box::new(CandidateMacroAlternateParts {
            parts: alternate,
            candidates,
        }));
    }

    pub fn new(
        id: ProcedureId,
        locator: SemanticLocator,
        kind: ProcedureKind,
        source: SourceMappingId,
        evidence: EvidenceId,
    ) -> Self {
        Self {
            id,
            locator,
            candidate_alternate: None,
            declared_result_classes: None,
            source_range_holes: Vec::new(),
            lexical_parent: None,
            kind,
            properties: ProcedureProperties::default(),
            footprint_coverage: ProcedureFootprintCoverage::unclassified(),
            call_control_coverage: ProcedureCallControlCoverage::default(),
            source,
            evidence,
            values: Vec::new(),
            allocations: Vec::new(),
            memory_locations: Vec::new(),
            captures: Vec::new(),
            call_sites: Vec::new(),
            source_mappings: Vec::new(),
            statement_entries: Vec::new(),
            loop_sites: Vec::new(),
            evidence_rows: Vec::new(),
            gaps: Vec::new(),
            blocks: Vec::new(),
            points: Vec::new(),
            control_edges: Vec::new(),
            guard_facts: Vec::new(),
            switch_facts: Vec::new(),
            cleanup_chains: super::CleanupChains::default(),
            drops: Vec::new(),
            move_outs: Vec::new(),
            scope_ends: Vec::new(),
            pointer_origins: Vec::new(),
            pointer_aliases: Vec::new(),
            pointer_accesses: Vec::new(),
            pointer_invalidations: Vec::new(),
            incomplete_facts: Vec::new(),
            receiver_type_facts: Vec::new(),
            guarded_pattern_projections: Vec::new(),
            go_predeclared_builtin_assumptions: Vec::new(),
        }
    }
}

/// Borrowed destruction fact, including a point projected from a cleanup anchor.
#[derive(Debug, Clone, Copy)]
pub struct LogicalDropFact<'a> {
    pub place: &'a SemanticPlace,
    pub point: ProgramPointId,
    pub behavior: &'a DropBehavior,
    pub source: SourceMappingId,
    pub evidence: EvidenceId,
}

#[derive(Debug, Clone, Copy)]
pub struct LogicalScopeEndFact<'a> {
    pub place: &'a SemanticPlace,
    pub at: ScopeEndAt,
    pub source: SourceMappingId,
    pub evidence: EvidenceId,
}
impl LogicalScopeEndFact<'_> {
    pub fn to_owned(self) -> ScopeEndFact {
        ScopeEndFact {
            place: self.place.clone(),
            at: self.at,
            source: self.source,
            evidence: self.evidence,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum LogicalIncompleteSubject<'a> {
    Procedure,
    Place(&'a SemanticPlace),
    Value(ValueId),
    PointerOrigin(PointerOriginId),
}
#[derive(Debug, Clone, Copy)]
pub struct LogicalIncompleteFact<'a> {
    pub point: ProgramPointId,
    pub subject: LogicalIncompleteSubject<'a>,
    pub reason: SemanticIncompleteReason,
    pub source: SourceMappingId,
    pub evidence: EvidenceId,
}

#[cfg(test)]
mod value_flow_hash_stability {
    use super::*;
    use std::hash::{Hash, Hasher};

    #[derive(Default)]
    struct HashBytes(Vec<Vec<u8>>);

    macro_rules! numeric_write {
        ($name:ident, $ty:ty) => {
            fn $name(&mut self, value: $ty) {
                self.write(&value.to_le_bytes());
            }
        };
    }

    impl Hasher for HashBytes {
        fn finish(&self) -> u64 {
            0
        }
        fn write(&mut self, bytes: &[u8]) {
            self.0.push(bytes.to_vec());
        }
        numeric_write!(write_u8, u8);
        numeric_write!(write_u16, u16);
        numeric_write!(write_u32, u32);
        numeric_write!(write_u64, u64);
        numeric_write!(write_u128, u128);
        numeric_write!(write_i8, i8);
        numeric_write!(write_i16, i16);
        numeric_write!(write_i32, i32);
        numeric_write!(write_i64, i64);
        numeric_write!(write_i128, i128);
        fn write_usize(&mut self, value: usize) {
            self.write_u64(u64::try_from(value).unwrap());
        }
        fn write_isize(&mut self, value: isize) {
            self.write_i64(i64::try_from(value).unwrap());
        }
    }

    #[test]
    fn encoded_hash_is_stable() {
        use crate::analyzer::semantic::ids::SemanticDigestHasher;
        let kinds = [
            ValueFlowKind::Local,
            ValueFlowKind::OwnershipUnknown,
            ValueFlowKind::Transfer(ValueTransfer {
                kind: TransferKind::Copy,
                operation: TransferOperation::None,
            }),
            ValueFlowKind::BackingStore {
                offset: BackingStoreOffset::Zero,
            },
            ValueFlowKind::IntegerOffset {
                offset: SignedIntegerMagnitude::new(false, 3),
            },
            ValueFlowKind::BackingStoreAlternative {
                offset: BackingStoreOffset::Zero,
                allocation: AllocationId::new(2),
            },
            ValueFlowKind::Parameter,
            ValueFlowKind::Receiver,
            ValueFlowKind::Return,
            ValueFlowKind::IndexedReturn { ordinal: 2 },
            ValueFlowKind::ReferenceBoxing,
            ValueFlowKind::ReferenceUnboxing,
            ValueFlowKind::LanguageDefined,
            ValueFlowKind::ByValueCapture,
            ValueFlowKind::AddressOf,
            ValueFlowKind::MemoryLoad {
                location: MemoryLocationId::new(2),
            },
        ];
        let mut actual = String::new();
        for kind in kinds {
            let mut bytes = HashBytes::default();
            kind.hash(&mut bytes);
            let encoded = bytes
                .0
                .iter()
                .map(|chunk| {
                    chunk
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>()
                })
                .collect::<Vec<_>>()
                .join("/");
            let mut digest =
                SemanticDigestHasher::new(b"bifrost-value-flow-kind-hash-stability-v1");
            kind.hash(&mut digest);
            actual.push_str(&format!(
                "{} {} {}\n",
                kind.label(),
                encoded,
                digest.finish_digest()
            ));
        }
        assert_eq!(
            actual,
            include_str!("../../../../tests/fixtures/value-flow-kind-hash-v1.txt")
        );
    }
}
