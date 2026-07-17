//! Immutable, language-neutral procedure semantics.
//!
//! The IR deliberately keeps dense IDs in hot rows.  A bare [`ValueId`] (or
//! any other procedure-local ID) is meaningful only together with its owning
//! procedure.  Provider and oracle boundaries should therefore use
//! [`ProcedureHandle`] or [`ProcedureLocalHandle`], while validated artifact
//! internals can use the compact IDs directly.

use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use crate::compact_graph::CompactRows;
use crate::hash::{HashMap, HashSet};

use super::capabilities::{CapabilitySupport, SemanticCapabilities, SemanticCapability};
use super::ids::{
    AllocationId, BlockId, CallSiteId, CaptureId, ControlEdgeId, DeclarationSegmentKind,
    EvidenceId, MemoryLocationId, ProcedureId, ProgramPointId, SemanticArtifactKey, SemanticGapId,
    SemanticLocator, SemanticRole, SourceMappingId, ValueId,
};
use super::provider::{SemanticBudget, SemanticBudgetExceeded, SemanticWork};

/// A stable category for one validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SemanticIrErrorKind {
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
}

impl SemanticIrErrorKind {
    pub const fn label(self) -> &'static str {
        match self {
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
        }
    }
}

/// A construction-time invariant violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticIrError {
    kind: SemanticIrErrorKind,
    procedure: Option<ProcedureId>,
    detail: Box<str>,
}

impl SemanticIrError {
    fn artifact(kind: SemanticIrErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            procedure: None,
            detail: detail.into().into_boxed_str(),
        }
    }

    fn procedure(
        procedure: ProcedureId,
        kind: SemanticIrErrorKind,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            procedure: Some(procedure),
            detail: detail.into().into_boxed_str(),
        }
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
        if let Some(procedure) = self.procedure {
            write!(
                formatter,
                "semantic IR {} error in procedure {}: {}",
                self.kind.label(),
                procedure,
                self.detail
            )
        } else {
            write!(
                formatter,
                "semantic IR {} error: {}",
                self.kind.label(),
                self.detail
            )
        }
    }
}

impl std::error::Error for SemanticIrError {}

/// Failure to validate or fit a semantic artifact into its retained-work
/// budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SemanticArtifactBuildError {
    Invalid(SemanticIrError),
    ExceededBudget(SemanticBudgetExceeded),
}

impl SemanticArtifactBuildError {
    pub const fn invalid_ir(&self) -> Option<&SemanticIrError> {
        match self {
            Self::Invalid(error) => Some(error),
            Self::ExceededBudget(_) => None,
        }
    }

    pub const fn budget_exceeded(&self) -> Option<SemanticBudgetExceeded> {
        match self {
            Self::Invalid(_) => None,
            Self::ExceededBudget(error) => Some(*error),
        }
    }
}

impl From<SemanticIrError> for SemanticArtifactBuildError {
    fn from(error: SemanticIrError) -> Self {
        Self::Invalid(error)
    }
}

impl From<SemanticBudgetExceeded> for SemanticArtifactBuildError {
    fn from(error: SemanticBudgetExceeded) -> Self {
        Self::ExceededBudget(error)
    }
}

impl fmt::Display for SemanticArtifactBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(error) => error.fmt(formatter),
            Self::ExceededBudget(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for SemanticArtifactBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Invalid(error) => Some(error),
            Self::ExceededBudget(error) => Some(error),
        }
    }
}

/// The language-neutral shape of an executable body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProcedureKind {
    Function,
    Method,
    Constructor,
    Initializer,
    LocalFunction,
    Lambda,
    Closure,
    Accessor,
    Operator,
}

impl ProcedureKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Function => "function",
            Self::Method => "method",
            Self::Constructor => "constructor",
            Self::Initializer => "initializer",
            Self::LocalFunction => "local_function",
            Self::Lambda => "lambda",
            Self::Closure => "closure",
            Self::Accessor => "accessor",
            Self::Operator => "operator",
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
}

/// The semantic role of a value row.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SemanticValueKind {
    Local,
    Parameter { ordinal: u32 },
    Receiver,
    Return,
    Temporary,
    Constant,
    Exception,
    Callable,
    AwaitResult,
    LanguageDefined(Box<str>),
}

impl SemanticValueKind {
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Parameter { .. } => "parameter",
            Self::Receiver => "receiver",
            Self::Return => "return",
            Self::Temporary => "temporary",
            Self::Constant => "constant",
            Self::Exception => "exception",
            Self::Callable => "callable",
            Self::AwaitResult => "await_result",
            Self::LanguageDefined(_) => "language_defined",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SemanticValue {
    pub id: ValueId,
    pub kind: SemanticValueKind,
    pub source: SourceMappingId,
    pub evidence: EvidenceId,
}

/// The abstract allocation represented by an allocation-site row.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AllocationKind {
    Object,
    Array,
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
    Static {
        member: SemanticLocator,
    },
    Index {
        base: ValueId,
        index: Option<ValueId>,
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
    },
}

impl MemoryLocationKind {
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Field { .. } => "field",
            Self::Static { .. } => "static",
            Self::Index { .. } => "index",
            Self::LexicalCell { .. } => "lexical_cell",
            Self::Capture { .. } => "capture",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MemoryLocation {
    pub id: MemoryLocationId,
    pub kind: MemoryLocationKind,
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

/// A resolved local body or a durable external declaration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CallableTarget {
    Local(ProcedureId),
    /// A declaration in this artifact whose procedure body was not published
    /// because materialization was incomplete.  This form is legal only in an
    /// explicitly unproven or budget-exceeded candidate set.
    Unmaterialized(SemanticLocator),
    External(SemanticLocator),
}

impl CallableTarget {
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Local(_) => "local",
            Self::Unmaterialized(_) => "unmaterialized",
            Self::External(_) => "external",
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
            Self::Ambiguous(_) => "ambiguous",
            Self::Unknown => "unknown",
            Self::Unsupported => "unsupported",
            Self::Unproven(_) => "unproven",
            Self::ExceededBudget(_) => "exceeded_budget",
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SemanticCallSite {
    pub id: CallSiteId,
    pub point: ProgramPointId,
    pub callee: ValueId,
    pub receiver: Option<ValueId>,
    pub arguments: Box<[ValueId]>,
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
}

/// Whether the evidence actually establishes the attached fact.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ProofStatus {
    Proven,
    Unproven(Box<str>),
}

impl ProofStatus {
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
    Point,
    Value(ValueId),
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

impl SemanticGapSubject {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Procedure => "procedure",
            Self::Point => "point",
            Self::Value(_) => "value",
            Self::MemoryLocation(_) => "memory_location",
            Self::Capture(_) => "capture",
            Self::CallSite(_) => "call_site",
            Self::CallContinuation { .. } => "call_continuation",
            Self::AsyncContinuation { .. } => "async_continuation",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SemanticGap {
    pub id: SemanticGapId,
    pub point: ProgramPointId,
    pub subject: SemanticGapSubject,
    pub capability: SemanticCapability,
    pub kind: SemanticGapKind,
    /// Required exactly when `kind` is `ExceededBudget`.
    pub budget: Option<SemanticBudgetExceeded>,
    pub detail: Box<str>,
    pub source: SourceMappingId,
    pub evidence: EvidenceId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValueFlowKind {
    Local,
    Parameter,
    Receiver,
    Return,
}

impl ValueFlowKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Parameter => "parameter",
            Self::Receiver => "receiver",
            Self::Return => "return",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemoryAccessKind {
    Field,
    Static,
    Index,
    LexicalCell,
    Capture,
}

impl MemoryAccessKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Field => "field",
            Self::Static => "static",
            Self::Index => "index",
            Self::LexicalCell => "lexical_cell",
            Self::Capture => "capture",
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
    ValueFlow {
        kind: ValueFlowKind,
        source: ValueId,
        target: ValueId,
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
}

impl SemanticEffect {
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Entry => "entry",
            Self::NormalExit => "normal_exit",
            Self::ExceptionalExit => "exceptional_exit",
            Self::Assignment { .. } => "assignment",
            Self::ValueFlow { .. } => "value_flow",
            Self::Allocation { .. } => "allocation",
            Self::MemoryLoad { .. } => "memory_load",
            Self::MemoryStore { .. } => "memory_store",
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
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ControlEdge {
    pub source_point: ProgramPointId,
    pub target_point: ProgramPointId,
    pub kind: ControlEdgeKind,
    pub source: SourceMappingId,
    pub evidence: EvidenceId,
}

/// Immutable intraprocedural control-flow topology.
///
/// Edge IDs are procedure-local indices into one canonical rich-edge table.
/// Outgoing rows are contiguous ranges in that source-sorted table, while
/// incoming rows retain edge IDs so both directions share the same payload.
#[derive(Debug, Clone)]
pub struct ControlFlowGraph {
    edges: Box<[ControlEdge]>,
    outgoing_row_offsets: Box<[u32]>,
    incoming: CompactRows<ControlEdgeId>,
}

impl ControlFlowGraph {
    fn try_from_edges(
        procedure: ProcedureId,
        point_count: usize,
        mut edges: Vec<ControlEdge>,
    ) -> Result<Self, SemanticIrError> {
        let edge_count = u32::try_from(edges.len()).map_err(|_| {
            SemanticIrError::procedure(
                procedure,
                SemanticIrErrorKind::ResourceLimit,
                format!(
                    "control-edge count {} cannot be represented by compact u32 row offsets",
                    edges.len()
                ),
            )
        })?;
        for edge in &edges {
            if edge.source_point.index() >= point_count || edge.target_point.index() >= point_count
            {
                return Err(SemanticIrError::procedure(
                    procedure,
                    SemanticIrErrorKind::ControlFlowContract,
                    format!(
                        "{} edge {} -> {} cannot be frozen for {point_count} program points",
                        edge.kind.label(),
                        edge.source_point,
                        edge.target_point
                    ),
                ));
            }
        }

        edges.sort_unstable_by_key(control_edge_sort_key);

        let row_capacity = point_count.checked_add(1).ok_or_else(|| {
            SemanticIrError::procedure(
                procedure,
                SemanticIrErrorKind::ResourceLimit,
                "control-flow row count overflows usize",
            )
        })?;
        let mut outgoing_row_offsets = Vec::with_capacity(row_capacity);
        outgoing_row_offsets.push(0);
        let mut cursor = 0usize;
        for source in 0..point_count {
            while cursor < edges.len() && edges[cursor].source_point.index() == source {
                cursor += 1;
            }
            outgoing_row_offsets.push(u32::try_from(cursor).map_err(|_| {
                SemanticIrError::procedure(
                    procedure,
                    SemanticIrErrorKind::ResourceLimit,
                    "control-flow outgoing offset does not fit in u32",
                )
            })?);
        }
        if cursor != edges.len() {
            return Err(SemanticIrError::procedure(
                procedure,
                SemanticIrErrorKind::ControlFlowContract,
                "canonical control-edge table contains an out-of-range source row",
            ));
        }

        let mut incoming_counts = vec![0_u32; point_count];
        for edge in &edges {
            let count = &mut incoming_counts[edge.target_point.index()];
            *count = count.checked_add(1).ok_or_else(|| {
                SemanticIrError::procedure(
                    procedure,
                    SemanticIrErrorKind::ResourceLimit,
                    format!(
                        "incoming edge count for program point {} does not fit in u32",
                        edge.target_point
                    ),
                )
            })?;
        }
        let mut incoming_offsets = Vec::with_capacity(row_capacity);
        incoming_offsets.push(0);
        let mut incoming_total = 0_u32;
        for count in incoming_counts {
            incoming_total = incoming_total.checked_add(count).ok_or_else(|| {
                SemanticIrError::procedure(
                    procedure,
                    SemanticIrErrorKind::ResourceLimit,
                    "control-flow incoming offsets do not fit in u32",
                )
            })?;
            incoming_offsets.push(incoming_total);
        }
        debug_assert_eq!(incoming_total, edge_count);

        let mut incoming_cursors = incoming_offsets[..point_count].to_vec();
        let mut incoming_edge_ids = vec![ControlEdgeId::default(); edges.len()];
        for (index, edge) in edges.iter().enumerate() {
            let target = edge.target_point.index();
            let destination = incoming_cursors[target] as usize;
            incoming_edge_ids[destination] =
                ControlEdgeId::try_from_index(index).map_err(|error| {
                    SemanticIrError::procedure(
                        procedure,
                        SemanticIrErrorKind::ResourceLimit,
                        error.to_string(),
                    )
                })?;
            incoming_cursors[target] = incoming_cursors[target]
                .checked_add(1)
                .expect("validated incoming edge count cannot overflow");
        }

        Self::try_from_parts(
            procedure,
            point_count,
            edges,
            outgoing_row_offsets,
            incoming_offsets,
            incoming_edge_ids,
        )
    }

    fn try_from_parts(
        procedure: ProcedureId,
        point_count: usize,
        edges: Vec<ControlEdge>,
        outgoing_row_offsets: Vec<u32>,
        incoming_offsets: Vec<u32>,
        incoming_edge_ids: Vec<ControlEdgeId>,
    ) -> Result<Self, SemanticIrError> {
        let incoming =
            CompactRows::try_from_parts(incoming_offsets, incoming_edge_ids).map_err(|detail| {
                SemanticIrError::procedure(
                    procedure,
                    SemanticIrErrorKind::ControlFlowContract,
                    format!("invalid incoming control-flow rows: {detail}"),
                )
            })?;
        let graph = Self {
            edges: edges.into_boxed_slice(),
            outgoing_row_offsets: outgoing_row_offsets.into_boxed_slice(),
            incoming,
        };
        graph.validate(procedure, point_count)?;
        Ok(graph)
    }

    fn validate(&self, procedure: ProcedureId, point_count: usize) -> Result<(), SemanticIrError> {
        let expected_offset_count = point_count.checked_add(1).ok_or_else(|| {
            SemanticIrError::procedure(
                procedure,
                SemanticIrErrorKind::ResourceLimit,
                "control-flow row count overflows usize",
            )
        })?;
        if self.outgoing_row_offsets.len() != expected_offset_count
            || self.outgoing_row_offsets.first().copied() != Some(0)
            || self
                .outgoing_row_offsets
                .last()
                .copied()
                .map(|offset| offset as usize)
                != Some(self.edges.len())
            || !self
                .outgoing_row_offsets
                .windows(2)
                .all(|pair| pair[0] <= pair[1])
        {
            return Err(SemanticIrError::procedure(
                procedure,
                SemanticIrErrorKind::ControlFlowContract,
                "outgoing control-flow row offsets are not a complete monotonic edge partition",
            ));
        }
        if self.incoming.rows() != point_count {
            return Err(SemanticIrError::procedure(
                procedure,
                SemanticIrErrorKind::ControlFlowContract,
                format!(
                    "incoming control-flow row count {} does not match {point_count} program points",
                    self.incoming.rows()
                ),
            ));
        }
        if self
            .edges
            .windows(2)
            .any(|pair| control_edge_sort_key(&pair[0]) > control_edge_sort_key(&pair[1]))
        {
            return Err(SemanticIrError::procedure(
                procedure,
                SemanticIrErrorKind::ControlFlowContract,
                "control-edge table is not in canonical order",
            ));
        }
        if self.edges.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(SemanticIrError::procedure(
                procedure,
                SemanticIrErrorKind::DuplicateEdge,
                "control-edge table contains an exact duplicate rich edge",
            ));
        }

        for point in 0..point_count {
            let start = self.outgoing_row_offsets[point] as usize;
            let end = self.outgoing_row_offsets[point + 1] as usize;
            for edge in &self.edges[start..end] {
                if edge.source_point.index() != point {
                    return Err(SemanticIrError::procedure(
                        procedure,
                        SemanticIrErrorKind::ControlFlowContract,
                        format!(
                            "outgoing row {point} contains edge {} -> {} owned by source row {}",
                            edge.source_point, edge.target_point, edge.source_point
                        ),
                    ));
                }
                if edge.target_point.index() >= point_count {
                    return Err(SemanticIrError::procedure(
                        procedure,
                        SemanticIrErrorKind::ControlFlowContract,
                        format!(
                            "edge {} -> {} has an out-of-range target",
                            edge.source_point, edge.target_point
                        ),
                    ));
                }
            }
        }

        let mut incoming_seen = vec![false; self.edges.len()];
        for point in 0..point_count {
            let incoming_row = self.incoming.row(point);
            if incoming_row.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(SemanticIrError::procedure(
                    procedure,
                    SemanticIrErrorKind::ControlFlowContract,
                    format!(
                        "incoming row {point} is not in canonical increasing control-edge order"
                    ),
                ));
            }
            for edge_id in incoming_row {
                let Some(edge) = self.edges.get(edge_id.index()) else {
                    return Err(SemanticIrError::procedure(
                        procedure,
                        SemanticIrErrorKind::ControlFlowContract,
                        format!("incoming row {point} references out-of-range edge {edge_id}"),
                    ));
                };
                if incoming_seen[edge_id.index()] {
                    return Err(SemanticIrError::procedure(
                        procedure,
                        SemanticIrErrorKind::ControlFlowContract,
                        format!("incoming rows reference edge {edge_id} more than once"),
                    ));
                }
                incoming_seen[edge_id.index()] = true;
                if edge.target_point.index() != point {
                    return Err(SemanticIrError::procedure(
                        procedure,
                        SemanticIrErrorKind::ControlFlowContract,
                        format!(
                            "incoming row {point} references edge {edge_id} targeting {}",
                            edge.target_point
                        ),
                    ));
                }
            }
        }
        if let Some(missing) = incoming_seen.iter().position(|seen| !seen) {
            return Err(SemanticIrError::procedure(
                procedure,
                SemanticIrErrorKind::ControlFlowContract,
                format!("incoming rows do not reference edge {missing}"),
            ));
        }
        Ok(())
    }

    pub fn edges(&self) -> &[ControlEdge] {
        &self.edges
    }

    pub fn edge(&self, id: ControlEdgeId) -> Option<&ControlEdge> {
        self.edges.get(id.index())
    }

    pub fn successor_edges(
        &self,
        point: ProgramPointId,
    ) -> impl ExactSizeIterator<Item = (ControlEdgeId, &ControlEdge)> + '_ {
        let point = point.index();
        assert!(
            point < self.incoming.rows(),
            "program point {point} is outside this control-flow graph"
        );
        let start = self.outgoing_row_offsets[point] as usize;
        let end = self.outgoing_row_offsets[point + 1] as usize;
        self.edges[start..end]
            .iter()
            .enumerate()
            .map(move |(offset, edge)| {
                let id = ControlEdgeId::try_from_index(start + offset)
                    .expect("validated control-edge index fits in u32");
                (id, edge)
            })
    }

    pub fn predecessor_edges(
        &self,
        point: ProgramPointId,
    ) -> impl ExactSizeIterator<Item = (ControlEdgeId, &ControlEdge)> + '_ {
        let point = point.index();
        assert!(
            point < self.incoming.rows(),
            "program point {point} is outside this control-flow graph"
        );
        let edge_ids = self.incoming.row(point);
        edge_ids.iter().copied().map(|id| {
            let edge = &self.edges[id.index()];
            (id, edge)
        })
    }
}

fn control_edge_sort_key(
    edge: &ControlEdge,
) -> (
    ProgramPointId,
    &'static str,
    ProgramPointId,
    SourceMappingId,
    EvidenceId,
) {
    (
        edge.source_point,
        edge.kind.label(),
        edge.target_point,
        edge.source,
        edge.evidence,
    )
}

/// Mutable construction parts.  Once accepted by [`SemanticArtifact::try_new`],
/// every collection is boxed and only shared immutably.
#[derive(Debug, Clone)]
pub struct ProcedureSemanticsParts {
    pub id: ProcedureId,
    pub locator: SemanticLocator,
    pub lexical_parent: Option<ProcedureId>,
    pub kind: ProcedureKind,
    pub properties: ProcedureProperties,
    pub source: SourceMappingId,
    pub evidence: EvidenceId,
    pub values: Vec<SemanticValue>,
    pub allocations: Vec<AllocationSite>,
    pub memory_locations: Vec<MemoryLocation>,
    pub captures: Vec<CaptureBinding>,
    pub call_sites: Vec<SemanticCallSite>,
    pub source_mappings: Vec<SourceMapping>,
    pub evidence_rows: Vec<Evidence>,
    pub gaps: Vec<SemanticGap>,
    pub blocks: Vec<BasicBlock>,
    pub points: Vec<ProgramPoint>,
    pub control_edges: Vec<ControlEdge>,
}

impl ProcedureSemanticsParts {
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
            lexical_parent: None,
            kind,
            properties: ProcedureProperties::default(),
            source,
            evidence,
            values: Vec::new(),
            allocations: Vec::new(),
            memory_locations: Vec::new(),
            captures: Vec::new(),
            call_sites: Vec::new(),
            source_mappings: Vec::new(),
            evidence_rows: Vec::new(),
            gaps: Vec::new(),
            blocks: Vec::new(),
            points: Vec::new(),
            control_edges: Vec::new(),
        }
    }
}

/// One validated executable body.
#[derive(Debug, Clone)]
pub struct ProcedureSemantics {
    id: ProcedureId,
    locator: SemanticLocator,
    lexical_parent: Option<ProcedureId>,
    kind: ProcedureKind,
    properties: ProcedureProperties,
    source: SourceMappingId,
    evidence: EvidenceId,
    values: Box<[SemanticValue]>,
    allocations: Box<[AllocationSite]>,
    memory_locations: Box<[MemoryLocation]>,
    captures: Box<[CaptureBinding]>,
    call_sites: Box<[SemanticCallSite]>,
    source_mappings: Box<[SourceMapping]>,
    evidence_rows: Box<[Evidence]>,
    gaps: Box<[SemanticGap]>,
    blocks: Box<[BasicBlock]>,
    points: Box<[ProgramPoint]>,
    cfg: ControlFlowGraph,
    entry_point: ProgramPointId,
    normal_exit_point: ProgramPointId,
    exceptional_exit_point: ProgramPointId,
}

impl ProcedureSemantics {
    fn try_from_parts(
        parts: ProcedureSemanticsParts,
        entry_point: ProgramPointId,
        normal_exit_point: ProgramPointId,
        exceptional_exit_point: ProgramPointId,
    ) -> Result<Self, SemanticIrError> {
        let cfg =
            ControlFlowGraph::try_from_edges(parts.id, parts.points.len(), parts.control_edges)?;
        Ok(Self {
            id: parts.id,
            locator: parts.locator,
            lexical_parent: parts.lexical_parent,
            kind: parts.kind,
            properties: parts.properties,
            source: parts.source,
            evidence: parts.evidence,
            values: parts.values.into_boxed_slice(),
            allocations: parts.allocations.into_boxed_slice(),
            memory_locations: parts.memory_locations.into_boxed_slice(),
            captures: parts.captures.into_boxed_slice(),
            call_sites: parts.call_sites.into_boxed_slice(),
            source_mappings: parts.source_mappings.into_boxed_slice(),
            evidence_rows: parts.evidence_rows.into_boxed_slice(),
            gaps: parts.gaps.into_boxed_slice(),
            blocks: parts.blocks.into_boxed_slice(),
            points: parts.points.into_boxed_slice(),
            cfg,
            entry_point,
            normal_exit_point,
            exceptional_exit_point,
        })
    }

    pub const fn id(&self) -> ProcedureId {
        self.id
    }

    pub fn locator(&self) -> &SemanticLocator {
        &self.locator
    }

    pub const fn lexical_parent(&self) -> Option<ProcedureId> {
        self.lexical_parent
    }

    pub const fn kind(&self) -> ProcedureKind {
        self.kind
    }

    pub const fn properties(&self) -> ProcedureProperties {
        self.properties
    }

    pub const fn source(&self) -> SourceMappingId {
        self.source
    }

    pub const fn evidence(&self) -> EvidenceId {
        self.evidence
    }

    pub fn values(&self) -> &[SemanticValue] {
        &self.values
    }

    pub fn allocations(&self) -> &[AllocationSite] {
        &self.allocations
    }

    pub fn memory_locations(&self) -> &[MemoryLocation] {
        &self.memory_locations
    }

    pub fn captures(&self) -> &[CaptureBinding] {
        &self.captures
    }

    pub fn call_sites(&self) -> &[SemanticCallSite] {
        &self.call_sites
    }

    pub fn source_mappings(&self) -> &[SourceMapping] {
        &self.source_mappings
    }

    pub fn evidence_rows(&self) -> &[Evidence] {
        &self.evidence_rows
    }

    pub fn gaps(&self) -> &[SemanticGap] {
        &self.gaps
    }

    pub fn blocks(&self) -> &[BasicBlock] {
        &self.blocks
    }

    pub fn points(&self) -> &[ProgramPoint] {
        &self.points
    }

    pub fn cfg(&self) -> &ControlFlowGraph {
        &self.cfg
    }

    /// Compatibility view over the canonical control-flow edge table.
    pub fn control_edges(&self) -> &[ControlEdge] {
        self.cfg.edges()
    }

    pub fn control_edge(&self, id: ControlEdgeId) -> Option<&ControlEdge> {
        self.cfg.edge(id)
    }

    pub fn successor_edges(
        &self,
        point: ProgramPointId,
    ) -> impl ExactSizeIterator<Item = (ControlEdgeId, &ControlEdge)> + '_ {
        self.cfg.successor_edges(point)
    }

    pub fn predecessor_edges(
        &self,
        point: ProgramPointId,
    ) -> impl ExactSizeIterator<Item = (ControlEdgeId, &ControlEdge)> + '_ {
        self.cfg.predecessor_edges(point)
    }

    pub const fn entry_point(&self) -> ProgramPointId {
        self.entry_point
    }

    pub const fn normal_exit_point(&self) -> ProgramPointId {
        self.normal_exit_point
    }

    pub const fn exceptional_exit_point(&self) -> ProgramPointId {
        self.exceptional_exit_point
    }

    pub fn value(&self, id: ValueId) -> Option<&SemanticValue> {
        self.values.get(id.index())
    }

    pub fn allocation(&self, id: AllocationId) -> Option<&AllocationSite> {
        self.allocations.get(id.index())
    }

    pub fn memory_location(&self, id: MemoryLocationId) -> Option<&MemoryLocation> {
        self.memory_locations.get(id.index())
    }

    pub fn capture(&self, id: CaptureId) -> Option<&CaptureBinding> {
        self.captures.get(id.index())
    }

    pub fn call_site(&self, id: CallSiteId) -> Option<&SemanticCallSite> {
        self.call_sites.get(id.index())
    }

    pub fn source_mapping(&self, id: SourceMappingId) -> Option<&SourceMapping> {
        self.source_mappings.get(id.index())
    }

    pub fn evidence_row(&self, id: EvidenceId) -> Option<&Evidence> {
        self.evidence_rows.get(id.index())
    }

    pub fn gap(&self, id: SemanticGapId) -> Option<&SemanticGap> {
        self.gaps.get(id.index())
    }

    pub fn block(&self, id: BlockId) -> Option<&BasicBlock> {
        self.blocks.get(id.index())
    }

    pub fn point(&self, id: ProgramPointId) -> Option<&ProgramPoint> {
        self.points.get(id.index())
    }
}

/// One immutable interpretation of one mounted source snapshot.
#[derive(Debug)]
pub struct SemanticArtifact {
    key: SemanticArtifactKey,
    capabilities: SemanticCapabilities,
    work: SemanticWork,
    procedures: Box<[ProcedureSemantics]>,
    procedures_by_locator: HashMap<SemanticLocator, ProcedureId>,
}

impl SemanticArtifact {
    /// Validate all artifact, procedure, side-table, event, and topology
    /// invariants before exposing immutable semantics.
    pub fn try_new(
        key: SemanticArtifactKey,
        capabilities: SemanticCapabilities,
        procedure_parts: Vec<ProcedureSemanticsParts>,
    ) -> Result<Self, SemanticIrError> {
        let mut budget = SemanticBudget::default();
        Self::try_new_with_budget(key, capabilities, procedure_parts, &mut budget).map_err(
            |error| match error {
                SemanticArtifactBuildError::Invalid(error) => error,
                SemanticArtifactBuildError::ExceededBudget(error) => {
                    SemanticIrError::artifact(SemanticIrErrorKind::ResourceLimit, error.to_string())
                }
            },
        )
    }

    /// Validate and publish an artifact while atomically charging every
    /// retained row, event, edge, nested entry, and owned string byte.
    /// Failed validation or charging leaves `budget` unchanged.
    pub fn try_new_with_budget(
        key: SemanticArtifactKey,
        capabilities: SemanticCapabilities,
        procedure_parts: Vec<ProcedureSemanticsParts>,
        budget: &mut SemanticBudget,
    ) -> Result<Self, SemanticArtifactBuildError> {
        let work = measure_artifact_work(&key, &procedure_parts);
        let mut charged_budget = budget.clone();
        charged_budget.charge(work)?;
        validate_artifact(&key, &capabilities, &procedure_parts)?;

        let mut procedures_by_locator = HashMap::default();
        let mut procedures = Vec::with_capacity(procedure_parts.len());
        for parts in procedure_parts {
            let boundaries = find_boundaries(&parts)?;
            procedures_by_locator.insert(parts.locator.clone(), parts.id);
            procedures.push(ProcedureSemantics::try_from_parts(
                parts,
                boundaries.entry,
                boundaries.normal_exit,
                boundaries.exceptional_exit,
            )?);
        }

        let artifact = Self {
            key,
            capabilities,
            work,
            procedures: procedures.into_boxed_slice(),
            procedures_by_locator,
        };
        *budget = charged_budget;
        Ok(artifact)
    }

    pub fn key(&self) -> &SemanticArtifactKey {
        &self.key
    }

    pub fn capabilities(&self) -> &SemanticCapabilities {
        &self.capabilities
    }

    pub const fn work(&self) -> SemanticWork {
        self.work
    }

    pub fn procedures(&self) -> &[ProcedureSemantics] {
        &self.procedures
    }

    pub fn procedure(&self, id: ProcedureId) -> Option<&ProcedureSemantics> {
        self.procedures.get(id.index())
    }

    pub fn procedure_id(&self, locator: &SemanticLocator) -> Option<ProcedureId> {
        self.procedures_by_locator.get(locator).copied()
    }

    pub fn procedure_by_locator(&self, locator: &SemanticLocator) -> Option<&ProcedureSemantics> {
        self.procedure(self.procedure_id(locator)?)
    }

    pub fn procedure_handle(self: &Arc<Self>, id: ProcedureId) -> Option<ProcedureHandle> {
        self.procedure(id)?;
        Some(ProcedureHandle {
            artifact: Arc::clone(self),
            id,
        })
    }
}

/// An artifact-instance-scoped procedure identity safe for provider/oracle
/// boundaries.  Two materializations may share a durable artifact key while
/// retaining different partial rows, so equality includes `Arc` identity.
#[derive(Clone)]
pub struct ProcedureHandle {
    artifact: Arc<SemanticArtifact>,
    id: ProcedureId,
}

impl ProcedureHandle {
    pub fn artifact(&self) -> &Arc<SemanticArtifact> {
        &self.artifact
    }

    pub const fn id(&self) -> ProcedureId {
        self.id
    }

    pub fn semantics(&self) -> &ProcedureSemantics {
        // Construction is private and checked by SemanticArtifact::procedure_handle.
        &self.artifact.procedures[self.id.index()]
    }

    fn scoped<I>(&self, id: I) -> ProcedureLocalHandle<I> {
        ProcedureLocalHandle {
            procedure: self.clone(),
            id,
        }
    }

    pub fn value_handle(&self, id: ValueId) -> Option<ValueHandle> {
        self.semantics().value(id)?;
        Some(self.scoped(id))
    }

    pub fn block_handle(&self, id: BlockId) -> Option<BlockHandle> {
        self.semantics().block(id)?;
        Some(self.scoped(id))
    }

    pub fn allocation_handle(&self, id: AllocationId) -> Option<AllocationHandle> {
        self.semantics().allocation(id)?;
        Some(self.scoped(id))
    }

    pub fn point_handle(&self, id: ProgramPointId) -> Option<ProgramPointHandle> {
        self.semantics().point(id)?;
        Some(self.scoped(id))
    }

    pub fn control_edge_handle(&self, id: ControlEdgeId) -> Option<ControlEdgeHandle> {
        self.semantics().control_edge(id)?;
        Some(self.scoped(id))
    }

    pub fn call_site_handle(&self, id: CallSiteId) -> Option<CallSiteHandle> {
        self.semantics().call_site(id)?;
        Some(self.scoped(id))
    }

    pub fn memory_location_handle(&self, id: MemoryLocationId) -> Option<MemoryLocationHandle> {
        self.semantics().memory_location(id)?;
        Some(self.scoped(id))
    }

    pub fn capture_handle(&self, id: CaptureId) -> Option<CaptureHandle> {
        self.semantics().capture(id)?;
        Some(self.scoped(id))
    }

    pub fn source_mapping_handle(&self, id: SourceMappingId) -> Option<SourceMappingHandle> {
        self.semantics().source_mapping(id)?;
        Some(self.scoped(id))
    }

    pub fn evidence_handle(&self, id: EvidenceId) -> Option<EvidenceHandle> {
        self.semantics().evidence_row(id)?;
        Some(self.scoped(id))
    }

    pub fn gap_handle(&self, id: SemanticGapId) -> Option<SemanticGapHandle> {
        self.semantics().gap(id)?;
        Some(self.scoped(id))
    }
}

impl fmt::Debug for ProcedureHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcedureHandle")
            .field("artifact_key", self.artifact.key())
            .field("id", &self.id)
            .finish()
    }
}

impl PartialEq for ProcedureHandle {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && Arc::ptr_eq(&self.artifact, &other.artifact)
    }
}

impl Eq for ProcedureHandle {}

impl Hash for ProcedureHandle {
    fn hash<H: Hasher>(&self, state: &mut H) {
        std::ptr::hash(Arc::as_ptr(&self.artifact), state);
        self.id.hash(state);
    }
}

/// A local ID paired with its owning artifact and procedure.  Type aliases
/// below keep APIs readable without duplicating wrapper implementations.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProcedureLocalHandle<I> {
    procedure: ProcedureHandle,
    id: I,
}

impl<I: Copy> ProcedureLocalHandle<I> {
    pub fn procedure(&self) -> &ProcedureHandle {
        &self.procedure
    }

    pub const fn id(&self) -> I {
        self.id
    }
}

pub type BlockHandle = ProcedureLocalHandle<BlockId>;
pub type ProgramPointHandle = ProcedureLocalHandle<ProgramPointId>;
pub type ControlEdgeHandle = ProcedureLocalHandle<ControlEdgeId>;
pub type ValueHandle = ProcedureLocalHandle<ValueId>;
pub type AllocationHandle = ProcedureLocalHandle<AllocationId>;
pub type CallSiteHandle = ProcedureLocalHandle<CallSiteId>;
pub type MemoryLocationHandle = ProcedureLocalHandle<MemoryLocationId>;
pub type CaptureHandle = ProcedureLocalHandle<CaptureId>;
pub type SourceMappingHandle = ProcedureLocalHandle<SourceMappingId>;
pub type EvidenceHandle = ProcedureLocalHandle<EvidenceId>;
pub type SemanticGapHandle = ProcedureLocalHandle<SemanticGapId>;

#[derive(Debug, Clone, Copy)]
struct Boundaries {
    entry: ProgramPointId,
    normal_exit: ProgramPointId,
    exceptional_exit: ProgramPointId,
}

#[derive(Default)]
struct ControlEdgeIndex {
    exact: HashSet<(
        ProgramPointId,
        ProgramPointId,
        ControlEdgeKind,
        SourceMappingId,
        EvidenceId,
    )>,
    topology: HashSet<(ProgramPointId, ProgramPointId, ControlEdgeKind)>,
    outgoing_by_kind: HashMap<(ProgramPointId, ControlEdgeKind), usize>,
    outgoing_total: HashMap<ProgramPointId, usize>,
}

impl ControlEdgeIndex {
    fn insert(&mut self, edge: &ControlEdge) -> bool {
        if !self.exact.insert((
            edge.source_point,
            edge.target_point,
            edge.kind,
            edge.source,
            edge.evidence,
        )) {
            return false;
        }
        let topology_inserted =
            self.topology
                .insert((edge.source_point, edge.target_point, edge.kind));
        if topology_inserted {
            *self
                .outgoing_by_kind
                .entry((edge.source_point, edge.kind))
                .or_default() += 1;
            *self.outgoing_total.entry(edge.source_point).or_default() += 1;
        }
        true
    }

    fn contains(
        &self,
        source: ProgramPointId,
        target: ProgramPointId,
        kind: ControlEdgeKind,
    ) -> bool {
        self.topology.contains(&(source, target, kind))
    }

    fn outgoing_count(&self, source: ProgramPointId, kind: ControlEdgeKind) -> usize {
        self.outgoing_by_kind
            .get(&(source, kind))
            .copied()
            .unwrap_or_default()
    }

    fn total_outgoing_count(&self, source: ProgramPointId) -> usize {
        self.outgoing_total
            .get(&source)
            .copied()
            .unwrap_or_default()
    }
}

type CaptureDestinationIndex = HashSet<(ProcedureId, MemoryLocationId)>;
type ProcedureLocatorIndex = HashMap<SemanticLocator, ProcedureId>;
type AsyncSuspendIndex = HashMap<ProgramPointId, (ControlContinuation, ControlContinuation)>;

#[derive(Default)]
struct GapIndex {
    facts: HashMap<(ProgramPointId, SemanticGapSubject, SemanticCapability), SemanticGapKind>,
    subjects: HashSet<(SemanticGapSubject, SemanticCapability)>,
}

impl GapIndex {
    fn insert(&mut self, procedure: ProcedureId, gap: &SemanticGap) -> Result<(), SemanticIrError> {
        let fact = (gap.point, gap.subject, gap.capability);
        if let Some(previous) = self.facts.insert(fact, gap.kind) {
            return Err(SemanticIrError::procedure(
                procedure,
                SemanticIrErrorKind::GapContract,
                format!(
                    "gap {} duplicates the same scoped fact with {} and {} outcomes",
                    gap.id,
                    previous.label(),
                    gap.kind.label()
                ),
            ));
        }
        self.subjects.insert((gap.subject, gap.capability));
        Ok(())
    }

    fn fact_kind(
        &self,
        point: ProgramPointId,
        subject: SemanticGapSubject,
        capability: SemanticCapability,
    ) -> Option<SemanticGapKind> {
        self.facts.get(&(point, subject, capability)).copied()
    }

    fn has_subject(&self, subject: SemanticGapSubject, capability: SemanticCapability) -> bool {
        self.subjects.contains(&(subject, capability))
    }
}

fn measure_artifact_work(
    key: &SemanticArtifactKey,
    procedures: &[ProcedureSemanticsParts],
) -> SemanticWork {
    let mut work = SemanticWork {
        procedures: procedures.len(),
        owned_text_bytes: key
            .path()
            .as_str()
            .len()
            .saturating_add(key.adapter().name().len()),
        ..SemanticWork::default()
    };

    for procedure in procedures {
        work.values = work.values.saturating_add(procedure.values.len());
        work.allocations = work.allocations.saturating_add(procedure.allocations.len());
        work.memory_locations = work
            .memory_locations
            .saturating_add(procedure.memory_locations.len());
        work.captures = work.captures.saturating_add(procedure.captures.len());
        work.call_sites = work.call_sites.saturating_add(procedure.call_sites.len());
        work.source_mappings = work
            .source_mappings
            .saturating_add(procedure.source_mappings.len());
        work.evidence = work.evidence.saturating_add(procedure.evidence_rows.len());
        work.gaps = work.gaps.saturating_add(procedure.gaps.len());
        work.blocks = work.blocks.saturating_add(procedure.blocks.len());
        work.program_points = work.program_points.saturating_add(procedure.points.len());
        work.control_edges = work
            .control_edges
            .saturating_add(procedure.control_edges.len());
        // The frozen CFG retains two point-indexed offset arrays plus one
        // incoming procedure-local edge ID per canonical rich edge.
        let adjacency_entries = procedure
            .points
            .len()
            .saturating_add(1)
            .saturating_mul(2)
            .saturating_add(procedure.control_edges.len());
        work.nested_entries = work.nested_entries.saturating_add(adjacency_entries);

        // The locator is retained once on the procedure and once as the key
        // in the artifact's locator index.
        account_locator(&procedure.locator, &mut work);
        account_locator(&procedure.locator, &mut work);

        for value in &procedure.values {
            if let SemanticValueKind::LanguageDefined(name) = &value.kind {
                account_text(name, &mut work);
            }
        }
        for allocation in &procedure.allocations {
            if let AllocationKind::LanguageDefined(name) = &allocation.kind {
                account_text(name, &mut work);
            }
        }
        for location in &procedure.memory_locations {
            match &location.kind {
                MemoryLocationKind::Field { member, .. }
                | MemoryLocationKind::Static { member } => account_locator(member, &mut work),
                MemoryLocationKind::Index { .. }
                | MemoryLocationKind::LexicalCell { .. }
                | MemoryLocationKind::Capture { .. } => {}
            }
        }
        for capture in &procedure.captures {
            if let CaptureMode::LanguageDefined(name) = &capture.mode {
                account_text(name, &mut work);
            }
        }
        for call_site in &procedure.call_sites {
            work.nested_entries = work
                .nested_entries
                .saturating_add(call_site.arguments.len());
            account_target_resolution(&call_site.declared_targets, &mut work);
        }
        for mapping in &procedure.source_mappings {
            account_locator(&mapping.locator, &mut work);
        }
        for evidence in &procedure.evidence_rows {
            work.nested_entries = work.nested_entries.saturating_add(evidence.sources.len());
            if let ProofStatus::Unproven(detail) = &evidence.proof {
                account_text(detail, &mut work);
            }
            if let EvidenceCompleteness::Partial(detail) = &evidence.completeness {
                account_text(detail, &mut work);
            }
        }
        for gap in &procedure.gaps {
            account_text(&gap.detail, &mut work);
        }
        for block in &procedure.blocks {
            work.nested_entries = work.nested_entries.saturating_add(block.points.len());
        }
        for point in &procedure.points {
            work.events = work.events.saturating_add(point.events.len());
            for event in &point.events {
                match &event.effect {
                    SemanticEffect::CallableCreation { callable, .. }
                    | SemanticEffect::CallableReference { callable, .. } => {
                        account_target_resolution(&callable.targets, &mut work);
                    }
                    SemanticEffect::Entry
                    | SemanticEffect::NormalExit
                    | SemanticEffect::ExceptionalExit
                    | SemanticEffect::Assignment { .. }
                    | SemanticEffect::ValueFlow { .. }
                    | SemanticEffect::Allocation { .. }
                    | SemanticEffect::MemoryLoad { .. }
                    | SemanticEffect::MemoryStore { .. }
                    | SemanticEffect::CaptureBind { .. }
                    | SemanticEffect::Invoke { .. }
                    | SemanticEffect::CallContinuation { .. }
                    | SemanticEffect::ProcedureReturn { .. }
                    | SemanticEffect::Throw { .. }
                    | SemanticEffect::AsyncSuspend { .. }
                    | SemanticEffect::AsyncResume { .. }
                    | SemanticEffect::Gap { .. } => {}
                }
            }
        }
    }
    work
}

fn account_target_resolution(resolution: &CallableTargetResolution, work: &mut SemanticWork) {
    work.nested_entries = work
        .nested_entries
        .saturating_add(resolution.candidates().len());
    for target in resolution.candidates() {
        match target {
            CallableTarget::Local(_) => {}
            CallableTarget::Unmaterialized(locator) | CallableTarget::External(locator) => {
                account_locator(locator, work);
            }
        }
    }
}

fn account_locator(locator: &SemanticLocator, work: &mut SemanticWork) {
    account_text(locator.path().as_str(), work);
    work.nested_entries = work
        .nested_entries
        .saturating_add(locator.declaration().segments().len());
    for segment in locator.declaration().segments() {
        if let Some(name) = segment.name() {
            account_text(name, work);
        }
    }
}

fn account_text(text: &str, work: &mut SemanticWork) {
    work.owned_text_bytes = work.owned_text_bytes.saturating_add(text.len());
}

fn validate_artifact(
    key: &SemanticArtifactKey,
    capabilities: &SemanticCapabilities,
    procedures: &[ProcedureSemanticsParts],
) -> Result<(), SemanticIrError> {
    if key.language().language() == crate::analyzer::Language::None {
        return Err(SemanticIrError::artifact(
            SemanticIrErrorKind::ArtifactIdentity,
            "semantic artifact language must be analyzable",
        ));
    }
    if !procedures.is_empty() {
        for capability in [
            SemanticCapability::Procedures,
            SemanticCapability::EntryBoundary,
            SemanticCapability::NormalExitBoundary,
            SemanticCapability::ExceptionalExitBoundary,
            SemanticCapability::BasicBlocks,
            SemanticCapability::ProgramPoints,
        ] {
            require_artifact_capability(capabilities, capability, "procedure core")?;
        }
    }
    let mut locators = HashMap::default();
    for (index, procedure) in procedures.iter().enumerate() {
        if procedure.id.index() != index {
            return Err(SemanticIrError::procedure(
                procedure.id,
                SemanticIrErrorKind::DenseId,
                format!(
                    "procedures row {index} carries id {}; expected {index}",
                    procedure.id
                ),
            ));
        }
        validate_locator_scope(key, procedure.id, "procedure locator", &procedure.locator)?;
        if procedure.locator.role() != SemanticRole::Procedure {
            return Err(SemanticIrError::procedure(
                procedure.id,
                SemanticIrErrorKind::LocatorRole,
                format!(
                    "procedure locator has role {}, expected {}",
                    procedure.locator.role().stable_label(),
                    SemanticRole::Procedure.stable_label()
                ),
            ));
        }
        if let Some(first) = locators.insert(procedure.locator.clone(), procedure.id) {
            return Err(SemanticIrError::procedure(
                procedure.id,
                SemanticIrErrorKind::DuplicateLocator,
                format!("procedure locator is already owned by procedure {first}"),
            ));
        }
        if let Some(parent) = procedure.lexical_parent {
            ensure_index(
                procedure.id,
                "lexical parent",
                parent.index(),
                procedures.len(),
            )?;
            if parent == procedure.id {
                return Err(SemanticIrError::procedure(
                    procedure.id,
                    SemanticIrErrorKind::ParentCycle,
                    "procedure cannot be its own lexical parent",
                ));
            }
        }
    }

    validate_parent_forest(procedures)?;
    let capture_destinations = procedures
        .iter()
        .flat_map(|procedure| {
            procedure
                .captures
                .iter()
                .map(|capture| (capture.target, capture.destination))
        })
        .collect();
    for procedure in procedures {
        validate_procedure(
            key,
            capabilities,
            procedures,
            &locators,
            procedure,
            &capture_destinations,
        )?;
    }
    Ok(())
}

fn validate_locator_scope(
    key: &SemanticArtifactKey,
    procedure: ProcedureId,
    context: &str,
    locator: &SemanticLocator,
) -> Result<(), SemanticIrError> {
    if locator.mount() != key.mount()
        || locator.path() != key.path()
        || locator.language() != key.language()
    {
        return Err(SemanticIrError::procedure(
            procedure,
            SemanticIrErrorKind::SourceScope,
            format!(
                "{context} belongs to mount/path/language outside artifact {}/{} ({})",
                key.mount(),
                key.path(),
                key.language()
            ),
        ));
    }
    Ok(())
}

/// Validate a single-parent forest without recursive stack growth.
fn validate_parent_forest(procedures: &[ProcedureSemanticsParts]) -> Result<(), SemanticIrError> {
    // 0 = unseen, 1 = on the current iterative path, 2 = complete.
    let mut state = vec![0_u8; procedures.len()];
    for start in 0..procedures.len() {
        if state[start] != 0 {
            continue;
        }
        let mut path = Vec::new();
        let mut cursor = Some(start);
        while let Some(index) = cursor {
            match state[index] {
                0 => {
                    state[index] = 1;
                    path.push(index);
                    cursor = procedures[index].lexical_parent.map(ProcedureId::index);
                }
                1 => {
                    return Err(SemanticIrError::procedure(
                        procedures[index].id,
                        SemanticIrErrorKind::ParentCycle,
                        "lexical-parent relation contains a cycle",
                    ));
                }
                2 => break,
                _ => unreachable!("parent validation state is internal"),
            }
        }
        for index in path {
            state[index] = 2;
        }
    }
    Ok(())
}

fn validate_procedure(
    key: &SemanticArtifactKey,
    capabilities: &SemanticCapabilities,
    procedures: &[ProcedureSemanticsParts],
    procedure_locators: &ProcedureLocatorIndex,
    procedure: &ProcedureSemanticsParts,
    capture_destinations: &CaptureDestinationIndex,
) -> Result<(), SemanticIrError> {
    let id = procedure.id;

    validate_dense_rows(procedure)?;
    for mapping in &procedure.source_mappings {
        validate_locator_scope(key, id, "source mapping", &mapping.locator)?;
    }

    ensure_source(
        id,
        procedure.source,
        procedure.source_mappings.len(),
        "procedure",
    )?;
    ensure_evidence(
        id,
        procedure.evidence,
        procedure.evidence_rows.len(),
        "procedure",
    )?;

    for evidence in &procedure.evidence_rows {
        if evidence.sources.is_empty() {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::OutOfBounds,
                format!("evidence {} has no source mapping", evidence.id),
            ));
        }
        for source in &evidence.sources {
            ensure_source(
                id,
                *source,
                procedure.source_mappings.len(),
                "evidence source",
            )?;
        }
        if matches!(&evidence.proof, ProofStatus::Unproven(reason) if reason.is_empty()) {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::GapContract,
                format!("evidence {} has an empty unproven reason", evidence.id),
            ));
        }
        if matches!(
            &evidence.completeness,
            EvidenceCompleteness::Partial(reason) if reason.is_empty()
        ) {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::GapContract,
                format!("evidence {} has an empty partial reason", evidence.id),
            ));
        }
    }

    let async_suspends = index_async_suspends(procedure)?;
    let mut gap_index = GapIndex::default();
    for gap in &procedure.gaps {
        ensure_point(id, gap.point, procedure.points.len(), "gap point")?;
        validate_metadata(id, gap.source, gap.evidence, procedure, "gap")?;
        if gap.detail.is_empty() {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::GapContract,
                format!("gap {} has no diagnostic detail", gap.id),
            ));
        }
        if gap.kind == SemanticGapKind::Unproven
            && !matches!(
                procedure.evidence_rows[gap.evidence.index()].proof,
                ProofStatus::Unproven(_)
            )
        {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::GapContract,
                format!("unproven gap {} cites proven evidence", gap.id),
            ));
        }
        validate_gap_capability(id, capabilities, gap)?;
        validate_gap_subject(id, procedure, &async_suspends, gap)?;
        if (gap.kind == SemanticGapKind::ExceededBudget) != gap.budget.is_some() {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::GapContract,
                format!(
                    "gap {} must carry structured budget data exactly for an exceeded-budget outcome",
                    gap.id
                ),
            ));
        }
        gap_index.insert(id, gap)?;
    }

    for value in &procedure.values {
        validate_metadata(id, value.source, value.evidence, procedure, "value")?;
    }
    if !procedure.values.is_empty() {
        require_capability(id, capabilities, SemanticCapability::Values, "value rows")?;
    }

    for allocation in &procedure.allocations {
        ensure_point(
            id,
            allocation.point,
            procedure.points.len(),
            "allocation point",
        )?;
        ensure_value(
            id,
            allocation.result,
            procedure.values.len(),
            "allocation result",
        )?;
        validate_metadata(
            id,
            allocation.source,
            allocation.evidence,
            procedure,
            "allocation",
        )?;
    }
    if !procedure.allocations.is_empty() {
        require_capability(
            id,
            capabilities,
            SemanticCapability::Allocations,
            "allocation rows",
        )?;
    }

    for location in &procedure.memory_locations {
        validate_memory_location(
            procedures,
            procedure,
            location,
            capture_destinations,
            &gap_index,
        )?;
        require_capability(
            id,
            capabilities,
            memory_location_capability(&location.kind),
            "memory-location row",
        )?;
        validate_metadata(
            id,
            location.source,
            location.evidence,
            procedure,
            "memory location",
        )?;
    }

    for capture in &procedure.captures {
        validate_capture_row(procedures, procedure, capture, &gap_index)?;
        validate_metadata(id, capture.source, capture.evidence, procedure, "capture")?;
    }
    if !procedure.captures.is_empty() {
        require_capability(
            id,
            capabilities,
            SemanticCapability::Captures,
            "capture rows",
        )?;
    }
    validate_capture_consistency(procedure)?;

    for call_site in &procedure.call_sites {
        validate_metadata(
            id,
            call_site.source,
            call_site.evidence,
            procedure,
            "call site",
        )?;
        validate_call_site(procedures, procedure_locators, procedure, call_site)?;
    }
    if !procedure.call_sites.is_empty() {
        require_capability(
            id,
            capabilities,
            SemanticCapability::Calls,
            "call-site rows",
        )?;
    }

    validate_blocks(procedure)?;
    let control_edges = validate_control_edges(capabilities, procedure)?;
    validate_events(
        capabilities,
        procedures,
        procedure_locators,
        procedure,
        &gap_index,
        &control_edges,
    )?;
    find_boundaries(procedure)?;
    Ok(())
}

fn validate_dense_rows(procedure: &ProcedureSemanticsParts) -> Result<(), SemanticIrError> {
    macro_rules! dense {
        ($rows:expr, $table:literal) => {
            for (expected, row) in $rows.iter().enumerate() {
                if row.id.index() != expected {
                    return Err(SemanticIrError::procedure(
                        procedure.id,
                        SemanticIrErrorKind::DenseId,
                        format!(
                            "{} row {expected} carries id {}; expected {expected}",
                            $table, row.id
                        ),
                    ));
                }
            }
        };
    }

    dense!(procedure.values, "values");
    dense!(procedure.allocations, "allocations");
    dense!(procedure.memory_locations, "memory_locations");
    dense!(procedure.captures, "captures");
    dense!(procedure.call_sites, "call_sites");
    dense!(procedure.source_mappings, "source_mappings");
    dense!(procedure.evidence_rows, "evidence");
    dense!(procedure.gaps, "gaps");
    dense!(procedure.blocks, "blocks");
    dense!(procedure.points, "points");
    Ok(())
}

fn validate_memory_location(
    procedures: &[ProcedureSemanticsParts],
    procedure: &ProcedureSemanticsParts,
    location: &MemoryLocation,
    capture_destinations: &CaptureDestinationIndex,
    gaps: &GapIndex,
) -> Result<(), SemanticIrError> {
    let id = procedure.id;
    match &location.kind {
        MemoryLocationKind::Field { base, member } => {
            ensure_value(id, *base, procedure.values.len(), "field base")?;
            validate_memory_member_locator(id, member, "field member")?;
        }
        MemoryLocationKind::Static { member } => {
            validate_memory_member_locator(id, member, "static member")?;
        }
        MemoryLocationKind::Index { base, index } => {
            ensure_value(id, *base, procedure.values.len(), "indexed base")?;
            if let Some(index) = index {
                ensure_value(id, *index, procedure.values.len(), "index value")?;
            }
        }
        MemoryLocationKind::LexicalCell { binding } => {
            ensure_value(id, *binding, procedure.values.len(), "lexical-cell binding")?;
        }
        MemoryLocationKind::Capture { lexical_parent } => {
            ensure_index(
                id,
                "capture-slot lexical parent",
                lexical_parent.index(),
                procedures.len(),
            )?;
            if procedure.lexical_parent != Some(*lexical_parent) {
                return Err(SemanticIrError::procedure(
                    id,
                    SemanticIrErrorKind::CaptureContract,
                    format!(
                        "capture location {} names procedure {} as lexical parent, but procedure {} has parent {:?}",
                        location.id, lexical_parent, id, procedure.lexical_parent
                    ),
                ));
            }
            let has_binding = capture_destinations.contains(&(id, location.id));
            let has_gap = gaps.has_subject(
                SemanticGapSubject::MemoryLocation(location.id),
                SemanticCapability::Captures,
            );
            if !has_binding && !has_gap {
                return Err(SemanticIrError::procedure(
                    id,
                    SemanticIrErrorKind::CaptureContract,
                    format!(
                        "capture location {} has no lexical-parent binding or explicit capture gap",
                        location.id
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn index_async_suspends(
    procedure: &ProcedureSemanticsParts,
) -> Result<AsyncSuspendIndex, SemanticIrError> {
    let mut suspends = AsyncSuspendIndex::default();
    for point in &procedure.points {
        for event in &point.events {
            if let SemanticEffect::AsyncSuspend {
                normal_resume,
                exceptional_resume,
                ..
            } = event.effect
                && suspends
                    .insert(point.id, (normal_resume, exceptional_resume))
                    .is_some()
            {
                return Err(SemanticIrError::procedure(
                    procedure.id,
                    SemanticIrErrorKind::AsyncContract,
                    format!("point {} contains more than one async suspend", point.id),
                ));
            }
        }
    }
    Ok(suspends)
}

fn validate_gap_subject(
    procedure_id: ProcedureId,
    procedure: &ProcedureSemanticsParts,
    async_suspends: &AsyncSuspendIndex,
    gap: &SemanticGap,
) -> Result<(), SemanticIrError> {
    match gap.subject {
        SemanticGapSubject::Procedure | SemanticGapSubject::Point => {}
        SemanticGapSubject::Value(value) => {
            ensure_value(
                procedure_id,
                value,
                procedure.values.len(),
                "gap subject value",
            )?;
        }
        SemanticGapSubject::MemoryLocation(location) => {
            ensure_location(
                procedure_id,
                location,
                procedure.memory_locations.len(),
                "gap subject memory location",
            )?;
        }
        SemanticGapSubject::Capture(capture) => {
            ensure_capture(
                procedure_id,
                capture,
                procedure.captures.len(),
                "gap subject capture",
            )?;
            if procedure.captures[capture.index()].point != gap.point
                || gap.capability != SemanticCapability::Captures
            {
                return Err(SemanticIrError::procedure(
                    procedure_id,
                    SemanticIrErrorKind::GapContract,
                    format!(
                        "gap {} capture subject must use the binding point and captures capability",
                        gap.id
                    ),
                ));
            }
            let expected = (procedure.captures[capture.index()].mode == CaptureMode::Unknown)
                .then_some(SemanticGapKind::Unknown);
            if expected != Some(gap.kind) {
                return Err(SemanticIrError::procedure(
                    procedure_id,
                    SemanticIrErrorKind::GapContract,
                    format!(
                        "gap {} outcome {} contradicts capture {} mode {}",
                        gap.id,
                        gap.kind.label(),
                        capture,
                        procedure.captures[capture.index()].mode.label()
                    ),
                ));
            }
        }
        SemanticGapSubject::CallSite(call_site) => {
            ensure_call_site(
                procedure_id,
                call_site,
                procedure.call_sites.len(),
                "gap subject call site",
            )?;
            if procedure.call_sites[call_site.index()].point != gap.point {
                return Err(SemanticIrError::procedure(
                    procedure_id,
                    SemanticIrErrorKind::GapContract,
                    format!(
                        "gap {} point {} differs from subject call site {} point {}",
                        gap.id,
                        gap.point,
                        call_site,
                        procedure.call_sites[call_site.index()].point
                    ),
                ));
            }
            if gap.capability == SemanticCapability::Calls
                && required_gap_kind(&procedure.call_sites[call_site.index()].declared_targets)
                    != Some(gap.kind)
            {
                return Err(SemanticIrError::procedure(
                    procedure_id,
                    SemanticIrErrorKind::GapContract,
                    format!(
                        "gap {} outcome {} contradicts call site {} target outcome {}",
                        gap.id,
                        gap.kind.label(),
                        call_site,
                        procedure.call_sites[call_site.index()]
                            .declared_targets
                            .label()
                    ),
                ));
            }
        }
        SemanticGapSubject::CallContinuation { call_site, kind } => {
            ensure_call_site(
                procedure_id,
                call_site,
                procedure.call_sites.len(),
                "gap subject call continuation",
            )?;
            if procedure.call_sites[call_site.index()].point != gap.point {
                return Err(SemanticIrError::procedure(
                    procedure_id,
                    SemanticIrErrorKind::GapContract,
                    format!(
                        "gap {} point {} differs from subject call site {} point {}",
                        gap.id,
                        gap.point,
                        call_site,
                        procedure.call_sites[call_site.index()].point
                    ),
                ));
            }
            let expected = match kind {
                CallContinuationKind::Normal => SemanticCapability::NormalCallContinuation,
                CallContinuationKind::Exceptional => {
                    SemanticCapability::ExceptionalCallContinuation
                }
            };
            if gap.capability != expected {
                return Err(SemanticIrError::procedure(
                    procedure_id,
                    SemanticIrErrorKind::GapContract,
                    format!(
                        "gap {} subject {} requires capability {}, found {}",
                        gap.id,
                        kind.label(),
                        expected.label(),
                        gap.capability.label()
                    ),
                ));
            }
            let continuation = match kind {
                CallContinuationKind::Normal => {
                    procedure.call_sites[call_site.index()].normal_continuation
                }
                CallContinuationKind::Exceptional => {
                    procedure.call_sites[call_site.index()].exceptional_continuation
                }
            };
            if continuation_gap_kind(continuation) != Some(gap.kind) {
                return Err(SemanticIrError::procedure(
                    procedure_id,
                    SemanticIrErrorKind::GapContract,
                    format!(
                        "gap {} outcome {} contradicts call {} {} continuation outcome {}",
                        gap.id,
                        gap.kind.label(),
                        call_site,
                        kind.label(),
                        continuation.label()
                    ),
                ));
            }
        }
        SemanticGapSubject::AsyncContinuation { suspend, kind } => {
            ensure_point(
                procedure_id,
                suspend,
                procedure.points.len(),
                "gap subject async suspend",
            )?;
            if gap.point != suspend || gap.capability != SemanticCapability::AsyncSuspendResume {
                return Err(SemanticIrError::procedure(
                    procedure_id,
                    SemanticIrErrorKind::GapContract,
                    format!(
                        "gap {} async-continuation subject must use its suspend point and async capability",
                        gap.id
                    ),
                ));
            }
            let Some((normal, exceptional)) = async_suspends.get(&suspend) else {
                return Err(SemanticIrError::procedure(
                    procedure_id,
                    SemanticIrErrorKind::GapContract,
                    format!(
                        "gap {} names point {} as an async continuation source, but it has no async suspend",
                        gap.id, suspend
                    ),
                ));
            };
            let continuation = match kind {
                AsyncResumeKind::Normal => *normal,
                AsyncResumeKind::Exceptional => *exceptional,
            };
            if continuation_gap_kind(continuation) != Some(gap.kind) {
                return Err(SemanticIrError::procedure(
                    procedure_id,
                    SemanticIrErrorKind::GapContract,
                    format!(
                        "gap {} outcome {} contradicts suspend {} {} continuation outcome {}",
                        gap.id,
                        gap.kind.label(),
                        suspend,
                        kind.label(),
                        continuation.label()
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn validate_capture_consistency(
    procedure: &ProcedureSemanticsParts,
) -> Result<(), SemanticIrError> {
    let mut static_bindings = HashSet::default();
    let mut slot_modes = HashMap::default();
    for capture in &procedure.captures {
        let static_key = (
            capture.point,
            capture.callable,
            capture.environment,
            capture.target,
            capture.destination,
        );
        if !static_bindings.insert(static_key) {
            return Err(SemanticIrError::procedure(
                procedure.id,
                SemanticIrErrorKind::CaptureContract,
                format!(
                    "capture {} duplicates a binding at point {} for callable {}, environment {}, and procedure {} location {}",
                    capture.id,
                    capture.point,
                    capture.callable,
                    capture.environment,
                    capture.target,
                    capture.destination
                ),
            ));
        }

        let slot = (capture.target, capture.destination);
        if let Some(previous) = slot_modes.insert(slot, capture.mode.clone())
            && previous != capture.mode
        {
            return Err(SemanticIrError::procedure(
                procedure.id,
                SemanticIrErrorKind::CaptureContract,
                format!(
                    "procedure {} capture slot {} has contradictory {} and {} modes",
                    capture.target,
                    capture.destination,
                    previous.label(),
                    capture.mode.label()
                ),
            ));
        }
    }
    Ok(())
}

fn validate_capture_row(
    procedures: &[ProcedureSemanticsParts],
    procedure: &ProcedureSemanticsParts,
    capture: &CaptureBinding,
    gaps: &GapIndex,
) -> Result<(), SemanticIrError> {
    let id = procedure.id;
    ensure_point(id, capture.point, procedure.points.len(), "capture point")?;
    ensure_value(
        id,
        capture.callable,
        procedure.values.len(),
        "capturing callable",
    )?;
    ensure_index(
        id,
        "capture target procedure",
        capture.target.index(),
        procedures.len(),
    )?;
    if procedures[capture.target.index()].lexical_parent != Some(id) {
        return Err(SemanticIrError::procedure(
            id,
            SemanticIrErrorKind::CaptureContract,
            format!(
                "capture {} targets procedure {}, which is not a lexical child",
                capture.id, capture.target
            ),
        ));
    }
    ensure_allocation(
        id,
        capture.environment,
        procedure.allocations.len(),
        "capture environment",
    )?;
    let target = &procedures[capture.target.index()];
    if capture.destination.index() >= target.memory_locations.len() {
        return Err(SemanticIrError::procedure(
            id,
            SemanticIrErrorKind::CaptureContract,
            format!(
                "capture {} destination {} is outside target procedure {} memory-location table of length {}; creator-local locations cannot be used here",
                capture.id,
                capture.destination,
                capture.target,
                target.memory_locations.len()
            ),
        ));
    }
    match capture.captured {
        CaptureSource::Value(value) => {
            ensure_value(id, value, procedure.values.len(), "captured value")?;
            if matches!(
                &capture.mode,
                CaptureMode::SharedCell | CaptureMode::MutableCell
            ) {
                return Err(SemanticIrError::procedure(
                    id,
                    SemanticIrErrorKind::CaptureContract,
                    format!(
                        "capture {} uses {} mode with a value source; cell modes require a location",
                        capture.id,
                        capture.mode.label()
                    ),
                ));
            }
            if capture.mode == CaptureMode::Receiver
                && !matches!(
                    procedure.values[value.index()].kind,
                    SemanticValueKind::Receiver
                )
            {
                return Err(SemanticIrError::procedure(
                    id,
                    SemanticIrErrorKind::CaptureContract,
                    format!(
                        "capture {} uses receiver mode with non-receiver value {}",
                        capture.id, value
                    ),
                ));
            }
        }
        CaptureSource::Location(location) => {
            ensure_location(
                id,
                location,
                procedure.memory_locations.len(),
                "captured location",
            )?;
            if matches!(
                &capture.mode,
                CaptureMode::Value | CaptureMode::Move | CaptureMode::Receiver
            ) {
                return Err(SemanticIrError::procedure(
                    id,
                    SemanticIrErrorKind::CaptureContract,
                    format!(
                        "capture {} uses {} mode with a location source; snapshot, move, and receiver modes require a value",
                        capture.id,
                        capture.mode.label()
                    ),
                ));
            }
        }
    }
    if matches!(&capture.mode, CaptureMode::LanguageDefined(name) if name.is_empty()) {
        return Err(SemanticIrError::procedure(
            id,
            SemanticIrErrorKind::CaptureContract,
            format!("capture {} has an empty language-defined mode", capture.id),
        ));
    }
    if capture.mode == CaptureMode::Unknown
        && gaps.fact_kind(
            capture.point,
            SemanticGapSubject::Capture(capture.id),
            SemanticCapability::Captures,
        ) != Some(SemanticGapKind::Unknown)
    {
        return Err(SemanticIrError::procedure(
            id,
            SemanticIrErrorKind::GapContract,
            format!(
                "capture {} has unknown mode without a subject-specific capture gap",
                capture.id
            ),
        ));
    }
    match &target.memory_locations[capture.destination.index()].kind {
        MemoryLocationKind::Capture { lexical_parent } if *lexical_parent == id => {}
        _ => {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::CaptureContract,
                format!(
                    "capture {} destination {} in procedure {} is not a capture slot for lexical parent {}",
                    capture.id, capture.destination, capture.target, id
                ),
            ));
        }
    }
    Ok(())
}

fn validate_call_site(
    procedures: &[ProcedureSemanticsParts],
    procedure_locators: &ProcedureLocatorIndex,
    procedure: &ProcedureSemanticsParts,
    call_site: &SemanticCallSite,
) -> Result<(), SemanticIrError> {
    let id = procedure.id;
    ensure_point(id, call_site.point, procedure.points.len(), "call point")?;
    ensure_value(id, call_site.callee, procedure.values.len(), "callee")?;
    if !matches!(
        procedure.values[call_site.callee.index()].kind,
        SemanticValueKind::Callable
    ) {
        return Err(SemanticIrError::procedure(
            id,
            SemanticIrErrorKind::CallableContract,
            format!(
                "call site {} callee {} is not a callable value row",
                call_site.id, call_site.callee
            ),
        ));
    }
    if let Some(receiver) = call_site.receiver {
        ensure_value(id, receiver, procedure.values.len(), "call receiver")?;
    }
    for argument in &call_site.arguments {
        ensure_value(id, *argument, procedure.values.len(), "call argument")?;
    }
    if let Some(result) = call_site.result {
        ensure_value(id, result, procedure.values.len(), "call result")?;
    }
    if let Some(thrown) = call_site.thrown {
        ensure_value(id, thrown, procedure.values.len(), "thrown call value")?;
    }
    ensure_evidence(
        id,
        call_site.target_evidence,
        procedure.evidence_rows.len(),
        "call-site target evidence",
    )?;
    if let Some(normal) = call_site.normal_continuation.target() {
        ensure_point(
            id,
            normal,
            procedure.points.len(),
            "normal call continuation",
        )?;
    }
    if let Some(exceptional) = call_site.exceptional_continuation.target() {
        ensure_point(
            id,
            exceptional,
            procedure.points.len(),
            "exceptional call continuation",
        )?;
    }
    let normal = call_site.normal_continuation.target();
    let exceptional = call_site.exceptional_continuation.target();
    if normal == Some(call_site.point) || exceptional == Some(call_site.point) {
        return Err(SemanticIrError::procedure(
            id,
            SemanticIrErrorKind::CallContract,
            format!(
                "call site {} cannot continue at its own invocation point",
                call_site.id
            ),
        ));
    }
    validate_target_resolution(
        id,
        procedures,
        procedure_locators,
        &call_site.declared_targets,
        &procedure.evidence_rows[call_site.target_evidence.index()].proof,
        "call site declared target",
    )
}

fn validate_target_resolution(
    procedure: ProcedureId,
    procedures: &[ProcedureSemanticsParts],
    procedure_locators: &ProcedureLocatorIndex,
    resolution: &CallableTargetResolution,
    proof: &ProofStatus,
    context: &str,
) -> Result<(), SemanticIrError> {
    if let CallableTargetResolution::Ambiguous(candidates) = resolution
        && candidates.len() < 2
    {
        return Err(SemanticIrError::procedure(
            procedure,
            SemanticIrErrorKind::CallableContract,
            format!("{context} is ambiguous but has fewer than two candidates"),
        ));
    }

    if matches!(resolution, CallableTargetResolution::Proven(_))
        && !matches!(proof, ProofStatus::Proven)
    {
        return Err(SemanticIrError::procedure(
            procedure,
            SemanticIrErrorKind::CallableContract,
            format!("{context} is proven but cites unproven evidence"),
        ));
    }
    if matches!(resolution, CallableTargetResolution::Unproven(_))
        && !matches!(proof, ProofStatus::Unproven(_))
    {
        return Err(SemanticIrError::procedure(
            procedure,
            SemanticIrErrorKind::CallableContract,
            format!("{context} is unproven but cites proven evidence"),
        ));
    }

    let allows_unmaterialized = matches!(
        resolution,
        CallableTargetResolution::Unproven(_) | CallableTargetResolution::ExceededBudget(_)
    );
    let mut unique = HashSet::default();
    for target in resolution.candidates() {
        if !unique.insert(target) {
            return Err(SemanticIrError::procedure(
                procedure,
                SemanticIrErrorKind::CallableContract,
                format!("{context} contains a duplicate candidate"),
            ));
        }
        match target {
            CallableTarget::Local(target) => {
                ensure_index(procedure, context, target.index(), procedures.len())?
            }
            CallableTarget::Unmaterialized(locator) => {
                validate_procedure_target_locator(procedure, procedures, locator, context)?;
                if let Some(materialized) = procedure_locators.get(locator) {
                    return Err(SemanticIrError::procedure(
                        procedure,
                        SemanticIrErrorKind::CallableContract,
                        format!(
                            "{context} marks the locator of materialized procedure {materialized} as unmaterialized; use its local ProcedureId"
                        ),
                    ));
                }
                let owner = &procedures[procedure.index()].locator;
                if locator.mount() != owner.mount()
                    || locator.path() != owner.path()
                    || locator.language() != owner.language()
                {
                    return Err(SemanticIrError::procedure(
                        procedure,
                        SemanticIrErrorKind::CallableContract,
                        format!("{context} unmaterialized locator is outside the owning artifact"),
                    ));
                }
                if !allows_unmaterialized {
                    return Err(SemanticIrError::procedure(
                        procedure,
                        SemanticIrErrorKind::CallableContract,
                        format!(
                            "{context} may use an unmaterialized locator only for an unproven or budget-exceeded outcome"
                        ),
                    ));
                }
            }
            CallableTarget::External(locator) => {
                validate_procedure_target_locator(procedure, procedures, locator, context)?;
                let owner = &procedures[procedure.index()].locator;
                if locator.mount() == owner.mount()
                    && locator.path() == owner.path()
                    && locator.language() == owner.language()
                {
                    return Err(SemanticIrError::procedure(
                        procedure,
                        SemanticIrErrorKind::CallableContract,
                        format!(
                            "{context} uses an external locator in the owning artifact; exhaustive file procedures require a local ProcedureId"
                        ),
                    ));
                }
            }
        }
    }
    Ok(())
}

fn validate_procedure_target_locator(
    procedure: ProcedureId,
    procedures: &[ProcedureSemanticsParts],
    locator: &SemanticLocator,
    context: &str,
) -> Result<(), SemanticIrError> {
    if locator.role() == SemanticRole::Procedure {
        return Ok(());
    }
    Err(SemanticIrError::procedure(
        procedure,
        SemanticIrErrorKind::LocatorRole,
        format!(
            "{context} locator has role {}, expected procedure (owner {})",
            locator.role().stable_label(),
            procedures[procedure.index()].id
        ),
    ))
}

fn is_direct_lexical_child(parent: &SemanticLocator, child: &SemanticLocator) -> bool {
    let parent_segments = parent.declaration().segments();
    let child_segments = child.declaration().segments();
    child_segments.len() == parent_segments.len().saturating_add(1)
        && child_segments.starts_with(parent_segments)
        && child_segments.last().is_some_and(|segment| {
            matches!(
                segment.kind(),
                DeclarationSegmentKind::Function
                    | DeclarationSegmentKind::Method
                    | DeclarationSegmentKind::Constructor
                    | DeclarationSegmentKind::Initializer
                    | DeclarationSegmentKind::LocalFunction
                    | DeclarationSegmentKind::Lambda
                    | DeclarationSegmentKind::Closure
                    | DeclarationSegmentKind::AnonymousCallable
            )
        })
}

fn validate_memory_member_locator(
    procedure: ProcedureId,
    locator: &SemanticLocator,
    context: &str,
) -> Result<(), SemanticIrError> {
    if locator.role() == SemanticRole::MemoryLocation {
        return Ok(());
    }
    Err(SemanticIrError::procedure(
        procedure,
        SemanticIrErrorKind::LocatorRole,
        format!(
            "{context} locator has role {}, expected memory_location",
            locator.role().stable_label()
        ),
    ))
}

fn validate_blocks(procedure: &ProcedureSemanticsParts) -> Result<(), SemanticIrError> {
    let id = procedure.id;
    let mut membership = vec![None; procedure.points.len()];
    for block in &procedure.blocks {
        validate_metadata(id, block.source, block.evidence, procedure, "block")?;
        if block.points.is_empty() {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::BlockMembership,
                format!("block {} contains no program point", block.id),
            ));
        }
        for point in &block.points {
            ensure_point(id, *point, procedure.points.len(), "block member")?;
            if let Some(previous) = membership[point.index()].replace(block.id) {
                return Err(SemanticIrError::procedure(
                    id,
                    SemanticIrErrorKind::BlockMembership,
                    format!(
                        "program point {} appears in blocks {} and {}",
                        point, previous, block.id
                    ),
                ));
            }
            if procedure.points[point.index()].block != block.id {
                return Err(SemanticIrError::procedure(
                    id,
                    SemanticIrErrorKind::BlockMembership,
                    format!(
                        "block {} lists point {}, but the point names block {}",
                        block.id,
                        point,
                        procedure.points[point.index()].block
                    ),
                ));
            }
        }
    }
    for point in &procedure.points {
        ensure_block(
            id,
            point.block,
            procedure.blocks.len(),
            "program-point block",
        )?;
        if membership[point.id.index()] != Some(point.block) {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::BlockMembership,
                format!("program point {} is not listed by its block", point.id),
            ));
        }
        validate_metadata(id, point.source, point.evidence, procedure, "program point")?;
    }
    Ok(())
}

fn validate_control_edges(
    capabilities: &SemanticCapabilities,
    procedure: &ProcedureSemanticsParts,
) -> Result<ControlEdgeIndex, SemanticIrError> {
    let id = procedure.id;
    let mut edges = ControlEdgeIndex::default();
    for edge in &procedure.control_edges {
        require_capability(
            id,
            capabilities,
            control_edge_capability(edge.kind),
            "control edge",
        )?;
        ensure_point(
            id,
            edge.source_point,
            procedure.points.len(),
            "control-edge source",
        )?;
        ensure_point(
            id,
            edge.target_point,
            procedure.points.len(),
            "control-edge target",
        )?;
        validate_metadata(id, edge.source, edge.evidence, procedure, "control edge")?;
        if !matches!(
            procedure.evidence_rows[edge.evidence.index()].proof,
            ProofStatus::Proven
        ) {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::ControlFlowContract,
                format!(
                    "{} edge {} -> {} cites unproven evidence; omit the edge and emit an unproven gap instead",
                    edge.kind.label(),
                    edge.source_point,
                    edge.target_point
                ),
            ));
        }
        if !edges.insert(edge) {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::DuplicateEdge,
                format!(
                    "duplicate {} edge {} -> {} with source {} and evidence {}",
                    edge.kind.label(),
                    edge.source_point,
                    edge.target_point,
                    edge.source,
                    edge.evidence,
                ),
            ));
        }
    }
    Ok(edges)
}

fn validate_events(
    capabilities: &SemanticCapabilities,
    procedures: &[ProcedureSemanticsParts],
    procedure_locators: &ProcedureLocatorIndex,
    procedure: &ProcedureSemanticsParts,
    gaps: &GapIndex,
    control_edges: &ControlEdgeIndex,
) -> Result<(), SemanticIrError> {
    let id = procedure.id;
    let mut allocation_events = vec![0_usize; procedure.allocations.len()];
    let mut capture_events = vec![0_usize; procedure.captures.len()];
    let mut invoke_events = vec![0_usize; procedure.call_sites.len()];
    let mut continuation_events = vec![[0_usize; 2]; procedure.call_sites.len()];
    let mut gap_events = vec![0_usize; procedure.gaps.len()];
    let mut callable_creations =
        HashSet::<(ProgramPointId, ValueId, AllocationId, ProcedureId)>::default();
    let mut suspends: HashMap<ProgramPointId, (ControlContinuation, ControlContinuation)> =
        HashMap::default();
    let mut resumes: HashMap<(ProgramPointId, AsyncResumeKind), Vec<ProgramPointId>> =
        HashMap::default();

    for point in &procedure.points {
        let mut control_splits = 0_usize;
        for event in &point.events {
            validate_metadata(id, event.source, event.evidence, procedure, "event")?;
            if is_control_splitting_effect(&event.effect) {
                control_splits += 1;
                if control_splits > 1 {
                    return Err(SemanticIrError::procedure(
                        id,
                        SemanticIrErrorKind::ControlFlowContract,
                        format!(
                            "program point {} contains more than one control-splitting or terminating effect",
                            point.id
                        ),
                    ));
                }
            }
            match &event.effect {
                SemanticEffect::Entry
                | SemanticEffect::NormalExit
                | SemanticEffect::ExceptionalExit => {}
                SemanticEffect::Assignment { target, value } => {
                    ensure_value(id, *target, procedure.values.len(), "assignment target")?;
                    ensure_value(id, *value, procedure.values.len(), "assigned value")?;
                }
                SemanticEffect::ValueFlow {
                    kind,
                    source,
                    target,
                } => {
                    ensure_value(id, *source, procedure.values.len(), "value-flow source")?;
                    ensure_value(id, *target, procedure.values.len(), "value-flow target")?;
                    validate_value_flow_kind(procedure, *kind, *source, *target)?;
                }
                SemanticEffect::Allocation { allocation } => {
                    ensure_allocation(
                        id,
                        *allocation,
                        procedure.allocations.len(),
                        "allocation event",
                    )?;
                    let row = &procedure.allocations[allocation.index()];
                    if row.point != point.id {
                        return Err(SemanticIrError::procedure(
                            id,
                            SemanticIrErrorKind::OutOfBounds,
                            format!(
                                "allocation {} is emitted at point {}, but its row names point {}",
                                allocation, point.id, row.point
                            ),
                        ));
                    }
                    allocation_events[allocation.index()] += 1;
                }
                SemanticEffect::MemoryLoad {
                    kind,
                    location,
                    result,
                } => {
                    ensure_location(
                        id,
                        *location,
                        procedure.memory_locations.len(),
                        "load location",
                    )?;
                    ensure_value(id, *result, procedure.values.len(), "load result")?;
                    validate_memory_access_kind(procedure, *location, *kind)?;
                }
                SemanticEffect::MemoryStore {
                    kind,
                    location,
                    value,
                } => {
                    ensure_location(
                        id,
                        *location,
                        procedure.memory_locations.len(),
                        "store location",
                    )?;
                    ensure_value(id, *value, procedure.values.len(), "stored value")?;
                    validate_memory_access_kind(procedure, *location, *kind)?;
                }
                SemanticEffect::CallableCreation { result, callable } => {
                    validate_callable_value(
                        procedures,
                        procedure_locators,
                        procedure,
                        point.id,
                        *result,
                        callable,
                        gaps,
                        true,
                    )?;
                    if let Some(environment) = callable.environment {
                        for target in callable.targets.candidates() {
                            if let CallableTarget::Local(target) = target {
                                callable_creations.insert((
                                    point.id,
                                    *result,
                                    environment,
                                    *target,
                                ));
                            }
                        }
                    }
                }
                SemanticEffect::CallableReference { result, callable } => {
                    validate_callable_value(
                        procedures,
                        procedure_locators,
                        procedure,
                        point.id,
                        *result,
                        callable,
                        gaps,
                        false,
                    )?;
                }
                SemanticEffect::CaptureBind { capture } => {
                    ensure_capture(id, *capture, procedure.captures.len(), "capture event")?;
                    let row = &procedure.captures[capture.index()];
                    if row.point != point.id {
                        return Err(SemanticIrError::procedure(
                            id,
                            SemanticIrErrorKind::CaptureContract,
                            format!(
                                "capture {} is bound at point {}, but its row names point {}",
                                capture, point.id, row.point
                            ),
                        ));
                    }
                    capture_events[capture.index()] += 1;
                }
                SemanticEffect::Invoke { call_site } => {
                    ensure_call_site(id, *call_site, procedure.call_sites.len(), "invoke event")?;
                    let row = &procedure.call_sites[call_site.index()];
                    if row.point != point.id {
                        return Err(SemanticIrError::procedure(
                            id,
                            SemanticIrErrorKind::CallContract,
                            format!(
                                "call site {} is invoked at point {}, but its row names point {}",
                                call_site, point.id, row.point
                            ),
                        ));
                    }
                    invoke_events[call_site.index()] += 1;
                }
                SemanticEffect::CallContinuation { call_site, kind } => {
                    ensure_call_site(
                        id,
                        *call_site,
                        procedure.call_sites.len(),
                        "call continuation",
                    )?;
                    let row = &procedure.call_sites[call_site.index()];
                    let (continuation, slot) = match kind {
                        CallContinuationKind::Normal => (row.normal_continuation, 0),
                        CallContinuationKind::Exceptional => (row.exceptional_continuation, 1),
                    };
                    let Some(expected) = continuation.target() else {
                        return Err(SemanticIrError::procedure(
                            id,
                            SemanticIrErrorKind::CallContract,
                            format!(
                                "{} continuation event for call {} contradicts {} continuation outcome",
                                kind.label(),
                                call_site,
                                continuation.label()
                            ),
                        ));
                    };
                    if expected != point.id {
                        return Err(SemanticIrError::procedure(
                            id,
                            SemanticIrErrorKind::CallContract,
                            format!(
                                "{} continuation for call {} occurs at point {}, expected {}",
                                kind.label(),
                                call_site,
                                point.id,
                                expected
                            ),
                        ));
                    }
                    continuation_events[call_site.index()][slot] += 1;
                }
                SemanticEffect::ProcedureReturn { value } => {
                    if let Some(value) = value {
                        ensure_value(id, *value, procedure.values.len(), "returned value")?;
                    }
                }
                SemanticEffect::Throw { value } => {
                    if let Some(value) = value {
                        ensure_value(id, *value, procedure.values.len(), "thrown value")?;
                    }
                }
                SemanticEffect::AsyncSuspend {
                    awaited,
                    normal_resume,
                    exceptional_resume,
                } => {
                    if let Some(awaited) = awaited {
                        ensure_value(id, *awaited, procedure.values.len(), "awaited value")?;
                    }
                    if let Some(normal) = normal_resume.target() {
                        ensure_point(id, normal, procedure.points.len(), "normal async resume")?;
                    }
                    if let Some(exceptional) = exceptional_resume.target() {
                        ensure_point(
                            id,
                            exceptional,
                            procedure.points.len(),
                            "exceptional async resume",
                        )?;
                    }
                    let normal = normal_resume.target();
                    let exceptional = exceptional_resume.target();
                    if normal == Some(point.id) || exceptional == Some(point.id) {
                        return Err(SemanticIrError::procedure(
                            id,
                            SemanticIrErrorKind::AsyncContract,
                            format!("suspend point {} cannot resume at itself", point.id),
                        ));
                    }
                    if suspends
                        .insert(point.id, (*normal_resume, *exceptional_resume))
                        .is_some()
                    {
                        return Err(SemanticIrError::procedure(
                            id,
                            SemanticIrErrorKind::AsyncContract,
                            format!("point {} contains more than one async suspend", point.id),
                        ));
                    }
                }
                SemanticEffect::AsyncResume {
                    suspend,
                    kind,
                    result,
                } => {
                    ensure_point(
                        id,
                        *suspend,
                        procedure.points.len(),
                        "async suspend reference",
                    )?;
                    if let Some(result) = result {
                        ensure_value(id, *result, procedure.values.len(), "async result")?;
                    }
                    resumes.entry((*suspend, *kind)).or_default().push(point.id);
                }
                SemanticEffect::Gap { gap } => {
                    ensure_gap(id, *gap, procedure.gaps.len(), "gap event")?;
                    let row = &procedure.gaps[gap.index()];
                    if row.point != point.id {
                        return Err(SemanticIrError::procedure(
                            id,
                            SemanticIrErrorKind::GapContract,
                            format!(
                                "gap {} is emitted at point {}, but its row names point {}",
                                gap, point.id, row.point
                            ),
                        ));
                    }
                    gap_events[gap.index()] += 1;
                }
            }
            for capability in effect_capabilities(&event.effect) {
                require_capability(id, capabilities, *capability, event.effect.label())?;
            }
        }
    }

    validate_exactly_once(id, "allocation", &allocation_events)?;
    validate_exactly_once(id, "capture", &capture_events)?;
    validate_exactly_once(id, "invoke", &invoke_events)?;
    validate_exactly_once(id, "gap", &gap_events)?;
    for (index, counts) in continuation_events.into_iter().enumerate() {
        let call_site = &procedure.call_sites[index];
        let expected = [
            usize::from(call_site.normal_continuation.target().is_some()),
            usize::from(call_site.exceptional_continuation.target().is_some()),
        ];
        if counts != expected {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::CallContract,
                format!(
                    "call site {index} continuation events do not match available arms; expected {} and {}, found {} and {}",
                    expected[0], expected[1], counts[0], counts[1]
                ),
            ));
        }
    }

    for call_site in &procedure.call_sites {
        validate_control_continuation(
            capabilities,
            procedure,
            gaps,
            control_edges,
            call_site.point,
            call_site.normal_continuation,
            SemanticGapSubject::CallContinuation {
                call_site: call_site.id,
                kind: CallContinuationKind::Normal,
            },
            SemanticCapability::NormalCallContinuation,
            ControlEdgeKind::Normal,
            "normal call continuation",
        )?;
        validate_control_continuation(
            capabilities,
            procedure,
            gaps,
            control_edges,
            call_site.point,
            call_site.exceptional_continuation,
            SemanticGapSubject::CallContinuation {
                call_site: call_site.id,
                kind: CallContinuationKind::Exceptional,
            },
            SemanticCapability::ExceptionalCallContinuation,
            ControlEdgeKind::Exceptional,
            "exceptional call continuation",
        )?;
        validate_complete_outgoing_topology(
            procedure,
            control_edges,
            call_site.point,
            usize::from(call_site.normal_continuation.target().is_some())
                + usize::from(call_site.exceptional_continuation.target().is_some()),
            "call",
        )?;
        require_resolution_gap(
            procedure,
            gaps,
            call_site.point,
            SemanticGapSubject::CallSite(call_site.id),
            SemanticCapability::Calls,
            &call_site.declared_targets,
        )?;
    }

    for capture in &procedure.captures {
        let matches_creation = callable_creations.contains(&(
            capture.point,
            capture.callable,
            capture.environment,
            capture.target,
        ));
        if !matches_creation {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::CaptureContract,
                format!(
                    "capture {} has no same-point callable creation with matching body and environment",
                    capture.id
                ),
            ));
        }
    }

    validate_async_pairs(
        capabilities,
        procedure,
        gaps,
        control_edges,
        &suspends,
        &resumes,
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_callable_value(
    procedures: &[ProcedureSemanticsParts],
    procedure_locators: &ProcedureLocatorIndex,
    procedure: &ProcedureSemanticsParts,
    point: ProgramPointId,
    result: ValueId,
    callable: &CallableValue,
    gaps: &GapIndex,
    creation: bool,
) -> Result<(), SemanticIrError> {
    let id = procedure.id;
    ensure_value(id, result, procedure.values.len(), "callable result")?;
    if !matches!(
        procedure.values[result.index()].kind,
        SemanticValueKind::Callable
    ) {
        return Err(SemanticIrError::procedure(
            id,
            SemanticIrErrorKind::CallableContract,
            format!("callable event result {result} is not a callable value row"),
        ));
    }
    match (creation, callable.kind) {
        (
            true,
            CallableReferenceKind::BoundMethod
            | CallableReferenceKind::UnboundMethod
            | CallableReferenceKind::StaticMethod
            | CallableReferenceKind::Constructor,
        ) => {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::CallableContract,
                format!(
                    "{} must be represented as a callable reference, not callable creation",
                    callable.kind.label()
                ),
            ));
        }
        (false, CallableReferenceKind::Lambda) => {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::CallableContract,
                "lambda evaluation must be represented as callable creation",
            ));
        }
        _ => {}
    }
    ensure_evidence(
        id,
        callable.target_evidence,
        procedure.evidence_rows.len(),
        "callable target evidence",
    )?;
    validate_target_resolution(
        id,
        procedures,
        procedure_locators,
        &callable.targets,
        &procedure.evidence_rows[callable.target_evidence.index()].proof,
        "callable target",
    )?;
    if creation {
        if callable.targets.candidates().len() > 1 {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::CallableContract,
                "callable creation cannot identify more than one nested executable body",
            ));
        }
        for target in callable.targets.candidates() {
            match target {
                CallableTarget::Local(target)
                    if procedures[target.index()].lexical_parent == Some(id) => {}
                CallableTarget::Local(target) => {
                    return Err(SemanticIrError::procedure(
                        id,
                        SemanticIrErrorKind::CallableContract,
                        format!(
                            "callable creation targets procedure {}, which is not a lexical child",
                            target
                        ),
                    ));
                }
                CallableTarget::Unmaterialized(locator)
                    if is_direct_lexical_child(&procedure.locator, locator) => {}
                CallableTarget::Unmaterialized(_) => {
                    return Err(SemanticIrError::procedure(
                        id,
                        SemanticIrErrorKind::CallableContract,
                        "unmaterialized callable creation target is not a direct lexical child",
                    ));
                }
                CallableTarget::External(_) => {
                    return Err(SemanticIrError::procedure(
                        id,
                        SemanticIrErrorKind::CallableContract,
                        "callable creation must target a separate lexical-child procedure; existing declarations are callable references",
                    ));
                }
            }
        }
    }
    match (callable.kind, callable.bound_receiver) {
        (CallableReferenceKind::BoundMethod, Some(receiver)) => {
            ensure_value(id, receiver, procedure.values.len(), "bound receiver")?;
        }
        (CallableReferenceKind::BoundMethod, None) => {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::CallableContract,
                "bound method reference is missing its evaluated receiver",
            ));
        }
        (_, Some(_)) => {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::CallableContract,
                format!(
                    "{} callable cannot carry a bound receiver",
                    callable.kind.label()
                ),
            ));
        }
        (_, None) => {}
    }
    if !creation && callable.environment.is_some() {
        return Err(SemanticIrError::procedure(
            id,
            SemanticIrErrorKind::CallableContract,
            "callable reference cannot allocate a capture environment",
        ));
    }
    if let Some(environment) = callable.environment {
        ensure_allocation(
            id,
            environment,
            procedure.allocations.len(),
            "callable environment",
        )?;
        if !matches!(
            procedure.allocations[environment.index()].kind,
            AllocationKind::ClosureEnvironment | AllocationKind::LanguageDefined(_)
        ) {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::CallableContract,
                format!(
                    "callable environment {} is not a closure-environment allocation",
                    environment
                ),
            ));
        }
        if procedure.allocations[environment.index()].point != point {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::CallableContract,
                format!(
                    "callable environment {} is allocated at point {}, not creation point {}",
                    environment,
                    procedure.allocations[environment.index()].point,
                    point
                ),
            ));
        }
    }
    require_resolution_gap(
        procedure,
        gaps,
        point,
        SemanticGapSubject::Value(result),
        SemanticCapability::CallableReferences,
        &callable.targets,
    )
}

fn validate_value_flow_kind(
    procedure: &ProcedureSemanticsParts,
    kind: ValueFlowKind,
    source: ValueId,
    target: ValueId,
) -> Result<(), SemanticIrError> {
    let source_kind = &procedure.values[source.index()].kind;
    let target_kind = &procedure.values[target.index()].kind;
    let valid = match kind {
        ValueFlowKind::Local => true,
        ValueFlowKind::Parameter => {
            matches!(source_kind, SemanticValueKind::Parameter { .. })
                || matches!(target_kind, SemanticValueKind::Parameter { .. })
        }
        ValueFlowKind::Receiver => {
            matches!(source_kind, SemanticValueKind::Receiver)
                || matches!(target_kind, SemanticValueKind::Receiver)
        }
        ValueFlowKind::Return => {
            matches!(source_kind, SemanticValueKind::Return)
                || matches!(target_kind, SemanticValueKind::Return)
        }
    };
    if !valid {
        return Err(SemanticIrError::procedure(
            procedure.id,
            SemanticIrErrorKind::ValueFlowContract,
            format!(
                "{} flow {} -> {} has no value row with that role",
                kind.label(),
                source,
                target
            ),
        ));
    }
    Ok(())
}

fn validate_memory_access_kind(
    procedure: &ProcedureSemanticsParts,
    location: MemoryLocationId,
    access: MemoryAccessKind,
) -> Result<(), SemanticIrError> {
    let location_kind = &procedure.memory_locations[location.index()].kind;
    let matches = matches!(
        (access, location_kind),
        (MemoryAccessKind::Field, MemoryLocationKind::Field { .. })
            | (MemoryAccessKind::Static, MemoryLocationKind::Static { .. })
            | (MemoryAccessKind::Index, MemoryLocationKind::Index { .. })
            | (
                MemoryAccessKind::LexicalCell,
                MemoryLocationKind::LexicalCell { .. }
            )
            | (
                MemoryAccessKind::Capture,
                MemoryLocationKind::Capture { .. }
            )
    );
    if !matches {
        return Err(SemanticIrError::procedure(
            procedure.id,
            SemanticIrErrorKind::MemoryContract,
            format!(
                "{} access names {} location {}",
                access.label(),
                location_kind.label(),
                location
            ),
        ));
    }
    Ok(())
}

fn required_gap_kind(resolution: &CallableTargetResolution) -> Option<SemanticGapKind> {
    match resolution {
        CallableTargetResolution::Proven(_) => None,
        CallableTargetResolution::Ambiguous(_) => Some(SemanticGapKind::Ambiguous),
        CallableTargetResolution::Unknown => Some(SemanticGapKind::Unknown),
        CallableTargetResolution::Unsupported => Some(SemanticGapKind::Unsupported),
        CallableTargetResolution::Unproven(_) => Some(SemanticGapKind::Unproven),
        CallableTargetResolution::ExceededBudget(_) => Some(SemanticGapKind::ExceededBudget),
    }
}

fn continuation_gap_kind(continuation: ControlContinuation) -> Option<SemanticGapKind> {
    match continuation {
        ControlContinuation::Target(_) | ControlContinuation::Absent => None,
        ControlContinuation::Unknown => Some(SemanticGapKind::Unknown),
        ControlContinuation::Unsupported => Some(SemanticGapKind::Unsupported),
        ControlContinuation::Unproven => Some(SemanticGapKind::Unproven),
        ControlContinuation::ExceededBudget => Some(SemanticGapKind::ExceededBudget),
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_control_continuation(
    capabilities: &SemanticCapabilities,
    procedure: &ProcedureSemanticsParts,
    gaps: &GapIndex,
    control_edges: &ControlEdgeIndex,
    source: ProgramPointId,
    continuation: ControlContinuation,
    subject: SemanticGapSubject,
    capability: SemanticCapability,
    edge_kind: ControlEdgeKind,
    context: &str,
) -> Result<(), SemanticIrError> {
    let outgoing_count = control_edges.outgoing_count(source, edge_kind);
    if let Some(target) = continuation.target() {
        require_capability(procedure.id, capabilities, capability, context)?;
        if outgoing_count != 1 || !control_edges.contains(source, target, edge_kind) {
            return Err(SemanticIrError::procedure(
                procedure.id,
                SemanticIrErrorKind::ControlFlowContract,
                format!(
                    "{context} requires exactly one {} edge {} -> {}; found {outgoing_count} outgoing edges of that kind",
                    edge_kind.label(),
                    source,
                    target
                ),
            ));
        }
    } else {
        if outgoing_count != 0 {
            return Err(SemanticIrError::procedure(
                procedure.id,
                SemanticIrErrorKind::ControlFlowContract,
                format!(
                    "{context} {} outcome forbids {} edges from point {}; found {outgoing_count}",
                    continuation.label(),
                    edge_kind.label(),
                    source
                ),
            ));
        }
        if continuation == ControlContinuation::Absent {
            require_capability(procedure.id, capabilities, capability, context)?;
        }
    }
    validate_expected_gap(
        procedure,
        gaps,
        source,
        subject,
        capability,
        continuation_gap_kind(continuation),
        context,
    )
}

fn validate_complete_outgoing_topology(
    procedure: &ProcedureSemanticsParts,
    control_edges: &ControlEdgeIndex,
    source: ProgramPointId,
    expected: usize,
    context: &str,
) -> Result<(), SemanticIrError> {
    let actual = control_edges.total_outgoing_count(source);
    if actual == expected {
        return Ok(());
    }
    Err(SemanticIrError::procedure(
        procedure.id,
        SemanticIrErrorKind::ControlFlowContract,
        format!(
            "{context} point {source} owns its complete outgoing topology; expected {expected} continuation edges, found {actual} total outgoing edges"
        ),
    ))
}

fn require_resolution_gap(
    procedure: &ProcedureSemanticsParts,
    gaps: &GapIndex,
    point: ProgramPointId,
    subject: SemanticGapSubject,
    capability: SemanticCapability,
    resolution: &CallableTargetResolution,
) -> Result<(), SemanticIrError> {
    validate_expected_gap(
        procedure,
        gaps,
        point,
        subject,
        capability,
        required_gap_kind(resolution),
        resolution.label(),
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_expected_gap(
    procedure: &ProcedureSemanticsParts,
    gaps: &GapIndex,
    point: ProgramPointId,
    subject: SemanticGapSubject,
    capability: SemanticCapability,
    expected: Option<SemanticGapKind>,
    context: &str,
) -> Result<(), SemanticIrError> {
    let actual = gaps.fact_kind(point, subject, capability);
    if actual == expected {
        return Ok(());
    }
    let expected = expected.map_or("none", SemanticGapKind::label);
    let actual = actual.map_or("none", SemanticGapKind::label);
    Err(SemanticIrError::procedure(
        procedure.id,
        SemanticIrErrorKind::GapContract,
        format!(
            "{context} outcome at point {point} requires gap {expected}, found {actual} for {}",
            capability.label()
        ),
    ))
}

fn validate_async_pairs(
    capabilities: &SemanticCapabilities,
    procedure: &ProcedureSemanticsParts,
    gaps: &GapIndex,
    control_edges: &ControlEdgeIndex,
    suspends: &HashMap<ProgramPointId, (ControlContinuation, ControlContinuation)>,
    resumes: &HashMap<(ProgramPointId, AsyncResumeKind), Vec<ProgramPointId>>,
) -> Result<(), SemanticIrError> {
    let id = procedure.id;
    for (suspend, (normal, exceptional)) in suspends {
        let normal_points = resumes
            .get(&(*suspend, AsyncResumeKind::Normal))
            .map(Vec::as_slice)
            .unwrap_or_default();
        let exceptional_points = resumes
            .get(&(*suspend, AsyncResumeKind::Exceptional))
            .map(Vec::as_slice)
            .unwrap_or_default();
        let normal_matches = match normal.target() {
            Some(target) => normal_points == [target],
            None => normal_points.is_empty(),
        };
        let exceptional_matches = match exceptional.target() {
            Some(target) => exceptional_points == [target],
            None => exceptional_points.is_empty(),
        };
        if !normal_matches || !exceptional_matches {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::AsyncContract,
                format!(
                    "suspend point {} resume events do not match its normal {} and exceptional {} outcomes",
                    suspend,
                    normal.label(),
                    exceptional.label()
                ),
            ));
        }
        validate_control_continuation(
            capabilities,
            procedure,
            gaps,
            control_edges,
            *suspend,
            *normal,
            SemanticGapSubject::AsyncContinuation {
                suspend: *suspend,
                kind: AsyncResumeKind::Normal,
            },
            SemanticCapability::AsyncSuspendResume,
            ControlEdgeKind::AsyncNormal,
            "normal async resume",
        )?;
        validate_control_continuation(
            capabilities,
            procedure,
            gaps,
            control_edges,
            *suspend,
            *exceptional,
            SemanticGapSubject::AsyncContinuation {
                suspend: *suspend,
                kind: AsyncResumeKind::Exceptional,
            },
            SemanticCapability::AsyncSuspendResume,
            ControlEdgeKind::AsyncExceptional,
            "exceptional async resume",
        )?;
        validate_complete_outgoing_topology(
            procedure,
            control_edges,
            *suspend,
            usize::from(normal.target().is_some()) + usize::from(exceptional.target().is_some()),
            "async suspend",
        )?;
    }
    for ((suspend, _), points) in resumes {
        if !suspends.contains_key(suspend) || points.len() != 1 {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::AsyncContract,
                format!(
                    "async resume references absent or non-unique suspend point {}",
                    suspend
                ),
            ));
        }
    }
    if (!suspends.is_empty() || !resumes.is_empty()) && !procedure.properties.is_async {
        return Err(SemanticIrError::procedure(
            id,
            SemanticIrErrorKind::AsyncContract,
            "async suspend/resume events require an async procedure",
        ));
    }
    Ok(())
}

fn validate_exactly_once(
    procedure: ProcedureId,
    table: &str,
    counts: &[usize],
) -> Result<(), SemanticIrError> {
    for (index, count) in counts.iter().copied().enumerate() {
        if count != 1 {
            return Err(SemanticIrError::procedure(
                procedure,
                SemanticIrErrorKind::EventContract,
                format!("{table} row {index} must have exactly one event; found {count}"),
            ));
        }
    }
    Ok(())
}

fn find_boundaries(procedure: &ProcedureSemanticsParts) -> Result<Boundaries, SemanticIrError> {
    let mut entry = None;
    let mut normal_exit = None;
    let mut exceptional_exit = None;
    let mut counts = [0_usize; 3];
    for point in &procedure.points {
        for event in &point.events {
            match event.effect {
                SemanticEffect::Entry => {
                    counts[0] += 1;
                    entry.get_or_insert(point.id);
                }
                SemanticEffect::NormalExit => {
                    counts[1] += 1;
                    normal_exit.get_or_insert(point.id);
                }
                SemanticEffect::ExceptionalExit => {
                    counts[2] += 1;
                    exceptional_exit.get_or_insert(point.id);
                }
                _ => {}
            }
        }
    }
    if counts != [1, 1, 1] {
        return Err(SemanticIrError::procedure(
            procedure.id,
            SemanticIrErrorKind::Boundary,
            format!(
                "expected exactly one entry, normal exit, and exceptional exit; found {}, {}, and {}",
                counts[0], counts[1], counts[2]
            ),
        ));
    }
    let entry = entry.expect("exactly one entry was counted");
    let normal_exit = normal_exit.expect("exactly one normal exit was counted");
    let exceptional_exit = exceptional_exit.expect("exactly one exceptional exit was counted");
    if entry == normal_exit || entry == exceptional_exit || normal_exit == exceptional_exit {
        return Err(SemanticIrError::procedure(
            procedure.id,
            SemanticIrErrorKind::Boundary,
            "entry, normal exit, and exceptional exit must be distinct program points",
        ));
    }
    Ok(Boundaries {
        entry,
        normal_exit,
        exceptional_exit,
    })
}

fn validate_metadata(
    procedure: ProcedureId,
    source: SourceMappingId,
    evidence: EvidenceId,
    parts: &ProcedureSemanticsParts,
    context: &str,
) -> Result<(), SemanticIrError> {
    ensure_source(procedure, source, parts.source_mappings.len(), context)?;
    ensure_evidence(procedure, evidence, parts.evidence_rows.len(), context)
}

fn ensure_index(
    procedure: ProcedureId,
    context: &str,
    index: usize,
    len: usize,
) -> Result<(), SemanticIrError> {
    if index < len {
        Ok(())
    } else {
        Err(SemanticIrError::procedure(
            procedure,
            SemanticIrErrorKind::OutOfBounds,
            format!("{context} id {index} is outside dense table length {len}"),
        ))
    }
}

macro_rules! ensure_local_id {
    ($name:ident, $id_ty:ty, $label:literal) => {
        fn $name(
            procedure: ProcedureId,
            id: $id_ty,
            len: usize,
            context: &str,
        ) -> Result<(), SemanticIrError> {
            ensure_index(
                procedure,
                &format!("{context} ({})", $label),
                id.index(),
                len,
            )
        }
    };
}

ensure_local_id!(ensure_block, BlockId, "block");
ensure_local_id!(ensure_point, ProgramPointId, "program point");
ensure_local_id!(ensure_value, ValueId, "value");
ensure_local_id!(ensure_allocation, AllocationId, "allocation");
ensure_local_id!(ensure_call_site, CallSiteId, "call site");
ensure_local_id!(ensure_location, MemoryLocationId, "memory location");
ensure_local_id!(ensure_capture, CaptureId, "capture");
ensure_local_id!(ensure_source, SourceMappingId, "source mapping");
ensure_local_id!(ensure_evidence, EvidenceId, "evidence");
ensure_local_id!(ensure_gap, SemanticGapId, "semantic gap");

fn require_artifact_capability(
    capabilities: &SemanticCapabilities,
    capability: SemanticCapability,
    context: &str,
) -> Result<(), SemanticIrError> {
    if capabilities.is_available(capability) {
        return Ok(());
    }
    Err(SemanticIrError::artifact(
        SemanticIrErrorKind::CapabilityContract,
        format!(
            "{context} emits {}, but the capability table marks it unsupported",
            capability.label()
        ),
    ))
}

fn require_capability(
    procedure: ProcedureId,
    capabilities: &SemanticCapabilities,
    capability: SemanticCapability,
    context: &str,
) -> Result<(), SemanticIrError> {
    if capabilities.is_available(capability) {
        return Ok(());
    }
    Err(SemanticIrError::procedure(
        procedure,
        SemanticIrErrorKind::CapabilityContract,
        format!(
            "{context} emits {}, but the capability table marks it unsupported",
            capability.label()
        ),
    ))
}

fn validate_gap_capability(
    procedure: ProcedureId,
    capabilities: &SemanticCapabilities,
    gap: &SemanticGap,
) -> Result<(), SemanticIrError> {
    let support = capabilities.support(gap.capability);
    let consistent = match gap.kind {
        SemanticGapKind::Unsupported => support != CapabilitySupport::Complete,
        SemanticGapKind::Ambiguous
        | SemanticGapKind::Unknown
        | SemanticGapKind::Unproven
        | SemanticGapKind::ExceededBudget => support != CapabilitySupport::Unsupported,
    };
    if consistent {
        return Ok(());
    }
    Err(SemanticIrError::procedure(
        procedure,
        SemanticIrErrorKind::CapabilityContract,
        format!(
            "{} gap for {} contradicts capability support {:?}",
            gap.kind.label(),
            gap.capability.label(),
            support
        ),
    ))
}

fn memory_location_capability(kind: &MemoryLocationKind) -> SemanticCapability {
    match kind {
        MemoryLocationKind::Field { .. } => SemanticCapability::FieldMemory,
        MemoryLocationKind::Static { .. } => SemanticCapability::StaticMemory,
        MemoryLocationKind::Index { .. } => SemanticCapability::IndexMemory,
        MemoryLocationKind::LexicalCell { .. } => SemanticCapability::LocalFlow,
        MemoryLocationKind::Capture { .. } => SemanticCapability::Captures,
    }
}

fn memory_access_capability(kind: MemoryAccessKind) -> SemanticCapability {
    match kind {
        MemoryAccessKind::Field => SemanticCapability::FieldMemory,
        MemoryAccessKind::Static => SemanticCapability::StaticMemory,
        MemoryAccessKind::Index => SemanticCapability::IndexMemory,
        MemoryAccessKind::LexicalCell => SemanticCapability::LocalFlow,
        MemoryAccessKind::Capture => SemanticCapability::Captures,
    }
}

fn control_edge_capability(kind: ControlEdgeKind) -> SemanticCapability {
    match kind {
        ControlEdgeKind::Normal
        | ControlEdgeKind::ConditionalTrue
        | ControlEdgeKind::ConditionalFalse
        | ControlEdgeKind::SwitchCase
        | ControlEdgeKind::LoopBack => SemanticCapability::NormalControlFlow,
        ControlEdgeKind::Exceptional => SemanticCapability::ExceptionalControlFlow,
        ControlEdgeKind::Cleanup => SemanticCapability::CleanupControlFlow,
        ControlEdgeKind::AsyncNormal | ControlEdgeKind::AsyncExceptional => {
            SemanticCapability::AsyncSuspendResume
        }
    }
}

fn is_control_splitting_effect(effect: &SemanticEffect) -> bool {
    matches!(
        effect,
        SemanticEffect::NormalExit
            | SemanticEffect::ExceptionalExit
            | SemanticEffect::Invoke { .. }
            | SemanticEffect::ProcedureReturn { .. }
            | SemanticEffect::Throw { .. }
            | SemanticEffect::AsyncSuspend { .. }
    )
}

fn effect_capabilities(effect: &SemanticEffect) -> &'static [SemanticCapability] {
    match effect {
        SemanticEffect::Entry => &[SemanticCapability::EntryBoundary],
        SemanticEffect::NormalExit => &[SemanticCapability::NormalExitBoundary],
        SemanticEffect::ExceptionalExit => &[SemanticCapability::ExceptionalExitBoundary],
        SemanticEffect::Assignment { .. } => {
            &[SemanticCapability::Assignments, SemanticCapability::Values]
        }
        SemanticEffect::ValueFlow { kind, .. } => match kind {
            ValueFlowKind::Local => &[SemanticCapability::Values, SemanticCapability::LocalFlow],
            ValueFlowKind::Parameter => &[
                SemanticCapability::Values,
                SemanticCapability::ParameterFlow,
            ],
            ValueFlowKind::Receiver => {
                &[SemanticCapability::Values, SemanticCapability::ReceiverFlow]
            }
            ValueFlowKind::Return => &[SemanticCapability::Values, SemanticCapability::ReturnFlow],
        },
        SemanticEffect::Allocation { .. } => &[SemanticCapability::Allocations],
        SemanticEffect::MemoryLoad { kind, .. } | SemanticEffect::MemoryStore { kind, .. } => {
            match memory_access_capability(*kind) {
                SemanticCapability::FieldMemory => {
                    &[SemanticCapability::Values, SemanticCapability::FieldMemory]
                }
                SemanticCapability::StaticMemory => {
                    &[SemanticCapability::Values, SemanticCapability::StaticMemory]
                }
                SemanticCapability::IndexMemory => {
                    &[SemanticCapability::Values, SemanticCapability::IndexMemory]
                }
                SemanticCapability::LocalFlow => {
                    &[SemanticCapability::Values, SemanticCapability::LocalFlow]
                }
                SemanticCapability::Captures => {
                    &[SemanticCapability::Values, SemanticCapability::Captures]
                }
                _ => unreachable!("memory access maps only to memory capabilities"),
            }
        }
        SemanticEffect::CallableCreation { .. } | SemanticEffect::CallableReference { .. } => &[
            SemanticCapability::Values,
            SemanticCapability::CallableReferences,
        ],
        SemanticEffect::CaptureBind { .. } => &[SemanticCapability::Captures],
        SemanticEffect::Invoke { .. } => &[SemanticCapability::Calls],
        SemanticEffect::CallContinuation { kind, .. } => match kind {
            CallContinuationKind::Normal => &[SemanticCapability::NormalCallContinuation],
            CallContinuationKind::Exceptional => &[SemanticCapability::ExceptionalCallContinuation],
        },
        SemanticEffect::ProcedureReturn { .. } => &[SemanticCapability::ReturnFlow],
        SemanticEffect::Throw { .. } => &[SemanticCapability::ExceptionalControlFlow],
        SemanticEffect::AsyncSuspend { .. } | SemanticEffect::AsyncResume { .. } => {
            &[SemanticCapability::AsyncSuspendResume]
        }
        SemanticEffect::Gap { .. } => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::Language;

    use super::super::ids::{
        AdapterSemanticsVersion, ConfigurationFingerprint, ContentIdentity, DeclarationLocator,
        DeclarationSegment, DeclarationSegmentKind, DependencyFingerprint, SemanticIrVersion,
        SemanticLanguage, SourceAnchor, SourcePosition, SourceRevision, SourceSpan,
        WorkspaceMountId, WorkspaceRelativePath,
    };

    fn key_with_language(language: SemanticLanguage) -> SemanticArtifactKey {
        SemanticArtifactKey::new(
            WorkspaceMountId::hash_bytes(b"test mount"),
            WorkspaceRelativePath::new("src/Test.java").expect("valid fixture path"),
            language,
            SourceRevision::Disk {
                content: ContentIdentity::hash_bytes(b"class Test {}"),
            },
            AdapterSemanticsVersion::hash_bytes("test-java", b"adapter")
                .expect("non-empty adapter"),
            SemanticIrVersion::hash_bytes(b"semantic-ir-test"),
            ConfigurationFingerprint::hash_bytes(b"configuration"),
            DependencyFingerprint::hash_bytes(b"dependencies"),
        )
    }

    fn key() -> SemanticArtifactKey {
        key_with_language(SemanticLanguage::Standard(Language::Java))
    }

    fn capabilities(features: &[SemanticCapability]) -> SemanticCapabilities {
        let mut builder = SemanticCapabilities::builder();
        for capability in [
            SemanticCapability::Procedures,
            SemanticCapability::EntryBoundary,
            SemanticCapability::NormalExitBoundary,
            SemanticCapability::ExceptionalExitBoundary,
            SemanticCapability::BasicBlocks,
            SemanticCapability::ProgramPoints,
            SemanticCapability::NormalControlFlow,
            SemanticCapability::ExceptionalControlFlow,
        ]
        .into_iter()
        .chain(features.iter().copied())
        {
            builder = builder.complete(capability);
        }
        builder.build()
    }

    fn anchor(offset: u32, occurrence: u32) -> SourceAnchor {
        let start = SourcePosition::new(offset, 0, offset);
        let end = SourcePosition::new(offset + 1, 0, offset + 1);
        SourceAnchor::new(
            SourceSpan::new(start, end).expect("ordered fixture span"),
            occurrence,
        )
    }

    fn procedure_locator(key: &SemanticArtifactKey, name: &str, offset: u32) -> SemanticLocator {
        let file_anchor = anchor(0, 0);
        let procedure_anchor = anchor(offset, 0);
        let declaration = DeclarationLocator::new(vec![
            DeclarationSegment::named(DeclarationSegmentKind::File, "Test.java", file_anchor, 0)
                .expect("named file segment"),
            DeclarationSegment::named(DeclarationSegmentKind::Function, name, procedure_anchor, 0)
                .expect("named procedure segment"),
        ])
        .expect("non-empty declaration path");
        SemanticLocator::new(
            key.mount(),
            key.path().clone(),
            key.language(),
            declaration,
            SemanticRole::Procedure,
            procedure_anchor,
        )
    }

    fn direct_child_locator(
        key: &SemanticArtifactKey,
        parent: &SemanticLocator,
        kind: DeclarationSegmentKind,
        name: &str,
        offset: u32,
    ) -> SemanticLocator {
        let child_anchor = anchor(offset, 0);
        let mut segments = parent.declaration().segments().to_vec();
        segments.push(
            DeclarationSegment::named(kind, name, child_anchor, 0)
                .expect("named child procedure segment"),
        );
        SemanticLocator::new(
            key.mount(),
            key.path().clone(),
            key.language(),
            DeclarationLocator::new(segments).expect("non-empty child declaration path"),
            SemanticRole::Procedure,
            child_anchor,
        )
    }

    fn minimal_procedure(
        key: &SemanticArtifactKey,
        id: ProcedureId,
        name: &str,
        offset: u32,
    ) -> ProcedureSemanticsParts {
        let locator = procedure_locator(key, name, offset);
        let source = SourceMappingId::new(0);
        let evidence = EvidenceId::new(0);
        let mut parts = ProcedureSemanticsParts::new(
            id,
            locator.clone(),
            ProcedureKind::Function,
            source,
            evidence,
        );
        parts.source_mappings.push(SourceMapping {
            id: source,
            locator,
            kind: SourceMappingKind::Exact,
        });
        parts.evidence_rows.push(Evidence {
            id: evidence,
            proof: ProofStatus::Proven,
            completeness: EvidenceCompleteness::Complete,
            sources: vec![source].into_boxed_slice(),
        });

        let entry = ProgramPointId::new(0);
        let normal_exit = ProgramPointId::new(1);
        let exceptional_exit = ProgramPointId::new(2);
        parts.blocks.push(BasicBlock {
            id: BlockId::new(0),
            points: vec![entry, normal_exit, exceptional_exit].into_boxed_slice(),
            source,
            evidence,
        });
        parts.points.extend([
            ProgramPoint {
                id: entry,
                block: BlockId::new(0),
                events: vec![SemanticEvent::new(SemanticEffect::Entry, source, evidence)]
                    .into_boxed_slice(),
                source,
                evidence,
            },
            ProgramPoint {
                id: normal_exit,
                block: BlockId::new(0),
                events: vec![SemanticEvent::new(
                    SemanticEffect::NormalExit,
                    source,
                    evidence,
                )]
                .into_boxed_slice(),
                source,
                evidence,
            },
            ProgramPoint {
                id: exceptional_exit,
                block: BlockId::new(0),
                events: vec![SemanticEvent::new(
                    SemanticEffect::ExceptionalExit,
                    source,
                    evidence,
                )]
                .into_boxed_slice(),
                source,
                evidence,
            },
        ]);
        parts.control_edges.extend([
            ControlEdge {
                source_point: entry,
                target_point: normal_exit,
                kind: ControlEdgeKind::Normal,
                source,
                evidence,
            },
            ControlEdge {
                source_point: entry,
                target_point: exceptional_exit,
                kind: ControlEdgeKind::Exceptional,
                source,
                evidence,
            },
        ]);
        parts
    }

    #[test]
    fn minimal_valid_artifact_exposes_scoped_handles() {
        let key = key();
        let artifact = SemanticArtifact::try_new(
            key.clone(),
            capabilities(&[]),
            vec![minimal_procedure(&key, ProcedureId::new(0), "main", 1)],
        )
        .expect("minimal procedure is valid");
        assert_eq!(artifact.key(), &key);
        assert_eq!(artifact.procedures().len(), 1);
        let procedure = &artifact.procedures()[0];
        assert_eq!(procedure.entry_point(), ProgramPointId::new(0));
        assert_eq!(procedure.normal_exit_point(), ProgramPointId::new(1));
        assert_eq!(procedure.exceptional_exit_point(), ProgramPointId::new(2));

        let artifact = Arc::new(artifact);
        let handle = artifact
            .procedure_handle(ProcedureId::new(0))
            .expect("in-bounds procedure handle");
        assert!(handle.point_handle(ProgramPointId::new(2)).is_some());
        assert!(handle.point_handle(ProgramPointId::new(3)).is_none());
        assert!(handle.control_edge_handle(ControlEdgeId::new(1)).is_some());
        assert!(handle.control_edge_handle(ControlEdgeId::new(2)).is_none());
        assert!(handle.value_handle(ValueId::new(0)).is_none());
    }

    #[test]
    fn cfg_freeze_assigns_canonical_edge_ids_and_bidirectional_rows() {
        let key = key();
        let mut parts = minimal_procedure(&key, ProcedureId::new(0), "main", 1);
        parts.control_edges.reverse();

        let artifact = SemanticArtifact::try_new(key, capabilities(&[]), vec![parts])
            .expect("valid edges should freeze into indexed topology");
        let procedure = &artifact.procedures()[0];

        // Six locator segments, one evidence source, three block members,
        // eight row offsets, and two incoming edge IDs are retained.
        assert_eq!(artifact.work().nested_entries, 20);
        assert_eq!(procedure.control_edges(), procedure.cfg().edges());
        assert_eq!(procedure.control_edges().len(), 2);
        assert_eq!(
            procedure.control_edge(ControlEdgeId::new(0)).unwrap().kind,
            ControlEdgeKind::Exceptional
        );
        assert_eq!(
            procedure.control_edge(ControlEdgeId::new(1)).unwrap().kind,
            ControlEdgeKind::Normal
        );
        assert!(procedure.control_edge(ControlEdgeId::new(2)).is_none());

        let successors = procedure
            .successor_edges(ProgramPointId::new(0))
            .map(|(id, edge)| (id, edge.target_point, edge.kind))
            .collect::<Vec<_>>();
        assert_eq!(
            successors,
            vec![
                (
                    ControlEdgeId::new(0),
                    ProgramPointId::new(2),
                    ControlEdgeKind::Exceptional,
                ),
                (
                    ControlEdgeId::new(1),
                    ProgramPointId::new(1),
                    ControlEdgeKind::Normal,
                ),
            ]
        );
        assert_eq!(
            procedure
                .predecessor_edges(ProgramPointId::new(1))
                .map(|(id, _)| id)
                .collect::<Vec<_>>(),
            vec![ControlEdgeId::new(1)]
        );
        assert_eq!(
            procedure
                .predecessor_edges(ProgramPointId::new(2))
                .map(|(id, _)| id)
                .collect::<Vec<_>>(),
            vec![ControlEdgeId::new(0)]
        );
        assert_eq!(procedure.predecessor_edges(ProgramPointId::new(0)).len(), 0);
        assert_eq!(procedure.successor_edges(ProgramPointId::new(1)).len(), 0);

        let invalid = ProgramPointId::new(u32::MAX);
        assert!(
            std::panic::catch_unwind(|| procedure.cfg().successor_edges(invalid).count()).is_err()
        );
        assert!(
            std::panic::catch_unwind(|| procedure.cfg().predecessor_edges(invalid).count())
                .is_err()
        );
        assert!(std::panic::catch_unwind(|| procedure.successor_edges(invalid).count()).is_err());
        assert!(std::panic::catch_unwind(|| procedure.predecessor_edges(invalid).count()).is_err());
    }

    #[test]
    fn exact_rich_edges_are_rejected_but_distinct_provenance_is_preserved() {
        let key = key();
        let mut duplicate = minimal_procedure(&key, ProcedureId::new(0), "duplicate", 1);
        duplicate
            .control_edges
            .push(duplicate.control_edges[0].clone());
        let error = SemanticArtifact::try_new(key.clone(), capabilities(&[]), vec![duplicate])
            .expect_err("an exact rich-edge duplicate must fail");
        assert_eq!(error.kind(), SemanticIrErrorKind::DuplicateEdge);

        let mut parallel = minimal_procedure(&key, ProcedureId::new(0), "parallel", 1);
        let second_source = SourceMappingId::new(1);
        let second_evidence = EvidenceId::new(1);
        parallel.source_mappings.push(SourceMapping {
            id: second_source,
            locator: parallel.locator.clone(),
            kind: SourceMappingKind::Exact,
        });
        parallel.evidence_rows.push(Evidence {
            id: second_evidence,
            proof: ProofStatus::Proven,
            completeness: EvidenceCompleteness::Complete,
            sources: Box::new([second_source]),
        });
        let mut second = parallel.control_edges[0].clone();
        second.source = second_source;
        second.evidence = second_evidence;
        parallel.control_edges.push(second);

        let artifact = SemanticArtifact::try_new(key, capabilities(&[]), vec![parallel])
            .expect("parallel rich edges with distinct provenance are valid");
        let procedure = &artifact.procedures()[0];
        let parallel_edges = procedure
            .predecessor_edges(ProgramPointId::new(1))
            .map(|(_, edge)| (edge.source, edge.evidence))
            .collect::<Vec<_>>();
        assert_eq!(
            parallel_edges,
            vec![
                (SourceMappingId::new(0), EvidenceId::new(0)),
                (second_source, second_evidence),
            ]
        );
    }

    fn raw_cfg_parts() -> (Vec<ControlEdge>, Vec<u32>, Vec<u32>, Vec<ControlEdgeId>) {
        let source = SourceMappingId::new(0);
        let evidence = EvidenceId::new(0);
        (
            vec![
                ControlEdge {
                    source_point: ProgramPointId::new(0),
                    target_point: ProgramPointId::new(2),
                    kind: ControlEdgeKind::Exceptional,
                    source,
                    evidence,
                },
                ControlEdge {
                    source_point: ProgramPointId::new(0),
                    target_point: ProgramPointId::new(1),
                    kind: ControlEdgeKind::Normal,
                    source,
                    evidence,
                },
            ],
            vec![0, 2, 2, 2],
            vec![0, 0, 1, 2],
            vec![ControlEdgeId::new(1), ControlEdgeId::new(0)],
        )
    }

    #[test]
    fn checked_cfg_parts_reject_corrupt_adjacency() {
        let procedure = ProcedureId::new(0);
        let (edges, outgoing, incoming_offsets, incoming_ids) = raw_cfg_parts();
        ControlFlowGraph::try_from_parts(
            procedure,
            3,
            edges,
            outgoing,
            incoming_offsets,
            incoming_ids,
        )
        .expect("valid raw adjacency should pass defensive validation");

        let (edges, _, incoming_offsets, incoming_ids) = raw_cfg_parts();
        let error = ControlFlowGraph::try_from_parts(
            procedure,
            3,
            edges,
            vec![0, 1, 2, 2],
            incoming_offsets,
            incoming_ids,
        )
        .expect_err("an edge in the wrong outgoing row must fail");
        assert_eq!(error.kind(), SemanticIrErrorKind::ControlFlowContract);

        let (edges, outgoing, incoming_offsets, _) = raw_cfg_parts();
        let error = ControlFlowGraph::try_from_parts(
            procedure,
            3,
            edges,
            outgoing,
            incoming_offsets,
            vec![ControlEdgeId::new(1), ControlEdgeId::new(9)],
        )
        .expect_err("an out-of-range incoming edge id must fail");
        assert_eq!(error.kind(), SemanticIrErrorKind::ControlFlowContract);

        let (edges, outgoing, incoming_offsets, _) = raw_cfg_parts();
        let error = ControlFlowGraph::try_from_parts(
            procedure,
            3,
            edges,
            outgoing,
            incoming_offsets,
            vec![ControlEdgeId::new(0), ControlEdgeId::new(1)],
        )
        .expect_err("an edge in the wrong incoming row must fail");
        assert_eq!(error.kind(), SemanticIrErrorKind::ControlFlowContract);

        let (edges, outgoing, incoming_offsets, _) = raw_cfg_parts();
        let error = ControlFlowGraph::try_from_parts(
            procedure,
            3,
            edges,
            outgoing,
            incoming_offsets,
            vec![ControlEdgeId::new(1), ControlEdgeId::new(1)],
        )
        .expect_err("duplicate and missing incoming membership must fail");
        assert_eq!(error.kind(), SemanticIrErrorKind::ControlFlowContract);

        let source = SourceMappingId::new(0);
        let evidence = EvidenceId::new(0);
        let (mut edges, _, _, _) = raw_cfg_parts();
        edges.push(ControlEdge {
            source_point: ProgramPointId::new(1),
            target_point: ProgramPointId::new(2),
            kind: ControlEdgeKind::Normal,
            source,
            evidence,
        });
        let error = ControlFlowGraph::try_from_parts(
            procedure,
            3,
            edges,
            vec![0, 2, 3, 3],
            vec![0, 0, 1, 3],
            vec![
                ControlEdgeId::new(1),
                ControlEdgeId::new(2),
                ControlEdgeId::new(0),
            ],
        )
        .expect_err("incoming rows must retain canonical control-edge order");
        assert_eq!(error.kind(), SemanticIrErrorKind::ControlFlowContract);
    }

    #[test]
    fn rejects_non_dense_and_out_of_bounds_local_ids() {
        let key = key();
        let mut non_dense = minimal_procedure(&key, ProcedureId::new(0), "main", 1);
        non_dense.points[1].id = ProgramPointId::new(99);
        let error = SemanticArtifact::try_new(key.clone(), capabilities(&[]), vec![non_dense])
            .expect_err("non-dense point id must fail");
        assert_eq!(error.kind(), SemanticIrErrorKind::DenseId);

        let mut out_of_bounds = minimal_procedure(&key, ProcedureId::new(0), "main", 1);
        let mut entry_events = out_of_bounds.points[0].events.to_vec();
        entry_events.push(SemanticEvent::new(
            SemanticEffect::Assignment {
                target: ValueId::new(0),
                value: ValueId::new(0),
            },
            SourceMappingId::new(0),
            EvidenceId::new(0),
        ));
        out_of_bounds.points[0].events = entry_events.into_boxed_slice();
        let error = SemanticArtifact::try_new(key, capabilities(&[]), vec![out_of_bounds])
            .expect_err("bare value id outside this procedure must fail");
        assert_eq!(error.kind(), SemanticIrErrorKind::OutOfBounds);
    }

    #[test]
    fn rejects_lexical_parent_cycle_iteratively() {
        let key = key();
        let mut outer = minimal_procedure(&key, ProcedureId::new(0), "outer", 1);
        let mut inner = minimal_procedure(&key, ProcedureId::new(1), "inner", 3);
        outer.lexical_parent = Some(ProcedureId::new(1));
        inner.lexical_parent = Some(ProcedureId::new(0));

        let error = SemanticArtifact::try_new(key, capabilities(&[]), vec![outer, inner])
            .expect_err("lexical cycle must fail");
        assert_eq!(error.kind(), SemanticIrErrorKind::ParentCycle);
    }

    #[test]
    fn rejects_non_analyzable_artifact_language() {
        let key = key_with_language(SemanticLanguage::Standard(Language::None));
        let error = SemanticArtifact::try_new(key, SemanticCapabilities::default(), Vec::new())
            .expect_err("Language::None is not a semantic adapter language");
        assert_eq!(error.kind(), SemanticIrErrorKind::ArtifactIdentity);
    }

    #[test]
    fn rejects_exact_ir_for_unsupported_capabilities() {
        let key = key();
        let parts = minimal_procedure(&key, ProcedureId::new(0), "main", 1);
        let error = SemanticArtifact::try_new(key, SemanticCapabilities::default(), vec![parts])
            .expect_err("exact procedure rows contradict unsupported capabilities");
        assert_eq!(error.kind(), SemanticIrErrorKind::CapabilityContract);
    }

    #[test]
    fn rejects_source_mapping_outside_artifact_scope() {
        let key = key();
        let mut parts = minimal_procedure(&key, ProcedureId::new(0), "main", 1);
        let local = &parts.source_mappings[0].locator;
        parts.source_mappings[0].locator = SemanticLocator::new(
            WorkspaceMountId::hash_bytes(b"different mount"),
            local.path().clone(),
            local.language(),
            local.declaration().clone(),
            local.role(),
            local.anchor(),
        );

        let error = SemanticArtifact::try_new(key, capabilities(&[]), vec![parts])
            .expect_err("source mappings cannot cross mounted artifact scope");
        assert_eq!(error.kind(), SemanticIrErrorKind::SourceScope);
    }

    #[test]
    fn rejects_creator_local_capture_destination() {
        let key = key();
        let mut outer = minimal_procedure(&key, ProcedureId::new(0), "outer", 1);
        let mut child = minimal_procedure(&key, ProcedureId::new(1), "child", 3);
        child.lexical_parent = Some(ProcedureId::new(0));
        outer.values.extend([
            SemanticValue {
                id: ValueId::new(0),
                kind: SemanticValueKind::Callable,
                source: SourceMappingId::new(0),
                evidence: EvidenceId::new(0),
            },
            SemanticValue {
                id: ValueId::new(1),
                kind: SemanticValueKind::Local,
                source: SourceMappingId::new(0),
                evidence: EvidenceId::new(0),
            },
        ]);
        outer.allocations.push(AllocationSite {
            id: AllocationId::new(0),
            point: ProgramPointId::new(0),
            result: ValueId::new(0),
            kind: AllocationKind::ClosureEnvironment,
            source: SourceMappingId::new(0),
            evidence: EvidenceId::new(0),
        });
        // This location exists only in the creator.  Destination IDs are
        // scoped by `target`, so using raw id 0 cannot make it a child slot.
        outer.memory_locations.push(MemoryLocation {
            id: MemoryLocationId::new(0),
            kind: MemoryLocationKind::LexicalCell {
                binding: ValueId::new(1),
            },
            source: SourceMappingId::new(0),
            evidence: EvidenceId::new(0),
        });
        outer.captures.push(CaptureBinding {
            id: CaptureId::new(0),
            point: ProgramPointId::new(0),
            callable: ValueId::new(0),
            target: ProcedureId::new(1),
            environment: AllocationId::new(0),
            captured: CaptureSource::Value(ValueId::new(1)),
            destination: MemoryLocationId::new(0),
            mode: CaptureMode::Value,
            source: SourceMappingId::new(0),
            evidence: EvidenceId::new(0),
        });

        let error = SemanticArtifact::try_new(
            key,
            capabilities(&[
                SemanticCapability::Values,
                SemanticCapability::Allocations,
                SemanticCapability::LocalFlow,
                SemanticCapability::Captures,
            ]),
            vec![outer, child],
        )
        .expect_err("capture destination must exist in the target child");
        assert_eq!(error.kind(), SemanticIrErrorKind::CaptureContract);
        assert!(error.detail().contains("target procedure"));
    }

    #[test]
    fn capture_slot_requires_a_subject_specific_binding_gap() {
        let key = key();
        let outer = minimal_procedure(&key, ProcedureId::new(0), "outer", 1);
        let mut child = minimal_procedure(&key, ProcedureId::new(1), "child", 3);
        child.lexical_parent = Some(ProcedureId::new(0));
        child.memory_locations.push(MemoryLocation {
            id: MemoryLocationId::new(0),
            kind: MemoryLocationKind::Capture {
                lexical_parent: ProcedureId::new(0),
            },
            source: SourceMappingId::new(0),
            evidence: EvidenceId::new(0),
        });
        child.gaps.push(SemanticGap {
            id: SemanticGapId::new(0),
            point: ProgramPointId::new(0),
            subject: SemanticGapSubject::Point,
            capability: SemanticCapability::Captures,
            kind: SemanticGapKind::Unknown,
            budget: None,
            detail: "unrelated capture uncertainty".into(),
            source: SourceMappingId::new(0),
            evidence: EvidenceId::new(0),
        });
        let mut events = child.points[0].events.to_vec();
        events.push(SemanticEvent::new(
            SemanticEffect::Gap {
                gap: SemanticGapId::new(0),
            },
            SourceMappingId::new(0),
            EvidenceId::new(0),
        ));
        child.points[0].events = events.into_boxed_slice();

        let error = SemanticArtifact::try_new(
            key.clone(),
            capabilities(&[SemanticCapability::Captures]),
            vec![outer.clone(), child.clone()],
        )
        .expect_err("a broad point gap cannot legitimize an unbound capture slot");
        assert_eq!(error.kind(), SemanticIrErrorKind::CaptureContract);

        child.gaps[0].subject = SemanticGapSubject::MemoryLocation(MemoryLocationId::new(0));
        SemanticArtifact::try_new(
            key,
            capabilities(&[SemanticCapability::Captures]),
            vec![outer, child],
        )
        .expect("a slot-specific gap explicitly preserves the missing binding");
    }

    #[test]
    fn receiver_capture_requires_a_receiver_value() {
        let key = key();
        let mut outer = minimal_procedure(&key, ProcedureId::new(0), "outer", 1);
        let mut child = minimal_procedure(&key, ProcedureId::new(1), "child", 3);
        child.lexical_parent = Some(ProcedureId::new(0));
        child.memory_locations.push(MemoryLocation {
            id: MemoryLocationId::new(0),
            kind: MemoryLocationKind::Capture {
                lexical_parent: ProcedureId::new(0),
            },
            source: SourceMappingId::new(0),
            evidence: EvidenceId::new(0),
        });
        outer.values.extend([
            SemanticValue {
                id: ValueId::new(0),
                kind: SemanticValueKind::Callable,
                source: SourceMappingId::new(0),
                evidence: EvidenceId::new(0),
            },
            SemanticValue {
                id: ValueId::new(1),
                kind: SemanticValueKind::Local,
                source: SourceMappingId::new(0),
                evidence: EvidenceId::new(0),
            },
        ]);
        outer.allocations.push(AllocationSite {
            id: AllocationId::new(0),
            point: ProgramPointId::new(0),
            result: ValueId::new(0),
            kind: AllocationKind::ClosureEnvironment,
            source: SourceMappingId::new(0),
            evidence: EvidenceId::new(0),
        });
        outer.captures.push(CaptureBinding {
            id: CaptureId::new(0),
            point: ProgramPointId::new(0),
            callable: ValueId::new(0),
            target: ProcedureId::new(1),
            environment: AllocationId::new(0),
            captured: CaptureSource::Value(ValueId::new(1)),
            destination: MemoryLocationId::new(0),
            mode: CaptureMode::Receiver,
            source: SourceMappingId::new(0),
            evidence: EvidenceId::new(0),
        });

        let error = SemanticArtifact::try_new(
            key.clone(),
            capabilities(&[
                SemanticCapability::Values,
                SemanticCapability::Allocations,
                SemanticCapability::Captures,
            ]),
            vec![outer.clone(), child.clone()],
        )
        .expect_err("receiver capture cannot relabel a local value");
        assert_eq!(error.kind(), SemanticIrErrorKind::CaptureContract);

        outer.captures[0].mode = CaptureMode::Unknown;
        let error = SemanticArtifact::try_new(
            key,
            capabilities(&[
                SemanticCapability::Values,
                SemanticCapability::Allocations,
                SemanticCapability::Captures,
            ]),
            vec![outer, child],
        )
        .expect_err("unknown capture mode requires a subject-specific gap");
        assert_eq!(error.kind(), SemanticIrErrorKind::GapContract);
    }

    #[test]
    fn known_capture_mode_rejects_a_contradictory_unknown_gap() {
        let key = key();
        let source = SourceMappingId::new(0);
        let evidence = EvidenceId::new(0);
        let mut outer = minimal_procedure(&key, ProcedureId::new(0), "outer", 1);
        let mut child = minimal_procedure(&key, ProcedureId::new(1), "child", 3);
        child.lexical_parent = Some(ProcedureId::new(0));
        child.memory_locations.push(MemoryLocation {
            id: MemoryLocationId::new(0),
            kind: MemoryLocationKind::Capture {
                lexical_parent: ProcedureId::new(0),
            },
            source,
            evidence,
        });
        outer.values.extend([
            SemanticValue {
                id: ValueId::new(0),
                kind: SemanticValueKind::Callable,
                source,
                evidence,
            },
            SemanticValue {
                id: ValueId::new(1),
                kind: SemanticValueKind::Local,
                source,
                evidence,
            },
        ]);
        outer.allocations.push(AllocationSite {
            id: AllocationId::new(0),
            point: ProgramPointId::new(0),
            result: ValueId::new(0),
            kind: AllocationKind::ClosureEnvironment,
            source,
            evidence,
        });
        outer.captures.push(CaptureBinding {
            id: CaptureId::new(0),
            point: ProgramPointId::new(0),
            callable: ValueId::new(0),
            target: ProcedureId::new(1),
            environment: AllocationId::new(0),
            captured: CaptureSource::Value(ValueId::new(1)),
            destination: MemoryLocationId::new(0),
            mode: CaptureMode::Value,
            source,
            evidence,
        });
        let mut events = outer.points[0].events.to_vec();
        events.extend([
            SemanticEvent::new(
                SemanticEffect::Allocation {
                    allocation: AllocationId::new(0),
                },
                source,
                evidence,
            ),
            SemanticEvent::new(
                SemanticEffect::CallableCreation {
                    result: ValueId::new(0),
                    callable: CallableValue {
                        kind: CallableReferenceKind::Lambda,
                        targets: CallableTargetResolution::Proven(CallableTarget::Local(
                            ProcedureId::new(1),
                        )),
                        target_evidence: evidence,
                        bound_receiver: None,
                        environment: Some(AllocationId::new(0)),
                    },
                },
                source,
                evidence,
            ),
            SemanticEvent::new(
                SemanticEffect::CaptureBind {
                    capture: CaptureId::new(0),
                },
                source,
                evidence,
            ),
        ]);
        outer.points[0].events = events.into_boxed_slice();
        let semantic_capabilities = capabilities(&[
            SemanticCapability::Values,
            SemanticCapability::Allocations,
            SemanticCapability::Captures,
            SemanticCapability::CallableReferences,
        ]);

        SemanticArtifact::try_new(
            key.clone(),
            semantic_capabilities.clone(),
            vec![outer.clone(), child.clone()],
        )
        .expect("the known value capture fixture is valid before adding a gap");

        outer.gaps.push(SemanticGap {
            id: SemanticGapId::new(0),
            point: ProgramPointId::new(0),
            subject: SemanticGapSubject::Capture(CaptureId::new(0)),
            capability: SemanticCapability::Captures,
            kind: SemanticGapKind::Unknown,
            budget: None,
            detail: "capture mode is allegedly unknown".into(),
            source,
            evidence,
        });
        let mut events = outer.points[0].events.to_vec();
        events.push(SemanticEvent::new(
            SemanticEffect::Gap {
                gap: SemanticGapId::new(0),
            },
            source,
            evidence,
        ));
        outer.points[0].events = events.into_boxed_slice();

        let error = SemanticArtifact::try_new(key, semantic_capabilities, vec![outer, child])
            .expect_err("a known capture mode cannot also carry an unknown gap");
        assert_eq!(error.kind(), SemanticIrErrorKind::GapContract);
    }

    #[test]
    fn rejects_same_artifact_external_callable_target() {
        let key = key();
        let external_in_name_only = procedure_locator(&key, "other", 3);
        let mut parts = minimal_procedure(&key, ProcedureId::new(0), "main", 1);
        parts.values.push(SemanticValue {
            id: ValueId::new(0),
            kind: SemanticValueKind::Callable,
            source: SourceMappingId::new(0),
            evidence: EvidenceId::new(0),
        });
        let mut events = parts.points[0].events.to_vec();
        events.push(SemanticEvent::new(
            SemanticEffect::CallableReference {
                result: ValueId::new(0),
                callable: CallableValue {
                    kind: CallableReferenceKind::Function,
                    targets: CallableTargetResolution::Proven(CallableTarget::External(
                        external_in_name_only,
                    )),
                    target_evidence: EvidenceId::new(0),
                    bound_receiver: None,
                    environment: None,
                },
            },
            SourceMappingId::new(0),
            EvidenceId::new(0),
        ));
        parts.points[0].events = events.into_boxed_slice();

        let error = SemanticArtifact::try_new(
            key,
            capabilities(&[
                SemanticCapability::Values,
                SemanticCapability::CallableReferences,
            ]),
            vec![parts],
        )
        .expect_err("same-artifact targets must use artifact-local ProcedureId");
        assert_eq!(error.kind(), SemanticIrErrorKind::CallableContract);
    }

    #[test]
    fn rejects_unsupported_gap_for_complete_capability() {
        let key = key();
        let mut parts = minimal_procedure(&key, ProcedureId::new(0), "main", 1);
        parts.gaps.push(SemanticGap {
            id: SemanticGapId::new(0),
            point: ProgramPointId::new(0),
            subject: SemanticGapSubject::Point,
            capability: SemanticCapability::Calls,
            kind: SemanticGapKind::Unsupported,
            budget: None,
            detail: "calls are unsupported here".into(),
            source: SourceMappingId::new(0),
            evidence: EvidenceId::new(0),
        });
        let mut events = parts.points[0].events.to_vec();
        events.push(SemanticEvent::new(
            SemanticEffect::Gap {
                gap: SemanticGapId::new(0),
            },
            SourceMappingId::new(0),
            EvidenceId::new(0),
        ));
        parts.points[0].events = events.into_boxed_slice();

        let error =
            SemanticArtifact::try_new(key, capabilities(&[SemanticCapability::Calls]), vec![parts])
                .expect_err("unsupported gap contradicts complete support");
        assert_eq!(error.kind(), SemanticIrErrorKind::CapabilityContract);
    }

    #[test]
    fn method_references_cannot_be_callable_creation_events() {
        let key = key();
        let mut parts = minimal_procedure(&key, ProcedureId::new(0), "main", 1);
        parts.values.push(SemanticValue {
            id: ValueId::new(0),
            kind: SemanticValueKind::Callable,
            source: SourceMappingId::new(0),
            evidence: EvidenceId::new(0),
        });
        let mut events = parts.points[0].events.to_vec();
        events.push(SemanticEvent::new(
            SemanticEffect::CallableCreation {
                result: ValueId::new(0),
                callable: CallableValue {
                    kind: CallableReferenceKind::StaticMethod,
                    targets: CallableTargetResolution::Proven(CallableTarget::Local(
                        ProcedureId::new(0),
                    )),
                    target_evidence: EvidenceId::new(0),
                    bound_receiver: None,
                    environment: None,
                },
            },
            SourceMappingId::new(0),
            EvidenceId::new(0),
        ));
        parts.points[0].events = events.into_boxed_slice();

        let error = SemanticArtifact::try_new(
            key,
            capabilities(&[
                SemanticCapability::Values,
                SemanticCapability::CallableReferences,
            ]),
            vec![parts],
        )
        .expect_err("method references are values, not body creation");
        assert_eq!(error.kind(), SemanticIrErrorKind::CallableContract);
    }

    #[test]
    fn out_of_bounds_callable_creation_target_returns_an_error() {
        let key = key();
        let mut parts = minimal_procedure(&key, ProcedureId::new(0), "main", 1);
        parts.values.push(SemanticValue {
            id: ValueId::new(0),
            kind: SemanticValueKind::Callable,
            source: SourceMappingId::new(0),
            evidence: EvidenceId::new(0),
        });
        let mut events = parts.points[0].events.to_vec();
        events.push(SemanticEvent::new(
            SemanticEffect::CallableCreation {
                result: ValueId::new(0),
                callable: CallableValue {
                    kind: CallableReferenceKind::Lambda,
                    targets: CallableTargetResolution::Proven(CallableTarget::Local(
                        ProcedureId::new(u32::MAX),
                    )),
                    target_evidence: EvidenceId::new(0),
                    bound_receiver: None,
                    environment: None,
                },
            },
            SourceMappingId::new(0),
            EvidenceId::new(0),
        ));
        parts.points[0].events = events.into_boxed_slice();

        let error = SemanticArtifact::try_new(
            key,
            capabilities(&[
                SemanticCapability::Values,
                SemanticCapability::CallableReferences,
            ]),
            vec![parts],
        )
        .expect_err("invalid local target must be rejected without indexing it");
        assert_eq!(error.kind(), SemanticIrErrorKind::OutOfBounds);
    }

    #[test]
    fn callable_creation_preserves_target_uncertainty_without_a_locator() {
        let key = key();
        let mut budget = SemanticBudget::uniform(1).unwrap();
        budget
            .charge(SemanticWork {
                procedures: 1,
                ..SemanticWork::default()
            })
            .unwrap();
        let exceeded = budget
            .charge(SemanticWork {
                procedures: 1,
                ..SemanticWork::default()
            })
            .unwrap_err();
        let cases = [
            (
                CallableTargetResolution::Unknown,
                SemanticGapKind::Unknown,
                None,
            ),
            (
                CallableTargetResolution::Unsupported,
                SemanticGapKind::Unsupported,
                None,
            ),
            (
                CallableTargetResolution::ExceededBudget(Box::new([])),
                SemanticGapKind::ExceededBudget,
                Some(exceeded),
            ),
        ];

        let mut capability_builder = SemanticCapabilities::builder();
        for capability in [
            SemanticCapability::Procedures,
            SemanticCapability::EntryBoundary,
            SemanticCapability::NormalExitBoundary,
            SemanticCapability::ExceptionalExitBoundary,
            SemanticCapability::BasicBlocks,
            SemanticCapability::ProgramPoints,
            SemanticCapability::NormalControlFlow,
            SemanticCapability::ExceptionalControlFlow,
            SemanticCapability::Values,
        ] {
            capability_builder = capability_builder.complete(capability);
        }
        let semantic_capabilities = capability_builder
            .partial(SemanticCapability::CallableReferences)
            .build();

        for (targets, gap_kind, budget) in cases {
            let mut parts = minimal_procedure(&key, ProcedureId::new(0), "main", 1);
            let source = SourceMappingId::new(0);
            let evidence = EvidenceId::new(0);
            parts.values.push(SemanticValue {
                id: ValueId::new(0),
                kind: SemanticValueKind::Callable,
                source,
                evidence,
            });
            parts.gaps.push(SemanticGap {
                id: SemanticGapId::new(0),
                point: ProgramPointId::new(0),
                subject: SemanticGapSubject::Value(ValueId::new(0)),
                capability: SemanticCapability::CallableReferences,
                kind: gap_kind,
                budget,
                detail: "nested body target is unavailable".into(),
                source,
                evidence,
            });
            let mut events = parts.points[0].events.to_vec();
            events.extend([
                SemanticEvent::new(
                    SemanticEffect::CallableCreation {
                        result: ValueId::new(0),
                        callable: CallableValue {
                            kind: CallableReferenceKind::Lambda,
                            targets,
                            target_evidence: evidence,
                            bound_receiver: None,
                            environment: None,
                        },
                    },
                    source,
                    evidence,
                ),
                SemanticEvent::new(
                    SemanticEffect::Gap {
                        gap: SemanticGapId::new(0),
                    },
                    source,
                    evidence,
                ),
            ]);
            parts.points[0].events = events.into_boxed_slice();

            SemanticArtifact::try_new(key.clone(), semantic_capabilities.clone(), vec![parts])
                .expect("a known creation event may retain typed target uncertainty");
        }
    }

    #[test]
    fn budget_limited_same_artifact_target_remains_explicitly_unmaterialized() {
        let key = key();
        let omitted = procedure_locator(&key, "omitted", 7);
        let mut parts = minimal_procedure(&key, ProcedureId::new(0), "main", 1);
        parts.values.push(SemanticValue {
            id: ValueId::new(0),
            kind: SemanticValueKind::Callable,
            source: SourceMappingId::new(0),
            evidence: EvidenceId::new(0),
        });
        let mut budget = SemanticBudget::uniform(1).unwrap();
        budget
            .charge(SemanticWork {
                procedures: 1,
                ..SemanticWork::default()
            })
            .unwrap();
        let exceeded = budget
            .charge(SemanticWork {
                procedures: 1,
                ..SemanticWork::default()
            })
            .unwrap_err();
        parts.gaps.push(SemanticGap {
            id: SemanticGapId::new(0),
            point: ProgramPointId::new(0),
            subject: SemanticGapSubject::Value(ValueId::new(0)),
            capability: SemanticCapability::CallableReferences,
            kind: SemanticGapKind::ExceededBudget,
            budget: Some(exceeded),
            detail: "nested body was recognized but not materialized".into(),
            source: SourceMappingId::new(0),
            evidence: EvidenceId::new(0),
        });
        let targets =
            CallableTargetResolution::ExceededBudget(Box::new([CallableTarget::Unmaterialized(
                omitted,
            )]));
        let mut events = parts.points[0].events.to_vec();
        events.extend([
            SemanticEvent::new(
                SemanticEffect::CallableReference {
                    result: ValueId::new(0),
                    callable: CallableValue {
                        kind: CallableReferenceKind::Function,
                        targets,
                        target_evidence: EvidenceId::new(0),
                        bound_receiver: None,
                        environment: None,
                    },
                },
                SourceMappingId::new(0),
                EvidenceId::new(0),
            ),
            SemanticEvent::new(
                SemanticEffect::Gap {
                    gap: SemanticGapId::new(0),
                },
                SourceMappingId::new(0),
                EvidenceId::new(0),
            ),
        ]);
        parts.points[0].events = events.into_boxed_slice();

        SemanticArtifact::try_new(
            key,
            capabilities(&[
                SemanticCapability::Values,
                SemanticCapability::CallableReferences,
            ]),
            vec![parts],
        )
        .expect("same-artifact locator is legal only as an incomplete target");
    }

    #[test]
    fn unmaterialized_creation_requires_an_unpublished_direct_lexical_child() {
        let key = key();
        let mut outer = minimal_procedure(&key, ProcedureId::new(0), "outer", 1);
        outer.values.push(SemanticValue {
            id: ValueId::new(0),
            kind: SemanticValueKind::Callable,
            source: SourceMappingId::new(0),
            evidence: EvidenceId::new(0),
        });
        let mut budget = SemanticBudget::uniform(1).unwrap();
        budget
            .charge(SemanticWork {
                procedures: 1,
                ..SemanticWork::default()
            })
            .unwrap();
        let exceeded = budget
            .charge(SemanticWork {
                procedures: 1,
                ..SemanticWork::default()
            })
            .unwrap_err();
        outer.gaps.push(SemanticGap {
            id: SemanticGapId::new(0),
            point: ProgramPointId::new(0),
            subject: SemanticGapSubject::Value(ValueId::new(0)),
            capability: SemanticCapability::CallableReferences,
            kind: SemanticGapKind::ExceededBudget,
            budget: Some(exceeded),
            detail: "nested body was recognized but not materialized".into(),
            source: SourceMappingId::new(0),
            evidence: EvidenceId::new(0),
        });
        let top_level = procedure_locator(&key, "not_nested", 7);
        let mut events = outer.points[0].events.to_vec();
        events.extend([
            SemanticEvent::new(
                SemanticEffect::CallableCreation {
                    result: ValueId::new(0),
                    callable: CallableValue {
                        kind: CallableReferenceKind::Lambda,
                        targets: CallableTargetResolution::ExceededBudget(Box::new([
                            CallableTarget::Unmaterialized(top_level),
                        ])),
                        target_evidence: EvidenceId::new(0),
                        bound_receiver: None,
                        environment: None,
                    },
                },
                SourceMappingId::new(0),
                EvidenceId::new(0),
            ),
            SemanticEvent::new(
                SemanticEffect::Gap {
                    gap: SemanticGapId::new(0),
                },
                SourceMappingId::new(0),
                EvidenceId::new(0),
            ),
        ]);
        outer.points[0].events = events.into_boxed_slice();
        let semantic_capabilities = capabilities(&[
            SemanticCapability::Values,
            SemanticCapability::CallableReferences,
        ]);

        let error = SemanticArtifact::try_new(
            key.clone(),
            semantic_capabilities.clone(),
            vec![outer.clone()],
        )
        .expect_err("callable creation cannot name a top-level unmaterialized procedure");
        assert_eq!(error.kind(), SemanticIrErrorKind::CallableContract);

        let direct_child = direct_child_locator(
            &key,
            &outer.locator,
            DeclarationSegmentKind::Lambda,
            "lambda",
            9,
        );
        let SemanticEffect::CallableCreation { callable, .. } =
            &mut outer.points[0].events[1].effect
        else {
            panic!("fixture callable creation event moved");
        };
        callable.targets =
            CallableTargetResolution::ExceededBudget(Box::new([CallableTarget::Unmaterialized(
                direct_child.clone(),
            )]));

        SemanticArtifact::try_new(
            key.clone(),
            semantic_capabilities.clone(),
            vec![outer.clone()],
        )
        .expect("an omitted direct lexical child remains a valid incomplete creation target");

        let mut child = minimal_procedure(&key, ProcedureId::new(1), "placeholder", 11);
        child.locator = direct_child.clone();
        child.source_mappings[0].locator = direct_child;
        child.lexical_parent = Some(ProcedureId::new(0));
        let error = SemanticArtifact::try_new(key, semantic_capabilities, vec![outer, child])
            .expect_err("a published procedure must be named by its local ProcedureId");
        assert_eq!(error.kind(), SemanticIrErrorKind::CallableContract);
    }

    #[test]
    fn artifact_construction_charges_retained_work_atomically() {
        let key = key();
        let parts = minimal_procedure(&key, ProcedureId::new(0), "main", 1);
        let mut budget = SemanticBudget::uniform(1).unwrap();
        let before = budget.used();

        let error =
            SemanticArtifact::try_new_with_budget(key, capabilities(&[]), vec![parts], &mut budget)
                .expect_err("three points exceed a one-point artifact budget");

        let exceeded = error.budget_exceeded().unwrap();
        assert_eq!(
            exceeded.dimension(),
            super::super::provider::SemanticBudgetDimension::ProgramPoints
        );
        assert_eq!(budget.used(), before);
    }

    #[test]
    fn handles_from_different_materializations_do_not_compare_equal() {
        let key = key();
        let first = Arc::new(
            SemanticArtifact::try_new(
                key.clone(),
                capabilities(&[]),
                vec![minimal_procedure(&key, ProcedureId::new(0), "main", 1)],
            )
            .unwrap(),
        );
        let second = Arc::new(
            SemanticArtifact::try_new(
                key.clone(),
                capabilities(&[]),
                vec![minimal_procedure(&key, ProcedureId::new(0), "main", 1)],
            )
            .unwrap(),
        );
        let first = first.procedure_handle(ProcedureId::new(0)).unwrap();
        let second = second.procedure_handle(ProcedureId::new(0)).unwrap();

        assert_ne!(first, second);
        let mut handles = HashSet::default();
        handles.insert(first);
        handles.insert(second);
        assert_eq!(handles.len(), 2);
    }

    #[test]
    fn callable_environment_allocation_is_at_creation_point() {
        let key = key();
        let mut parts = minimal_procedure(&key, ProcedureId::new(0), "main", 1);
        let mut child = minimal_procedure(&key, ProcedureId::new(1), "lambda", 3);
        child.lexical_parent = Some(ProcedureId::new(0));
        parts.values.push(SemanticValue {
            id: ValueId::new(0),
            kind: SemanticValueKind::Callable,
            source: SourceMappingId::new(0),
            evidence: EvidenceId::new(0),
        });
        parts.allocations.push(AllocationSite {
            id: AllocationId::new(0),
            point: ProgramPointId::new(1),
            result: ValueId::new(0),
            kind: AllocationKind::ClosureEnvironment,
            source: SourceMappingId::new(0),
            evidence: EvidenceId::new(0),
        });
        let mut entry_events = parts.points[0].events.to_vec();
        entry_events.push(SemanticEvent::new(
            SemanticEffect::CallableCreation {
                result: ValueId::new(0),
                callable: CallableValue {
                    kind: CallableReferenceKind::Lambda,
                    targets: CallableTargetResolution::Proven(CallableTarget::Local(
                        ProcedureId::new(1),
                    )),
                    target_evidence: EvidenceId::new(0),
                    bound_receiver: None,
                    environment: Some(AllocationId::new(0)),
                },
            },
            SourceMappingId::new(0),
            EvidenceId::new(0),
        ));
        parts.points[0].events = entry_events.into_boxed_slice();
        let mut exit_events = parts.points[1].events.to_vec();
        exit_events.push(SemanticEvent::new(
            SemanticEffect::Allocation {
                allocation: AllocationId::new(0),
            },
            SourceMappingId::new(0),
            EvidenceId::new(0),
        ));
        parts.points[1].events = exit_events.into_boxed_slice();

        let error = SemanticArtifact::try_new(
            key,
            capabilities(&[
                SemanticCapability::Values,
                SemanticCapability::Allocations,
                SemanticCapability::CallableReferences,
            ]),
            vec![parts, child],
        )
        .expect_err("capture environment must be allocated at callable creation");
        assert_eq!(error.kind(), SemanticIrErrorKind::CallableContract);
    }

    #[test]
    fn call_site_callee_must_be_a_callable_value() {
        let key = key();
        let mut parts = minimal_procedure(&key, ProcedureId::new(0), "main", 1);
        parts.values.push(SemanticValue {
            id: ValueId::new(0),
            kind: SemanticValueKind::Temporary,
            source: SourceMappingId::new(0),
            evidence: EvidenceId::new(0),
        });
        parts.call_sites.push(SemanticCallSite {
            id: CallSiteId::new(0),
            point: ProgramPointId::new(0),
            callee: ValueId::new(0),
            receiver: None,
            arguments: Box::new([]),
            result: None,
            thrown: None,
            declared_targets: CallableTargetResolution::Proven(CallableTarget::Local(
                ProcedureId::new(0),
            )),
            target_evidence: EvidenceId::new(0),
            normal_continuation: ControlContinuation::Target(ProgramPointId::new(1)),
            exceptional_continuation: ControlContinuation::Target(ProgramPointId::new(2)),
            source: SourceMappingId::new(0),
            evidence: EvidenceId::new(0),
        });

        let error = SemanticArtifact::try_new(
            key,
            capabilities(&[
                SemanticCapability::Values,
                SemanticCapability::Calls,
                SemanticCapability::NormalCallContinuation,
                SemanticCapability::ExceptionalCallContinuation,
            ]),
            vec![parts],
        )
        .expect_err("call site must classify its callee as callable");
        assert_eq!(error.kind(), SemanticIrErrorKind::CallableContract);
    }

    #[test]
    fn valid_call_has_matched_normal_and_exceptional_continuations() {
        let key = key();
        let mut parts = minimal_procedure(&key, ProcedureId::new(0), "main", 1);
        let source = SourceMappingId::new(0);
        let evidence = EvidenceId::new(0);
        parts.values.push(SemanticValue {
            id: ValueId::new(0),
            kind: SemanticValueKind::Callable,
            source,
            evidence,
        });
        let target = CallableTargetResolution::Proven(CallableTarget::Local(ProcedureId::new(0)));
        parts.call_sites.push(SemanticCallSite {
            id: CallSiteId::new(0),
            point: ProgramPointId::new(0),
            callee: ValueId::new(0),
            receiver: None,
            arguments: Box::new([]),
            result: None,
            thrown: None,
            declared_targets: target.clone(),
            target_evidence: evidence,
            normal_continuation: ControlContinuation::Target(ProgramPointId::new(1)),
            exceptional_continuation: ControlContinuation::Target(ProgramPointId::new(2)),
            source,
            evidence,
        });
        let mut entry_events = parts.points[0].events.to_vec();
        entry_events.extend([
            SemanticEvent::new(
                SemanticEffect::CallableReference {
                    result: ValueId::new(0),
                    callable: CallableValue {
                        kind: CallableReferenceKind::Function,
                        targets: target,
                        target_evidence: evidence,
                        bound_receiver: None,
                        environment: None,
                    },
                },
                source,
                evidence,
            ),
            SemanticEvent::new(
                SemanticEffect::Invoke {
                    call_site: CallSiteId::new(0),
                },
                source,
                evidence,
            ),
        ]);
        parts.points[0].events = entry_events.into_boxed_slice();
        let mut normal_events = parts.points[1].events.to_vec();
        normal_events.push(SemanticEvent::new(
            SemanticEffect::CallContinuation {
                call_site: CallSiteId::new(0),
                kind: CallContinuationKind::Normal,
            },
            source,
            evidence,
        ));
        parts.points[1].events = normal_events.into_boxed_slice();
        let mut exceptional_events = parts.points[2].events.to_vec();
        exceptional_events.push(SemanticEvent::new(
            SemanticEffect::CallContinuation {
                call_site: CallSiteId::new(0),
                kind: CallContinuationKind::Exceptional,
            },
            source,
            evidence,
        ));
        parts.points[2].events = exceptional_events.into_boxed_slice();

        let semantic_capabilities = capabilities(&[
            SemanticCapability::Values,
            SemanticCapability::CallableReferences,
            SemanticCapability::Calls,
            SemanticCapability::NormalCallContinuation,
            SemanticCapability::ExceptionalCallContinuation,
        ]);
        let mut extra_edge = parts.clone();
        extra_edge.control_edges.push(ControlEdge {
            source_point: ProgramPointId::new(0),
            target_point: ProgramPointId::new(2),
            kind: ControlEdgeKind::Normal,
            source,
            evidence,
        });
        let error =
            SemanticArtifact::try_new(key.clone(), semantic_capabilities.clone(), vec![extra_edge])
                .expect_err("a target continuation must own exactly one matching edge");
        assert_eq!(error.kind(), SemanticIrErrorKind::ControlFlowContract);

        let mut unrelated_edge_kind = parts.clone();
        unrelated_edge_kind.control_edges.push(ControlEdge {
            source_point: ProgramPointId::new(0),
            target_point: ProgramPointId::new(1),
            kind: ControlEdgeKind::ConditionalTrue,
            source,
            evidence,
        });
        let error = SemanticArtifact::try_new(
            key.clone(),
            semantic_capabilities.clone(),
            vec![unrelated_edge_kind],
        )
        .expect_err("an invoke point cannot carry an unrelated outgoing edge kind");
        assert_eq!(error.kind(), SemanticIrErrorKind::ControlFlowContract);

        let mut contradictory_gap = parts.clone();
        contradictory_gap.gaps.push(SemanticGap {
            id: SemanticGapId::new(0),
            point: ProgramPointId::new(0),
            subject: SemanticGapSubject::CallContinuation {
                call_site: CallSiteId::new(0),
                kind: CallContinuationKind::Normal,
            },
            capability: SemanticCapability::NormalCallContinuation,
            kind: SemanticGapKind::Unknown,
            budget: None,
            detail: "normal continuation is allegedly unknown".into(),
            source,
            evidence,
        });
        let mut events = contradictory_gap.points[0].events.to_vec();
        events.push(SemanticEvent::new(
            SemanticEffect::Gap {
                gap: SemanticGapId::new(0),
            },
            source,
            evidence,
        ));
        contradictory_gap.points[0].events = events.into_boxed_slice();
        let error = SemanticArtifact::try_new(
            key.clone(),
            semantic_capabilities.clone(),
            vec![contradictory_gap],
        )
        .expect_err("an exact continuation cannot also carry an unknown gap");
        assert_eq!(error.kind(), SemanticIrErrorKind::GapContract);

        let mut contradictory_targets = parts.clone();
        contradictory_targets.gaps.push(SemanticGap {
            id: SemanticGapId::new(0),
            point: ProgramPointId::new(0),
            subject: SemanticGapSubject::CallSite(CallSiteId::new(0)),
            capability: SemanticCapability::Calls,
            kind: SemanticGapKind::Unknown,
            budget: None,
            detail: "declared targets are allegedly unknown".into(),
            source,
            evidence,
        });
        let mut events = contradictory_targets.points[0].events.to_vec();
        events.push(SemanticEvent::new(
            SemanticEffect::Gap {
                gap: SemanticGapId::new(0),
            },
            source,
            evidence,
        ));
        contradictory_targets.points[0].events = events.into_boxed_slice();
        let error = SemanticArtifact::try_new(
            key.clone(),
            semantic_capabilities.clone(),
            vec![contradictory_targets],
        )
        .expect_err("proven declared targets cannot also carry an unknown gap");
        assert_eq!(error.kind(), SemanticIrErrorKind::GapContract);

        let mut converged = parts.clone();
        converged.call_sites[0].exceptional_continuation =
            ControlContinuation::Target(ProgramPointId::new(1));
        let exceptional_event = converged.points[2]
            .events
            .iter()
            .find(|event| {
                matches!(
                    event.effect,
                    SemanticEffect::CallContinuation {
                        kind: CallContinuationKind::Exceptional,
                        ..
                    }
                )
            })
            .cloned()
            .expect("fixture has an exceptional continuation event");
        converged.points[2].events = converged.points[2]
            .events
            .iter()
            .filter(|event| {
                !matches!(
                    event.effect,
                    SemanticEffect::CallContinuation {
                        kind: CallContinuationKind::Exceptional,
                        ..
                    }
                )
            })
            .cloned()
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let mut joined_events = converged.points[1].events.to_vec();
        joined_events.push(exceptional_event);
        converged.points[1].events = joined_events.into_boxed_slice();
        converged
            .control_edges
            .iter_mut()
            .filter(|edge| {
                edge.source_point == ProgramPointId::new(0)
                    && edge.kind == ControlEdgeKind::Exceptional
            })
            .for_each(|edge| edge.target_point = ProgramPointId::new(1));
        SemanticArtifact::try_new(key.clone(), semantic_capabilities.clone(), vec![converged])
            .expect("normal and exceptional call arms may converge on one typed join point");

        let mut parallel_provenance = parts.clone();
        let second_source = SourceMappingId::new(1);
        let second_evidence = EvidenceId::new(1);
        parallel_provenance.source_mappings.push(SourceMapping {
            id: second_source,
            locator: parallel_provenance.locator.clone(),
            kind: SourceMappingKind::Exact,
        });
        parallel_provenance.evidence_rows.push(Evidence {
            id: second_evidence,
            proof: ProofStatus::Proven,
            completeness: EvidenceCompleteness::Complete,
            sources: Box::new([second_source]),
        });
        let mut parallel_normal_edge = parallel_provenance
            .control_edges
            .iter()
            .find(|edge| edge.kind == ControlEdgeKind::Normal)
            .cloned()
            .expect("fixture has a normal continuation edge");
        parallel_normal_edge.source = second_source;
        parallel_normal_edge.evidence = second_evidence;
        parallel_provenance.control_edges.push(parallel_normal_edge);
        SemanticArtifact::try_new(
            key.clone(),
            semantic_capabilities.clone(),
            vec![parallel_provenance],
        )
        .expect("parallel provenance must not multiply call-continuation topology");

        let artifact = SemanticArtifact::try_new(key, semantic_capabilities, vec![parts])
            .expect("matched call continuations are valid");

        assert_eq!(artifact.procedures()[0].call_sites().len(), 1);
    }

    #[test]
    fn unsupported_call_arm_requires_a_gap_and_no_fabricated_edge() {
        let key = key();
        let mut parts = minimal_procedure(&key, ProcedureId::new(0), "main", 1);
        let source = SourceMappingId::new(0);
        let evidence = EvidenceId::new(0);
        parts.values.push(SemanticValue {
            id: ValueId::new(0),
            kind: SemanticValueKind::Callable,
            source,
            evidence,
        });
        let target = CallableTargetResolution::Proven(CallableTarget::Local(ProcedureId::new(0)));
        parts.call_sites.push(SemanticCallSite {
            id: CallSiteId::new(0),
            point: ProgramPointId::new(0),
            callee: ValueId::new(0),
            receiver: None,
            arguments: Box::new([]),
            result: None,
            thrown: None,
            declared_targets: target.clone(),
            target_evidence: evidence,
            normal_continuation: ControlContinuation::Target(ProgramPointId::new(1)),
            exceptional_continuation: ControlContinuation::Unsupported,
            source,
            evidence,
        });
        parts.gaps.push(SemanticGap {
            id: SemanticGapId::new(0),
            point: ProgramPointId::new(0),
            subject: SemanticGapSubject::CallContinuation {
                call_site: CallSiteId::new(0),
                kind: CallContinuationKind::Exceptional,
            },
            capability: SemanticCapability::ExceptionalCallContinuation,
            kind: SemanticGapKind::Unsupported,
            budget: None,
            detail: "adapter does not model exceptional call continuation".into(),
            source,
            evidence,
        });
        let mut entry_events = parts.points[0].events.to_vec();
        entry_events.extend([
            SemanticEvent::new(
                SemanticEffect::CallableReference {
                    result: ValueId::new(0),
                    callable: CallableValue {
                        kind: CallableReferenceKind::Function,
                        targets: target,
                        target_evidence: evidence,
                        bound_receiver: None,
                        environment: None,
                    },
                },
                source,
                evidence,
            ),
            SemanticEvent::new(
                SemanticEffect::Invoke {
                    call_site: CallSiteId::new(0),
                },
                source,
                evidence,
            ),
            SemanticEvent::new(
                SemanticEffect::Gap {
                    gap: SemanticGapId::new(0),
                },
                source,
                evidence,
            ),
        ]);
        parts.points[0].events = entry_events.into_boxed_slice();
        let mut normal_events = parts.points[1].events.to_vec();
        normal_events.push(SemanticEvent::new(
            SemanticEffect::CallContinuation {
                call_site: CallSiteId::new(0),
                kind: CallContinuationKind::Normal,
            },
            source,
            evidence,
        ));
        parts.points[1].events = normal_events.into_boxed_slice();
        parts.control_edges.retain(|edge| {
            !(edge.source_point == ProgramPointId::new(0)
                && edge.target_point == ProgramPointId::new(2))
        });

        let semantic_capabilities = capabilities(&[
            SemanticCapability::Values,
            SemanticCapability::CallableReferences,
            SemanticCapability::Calls,
            SemanticCapability::NormalCallContinuation,
        ]);
        let mut fabricated_edge = parts.clone();
        fabricated_edge.control_edges.push(ControlEdge {
            source_point: ProgramPointId::new(0),
            target_point: ProgramPointId::new(2),
            kind: ControlEdgeKind::Exceptional,
            source,
            evidence,
        });
        let error = SemanticArtifact::try_new(
            key.clone(),
            semantic_capabilities.clone(),
            vec![fabricated_edge],
        )
        .expect_err("an unsupported continuation cannot retain a fabricated edge");
        assert_eq!(error.kind(), SemanticIrErrorKind::ControlFlowContract);

        let artifact = SemanticArtifact::try_new(key, semantic_capabilities, vec![parts])
            .expect("an unsupported arm is valid only as a scoped gap");

        assert!(
            artifact.procedures()[0]
                .control_edges()
                .iter()
                .all(|edge| edge.kind != ControlEdgeKind::Exceptional)
        );
    }

    #[test]
    fn valid_async_suspend_has_matched_resume_arms() {
        let key = key();
        let mut parts = minimal_procedure(&key, ProcedureId::new(0), "main", 1);
        parts.properties.is_async = true;
        let source = SourceMappingId::new(0);
        let evidence = EvidenceId::new(0);

        let mut entry_events = parts.points[0].events.to_vec();
        entry_events.push(SemanticEvent::new(
            SemanticEffect::AsyncSuspend {
                awaited: None,
                normal_resume: ControlContinuation::Target(ProgramPointId::new(1)),
                exceptional_resume: ControlContinuation::Target(ProgramPointId::new(2)),
            },
            source,
            evidence,
        ));
        parts.points[0].events = entry_events.into_boxed_slice();
        let mut normal_events = parts.points[1].events.to_vec();
        normal_events.push(SemanticEvent::new(
            SemanticEffect::AsyncResume {
                suspend: ProgramPointId::new(0),
                kind: AsyncResumeKind::Normal,
                result: None,
            },
            source,
            evidence,
        ));
        parts.points[1].events = normal_events.into_boxed_slice();
        let mut exceptional_events = parts.points[2].events.to_vec();
        exceptional_events.push(SemanticEvent::new(
            SemanticEffect::AsyncResume {
                suspend: ProgramPointId::new(0),
                kind: AsyncResumeKind::Exceptional,
                result: None,
            },
            source,
            evidence,
        ));
        parts.points[2].events = exceptional_events.into_boxed_slice();
        parts
            .control_edges
            .retain(|edge| edge.source_point != ProgramPointId::new(0));
        parts.control_edges.extend([
            ControlEdge {
                source_point: ProgramPointId::new(0),
                target_point: ProgramPointId::new(1),
                kind: ControlEdgeKind::AsyncNormal,
                source,
                evidence,
            },
            ControlEdge {
                source_point: ProgramPointId::new(0),
                target_point: ProgramPointId::new(2),
                kind: ControlEdgeKind::AsyncExceptional,
                source,
                evidence,
            },
        ]);

        let mut extra_edge = parts.clone();
        extra_edge.control_edges.push(ControlEdge {
            source_point: ProgramPointId::new(0),
            target_point: ProgramPointId::new(2),
            kind: ControlEdgeKind::AsyncNormal,
            source,
            evidence,
        });
        let error = SemanticArtifact::try_new(
            key.clone(),
            capabilities(&[SemanticCapability::AsyncSuspendResume]),
            vec![extra_edge],
        )
        .expect_err("an async target arm must own exactly one matching edge");
        assert_eq!(error.kind(), SemanticIrErrorKind::ControlFlowContract);

        let mut unrelated_edge_kind = parts.clone();
        unrelated_edge_kind.control_edges.push(ControlEdge {
            source_point: ProgramPointId::new(0),
            target_point: ProgramPointId::new(1),
            kind: ControlEdgeKind::Normal,
            source,
            evidence,
        });
        let error = SemanticArtifact::try_new(
            key.clone(),
            capabilities(&[SemanticCapability::AsyncSuspendResume]),
            vec![unrelated_edge_kind],
        )
        .expect_err("an async-suspend point cannot carry an unrelated outgoing edge kind");
        assert_eq!(error.kind(), SemanticIrErrorKind::ControlFlowContract);

        let mut converged = parts.clone();
        let SemanticEffect::AsyncSuspend {
            exceptional_resume, ..
        } = &mut converged.points[0].events[1].effect
        else {
            panic!("fixture async suspend event moved");
        };
        *exceptional_resume = ControlContinuation::Target(ProgramPointId::new(1));
        let exceptional_event = converged.points[2]
            .events
            .iter()
            .find(|event| {
                matches!(
                    event.effect,
                    SemanticEffect::AsyncResume {
                        kind: AsyncResumeKind::Exceptional,
                        ..
                    }
                )
            })
            .cloned()
            .expect("fixture has an exceptional resume event");
        converged.points[2].events = converged.points[2]
            .events
            .iter()
            .filter(|event| {
                !matches!(
                    event.effect,
                    SemanticEffect::AsyncResume {
                        kind: AsyncResumeKind::Exceptional,
                        ..
                    }
                )
            })
            .cloned()
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let mut joined_events = converged.points[1].events.to_vec();
        joined_events.push(exceptional_event);
        converged.points[1].events = joined_events.into_boxed_slice();
        converged
            .control_edges
            .iter_mut()
            .filter(|edge| {
                edge.source_point == ProgramPointId::new(0)
                    && edge.kind == ControlEdgeKind::AsyncExceptional
            })
            .for_each(|edge| edge.target_point = ProgramPointId::new(1));
        SemanticArtifact::try_new(
            key.clone(),
            capabilities(&[SemanticCapability::AsyncSuspendResume]),
            vec![converged],
        )
        .expect("normal and exceptional async arms may converge on one typed join point");

        SemanticArtifact::try_new(
            key,
            capabilities(&[SemanticCapability::AsyncSuspendResume]),
            vec![parts],
        )
        .expect("matched async resume arms are valid");
    }

    #[test]
    fn async_continuation_gap_requires_a_real_matching_suspend_arm() {
        let key = key();
        let mut parts = minimal_procedure(&key, ProcedureId::new(0), "main", 1);
        let source = SourceMappingId::new(0);
        let evidence = EvidenceId::new(0);
        parts.gaps.push(SemanticGap {
            id: SemanticGapId::new(0),
            point: ProgramPointId::new(0),
            subject: SemanticGapSubject::AsyncContinuation {
                suspend: ProgramPointId::new(0),
                kind: AsyncResumeKind::Normal,
            },
            capability: SemanticCapability::AsyncSuspendResume,
            kind: SemanticGapKind::Unknown,
            budget: None,
            detail: "normal resume is allegedly unknown".into(),
            source,
            evidence,
        });
        let mut events = parts.points[0].events.to_vec();
        events.push(SemanticEvent::new(
            SemanticEffect::Gap {
                gap: SemanticGapId::new(0),
            },
            source,
            evidence,
        ));
        parts.points[0].events = events.into_boxed_slice();

        let error = SemanticArtifact::try_new(
            key,
            capabilities(&[SemanticCapability::AsyncSuspendResume]),
            vec![parts],
        )
        .expect_err("an async-continuation gap must name an actual suspend event");
        assert_eq!(error.kind(), SemanticIrErrorKind::GapContract);
    }

    #[test]
    fn multiple_control_splits_at_one_point_are_rejected() {
        let key = key();
        let mut parts = minimal_procedure(&key, ProcedureId::new(0), "main", 1);
        let mut events = parts.points[0].events.to_vec();
        events.extend([
            SemanticEvent::new(
                SemanticEffect::ProcedureReturn { value: None },
                SourceMappingId::new(0),
                EvidenceId::new(0),
            ),
            SemanticEvent::new(
                SemanticEffect::Throw { value: None },
                SourceMappingId::new(0),
                EvidenceId::new(0),
            ),
        ]);
        parts.points[0].events = events.into_boxed_slice();

        let error = SemanticArtifact::try_new(
            key,
            capabilities(&[SemanticCapability::ReturnFlow]),
            vec![parts],
        )
        .expect_err("one point cannot contain two control splits");
        assert_eq!(error.kind(), SemanticIrErrorKind::ControlFlowContract);
    }

    #[test]
    fn async_events_require_async_procedure_property() {
        let key = key();
        let mut parts = minimal_procedure(&key, ProcedureId::new(0), "main", 1);
        let source = SourceMappingId::new(0);
        let evidence = EvidenceId::new(0);

        let mut entry_events = parts.points[0].events.to_vec();
        entry_events.push(SemanticEvent::new(
            SemanticEffect::AsyncSuspend {
                awaited: None,
                normal_resume: ControlContinuation::Target(ProgramPointId::new(1)),
                exceptional_resume: ControlContinuation::Target(ProgramPointId::new(2)),
            },
            source,
            evidence,
        ));
        parts.points[0].events = entry_events.into_boxed_slice();

        let mut normal_events = parts.points[1].events.to_vec();
        normal_events.push(SemanticEvent::new(
            SemanticEffect::AsyncResume {
                suspend: ProgramPointId::new(0),
                kind: AsyncResumeKind::Normal,
                result: None,
            },
            source,
            evidence,
        ));
        parts.points[1].events = normal_events.into_boxed_slice();

        let mut exceptional_events = parts.points[2].events.to_vec();
        exceptional_events.push(SemanticEvent::new(
            SemanticEffect::AsyncResume {
                suspend: ProgramPointId::new(0),
                kind: AsyncResumeKind::Exceptional,
                result: None,
            },
            source,
            evidence,
        ));
        parts.points[2].events = exceptional_events.into_boxed_slice();
        parts
            .control_edges
            .retain(|edge| edge.source_point != ProgramPointId::new(0));
        parts.control_edges.extend([
            ControlEdge {
                source_point: ProgramPointId::new(0),
                target_point: ProgramPointId::new(1),
                kind: ControlEdgeKind::AsyncNormal,
                source,
                evidence,
            },
            ControlEdge {
                source_point: ProgramPointId::new(0),
                target_point: ProgramPointId::new(2),
                kind: ControlEdgeKind::AsyncExceptional,
                source,
                evidence,
            },
        ]);

        let error = SemanticArtifact::try_new(
            key,
            capabilities(&[SemanticCapability::AsyncSuspendResume]),
            vec![parts],
        )
        .expect_err("async events in a non-async procedure must fail");
        assert_eq!(error.kind(), SemanticIrErrorKind::AsyncContract);
    }
}
