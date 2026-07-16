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

use crate::hash::{HashMap, HashSet};

use super::capabilities::{CapabilitySupport, SemanticCapabilities, SemanticCapability};
use super::ids::{
    AllocationId, BlockId, CallSiteId, CaptureId, EvidenceId, MemoryLocationId, ProcedureId,
    ProgramPointId, SemanticArtifactKey, SemanticGapId, SemanticLocator, SemanticRole,
    SourceMappingId, ValueId,
};

/// A stable category for one validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SemanticIrErrorKind {
    ArtifactIdentity,
    CapabilityContract,
    DenseId,
    OutOfBounds,
    SourceScope,
    LocatorRole,
    DuplicateLocator,
    ParentCycle,
    BlockMembership,
    Boundary,
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
            Self::CapabilityContract => "capability_contract",
            Self::DenseId => "dense_id",
            Self::OutOfBounds => "out_of_bounds",
            Self::SourceScope => "source_scope",
            Self::LocatorRole => "locator_role",
            Self::DuplicateLocator => "duplicate_locator",
            Self::ParentCycle => "parent_cycle",
            Self::BlockMembership => "block_membership",
            Self::Boundary => "boundary",
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
    Synthetic,
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
            Self::Synthetic => "synthetic",
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CaptureMode {
    Value,
    Move,
    SharedCell,
    MutableCell,
    Receiver,
    LanguageDefined,
    Unknown,
}

impl CaptureMode {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Value => "value",
            Self::Move => "move",
            Self::SharedCell => "shared_cell",
            Self::MutableCell => "mutable_cell",
            Self::Receiver => "receiver",
            Self::LanguageDefined => "language_defined",
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
    External(SemanticLocator),
}

impl CallableTarget {
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Local(_) => "local",
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
    pub bound_receiver: Option<ValueId>,
    /// Present only when evaluating this callable allocates a capture
    /// environment.  Repeated evaluations can therefore share a body target
    /// while retaining distinct allocation sites.
    pub environment: Option<AllocationId>,
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
    pub targets: CallableTargetResolution,
    pub normal_continuation: ProgramPointId,
    pub exceptional_continuation: ProgramPointId,
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SemanticGap {
    pub id: SemanticGapId,
    pub point: ProgramPointId,
    pub capability: SemanticCapability,
    pub kind: SemanticGapKind,
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
        normal_resume: ProgramPointId,
        exceptional_resume: ProgramPointId,
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
    control_edges: Box<[ControlEdge]>,
    entry_point: ProgramPointId,
    normal_exit_point: ProgramPointId,
    exceptional_exit_point: ProgramPointId,
}

impl ProcedureSemantics {
    fn from_parts(
        parts: ProcedureSemanticsParts,
        entry_point: ProgramPointId,
        normal_exit_point: ProgramPointId,
        exceptional_exit_point: ProgramPointId,
    ) -> Self {
        Self {
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
            control_edges: parts.control_edges.into_boxed_slice(),
            entry_point,
            normal_exit_point,
            exceptional_exit_point,
        }
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

    pub fn control_edges(&self) -> &[ControlEdge] {
        &self.control_edges
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
        validate_artifact(&key, &capabilities, &procedure_parts)?;

        let mut procedures_by_locator = HashMap::default();
        let mut procedures = Vec::with_capacity(procedure_parts.len());
        for parts in procedure_parts {
            let boundaries = find_boundaries(&parts)?;
            procedures_by_locator.insert(parts.locator.clone(), parts.id);
            procedures.push(ProcedureSemantics::from_parts(
                parts,
                boundaries.entry,
                boundaries.normal_exit,
                boundaries.exceptional_exit,
            ));
        }

        Ok(Self {
            key,
            capabilities,
            procedures: procedures.into_boxed_slice(),
            procedures_by_locator,
        })
    }

    pub fn key(&self) -> &SemanticArtifactKey {
        &self.key
    }

    pub fn capabilities(&self) -> &SemanticCapabilities {
        &self.capabilities
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

/// An artifact-scoped procedure identity safe for provider/oracle boundaries.
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
        self.id == other.id && self.artifact.key == other.artifact.key
    }
}

impl Eq for ProcedureHandle {}

impl Hash for ProcedureHandle {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.artifact.key.hash(state);
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
    for procedure in procedures {
        validate_procedure(key, capabilities, procedures, procedure)?;
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
    procedure: &ProcedureSemanticsParts,
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
        validate_memory_location(procedures, procedure, location)?;
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
        validate_capture_row(procedures, procedure, capture)?;
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
        validate_call_site(procedures, procedure, call_site)?;
        validate_metadata(
            id,
            call_site.source,
            call_site.evidence,
            procedure,
            "call site",
        )?;
    }
    if !procedure.call_sites.is_empty() {
        for capability in [
            SemanticCapability::Calls,
            SemanticCapability::NormalCallContinuation,
            SemanticCapability::ExceptionalCallContinuation,
        ] {
            require_capability(id, capabilities, capability, "call-site rows")?;
        }
    }

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
    }

    validate_blocks(procedure)?;
    validate_events(capabilities, procedures, procedure)?;
    validate_control_edges(capabilities, procedure)?;
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
            let has_binding = procedures[lexical_parent.index()]
                .captures
                .iter()
                .any(|binding| binding.target == id && binding.destination == location.id);
            let has_gap = procedure
                .gaps
                .iter()
                .any(|gap| gap.capability == SemanticCapability::Captures);
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
        if let Some(previous) = slot_modes.insert(slot, capture.mode)
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
                capture.mode,
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
        }
        CaptureSource::Location(location) => {
            ensure_location(
                id,
                location,
                procedure.memory_locations.len(),
                "captured location",
            )?;
            if matches!(
                capture.mode,
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
    ensure_point(
        id,
        call_site.normal_continuation,
        procedure.points.len(),
        "normal call continuation",
    )?;
    ensure_point(
        id,
        call_site.exceptional_continuation,
        procedure.points.len(),
        "exceptional call continuation",
    )?;
    if call_site.point == call_site.normal_continuation
        || call_site.point == call_site.exceptional_continuation
        || call_site.normal_continuation == call_site.exceptional_continuation
    {
        return Err(SemanticIrError::procedure(
            id,
            SemanticIrErrorKind::CallContract,
            format!(
                "call site {} point and normal/exceptional continuations must be distinct",
                call_site.id
            ),
        ));
    }
    validate_target_resolution(id, procedures, &call_site.targets, "call site target")
}

fn validate_target_resolution(
    procedure: ProcedureId,
    procedures: &[ProcedureSemanticsParts],
    resolution: &CallableTargetResolution,
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
            CallableTarget::External(locator) => {
                if locator.role() != SemanticRole::Procedure {
                    return Err(SemanticIrError::procedure(
                        procedure,
                        SemanticIrErrorKind::LocatorRole,
                        format!(
                            "{context} external locator has role {}, expected procedure",
                            locator.role().stable_label()
                        ),
                    ));
                }
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
) -> Result<(), SemanticIrError> {
    let id = procedure.id;
    let mut edges = HashSet::default();
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
        if !edges.insert((edge.source_point, edge.target_point, edge.kind)) {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::DuplicateEdge,
                format!(
                    "duplicate {} edge {} -> {}",
                    edge.kind.label(),
                    edge.source_point,
                    edge.target_point
                ),
            ));
        }
    }
    Ok(())
}

fn validate_events(
    capabilities: &SemanticCapabilities,
    procedures: &[ProcedureSemanticsParts],
    procedure: &ProcedureSemanticsParts,
) -> Result<(), SemanticIrError> {
    let id = procedure.id;
    let mut allocation_events = vec![0_u32; procedure.allocations.len()];
    let mut capture_events = vec![0_u32; procedure.captures.len()];
    let mut invoke_events = vec![0_u32; procedure.call_sites.len()];
    let mut continuation_events = vec![[0_u32; 2]; procedure.call_sites.len()];
    let mut gap_events = vec![0_u32; procedure.gaps.len()];
    let mut callable_creations: HashMap<ValueId, Vec<(ProgramPointId, &CallableValue)>> =
        HashMap::default();
    let mut suspends: HashMap<ProgramPointId, (ProgramPointId, ProgramPointId)> =
        HashMap::default();
    let mut resumes: HashMap<(ProgramPointId, AsyncResumeKind), Vec<ProgramPointId>> =
        HashMap::default();

    for point in &procedure.points {
        for event in &point.events {
            validate_metadata(id, event.source, event.evidence, procedure, "event")?;
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
                        procedures, procedure, point.id, *result, callable, true,
                    )?;
                    callable_creations
                        .entry(*result)
                        .or_default()
                        .push((point.id, callable));
                }
                SemanticEffect::CallableReference { result, callable } => {
                    validate_callable_value(
                        procedures, procedure, point.id, *result, callable, false,
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
                    let (expected, slot) = match kind {
                        CallContinuationKind::Normal => (row.normal_continuation, 0),
                        CallContinuationKind::Exceptional => (row.exceptional_continuation, 1),
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
                    ensure_point(
                        id,
                        *normal_resume,
                        procedure.points.len(),
                        "normal async resume",
                    )?;
                    ensure_point(
                        id,
                        *exceptional_resume,
                        procedure.points.len(),
                        "exceptional async resume",
                    )?;
                    if point.id == *normal_resume
                        || point.id == *exceptional_resume
                        || normal_resume == exceptional_resume
                    {
                        return Err(SemanticIrError::procedure(
                            id,
                            SemanticIrErrorKind::AsyncContract,
                            format!(
                                "suspend point {} and its two resume points must be distinct",
                                point.id
                            ),
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
        if counts != [1, 1] {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::CallContract,
                format!(
                    "call site {index} must have exactly one normal and one exceptional continuation event; found {} and {}",
                    counts[0], counts[1]
                ),
            ));
        }
    }

    for call_site in &procedure.call_sites {
        require_control_edge(
            procedure,
            call_site.point,
            call_site.normal_continuation,
            ControlEdgeKind::Normal,
            "normal call continuation",
        )?;
        require_control_edge(
            procedure,
            call_site.point,
            call_site.exceptional_continuation,
            ControlEdgeKind::Exceptional,
            "exceptional call continuation",
        )?;
        require_resolution_gap(
            procedure,
            call_site.point,
            SemanticCapability::Calls,
            &call_site.targets,
        )?;
    }

    for capture in &procedure.captures {
        let matches_creation = callable_creations
            .get(&capture.callable)
            .is_some_and(|creations| {
                creations.iter().any(|(point, callable)| {
                    *point == capture.point
                        && callable.environment == Some(capture.environment)
                        && callable
                            .targets
                            .candidates()
                            .contains(&CallableTarget::Local(capture.target))
                })
            });
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

    validate_async_pairs(procedure, &suspends, &resumes)?;
    Ok(())
}

fn validate_callable_value(
    procedures: &[ProcedureSemanticsParts],
    procedure: &ProcedureSemanticsParts,
    point: ProgramPointId,
    result: ValueId,
    callable: &CallableValue,
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
    if creation {
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
    validate_target_resolution(id, procedures, &callable.targets, "callable target")?;
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
        point,
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
            SemanticIrErrorKind::OutOfBounds,
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

fn require_resolution_gap(
    procedure: &ProcedureSemanticsParts,
    point: ProgramPointId,
    capability: SemanticCapability,
    resolution: &CallableTargetResolution,
) -> Result<(), SemanticIrError> {
    let Some(kind) = required_gap_kind(resolution) else {
        return Ok(());
    };
    if procedure
        .gaps
        .iter()
        .any(|gap| gap.point == point && gap.capability == capability && gap.kind == kind)
    {
        return Ok(());
    }
    Err(SemanticIrError::procedure(
        procedure.id,
        SemanticIrErrorKind::GapContract,
        format!(
            "{} {} outcome at point {} has no matching semantic gap",
            capability.label(),
            resolution.label(),
            point
        ),
    ))
}

fn validate_async_pairs(
    procedure: &ProcedureSemanticsParts,
    suspends: &HashMap<ProgramPointId, (ProgramPointId, ProgramPointId)>,
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
        if normal_points != [*normal] || exceptional_points != [*exceptional] {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::AsyncContract,
                format!(
                    "suspend point {} does not have exactly its declared normal {} and exceptional {} resume events",
                    suspend, normal, exceptional
                ),
            ));
        }
        require_control_edge(
            procedure,
            *suspend,
            *normal,
            ControlEdgeKind::AsyncNormal,
            "normal async resume",
        )?;
        require_control_edge(
            procedure,
            *suspend,
            *exceptional,
            ControlEdgeKind::AsyncExceptional,
            "exceptional async resume",
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

fn require_control_edge(
    procedure: &ProcedureSemanticsParts,
    source: ProgramPointId,
    target: ProgramPointId,
    kind: ControlEdgeKind,
    context: &str,
) -> Result<(), SemanticIrError> {
    if procedure
        .control_edges
        .iter()
        .any(|edge| edge.source_point == source && edge.target_point == target && edge.kind == kind)
    {
        return Ok(());
    }
    Err(SemanticIrError::procedure(
        procedure.id,
        SemanticIrErrorKind::OutOfBounds,
        format!(
            "{context} requires {} edge {} -> {}",
            kind.label(),
            source,
            target
        ),
    ))
}

fn validate_exactly_once(
    procedure: ProcedureId,
    table: &str,
    counts: &[u32],
) -> Result<(), SemanticIrError> {
    for (index, count) in counts.iter().copied().enumerate() {
        if count != 1 {
            return Err(SemanticIrError::procedure(
                procedure,
                SemanticIrErrorKind::OutOfBounds,
                format!("{table} row {index} must have exactly one event; found {count}"),
            ));
        }
    }
    Ok(())
}

fn find_boundaries(procedure: &ProcedureSemanticsParts) -> Result<Boundaries, SemanticIrError> {
    let mut entries = Vec::new();
    let mut normal_exits = Vec::new();
    let mut exceptional_exits = Vec::new();
    for point in &procedure.points {
        for event in &point.events {
            match event.effect {
                SemanticEffect::Entry => entries.push(point.id),
                SemanticEffect::NormalExit => normal_exits.push(point.id),
                SemanticEffect::ExceptionalExit => exceptional_exits.push(point.id),
                _ => {}
            }
        }
    }
    if entries.len() != 1 || normal_exits.len() != 1 || exceptional_exits.len() != 1 {
        return Err(SemanticIrError::procedure(
            procedure.id,
            SemanticIrErrorKind::Boundary,
            format!(
                "expected exactly one entry, normal exit, and exceptional exit; found {}, {}, and {}",
                entries.len(),
                normal_exits.len(),
                exceptional_exits.len()
            ),
        ));
    }
    if entries[0] == normal_exits[0]
        || entries[0] == exceptional_exits[0]
        || normal_exits[0] == exceptional_exits[0]
    {
        return Err(SemanticIrError::procedure(
            procedure.id,
            SemanticIrErrorKind::Boundary,
            "entry, normal exit, and exceptional exit must be distinct program points",
        ));
    }
    Ok(Boundaries {
        entry: entries[0],
        normal_exit: normal_exits[0],
        exceptional_exit: exceptional_exits[0],
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
        assert!(handle.value_handle(ValueId::new(0)).is_none());
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
            capability: SemanticCapability::Calls,
            kind: SemanticGapKind::Unsupported,
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
            targets: CallableTargetResolution::Proven(CallableTarget::Local(ProcedureId::new(0))),
            normal_continuation: ProgramPointId::new(1),
            exceptional_continuation: ProgramPointId::new(2),
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
    fn async_events_require_async_procedure_property() {
        let key = key();
        let mut parts = minimal_procedure(&key, ProcedureId::new(0), "main", 1);
        let source = SourceMappingId::new(0);
        let evidence = EvidenceId::new(0);

        let mut entry_events = parts.points[0].events.to_vec();
        entry_events.push(SemanticEvent::new(
            SemanticEffect::AsyncSuspend {
                awaited: None,
                normal_resume: ProgramPointId::new(1),
                exceptional_resume: ProgramPointId::new(2),
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
