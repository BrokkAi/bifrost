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

use validate::{find_boundaries, measure_artifact_work, validate_artifact};

mod validate;

#[cfg(test)]
mod tests;

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
}

impl ProcedureInvocationKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Immediate => "immediate",
            Self::Deferred => "deferred",
        }
    }
}

/// Orthogonal properties that should not be encoded in [`ProcedureKind`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DispatchExtensibility {
    /// Additional runtime targets may exist unless a dispatch oracle proves
    /// closure through stronger language-specific evidence.
    #[default]
    Open,
    /// The declaration itself proves that invocation cannot select an
    /// overriding implementation.
    Closed,
}

impl DispatchExtensibility {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Closed => "closed",
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
}

/// The positional or keyword domain accepted or produced at a call boundary.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub enum FormalMultiplicity {
    #[default]
    One,
    Rest(ArgumentDomain),
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

/// The semantic role of a value row.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SemanticValueKind {
    Local,
    Parameter {
        ordinal: u32,
        multiplicity: FormalMultiplicity,
    },
    Receiver,
    Return,
    Temporary,
    Constant,
    Exception,
    Callable,
    AwaitResult,
    LanguageDefined(Box<str>),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SemanticCallArgument {
    pub value: ValueId,
    pub expansion: CallArgumentExpansion,
}

impl SemanticCallArgument {
    /// Construct a direct argument when structured lowering established that
    /// the source is not a spread and identified its argument domain.
    pub fn direct(value: ValueId, domain: ArgumentDomain) -> Self {
        Self {
            value,
            expansion: CallArgumentExpansion::Direct(domain),
        }
    }

    /// Preserve the pre-v5 contract without manufacturing direct/spread or
    /// positional/keyword semantics. Adapters refine this row only from their
    /// structured syntax.
    pub fn unclassified(value: ValueId) -> Self {
        Self {
            value,
            expansion: CallArgumentExpansion::Unclassified,
        }
    }
}

impl From<ValueId> for SemanticCallArgument {
    fn from(value: ValueId) -> Self {
        Self::unclassified(value)
    }
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
    pub arguments: Box<[SemanticCallArgument]>,
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

    const VALUE: Self =
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
    const CONTROL_FLOW: Self = Self::DEFERRED_EFFECTS;
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
            | SemanticCapability::NonLocalControl => Self::CONTROL_FLOW,
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
            SemanticCapability::ConcurrentSpawn => Self::CALL_EVALUATION,
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
            SemanticGapSubject::Value(_) => Self::VALUE,
            SemanticGapSubject::MemoryLocation(_) | SemanticGapSubject::Capture(_) => Self::MEMORY,
            SemanticGapSubject::CallContinuation { .. }
            | SemanticGapSubject::AsyncContinuation { .. } => Self::CALL_EVALUATION,
            SemanticGapSubject::Procedure
            | SemanticGapSubject::Point
            | SemanticGapSubject::CallSite(_) => Self::NONE,
        };
        capability_impacts.union(subject_impacts)
    }

    /// Iterate in [`SemanticGapImpact::ALL`] order, which is part of the
    /// deterministic semantic rendering contract.
    pub fn iter(self) -> impl Iterator<Item = SemanticGapImpact> {
        SemanticGapImpact::ALL
            .into_iter()
            .filter(move |impact| self.contains(*impact))
    }
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
