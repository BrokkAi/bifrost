use std::fmt;

use super::super::capabilities::SemanticCapability;
use super::super::ids::{
    AllocationId, BlockId, CallSiteId, CaptureId, EvidenceId, GuardId, MemoryLocationId,
    ProcedureId, ProgramPointId, SemanticGapId, SemanticLocator, SourceMappingId, StableDigest,
    StructuralNodeIdentity, SwitchFactId, ValueId,
};
use super::super::provider::SemanticBudgetExceeded;
pub use crate::analyzer::DispatchExtensibility;

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
    GuardContract,
    SwitchContract,
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
            Self::GuardContract => "guard_contract",
            Self::SwitchContract => "switch_contract",
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
    pub(super) fn artifact(kind: SemanticIrErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            procedure: None,
            detail: detail.into().into_boxed_str(),
        }
    }

    pub(super) fn procedure(
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
}

impl ProcedureKind {
    /// The value domain the `procedure.procedure_kind` row field publishes
    /// (issue #2515).
    pub const LABELS: &'static [&'static str] = &[
        "function",
        "method",
        "constructor",
        "initializer",
        "local_function",
        "lambda",
        "closure",
        "accessor",
        "operator",
    ];

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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum FormalParameterPassingMode {
    PositionalOnly,
    #[default]
    PositionalOrNamed,
    NamedOnly,
}

impl FormalParameterPassingMode {
    pub const fn accepts_positional(self) -> bool {
        matches!(self, Self::PositionalOnly | Self::PositionalOrNamed)
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
        name: Option<Box<str>>,
        passing_mode: FormalParameterPassingMode,
    },
    /// The procedure's receiver formal. `dispatch` states whether the value
    /// is the object the call dispatches on (`this`/`self`), as opposed to a
    /// passed-in receiver -- a Kotlin or Scala extension receiver -- that
    /// binds like a parameter and is never the caller's own `this`.
    Receiver {
        dispatch: bool,
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
    /// A compile-time constant whose payload is not represented structurally.
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
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Parameter { .. } => "parameter",
            Self::Receiver { .. } => "receiver",
            Self::Return => "return",
            Self::Temporary => "temporary",
            Self::Address => "address",
            Self::Null => "null",
            Self::Boolean(_) => "boolean",
            Self::UnsignedInteger(_) => "unsigned_integer",
            Self::Constant => "constant",
            Self::Exception => "exception",
            Self::Callable => "callable",
            Self::AwaitResult => "await_result",
            Self::LanguageDefined(_) => "language_defined",
        }
    }

    pub const fn is_constant(&self) -> bool {
        matches!(
            self,
            Self::Null | Self::Boolean(_) | Self::UnsignedInteger(_) | Self::Constant
        )
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
            Self::Static { .. } => "static",
            Self::Index { .. } => "index",
            Self::LexicalCell { .. } => "lexical_cell",
            Self::Capture { .. } => "capture",
        }
    }

    /// Whether this location's structured identity consumes `value` as its
    /// base, index, or lexical binding.
    pub fn uses_value(&self, value: ValueId) -> bool {
        match self {
            Self::Field { base, .. } => *base == value,
            Self::Index { base, index, .. } => *base == value || *index == Some(value),
            Self::LexicalCell { binding } => *binding == value,
            Self::Capture { binding, .. } => *binding == Some(value),
            Self::Static { .. } => false,
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

/// A caller-side receiver fact established at one call site.
///
/// This describes evaluation of the callable value, not whether a resolved
/// target declares a receiver-like formal. In particular, an unbound method or
/// constructor can require target-specific binding even though the caller did
/// not evaluate a bound receiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CallerReceiverBinding {
    Absent,
    Bound(ValueId),
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
    /// Whether this is an ordinary caller-local call operation or a detached
    /// spawn. Target-level async/generator behavior is refined separately.
    pub invocation_mode: CallInvocationMode,
    /// When this invocation executes relative to the source construct that
    /// registered or started it. The call row's source/evidence pair proves
    /// this fact; `Unknown` is never interpreted as synchronous execution.
    pub execution_timing: ExecutionTiming,
    pub callee: ValueId,
    pub receiver: Option<ValueId>,
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

/// Whether the evidence actually establishes the attached fact.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ProofStatus {
    Proven,
    Unproven(Box<str>),
}

impl ProofStatus {
    pub fn retained_heap_bytes(&self) -> usize {
        match self {
            Self::Proven => 0,
            Self::Unproven(reason) => reason.len(),
        }
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
        match self {
            Self::Complete => 0,
            Self::Partial(reason) => reason.len(),
        }
    }
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

    pub(super) const VALUE: Self =
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
    pub(super) const CONTROL_FLOW: Self = Self::DEFERRED_EFFECTS;
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

/// What answers a gap, stated by the adapter that published it.
///
/// `CallResolution` marks a call-site-scoped gap whose question a complete
/// workspace resolution and binding of that call answers -- for example
/// Scala argument-evaluation strictness, which the resolved signature proves
/// because a deferring callee carries its own procedure-level gap that keeps
/// every binding to it open. `RetainedEvaluationOrder` marks a point-scoped
/// gap where the adapter retained every evaluation but chose one deterministic
/// order for evaluations whose relative order the language leaves open. A
/// consumer may discharge that gap only when its answer depends on the set of
/// evaluations rather than their order. `RetainedControlTopology` marks a
/// point-scoped control gap where every source-local parent normal successor is
/// retained, but feasibility, blocking, termination, or concurrent child
/// execution remains unresolved. A consumer may discharge it only for a
/// positive proof that depends on the retained parent successor topology, not
/// on liveness, evaluation effects, or spawned work.
/// `CanonicalIndexIdentity` marks a memory-location-scoped index gap where the
/// producer retained one exact value and numeric magnitude for every
/// occurrence of the same literal index. Consumers such as value flow may
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
/// covers a point- or value-scoped exceptional transfer that can run active Go
/// cleanup code before the panicking function returns, including when that
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
    NonRejoiningExceptionalExit,
    ExitOnlyProcedureCompletion,
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
    pub detail: Box<str>,
    pub source: SourceMappingId,
    pub evidence: EvidenceId,
}

/// Whether a producer-authored gap certifies one exact index identity across
/// source occurrences.
///
/// The discharge marker is the producer's cross-occurrence guarantee. The
/// structural checks keep that guarantee scoped to an indexed memory location
/// whose retained index is a constant value and whose exact access remains at
/// the gap point. A dynamic, rebound, missing, or retargeted access therefore
/// cannot acquire the proof merely by carrying the marker.
pub(crate) fn gap_certifies_canonical_index_identity(
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
                index: Some(index),
                constant_index: Some(_),
                ..
            },
        ..
    }) = memory_locations.get(location.index())
    else {
        return false;
    };
    let constant_index_value = values
        .get(index.index())
        .is_some_and(|value| value.kind.is_constant());
    constant_index_value
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
    /// The source value is wrapped into a distinct container object.
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
    /// An operation runs but was not selected exactly. The event's evidence
    /// must not claim proven, complete knowledge.
    Unknown,
}

impl TransferOperation {
    pub const fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::CallSite(_) => "call_site",
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValueFlowKind {
    Local,
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
    Parameter,
    Receiver,
    Return,
    IndexedReturn {
        ordinal: u32,
    },
    LanguageDefined,
}

impl ValueFlowKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Transfer(_) => "transfer",
            Self::BackingStore { .. } => "backing_store",
            Self::Parameter => "parameter",
            Self::Receiver => "receiver",
            Self::Return => "return",
            Self::IndexedReturn { .. } => "indexed_return",
            Self::LanguageDefined => "language_defined",
        }
    }
}

/// A structured operation that consumes a value without claiming that the
/// consumed value flows into the operation's result.
///
/// This is deliberately separate from [`ValueFlowKind`]. For example, an
/// address value is required to dereference memory, but the address itself is
/// not the value loaded from that memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValueUseKind {
    Dereference,
}

impl ValueUseKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Dereference => "dereference",
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
pub(crate) fn assignment_transfer(
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
    /// The condition tests whether `value` is an instance of one or more
    /// classes denoted by `classes`.
    InstanceOf { value: ValueId, classes: ValueId },
    /// The condition tests whether `value` has the member named by `member`.
    HasMember { value: ValueId, member: ValueId },
    /// The decision is represented, but its condition was not normalizable.
    Opaque { digest: GuardConditionDigest },
}

impl GuardPredicate {
    /// The value domain the `guard.predicate` row field publishes
    /// (issue #2515), in variant order.
    pub const LABELS: &'static [&'static str] = &[
        "constant_boolean",
        "null_comparison",
        "constant_equality",
        "instance_of",
        "has_member",
        "opaque",
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::ConstantBoolean { .. } => "constant_boolean",
            Self::NullComparison { .. } => "null_comparison",
            Self::ConstantEquality { .. } => "constant_equality",
            Self::InstanceOf { .. } => "instance_of",
            Self::HasMember { .. } => "has_member",
            Self::Opaque { .. } => "opaque",
        }
    }

    /// The value the predicate proves the condition always takes, when it
    /// proves one at all.
    pub const fn constant_value(self) -> Option<bool> {
        match self {
            Self::ConstantBoolean { value } => Some(value),
            Self::NullComparison { .. }
            | Self::ConstantEquality { .. }
            | Self::InstanceOf { .. }
            | Self::HasMember { .. }
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

/// Mutable construction parts. Once accepted by
/// [`crate::analyzer::semantic::SemanticArtifact::try_new`],
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
    pub guard_facts: Vec<GuardFactParts>,
    pub switch_facts: Vec<SwitchFactParts>,
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
            guard_facts: Vec::new(),
            switch_facts: Vec::new(),
        }
    }
}
