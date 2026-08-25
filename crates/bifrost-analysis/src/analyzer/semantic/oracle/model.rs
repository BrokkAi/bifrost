use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use super::super::ids::{MemoryLocationId, SemanticLocator, SemanticRole, SourceMappingId};
use super::super::ir::{
    AllocationHandle, CallSiteHandle, EvidenceCompleteness, FormalMultiplicity,
    MemoryLocationHandle, MemoryLocationKind, ProcedureHandle, ProgramPointHandle, ProofStatus,
    SemanticArtifact, SemanticEffect, SemanticValueKind, ValueHandle,
};
use super::call::{CallBinding, CallBindings};
use super::error::{OracleContractError, require_same_procedure};
use super::limits::OracleLimits;
use super::relation::{OracleRelationHandle, validate_retained_relation_arenas};
use super::value_flow::{
    ValueFlowEndpoint, ValueFlowRelation, ValueFlowRelationKind, ValueFlowSnapshot,
};

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

    /// Extend this context with one call while retaining only the configured
    /// recent-call suffix. Prior truncation remains observable even when the
    /// already-retained suffix is shorter than the current limit.
    pub fn extended(&self, call: CallSiteHandle, limits: OracleLimits) -> Self {
        let mut calls = self.calls.to_vec();
        calls.push(call);
        let retained = limits.call_context_depth();
        let truncated = self.truncated || calls.len() > retained;
        if calls.len() > retained {
            calls.drain(..calls.len() - retained);
        }
        Self {
            calls: calls.into_boxed_slice(),
            truncated,
        }
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
                    .any(|value| matches!(value.kind, SemanticValueKind::Receiver { .. })) =>
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

/// Caller-local identity for the value produced by one resolved call arm.
///
/// Callee allocations and temporary values remain procedure-local. This
/// handle instead retains the validated dispatch, call-binding, and
/// normal-return-flow facts that justify projecting the result into the
/// caller. Relation handles are audit material rather than identity: repeated
/// materializations of the same call arm compare equal even though each query
/// owns fresh relation arenas.
#[derive(Debug, Clone)]
pub struct CallResultHandle {
    call: CallSiteHandle,
    result: ValueHandle,
    callee: ProcedureHandle,
    caller_context: OracleCallContext,
    callee_context: OracleCallContext,
    dispatch_provenance: Box<[OracleRelationHandle]>,
    binding_relation: OracleRelationHandle,
    return_relations: Box<[ValueFlowRelation]>,
}

impl CallResultHandle {
    pub(crate) fn new(
        bindings: &CallBindings,
        flow: &ValueFlowSnapshot,
        limits: OracleLimits,
    ) -> Result<Self, OracleContractError> {
        bindings.candidate().validate_for_call(bindings.call())?;
        let (binding_relation, formal, result) = bindings
            .bindings()
            .iter()
            .find_map(|binding| match binding {
                CallBinding::NormalReturn {
                    relation,
                    formal,
                    result,
                } => Some((relation.clone(), formal, result.clone())),
                CallBinding::Receiver { .. }
                | CallBinding::ArgumentGroup(_)
                | CallBinding::ImplicitArgument { .. }
                | CallBinding::ExceptionalReturn { .. } => None,
            })
            .ok_or(OracleContractError::InvalidAccessRoot(
                "call-result roots require a validated normal-return binding",
            ))?;

        let call = bindings.call().clone();
        let callee = bindings.callee().clone();
        let callee_context = bindings.context().extended(call.clone(), limits);
        if flow.procedure() != &callee || flow.context() != &callee_context {
            return Err(OracleContractError::InvalidAccessRoot(
                "call-result return flow must belong to the bound callee and context",
            ));
        }
        let return_relations = flow
            .relations()
            .iter()
            .filter(|relation| {
                relation.kind == ValueFlowRelationKind::NormalReturn
                    && matches!(&relation.source, ValueFlowEndpoint::Value(_))
                    && matches!(&relation.target, ValueFlowEndpoint::Port(port) if port == formal)
            })
            .cloned()
            .collect::<Vec<_>>();
        if return_relations.is_empty() {
            return Err(OracleContractError::InvalidAccessRoot(
                "call-result roots require a validated callee normal-return flow",
            ));
        }

        validate_retained_relation_arenas(
            bindings
                .candidate()
                .provenance()
                .iter()
                .chain(std::iter::once(&binding_relation))
                .chain(return_relations.iter().map(|relation| &relation.id)),
            limits,
        )?;
        Ok(Self {
            call,
            result,
            callee,
            caller_context: bindings.context().clone(),
            callee_context,
            dispatch_provenance: bindings.candidate().provenance().into(),
            binding_relation,
            return_relations: return_relations.into_boxed_slice(),
        })
    }

    pub fn call(&self) -> &CallSiteHandle {
        &self.call
    }

    pub fn result(&self) -> &ValueHandle {
        &self.result
    }

    pub fn callee(&self) -> &ProcedureHandle {
        &self.callee
    }

    pub fn caller_context(&self) -> &OracleCallContext {
        &self.caller_context
    }

    pub fn callee_context(&self) -> &OracleCallContext {
        &self.callee_context
    }

    pub fn dispatch_provenance(&self) -> &[OracleRelationHandle] {
        &self.dispatch_provenance
    }

    pub fn binding_relation(&self) -> &OracleRelationHandle {
        &self.binding_relation
    }

    pub fn return_relations(&self) -> &[ValueFlowRelation] {
        &self.return_relations
    }

    fn validate_shape(&self) -> Result<(), OracleContractError> {
        require_same_procedure(self.call.procedure(), self.result.procedure())?;
        let call = self
            .call
            .procedure()
            .semantics()
            .call_site(self.call.id())
            .expect("call-site handles are validated at construction");
        if call.result != Some(self.result.id()) {
            return Err(OracleContractError::InvalidAccessRoot(
                "call-result root does not name the call's normal result",
            ));
        }
        Ok(())
    }
}

impl PartialEq for CallResultHandle {
    fn eq(&self, other: &Self) -> bool {
        self.call == other.call
            && self.result == other.result
            && self.callee == other.callee
            && self.caller_context == other.caller_context
            && self.callee_context == other.callee_context
    }
}

impl Eq for CallResultHandle {}

impl Hash for CallResultHandle {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.call.hash(state);
        self.result.hash(state);
        self.callee.hash(state);
        self.caller_context.hash(state);
        self.callee_context.hash(state);
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
    CallResult(CallResultHandle),
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
            Self::CallResult(result) => Some(result.result().procedure()),
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
            Self::CallResult(result) => result.validate_shape()?,
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

    fn validate_at(&self, procedure: &ProcedureHandle) -> Result<(), OracleContractError> {
        match self {
            Self::Value(value) => require_same_procedure(value.procedure(), procedure),
            Self::CallResult(result) => {
                result.validate_shape()?;
                require_same_procedure(result.result().procedure(), procedure)
            }
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

    pub(super) fn validate_at(
        &self,
        procedure: &ProcedureHandle,
    ) -> Result<(), OracleContractError> {
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
            | AccessPathRoot::CallResult(_)
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

/// The identity component of one abstract object. Object identities and
/// access-path roots deliberately share one canonical symbolic domain so
/// conversion cannot drift as new root kinds are added.
pub type AbstractObjectIdentity = AccessPathRoot;

/// Why a durable identity could not be projected from a live handle.
///
/// Both variants mean the same thing operationally -- the artifact the handle
/// was minted against no longer holds the row the projection needs -- but they
/// are kept apart because the value-flow model already reports them apart and
/// re-expressing its key must not change what a caller observes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurableIdentityError {
    /// A handle names a value, allocation, call site, or memory location the
    /// live artifact no longer has.
    StaleRow,
    /// A retained row names a source mapping the live artifact no longer has.
    StaleSourceMapping,
}

impl fmt::Display for DurableIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StaleRow => formatter.write_str("oracle handle names a stale semantic row"),
            Self::StaleSourceMapping => {
                formatter.write_str("semantic row names a stale source mapping")
            }
        }
    }
}

impl std::error::Error for DurableIdentityError {}

/// Durable identity of one value slot.
///
/// A source locator alone does not separate two values a lowerer minted at one
/// anchor, so the role and the artifact's stable identity ordinal travel with
/// it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DurableValueIdentity {
    pub locator: SemanticLocator,
    pub role: Box<str>,
    pub ordinal: Option<u32>,
}

impl DurableValueIdentity {
    pub fn of(value: &ValueHandle) -> Result<Self, DurableIdentityError> {
        let procedure = value.procedure();
        let row = procedure
            .semantics()
            .value(value.id())
            .ok_or(DurableIdentityError::StaleRow)?;
        Ok(Self {
            locator: durable_source_locator(procedure, row.source)?,
            role: row.kind.label().into(),
            ordinal: procedure.semantics().stable_value_ordinal(value.id()),
        })
    }
}

/// Durable identity of one procedure-boundary slot.
///
/// A capture slot carries both spellings its consumers need: the artifact-dense
/// slot ordinal, which is deterministic for one artifact, and the captured
/// location's source locator, which survives a re-lowering.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DurablePortIdentity {
    Receiver,
    Parameter { ordinal: u32 },
    NormalReturn,
    ExceptionalReturn,
    Capture { slot: u32, locator: SemanticLocator },
}

impl DurablePortIdentity {
    pub fn of(port: &ProcedurePortHandle) -> Result<Self, DurableIdentityError> {
        Ok(match port.kind() {
            ProcedurePortKind::Receiver => Self::Receiver,
            ProcedurePortKind::Parameter { ordinal } => Self::Parameter { ordinal },
            ProcedurePortKind::NormalReturn => Self::NormalReturn,
            ProcedurePortKind::ExceptionalReturn => Self::ExceptionalReturn,
            ProcedurePortKind::Capture { slot } => {
                let row = port
                    .procedure()
                    .semantics()
                    .memory_location(slot)
                    .ok_or(DurableIdentityError::StaleRow)?;
                Self::Capture {
                    slot: slot.get(),
                    locator: durable_source_locator(port.procedure(), row.source)?,
                }
            }
        })
    }
}

/// Durable form of one bounded call context.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DurableCallContext {
    pub calls: Box<[SemanticLocator]>,
    pub truncated: bool,
}

impl DurableCallContext {
    pub fn of(context: &OracleCallContext) -> Result<Self, DurableIdentityError> {
        Ok(Self {
            calls: context
                .calls()
                .iter()
                .map(durable_call_locator)
                .collect::<Result<Vec<_>, _>>()?
                .into_boxed_slice(),
            truncated: context.was_truncated(),
        })
    }
}

/// Durable identity of one abstract object.
///
/// [`AbstractObjectIdentity`] is scoped to the exact materialization that
/// produced its handles: `ProcedureHandle` and `ScopedSemanticLocator` compare
/// their owning `Arc<SemanticArtifact>` by pointer, so two handles minted from
/// two materializations of the same immutable artifact are unequal even though
/// they name one object. The artifact cache is byte-bounded and does evict, so
/// a caller that holds facts discovered across several oracle calls can
/// legitimately hold both.
///
/// This is the identity that survives that. It names only source-derived
/// locators and artifact-deterministic ordinals, so it is comparable across
/// materializations and is what every durable projection of an abstract object
/// is derived from. It is deliberately one type: the value-flow carrier key and
/// the typestate subject key are lossy views of it, and a third consumer takes
/// a third view rather than writing a fourth traversal of `AccessPathRoot`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DurableObjectIdentity {
    Value(DurableValueIdentity),
    CallResult {
        call: SemanticLocator,
        result: DurableValueIdentity,
        callee: SemanticLocator,
        caller_context: DurableCallContext,
        callee_context: DurableCallContext,
    },
    ProcedurePort {
        procedure: SemanticLocator,
        port: DurablePortIdentity,
    },
    Allocation {
        locator: SemanticLocator,
    },
    Static {
        locator: SemanticLocator,
    },
    LexicalCell {
        locator: SemanticLocator,
    },
    CaptureSlot {
        procedure: SemanticLocator,
        port: DurablePortIdentity,
    },
    TypeSummary {
        locator: SemanticLocator,
    },
    ModuleObject {
        locator: SemanticLocator,
    },
    External {
        locator: SemanticLocator,
    },
}

impl AccessPathRoot {
    /// Project this materialization-scoped root onto its durable identity.
    pub fn durable_identity(&self) -> Result<DurableObjectIdentity, DurableIdentityError> {
        Ok(match self {
            Self::Value(value) => DurableObjectIdentity::Value(DurableValueIdentity::of(value)?),
            Self::CallResult(result) => DurableObjectIdentity::CallResult {
                call: durable_call_locator(result.call())?,
                result: DurableValueIdentity::of(result.result())?,
                callee: result.callee().semantics().locator().clone(),
                caller_context: DurableCallContext::of(result.caller_context())?,
                callee_context: DurableCallContext::of(result.callee_context())?,
            },
            Self::ProcedurePort(port) => DurableObjectIdentity::ProcedurePort {
                procedure: port.procedure().semantics().locator().clone(),
                port: DurablePortIdentity::of(port)?,
            },
            Self::CaptureSlot(port) => DurableObjectIdentity::CaptureSlot {
                procedure: port.procedure().semantics().locator().clone(),
                port: DurablePortIdentity::of(port)?,
            },
            Self::Allocation(allocation) => {
                let row = allocation
                    .procedure()
                    .semantics()
                    .allocation(allocation.id())
                    .ok_or(DurableIdentityError::StaleRow)?;
                DurableObjectIdentity::Allocation {
                    locator: durable_source_locator(allocation.procedure(), row.source)?,
                }
            }
            Self::LexicalCell(location) => {
                let row = location
                    .procedure()
                    .semantics()
                    .memory_location(location.id())
                    .ok_or(DurableIdentityError::StaleRow)?;
                DurableObjectIdentity::LexicalCell {
                    locator: durable_source_locator(location.procedure(), row.source)?,
                }
            }
            Self::Static(locator) => DurableObjectIdentity::Static {
                locator: locator.locator().clone(),
            },
            Self::TypeSummary(locator) => DurableObjectIdentity::TypeSummary {
                locator: locator.locator().clone(),
            },
            Self::ModuleObject(locator) => DurableObjectIdentity::ModuleObject {
                locator: locator.locator().clone(),
            },
            Self::External(locator) => DurableObjectIdentity::External {
                locator: locator.locator().clone(),
            },
        })
    }
}

fn durable_source_locator(
    procedure: &ProcedureHandle,
    source: SourceMappingId,
) -> Result<SemanticLocator, DurableIdentityError> {
    procedure
        .semantics()
        .source_mapping(source)
        .map(|mapping| mapping.locator.clone())
        .ok_or(DurableIdentityError::StaleSourceMapping)
}

fn durable_call_locator(call: &CallSiteHandle) -> Result<SemanticLocator, DurableIdentityError> {
    let row = call
        .procedure()
        .semantics()
        .call_site(call.id())
        .ok_or(DurableIdentityError::StaleRow)?;
    durable_source_locator(call.procedure(), row.source)
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

    pub(super) fn validate_at(
        &self,
        procedure: &ProcedureHandle,
    ) -> Result<(), OracleContractError> {
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
        if &object.identity != path.root() {
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
        AccessPathRoot::CallResult(result) => result.result() == value,
        AccessPathRoot::ProcedurePort(port) => {
            require_same_procedure(port.procedure(), value.procedure()).is_ok()
                && match port.kind() {
                    ProcedurePortKind::Receiver => value
                        .procedure()
                        .semantics()
                        .value(value.id())
                        .is_some_and(|row| matches!(row.kind, SemanticValueKind::Receiver { .. })),
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
/// A dispatch arm that cannot enter a materialized workspace procedure.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

impl DispatchBoundaryKind {
    /// The value domain the `dispatch_target.boundary_kind` row field
    /// publishes (issue #2515).
    pub const LABELS: &'static [&'static str] = &[
        "external",
        "unmaterialized",
        "deferred",
        "unresolved",
        "truncated",
    ];

    /// The stable public spelling of this boundary kind.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::External(_) => "external",
            Self::Unmaterialized(_) => "unmaterialized",
            Self::Deferred { .. } => "deferred",
            Self::Unresolved => "unresolved",
            Self::Truncated => "truncated",
        }
    }

    /// Exact structured target retained for a non-materialized dispatch arm.
    /// Unresolved and truncated residual arms do not name one target.
    pub fn target_locator(&self) -> Option<&SemanticLocator> {
        match self {
            Self::External(Some(target))
            | Self::Unmaterialized(target)
            | Self::Deferred { target, .. } => Some(target),
            Self::External(None) | Self::Unresolved | Self::Truncated => None,
        }
    }
}

/// When the target of a semantic relation is evaluated, relative to the
/// evaluation of its source (issue #2446).
///
/// This is the analyzer's execution-timing vocabulary. It exists because
/// "lexically inside" is not "executes now": a statement in a callback body
/// sits inside the enclosing function's source range and does not run during
/// that function's evaluation. Every timing claim must come from evidence
/// about how the runtime schedules the target -- a lowered control edge, a
/// modeled callable, or a declared framework contract. A component that only
/// knows one site encloses another knows nothing about timing and must say
/// [`ExecutionTiming::Unknown`].
///
/// The vocabulary is frozen here as a whole so that later slices which add
/// asynchronous edges extend the producers rather than the labels. Nothing in
/// this slice publishes an asynchronous label; the synchronous labels and
/// `Unknown` are the ones in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExecutionTiming {
    /// The source and the target are evaluated by one indivisible step of the
    /// procedure: they belong to the same program point's event sequence, so
    /// no other program point can be evaluated between them.
    SameEvaluation,
    /// The target is evaluated later in the same synchronous activation of the
    /// procedure that evaluated the source. Control may pass through other
    /// program points and other procedures in between, but it never leaves
    /// this activation record and never returns to a scheduler.
    SameInvocation,
    /// The target is evaluated after the source in the same cooperative turn
    /// (event-loop tick, coroutine step) but in a different activation, so
    /// nothing else that the same turn owns can interleave.
    LaterSameTurn,
    /// The target is evaluated after the procedure suspended and resumed:
    /// arbitrary other work of the same task may have run in between, and the
    /// resumption may occur on a different underlying thread.
    AfterSuspension,
    /// The target is evaluated by a different task of the same runtime. The
    /// two evaluations are unordered unless a separate synchronization
    /// relation orders them.
    DifferentTask,
    /// The target is evaluated by a different thread. The two evaluations are
    /// unordered and may overlap, so state read on one side needs its own
    /// memory-model argument.
    DifferentThread,
    /// The target is the body of a callable that was handed to another
    /// component, which decides whether and when to invoke it. The evaluation
    /// may never happen, may happen once, or may happen many times.
    DeferredCallback,
    /// The target is evaluated when a suspended generator or iterator is
    /// resumed by its consumer. Between the source and the target the consumer
    /// ran arbitrary code and may abandon the generator entirely.
    GeneratorResume,
    /// The target is evaluated while an activation is being unwound or
    /// cancelled: a finally body, a destructor, or a cancellation handler. It
    /// runs on abnormal completion paths that the normal successor edges do
    /// not describe.
    CancellationCleanup,
    /// The evidence does not establish when the target is evaluated. This is
    /// the answer whenever the only available fact is that one site encloses
    /// another.
    Unknown,
}

impl ExecutionTiming {
    /// The value domain every `timing` field fed by this vocabulary publishes
    /// (issue #2515).
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

    /// The stable public spelling of this timing.
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

    /// Whether this timing keeps the target inside the source's own
    /// synchronous activation, so a caller may treat the two evaluations as
    /// ordered without any scheduling model.
    ///
    /// `Unknown` is deliberately not synchronous: an unestablished timing is
    /// never permission to assume one.
    pub const fn is_synchronous(self) -> bool {
        matches!(self, Self::SameEvaluation | Self::SameInvocation)
    }
}

/// One timing answer plus the quality of the evidence behind it.
///
/// The carriers are the same two the rest of the oracle model uses, so a
/// consumer applies one rule everywhere: act on the timing only when the claim
/// is proven and complete, and treat anything weaker as a candidate that needs
/// its own justification.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExecutionTimingClaim {
    timing: ExecutionTiming,
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
}

impl ExecutionTimingClaim {
    pub const fn new(
        timing: ExecutionTiming,
        proof: ProofStatus,
        completeness: EvidenceCompleteness,
    ) -> Self {
        Self {
            timing,
            proof,
            completeness,
        }
    }

    /// An [`ExecutionTiming::Unknown`] claim naming why the timing could not be
    /// established. Both carriers are weakened, because an unknown timing is
    /// neither a proven answer nor a complete one.
    pub fn unknown(reason: impl Into<Box<str>>) -> Self {
        let reason = reason.into();
        Self {
            timing: ExecutionTiming::Unknown,
            proof: ProofStatus::Unproven(reason.clone()),
            completeness: EvidenceCompleteness::Partial(reason),
        }
    }

    pub const fn timing(&self) -> ExecutionTiming {
        self.timing
    }

    pub const fn proof(&self) -> &ProofStatus {
        &self.proof
    }

    pub const fn completeness(&self) -> &EvidenceCompleteness {
        &self.completeness
    }

    /// Whether a consumer may act on this timing without adding its own
    /// justification.
    pub const fn is_proven_complete(&self) -> bool {
        matches!(self.proof, ProofStatus::Proven)
            && matches!(self.completeness, EvidenceCompleteness::Complete)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
