use std::{error::Error, fmt, mem::size_of_val, sync::Arc};

use crate::analyzer::semantic::{
    AbstractLocation, AccessPath, AccessPathRoot, AccessPathTail, AccessSelector, CallSiteHandle,
    DurableIdentityError, DurableObjectIdentity, DurablePortIdentity, DurableValueIdentity,
    EvidenceCompleteness, IndexSelector, OracleCallContext, ProcedureHandle, ProcedurePortHandle,
    ProgramPointHandle, ProofStatus, ScopedSemanticLocator, SemanticArtifact, SemanticLocator,
    ValueFlowEndpoint, ValueHandle,
};
use brokk_bifrost_core::analyzer::dense_id::define_dense_id;

define_dense_id! {
    /// Run-local identity for one canonical value-flow carrier.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct ValueFlowCarrierId {
        new: pub(crate),
        get: pub,
        index: pub(crate),
        try_from_index: pub(crate),
    }
}

define_dense_id! {
    /// Run-local identity for one resolved flow source.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct ValueFlowSourceId {
        new: pub(crate),
        get: pub,
        index: pub(crate),
        try_from_index: pub(crate),
    }
}

define_dense_id! {
    /// Run-local identity for one resolved flow sink.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct ValueFlowSinkId {
        new: pub(crate),
        get: pub,
        index: pub(crate),
        try_from_index: pub(crate),
    }
}

/// One live structured entity that may carry a value through the flow client.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ValueFlowCarrier {
    Value(ValueHandle),
    Port(ProcedurePortHandle),
    Location(Box<AbstractLocation>),
}

impl ValueFlowCarrier {
    pub fn procedure(&self) -> Option<&ProcedureHandle> {
        match self {
            Self::Value(value) => Some(value.procedure()),
            Self::Port(port) => Some(port.procedure()),
            Self::Location(location) => location.path().root().scoped_procedure(),
        }
    }

    pub(crate) fn for_each_retained_artifact(&self, mut visit: impl FnMut(&Arc<SemanticArtifact>)) {
        match self {
            Self::Value(value) => visit(value.procedure().artifact()),
            Self::Port(port) => visit(port.procedure().artifact()),
            Self::Location(location) => location.for_each_retained_artifact(visit),
        }
    }

    pub fn stable_key(&self) -> Result<ValueFlowCarrierKey, ValueFlowModelError> {
        match self {
            Self::Value(value) => value_key(value),
            Self::Port(port) => port_key(port),
            Self::Location(location) => Ok(ValueFlowCarrierKey::Location {
                root: Box::new(root_key(location.path().root())?),
                selectors: location
                    .path()
                    .selectors()
                    .iter()
                    .map(selector_key)
                    .collect::<Result<Vec<_>, _>>()?
                    .into_boxed_slice(),
                exact: matches!(location.path().tail(), AccessPathTail::Exact),
            }),
        }
    }

    /// Whether two carriers name the same entity of the same artifact.
    ///
    /// Handle equality is materialization-scoped on purpose: `ProcedureHandle`
    /// and `ScopedSemanticLocator` compare their owning `Arc<SemanticArtifact>`
    /// by pointer, so a handle minted from a second materialization of one
    /// immutable artifact is unequal to the first even though both name the
    /// same value, port, or location. A caller that discovers an
    /// interprocedural closure can legitimately hold both, because the
    /// artifact cache is byte-bounded and can evict an artifact that a later
    /// call resolution then re-materializes.
    ///
    /// `SemanticArtifactKey` is the artifact's durable identity, and it pins
    /// the revision, adapter, IR version, configuration, and dependencies. Two
    /// handles that agree on that key and on every dense ID beneath it name one
    /// entity. Comparing through it answers the identity question without
    /// widening `stable_key` and without weakening handle equality anywhere
    /// else.
    pub(crate) fn denotes_same_entity(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Value(left), Self::Value(right)) => same_value(left, right),
            (Self::Port(left), Self::Port(right)) => same_port(left, right),
            // `AbstractLocation::new` is the only constructor and it requires
            // the object identity to be the path root, so the path carries the
            // identity and only the cardinality is left to compare.
            (Self::Location(left), Self::Location(right)) => {
                left.object().cardinality() == right.object().cardinality()
                    && same_path(left.path(), right.path())
            }
            _ => false,
        }
    }
}

/// The borrowed form of [`ProcedureHandle::durable_key`]. Carrier comparison
/// runs for every endpoint of every relation the plan reads, so it compares the
/// two identity components in place instead of cloning an owned key.
fn same_procedure(left: &ProcedureHandle, right: &ProcedureHandle) -> bool {
    left.id() == right.id() && left.artifact().key() == right.artifact().key()
}

fn same_value(left: &ValueHandle, right: &ValueHandle) -> bool {
    left.id() == right.id() && same_procedure(left.procedure(), right.procedure())
}

fn same_port(left: &ProcedurePortHandle, right: &ProcedurePortHandle) -> bool {
    left.kind() == right.kind() && same_procedure(left.procedure(), right.procedure())
}

fn same_call(left: &CallSiteHandle, right: &CallSiteHandle) -> bool {
    left.id() == right.id() && same_procedure(left.procedure(), right.procedure())
}

fn same_call_context(left: &OracleCallContext, right: &OracleCallContext) -> bool {
    left.was_truncated() == right.was_truncated()
        && left.calls().len() == right.calls().len()
        && left
            .calls()
            .iter()
            .zip(right.calls())
            .all(|(left, right)| same_call(left, right))
}

fn same_scoped_locator(left: &ScopedSemanticLocator, right: &ScopedSemanticLocator) -> bool {
    left.scope().key() == right.scope().key() && left.locator() == right.locator()
}

fn same_root(left: &AccessPathRoot, right: &AccessPathRoot) -> bool {
    match (left, right) {
        (AccessPathRoot::Value(left), AccessPathRoot::Value(right)) => same_value(left, right),
        (AccessPathRoot::CallResult(left), AccessPathRoot::CallResult(right)) => {
            same_call(left.call(), right.call())
                && same_value(left.result(), right.result())
                && same_procedure(left.callee(), right.callee())
                && same_call_context(left.caller_context(), right.caller_context())
                && same_call_context(left.callee_context(), right.callee_context())
        }
        (AccessPathRoot::ProcedurePort(left), AccessPathRoot::ProcedurePort(right))
        | (AccessPathRoot::CaptureSlot(left), AccessPathRoot::CaptureSlot(right)) => {
            same_port(left, right)
        }
        (AccessPathRoot::Allocation(left), AccessPathRoot::Allocation(right)) => {
            left.id() == right.id() && same_procedure(left.procedure(), right.procedure())
        }
        (AccessPathRoot::LexicalCell(left), AccessPathRoot::LexicalCell(right)) => {
            left.id() == right.id() && same_procedure(left.procedure(), right.procedure())
        }
        (AccessPathRoot::Static(left), AccessPathRoot::Static(right))
        | (AccessPathRoot::TypeSummary(left), AccessPathRoot::TypeSummary(right))
        | (AccessPathRoot::ModuleObject(left), AccessPathRoot::ModuleObject(right))
        | (AccessPathRoot::External(left), AccessPathRoot::External(right)) => {
            same_scoped_locator(left, right)
        }
        _ => false,
    }
}

fn same_path(left: &AccessPath, right: &AccessPath) -> bool {
    left.tail() == right.tail()
        && same_root(left.root(), right.root())
        && left.selectors().len() == right.selectors().len()
        && left
            .selectors()
            .iter()
            .zip(right.selectors())
            .all(|(left, right)| match (left, right) {
                (AccessSelector::Field(left), AccessSelector::Field(right)) => {
                    same_scoped_locator(left, right)
                }
                (
                    AccessSelector::Index(IndexSelector::Exact(left)),
                    AccessSelector::Index(IndexSelector::Exact(right)),
                ) => same_value(left, right),
                (
                    AccessSelector::Index(IndexSelector::Constant(left)),
                    AccessSelector::Index(IndexSelector::Constant(right)),
                ) => left == right,
                (
                    AccessSelector::Index(IndexSelector::Any),
                    AccessSelector::Index(IndexSelector::Any),
                ) => true,
                _ => false,
            })
}

impl From<ValueFlowEndpoint> for ValueFlowCarrier {
    fn from(endpoint: ValueFlowEndpoint) -> Self {
        match endpoint {
            ValueFlowEndpoint::Value(value) => Self::Value(value),
            ValueFlowEndpoint::Port(port) => Self::Port(port),
            ValueFlowEndpoint::Location(location) => Self::Location(location),
        }
    }
}

impl From<&ValueFlowEndpoint> for ValueFlowCarrier {
    fn from(endpoint: &ValueFlowEndpoint) -> Self {
        endpoint.clone().into()
    }
}

/// Stable semantic identity for a carrier, independent of run-local dense IDs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ValueFlowCarrierKey {
    Value {
        locator: SemanticLocator,
        role: Box<str>,
        ordinal: Option<u32>,
    },
    Port {
        procedure: SemanticLocator,
        kind: ValueFlowPortKey,
    },
    Allocation {
        locator: SemanticLocator,
    },
    CallResult {
        call: SemanticLocator,
        result: Box<ValueFlowCarrierKey>,
        callee: SemanticLocator,
    },
    ScopedRoot {
        kind: ValueFlowScopedRootKind,
        locator: SemanticLocator,
    },
    Location {
        root: Box<ValueFlowCarrierKey>,
        selectors: Box<[ValueFlowSelectorKey]>,
        exact: bool,
    },
}

impl ValueFlowCarrierKey {
    /// Conservative retained size, including boxed nested access paths.
    pub fn retained_bytes(&self) -> usize {
        let mut total = std::mem::size_of::<Self>();
        let mut stack = vec![self];
        while let Some(key) = stack.pop() {
            match key {
                Self::Value { locator, role, .. } => {
                    total = total
                        .saturating_add(semantic_locator_heap_bytes(locator))
                        .saturating_add(role.len());
                }
                Self::Port { procedure, .. } => {
                    total = total.saturating_add(semantic_locator_heap_bytes(procedure));
                }
                Self::Allocation { locator } | Self::ScopedRoot { locator, .. } => {
                    total = total.saturating_add(semantic_locator_heap_bytes(locator));
                }
                Self::CallResult {
                    call,
                    result,
                    callee,
                } => {
                    total = total
                        .saturating_add(semantic_locator_heap_bytes(call))
                        .saturating_add(semantic_locator_heap_bytes(callee))
                        .saturating_add(std::mem::size_of::<Self>());
                    stack.push(result);
                }
                Self::Location {
                    root, selectors, ..
                } => {
                    total = total
                        .saturating_add(std::mem::size_of::<Self>())
                        .saturating_add(size_of_val(selectors.as_ref()));
                    stack.push(root);
                    for selector in selectors {
                        match selector {
                            ValueFlowSelectorKey::Field(locator) => {
                                total = total.saturating_add(semantic_locator_heap_bytes(locator));
                            }
                            ValueFlowSelectorKey::ExactIndex(key) => {
                                total = total.saturating_add(std::mem::size_of::<Self>());
                                stack.push(key);
                            }
                            ValueFlowSelectorKey::ConstantIndex(_) => {}
                            ValueFlowSelectorKey::AnyIndex => {}
                        }
                    }
                }
            }
        }
        total
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ValueFlowPortKey {
    Receiver,
    Parameter { ordinal: u32 },
    NormalReturn,
    IndexedNormalReturn { ordinal: u32 },
    ExceptionalReturn,
    Capture { slot: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ValueFlowScopedRootKind {
    Static,
    LexicalCell,
    TypeSummary,
    ModuleObject,
    External,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ValueFlowSelectorKey {
    Field(SemanticLocator),
    ExactIndex(Box<ValueFlowCarrierKey>),
    ConstantIndex(u128),
    AnyIndex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ValueFlowEventKind {
    Source,
    Sink,
    Sanitizer,
    Transform,
}

/// Stable identity for one resolved semantic event binding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ValueFlowEventKey {
    site: SemanticLocator,
    ordinal: u32,
    kind: ValueFlowEventKind,
}

impl ValueFlowEventKey {
    pub fn at_point(
        point: &ProgramPointHandle,
        ordinal: u32,
        kind: ValueFlowEventKind,
    ) -> Result<Self, ValueFlowModelError> {
        let row = point
            .procedure()
            .semantics()
            .point(point.id())
            .ok_or(ValueFlowModelError::StaleProgramPoint)?;
        let site = source_locator(point.procedure(), row.source)?;
        Ok(Self {
            site,
            ordinal,
            kind,
        })
    }

    pub const fn site(&self) -> &SemanticLocator {
        &self.site
    }

    pub const fn ordinal(&self) -> u32 {
        self.ordinal
    }

    pub const fn kind(&self) -> ValueFlowEventKind {
        self.kind
    }

    pub fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>().saturating_add(semantic_locator_heap_bytes(&self.site))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ValueFlowObservationPhase {
    BeforeEffects,
    AfterEffects,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ValueFlowSourceSpec {
    key: ValueFlowEventKey,
    point: ProgramPointHandle,
    phase: ValueFlowObservationPhase,
    carrier: ValueFlowCarrier,
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
}

impl ValueFlowSourceSpec {
    pub fn new(
        key: ValueFlowEventKey,
        point: ProgramPointHandle,
        phase: ValueFlowObservationPhase,
        carrier: ValueFlowCarrier,
        proof: ProofStatus,
        completeness: EvidenceCompleteness,
    ) -> Self {
        Self {
            key,
            point,
            phase,
            carrier,
            proof,
            completeness,
        }
    }

    pub fn key(&self) -> &ValueFlowEventKey {
        &self.key
    }

    pub fn point(&self) -> &ProgramPointHandle {
        &self.point
    }

    pub const fn phase(&self) -> ValueFlowObservationPhase {
        self.phase
    }

    pub fn carrier(&self) -> &ValueFlowCarrier {
        &self.carrier
    }

    pub fn proof(&self) -> &ProofStatus {
        &self.proof
    }

    pub fn completeness(&self) -> &EvidenceCompleteness {
        &self.completeness
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ValueFlowSinkSpec {
    key: ValueFlowEventKey,
    point: ProgramPointHandle,
    phase: ValueFlowObservationPhase,
    carrier: ValueFlowCarrier,
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
}

impl ValueFlowSinkSpec {
    pub fn new(
        key: ValueFlowEventKey,
        point: ProgramPointHandle,
        phase: ValueFlowObservationPhase,
        carrier: ValueFlowCarrier,
        proof: ProofStatus,
        completeness: EvidenceCompleteness,
    ) -> Self {
        Self {
            key,
            point,
            phase,
            carrier,
            proof,
            completeness,
        }
    }

    pub fn key(&self) -> &ValueFlowEventKey {
        &self.key
    }

    pub fn point(&self) -> &ProgramPointHandle {
        &self.point
    }

    pub const fn phase(&self) -> ValueFlowObservationPhase {
        self.phase
    }

    pub fn carrier(&self) -> &ValueFlowCarrier {
        &self.carrier
    }

    pub fn proof(&self) -> &ProofStatus {
        &self.proof
    }

    pub fn completeness(&self) -> &EvidenceCompleteness {
        &self.completeness
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueFlowModelError {
    StaleProgramPoint,
    StaleSourceMapping,
    StaleCarrier,
}

impl fmt::Display for ValueFlowModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StaleProgramPoint => formatter.write_str("value-flow event point is stale"),
            Self::StaleSourceMapping => {
                formatter.write_str("value-flow carrier source mapping is stale")
            }
            Self::StaleCarrier => formatter.write_str("value-flow carrier is stale"),
        }
    }
}

impl Error for ValueFlowModelError {}

pub(crate) fn semantic_locator_heap_bytes(locator: &SemanticLocator) -> usize {
    let segments = locator.declaration().segments();
    locator
        .path()
        .as_str()
        .len()
        .saturating_add(size_of_val(segments))
        .saturating_add(
            segments
                .iter()
                .filter_map(|segment| segment.name())
                .map(str::len)
                .fold(0usize, usize::saturating_add),
        )
}

fn source_locator(
    procedure: &ProcedureHandle,
    source: crate::analyzer::semantic::SourceMappingId,
) -> Result<SemanticLocator, ValueFlowModelError> {
    procedure
        .semantics()
        .source_mapping(source)
        .map(|mapping| mapping.locator.clone())
        .ok_or(ValueFlowModelError::StaleSourceMapping)
}

impl From<DurableIdentityError> for ValueFlowModelError {
    fn from(error: DurableIdentityError) -> Self {
        match error {
            DurableIdentityError::StaleRow => Self::StaleCarrier,
            DurableIdentityError::StaleSourceMapping => Self::StaleSourceMapping,
        }
    }
}

/// Project the oracle's durable object identity onto the carrier key.
///
/// This view is lossy on purpose: a carrier is a flow slot, not a
/// context-sensitive object, so the call contexts a call-result identity
/// carries are dropped, a capture port keeps only its artifact-dense slot, and
/// the four locator-rooted identities collapse into one `ScopedRoot`. Nothing
/// here reads a handle: the durable identity already did that once.
fn carrier_key(identity: &DurableObjectIdentity) -> ValueFlowCarrierKey {
    match identity {
        DurableObjectIdentity::Value(value) => value_carrier_key(value),
        DurableObjectIdentity::CallResult {
            call,
            result,
            callee,
            ..
        } => ValueFlowCarrierKey::CallResult {
            call: call.clone(),
            result: Box::new(value_carrier_key(result)),
            callee: callee.clone(),
        },
        DurableObjectIdentity::ProcedurePort { procedure, port }
        | DurableObjectIdentity::CaptureSlot { procedure, port } => ValueFlowCarrierKey::Port {
            procedure: procedure.clone(),
            kind: match port {
                DurablePortIdentity::Receiver => ValueFlowPortKey::Receiver,
                DurablePortIdentity::Parameter { ordinal } => {
                    ValueFlowPortKey::Parameter { ordinal: *ordinal }
                }
                DurablePortIdentity::NormalReturn => ValueFlowPortKey::NormalReturn,
                DurablePortIdentity::IndexedNormalReturn { ordinal } => {
                    ValueFlowPortKey::IndexedNormalReturn { ordinal: *ordinal }
                }
                DurablePortIdentity::ExceptionalReturn => ValueFlowPortKey::ExceptionalReturn,
                DurablePortIdentity::Capture { slot, .. } => {
                    ValueFlowPortKey::Capture { slot: *slot }
                }
            },
        },
        DurableObjectIdentity::Allocation { locator } => ValueFlowCarrierKey::Allocation {
            locator: locator.clone(),
        },
        DurableObjectIdentity::Static { locator } => ValueFlowCarrierKey::ScopedRoot {
            kind: ValueFlowScopedRootKind::Static,
            locator: locator.clone(),
        },
        DurableObjectIdentity::LexicalCell { locator } => ValueFlowCarrierKey::ScopedRoot {
            kind: ValueFlowScopedRootKind::LexicalCell,
            locator: locator.clone(),
        },
        DurableObjectIdentity::TypeSummary { locator } => ValueFlowCarrierKey::ScopedRoot {
            kind: ValueFlowScopedRootKind::TypeSummary,
            locator: locator.clone(),
        },
        DurableObjectIdentity::ModuleObject { locator } => ValueFlowCarrierKey::ScopedRoot {
            kind: ValueFlowScopedRootKind::ModuleObject,
            locator: locator.clone(),
        },
        DurableObjectIdentity::External { locator } => ValueFlowCarrierKey::ScopedRoot {
            kind: ValueFlowScopedRootKind::External,
            locator: locator.clone(),
        },
    }
}

fn value_carrier_key(value: &DurableValueIdentity) -> ValueFlowCarrierKey {
    ValueFlowCarrierKey::Value {
        locator: value.locator.clone(),
        role: value.role.clone(),
        ordinal: value.ordinal,
    }
}

fn value_key(value: &ValueHandle) -> Result<ValueFlowCarrierKey, ValueFlowModelError> {
    Ok(value_carrier_key(&DurableValueIdentity::of(value)?))
}

fn port_key(port: &ProcedurePortHandle) -> Result<ValueFlowCarrierKey, ValueFlowModelError> {
    Ok(carrier_key(&DurableObjectIdentity::ProcedurePort {
        procedure: port.procedure().semantics().locator().clone(),
        port: DurablePortIdentity::of(port)?,
    }))
}

fn root_key(root: &AccessPathRoot) -> Result<ValueFlowCarrierKey, ValueFlowModelError> {
    Ok(carrier_key(&root.durable_identity()?))
}

fn selector_key(selector: &AccessSelector) -> Result<ValueFlowSelectorKey, ValueFlowModelError> {
    match selector {
        AccessSelector::Field(field) => Ok(ValueFlowSelectorKey::Field(field.locator().clone())),
        AccessSelector::Index(IndexSelector::Exact(index)) => Ok(ValueFlowSelectorKey::ExactIndex(
            Box::new(value_key(index)?),
        )),
        AccessSelector::Index(IndexSelector::Constant(index)) => {
            Ok(ValueFlowSelectorKey::ConstantIndex(*index))
        }
        AccessSelector::Index(IndexSelector::Any) => Ok(ValueFlowSelectorKey::AnyIndex),
    }
}
