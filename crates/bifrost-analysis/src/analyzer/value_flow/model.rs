use std::{error::Error, fmt, mem::size_of_val};

use crate::analyzer::dense_id::define_dense_id;
use crate::analyzer::semantic::{
    AbstractLocation, AccessPathRoot, AccessPathTail, AccessSelector, AllocationHandle,
    CallResultHandle, EvidenceCompleteness, IndexSelector, MemoryLocationHandle, ProcedureHandle,
    ProcedurePortHandle, ProcedurePortKind, ProgramPointHandle, ProofStatus, SemanticLocator,
    SemanticValueKind, ValueFlowEndpoint, ValueHandle,
};

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
            Self::Location(location) => carrier_root_procedure(location.path().root()),
        }
    }

    pub fn stable_key(&self) -> Result<ValueFlowCarrierKey, ValueFlowModelError> {
        match self {
            Self::Value(value) => value_key(value),
            Self::Port(port) => Ok(port_key(port)),
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

fn value_key(value: &ValueHandle) -> Result<ValueFlowCarrierKey, ValueFlowModelError> {
    let row = value
        .procedure()
        .semantics()
        .value(value.id())
        .ok_or(ValueFlowModelError::StaleCarrier)?;
    let ordinal = match row.kind {
        SemanticValueKind::Parameter { ordinal, .. } => Some(ordinal),
        _ => None,
    };
    Ok(ValueFlowCarrierKey::Value {
        locator: source_locator(value.procedure(), row.source)?,
        role: row.kind.label().into(),
        ordinal,
    })
}

fn allocation_key(
    allocation: &AllocationHandle,
) -> Result<ValueFlowCarrierKey, ValueFlowModelError> {
    let row = allocation
        .procedure()
        .semantics()
        .allocation(allocation.id())
        .ok_or(ValueFlowModelError::StaleCarrier)?;
    Ok(ValueFlowCarrierKey::Allocation {
        locator: source_locator(allocation.procedure(), row.source)?,
    })
}

fn memory_key(location: &MemoryLocationHandle) -> Result<ValueFlowCarrierKey, ValueFlowModelError> {
    let row = location
        .procedure()
        .semantics()
        .memory_location(location.id())
        .ok_or(ValueFlowModelError::StaleCarrier)?;
    Ok(ValueFlowCarrierKey::ScopedRoot {
        kind: ValueFlowScopedRootKind::LexicalCell,
        locator: source_locator(location.procedure(), row.source)?,
    })
}

fn port_key(port: &ProcedurePortHandle) -> ValueFlowCarrierKey {
    let kind = match port.kind() {
        ProcedurePortKind::Receiver => ValueFlowPortKey::Receiver,
        ProcedurePortKind::Parameter { ordinal } => ValueFlowPortKey::Parameter { ordinal },
        ProcedurePortKind::NormalReturn => ValueFlowPortKey::NormalReturn,
        ProcedurePortKind::ExceptionalReturn => ValueFlowPortKey::ExceptionalReturn,
        ProcedurePortKind::Capture { slot } => ValueFlowPortKey::Capture { slot: slot.get() },
    };
    ValueFlowCarrierKey::Port {
        procedure: port.procedure().semantics().locator().clone(),
        kind,
    }
}

fn call_result_key(result: &CallResultHandle) -> Result<ValueFlowCarrierKey, ValueFlowModelError> {
    let call_row = result
        .call()
        .procedure()
        .semantics()
        .call_site(result.call().id())
        .ok_or(ValueFlowModelError::StaleCarrier)?;
    Ok(ValueFlowCarrierKey::CallResult {
        call: source_locator(result.call().procedure(), call_row.source)?,
        result: Box::new(value_key(result.result())?),
        callee: result.callee().semantics().locator().clone(),
    })
}

fn root_key(root: &AccessPathRoot) -> Result<ValueFlowCarrierKey, ValueFlowModelError> {
    match root {
        AccessPathRoot::Value(value) => value_key(value),
        AccessPathRoot::CallResult(result) => call_result_key(result),
        AccessPathRoot::ProcedurePort(port) | AccessPathRoot::CaptureSlot(port) => {
            Ok(port_key(port))
        }
        AccessPathRoot::Allocation(allocation) => allocation_key(allocation),
        AccessPathRoot::Static(locator) => Ok(ValueFlowCarrierKey::ScopedRoot {
            kind: ValueFlowScopedRootKind::Static,
            locator: locator.locator().clone(),
        }),
        AccessPathRoot::LexicalCell(location) => memory_key(location),
        AccessPathRoot::TypeSummary(locator) => Ok(ValueFlowCarrierKey::ScopedRoot {
            kind: ValueFlowScopedRootKind::TypeSummary,
            locator: locator.locator().clone(),
        }),
        AccessPathRoot::ModuleObject(locator) => Ok(ValueFlowCarrierKey::ScopedRoot {
            kind: ValueFlowScopedRootKind::ModuleObject,
            locator: locator.locator().clone(),
        }),
        AccessPathRoot::External(locator) => Ok(ValueFlowCarrierKey::ScopedRoot {
            kind: ValueFlowScopedRootKind::External,
            locator: locator.locator().clone(),
        }),
    }
}

fn selector_key(selector: &AccessSelector) -> Result<ValueFlowSelectorKey, ValueFlowModelError> {
    match selector {
        AccessSelector::Field(field) => Ok(ValueFlowSelectorKey::Field(field.locator().clone())),
        AccessSelector::Index(IndexSelector::Exact(index)) => Ok(ValueFlowSelectorKey::ExactIndex(
            Box::new(value_key(index)?),
        )),
        AccessSelector::Index(IndexSelector::Any) => Ok(ValueFlowSelectorKey::AnyIndex),
    }
}

fn carrier_root_procedure(root: &AccessPathRoot) -> Option<&ProcedureHandle> {
    match root {
        AccessPathRoot::Value(value) => Some(value.procedure()),
        AccessPathRoot::CallResult(result) => Some(result.result().procedure()),
        AccessPathRoot::ProcedurePort(port) | AccessPathRoot::CaptureSlot(port) => {
            Some(port.procedure())
        }
        AccessPathRoot::Allocation(allocation) => Some(allocation.procedure()),
        AccessPathRoot::LexicalCell(location) => Some(location.procedure()),
        AccessPathRoot::Static(_)
        | AccessPathRoot::TypeSummary(_)
        | AccessPathRoot::ModuleObject(_)
        | AccessPathRoot::External(_) => None,
    }
}
