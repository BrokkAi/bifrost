use std::{error::Error, fmt, mem::size_of_val, sync::Arc};

use crate::analyzer::semantic::LengthDelimitedDigest;
use crate::analyzer::semantic::{
    AbstractLocation, AccessPath, AccessPathRoot, AccessPathTail, AccessSelector, CallSiteHandle,
    DurableIdentityError, DurableObjectIdentity, DurablePortIdentity, DurableValueIdentity,
    EvidenceCompleteness, IndexSelector, OracleCallContext, ProcedureHandle, ProcedurePortHandle,
    ProgramPointHandle, ProofStatus, ScopedSemanticLocator, SemanticArtifact, SemanticLocator,
    StableDigest, ValueFlowEndpoint, ValueHandle,
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
        (AccessPathRoot::RuntimeObject(left), AccessPathRoot::RuntimeObject(right)) => {
            left == right
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
                (AccessSelector::Property(left), AccessSelector::Property(right)) => left == right,
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
    RuntimeObject {
        runtime_profile_digest: String,
        realm: String,
        exposure_id: String,
        container_member: String,
        state_boundary: String,
        refinement_identity: StableDigest,
        active_model_set_hash: String,
        manifest_digest: String,
        shard_id: String,
        behavior_id: String,
        activation_source: String,
    },
    LexicalCell {
        locator: SemanticLocator,
        binding: DurableValueIdentity,
    },
    Location {
        root: Box<ValueFlowCarrierKey>,
        selectors: Box<[ValueFlowSelectorKey]>,
        exact: bool,
    },
}

impl ValueFlowCarrierKey {
    /// Add this carrier's checkout-independent structured identity to `digest`.
    ///
    /// The caller owns the outer domain separation. Every carrier and selector
    /// variant is tagged, collection lengths are explicit, and locators use the
    /// semantic layer's sanctioned stable encoding. The explicit work stack is
    /// intentional: access paths can be deeply nested and identity production
    /// must not consume the Rust call stack.
    pub fn push_stable_identity(&self, digest: &mut LengthDelimitedDigest) {
        self.push_stable_identity_with(digest, None);
    }

    /// Add this carrier's structured identity relative to its owning
    /// procedure. Procedure-local source movement is normalized. Procedure
    /// locators at a call boundary retain an anchor-free declaration address;
    /// other locators outside the owner remain exact external inputs.
    pub(crate) fn push_procedure_local_identity(
        &self,
        digest: &mut LengthDelimitedDigest,
        procedure: &SemanticLocator,
    ) {
        self.push_stable_identity_with(digest, Some(procedure));
    }

    fn push_stable_identity_with(
        &self,
        digest: &mut LengthDelimitedDigest,
        procedure: Option<&SemanticLocator>,
    ) {
        enum Part<'key> {
            Carrier(&'key ValueFlowCarrierKey),
            Selector(&'key ValueFlowSelectorKey),
        }

        let mut pending = vec![Part::Carrier(self)];
        while let Some(part) = pending.pop() {
            match part {
                Part::Carrier(Self::Value {
                    locator,
                    role,
                    ordinal,
                }) => {
                    digest.push(b"value");
                    push_value_identity(digest, locator, role.as_ref(), *ordinal, procedure);
                }
                Part::Carrier(Self::Port {
                    procedure: port_procedure,
                    kind,
                }) => {
                    digest.push(b"port");
                    push_call_boundary_procedure(digest, port_procedure, procedure);
                    match kind {
                        ValueFlowPortKey::Receiver => digest.push(b"receiver"),
                        ValueFlowPortKey::Parameter { ordinal } => {
                            digest.push(b"parameter");
                            digest.push(&ordinal.to_le_bytes());
                        }
                        ValueFlowPortKey::NormalReturn => digest.push(b"normal_return"),
                        ValueFlowPortKey::IndexedNormalReturn { ordinal } => {
                            digest.push(b"indexed_normal_return");
                            digest.push(&ordinal.to_le_bytes());
                        }
                        ValueFlowPortKey::ExceptionalReturn => digest.push(b"exceptional_return"),
                        ValueFlowPortKey::Capture { slot } => {
                            digest.push(b"capture");
                            digest.push(&slot.to_le_bytes());
                        }
                    }
                }
                Part::Carrier(Self::Allocation { locator }) => {
                    digest.push(b"allocation");
                    push_carrier_locator(digest, locator, procedure);
                }
                Part::Carrier(Self::CallResult {
                    call,
                    result,
                    callee,
                }) => {
                    digest.push(b"call_result");
                    push_carrier_locator(digest, call, procedure);
                    push_call_boundary_procedure(digest, callee, procedure);
                    pending.push(Part::Carrier(result));
                }
                Part::Carrier(Self::ScopedRoot { kind, locator }) => {
                    digest.push(b"scoped_root");
                    digest.push(match kind {
                        ValueFlowScopedRootKind::Static => b"static",
                        ValueFlowScopedRootKind::TypeSummary => b"type_summary",
                        ValueFlowScopedRootKind::ModuleObject => b"module_object",
                        ValueFlowScopedRootKind::External => b"external",
                    });
                    push_carrier_locator(digest, locator, procedure);
                }
                Part::Carrier(Self::RuntimeObject {
                    runtime_profile_digest,
                    realm,
                    exposure_id,
                    container_member,
                    state_boundary,
                    refinement_identity,
                    active_model_set_hash,
                    manifest_digest,
                    shard_id,
                    behavior_id,
                    activation_source,
                }) => {
                    digest.push(b"runtime_object");
                    digest.push(runtime_profile_digest.as_bytes());
                    digest.push(realm.as_bytes());
                    digest.push(exposure_id.as_bytes());
                    digest.push(container_member.as_bytes());
                    digest.push(state_boundary.as_bytes());
                    digest.push(refinement_identity.as_bytes());
                    digest.push(active_model_set_hash.as_bytes());
                    digest.push(manifest_digest.as_bytes());
                    digest.push(shard_id.as_bytes());
                    digest.push(behavior_id.as_bytes());
                    digest.push(activation_source.as_bytes());
                }
                Part::Carrier(Self::LexicalCell { locator, binding }) => {
                    digest.push(b"lexical_cell");
                    push_carrier_locator(digest, locator, procedure);
                    digest.push(b"binding");
                    push_value_identity(
                        digest,
                        &binding.locator,
                        binding.role.as_ref(),
                        binding.ordinal,
                        procedure,
                    );
                }
                Part::Carrier(Self::Location {
                    root,
                    selectors,
                    exact,
                }) => {
                    digest.push(b"location");
                    digest.push(if *exact { b"exact" } else { b"prefix" });
                    digest.push(
                        &u64::try_from(selectors.len())
                            .expect("value-flow selector count fits in u64")
                            .to_le_bytes(),
                    );
                    for selector in selectors.iter().rev() {
                        pending.push(Part::Selector(selector));
                    }
                    pending.push(Part::Carrier(root));
                }
                Part::Selector(ValueFlowSelectorKey::Field(locator)) => {
                    digest.push(b"field");
                    push_carrier_locator(digest, locator, procedure);
                }
                Part::Selector(ValueFlowSelectorKey::Property(property)) => {
                    digest.push(b"property");
                    digest.push(property.as_bytes());
                }
                Part::Selector(ValueFlowSelectorKey::ExactIndex(index)) => {
                    digest.push(b"exact_index");
                    pending.push(Part::Carrier(index));
                }
                Part::Selector(ValueFlowSelectorKey::ConstantIndex(index)) => {
                    digest.push(b"constant_index");
                    digest.push(&index.to_le_bytes());
                }
                Part::Selector(ValueFlowSelectorKey::AnyIndex) => digest.push(b"any_index"),
            }
        }
    }

    /// Checkout-independent fingerprint for one stable value-flow carrier.
    pub fn stable_fingerprint(&self) -> StableDigest {
        let mut digest = LengthDelimitedDigest::new(b"bifrost-value-flow-carrier-key-v1");
        self.push_stable_identity(&mut digest);
        digest.finish()
    }

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
                Self::RuntimeObject {
                    runtime_profile_digest,
                    realm,
                    exposure_id,
                    container_member,
                    state_boundary,
                    active_model_set_hash,
                    manifest_digest,
                    shard_id,
                    behavior_id,
                    activation_source,
                    ..
                } => {
                    total = total
                        .saturating_add(runtime_profile_digest.len())
                        .saturating_add(realm.len())
                        .saturating_add(exposure_id.len())
                        .saturating_add(container_member.len())
                        .saturating_add(state_boundary.len())
                        .saturating_add(active_model_set_hash.len())
                        .saturating_add(manifest_digest.len())
                        .saturating_add(shard_id.len())
                        .saturating_add(behavior_id.len())
                        .saturating_add(activation_source.len())
                        .saturating_add(std::mem::size_of::<StableDigest>());
                }
                Self::LexicalCell { locator, binding } => {
                    total = total
                        .saturating_add(semantic_locator_heap_bytes(locator))
                        .saturating_add(semantic_locator_heap_bytes(&binding.locator))
                        .saturating_add(binding.role.len());
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
                            ValueFlowSelectorKey::Property(property) => {
                                total = total.saturating_add(property.len());
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

fn push_carrier_locator(
    digest: &mut LengthDelimitedDigest,
    locator: &SemanticLocator,
    procedure: Option<&SemanticLocator>,
) {
    match procedure {
        Some(procedure) => locator.push_procedure_local_identity(digest, procedure),
        None => locator.push_stable_identity(digest),
    }
}

fn push_value_identity(
    digest: &mut LengthDelimitedDigest,
    locator: &SemanticLocator,
    role: &str,
    ordinal: Option<u32>,
    procedure: Option<&SemanticLocator>,
) {
    push_carrier_locator(digest, locator, procedure);
    digest.push(role.as_bytes());
    match ordinal {
        Some(ordinal) => {
            digest.push(b"ordinal");
            digest.push(&ordinal.to_le_bytes());
        }
        None => digest.push(b"no_ordinal"),
    }
}

/// Encode the procedure on the other side of a call boundary.
///
/// A procedure-local caller contract separately binds the call target's
/// semantic environment and output dependency, so its carrier identity names
/// the callee by lineage rather than absorbing that callee's source anchors.
fn push_call_boundary_procedure(
    digest: &mut LengthDelimitedDigest,
    procedure: &SemanticLocator,
    owner: Option<&SemanticLocator>,
) {
    if owner.is_some() {
        procedure.push_anchor_free_procedure_declaration_identity(digest);
    } else {
        procedure.push_stable_identity(digest);
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
    TypeSummary,
    ModuleObject,
    External,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ValueFlowSelectorKey {
    Field(SemanticLocator),
    Property(String),
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
        debug_assert_eq!(
            site.declaration()
                .segments()
                .last()
                .map(|segment| segment.anchor()),
            Some(point.procedure().semantics().locator().anchor()),
            "an event source mapping retains its procedure declaration anchor"
        );
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

    /// Add this event's checkout-independent structured identity to `digest`.
    pub fn push_stable_identity(&self, digest: &mut LengthDelimitedDigest) {
        self.push_stable_identity_with(digest, None);
    }

    pub(crate) fn push_procedure_local_identity(
        &self,
        digest: &mut LengthDelimitedDigest,
        procedure: &SemanticLocator,
    ) {
        self.push_stable_identity_with(digest, Some(procedure));
    }

    fn push_stable_identity_with(
        &self,
        digest: &mut LengthDelimitedDigest,
        procedure: Option<&SemanticLocator>,
    ) {
        digest.push(b"value_flow_event");
        match procedure {
            Some(owner) if self.site.belongs_to_procedure(owner) => {
                self.site.push_procedure_local_identity(digest, owner);
            }
            Some(_) => {
                digest.push(b"cross-procedure-event");
                self.site.push_enclosing_declaration_local_identity(digest);
            }
            None => self.site.push_stable_identity(digest),
        }
        digest.push(&self.ordinal.to_le_bytes());
        digest.push(match self.kind {
            ValueFlowEventKind::Source => b"source",
            ValueFlowEventKind::Sink => b"sink",
            ValueFlowEventKind::Sanitizer => b"sanitizer",
            ValueFlowEventKind::Transform => b"transform",
        });
    }

    /// Checkout-independent fingerprint for one resolved semantic event.
    pub fn stable_fingerprint(&self) -> StableDigest {
        let mut digest = LengthDelimitedDigest::new(b"bifrost-value-flow-event-key-v1");
        self.push_stable_identity(&mut digest);
        digest.finish()
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
    /// Source events that must already reach this source's carrier at its
    /// observation point before this source can be activated. `None` keeps
    /// the historical unconditional source behavior.
    conditional_triggers: Option<Box<[ValueFlowEventKey]>>,
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
            conditional_triggers: None,
        }
    }

    /// Make this source conditional on one of the supplied source events
    /// already reaching the same carrier at this observation point.
    ///
    /// The plan validates that every trigger names a source in the plan. The
    /// builder canonicalizes the set so source identity and summary behavior
    /// do not depend on caller ordering or duplicate entries.
    pub fn when_sources_reach(mut self, mut triggers: Vec<ValueFlowEventKey>) -> Self {
        triggers.sort_unstable();
        triggers.dedup();
        assert!(!triggers.is_empty(), "a conditional source needs a trigger");
        self.conditional_triggers = Some(triggers.into_boxed_slice());
        self
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

    /// Source events that activate this source, or `None` for an
    /// unconditional source.
    pub fn activation_triggers(&self) -> Option<&[ValueFlowEventKey]> {
        self.conditional_triggers.as_deref()
    }

    pub(crate) fn activation_triggers_retained_bytes(&self) -> usize {
        self.conditional_triggers.as_ref().map_or(0, |triggers| {
            std::mem::size_of_val(triggers.as_ref()).saturating_add(
                triggers
                    .iter()
                    .map(ValueFlowEventKey::retained_bytes)
                    .fold(0usize, usize::saturating_add),
            )
        })
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
/// carries are dropped and a capture port keeps only its artifact-dense slot.
/// Lexical cells retain their bound value identity because one lowering can
/// create several cells at one source locator. The other locator-rooted
/// identities collapse into `ScopedRoot`. Nothing here reads a handle: the
/// durable identity already did that once.
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
        DurableObjectIdentity::LexicalCell { locator, binding } => {
            ValueFlowCarrierKey::LexicalCell {
                locator: locator.clone(),
                binding: binding.clone(),
            }
        }
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
        DurableObjectIdentity::RuntimeObject {
            runtime_profile_digest,
            realm,
            exposure_id,
            container_member,
            state_boundary,
            refinement_identity,
            active_model_set_hash,
            manifest_digest,
            shard_id,
            behavior_id,
            activation_source,
        } => ValueFlowCarrierKey::RuntimeObject {
            runtime_profile_digest: runtime_profile_digest.clone(),
            realm: realm.clone(),
            exposure_id: exposure_id.clone(),
            container_member: container_member.clone(),
            state_boundary: state_boundary.clone(),
            refinement_identity: *refinement_identity,
            active_model_set_hash: active_model_set_hash.clone(),
            manifest_digest: manifest_digest.clone(),
            shard_id: shard_id.clone(),
            behavior_id: behavior_id.clone(),
            activation_source: activation_source.clone(),
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
        AccessSelector::Property(property) => Ok(ValueFlowSelectorKey::Property(property.clone())),
        AccessSelector::Index(IndexSelector::Exact(index)) => Ok(ValueFlowSelectorKey::ExactIndex(
            Box::new(value_key(index)?),
        )),
        AccessSelector::Index(IndexSelector::Constant(index)) => {
            Ok(ValueFlowSelectorKey::ConstantIndex(*index))
        }
        AccessSelector::Index(IndexSelector::Any) => Ok(ValueFlowSelectorKey::AnyIndex),
    }
}

#[cfg(test)]
mod tests {
    use crate::analyzer::Language;
    use crate::analyzer::semantic::{
        DeclarationLocator, DeclarationSegment, DeclarationSegmentKind, SemanticLanguage,
        SemanticRole, SourceAnchor, SourcePosition, SourceSpan, WorkspaceMountId,
        WorkspaceRelativePath,
    };

    use super::*;

    fn locator(mount: &str, role: SemanticRole, name: &str) -> SemanticLocator {
        let span =
            SourceSpan::new(SourcePosition::new(4, 1, 0), SourcePosition::new(8, 1, 4)).unwrap();
        let anchor = SourceAnchor::new(span, 0);
        SemanticLocator::new(
            WorkspaceMountId::hash_bytes(mount),
            WorkspaceRelativePath::new("src/fixture.py").unwrap(),
            SemanticLanguage::Standard(Language::Python),
            DeclarationLocator::new(vec![
                DeclarationSegment::named(DeclarationSegmentKind::Function, name, anchor, 0)
                    .unwrap(),
            ])
            .unwrap(),
            role,
            anchor,
        )
    }

    fn locator_at(
        mount: &str,
        role: SemanticRole,
        name: &str,
        procedure_start: u32,
        start: u32,
        end: u32,
    ) -> SemanticLocator {
        let anchor = |start, end| {
            SourceAnchor::new(
                SourceSpan::new(
                    SourcePosition::new(start, 0, start),
                    SourcePosition::new(end, 0, end),
                )
                .unwrap(),
                0,
            )
        };
        let procedure_anchor = anchor(procedure_start, procedure_start + 40);
        SemanticLocator::new(
            WorkspaceMountId::hash_bytes(mount),
            WorkspaceRelativePath::new("src/fixture.py").unwrap(),
            SemanticLanguage::Standard(Language::Python),
            DeclarationLocator::new(vec![
                DeclarationSegment::named(
                    DeclarationSegmentKind::Function,
                    name,
                    procedure_anchor,
                    0,
                )
                .unwrap(),
            ])
            .unwrap(),
            role,
            anchor(start, end),
        )
    }

    fn procedure_local_carrier_digest(
        carrier: &ValueFlowCarrierKey,
        procedure: &SemanticLocator,
    ) -> StableDigest {
        let mut digest = LengthDelimitedDigest::new(b"test-procedure-local-carrier");
        carrier.push_procedure_local_identity(&mut digest, procedure);
        digest.finish()
    }

    fn procedure_local_event_digest(
        event: &ValueFlowEventKey,
        procedure: &SemanticLocator,
    ) -> StableDigest {
        let mut digest = LengthDelimitedDigest::new(b"test-procedure-local-event");
        event.push_procedure_local_identity(&mut digest, procedure);
        digest.finish()
    }

    fn nested_carrier(mount: &str) -> ValueFlowCarrierKey {
        let procedure = locator(mount, SemanticRole::Procedure, "run");
        let value = locator(mount, SemanticRole::Value, "run");
        let call = locator(mount, SemanticRole::CallSite, "run");
        let field = locator(mount, SemanticRole::MemoryLocation, "run");
        ValueFlowCarrierKey::Location {
            root: Box::new(ValueFlowCarrierKey::CallResult {
                call,
                result: Box::new(ValueFlowCarrierKey::Value {
                    locator: value.clone(),
                    role: "result".into(),
                    ordinal: Some(u32::MAX),
                }),
                callee: procedure,
            }),
            selectors: vec![
                ValueFlowSelectorKey::Field(field),
                ValueFlowSelectorKey::ExactIndex(Box::new(ValueFlowCarrierKey::Value {
                    locator: value,
                    role: "index".into(),
                    ordinal: None,
                })),
                ValueFlowSelectorKey::ConstantIndex(u128::MAX),
                ValueFlowSelectorKey::AnyIndex,
            ]
            .into_boxed_slice(),
            exact: true,
        }
    }

    fn lexical_cell_key(
        mount: &str,
        binding_role: &str,
        binding_ordinal: Option<u32>,
    ) -> ValueFlowCarrierKey {
        ValueFlowCarrierKey::LexicalCell {
            locator: locator(mount, SemanticRole::MemoryLocation, "cell"),
            binding: DurableValueIdentity {
                locator: locator(mount, SemanticRole::Value, "binding"),
                role: binding_role.into(),
                ordinal: binding_ordinal,
            },
        }
    }

    #[test]
    fn lexical_cell_key_retains_binding_role_and_ordinal() {
        let base = lexical_cell_key("mount", "parameter", Some(0));
        let changed_role = lexical_cell_key("mount", "local", Some(0));
        let changed_ordinal = lexical_cell_key("mount", "parameter", Some(1));

        assert_ne!(base, changed_role);
        assert_ne!(base, changed_ordinal);
        assert_ne!(base.stable_fingerprint(), changed_role.stable_fingerprint());
        assert_ne!(
            base.stable_fingerprint(),
            changed_ordinal.stable_fingerprint()
        );
    }

    #[test]
    fn lexical_cell_key_is_checkout_independent() {
        let first = lexical_cell_key("first checkout", "parameter", Some(0));
        let second = lexical_cell_key("second checkout", "parameter", Some(0));

        assert_ne!(first, second, "mounted locators retain exact equality");
        assert_eq!(first.stable_fingerprint(), second.stable_fingerprint());
    }

    #[test]
    fn carrier_fingerprint_is_structured_and_checkout_independent() {
        let first = nested_carrier("first checkout");
        let second = nested_carrier("second checkout");
        assert_ne!(first, second, "mounted locators retain exact equality");
        assert_eq!(first.stable_fingerprint(), second.stable_fingerprint());

        let mut prefix = first.clone();
        let ValueFlowCarrierKey::Location { exact, .. } = &mut prefix else {
            unreachable!("fixture is a location")
        };
        *exact = false;
        assert_ne!(first.stable_fingerprint(), prefix.stable_fingerprint());
    }

    #[test]
    fn carrier_fingerprint_handles_deep_access_paths_iteratively() {
        let locator = locator("mount", SemanticRole::Value, "run");
        let mut carrier = ValueFlowCarrierKey::Value {
            locator,
            role: "seed".into(),
            ordinal: None,
        };
        for index in 0..4_096_u128 {
            carrier = ValueFlowCarrierKey::Location {
                root: Box::new(carrier),
                selectors: vec![ValueFlowSelectorKey::ConstantIndex(index)].into_boxed_slice(),
                exact: true,
            };
        }
        assert_ne!(carrier.stable_fingerprint().as_bytes(), &[0; 32]);
    }

    #[test]
    fn procedure_local_call_boundary_carriers_ignore_preceding_source_movement() {
        let make = |mount: &str, shift: u32, callee_name: &str| {
            let caller = locator_at(
                mount,
                SemanticRole::Procedure,
                "wrapper",
                100 + shift,
                100 + shift,
                140 + shift,
            );
            let call = locator_at(
                mount,
                SemanticRole::CallSite,
                "wrapper",
                100 + shift,
                112 + shift,
                120 + shift,
            );
            let result = locator_at(
                mount,
                SemanticRole::Value,
                "wrapper",
                100 + shift,
                112 + shift,
                120 + shift,
            );
            let callee = locator_at(
                mount,
                SemanticRole::Procedure,
                callee_name,
                20 + shift,
                20 + shift,
                60 + shift,
            );
            let port = ValueFlowCarrierKey::Port {
                procedure: callee.clone(),
                kind: ValueFlowPortKey::Parameter { ordinal: 0 },
            };
            let call_result = ValueFlowCarrierKey::CallResult {
                call,
                result: Box::new(ValueFlowCarrierKey::Allocation { locator: result }),
                callee,
            };
            (caller, port, call_result)
        };

        let (first_caller, first_port, first_result) = make("first", 0, "leaf");
        let (shifted_caller, shifted_port, shifted_result) = make("second", 200, "leaf");
        assert_eq!(
            procedure_local_carrier_digest(&first_port, &first_caller),
            procedure_local_carrier_digest(&shifted_port, &shifted_caller)
        );
        assert_eq!(
            procedure_local_carrier_digest(&first_result, &first_caller),
            procedure_local_carrier_digest(&shifted_result, &shifted_caller),
            "the call and caller-local result move with the caller while the callee uses lineage"
        );

        let (renamed_caller, renamed_port, renamed_result) = make("second", 200, "peer");
        assert_ne!(
            procedure_local_carrier_digest(&first_port, &first_caller),
            procedure_local_carrier_digest(&renamed_port, &renamed_caller)
        );
        assert_ne!(
            procedure_local_carrier_digest(&first_result, &first_caller),
            procedure_local_carrier_digest(&renamed_result, &renamed_caller),
            "changing the logical callee still rotates the boundary carrier"
        );
    }

    #[test]
    fn cross_procedure_events_use_their_declaring_procedure_coordinates() {
        let make = |mount: &str, shift: u32, callee_name: &str, site_offset: u32| {
            let caller = locator_at(
                mount,
                SemanticRole::Procedure,
                "root",
                100 + shift,
                100 + shift,
                140 + shift,
            );
            let procedure = locator_at(
                mount,
                SemanticRole::Procedure,
                callee_name,
                20 + shift,
                20 + shift,
                60 + shift,
            );
            let site = locator_at(
                mount,
                SemanticRole::ProgramPoint,
                callee_name,
                20 + shift,
                20 + shift + site_offset,
                25 + shift + site_offset,
            );
            (
                caller,
                procedure,
                ValueFlowEventKey {
                    site,
                    ordinal: 0,
                    kind: ValueFlowEventKind::Sink,
                },
            )
        };

        let (first_caller, first_procedure, first) = make("first", 0, "wrapper", 10);
        let (shifted_caller, shifted_procedure, shifted) = make("second", 200, "wrapper", 10);
        assert_eq!(
            procedure_local_event_digest(&first, &first_caller),
            procedure_local_event_digest(&shifted, &shifted_caller),
            "a preceding sibling may move both the wrapper and its sink"
        );
        assert_eq!(
            procedure_local_event_digest(&first, &first_procedure),
            procedure_local_event_digest(&shifted, &shifted_procedure),
            "an event remains stable when its own procedure moves intact"
        );

        let (moved_caller, moved_procedure, moved) = make("second", 200, "wrapper", 11);
        assert_ne!(
            procedure_local_event_digest(&first, &first_caller),
            procedure_local_event_digest(&moved, &moved_caller),
            "moving the sink within its declaring procedure rotates the event"
        );
        assert_ne!(
            procedure_local_event_digest(&first, &first_procedure),
            procedure_local_event_digest(&moved, &moved_procedure),
            "same-procedure event identity remains position-sensitive"
        );
        let (renamed_caller, _renamed_procedure, renamed) = make("second", 200, "peer", 10);
        assert_ne!(
            procedure_local_event_digest(&first, &first_caller),
            procedure_local_event_digest(&renamed, &renamed_caller),
            "changing the declaring procedure rotates the event"
        );
    }

    #[test]
    fn event_fingerprint_partitions_kind_and_ordinal_but_not_mount() {
        let event = ValueFlowEventKey {
            site: locator("first checkout", SemanticRole::ProgramPoint, "run"),
            ordinal: 7,
            kind: ValueFlowEventKind::Source,
        };
        let remounted = ValueFlowEventKey {
            site: locator("second checkout", SemanticRole::ProgramPoint, "run"),
            ..event.clone()
        };
        assert_eq!(event.stable_fingerprint(), remounted.stable_fingerprint());

        let changed_ordinal = ValueFlowEventKey {
            ordinal: 8,
            ..event.clone()
        };
        let changed_kind = ValueFlowEventKey {
            kind: ValueFlowEventKind::Sink,
            ..event.clone()
        };
        assert_ne!(
            event.stable_fingerprint(),
            changed_ordinal.stable_fingerprint()
        );
        assert_ne!(
            event.stable_fingerprint(),
            changed_kind.stable_fingerprint()
        );
    }
}
