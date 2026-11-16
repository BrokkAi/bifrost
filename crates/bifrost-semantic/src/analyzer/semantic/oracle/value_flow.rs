use std::hash::Hash;
use std::sync::Arc;

use crate::analyzer::semantic::ids::MemoryLocationId;

use crate::analyzer::semantic::ids::SemanticDigestHasher;

use crate::analyzer::semantic::ir::AsyncResumeKind;

use crate::analyzer::semantic::ir::BackingStoreOffset;

use crate::analyzer::semantic::ir::CallContinuationKind;

use crate::analyzer::semantic::ir::CaptureSource;

use crate::analyzer::semantic::ir::EvidenceCompleteness;

use crate::analyzer::semantic::ir::ExecutionTiming;

use crate::analyzer::semantic::ir::MemoryLocationHandle;

use crate::analyzer::semantic::ir::MemoryLocationKind;

use crate::analyzer::semantic::ir::ProcedureHandle;

use crate::analyzer::semantic::ir::ProgramPointHandle;

use crate::analyzer::semantic::ir::ProofStatus;

use crate::analyzer::semantic::ir::SemanticEffect;

use crate::analyzer::semantic::ir::SemanticValueKind;

use crate::analyzer::semantic::ir::ValueFlowKind;

use crate::analyzer::semantic::ir::ValueHandle;

use crate::analyzer::semantic::ir::ValueTransfer;

use crate::analyzer::semantic::oracle::error::OracleContractError;

use crate::analyzer::semantic::oracle::error::require_same_procedure;

use crate::analyzer::semantic::oracle::limits::OracleLimits;

use crate::analyzer::semantic::oracle::model::AbstractLocation;

use crate::analyzer::semantic::oracle::model::AbstractObjectIdentity;

use crate::analyzer::semantic::oracle::model::AccessPathRoot;

use crate::analyzer::semantic::oracle::model::AccessSelector;

use crate::analyzer::semantic::oracle::model::ExecutionTimingClaim;

use crate::analyzer::semantic::oracle::model::OracleCallContext;

use crate::analyzer::semantic::oracle::model::ProcedurePortHandle;

use crate::analyzer::semantic::oracle::model::ProcedurePortKind;

use crate::analyzer::semantic::oracle::relation::CandidateCoverage;

use crate::analyzer::semantic::oracle::relation::OracleRelationHandle;

use crate::analyzer::semantic::oracle::relation::OracleRelationKind;

use crate::analyzer::semantic::oracle::relation::OracleRelationOwner;

use crate::analyzer::semantic::oracle::relation::validate_retained_relation_arenas;

use crate::analyzer::semantic::ProgramPointId;

use crate::analyzer::semantic::SemanticGapId;

use crate::analyzer::semantic::StableDigest;

use crate::analyzer::semantic::ValueId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValueFlowRelationKind {
    Assignment,
    /// Exact value dependence with unresolved copy/move and storage identity.
    OwnershipUnknown,
    Parameter,
    Receiver,
    /// A returned value flows to its normal return port. A returned member
    /// instead flows to the same selector path rooted at that port, retaining
    /// the field identity for the caller's member reads.
    NormalReturn,
    ExceptionalReturn,
    Allocation,
    MemoryLoad,
    MemoryStore,
    Capture,
    /// The runtime binds a thrown value to a handler's own binding when it
    /// selects that handler (#2446). The source is the thrown value at the
    /// throw site and the target is the procedure-local value the handler
    /// binds it to; the relation rides the `Throw` event that publishes the
    /// value, because that is the exact event whose evidence justifies it.
    HandlerBinding,
    /// Reading a container as a whole reads everything inside it (#2444
    /// slice 2 / #2453). The source is a member or element location of the
    /// object the read is rooted at, and the target is the value that read
    /// produces.
    ///
    /// The direction is strictly element-to-whole and the relation is only
    /// ever published at a *consumption* of the whole value -- an argument, a
    /// receiver, a returned value, or a value stored as a whole. Publishing it
    /// at the read rather than at the member store is what keeps a strong
    /// update (#2444 slice 1) meaningful: the kill has already replaced what
    /// the member location holds by the time this relation reads it, so a
    /// member that was overwritten with a clean value does not resurrect the
    /// value it used to hold. Element-to-element separation, field separation
    /// and every existing kill are unchanged, because nothing here flows out
    /// of the whole value back into a member.
    ContainerCollapse,
    LanguageDefined,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CollapseRead {
    Root,
    Load(Box<[AccessSelector]>),
}

impl ValueFlowRelationKind {
    /// When the target of a relation of this kind is evaluated, relative to
    /// its source (#2446).
    ///
    /// Every point-local transfer publishes both endpoints from one event, so
    /// the two are evaluated by one step. The three that leave the event --
    /// a handler binding, a capture, and a port -- state their own timing
    /// instead of inheriting that assumption.
    pub const fn timing(self) -> ExecutionTiming {
        match self {
            Self::Assignment
            | Self::OwnershipUnknown
            | Self::Allocation
            | Self::MemoryLoad
            | Self::MemoryStore
            // A container collapse rides the event that reads the whole
            // value, so the member it names and the value the read produces
            // are observed by that one evaluation.
            | Self::ContainerCollapse
            | Self::LanguageDefined
            | Self::Parameter
            | Self::Receiver => ExecutionTiming::SameEvaluation,
            // The handler runs while this activation is still unwinding, so
            // the binding is later in the same synchronous invocation.
            Self::HandlerBinding => ExecutionTiming::SameInvocation,
            // A return port is written as this activation completes.
            Self::NormalReturn | Self::ExceptionalReturn => ExecutionTiming::SameInvocation,
            // A captured value is read whenever the capturing callable runs,
            // which nothing in this layer establishes. Lexical nesting is not
            // evidence that it runs now.
            Self::Capture => ExecutionTiming::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ValueFlowEndpoint {
    Value(ValueHandle),
    Port(ProcedurePortHandle),
    Location(Box<AbstractLocation>),
}

impl ValueFlowEndpoint {
    #[doc(hidden)]
    pub fn retained_artifacts(
        &self,
        census: &mut impl crate::analyzer::semantic::service::ArtifactRetentionVisitor,
    ) {
        super::model::collect_retained_model(
            super::model::RetainedModelPart::Endpoint(self),
            census,
        );
    }

    /// The runtime carrier for a value, including a formal binding's port.
    ///
    /// Formal bindings are read through procedure ports. Their assignments
    /// must overwrite those same ports, rather than a disconnected value
    /// carrier that leaves the incoming parameter or receiver alive (#3124).
    /// Locals and expression results are represented directly by values.
    pub fn for_value(value: ValueHandle) -> Self {
        let procedure = value.procedure();
        match procedure
            .semantics()
            .value(value.id())
            .expect("a retained value handle names a live value")
            .kind
        {
            SemanticValueKind::Parameter { ordinal, .. } => Self::Port(
                ProcedurePortHandle::parameter(procedure.clone(), ordinal)
                    .expect("a parameter value has a live parameter port"),
            ),
            SemanticValueKind::Receiver { .. } => Self::Port(
                ProcedurePortHandle::receiver(procedure.clone())
                    .expect("a receiver value has a live receiver port"),
            ),
            _ => Self::Value(value),
        }
    }

    /// Canonicalize a location for value flow. Heap cardinality is evidence
    /// used by update certificates, not a second identity for the flow slot.
    pub fn for_path(
        path: crate::analyzer::semantic::AccessPath,
    ) -> Result<Self, OracleContractError> {
        let cardinality = if matches!(path.root(), AccessPathRoot::TypeSummary(_)) {
            crate::analyzer::semantic::ObjectCardinality::Summary
        } else {
            crate::analyzer::semantic::ObjectCardinality::Unknown
        };
        let object =
            crate::analyzer::semantic::AbstractObject::new(path.root().clone(), cardinality)?;
        Ok(Self::Location(Box::new(AbstractLocation::new(
            object, path,
        )?)))
    }

    fn validate_at(&self, procedure: &ProcedureHandle) -> Result<(), OracleContractError> {
        match self {
            Self::Value(value) => require_same_procedure(value.procedure(), procedure),
            Self::Port(port) => require_same_procedure(port.procedure(), procedure),
            Self::Location(location) => {
                location.object().validate_at(procedure)?;
                location.path().validate_at(procedure)
            }
        }
    }
}

fn value_endpoint(endpoint: &ValueFlowEndpoint, expected: ValueId) -> bool {
    matches!(endpoint, ValueFlowEndpoint::Value(value) if value.id() == expected)
}

fn runtime_value_endpoint(
    procedure: &ProcedureHandle,
    endpoint: &ValueFlowEndpoint,
    expected: ValueId,
) -> bool {
    *endpoint
        == ValueFlowEndpoint::for_value(
            procedure
                .value_handle(expected)
                .expect("a validated effect value is live"),
        )
}

fn port_endpoint(endpoint: &ValueFlowEndpoint, expected: ProcedurePortKind) -> bool {
    matches!(endpoint, ValueFlowEndpoint::Port(port) if port.kind() == expected)
}

/// Whether this exact load location denotes a keyed container element rather
/// than an ordinary named member. Minting and validation share the language rule.
#[doc(hidden)]
pub fn keyed_property_reads_container_element(
    procedure: &ProcedureHandle,
    location: MemoryLocationId,
) -> bool {
    matches!(
        procedure
            .semantics()
            .memory_location(location)
            .expect("memory load names a validated location")
            .kind,
        MemoryLocationKind::Property { .. }
    ) && crate::analyzer::semantic::languages::language_knowledge(
        procedure.artifact().key().language().language(),
    )
    .is_some_and(|support| support.keyed_property_reads_container_element())
}

/// Where one value's defining event took it from.
///
/// This mirrors `workspace_oracle::value_flow::LoadOrigin`, which the minting
/// side's access-path resolver walks, and merges a value more than one event
/// defines differently by the same rule: plain copies from different sources
/// keep every source, as the resolver's definition alternatives do, and any
/// other conflict is `Ambiguous`. The two must answer the same question about
/// the same chain: what the resolver saw is exactly what decides which
/// relations get minted, so what this layer accepts has to be derived from
/// the same walk.
#[derive(PartialEq, Eq)]
enum ValueOrigin {
    Copies(Vec<ValueId>),
    Load(crate::analyzer::semantic::MemoryLocationId),
    Ambiguous,
}

/// The `(target, source)` pair of an event that defines `target` as an
/// unconditional copy of `source`, for the snapshot validator's origin walks.
///
/// It is the set of copy steps the minting side's `LoadOrigin` derivation
/// walks through, so both validator walks must use this one helper: a step the
/// minting walk crosses and a validator walk stops at makes the validator
/// reject a relation the provider minted, failing the run (#9988). A Go
/// assignment conversion is such a step: `var out []string = mk()` defines
/// `out` from the call result through a `go.assignment_conversion` value.
fn copy_definition(
    procedure: &ProcedureHandle,
    effect: &SemanticEffect,
) -> Option<(ValueId, ValueId)> {
    match *effect {
        SemanticEffect::Assignment { target, value } => Some((target, value)),
        SemanticEffect::ValueFlow {
            kind: ValueFlowKind::Local | ValueFlowKind::AddressOf | ValueFlowKind::BackingStore { .. },
            source,
            target,
        } => Some((target, source)),
        SemanticEffect::ValueFlow {
            kind: ValueFlowKind::LanguageDefined,
            source,
            target,
        } if crate::analyzer::semantic::workspace_oracle::value_flow::is_go_assignment_conversion(
            procedure.semantics(),
            target,
        ) =>
        {
            Some((target, source))
        }
        _ => None,
    }
}

/// The resolved access chain behind each memory location this procedure names,
/// derived once and asked about many times.
struct MemoryAccessChains {
    origins: std::collections::HashMap<ValueId, ValueOrigin>,
}

impl MemoryAccessChains {
    /// Read every value's defining copy or load off one pass over this
    /// procedure's events, the way the minting side derives the same map
    /// before it resolves any access path.
    fn derive(procedure: &ProcedureHandle) -> Self {
        let mut origins: std::collections::HashMap<ValueId, ValueOrigin> =
            std::collections::HashMap::new();
        for point in procedure.semantics().points() {
            for event in &point.events {
                let defined =
                    if let Some((target, source)) = copy_definition(procedure, &event.effect) {
                        (target, ValueOrigin::Copies(vec![source]))
                    } else {
                        match event.effect {
                            SemanticEffect::ValueFlow {
                                kind: ValueFlowKind::BackingStoreAlternative { .. },
                                target,
                                ..
                            } => (target, ValueOrigin::Ambiguous),
                            SemanticEffect::ValueFlow {
                                kind: ValueFlowKind::Transfer(_) | ValueFlowKind::OwnershipUnknown,
                                target,
                                ..
                            } => (target, ValueOrigin::Ambiguous),
                            SemanticEffect::MemoryLoad {
                                location, result, ..
                            } => (result, ValueOrigin::Load(location)),
                            _ => continue,
                        }
                    };
                match (origins.get_mut(&defined.0), defined.1) {
                    (None, origin) => {
                        origins.insert(defined.0, origin);
                    }
                    (Some(ValueOrigin::Copies(sources)), ValueOrigin::Copies(more)) => {
                        for source in more {
                            if !sources.contains(&source) {
                                sources.push(source);
                            }
                        }
                    }
                    (Some(existing), origin) => {
                        if *existing != origin {
                            *existing = ValueOrigin::Ambiguous;
                        }
                    }
                }
            }
        }
        Self { origins }
    }

    /// Whether a memory access resolves through an index selector.
    ///
    /// #2453: a subscript is not an identity the analysis can prove apart
    /// across accesses, so an index access publishes its *container* alongside
    /// the exact element it names -- the array reads out of, and writes into,
    /// one smashed cell. When the access-path resolver walked the subscripted
    /// expression back to an origin that a value or a port carries, that
    /// container is a value or a port endpoint rather than a location, so this
    /// is the one memory-access shape whose relation endpoint may be something
    /// other than a location.
    ///
    /// The question is asked of the whole resolved access chain, not only of
    /// the accessed location's own row, because that is the chain the minting
    /// side resolved. `items[0].value` lowers to a `t = items[0]` load followed
    /// by a `t.value` load, so the field access's own row is a `Field`, while
    /// the path the resolver produced for it is `items` with `[0]` then
    /// `.value` on top and therefore mints the array as a container endpoint. A
    /// field selector above an index selector still permits the container
    /// endpoint: the cell that was smashed is the array, not the object the
    /// element holds.
    ///
    /// A chain with no index selector answers `false`, which leaves field
    /// sensitivity exactly as it was. Smashing indices does not change what a
    /// member selector proves, and a purely field-rooted access that published
    /// its base this way would silently make the whole object one cell.
    fn is_indexed(
        &self,
        procedure: &ProcedureHandle,
        location: crate::analyzer::semantic::MemoryLocationId,
    ) -> bool {
        use crate::analyzer::semantic::MemoryLocationKind;

        // A base several copies define is walked through every one of them,
        // because the resolver mints one candidate path per definition and any
        // of them may be the indexed one.
        let mut pending_locations = vec![location];
        let mut pending_values = Vec::new();
        let mut visited_locations = std::collections::HashSet::new();
        let mut visited_values = std::collections::HashSet::new();
        while let Some(current) = pending_locations.pop() {
            if !visited_locations.insert(current) {
                continue;
            }
            let Some(row) = procedure.semantics().memory_location(current) else {
                continue;
            };
            let base = match row.kind {
                MemoryLocationKind::Index { .. } => return true,
                MemoryLocationKind::Field { base, .. }
                | MemoryLocationKind::Property { base, .. }
                | MemoryLocationKind::Dereference { address: base } => base,
                MemoryLocationKind::Static { .. }
                | MemoryLocationKind::LexicalCell { .. }
                | MemoryLocationKind::Capture { .. } => continue,
            };
            // Walk the base back through the unconditional copies that define
            // it, exactly as `walk_value_origin` does, and continue the chain
            // at the location its defining load read.
            pending_values.push(base);
            while let Some(value) = pending_values.pop() {
                match self.origins.get(&value) {
                    Some(ValueOrigin::Copies(sources)) if visited_values.insert(value) => {
                        pending_values.extend(sources.iter().copied());
                    }
                    Some(ValueOrigin::Load(location)) => pending_locations.push(*location),
                    Some(ValueOrigin::Copies(_) | ValueOrigin::Ambiguous) | None => {}
                }
            }
        }
        false
    }
}

/// Whether a relation is the container collapse a whole-value read publishes
/// (#2444 slice 2).
///
/// The read's own event decides which value the whole container arrives in;
/// the collapse names a location inside the object that value denotes. The
/// oracle proves the containment relationship when it derives the relation,
/// which this layer cannot re-derive from one event, so what is checked here
/// is the shape: a location on the source side and the exact value the event
/// defines on the target side.
fn is_container_collapse(relation: &ValueFlowRelation, defined: ValueId) -> bool {
    relation.kind == ValueFlowRelationKind::ContainerCollapse
        && matches!(&relation.source, ValueFlowEndpoint::Location(location)
            if !location.path().selectors().is_empty())
        && value_endpoint(&relation.target, defined)
}

/// A returned container member retains its selector path under the exact
/// return port. The producer resolves containment and the returned prefix with
/// the same structured origin walk used for container collapse; this validator
/// checks the retained projection shape and the event's return-port identity.
fn is_returned_member(relation: &ValueFlowRelation, kind: ProcedurePortKind) -> bool {
    let (ValueFlowEndpoint::Location(source), ValueFlowEndpoint::Location(target)) =
        (&relation.source, &relation.target)
    else {
        return false;
    };
    relation.kind == ValueFlowRelationKind::NormalReturn
        && matches!(target.path().root(), AccessPathRoot::ProcedurePort(port) if port.kind() == kind)
        && !target.path().selectors().is_empty()
        && source
            .path()
            .selectors()
            .ends_with(target.path().selectors())
}

/// A direct capture-slot access uses the same procedure port that a parent
/// `CaptureBind` targets. This is the only memory row whose direct endpoint is
/// a port rather than an abstract location.
fn direct_capture_port_matches(
    procedure: &ProcedureHandle,
    location: crate::analyzer::semantic::MemoryLocationId,
    endpoint: &ValueFlowEndpoint,
) -> bool {
    procedure
        .semantics()
        .memory_location(location)
        .is_some_and(|row| matches!(row.kind, MemoryLocationKind::Capture { .. }))
        && port_endpoint(endpoint, ProcedurePortKind::Capture { slot: location })
}

/// Validate one of the two bounded candidates projected from a backing-store
/// alternative. The candidate either names the fresh allocation directly or
/// names the complete source backing store. The alternative offset is applied
/// only when a later access path composes with the value, not on this event's
/// own whole-backing relation.
fn matches_backing_store_alternative(
    procedure: &ProcedureHandle,
    source: ValueId,
    _offset: BackingStoreOffset,
    allocation: crate::analyzer::semantic::AllocationId,
    endpoint: &ValueFlowEndpoint,
) -> bool {
    let ValueFlowEndpoint::Location(location) = endpoint else {
        return matches!(_offset, BackingStoreOffset::Zero)
            && matches!(endpoint, ValueFlowEndpoint::Value(value) if value.id() == source);
    };
    if matches!(
        location.path().root(),
        AccessPathRoot::Allocation(actual) if actual.id() == allocation
    ) {
        return location.path().selectors().is_empty();
    }
    structured_value_origin_matches_root(procedure, source, location.path().root())
}

/// Whether an access-path root is one of the structured identity origins of a
/// value. Alternative backing rows may materialize their existing-backing arm
/// at an allocation or formal root reached through earlier local/backing rows,
/// so checking only the immediate source value would reject a valid snapshot.
fn structured_value_origin_matches_root(
    procedure: &ProcedureHandle,
    source: ValueId,
    expected: &AccessPathRoot,
) -> bool {
    let mut pending = vec![source];
    let mut visited = std::collections::HashSet::new();
    while let Some(current) = pending.pop() {
        if !visited.insert(current) {
            continue;
        }
        let current_matches = match expected {
            AccessPathRoot::CallResult(_) | AccessPathRoot::LexicalCell(_) => false,
            root => crate::analyzer::semantic::oracle::model::access_root_identity_matches_value(
                root, procedure, current,
            ),
        };
        if current_matches {
            return true;
        }
        for point in procedure.semantics().points() {
            for event in &point.events {
                if let Some((target, source)) = copy_definition(procedure, &event.effect) {
                    if target == current {
                        pending.push(source);
                    }
                    continue;
                }
                match event.effect {
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::BackingStoreAlternative { allocation, .. },
                        source,
                        target,
                    } if target == current => {
                        pending.push(source);
                        if let Some(allocation) = procedure.semantics().allocation(allocation) {
                            pending.push(allocation.result);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    false
}

/// `chains` is derived on the first access shape that needs it and reused for
/// every later relation. Deriving it walks the whole procedure, which most
/// snapshots never need: only a memory access whose relation endpoint is not a
/// location asks this question.
fn relation_matches_event(
    procedure: &ProcedureHandle,
    relation: &ValueFlowRelation,
    effect: &SemanticEffect,
    chains: &mut Option<MemoryAccessChains>,
) -> bool {
    match effect {
        SemanticEffect::Assignment { target, value } => {
            (relation.kind == ValueFlowRelationKind::Assignment
                && relation.transfer.is_none()
                && runtime_value_endpoint(procedure, &relation.source, *value)
                && runtime_value_endpoint(procedure, &relation.target, *target))
                || is_container_collapse(relation, *target)
        }
        SemanticEffect::ValueFlow {
            kind:
                ValueFlowKind::Local | ValueFlowKind::AddressOf | ValueFlowKind::BackingStore { .. },
            source,
            target,
        } => {
            (relation.kind == ValueFlowRelationKind::Assignment
                && relation.transfer.is_none()
                && runtime_value_endpoint(procedure, &relation.source, *source)
                && runtime_value_endpoint(procedure, &relation.target, *target))
                || is_container_collapse(relation, *target)
        }
        SemanticEffect::ValueFlow {
            kind: ValueFlowKind::BackingStoreAlternative { offset, allocation },
            source,
            target,
        } => {
            relation.kind == ValueFlowRelationKind::Assignment
                && relation.transfer.is_none()
                && value_endpoint(&relation.target, *target)
                && matches_backing_store_alternative(
                    procedure,
                    *source,
                    *offset,
                    *allocation,
                    &relation.source,
                )
        }
        SemanticEffect::ValueFlow {
            kind: ValueFlowKind::Transfer(transfer),
            source,
            target,
        } => {
            relation.kind == ValueFlowRelationKind::Assignment
                && relation.transfer == Some(*transfer)
                && runtime_value_endpoint(procedure, &relation.source, *source)
                && runtime_value_endpoint(procedure, &relation.target, *target)
        }
        SemanticEffect::ValueFlow {
            kind: ValueFlowKind::OwnershipUnknown,
            source,
            target,
        } => {
            relation.kind == ValueFlowRelationKind::OwnershipUnknown
                && relation.transfer.is_none()
                && value_endpoint(&relation.source, *source)
                && value_endpoint(&relation.target, *target)
        }
        SemanticEffect::ValueFlow {
            kind: ValueFlowKind::ReferenceBoxing | ValueFlowKind::ReferenceUnboxing,
            source,
            target,
        } => {
            relation.kind == ValueFlowRelationKind::LanguageDefined
                && value_endpoint(&relation.source, *source)
                && value_endpoint(&relation.target, *target)
        }
        SemanticEffect::ValueFlow {
            kind: ValueFlowKind::Parameter,
            source,
            target,
        } => {
            relation.kind == ValueFlowRelationKind::Parameter
                && runtime_value_endpoint(procedure, &relation.source, *source)
                && runtime_value_endpoint(procedure, &relation.target, *target)
        }
        SemanticEffect::ValueFlow {
            kind: ValueFlowKind::Receiver,
            source,
            target,
        } => {
            relation.kind == ValueFlowRelationKind::Receiver
                && runtime_value_endpoint(procedure, &relation.source, *source)
                && runtime_value_endpoint(procedure, &relation.target, *target)
        }
        SemanticEffect::ValueFlow {
            kind: ValueFlowKind::Return,
            source,
            ..
        } => {
            (relation.kind == ValueFlowRelationKind::NormalReturn
                && value_endpoint(&relation.source, *source)
                && port_endpoint(&relation.target, ProcedurePortKind::NormalReturn))
                || is_returned_member(relation, ProcedurePortKind::NormalReturn)
        }
        SemanticEffect::ValueFlow {
            kind: ValueFlowKind::IndexedReturn { ordinal },
            source,
            ..
        } => {
            (relation.kind == ValueFlowRelationKind::NormalReturn
                && value_endpoint(&relation.source, *source)
                && port_endpoint(
                    &relation.target,
                    ProcedurePortKind::IndexedNormalReturn { ordinal: *ordinal },
                ))
                || is_returned_member(
                    relation,
                    ProcedurePortKind::IndexedNormalReturn { ordinal: *ordinal },
                )
        }
        SemanticEffect::ValueFlow {
            kind:
                ValueFlowKind::MemoryLoad { .. }
                | ValueFlowKind::LanguageDefined
                | ValueFlowKind::ByValueCapture
                | ValueFlowKind::IntegerOffset { .. },
            source,
            target,
        } => {
            relation.kind == ValueFlowRelationKind::LanguageDefined
                && value_endpoint(&relation.source, *source)
                && value_endpoint(&relation.target, *target)
        }
        SemanticEffect::ValueUse { .. } => false,
        SemanticEffect::Allocation { allocation } => procedure
            .semantics()
            .allocation(*allocation)
            .is_some_and(|row| {
                relation.kind == ValueFlowRelationKind::Allocation
                    && matches!(
                        &relation.source,
                        ValueFlowEndpoint::Location(location)
                            if matches!(
                                location.object().identity(),
                                AbstractObjectIdentity::Allocation(actual)
                                    if actual.id() == *allocation
                            )
                    )
                    && value_endpoint(&relation.target, row.result)
            }),
        SemanticEffect::MemoryLoad {
            location, result, ..
        } => {
            (relation.kind == ValueFlowRelationKind::MemoryLoad
                && (matches!(&relation.source, ValueFlowEndpoint::Location(_))
                    || direct_capture_port_matches(procedure, *location, &relation.source)
                    || keyed_property_reads_container_element(procedure, *location)
                    || chains
                        .get_or_insert_with(|| MemoryAccessChains::derive(procedure))
                        .is_indexed(procedure, *location))
                && value_endpoint(&relation.target, *result))
                || is_container_collapse(relation, *result)
        }
        SemanticEffect::MemoryStore {
            location, value, ..
        } => {
            relation.kind == ValueFlowRelationKind::MemoryStore
                && runtime_value_endpoint(procedure, &relation.source, *value)
                && (matches!(&relation.target, ValueFlowEndpoint::Location(_))
                    || direct_capture_port_matches(procedure, *location, &relation.target)
                    || chains
                        .get_or_insert_with(|| MemoryAccessChains::derive(procedure))
                        .is_indexed(procedure, *location))
        }
        SemanticEffect::CaptureBind { capture } => {
            procedure.semantics().capture(*capture).is_some_and(|row| {
                let source_matches = match (row.captured, &relation.source) {
                    (CaptureSource::Value(expected), ValueFlowEndpoint::Value(actual)) => {
                        actual.id() == expected
                    }
                    (CaptureSource::Location(expected), ValueFlowEndpoint::Location(actual)) => {
                        matches!(
                            actual.object().identity(),
                            AbstractObjectIdentity::LexicalCell(location)
                                if location.id() == expected
                        )
                    }
                    _ => false,
                };
                relation.kind == ValueFlowRelationKind::Capture
                    && source_matches
                    && matches!(
                        &relation.target,
                        ValueFlowEndpoint::Port(port)
                            if port.procedure().id() == row.target
                                && port.kind()
                                    == ProcedurePortKind::Capture { slot: row.destination }
                    )
            })
        }
        // A thrown value publishes two relation families from one event: it
        // leaves the procedure through the exceptional-return port, and, when
        // a handler in this procedure can select the throw, the runtime binds
        // it to that handler's own binding (#2446). Both are justified by this
        // event's evidence, so both ride it.
        SemanticEffect::Throw { value: Some(value) } => match relation.kind {
            ValueFlowRelationKind::ExceptionalReturn => {
                value_endpoint(&relation.source, *value)
                    && port_endpoint(&relation.target, ProcedurePortKind::ExceptionalReturn)
            }
            ValueFlowRelationKind::HandlerBinding => {
                value_endpoint(&relation.source, *value)
                    && matches!(&relation.target, ValueFlowEndpoint::Value(_))
            }
            _ => false,
        },
        // A call's exceptional continuation relays the callee's exception,
        // which the call names as its `thrown` value, toward this procedure's
        // own exceptional-return port (#8804).
        SemanticEffect::CallContinuation {
            call_site,
            kind: CallContinuationKind::Exceptional,
        } => {
            relation.kind == ValueFlowRelationKind::ExceptionalReturn
                && procedure
                    .semantics()
                    .call_site(*call_site)
                    .and_then(|row| row.thrown)
                    .is_some_and(|thrown| value_endpoint(&relation.source, thrown))
                && port_endpoint(&relation.target, ProcedurePortKind::ExceptionalReturn)
        }
        SemanticEffect::AsyncResume {
            suspend,
            kind: AsyncResumeKind::Normal,
            result: Some(result),
        } => {
            relation.kind == ValueFlowRelationKind::LanguageDefined
                && procedure
                    .semantics()
                    .awaited_value(*suspend)
                    .is_some_and(|awaited| value_endpoint(&relation.source, awaited))
                && value_endpoint(&relation.target, *result)
        }
        _ => false,
    }
}

fn validate_capture_flow(
    procedure: &ProcedureHandle,
    source: &ValueFlowEndpoint,
    target: &ValueFlowEndpoint,
) -> Result<(), OracleContractError> {
    source.validate_at(procedure)?;
    let ValueFlowEndpoint::Port(target) = target else {
        return Err(OracleContractError::CrossProcedure);
    };
    let ProcedurePortKind::Capture { slot } = target.kind() else {
        return Err(OracleContractError::CrossProcedure);
    };
    let child = target.procedure();
    if !Arc::ptr_eq(procedure.artifact(), child.artifact())
        || child.semantics().lexical_parent() != Some(procedure.id())
    {
        return Err(OracleContractError::CrossProcedure);
    }

    let matches_source = |captured: CaptureSource| match (captured, source) {
        (CaptureSource::Value(expected), ValueFlowEndpoint::Value(actual)) => {
            actual.id() == expected
        }
        (CaptureSource::Location(expected), ValueFlowEndpoint::Location(actual)) => {
            matches!(
                actual.object().identity(),
                AbstractObjectIdentity::LexicalCell(location) if location.id() == expected
            )
        }
        (CaptureSource::Value(_), _) | (CaptureSource::Location(_), _) => false,
    };
    if !procedure.semantics().captures().iter().any(|capture| {
        capture.target == child.id()
            && capture.destination == slot
            && matches_source(capture.captured)
    }) {
        return Err(OracleContractError::InvalidRelationIdentity);
    }
    Ok(())
}

/// Producer-attested role of a dependency published by a memory operation.
/// Roles do not establish endpoint resolution, proof, or completeness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemoryRelationRole {
    Canonical,
    Alternative,
    Supplemental,
}

/// Procedure-local origin carried by an immutable relation-arena record.
/// Obtain scoped identity through `ValueFlowRelation::memory_operation_key`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MemoryRelationOrigin {
    point: ProgramPointId,
    event_index: u32,
    location: MemoryLocationId,
    role: MemoryRelationRole,
}

impl MemoryRelationOrigin {
    pub(crate) const fn new(
        point: ProgramPointId,
        event_index: u32,
        location: MemoryLocationId,
        role: MemoryRelationRole,
    ) -> Self {
        Self {
            point,
            event_index,
            location,
            role,
        }
    }

    pub const fn role(&self) -> MemoryRelationRole {
        self.role
    }
}

/// Exact query-local memory operation, including its artifact and call context.
/// This key is not a durable or cross-process identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MemoryOperationKey<'a> {
    pub point: &'a ProgramPointHandle,
    pub event_index: u32,
    pub location: MemoryLocationHandle,
    pub context: &'a OracleCallContext,
}

/// Payload for constructing a relation without producer memory authority.
/// The trusted materializer moves the same payload into a sealed memory row.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ValueFlowRelationPayload {
    pub point: ProgramPointHandle,
    pub event_index: u32,
    pub kind: ValueFlowRelationKind,
    pub transfer: Option<ValueTransfer>,
    pub source: ValueFlowEndpoint,
    pub target: ValueFlowEndpoint,
    pub collapse_read: Option<CollapseRead>,
    pub proof: ProofStatus,
    pub completeness: EvidenceCompleteness,
    pub strong_update: bool,
    pub direct_cell_overwrite: bool,
}

/// Borrowed view keeps producer and validator hashing the same typed payload.
#[derive(Hash)]
struct ValueFlowPayloadRef<'a> {
    point: &'a ProgramPointHandle,
    event_index: u32,
    kind: ValueFlowRelationKind,
    transfer: &'a Option<ValueTransfer>,
    source: &'a ValueFlowEndpoint,
    target: &'a ValueFlowEndpoint,
    collapse_read: &'a Option<CollapseRead>,
    proof: &'a ProofStatus,
    completeness: &'a EvidenceCompleteness,
    strong_update: bool,
    direct_cell_overwrite: bool,
}

impl ValueFlowPayloadRef<'_> {
    fn memory_seal(
        &self,
        origin: &MemoryRelationOrigin,
        context: &OracleCallContext,
    ) -> StableDigest {
        let mut digest = SemanticDigestHasher::new(b"bifrost-query-local-memory-relation-seal-v1");
        (context, origin, self).hash(&mut digest);
        digest.finish_digest()
    }
}

impl ValueFlowRelationPayload {
    fn as_ref(&self) -> ValueFlowPayloadRef<'_> {
        ValueFlowPayloadRef {
            point: &self.point,
            event_index: self.event_index,
            kind: self.kind,
            transfer: &self.transfer,
            source: &self.source,
            target: &self.target,
            collapse_read: &self.collapse_read,
            proof: &self.proof,
            completeness: &self.completeness,
            strong_update: self.strong_update,
            direct_cell_overwrite: self.direct_cell_overwrite,
        }
    }

    pub(crate) fn memory_seal(
        &self,
        origin: &MemoryRelationOrigin,
        context: &OracleCallContext,
    ) -> StableDigest {
        self.as_ref().memory_seal(origin, context)
    }
}

/// One materialized value-flow relation.  Relation IDs provide stable identity
/// inside this oracle materialization without imposing any weight algebra.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ValueFlowRelation {
    /// Exact semantic program point whose event publishes this relation.
    pub point: ProgramPointHandle,
    /// Zero-based event ordinal within [`ValueFlowRelation::point`].
    pub event_index: u32,
    pub id: OracleRelationHandle,
    pub kind: ValueFlowRelationKind,
    /// Exact identity-separating transfer semantics when this relation was
    /// projected from [`ValueFlowKind::Transfer`]. Ordinary dependencies carry
    /// `None`.
    ///
    /// Keeping this metadata on an assignment relation lets generic clients
    /// retain data dependence while identity-sensitive consumers distinguish
    /// copies, moves, conversions and boxing.
    pub transfer: Option<ValueTransfer>,
    pub source: ValueFlowEndpoint,
    pub target: ValueFlowEndpoint,
    pub collapse_read: Option<CollapseRead>,
    pub proof: ProofStatus,
    pub completeness: EvidenceCompleteness,
    /// Whether this store holds a [`StrongUpdateCertificate`] at its own site
    /// (#2444).
    ///
    /// Only a `MemoryStore` relation can set this. A flow client that carries
    /// the overwritten location may replace, rather than join, the facts at
    /// that carrier; every other relation joins as before. The flag is the
    /// certificate's verdict and not the certificate itself, because the
    /// certificate retains a relation arena scoped to the query that issued it
    /// and a snapshot outlives that query.
    ///
    /// [`StrongUpdateCertificate`]: super::heap::StrongUpdateCertificate
    pub strong_update: bool,
    /// Exact direct lexical-cell replacement before any possible publication.
    /// This is a local write verdict, independent of heap escape certification.
    /// It does not establish complete capture execution or non-escape.
    pub direct_cell_overwrite: bool,
    // Independent original-row authority survives public payload/id mutation.
    pub(crate) original_cell: Option<AbstractLocation>,
    memory_seal: Option<StableDigest>,
}

impl ValueFlowRelation {
    /// Sufficient borrowed content correspondence; grants no admission authority.
    /// Executable handles retain their exact artifact and interpretation equality.
    #[doc(hidden)]
    fn has_same_content_by(
        &self,
        other: &Self,
        same_relation: &impl Fn(&OracleRelationHandle, &OracleRelationHandle) -> bool,
    ) -> bool {
        let Self {
            point: l_point,
            event_index: l_event_index,
            id: l_id,
            kind: l_kind,
            transfer: l_transfer,
            source: l_source,
            target: l_target,
            collapse_read: l_collapse_read,
            proof: l_proof,
            completeness: l_completeness,
            strong_update: l_strong_update,
            direct_cell_overwrite: l_direct_cell_overwrite,
            original_cell: l_original_cell,
            memory_seal: l_memory_seal,
        } = self;
        let Self {
            point: r_point,
            event_index: r_event_index,
            id: r_id,
            kind: r_kind,
            transfer: r_transfer,
            source: r_source,
            target: r_target,
            collapse_read: r_collapse_read,
            proof: r_proof,
            completeness: r_completeness,
            strong_update: r_strong_update,
            direct_cell_overwrite: r_direct_cell_overwrite,
            original_cell: r_original_cell,
            memory_seal: r_memory_seal,
        } = other;

        l_point == r_point
            && l_event_index == r_event_index
            && same_relation(l_id, r_id)
            && l_kind == r_kind
            && l_transfer == r_transfer
            && l_source == r_source
            && l_target == r_target
            && l_collapse_read == r_collapse_read
            && l_proof == r_proof
            && l_completeness == r_completeness
            && l_strong_update == r_strong_update
            && l_direct_cell_overwrite == r_direct_cell_overwrite
            && l_original_cell == r_original_cell
            && l_memory_seal == r_memory_seal
    }
}

impl ValueFlowRelation {
    pub(super) fn retained_artifacts(
        &self,
        census: &mut impl crate::analyzer::semantic::service::ArtifactRetentionVisitor,
    ) {
        super::model::collect_retained_model(
            super::model::RetainedModelPart::Relation(self),
            census,
        );
    }

    /// Construct an unsealed row. This grants no memory-operation authority.
    /// A snapshot rejects it at a memory event, even with a borrowed sealed ID.
    pub fn unsealed(id: OracleRelationHandle, payload: ValueFlowRelationPayload) -> Self {
        Self {
            point: payload.point,
            event_index: payload.event_index,
            id,
            kind: payload.kind,
            transfer: payload.transfer,
            source: payload.source,
            target: payload.target,
            collapse_read: payload.collapse_read,
            proof: payload.proof,
            completeness: payload.completeness,
            strong_update: payload.strong_update,
            direct_cell_overwrite: payload.direct_cell_overwrite,
            original_cell: None,
            memory_seal: None,
        }
    }

    pub(crate) fn sealed(
        id: OracleRelationHandle,
        payload: ValueFlowRelationPayload,
        seal: StableDigest,
    ) -> Self {
        let mut relation = Self::unsealed(id, payload);
        relation.memory_seal = Some(seal);
        relation
    }

    fn as_payload_ref(&self) -> ValueFlowPayloadRef<'_> {
        ValueFlowPayloadRef {
            point: &self.point,
            event_index: self.event_index,
            kind: self.kind,
            transfer: &self.transfer,
            source: &self.source,
            target: &self.target,
            collapse_read: &self.collapse_read,
            proof: &self.proof,
            completeness: &self.completeness,
            strong_update: self.strong_update,
            direct_cell_overwrite: self.direct_cell_overwrite,
        }
    }

    /// Return producer origin only while both the original row and immutable
    /// arena record attest this exact payload, namespace, and call context.
    pub fn memory_origin(&self) -> Option<&MemoryRelationOrigin> {
        let original = self.memory_seal?;
        if self.id.record().kind() != OracleRelationKind::ValueFlow {
            return None;
        }
        let binding = self.id.record().memory_origin_binding()?;
        let OracleRelationOwner::ProcedureValueFlow { procedure, context } = self.id.owner() else {
            return None;
        };
        if procedure != self.point.procedure() {
            return None;
        }
        let origin = binding.origin();
        if origin.point != self.point.id() || origin.event_index != self.event_index {
            return None;
        }
        let point = procedure.semantics().point(self.point.id())?;
        let event = point.events.get(self.event_index as usize)?;
        let direction_matches = match event.effect {
            SemanticEffect::MemoryLoad { location, .. } => {
                location == origin.location
                    && match origin.role {
                        MemoryRelationRole::Canonical | MemoryRelationRole::Alternative => {
                            self.kind == ValueFlowRelationKind::MemoryLoad
                        }
                        MemoryRelationRole::Supplemental => matches!(
                            self.kind,
                            ValueFlowRelationKind::MemoryLoad
                                | ValueFlowRelationKind::ContainerCollapse
                        ),
                    }
            }
            SemanticEffect::MemoryStore { location, .. } => {
                location == origin.location && self.kind == ValueFlowRelationKind::MemoryStore
            }
            _ => false,
        };
        if !direction_matches
            || original != binding.seal()
            || original != self.as_payload_ref().memory_seal(origin, context)
        {
            return None;
        }
        Some(origin)
    }

    pub fn memory_operation_key(&self) -> Option<MemoryOperationKey<'_>> {
        let origin = self.memory_origin()?;
        let OracleRelationOwner::ProcedureValueFlow { procedure, context } = self.id.owner() else {
            return None;
        };
        Some(MemoryOperationKey {
            point: &self.point,
            event_index: origin.event_index,
            location: procedure.memory_location_handle(origin.location)?,
            context,
        })
    }

    fn has_valid_memory_authority(&self, effect: &SemanticEffect) -> bool {
        if matches!(
            effect,
            SemanticEffect::MemoryLoad { .. } | SemanticEffect::MemoryStore { .. }
        ) {
            self.memory_origin().is_some()
        } else {
            self.memory_seal.is_none() && self.id.record().memory_origin_binding().is_none()
        }
    }
    /// Whether this dependency also establishes unchanged runtime class.
    /// Element-to-container dependence and language computations are not
    /// class identity. Retain them for value-flow, but not for class copying.
    fn preserves_runtime_class(&self, chains: &mut Option<MemoryAccessChains>) -> bool {
        let point = self
            .point
            .procedure()
            .semantics()
            .point(self.point.id())
            .expect("a validated relation belongs to a retained point");
        let index = self.event_index as usize;
        let event = &point.events[index];
        match self.kind {
            ValueFlowRelationKind::Assignment => match event.effect {
                SemanticEffect::Assignment { .. } => {
                    // The immediately following marker overrides the plain
                    // assignment for identity consumers. Only its own row
                    // can establish whether the transfer preserves class.
                    !point.assignment_has_transfer_marker(index)
                }
                SemanticEffect::ValueFlow { kind, .. } => kind.preserves_runtime_class(),
                _ => unreachable!("validated assignment relation has an assignment event"),
            },
            ValueFlowRelationKind::MemoryLoad | ValueFlowRelationKind::MemoryStore => {
                let (location, endpoint) = match event.effect {
                    SemanticEffect::MemoryLoad { location, .. } => (location, &self.source),
                    SemanticEffect::MemoryStore { location, .. } => (location, &self.target),
                    _ => unreachable!("validated memory relation has a memory event"),
                };
                let procedure = self.point.procedure();
                if matches!(
                    procedure
                        .semantics()
                        .memory_location(location)
                        .expect("validated memory location")
                        .kind,
                    MemoryLocationKind::Index {
                        identity: super::super::ir::IndexedLocationIdentity::Aggregate,
                        ..
                    }
                ) {
                    return false;
                }
                // A keyed element's container/base dependence carries taint,
                // never the container's runtime class into the stored value.
                if keyed_property_reads_container_element(procedure, location)
                    && self
                        .memory_origin()
                        .is_some_and(|origin| origin.role() == MemoryRelationRole::Supplemental)
                {
                    return false;
                }
                // Indexed accesses also publish dependencies on the whole
                // container. Only an element location transports its stored
                // value's class; the container/base endpoint does not.
                !chains
                    .get_or_insert_with(|| MemoryAccessChains::derive(procedure))
                    .is_indexed(procedure, location)
                    || matches!(endpoint, ValueFlowEndpoint::Location(location)
                        if location.path().selectors().iter().any(|selector|
                            matches!(selector, AccessSelector::Index(_))))
            }
            ValueFlowRelationKind::Parameter
            | ValueFlowRelationKind::Receiver
            | ValueFlowRelationKind::NormalReturn
            | ValueFlowRelationKind::ExceptionalReturn
            | ValueFlowRelationKind::Capture
            | ValueFlowRelationKind::HandlerBinding => true,
            // Allocation classes are independently seeded at the allocation
            // result, never inherited from the abstract object's contents.
            ValueFlowRelationKind::Allocation
            | ValueFlowRelationKind::OwnershipUnknown
            | ValueFlowRelationKind::ContainerCollapse
            | ValueFlowRelationKind::LanguageDefined => false,
        }
    }

    pub fn point(&self) -> &ProgramPointHandle {
        &self.point
    }

    pub const fn event_index(&self) -> u32 {
        self.event_index
    }

    pub const fn is_proven_complete(&self) -> bool {
        self.proof.establishes_complete_evidence(&self.completeness)
    }

    /// When this relation's target is evaluated relative to its source, at the
    /// quality this relation's own evidence supports (#2446).
    ///
    /// The timing comes from the relation family and the carriers come from
    /// the relation, so a consumer never has to decide separately whether the
    /// timing is trustworthy: an unproven relation carries an unproven timing.
    pub fn timing_claim(&self) -> ExecutionTimingClaim {
        let timing = self.kind.timing();
        if matches!(timing, ExecutionTiming::Unknown) {
            return ExecutionTimingClaim::unknown(
                "this relation family does not establish when its target is evaluated",
            );
        }
        ExecutionTimingClaim::new(timing, self.proof.clone(), self.completeness.clone())
    }
}

/// Query-local receiver storage selected for one exact deferred member call.
/// Empty storage leaves a storage-dependent receiver port unbound; a method
/// whose summary never consumes or writes that port needs no such storage.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MemberReceiverFlow {
    call: crate::analyzer::semantic::CallSiteHandle,
    preparation: Option<crate::analyzer::semantic::MemberReceiverPreparation>,
    storage: Box<[ValueFlowEndpoint]>,
    field_read: Option<Box<MemberFieldRead>>,
}

/// A field load selected at the exact callable-reference event, before arguments.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MemberFieldRead {
    point: ProgramPointHandle,
    event_index: u32,
    source: ValueFlowEndpoint,
}

impl MemberReceiverFlow {
    pub fn new(
        call: crate::analyzer::semantic::CallSiteHandle,
        preparation: Option<crate::analyzer::semantic::MemberReceiverPreparation>,
        storage: Vec<ValueFlowEndpoint>,
        limits: OracleLimits,
    ) -> Result<Self, OracleContractError> {
        let row = call
            .procedure()
            .semantics()
            .call_site(call.id())
            .ok_or(OracleContractError::InvalidRelationIdentity)?;
        if row.member_selection.is_none() || (preparation.is_none() && !storage.is_empty()) {
            return Err(OracleContractError::InvalidRelationIdentity);
        }
        if storage.len() > limits.provenance_records() {
            return Err(OracleContractError::LimitExceeded {
                dimension: "member_receiver_storage",
                limit: limits.provenance_records(),
                attempted: storage.len(),
            });
        }
        for endpoint in &storage {
            endpoint.validate_at(call.procedure())?;
        }
        Ok(Self {
            call,
            preparation,
            storage: storage.into_boxed_slice(),
            field_read: None,
        })
    }

    /// Retain the load of a proven field without claiming its layout is resolved.
    /// The caller supplies the occurrence identity, never an interned member name.
    pub fn with_field_read(
        mut self,
        point: ProgramPointHandle,
        event_index: u32,
        source: ValueFlowEndpoint,
    ) -> Result<Self, OracleContractError> {
        require_same_procedure(point.procedure(), self.call.procedure())?;
        source.validate_at(self.call.procedure())?;
        let row = self
            .call
            .procedure()
            .semantics()
            .call_site(self.call.id())
            .ok_or(OracleContractError::InvalidRelationIdentity)?;
        let event = self
            .call
            .procedure()
            .semantics()
            .point(point.id())
            .and_then(|point| point.events.get(event_index as usize))
            .ok_or(OracleContractError::InvalidRelationIdentity)?;
        if self.preparation.is_some()
            || !matches!(event.effect,
            SemanticEffect::CallableReference { result, .. } if result == row.callee)
            || !matches!(source, ValueFlowEndpoint::Location(_))
        {
            return Err(OracleContractError::InvalidRelationIdentity);
        }
        self.field_read = Some(Box::new(MemberFieldRead {
            point,
            event_index,
            source,
        }));
        Ok(self)
    }

    pub fn call(&self) -> &crate::analyzer::semantic::CallSiteHandle {
        &self.call
    }
    pub const fn preparation(
        &self,
    ) -> Option<crate::analyzer::semantic::MemberReceiverPreparation> {
        self.preparation
    }
    pub fn storage(&self) -> &[ValueFlowEndpoint] {
        &self.storage
    }

    /// The entries this flow keeps once it is part of a snapshot: one for each
    /// storage endpoint and one for the field read, if any.
    pub fn retained_entries(&self) -> usize {
        self.storage.len() + usize::from(self.field_read.is_some())
    }

    /// Selecting a value method from a pointer must first read its pointee,
    /// even when the selected body or summary never consumes the receiver.
    pub fn selection_is_complete(&self) -> bool {
        match self.preparation {
            None => false,
            Some(crate::analyzer::semantic::MemberReceiverPreparation::CopyPointee) => {
                !self.storage.is_empty()
            }
            Some(_) => true,
        }
    }

    /// The selected receiver's dependencies before invocation and after return.
    /// Copies read their source storage and never write back into it.
    pub fn transfers(&self) -> impl Iterator<Item = MemberReceiverTransfer> + '_ {
        self.storage.iter().flat_map(|storage| {
            let procedure = self.call.procedure();
            let row = procedure.semantics().call_site(self.call.id()).expect("a selected member call exists");
            let receiver = ValueFlowEndpoint::for_value(procedure.value_handle(row.receiver.expect("a member receiver exists"))
                .expect("a member receiver value exists"));
            let point = procedure.point_handle(row.point).expect("a call point exists");
            let event_index = u32::try_from(procedure.semantics().point(row.point).expect("a call point exists").events.iter()
                .position(|event| matches!(event.effect, SemanticEffect::Invoke { call_site } if call_site == row.id))
                .expect("a call point invokes its call")).expect("an event index fits u32");
            let read = MemberReceiverTransfer { point, event_index, source: storage.clone(), target: receiver.clone(), before_call: true, proof: ProofStatus::Proven, completeness: EvidenceCompleteness::Complete };
            let write = matches!(self.preparation, Some(crate::analyzer::semantic::MemberReceiverPreparation::Reference
                | crate::analyzer::semantic::MemberReceiverPreparation::AddressOfPlace))
                .then(|| row.normal_continuation.target()).flatten().map(|normal| {
                    let point = procedure.point_handle(normal).expect("a normal continuation exists");
                    let event_index = u32::try_from(procedure.semantics().point(normal).expect("a normal continuation exists").events.iter()
                        .position(|event| matches!(event.effect, SemanticEffect::CallContinuation { call_site, .. } if call_site == row.id))
                        .expect("a normal continuation names its call")).expect("an event index fits u32");
                    MemberReceiverTransfer { point, event_index, source: receiver, target: storage.clone(), before_call: false, proof: ProofStatus::Proven, completeness: EvidenceCompleteness::Complete }
                });
            [Some(read), write].into_iter().flatten()
        }).chain(self.field_read.iter().map(|read| {
            let row = self.call.procedure().semantics().call_site(self.call.id())
                .expect("a member call exists");
            MemberReceiverTransfer {
                point: read.point.clone(), event_index: read.event_index,
                source: read.source.clone(), target: ValueFlowEndpoint::for_value(
                    self.call.procedure().value_handle(row.callee).expect("a member callee exists")),
                before_call: false,
                proof: ProofStatus::Unproven("selected field layout requires refinement".into()),
                completeness: EvidenceCompleteness::Partial("selected field layout requires refinement".into()),
            }
        }))
    }
}

/// A query-time dependency of a receiver selected from an open member call.
#[derive(Debug, Clone)]
pub struct MemberReceiverTransfer {
    pub point: ProgramPointHandle,
    pub event_index: u32,
    pub source: ValueFlowEndpoint,
    pub target: ValueFlowEndpoint,
    pub before_call: bool,
    pub proof: ProofStatus,
    pub completeness: EvidenceCompleteness,
}

/// A call on a closed local container whose complete collection-flow contract
/// the projection bound to heap cells (#10989).
///
/// The container is created in this procedure and every use of it is a call
/// the contract models, so the contract describes everything the call does
/// to it. The summary's transfers into and out of the receiver, which
/// collapse every key and element onto the container object, therefore do not
/// apply at the call's normal continuation; `transfers` publish the
/// contract's stores and loads on the container's per-key cells instead.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CollectionCellBinding {
    call: crate::analyzer::semantic::CallSiteHandle,
    transfers: Box<[CollectionCellTransfer]>,
}

/// One store into, or load from, a container cell, published at the bound
/// call's normal continuation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CollectionCellTransfer {
    pub point: ProgramPointHandle,
    pub event_index: u32,
    pub source: ValueFlowEndpoint,
    pub target: ValueFlowEndpoint,
}

impl CollectionCellBinding {
    #[doc(hidden)]
    pub fn new(
        call: crate::analyzer::semantic::CallSiteHandle,
        transfers: Vec<CollectionCellTransfer>,
    ) -> Self {
        Self {
            call,
            transfers: transfers.into_boxed_slice(),
        }
    }

    pub fn call(&self) -> &crate::analyzer::semantic::CallSiteHandle {
        &self.call
    }

    pub fn transfers(&self) -> &[CollectionCellTransfer] {
        &self.transfers
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ValueFlowSnapshot {
    /// Query-time execution dependence; never persisted with partial flows.
    execution_dependent: bool,
    procedure: ProcedureHandle,
    context: OracleCallContext,
    backing: Arc<ValueFlowSnapshotBacking>,
    /// Only this selected root may discharge this exact additional gap.
    selected_entry_gap: Option<SemanticGapId>,
    coverage: CandidateCoverage,
    /// The workspace proof could not discharge a lowered Go builtin assumption.
    unproven_go_builtin_assumptions: bool,
}

/// Immutable query-time rows shared by plain and selected-root snapshots.
/// Explicit row filtering uses copy-on-write; selecting an entry never does.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ValueFlowSnapshotBacking {
    relations: Box<[ValueFlowRelation]>,
    /// Gaps on this snapshot's procedure that a query-time discharge
    /// predicate proved do not apply, computed once while this snapshot was
    /// materialized (#2545).
    ///
    /// A gap's presence in the procedure's own IR never changes once
    /// lowering runs; whether it actually blocks anything is a query-time
    /// judgment ([`super::super::workspace_oracle::gap_impacts_value_flow`]
    /// composed with each discharge predicate). Before this field existed, a
    /// downstream consumer that needed to re-examine this snapshot's raw
    /// gaps (`ValueFlowPlan`'s own-procedure "refinable" residual check) had
    /// no way to see that judgment and had to either duplicate every
    /// discharge predicate or treat every non-refinement-shaped gap as
    /// permanently blocking, even one this snapshot's own construction had
    /// already proven discharged. Carrying the discharged set as data lets a
    /// consumer trust this snapshot's own judgment without re-deriving it
    /// and without needing the query-time analyzer access that judgment
    /// required.
    discharged_gaps: Box<[crate::analyzer::semantic::GapKey]>,
    /// Known omissions from the materialized relation list (#9766).
    omission_causes: Box<[ValueFlowOmissionCause]>,
    member_receivers: Box<[MemberReceiverFlow]>,
    /// Calls whose collection contract replaced their summary (#10989).
    collection_cells: Box<[CollectionCellBinding]>,
    payload_projection: super::SelectedPayloadProjection,
}

impl ValueFlowSnapshotBacking {
    /// Sufficient borrowed content correspondence; grants no admission authority.
    /// Executable handles retain their exact artifact and interpretation equality.
    #[doc(hidden)]
    fn has_same_content(&self, other: &Self) -> bool {
        let Self {
            relations: l_relations,
            discharged_gaps: l_discharged_gaps,
            member_receivers: l_member_receivers,
            collection_cells: l_collection_cells,
            payload_projection: l_payload_projection,
            omission_causes: l_omission_causes,
        } = self;
        let Self {
            relations: r_relations,
            discharged_gaps: r_discharged_gaps,
            member_receivers: r_member_receivers,
            collection_cells: r_collection_cells,
            payload_projection: r_payload_projection,
            omission_causes: r_omission_causes,
        } = other;

        l_relations.len() == r_relations.len()
            && match (l_relations.first(), r_relations.first()) {
                (None, None) => true,
                (Some(l), Some(r)) => {
                    l.id.has_same_arena_content(&r.id)
                        && l_relations.iter().zip(r_relations.iter()).all(|(a, b)| {
                            a.has_same_content_by(b, &|x, y| {
                                x.same_arena(&l.id) && y.same_arena(&r.id) && x.id() == y.id()
                            })
                        })
                }
                _ => false,
            }
            && l_discharged_gaps == r_discharged_gaps
            && l_member_receivers == r_member_receivers
            && l_collection_cells == r_collection_cells
            && l_payload_projection == r_payload_projection
            && l_omission_causes == r_omission_causes
    }
}

impl ValueFlowSnapshotBacking {
    fn retained_bytes(&self) -> usize {
        let mut bytes = std::mem::size_of::<Self>()
            .saturating_add(2 * std::mem::size_of::<usize>())
            .saturating_add(std::mem::size_of_val(self.relations.as_ref()))
            .saturating_add(std::mem::size_of_val(self.discharged_gaps.as_ref()))
            .saturating_add(std::mem::size_of_val(self.omission_causes.as_ref()))
            .saturating_add(std::mem::size_of_val(self.member_receivers.as_ref()))
            .saturating_add(std::mem::size_of_val(self.collection_cells.as_ref()));
        for relation in &self.relations {
            bytes = bytes
                .saturating_add(relation.proof.retained_heap_bytes())
                .saturating_add(relation.completeness.retained_heap_bytes());
        }
        for receiver in &self.member_receivers {
            bytes = bytes
                .saturating_add(std::mem::size_of_val(receiver.storage.as_ref()))
                .saturating_add(
                    receiver
                        .field_read
                        .as_ref()
                        .map_or(0, |read| std::mem::size_of_val(read.as_ref())),
                );
        }
        for binding in &self.collection_cells {
            bytes = bytes.saturating_add(std::mem::size_of_val(binding.transfers.as_ref()));
        }
        let projection = &self.payload_projection;
        bytes = bytes
            .saturating_add(std::mem::size_of_val(projection.replacements.as_ref()))
            .saturating_add(std::mem::size_of_val(projection.limitations.as_ref()));
        for limitation in &projection.limitations {
            bytes = bytes.saturating_add(limitation.len());
        }
        for event in &projection.replacements {
            bytes = bytes.saturating_add(std::mem::size_of_val(event.relations.as_ref()));
            if let Some(path) = &event.constructor_path {
                bytes = bytes.saturating_add(std::mem::size_of_val(path.as_ref()));
                for step in path.iter() {
                    bytes = bytes.saturating_add(match step {
                        crate::analyzer::semantic::PatternProjectionStep::Named(name) => name.len(),
                        crate::analyzer::semantic::PatternProjectionStep::Variant {
                            declaration,
                        } => declaration.len(),
                        crate::analyzer::semantic::PatternProjectionStep::Tuple(_)
                        | crate::analyzer::semantic::PatternProjectionStep::Element => 0,
                    });
                }
            }
        }
        bytes
    }
}

impl ValueFlowSnapshot {
    /// Sufficient borrowed content correspondence; grants no admission authority.
    /// Executable handles retain their exact artifact and interpretation equality.
    #[doc(hidden)]
    pub fn has_same_content(&self, other: &Self) -> bool {
        let Self {
            execution_dependent: l_execution_dependent,
            procedure: l_procedure,
            context: l_context,
            backing: l_backing,
            selected_entry_gap: l_selected_entry_gap,
            coverage: l_coverage,
            unproven_go_builtin_assumptions: l_unproven_go_builtin_assumptions,
        } = self;
        let Self {
            execution_dependent: r_execution_dependent,
            procedure: r_procedure,
            context: r_context,
            backing: r_backing,
            selected_entry_gap: r_selected_entry_gap,
            coverage: r_coverage,
            unproven_go_builtin_assumptions: r_unproven_go_builtin_assumptions,
        } = other;

        l_execution_dependent == r_execution_dependent
            && l_procedure == r_procedure
            && l_context == r_context
            && l_backing.has_same_content(r_backing)
            && l_selected_entry_gap == r_selected_entry_gap
            && l_coverage == r_coverage
            && l_unproven_go_builtin_assumptions == r_unproven_go_builtin_assumptions
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValueFlowOmissionCause {
    UntransportedReturnMember,
}

impl ValueFlowSnapshot {
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn retention_census_for_test(
        &self,
        census: &mut brokk_bifrost_core::retention_census::RetentionCensus<'_>,
        family: &'static str,
    ) {
        use crate::analyzer::semantic::oracle::retained::{
            RetainedNode, visit_retained_allocations_from_roots,
        };

        let mut roots = vec![
            RetainedNode::Procedure(&self.procedure),
            RetainedNode::CallContext(&self.context),
        ];
        for relation in self.relations() {
            roots.push(RetainedNode::ValueFlow(relation));
        }
        for binding in self.collection_cells() {
            roots.push(RetainedNode::Procedure(binding.call().procedure()));
            for transfer in binding.transfers() {
                roots.push(RetainedNode::ValueFlowEndpoint(&transfer.source));
                roots.push(RetainedNode::ValueFlowEndpoint(&transfer.target));
            }
        }
        for receiver in self.member_receivers() {
            roots.push(RetainedNode::Procedure(receiver.call().procedure()));
            if let Some(read) = &receiver.field_read {
                roots.push(RetainedNode::ValueFlowEndpoint(&read.source));
            }
            for endpoint in receiver.storage() {
                roots.push(RetainedNode::ValueFlowEndpoint(endpoint));
            }
        }
        for event in &self.backing.payload_projection.replacements {
            for relation in &event.relations {
                roots.push(RetainedNode::ValueFlowEndpoint(&relation.source));
                roots.push(RetainedNode::ValueFlowEndpoint(&relation.target));
            }
        }
        visit_retained_allocations_from_roots(roots, census, family);
    }

    /// Build a snapshot whose materialization discharged no gap. Equivalent
    /// to [`Self::with_discharged_gaps`] with an empty discharge set.
    pub fn new(
        procedure: ProcedureHandle,
        context: OracleCallContext,
        relations: Vec<ValueFlowRelation>,
        coverage: CandidateCoverage,
        limits: OracleLimits,
    ) -> Result<Self, OracleContractError> {
        Self::with_discharged_gaps(procedure, context, relations, coverage, limits, Vec::new())
    }

    /// Build a snapshot, recording which of its procedure's gaps a
    /// query-time discharge predicate proved do not apply while this
    /// snapshot was materialized (#2545). `discharged_gaps` need not be
    /// sorted or deduplicated; order does not matter to
    /// [`Self::gap_is_discharged`].
    pub fn with_discharged_gaps(
        procedure: ProcedureHandle,
        context: OracleCallContext,
        relations: Vec<ValueFlowRelation>,
        coverage: CandidateCoverage,
        limits: OracleLimits,
        discharged_gaps: Vec<crate::analyzer::semantic::GapKey>,
    ) -> Result<Self, OracleContractError> {
        Self::with_member_receivers_and_discharged_gaps(
            procedure,
            context,
            relations,
            coverage,
            limits,
            discharged_gaps,
            Vec::new(),
            Vec::new(),
            true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_member_receivers_and_discharged_gaps(
        procedure: ProcedureHandle,
        context: OracleCallContext,
        relations: Vec<ValueFlowRelation>,
        coverage: CandidateCoverage,
        limits: OracleLimits,
        discharged_gaps: Vec<crate::analyzer::semantic::GapKey>,
        receivers: Vec<MemberReceiverFlow>,
        collection_cells: Vec<CollectionCellBinding>,
        execution_dependent: bool,
    ) -> Result<Self, OracleContractError> {
        Self::with_selected_payload_projection(
            procedure,
            context,
            relations,
            coverage,
            limits,
            discharged_gaps,
            receivers,
            collection_cells,
            execution_dependent,
            Default::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn with_selected_payload_projection(
        procedure: ProcedureHandle,
        context: OracleCallContext,
        relations: Vec<ValueFlowRelation>,
        coverage: CandidateCoverage,
        limits: OracleLimits,
        discharged_gaps: Vec<crate::analyzer::semantic::GapKey>,
        receivers: Vec<MemberReceiverFlow>,
        collection_cells: Vec<CollectionCellBinding>,
        execution_dependent: bool,
        payload_projection: super::SelectedPayloadProjection,
    ) -> Result<Self, OracleContractError> {
        if (!payload_projection.affected() && !payload_projection.replacements.is_empty())
            || payload_projection
                .replacements
                .windows(2)
                .any(|rows| (rows[0].point, rows[0].event) >= (rows[1].point, rows[1].event))
        {
            return Err(OracleContractError::InvalidRelationIdentity);
        }
        for binding in &collection_cells {
            require_same_procedure(binding.call.procedure(), &procedure)?;
        }
        let mut metadata = Self {
            execution_dependent: execution_dependent || coverage == CandidateCoverage::Truncated,
            procedure: procedure.clone(),
            context: context.clone(),
            backing: Arc::new(ValueFlowSnapshotBacking {
                relations: Box::default(),
                omission_causes: Box::default(),
                discharged_gaps: Box::default(),
                member_receivers: Box::default(),
                collection_cells: collection_cells.into_boxed_slice(),
                payload_projection,
            }),
            selected_entry_gap: None,
            coverage,
            unproven_go_builtin_assumptions: !procedure
                .artifact()
                .go_predeclared_builtin_assumptions()
                .is_empty(),
        }
        .with_member_receivers(receivers, limits)?;
        let member_calls = metadata
            .backing
            .member_receivers
            .iter()
            .map(|receiver| (receiver.call.id(), receiver))
            .collect::<std::collections::HashMap<_, _>>();
        let owner = OracleRelationOwner::ProcedureValueFlow {
            procedure: procedure.clone(),
            context: context.clone(),
        };
        let mut seen = std::collections::HashSet::new();
        let mut chains = None;
        let first = relations.first().map(|relation| &relation.id);
        for relation in &relations {
            require_same_procedure(relation.point.procedure(), &procedure)?;
            if relation.kind == ValueFlowRelationKind::Capture {
                validate_capture_flow(&procedure, &relation.source, &relation.target)?;
            } else {
                relation.source.validate_at(&procedure)?;
                relation.target.validate_at(&procedure)?;
            }
            let point = procedure
                .semantics()
                .point(relation.point.id())
                .ok_or(OracleContractError::InvalidRelationIdentity)?;
            let event = point
                .events
                .get(relation.event_index as usize)
                .ok_or(OracleContractError::InvalidRelationIdentity)?;
            let matches_member_transfer = |receiver: &&MemberReceiverFlow| {
                receiver.transfers().any(|transfer| {
                    transfer.point == relation.point
                        && transfer.event_index == relation.event_index
                        && transfer.source == relation.source
                        && transfer.target == relation.target
                        && transfer.proof == relation.proof
                        && transfer.completeness == relation.completeness
                })
            };
            let member_transfer = relation.kind == ValueFlowRelationKind::LanguageDefined
                && relation.transfer.is_none()
                && match event.effect {
                    SemanticEffect::Invoke { call_site }
                    | SemanticEffect::CallContinuation { call_site, .. } => member_calls
                        .get(&call_site)
                        .is_some_and(matches_member_transfer),
                    SemanticEffect::CallableReference { .. } => {
                        member_calls.values().any(matches_member_transfer)
                    }
                    _ => false,
                };
            let collection_cell_transfer = relation.kind == ValueFlowRelationKind::LanguageDefined
                && relation.transfer.is_none()
                && matches!(event.effect, SemanticEffect::CallContinuation {
                    call_site,
                    kind: CallContinuationKind::Normal,
                } if metadata.backing.collection_cells.iter().any(|binding| {
                    binding.call.id() == call_site
                        && binding.transfers.iter().any(|transfer| {
                            transfer.point == relation.point
                                && transfer.event_index == relation.event_index
                                && transfer.source == relation.source
                                && transfer.target == relation.target
                        })
                }));
            let matches_selected_event = match metadata
                .backing
                .payload_projection
                .replacement_at(relation.point.id(), relation.event_index)
            {
                Some(selected) => selected.relations.iter().any(|row| {
                    row.kind == relation.kind
                        && row.source == relation.source
                        && row.target == relation.target
                        && relation.transfer.is_none()
                        && !relation.strong_update
                        && !relation.direct_cell_overwrite
                }),
                None => {
                    member_transfer
                        || collection_cell_transfer
                        || relation_matches_event(&procedure, relation, &event.effect, &mut chains)
                }
            };
            if !matches_selected_event || !relation.has_valid_memory_authority(&event.effect) {
                return Err(OracleContractError::InvalidRelationIdentity);
            }
            if relation.transfer.is_some() && relation.kind != ValueFlowRelationKind::Assignment {
                return Err(OracleContractError::InvalidRelationIdentity);
            }
            if relation.id.owner() != &owner
                || relation.id.record().kind() != OracleRelationKind::ValueFlow
                || relation.id.record().evidence().is_empty()
                || first.is_some_and(|first| !first.same_arena(&relation.id))
                || !seen.insert(relation.id.clone())
            {
                return Err(OracleContractError::InvalidRelationIdentity);
            }
            if !relation
                .id
                .record()
                .supports_quality(&relation.proof, &relation.completeness)
            {
                return Err(OracleContractError::InvalidRelationQuality);
            }
            // The local overwrite verdict is not a heap escape claim. It can
            // only license replacement of the exact directly named frame cell.
            if relation.direct_cell_overwrite
                && (relation.kind != ValueFlowRelationKind::MemoryStore
                    || !relation.is_proven_complete()
                    || !matches!((&event.effect, &relation.target),
                        (SemanticEffect::MemoryStore { location: id, .. },
                         ValueFlowEndpoint::Location(location))
                            if location.path().is_exact()
                                && location.path().selectors().is_empty()
                                && matches!(location.path().root(), AccessPathRoot::LexicalCell(cell)
                                    if cell.procedure() == &procedure && cell.id() == *id)
                                && procedure.semantics().memory_location(*id).is_some_and(|row|
                                    matches!(row.kind, MemoryLocationKind::LexicalCell { .. }))))
            {
                return Err(OracleContractError::InvalidRelationIdentity);
            }
            // A strong update is only ever a claim about one exact overwritten
            // location, backed by proven and complete evidence. Rejecting the
            // other shapes here means a client can act on the flag without
            // re-deriving the preconditions the certificate already required.
            if relation.strong_update
                && (relation.kind != ValueFlowRelationKind::MemoryStore
                    || !relation.is_proven_complete()
                    || !matches!(
                        &relation.target,
                        ValueFlowEndpoint::Location(location) if location.path().is_exact()
                    ))
            {
                return Err(OracleContractError::InvalidRelationIdentity);
            }
        }
        validate_retained_relation_arenas(relations.iter().map(|relation| &relation.id), limits)?;
        let backing = Arc::get_mut(&mut metadata.backing)
            .expect("a new snapshot uniquely owns its row backing");
        backing.relations = relations.into_boxed_slice();
        backing.discharged_gaps = discharged_gaps.into_boxed_slice();
        Ok(metadata)
    }

    /// This same selection decides the snapshot path and every derived key.
    pub fn payload_projection(&self) -> &super::SelectedPayloadProjection {
        &self.backing.payload_projection
    }

    pub fn is_execution_dependent(&self) -> bool {
        self.execution_dependent
    }

    /// Execution dependence joins monotonically after construction.
    pub fn mark_execution_dependent(&mut self) {
        self.execution_dependent = true;
    }

    /// Carry the workspace host's bounded package-declaration proof to the
    /// pure plan classifier without repeating a workspace read there.
    pub fn with_unproven_go_builtin_assumptions(mut self, open: bool) -> Self {
        self.unproven_go_builtin_assumptions = open;
        self
    }

    pub fn has_unproven_go_builtin_assumptions(&self) -> bool {
        self.unproven_go_builtin_assumptions
    }

    /// Record that the projection left a stored member of a returned join out of
    /// the relation list (#9766).
    pub fn with_untransported_return_member(mut self, untransported: bool) -> Self {
        Arc::make_mut(&mut self.backing).omission_causes = if untransported {
            vec![ValueFlowOmissionCause::UntransportedReturnMember].into_boxed_slice()
        } else {
            Box::default()
        };
        self
    }

    pub fn omission_causes(&self) -> &[ValueFlowOmissionCause] {
        &self.backing.omission_causes
    }

    /// Whether the relation list may lack a relation: a capacity cap cut it
    /// (Truncated coverage), or the projection left out a stored member of a
    /// returned join (#9766). Open coverage alone does not say this; it admits
    /// more candidates and still carries every relation the projection found.
    /// A consumer that treats the relations as complete must ask this, not
    /// match the coverage.
    pub fn relations_may_be_missing(&self) -> bool {
        self.coverage == CandidateCoverage::Truncated || !self.backing.omission_causes.is_empty()
    }

    pub fn with_member_receivers(
        mut self,
        receivers: Vec<MemberReceiverFlow>,
        limits: OracleLimits,
    ) -> Result<Self, OracleContractError> {
        if receivers.len() > limits.provenance_records() {
            return Err(OracleContractError::LimitExceeded {
                dimension: "member_receiver_calls",
                limit: limits.provenance_records(),
                attempted: receivers.len(),
            });
        }
        let mut calls = std::collections::HashSet::new();
        for receiver in &receivers {
            require_same_procedure(receiver.call.procedure(), &self.procedure)?;
            if !calls.insert(receiver.call.id()) {
                return Err(OracleContractError::InvalidRelationIdentity);
            }
        }
        if receivers
            .iter()
            .any(|receiver| !receiver.selection_is_complete())
            && self.coverage == CandidateCoverage::Exhaustive
        {
            self.coverage = CandidateCoverage::Open;
        }
        Arc::make_mut(&mut self.backing).member_receivers = receivers.into_boxed_slice();
        Ok(self)
    }

    pub fn member_receivers(&self) -> &[MemberReceiverFlow] {
        &self.backing.member_receivers
    }

    /// The calls whose collection contract this snapshot bound to container
    /// cells (#10989). Their summaries' receiver transfers must not also apply
    /// at the normal continuation.
    pub fn collection_cells(&self) -> &[CollectionCellBinding] {
        &self.backing.collection_cells
    }

    /// Full backing/context children beneath this inline snapshot. The same
    /// actual backing allocation is counted once across ordinary/selected views.
    #[doc(hidden)]
    pub fn retained_allocations(
        &self,
        census: &mut impl crate::analyzer::semantic::service::ArtifactRetentionVisitor,
    ) {
        self.retained_artifacts(census);
    }

    #[doc(hidden)]
    pub fn retained_artifacts(
        &self,
        census: &mut impl crate::analyzer::semantic::service::ArtifactRetentionVisitor,
    ) {
        census.procedure(&self.procedure);
        census.context(&self.context);
        if !census.shared_allocation(Arc::as_ptr(&self.backing) as usize, || {
            self.backing.retained_bytes()
        }) {
            return;
        }
        for relation in self.relations() {
            relation.retained_artifacts(census);
        }
        for event in &self.backing.payload_projection.replacements {
            for relation in &event.relations {
                relation.source.retained_artifacts(census);
                relation.target.retained_artifacts(census);
            }
        }
        for binding in &self.backing.collection_cells {
            census.procedure(binding.call.procedure());
            for transfer in &binding.transfers {
                transfer.source.retained_artifacts(census);
                transfer.target.retained_artifacts(census);
            }
        }
        for receiver in &self.backing.member_receivers {
            census.procedure(receiver.call.procedure());
            if let Some(read) = &receiver.field_read {
                read.source.retained_artifacts(census);
            }
            for endpoint in receiver.storage() {
                endpoint.retained_artifacts(census);
            }
        }
    }

    pub fn procedure(&self) -> &ProcedureHandle {
        &self.procedure
    }

    /// Exact immutable allocation identity, including empty row collections.
    #[doc(hidden)]
    pub fn shares_backing_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.backing, &other.backing)
    }

    pub fn relations(&self) -> &[ValueFlowRelation] {
        &self.backing.relations
    }

    /// Structural owned arena bytes, counted once even after filtering rows.
    /// Retained handles keep the entire original bounded arena alive.
    pub fn retained_arena_bytes(&self) -> usize {
        self.backing
            .relations
            .first()
            .map_or(0, |relation| relation.id.arena().retained_bytes())
    }

    /// Restrict an already validated snapshot to runtime-class identity flow.
    /// Retained rows keep their original evidence, owner, and arena identity;
    /// materialization coverage and discharged gaps are not reinterpreted.
    /// The client must independently account for results of excluded transfers
    /// rather than treating the missing dependency as proof of absence.
    pub fn into_class_identity_projection(mut self) -> Self {
        let backing = Arc::make_mut(&mut self.backing);
        let mut relations = std::mem::take(&mut backing.relations).into_vec();
        let mut chains = None;
        relations.retain(|relation| relation.preserves_runtime_class(&mut chains));
        backing.relations = relations.into_boxed_slice();
        self
    }

    /// Exclude address construction and address-to-load dependencies from
    /// pointer-identity propagation while
    /// preserving the same snapshot's ordinary dependence for taint clients.
    pub fn without_pointer_operand_dependencies(mut self) -> Self {
        let backing = Arc::make_mut(&mut self.backing);
        let mut relations = std::mem::take(&mut backing.relations).into_vec();
        relations.retain(|relation| {
            let point = self
                .procedure
                .semantics()
                .point(relation.point.id())
                .expect("validated relation point");
            !matches!(
                point.events[relation.event_index as usize].effect,
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::AddressOf | ValueFlowKind::MemoryLoad { .. },
                    ..
                }
            )
        });
        backing.relations = relations.into_boxed_slice();
        self
    }

    /// Remove incoming memory flow for loads whose result a client supplies
    /// independently. Replacing only the result's seeds would leave ordinary
    /// heap flow able to reintroduce values excluded by the client's model.
    /// Load identities are local to this snapshot's procedure. Other loads,
    /// stores, evidence identities, and coverage remain unchanged.
    pub fn without_memory_loads_into(
        mut self,
        loads: impl IntoIterator<Item = (ProgramPointId, ValueId)>,
    ) -> Self {
        let loads = loads.into_iter().collect::<std::collections::HashSet<_>>();
        for &(point, result) in &loads {
            assert!(
                self.procedure.semantics().point(point).is_some_and(|point| {
                    point.events.iter().any(|event| {
                        matches!(event.effect, SemanticEffect::MemoryLoad { result: actual, .. } if actual == result)
                    })
                }),
                "a replaced load must belong to the snapshot procedure"
            );
        }
        let backing = Arc::make_mut(&mut self.backing);
        let mut relations = std::mem::take(&mut backing.relations).into_vec();
        relations.retain(|relation| {
            !(relation.kind == ValueFlowRelationKind::MemoryLoad
                && matches!(&relation.target, ValueFlowEndpoint::Value(value)
                    if loads.contains(&(relation.point.id(), value.id()))))
        });
        backing.relations = relations.into_boxed_slice();
        self
    }

    pub fn context(&self) -> &OracleCallContext {
        &self.context
    }

    pub const fn coverage(&self) -> CandidateCoverage {
        self.coverage
    }

    /// Query-local selected-root provenance; this grants no source authority.
    pub const fn selected_entry_gap(&self) -> Option<SemanticGapId> {
        self.selected_entry_gap
    }

    /// Whether a query-time discharge predicate proved, while this snapshot
    /// was materialized, that `gap` does not apply (#2545). `false` for a
    /// gap this snapshot never examined (a stale or foreign ID) as well as
    /// for one it examined and left standing -- both keep whatever the gap
    /// would otherwise mean to a caller that re-examines this snapshot's
    /// procedure's raw gap list.
    pub fn gap_is_discharged(&self, gap: crate::analyzer::semantic::GapKey) -> bool {
        if matches!(gap, crate::analyzer::semantic::GapKey::Member(_))
            && self.procedure.semantics().logical_gap(gap).is_none()
        {
            return false;
        }
        self.selected_entry_gap
            .is_some_and(|selected| gap == crate::analyzer::semantic::GapKey::Gap(selected))
            || gap.is_discharged_by(|key| self.backing.discharged_gaps.contains(&key))
    }
}

/// Query-only entry evidence. This certifies the existing binder after its
/// guarded definition, never a transfer from the pattern's whole input.
/// Declaration/AST authority is supplied by admission; this layer validates
/// its exact correspondence with the immutable procedure and linked gap.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SelectedPatternEntry {
    observation: crate::analyzer::semantic::ValueAtPoint,
    candidate: u32,
    gap: SemanticGapId,
    field: crate::analyzer::semantic::SourceSpan,
}

impl SelectedPatternEntry {
    #[doc(hidden)]
    pub fn validate(
        observation: crate::analyzer::semantic::ValueAtPoint,
        candidate: u32,
        constructor: crate::analyzer::semantic::SourceSpan,
        field: crate::analyzer::semantic::SourceSpan,
        root_to_constructor: &[crate::analyzer::semantic::PatternProjectionStep],
        constructor_to_binding: &[crate::analyzer::semantic::PatternProjectionStep],
    ) -> Result<Self, OracleContractError> {
        use crate::analyzer::semantic::{SemanticCapability, SemanticGapKind, SemanticGapSubject};
        let procedure = observation.point().procedure();
        require_same_procedure(procedure, observation.value().procedure())?;
        let semantics = procedure.semantics();
        let projection = semantics
            .guarded_pattern_projections()
            .get(candidate as usize)
            .ok_or(OracleContractError::InvalidRelationIdentity)?;
        let gap = projection
            .gap
            .and_then(|id| semantics.gaps().get(id.index()))
            .ok_or(OracleContractError::InvalidRelationIdentity)?;
        let pattern = semantics
            .source_mapping(projection.pattern_source)
            .ok_or(OracleContractError::InvalidRelationIdentity)?
            .locator
            .anchor()
            .span();
        let binder = semantics
            .source_mapping(projection.binder_source)
            .ok_or(OracleContractError::InvalidRelationIdentity)?
            .locator
            .anchor()
            .span();
        let contains = |outer: crate::analyzer::semantic::SourceSpan,
                        inner: crate::analyzer::semantic::SourceSpan| {
            outer.start_byte() <= inner.start_byte() && inner.end_byte() <= outer.end_byte()
        };
        let point = semantics
            .point(projection.point)
            .ok_or(OracleContractError::InvalidRelationIdentity)?;
        if projection.ordinal != candidate
            || projection.point != observation.point().id()
            || projection.binder != observation.value().id()
            || observation.phase() != crate::analyzer::semantic::ObservationPhase::AfterEffects
            || gap.point != projection.point
            || gap.subject != SemanticGapSubject::Value(projection.binder)
            || gap.capability != SemanticCapability::Values
            || gap.kind != SemanticGapKind::Unsupported
            || !gap
                .impacts
                .contains(crate::analyzer::semantic::SemanticGapImpact::ValueFlow)
            || !contains(pattern, constructor)
            || !contains(pattern, field)
            || constructor.end_byte() > field.start_byte()
            || !contains(field, binder)
            || constructor_to_binding.is_empty()
            || !root_to_constructor
                .iter()
                .chain(constructor_to_binding)
                .eq(projection.path.iter())
            || !point.events.iter().any(|event| {
                matches!(event.effect,
                SemanticEffect::Gap { gap: id } if id == gap.id)
            })
            || !point.events.iter().any(|event| {
                matches!(event.effect,
                SemanticEffect::Assignment { target, .. } if target == projection.binder)
            })
        {
            return Err(OracleContractError::InvalidRelationIdentity);
        }
        let gap_id = gap.id;
        Ok(Self {
            observation,
            candidate,
            gap: gap_id,
            field,
        })
    }

    pub fn observation(&self) -> &crate::analyzer::semantic::ValueAtPoint {
        &self.observation
    }

    /// Retained candidate identity, without constructing or validating a proof.
    #[doc(hidden)]
    pub const fn candidate_ordinal(&self) -> u32 {
        self.candidate
    }

    /// The exact retained certified field geometry.
    #[doc(hidden)]
    pub const fn field(&self) -> &crate::analyzer::semantic::SourceSpan {
        &self.field
    }

    pub const fn gap(&self) -> SemanticGapId {
        self.gap
    }

    /// A distinct, selected-root product. The caller must keep it with this
    /// entry and must never publish it as a plain procedure snapshot/summary.
    /// Every relation, capability and other gap is retained unchanged.
    #[doc(hidden)]
    pub fn project(
        &self,
        base: &ValueFlowSnapshot,
    ) -> Result<ValueFlowSnapshot, OracleContractError> {
        require_same_procedure(base.procedure(), self.observation.point().procedure())?;
        if base.context() != self.observation.context() || base.selected_entry_gap.is_some() {
            return Err(OracleContractError::InvalidRelationIdentity);
        }
        let mut selected = base.clone();
        selected.selected_entry_gap = Some(self.gap);
        Ok(selected)
    }
}
