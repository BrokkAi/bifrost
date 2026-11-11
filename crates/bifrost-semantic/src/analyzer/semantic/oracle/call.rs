use crate::analyzer::semantic::ids::ProgramPointId;

use crate::analyzer::semantic::ids::SourceSpan;
use crate::analyzer::semantic::ids::ValueId;

use crate::analyzer::semantic::ir::ValueTransfer;

use crate::analyzer::semantic::ir::ArgumentDomain;

use crate::analyzer::semantic::ir::CallArgumentExpansion;

use crate::analyzer::semantic::ir::CallSiteHandle;

use crate::analyzer::semantic::ir::CallerReceiverBinding;

use crate::analyzer::semantic::ir::FormalMultiplicity;

use crate::analyzer::semantic::ir::ProcedureHandle;

use crate::analyzer::semantic::ir::ProcedureKind;

use crate::analyzer::semantic::ir::ProcedureReceiverBinding;

use crate::analyzer::semantic::ir::ProcedureSemantics;

use crate::analyzer::semantic::ir::ProofStatus;

use crate::analyzer::semantic::ir::SemanticCallSite;

use crate::analyzer::semantic::SemanticCapability;
use crate::analyzer::semantic::ir::AllocationKind;
use crate::analyzer::semantic::ir::MemoryLocationKind;
use crate::analyzer::semantic::ir::SemanticEffect;
use crate::analyzer::semantic::ir::SemanticGapSubject;
use crate::analyzer::semantic::ir::SemanticValueKind;
use crate::analyzer::semantic::ir::TransferKind;
use crate::analyzer::semantic::ir::ValueFlowKind;
use crate::analyzer::semantic::oracle::value_flow::CollapseRead;
use crate::analyzer::semantic::oracle::value_flow::ValueFlowEndpoint;
use crate::analyzer::semantic::oracle::value_flow::ValueFlowRelationKind;
use crate::analyzer::semantic::oracle::value_flow::ValueFlowSnapshot;
use brokk_bifrost_core::analyzer::language_knowledge::ScalarObjectFieldKind;

use crate::analyzer::semantic::ir::ValueHandle;

use crate::analyzer::semantic::oracle::dispatch::DispatchCandidate;

use crate::analyzer::semantic::oracle::error::OracleContractError;

use crate::analyzer::semantic::oracle::error::require_same_procedure;

use crate::analyzer::semantic::oracle::limits::OracleLimits;

use crate::analyzer::semantic::oracle::model::AccessPathAtPoint;

use crate::analyzer::semantic::oracle::model::ObservationPhase;

use crate::analyzer::semantic::oracle::model::OracleCallContext;

use crate::analyzer::semantic::oracle::model::ProcedurePortHandle;

use crate::analyzer::semantic::oracle::model::ProcedurePortKind;

use crate::analyzer::semantic::oracle::relation::CandidateCoverage;

use crate::analyzer::semantic::oracle::relation::EvidenceBacked;

use crate::analyzer::semantic::oracle::relation::OracleCandidate;

use crate::analyzer::semantic::oracle::relation::OracleRelationHandle;

use crate::analyzer::semantic::oracle::relation::OracleRelationKind;

use crate::analyzer::semantic::oracle::relation::OracleRelationOwner;

use crate::analyzer::semantic::oracle::relation::collect_bounded;

use crate::analyzer::semantic::oracle::relation::validate_retained_relation_arenas;

use crate::analyzer::semantic::call_conversion::ConversionUnknown;

/// The caller-side endpoint used by one argument binding.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CallArgumentEndpoint {
    Value(ValueHandle),
    Location {
        value: ValueHandle,
        location: Box<AccessPathAtPoint>,
    },
}

/// The storage relationship of an actual and its formal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CallStorageSharing {
    Shares,
    Isolated,
    Unknown,
}

/// The member of a by-value actual that a callee heap output writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallWrittenMember {
    /// An exact direct field of the copied aggregate, with no traversal.
    DirectField,
    /// A path whose storage isolation is not established by the copy alone.
    MayTraverseReferent,
}

/// Fields for which every matching store in the callee writes the formal's
/// own cell. This is shared by composition and ICFG writeback. In particular,
/// a single Field selector alone cannot exclude Rust DerefMut or a Go
/// promoted field through an embedded pointer.
pub fn direct_formal_store_fields(
    callee: &ProcedureHandle,
    formal: &crate::analyzer::semantic::partial_flow::PartialFlowPort,
) -> Box<[crate::analyzer::semantic::SemanticLocator]> {
    use crate::analyzer::semantic::partial_flow::PartialFlowPort;
    use std::collections::{HashMap, HashSet};

    let semantics = callee.semantics();
    let formal_values = semantics
        .values()
        .iter()
        .filter(|value| match (&value.kind, formal) {
            (
                SemanticValueKind::Parameter { ordinal: left, .. },
                PartialFlowPort::Parameter { ordinal: right },
            ) => left == right,
            (SemanticValueKind::Receiver { .. }, PartialFlowPort::Receiver) => true,
            _ => false,
        })
        .map(|value| value.id)
        .collect::<HashSet<_>>();
    // Adapters materialize a direct spelling of a formal (`p.f`) as a
    // Temporary with one lexical Parameter/Receiver flow from the formal.
    // A local alias has a Local flow instead and cannot certify this proof.
    let mut direct_uses = HashSet::new();
    let mut other_origins = HashSet::new();
    let mut copy_sources = Vec::new();
    let mut value_sources: HashMap<ValueId, Vec<ValueId>> = HashMap::new();
    for point in semantics.points() {
        for event in &point.events {
            match event.effect {
                SemanticEffect::ValueFlow {
                    kind,
                    source,
                    target,
                } => {
                    value_sources.entry(target).or_default().push(source);
                    if matches!(kind, ValueFlowKind::Transfer(transfer) if transfer.kind == TransferKind::AggregateCopy)
                    {
                        copy_sources.push((target, source));
                    }
                    if formal_values.contains(&source)
                        && matches!(kind, ValueFlowKind::Parameter | ValueFlowKind::Receiver)
                    {
                        direct_uses.insert(target);
                    } else {
                        other_origins.insert(target);
                    }
                }
                SemanticEffect::Assignment { target, value } => {
                    value_sources.entry(target).or_default().push(value);
                    other_origins.insert(target);
                }
                _ => {}
            }
        }
    }
    // An exact aggregate copy owns fresh direct member cells. A parallel
    // Assignment from the same source records value dependence, not another
    // storage identity. Stores to the copy therefore cannot disprove a store
    // to the formal's own field.
    let isolated_copies = copy_sources
        .into_iter()
        .filter_map(|(target, source)| {
            let direct_source = formal_values.contains(&source)
                || direct_uses.contains(&source) && !other_origins.contains(&source);
            (direct_source
                && value_sources[&target]
                    .iter()
                    .all(|origin| *origin == source))
            .then_some(target)
        })
        .collect::<HashSet<_>>();
    let blocked_points = semantics
        .gaps()
        .iter()
        .filter(|gap| {
            matches!(
                gap.capability,
                SemanticCapability::FieldMemory | SemanticCapability::Calls
            ) || matches!(gap.subject, SemanticGapSubject::Point)
                && gap.capability == SemanticCapability::Assignments
        })
        .map(|gap| gap.point)
        .collect::<HashSet<_>>();
    let mut fields = HashMap::new();
    for point in semantics.points() {
        let point_has_gap = blocked_points.contains(&point.id);
        let point_dereferences = point.events.iter().any(|event| match event.effect {
            SemanticEffect::MemoryLoad { location, .. }
            | SemanticEffect::MemoryStore { location, .. } => {
                semantics.memory_location(location).is_some_and(|location| {
                    matches!(location.kind, MemoryLocationKind::Dereference { .. })
                })
            }
            _ => false,
        });
        for event in &point.events {
            let SemanticEffect::MemoryStore { location, .. } = event.effect else {
                continue;
            };
            let Some(location) = semantics.memory_location(location) else {
                continue;
            };
            let MemoryLocationKind::Field { base, ref member } = location.kind else {
                continue;
            };
            if isolated_copies.contains(&base) {
                continue;
            }
            let direct = (formal_values.contains(&base)
                || direct_uses.contains(&base) && !other_origins.contains(&base))
                && !point_has_gap
                && !point_dereferences;
            fields
                .entry(member.clone())
                .and_modify(|safe: &mut bool| *safe &= direct)
                .or_insert(direct);
        }
    }
    fields
        .into_iter()
        .filter_map(|(field, safe)| safe.then_some(field))
        .collect()
}

/// Incoming value relations for one immutable procedure snapshot. Keep this
/// alongside the snapshot only for the query that reads it.
pub struct CallStorageRelationIndex {
    incoming: std::collections::HashMap<ValueId, Vec<usize>>,
    construction_points: std::collections::HashMap<SourceSpan, Vec<usize>>,
    relation_count: usize,
}

impl CallStorageRelationIndex {
    pub fn new(snapshot: &ValueFlowSnapshot) -> Self {
        let mut incoming = std::collections::HashMap::<ValueId, Vec<usize>>::new();
        for (index, relation) in snapshot.relations().iter().enumerate() {
            if let ValueFlowEndpoint::Value(target) = &relation.target {
                incoming.entry(target.id()).or_default().push(index);
            }
        }
        let semantics = snapshot.procedure().semantics();
        let mut construction_points = std::collections::HashMap::<SourceSpan, Vec<usize>>::new();
        for (index, point) in semantics.points().iter().enumerate() {
            let source = semantics
                .source_mapping(point.source)
                .expect("a point names its live source");
            construction_points
                .entry(source.locator.anchor().span())
                .or_default()
                .push(index);
        }
        Self {
            incoming,
            construction_points,
            relation_count: snapshot.relations().len(),
        }
    }
}

/// Classify a call actual from structured value-flow origins. An untraced
/// reference is unknown; an aggregate copy or a Rust struct allocation
/// proves independent storage for a by-value formal.
pub fn argument_shares_storage_with_formal(
    actual: &CallArgumentEndpoint,
    mode: CallPassingMode,
    member: CallWrittenMember,
    snapshot: &ValueFlowSnapshot,
    index: &CallStorageRelationIndex,
) -> CallStorageSharing {
    if mode != CallPassingMode::Value {
        return CallStorageSharing::Shares;
    }
    if matches!(actual, CallArgumentEndpoint::Location { .. }) {
        return CallStorageSharing::Shares;
    }
    assert_eq!(index.relation_count, snapshot.relations().len());
    let mut pending = vec![actual.value().id()];
    let mut seen = std::collections::HashSet::new();
    let mut isolated = false;
    let mut unknown = false;
    while let Some(value) = pending.pop() {
        if !seen.insert(value) {
            continue;
        }
        if snapshot
            .procedure()
            .semantics()
            .value(value)
            .is_some_and(|value| value.kind == SemanticValueKind::Address)
        {
            return CallStorageSharing::Shares;
        }
        let Some(relations) = index.incoming.get(&value) else {
            unknown = true;
            continue;
        };
        // A collapse records a member's contribution to an aggregate's
        // contents, not another storage origin for its own direct cells. A
        // proven copy isolates those cells even when another member is a
        // pointer. Traversal through that member still needs scalar proof.
        let has_direct_copy = member == CallWrittenMember::DirectField
            && has_proven_value_transfer(snapshot, index, value);
        for &relation_index in relations {
            let relation = &snapshot.relations()[relation_index];
            if !relation.is_proven_complete() {
                unknown = true;
                continue;
            }
            match (relation.kind, relation.transfer, &relation.source) {
                (ValueFlowRelationKind::Allocation, _, _)
                    if scalar_object_allocation(snapshot, index, value) =>
                {
                    isolated = true
                }
                // A by-value let also publishes its own fresh Allocation.
                // The proven copy, rather than that allocation's fields,
                // certifies isolation of this value's direct cells.
                (ValueFlowRelationKind::Allocation, _, _) if has_direct_copy => {}
                (
                    ValueFlowRelationKind::Assignment,
                    Some(transfer),
                    ValueFlowEndpoint::Value(source),
                ) if matches!(transfer.kind, TransferKind::AggregateCopy | TransferKind::Move { .. })
                    && (member == CallWrittenMember::DirectField
                        || scalar_object_origin(snapshot, index, source.id())) =>
                {
                    isolated = true
                }
                (ValueFlowRelationKind::Assignment, None, ValueFlowEndpoint::Value(source))
                    if member == CallWrittenMember::DirectField
                        && relations.iter().any(|&other| {
                            let copy = &snapshot.relations()[other];
                            copy.is_proven_complete()
                                && copy.kind == ValueFlowRelationKind::Assignment
                                && copy.transfer.is_some_and(|transfer| matches!(transfer.kind, TransferKind::AggregateCopy | TransferKind::Move { .. }))
                                && matches!(&copy.source, ValueFlowEndpoint::Value(from) if from.id() == source.id())
                        }) => {}
                (ValueFlowRelationKind::Assignment, None, ValueFlowEndpoint::Value(source)) => {
                    pending.push(source.id());
                }
                (
                    ValueFlowRelationKind::ContainerCollapse,
                    _,
                    ValueFlowEndpoint::Location(location),
                ) if has_direct_copy
                    && relation.collapse_read == Some(CollapseRead::Root)
                    && matches!(location.path().root(),
                        crate::analyzer::semantic::AccessPathRoot::Value(root)
                            if relations.iter().any(|&other| {
                                let copy = &snapshot.relations()[other];
                                copy.is_proven_complete()
                                    && copy.kind == ValueFlowRelationKind::Assignment
                                    && copy.transfer.is_some_and(|transfer| matches!(transfer.kind, TransferKind::AggregateCopy | TransferKind::Move { .. }))
                                    && matches!(&copy.source, ValueFlowEndpoint::Value(source) if source.id() == root.id())
                            })) => {}
                (
                    ValueFlowRelationKind::ContainerCollapse,
                    _,
                    ValueFlowEndpoint::Location(location),
                ) if matches!(location.path().root(),
                        crate::analyzer::semantic::AccessPathRoot::Allocation(allocation)
                            if snapshot.procedure().semantics().allocations().iter().any(|site|
                                site.id == allocation.id()
                                    && scalar_object_allocation(snapshot, index, site.result)))
                    || relation.collapse_read == Some(CollapseRead::Root)
                        && matches!(location.path().root(),
                            crate::analyzer::semantic::AccessPathRoot::Value(root)
                                if scalar_object_origin(snapshot, index, root.id())) => {}
                _ => unknown = true,
            }
        }
    }
    if unknown || !isolated {
        CallStorageSharing::Unknown
    } else {
        CallStorageSharing::Isolated
    }
}

fn has_proven_value_transfer(
    snapshot: &ValueFlowSnapshot,
    index: &CallStorageRelationIndex,
    value: ValueId,
) -> bool {
    index.incoming.get(&value).is_some_and(|relations| {
        relations.iter().any(|&relation_index| {
            let relation = &snapshot.relations()[relation_index];
            relation.is_proven_complete()
                && relation.kind == ValueFlowRelationKind::Assignment
                && relation.transfer.is_some_and(|transfer| {
                    matches!(
                        transfer.kind,
                        TransferKind::AggregateCopy | TransferKind::Move { .. }
                    )
                })
        })
    })
}

/// Follow only proven value copies to an object whose members cannot carry
/// addresses. A missing or mixed origin leaves a collapsed member unknown.
fn scalar_object_origin(
    snapshot: &ValueFlowSnapshot,
    index: &CallStorageRelationIndex,
    root: ValueId,
) -> bool {
    let mut pending = vec![(root, false)];
    let mut active = std::collections::HashSet::new();
    let mut done = std::collections::HashSet::new();
    let mut allocation = false;
    while let Some((value, exiting)) = pending.pop() {
        if exiting {
            active.remove(&value);
            done.insert(value);
            continue;
        }
        if done.contains(&value) {
            continue;
        }
        if !active.insert(value) {
            return false;
        }
        pending.push((value, true));
        if snapshot
            .procedure()
            .semantics()
            .value(value)
            .is_some_and(|row| row.kind == SemanticValueKind::Address)
        {
            return false;
        }
        let Some(relations) = index.incoming.get(&value) else {
            return false;
        };
        for &relation_index in relations {
            let relation = &snapshot.relations()[relation_index];
            if !relation.is_proven_complete() {
                return false;
            }
            match (relation.kind, relation.transfer, &relation.source) {
                (ValueFlowRelationKind::Allocation, _, _)
                    if scalar_object_allocation(snapshot, index, value) =>
                {
                    allocation = true;
                }
                (ValueFlowRelationKind::Assignment, None, ValueFlowEndpoint::Value(source)) => {
                    pending.push((source.id(), false));
                }
                (
                    ValueFlowRelationKind::Assignment,
                    Some(transfer),
                    ValueFlowEndpoint::Value(source),
                ) if transfer.kind == TransferKind::AggregateCopy => {
                    pending.push((source.id(), false));
                }
                _ => return false,
            }
        }
    }
    allocation
}

fn scalar_object_allocation(
    snapshot: &ValueFlowSnapshot,
    index: &CallStorageRelationIndex,
    value: ValueId,
) -> bool {
    let semantics = snapshot.procedure().semantics();
    let language = snapshot.procedure().artifact().key().language().language();
    let Some(knowledge) = crate::analyzer::semantic::languages::language_knowledge(language) else {
        return false;
    };
    let Some(allocation) = semantics
        .allocations()
        .iter()
        .find(|allocation| allocation.result == value && allocation.kind == AllocationKind::Object)
    else {
        return false;
    };
    // A partial struct update can store scalar fields while leaving an
    // omitted reference field unresolved. Its value-scoped initialization
    // gap is outside the relation projection, so check the snapshot itself.
    if semantics.gaps().iter().any(|gap| {
        !snapshot.gap_is_discharged(gap.id)
            && match gap.subject {
                SemanticGapSubject::Value(subject) if subject == value => {
                    gap.capability == SemanticCapability::FieldMemory
                        || gap.point == allocation.point
                }
                SemanticGapSubject::MemoryLocation(location)
                    if gap.capability == SemanticCapability::FieldMemory =>
                {
                    semantics.memory_location(location).is_some_and(|location| {
                        matches!(location.kind, MemoryLocationKind::Field { base, .. } if base == value)
                    })
                }
                _ => false,
            }
    }) {
        return false;
    }
    let construction_span = semantics
        .source_mapping(allocation.source)
        .expect("an allocation names its live source")
        .locator
        .anchor()
        .span();
    let mut fields = 0;
    // Go allocates at the composite literal's entry point and stores fields
    // at its terminal point. Both points retain that literal's source span.
    let Some(points) = index.construction_points.get(&construction_span) else {
        return false;
    };
    for &point_index in points {
        let point = &semantics.points()[point_index];
        for event in &point.events {
            if let SemanticEffect::MemoryStore {
                location,
                value: field_value,
                ..
            } = event.effect
                && let Some(location) = semantics.memory_location(location)
                && matches!(&location.kind, MemoryLocationKind::Field { base, .. } if *base == value)
            {
                let field_kind = semantics
                    .value(field_value)
                    .and_then(|field| match &field.kind {
                        SemanticValueKind::Boolean(_) => Some(ScalarObjectFieldKind::Boolean),
                        SemanticValueKind::UnsignedInteger(_)
                        | SemanticValueKind::SignedInteger(_)
                        | SemanticValueKind::FloatingPoint { .. } => {
                            Some(ScalarObjectFieldKind::Number)
                        }
                        SemanticValueKind::ConstantString(payload)
                            if knowledge.semantic_string_constant_value(payload).is_some() =>
                        {
                            Some(ScalarObjectFieldKind::String)
                        }
                        _ => None,
                    });
                if !field_kind.is_some_and(|kind| knowledge.scalar_object_field_is_copy(kind)) {
                    return false;
                }
                fields += 1;
            }
            if let SemanticEffect::ValueFlow { target, .. } = event.effect
                && target == value
            {
                return false;
            }
        }
    }
    fields > 0
}

impl CallArgumentEndpoint {
    pub fn location(value: ValueHandle, location: AccessPathAtPoint) -> Self {
        Self::Location {
            value,
            location: Box::new(location),
        }
    }

    pub fn value(&self) -> &ValueHandle {
        match self {
            Self::Value(value) | Self::Location { value, .. } => value,
        }
    }
}

/// Language-neutral argument passing semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CallPassingMode {
    Value,
    SharedReference,
    MutableReference,
    InputOutputReference,
    OutputReference,
    LanguageDefined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ImplicitArgumentKind {
    Default,
    Implicit,
    LanguageDefined,
}

/// One member contributed by a syntactic call argument. Direct positional and
/// unnamed keyword arguments contribute `Whole`; named direct arguments and
/// spreads can contribute structured positional, keyword, or language-defined
/// members.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CallArgumentMember {
    Whole,
    Positional(u32),
    Keyword(Box<str>),
    LanguageDefined(Box<str>),
}

/// One retained actual-to-formal mapping inside an argument group.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallArgumentMapping {
    source_index: u32,
    member: CallArgumentMember,
    actual: CallArgumentEndpoint,
    formal: ProcedurePortHandle,
    mode: CallPassingMode,
    conversion: Option<Result<Option<ValueTransfer>, ConversionUnknown>>,
}

impl CallArgumentMapping {
    pub fn new(
        source_index: u32,
        member: CallArgumentMember,
        actual: CallArgumentEndpoint,
        formal: ProcedurePortHandle,
        mode: CallPassingMode,
    ) -> Self {
        Self {
            source_index,
            member,
            actual,
            formal,
            mode,
            conversion: None,
        }
    }

    /// Conversion typing is independent of argument binding and runtime safety.
    #[doc(hidden)]
    pub fn with_conversion(
        mut self,
        conversion: Result<Option<ValueTransfer>, ConversionUnknown>,
    ) -> Self {
        self.conversion = Some(conversion);
        self
    }

    /// None means this adapter has no conversion producer. A successful None
    /// proves no identity-separating adjustment; Err retains missing evidence
    /// independently of the actual/formal binding's proof and completeness.
    pub fn conversion(&self) -> Option<Result<Option<ValueTransfer>, ConversionUnknown>> {
        self.conversion
    }

    /// A proven identity-separating transfer, when available. Absence is not
    /// proof of identity: inspect `conversion()` for typed unknown evidence,
    /// or `preserves_reference_identity()` before transporting heap aliases.
    pub fn transfer(&self) -> Option<ValueTransfer> {
        self.conversion.and_then(Result::ok).flatten()
    }

    /// A conversion barrier or unknown adjustment cannot transport heap aliases.
    pub fn preserves_reference_identity(&self) -> bool {
        matches!(self.conversion, None | Some(Ok(None)))
    }

    pub const fn source_index(&self) -> u32 {
        self.source_index
    }

    pub fn member(&self) -> &CallArgumentMember {
        &self.member
    }

    pub fn actual(&self) -> &CallArgumentEndpoint {
        &self.actual
    }

    pub fn formal(&self) -> &ProcedurePortHandle {
        &self.formal
    }

    pub const fn mode(&self) -> CallPassingMode {
        self.mode
    }
}

/// Cardinality derived from group coverage and candidate proof. Callers cannot
/// assert an exact cardinality independently of the validated mapping set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArgumentCardinality {
    Exact(usize),
    Between { minimum: usize, maximum: usize },
    AtLeast(usize),
}

/// One evidence-backed group of argument sources and retained mappings.
///
/// The separate closure relation proves that an exhaustive group has no
/// omitted members. Keeping source indices even when no mapping is retained
/// represents an exact empty spread or an open/truncated unknown spread
/// without pretending that the syntactic actual disappeared.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallArgumentGroup {
    closure_relation: OracleRelationHandle,
    sources: Box<[u32]>,
    mappings: Box<[EvidenceBacked<CallArgumentMapping>]>,
    coverage: CandidateCoverage,
}

impl CallArgumentGroup {
    pub fn new<I, M>(
        call: &CallSiteHandle,
        closure_relation: OracleRelationHandle,
        sources: I,
        mappings: M,
        coverage: CandidateCoverage,
        limits: OracleLimits,
    ) -> Result<Self, OracleContractError>
    where
        I: IntoIterator<Item = u32>,
        M: IntoIterator<Item = EvidenceBacked<CallArgumentMapping>>,
    {
        let call_row = call
            .procedure()
            .semantics()
            .call_site(call.id())
            .expect("call-site handles are validated at construction");
        let entry_limit = limits.call_binding_entries();
        let source_limit = entry_limit.min(call_row.arguments.len());
        let sources = sources
            .into_iter()
            .take(source_limit.saturating_add(1))
            .collect::<Vec<_>>();
        if sources.len() > entry_limit {
            return Err(OracleContractError::LimitExceeded {
                dimension: "call_binding_entries",
                limit: entry_limit,
                attempted: sources.len(),
            });
        }
        if sources.len() > call_row.arguments.len() {
            return Err(OracleContractError::InvalidCallBinding(
                "argument group has more sources than the exact call",
            ));
        }
        if sources.is_empty() {
            return Err(OracleContractError::InvalidCallBinding(
                "argument group must name at least one syntactic source",
            ));
        }
        let mut unique_sources = std::collections::HashSet::new();
        if sources.iter().any(|source| !unique_sources.insert(*source)) {
            return Err(OracleContractError::InvalidCallBinding(
                "argument group repeats one syntactic source",
            ));
        }
        if sources
            .iter()
            .any(|source| call_row.arguments.get(*source as usize).is_none())
        {
            return Err(OracleContractError::InvalidCallBinding(
                "argument group names a source outside the exact call",
            ));
        }
        let remaining = entry_limit.saturating_sub(sources.len());
        let mappings = mappings
            .into_iter()
            .take(remaining.saturating_add(1))
            .collect::<Vec<_>>();
        if mappings.len() > remaining {
            return Err(OracleContractError::LimitExceeded {
                dimension: "call_binding_entries",
                limit: entry_limit,
                attempted: sources.len().saturating_add(mappings.len()),
            });
        }
        let mut unique_members = std::collections::HashSet::new();
        if mappings.iter().any(|mapping| {
            !unique_sources.contains(&mapping.value().source_index)
                || !unique_members
                    .insert((mapping.value().source_index, mapping.value().member.clone()))
        }) {
            return Err(OracleContractError::InvalidCallBinding(
                "argument mapping repeats or names an undeclared source member",
            ));
        }
        validate_retained_relation_arenas(
            std::iter::once(&closure_relation)
                .chain(mappings.iter().flat_map(OracleCandidate::provenance)),
            limits,
        )?;
        Ok(Self {
            closure_relation,
            sources: sources.into_boxed_slice(),
            mappings: mappings.into_boxed_slice(),
            coverage,
        })
    }

    pub fn closure_relation(&self) -> &OracleRelationHandle {
        &self.closure_relation
    }

    pub fn sources(&self) -> &[u32] {
        &self.sources
    }

    pub fn mappings(&self) -> &[EvidenceBacked<CallArgumentMapping>] {
        &self.mappings
    }

    pub const fn coverage(&self) -> CandidateCoverage {
        self.coverage
    }

    pub fn cardinality(&self) -> ArgumentCardinality {
        let proven = self
            .mappings
            .iter()
            .filter(|mapping| matches!(mapping.proof(), ProofStatus::Proven))
            .count();
        match self.coverage {
            CandidateCoverage::Exhaustive if proven == self.mappings.len() => {
                ArgumentCardinality::Exact(proven)
            }
            CandidateCoverage::Exhaustive => ArgumentCardinality::Between {
                minimum: proven,
                maximum: self.mappings.len(),
            },
            CandidateCoverage::Open | CandidateCoverage::Truncated => {
                ArgumentCardinality::AtLeast(proven)
            }
        }
    }
}

/// Query-time preparation of a deferred member invocation's written receiver.
/// The owning call supplies its exact receiver value and optional place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemberReceiverPreparation {
    Reference,
    AddressOfPlace,
    ByValue,
    CopyValue,
    CopyPointee,
}

/// One candidate-specific caller/callee boundary relation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CallBinding {
    Receiver {
        relation: OracleRelationHandle,
        actual: ValueHandle,
        formal: ProcedurePortHandle,
    },
    ArgumentGroup(CallArgumentGroup),
    ImplicitArgument {
        relation: OracleRelationHandle,
        formal_ordinal: u32,
        source: ValueHandle,
        formal: ProcedurePortHandle,
        kind: ImplicitArgumentKind,
    },
    NormalReturn {
        relation: OracleRelationHandle,
        formal: ProcedurePortHandle,
        result: ValueHandle,
    },
    ExceptionalReturn {
        relation: OracleRelationHandle,
        formal: ProcedurePortHandle,
        result: ValueHandle,
    },
}

/// Actual/formal and return bindings for one exact dispatch candidate.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallBindings {
    call: CallSiteHandle,
    candidate: DispatchCandidate,
    context: OracleCallContext,
    bindings: Box<[CallBinding]>,
    coverage: CandidateCoverage,
}

fn validate_call_binding_relation(
    relation: &OracleRelationHandle,
    owner: &OracleRelationOwner,
    first: &mut Option<OracleRelationHandle>,
    seen: &mut std::collections::HashSet<OracleRelationHandle>,
) -> Result<(), OracleContractError> {
    if relation.owner() != owner
        || relation.record().kind() != OracleRelationKind::CallBinding
        || relation.record().evidence().is_empty()
        || first
            .as_ref()
            .is_some_and(|first| !first.same_arena(relation))
        || !seen.insert(relation.clone())
    {
        return Err(OracleContractError::InvalidRelationIdentity);
    }
    if first.is_none() {
        *first = Some(relation.clone());
    }
    Ok(())
}

fn member_matches_expansion(
    expansion: &CallArgumentExpansion,
    member: &CallArgumentMember,
) -> bool {
    match (expansion, member) {
        (CallArgumentExpansion::Direct(_), CallArgumentMember::Whole) => true,
        (
            CallArgumentExpansion::Direct(ArgumentDomain::Keyword),
            CallArgumentMember::Keyword(_),
        ) => true,
        (
            CallArgumentExpansion::Spread(ArgumentDomain::Positional),
            CallArgumentMember::Positional(_),
        )
        | (
            CallArgumentExpansion::Spread(ArgumentDomain::Keyword),
            CallArgumentMember::Keyword(_),
        ) => true,
        (
            CallArgumentExpansion::Spread(ArgumentDomain::PositionalOrKeyword),
            CallArgumentMember::Positional(_) | CallArgumentMember::Keyword(_),
        ) => true,
        (
            CallArgumentExpansion::Spread(ArgumentDomain::LanguageDefined(expected)),
            CallArgumentMember::LanguageDefined(actual),
        ) => expected == actual,
        _ => false,
    }
}

fn rest_domain_accepts_mapping(
    rest: &ArgumentDomain,
    expansion: &CallArgumentExpansion,
    member: &CallArgumentMember,
) -> bool {
    let accepts_positional = matches!(
        rest,
        ArgumentDomain::Positional | ArgumentDomain::PositionalOrKeyword
    );
    let accepts_keyword = matches!(
        rest,
        ArgumentDomain::Keyword | ArgumentDomain::PositionalOrKeyword
    );
    match (expansion, member) {
        (CallArgumentExpansion::Direct(ArgumentDomain::Positional), CallArgumentMember::Whole) => {
            accepts_positional
        }
        (CallArgumentExpansion::Direct(ArgumentDomain::Keyword), CallArgumentMember::Whole) => {
            accepts_keyword
        }
        (
            CallArgumentExpansion::Direct(ArgumentDomain::Keyword),
            CallArgumentMember::Keyword(_),
        ) => accepts_keyword,
        (
            CallArgumentExpansion::Direct(ArgumentDomain::PositionalOrKeyword),
            CallArgumentMember::Whole,
        ) => accepts_positional || accepts_keyword,
        (
            CallArgumentExpansion::Direct(ArgumentDomain::LanguageDefined(actual)),
            CallArgumentMember::Whole,
        )
        | (
            CallArgumentExpansion::Spread(ArgumentDomain::LanguageDefined(actual)),
            CallArgumentMember::LanguageDefined(_),
        ) => matches!(rest, ArgumentDomain::LanguageDefined(expected) if expected == actual),
        (CallArgumentExpansion::Spread(_), CallArgumentMember::Positional(_)) => accepts_positional,
        (CallArgumentExpansion::Spread(_), CallArgumentMember::Keyword(_)) => accepts_keyword,
        _ => false,
    }
}

fn validate_argument_endpoint(
    actual: &CallArgumentEndpoint,
    mode: CallPassingMode,
    caller: &ProcedureHandle,
    call_point: ProgramPointId,
    context: &OracleCallContext,
) -> Result<(), OracleContractError> {
    require_same_procedure(actual.value().procedure(), caller)?;
    if let CallArgumentEndpoint::Location { location, .. } = actual {
        require_same_procedure(location.point().procedure(), caller)?;
        if location.point().id() != call_point
            || location.phase() != ObservationPhase::BeforeEffects
            || location.context() != context
        {
            return Err(OracleContractError::InvalidCallBinding(
                "reference argument locations must be observed immediately before the call effects",
            ));
        }
        if !matches!(
            mode,
            CallPassingMode::SharedReference
                | CallPassingMode::MutableReference
                | CallPassingMode::InputOutputReference
                | CallPassingMode::OutputReference
                | CallPassingMode::LanguageDefined
        ) {
            return Err(OracleContractError::InvalidCallBinding(
                "location arguments require a reference-capable passing mode",
            ));
        }
    } else if matches!(
        mode,
        CallPassingMode::MutableReference
            | CallPassingMode::InputOutputReference
            | CallPassingMode::OutputReference
    ) {
        return Err(OracleContractError::InvalidCallBinding(
            "mutable/output argument modes require a caller location",
        ));
    }
    Ok(())
}

/// The result a receiver-less construction expression passes to its
/// constructor and returns to its caller. A direct or type-qualified
/// constructor invocation has a receiver binding and retains an ordinary
/// return-value boundary. Share this exact structural interpretation between
/// producer and validator. The resolved constructor candidate is the proof for
/// cross-file calls whose caller-side lowering cannot publish an allocation.
#[doc(hidden)]
pub fn constructor_call_result(
    caller: &ProcedureSemantics,
    call: &SemanticCallSite,
    callee: &ProcedureSemantics,
) -> Option<ValueId> {
    let caller_receiver_binding = caller.proven_caller_receiver_binding(call.id);
    let module_qualified = matches!(
        (call.receiver, caller_receiver_binding),
        (Some(receiver), Some(CallerReceiverBinding::ModuleQualified(qualifier)))
            if receiver == qualifier
    );
    if callee.kind() != ProcedureKind::Constructor || (call.receiver.is_some() && !module_qualified)
    {
        return None;
    }
    let result = call.result?;
    let has_allocation = caller
        .allocations()
        .iter()
        .any(|allocation| allocation.result == result);
    let receiverless = module_qualified
        || matches!(
            caller_receiver_binding,
            None | Some(CallerReceiverBinding::Absent)
        );
    (has_allocation || receiverless).then_some(result)
}

impl CallBindings {
    pub fn new<I>(
        call: CallSiteHandle,
        candidate: &DispatchCandidate,
        context: OracleCallContext,
        bindings: I,
        coverage: CandidateCoverage,
        limits: OracleLimits,
    ) -> Result<Self, OracleContractError>
    where
        I: IntoIterator<Item = CallBinding>,
    {
        candidate.validate_for_call(&call)?;
        let bindings = collect_bounded(
            bindings,
            limits.call_binding_entries(),
            "call_binding_entries",
        )?;
        let retained_entries = bindings.iter().fold(bindings.len(), |total, binding| {
            let CallBinding::ArgumentGroup(group) = binding else {
                return total;
            };
            total
                .saturating_add(group.sources().len())
                .saturating_add(group.mappings().len())
        });
        if retained_entries > limits.call_binding_entries() {
            return Err(OracleContractError::LimitExceeded {
                dimension: "call_binding_entries",
                limit: limits.call_binding_entries(),
                attempted: retained_entries,
            });
        }
        let callee = candidate.target().clone();
        let caller = call.procedure();
        let call_row = caller
            .semantics()
            .call_site(call.id())
            .expect("call-site handles are validated at construction");
        let constructed_result =
            constructor_call_result(caller.semantics(), call_row, callee.semantics()).filter(
                |_| {
                    callee.semantics().properties().construction_return
                        == crate::analyzer::semantic::ir::ConstructionReturn::PreservesAllocation
                },
            );
        let relation_owner = OracleRelationOwner::CallBinding {
            call: call.clone(),
            callee: callee.clone(),
            context: context.clone(),
        };
        let mut relation_ids = std::collections::HashSet::new();
        let mut first_relation = None;
        let mut actual_sources = std::collections::HashSet::new();
        let mut formal_bindings = std::collections::HashSet::new();
        let mut formal_mapping_counts = std::collections::HashMap::<u32, usize>::new();
        let mut implicit_formals = std::collections::HashSet::new();
        let caller_receiver_binding = caller.semantics().proven_caller_receiver_binding(call.id());
        let mut has_receiver = false;
        let mut normal_return_bindings = std::collections::HashSet::new();
        let mut has_exceptional_return = false;
        let mut has_open_group = false;
        let mut has_truncated_group = false;
        for binding in &bindings {
            match binding {
                CallBinding::Receiver {
                    relation,
                    actual,
                    formal,
                } => {
                    validate_call_binding_relation(
                        relation,
                        &relation_owner,
                        &mut first_relation,
                        &mut relation_ids,
                    )?;
                    if !relation.record().is_proven_complete() {
                        return Err(OracleContractError::InvalidRelationQuality);
                    }
                    require_same_procedure(actual.procedure(), caller)?;
                    require_same_procedure(formal.procedure(), &callee)?;
                    // A call that spells a receiver operand binds exactly that
                    // operand. An unbound method accounts for its receiver in
                    // an argument group. Other receiverless calls can bind a
                    // class qualifier or structurally proven implicit actuals: the caller's own
                    // dispatch receiver (a bare call between members of one
                    // declaring type dispatches on `this`), or -- a
                    // constructor call, `new Type(...)`, which spells no
                    // receiver syntax at all -- the exact object this call's
                    // own `result` allocated (#2574: the constructor's own
                    // `this` can only ever be the object being constructed).
                    let receiver_actual_matches = match (call_row.receiver, caller_receiver_binding)
                    {
                        (
                            Some(receiver),
                            Some(CallerReceiverBinding::ModuleQualified(qualifier)),
                        ) if receiver == qualifier => {
                            constructor_call_result(
                                caller.semantics(),
                                call_row,
                                callee.semantics(),
                            ) == Some(actual.id())
                        }
                        (Some(_), Some(CallerReceiverBinding::ModuleQualified(_))) => false,
                        (Some(receiver), _) => receiver == actual.id(),
                        (None, _)
                            if call
                                .source_receiver_argument_index(callee.semantics())
                                .is_some() =>
                        {
                            false
                        }
                        (None, _) => {
                            (matches!(caller_receiver_binding,
                                Some(CallerReceiverBinding::TypeQualified(qualifier))
                                    if qualifier == actual.id())
                                && callee.semantics().properties().receiver_binding
                                    == ProcedureReceiverBinding::Class)
                                || caller.semantics().value(actual.id()).is_some_and(|row| {
                                    matches!(
                                        row.kind,
                                        SemanticValueKind::Receiver { dispatch: true, .. }
                                    )
                                })
                                || constructor_call_result(
                                    caller.semantics(),
                                    call_row,
                                    callee.semantics(),
                                ) == Some(actual.id())
                        }
                    };
                    if !receiver_actual_matches || formal.kind() != ProcedurePortKind::Receiver {
                        return Err(OracleContractError::InvalidCallBinding(
                            "receiver binding does not match the call receiver and callee receiver port",
                        ));
                    }
                    if has_receiver {
                        return Err(OracleContractError::InvalidCallBinding(
                            "call binding contains more than one receiver relation",
                        ));
                    }
                    has_receiver = true;
                }
                CallBinding::ArgumentGroup(group) => {
                    validate_call_binding_relation(
                        group.closure_relation(),
                        &relation_owner,
                        &mut first_relation,
                        &mut relation_ids,
                    )?;
                    if group.coverage().is_exhaustive()
                        && !group.closure_relation().record().is_proven_complete()
                    {
                        return Err(OracleContractError::InvalidRelationQuality);
                    }
                    has_open_group |= group.coverage() == CandidateCoverage::Open;
                    has_truncated_group |= group.coverage().is_truncated();
                    for source_index in group.sources() {
                        let Some(argument) = call_row.arguments.get(*source_index as usize) else {
                            return Err(OracleContractError::InvalidCallBinding(
                                "argument group names a source outside the exact call",
                            ));
                        };
                        if !actual_sources.insert(*source_index) {
                            return Err(OracleContractError::InvalidCallBinding(
                                "one syntactic argument source appears in multiple groups",
                            ));
                        }
                        let has_mapping = group
                            .mappings()
                            .iter()
                            .any(|mapping| mapping.value().source_index == *source_index);
                        if group.coverage().is_exhaustive()
                            && !argument.expansion.is_spread()
                            && !has_mapping
                        {
                            return Err(OracleContractError::InvalidCallBinding(
                                "an exhaustive direct-argument group omits its mapping",
                            ));
                        }
                    }
                    for backed_mapping in group.mappings() {
                        if backed_mapping.provenance().is_empty() {
                            return Err(OracleContractError::InvalidRelationIdentity);
                        }
                        for relation in backed_mapping.provenance() {
                            validate_call_binding_relation(
                                relation,
                                &relation_owner,
                                &mut first_relation,
                                &mut relation_ids,
                            )?;
                            if !relation.record().supports_quality(
                                backed_mapping.proof(),
                                backed_mapping.completeness(),
                            ) {
                                return Err(OracleContractError::InvalidRelationQuality);
                            }
                        }
                        let mapping = backed_mapping.value();
                        let argument = call_row
                            .arguments
                            .get(mapping.source_index as usize)
                            .expect("group sources were validated above");
                        validate_argument_endpoint(
                            &mapping.actual,
                            mapping.mode,
                            caller,
                            call_row.point,
                            &context,
                        )?;
                        require_same_procedure(mapping.formal.procedure(), &callee)?;
                        if argument.value != mapping.actual.value().id()
                            || !member_matches_expansion(&argument.expansion, &mapping.member)
                        {
                            return Err(OracleContractError::InvalidCallBinding(
                                "argument mapping does not match the call source expansion",
                            ));
                        }
                        if mapping.formal.kind() == ProcedurePortKind::Receiver {
                            if has_receiver
                                || call
                                    .source_receiver_argument_index(callee.semantics())
                                    .is_none()
                                || !matches!(
                                    argument.expansion,
                                    CallArgumentExpansion::Direct(
                                        ArgumentDomain::Positional
                                            | ArgumentDomain::PositionalOrKeyword
                                    )
                                )
                                || call_row.arguments[..mapping.source_index as usize]
                                    .iter()
                                    .any(|source| {
                                        matches!(
                                            source.expansion,
                                            CallArgumentExpansion::Direct(
                                                ArgumentDomain::Positional
                                                    | ArgumentDomain::PositionalOrKeyword
                                            ) | CallArgumentExpansion::Spread(
                                                ArgumentDomain::Positional
                                                    | ArgumentDomain::PositionalOrKeyword
                                            )
                                        )
                                    })
                            {
                                return Err(OracleContractError::InvalidCallBinding(
                                    "receiver argument does not match an unbound method's first positional actual",
                                ));
                            }
                            has_receiver = true;
                            continue;
                        }
                        let ProcedurePortKind::Parameter { ordinal } = mapping.formal.kind() else {
                            return Err(OracleContractError::InvalidCallBinding(
                                "argument mapping does not name a callee parameter or receiver port",
                            ));
                        };
                        let multiplicity = mapping
                            .formal
                            .formal_multiplicity()
                            .expect("validated parameter port has multiplicity");
                        if implicit_formals.contains(&ordinal) {
                            return Err(OracleContractError::InvalidCallBinding(
                                "argument mapping conflicts with an implicit formal binding",
                            ));
                        }
                        let count = formal_mapping_counts.entry(ordinal).or_default();
                        match multiplicity {
                            FormalMultiplicity::One if *count > 0 => {
                                return Err(OracleContractError::InvalidCallBinding(
                                    "call binding maps one non-rest formal more than once",
                                ));
                            }
                            FormalMultiplicity::Rest(domain)
                                if !rest_domain_accepts_mapping(
                                    domain,
                                    &argument.expansion,
                                    &mapping.member,
                                ) =>
                            {
                                return Err(OracleContractError::InvalidCallBinding(
                                    "argument member domain is incompatible with the rest formal",
                                ));
                            }
                            FormalMultiplicity::One | FormalMultiplicity::Rest(_) => {}
                        }
                        *count = count.saturating_add(1);
                        formal_bindings.insert(ordinal);
                    }
                }
                CallBinding::ImplicitArgument {
                    relation,
                    formal_ordinal,
                    source,
                    formal,
                    ..
                } => {
                    validate_call_binding_relation(
                        relation,
                        &relation_owner,
                        &mut first_relation,
                        &mut relation_ids,
                    )?;
                    if !relation.record().is_proven_complete() {
                        return Err(OracleContractError::InvalidRelationQuality);
                    }
                    require_same_procedure(formal.procedure(), &callee)?;
                    if source.procedure() != caller && source.procedure() != &callee {
                        return Err(OracleContractError::CrossProcedure);
                    }
                    if let SemanticValueKind::DefaultArgument { ordinal } = source
                        .procedure()
                        .semantics()
                        .value(source.id())
                        .expect("a value handle names a live value")
                        .kind
                        && (source.procedure() != &callee || ordinal != *formal_ordinal)
                    {
                        return Err(OracleContractError::InvalidCallBinding(
                            "saved default does not name its callee parameter",
                        ));
                    }
                    if formal.kind()
                        != (ProcedurePortKind::Parameter {
                            ordinal: *formal_ordinal,
                        })
                        || formal_bindings.contains(formal_ordinal)
                        || !implicit_formals.insert(*formal_ordinal)
                    {
                        return Err(OracleContractError::InvalidCallBinding(
                            "implicit argument does not name one unbound callee parameter",
                        ));
                    }
                    formal_bindings.insert(*formal_ordinal);
                }
                CallBinding::NormalReturn {
                    relation,
                    formal,
                    result,
                } => {
                    validate_call_binding_relation(
                        relation,
                        &relation_owner,
                        &mut first_relation,
                        &mut relation_ids,
                    )?;
                    if !relation.record().is_proven_complete() {
                        return Err(OracleContractError::InvalidRelationQuality);
                    }
                    require_same_procedure(formal.procedure(), &callee)?;
                    require_same_procedure(result.procedure(), caller)?;
                    if Some(result.id()) == constructed_result {
                        return Err(OracleContractError::InvalidCallBinding(
                            "a construction result cannot be bound to its initializer return",
                        ));
                    }
                    let return_matches = match formal.kind() {
                        ProcedurePortKind::NormalReturn => call_row.result == Some(result.id()),
                        ProcedurePortKind::IndexedNormalReturn { ordinal } => {
                            !call_row.normal_results.is_empty()
                                && call_row.normal_result(ordinal as usize) == Some(result.id())
                        }
                        _ => false,
                    };
                    if !return_matches {
                        return Err(OracleContractError::InvalidCallBinding(
                            "normal-return binding does not match the call result and callee return port",
                        ));
                    }
                    if !normal_return_bindings.insert(formal.kind()) {
                        return Err(OracleContractError::InvalidCallBinding(
                            "call binding contains more than one relation for one normal-return port",
                        ));
                    }
                }
                CallBinding::ExceptionalReturn {
                    relation,
                    formal,
                    result,
                } => {
                    validate_call_binding_relation(
                        relation,
                        &relation_owner,
                        &mut first_relation,
                        &mut relation_ids,
                    )?;
                    if !relation.record().is_proven_complete() {
                        return Err(OracleContractError::InvalidRelationQuality);
                    }
                    require_same_procedure(formal.procedure(), &callee)?;
                    require_same_procedure(result.procedure(), caller)?;
                    if call_row.thrown != Some(result.id())
                        || formal.kind() != ProcedurePortKind::ExceptionalReturn
                    {
                        return Err(OracleContractError::InvalidCallBinding(
                            "exceptional-return binding does not match the call thrown value and callee exceptional port",
                        ));
                    }
                    if has_exceptional_return {
                        return Err(OracleContractError::InvalidCallBinding(
                            "call binding contains more than one exceptional-return relation",
                        ));
                    }
                    has_exceptional_return = true;
                }
            }
        }
        if has_truncated_group && coverage != CandidateCoverage::Truncated {
            return Err(OracleContractError::InvalidCallBinding(
                "a truncated argument group requires truncated call-binding coverage",
            ));
        }
        if has_open_group && coverage.is_exhaustive() {
            return Err(OracleContractError::InvalidCallBinding(
                "an open argument group cannot support exhaustive call bindings",
            ));
        }
        if coverage.is_exhaustive() {
            let all_actuals_bound =
                (0..call_row.arguments.len()).all(|index| actual_sources.contains(&(index as u32)));
            let all_formals_bound = callee
                .semantics()
                .values()
                .iter()
                .filter_map(|value| match &value.kind {
                    SemanticValueKind::Parameter {
                        ordinal,
                        multiplicity: FormalMultiplicity::One,
                        ..
                    } => Some(*ordinal),
                    _ => None,
                })
                .all(|ordinal| formal_bindings.contains(&ordinal));
            let receiver_bound = !callee
                .semantics()
                .values()
                .iter()
                .any(|value| matches!(value.kind, SemanticValueKind::Receiver { .. }))
                || has_receiver;
            let returns_bound = if call_row.normal_results.is_empty() {
                call_row.result.is_none()
                    || call_row.result == constructed_result
                    || normal_return_bindings.contains(&ProcedurePortKind::NormalReturn)
            } else {
                call_row
                    .normal_results
                    .iter()
                    .enumerate()
                    .all(|(ordinal, result)| {
                        Some(*result) == constructed_result
                            || normal_return_bindings.contains(
                                &ProcedurePortKind::IndexedNormalReturn {
                                    ordinal: ordinal as u32,
                                },
                            )
                    })
            };
            let throws_bound = call_row.thrown.is_none() || has_exceptional_return;
            if !all_actuals_bound
                || !all_formals_bound
                || !receiver_bound
                || !returns_bound
                || !throws_bound
            {
                return Err(OracleContractError::InvalidCallBinding(
                    "exhaustive call bindings omit an actual, formal, receiver, or return relation",
                ));
            }
        }
        validate_retained_relation_arenas(
            candidate.provenance().iter().chain(relation_ids.iter()),
            limits,
        )?;
        Ok(Self {
            call,
            candidate: candidate.clone(),
            context,
            bindings: bindings.into_boxed_slice(),
            coverage,
        })
    }

    #[doc(hidden)]
    pub fn retained_artifacts(
        &self,
        census: &mut crate::analyzer::semantic::service::ArtifactRetentionCensus,
    ) {
        census.procedure(self.call().procedure());
        census.context(self.context());
        self.candidate.retained_artifacts(census);
        for binding in self.bindings() {
            match binding {
                CallBinding::Receiver {
                    relation,
                    actual,
                    formal,
                } => {
                    relation.retained_artifacts(census);
                    census.procedure(actual.procedure());
                    census.procedure(formal.procedure());
                }
                CallBinding::ImplicitArgument {
                    relation,
                    source,
                    formal,
                    ..
                } => {
                    relation.retained_artifacts(census);
                    census.procedure(source.procedure());
                    census.procedure(formal.procedure());
                }
                CallBinding::NormalReturn {
                    relation,
                    formal,
                    result,
                }
                | CallBinding::ExceptionalReturn {
                    relation,
                    formal,
                    result,
                } => {
                    relation.retained_artifacts(census);
                    census.procedure(formal.procedure());
                    census.procedure(result.procedure());
                }
                CallBinding::ArgumentGroup(group) => {
                    group.closure_relation.retained_artifacts(census);
                    for mapping in group.mappings() {
                        for relation in mapping.provenance() {
                            relation.retained_artifacts(census);
                        }
                        census.procedure(mapping.value().actual().value().procedure());
                        census.procedure(mapping.value().formal().procedure());
                    }
                }
            }
        }
    }

    pub fn call(&self) -> &CallSiteHandle {
        &self.call
    }

    pub fn callee(&self) -> &ProcedureHandle {
        self.candidate.target()
    }

    pub fn candidate(&self) -> &DispatchCandidate {
        &self.candidate
    }

    pub fn bindings(&self) -> &[CallBinding] {
        &self.bindings
    }

    pub fn context(&self) -> &OracleCallContext {
        &self.context
    }

    pub const fn coverage(&self) -> CandidateCoverage {
        self.coverage
    }
}
