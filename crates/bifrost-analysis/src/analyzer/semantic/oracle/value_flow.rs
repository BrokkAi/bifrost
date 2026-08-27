use std::sync::Arc;

use super::super::ir::{
    CaptureSource, EvidenceCompleteness, ProcedureHandle, ProgramPointHandle, ProofStatus,
    SemanticEffect, SemanticValueKind, ValueFlowKind, ValueHandle,
};
use super::error::{OracleContractError, require_same_procedure};
use super::limits::OracleLimits;
use super::model::{
    AbstractLocation, AbstractObjectIdentity, ExecutionTiming, ExecutionTimingClaim,
    OracleCallContext, ProcedurePortHandle, ProcedurePortKind,
};
use super::relation::{
    CandidateCoverage, OracleRelationHandle, OracleRelationKind, OracleRelationOwner,
    validate_retained_relation_arenas,
};
use crate::analyzer::semantic::{SemanticGapId, ValueId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValueFlowRelationKind {
    Assignment,
    Parameter,
    Receiver,
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

fn port_endpoint(endpoint: &ValueFlowEndpoint, expected: ProcedurePortKind) -> bool {
    matches!(endpoint, ValueFlowEndpoint::Port(port) if port.kind() == expected)
}

/// Where one value's defining event took it from.
///
/// This mirrors `workspace_oracle::value_flow::LoadOrigin`, which the minting
/// side's access-path resolver walks, and merges a value more than one event
/// defines differently to `Ambiguous` by the same rule. The two must answer
/// the same question about the same chain: what the resolver saw is exactly
/// what decides which relations get minted, so what this layer accepts has to
/// be derived from the same walk.
#[derive(PartialEq, Eq)]
enum ValueOrigin {
    Copy(ValueId),
    Load(crate::analyzer::semantic::MemoryLocationId),
    Ambiguous,
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
                let defined = match event.effect {
                    SemanticEffect::Assignment { target, value }
                    | SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Local,
                        target,
                        source: value,
                    } => (target, ValueOrigin::Copy(value)),
                    SemanticEffect::MemoryLoad {
                        location, result, ..
                    } => (result, ValueOrigin::Load(location)),
                    _ => continue,
                };
                origins
                    .entry(defined.0)
                    .and_modify(|existing| {
                        if *existing != defined.1 {
                            *existing = ValueOrigin::Ambiguous;
                        }
                    })
                    .or_insert(defined.1);
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

        let mut current = location;
        let mut visited_locations = std::collections::HashSet::new();
        let mut visited_values = std::collections::HashSet::new();
        loop {
            if !visited_locations.insert(current) {
                return false;
            }
            let Some(row) = procedure.semantics().memory_location(current) else {
                return false;
            };
            let base = match row.kind {
                MemoryLocationKind::Index { .. } => return true,
                MemoryLocationKind::Field { base, .. } => base,
                MemoryLocationKind::Static { .. }
                | MemoryLocationKind::LexicalCell { .. }
                | MemoryLocationKind::Capture { .. } => return false,
            };
            // Walk the base back through the unconditional copies that define
            // it, exactly as `walk_value_origin` does, and continue the chain
            // at the location its defining load read.
            let mut value = base;
            let loaded = loop {
                match self.origins.get(&value) {
                    Some(ValueOrigin::Copy(next)) if visited_values.insert(value) => value = *next,
                    Some(ValueOrigin::Load(location)) => break Some(*location),
                    Some(ValueOrigin::Copy(_) | ValueOrigin::Ambiguous) | None => break None,
                }
            };
            let Some(loaded) = loaded else {
                return false;
            };
            current = loaded;
        }
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
                && value_endpoint(&relation.source, *value)
                && value_endpoint(&relation.target, *target))
                || is_container_collapse(relation, *target)
        }
        SemanticEffect::ValueFlow {
            kind: ValueFlowKind::Local,
            source,
            target,
        } => {
            (relation.kind == ValueFlowRelationKind::Assignment
                && value_endpoint(&relation.source, *source)
                && value_endpoint(&relation.target, *target))
                || is_container_collapse(relation, *target)
        }
        SemanticEffect::ValueFlow {
            kind: ValueFlowKind::Parameter,
            source,
            target,
        } => {
            if relation.kind != ValueFlowRelationKind::Parameter {
                return false;
            }
            let source_kind = procedure.semantics().value(*source).map(|row| &row.kind);
            let target_kind = procedure.semantics().value(*target).map(|row| &row.kind);
            match (source_kind, target_kind) {
                (Some(SemanticValueKind::Parameter { ordinal, .. }), _) => {
                    port_endpoint(
                        &relation.source,
                        ProcedurePortKind::Parameter { ordinal: *ordinal },
                    ) && value_endpoint(&relation.target, *target)
                }
                (_, Some(SemanticValueKind::Parameter { ordinal, .. })) => {
                    value_endpoint(&relation.source, *source)
                        && port_endpoint(
                            &relation.target,
                            ProcedurePortKind::Parameter { ordinal: *ordinal },
                        )
                }
                _ => false,
            }
        }
        SemanticEffect::ValueFlow {
            kind: ValueFlowKind::Receiver,
            target,
            ..
        } => {
            relation.kind == ValueFlowRelationKind::Receiver
                && port_endpoint(&relation.source, ProcedurePortKind::Receiver)
                && value_endpoint(&relation.target, *target)
        }
        SemanticEffect::ValueFlow {
            kind: ValueFlowKind::Return,
            source,
            ..
        } => {
            relation.kind == ValueFlowRelationKind::NormalReturn
                && value_endpoint(&relation.source, *source)
                && port_endpoint(&relation.target, ProcedurePortKind::NormalReturn)
        }
        SemanticEffect::ValueFlow {
            kind: ValueFlowKind::LanguageDefined,
            source,
            target,
        } => {
            relation.kind == ValueFlowRelationKind::LanguageDefined
                && value_endpoint(&relation.source, *source)
                && value_endpoint(&relation.target, *target)
        }
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
                && value_endpoint(&relation.source, *value)
                && (matches!(&relation.target, ValueFlowEndpoint::Location(_))
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
    pub source: ValueFlowEndpoint,
    pub target: ValueFlowEndpoint,
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
}

impl ValueFlowRelation {
    pub fn point(&self) -> &ProgramPointHandle {
        &self.point
    }

    pub const fn event_index(&self) -> u32 {
        self.event_index
    }

    pub const fn is_proven_complete(&self) -> bool {
        matches!(self.proof, ProofStatus::Proven)
            && matches!(self.completeness, EvidenceCompleteness::Complete)
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ValueFlowSnapshot {
    procedure: ProcedureHandle,
    context: OracleCallContext,
    relations: Box<[ValueFlowRelation]>,
    coverage: CandidateCoverage,
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
    discharged_gaps: Box<[SemanticGapId]>,
}

impl ValueFlowSnapshot {
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
        discharged_gaps: Vec<SemanticGapId>,
    ) -> Result<Self, OracleContractError> {
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
            if !relation_matches_event(&procedure, relation, &event.effect, &mut chains) {
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
        Ok(Self {
            procedure,
            context,
            relations: relations.into_boxed_slice(),
            coverage,
            discharged_gaps: discharged_gaps.into_boxed_slice(),
        })
    }

    pub fn procedure(&self) -> &ProcedureHandle {
        &self.procedure
    }

    pub fn relations(&self) -> &[ValueFlowRelation] {
        &self.relations
    }

    pub fn context(&self) -> &OracleCallContext {
        &self.context
    }

    pub const fn coverage(&self) -> CandidateCoverage {
        self.coverage
    }

    /// Whether a query-time discharge predicate proved, while this snapshot
    /// was materialized, that `gap` does not apply (#2545). `false` for a
    /// gap this snapshot never examined (a stale or foreign ID) as well as
    /// for one it examined and left standing -- both keep whatever the gap
    /// would otherwise mean to a caller that re-examines this snapshot's
    /// procedure's raw gap list.
    pub fn gap_is_discharged(&self, gap: SemanticGapId) -> bool {
        self.discharged_gaps.contains(&gap)
    }
}
