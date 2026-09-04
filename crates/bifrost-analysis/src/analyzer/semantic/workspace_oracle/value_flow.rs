//! Bounded value-flow and candidate-specific call-binding materialization.
//!
//! The implementation projects validated semantic IR rows into neutral oracle
//! relations. It never reparses source or matches declarations by text,
//! except for one narrow, explicitly named discharge predicate
//! ([`super::external_constant_field_read_discharges_gap`], #2538) composed
//! into the two gap sweeps below: it delegates to `dispatch.rs`'s own
//! source-and-text machinery (already used there to resolve an
//! unmaterialized external *call* target) to prove a specific `FieldMemory`
//! gap is a `static final` read on an external type. Every other relevance
//! and discharge decision in this file stays IR-only.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use super::WorkspaceSemanticOracle;
use super::common::{
    Interruption, WorkStager, dedup_evidence, evidence_handle, evidence_quality, internal_contract,
    value_handle,
};
use crate::analyzer::semantic::cfg_algorithms::{
    CfgAlgorithmBudget, CfgAlgorithmError, CfgAlgorithmRequest,
};
use crate::analyzer::semantic::{
    AbstractLocation, AbstractObject, AbstractObjectIdentity, AccessPath, AccessPathRoot,
    AccessPathTail, AccessSelector, AllocationHandle, BackingStoreOffset, CallArgumentEndpoint,
    CallArgumentExpansion, CallArgumentGroup, CallArgumentMapping, CallArgumentMember, CallBinding,
    CallBindings, CallPassingMode, CandidateCoverage, CaptureSource, ControlEdgeKind,
    DeclarationSegmentKind, DispatchCandidate, EvidenceCompleteness, EvidenceHandle,
    FormalMultiplicity, HeapOracle, IndexSelector, MemoryLocationId, MemoryLocationKind,
    ObjectCardinality, OracleCallContext, OracleCandidate, OracleRelationArena,
    OracleRelationHandle, OracleRelationId, OracleRelationKind, OracleRelationOwner,
    OracleRelationRecord, ProcedureHandle, ProcedureKind, ProcedurePortHandle, ProgramPointHandle,
    ProgramPointId, ProofStatus, ScopedSemanticLocator, SemanticCapability, SemanticEffect,
    SemanticGapDischarge, SemanticGapImpact, SemanticGapKind, SemanticGapSubject, SemanticLocator,
    SemanticOutcome, SemanticProviderError, SemanticRequest, SemanticValueKind, SemanticWork,
    ValueFlowEndpoint, ValueFlowKind, ValueFlowOracle, ValueFlowRelation, ValueFlowRelationKind,
    ValueFlowSnapshot, ValueHandle, ValueId, ValueTransfer, assignment_transfer,
    gap_certifies_canonical_index_identity,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GapOutcomeQuality {
    Ambiguous,
    Unproven,
    Unknown,
    Unsupported(SemanticCapability),
}

/// Combine relation evidence with the strongest typed semantic gap.
///
/// An unproven relation is retained in the partial artifact regardless of the
/// top-level outcome. It must not erase a stronger explanation for why the
/// artifact is incomplete: an unsupported capability or an unknown semantic
/// choice is more actionable than the generic fact that one retained relation
/// is not proven complete. Unproven relation evidence still dominates an
/// ambiguous gap, matching the quality order used by the ICFG builder.
fn merge_relation_quality(
    gap_quality: Option<GapOutcomeQuality>,
    has_unproven_relation: bool,
) -> Option<GapOutcomeQuality> {
    match gap_quality {
        quality @ Some(GapOutcomeQuality::Unsupported(_) | GapOutcomeQuality::Unknown) => quality,
        Some(GapOutcomeQuality::Unproven | GapOutcomeQuality::Ambiguous) | None
            if has_unproven_relation =>
        {
            Some(GapOutcomeQuality::Unproven)
        }
        quality => quality,
    }
}

fn merge_gap_quality(
    current: Option<GapOutcomeQuality>,
    gap: &crate::analyzer::semantic::SemanticGap,
) -> Option<GapOutcomeQuality> {
    use GapOutcomeQuality::{Ambiguous, Unknown, Unproven, Unsupported};
    let incoming = match gap.kind {
        SemanticGapKind::Ambiguous => Ambiguous,
        SemanticGapKind::Unknown => Unknown,
        SemanticGapKind::Unsupported => Unsupported(gap.capability),
        SemanticGapKind::Unproven | SemanticGapKind::ExceededBudget => Unproven,
    };
    Some(match (current, incoming) {
        (Some(Unsupported(capability)), _) => Unsupported(capability),
        (_, Unsupported(capability)) => Unsupported(capability),
        (Some(Unknown), _) | (_, Unknown) => Unknown,
        (Some(Unproven), _) | (_, Unproven) => Unproven,
        (Some(Ambiguous), Ambiguous) | (None, Ambiguous) => Ambiguous,
    })
}

#[derive(Clone)]
struct FlowRelationDraft {
    point: ProgramPointHandle,
    event_index: u32,
    kind: ValueFlowRelationKind,
    transfer: Option<ValueTransfer>,
    source: ValueFlowEndpoint,
    target: ValueFlowEndpoint,
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
    evidence: Vec<EvidenceHandle>,
    strong_update: bool,
}

/// Which base values this procedure can ask a heap-identity question about
/// without leaving the procedure.
///
/// Two things ride on that. The obvious one is cost: both the canonical-index
/// points-to certificate and `update_eligibility` resolve a base value through
/// the full points-to trace, and asking either question for every access in a
/// workspace would pay for a trace that cannot end in a certificate anyway. A
/// base value that is not locally allocated cannot supply either certificate.
///
/// The other is re-entrancy. The points-to trace enters a callee through
/// `materialize_call_result`, which calls `procedure_relations` again. Asking
/// the question from inside `procedure_relations` without this gate would make
/// two mutually recursive procedures materialize each other until the budget
/// ran out. A base value whose every backward producer chain ends at an
/// allocation of this procedure never reaches that path, because the trace
/// stops at the allocation effect.
struct LocalStoreBases {
    /// Copy producers, as (target, source) pairs in target order.
    copies: Box<[(ValueId, ValueId)]>,
    /// Copy consumers, as (source, target) pairs in source order.
    forward_copies: Box<[(ValueId, ValueId)]>,
    /// Exact backing-store aliases, as (source, target) pairs in source order.
    backing_aliases: Box<[(ValueId, ValueId)]>,
    allocation_results: HashSet<ValueId>,
    array_allocation_results: HashSet<ValueId>,
    slice_allocation_results: HashSet<ValueId>,
    /// Values that own a language binding rather than naming one temporary
    /// occurrence of that binding.
    binding_values: HashSet<ValueId>,
    /// Values a call or a memory load produces, which the trace would follow
    /// out of this procedure or open.
    foreign: HashSet<ValueId>,
    /// Values whose address escapes into an explicit address value or whose
    /// binding is captured by a nested procedure. Either shape lets code
    /// outside the local copy graph observe or mutate an array allocation.
    escaped: HashSet<ValueId>,
}

impl LocalStoreBases {
    fn derive(semantics: &crate::analyzer::semantic::ProcedureSemantics) -> Self {
        let mut copies = Vec::new();
        let mut backing_aliases = Vec::new();
        let mut foreign = HashSet::new();
        let mut escaped = HashSet::new();
        for point in semantics.points() {
            for (event_index, event) in point.events.iter().enumerate() {
                if let SemanticEffect::Assignment { target, value } = event.effect
                    && semantics
                        .value(target)
                        .is_some_and(|target| target.kind == SemanticValueKind::Address)
                {
                    escaped.insert(value);
                }
                if let SemanticEffect::ValueFlow { source, target, .. } = event.effect
                    && semantics
                        .value(target)
                        .is_some_and(|target| target.kind == SemanticValueKind::Address)
                {
                    escaped.insert(source);
                }
                if let SemanticEffect::CaptureBind { capture } = event.effect
                    && let Some(capture) = semantics.capture(capture)
                    && let CaptureSource::Value(value) = capture.captured
                {
                    escaped.insert(value);
                }
                match event.effect {
                    SemanticEffect::Assignment { target, value }
                        if assignment_transfer(&point.events, event_index, value, target)
                            .is_none() =>
                    {
                        copies.push((target, value))
                    }
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Local,
                        source,
                        target,
                    } => copies.push((target, source)),
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::BackingStore { .. },
                        source,
                        target,
                    } => {
                        copies.push((target, source));
                        backing_aliases.push((source, target));
                    }
                    SemanticEffect::MemoryLoad { result, .. } => {
                        foreign.insert(result);
                    }
                    _ => {}
                }
            }
        }
        let allocation_results: HashSet<ValueId> = semantics
            .allocations()
            .iter()
            .map(|allocation| allocation.result)
            .collect();
        let array_allocation_results = semantics
            .allocations()
            .iter()
            .filter_map(|allocation| {
                (allocation.kind == crate::analyzer::semantic::AllocationKind::Array)
                    .then_some(allocation.result)
            })
            .collect();
        let slice_allocation_results = semantics
            .allocations()
            .iter()
            .filter_map(|allocation| {
                (allocation.kind == crate::analyzer::semantic::AllocationKind::Slice)
                    .then_some(allocation.result)
            })
            .collect();
        for call in semantics.call_sites() {
            // A constructor call whose result is this procedure's own
            // allocation does not carry the object in from elsewhere -- it is
            // how several adapters lower `new`. Treating it as foreign would
            // make every constructed object unresolvable here.
            foreign.extend(
                call.normal_result_values()
                    .filter(|result| !allocation_results.contains(result)),
            );
            foreign.extend(call.thrown);
        }
        copies.sort_unstable();
        copies.dedup();
        let mut forward_copies = copies
            .iter()
            .map(|(target, source)| (*source, *target))
            .collect::<Vec<_>>();
        forward_copies.sort_unstable();
        backing_aliases.sort_unstable();
        backing_aliases.dedup();
        let binding_values = semantics
            .values()
            .iter()
            .filter_map(|value| {
                matches!(
                    value.kind,
                    SemanticValueKind::Local
                        | SemanticValueKind::Parameter { .. }
                        | SemanticValueKind::Receiver { .. }
                )
                .then_some(value.id)
            })
            .collect();
        Self {
            copies: copies.into_boxed_slice(),
            forward_copies: forward_copies.into_boxed_slice(),
            backing_aliases: backing_aliases.into_boxed_slice(),
            allocation_results,
            array_allocation_results,
            slice_allocation_results,
            binding_values,
            foreign,
            escaped,
        }
    }

    /// Whether every backward producer chain from `base` ends at an allocation
    /// of this procedure.
    fn is_locally_allocated(&self, base: ValueId) -> bool {
        let mut pending = vec![base];
        let mut seen = HashSet::new();
        while let Some(value) = pending.pop() {
            if !seen.insert(value) {
                continue;
            }
            if self.foreign.contains(&value) {
                return false;
            }
            if self.allocation_results.contains(&value) {
                continue;
            }
            let start = self.copies.partition_point(|(target, _)| *target < value);
            let sources = self.copies[start..]
                .iter()
                .take_while(|(target, _)| *target == value);
            let mut any = false;
            for (_, source) in sources {
                any = true;
                pending.push(*source);
            }
            if !any {
                return false;
            }
        }
        true
    }

    /// Whether each allocation that can produce `base` reaches at most one
    /// language binding through the IR's local-copy relation.
    ///
    /// A producer-authored `AggregateCopy` is removed from this identity graph
    /// altogether. An ordinary aggregate assignment remains ambiguous between
    /// identity aliasing and a by-value copy. A producer-authored
    /// `BackingStore` edge is the exact exception: every secondary slice
    /// binding reached solely by those edges still names the allocation's one
    /// element store. Array roots never receive this exception, so
    /// `second := first` retains copy semantics rather than being silently
    /// treated as an alias.
    /// Temporary occurrence values are deliberately ignored: they do not own
    /// storage, and duplicate Assignment/Local events were removed in
    /// `derive`. A backward copy cycle with no allocation root fails closed;
    /// the caller separately requires the heap oracle's singleton allocation
    /// certificate.
    fn canonical_base_has_no_secondary_binding_owner(&self, base: ValueId) -> bool {
        let mut pending = vec![base];
        let mut seen = HashSet::new();
        let mut roots = HashSet::new();
        while let Some(value) = pending.pop() {
            if !seen.insert(value) {
                continue;
            }
            if self.foreign.contains(&value) {
                return false;
            }
            if self.allocation_results.contains(&value) {
                roots.insert(value);
                continue;
            }
            let start = self.copies.partition_point(|(target, _)| *target < value);
            let sources = self.copies[start..]
                .iter()
                .take_while(|(target, _)| *target == value);
            let mut any = false;
            for (_, source) in sources {
                any = true;
                pending.push(*source);
            }
            if !any {
                return false;
            }
        }
        if roots.len() != 1 {
            return false;
        }

        for root in roots {
            let mut pending = vec![root];
            let mut seen = HashSet::new();
            let mut owners = HashSet::new();
            while let Some(value) = pending.pop() {
                if !seen.insert(value) {
                    continue;
                }
                if self.binding_values.contains(&value) {
                    owners.insert(value);
                }
                let start = self
                    .forward_copies
                    .partition_point(|(source, _)| *source < value);
                for (_, target) in self.forward_copies[start..]
                    .iter()
                    .take_while(|(source, _)| *source == value)
                {
                    pending.push(*target);
                }
            }
            if owners.len() > 1 {
                if !self.slice_allocation_results.contains(&root) {
                    return false;
                }
                let mut aliased = HashSet::from([root]);
                let mut pending = vec![root];
                while let Some(value) = pending.pop() {
                    let start = self
                        .forward_copies
                        .partition_point(|(source, _)| *source < value);
                    for (_, target) in self.forward_copies[start..]
                        .iter()
                        .take_while(|(source, _)| *source == value)
                    {
                        // Reading a slice binding produces a temporary slice
                        // descriptor through an ordinary Local edge. It still
                        // names the same backing store, but an ordinary edge
                        // into another binding is exactly the ambiguous
                        // aggregate-assignment case this proof must reject.
                        let exact_alias = !self.binding_values.contains(target)
                            || self
                                .backing_aliases
                                .binary_search(&(value, *target))
                                .is_ok();
                        if exact_alias && aliased.insert(*target) {
                            pending.push(*target);
                        }
                    }
                }
                if !owners.is_subset(&aliased) {
                    return false;
                }
            }
        }
        true
    }

    /// Whether `base` is backed by exactly one fresh local array whose
    /// copy closure never escapes by address or capture.
    ///
    /// Go arrays have value semantics. An unrelated call cannot change such
    /// an array even when evaluation-order uncertainty makes the generic heap
    /// oracle decline a points-to certificate. Slices deliberately fail this
    /// predicate because their copied descriptors retain one backing store;
    /// arrays with a second binding owner fail the caller's separate owner
    /// check so a by-value copy is never promoted into alias identity.
    fn is_closed_local_array(&self, base: ValueId) -> bool {
        let mut pending = vec![base];
        let mut seen = HashSet::new();
        let mut roots = HashSet::new();
        while let Some(value) = pending.pop() {
            if !seen.insert(value) {
                continue;
            }
            if self.foreign.contains(&value) {
                return false;
            }
            if self.allocation_results.contains(&value) {
                if !self.array_allocation_results.contains(&value) {
                    return false;
                }
                roots.insert(value);
                continue;
            }
            let start = self.copies.partition_point(|(target, _)| *target < value);
            let sources = self.copies[start..]
                .iter()
                .take_while(|(target, _)| *target == value);
            let mut any = false;
            for (_, source) in sources {
                any = true;
                pending.push(*source);
            }
            if !any {
                return false;
            }
        }
        if roots.len() != 1 {
            return false;
        }

        let mut pending = roots.into_iter().collect::<Vec<_>>();
        let mut seen = HashSet::new();
        while let Some(value) = pending.pop() {
            if !seen.insert(value) {
                continue;
            }
            if self.escaped.contains(&value) {
                return false;
            }
            let start = self
                .forward_copies
                .partition_point(|(source, _)| *source < value);
            pending.extend(
                self.forward_copies[start..]
                    .iter()
                    .take_while(|(source, _)| *source == value)
                    .map(|(_, target)| *target),
            );
        }
        true
    }
}

/// Why a derived handler binding is never a proven, complete relation.
///
/// The IR carries no type for a thrown value and no caught type for a catch
/// clause, so nothing at this layer can decide which alternative the runtime
/// selects. The relation is published anyway, as a may-bind to each reachable
/// alternative, because dropping it would leave a caught value unanalyzed
/// while the run still looked decisive.
const HANDLER_SELECTION_UNPROVEN: &str =
    "handler selection is not proven: the thrown value may bind to any reachable catch clause";

/// Where a thrown value can be bound by a handler of the same procedure
/// (#2446).
///
/// Several adapters bind the caught value at lowering time when the handler is
/// unambiguous: the Java lowerer writes a `ValueFlow` effect from the thrown
/// value to the catch parameter when a `try` has exactly one catch clause with
/// a precise type. When it cannot select the handler -- more than one clause,
/// or a union type -- it publishes an `ExceptionalControlFlow` gap at the
/// dispatcher instead and binds nothing, so the caught value is unreachable
/// for every downstream client.
///
/// This derivation answers the part the lowering left open, from rows the IR
/// already carries and without asking any adapter for new events:
///
/// * A *dispatcher* is a point that selects between handler alternatives:
///   it has `SwitchCase` successors, an `Exceptional` successor for the
///   throw it does not match, and an undischarged point-scoped
///   `ExceptionalControlFlow` gap. That gap is exactly the adapter's own
///   record that it could not select, so a handler the adapter already bound
///   is never derived here a second time.
/// * A handler's *binding* is the procedure-local value the runtime assigns
///   the caught exception to. It is identified structurally: a `Local` value
///   that no event in the procedure ever defines, and that is read at a point
///   the handler's entry dominates. Nothing about source ranges or names
///   enters this; the nearest dominating handler entry owns the read, so a
///   `try` nested inside a handler body attributes its own binding to itself.
/// * A throw reaches a dispatcher through the `Exceptional` and `Cleanup`
///   edges the adapter already routed. The walk does not follow `SwitchCase`
///   edges, so it passes through a dispatcher that already bound its handler
///   by way of that dispatcher's unmatched route, which is what the runtime
///   does.
///
/// Handler *selection* stays unproven. Deciding which alternative catches a
/// given throw needs the thrown value's type and each clause's caught type,
/// and neither is in the IR, so the derived relations bind the value to every
/// alternative the route can reach and say so in their proof and completeness.
/// That is an over-approximation for a may analysis, never a clean answer:
/// a handler this derivation cannot resolve keeps the dispatcher's gap, and
/// the gap keeps the snapshot open.
#[derive(Debug, Default)]
struct HandlerBindings {
    /// Throw point -> the handler bindings that point's exception route can
    /// reach, in dispatcher alternative order and without repeats.
    by_throw_point: HashMap<ProgramPointId, Box<[ValueId]>>,
    /// Handler binding -> the thrown value the runtime copies into it, for the
    /// one throw that reaches it. A binding more than one throw reaches has no
    /// single origin and is [`LoadOrigin::Ambiguous`].
    ///
    /// This is what makes a field read through the binding observe the object
    /// the throw carried. Without it the access-path resolver roots
    /// `caught.field` at the binding itself, which no store can ever reach,
    /// and the derived relation would bind a value nothing then reads.
    binder_origins: HashMap<ValueId, LoadOrigin>,
}

impl HandlerBindings {
    fn derive(
        procedure: &ProcedureHandle,
        cancellation: &crate::CancellationToken,
        mut charge: impl FnMut(SemanticWork) -> Result<(), Interruption>,
    ) -> Result<Self, Interruption> {
        let semantics = procedure.semantics();
        let mut alternatives_by_dispatcher: HashMap<ProgramPointId, Vec<ProgramPointId>> =
            HashMap::new();
        for gap in semantics.gaps() {
            if cancellation.is_cancelled() {
                return Err(Interruption::Cancelled);
            }
            charge(SemanticWork {
                gaps: 1,
                ..SemanticWork::default()
            })?;
            // Completion provenance belongs to result-specific dominance; it
            // does not discharge handler selection or exceptional value
            // binding here, so treat either marker like a standing gap.
            if gap.capability != SemanticCapability::ExceptionalControlFlow
                || gap.subject != SemanticGapSubject::Point
                || !matches!(
                    gap.discharge,
                    SemanticGapDischarge::None
                        | SemanticGapDischarge::NonRejoiningExceptionalExit
                        | SemanticGapDischarge::ExitOnlyProcedureCompletion
                )
            {
                continue;
            }
            let mut alternatives = Vec::new();
            let mut has_residual_route = false;
            for (_, edge) in semantics.successor_edges(gap.point) {
                match edge.kind {
                    ControlEdgeKind::SwitchCase => alternatives.push(edge.target_point),
                    ControlEdgeKind::Exceptional => has_residual_route = true,
                    _ => {}
                }
            }
            if alternatives.is_empty() || !has_residual_route {
                continue;
            }
            alternatives_by_dispatcher.insert(gap.point, alternatives);
        }
        if alternatives_by_dispatcher.is_empty() {
            return Ok(Self::default());
        }

        let binders = Self::handler_binders(procedure, &alternatives_by_dispatcher, cancellation)?;
        let mut by_throw_point = HashMap::new();
        let mut binder_origins: HashMap<ValueId, LoadOrigin> = HashMap::new();
        for point in semantics.points() {
            if cancellation.is_cancelled() {
                return Err(Interruption::Cancelled);
            }
            charge(SemanticWork {
                program_points: 1,
                ..SemanticWork::default()
            })?;
            if !point
                .events
                .iter()
                .any(|event| matches!(event.effect, SemanticEffect::Throw { value: Some(_) }))
            {
                continue;
            }
            let mut reached = Vec::new();
            // The route is walked in two modes. Outside a cleanup region only
            // the abrupt edges belong to it. Inside one -- entered by a
            // `Cleanup` edge -- the region's own statements run on ordinary
            // edges before the route resumes, and each adapter lowers one copy
            // of the region per completion route, so following those edges
            // stays on this throw's route rather than joining the normal one.
            let mut visited: HashSet<(ProgramPointId, bool)> = HashSet::new();
            let mut pending = VecDeque::new();
            pending.push_back((point.id, false));
            visited.insert((point.id, false));
            while let Some((current, in_cleanup)) = pending.pop_front() {
                if cancellation.is_cancelled() {
                    return Err(Interruption::Cancelled);
                }
                charge(SemanticWork {
                    program_points: 1,
                    ..SemanticWork::default()
                })?;
                if current != point.id
                    && let Some(alternatives) = alternatives_by_dispatcher.get(&current)
                {
                    for entry in alternatives {
                        if let Some(binder) = binders.get(entry).copied().flatten()
                            && !reached.contains(&binder)
                        {
                            reached.push(binder);
                        }
                    }
                    continue;
                }
                for (_, edge) in semantics.successor_edges(current) {
                    let follows = match edge.kind {
                        ControlEdgeKind::Exceptional | ControlEdgeKind::Cleanup => true,
                        // A handler alternative is entered by selecting it,
                        // which is the decision this walk is enumerating.
                        ControlEdgeKind::SwitchCase => false,
                        _ => in_cleanup,
                    };
                    if !follows {
                        continue;
                    }
                    let next = (
                        edge.target_point,
                        in_cleanup || edge.kind == ControlEdgeKind::Cleanup,
                    );
                    if visited.insert(next) {
                        pending.push_back(next);
                    }
                }
            }
            if reached.is_empty() {
                continue;
            }
            for thrown in point.events.iter().filter_map(|event| match event.effect {
                SemanticEffect::Throw { value } => value,
                _ => None,
            }) {
                for binder in &reached {
                    binder_origins
                        .entry(*binder)
                        .and_modify(|existing| {
                            if *existing != LoadOrigin::Value(thrown) {
                                *existing = LoadOrigin::Ambiguous;
                            }
                        })
                        .or_insert(LoadOrigin::Value(thrown));
                }
            }
            by_throw_point.insert(point.id, reached.into_boxed_slice());
        }
        Ok(Self {
            by_throw_point,
            binder_origins,
        })
    }

    /// The value each handler entry binds its caught exception to.
    ///
    /// An entry maps to `None` when the procedure offers no unique candidate:
    /// either nothing the entry dominates reads an undefined local, or more
    /// than one does. Both stay unbound rather than picking one, because a
    /// binding written to the wrong local would be a fact about a value the
    /// handler never received.
    fn handler_binders(
        procedure: &ProcedureHandle,
        alternatives_by_dispatcher: &HashMap<ProgramPointId, Vec<ProgramPointId>>,
        cancellation: &crate::CancellationToken,
    ) -> Result<HashMap<ProgramPointId, Option<ValueId>>, Interruption> {
        let semantics = procedure.semantics();
        let mut binders: HashMap<ProgramPointId, Option<ValueId>> = HashMap::new();
        for entries in alternatives_by_dispatcher.values() {
            for entry in entries {
                binders.insert(*entry, None);
            }
        }

        let mut defined: HashSet<ValueId> = semantics
            .allocations()
            .iter()
            .map(|allocation| allocation.result)
            .collect();
        for call in semantics.call_sites() {
            defined.extend(call.normal_result_values());
            defined.extend(call.thrown);
        }
        for point in semantics.points() {
            for event in &point.events {
                match &event.effect {
                    SemanticEffect::Assignment { target, .. }
                    | SemanticEffect::ValueFlow { target, .. } => {
                        defined.insert(*target);
                    }
                    SemanticEffect::MemoryLoad { result, .. }
                    | SemanticEffect::CallableCreation { result, .. }
                    | SemanticEffect::CallableReference { result, .. } => {
                        defined.insert(*result);
                    }
                    SemanticEffect::AsyncResume { result, .. } => {
                        defined.extend(*result);
                    }
                    _ => {}
                }
            }
        }

        let mut budget = crate::analyzer::semantic::cfg_algorithms::CfgAlgorithmBudget::default();
        let mut request = crate::analyzer::semantic::cfg_algorithms::CfgAlgorithmRequest::new(
            &mut budget,
            cancellation,
        );
        let dominators = match crate::analyzer::semantic::cfg_algorithms::dominators(
            semantics,
            semantics.entry_point(),
            &mut request,
        ) {
            Ok(dominators) => dominators,
            Err(crate::analyzer::semantic::cfg_algorithms::CfgAlgorithmError::Cancelled {
                ..
            }) => return Err(Interruption::Cancelled),
            // A procedure whose dominance the shared budget will not pay for
            // publishes no handler binding. Its dispatcher gap is untouched,
            // so the answer stays open rather than becoming clean.
            Err(_) => return Ok(binders),
        };

        let mut ambiguous: HashSet<ProgramPointId> = HashSet::new();
        for (point, value) in read_values(semantics) {
            if cancellation.is_cancelled() {
                return Err(Interruption::Cancelled);
            }
            if defined.contains(&value)
                || !matches!(
                    semantics.value(value).map(|row| &row.kind),
                    Some(SemanticValueKind::Local)
                )
            {
                continue;
            }
            // The nearest dominating handler entry owns the read. The chain
            // strictly ascends, so the walk terminates.
            let mut cursor = Some(point);
            while let Some(current) = cursor {
                if let Some(slot) = binders.get_mut(&current) {
                    match slot {
                        Some(existing) if *existing == value => {}
                        Some(_) => {
                            ambiguous.insert(current);
                        }
                        None if ambiguous.contains(&current) => {}
                        None => *slot = Some(value),
                    }
                    break;
                }
                cursor = dominators.immediate_dominator(semantics, current);
            }
        }
        for entry in ambiguous {
            binders.insert(entry, None);
        }
        Ok(binders)
    }

    fn alternatives_for(&self, point: ProgramPointId) -> &[ValueId] {
        self.by_throw_point
            .get(&point)
            .map_or(&[][..], |values| &values[..])
    }

    fn binder_origins(&self) -> &HashMap<ValueId, LoadOrigin> {
        &self.binder_origins
    }
}

/// Every value one procedure reads, paired with the point that reads it.
///
/// Reads are enumerated from the events and call rows that name a value in an
/// operand position. A value that only appears as the base of a memory row is
/// deliberately absent: the adapters lower a base into an operand of its own
/// before the access, so the operand position is the one that names it.
fn read_values(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
) -> impl Iterator<Item = (ProgramPointId, ValueId)> + '_ {
    let event_reads = semantics.points().iter().flat_map(move |point| {
        point
            .events
            .iter()
            .flat_map(move |event| -> Vec<ValueId> {
                match &event.effect {
                    SemanticEffect::Assignment { value, .. } => vec![*value],
                    SemanticEffect::ValueFlow { source, .. } => vec![*source],
                    SemanticEffect::ValueUse { value, .. } => vec![*value],
                    SemanticEffect::MemoryStore { value, .. } => vec![*value],
                    SemanticEffect::ProcedureReturn { value } | SemanticEffect::Throw { value } => {
                        value.iter().copied().collect()
                    }
                    SemanticEffect::AsyncSuspend { awaited, .. } => {
                        awaited.iter().copied().collect()
                    }
                    SemanticEffect::CaptureBind { capture } => semantics
                        .capture(*capture)
                        .and_then(|row| match row.captured {
                            CaptureSource::Value(value) => Some(value),
                            CaptureSource::Location(_) => None,
                        })
                        .into_iter()
                        .collect(),
                    _ => Vec::new(),
                }
            })
            .map(move |value| (point.id, value))
    });
    let call_reads = semantics.call_sites().iter().flat_map(|call| {
        std::iter::once(call.callee)
            .chain(call.receiver)
            .chain(call.arguments.iter().map(|argument| argument.value))
            .map(move |value| (call.point, value))
    });
    event_reads.chain(call_reads)
}

/// Whether this procedure's relation stream is open because of a capability
/// the procedure needs (#1952).
///
/// Scalar-core capabilities are a blanket requirement: without them the
/// relation stream itself cannot be trusted, however simple the body is.
/// Memory-family capabilities open the snapshot only when the procedure
/// retains a memory row of that kind. IR validation rejects a memory row
/// whose capability is unavailable, so an unavailable memory capability is
/// by construction unused here; a construct the adapter could not lower is
/// reported through its per-construct semantic gap instead, which the gap
/// sweep in `procedure_relations` already applies.
pub fn value_flow_capabilities_are_open(procedure: &ProcedureHandle) -> bool {
    let capabilities = procedure.artifact().capabilities();
    if [
        SemanticCapability::Values,
        SemanticCapability::Assignments,
        SemanticCapability::Allocations,
        SemanticCapability::LocalFlow,
        SemanticCapability::ParameterFlow,
        SemanticCapability::ReceiverFlow,
        SemanticCapability::ReturnFlow,
    ]
    .into_iter()
    .any(|capability| !capabilities.is_available(capability))
    {
        return true;
    }
    let location_capability = |kind: &MemoryLocationKind| match kind {
        MemoryLocationKind::Field { .. } => SemanticCapability::FieldMemory,
        MemoryLocationKind::Static { .. } => SemanticCapability::StaticMemory,
        MemoryLocationKind::Index { .. } => SemanticCapability::IndexMemory,
        MemoryLocationKind::LexicalCell { .. } => SemanticCapability::LocalFlow,
        MemoryLocationKind::Capture { .. } => SemanticCapability::Captures,
    };
    procedure
        .semantics()
        .memory_locations()
        .iter()
        .any(|location| !capabilities.is_available(location_capability(&location.kind)))
        || (!procedure.semantics().captures().is_empty()
            && !capabilities.is_available(SemanticCapability::Captures))
}

/// The call site a call-target refinement gap is scoped to, when the gap is
/// of the dischargeable kind (#1952).
///
/// Adapters publish blanket `Unknown`/`Unproven` gaps ("target requires
/// whole-program dispatch refinement") on every call's site and callee value.
/// The workspace dispatch resolver performs exactly that refinement, so a gap
/// of this shape is answered by a complete resolution of its call and must
/// not independently open the selected path. `Unsupported`, `Ambiguous`, and
/// `ExceededBudget` gaps are never of this shape.
///
/// A gap that declares `SemanticGapDischarge::CallResolution` is dischargeable
/// by the same rule regardless of its capability (#1989): the adapter states
/// that a complete resolution and binding of its call answers the question --
/// for example Scala argument-evaluation strictness, where a deferring callee
/// carries its own procedure-level gap that keeps every binding to it open.
pub fn call_target_refinement_call(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    gap: &crate::analyzer::semantic::SemanticGap,
) -> Option<crate::analyzer::semantic::CallSiteId> {
    let refinement_shape = matches!(
        gap.kind,
        SemanticGapKind::Unknown | SemanticGapKind::Unproven
    ) && matches!(
        gap.capability,
        SemanticCapability::Calls
            | SemanticCapability::CallableReferences
            | SemanticCapability::DynamicDispatch
    );
    if !refinement_shape
        && gap.discharge != crate::analyzer::semantic::SemanticGapDischarge::CallResolution
    {
        return None;
    }
    match gap.subject {
        SemanticGapSubject::CallSite(call_site) => semantics.call_site(call_site).map(|row| row.id),
        SemanticGapSubject::Value(value) => semantics
            .call_sites()
            .iter()
            .find(|row| row.callee == value)
            .map(|row| row.id),
        _ => None,
    }
}

/// Whether an unresolved call-target gap belongs to a zero-argument object
/// allocation whose constructor body is not materialized. The allocation
/// effect itself gives heap flow a complete identity; constructor dispatch is
/// retained as a structured gap but does not invalidate that identity.
pub fn constructor_call_gap_is_discharged(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    gap: &crate::analyzer::semantic::SemanticGap,
) -> bool {
    let Some(call) =
        call_target_refinement_call(semantics, gap).and_then(|call| semantics.call_site(call))
    else {
        return false;
    };
    allocation_call_is_dischargeable(semantics, call)
}

/// Whether an unresolved constructor-call gap leaves the identity of this
/// exact allocation result unchanged.
///
/// Constructor dispatch can still leave the constructor body's heap effects
/// open. It cannot, however, change which object an object-creation
/// expression allocated. Keep this proof value-specific so other values used
/// by the call, and non-allocation call results, retain the gap.
pub(crate) fn constructor_allocation_identity_discharges_gap(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    gap: &crate::analyzer::semantic::SemanticGap,
    value: ValueId,
) -> bool {
    let Some(call) =
        call_target_refinement_call(semantics, gap).and_then(|call| semantics.call_site(call))
    else {
        return false;
    };
    call.result == Some(value)
        && allocation_call_is_dischargeable(semantics, call)
        && semantics
            .allocations()
            .iter()
            .any(|allocation| allocation.result == value)
}

/// Whether a call's retained allocation result makes an unresolved
/// zero-argument constructor boundary fully modeled for value flow.
pub fn allocation_call_is_dischargeable(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    call: &crate::analyzer::semantic::SemanticCallSite,
) -> bool {
    if !call.arguments.is_empty() {
        return false;
    }
    let Some(result) = call.result else {
        return false;
    };
    semantics
        .allocations()
        .iter()
        .any(|allocation| allocation.result == result)
}

/// The allocation site a constructor call's own result names, when this call
/// *is* an object-creation expression (`new Type(...)`) -- any argument
/// count, unlike `allocation_call_is_dischargeable`'s zero-argument
/// restriction (a different question: whether an *unresolved* dispatch
/// still leaves the allocated object's own identity provable). A `new
/// Type(...)` call site spells no receiver operand at all: there is no
/// existing object to invoke on, only the one this expression is about to
/// create. The constructor procedure's own `this` is exactly that object,
/// regardless of how many constructor parameters it takes, so the call
/// site's own `result` -- not a sibling-`this` guess -- is the structurally
/// correct actual for the callee's `Receiver` port (#2574).
fn constructor_call_allocation_site<'a>(
    semantics: &'a crate::analyzer::semantic::ProcedureSemantics,
    call: &crate::analyzer::semantic::SemanticCallSite,
) -> Option<&'a crate::analyzer::semantic::AllocationSite> {
    let result = call.result?;
    semantics
        .allocations()
        .iter()
        .find(|allocation| allocation.result == result)
}

/// Whether a call-target refinement gap is discharged directly by the
/// adapter's own statically proven `declared_targets` (#1952). A refinement
/// gap on a call the adapter could not prove stays relevant here; the plan
/// discharges it only when the same plan retains a complete resolution and
/// binding for that call.
fn declared_proven_target_discharges_gap(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    gap: &crate::analyzer::semantic::SemanticGap,
) -> bool {
    call_target_refinement_call(semantics, gap)
        .and_then(|call| semantics.call_site(call))
        .is_some_and(|row| {
            matches!(
                row.declared_targets,
                crate::analyzer::semantic::CallableTargetResolution::Proven(_)
            )
        })
}

/// Whether a snapshot gap's impacts can affect value-flow relations at all.
pub fn gap_impacts_value_flow(gap: &crate::analyzer::semantic::SemanticGap) -> bool {
    gap.impacts.contains(SemanticGapImpact::ValueFlow)
        || gap.impacts.contains(SemanticGapImpact::ReturnTransfer)
        || gap.impacts.contains(SemanticGapImpact::HeapRead)
        || gap.impacts.contains(SemanticGapImpact::HeapWrite)
}

/// Whether any point reachable through an exceptional or cleanup edge, before
/// the exceptional exit, runs user code (an assignment, flow, memory access,
/// allocation, capture, call, or valued throw).
///
/// An adapter's implicit-exception gap states that an abort edge from a
/// runtime operation to the exceptional exit is not lowered. When every abort
/// path only unwinds -- no handler or cleanup body executes user code -- the
/// missing edge can only remove paths from a may analysis, so it cannot hide
/// a value flow and must not open the snapshot (#1952). When aborts can run
/// user code, the gap keeps standing: a flow into that code may depend on the
/// missing edge.
pub fn abort_paths_run_user_code(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
) -> bool {
    let cancellation = crate::cancellation::CancellationToken::default();
    let mut budget = CfgAlgorithmBudget::uniform(usize::MAX);
    match abort_paths_run_user_code_bounded(
        semantics,
        &mut CfgAlgorithmRequest::new(&mut budget, &cancellation),
    ) {
        Ok(runs_user_code) => runs_user_code,
        Err(CfgAlgorithmError::InvalidNode(point)) => {
            unreachable!("validated procedure has an invalid abort-path point {point}")
        }
        Err(CfgAlgorithmError::Cancelled { .. }) => {
            unreachable!("an uncancelled abort-path traversal cannot be cancelled")
        }
        Err(CfgAlgorithmError::ExceededBudget(exceeded)) => {
            unreachable!(
                "the unbounded abort-path traversal exceeded its {:?} limit: {exceeded:?}",
                exceeded.limit_kind
            )
        }
    }
}

/// Whether an exceptional or cleanup route can run user code, under one
/// caller-owned CFG work ledger.
///
/// The initial edge pass identifies every abort-route entry once. The worklist
/// then visits each reachable point and each of its outgoing edges at most
/// once, avoiding the repeated whole-edge scans of the original helper. A
/// caller that reuses this procedure-level fact can cache the complete answer;
/// cancellation or budget exhaustion publishes no partial boolean.
pub fn abort_paths_run_user_code_bounded(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    request: &mut CfgAlgorithmRequest<'_>,
) -> Result<bool, CfgAlgorithmError<ProgramPointId>> {
    let exceptional_exit = semantics.exceptional_exit_point();
    let mut pending = Vec::new();
    for edge in semantics.cfg().edges() {
        request.visit_edge::<ProgramPointId>()?;
        if matches!(
            edge.kind,
            crate::analyzer::semantic::ControlEdgeKind::Exceptional
                | crate::analyzer::semantic::ControlEdgeKind::Cleanup
        ) && edge.target_point != exceptional_exit
        {
            pending.push(edge.target_point);
        }
    }
    let mut visited = HashSet::new();
    while let Some(point_id) = pending.pop() {
        if point_id == exceptional_exit || !visited.insert(point_id) {
            continue;
        }
        request.visit_node::<ProgramPointId>()?;
        let point = semantics
            .point(point_id)
            .ok_or(CfgAlgorithmError::InvalidNode(point_id))?;
        if point.events.iter().any(|event| {
            matches!(
                event.effect,
                SemanticEffect::Assignment { .. }
                    | SemanticEffect::ValueFlow { .. }
                    | SemanticEffect::Allocation { .. }
                    | SemanticEffect::MemoryLoad { .. }
                    | SemanticEffect::MemoryStore { .. }
                    | SemanticEffect::CaptureBind { .. }
                    | SemanticEffect::Invoke { .. }
                    | SemanticEffect::Throw { value: Some(_) }
            )
        }) {
            return Ok(true);
        }
        for (_, edge) in semantics.successor_edges(point_id) {
            request.visit_edge::<ProgramPointId>()?;
            pending.push(edge.target_point);
        }
    }
    Ok(false)
}

/// Whether an implicit-exception gap is discharged because its abort path only
/// unwinds.
///
/// Only an `Unsupported` point- or value-scoped gap qualifies: it states that
/// a represented operation's implicit abort edge is not lowered, which cannot
/// carry a value when aborts run no user code. A value subject is the result
/// that does not exist on the omitted abort route; it does not make the
/// represented normal route uncertain. A non-rejoining discharge retained by
/// an adapter is a stronger point-local answer: the exact lowering scope had
/// no already-active handler or cleanup user code, even if a later construct
/// adds one elsewhere in the procedure. An `Unknown` exceptional gap
/// (deferred-call panic propagation, destructor unwinding) makes that route
/// itself uncertain and always keeps standing, matching the matched-return
/// rule in the ICFG exit profiles.
pub fn implicit_abort_gap_is_discharged(
    gap: &crate::analyzer::semantic::SemanticGap,
    abort_user_code: bool,
) -> bool {
    gap.capability == SemanticCapability::ExceptionalControlFlow
        && matches!(
            gap.subject,
            SemanticGapSubject::Point | SemanticGapSubject::Value(_)
        )
        && gap.kind == SemanticGapKind::Unsupported
        && (!abort_user_code
            || gap.discharge
                == crate::analyzer::semantic::SemanticGapDischarge::NonRejoiningExceptionalExit)
}

/// The caller value a receiverless call's dispatch receiver binds to, when
/// that identity is structurally proven.
///
/// A bare call between members of one declaring type dispatches on the
/// caller's own `this`: the caller and callee share a declaration parent
/// whose innermost segment is a type, in the same file, and both receivers
/// are dispatch receivers. Each condition carries a semantic boundary:
///
/// - A passed-in receiver on either side (a Kotlin or Scala extension
///   receiver) never carries the caller's `this`.
/// - An inherited, companion-object, or imported-singleton member does not
///   share the declaration parent.
/// - Sibling callables outside a declaring type that are not dispatched
///   members -- JavaScript file-level `function` declarations, which own a
///   `this` but receive `undefined`, not the caller's, through a bare call --
///   do not share it either.
///
/// Those shapes return `None` and the binding stays honestly open.
///
/// The shared parent does not have to be a type. A Ruby top-level `def` is a
/// private instance method of `Object` lowered as `ProcedureKind::Method`
/// with a `File` parent, and a `def` in a `module` body has a `Namespace`
/// parent; in both, a bare sibling call dispatches on the caller's own `self`
/// exactly as a same-class call does (#2637). The kind is what separates that
/// from the JavaScript case: a `Method` is by construction invoked on a
/// receiver object, so a receiverless call to one is an implicit-`self`
/// dispatch, while a `Function` is not a member and its bare call binds no
/// caller `this`. The type-parent arm is kept as its own disjunct so a
/// non-member caller inside a type -- a static initializer, say -- keeps the
/// binding it already had.
fn implicit_dispatch_receiver_actual<'caller>(
    caller: &'caller ProcedureHandle,
    callee: &ProcedureHandle,
    callee_receiver: &crate::analyzer::semantic::SemanticValue,
) -> Option<&'caller crate::analyzer::semantic::SemanticValue> {
    if callee_receiver.kind != (SemanticValueKind::Receiver { dispatch: true }) {
        return None;
    }
    let caller_receiver = caller
        .semantics()
        .values()
        .iter()
        .find(|value| value.kind == SemanticValueKind::Receiver { dispatch: true })?;
    let caller_locator = caller.semantics().locator();
    let callee_locator = callee.semantics().locator();
    let (_, caller_parent) = caller_locator.declaration().segments().split_last()?;
    let (_, callee_parent) = callee_locator.declaration().segments().split_last()?;
    let dispatched_member = |procedure: &ProcedureHandle| {
        matches!(
            procedure.semantics().kind(),
            ProcedureKind::Method | ProcedureKind::Constructor
        )
    };
    (caller_locator.mount() == callee_locator.mount()
        && caller_locator.path() == callee_locator.path()
        && caller_parent == callee_parent
        && (caller_parent
            .last()
            .is_some_and(|segment| segment.kind() == DeclarationSegmentKind::Type)
            || (dispatched_member(caller) && dispatched_member(callee))))
    .then_some(caller_receiver)
}

fn proven_complete(evidence: &[EvidenceHandle]) -> bool {
    matches!(
        evidence_quality(evidence),
        (ProofStatus::Proven, EvidenceCompleteness::Complete)
    )
}

fn location_value_reads(location: &MemoryLocationKind) -> usize {
    match location {
        MemoryLocationKind::Field { .. } | MemoryLocationKind::LexicalCell { .. } => 1,
        MemoryLocationKind::Index { index: Some(_), .. } => 2,
        MemoryLocationKind::Index { index: None, .. }
        | MemoryLocationKind::Static { .. }
        | MemoryLocationKind::Capture { .. } => 0,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoadOrigin {
    Unique(MemoryLocationId),
    Value(ValueId),
    BackingStore {
        source: ValueId,
        offset: BackingStoreOffset,
    },
    Ambiguous,
}

#[derive(Debug)]
enum AccessPathRootDraft {
    Value(ValueId),
    Static(SemanticLocator),
    LexicalCell(MemoryLocationId),
    Capture(MemoryLocationId),
}

#[derive(Debug)]
enum AccessSelectorDraft {
    Field(SemanticLocator),
    Index {
        value: Option<ValueId>,
        constant: Option<u128>,
        identity: crate::analyzer::semantic::IndexedLocationIdentity,
    },
}

#[derive(Debug)]
struct AccessPathDraft {
    root: AccessPathRootDraft,
    selectors: Vec<AccessSelectorDraft>,
    tail: AccessPathTail,
}

#[derive(Debug)]
enum AccessPathResolution {
    Resolved(AccessPathDraft),
    Interrupted(Interruption),
}

/// What one backward scan over a procedure's events establishes about its
/// values.
///
/// Both facts are read off the same event, so they are derived by one
/// traversal rather than two. A second pass would not only cost a second walk;
/// it would charge a second program-point census against the caller's semantic
/// budget, which is a published cost model (`#2295`) and not free to move.
struct ProcedureValueFacts {
    /// Where each value's defining copy or load came from, or `Ambiguous` when
    /// more than one event defines it differently.
    load_origins: HashMap<ValueId, LoadOrigin>,
    /// Values some consumption reads as a whole object (#2444 slice 2): a call
    /// argument, a call receiver, a returned value, or a value stored as a
    /// whole. These are the reads a container collapse is published at, and
    /// deliberately not every read of a value -- see `ContainerRead`.
    whole_container_reads: HashSet<ValueId>,
}

pub(super) fn is_go_assignment_conversion(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    target: ValueId,
) -> bool {
    semantics.value(target).is_some_and(|value| {
        matches!(
            &value.kind,
            SemanticValueKind::LanguageDefined(kind)
                if kind.as_ref() == "go.assignment_conversion"
        )
    })
}

fn procedure_value_facts(
    procedure: &ProcedureHandle,
    seeded: &HashMap<ValueId, LoadOrigin>,
    cancellation: &crate::CancellationToken,
    mut charge: impl FnMut(SemanticWork) -> Result<(), Interruption>,
) -> Result<ProcedureValueFacts, Interruption> {
    // The derived handler bindings (#2446) are copies the runtime performs
    // rather than copies an event records, so they are seeded here instead of
    // being discovered by the event scan below. A binding a later event also
    // defines would resolve to `Ambiguous` through the same merge rule as any
    // other conflicting origin.
    let mut origins = seeded.clone();
    let mut whole_container_reads = HashSet::new();
    let mut go_assignment_conversions = HashSet::new();
    let semantics = procedure.semantics();
    for point in semantics.points() {
        if cancellation.is_cancelled() {
            return Err(Interruption::Cancelled);
        }
        charge(SemanticWork {
            program_points: 1,
            ..SemanticWork::default()
        })?;
        for event in &point.events {
            if cancellation.is_cancelled() {
                return Err(Interruption::Cancelled);
            }
            charge(SemanticWork {
                events: 1,
                ..SemanticWork::default()
            })?;
            let origin = match event.effect {
                SemanticEffect::Assignment { target, value }
                | SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Local,
                    target,
                    source: value,
                } => {
                    charge(SemanticWork {
                        values: 2,
                        nested_entries: 1,
                        ..SemanticWork::default()
                    })?;
                    Some((target, LoadOrigin::Value(value)))
                }
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::BackingStore { offset },
                    source,
                    target,
                } => {
                    charge(SemanticWork {
                        values: 2,
                        nested_entries: 1,
                        ..SemanticWork::default()
                    })?;
                    Some((target, LoadOrigin::BackingStore { source, offset }))
                }
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Transfer(_),
                    target,
                    ..
                } => {
                    charge(SemanticWork {
                        values: 1,
                        nested_entries: 1,
                        ..SemanticWork::default()
                    })?;
                    Some((target, LoadOrigin::Ambiguous))
                }
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::LanguageDefined,
                    source,
                    target,
                } if is_go_assignment_conversion(semantics, target) => {
                    charge(SemanticWork {
                        values: 2,
                        nested_entries: 2,
                        ..SemanticWork::default()
                    })?;
                    go_assignment_conversions.insert(target);
                    Some((target, LoadOrigin::Value(source)))
                }
                SemanticEffect::MemoryLoad {
                    location, result, ..
                } => {
                    charge(SemanticWork {
                        values: 1,
                        memory_locations: 1,
                        nested_entries: 1,
                        ..SemanticWork::default()
                    })?;
                    Some((result, LoadOrigin::Unique(location)))
                }
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Return | ValueFlowKind::IndexedReturn { .. },
                    source,
                    ..
                }
                | SemanticEffect::MemoryStore { value: source, .. } => {
                    charge(SemanticWork {
                        values: 1,
                        ..SemanticWork::default()
                    })?;
                    whole_container_reads.insert(source);
                    None
                }
                SemanticEffect::Invoke { call_site } => {
                    if let Some(call) = semantics.call_site(call_site) {
                        charge(SemanticWork {
                            call_sites: 1,
                            values: call.arguments.len() + usize::from(call.receiver.is_some()),
                            ..SemanticWork::default()
                        })?;
                        whole_container_reads.extend(call.receiver);
                        whole_container_reads
                            .extend(call.arguments.iter().map(|argument| argument.value));
                    }
                    None
                }
                _ => None,
            };
            if let Some((value, origin)) = origin {
                origins
                    .entry(value)
                    .and_modify(|existing| merge_load_origin(existing, origin))
                    .or_insert(origin);
            }
        }
    }
    // A Go assignment conversion is structured data dependence without exact
    // predicate or resource identity. Preserve that distinction in the
    // published relation, but let container provenance walk back through the
    // converted value. A direct store consumes the conversion result without
    // another ordinary copy event, so retain the raw source as the event where
    // the existing container-collapse machinery can publish the dependence.
    // Only a uniquely defined, explicitly tagged conversion is transparent to
    // this provenance walk; an ambiguous target remains closed here.
    let mut pending = go_assignment_conversions
        .iter()
        .copied()
        .filter(|target| whole_container_reads.contains(target))
        .collect::<Vec<_>>();
    while let Some(target) = pending.pop() {
        if cancellation.is_cancelled() {
            return Err(Interruption::Cancelled);
        }
        charge(SemanticWork {
            values: 2,
            nested_entries: 1,
            ..SemanticWork::default()
        })?;
        let Some(LoadOrigin::Value(source)) = origins.get(&target) else {
            continue;
        };
        if whole_container_reads.insert(*source) && go_assignment_conversions.contains(source) {
            pending.push(*source);
        }
    }
    Ok(ProcedureValueFacts {
        load_origins: origins,
        whole_container_reads,
    })
}

fn merge_load_origin(existing: &mut LoadOrigin, incoming: LoadOrigin) {
    match (*existing, incoming) {
        (left, right) if left == right => {}
        (
            LoadOrigin::Value(left),
            LoadOrigin::BackingStore {
                source: right,
                offset,
            },
        ) if left == right => {
            *existing = LoadOrigin::BackingStore {
                source: right,
                offset,
            };
        }
        (LoadOrigin::BackingStore { source: left, .. }, LoadOrigin::Value(right))
            if left == right => {}
        _ => *existing = LoadOrigin::Ambiguous,
    }
}

fn exact_unsigned_integer_origin(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    load_origins: &HashMap<ValueId, LoadOrigin>,
    start: ValueId,
) -> Option<u128> {
    let mut current = start;
    let mut visited = HashSet::new();
    loop {
        if !visited.insert(current) {
            return None;
        }
        if let Some(value) = semantics.value(current)
            && let SemanticValueKind::UnsignedInteger(value) = value.kind
        {
            return Some(value);
        }
        match load_origins.get(&current) {
            Some(LoadOrigin::Value(source)) => current = *source,
            _ => return None,
        }
    }
}

fn retain_selector(
    selectors: &mut VecDeque<AccessSelectorDraft>,
    selector: AccessSelectorDraft,
    limit: usize,
    summarized: &mut bool,
) {
    selectors.push_back(selector);
    if selectors.len() > limit {
        selectors.pop_front();
        *summarized = true;
    }
}

/// Where a backward walk over copy origins ended.
enum ValueOriginWalk {
    /// The walk reached a value nothing else in this procedure defines, or it
    /// stopped on a join it cannot see through. `summarized` records the
    /// second case, where the value named is the last unambiguous step rather
    /// than a proven origin.
    Root {
        value: ValueId,
        offset: Option<u128>,
        summarized: bool,
    },
    /// The walk reached a value a memory load defines. `value` is that value,
    /// so a caller that declines to follow the load still names a root.
    Load {
        location: MemoryLocationId,
        value: ValueId,
        offset: Option<u128>,
    },
}

/// Walk one value back through the unconditional copies that define it.
///
/// This is the canonicalization that makes `alias.value` and `box.value` name
/// one location, and #2444 slice 2 asks the same question of a value that is
/// read as a whole, so the walk is shared rather than restated. `visited` is
/// the caller's own cycle guard, carried across calls because one access path
/// can walk several bases.
fn walk_value_origin(
    load_origins: &HashMap<ValueId, LoadOrigin>,
    start: ValueId,
    visited: &mut HashSet<ValueId>,
    exact_integer: impl Fn(ValueId) -> Option<u128>,
) -> ValueOriginWalk {
    let mut current = start;
    let mut offset = Some(0_u128);
    loop {
        match load_origins.get(&current) {
            Some(LoadOrigin::Value(next)) if visited.insert(current) => current = *next,
            Some(LoadOrigin::BackingStore {
                source,
                offset: step,
            }) if visited.insert(current) => {
                let step = match step {
                    BackingStoreOffset::Zero => Some(0),
                    BackingStoreOffset::Constant(step) => Some(*step),
                    BackingStoreOffset::Value(value) => exact_integer(*value),
                };
                offset = offset
                    .zip(step)
                    .and_then(|(offset, step)| offset.checked_add(step));
                current = *source;
            }
            Some(LoadOrigin::Unique(location)) => {
                return ValueOriginWalk::Load {
                    location: *location,
                    value: current,
                    offset,
                };
            }
            Some(LoadOrigin::Value(_))
            | Some(LoadOrigin::BackingStore { .. })
            | Some(LoadOrigin::Ambiguous) => {
                return ValueOriginWalk::Root {
                    value: current,
                    offset,
                    summarized: true,
                };
            }
            None => {
                return ValueOriginWalk::Root {
                    value: current,
                    offset,
                    summarized: false,
                };
            }
        }
    }
}

fn resolve_access_path<'location>(
    location: MemoryLocationId,
    load_origins: &HashMap<ValueId, LoadOrigin>,
    selector_limit: usize,
    cancellation: &crate::CancellationToken,
    location_kind: impl Fn(MemoryLocationId) -> Option<&'location MemoryLocationKind>,
    exact_integer: impl Fn(ValueId) -> Option<u128> + Copy,
    mut charge: impl FnMut(SemanticWork) -> Result<(), Interruption>,
) -> Result<AccessPathResolution, SemanticProviderError> {
    let mut current = location;
    let mut visited = HashSet::new();
    let mut visited_values = HashSet::new();
    let mut selectors = VecDeque::new();
    let mut summarized = false;

    let root = 'locations: loop {
        if cancellation.is_cancelled() {
            return Ok(AccessPathResolution::Interrupted(Interruption::Cancelled));
        }
        let kind = location_kind(current)
            .ok_or_else(|| SemanticProviderError::internal("memory location handle is stale"))?;
        let selector_count = usize::from(matches!(
            kind,
            MemoryLocationKind::Field { .. } | MemoryLocationKind::Index { .. }
        ));
        let step_work = SemanticWork {
            values: location_value_reads(kind),
            memory_locations: 1,
            nested_entries: selector_count,
            ..SemanticWork::default()
        };
        if let Err(stop) = charge(step_work) {
            return Ok(AccessPathResolution::Interrupted(stop));
        }
        assert!(
            visited.insert(current),
            "access-path cycles are stopped before revisiting a location"
        );
        let base = match kind {
            MemoryLocationKind::Field { base, member } => {
                retain_selector(
                    &mut selectors,
                    AccessSelectorDraft::Field(member.clone()),
                    selector_limit,
                    &mut summarized,
                );
                *base
            }
            MemoryLocationKind::Index {
                base,
                index,
                constant_index,
                identity,
            } => {
                retain_selector(
                    &mut selectors,
                    AccessSelectorDraft::Index {
                        value: *index,
                        constant: *constant_index,
                        identity: *identity,
                    },
                    selector_limit,
                    &mut summarized,
                );
                *base
            }
            MemoryLocationKind::Static { member } => {
                break AccessPathRootDraft::Static(member.clone());
            }
            MemoryLocationKind::LexicalCell { .. } => {
                break AccessPathRootDraft::LexicalCell(current);
            }
            MemoryLocationKind::Capture { .. } => {
                break AccessPathRootDraft::Capture(current);
            }
        };

        match walk_value_origin(load_origins, base, &mut visited_values, exact_integer) {
            ValueOriginWalk::Root {
                value,
                offset,
                summarized: joined,
            } => {
                summarized |= joined || !apply_backing_offset(&mut selectors, offset);
                break AccessPathRootDraft::Value(value);
            }
            ValueOriginWalk::Load {
                location,
                value,
                offset,
            } => {
                summarized |= !apply_backing_offset(&mut selectors, offset);
                if visited.contains(&location) {
                    summarized = true;
                    break AccessPathRootDraft::Value(value);
                }
                current = location;
                continue 'locations;
            }
        }
    };

    Ok(AccessPathResolution::Resolved(AccessPathDraft {
        root,
        selectors: selectors.into_iter().rev().collect(),
        tail: if summarized {
            AccessPathTail::Summary
        } else {
            AccessPathTail::Exact
        },
    }))
}

fn apply_backing_offset(
    selectors: &mut VecDeque<AccessSelectorDraft>,
    offset: Option<u128>,
) -> bool {
    let Some(offset) = offset else {
        return false;
    };
    if offset == 0 {
        return true;
    }
    let Some(AccessSelectorDraft::Index {
        constant: Some(index),
        ..
    }) = selectors.back_mut()
    else {
        return false;
    };
    let Some(translated) = index.checked_add(offset) else {
        return false;
    };
    *index = translated;
    true
}

/// Whether a bounded location names a non-constant exact index selector.
/// Constant index values are canonicalized by language lowering, while a
/// dynamic index remains an unproven join even when its expression value is
/// reused across accesses.
fn location_has_unproven_exact_index(location: &AbstractLocation) -> bool {
    location
        .path()
        .selectors()
        .iter()
        .any(|selector| match selector {
            AccessSelector::Index(IndexSelector::Exact(index)) => !index
                .procedure()
                .semantics()
                .value(index.id())
                .is_some_and(|value| value.kind.is_constant()),
            AccessSelector::Index(IndexSelector::Constant(_))
            | AccessSelector::Index(IndexSelector::Any)
            | AccessSelector::Field(_) => false,
        })
}

/// The carrier that stands for an access path's root object.
///
/// This mirrors `value_flow::plan::root_carrier`, which the fallback-location
/// index already uses to decide which carrier an unmodeled call's escaping
/// locations belong to. Every root that names a value, a call result, a port,
/// an allocation or a lexical cell is carried by that value or port; the four
/// program-global roots have no value carrier and stand for themselves as a
/// selector-free location.
fn access_root_endpoint(
    location: &AbstractLocation,
    limits: crate::analyzer::semantic::OracleLimits,
) -> Result<ValueFlowEndpoint, SemanticProviderError> {
    let root = location.path().root();
    let value = match root {
        AccessPathRoot::Value(value) => Some(value.clone()),
        AccessPathRoot::CallResult(result) => Some(result.result().clone()),
        AccessPathRoot::ProcedurePort(port) | AccessPathRoot::CaptureSlot(port) => {
            return Ok(ValueFlowEndpoint::Port(port.clone()));
        }
        AccessPathRoot::Allocation(allocation) => allocation
            .procedure()
            .semantics()
            .allocation(allocation.id())
            .and_then(|row| allocation.procedure().value_handle(row.result)),
        AccessPathRoot::LexicalCell(cell) => cell
            .procedure()
            .semantics()
            .memory_location(cell.id())
            .and_then(|row| match row.kind {
                MemoryLocationKind::LexicalCell { binding } => {
                    cell.procedure().value_handle(binding)
                }
                _ => None,
            }),
        AccessPathRoot::Static(_)
        | AccessPathRoot::TypeSummary(_)
        | AccessPathRoot::ModuleObject(_)
        | AccessPathRoot::External(_) => None,
    };
    if let Some(value) = value {
        return Ok(ValueFlowEndpoint::Value(value));
    }
    let path = AccessPath::bounded(root.clone(), Vec::new(), location.path().tail(), limits)
        .map_err(|error| internal_contract("invalid container access path", error))?;
    let container = AbstractLocation::new(location.object().clone(), path)
        .map_err(|error| internal_contract("invalid container location", error))?;
    Ok(ValueFlowEndpoint::Location(Box::new(container)))
}

/// The container an indexed access reads out of or writes into, with every
/// index selector dropped.
///
/// #2453: a taint label can live on the array object itself, which is a
/// different carrier from any element of it. `String[] values =
/// request.getParameterValues(name)` labels the array; `values[0]` names an
/// element. Publishing the container alongside the element is what carries the
/// array's own label into a read of it.
///
/// Answers `None` for a path with no index selector, which leaves field
/// sensitivity exactly as it was: this is about subscripts, not members.
fn indexed_container_endpoint(
    location: &AbstractLocation,
    limits: crate::analyzer::semantic::OracleLimits,
) -> Result<Option<ValueFlowEndpoint>, SemanticProviderError> {
    let selectors = location.path().selectors();
    let Some(first_index) = selectors
        .iter()
        .position(|selector| matches!(selector, AccessSelector::Index(_)))
    else {
        return Ok(None);
    };
    if first_index == 0 {
        return access_root_endpoint(location, limits).map(Some);
    }
    let path = AccessPath::bounded(
        location.path().root().clone(),
        selectors[..first_index].to_vec(),
        location.path().tail(),
        limits,
    )
    .map_err(|error| internal_contract("invalid container access path", error))?;
    let container = AbstractLocation::new(location.object().clone(), path)
        .map_err(|error| internal_contract("invalid container location", error))?;
    Ok(Some(ValueFlowEndpoint::Location(Box::new(container))))
}

/// The same location with every index selector replaced by the structured
/// wildcard.
///
/// This is the cell an access whose subscript the analysis cannot prove reads
/// out of or writes into. It is deliberately *not* the cell a proven-constant
/// subscript uses: #2191 established that two literal subscripts of one array
/// are separable, and the `array-element-negative` kernel in
/// `tests/suite_bench_policy/issue_2314_dataflowbench_kernel.rs` pins that in
/// Java, Python and JavaScript. Smashing every subscript would revoke it. So a
/// store always publishes the wildcard cell and only an *unproven* load reads
/// it, which keeps two constants apart while never letting an unprovable
/// subscript be treated as precise.
fn wildcard_index_endpoint(
    location: &AbstractLocation,
    limits: crate::analyzer::semantic::OracleLimits,
) -> Result<Option<ValueFlowEndpoint>, SemanticProviderError> {
    let selectors = location.path().selectors();
    if !selectors
        .iter()
        .any(|selector| matches!(selector, AccessSelector::Index(_)))
    {
        return Ok(None);
    }
    let wildcard = selectors
        .iter()
        .map(|selector| match selector {
            AccessSelector::Index(_) => AccessSelector::Index(IndexSelector::Any),
            other => other.clone(),
        })
        .collect::<Vec<_>>();
    let path = AccessPath::bounded(
        location.path().root().clone(),
        wildcard,
        location.path().tail(),
        limits,
    )
    .map_err(|error| internal_contract("invalid wildcard access path", error))?;
    let cell = AbstractLocation::new(location.object().clone(), path)
        .map_err(|error| internal_contract("invalid wildcard location", error))?;
    Ok(Some(ValueFlowEndpoint::Location(Box::new(cell))))
}

/// The value the language lowering subscripted, when a memory location names an
/// index access.
///
/// The container endpoint above is rooted at the access path's *origin*, which
/// the resolver walks back through assignments; this is the array expression as
/// it stands at the access itself. Both are needed: the origin is what a store
/// into an unprovable subscript marks, and the subscripted expression is what
/// carries a label that entered the array downstream of its origin -- the
/// `String[] values = request.getParameterValues(...)` shape the OWASP corpus is
/// built from.
fn indexed_base_value(
    procedure: &ProcedureHandle,
    location: MemoryLocationId,
) -> Result<Option<ValueHandle>, SemanticProviderError> {
    let Some(row) = procedure.semantics().memory_location(location) else {
        return Ok(None);
    };
    let MemoryLocationKind::Index { base, .. } = row.kind else {
        return Ok(None);
    };
    value_handle(procedure, base).map(Some)
}

/// One member or element location this procedure named, and the weakest
/// quality any relation that named it carried.
///
/// The quality travels with the carrier because a collapse must never be
/// better evidenced than the access that put the label there: a member reached
/// through a path the resolver summarized is `Partial` on its own relation,
/// and the collapse that reads it inherits that.
struct ContainerElement {
    location: AbstractLocation,
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
}

/// One event that reads a whole value which some consumption passes on.
struct ContainerRead {
    point: ProgramPointHandle,
    event_index: u32,
    value: ValueId,
    evidence: EvidenceHandle,
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
}

/// The member locations a procedure named, in the order they were named.
///
/// Insertion order is the published order of the collapse relations, so it is
/// a `Vec` rather than a map: a hash order would make one run's relation ids,
/// and therefore its explanations, differ from the next run's on identical
/// input.
#[derive(Default)]
struct ContainerElements {
    elements: Vec<ContainerElement>,
    seen: HashMap<AbstractLocation, usize>,
}

impl ContainerElements {
    fn observe(
        &mut self,
        endpoint: &ValueFlowEndpoint,
        proof: &ProofStatus,
        completeness: &EvidenceCompleteness,
    ) {
        let ValueFlowEndpoint::Location(location) = endpoint else {
            return;
        };
        if location.path().selectors().is_empty() {
            return;
        }
        match self.seen.get(location.as_ref()) {
            Some(index) => {
                let element = &mut self.elements[*index];
                if !matches!(proof, ProofStatus::Proven) {
                    element.proof = proof.clone();
                }
                if !matches!(completeness, EvidenceCompleteness::Complete) {
                    element.completeness = completeness.clone();
                }
            }
            None => {
                self.seen
                    .insert(location.as_ref().clone(), self.elements.len());
                self.elements.push(ContainerElement {
                    location: location.as_ref().clone(),
                    proof: proof.clone(),
                    completeness: completeness.clone(),
                });
            }
        }
    }
}

/// Whether `candidate` names something strictly inside `root` + `prefix`.
fn selectors_extend(candidate: &[AccessSelector], prefix: &[AccessSelector]) -> bool {
    candidate.len() > prefix.len() && candidate.starts_with(prefix)
}

/// Direct reads and writes of a capture slot share the exact port carrier
/// targeted by the parent's `CaptureBind`. Projecting them as an abstract
/// location would create a second, unrelated identity for the same slot.
fn direct_capture_port_endpoint(
    procedure: &ProcedureHandle,
    location: MemoryLocationId,
) -> Result<Option<ValueFlowEndpoint>, SemanticProviderError> {
    if !procedure
        .semantics()
        .memory_location(location)
        .is_some_and(|row| matches!(row.kind, MemoryLocationKind::Capture { .. }))
    {
        return Ok(None);
    }
    let port = ProcedurePortHandle::capture(procedure.clone(), location)
        .map_err(|error| internal_contract("invalid capture port", error))?;
    Ok(Some(ValueFlowEndpoint::Port(port)))
}

fn materialize_abstract_location(
    procedure: &ProcedureHandle,
    draft: AccessPathDraft,
    limits: crate::analyzer::semantic::OracleLimits,
) -> Result<(AbstractLocation, bool), SemanticProviderError> {
    let (identity, root) = match draft.root {
        AccessPathRootDraft::Value(value) => {
            let value = value_handle(procedure, value)?;
            (
                AbstractObjectIdentity::Value(value.clone()),
                AccessPathRoot::Value(value),
            )
        }
        AccessPathRootDraft::Static(member) => {
            let member = ScopedSemanticLocator::new(Arc::clone(procedure.artifact()), member)
                .map_err(|error| internal_contract("invalid static locator", error))?;
            (
                AbstractObjectIdentity::Static(member.clone()),
                AccessPathRoot::Static(member),
            )
        }
        AccessPathRootDraft::LexicalCell(location) => {
            let location = procedure.memory_location_handle(location).ok_or_else(|| {
                SemanticProviderError::internal("lexical-cell root has a stale location")
            })?;
            (
                AbstractObjectIdentity::LexicalCell(location.clone()),
                AccessPathRoot::LexicalCell(location),
            )
        }
        AccessPathRootDraft::Capture(location) => {
            let port = ProcedurePortHandle::capture(procedure.clone(), location)
                .map_err(|error| internal_contract("invalid capture port", error))?;
            (
                AbstractObjectIdentity::CaptureSlot(port.clone()),
                AccessPathRoot::CaptureSlot(port),
            )
        }
    };
    let selector_is_summarized = draft.selectors.iter().any(|selector| {
        matches!(
            selector,
            AccessSelectorDraft::Index {
                value: None,
                constant: None,
                identity: crate::analyzer::semantic::IndexedLocationIdentity::Element,
            }
        )
    });
    let selectors = draft
        .selectors
        .into_iter()
        .map(|selector| match selector {
            AccessSelectorDraft::Field(member) => {
                ScopedSemanticLocator::new(Arc::clone(procedure.artifact()), member)
                    .map(AccessSelector::Field)
                    .map_err(|error| internal_contract("invalid field locator", error))
            }
            AccessSelectorDraft::Index {
                constant: Some(index),
                ..
            } => Ok(AccessSelector::Index(IndexSelector::Constant(index))),
            AccessSelectorDraft::Index {
                value: Some(index),
                constant: None,
                ..
            } => value_handle(procedure, index)
                .map(IndexSelector::Exact)
                .map(AccessSelector::Index),
            AccessSelectorDraft::Index {
                value: None,
                constant: None,
                ..
            } => Ok(AccessSelector::Index(IndexSelector::Any)),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let path = AccessPath::bounded(root, selectors, draft.tail, limits)
        .map_err(|error| internal_contract("invalid semantic access path", error))?;
    // `Any` normally means one element whose identity is unknown. An
    // `Aggregate` producer instead means the exact abstract cell containing
    // all indexed elements, so its wildcard is a deliberate complete domain,
    // not missing selector evidence. The path stays non-exact, which prevents
    // strong updates; only the relation's evidence completeness is refined.
    let summary = draft.tail == AccessPathTail::Summary || selector_is_summarized;
    let object = AbstractObject::new(identity, ObjectCardinality::Unknown)
        .map_err(|error| internal_contract("invalid semantic object", error))?;
    let location = AbstractLocation::new(object, path)
        .map_err(|error| internal_contract("invalid semantic location", error))?;
    Ok((location, summary))
}

fn allocation_location(
    allocation: AllocationHandle,
    limits: crate::analyzer::semantic::OracleLimits,
) -> Result<AbstractLocation, SemanticProviderError> {
    let identity = AbstractObjectIdentity::Allocation(allocation.clone());
    let object = AbstractObject::new(identity, ObjectCardinality::Unknown)
        .map_err(|error| internal_contract("invalid allocation object", error))?;
    let path = AccessPath::exact(AccessPathRoot::Allocation(allocation), Vec::new(), limits)
        .map_err(|error| internal_contract("invalid allocation path", error))?;
    AbstractLocation::new(object, path)
        .map_err(|error| internal_contract("invalid allocation location", error))
}

fn push_flow_relation(
    drafts: &mut Vec<FlowRelationDraft>,
    retained_evidence: &mut usize,
    limits: crate::analyzer::semantic::OracleLimits,
    draft: FlowRelationDraft,
) -> bool {
    if drafts.len() >= limits.provenance_records()
        || retained_evidence.saturating_add(draft.evidence.len()) > limits.evidence_handles()
    {
        return false;
    }
    *retained_evidence = retained_evidence.saturating_add(draft.evidence.len());
    drafts.push(draft);
    true
}

/// How a strong-update query stopped when it did not produce a verdict.
enum StrongUpdateStop {
    Interruption(Interruption),
    Provider(SemanticProviderError),
}

fn materialize_flow_snapshot(
    procedure: &ProcedureHandle,
    context: &OracleCallContext,
    drafts: Vec<FlowRelationDraft>,
    coverage: CandidateCoverage,
    limits: crate::analyzer::semantic::OracleLimits,
    discharged_gaps: Vec<crate::analyzer::semantic::SemanticGapId>,
) -> Result<ValueFlowSnapshot, SemanticProviderError> {
    let records = drafts
        .iter()
        .map(|draft| {
            OracleRelationRecord::new(
                OracleRelationKind::ValueFlow,
                draft.evidence.clone(),
                limits,
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| internal_contract("could not create value-flow provenance", error))?;
    let arena = OracleRelationArena::new(
        OracleRelationOwner::ProcedureValueFlow {
            procedure: procedure.clone(),
            context: context.clone(),
        },
        records,
        limits,
    )
    .map_err(|error| internal_contract("could not create value-flow arena", error))?;
    let relations = drafts
        .into_iter()
        .enumerate()
        .map(|(index, draft)| {
            let id = u32::try_from(index)
                .map(OracleRelationId::new)
                .map_err(|_| SemanticProviderError::internal("value-flow relation ID overflow"))?;
            Ok(ValueFlowRelation {
                point: draft.point,
                event_index: draft.event_index,
                id: arena
                    .handle(id)
                    .expect("value-flow record was inserted into the arena"),
                kind: draft.kind,
                transfer: draft.transfer,
                source: draft.source,
                target: draft.target,
                proof: draft.proof,
                completeness: draft.completeness,
                strong_update: draft.strong_update,
            })
        })
        .collect::<Result<Vec<_>, SemanticProviderError>>()?;
    ValueFlowSnapshot::with_discharged_gaps(
        procedure.clone(),
        context.clone(),
        relations,
        coverage,
        limits,
        discharged_gaps,
    )
    .map_err(|error| internal_contract("invalid value-flow snapshot", error))
}

fn publish_flow_outcome(
    snapshot: ValueFlowSnapshot,
    interrupted: Option<Interruption>,
    has_unproven_relation: bool,
    gap_quality: Option<GapOutcomeQuality>,
    work: SemanticWork,
) -> SemanticOutcome<ValueFlowSnapshot> {
    let quality = merge_relation_quality(gap_quality, has_unproven_relation);
    match interrupted {
        Some(Interruption::Budget(exceeded)) => SemanticOutcome::ExceededBudget {
            partial: Some(snapshot),
            exceeded,
            work,
        },
        Some(Interruption::Cancelled) => SemanticOutcome::Cancelled {
            partial: Some(snapshot),
            work,
        },
        None if snapshot.coverage() == CandidateCoverage::Truncated => SemanticOutcome::Unproven {
            partial: snapshot,
            work,
        },
        None if matches!(quality, Some(GapOutcomeQuality::Unsupported(_))) => {
            let Some(GapOutcomeQuality::Unsupported(capability)) = quality else {
                unreachable!("guard establishes unsupported gap quality")
            };
            SemanticOutcome::Unsupported {
                capability,
                partial: Some(snapshot),
                work,
            }
        }
        None if matches!(quality, Some(GapOutcomeQuality::Unknown)) => SemanticOutcome::Unknown {
            partial: Some(snapshot),
            work,
        },
        None if matches!(quality, Some(GapOutcomeQuality::Unproven)) => SemanticOutcome::Unproven {
            partial: snapshot,
            work,
        },
        None if matches!(quality, Some(GapOutcomeQuality::Ambiguous)) => {
            SemanticOutcome::Ambiguous {
                candidates: snapshot,
                work,
            }
        }
        None if snapshot.coverage() == CandidateCoverage::Open => SemanticOutcome::Unknown {
            partial: Some(snapshot),
            work,
        },
        None => SemanticOutcome::Complete {
            value: snapshot,
            work,
        },
    }
}

#[derive(Clone)]
struct BindingRelationDraft {
    evidence: Vec<EvidenceHandle>,
}

enum CallBindingDraft {
    Receiver {
        relation: usize,
        actual: ValueHandle,
        formal: ProcedurePortHandle,
    },
    ArgumentGroup {
        closure_relation: usize,
        source: u32,
        mapping: Option<
            Box<(
                usize,
                CallArgumentMapping,
                ProofStatus,
                EvidenceCompleteness,
            )>,
        >,
        coverage: CandidateCoverage,
    },
    NormalReturn {
        relation: usize,
        formal: ProcedurePortHandle,
        result: ValueHandle,
    },
    ExceptionalReturn {
        relation: usize,
        formal: ProcedurePortHandle,
        result: ValueHandle,
    },
}

struct BindingBuild {
    relations: Vec<BindingRelationDraft>,
    bindings: Vec<CallBindingDraft>,
    retained_evidence: usize,
    retained_entries: usize,
    open: bool,
    truncated: bool,
    has_unproven_relation: bool,
    gap_quality: Option<GapOutcomeQuality>,
}

impl BindingBuild {
    fn new(open: bool) -> Self {
        Self {
            relations: Vec::new(),
            bindings: Vec::new(),
            retained_evidence: 0,
            retained_entries: 0,
            open,
            truncated: false,
            has_unproven_relation: false,
            gap_quality: None,
        }
    }

    fn can_retain(
        &self,
        relation_evidence: &[Vec<EvidenceHandle>],
        entry_cost: usize,
        limits: crate::analyzer::semantic::OracleLimits,
    ) -> bool {
        self.relations.len().saturating_add(relation_evidence.len()) <= limits.provenance_records()
            && self
                .retained_evidence
                .saturating_add(relation_evidence.iter().map(Vec::len).sum::<usize>())
                <= limits.evidence_handles()
            && self.retained_entries.saturating_add(entry_cost) <= limits.call_binding_entries()
    }

    fn push_relation(&mut self, evidence: Vec<EvidenceHandle>) -> usize {
        let index = self.relations.len();
        self.has_unproven_relation |= !proven_complete(&evidence);
        self.retained_evidence = self.retained_evidence.saturating_add(evidence.len());
        self.relations.push(BindingRelationDraft { evidence });
        index
    }
}

fn materialize_call_bindings(
    call: &crate::analyzer::semantic::CallSiteHandle,
    candidate: &DispatchCandidate,
    context: &OracleCallContext,
    build: BindingBuild,
    coverage: CandidateCoverage,
    limits: crate::analyzer::semantic::OracleLimits,
) -> Result<CallBindings, SemanticProviderError> {
    let records = build
        .relations
        .iter()
        .map(|draft| {
            OracleRelationRecord::new(
                OracleRelationKind::CallBinding,
                draft.evidence.clone(),
                limits,
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| internal_contract("could not create call-binding provenance", error))?;
    let arena = OracleRelationArena::new(
        OracleRelationOwner::CallBinding {
            call: call.clone(),
            callee: candidate.target().clone(),
            context: context.clone(),
        },
        records,
        limits,
    )
    .map_err(|error| internal_contract("could not create call-binding arena", error))?;
    let relation = |index: usize| -> Result<OracleRelationHandle, SemanticProviderError> {
        let id = u32::try_from(index)
            .map(OracleRelationId::new)
            .map_err(|_| SemanticProviderError::internal("call-binding relation ID overflow"))?;
        arena
            .handle(id)
            .ok_or_else(|| SemanticProviderError::internal("missing call-binding relation"))
    };
    let bindings = build
        .bindings
        .into_iter()
        .map(|draft| match draft {
            CallBindingDraft::Receiver {
                relation: relation_id,
                actual,
                formal,
            } => Ok(CallBinding::Receiver {
                relation: relation(relation_id)?,
                actual,
                formal,
            }),
            CallBindingDraft::ArgumentGroup {
                closure_relation,
                source,
                mapping,
                coverage,
            } => {
                let mappings = mapping
                    .map(|mapping| {
                        let (relation_id, mapping, proof, completeness) = *mapping;
                        OracleCandidate::new(
                            mapping,
                            proof,
                            completeness,
                            [relation(relation_id)?],
                            limits,
                        )
                        .map_err(|error| {
                            internal_contract("invalid argument mapping provenance", error)
                        })
                    })
                    .into_iter()
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(CallBinding::ArgumentGroup(
                    CallArgumentGroup::new(
                        call,
                        relation(closure_relation)?,
                        [source],
                        mappings,
                        coverage,
                        limits,
                    )
                    .map_err(|error| internal_contract("invalid argument group", error))?,
                ))
            }
            CallBindingDraft::NormalReturn {
                relation: relation_id,
                formal,
                result,
            } => Ok(CallBinding::NormalReturn {
                relation: relation(relation_id)?,
                formal,
                result,
            }),
            CallBindingDraft::ExceptionalReturn {
                relation: relation_id,
                formal,
                result,
            } => Ok(CallBinding::ExceptionalReturn {
                relation: relation(relation_id)?,
                formal,
                result,
            }),
        })
        .collect::<Result<Vec<_>, SemanticProviderError>>()?;
    CallBindings::new(
        call.clone(),
        candidate,
        context.clone(),
        bindings,
        coverage,
        limits,
    )
    .map_err(|error| internal_contract("invalid candidate-specific call bindings", error))
}

fn interrupted_call_bindings(
    call: &crate::analyzer::semantic::CallSiteHandle,
    candidate: &DispatchCandidate,
    context: &OracleCallContext,
    build: BindingBuild,
    interruption: Interruption,
    work: SemanticWork,
    limits: crate::analyzer::semantic::OracleLimits,
) -> Result<SemanticOutcome<CallBindings>, SemanticProviderError> {
    let bindings = materialize_call_bindings(
        call,
        candidate,
        context,
        build,
        CandidateCoverage::Open,
        limits,
    )?;
    Ok(match interruption {
        Interruption::Budget(exceeded) => SemanticOutcome::ExceededBudget {
            partial: Some(bindings),
            exceeded,
            work,
        },
        Interruption::Cancelled => SemanticOutcome::Cancelled {
            partial: Some(bindings),
            work,
        },
    })
}

impl WorkspaceSemanticOracle<'_> {
    /// Whether the producer's canonical index identity is backed by one exact
    /// base object in this activation.
    ///
    /// The marker proves only the selector. Before discharging its value-flow
    /// gap, independently require the existing heap oracle to close the base
    /// to one proven singleton allocation and require its local copy closure
    /// to contain no secondary binding owner. The local-allocation precheck
    /// keeps this query intra-procedural, so its points-to trace cannot re-enter
    /// `procedure_relations` through a call result. Parameter-backed slices,
    /// aggregate copies, joined bases, cyclic allocations, captures, and
    /// incomplete heap proofs all fail closed.
    #[allow(clippy::too_many_arguments)]
    fn canonical_index_identity_discharges_gap(
        &self,
        procedure: &ProcedureHandle,
        context: &OracleCallContext,
        gap: &crate::analyzer::semantic::SemanticGap,
        bases: &LocalStoreBases,
        staged: &mut WorkStager,
        cancellation: &crate::cancellation::CancellationToken,
    ) -> Result<bool, StrongUpdateStop> {
        if !gap_certifies_canonical_index_identity(
            gap,
            procedure.semantics().points(),
            procedure.semantics().memory_locations(),
            procedure.semantics().values(),
        ) {
            return Ok(false);
        }
        let SemanticGapSubject::MemoryLocation(location) = gap.subject else {
            return Ok(false);
        };
        let Some(MemoryLocationKind::Index { base, .. }) = procedure
            .semantics()
            .memory_location(location)
            .map(|location| &location.kind)
        else {
            return Ok(false);
        };
        if !bases.is_locally_allocated(*base)
            || !bases.canonical_base_has_no_secondary_binding_owner(*base)
        {
            return Ok(false);
        }
        if bases.is_closed_local_array(*base) {
            return Ok(true);
        }
        let point = procedure.point_handle(gap.point).ok_or_else(|| {
            StrongUpdateStop::Provider(SemanticProviderError::internal(
                "canonical-index gap has a stale program point",
            ))
        })?;
        let base = value_handle(procedure, *base).map_err(StrongUpdateStop::Provider)?;
        let observation = crate::analyzer::semantic::ValueAtPoint::new(
            base,
            point,
            crate::analyzer::semantic::ObservationPhase::BeforeEffects,
            context.clone(),
        )
        .map_err(|error| {
            StrongUpdateStop::Provider(internal_contract(
                "invalid canonical-index base observation",
                error,
            ))
        })?;
        let outcome = {
            let mut request = staged.request(cancellation);
            self.pointees(&observation, &mut request)
                .map_err(StrongUpdateStop::Provider)?
        };
        staged.work = staged.work.conservative_add(outcome.work());
        match outcome {
            SemanticOutcome::Complete { value, .. } => {
                let objects = value.objects();
                let [candidate] = objects.candidates() else {
                    return Ok(false);
                };
                Ok(objects.coverage() == CandidateCoverage::Exhaustive
                    && candidate.is_proven_complete()
                    && candidate.value().cardinality() == ObjectCardinality::Singleton
                    && matches!(
                        candidate.value().identity(),
                        AbstractObjectIdentity::Allocation(_)
                    ))
            }
            SemanticOutcome::ExceededBudget { exceeded, .. } => Err(
                StrongUpdateStop::Interruption(Interruption::Budget(exceeded)),
            ),
            SemanticOutcome::Cancelled { .. } => {
                Err(StrongUpdateStop::Interruption(Interruption::Cancelled))
            }
            SemanticOutcome::Ambiguous { .. }
            | SemanticOutcome::Unknown { .. }
            | SemanticOutcome::Unsupported { .. }
            | SemanticOutcome::Unproven { .. } => Ok(false),
        }
    }

    /// Whether the heap oracle certifies this store as a strong update.
    ///
    /// This is the first production consumer of `update_eligibility` (#2444).
    /// The query is demand-driven twice over: the caller only reaches it for a
    /// proven, complete `MemoryStore` whose resolved location is exact, and
    /// this method declines before asking whenever the store's base value is
    /// not locally allocated -- which covers both the shapes that cannot be
    /// certified and the shapes whose points-to trace would re-enter
    /// `procedure_relations`.
    ///
    /// The queried target is built from the store's own memory row, not from
    /// the relation's resolved access path. A certificate is bound to the IR
    /// address it overwrites, while the resolver deliberately rewrites a base
    /// value to the canonical origin it copies from -- `holder` at two
    /// statements resolves to the one allocation, which is what gives the two
    /// stores one carrier in the first place. The certificate covers that
    /// address, so it licenses replacing the facts at the carrier the resolver
    /// produced for it.
    ///
    /// Only a `Complete` outcome licenses the flag. A partial verdict from an
    /// exhausted budget or an open trace is exactly the case where the store
    /// may not have overwritten what a client would otherwise kill.
    #[allow(clippy::too_many_arguments)]
    fn store_holds_strong_update(
        &self,
        procedure: &ProcedureHandle,
        context: &OracleCallContext,
        point: &ProgramPointHandle,
        event_index: usize,
        location: MemoryLocationId,
        stored: ValueId,
        bases: &LocalStoreBases,
        staged: &mut WorkStager,
        cancellation: &crate::cancellation::CancellationToken,
    ) -> Result<bool, StrongUpdateStop> {
        let row = procedure
            .semantics()
            .memory_location(location)
            .ok_or_else(|| {
                StrongUpdateStop::Provider(SemanticProviderError::internal(
                    "memory-store effect has a stale location",
                ))
            })?;
        let scoped = |member: &SemanticLocator| {
            ScopedSemanticLocator::new(Arc::clone(procedure.artifact()), member.clone())
                .map_err(|error| internal_contract("invalid store locator", error))
        };
        let (base, root, selectors) = match &row.kind {
            MemoryLocationKind::Field { base, member } => {
                if !bases.is_locally_allocated(*base) {
                    return Ok(false);
                }
                (
                    Some(*base),
                    AccessPathRoot::Value(
                        value_handle(procedure, *base).map_err(StrongUpdateStop::Provider)?,
                    ),
                    vec![AccessSelector::Field(
                        scoped(member).map_err(StrongUpdateStop::Provider)?,
                    )],
                )
            }
            MemoryLocationKind::Index {
                base,
                index,
                constant_index,
                ..
            } => {
                // A subscript the analysis cannot pin names a summary cell, and
                // a summary cell can never be strongly updated (#2453).
                let Some(index) = index else {
                    return Ok(false);
                };
                if !bases.is_locally_allocated(*base) {
                    return Ok(false);
                }
                (
                    Some(*base),
                    AccessPathRoot::Value(
                        value_handle(procedure, *base).map_err(StrongUpdateStop::Provider)?,
                    ),
                    vec![AccessSelector::Index(match constant_index {
                        Some(index) => IndexSelector::Constant(*index),
                        None => IndexSelector::Exact(
                            value_handle(procedure, *index).map_err(StrongUpdateStop::Provider)?,
                        ),
                    })],
                )
            }
            MemoryLocationKind::Static { member } => (
                None,
                AccessPathRoot::Static(scoped(member).map_err(StrongUpdateStop::Provider)?),
                Vec::new(),
            ),
            MemoryLocationKind::LexicalCell { .. } => {
                let handle = procedure.memory_location_handle(location).ok_or_else(|| {
                    StrongUpdateStop::Provider(SemanticProviderError::internal(
                        "lexical-cell store names a stale location",
                    ))
                })?;
                (None, AccessPathRoot::LexicalCell(handle), Vec::new())
            }
            MemoryLocationKind::Capture { .. } => {
                let port =
                    ProcedurePortHandle::capture(procedure.clone(), location).map_err(|error| {
                        StrongUpdateStop::Provider(internal_contract("invalid capture port", error))
                    })?;
                (None, AccessPathRoot::CaptureSlot(port), Vec::new())
            }
        };
        let Ok(path) = AccessPath::exact(root, selectors, *self.limits()) else {
            return Ok(false);
        };
        let Ok(store) =
            crate::analyzer::semantic::MemoryStoreHandle::new(point.clone(), event_index)
        else {
            return Ok(false);
        };
        let observe = |value: ValueId| {
            value_handle(procedure, value).and_then(|value| {
                crate::analyzer::semantic::ValueAtPoint::new(
                    value,
                    point.clone(),
                    crate::analyzer::semantic::ObservationPhase::BeforeEffects,
                    context.clone(),
                )
                .map_err(|error| internal_contract("invalid store observation", error))
            })
        };
        let stored = observe(stored).map_err(StrongUpdateStop::Provider)?;
        let base = base
            .map(observe)
            .transpose()
            .map_err(StrongUpdateStop::Provider)?;
        let Ok(target) = crate::analyzer::semantic::AccessPathAtPoint::new(
            path,
            point.clone(),
            crate::analyzer::semantic::ObservationPhase::BeforeEffects,
            context.clone(),
        ) else {
            return Ok(false);
        };
        let Ok(store) = crate::analyzer::semantic::StoreAtPoint::new(store, target, stored, base)
        else {
            return Ok(false);
        };
        let outcome = {
            let mut request = staged.request(cancellation);
            self.update_eligibility(&store, &mut request)
                .map_err(StrongUpdateStop::Provider)?
        };
        staged.work = staged.work.conservative_add(outcome.work());
        match outcome {
            SemanticOutcome::Complete {
                value: crate::analyzer::semantic::UpdateEligibility::Strong(_),
                ..
            } => Ok(true),
            // A shortfall is reported, not swallowed: the snapshot spent this
            // request's budget on the question and must say so.
            SemanticOutcome::ExceededBudget { exceeded, .. } => Err(
                StrongUpdateStop::Interruption(Interruption::Budget(exceeded)),
            ),
            SemanticOutcome::Cancelled { .. } => {
                Err(StrongUpdateStop::Interruption(Interruption::Cancelled))
            }
            _ => Ok(false),
        }
    }
}

impl ValueFlowOracle for WorkspaceSemanticOracle<'_> {
    fn procedure_relations(
        &self,
        procedure: &ProcedureHandle,
        context: &OracleCallContext,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<ValueFlowSnapshot>, SemanticProviderError> {
        if request.cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: SemanticWork::default(),
            });
        }
        let mut staged = WorkStager::new(request);
        if let Err(Interruption::Budget(exceeded)) = staged.charge(SemanticWork {
            procedures: 1,
            ..SemanticWork::default()
        }) {
            return Ok(SemanticOutcome::ExceededBudget {
                partial: None,
                exceeded,
                work: SemanticWork {
                    procedures: 1,
                    ..SemanticWork::default()
                },
            });
        }
        let mut interrupted = None;

        let mut open = value_flow_capabilities_are_open(procedure);
        let mut gap_quality = None;
        // Shared by the canonical-index base certificate and store strong
        // updates. Derive it lazily only when one of those questions exists.
        let mut store_bases: Option<LocalStoreBases> = None;
        // #2545: every gap this sweep proves discharged (impacts value flow,
        // but a predicate proved it does not apply), so a downstream
        // consumer that re-examines this procedure's raw gap list -- most
        // notably `ValueFlowPlan`'s own "refinable" residual check, which has
        // no analyzer access and cannot re-run these predicates itself --
        // can see this sweep's own judgment instead of re-deriving (or
        // failing to re-derive) it. See `ValueFlowSnapshot::gap_is_discharged`.
        let mut discharged_gaps = Vec::new();
        if interrupted.is_none() {
            let abort_user_code = abort_paths_run_user_code(procedure.semantics());
            for gap in procedure.semantics().gaps() {
                if request.cancellation.is_cancelled() {
                    interrupted = Some(Interruption::Cancelled);
                    break;
                }
                if let Err(stop) = staged.charge(SemanticWork {
                    gaps: 1,
                    ..SemanticWork::default()
                }) {
                    interrupted = Some(stop);
                    break;
                }
                let impacts_value_flow = gap_impacts_value_flow(gap);
                let canonical_index_identity_discharged =
                    if gap.discharge == SemanticGapDischarge::CanonicalIndexIdentity {
                        let bases = store_bases
                            .get_or_insert_with(|| LocalStoreBases::derive(procedure.semantics()));
                        match self.canonical_index_identity_discharges_gap(
                            procedure,
                            context,
                            gap,
                            bases,
                            &mut staged,
                            request.cancellation,
                        ) {
                            Ok(discharged) => discharged,
                            Err(StrongUpdateStop::Provider(error)) => return Err(error),
                            Err(StrongUpdateStop::Interruption(stop)) => {
                                interrupted = Some(stop);
                                break;
                            }
                        }
                    } else {
                        false
                    };
                let relevant = impacts_value_flow
                    && !declared_proven_target_discharges_gap(procedure.semantics(), gap)
                    && !constructor_call_gap_is_discharged(procedure.semantics(), gap)
                    && !canonical_index_identity_discharged
                    && !implicit_abort_gap_is_discharged(gap, abort_user_code)
                    && !super::external_constant_field_read_discharges_gap(
                        gap,
                        procedure,
                        self.workspace,
                        request,
                    )?;
                if impacts_value_flow && !relevant {
                    discharged_gaps.push(gap.id);
                }
                open |= relevant;
                if relevant {
                    gap_quality = merge_gap_quality(gap_quality, gap);
                }
            }
        }

        // #2446: derived before the access-path origins, because a handler
        // binding is one of them. Nothing is derived for a procedure whose
        // adapter already selected every handler.
        let mut handler_bindings = HandlerBindings::default();
        if interrupted.is_none() {
            match HandlerBindings::derive(procedure, request.cancellation, |work| {
                staged.charge(work)
            }) {
                Ok(derived) => handler_bindings = derived,
                Err(stop) => interrupted = Some(stop),
            }
        }

        // The access-path origins, and (#2444 slice 2) which values some
        // consumption reads as a whole object. Both are established before the
        // relation pass, so a whole read that precedes every member store in
        // event order still collapses.
        let ProcedureValueFacts {
            load_origins,
            whole_container_reads,
        } = if interrupted.is_none() {
            match procedure_value_facts(
                procedure,
                handler_bindings.binder_origins(),
                request.cancellation,
                |work| staged.charge(work),
            ) {
                Ok(facts) => facts,
                Err(stop) => {
                    interrupted = Some(stop);
                    ProcedureValueFacts {
                        load_origins: HashMap::new(),
                        whole_container_reads: HashSet::new(),
                    }
                }
            }
        } else {
            ProcedureValueFacts {
                load_origins: HashMap::new(),
                whole_container_reads: HashSet::new(),
            }
        };
        let exact_integer =
            |value| exact_unsigned_integer_origin(procedure.semantics(), &load_origins, value);

        let mut drafts = Vec::new();
        let mut retained_evidence = 0usize;
        let mut truncated = false;
        // #2444 slice 2: the member carriers this procedure named, and the
        // events that read a whole value some consumption passes on. The
        // collapse relations that join them are published after this pass,
        // because a member store can follow the read that observes it in
        // event order while preceding it in execution order.
        let mut container_elements = ContainerElements::default();
        let mut container_reads: Vec<ContainerRead> = Vec::new();
        'points: for point in procedure.semantics().points() {
            if interrupted.is_some() {
                break;
            }
            if request.cancellation.is_cancelled() {
                interrupted = Some(Interruption::Cancelled);
                break;
            }
            if let Err(stop) = staged.charge(SemanticWork {
                program_points: 1,
                ..SemanticWork::default()
            }) {
                interrupted = Some(stop);
                break;
            }
            for (event_index, event) in point.events.iter().enumerate() {
                if request.cancellation.is_cancelled() {
                    interrupted = Some(Interruption::Cancelled);
                    break 'points;
                }
                if let Err(stop) = staged.charge(SemanticWork {
                    events: 1,
                    ..SemanticWork::default()
                }) {
                    interrupted = Some(stop);
                    break 'points;
                }

                let mut access_path = None;
                let relation_work = match &event.effect {
                    SemanticEffect::Assignment { .. } | SemanticEffect::ValueFlow { .. } => {
                        Some(SemanticWork {
                            values: 2,
                            evidence: 1,
                            nested_entries: 1,
                            ..SemanticWork::default()
                        })
                    }
                    SemanticEffect::Allocation { .. } => Some(SemanticWork {
                        values: 1,
                        allocations: 1,
                        evidence: 1,
                        nested_entries: 1,
                        ..SemanticWork::default()
                    }),
                    SemanticEffect::MemoryLoad { location, .. }
                    | SemanticEffect::MemoryStore { location, .. } => {
                        let resolved = match resolve_access_path(
                            *location,
                            &load_origins,
                            self.limits().access_path_length(),
                            request.cancellation,
                            |id| {
                                procedure
                                    .semantics()
                                    .memory_location(id)
                                    .map(|row| &row.kind)
                            },
                            exact_integer,
                            |work| staged.charge(work),
                        )? {
                            AccessPathResolution::Resolved(resolved) => resolved,
                            AccessPathResolution::Interrupted(stop) => {
                                interrupted = Some(stop);
                                break 'points;
                            }
                        };
                        let work = SemanticWork {
                            values: 1,
                            evidence: 1,
                            nested_entries: 1,
                            ..SemanticWork::default()
                        };
                        access_path = Some(resolved);
                        Some(work)
                    }
                    SemanticEffect::CaptureBind { capture } => {
                        let capture = procedure.semantics().capture(*capture).ok_or_else(|| {
                            SemanticProviderError::internal("capture effect has a stale ID")
                        })?;
                        let source_work = match capture.captured {
                            CaptureSource::Value(_) => SemanticWork {
                                values: 1,
                                memory_locations: 1,
                                ..SemanticWork::default()
                            },
                            CaptureSource::Location(location) => {
                                let resolved = match resolve_access_path(
                                    location,
                                    &load_origins,
                                    self.limits().access_path_length(),
                                    request.cancellation,
                                    |id| {
                                        procedure
                                            .semantics()
                                            .memory_location(id)
                                            .map(|row| &row.kind)
                                    },
                                    exact_integer,
                                    |work| staged.charge(work),
                                )? {
                                    AccessPathResolution::Resolved(resolved) => resolved,
                                    AccessPathResolution::Interrupted(stop) => {
                                        interrupted = Some(stop);
                                        break 'points;
                                    }
                                };
                                let work = SemanticWork {
                                    memory_locations: 1,
                                    ..SemanticWork::default()
                                };
                                access_path = Some(resolved);
                                work
                            }
                        };
                        Some(source_work.conservative_add(SemanticWork {
                            procedures: 1,
                            captures: 1,
                            evidence: 1,
                            nested_entries: 1,
                            ..SemanticWork::default()
                        }))
                    }
                    SemanticEffect::Throw { value: Some(_) } => Some(SemanticWork {
                        values: 1,
                        evidence: 1,
                        nested_entries: 1,
                        ..SemanticWork::default()
                    }),
                    SemanticEffect::Entry
                    | SemanticEffect::NormalExit
                    | SemanticEffect::ExceptionalExit
                    | SemanticEffect::ValueUse { .. }
                    | SemanticEffect::CallableCreation { .. }
                    | SemanticEffect::CallableReference { .. }
                    | SemanticEffect::Invoke { .. }
                    | SemanticEffect::CallContinuation { .. }
                    | SemanticEffect::ProcedureReturn { .. }
                    | SemanticEffect::Throw { value: None }
                    | SemanticEffect::AsyncSuspend { .. }
                    | SemanticEffect::AsyncResume { .. }
                    | SemanticEffect::Synchronization { .. }
                    | SemanticEffect::Gap { .. } => None,
                };
                let Some(relation_work) = relation_work else {
                    continue;
                };
                if drafts.len() >= self.limits().provenance_records()
                    || retained_evidence >= self.limits().evidence_handles()
                {
                    truncated = true;
                    break 'points;
                }
                if let Err(stop) = staged.charge(relation_work) {
                    interrupted = Some(stop);
                    break 'points;
                }

                let evidence = evidence_handle(procedure, event.evidence)?;
                let (proof, mut completeness) = evidence_quality(std::slice::from_ref(&evidence));
                let mut exact_index = false;
                /// One relation derived from the event being projected, rather
                /// than from the event's own endpoints.
                ///
                /// `quality` is `None` when the derived relation is exactly as
                /// well evidenced as the event it rides -- the #2453 smashed
                /// container cells, which restate one access -- and `Some`
                /// when the derivation itself is weaker than the event, as a
                /// #2446 handler binding is.
                struct DerivedRelation {
                    kind: ValueFlowRelationKind,
                    source: ValueFlowEndpoint,
                    target: ValueFlowEndpoint,
                    quality: Option<(ProofStatus, EvidenceCompleteness)>,
                }
                // #2453: the extra relations an indexed access publishes, so a
                // label on the array itself is not silently lost at the
                // subscript. They ride the same event, so they carry the same
                // evidence, proof and completeness as the access they derive
                // from.
                let mut smashed: Vec<DerivedRelation> = Vec::new();
                let (kind, source, target, summary) = match &event.effect {
                    SemanticEffect::Assignment { target, value } => (
                        ValueFlowRelationKind::Assignment,
                        ValueFlowEndpoint::Value(value_handle(procedure, *value)?),
                        ValueFlowEndpoint::Value(value_handle(procedure, *target)?),
                        false,
                    ),
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Local,
                        source,
                        target,
                    }
                    | SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::BackingStore { .. },
                        source,
                        target,
                    }
                    | SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Transfer(_),
                        source,
                        target,
                    } => (
                        ValueFlowRelationKind::Assignment,
                        ValueFlowEndpoint::Value(value_handle(procedure, *source)?),
                        ValueFlowEndpoint::Value(value_handle(procedure, *target)?),
                        false,
                    ),
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Parameter,
                        source,
                        target,
                    } => {
                        let source_row = procedure.semantics().value(*source).ok_or_else(|| {
                            SemanticProviderError::internal("parameter flow has a stale source")
                        })?;
                        let target_row = procedure.semantics().value(*target).ok_or_else(|| {
                            SemanticProviderError::internal("parameter flow has a stale target")
                        })?;
                        match (&source_row.kind, &target_row.kind) {
                            (SemanticValueKind::Parameter { ordinal, .. }, _) => (
                                ValueFlowRelationKind::Parameter,
                                ValueFlowEndpoint::Port(
                                    ProcedurePortHandle::parameter(procedure.clone(), *ordinal)
                                        .map_err(|error| {
                                            internal_contract("invalid parameter port", error)
                                        })?,
                                ),
                                ValueFlowEndpoint::Value(value_handle(procedure, *target)?),
                                false,
                            ),
                            (_, SemanticValueKind::Parameter { ordinal, .. }) => (
                                ValueFlowRelationKind::Parameter,
                                ValueFlowEndpoint::Value(value_handle(procedure, *source)?),
                                ValueFlowEndpoint::Port(
                                    ProcedurePortHandle::parameter(procedure.clone(), *ordinal)
                                        .map_err(|error| {
                                            internal_contract("invalid parameter port", error)
                                        })?,
                                ),
                                false,
                            ),
                            _ => {
                                return Err(SemanticProviderError::internal(
                                    "parameter flow has no parameter endpoint",
                                ));
                            }
                        }
                    }
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Receiver,
                        target,
                        ..
                    } => (
                        ValueFlowRelationKind::Receiver,
                        ValueFlowEndpoint::Port(
                            ProcedurePortHandle::receiver(procedure.clone()).map_err(|error| {
                                internal_contract("invalid receiver port", error)
                            })?,
                        ),
                        ValueFlowEndpoint::Value(value_handle(procedure, *target)?),
                        false,
                    ),
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Return,
                        source,
                        ..
                    } => (
                        ValueFlowRelationKind::NormalReturn,
                        ValueFlowEndpoint::Value(value_handle(procedure, *source)?),
                        ValueFlowEndpoint::Port(ProcedurePortHandle::normal_return(
                            procedure.clone(),
                        )),
                        false,
                    ),
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::IndexedReturn { ordinal },
                        source,
                        ..
                    } => (
                        ValueFlowRelationKind::NormalReturn,
                        ValueFlowEndpoint::Value(value_handle(procedure, *source)?),
                        ValueFlowEndpoint::Port(
                            ProcedurePortHandle::indexed_normal_return(procedure.clone(), *ordinal)
                                .map_err(|error| {
                                    internal_contract("invalid indexed return port", error)
                                })?,
                        ),
                        false,
                    ),
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::LanguageDefined,
                        source,
                        target,
                    } => (
                        ValueFlowRelationKind::LanguageDefined,
                        ValueFlowEndpoint::Value(value_handle(procedure, *source)?),
                        ValueFlowEndpoint::Value(value_handle(procedure, *target)?),
                        false,
                    ),
                    SemanticEffect::ValueUse { .. } => {
                        unreachable!("value-use events do not derive value-flow relations")
                    }
                    SemanticEffect::Allocation { allocation } => {
                        let allocation =
                            procedure.allocation_handle(*allocation).ok_or_else(|| {
                                SemanticProviderError::internal("allocation effect has a stale ID")
                            })?;
                        let row = procedure
                            .semantics()
                            .allocation(allocation.id())
                            .expect("allocation handle is validated");
                        (
                            ValueFlowRelationKind::Allocation,
                            ValueFlowEndpoint::Location(Box::new(allocation_location(
                                allocation,
                                *self.limits(),
                            )?)),
                            ValueFlowEndpoint::Value(value_handle(procedure, row.result)?),
                            false,
                        )
                    }
                    SemanticEffect::MemoryLoad {
                        location: memory,
                        result,
                        ..
                    } => {
                        let (location, summary) = materialize_abstract_location(
                            procedure,
                            access_path
                                .take()
                                .expect("memory loads resolve an access path"),
                            *self.limits(),
                        )?;
                        let unproven_index = location_has_unproven_exact_index(&location);
                        exact_index |= unproven_index;
                        let loaded = ValueFlowEndpoint::Value(value_handle(procedure, *result)?);
                        // #2453: an element read of a tainted array carries the
                        // array's label. The subscripted expression carries a
                        // label the array acquired downstream of its access-path
                        // origin; the container carries one it acquired at or
                        // before that origin, and is also what a store through
                        // an unprovable subscript marks.
                        if let Some(base) = indexed_base_value(procedure, *memory)? {
                            smashed.push(DerivedRelation {
                                kind: ValueFlowRelationKind::MemoryLoad,
                                source: ValueFlowEndpoint::Value(base),
                                target: loaded.clone(),
                                quality: None,
                            });
                        }
                        if let Some(container) =
                            indexed_container_endpoint(&location, *self.limits())?
                        {
                            smashed.push(DerivedRelation {
                                kind: ValueFlowRelationKind::MemoryLoad,
                                source: container,
                                target: loaded.clone(),
                                quality: None,
                            });
                        }
                        // A subscript the analysis cannot prove reads whatever
                        // any store put in the array, so it reads the wildcard
                        // cell every store also writes. A proven-constant
                        // subscript does not, which is what keeps #2191's
                        // constant-index separation intact.
                        if unproven_index
                            && let Some(cell) = wildcard_index_endpoint(&location, *self.limits())?
                        {
                            smashed.push(DerivedRelation {
                                kind: ValueFlowRelationKind::MemoryLoad,
                                source: cell,
                                target: loaded.clone(),
                                quality: None,
                            });
                        }
                        let source = direct_capture_port_endpoint(procedure, *memory)?
                            .unwrap_or_else(|| ValueFlowEndpoint::Location(Box::new(location)));
                        (ValueFlowRelationKind::MemoryLoad, source, loaded, summary)
                    }
                    SemanticEffect::MemoryStore {
                        location: memory,
                        value,
                        ..
                    } => {
                        let (location, summary) = materialize_abstract_location(
                            procedure,
                            access_path
                                .take()
                                .expect("memory stores resolve an access path"),
                            *self.limits(),
                        )?;
                        let unproven_index = location_has_unproven_exact_index(&location);
                        exact_index |= unproven_index;
                        let stored = ValueFlowEndpoint::Value(value_handle(procedure, *value)?);
                        // #2453, the write direction. Every element store also
                        // writes the wildcard cell, which is what an unprovable
                        // subscript later reads.
                        if let Some(cell) = wildcard_index_endpoint(&location, *self.limits())? {
                            smashed.push(DerivedRelation {
                                kind: ValueFlowRelationKind::MemoryStore,
                                source: stored.clone(),
                                target: cell,
                                quality: None,
                            });
                        }
                        // A store *through* an unprovable subscript could have
                        // landed anywhere in the array, so it marks the array
                        // itself, which every element read observes. A store at
                        // a proven constant does not: #2191 separates two
                        // literal subscripts and this must not revoke that.
                        if unproven_index
                            && let Some(container) =
                                indexed_container_endpoint(&location, *self.limits())?
                        {
                            smashed.push(DerivedRelation {
                                kind: ValueFlowRelationKind::MemoryStore,
                                source: stored.clone(),
                                target: container,
                                quality: None,
                            });
                        }
                        let target = direct_capture_port_endpoint(procedure, *memory)?
                            .unwrap_or_else(|| ValueFlowEndpoint::Location(Box::new(location)));
                        (ValueFlowRelationKind::MemoryStore, stored, target, summary)
                    }
                    SemanticEffect::CaptureBind { capture } => {
                        let row = procedure.semantics().capture(*capture).ok_or_else(|| {
                            SemanticProviderError::internal("capture effect has a stale ID")
                        })?;
                        let child = procedure
                            .artifact()
                            .procedure_handle(row.target)
                            .ok_or_else(|| {
                                SemanticProviderError::internal(
                                    "capture target procedure is not materialized",
                                )
                            })?;
                        let source = match row.captured {
                            CaptureSource::Value(value) => {
                                ValueFlowEndpoint::Value(value_handle(procedure, value)?)
                            }
                            CaptureSource::Location(_) => ValueFlowEndpoint::Location(Box::new(
                                materialize_abstract_location(
                                    procedure,
                                    access_path
                                        .take()
                                        .expect("capture locations resolve an access path"),
                                    *self.limits(),
                                )?
                                .0,
                            )),
                        };
                        (
                            ValueFlowRelationKind::Capture,
                            source,
                            ValueFlowEndpoint::Port(
                                ProcedurePortHandle::capture(child, row.destination).map_err(
                                    |error| internal_contract("invalid child capture port", error),
                                )?,
                            ),
                            false,
                        )
                    }
                    SemanticEffect::Throw { value: Some(value) } => {
                        // #2446: the same thrown value the exceptional-return
                        // port receives is also what a handler of this
                        // procedure binds, when the adapter left the handler
                        // selection open. Both relations ride this event.
                        for binder in handler_bindings.alternatives_for(point.id) {
                            smashed.push(DerivedRelation {
                                kind: ValueFlowRelationKind::HandlerBinding,
                                source: ValueFlowEndpoint::Value(value_handle(procedure, *value)?),
                                target: ValueFlowEndpoint::Value(value_handle(procedure, *binder)?),
                                quality: Some((
                                    ProofStatus::Unproven(HANDLER_SELECTION_UNPROVEN.into()),
                                    EvidenceCompleteness::Partial(
                                        HANDLER_SELECTION_UNPROVEN.into(),
                                    ),
                                )),
                            });
                        }
                        (
                            ValueFlowRelationKind::ExceptionalReturn,
                            ValueFlowEndpoint::Value(value_handle(procedure, *value)?),
                            ValueFlowEndpoint::Port(ProcedurePortHandle::exceptional_return(
                                procedure.clone(),
                            )),
                            false,
                        )
                    }
                    _ => unreachable!("relation-producing effects were classified above"),
                };
                if summary {
                    completeness = EvidenceCompleteness::Partial(
                        "access path retains an unknown selector".into(),
                    );
                    open = true;
                } else if exact_index && matches!(completeness, EvidenceCompleteness::Complete) {
                    completeness = EvidenceCompleteness::Partial(
                        "exact index identity is not value-proven across accesses".into(),
                    );
                }
                let relation_point = procedure.point_handle(point.id).ok_or_else(|| {
                    SemanticProviderError::internal("value-flow relation point could not be scoped")
                })?;
                let relation_event = u32::try_from(event_index).map_err(|_| {
                    SemanticProviderError::internal("value-flow event ordinal exceeds u32")
                })?;
                // #2444: the store's own strong-update verdict, asked only for a
                // store that could hold one. Everything else keeps joining.
                let strong_update = if kind == ValueFlowRelationKind::MemoryStore
                    && matches!(proof, ProofStatus::Proven)
                    && matches!(completeness, EvidenceCompleteness::Complete)
                    && let SemanticEffect::MemoryStore {
                        location, value, ..
                    } = &event.effect
                    && let ValueFlowEndpoint::Location(stored_location) = &target
                    && stored_location.path().is_exact()
                {
                    let bases = store_bases
                        .get_or_insert_with(|| LocalStoreBases::derive(procedure.semantics()));
                    match self.store_holds_strong_update(
                        procedure,
                        context,
                        &relation_point,
                        event_index,
                        *location,
                        *value,
                        bases,
                        &mut staged,
                        request.cancellation,
                    ) {
                        Ok(strong) => strong,
                        Err(StrongUpdateStop::Provider(error)) => return Err(error),
                        Err(StrongUpdateStop::Interruption(stop)) => {
                            interrupted = Some(stop);
                            break 'points;
                        }
                    }
                } else {
                    false
                };
                // #2444 slice 2: every member carrier this event named, and
                // whether this event reads a value a consumption passes on as
                // a whole object. Recorded before the endpoints are moved into
                // the draft.
                container_elements.observe(&source, &proof, &completeness);
                container_elements.observe(&target, &proof, &completeness);
                if let Some(read) = match event.effect {
                    SemanticEffect::Assignment { target, .. }
                    | SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Local,
                        target,
                        ..
                    }
                    | SemanticEffect::MemoryLoad { result: target, .. } => Some(target),
                    _ => None,
                } && whole_container_reads.contains(&read)
                {
                    container_reads.push(ContainerRead {
                        point: relation_point.clone(),
                        event_index: relation_event,
                        value: read,
                        evidence: evidence.clone(),
                        proof: proof.clone(),
                        completeness: completeness.clone(),
                    });
                }
                let transfer = match &event.effect {
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Transfer(transfer),
                        ..
                    } => Some(*transfer),
                    _ => None,
                };
                let draft = FlowRelationDraft {
                    point: relation_point.clone(),
                    event_index: relation_event,
                    kind,
                    transfer,
                    source,
                    target,
                    proof: proof.clone(),
                    completeness: completeness.clone(),
                    evidence: vec![evidence.clone()],
                    strong_update,
                };
                if !push_flow_relation(&mut drafts, &mut retained_evidence, *self.limits(), draft) {
                    truncated = true;
                    break 'points;
                }
                // #2453: the smashed-container relations derived from this same
                // access. They are published after the access they derive from
                // so the primary relation is never dropped in favour of one of
                // them when the provenance budget runs out.
                for derived in smashed {
                    let (derived_proof, derived_completeness) = derived
                        .quality
                        .unwrap_or_else(|| (proof.clone(), completeness.clone()));
                    container_elements.observe(
                        &derived.source,
                        &derived_proof,
                        &derived_completeness,
                    );
                    container_elements.observe(
                        &derived.target,
                        &derived_proof,
                        &derived_completeness,
                    );
                    let draft = FlowRelationDraft {
                        point: relation_point.clone(),
                        event_index: relation_event,
                        kind: derived.kind,
                        transfer: None,
                        source: derived.source,
                        target: derived.target,
                        proof: derived_proof,
                        completeness: derived_completeness,
                        evidence: vec![evidence.clone()],
                        // No derived relation replaces what its target holds.
                        // A smashed container cell is a summary of many
                        // elements by construction, so no store into it can
                        // replace what another store put there (#2453), and a
                        // handler binding the analysis did not prove is
                        // selected must join with whatever else reaches the
                        // binding (#2446).
                        strong_update: false,
                    };
                    if !push_flow_relation(
                        &mut drafts,
                        &mut retained_evidence,
                        *self.limits(),
                        draft,
                    ) {
                        truncated = true;
                        break 'points;
                    }
                }
            }
        }

        // #2444 slice 2: reading a container as a whole reads what is inside
        // it. Every member carrier of the object the read is rooted at flows
        // into the value the read produces, and nothing flows the other way,
        // so element separation, field separation and every strong-update kill
        // keep the behaviour they already had. The relation rides the read's
        // own event, which is what makes the solver ask what the member holds
        // *at the read* rather than what was ever written into it.
        if interrupted.is_none() && !truncated && !container_elements.elements.is_empty() {
            'reads: for read in &container_reads {
                if request.cancellation.is_cancelled() {
                    interrupted = Some(Interruption::Cancelled);
                    break;
                }
                let mut visited_values = HashSet::new();
                let (root, prefix, summarized) = match walk_value_origin(
                    &load_origins,
                    read.value,
                    &mut visited_values,
                    exact_integer,
                ) {
                    ValueOriginWalk::Root {
                        value,
                        offset,
                        summarized,
                    } => (
                        AccessPathRoot::Value(value_handle(procedure, value)?),
                        Vec::new(),
                        summarized || offset != Some(0),
                    ),
                    ValueOriginWalk::Load { location, .. } => {
                        // The whole value was loaded out of memory, so the
                        // object it denotes is whatever that load names.
                        match resolve_access_path(
                            location,
                            &load_origins,
                            self.limits().access_path_length(),
                            request.cancellation,
                            |id| {
                                procedure
                                    .semantics()
                                    .memory_location(id)
                                    .map(|row| &row.kind)
                            },
                            exact_integer,
                            |work| staged.charge(work),
                        )? {
                            AccessPathResolution::Resolved(resolved) => {
                                let (location, summary) = materialize_abstract_location(
                                    procedure,
                                    resolved,
                                    *self.limits(),
                                )?;
                                (
                                    location.path().root().clone(),
                                    location.path().selectors().to_vec(),
                                    summary,
                                )
                            }
                            AccessPathResolution::Interrupted(stop) => {
                                interrupted = Some(stop);
                                break 'reads;
                            }
                        }
                    }
                };
                for element in &container_elements.elements {
                    if element.location.path().root() != &root
                        || !selectors_extend(element.location.path().selectors(), &prefix)
                    {
                        continue;
                    }
                    if let Err(stop) = staged.charge(SemanticWork {
                        values: 1,
                        memory_locations: 1,
                        evidence: 1,
                        nested_entries: 1,
                        ..SemanticWork::default()
                    }) {
                        interrupted = Some(stop);
                        break 'reads;
                    }
                    // The collapse is never better evidenced than the access
                    // that put a label on the member, nor than the read that
                    // observes it: a member reached through a summarized path
                    // stays partial, and a read whose own object identity was
                    // joined does too.
                    let proof = match (&read.proof, &element.proof) {
                        (ProofStatus::Proven, ProofStatus::Proven) => ProofStatus::Proven,
                        (ProofStatus::Unproven(reason), _) | (_, ProofStatus::Unproven(reason)) => {
                            ProofStatus::Unproven(reason.clone())
                        }
                    };
                    let completeness = match (&read.completeness, &element.completeness) {
                        _ if summarized => EvidenceCompleteness::Partial(
                            "the whole value read does not resolve to one proven object".into(),
                        ),
                        (EvidenceCompleteness::Complete, EvidenceCompleteness::Complete) => {
                            EvidenceCompleteness::Complete
                        }
                        (EvidenceCompleteness::Partial(reason), _)
                        | (_, EvidenceCompleteness::Partial(reason)) => {
                            EvidenceCompleteness::Partial(reason.clone())
                        }
                    };
                    let draft = FlowRelationDraft {
                        point: read.point.clone(),
                        event_index: read.event_index,
                        kind: ValueFlowRelationKind::ContainerCollapse,
                        transfer: None,
                        source: ValueFlowEndpoint::Location(Box::new(element.location.clone())),
                        target: ValueFlowEndpoint::Value(value_handle(procedure, read.value)?),
                        proof,
                        completeness,
                        evidence: vec![read.evidence.clone()],
                        // A collapse only ever adds what a member holds to
                        // what the whole value holds. It replaces nothing.
                        strong_update: false,
                    };
                    if !push_flow_relation(
                        &mut drafts,
                        &mut retained_evidence,
                        *self.limits(),
                        draft,
                    ) {
                        truncated = true;
                        break 'reads;
                    }
                }
            }
        }

        let has_unproven_relation = drafts.iter().any(|draft| {
            !matches!(draft.proof, ProofStatus::Proven)
                || !matches!(draft.completeness, EvidenceCompleteness::Complete)
        });
        let coverage = if truncated {
            CandidateCoverage::Truncated
        } else if interrupted.is_some() || open {
            CandidateCoverage::Open
        } else {
            CandidateCoverage::Exhaustive
        };
        let snapshot = materialize_flow_snapshot(
            procedure,
            context,
            drafts,
            coverage,
            *self.limits(),
            discharged_gaps,
        )?;
        if interrupted.is_none() && !request.cancellation.is_cancelled() {
            *request.budget = staged.budget;
        } else if interrupted.is_none() {
            interrupted = Some(Interruption::Cancelled);
        }
        Ok(publish_flow_outcome(
            snapshot,
            interrupted,
            has_unproven_relation,
            gap_quality,
            staged.work,
        ))
    }

    fn call_bindings(
        &self,
        call: &crate::analyzer::semantic::CallSiteHandle,
        candidate: &DispatchCandidate,
        context: &OracleCallContext,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<CallBindings>, SemanticProviderError> {
        if request.cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: SemanticWork::default(),
            });
        }
        let mut staged = WorkStager::new(request);
        let initial_work = SemanticWork {
            procedures: 1,
            call_sites: 1,
            nested_entries: 1,
            ..SemanticWork::default()
        };
        if let Err(Interruption::Budget(exceeded)) = staged.charge(initial_work) {
            return Ok(SemanticOutcome::ExceededBudget {
                partial: None,
                exceeded,
                work: initial_work,
            });
        }
        let call_row = call
            .procedure()
            .semantics()
            .call_site(call.id())
            .ok_or_else(|| SemanticProviderError::internal("call-site handle is stale"))?
            .clone();
        let callee = candidate.target();
        let mut interrupted = None;

        let mut build = BindingBuild::new(false);
        let caller_abort_user_code = abort_paths_run_user_code(call.procedure().semantics());
        for gap in call.procedure().semantics().gaps() {
            if interrupted.is_some() {
                break;
            }
            if request.cancellation.is_cancelled() {
                interrupted = Some(Interruption::Cancelled);
                break;
            }
            if let Err(stop) = staged.charge(SemanticWork {
                gaps: 1,
                ..SemanticWork::default()
            }) {
                interrupted = Some(stop);
                break;
            }
            let scoped_to_call = match gap.subject {
                SemanticGapSubject::Procedure => true,
                SemanticGapSubject::Point => gap.point == call_row.point,
                SemanticGapSubject::Value(value) => {
                    call_row.callee == value
                        || call_row.receiver == Some(value)
                        || call_row
                            .arguments
                            .iter()
                            .any(|argument| argument.value == value)
                        || call_row
                            .normal_result_values()
                            .any(|result| result == value)
                        || call_row.thrown == Some(value)
                }
                SemanticGapSubject::CallSite(call_site) => call_site == call.id(),
                SemanticGapSubject::CallContinuation { call_site, .. } => call_site == call.id(),
                SemanticGapSubject::MemoryLocation(_)
                | SemanticGapSubject::Capture(_)
                | SemanticGapSubject::AsyncContinuation { .. } => false,
            };
            let relevant = scoped_to_call
                && (gap.impacts.contains(SemanticGapImpact::CallEvaluation)
                    || gap.impacts.contains(SemanticGapImpact::ValueFlow))
                && call_target_refinement_call(call.procedure().semantics(), gap).is_none()
                && !implicit_abort_gap_is_discharged(gap, caller_abort_user_code);
            build.open |= relevant;
            if relevant {
                build.gap_quality = merge_gap_quality(build.gap_quality, gap);
            }
        }
        let callee_abort_user_code = abort_paths_run_user_code(callee.semantics());
        for gap in callee.semantics().gaps() {
            if interrupted.is_some() {
                break;
            }
            if request.cancellation.is_cancelled() {
                interrupted = Some(Interruption::Cancelled);
                break;
            }
            if let Err(stop) = staged.charge(SemanticWork {
                gaps: 1,
                ..SemanticWork::default()
            }) {
                interrupted = Some(stop);
                break;
            }
            let relevant = (gap.impacts.contains(SemanticGapImpact::CallEvaluation)
                || gap.impacts.contains(SemanticGapImpact::ReturnTransfer)
                || gap.impacts.contains(SemanticGapImpact::ValueFlow))
                && call_target_refinement_call(callee.semantics(), gap).is_none()
                && !implicit_abort_gap_is_discharged(gap, callee_abort_user_code)
                && !super::external_constant_field_read_discharges_gap(
                    gap,
                    callee,
                    self.workspace,
                    request,
                )?;
            build.open |= relevant;
            if relevant {
                build.gap_quality = merge_gap_quality(build.gap_quality, gap);
            }
        }

        if let Some(interruption) = interrupted {
            return interrupted_call_bindings(
                call,
                candidate,
                context,
                build,
                interruption,
                staged.work,
                *self.limits(),
            );
        }

        if let Err(interruption) = staged.charge(SemanticWork {
            values: callee.semantics().values().len(),
            ..SemanticWork::default()
        }) {
            return interrupted_call_bindings(
                call,
                candidate,
                context,
                build,
                interruption,
                staged.work,
                *self.limits(),
            );
        }

        let call_evidence = evidence_handle(call.procedure(), call_row.evidence)?;
        let callee_evidence = evidence_handle(callee, callee.semantics().evidence())?;
        let mut formals = callee
            .semantics()
            .values()
            .iter()
            .filter_map(|value| match &value.kind {
                SemanticValueKind::Parameter {
                    ordinal,
                    multiplicity,
                    name,
                    passing_mode,
                } => Some((
                    *ordinal,
                    multiplicity.clone(),
                    name.clone(),
                    *passing_mode,
                    value.evidence,
                )),
                _ => None,
            })
            .collect::<Vec<_>>();
        formals.sort_by_key(|(ordinal, _, _, _, _)| *ordinal);

        let mut bound_formals = std::collections::HashSet::new();
        if interrupted.is_none()
            && let Some(receiver_row) = callee
                .semantics()
                .values()
                .iter()
                .find(|value| matches!(value.kind, SemanticValueKind::Receiver { .. }))
        {
            // A call that spells no receiver operand can still dispatch on
            // one, two different ways.
            //
            // The first is a constructor call: `new Type(...)` spells no
            // receiver syntax at all (there is no existing object to invoke
            // on), but the call's own `result` names the object it is about
            // to allocate, and that is exactly what the constructor's own
            // `this` binds to (#2574) -- true for any argument count, not
            // only the zero-argument case `allocation_call_is_dischargeable`
            // restricts itself to for its own, different question (whether
            // an *unresolved* dispatch still leaves the allocated identity
            // provable).
            //
            // The second is a bare call between members of one declaring
            // type, which runs on the caller's own `this`. Bind that
            // implicit actual only when the sibling identity is
            // structurally proven; otherwise the missing operand keeps the
            // binding honestly open.
            let (actual, extra_evidence) = match call_row.receiver {
                Some(actual_id) => (Some(actual_id), None),
                None => {
                    match constructor_call_allocation_site(call.procedure().semantics(), &call_row)
                    {
                        Some(allocation) => (
                            Some(allocation.result),
                            Some(evidence_handle(call.procedure(), allocation.evidence)?),
                        ),
                        None => {
                            match implicit_dispatch_receiver_actual(
                                call.procedure(),
                                callee,
                                receiver_row,
                            ) {
                                Some(caller_receiver) => (
                                    Some(caller_receiver.id),
                                    Some(evidence_handle(
                                        call.procedure(),
                                        caller_receiver.evidence,
                                    )?),
                                ),
                                None => (None, None),
                            }
                        }
                    }
                }
            };
            if request.cancellation.is_cancelled() {
                interrupted = Some(Interruption::Cancelled);
            } else if let Some(actual_id) = actual {
                let evidence = dedup_evidence(
                    [
                        call_evidence.clone(),
                        evidence_handle(callee, receiver_row.evidence)?,
                    ]
                    .into_iter()
                    .chain(extra_evidence),
                );
                if !proven_complete(&evidence) {
                    build.open = true;
                } else if build.can_retain(std::slice::from_ref(&evidence), 1, *self.limits()) {
                    if let Err(stop) = staged.charge(SemanticWork {
                        values: 2,
                        evidence: evidence.len(),
                        nested_entries: 1,
                        ..SemanticWork::default()
                    }) {
                        interrupted = Some(stop);
                    } else {
                        let relation = build.push_relation(evidence);
                        build.retained_entries += 1;
                        build.bindings.push(CallBindingDraft::Receiver {
                            relation,
                            actual: value_handle(call.procedure(), actual_id)?,
                            formal: ProcedurePortHandle::receiver(callee.clone()).map_err(
                                |error| internal_contract("invalid callee receiver port", error),
                            )?,
                        });
                    }
                } else {
                    build.truncated = true;
                }
            } else {
                build.open = true;
            }
        }

        let mut formal_cursor = 0usize;
        let mut positional_width_unknown = false;
        for (source_index, argument) in call_row.arguments.iter().enumerate() {
            if interrupted.is_some() || build.truncated {
                break;
            }
            if request.cancellation.is_cancelled() {
                interrupted = Some(Interruption::Cancelled);
                break;
            }
            if let Err(stop) = staged.charge(SemanticWork {
                values: 1,
                nested_entries: 1,
                ..SemanticWork::default()
            }) {
                interrupted = Some(stop);
                break;
            }
            let actual = value_handle(call.procedure(), argument.value)?;
            let selected = match &argument.expansion {
                CallArgumentExpansion::Direct(
                    crate::analyzer::semantic::ArgumentDomain::Positional
                    | crate::analyzer::semantic::ArgumentDomain::PositionalOrKeyword,
                ) if !positional_width_unknown => loop {
                    let Some((ordinal, multiplicity, _, passing_mode, evidence)) =
                        formals.get(formal_cursor)
                    else {
                        break None;
                    };
                    match multiplicity {
                        FormalMultiplicity::One => {
                            formal_cursor += 1;
                            if passing_mode.accepts_positional() && !bound_formals.contains(ordinal)
                            {
                                break Some((*ordinal, evidence, false, CallArgumentMember::Whole));
                            }
                        }
                        FormalMultiplicity::Rest(
                            crate::analyzer::semantic::ArgumentDomain::Positional
                            | crate::analyzer::semantic::ArgumentDomain::PositionalOrKeyword,
                        ) if passing_mode.accepts_positional() => {
                            break Some((*ordinal, evidence, true, CallArgumentMember::Whole));
                        }
                        FormalMultiplicity::Rest(_) => formal_cursor += 1,
                    }
                },
                CallArgumentExpansion::Direct(
                    crate::analyzer::semantic::ArgumentDomain::Keyword,
                ) => {
                    let named = argument.keyword.as_deref();
                    let duplicate = named.is_some_and(|actual| {
                        formals.iter().any(|(ordinal, multiplicity, name, _, _)| {
                            matches!(multiplicity, FormalMultiplicity::One)
                                && name.as_deref() == Some(actual)
                                && bound_formals.contains(ordinal)
                        })
                    });
                    if duplicate {
                        None
                    } else {
                        let exact = named.and_then(|actual| {
                            formals
                                .iter()
                                .find(|(ordinal, multiplicity, name, mode, _)| {
                                    matches!(multiplicity, FormalMultiplicity::One)
                                        && name.as_deref() == Some(actual)
                                        && mode.accepts_named()
                                        && !bound_formals.contains(ordinal)
                                })
                        });
                        let rest = || {
                            formals.iter().find(|(_, multiplicity, _, mode, _)| {
                                matches!(
                                    multiplicity,
                                    FormalMultiplicity::Rest(
                                        crate::analyzer::semantic::ArgumentDomain::Keyword
                                            | crate::analyzer::semantic::ArgumentDomain::PositionalOrKeyword
                                    )
                                ) && mode.accepts_named()
                            })
                        };
                        exact
                            .or_else(rest)
                            .map(|(ordinal, multiplicity, _, _, evidence)| {
                                let member = named.map_or(CallArgumentMember::Whole, |name| {
                                    CallArgumentMember::Keyword(name.into())
                                });
                                (
                                    *ordinal,
                                    evidence,
                                    matches!(multiplicity, FormalMultiplicity::Rest(_)),
                                    member,
                                )
                            })
                    }
                }
                CallArgumentExpansion::Direct(
                    crate::analyzer::semantic::ArgumentDomain::LanguageDefined(actual),
                ) => formals
                    .iter()
                    .find_map(
                        |(ordinal, multiplicity, _, _, evidence)| match multiplicity {
                            FormalMultiplicity::Rest(
                                crate::analyzer::semantic::ArgumentDomain::LanguageDefined(
                                    expected,
                                ),
                            ) if expected == actual => {
                                Some((*ordinal, evidence, true, CallArgumentMember::Whole))
                            }
                            FormalMultiplicity::One | FormalMultiplicity::Rest(_) => None,
                        },
                    ),
                CallArgumentExpansion::Spread(
                    crate::analyzer::semantic::ArgumentDomain::Positional
                    | crate::analyzer::semantic::ArgumentDomain::PositionalOrKeyword,
                ) => {
                    positional_width_unknown = true;
                    None
                }
                CallArgumentExpansion::Unclassified
                | CallArgumentExpansion::Spread(_)
                | CallArgumentExpansion::Direct(
                    crate::analyzer::semantic::ArgumentDomain::Positional
                    | crate::analyzer::semantic::ArgumentDomain::PositionalOrKeyword,
                ) => None,
            };
            let closure_evidence = vec![call_evidence.clone()];
            let mut relation_evidence = vec![closure_evidence.clone()];
            let mapping = if let Some((ordinal, formal_evidence_id, rest, member)) = selected {
                let mapping_evidence = dedup_evidence([
                    call_evidence.clone(),
                    evidence_handle(callee, *formal_evidence_id)?,
                ]);
                relation_evidence.push(mapping_evidence.clone());
                let (proof, completeness) = evidence_quality(&mapping_evidence);
                if !rest {
                    bound_formals.insert(ordinal);
                }
                Some((
                    mapping_evidence,
                    CallArgumentMapping::new(
                        source_index as u32,
                        member,
                        CallArgumentEndpoint::Value(actual),
                        ProcedurePortHandle::parameter(callee.clone(), ordinal).map_err(
                            |error| internal_contract("invalid callee parameter port", error),
                        )?,
                        CallPassingMode::Value,
                    ),
                    proof,
                    completeness,
                ))
            } else {
                build.open = true;
                None
            };
            let group_coverage = if mapping.is_some() && proven_complete(&closure_evidence) {
                CandidateCoverage::Exhaustive
            } else {
                CandidateCoverage::Open
            };
            let entry_cost = 2 + usize::from(mapping.is_some());
            if !build.can_retain(&relation_evidence, entry_cost, *self.limits()) {
                build.truncated = true;
                break;
            }
            let relation_work = SemanticWork {
                evidence: relation_evidence.iter().map(Vec::len).sum(),
                nested_entries: relation_evidence.len(),
                ..SemanticWork::default()
            };
            if let Err(stop) = staged.charge(relation_work) {
                interrupted = Some(stop);
                break;
            }
            let closure_relation = build.push_relation(closure_evidence);
            let mapping = mapping.map(|(evidence, mapping, proof, completeness)| {
                let relation = build.push_relation(evidence);
                Box::new((relation, mapping, proof, completeness))
            });
            build.retained_entries += entry_cost;
            build.bindings.push(CallBindingDraft::ArgumentGroup {
                closure_relation,
                source: source_index as u32,
                mapping,
                coverage: group_coverage,
            });
        }

        if interrupted.is_none() && !build.truncated {
            for (ordinal, result_id) in call_row.normal_results.iter().copied().enumerate() {
                if request.cancellation.is_cancelled() {
                    interrupted = Some(Interruption::Cancelled);
                    break;
                }
                let Ok(formal) =
                    ProcedurePortHandle::indexed_normal_return(callee.clone(), ordinal as u32)
                else {
                    build.open = true;
                    continue;
                };
                let evidence = dedup_evidence([call_evidence.clone(), callee_evidence.clone()]);
                if !proven_complete(&evidence) {
                    build.open = true;
                    continue;
                }
                if !build.can_retain(std::slice::from_ref(&evidence), 1, *self.limits()) {
                    build.truncated = true;
                    break;
                }
                if let Err(stop) = staged.charge(SemanticWork {
                    values: 1,
                    evidence: evidence.len(),
                    nested_entries: 1,
                    ..SemanticWork::default()
                }) {
                    interrupted = Some(stop);
                    break;
                }
                let relation = build.push_relation(evidence);
                build.retained_entries += 1;
                build.bindings.push(CallBindingDraft::NormalReturn {
                    relation,
                    formal,
                    result: value_handle(call.procedure(), result_id)?,
                });
            }
        }
        if interrupted.is_none() && !build.truncated {
            for (exceptional, result_id) in [(false, call_row.result), (true, call_row.thrown)] {
                let Some(result_id) = result_id else {
                    continue;
                };
                if request.cancellation.is_cancelled() {
                    interrupted = Some(Interruption::Cancelled);
                    break;
                }
                let evidence = dedup_evidence([call_evidence.clone(), callee_evidence.clone()]);
                if !proven_complete(&evidence) {
                    build.open = true;
                    continue;
                }
                if !build.can_retain(std::slice::from_ref(&evidence), 1, *self.limits()) {
                    build.truncated = true;
                    break;
                }
                if let Err(stop) = staged.charge(SemanticWork {
                    values: 1,
                    evidence: evidence.len(),
                    nested_entries: 1,
                    ..SemanticWork::default()
                }) {
                    interrupted = Some(stop);
                    break;
                }
                let relation = build.push_relation(evidence);
                build.retained_entries += 1;
                let result = value_handle(call.procedure(), result_id)?;
                if exceptional {
                    build.bindings.push(CallBindingDraft::ExceptionalReturn {
                        relation,
                        formal: ProcedurePortHandle::exceptional_return(callee.clone()),
                        result,
                    });
                } else {
                    build.bindings.push(CallBindingDraft::NormalReturn {
                        relation,
                        formal: ProcedurePortHandle::normal_return(callee.clone()),
                        result,
                    });
                }
            }
        }

        if formals.iter().any(|(ordinal, multiplicity, _, _, _)| {
            matches!(multiplicity, FormalMultiplicity::One) && !bound_formals.contains(ordinal)
        }) {
            build.open = true;
        }
        let coverage = if build.truncated {
            CandidateCoverage::Truncated
        } else if interrupted.is_some() || build.open {
            CandidateCoverage::Open
        } else {
            CandidateCoverage::Exhaustive
        };
        let has_unproven_relation = build.has_unproven_relation;
        let gap_quality = build.gap_quality;
        let quality = merge_relation_quality(gap_quality, has_unproven_relation);
        let bindings =
            materialize_call_bindings(call, candidate, context, build, coverage, *self.limits())?;
        if interrupted.is_none() && !request.cancellation.is_cancelled() {
            *request.budget = staged.budget;
        } else if interrupted.is_none() {
            interrupted = Some(Interruption::Cancelled);
        }
        Ok(match interrupted {
            Some(Interruption::Budget(exceeded)) => SemanticOutcome::ExceededBudget {
                partial: Some(bindings),
                exceeded,
                work: staged.work,
            },
            Some(Interruption::Cancelled) => SemanticOutcome::Cancelled {
                partial: Some(bindings),
                work: staged.work,
            },
            None if coverage == CandidateCoverage::Truncated => SemanticOutcome::Unproven {
                partial: bindings,
                work: staged.work,
            },
            None if matches!(quality, Some(GapOutcomeQuality::Unsupported(_))) => {
                let Some(GapOutcomeQuality::Unsupported(capability)) = quality else {
                    unreachable!("guard establishes unsupported gap quality")
                };
                SemanticOutcome::Unsupported {
                    capability,
                    partial: Some(bindings),
                    work: staged.work,
                }
            }
            None if matches!(quality, Some(GapOutcomeQuality::Unknown)) => {
                SemanticOutcome::Unknown {
                    partial: Some(bindings),
                    work: staged.work,
                }
            }
            None if matches!(quality, Some(GapOutcomeQuality::Unproven)) => {
                SemanticOutcome::Unproven {
                    partial: bindings,
                    work: staged.work,
                }
            }
            None if matches!(quality, Some(GapOutcomeQuality::Ambiguous)) => {
                SemanticOutcome::Ambiguous {
                    candidates: bindings,
                    work: staged.work,
                }
            }
            None if coverage == CandidateCoverage::Open => SemanticOutcome::Unknown {
                partial: Some(bindings),
                work: staged.work,
            },
            None => SemanticOutcome::Complete {
                value: bindings,
                work: staged.work,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{AnalyzerConfig, Language};
    use crate::cancellation::CancellationToken;

    use crate::inline_project::InlineTestProject;

    #[test]
    fn typed_gap_quality_dominates_unproven_relation_evidence() {
        assert_eq!(
            merge_relation_quality(
                Some(GapOutcomeQuality::Unsupported(SemanticCapability::Calls)),
                true,
            ),
            Some(GapOutcomeQuality::Unsupported(SemanticCapability::Calls))
        );
        assert_eq!(
            merge_relation_quality(Some(GapOutcomeQuality::Unknown), true),
            Some(GapOutcomeQuality::Unknown)
        );
    }

    #[test]
    fn unproven_relation_evidence_keeps_its_existing_quality_floor() {
        assert_eq!(
            merge_relation_quality(None, true),
            Some(GapOutcomeQuality::Unproven)
        );
        assert_eq!(
            merge_relation_quality(Some(GapOutcomeQuality::Ambiguous), true),
            Some(GapOutcomeQuality::Unproven)
        );
        assert_eq!(
            merge_relation_quality(Some(GapOutcomeQuality::Unproven), true),
            Some(GapOutcomeQuality::Unproven)
        );
        assert_eq!(merge_relation_quality(None, false), None);
    }

    #[test]
    fn issue_2835_balanced_templates_preserve_their_typed_quality_bound() {
        fn assert_run_outcomes(
            language: Language,
            path: &str,
            source: &str,
            assert_outcome: impl Fn(&SemanticOutcome<ValueFlowSnapshot>),
        ) {
            let project = InlineTestProject::with_language(language)
                .file(path, source)
                .build();
            let file = project.file(path);
            let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
            let cancellation = CancellationToken::default();
            let mut materialization_budget = crate::analyzer::semantic::SemanticBudget::default();
            let artifact = analyzer
                .materialize_program_semantics(
                    &file,
                    &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
                )
                .expect("semantic materialization runs")
                .available_value()
                .cloned()
                .expect("semantic artifact is available");
            let oracle = analyzer.semantic_oracle_provider();

            for name in ["positive", "negative"] {
                let procedure = artifact
                    .procedures()
                    .iter()
                    .find(|procedure| {
                        procedure
                            .locator()
                            .declaration()
                            .segments()
                            .last()
                            .and_then(|segment| segment.name())
                            == Some(name)
                    })
                    .and_then(|procedure| artifact.procedure_handle(procedure.id()))
                    .unwrap_or_else(|| panic!("missing {name} procedure"));
                let mut budget = crate::analyzer::semantic::SemanticBudget::default();
                let outcome = oracle
                    .procedure_relations(
                        &procedure,
                        &OracleCallContext::empty(),
                        &mut SemanticRequest::new(&mut budget, &cancellation),
                    )
                    .expect("value-flow relation query runs");
                assert_outcome(&outcome);
                assert!(
                    outcome.available_value().is_some(),
                    "{name} must retain its partial relation artifact: {outcome:#?}"
                );
            }
        }

        assert_run_outcomes(
            Language::Cpp,
            "kernel.c",
            r#"#include <string.h>
struct Record { const char *key; int value; };
int source(void) { return 1; }
void sink(int value) {}
void positive(void) {
    struct Record records[2];
    records[0].key = "record";
    records[0].value = source();
    for (int index = 0; index < 2; index++) {
        if (strcmp(records[index].key, "record") == 0) sink(records[index].value);
    }
}
void negative(void) {
    struct Record records[2];
    struct Record others[2];
    records[0].value = source();
    others[0].key = "record";
    others[0].value = 0;
    for (int index = 0; index < 2; index++) {
        if (strcmp(others[index].key, "record") == 0) sink(others[index].value);
    }
}
"#,
            |outcome| {
                assert!(
                    matches!(outcome, SemanticOutcome::Unknown { .. }),
                    "dynamic-index evidence must not hide C's unknown call resolution: {outcome:#?}"
                );
            },
        );

        assert_run_outcomes(
            Language::Cpp,
            "kernel.cpp",
            r#"struct FlowException { int value; };
int source() { return 1; }
void sink(int value) {}
void positive() {
    try {
        FlowException flow;
        flow.value = source();
        throw flow;
    } catch (FlowException &caught) {
        sink(caught.value);
    }
}
void negative() {
    try {
        FlowException flow;
        int ignored = source();
        flow.value = 0;
        throw flow;
    } catch (FlowException &caught) {
        sink(caught.value);
    }
}
"#,
            |outcome| {
                assert!(
                    matches!(
                        outcome,
                        SemanticOutcome::Unsupported {
                            capability: SemanticCapability::ExceptionalControlFlow,
                            ..
                        }
                    ),
                    "unproven catch relations must retain C++'s typed handler-selection boundary: {outcome:#?}"
                );
            },
        );
    }

    #[test]
    fn active_cleanup_exceptional_completion_keeps_value_flow_open() {
        let project = InlineTestProject::with_language(Language::Go)
            .file(
                "main.go",
                r#"package main

type item struct { value int }

func cleanup() {}

func active(input *item) int {
    defer cleanup()
    return input.value
}
"#,
            )
            .build();
        let file = project.file("main.go");
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut materialization_budget = crate::analyzer::semantic::SemanticBudget::default();
        let artifact = analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("Go semantic materialization runs")
            .available_value()
            .cloned()
            .expect("Go semantic artifact is available");
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("active")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("active procedure");
        let exceptional_gap = procedure
            .semantics()
            .gaps()
            .iter()
            .find(|gap| {
                gap.capability == SemanticCapability::ExceptionalControlFlow
                    && gap.detail.as_ref() == "selection may panic on a nil operand"
            })
            .expect("field selection exceptional-flow gap");
        assert_eq!(
            exceptional_gap.discharge,
            SemanticGapDischarge::ExitOnlyProcedureCompletion
        );
        assert!(
            exceptional_gap
                .impacts
                .contains(SemanticGapImpact::ValueFlow)
        );
        let abort_user_code = abort_paths_run_user_code(procedure.semantics());
        assert!(abort_user_code, "the active defer runs user code on unwind");
        assert!(
            !implicit_abort_gap_is_discharged(exceptional_gap, abort_user_code),
            "exit-only procedure completion is not a value-flow discharge"
        );

        let oracle = analyzer.semantic_oracle_provider();
        let mut budget = crate::analyzer::semantic::SemanticBudget::default();
        let outcome = oracle
            .procedure_relations(
                &procedure,
                &OracleCallContext::empty(),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("Go value-flow relation query runs");
        assert!(!outcome.is_complete(), "{outcome:#?}");
        let snapshot = outcome
            .available_value()
            .expect("an open value-flow snapshot remains available");
        assert_eq!(snapshot.coverage(), CandidateCoverage::Open);
        assert!(
            !snapshot.gap_is_discharged(exceptional_gap.id),
            "the new completion marker remains an explicit value-flow boundary: {outcome:#?}"
        );
    }

    #[test]
    fn go_canonical_literal_indices_require_closed_base_identity() {
        let project = InlineTestProject::with_language(Language::Go)
            .file(
                "main.go",
                r#"package main

func literal() int {
    values := [2]int{}
    values[0] = 1
    return values[0]
}

func directLiteral() int {
    return [2]int{1}[0]
}

func source() int { return 1 }

func directCallStore() int {
    values := [2]int{}
    values[0] = source()
    values[1] = 0
    return values[0]
}

func siblingLiteral() int {
    values := [2]int{}
    values[0] = 1
    values[1] = 0
    return values[0]
}

func siblingLiteralNegative() int {
    values := [2]int{}
    values[0] = 1
    values[1] = 0
    return values[1]
}

func dynamic(index int) int {
    values := [2]int{}
    values[index] = 1
    return values[index]
}

func rebound() int {
    values := [2]int{}
    index := 0
    values[index] = 1
    return values[index]
}

func parameterAlias(first, second []int) int {
    first[0] = 1
    return second[0]
}

func addressEscape(consume func(*[2]int)) int {
    values := [2]int{}
    consume(&values)
    values[0] = 1
    return values[0]
}

func arrayCopy() int {
    first := [2]int{}
    first[0] = 1
    second := first
    first[0] = 0
    return second[0]
}
"#,
            )
            .build();
        let file = project.file("main.go");
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut materialization_budget = crate::analyzer::semantic::SemanticBudget::default();
        let artifact = analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("Go semantic materialization runs")
            .available_value()
            .cloned()
            .expect("Go semantic artifact is available");
        let oracle = analyzer.semantic_oracle_provider();
        let query = |name: &str| {
            let semantics = artifact
                .procedures()
                .iter()
                .find(|procedure| {
                    procedure
                        .locator()
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some(name)
                })
                .unwrap_or_else(|| panic!("missing Go procedure {name}"));
            let gaps = semantics
                .gaps()
                .iter()
                .map(|gap| {
                    (
                        gap.id,
                        gap.capability,
                        gap.discharge,
                        gap.point,
                        gap.subject,
                        gap.detail.clone(),
                    )
                })
                .collect::<Vec<_>>();
            let index_gaps = gaps
                .iter()
                .filter(|(_, capability, _, _, _, _)| {
                    *capability == SemanticCapability::IndexMemory
                })
                .map(|(id, _, _, _, _, _)| *id)
                .collect::<Vec<_>>();
            let procedure = artifact
                .procedure_handle(semantics.id())
                .expect("Go procedure handle");
            let mut budget = crate::analyzer::semantic::SemanticBudget::default();
            let outcome = oracle
                .procedure_relations(
                    &procedure,
                    &OracleCallContext::empty(),
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .expect("Go value-flow relation query runs");
            (index_gaps, gaps, outcome)
        };

        for (name, expected_gaps) in [
            ("literal", 2),
            ("directLiteral", 1),
            ("siblingLiteral", 3),
            ("siblingLiteralNegative", 3),
        ] {
            let (literal_gaps, gaps, literal) = query(name);
            let SemanticOutcome::Complete {
                value: literal_snapshot,
                ..
            } = literal
            else {
                panic!("{name} canonical literal index flow must be complete; gaps: {gaps:#?}");
            };
            assert_eq!(literal_gaps.len(), expected_gaps, "{name}");
            assert_eq!(
                literal_snapshot.coverage(),
                CandidateCoverage::Exhaustive,
                "{name}"
            );
            assert!(
                literal_gaps
                    .iter()
                    .all(|gap| literal_snapshot.gap_is_discharged(*gap)),
                "{name}"
            );
        }

        let (direct_call_index_gaps, direct_call_gaps, direct_call) = query("directCallStore");
        assert_eq!(direct_call_index_gaps.len(), 3);
        assert!(direct_call_gaps.iter().all(|(_, _, discharge, _, _, _)| {
            *discharge != SemanticGapDischarge::RetainedEvaluationOrder
        }));
        let direct_call_snapshot = direct_call
            .available_value()
            .unwrap_or_else(|| panic!("directCallStore must retain relations: {direct_call:#?}"));
        assert!(
            direct_call_index_gaps
                .iter()
                .all(|gap| direct_call_snapshot.gap_is_discharged(*gap)),
            "directCallStore: {direct_call:#?}"
        );
        for (gap, capability, discharge, point, subject, detail) in direct_call_gaps {
            let must_be_discharged = matches!(
                discharge,
                SemanticGapDischarge::CanonicalIndexIdentity
                    | SemanticGapDischarge::NonRejoiningExceptionalExit
            );
            assert_eq!(
                direct_call_snapshot.gap_is_discharged(gap),
                must_be_discharged,
                "directCallStore {capability:?} gap {gap:?} at {point:?} subject={subject:?} detail={detail}"
            );
        }

        for (name, expected_gaps) in [("dynamic", 2), ("rebound", 2), ("parameterAlias", 2)] {
            let (index_gaps, _, outcome) = query(name);
            assert_eq!(index_gaps.len(), expected_gaps, "{name}");
            assert!(!outcome.is_complete(), "{name}: {outcome:#?}");
            let snapshot = outcome
                .available_value()
                .unwrap_or_else(|| panic!("{name} must retain partial relations: {outcome:#?}"));
            assert_eq!(snapshot.coverage(), CandidateCoverage::Open, "{name}");
            assert!(
                index_gaps
                    .iter()
                    .all(|gap| !snapshot.gap_is_discharged(*gap)),
                "{name}: {outcome:#?}"
            );
        }

        let (address_escape_gaps, _, address_escape) = query("addressEscape");
        assert_eq!(address_escape_gaps.len(), 2);
        assert!(
            !address_escape.is_complete(),
            "an array passed by address to an unresolved call must remain open"
        );

        let (array_copy_gaps, _, array_copy) = query("arrayCopy");
        let [first_store, first_overwrite, copied_load] = array_copy_gaps.as_slice() else {
            panic!("arrayCopy must retain its three index gaps: {array_copy_gaps:#?}");
        };
        assert!(!array_copy.is_complete(), "arrayCopy: {array_copy:#?}");
        let snapshot = array_copy
            .available_value()
            .unwrap_or_else(|| panic!("arrayCopy must retain partial relations: {array_copy:#?}"));
        assert_eq!(snapshot.coverage(), CandidateCoverage::Open);
        assert!(
            snapshot.relations().iter().any(|relation| {
                matches!(
                    relation.transfer,
                    Some(ValueTransfer {
                        kind: crate::analyzer::semantic::TransferKind::AggregateCopy,
                        operation: crate::analyzer::semantic::TransferOperation::None,
                    })
                ) && relation.kind == ValueFlowRelationKind::Assignment
                    && relation.is_proven_complete()
            }),
            "the proven transfer positive survives unrelated open index coverage: {array_copy:#?}"
        );
        assert!(snapshot.gap_is_discharged(*first_store));
        assert!(snapshot.gap_is_discharged(*first_overwrite));
        assert!(
            !snapshot.gap_is_discharged(*copied_load),
            "the copied array has no proven element-store identity: {array_copy:#?}"
        );
    }

    #[test]
    fn ambiguous_load_origin_summarizes_access_path() {
        let base = ValueId::new(0);
        let locations = [MemoryLocationKind::Index {
            base,
            index: None,
            constant_index: None,
            identity: crate::analyzer::semantic::IndexedLocationIdentity::Element,
        }];
        let load_origins = HashMap::from([(base, LoadOrigin::Ambiguous)]);

        let draft = resolve_access_path(
            MemoryLocationId::new(0),
            &load_origins,
            8,
            &crate::CancellationToken::default(),
            |id| locations.get(id.index()),
            |_| None,
            |_| Ok(()),
        )
        .unwrap();
        let AccessPathResolution::Resolved(draft) = draft else {
            panic!("unbudgeted access-path resolution must complete")
        };

        assert!(matches!(draft.root, AccessPathRootDraft::Value(value) if value == base));
        assert_eq!(draft.selectors.len(), 1);
        assert_eq!(draft.tail, AccessPathTail::Summary);
    }

    #[test]
    fn local_integer_slice_offsets_canonicalize_index_paths() {
        let project = InlineTestProject::with_language(Language::Go)
            .file(
                "main.go",
                r#"package main

func shifted(dynamic int) int {
    values := make([]int, 4)
    start := 1
    exact := values[start:dynamic]
    open := values[dynamic:]
    exact[0] = 7
    open[0] = 8
    return values[1]
}
"#,
            )
            .build();
        let file = project.file("main.go");
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut budget = crate::analyzer::semantic::SemanticBudget::default();
        let artifact = analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("Go semantic materialization runs")
            .available_value()
            .cloned()
            .expect("Go semantic artifact is available");
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("shifted")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("shifted procedure");
        let facts = procedure_value_facts(&procedure, &HashMap::new(), &cancellation, |_| Ok(()))
            .expect("unbudgeted local origin derivation completes");
        let exact_integer = |value| {
            exact_unsigned_integer_origin(procedure.semantics(), &facts.load_origins, value)
        };
        let offset_values = facts
            .load_origins
            .values()
            .filter_map(|origin| match origin {
                LoadOrigin::BackingStore {
                    offset: BackingStoreOffset::Value(value),
                    ..
                } => Some(*value),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(offset_values.len(), 2, "{:#?}", procedure.semantics());
        let mut refined_offsets = offset_values
            .into_iter()
            .map(exact_integer)
            .collect::<Vec<_>>();
        refined_offsets.sort_unstable();
        assert_eq!(refined_offsets, [None, Some(1)]);

        let mut translated = Vec::new();
        let mut open = Vec::new();
        for location in procedure.semantics().memory_locations() {
            let resolution = resolve_access_path(
                location.id,
                &facts.load_origins,
                8,
                &cancellation,
                |id| {
                    procedure
                        .semantics()
                        .memory_location(id)
                        .map(|row| &row.kind)
                },
                exact_integer,
                |_| Ok(()),
            )
            .expect("access-path resolution runs");
            let AccessPathResolution::Resolved(draft) = resolution else {
                panic!("unbudgeted access-path resolution completes")
            };
            let [
                AccessSelectorDraft::Index {
                    constant: Some(index),
                    ..
                },
            ] = draft.selectors.as_slice()
            else {
                continue;
            };
            if draft.tail == AccessPathTail::Exact {
                translated.push(*index);
            } else {
                open.push(*index);
            }
        }
        translated.sort_unstable();
        assert_eq!(translated, [1, 1], "{:#?}", procedure.semantics());
        assert_eq!(
            open,
            [0],
            "an unknown start preserves the backing root but leaves index overlap open: {:#?}",
            procedure.semantics()
        );
    }

    #[test]
    fn cyclic_load_origins_terminate_with_summary() {
        let first_base = ValueId::new(0);
        let second_base = ValueId::new(1);
        let first_location = MemoryLocationId::new(0);
        let second_location = MemoryLocationId::new(1);
        let locations = [
            MemoryLocationKind::Index {
                base: first_base,
                index: None,
                constant_index: None,
                identity: crate::analyzer::semantic::IndexedLocationIdentity::Element,
            },
            MemoryLocationKind::Index {
                base: second_base,
                index: None,
                constant_index: None,
                identity: crate::analyzer::semantic::IndexedLocationIdentity::Element,
            },
        ];
        let load_origins = HashMap::from([
            (first_base, LoadOrigin::Unique(second_location)),
            (second_base, LoadOrigin::Unique(first_location)),
        ]);

        let draft = resolve_access_path(
            first_location,
            &load_origins,
            8,
            &crate::CancellationToken::default(),
            |id| locations.get(id.index()),
            |_| None,
            |_| Ok(()),
        )
        .unwrap();
        let AccessPathResolution::Resolved(draft) = draft else {
            panic!("unbudgeted access-path resolution must complete")
        };

        assert!(matches!(draft.root, AccessPathRootDraft::Value(value) if value == second_base));
        assert_eq!(draft.selectors.len(), 2);
        assert_eq!(draft.tail, AccessPathTail::Summary);
    }

    #[test]
    fn nested_access_path_stops_at_the_memory_location_budget() {
        let first_base = ValueId::new(0);
        let second_base = ValueId::new(1);
        let first_location = MemoryLocationId::new(0);
        let second_location = MemoryLocationId::new(1);
        let locations = [
            MemoryLocationKind::Index {
                base: first_base,
                index: None,
                constant_index: None,
                identity: crate::analyzer::semantic::IndexedLocationIdentity::Element,
            },
            MemoryLocationKind::Index {
                base: second_base,
                index: None,
                constant_index: None,
                identity: crate::analyzer::semantic::IndexedLocationIdentity::Element,
            },
        ];
        let load_origins = HashMap::from([(first_base, LoadOrigin::Unique(second_location))]);
        let mut limits = SemanticWork::default_limits();
        limits.memory_locations = 1;
        let mut budget = crate::analyzer::semantic::SemanticBudget::new(limits).unwrap();

        let resolution = resolve_access_path(
            first_location,
            &load_origins,
            8,
            &crate::CancellationToken::default(),
            |id| locations.get(id.index()),
            |_| None,
            |work| budget.charge(work).map_err(Interruption::Budget),
        )
        .unwrap();

        let AccessPathResolution::Interrupted(Interruption::Budget(exceeded)) = resolution else {
            panic!("the second location must exceed the one-location budget")
        };
        assert_eq!(exceeded.dimension().label(), "memory_locations");
        assert_eq!(exceeded.limit(), 1);
        assert_eq!(exceeded.attempted(), 2);
        assert_eq!(budget.used().memory_locations, 1);
    }
}
