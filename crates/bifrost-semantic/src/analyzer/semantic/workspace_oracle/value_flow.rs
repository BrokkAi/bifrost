//! Bounded value-flow and candidate-specific call-binding materialization.
//!
//! The implementation projects validated semantic IR rows into neutral oracle
//! relations. Java argument conversions delegate to the shared resolver-owned
//! producer through `conversions.rs`; no type interpretation lives here.
//! The remaining projection never reparses source or matches declarations by text,
//! except for one narrow, explicitly named discharge predicate
//! ([`super::external_constant_field_read_discharges_gap`], #2538) composed
//! into the two gap sweeps below: it delegates to `dispatch.rs`'s own
//! source-and-text machinery (already used there to resolve an
//! unmaterialized external *call* target) to prove a specific `FieldMemory`
//! gap is a `static final` read on an external type. Every other relevance
//! and discharge decision in this file stays IR-only. Saved Python defaults
//! additionally consult the provider's captured workspace metadata authority;
//! this file does not scan their source again.
//!
//! The relation pass, [`project_procedure_relations`], takes every answer that
//! does not come from the procedure's own IR from a [`RelationProjectionHost`],
//! so it can run against the workspace at query time or against one file at
//! parse time.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

/// Which globally unique value writer a caller is allowed to follow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum ClosedOriginEdge {
    Follow,
    Refuse,
}

/// Trace one value through a globally closed chain of paired assignments and
/// flows. The classifier decides the meaning of a flow; the scan, quality,
/// writer, cycle and stop rules are shared by all clients.
#[doc(hidden)]
pub fn closed_value_origin(
    procedure: &crate::analyzer::semantic::ProcedureHandle,
    start: crate::analyzer::semantic::ValueId,
    terminal: impl Fn(crate::analyzer::semantic::ValueId) -> bool,
    classify: impl Fn(&crate::analyzer::semantic::ValueFlowKind) -> ClosedOriginEdge,
    cancellation: &brokk_bifrost_core::CancellationToken,
    charge: impl FnMut(crate::analyzer::semantic::SemanticWork) -> Result<(), Interruption>,
) -> Result<Option<crate::analyzer::semantic::ValueId>, Interruption> {
    closed_value_origin_at_capture(
        procedure,
        start,
        terminal,
        |kind, _, _| classify(kind),
        |_, _| true,
        cancellation,
        charge,
    )
}

/// The same closed-origin proof restricted to write events reaching a capture.
#[doc(hidden)]
pub fn closed_value_origin_at_capture(
    procedure: &crate::analyzer::semantic::ProcedureHandle,
    start: crate::analyzer::semantic::ValueId,
    terminal: impl Fn(crate::analyzer::semantic::ValueId) -> bool,
    classify: impl Fn(
        &crate::analyzer::semantic::ValueFlowKind,
        crate::analyzer::semantic::ValueId,
        crate::analyzer::semantic::ValueId,
    ) -> ClosedOriginEdge,
    include_write: impl Fn(crate::analyzer::semantic::ProgramPointId, usize) -> bool,
    cancellation: &brokk_bifrost_core::CancellationToken,
    mut charge: impl FnMut(crate::analyzer::semantic::SemanticWork) -> Result<(), Interruption>,
) -> Result<Option<crate::analyzer::semantic::ValueId>, Interruption> {
    use crate::analyzer::semantic::{
        SemanticEffect, SemanticGapImpact, SemanticGapSubject, SemanticIncompleteSubject,
        SemanticWork,
    };
    let semantics = procedure.semantics();
    let event_count = semantics
        .points()
        .iter()
        .map(|point| point.events.len())
        .sum();
    let census = SemanticWork {
        events: semantics.incomplete_facts().len() + semantics.gaps().len(),
        ..Default::default()
    };
    charge(census)?;
    let mut current = start;
    let mut seen = HashSet::new();
    loop {
        if cancellation.is_cancelled() {
            return Err(Interruption::Cancelled);
        }
        if !seen.insert(current) {
            return Ok(None);
        }
        if semantics.incomplete_facts().iter().any(|fact| {
            matches!(fact.subject, SemanticIncompleteSubject::Procedure)
                || matches!(fact.subject, SemanticIncompleteSubject::Value(value) if value == current)
        }) || semantics.gaps().iter().any(|gap| {
            (gap.impacts.contains(SemanticGapImpact::ValueFlow)
                || gap.impacts.contains(SemanticGapImpact::ReturnTransfer)
                || gap.impacts.contains(SemanticGapImpact::CallEvaluation))
                && (matches!(gap.subject, SemanticGapSubject::Procedure | SemanticGapSubject::Point)
                    || matches!(gap.subject, SemanticGapSubject::Value(value) if value == current))
        }) {
            return Ok(None);
        }
        let scan = SemanticWork {
            events: event_count,
            ..Default::default()
        };
        charge(scan)?;
        let mut source = None;
        let mut writers = 0;
        for point in semantics.points() {
            if cancellation.is_cancelled() {
                return Err(Interruption::Cancelled);
            }
            for (index, event) in point.events.iter().enumerate() {
                if !include_write(point.id, index) {
                    continue;
                }
                let complete = semantics
                    .evidence_row(event.evidence)
                    .is_some_and(|evidence| {
                        evidence
                            .proof
                            .establishes_complete_evidence(&evidence.completeness)
                    });
                match &event.effect {
                    SemanticEffect::Assignment { target, value } if *target == current => {
                        let paired = point.events.get(index + 1).is_some_and(|next| {
                            matches!(&next.effect, SemanticEffect::ValueFlow { kind, source, target }
                                if *source == *value && *target == current
                                    && classify(kind, *source, *target) == ClosedOriginEdge::Follow)
                        });
                        if !complete || !paired {
                            return Ok(None);
                        }
                    }
                    SemanticEffect::ValueFlow {
                        kind,
                        source: value,
                        target,
                    } if *target == current => {
                        if !complete || classify(kind, *value, *target) != ClosedOriginEdge::Follow
                        {
                            return Ok(None);
                        }
                        writers += 1;
                        source = Some(*value);
                    }
                    SemanticEffect::MemoryLoad { result, .. } if *result == current => {
                        return Ok(None);
                    }
                    _ => {}
                }
            }
        }
        if terminal(current) {
            return Ok((writers == 0).then_some(current));
        }
        if writers != 1 {
            return Ok(None);
        }
        current = source.expect("one accepted flow has one source");
    }
}

use crate::analyzer::semantic::AsyncResumeKind;

use crate::analyzer::semantic::workspace_oracle::common::Interruption;

use crate::analyzer::semantic::workspace_oracle::common::WorkStager;

use crate::analyzer::semantic::workspace_oracle::common::evidence_handle;

use crate::analyzer::semantic::workspace_oracle::common::evidence_quality;

use crate::analyzer::semantic::workspace_oracle::common::internal_contract;

use crate::analyzer::semantic::workspace_oracle::common::value_flow_core_capabilities_are_open;

use crate::analyzer::semantic::workspace_oracle::common::value_handle;

use crate::analyzer::semantic::workspace_oracle::RuntimeKeyedReadResult;

use crate::analyzer::semantic::cfg_algorithms::CfgAlgorithmBudget;

use crate::analyzer::semantic::cfg_algorithms::CfgAlgorithmError;

use crate::analyzer::semantic::cfg_algorithms::CfgAlgorithmRequest;

use crate::analyzer::semantic::oracle::keyed_property_reads_container_element;

use crate::analyzer::semantic::AbstractLocation;

use crate::analyzer::semantic::AbstractObject;

use crate::analyzer::semantic::AbstractObjectIdentity;

use crate::analyzer::semantic::AccessPath;

use crate::analyzer::semantic::AccessPathRoot;

use crate::analyzer::semantic::AccessPathTail;

use crate::analyzer::semantic::AccessSelector;

use crate::analyzer::semantic::AllocationHandle;

use crate::analyzer::semantic::BackingStoreOffset;

use crate::analyzer::semantic::BindingOriginIndex;

use crate::analyzer::semantic::CallArgumentGroup;

use crate::analyzer::semantic::CallArgumentMapping;

use crate::analyzer::semantic::CallBinding;

use crate::analyzer::semantic::CallBindings;

use crate::analyzer::semantic::CallContinuationKind;

use crate::analyzer::semantic::CallSiteId;

use crate::analyzer::semantic::CandidateCoverage;

use crate::analyzer::semantic::CaptureBinding;

use crate::analyzer::semantic::CaptureSource;

use crate::analyzer::semantic::ControlEdgeKind;

use crate::analyzer::semantic::DeclarationSegmentKind;

use crate::analyzer::semantic::DispatchCandidate;

use crate::analyzer::semantic::EvidenceCompleteness;

use crate::analyzer::semantic::EvidenceHandle;

use crate::analyzer::semantic::ImplicitArgumentKind;

use crate::analyzer::semantic::IndexSelector;

use crate::analyzer::semantic::MemoryLocationId;

use crate::analyzer::semantic::MemoryLocationKind;

use crate::analyzer::semantic::MemoryRelationOrigin;

use crate::analyzer::semantic::MemoryRelationRole;

use crate::analyzer::semantic::MemoryValueCopy;

use crate::analyzer::semantic::ObjectCardinality;

use crate::analyzer::semantic::OracleCallContext;

use crate::analyzer::semantic::OracleCandidate;

use crate::analyzer::semantic::OracleLimits;

use crate::analyzer::semantic::OracleRelationArena;

use crate::analyzer::semantic::OracleRelationHandle;

use crate::analyzer::semantic::OracleRelationId;

use crate::analyzer::semantic::OracleRelationKind;

use crate::analyzer::semantic::OracleRelationOwner;

use crate::analyzer::semantic::OracleRelationRecord;

use crate::analyzer::semantic::ProcedureHandle;

use crate::analyzer::semantic::ProcedureKind;

use crate::analyzer::semantic::ProcedurePortHandle;

use crate::analyzer::semantic::ProcedurePortKind;

use crate::analyzer::semantic::ProgramPointHandle;

use crate::analyzer::semantic::ProgramPointId;

use crate::analyzer::semantic::ProofStatus;

use crate::analyzer::semantic::ScopedSemanticLocator;

use crate::analyzer::semantic::SemanticCapability;

use crate::analyzer::semantic::SemanticEffect;

use crate::analyzer::semantic::SemanticGapDischarge;

use crate::analyzer::semantic::SemanticGapId;

use crate::analyzer::semantic::SemanticGapImpact;

use crate::analyzer::semantic::SemanticGapKind;

use crate::analyzer::semantic::SemanticGapSubject;

use crate::analyzer::semantic::SemanticLocator;

use crate::analyzer::semantic::SemanticOutcome;

use crate::analyzer::semantic::SemanticProviderError;

use crate::analyzer::semantic::SemanticRequest;

use crate::analyzer::semantic::SemanticValueKind;

use crate::analyzer::semantic::SemanticWork;

use crate::analyzer::semantic::SynchronizationPayload;

use crate::analyzer::semantic::ValueTransfer;

use crate::analyzer::semantic::ValueFlowEndpoint;

use crate::analyzer::semantic::ValueFlowKind;

use crate::analyzer::semantic::ValueFlowRelation;

use crate::analyzer::semantic::ValueFlowRelationKind;

use crate::analyzer::semantic::ValueFlowRelationPayload;
use crate::analyzer::semantic::oracle::value_flow::CollapseRead;

use crate::analyzer::semantic::ValueFlowSnapshot;

use crate::analyzer::semantic::ValueHandle;

use crate::analyzer::semantic::ValueId;

use crate::analyzer::semantic::assignment_transfer;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum GapOutcomeQuality {
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
#[doc(hidden)]
pub fn merge_relation_quality(
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

#[doc(hidden)]
pub fn merge_gap_quality(
    current: Option<GapOutcomeQuality>,
    gap: &crate::analyzer::semantic::SemanticGap,
) -> Option<GapOutcomeQuality> {
    use crate::analyzer::semantic::workspace_oracle::value_flow::GapOutcomeQuality::Ambiguous;

    use crate::analyzer::semantic::workspace_oracle::value_flow::GapOutcomeQuality::Unknown;

    use crate::analyzer::semantic::workspace_oracle::value_flow::GapOutcomeQuality::Unproven;

    use crate::analyzer::semantic::workspace_oracle::value_flow::GapOutcomeQuality::Unsupported;
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

mod closed_containers;

#[derive(Clone)]
struct FlowRelationDraft {
    original_cell: Option<AbstractLocation>,
    payload: ValueFlowRelationPayload,
    memory_origin: Option<MemoryRelationOrigin>,
    evidence: Vec<EvidenceHandle>,
}

/// A direct lexical store replaces one activation-local slot even when a
/// later closure captures it. Do not use a heap non-escape certificate for
/// this fact. Refuse after any operation that could have published the cell
/// or launched a mutator, and propagate that refusal through CFG cycles.
/// All state here belongs to this one procedure-relations query.
fn local_cell_overwrite_points(
    procedure: &ProcedureHandle,
    staged: &mut WorkStager,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
) -> Result<HashSet<ProgramPointId>, Interruption> {
    let semantics = procedure.semantics();
    let mut unsafe_points = HashSet::new();
    let mut successors: HashMap<ProgramPointId, Vec<ProgramPointId>> = HashMap::new();
    let mut pending = VecDeque::new();
    for gap in semantics.gaps() {
        staged.charge_work(SemanticWork {
            gaps: 1,
            ..SemanticWork::default()
        });
        // Missing control edges could bypass the hazard propagation itself.
        if matches!(
            gap.capability,
            SemanticCapability::NormalControlFlow
                | SemanticCapability::ExceptionalControlFlow
                | SemanticCapability::CleanupControlFlow
                | SemanticCapability::NonLocalControl
        ) {
            return Ok(HashSet::new());
        }
        if gap.capability != SemanticCapability::Captures && unsafe_points.insert(gap.point) {
            pending.push_back(gap.point);
        }
    }
    for point in semantics.points() {
        staged.charge_work(SemanticWork {
            program_points: 1,
            events: point.events.len(),
            ..SemanticWork::default()
        });
        if cancellation.is_cancelled() {
            return Err(Interruption::Cancelled);
        }
        let unsafe_effect = point.events.iter().any(|event| match event.effect {
            SemanticEffect::Invoke { .. }
            | SemanticEffect::CallContinuation { .. }
            | SemanticEffect::AsyncSuspend { .. }
            | SemanticEffect::AsyncResume { .. }
            | SemanticEffect::Synchronization { .. }
            | SemanticEffect::ProcedureReturn { .. }
            | SemanticEffect::Throw { .. } => true,
            SemanticEffect::MemoryStore { location, .. } => semantics
                .memory_location(location)
                .is_none_or(|row| !matches!(row.kind, MemoryLocationKind::LexicalCell { .. })),
            SemanticEffect::Gap { gap } => semantics
                .gaps()
                .get(gap.index())
                .is_none_or(|gap| gap.capability != SemanticCapability::Captures),
            _ => false,
        });
        if unsafe_effect && unsafe_points.insert(point.id) {
            pending.push_back(point.id);
        }
    }
    for edge in semantics.control_edges() {
        staged.charge_work(SemanticWork {
            control_edges: 1,
            nested_entries: 1,
            ..SemanticWork::default()
        });
        successors
            .entry(edge.source_point)
            .or_default()
            .push(edge.target_point);
    }
    while let Some(point) = pending.pop_front() {
        if cancellation.is_cancelled() {
            return Err(Interruption::Cancelled);
        }
        for next in successors.get(&point).into_iter().flatten() {
            staged.charge_work(SemanticWork {
                nested_entries: 1,
                ..SemanticWork::default()
            });
            if unsafe_points.insert(*next) {
                pending.push_back(*next);
            }
        }
    }
    Ok(semantics
        .points()
        .iter()
        .filter_map(|point| (!unsafe_points.contains(&point.id)).then_some(point.id))
        .collect())
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
#[doc(hidden)]
pub struct LocalStoreBases {
    /// Copy producers, as (target, source) pairs in target order.
    copies: Box<[(ValueId, ValueId)]>,
    /// Copy consumers, as (source, target) pairs in source order.
    forward_copies: Box<[(ValueId, ValueId)]>,
    /// Exact backing-store aliases, as (source, target) pairs in source order.
    backing_aliases: Box<[(ValueId, ValueId)]>,
    allocation_results: HashSet<ValueId>,
    object_allocation_results: HashSet<ValueId>,
    aggregate_copy_bindings: HashSet<ValueId>,
    array_allocation_results: HashSet<ValueId>,
    slice_allocation_results: HashSet<ValueId>,
    /// Values that own a language binding rather than naming one temporary
    /// occurrence of that binding.
    binding_values: HashSet<ValueId>,
    /// Parameter and receiver formals.
    formal_values: HashSet<ValueId>,
    /// Parameter and receiver flows, as (target, source) pairs in target
    /// order: reads of a formal and, in some adapters, writes back to it.
    formal_flows: Box<[(ValueId, ValueId)]>,
    /// Values a call or a memory load produces, which the trace would follow
    /// out of this procedure or open.
    foreign: HashSet<ValueId>,
    /// Values whose address escapes into an explicit address value or whose
    /// binding is captured by a nested procedure. Either shape lets code
    /// outside the local copy graph observe or mutate an array allocation.
    escaped: HashSet<ValueId>,
}

/// The sources of the (target, source) `edges`, sorted by target, that
/// produce `value`.
fn producers(
    edges: &[(ValueId, ValueId)],
    value: ValueId,
) -> impl Iterator<Item = &(ValueId, ValueId)> {
    let start = edges.partition_point(|(target, _)| *target < value);
    edges[start..]
        .iter()
        .take_while(move |(target, _)| *target == value)
}

impl LocalStoreBases {
    fn derive(semantics: &crate::analyzer::semantic::ProcedureSemantics) -> Self {
        let mut copies = Vec::new();
        let mut formal_flows = Vec::new();
        let mut backing_aliases = Vec::new();
        let mut foreign = HashSet::new();
        let mut escaped = HashSet::new();
        let mut aggregate_copy_bindings = HashSet::new();
        for point in semantics.points() {
            for (event_index, event) in point.events.iter().enumerate() {
                let copied_target = match event.effect {
                    SemanticEffect::Assignment { target, value }
                        if assignment_transfer(&point.events, event_index, value, target)
                            .is_some_and(|transfer| {
                                transfer.kind
                                    == crate::analyzer::semantic::TransferKind::AggregateCopy
                            }) =>
                    {
                        Some(target)
                    }
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Transfer(transfer),
                        target,
                        ..
                    } if transfer.kind
                        == crate::analyzer::semantic::TransferKind::AggregateCopy =>
                    {
                        Some(target)
                    }
                    _ => None,
                };
                if let Some(target) = copied_target
                    && semantics
                        .value(target)
                        .is_some_and(|row| row.kind == SemanticValueKind::Local)
                {
                    aggregate_copy_bindings.insert(target);
                }
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
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Parameter | ValueFlowKind::Receiver,
                        source,
                        target,
                    } => formal_flows.push((target, source)),
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
        let object_allocation_results = semantics
            .allocations()
            .iter()
            .filter_map(|allocation| {
                (allocation.kind == crate::analyzer::semantic::AllocationKind::Object)
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
        formal_flows.sort_unstable();
        formal_flows.dedup();
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
        let formal_values = semantics
            .values()
            .iter()
            .filter_map(|value| {
                matches!(
                    value.kind,
                    SemanticValueKind::Parameter { .. } | SemanticValueKind::Receiver { .. }
                )
                .then_some(value.id)
            })
            .collect();
        Self {
            copies: copies.into_boxed_slice(),
            forward_copies: forward_copies.into_boxed_slice(),
            backing_aliases: backing_aliases.into_boxed_slice(),
            allocation_results,
            object_allocation_results,
            aggregate_copy_bindings,
            array_allocation_results,
            slice_allocation_results,
            binding_values,
            formal_values,
            formal_flows: formal_flows.into_boxed_slice(),
            foreign,
            escaped,
        }
    }

    /// Whether every backward producer chain from `base` ends at an allocation
    /// of this procedure.
    #[doc(hidden)]
    pub fn is_locally_allocated(&self, base: ValueId) -> bool {
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
    #[doc(hidden)]
    pub fn canonical_base_has_no_secondary_binding_owner(&self, base: ValueId) -> bool {
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

    /// Whether the store at `point` to `location` overwrites one exact member
    /// of the object a formal names (#9651).
    ///
    /// Every backward producer chain from the store's base must end at the
    /// same parameter or receiver formal, and the procedure must never rebind
    /// that formal or let its binding escape by address or capture. The base
    /// then names one object for the whole invocation, whatever the caller
    /// passed, so the formal-relative carrier stands for exactly the location
    /// the store writes. The heap oracle cannot certify this: the object
    /// comes from the caller, which binds its own actual at the call. A store
    /// whose point records unresolved dispatch or field memory (an accessor,
    /// an overloaded assignment, a `DerefMut` projection) stays weak.
    #[doc(hidden)]
    pub fn holds_formal_member_overwrite(
        &self,
        procedure: &ProcedureHandle,
        point: ProgramPointId,
        location: MemoryLocationId,
    ) -> bool {
        let Some(MemoryLocationKind::Field { base, .. }) = procedure
            .semantics()
            .memory_location(location)
            .map(|row| &row.kind)
        else {
            return false;
        };
        if procedure.semantics().gaps().iter().any(|gap| {
            gap.point == point
                && matches!(
                    gap.capability,
                    SemanticCapability::Calls | SemanticCapability::FieldMemory
                )
        }) {
            return false;
        }
        let mut pending = vec![*base];
        let mut seen = HashSet::new();
        let mut roots = HashSet::new();
        while let Some(value) = pending.pop() {
            if !seen.insert(value) {
                continue;
            }
            if self.foreign.contains(&value)
                || self.escaped.contains(&value)
                || self.allocation_results.contains(&value)
            {
                return false;
            }
            let mut sources = producers(&self.copies, value)
                .chain(producers(&self.formal_flows, value))
                .peekable();
            if self.formal_values.contains(&value) {
                // A flow into the formal rebinds it.
                if sources.peek().is_some() {
                    return false;
                }
                roots.insert(value);
                continue;
            }
            if sources.peek().is_none() {
                return false;
            }
            pending.extend(sources.map(|(_, source)| *source));
        }
        roots.len() == 1
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
    #[doc(hidden)]
    pub fn is_closed_local_array(&self, base: ValueId) -> bool {
        self.is_closed_local_allocation(base, &self.array_allocation_results)
    }

    /// A fresh object that remains in one local binding and has no address or
    /// capture escape. Languages with value aggregate semantics can strongly
    /// replace one exact field of this object without a workspace heap read.
    #[doc(hidden)]
    pub fn is_closed_local_object(&self, base: ValueId) -> bool {
        self.is_closed_local_allocation(base, &self.object_allocation_results)
    }

    /// An aggregate-copy transfer gives a local binding its own member
    /// storage. It remains private only while no address or capture of that
    /// binding (or an identity-preserving local copy) escapes.
    #[doc(hidden)]
    pub fn is_closed_local_aggregate_copy_binding(&self, base: ValueId) -> bool {
        let mut sources = vec![base];
        let mut visited = HashSet::new();
        let mut roots = HashSet::new();
        while let Some(value) = sources.pop() {
            if !visited.insert(value) || self.foreign.contains(&value) {
                return false;
            }
            if self.aggregate_copy_bindings.contains(&value) {
                roots.insert(value);
                continue;
            }
            if self.binding_values.contains(&value) {
                return false;
            }
            let start = self.copies.partition_point(|(target, _)| *target < value);
            let copied = self.copies[start..]
                .iter()
                .take_while(|(target, _)| *target == value);
            let mut any = false;
            for (_, source) in copied {
                any = true;
                sources.push(*source);
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

    fn is_closed_local_allocation(&self, base: ValueId, allowed: &HashSet<ValueId>) -> bool {
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
                if !allowed.contains(&value) {
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

/// The value a call's exceptional continuation receives from its callee, when
/// the call names one (#8804).
fn exceptional_continuation_thrown(
    procedure: &ProcedureHandle,
    call_site: CallSiteId,
) -> Option<ValueId> {
    procedure
        .semantics()
        .call_site(call_site)
        .expect("a validated call continuation names a live call site")
        .thrown
}

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
    /// Handler binding -> the thrown value the runtime copies into it. A
    /// binding more than one throw reaches is one of their values, which is
    /// [`LoadOrigin::Definitions`].
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
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
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
                            merge_load_origin(existing, LoadOrigin::Value(thrown))
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
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
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
/// A callable selected solely for its exact invocation does not publish its
/// bound receiver at selection time. Assignment, capture, storage, argument
/// passing, or any other use retains the ordinary capture publication.
#[doc(hidden)]
pub fn callable_selection_is_non_escaping(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    point: ProgramPointId,
    index: usize,
) -> bool {
    let Some(event) = semantics
        .point(point)
        .and_then(|point| point.events.get(index))
    else {
        return false;
    };
    let SemanticEffect::CallableReference { result, .. } = event.effect else {
        return false;
    };
    let calls = semantics
        .call_sites()
        .iter()
        .filter(|call| call.callee == result)
        .collect::<Vec<_>>();
    if calls.is_empty() {
        return false;
    }
    for call in &calls {
        if call.receiver == Some(result)
            || call
                .arguments
                .iter()
                .any(|argument| argument.value == result)
        {
            return false;
        }
        let Some(evidence) = semantics.evidence_row(call.evidence) else {
            return false;
        };
        if !evidence
            .proof
            .establishes_complete_evidence(&evidence.completeness)
            || !semantics
                .callable_selection_events(call.id)
                .iter()
                .any(|(selected, ordinal, _)| *selected == point && *ordinal == index)
        {
            return false;
        }
    }
    let names = HashSet::from_iter([result]);
    for candidate in semantics.points() {
        for event in &candidate.events {
            match &event.effect {
                SemanticEffect::CallableReference { result: target, .. }
                    if *target == result && candidate.id == point =>
                {
                    let Some(evidence) = semantics.evidence_row(event.evidence) else {
                        return false;
                    };
                    if !evidence
                        .proof
                        .establishes_complete_evidence(&evidence.completeness)
                    {
                        return false;
                    }
                }
                SemanticEffect::Invoke { call_site }
                | SemanticEffect::CallContinuation { call_site, .. }
                    if calls.iter().any(|call| call.id == *call_site) => {}
                effect if super::heap::effect_names_any(semantics, effect, &names) => return false,
                _ => {}
            }
        }
    }
    true
}

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
                    SemanticEffect::AggregateInitializer {
                        aggregate, value, ..
                    } => vec![*aggregate, *value],
                    SemanticEffect::ValueFlow { source, .. } => vec![*source],
                    SemanticEffect::ValueUse { value, .. } => vec![*value],
                    SemanticEffect::MemoryStore { value, .. } => vec![*value],
                    SemanticEffect::Synchronization {
                        subject, payload, ..
                    } => {
                        let mut values = vec![*subject];
                        if let Some(SynchronizationPayload::Send { value, .. }) = payload {
                            values.push(*value);
                        }
                        values
                    }
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
    if value_flow_core_capabilities_are_open(procedure) {
        return true;
    }
    let location_capability = |kind: &MemoryLocationKind| match kind {
        MemoryLocationKind::Field { .. } | MemoryLocationKind::Property { .. } => {
            SemanticCapability::FieldMemory
        }
        MemoryLocationKind::Static { .. } => SemanticCapability::StaticMemory,
        MemoryLocationKind::Index { .. } => SemanticCapability::IndexMemory,
        MemoryLocationKind::Dereference { .. } => SemanticCapability::FieldMemory,
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

/// How one gap of a procedure bears on the procedure's openness, decided from
/// the procedure's semantics alone (#1952). The plan and the
/// composition add their own checks to the gaps they do not discharge here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GapOpenness {
    /// The gap cannot change value flow.
    Irrelevant,
    /// A proof in the procedure's semantics discharges the gap.
    Discharged,
    /// A complete dispatch of this call answers the gap.
    RefinementCall(CallSiteId),
    /// Nothing in the procedure's semantics answers the gap.
    Blocked,
}

/// Classifies one gap of a procedure with no plan state. The ICFG plan and
/// the composition's openness both call it, so both apply the same rule to
/// the same gap.
pub fn classify_gap_openness(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    gap: &crate::analyzer::semantic::SemanticGap,
    abort_user_code: bool,
) -> GapOpenness {
    if !gap_impacts_value_flow(gap) {
        return GapOpenness::Irrelevant;
    }
    if implicit_abort_gap_is_discharged(gap, abort_user_code)
        || constructor_call_gap_is_discharged(semantics, gap)
    {
        return GapOpenness::Discharged;
    }
    match call_target_refinement_call(semantics, gap) {
        Some(call) => GapOpenness::RefinementCall(call),
        None => GapOpenness::Blocked,
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
#[doc(hidden)]
pub fn constructor_allocation_identity_discharges_gap(
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

/// An isolated heap partition cannot affect value flow when its local result
/// and every identity-preserving alias are never read or published. This covers
/// missing prior-element reads and missing writes into a fresh collection;
/// returning, capturing, loading, or passing that collection remains open.
fn unobserved_local_heap_gap_is_discharged(
    procedure: &ProcedureHandle,
    gap: &crate::analyzer::semantic::SemanticGap,
) -> bool {
    let read = crate::analyzer::semantic::SemanticGapImpacts::single(SemanticGapImpact::HeapRead);
    let write = crate::analyzer::semantic::SemanticGapImpacts::single(SemanticGapImpact::HeapWrite);
    if (gap.impacts != read && gap.impacts != write)
        || gap.discharge != SemanticGapDischarge::ModeledEffectPartition
    {
        return false;
    }
    let SemanticGapSubject::Value(subject) = gap.subject else {
        return false;
    };

    if gap.impacts == write
        && !procedure
            .semantics()
            .allocations()
            .iter()
            .any(|allocation| allocation.result == subject)
    {
        return false;
    }

    let mut aliases = HashSet::from([subject]);
    let mut changed = true;
    while changed {
        changed = false;
        for point in procedure.semantics().points() {
            for event in &point.events {
                let alias = match event.effect {
                    SemanticEffect::Assignment { target, value } => Some((value, target)),
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Local | ValueFlowKind::BackingStore { .. },
                        source,
                        target,
                    } => Some((source, target)),
                    _ => None,
                };
                if let Some((source, target)) = alias
                    && aliases.contains(&source)
                    && aliases.insert(target)
                {
                    changed = true;
                }
            }
        }
    }

    for point in procedure.semantics().points() {
        for event in &point.events {
            match &event.effect {
                SemanticEffect::MemoryLoad { location, .. } => {
                    if procedure
                        .semantics()
                        .memory_location(*location)
                        .is_some_and(|row| aliases.iter().any(|value| row.kind.uses_value(*value)))
                    {
                        return false;
                    }
                }
                SemanticEffect::MemoryStore { value, .. } if aliases.contains(value) => {
                    return false;
                }
                SemanticEffect::CaptureBind { capture } => {
                    let Some(row) = procedure.semantics().capture(*capture) else {
                        return false;
                    };
                    let publishes = match row.captured {
                        CaptureSource::Value(value) => aliases.contains(&value),
                        CaptureSource::Location(location) => procedure
                            .semantics()
                            .memory_location(location)
                            .is_some_and(|row| {
                                aliases.iter().any(|value| row.kind.uses_value(*value))
                            }),
                    };
                    if publishes {
                        return false;
                    }
                }
                SemanticEffect::Invoke { call_site } => {
                    let Some(call) = procedure.semantics().call_site(*call_site) else {
                        return false;
                    };
                    if aliases.contains(&call.callee)
                        || call.receiver.is_some_and(|value| aliases.contains(&value))
                        || call
                            .arguments
                            .iter()
                            .any(|argument| aliases.contains(&argument.value))
                    {
                        return false;
                    }
                }
                SemanticEffect::ProcedureReturn { value } | SemanticEffect::Throw { value }
                    if value.is_some_and(|value| aliases.contains(&value)) =>
                {
                    return false;
                }
                SemanticEffect::AsyncSuspend { awaited, .. }
                    if awaited.is_some_and(|value| aliases.contains(&value)) =>
                {
                    return false;
                }
                SemanticEffect::CallableCreation { callable, .. }
                | SemanticEffect::CallableReference { callable, .. }
                    if callable
                        .bound_receiver
                        .is_some_and(|value| aliases.contains(&value)) =>
                {
                    return false;
                }
                SemanticEffect::ValueFlow { kind, source, .. }
                    if aliases.contains(source)
                        && !matches!(
                            kind,
                            ValueFlowKind::Local | ValueFlowKind::BackingStore { .. }
                        ) =>
                {
                    return false;
                }
                _ => {}
            }
        }
    }
    true
}

/// Whether a local base is the exact result (or an identity-preserving local
/// alias) of an operation whose remaining semantics are a modeled read-only
/// partition. For Go today this identifies the fresh result of a proven
/// reallocating append without treating arbitrary secondary slice bindings as
/// canonical-index proofs.
#[doc(hidden)]
pub fn value_traces_to_modeled_read_partition(procedure: &ProcedureHandle, base: ValueId) -> bool {
    let partitioned = procedure
        .semantics()
        .gaps()
        .iter()
        .filter_map(|gap| {
            (gap.discharge == SemanticGapDischarge::ModeledEffectPartition
                && gap.impacts
                    == crate::analyzer::semantic::SemanticGapImpacts::single(
                        SemanticGapImpact::HeapRead,
                    ))
            .then_some(gap.subject)
        })
        .filter_map(|subject| match subject {
            SemanticGapSubject::Value(value) => Some(value),
            _ => None,
        })
        .collect::<HashSet<_>>();
    let mut pending = vec![base];
    let mut visited = HashSet::new();
    while let Some(current) = pending.pop() {
        if !visited.insert(current) {
            continue;
        }
        if partitioned.contains(&current) {
            return true;
        }
        for point in procedure.semantics().points() {
            for event in &point.events {
                match event.effect {
                    SemanticEffect::Assignment { target, value } if target == current => {
                        pending.push(value);
                    }
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Local | ValueFlowKind::BackingStore { .. },
                        source,
                        target,
                    } if target == current => pending.push(source),
                    _ => {}
                }
            }
        }
    }
    false
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
    semantics.memoized_abort_paths_run_user_code(|| {
        let cancellation = brokk_bifrost_core::cancellation::CancellationToken::default();
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
    })
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
#[doc(hidden)]
pub fn implicit_dispatch_receiver_actual<'caller>(
    caller: &'caller ProcedureHandle,
    callee: &ProcedureHandle,
    callee_receiver: &crate::analyzer::semantic::SemanticValue,
) -> Option<&'caller crate::analyzer::semantic::SemanticValue> {
    if !matches!(
        callee_receiver.kind,
        SemanticValueKind::Receiver { dispatch: true, .. }
    ) {
        return None;
    }
    let caller_receiver = caller.semantics().values().iter().find(|value| {
        matches!(
            value.kind,
            SemanticValueKind::Receiver { dispatch: true, .. }
        )
    })?;
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

#[doc(hidden)]
pub fn proven_complete(evidence: &[EvidenceHandle]) -> bool {
    let (proof, completeness) = evidence_quality(evidence);
    proof.establishes_complete_evidence(&completeness)
}

fn location_value_reads(location: &MemoryLocationKind) -> usize {
    match location {
        MemoryLocationKind::Field { .. }
        | MemoryLocationKind::Property { .. }
        | MemoryLocationKind::Dereference { .. }
        | MemoryLocationKind::LexicalCell { .. } => 1,
        MemoryLocationKind::Index { index: Some(_), .. } => 2,
        MemoryLocationKind::Index { index: None, .. }
        | MemoryLocationKind::Static { .. }
        | MemoryLocationKind::Capture { .. } => 0,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub enum LoadOrigin {
    Unique(MemoryLocationId),
    Value(ValueId),
    ProcedurePort(ProcedurePortKind),
    BackingStore {
        source: ValueId,
        offset: BackingStoreOffset,
    },
    BackingStoreAlternative {
        source: ValueId,
        offset: BackingStoreOffset,
        allocation: crate::analyzer::semantic::AllocationId,
    },
    /// An identity-separating transfer defined this value from `source`, and
    /// the producer stated the copied contents at the same point.
    ///
    /// The shared transfer contract states that every `TransferKind` gives the
    /// destination a distinct storage identity, so the walk stops here with the
    /// destination itself as an exact root. That is stronger than
    /// [`Self::Ambiguous`]: nothing about which definition applies is unknown,
    /// only the source identity is deliberately cut.
    ///
    /// Distinct storage identity is not by itself a statement about what that
    /// storage holds: `TransferKind::AggregateCopy` says the copied element
    /// contents are a separate, explicitly incomplete concern. A destination
    /// whose contents the producer did not state must therefore stay
    /// [`Self::Ambiguous`], or a member read of the copy would resolve against
    /// an exact root with no definition and be answered as a proven absence.
    /// The producer states those contents by storing into the destination's own
    /// member locations at the copy point, which is what this variant requires.
    Separated(SeparatedTransfer),
    /// Exhaustive separated definitions of one destination value.
    SeparatedDefinitions(Box<[SeparatedTransfer]>),
    /// A plain assignment awaits its immediately following separated transfer.
    /// If no such transfer arrives, finalization makes this ambiguous.
    SeparatedPending {
        transfers: Box<[SeparatedTransfer]>,
        source: ValueId,
    },
    /// More than one unconditional copy defines this value, each from a
    /// different source, in first-seen order and without repeats.
    ///
    /// The set is exhaustive: every definition the procedure states is in it,
    /// so the value is exactly one of them at any read. A member access
    /// through it is resolved once per definition as a finite alternative,
    /// rather than stopping on a summarized root as [`Self::Ambiguous`] does.
    /// A catch parameter that several throws reach is the motivating shape
    /// (#7960, #8836).
    Definitions(Box<[ValueId]>),
    Ambiguous,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct SeparatedTransfer {
    source: ValueId,
    destination: ValueId,
    point: ProgramPointId,
    transfer: ValueTransfer,
    stores: Box<[MemoryLocationId]>,
}

#[derive(Debug, Clone)]
#[doc(hidden)]
pub enum AccessPathRootDraft {
    Value(ValueId),
    ProcedurePort(ProcedurePortKind),
    Allocation(crate::analyzer::semantic::AllocationId),
    Static(SemanticLocator),
    LexicalCell(MemoryLocationId),
    Capture(MemoryLocationId),
}

#[derive(Debug, Clone)]
#[doc(hidden)]
pub enum AccessSelectorDraft {
    Field(SemanticLocator),
    Property(String),
    Index {
        value: Option<ValueId>,
        constant: Option<u128>,
        identity: crate::analyzer::semantic::IndexedLocationIdentity,
    },
}

#[derive(Debug)]
#[doc(hidden)]
pub struct AccessPathDraft {
    /// Source-named coordinate before a prefix redirect; never a flow arm.
    pub original_cell: Option<Box<AccessPathDraft>>,
    #[doc(hidden)]
    pub root: AccessPathRootDraft,
    #[doc(hidden)]
    pub selectors: Vec<AccessSelectorDraft>,
    #[doc(hidden)]
    pub tail: AccessPathTail,
    /// A store reaches a cell the path continues through and cannot be
    /// followed, so members stored there cannot be proven absent.
    #[doc(hidden)]
    pub opaque_prefix: bool,
}

#[derive(Debug)]
#[doc(hidden)]
pub enum AccessPathResolution {
    Resolved(AccessPathDraft),
    Interrupted(Interruption),
}

/// One selector of a cell, reduced to what decides whether two cells may be
/// one cell. Field and property selectors compare by identity; an index
/// compares by the constant it denotes, or may equal any index otherwise.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum CellSelector {
    Field(SemanticLocator),
    Property(String),
    Index(CellIndex),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum CellIndex {
    /// An index with a known integer value.
    Constant(u128),
    /// A constant index value that language lowering canonicalizes, so two
    /// accesses name the same index only when they share this value.
    Canonical(ValueId),
    /// An index value that may equal any other.
    Exact(ValueId),
    Any,
}

impl CellSelector {
    /// The selector with its index erased, so cells that may alias hash alike.
    fn erased(&self) -> Self {
        match self {
            Self::Index(_) => Self::Index(CellIndex::Any),
            other => other.clone(),
        }
    }

    fn may_equal(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Field(left), Self::Field(right)) => left == right,
            (Self::Property(left), Self::Property(right)) => left == right,
            (Self::Index(CellIndex::Constant(left)), Self::Index(CellIndex::Constant(right))) => {
                left == right
            }
            (Self::Index(CellIndex::Canonical(left)), Self::Index(CellIndex::Canonical(right))) => {
                left == right
            }
            (Self::Index(_), Self::Index(_)) => true,
            _ => false,
        }
    }
}

/// The root of a resolved access path, as far as two accesses of one
/// procedure can be compared.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum CellRoot {
    Value(ValueId),
    Port(ProcedurePortKind),
    Allocation(crate::analyzer::semantic::AllocationId),
    Static(SemanticLocator),
    LexicalCell(MemoryLocationId),
    Capture(MemoryLocationId),
}

impl CellRoot {
    fn of(root: &AccessPathRootDraft) -> Self {
        match root {
            AccessPathRootDraft::Value(value) => Self::Value(*value),
            AccessPathRootDraft::ProcedurePort(kind) => Self::Port(*kind),
            AccessPathRootDraft::Allocation(allocation) => Self::Allocation(*allocation),
            AccessPathRootDraft::Static(member) => Self::Static(member.clone()),
            AccessPathRootDraft::LexicalCell(cell) => Self::LexicalCell(*cell),
            AccessPathRootDraft::Capture(cell) => Self::Capture(*cell),
        }
    }
}

/// What a store put into one cell, as far as a read through the cell can
/// follow it.
#[derive(Debug)]
struct PrefixStore {
    /// The stored cell's path below its root, root-nearest selector first.
    selectors: Vec<CellSelector>,
    /// The stored value, or `None` when the store cannot be followed: it
    /// copied an inline aggregate, or its language states nothing about
    /// whether it copied.
    followed: Option<ValueId>,
}

/// One way a strict-prefix cell may have been written.
#[derive(Debug, Clone, Copy)]
struct PrefixCandidate {
    /// How many root-nearest selectors the prefix cell consumes.
    depth: usize,
    followed: Option<ValueId>,
}

/// The stores to the cells a longer access path may continue through.
///
/// A store of a reference puts the stored object's identity into a cell, so a
/// path that continues *through* that cell names storage the stored value
/// names. Carriers meet only on equal paths, so without this index the
/// continuation path never meets the stored value's own members and a read
/// through the cell looks like proven absence. Cells are keyed by their
/// resolved root and selectors, so every access of one procedure that names
/// the cell finds the same stores.
///
/// The index is flow-insensitive, like the other facts of a procedure: every
/// store to a cell that may be the prefix is a candidate. That is a may
/// answer: the original path is always an alternative because the index cannot
/// prove that any store ran before the read. An overwritten store only adds a flow.
#[derive(Debug, Default)]
#[doc(hidden)]
pub struct PrefixStores {
    /// An unenumerated store may reach any prefix in this procedure.
    incomplete: bool,
    cells: HashMap<(CellRoot, Vec<CellSelector>), Vec<PrefixStore>>,
    /// The index values of this procedure that are constants.
    constant_indexes: HashSet<ValueId>,
}

impl PrefixStores {
    fn cell_selector(
        &self,
        selector: &AccessSelectorDraft,
        exact_integer: impl Fn(ValueId) -> Option<u128>,
    ) -> CellSelector {
        match selector {
            AccessSelectorDraft::Field(member) => CellSelector::Field(member.clone()),
            AccessSelectorDraft::Property(key) => CellSelector::Property(key.clone()),
            // An aggregate location is the one cell holding every element, so
            // any index names it.
            AccessSelectorDraft::Index {
                identity: crate::analyzer::semantic::IndexedLocationIdentity::Aggregate,
                ..
            } => CellSelector::Index(CellIndex::Any),
            AccessSelectorDraft::Index {
                constant: Some(constant),
                ..
            } => CellSelector::Index(CellIndex::Constant(*constant)),
            AccessSelectorDraft::Index {
                value: Some(value), ..
            } => CellSelector::Index(match exact_integer(*value) {
                Some(constant) => CellIndex::Constant(constant),
                None if self.constant_indexes.contains(value) => CellIndex::Canonical(*value),
                None => CellIndex::Exact(*value),
            }),
            AccessSelectorDraft::Index { .. } => CellSelector::Index(CellIndex::Any),
        }
    }

    /// Every store to a strict prefix of the path `root` + `selectors`, where
    /// `selectors` runs from the leaf toward the root, shortest prefix first.
    fn candidates(
        &self,
        root: CellRoot,
        selectors: &VecDeque<AccessSelectorDraft>,
        exact_integer: impl Fn(ValueId) -> Option<u128>,
    ) -> Vec<PrefixCandidate> {
        if (self.cells.is_empty() && !self.incomplete) || selectors.len() < 2 {
            return Vec::new();
        }
        let path = selectors
            .iter()
            .rev()
            .map(|selector| self.cell_selector(selector, &exact_integer))
            .collect::<Vec<_>>();
        self.candidates_for_path(root, &path)
    }

    fn candidates_for_path(&self, root: CellRoot, path: &[CellSelector]) -> Vec<PrefixCandidate> {
        let mut candidates = Vec::new();
        if self.incomplete && path.len() >= 2 {
            candidates.push(PrefixCandidate {
                depth: 1,
                followed: None,
            });
        }
        for depth in 1..path.len() {
            let prefix = &path[..depth];
            let key = (
                root.clone(),
                prefix.iter().map(CellSelector::erased).collect(),
            );
            for store in self.cells.get(&key).into_iter().flatten() {
                if store
                    .selectors
                    .iter()
                    .zip(prefix)
                    .all(|(stored, read)| stored.may_equal(read))
                {
                    candidates.push(PrefixCandidate {
                        depth,
                        followed: store.followed,
                    });
                }
            }
        }
        candidates
    }
}

/// The per-procedure origin facts one access-path walk resolves against: where
/// each value came from, and which stores can reach a cell a path continues
/// through.
#[derive(Clone, Copy)]
#[doc(hidden)]
pub struct ValueOriginFacts<'facts> {
    #[doc(hidden)]
    pub load_origins: &'facts HashMap<ValueId, LoadOrigin>,
    #[doc(hidden)]
    pub prefix_stores: &'facts PrefixStores,
    #[doc(hidden)]
    pub binding_origins: Option<&'facts BindingOriginIndex>,
}

#[doc(hidden)]
pub struct ProcedureValueFacts {
    /// Where each value's defining copy or load came from, or `Ambiguous` when
    /// more than one event defines it differently.
    #[doc(hidden)]
    pub load_origins: HashMap<ValueId, LoadOrigin>,
    /// The stores to cells that a longer path may continue through. A store of
    /// a reference duplicates the reference, not the object it names, so a
    /// path that continues through the cell names the same storage the stored
    /// value names.
    #[doc(hidden)]
    pub prefix_stores: PrefixStores,
    /// Values some consumption reads as a whole object (#2444 slice 2): a call
    /// argument, a call receiver, a returned value, or a value stored as a
    /// whole. These are the reads a container collapse is published at, and
    /// deliberately not every read of a value -- see `ContainerRead`.
    whole_container_reads: HashSet<ValueId>,
}

#[doc(hidden)]
pub fn is_go_assignment_conversion(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    target: ValueId,
) -> bool {
    semantics
        .value(target)
        .is_some_and(|value| value.kind.is_language_defined("go.assignment_conversion"))
}

/// The destinations whose copied contents this point's own events state.
///
/// A by-value transfer separates storage identity; whether the copy's contents
/// are also modeled is a separate producer fact, and only the producer's own
/// member stores at the copy point can establish it.
fn stated_member_contents(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    point: &crate::analyzer::semantic::ProgramPoint,
    charge: &mut impl FnMut(SemanticWork) -> Result<(), Interruption>,
) -> Result<HashSet<ValueId>, Interruption> {
    let mut bases = HashSet::new();
    for event in &point.events {
        let SemanticEffect::MemoryStore { location, .. } = event.effect else {
            continue;
        };
        charge(SemanticWork {
            memory_locations: 1,
            nested_entries: 1,
            ..SemanticWork::default()
        })?;
        let Some(location) = semantics.memory_location(location) else {
            continue;
        };
        match location.kind {
            MemoryLocationKind::Field { base, .. }
            | MemoryLocationKind::Index { base, .. }
            | MemoryLocationKind::Property { base, .. } => {
                bases.insert(base);
            }
            MemoryLocationKind::Dereference { .. } => {}
            MemoryLocationKind::Static { .. }
            | MemoryLocationKind::LexicalCell { .. }
            | MemoryLocationKind::Capture { .. } => {}
        }
    }
    Ok(bases)
}

#[doc(hidden)]
pub fn procedure_value_facts(
    procedure: &ProcedureHandle,
    seeded: &HashMap<ValueId, LoadOrigin>,
    refuted: &HashSet<(ProgramPointId, usize)>,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    mut charge: impl FnMut(SemanticWork) -> Result<(), Interruption>,
) -> Result<ProcedureValueFacts, Interruption> {
    // The derived handler bindings (#2446) are copies the runtime performs
    // rather than copies an event records, so they are seeded here instead of
    // being discovered by the event scan below. A binding a later event also
    // defines would resolve to `Ambiguous` through the same merge rule as any
    // other conflicting origin.
    let mut origins = seeded.clone();
    let mut member_stores = Vec::<(MemoryLocationId, ValueId, Option<MemoryLocationId>)>::new();
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
        // Which destinations the producer gave stated copied contents at this
        // point. Computed once per point, and only where a transfer can consume
        // it, because it is a second pass over the point's own events.
        let stated_contents = if point.events.iter().any(|event| {
            matches!(
                event.effect,
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Transfer(_),
                    ..
                }
            )
        }) {
            stated_member_contents(semantics, point, &mut charge)?
        } else {
            HashSet::new()
        };
        for (event_index, event) in point.events.iter().enumerate() {
            if cancellation.is_cancelled() {
                return Err(Interruption::Cancelled);
            }
            charge(SemanticWork {
                events: 1,
                ..SemanticWork::default()
            })?;
            if refuted.contains(&(point.id, event_index)) {
                continue;
            }
            let origin = match event.effect {
                SemanticEffect::Assignment { target, value } => {
                    charge(SemanticWork {
                        values: 2,
                        nested_entries: 1,
                        ..SemanticWork::default()
                    })?;
                    let origin = if semantics
                        .value(target)
                        .is_some_and(|target| target.kind == SemanticValueKind::Address)
                    {
                        semantics
                            .binding_memory_location(value)
                            .map_or(LoadOrigin::Value(value), LoadOrigin::Unique)
                    } else {
                        LoadOrigin::Value(value)
                    };
                    if point.events.iter().any(|event| matches!(event.effect,
                        SemanticEffect::ValueFlow { kind: ValueFlowKind::Transfer(_), source, target: destination }
                            if source == value && destination == target)) {
                        None
                    } else {
                        Some((target, origin))
                    }
                }
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Local,
                    target,
                    source: value,
                } => {
                    charge(SemanticWork {
                        values: 2,
                        nested_entries: 1,
                        ..SemanticWork::default()
                    })?;
                    if point.events.iter().any(|event| matches!(event.effect,
                        SemanticEffect::ValueFlow { kind: ValueFlowKind::Transfer(_), source, target: destination }
                            if source == value && destination == target)) {
                        None
                    } else {
                        Some((target, LoadOrigin::Value(value)))
                    }
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
                    kind: ValueFlowKind::BackingStoreAlternative { offset, allocation },
                    source,
                    target,
                } => {
                    charge(SemanticWork {
                        values: 2,
                        allocations: 1,
                        nested_entries: 2,
                        ..SemanticWork::default()
                    })?;
                    Some((
                        target,
                        LoadOrigin::BackingStoreAlternative {
                            source,
                            offset,
                            allocation,
                        },
                    ))
                }
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Parameter,
                    source,
                    target,
                } => {
                    charge(SemanticWork {
                        values: 2,
                        nested_entries: 1,
                        ..SemanticWork::default()
                    })?;
                    let source_kind = semantics.value(source).map(|value| &value.kind);
                    let target_kind = semantics.value(target).map(|value| &value.kind);
                    match (source_kind, target_kind) {
                        (Some(SemanticValueKind::Parameter { ordinal, .. }), _) => Some((
                            target,
                            LoadOrigin::ProcedurePort(ProcedurePortKind::Parameter {
                                ordinal: *ordinal,
                            }),
                        )),
                        (_, Some(SemanticValueKind::Parameter { ordinal, .. })) => Some((
                            source,
                            LoadOrigin::ProcedurePort(ProcedurePortKind::Parameter {
                                ordinal: *ordinal,
                            }),
                        )),
                        _ => None,
                    }
                }
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Receiver,
                    source,
                    target,
                } => {
                    charge(SemanticWork {
                        values: 2,
                        nested_entries: 1,
                        ..SemanticWork::default()
                    })?;
                    let source_is_receiver = semantics.value(source).is_some_and(|value| {
                        matches!(value.kind, SemanticValueKind::Receiver { .. })
                    });
                    let target_is_receiver = semantics.value(target).is_some_and(|value| {
                        matches!(value.kind, SemanticValueKind::Receiver { .. })
                    });
                    if source_is_receiver {
                        Some((
                            target,
                            LoadOrigin::ProcedurePort(ProcedurePortKind::Receiver),
                        ))
                    } else if target_is_receiver {
                        Some((
                            source,
                            LoadOrigin::ProcedurePort(ProcedurePortKind::Receiver),
                        ))
                    } else {
                        None
                    }
                }
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Transfer(transfer),
                    source,
                    target,
                } => {
                    charge(SemanticWork {
                        values: 2,
                        nested_entries: 1,
                        ..SemanticWork::default()
                    })?;
                    Some((
                        target,
                        if stated_contents.contains(&target) {
                            let stores = point
                                .events
                                .iter()
                                .filter_map(|event| {
                                    let SemanticEffect::MemoryStore { location, .. } = event.effect
                                    else {
                                        return None;
                                    };
                                    let location_row = semantics.memory_location(location)?;
                                    match location_row.kind {
                                        MemoryLocationKind::Field { base, .. }
                                        | MemoryLocationKind::Index { base, .. }
                                        | MemoryLocationKind::Property { base, .. }
                                            if base == target =>
                                        {
                                            Some(location)
                                        }
                                        _ => None,
                                    }
                                })
                                .collect::<Vec<_>>();
                            charge(SemanticWork {
                                memory_locations: stores.len(),
                                nested_entries: stores.len(),
                                ..SemanticWork::default()
                            })?;
                            LoadOrigin::Separated(SeparatedTransfer {
                                source,
                                destination: target,
                                point: point.id,
                                transfer,
                                stores: stores.into_boxed_slice(),
                            })
                        } else {
                            LoadOrigin::Ambiguous
                        },
                    ))
                }
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::ReferenceBoxing | ValueFlowKind::ReferenceUnboxing,
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
                    // A store to a member, element or property is a candidate
                    // for the cell a longer path continues through. Which of
                    // them can be followed is decided once every origin is
                    // known.
                    if let SemanticEffect::MemoryStore { location, .. } = event.effect
                        && let Some(row) = semantics.memory_location(location)
                        && matches!(
                            row.kind,
                            MemoryLocationKind::Field { .. }
                                | MemoryLocationKind::Index { .. }
                                | MemoryLocationKind::Property { .. }
                        )
                    {
                        charge(SemanticWork {
                            memory_locations: 1,
                            nested_entries: 1,
                            ..SemanticWork::default()
                        })?;
                        let copied_from =
                            event_index.checked_sub(1).and_then(|previous| {
                                match point.events[previous].effect {
                                    SemanticEffect::MemoryLoad {
                                        location, result, ..
                                    } if result == source => Some(location),
                                    _ => None,
                                }
                            });
                        member_stores.push((location, source, copied_from));
                    }
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
                    .and_modify(|existing| merge_load_origin(existing, origin.clone()))
                    .or_insert(origin);
            }
        }
    }
    for origin in origins.values_mut() {
        if matches!(origin, LoadOrigin::SeparatedPending { .. }) {
            *origin = LoadOrigin::Ambiguous;
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
    let prefix_stores = prefix_stores(procedure, &origins, &member_stores, cancellation, charge)?;
    Ok(ProcedureValueFacts {
        load_origins: origins,
        prefix_stores,
        whole_container_reads,
    })
}

/// Index the member stores of one procedure by the cell they write, when some
/// access continues through a loaded value at all.
///
/// A store is followable when the stored value names the object a path
/// through the cell reaches: the producer states a reference or a backing
/// store, or states nothing and the language never copies an object on
/// assignment. An inline aggregate copy, and a store that states nothing in a
/// language that may copy, are recorded as not followable so a read through
/// the cell is reported partial instead of proving the stored members absent.
fn prefix_stores(
    procedure: &ProcedureHandle,
    origins: &HashMap<ValueId, LoadOrigin>,
    member_stores: &[(MemoryLocationId, ValueId, Option<MemoryLocationId>)],
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    mut charge: impl FnMut(SemanticWork) -> Result<(), Interruption>,
) -> Result<PrefixStores, Interruption> {
    let mut stores = PrefixStores::default();
    if member_stores.is_empty() {
        return Ok(stores);
    }
    // Index values that language lowering canonicalizes as constants.
    stores.constant_indexes = semantics_constant_indexes(procedure.semantics());
    let semantics = procedure.semantics();
    let exact_integer = |value| exact_unsigned_integer_origin(semantics, origins, value);
    // Only a base that is itself a loaded value lets a path continue through a
    // cell; without one, no access has a strict-prefix cell.
    let mut continues_through_a_load = false;
    for location in semantics.memory_locations() {
        charge(SemanticWork {
            memory_locations: 1,
            nested_entries: 1,
            ..SemanticWork::default()
        })?;
        let (MemoryLocationKind::Field { base, .. }
        | MemoryLocationKind::Index { base, .. }
        | MemoryLocationKind::Property { base, .. }) = location.kind
        else {
            continue;
        };
        if matches!(
            walk_value_origin(
                origins,
                base,
                &mut HashSet::new(),
                exact_integer,
                &[],
                &mut 0
            ),
            ValueOriginWalk::Load { .. }
        ) {
            continues_through_a_load = true;
            break;
        }
    }
    if !continues_through_a_load {
        return Ok(stores);
    }
    use brokk_bifrost_core::analyzer::language_knowledge::UnmarkedMemberStores;
    let unmarked_stores = crate::analyzer::semantic::languages::language_knowledge(
        procedure.artifact().key().language().language(),
    )
    .map_or(UnmarkedMemberStores::Opaque, |knowledge| {
        knowledge.unmarked_member_stores()
    });
    if unmarked_stores == UnmarkedMemberStores::Unindexed
        && !member_stores.iter().any(|&(location, _, _)| {
            matches!(
                semantics
                    .memory_location(location)
                    .expect("a recorded member store names a validated location")
                    .value_copy,
                MemoryValueCopy::Reference | MemoryValueCopy::BackingStore { .. }
            )
        })
    {
        return Ok(stores);
    }
    let unmarked_stores_share_object = unmarked_stores == UnmarkedMemberStores::Followable;
    let binding_origins = BindingOriginIndex::from_semantics(semantics);
    // The stores are keyed by their own unredirected path.
    let unredirected = PrefixStores::default();
    for &(location, stored, copied_from) in member_stores {
        let row = semantics
            .memory_location(location)
            .expect("a recorded member store names a validated location");
        let followed = match row.value_copy {
            MemoryValueCopy::Reference | MemoryValueCopy::BackingStore { .. } => Some(stored),
            MemoryValueCopy::Unknown if unmarked_stores_share_object => Some(stored),
            MemoryValueCopy::Unknown | MemoryValueCopy::Value => None,
        };
        // A copied field can canonicalize to its source cell. Such an
        // identity store does not redirect a longer access through that cell.
        // Only an adjacent load/store pair proves no write intervened.
        let copied_from = match copied_from {
            Some(location) => {
                match resolve_access_path(
                    location,
                    ValueOriginFacts {
                        load_origins: origins,
                        prefix_stores: &unredirected,
                        binding_origins: Some(&binding_origins),
                    },
                    PREFIX_STORE_SELECTOR_LIMIT,
                    cancellation,
                    |id| semantics.memory_location(id).map(|row| &row.kind),
                    exact_integer,
                    &mut charge,
                )
                .expect("a stored load names a validated location")
                {
                    AccessPathResolution::Resolved(draft)
                        if draft.tail == AccessPathTail::Exact =>
                    {
                        Some((
                            CellRoot::of(&draft.root),
                            draft
                                .selectors
                                .iter()
                                .map(|selector| stores.cell_selector(selector, exact_integer))
                                .collect::<Vec<_>>(),
                        ))
                    }
                    AccessPathResolution::Interrupted(stop) => return Err(stop),
                    AccessPathResolution::Resolved(_) => None,
                }
            }
            _ => None,
        };
        let (plans, truncated) = alternative_choice_plans(
            location,
            origins,
            &unredirected,
            |id| semantics.memory_location(id).map(|row| &row.kind),
            exact_integer,
            PREFIX_STORE_SELECTOR_LIMIT,
            cancellation,
        );
        stores.incomplete |= truncated;
        for choices in plans {
            let resolution = resolve_access_path_with_choice(
                location,
                AccessPathResolutionInputs {
                    origins: ValueOriginFacts {
                        load_origins: origins,
                        prefix_stores: &unredirected,
                        binding_origins: Some(&binding_origins),
                    },
                    selector_limit: PREFIX_STORE_SELECTOR_LIMIT,
                    cancellation,
                    choices: &choices,
                },
                |id| semantics.memory_location(id).map(|row| &row.kind),
                exact_integer,
                &mut charge,
            )
            .expect("a recorded member store names a validated location");
            let draft = match resolution {
                AccessPathResolution::Resolved(draft) => draft,
                AccessPathResolution::Interrupted(stop) => return Err(stop),
            };
            let selectors = draft
                .selectors
                .iter()
                .map(|selector| stores.cell_selector(selector, exact_integer))
                .collect::<Vec<_>>();
            let root = CellRoot::of(&draft.root);
            if draft.tail == AccessPathTail::Exact
                && selectors.iter().all(|selector| {
                    !matches!(
                        selector,
                        CellSelector::Index(CellIndex::Any | CellIndex::Exact(_))
                    )
                })
                && copied_from
                    .as_ref()
                    .is_some_and(|(source_root, source_selectors)| {
                        source_root == &root && source_selectors == &selectors
                    })
            {
                continue;
            }
            let key = (root, selectors.iter().map(CellSelector::erased).collect());
            stores.cells.entry(key).or_default().push(PrefixStore {
                selectors,
                followed,
            });
        }
    }
    Ok(stores)
}

fn semantics_constant_indexes(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
) -> HashSet<ValueId> {
    semantics
        .memory_locations()
        .iter()
        .filter_map(|location| match location.kind {
            MemoryLocationKind::Index {
                index: Some(index), ..
            } => Some(index),
            _ => None,
        })
        .filter(|index| {
            semantics
                .value(*index)
                .is_some_and(|value| value.kind.is_constant())
        })
        .collect()
}

/// The longest selector chain a recorded store path keeps. A read path is
/// truncated at the oracle's own limit from its leaf end, so a prefix near the
/// root is never lost by that truncation.
const PREFIX_STORE_SELECTOR_LIMIT: usize = 32;

fn merge_load_origin(existing: &mut LoadOrigin, incoming: LoadOrigin) {
    match (&*existing, &incoming) {
        (left, right) if left == right => {}
        (
            LoadOrigin::Value(left),
            LoadOrigin::BackingStore {
                source: right,
                offset,
            },
        ) if left == right => {
            *existing = LoadOrigin::BackingStore {
                source: *right,
                offset: *offset,
            };
        }
        (LoadOrigin::BackingStore { source: left, .. }, LoadOrigin::Value(right))
            if left == right => {}
        // The transfer and the assignment it must immediately follow are two
        // events for one definition, so the transfer's separated identity
        // stands instead of making the pair ambiguous.
        (LoadOrigin::Value(left), LoadOrigin::Separated(transfer)) if left == &transfer.source => {
            *existing = incoming;
        }
        (LoadOrigin::Separated(transfer), LoadOrigin::Value(right))
            if &transfer.source == right => {}
        (LoadOrigin::SeparatedDefinitions(transfers), LoadOrigin::Value(right))
            if transfers.iter().any(|transfer| &transfer.source == right) => {}
        (
            LoadOrigin::Separated(_) | LoadOrigin::SeparatedDefinitions(_),
            LoadOrigin::Value(source),
        ) => {
            let transfers = match std::mem::replace(existing, LoadOrigin::Ambiguous) {
                LoadOrigin::Separated(transfer) => vec![transfer].into_boxed_slice(),
                LoadOrigin::SeparatedDefinitions(transfers) => transfers,
                _ => unreachable!(),
            };
            *existing = LoadOrigin::SeparatedPending {
                transfers,
                source: *source,
            };
        }
        (LoadOrigin::SeparatedPending { source, .. }, LoadOrigin::Separated(transfer))
            if source == &transfer.source =>
        {
            let LoadOrigin::SeparatedPending { transfers, .. } =
                std::mem::replace(existing, LoadOrigin::Ambiguous)
            else {
                unreachable!()
            };
            let mut transfers = transfers.into_vec();
            let LoadOrigin::Separated(transfer) = incoming else {
                unreachable!()
            };
            if !transfers.contains(&transfer) {
                transfers.push(transfer);
            }
            *existing = LoadOrigin::SeparatedDefinitions(transfers.into_boxed_slice());
        }
        (
            LoadOrigin::Separated(_) | LoadOrigin::SeparatedDefinitions(_),
            LoadOrigin::Separated(_),
        ) => {
            let mut transfers = match std::mem::replace(existing, LoadOrigin::Ambiguous) {
                LoadOrigin::Separated(transfer) => vec![transfer],
                LoadOrigin::SeparatedDefinitions(transfers) => transfers.into_vec(),
                _ => unreachable!(),
            };
            let LoadOrigin::Separated(transfer) = incoming else {
                unreachable!()
            };
            if !transfers.contains(&transfer) {
                transfers.push(transfer);
            }
            *existing = LoadOrigin::SeparatedDefinitions(transfers.into_boxed_slice());
        }
        // Plain copies from different sources are a finite set of
        // definitions, not an unknown one.
        (
            LoadOrigin::Value(_) | LoadOrigin::Definitions(_),
            LoadOrigin::Value(_) | LoadOrigin::Definitions(_),
        ) => {
            let mut sources = Vec::new();
            for origin in [std::mem::replace(existing, LoadOrigin::Ambiguous), incoming] {
                match origin {
                    LoadOrigin::Value(source) => sources.push(source),
                    LoadOrigin::Definitions(more) => sources.extend(more),
                    _ => unreachable!("only plain copies reach the definition merge"),
                }
            }
            let mut seen = HashSet::new();
            sources.retain(|source| seen.insert(*source));
            *existing = LoadOrigin::Definitions(sources.into_boxed_slice());
        }
        _ => *existing = LoadOrigin::Ambiguous,
    }
}

/// Follow only unconditional value aliases. A separated definition's source
/// has a different object identity, so it must never be followed here.
fn separated_return_definitions(
    origins: &HashMap<ValueId, LoadOrigin>,
    start: ValueId,
) -> Option<&[SeparatedTransfer]> {
    let mut current = start;
    let mut visited = HashSet::new();
    while visited.insert(current) {
        match origins.get(&current) {
            Some(LoadOrigin::Value(next)) => current = *next,
            Some(LoadOrigin::SeparatedDefinitions(transfers)) => return Some(transfers),
            _ => return None,
        }
    }
    None
}

/// Object roots a finite origin choice can present at a whole-value read.
/// A separated copy contributes its destination, never its source object.
struct ReturnCandidates<'a> {
    roots: HashSet<ValueId>,
    /// The transfer that defined each separated destination root.
    transfers: HashMap<ValueId, &'a SeparatedTransfer>,
    /// Every leaf of the finite choice is an exact root (a separated
    /// destination, or a local allocation result), so the roots enumerate
    /// every object the read can denote.
    exhaustive: bool,
}

fn return_candidate_roots<'a>(
    origins: &'a HashMap<ValueId, LoadOrigin>,
    local_allocations: &HashSet<ValueId>,
    start: ValueId,
) -> ReturnCandidates<'a> {
    let mut candidates = ReturnCandidates {
        roots: HashSet::new(),
        transfers: HashMap::new(),
        exhaustive: true,
    };
    let mut seen = HashSet::new();
    let mut pending = vec![start];
    while let Some(value) = pending.pop() {
        if !seen.insert(value) {
            continue;
        }
        match origins.get(&value) {
            Some(LoadOrigin::Value(source)) => pending.push(*source),
            Some(LoadOrigin::Definitions(sources)) => pending.extend(sources.iter().copied()),
            Some(LoadOrigin::SeparatedDefinitions(transfers)) => {
                for transfer in transfers {
                    candidates.roots.insert(transfer.destination);
                    candidates.transfers.insert(transfer.destination, transfer);
                }
            }
            Some(LoadOrigin::Separated(transfer)) => {
                candidates.roots.insert(value);
                candidates.transfers.insert(value, transfer);
            }
            // Only an allocation effect in this procedure proves that the
            // value denotes an object whose members were stored locally.
            // Parameters and call results can also lack a load origin.
            None => {
                candidates.roots.insert(value);
                if !local_allocations.contains(&value) {
                    candidates.exhaustive = false;
                }
            }
            Some(_) => {
                candidates.roots.insert(value);
                candidates.exhaustive = false;
            }
        }
    }
    candidates
}

/// Records that a stored member of a returned join was not transported to the
/// return port (#9766). The gap is a property of the procedure's content, not of
/// a limit, so the caller passes the content flag unless a capacity bound may
/// have shaped the decision (see the call site).
fn mark_rejected_return_member_incomplete(
    incomplete: &mut bool,
    has_stored_contents: bool,
    candidate: Option<ValueId>,
    roots: &HashSet<ValueId>,
) {
    if has_stored_contents && candidate.is_some_and(|value| roots.contains(&value)) {
        *incomplete = true;
    }
}

#[cfg(test)]
mod separated_member_guard_tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon("#9766: a rejected candidate return member was silently completed")]
    fn rejected_candidate_member_opens_boundary_coverage() {
        let candidate = ValueId::new(1);
        let unrelated = ValueId::new(2);
        let roots = HashSet::from([candidate]);
        let mut incomplete = false;
        mark_rejected_return_member_incomplete(&mut incomplete, true, Some(unrelated), &roots);
        assert!(!incomplete, "an unrelated store must not open the return");
        mark_rejected_return_member_incomplete(&mut incomplete, true, Some(candidate), &roots);
        assert!(
            incomplete,
            "a rejected candidate must keep coverage incomplete"
        );
    }
}

#[doc(hidden)]
pub fn exact_unsigned_integer_origin(
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

/// The selector a location adds to an access path, if it is a member, element
/// or property access.
fn selector_draft(kind: &MemoryLocationKind) -> Option<AccessSelectorDraft> {
    match kind {
        MemoryLocationKind::Property { key, .. } => {
            Some(AccessSelectorDraft::Property(key.clone()))
        }
        MemoryLocationKind::Field { member, .. } => {
            Some(AccessSelectorDraft::Field(member.clone()))
        }
        MemoryLocationKind::Index {
            index,
            constant_index,
            identity,
            ..
        } => Some(AccessSelectorDraft::Index {
            value: *index,
            constant: *constant_index,
            identity: *identity,
        }),
        MemoryLocationKind::Dereference { .. }
        | MemoryLocationKind::Static { .. }
        | MemoryLocationKind::LexicalCell { .. }
        | MemoryLocationKind::Capture { .. } => None,
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
    /// The walk reached a formal parameter or receiver. Formal roots retain
    /// the durable procedure-port identity instead of becoming procedure-local
    /// temporary values.
    Port {
        kind: ProcedurePortKind,
        offset: Option<u128>,
        summarized: bool,
    },
    Allocation {
        allocation: crate::analyzer::semantic::AllocationId,
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

#[derive(Debug, Clone, Copy)]
enum AlternativeChoice {
    Source,
    Allocation,
    /// The definition at this position of a [`LoadOrigin::Definitions`] set.
    Definition(usize),
}

impl AlternativeChoice {
    /// Whether the choice is a backing-store candidate, which may name storage
    /// the access never touches. A definition choice is one arm of an
    /// exhaustive set, so the union of its arms is the exact answer.
    fn is_backing_store_candidate(self) -> bool {
        match self {
            Self::Source | Self::Allocation => true,
            Self::Definition(_) => false,
        }
    }
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
    choices: &[AlternativeChoice],
    choice_index: &mut usize,
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
            Some(LoadOrigin::ProcedurePort(kind)) => {
                return ValueOriginWalk::Port {
                    kind: *kind,
                    offset,
                    summarized: false,
                };
            }
            Some(LoadOrigin::BackingStoreAlternative {
                source,
                offset: step,
                allocation,
            }) => {
                let choice = choices.get(*choice_index).copied();
                *choice_index = (*choice_index).saturating_add(1);
                match choice {
                    Some(AlternativeChoice::Source) => {
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
                    Some(AlternativeChoice::Allocation) => {
                        return ValueOriginWalk::Allocation {
                            allocation: *allocation,
                            offset,
                            summarized: false,
                        };
                    }
                    Some(AlternativeChoice::Definition(_)) | None => {
                        return ValueOriginWalk::Root {
                            value: current,
                            offset,
                            summarized: true,
                        };
                    }
                }
            }
            Some(LoadOrigin::Unique(location)) => {
                return ValueOriginWalk::Load {
                    location: *location,
                    value: current,
                    offset,
                };
            }
            Some(LoadOrigin::Separated(_) | LoadOrigin::SeparatedDefinitions(_)) => {
                return ValueOriginWalk::Root {
                    value: current,
                    offset,
                    summarized: false,
                };
            }
            Some(LoadOrigin::Definitions(sources)) if visited.insert(current) => {
                let choice = choices.get(*choice_index).copied();
                *choice_index = (*choice_index).saturating_add(1);
                // A plan is enumerated along the same chain this walk takes,
                // so its choice here is a definition of this set. A choice
                // that is not stops on a summarized root, as an unplanned
                // walk does.
                match choice.and_then(|choice| match choice {
                    AlternativeChoice::Definition(position) => sources.get(position),
                    AlternativeChoice::Source | AlternativeChoice::Allocation => None,
                }) {
                    Some(source) => current = *source,
                    None => {
                        return ValueOriginWalk::Root {
                            value: current,
                            offset,
                            summarized: true,
                        };
                    }
                }
            }
            Some(LoadOrigin::Value(_))
            | Some(LoadOrigin::BackingStore { .. })
            | Some(LoadOrigin::Definitions(_))
            | Some(LoadOrigin::SeparatedPending { .. })
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

/// What a walk does at a root that a longer path still continues through.
enum PrefixStep {
    /// No store reaches a strict prefix of the path.
    Unchanged,
    /// A prefix cell holds this value; the walk continues from it with the
    /// prefix selectors consumed.
    Follow(ValueId),
    /// A store reaches a prefix cell and cannot be followed, so the stored
    /// members cannot be proven absent.
    Opaque,
}

/// Take the redirect through a strict-prefix cell at `root`, consuming the
/// prefix's selectors.
///
/// Every nonempty candidate set is a may-choice: position zero keeps the
/// original path, and later positions follow stores. The flow-insensitive index
/// cannot prove a store ran before the read. A walk with no plan entry is
/// reported opaque rather than silently taking an arm.
fn follow_prefix_store(
    prefix_stores: &PrefixStores,
    root: CellRoot,
    selectors: &mut VecDeque<AccessSelectorDraft>,
    choices: &[AlternativeChoice],
    choice_index: &mut usize,
    exact_integer: impl Fn(ValueId) -> Option<u128>,
) -> PrefixStep {
    let candidates = prefix_stores.candidates(root, selectors, exact_integer);
    if candidates.is_empty() {
        return PrefixStep::Unchanged;
    }
    let choice = choices.get(*choice_index).copied();
    *choice_index = (*choice_index).saturating_add(1);
    let candidate = match choice {
        Some(AlternativeChoice::Definition(0)) => return PrefixStep::Unchanged,
        Some(AlternativeChoice::Definition(position)) => candidates.get(position - 1).copied(),
        _ => None,
    };
    match candidate.and_then(|candidate| Some((candidate.depth, candidate.followed?))) {
        Some((depth, value)) => {
            for _ in 0..depth {
                selectors.pop_back();
            }
            PrefixStep::Follow(value)
        }
        None => PrefixStep::Opaque,
    }
}

#[doc(hidden)]
pub fn resolve_access_path<'location>(
    location: MemoryLocationId,
    origins: ValueOriginFacts<'_>,
    selector_limit: usize,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    location_kind: impl Fn(MemoryLocationId) -> Option<&'location MemoryLocationKind>,
    exact_integer: impl Fn(ValueId) -> Option<u128> + Copy,
    charge: impl FnMut(SemanticWork) -> Result<(), Interruption>,
) -> Result<AccessPathResolution, SemanticProviderError> {
    resolve_access_path_with_choice(
        location,
        AccessPathResolutionInputs {
            origins,
            selector_limit,
            cancellation,
            choices: &[],
        },
        location_kind,
        exact_integer,
        charge,
    )
}

struct AccessPathResolutionInputs<'input> {
    origins: ValueOriginFacts<'input>,
    selector_limit: usize,
    cancellation: &'input brokk_bifrost_core::cancellation::CancellationToken,
    choices: &'input [AlternativeChoice],
}

fn resolve_access_path_with_choice<'location>(
    location: MemoryLocationId,
    inputs: AccessPathResolutionInputs<'_>,
    location_kind: impl Fn(MemoryLocationId) -> Option<&'location MemoryLocationKind>,
    exact_integer: impl Fn(ValueId) -> Option<u128> + Copy,
    mut charge: impl FnMut(SemanticWork) -> Result<(), Interruption>,
) -> Result<AccessPathResolution, SemanticProviderError> {
    let AccessPathResolutionInputs {
        origins:
            ValueOriginFacts {
                load_origins,
                prefix_stores,
                binding_origins,
            },
        selector_limit,
        cancellation,
        choices,
    } = inputs;
    let mut current = location;
    let mut visited = HashSet::new();
    let mut visited_values = HashSet::new();
    let mut choice_index = 0usize;
    let mut selectors = VecDeque::new();
    let mut summarized = false;
    let mut opaque_prefix = false;
    let mut original_cell = None;

    let root = 'locations: loop {
        if cancellation.is_cancelled() {
            return Ok(AccessPathResolution::Interrupted(Interruption::Cancelled));
        }
        let kind = location_kind(current)
            .ok_or_else(|| SemanticProviderError::internal("memory location handle is stale"))?;
        let selector_count = usize::from(matches!(
            kind,
            MemoryLocationKind::Field { .. }
                | MemoryLocationKind::Property { .. }
                | MemoryLocationKind::Index { .. }
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
        if let Some(selector) = selector_draft(kind) {
            retain_selector(&mut selectors, selector, selector_limit, &mut summarized);
        }
        let mut base = match kind {
            MemoryLocationKind::Property { base, .. }
            | MemoryLocationKind::Field { base, .. }
            | MemoryLocationKind::Index { base, .. } => *base,
            MemoryLocationKind::Dereference { address } => {
                let unique_binding_cell = binding_origins.and_then(|origins| {
                    origins
                        .addressed_binding_origins(*address)
                        .unique_binding()
                        .and_then(|binding| origins.binding_memory_location(binding))
                });
                if let Some(cell) = unique_binding_cell {
                    current = cell;
                    continue 'locations;
                }
                match walk_value_origin(
                    load_origins,
                    *address,
                    &mut visited_values,
                    exact_integer,
                    choices,
                    &mut choice_index,
                ) {
                    ValueOriginWalk::Load { location, .. } => {
                        current = location;
                        continue 'locations;
                    }
                    _ => {
                        summarized = true;
                        break 'locations AccessPathRootDraft::Value(*address);
                    }
                }
            }
            MemoryLocationKind::Static { member } => {
                match redirect_at_root(
                    prefix_stores,
                    AccessPathRootDraft::Static(member.clone()),
                    &mut selectors,
                    choices,
                    &mut choice_index,
                    exact_integer,
                    &mut opaque_prefix,
                    &mut original_cell,
                ) {
                    Ok(stored) => stored,
                    Err(root) => break 'locations root,
                }
            }
            MemoryLocationKind::LexicalCell { .. } => {
                match redirect_at_root(
                    prefix_stores,
                    AccessPathRootDraft::LexicalCell(current),
                    &mut selectors,
                    choices,
                    &mut choice_index,
                    exact_integer,
                    &mut opaque_prefix,
                    &mut original_cell,
                ) {
                    Ok(stored) => stored,
                    Err(root) => break 'locations root,
                }
            }
            MemoryLocationKind::Capture { .. } => {
                match redirect_at_root(
                    prefix_stores,
                    AccessPathRootDraft::Capture(current),
                    &mut selectors,
                    choices,
                    &mut choice_index,
                    exact_integer,
                    &mut opaque_prefix,
                    &mut original_cell,
                ) {
                    Ok(stored) => stored,
                    Err(root) => break 'locations root,
                }
            }
        };

        // Each prefix redirect drops the selectors it consumed, so the walk
        // cannot revisit one and terminates in the retained selector count.
        loop {
            match walk_value_origin(
                load_origins,
                base,
                &mut visited_values,
                exact_integer,
                choices,
                &mut choice_index,
            ) {
                ValueOriginWalk::Root {
                    value,
                    offset,
                    summarized: joined,
                } => {
                    summarized |= joined || !apply_backing_offset(&mut selectors, offset);
                    match redirect_at_root(
                        prefix_stores,
                        AccessPathRootDraft::Value(value),
                        &mut selectors,
                        choices,
                        &mut choice_index,
                        exact_integer,
                        &mut opaque_prefix,
                        &mut original_cell,
                    ) {
                        Ok(stored) => {
                            base = stored;
                            continue;
                        }
                        Err(root) => break 'locations root,
                    }
                }
                ValueOriginWalk::Port {
                    kind,
                    offset,
                    summarized: joined,
                } => {
                    summarized |= joined || !apply_backing_offset(&mut selectors, offset);
                    match redirect_at_root(
                        prefix_stores,
                        AccessPathRootDraft::ProcedurePort(kind),
                        &mut selectors,
                        choices,
                        &mut choice_index,
                        exact_integer,
                        &mut opaque_prefix,
                        &mut original_cell,
                    ) {
                        Ok(stored) => {
                            base = stored;
                            continue;
                        }
                        Err(root) => break 'locations root,
                    }
                }
                ValueOriginWalk::Allocation {
                    allocation,
                    offset,
                    summarized: joined,
                } => {
                    summarized |= joined || !apply_backing_offset(&mut selectors, offset);
                    match redirect_at_root(
                        prefix_stores,
                        AccessPathRootDraft::Allocation(allocation),
                        &mut selectors,
                        choices,
                        &mut choice_index,
                        exact_integer,
                        &mut opaque_prefix,
                        &mut original_cell,
                    ) {
                        Ok(stored) => {
                            base = stored;
                            continue;
                        }
                        Err(root) => break 'locations root,
                    }
                }
                ValueOriginWalk::Load {
                    location,
                    value,
                    offset,
                } => {
                    summarized |= !apply_backing_offset(&mut selectors, offset);
                    if visited.contains(&location) {
                        summarized = true;
                        break 'locations AccessPathRootDraft::Value(value);
                    }
                    current = location;
                    continue 'locations;
                }
            }
        }
    };

    if summarized && let Some(original) = original_cell.as_mut() {
        original.tail = AccessPathTail::Summary;
    }
    Ok(AccessPathResolution::Resolved(AccessPathDraft {
        original_cell,
        root,
        selectors: selectors.into_iter().rev().collect(),
        tail: if summarized {
            AccessPathTail::Summary
        } else {
            AccessPathTail::Exact
        },
        opaque_prefix,
    }))
}

/// Apply the strict-prefix redirect at the root `root` a walk reached.
///
/// `Ok` is the value the walk continues from, `Err` the root the path ends
/// at. An unfollowable store marks the path opaque, so the relation is
/// partial. The path keeps its exact selectors: it is the cell the access
/// names, and what is unknown is only what an unfollowed store put below it.
#[allow(clippy::too_many_arguments)]
fn redirect_at_root(
    prefix_stores: &PrefixStores,
    root: AccessPathRootDraft,
    selectors: &mut VecDeque<AccessSelectorDraft>,
    choices: &[AlternativeChoice],
    choice_index: &mut usize,
    exact_integer: impl Fn(ValueId) -> Option<u128>,
    opaque_prefix: &mut bool,
    original_cell: &mut Option<Box<AccessPathDraft>>,
) -> Result<ValueId, AccessPathRootDraft> {
    let original_selectors = selectors.iter().rev().cloned().collect();
    match follow_prefix_store(
        prefix_stores,
        CellRoot::of(&root),
        selectors,
        choices,
        choice_index,
        exact_integer,
    ) {
        PrefixStep::Follow(stored) => {
            original_cell.get_or_insert_with(|| {
                Box::new(AccessPathDraft {
                    original_cell: None,
                    root: root.clone(),
                    selectors: original_selectors,
                    tail: AccessPathTail::Exact,
                    opaque_prefix: false,
                })
            });
            Ok(stored)
        }
        PrefixStep::Unchanged => Err(root),
        PrefixStep::Opaque => {
            *opaque_prefix = true;
            Err(root)
        }
    }
}

fn apply_backing_offset(
    selectors: &mut VecDeque<AccessSelectorDraft>,
    offset: Option<u128>,
) -> bool {
    if offset == Some(0) {
        return true;
    }
    let Some(AccessSelectorDraft::Index {
        value, constant, ..
    }) = selectors.back_mut()
    else {
        return false;
    };
    if let (Some(offset), Some(index)) = (offset, constant.as_mut())
        && let Some(translated) = index.checked_add(offset)
    {
        *index = translated;
        return true;
    }
    // An index the offset cannot translate (an unknown offset, or a
    // non-constant index past a nonzero one) may name any element, so the
    // prefix lookup and the redirect must not keep the untranslated index.
    *value = None;
    *constant = None;
    false
}

/// Enumerate the finite alternative choices reachable from a memory location.
/// The worklist keeps nested alternatives distinct: an outer retained arm can
/// still encounter an inner fresh arm. The returned boolean records a breadth
/// truncation without hiding the candidates already retained.
///
/// This mirrors the walk in [`resolve_access_path_with_choice`] step for step,
/// including the selectors it retains, because a strict-prefix redirect depends
/// on them: every root reached by a prefix candidate is a choice point, with
/// the original path first and then the stores. The index is flow-insensitive
/// and cannot prove a store ran before the read.
fn alternative_choice_plans<'location>(
    location: MemoryLocationId,
    load_origins: &HashMap<ValueId, LoadOrigin>,
    prefix_stores: &PrefixStores,
    location_kind: impl Fn(MemoryLocationId) -> Option<&'location MemoryLocationKind>,
    exact_integer: impl Fn(ValueId) -> Option<u128> + Copy,
    limit: usize,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
) -> (Vec<Vec<AlternativeChoice>>, bool) {
    /// The choices taken so far and the cells the path retains, leaf first.
    type Walk = (Vec<AlternativeChoice>, Vec<CellSelector>);
    enum Pending {
        Location(MemoryLocationId, Walk),
        Value(ValueId, Walk),
    }
    /// Continue past a root the walk reached: through the stores that reach a
    /// strict prefix of the path, or to the end of the plan.
    fn at_root(
        prefix_stores: &PrefixStores,
        root: CellRoot,
        (choices, cells): Walk,
        pending: &mut Vec<Pending>,
        plans: &mut Vec<Vec<AlternativeChoice>>,
    ) {
        let path = cells.iter().rev().cloned().collect::<Vec<_>>();
        let candidates = if path.len() < 2 {
            Vec::new()
        } else {
            prefix_stores.candidates_for_path(root, &path)
        };
        if candidates.is_empty() {
            plans.push(choices);
            return;
        }
        let mut original_choices = choices.clone();
        original_choices.push(AlternativeChoice::Definition(0));
        plans.push(original_choices);
        for (position, candidate) in candidates.iter().enumerate() {
            let mut choices = choices.clone();
            choices.push(AlternativeChoice::Definition(position + 1));
            match candidate.followed {
                Some(stored) => {
                    let mut cells = cells.clone();
                    cells.truncate(cells.len() - candidate.depth);
                    pending.push(Pending::Value(stored, (choices, cells)));
                }
                None => plans.push(choices),
            }
        }
    }
    let limit = limit.max(2);
    let mut pending = vec![Pending::Location(location, (Vec::new(), Vec::new()))];
    let mut seen = HashSet::new();
    let mut expanded = HashSet::new();
    let mut plans = Vec::new();
    let mut truncated = false;
    let mut steps = 0_usize;
    while let Some(state) = pending.pop() {
        steps += 1;
        if cancellation.is_cancelled() || steps > limit.saturating_mul(64) {
            truncated = true;
            break;
        }
        let (tag, id, cells) = match &state {
            Pending::Location(location, (_, cells)) => (0_u8, location.index(), cells.clone()),
            Pending::Value(value, (_, cells)) => (1_u8, value.index(), cells.clone()),
        };
        if !seen.insert((tag, id, cells)) {
            truncated = true;
            continue;
        }
        match state {
            Pending::Location(current, (choices, mut cells)) => {
                let Some(kind) = location_kind(current) else {
                    plans.push(choices);
                    continue;
                };
                if let Some(selector) = selector_draft(kind) {
                    cells.push(prefix_stores.cell_selector(&selector, exact_integer));
                }
                let walk = (choices, cells);
                match kind {
                    MemoryLocationKind::Field { base, .. }
                    | MemoryLocationKind::Index { base, .. }
                    | MemoryLocationKind::Property { base, .. } => {
                        pending.push(Pending::Value(*base, walk));
                    }
                    MemoryLocationKind::Dereference { .. } => plans.push(walk.0),
                    MemoryLocationKind::Static { member } => at_root(
                        prefix_stores,
                        CellRoot::Static(member.clone()),
                        walk,
                        &mut pending,
                        &mut plans,
                    ),
                    MemoryLocationKind::LexicalCell { .. } => at_root(
                        prefix_stores,
                        CellRoot::LexicalCell(current),
                        walk,
                        &mut pending,
                        &mut plans,
                    ),
                    MemoryLocationKind::Capture { .. } => at_root(
                        prefix_stores,
                        CellRoot::Capture(current),
                        walk,
                        &mut pending,
                        &mut plans,
                    ),
                }
            }
            Pending::Value(value, (choices, mut cells)) => {
                // The walk applies the backing-store offsets it passed to the
                // selector nearest the root once, where it stops; adding each
                // step as it is passed gives the same sum.
                let step = |offset: &BackingStoreOffset| match offset {
                    BackingStoreOffset::Zero => Some(0),
                    BackingStoreOffset::Constant(step) => Some(*step),
                    BackingStoreOffset::Value(value) => exact_integer(*value),
                };
                // Mirrors apply_backing_offset: an index the step cannot
                // translate may name any element.
                fn shift(cells: &mut [CellSelector], step: Option<u128>) {
                    if step == Some(0) {
                        return;
                    }
                    if let Some(CellSelector::Index(index)) = cells.last_mut() {
                        *index = match (step, &*index) {
                            (Some(step), CellIndex::Constant(constant)) => constant
                                .checked_add(step)
                                .map_or(CellIndex::Any, CellIndex::Constant),
                            _ => CellIndex::Any,
                        };
                    }
                }
                match load_origins.get(&value) {
                    Some(LoadOrigin::Value(next)) => {
                        pending.push(Pending::Value(*next, (choices, cells)));
                    }
                    Some(LoadOrigin::BackingStore {
                        source: next,
                        offset,
                    }) => {
                        shift(&mut cells, step(offset));
                        pending.push(Pending::Value(*next, (choices, cells)));
                    }
                    Some(LoadOrigin::Unique(next)) => {
                        pending.push(Pending::Location(*next, (choices, cells)));
                    }
                    Some(LoadOrigin::BackingStoreAlternative {
                        source,
                        offset,
                        allocation,
                    }) => {
                        let mut allocation_choices = choices.clone();
                        allocation_choices.push(AlternativeChoice::Allocation);
                        let mut source_choices = choices;
                        source_choices.push(AlternativeChoice::Source);
                        let allocation_cells = cells.clone();
                        shift(&mut cells, step(offset));
                        pending.push(Pending::Value(*source, (source_choices, cells)));
                        at_root(
                            prefix_stores,
                            CellRoot::Allocation(*allocation),
                            (allocation_choices, allocation_cells),
                            &mut pending,
                            &mut plans,
                        );
                    }
                    // A definition set met again on this walk is a copy cycle. The
                    // plan stops there, and its walk stops on a summarized root.
                    Some(LoadOrigin::Definitions(_)) if !expanded.insert(value) => {
                        truncated = true;
                        plans.push(choices);
                    }
                    Some(LoadOrigin::Definitions(sources)) => {
                        for (position, source) in sources.iter().enumerate() {
                            let mut definition_choices = choices.clone();
                            definition_choices.push(AlternativeChoice::Definition(position));
                            pending
                                .push(Pending::Value(*source, (definition_choices, cells.clone())));
                        }
                    }
                    Some(LoadOrigin::ProcedurePort(kind)) => at_root(
                        prefix_stores,
                        CellRoot::Port(*kind),
                        (choices, cells),
                        &mut pending,
                        &mut plans,
                    ),
                    Some(LoadOrigin::Separated(_) | LoadOrigin::SeparatedDefinitions(_))
                    | Some(LoadOrigin::SeparatedPending { .. })
                    | Some(LoadOrigin::Ambiguous)
                    | None => at_root(
                        prefix_stores,
                        CellRoot::Value(value),
                        (choices, cells),
                        &mut pending,
                        &mut plans,
                    ),
                }
            }
        }
        if plans.len() >= limit {
            truncated |= !pending.is_empty();
            break;
        }
    }
    if plans.is_empty() {
        plans.push(Vec::new());
    }
    (plans, truncated)
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
            | AccessSelector::Field(_)
            | AccessSelector::Property(_) => false,
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
        | AccessPathRoot::External(_)
        | AccessPathRoot::RuntimeObject(_)
        | AccessPathRoot::FieldPath { .. }
        | AccessPathRoot::CallSubstitution { .. } => None,
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

fn possible_dereference_store_targets(
    procedure: &ProcedureHandle,
    location: MemoryLocationId,
    binding_origins: Option<&BindingOriginIndex>,
) -> Vec<MemoryLocationId> {
    let Some(binding_origins) = binding_origins else {
        return Vec::new();
    };
    let Some(MemoryLocationKind::Dereference { address }) = procedure
        .semantics()
        .memory_location(location)
        .map(|location| &location.kind)
    else {
        return Vec::new();
    };
    let origins = binding_origins.addressed_binding_origins(*address);
    if origins.unique_binding().is_some() {
        return Vec::new();
    }
    let bindings = if origins.is_complete() {
        origins.bindings().iter().copied().collect::<Vec<_>>()
    } else {
        binding_origins
            .address_taken_binding_set()
            .iter()
            .copied()
            .collect()
    };
    let mut targets = bindings
        .into_iter()
        .filter_map(|binding| binding_origins.binding_memory_location(binding))
        .collect::<Vec<_>>();
    targets.sort_unstable();
    targets.dedup();
    targets
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
    container_endpoint_at(location, first_index, limits).map(Some)
}

/// The container prefix consumed by an element read, including keyed elements
/// only when the language's Property vocabulary denotes container subscripts.
fn element_read_container_endpoint(
    procedure: &ProcedureHandle,
    memory: MemoryLocationId,
    location: &AbstractLocation,
    limits: crate::analyzer::semantic::OracleLimits,
) -> Result<Option<ValueFlowEndpoint>, SemanticProviderError> {
    if !keyed_property_reads_container_element(procedure, memory) {
        return indexed_container_endpoint(location, limits);
    }
    let Some(first_element) = location.path().selectors().iter().position(|selector| {
        matches!(
            selector,
            AccessSelector::Index(_) | AccessSelector::Property(_)
        )
    }) else {
        return Ok(None);
    };
    container_endpoint_at(location, first_element, limits).map(Some)
}

fn container_endpoint_at(
    location: &AbstractLocation,
    first_element: usize,
    limits: crate::analyzer::semantic::OracleLimits,
) -> Result<ValueFlowEndpoint, SemanticProviderError> {
    let selectors = location.path().selectors();
    if first_element == 0 {
        return access_root_endpoint(location, limits);
    }
    let path = AccessPath::bounded(
        location.path().root().clone(),
        selectors[..first_element].to_vec(),
        location.path().tail(),
        limits,
    )
    .map_err(|error| internal_contract("invalid container access path", error))?;
    let container = AbstractLocation::new(location.object().clone(), path)
        .map_err(|error| internal_contract("invalid container location", error))?;
    Ok(ValueFlowEndpoint::Location(Box::new(container)))
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

/// The value the language lowering subscripted, for an index access or a
/// keyed property access whose language treats it as a container element.
///
/// The container endpoint above is rooted at the access path's *origin*, which
/// the resolver walks back through assignments; this is the array expression as
/// it stands at the access itself. Both are needed: the origin is what a store
/// into an unprovable subscript marks, and the subscripted expression is what
/// carries a label that entered the array downstream of its origin -- the
/// `String[] values = request.getParameterValues(...)` shape the OWASP corpus is
/// built from.
fn element_read_base_value(
    procedure: &ProcedureHandle,
    location: MemoryLocationId,
) -> Result<Option<ValueHandle>, SemanticProviderError> {
    let Some(row) = procedure.semantics().memory_location(location) else {
        return Ok(None);
    };
    let base = match row.kind {
        MemoryLocationKind::Index { base, .. } => base,
        MemoryLocationKind::Property { base, .. }
            if keyed_property_reads_container_element(procedure, location) =>
        {
            base
        }
        _ => return Ok(None),
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
    has_stored_contents: bool,
    store_locations: HashSet<MemoryLocationId>,
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
    fn record_store(&mut self, endpoint: &ValueFlowEndpoint, store_location: MemoryLocationId) {
        if let ValueFlowEndpoint::Location(location) = endpoint
            && let Some(index) = self.seen.get(location.as_ref())
        {
            self.elements[*index].has_stored_contents = true;
            self.elements[*index].store_locations.insert(store_location);
        }
    }

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
                    has_stored_contents: false,
                    store_locations: HashSet::new(),
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
        AccessPathRootDraft::ProcedurePort(kind) => {
            let port = ProcedurePortHandle::new(procedure.clone(), kind)
                .map_err(|error| internal_contract("invalid procedure port root", error))?;
            (
                AbstractObjectIdentity::ProcedurePort(port.clone()),
                AccessPathRoot::ProcedurePort(port),
            )
        }
        AccessPathRootDraft::Allocation(allocation) => {
            let allocation = procedure.allocation_handle(allocation).ok_or_else(|| {
                SemanticProviderError::internal("alternative allocation root is stale")
            })?;
            (
                AbstractObjectIdentity::Allocation(allocation.clone()),
                AccessPathRoot::Allocation(allocation),
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
            AccessSelectorDraft::Property(key) => Ok(AccessSelector::Property(key)),
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

/// Materialize the source-backed arm of a bounded backing-store alternative.
/// The source value is first canonicalized through local copies and formal
/// origins. The alternative event itself names the complete source backing;
/// its offset is composed only when a downstream access path is resolved.
/// Dynamic or joined existing offsets retain a summary tail so the candidate
/// remains a useful may-path without becoming an exact separation claim.
fn backing_store_alternative_location(
    procedure: &ProcedureHandle,
    source: ValueId,
    offset: BackingStoreOffset,
    load_origins: &HashMap<ValueId, LoadOrigin>,
    exact_integer: impl Fn(ValueId) -> Option<u128>,
    limits: crate::analyzer::semantic::OracleLimits,
) -> Result<(AbstractLocation, bool), SemanticProviderError> {
    let mut visited = HashSet::new();
    let mut choice_index = 0usize;
    let origin = walk_value_origin(
        load_origins,
        source,
        &mut visited,
        exact_integer,
        &[],
        &mut choice_index,
    );
    let (root, prior_offset, mut summarized) = match origin {
        ValueOriginWalk::Root {
            value,
            offset,
            summarized,
        } => (AccessPathRootDraft::Value(value), offset, summarized),
        ValueOriginWalk::Port {
            kind,
            offset,
            summarized,
        } => (AccessPathRootDraft::ProcedurePort(kind), offset, summarized),
        ValueOriginWalk::Allocation {
            allocation,
            offset,
            summarized,
        } => (
            AccessPathRootDraft::Allocation(allocation),
            offset,
            summarized,
        ),
        ValueOriginWalk::Load { value, offset, .. } => {
            (AccessPathRootDraft::Value(value), offset, true)
        }
    };

    let mut selectors = Vec::new();
    // The alternative event maps the complete source backing. Its own offset
    // is applied only when a downstream access path composes with this value;
    // an index here would incorrectly narrow the alternative relation itself.
    let _ = offset;
    match prior_offset {
        Some(prior) => {
            if prior != 0 {
                selectors.push(AccessSelectorDraft::Index {
                    value: None,
                    constant: Some(prior),
                    identity: crate::analyzer::semantic::IndexedLocationIdentity::Element,
                });
            }
        }
        None => append_any_selector(&mut selectors, &mut summarized),
    }
    materialize_abstract_location(
        procedure,
        AccessPathDraft {
            original_cell: None,
            root,
            selectors,
            tail: if summarized {
                AccessPathTail::Summary
            } else {
                AccessPathTail::Exact
            },
            opaque_prefix: false,
        },
        limits,
    )
}

fn append_any_selector(selectors: &mut Vec<AccessSelectorDraft>, summarized: &mut bool) {
    selectors.push(AccessSelectorDraft::Index {
        value: None,
        constant: None,
        identity: crate::analyzer::semantic::IndexedLocationIdentity::Element,
    });
    *summarized = true;
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
#[doc(hidden)]
pub enum StrongUpdateStop {
    Interruption(Interruption),
    Provider(SemanticProviderError),
}

#[allow(clippy::too_many_arguments)]
fn materialize_flow_snapshot(
    procedure: &ProcedureHandle,
    context: &OracleCallContext,
    drafts: Vec<FlowRelationDraft>,
    coverage: CandidateCoverage,
    limits: crate::analyzer::semantic::OracleLimits,
    discharged_gaps: Vec<crate::analyzer::semantic::SemanticGapId>,
    unproven_go_builtin_assumptions: bool,
    member_receivers: Vec<crate::analyzer::semantic::MemberReceiverFlow>,
    collection_cells: Vec<crate::analyzer::semantic::CollectionCellBinding>,
    execution_dependent: bool,
) -> Result<ValueFlowSnapshot, SemanticProviderError> {
    let records = drafts
        .iter()
        .map(|draft| {
            let record = OracleRelationRecord::new(
                OracleRelationKind::ValueFlow,
                draft.evidence.clone(),
                limits,
            )?;
            Ok(match draft.memory_origin {
                Some(origin) => {
                    record.with_memory_origin(origin, draft.payload.memory_seal(&origin, context))
                }
                None => record,
            })
        })
        .collect::<Result<Vec<_>, crate::analyzer::semantic::OracleContractError>>()
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
            let id = arena
                .handle(id)
                .expect("value-flow record was inserted into the arena");
            let mut relation = match draft.memory_origin {
                Some(_) => {
                    let seal = id
                        .record()
                        .memory_origin_binding()
                        .expect("the trusted draft attested its memory origin")
                        .seal();
                    ValueFlowRelation::sealed(id, draft.payload, seal)
                }
                None => ValueFlowRelation::unsealed(id, draft.payload),
            };
            relation.original_cell = draft.original_cell;
            Ok(relation)
        })
        .collect::<Result<Vec<_>, SemanticProviderError>>()?;
    ValueFlowSnapshot::with_member_receivers_and_discharged_gaps(
        procedure.clone(),
        context.clone(),
        relations,
        coverage,
        limits,
        discharged_gaps,
        member_receivers,
        collection_cells,
        execution_dependent,
    )
    .map(|snapshot| snapshot.with_unproven_go_builtin_assumptions(unproven_go_builtin_assumptions))
    .map_err(|error| internal_contract("invalid value-flow snapshot", error))
}

fn publish_flow_outcome(
    mut snapshot: ValueFlowSnapshot,
    interrupted: Option<Interruption>,
    has_unproven_relation: bool,
    gap_quality: Option<GapOutcomeQuality>,
    work: SemanticWork,
) -> SemanticOutcome<ValueFlowSnapshot> {
    if interrupted.is_some() || snapshot.coverage() == CandidateCoverage::Truncated {
        snapshot.mark_execution_dependent();
    }
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

#[doc(hidden)]
pub enum CallBindingDraft {
    Receiver {
        relation: usize,
        actual: ValueHandle,
        formal: ProcedurePortHandle,
    },
    ImplicitArgument {
        relation: usize,
        formal_ordinal: u32,
        source: ValueHandle,
        formal: ProcedurePortHandle,
        kind: ImplicitArgumentKind,
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

#[doc(hidden)]
pub struct BindingBuild {
    relations: Vec<BindingRelationDraft>,
    #[doc(hidden)]
    pub bindings: Vec<CallBindingDraft>,
    retained_evidence: usize,
    #[doc(hidden)]
    pub retained_entries: usize,
    #[doc(hidden)]
    pub open: bool,
    #[doc(hidden)]
    pub truncated: bool,
    #[doc(hidden)]
    pub has_unproven_relation: bool,
    #[doc(hidden)]
    pub gap_quality: Option<GapOutcomeQuality>,
}

impl BindingBuild {
    #[doc(hidden)]
    pub fn new(open: bool) -> Self {
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

    #[doc(hidden)]
    pub fn can_retain(
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

    #[doc(hidden)]
    pub fn push_relation(&mut self, evidence: Vec<EvidenceHandle>) -> usize {
        let index = self.relations.len();
        self.has_unproven_relation |= !proven_complete(&evidence);
        self.retained_evidence = self.retained_evidence.saturating_add(evidence.len());
        self.relations.push(BindingRelationDraft { evidence });
        index
    }
}

#[doc(hidden)]
pub fn materialize_call_bindings(
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
            CallBindingDraft::ImplicitArgument {
                relation: relation_id,
                formal_ordinal,
                source,
                formal,
                kind,
            } => Ok(CallBinding::ImplicitArgument {
                relation: relation(relation_id)?,
                formal_ordinal,
                source,
                formal,
                kind,
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

#[doc(hidden)]
pub fn interrupted_call_bindings(
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

#[doc(hidden)]
pub fn returned_callable_interruption(
    request: &mut SemanticRequest<'_>,
    staged: WorkStager,
    interruption: Interruption,
) -> SemanticOutcome<Option<LocalCallableTarget>> {
    *request.budget = staged.budget;
    let work = staged.work;
    match interruption {
        Interruption::Budget(exceeded) => SemanticOutcome::ExceededBudget {
            partial: None,
            exceeded,
            work,
        },
        Interruption::Cancelled => SemanticOutcome::Cancelled {
            partial: None,
            work,
        },
    }
}

/// A refuted returned-callable question: no callable is proven, and the work
/// the probe already spent stays charged to the caller's request.
#[doc(hidden)]
pub fn returned_callable_refusal(
    request: &mut SemanticRequest<'_>,
    staged: &WorkStager,
) -> SemanticOutcome<Option<LocalCallableTarget>> {
    *request.budget = staged.budget.clone();
    SemanticOutcome::Complete {
        value: None,
        work: staged.work,
    }
}

/// One exact local callable creation and its environment slots.
///
/// The closure is the exact body an invocation of the callable dispatches to.
/// Each slot is the structured destination of one `CaptureBind` row the callee
/// published for that creation, so a consumer can name the closure's captured
/// storage without reading the source again.
#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct LocalCallableTarget {
    #[doc(hidden)]
    pub closure: ProcedureHandle,
    #[doc(hidden)]
    pub creation: ValueHandle,
    /// The exact creation event in `creation.procedure()`.
    #[doc(hidden)]
    pub creation_point: ProgramPointId,
    #[doc(hidden)]
    pub creation_event_index: usize,
    #[doc(hidden)]
    pub captures: Box<[MemoryLocationId]>,
    #[doc(hidden)]
    pub capture_bindings: Box<[CaptureBinding]>,
}

/// Result of a source-backed gap discharge proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GapDischargeVerdict {
    Discharged,
    Undischarged,
    RefusedByRequestLimit,
}

impl From<bool> for GapDischargeVerdict {
    fn from(discharged: bool) -> Self {
        if discharged {
            Self::Discharged
        } else {
            Self::Undischarged
        }
    }
}

/// The answers the value-flow relation projection takes from outside the
/// procedure's own IR.
///
/// [`project_procedure_relations`] reads the procedure's IR itself and asks
/// the host for everything else. The workspace oracle answers from the whole
/// workspace at query time; a file-local host answers from one file at parse
/// time. A host that cannot prove a discharge or a strong update answers
/// `false`, which keeps the gap open or the store a weak update.
#[doc(hidden)]
pub trait RelationProjectionHost {
    /// Select receiver semantics from the exact member declaration bound by
    /// dispatch. Parse-time hosts abstain without inventing a method kind.
    fn member_receiver_flow(
        &self,
        call: &crate::analyzer::semantic::CallSiteHandle,
        _context: &OracleCallContext,
        _place: Option<ValueFlowEndpoint>,
        _request: &mut SemanticRequest<'_>,
        limits: OracleLimits,
    ) -> Result<SemanticOutcome<crate::analyzer::semantic::MemberReceiverFlow>, SemanticProviderError>
    {
        let value = crate::analyzer::semantic::MemberReceiverFlow::new(
            call.clone(),
            None,
            Vec::new(),
            limits,
        )
        .map_err(|error| internal_contract("invalid open member receiver", error))?;
        Ok(SemanticOutcome::Complete {
            value,
            work: SemanticWork::default(),
        })
    }

    /// Runtime-value refinements for JS, TS and Python procedures.
    fn runtime_refinements(
        &self,
        procedure: &ProcedureHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<RuntimeKeyedReadResult>, SemanticProviderError>;

    /// Whether no same-package declaration shadows a Go predeclared builtin
    /// the lowering assumed. `false` keeps the procedure open.
    fn go_builtin_scope_absent(
        &self,
        procedure: &ProcedureHandle,
        builtin: crate::analyzer::semantic::GoPredeclaredBuiltin,
        limit: usize,
        staged: &mut WorkStager,
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> Result<bool, Interruption>;

    /// The catch-binding events whose call cannot throw what the catch
    /// parameter catches, keyed by point and event index.
    fn refuted_catch_bindings(
        &self,
        procedure: &ProcedureHandle,
        request: &SemanticRequest<'_>,
    ) -> Result<HashSet<(ProgramPointId, usize)>, SemanticProviderError>;

    /// Whether a canonical-index gap is discharged because its base is one
    /// exact object in this activation.
    #[allow(clippy::too_many_arguments)]
    fn canonical_index_identity_discharged(
        &self,
        procedure: &ProcedureHandle,
        context: &OracleCallContext,
        gap: &crate::analyzer::semantic::SemanticGap,
        bases: &LocalStoreBases,
        staged: &mut WorkStager,
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> Result<bool, StrongUpdateStop>;

    /// Whether a field-memory gap is a read of a constant field on an
    /// external type.
    fn external_constant_field_read_discharged(
        &self,
        gap: &crate::analyzer::semantic::SemanticGap,
        procedure: &ProcedureHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<
        crate::analyzer::semantic::workspace_oracle::value_flow::GapDischargeVerdict,
        SemanticProviderError,
    >;

    /// Whether an implicit-drop gap is discharged because the procedure's
    /// drops run no user code. `inert` memoizes the per-procedure answer
    /// across the gaps of one sweep.
    fn inert_drop_glue_discharged(
        &self,
        gap: &crate::analyzer::semantic::SemanticGap,
        procedure: &ProcedureHandle,
        request: &mut SemanticRequest<'_>,
        inert: &mut Option<bool>,
    ) -> Result<
        crate::analyzer::semantic::workspace_oracle::value_flow::GapDischargeVerdict,
        SemanticProviderError,
    >;

    fn residual_conversion_discharged(
        &self,
        _gap: &crate::analyzer::semantic::SemanticGap,
        _procedure: &ProcedureHandle,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<
        crate::analyzer::semantic::workspace_oracle::value_flow::GapDischargeVerdict,
        SemanticProviderError,
    > {
        Ok(crate::analyzer::semantic::workspace_oracle::value_flow::GapDischargeVerdict::Undischarged)
    }

    /// Whether the active semantic models may publish a complete
    /// collection-flow contract. A false answer promises that
    /// [`Self::collection_flow_contract`] returns `None` for every call in
    /// this projection, so the closed-container proof can decide every
    /// allocation is unbound without resolving its calls (#11092). Parse-time
    /// hosts abstain.
    fn may_have_complete_collection_flow_contracts(&self) -> bool {
        false
    }

    /// The exact class a constructor call instantiates, when dispatch proves
    /// it (#10989). Parse-time hosts abstain.
    fn constructed_class(
        &self,
        _call: &crate::analyzer::semantic::CallSiteHandle,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<Option<Box<str>>, SemanticProviderError> {
        Ok(None)
    }

    /// The complete collection-flow contract of the member `call` selects on
    /// a receiver whose exact runtime class is `receiver_class` (#10989).
    ///
    /// The caller proves the receiver's class; the host answers only when
    /// dispatch names exactly one external member owned by that class, so an
    /// unknown override cannot be selected instead. Parse-time hosts abstain:
    /// pack content is not part of the identity of stored partial-flow rows,
    /// so it must not reach them.
    fn collection_flow_contract(
        &self,
        _call: &crate::analyzer::semantic::CallSiteHandle,
        _receiver_class: &str,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<
        Option<Arc<crate::analyzer::semantic_model::CollectionFlowContract>>,
        SemanticProviderError,
    > {
        Ok(None)
    }

    /// Whether a field or index memory gap is retired because the workspace
    /// resolver proves that the location's member names one declaration in
    /// this procedure (#9402). `proven` memoizes the procedure's retired gaps
    /// across the gaps of one sweep. Parse-time hosts have no resolver and
    /// abstain.
    fn resolved_member_identity_discharged(
        &self,
        _gap: &crate::analyzer::semantic::SemanticGap,
        _procedure: &ProcedureHandle,
        _request: &mut SemanticRequest<'_>,
        _proven: &mut Option<Vec<SemanticGapId>>,
    ) -> Result<
        crate::analyzer::semantic::workspace_oracle::value_flow::GapDischargeVerdict,
        SemanticProviderError,
    > {
        Ok(crate::analyzer::semantic::workspace_oracle::value_flow::GapDischargeVerdict::Undischarged)
    }

    /// Whether the heap oracle certifies one exact store as a strong update.
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
        binding_origins: Option<&BindingOriginIndex>,
        staged: &mut WorkStager,
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> Result<bool, StrongUpdateStop>;
}

/// Project one procedure's value-flow relations from its IR.
///
/// Every answer that does not come from the procedure's own IR comes from
/// `host`. The function has no access to a workspace, so the same pass runs
/// at query time through [`WorkspaceSemanticOracle`] and at parse time
/// through a file-local host.
/// The gap sweep of one procedure: which value-flow gaps stay relevant after
/// the host's discharge predicates and the procedure's own proofs.
#[doc(hidden)]
pub struct GapSweep {
    pub execution_dependent: bool,
    #[doc(hidden)]
    pub open: bool,
    /// Whether a recorded Go builtin assumption survived the package proof.
    pub unproven_go_builtin_assumptions: bool,
    #[doc(hidden)]
    pub relevant_gaps: Vec<SemanticGapId>,
    pub(crate) gap_quality: Option<GapOutcomeQuality>,
    pub(crate) discharged_gaps: Vec<SemanticGapId>,
    #[doc(hidden)]
    pub interrupted: Option<Interruption>,
    /// The per-procedure store bases the sweep derived, if any store asked.
    pub(crate) store_bases: Option<LocalStoreBases>,
}

/// The query-time proof shared by snapshot projection and openness sweeps.
/// The host owns the workspace read; its bounded lookup charges work and
/// observes cancellation through the supplied stager and token.
fn unproven_go_builtin_assumptions(
    host: &dyn RelationProjectionHost,
    procedure: &ProcedureHandle,
    limit: usize,
    staged: &mut WorkStager,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
) -> Result<bool, Interruption> {
    let mut open = false;
    for builtin in procedure
        .artifact()
        .go_predeclared_builtin_assumptions()
        .iter()
        .copied()
    {
        if !host.go_builtin_scope_absent(procedure, builtin, limit, staged, cancellation)? {
            open = true;
        }
    }
    Ok(open)
}

/// The gap sweep of the relation projection. Every gap that
/// impacts value flow is tested against the host's discharge predicates. The
/// projection and the workspace openness query both call it, so both answer
/// from one set of predicates.
#[doc(hidden)]
pub fn sweep_procedure_gaps(
    host: &dyn RelationProjectionHost,
    procedure: &ProcedureHandle,
    context: &OracleCallContext,
    limits: OracleLimits,
    runtime_reads: Option<&RuntimeKeyedReadResult>,
    staged: &mut WorkStager,
    request: &mut SemanticRequest<'_>,
) -> Result<GapSweep, SemanticProviderError> {
    let mut store_bases: Option<LocalStoreBases> = None;
    let mut execution_dependent = false;
    let mut open = false;
    let mut relevant_gaps = Vec::new();
    let mut gap_quality = None;
    let mut discharged_gaps = Vec::new();
    let mut interrupted = None;
    let unproven_go_builtin_assumptions = match unproven_go_builtin_assumptions(
        host,
        procedure,
        limits.dispatch_targets(),
        staged,
        request.cancellation,
    ) {
        Ok(open) => open,
        Err(stop) => {
            interrupted = Some(stop);
            true
        }
    };
    if unproven_go_builtin_assumptions {
        open = true;
        gap_quality = Some(GapOutcomeQuality::Unknown);
    }
    if interrupted.is_none() {
        let abort_user_code = abort_paths_run_user_code(procedure.semantics());
        let mut inert_drops = None;
        let mut member_identities = None;
        for gap in procedure.semantics().gaps() {
            if request.cancellation.is_cancelled() {
                interrupted = Some(Interruption::Cancelled);
                break;
            }
            staged.charge_work(SemanticWork {
                gaps: 1,
                ..SemanticWork::default()
            });
            let impacts_value_flow = gap_impacts_value_flow(gap);
            let canonical_index_identity_discharged =
                if gap.discharge == SemanticGapDischarge::CanonicalIndexIdentity {
                    let bases = store_bases
                        .get_or_insert_with(|| LocalStoreBases::derive(procedure.semantics()));
                    match host.canonical_index_identity_discharged(
                        procedure,
                        context,
                        gap,
                        bases,
                        staged,
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
                && !runtime_reads.is_some_and(|reads| reads.discharges(gap.id))
                && !declared_proven_target_discharges_gap(procedure.semantics(), gap)
                && !constructor_call_gap_is_discharged(procedure.semantics(), gap)
                && !canonical_index_identity_discharged
                && !unobserved_local_heap_gap_is_discharged(procedure, gap)
                && !implicit_abort_gap_is_discharged(gap, abort_user_code)
                && {
                    let before = staged.budget.used();
                    let relevant = {
                        let mut nested = staged.request(request.cancellation);
                        let mut relevant = true;
                        for predicate in 0..4 {
                            let verdict = match predicate {
                                0 => host.residual_conversion_discharged(
                                    gap,
                                    procedure,
                                    &mut nested,
                                )?,
                                1 => host.external_constant_field_read_discharged(
                                    gap,
                                    procedure,
                                    &mut nested,
                                )?,
                                2 => host.inert_drop_glue_discharged(
                                    gap,
                                    procedure,
                                    &mut nested,
                                    &mut inert_drops,
                                )?,
                                _ => host.resolved_member_identity_discharged(
                                    gap,
                                    procedure,
                                    &mut nested,
                                    &mut member_identities,
                                )?,
                            };
                            match verdict {
                                GapDischargeVerdict::Discharged => {
                                    relevant = false;
                                    break;
                                }
                                GapDischargeVerdict::Undischarged => {}
                                GapDischargeVerdict::RefusedByRequestLimit => {
                                    execution_dependent = true
                                }
                            }
                        }
                        relevant
                    };
                    staged.work = staged
                        .work
                        .conservative_add(staged.budget.used().saturating_sub(before));
                    relevant
                };
            if impacts_value_flow && !relevant {
                discharged_gaps.push(gap.id);
            }
            open |= relevant;
            if relevant {
                relevant_gaps.push(gap.id);
                execution_dependent |= gap.kind == SemanticGapKind::ExceededBudget;
                gap_quality = merge_gap_quality(gap_quality, gap);
            }
        }
    }
    Ok(GapSweep {
        execution_dependent: execution_dependent || interrupted.is_some(),
        open,
        unproven_go_builtin_assumptions,
        relevant_gaps,
        gap_quality,
        discharged_gaps,
        interrupted,
        store_bases,
    })
}

/// Whether one procedure is open, decided from its gaps and the workspace
/// host's predicates with no relation projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcedureOpenness {
    pub open: bool,
    /// The gaps that keep the procedure open.
    pub relevant_gaps: Vec<SemanticGapId>,
}

impl brokk_bifrost_core::retention_budget::RetainedBytes for ProcedureOpenness {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(self.relevant_gaps.capacity() * std::mem::size_of::<SemanticGapId>())
    }
}

#[doc(hidden)]
pub fn interrupted_openness(
    stop: Interruption,
    work: SemanticWork,
) -> SemanticOutcome<ProcedureOpenness> {
    match stop {
        Interruption::Cancelled => SemanticOutcome::Cancelled {
            partial: None,
            work,
        },
        Interruption::Budget(exceeded) => SemanticOutcome::ExceededBudget {
            partial: None,
            exceeded,
            work,
        },
    }
}

#[doc(hidden)]
pub fn project_procedure_relations(
    host: &dyn RelationProjectionHost,
    procedure: &ProcedureHandle,
    context: &OracleCallContext,
    limits: OracleLimits,
    request: &mut SemanticRequest<'_>,
) -> Result<SemanticOutcome<ValueFlowSnapshot>, SemanticProviderError> {
    if request.cancellation.is_cancelled() {
        return Ok(SemanticOutcome::Cancelled {
            partial: None,
            work: SemanticWork::default(),
        });
    }
    let mut staged = WorkStager::new(request);
    staged.charge_work(SemanticWork {
        procedures: 1,
        ..SemanticWork::default()
    });
    let mut interrupted = None;

    let runtime_outcome =
        host.runtime_refinements(procedure, &mut staged.request(request.cancellation))?;
    staged.work = staged.work.conservative_add(runtime_outcome.work());
    match &runtime_outcome {
        SemanticOutcome::Cancelled { .. } => interrupted = Some(Interruption::Cancelled),
        SemanticOutcome::ExceededBudget { exceeded, .. } => {
            interrupted = Some(Interruption::Budget(*exceeded))
        }
        _ => {}
    }
    let mut execution_dependent = !matches!(runtime_outcome, SemanticOutcome::Complete { .. });
    let runtime_reads = runtime_outcome.available_value();
    let mut open = value_flow_capabilities_are_open(procedure);
    let mut gap_quality = None;
    // Shared by the canonical-index base certificate and store strong
    // updates. Derive it lazily only when one of those questions exists.
    let mut store_bases: Option<LocalStoreBases> = None;
    // Pay for the CFG publication proof only when an exact direct cell
    // store actually asks for it. Ordinary value-only procedures need no
    // heap/local-store proof and must not pay for one.
    let mut local_overwrites: Option<HashSet<ProgramPointId>> = None;
    // #2545: every gap this sweep proves discharged (impacts value flow,
    // but a predicate proved it does not apply), so a downstream
    // consumer that re-examines this procedure's raw gap list -- most
    // notably `ValueFlowPlan`'s own "refinable" residual check, which has
    // no analyzer access and cannot re-run these predicates itself --
    // can see this sweep's own judgment instead of re-deriving (or
    // failing to re-derive) it. See `ValueFlowSnapshot::gap_is_discharged`.
    let mut discharged_gaps = Vec::new();
    let mut unproven_go_builtin_assumptions = !procedure
        .artifact()
        .go_predeclared_builtin_assumptions()
        .is_empty();
    if interrupted.is_none() {
        let sweep = sweep_procedure_gaps(
            host,
            procedure,
            context,
            limits,
            runtime_reads,
            &mut staged,
            request,
        )?;
        execution_dependent |= sweep.execution_dependent;
        store_bases = sweep.store_bases;
        open |= sweep.open;
        gap_quality = sweep.gap_quality;
        discharged_gaps = sweep.discharged_gaps;
        unproven_go_builtin_assumptions = sweep.unproven_go_builtin_assumptions;
        interrupted = sweep.interrupted;
    }

    // Catch bindings the language proves a call cannot reach are neither
    // origins nor relations (#2192).
    let refuted_bindings = if interrupted.is_none() {
        host.refuted_catch_bindings(procedure, request)?
    } else {
        HashSet::new()
    };

    // #2446: derived before the access-path origins, because a handler
    // binding is one of them. Nothing is derived for a procedure whose
    // adapter already selected every handler.
    let mut handler_bindings = HandlerBindings::default();
    if interrupted.is_none() {
        match HandlerBindings::derive(procedure, request.cancellation, |work| {
            staged.charge_work(work);
            Ok(())
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
        prefix_stores,
        whole_container_reads,
    } = if interrupted.is_none() {
        match procedure_value_facts(
            procedure,
            handler_bindings.binder_origins(),
            &refuted_bindings,
            request.cancellation,
            |work| {
                staged.charge_work(work);
                Ok(())
            },
        ) {
            Ok(facts) => facts,
            Err(stop) => {
                interrupted = Some(stop);
                ProcedureValueFacts {
                    load_origins: HashMap::new(),
                    prefix_stores: PrefixStores::default(),
                    whole_container_reads: HashSet::new(),
                }
            }
        }
    } else {
        ProcedureValueFacts {
            load_origins: HashMap::new(),
            prefix_stores: PrefixStores::default(),
            whole_container_reads: HashSet::new(),
        }
    };
    let binding_origins = BindingOriginIndex::from_semantics(procedure.semantics());
    let origins = ValueOriginFacts {
        load_origins: &load_origins,
        prefix_stores: &prefix_stores,
        binding_origins: Some(&binding_origins),
    };
    let exact_integer =
        |value| exact_unsigned_integer_origin(procedure.semantics(), &load_origins, value);

    let mut drafts = Vec::new();
    let mut retained_evidence = 0usize;
    let mut truncated = false;
    // A stored member of a returned join that the return projection could not
    // transport (#9766). It is a content gap, so the coverage is Open, but the
    // relation list lacks a relation, which the snapshot records for readers
    // that treat an Open snapshot's relations as complete.
    let mut untransported_return_member = false;
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
        staged.charge_work(SemanticWork {
            program_points: 1,
            ..SemanticWork::default()
        });
        for (event_index, event) in point.events.iter().enumerate() {
            if request.cancellation.is_cancelled() {
                interrupted = Some(Interruption::Cancelled);
                break 'points;
            }
            staged.charge_work(SemanticWork {
                events: 1,
                ..SemanticWork::default()
            });

            if refuted_bindings.contains(&(point.id, event_index)) {
                continue;
            }
            let mut access_path = None;
            let mut alternative_access_paths = Vec::new();
            let mut original_cell = None;
            let mut alternative_paths_truncated = false;
            let mut backing_store_candidates = false;
            let mut opaque_prefix = false;
            let relation_work = match &event.effect {
                SemanticEffect::Assignment { .. } | SemanticEffect::ValueFlow { .. } => {
                    Some(SemanticWork {
                        values: 2,
                        evidence: 1,
                        nested_entries: 1,
                        ..SemanticWork::default()
                    })
                }
                SemanticEffect::AsyncResume {
                    suspend,
                    kind: AsyncResumeKind::Normal,
                    result: Some(_),
                } if procedure.semantics().awaited_value(*suspend).is_some() => {
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
                    let (plans, plans_truncated) = alternative_choice_plans(
                        *location,
                        &load_origins,
                        &prefix_stores,
                        |id| {
                            procedure
                                .semantics()
                                .memory_location(id)
                                .map(|row| &row.kind)
                        },
                        exact_integer,
                        limits.provenance_records(),
                        request.cancellation,
                    );
                    let has_alternative = plans.iter().any(|plan| !plan.is_empty());
                    alternative_paths_truncated = plans_truncated;
                    backing_store_candidates = plans
                        .iter()
                        .flatten()
                        .any(|choice| choice.is_backing_store_candidate());
                    let mut paths = Vec::new();
                    if has_alternative {
                        for plan in plans {
                            match resolve_access_path_with_choice(
                                *location,
                                AccessPathResolutionInputs {
                                    origins,
                                    selector_limit: limits.access_path_length(),
                                    cancellation: request.cancellation,
                                    choices: &plan,
                                },
                                |id| {
                                    procedure
                                        .semantics()
                                        .memory_location(id)
                                        .map(|row| &row.kind)
                                },
                                exact_integer,
                                |work| {
                                    staged.charge_work(work);
                                    Ok(())
                                },
                            )? {
                                AccessPathResolution::Resolved(resolved) => paths.push(resolved),
                                AccessPathResolution::Interrupted(stop) => {
                                    interrupted = Some(stop);
                                    break 'points;
                                }
                            }
                        }
                    }
                    if !has_alternative {
                        match resolve_access_path(
                            *location,
                            origins,
                            limits.access_path_length(),
                            request.cancellation,
                            |id| {
                                procedure
                                    .semantics()
                                    .memory_location(id)
                                    .map(|row| &row.kind)
                            },
                            exact_integer,
                            |work| {
                                staged.charge_work(work);
                                Ok(())
                            },
                        )? {
                            AccessPathResolution::Resolved(resolved) => paths.push(resolved),
                            AccessPathResolution::Interrupted(stop) => {
                                interrupted = Some(stop);
                                break 'points;
                            }
                        }
                    }
                    opaque_prefix = paths.iter().any(|path| path.opaque_prefix);
                    let mut resolved = paths.remove(0);
                    if matches!(event.effect, SemanticEffect::MemoryLoad { .. })
                        && let Some(original) = resolved.original_cell.take()
                    {
                        original_cell =
                            Some(materialize_abstract_location(procedure, *original, limits)?.0);
                    }
                    alternative_access_paths = paths;
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
                                origins,
                                limits.access_path_length(),
                                request.cancellation,
                                |id| {
                                    procedure
                                        .semantics()
                                        .memory_location(id)
                                        .map(|row| &row.kind)
                                },
                                exact_integer,
                                |work| {
                                    staged.charge_work(work);
                                    Ok(())
                                },
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
                SemanticEffect::CallContinuation {
                    call_site,
                    kind: CallContinuationKind::Exceptional,
                } if exceptional_continuation_thrown(procedure, *call_site).is_some() => {
                    Some(SemanticWork {
                        values: 1,
                        evidence: 1,
                        nested_entries: 1,
                        ..SemanticWork::default()
                    })
                }
                SemanticEffect::Entry
                | SemanticEffect::NormalExit
                | SemanticEffect::ExceptionalExit
                | SemanticEffect::AggregateInitializer { .. }
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
            if drafts.len() >= limits.provenance_records()
                || retained_evidence >= limits.evidence_handles()
            {
                truncated = true;
                break 'points;
            }
            if let Err(stop) = staged.admit(relation_work) {
                interrupted = Some(stop);
                break 'points;
            }
            if matches!(
                event.effect,
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::BackingStoreAlternative { .. },
                    ..
                }
            ) && let Err(stop) = staged.admit(SemanticWork {
                values: 2,
                allocations: 1,
                nested_entries: 2,
                ..SemanticWork::default()
            }) {
                interrupted = Some(stop);
                break 'points;
            }

            let evidence = evidence_handle(procedure, event.evidence)?;
            let alternative_relation = matches!(
                &event.effect,
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::BackingStoreAlternative { .. },
                    ..
                }
            );
            let (proof, mut completeness) = evidence_quality(std::slice::from_ref(&evidence));
            // The arms of a definition set are exhaustive, so publishing every
            // one of them is the complete answer. Only a backing-store
            // candidate, which may name storage the access never touches,
            // leaves the relation partial.
            if alternative_relation || backing_store_candidates || alternative_paths_truncated {
                completeness = EvidenceCompleteness::Partial(
                    "backing-store alternative retains both access-path candidates".into(),
                );
                open = true;
            }
            // A store to a cell the access continues through cannot be
            // followed on at least one candidate path, so the members it
            // stored cannot be proven absent from the read.
            if opaque_prefix {
                completeness = EvidenceCompleteness::Partial(
                    "a store to a prefix of the access path cannot be followed".into(),
                );
                open = true;
            }
            // An access with more than one candidate target writes only one of
            // them, so none of its stores may overwrite what a target held.
            let single_target = alternative_access_paths.is_empty() && !alternative_paths_truncated;
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
                memory_role: Option<MemoryRelationRole>,
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
                    ValueFlowEndpoint::for_value(value_handle(procedure, *value)?),
                    ValueFlowEndpoint::for_value(value_handle(procedure, *target)?),
                    false,
                ),
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::BackingStoreAlternative { offset, allocation },
                    source,
                    target,
                } => {
                    let (source_location, source_summary) = backing_store_alternative_location(
                        procedure,
                        *source,
                        *offset,
                        &load_origins,
                        exact_integer,
                        limits,
                    )?;
                    let allocation = procedure.allocation_handle(*allocation).ok_or_else(|| {
                        SemanticProviderError::internal(
                            "backing-store alternative allocation is stale",
                        )
                    })?;
                    let allocation_location = allocation_location(allocation, limits)?;
                    let target = ValueFlowEndpoint::Value(value_handle(procedure, *target)?);
                    smashed.push(DerivedRelation {
                        kind: ValueFlowRelationKind::Assignment,
                        memory_role: None,
                        source: ValueFlowEndpoint::Location(Box::new(allocation_location)),
                        target: target.clone(),
                        quality: Some((
                            ProofStatus::Unproven(
                                "backing-store alternative has two runtime candidates".into(),
                            ),
                            EvidenceCompleteness::Partial(
                                "backing-store alternative retains both candidates".into(),
                            ),
                        )),
                    });
                    (
                        ValueFlowRelationKind::Assignment,
                        ValueFlowEndpoint::Location(Box::new(source_location)),
                        target,
                        source_summary,
                    )
                }
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
                    ValueFlowEndpoint::for_value(value_handle(procedure, *source)?),
                    ValueFlowEndpoint::for_value(value_handle(procedure, *target)?),
                    false,
                ),
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::OwnershipUnknown,
                    source,
                    target,
                } => (
                    ValueFlowRelationKind::OwnershipUnknown,
                    ValueFlowEndpoint::for_value(value_handle(procedure, *source)?),
                    ValueFlowEndpoint::for_value(value_handle(procedure, *target)?),
                    false,
                ),
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::ReferenceBoxing | ValueFlowKind::ReferenceUnboxing,
                    source,
                    target,
                } => (
                    ValueFlowRelationKind::LanguageDefined,
                    ValueFlowEndpoint::for_value(value_handle(procedure, *source)?),
                    ValueFlowEndpoint::for_value(value_handle(procedure, *target)?),
                    false,
                ),
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Parameter,
                    source,
                    target,
                } => (
                    ValueFlowRelationKind::Parameter,
                    ValueFlowEndpoint::for_value(value_handle(procedure, *source)?),
                    ValueFlowEndpoint::for_value(value_handle(procedure, *target)?),
                    false,
                ),
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Receiver,
                    source,
                    target,
                } => (
                    ValueFlowRelationKind::Receiver,
                    ValueFlowEndpoint::for_value(value_handle(procedure, *source)?),
                    ValueFlowEndpoint::for_value(value_handle(procedure, *target)?),
                    false,
                ),
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Return,
                    source,
                    ..
                } => (
                    ValueFlowRelationKind::NormalReturn,
                    ValueFlowEndpoint::Value(value_handle(procedure, *source)?),
                    ValueFlowEndpoint::Port(ProcedurePortHandle::normal_return(procedure.clone())),
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
                    kind:
                        ValueFlowKind::LanguageDefined
                        | ValueFlowKind::ByValueCapture
                        | ValueFlowKind::IntegerOffset { .. },
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
                    let allocation = procedure.allocation_handle(*allocation).ok_or_else(|| {
                        SemanticProviderError::internal("allocation effect has a stale ID")
                    })?;
                    let row = procedure
                        .semantics()
                        .allocation(allocation.id())
                        .expect("allocation handle is validated");
                    (
                        ValueFlowRelationKind::Allocation,
                        ValueFlowEndpoint::Location(Box::new(allocation_location(
                            allocation, limits,
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
                        limits,
                    )?;
                    let unproven_index = summary || location_has_unproven_exact_index(&location);
                    exact_index |= unproven_index;
                    let loaded = ValueFlowEndpoint::Value(value_handle(procedure, *result)?);
                    // #2453: an element read of a tainted array carries the
                    // array's label. The subscripted expression carries a
                    // label the array acquired downstream of its access-path
                    // origin; the container carries one it acquired at or
                    // before that origin, and is also what a store through
                    // an unprovable subscript marks.
                    if let Some(base) = element_read_base_value(procedure, *memory)? {
                        smashed.push(DerivedRelation {
                            kind: ValueFlowRelationKind::MemoryLoad,
                            memory_role: Some(MemoryRelationRole::Supplemental),
                            source: ValueFlowEndpoint::Value(base),
                            target: loaded.clone(),
                            quality: None,
                        });
                    }
                    if let Some(container) =
                        element_read_container_endpoint(procedure, *memory, &location, limits)?
                    {
                        smashed.push(DerivedRelation {
                            kind: ValueFlowRelationKind::MemoryLoad,
                            memory_role: Some(MemoryRelationRole::Supplemental),
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
                        && let Some(cell) = wildcard_index_endpoint(&location, limits)?
                    {
                        smashed.push(DerivedRelation {
                            kind: ValueFlowRelationKind::MemoryLoad,
                            memory_role: Some(MemoryRelationRole::Supplemental),
                            source: cell,
                            target: loaded.clone(),
                            quality: None,
                        });
                    }
                    for alternative in alternative_access_paths.drain(..) {
                        let (alternative, _) =
                            materialize_abstract_location(procedure, alternative, limits)?;
                        smashed.push(DerivedRelation {
                            kind: ValueFlowRelationKind::MemoryLoad,
                            memory_role: Some(MemoryRelationRole::Alternative),
                            source: ValueFlowEndpoint::Location(Box::new(alternative)),
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
                        limits,
                    )?;
                    let unproven_index = summary || location_has_unproven_exact_index(&location);
                    exact_index |= unproven_index;
                    let stored = ValueFlowEndpoint::for_value(value_handle(procedure, *value)?);
                    let dereference_targets = possible_dereference_store_targets(
                        procedure,
                        *memory,
                        origins.binding_origins,
                    );
                    if !dereference_targets.is_empty() {
                        completeness = EvidenceCompleteness::Partial(
                            "dereference store may target multiple or incomplete binding origins"
                                .into(),
                        );
                        open = true;
                    }
                    for target in dereference_targets {
                        let (target, _) = materialize_abstract_location(
                            procedure,
                            AccessPathDraft {
                                original_cell: None,
                                root: AccessPathRootDraft::LexicalCell(target),
                                selectors: Vec::new(),
                                tail: AccessPathTail::Exact,
                                opaque_prefix: false,
                            },
                            limits,
                        )?;
                        smashed.push(DerivedRelation {
                            kind: ValueFlowRelationKind::MemoryStore,
                            memory_role: Some(MemoryRelationRole::Alternative),
                            source: stored.clone(),
                            target: ValueFlowEndpoint::Location(Box::new(target)),
                            quality: Some((
                                ProofStatus::Unproven(
                                    "dereference store has multiple or incomplete binding origins"
                                        .into(),
                                ),
                                EvidenceCompleteness::Partial(
                                    "dereference store may target multiple bindings".into(),
                                ),
                            )),
                        });
                    }
                    // #2453, the write direction. Every element store also
                    // writes the wildcard cell, which is what an unprovable
                    // subscript later reads.
                    if let Some(cell) = wildcard_index_endpoint(&location, limits)? {
                        smashed.push(DerivedRelation {
                            kind: ValueFlowRelationKind::MemoryStore,
                            memory_role: Some(MemoryRelationRole::Supplemental),
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
                        && let Some(container) = indexed_container_endpoint(&location, limits)?
                    {
                        smashed.push(DerivedRelation {
                            kind: ValueFlowRelationKind::MemoryStore,
                            memory_role: Some(MemoryRelationRole::Supplemental),
                            source: stored.clone(),
                            target: container,
                            quality: None,
                        });
                    }
                    for alternative in alternative_access_paths.drain(..) {
                        let (alternative, _) =
                            materialize_abstract_location(procedure, alternative, limits)?;
                        smashed.push(DerivedRelation {
                            kind: ValueFlowRelationKind::MemoryStore,
                            memory_role: Some(MemoryRelationRole::Alternative),
                            source: stored.clone(),
                            target: ValueFlowEndpoint::Location(Box::new(alternative)),
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
                                limits,
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
                            memory_role: None,
                            source: ValueFlowEndpoint::Value(value_handle(procedure, *value)?),
                            target: ValueFlowEndpoint::Value(value_handle(procedure, *binder)?),
                            quality: Some((
                                ProofStatus::Unproven(HANDLER_SELECTION_UNPROVEN.into()),
                                EvidenceCompleteness::Partial(HANDLER_SELECTION_UNPROVEN.into()),
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
                // #8804: a call's exceptional continuation receives the
                // callee's exception in the call's `thrown` value. Whether a
                // local handler catches it is the control flow's business, as
                // for a local `throw`: the port carrier only reaches this
                // procedure's exceptional exit on a path that leaves it. This
                // is what relays a callee's exception through an intermediate
                // procedure. It rides the continuation event rather than a
                // synthetic `Throw`, because throw-site search and quality
                // rules read `Throw` as a source-level throw statement.
                SemanticEffect::CallContinuation {
                    call_site,
                    kind: CallContinuationKind::Exceptional,
                } => (
                    ValueFlowRelationKind::ExceptionalReturn,
                    ValueFlowEndpoint::Value(value_handle(
                        procedure,
                        exceptional_continuation_thrown(procedure, *call_site)
                            .expect("an exceptional continuation relation was classified with its thrown value"),
                    )?),
                    ValueFlowEndpoint::Port(ProcedurePortHandle::exceptional_return(
                        procedure.clone(),
                    )),
                    false,
                ),
                // The value a normal resume produces is computed from the
                // value the matching suspend awaited: a task's or promise's
                // completion, a future's output. It is a different object, so
                // the dependence is language-defined, not an alias.
                SemanticEffect::AsyncResume {
                    suspend,
                    result: Some(result),
                    ..
                } => (
                    ValueFlowRelationKind::LanguageDefined,
                    ValueFlowEndpoint::for_value(value_handle(
                        procedure,
                        procedure
                            .semantics()
                            .awaited_value(*suspend)
                            .expect("a resume relation was classified with its awaited value"),
                    )?),
                    ValueFlowEndpoint::for_value(value_handle(procedure, *result)?),
                    false,
                ),
                _ => unreachable!("relation-producing effects were classified above"),
            };
            if summary {
                completeness =
                    EvidenceCompleteness::Partial("access path retains an unknown selector".into());
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
                && single_target
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
                match host.store_holds_strong_update(
                    procedure,
                    context,
                    &relation_point,
                    event_index,
                    *location,
                    *value,
                    bases,
                    origins.binding_origins,
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
            if kind == ValueFlowRelationKind::MemoryStore {
                let SemanticEffect::MemoryStore { location, .. } = event.effect else {
                    unreachable!("memory store relation has a store event")
                };
                container_elements.record_store(&target, location);
            }
            if let Some(read) = match event.effect {
                SemanticEffect::Assignment { target, .. }
                | SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Local,
                    target,
                    ..
                }
                | SemanticEffect::MemoryLoad { result: target, .. } => Some(target),
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Return | ValueFlowKind::IndexedReturn { .. },
                    source,
                    ..
                } => Some(source),
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
            let direct_cell_store = kind == ValueFlowRelationKind::MemoryStore
                && single_target
                && matches!(proof, ProofStatus::Proven)
                && matches!(completeness, EvidenceCompleteness::Complete)
                && matches!(&event.effect, SemanticEffect::MemoryStore { location, .. }
                        if procedure.semantics().memory_location(*location).is_some_and(|row|
                            matches!(row.kind, MemoryLocationKind::LexicalCell { .. })))
                && matches!(&target, ValueFlowEndpoint::Location(location)
                        if location.path().is_exact()
                            && location.path().selectors().is_empty()
                            && matches!(location.path().root(), AccessPathRoot::LexicalCell(_)));
            let direct_cell_overwrite = if direct_cell_store {
                if local_overwrites.is_none() {
                    match local_cell_overwrite_points(procedure, &mut staged, request.cancellation)
                    {
                        Ok(points) => local_overwrites = Some(points),
                        Err(stop) => {
                            interrupted = Some(stop);
                            break 'points;
                        }
                    }
                }
                local_overwrites
                    .as_ref()
                    .expect("direct store paid its CFG proof")
                    .contains(&point.id)
            } else {
                false
            };
            let memory_location = match event.effect {
                SemanticEffect::MemoryLoad { location, .. }
                | SemanticEffect::MemoryStore { location, .. } => Some(location),
                _ => None,
            };
            let memory_origin = memory_location.map(|location| {
                MemoryRelationOrigin::new(
                    point.id,
                    relation_event,
                    location,
                    MemoryRelationRole::Canonical,
                )
            });
            let draft = FlowRelationDraft {
                original_cell,
                payload: ValueFlowRelationPayload {
                    point: relation_point.clone(),
                    event_index: relation_event,
                    kind,
                    transfer,
                    source,
                    target,
                    collapse_read: None,
                    proof: proof.clone(),
                    completeness: completeness.clone(),
                    strong_update,
                    direct_cell_overwrite,
                },
                memory_origin,
                evidence: vec![evidence.clone()],
            };
            if !push_flow_relation(&mut drafts, &mut retained_evidence, limits, draft) {
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
                container_elements.observe(&derived.source, &derived_proof, &derived_completeness);
                container_elements.observe(&derived.target, &derived_proof, &derived_completeness);
                let memory_origin = derived.memory_role.map(|role| {
                    MemoryRelationOrigin::new(
                        point.id,
                        relation_event,
                        memory_location.expect("a derived memory dependency rides a memory event"),
                        role,
                    )
                });
                let draft = FlowRelationDraft {
                    original_cell: None,
                    payload: ValueFlowRelationPayload {
                        point: relation_point.clone(),
                        event_index: relation_event,
                        kind: derived.kind,
                        transfer: None,
                        source: derived.source,
                        target: derived.target,
                        collapse_read: None,
                        proof: derived_proof,
                        completeness: derived_completeness,
                        // Supplemental summaries and alternative candidates join;
                        // none inherits the direct store's overwrite authority.
                        strong_update: false,
                        direct_cell_overwrite: false,
                    },
                    memory_origin,
                    evidence: vec![evidence.clone()],
                };
                if !push_flow_relation(&mut drafts, &mut retained_evidence, limits, draft) {
                    truncated = true;
                    break 'points;
                }
            }
            if alternative_paths_truncated {
                truncated = true;
                break 'points;
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
        let local_allocations: HashSet<_> = procedure
            .semantics()
            .allocations()
            .iter()
            .map(|allocation| allocation.result)
            .collect();
        'reads: for read in &container_reads {
            if request.cancellation.is_cancelled() {
                interrupted = Some(Interruption::Cancelled);
                break;
            }
            let mut visited_values = HashSet::new();
            let mut choice_index = 0usize;
            let (root, prefix, summarized, collapse_read) = match walk_value_origin(
                &load_origins,
                read.value,
                &mut visited_values,
                exact_integer,
                &[],
                &mut choice_index,
            ) {
                ValueOriginWalk::Root {
                    value,
                    offset,
                    summarized,
                } => (
                    AccessPathRoot::Value(value_handle(procedure, value)?),
                    Vec::new(),
                    summarized || offset != Some(0),
                    Some(CollapseRead::Root),
                ),
                ValueOriginWalk::Port {
                    kind,
                    offset,
                    summarized,
                } => (
                    AccessPathRoot::ProcedurePort(
                        ProcedurePortHandle::new(procedure.clone(), kind).map_err(|error| {
                            internal_contract("invalid formal procedure port", error)
                        })?,
                    ),
                    Vec::new(),
                    summarized || offset != Some(0),
                    None,
                ),
                ValueOriginWalk::Allocation {
                    allocation,
                    offset,
                    summarized,
                } => (
                    AccessPathRoot::Allocation(
                        procedure.allocation_handle(allocation).ok_or_else(|| {
                            SemanticProviderError::internal("alternative allocation root is stale")
                        })?,
                    ),
                    Vec::new(),
                    summarized || offset != Some(0),
                    None,
                ),
                ValueOriginWalk::Load { location, .. } => {
                    // The whole value was loaded out of memory, so the
                    // object it denotes is whatever that load names.
                    match resolve_access_path(
                        location,
                        origins,
                        limits.access_path_length(),
                        request.cancellation,
                        |id| {
                            procedure
                                .semantics()
                                .memory_location(id)
                                .map(|row| &row.kind)
                        },
                        exact_integer,
                        |work| {
                            staged.charge_work(work);
                            Ok(())
                        },
                    )? {
                        AccessPathResolution::Resolved(resolved) => {
                            let (location, summary) =
                                materialize_abstract_location(procedure, resolved, limits)?;
                            (
                                location.path().root().clone(),
                                location.path().selectors().to_vec(),
                                summary,
                                Some(CollapseRead::Load(
                                    location.path().selectors().to_vec().into_boxed_slice(),
                                )),
                            )
                        }
                        AccessPathResolution::Interrupted(stop) => {
                            interrupted = Some(stop);
                            break 'reads;
                        }
                    }
                }
            };
            let return_port = match procedure
                .semantics()
                .point(read.point.id())
                .expect("container read names a validated point")
                .events[read.event_index as usize]
                .effect
            {
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Return,
                    ..
                } => Some(ProcedurePortHandle::normal_return(procedure.clone())),
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::IndexedReturn { ordinal },
                    ..
                } => Some(
                    ProcedurePortHandle::indexed_normal_return(procedure.clone(), ordinal)
                        .expect("validated indexed return has a live port"),
                ),
                _ => None,
            };
            let separated = return_port
                .as_ref()
                .and_then(|_| separated_return_definitions(&load_origins, read.value));
            let candidate_roots = return_port
                .as_ref()
                .map(|_| return_candidate_roots(&load_origins, &local_allocations, read.value));
            for element in &container_elements.elements {
                // All separated definitions name the same destination object.
                // Admit a member only when one transfer's own copy point
                // stored it; the transfer source's member stores do not count.
                let stated_by_alternative = separated.is_none_or(|transfers| {
                    transfers.iter().any(|transfer| {
                        transfer
                            .stores
                            .iter()
                            .any(|store| element.store_locations.contains(store))
                    })
                });
                // A join presents one of finitely many objects: the values its
                // definitions name, or separated copies' destinations. When
                // every alternative is an exact root, a member stored on one of
                // them is a member of the returned value under that choice.
                let via_alternative = candidate_roots.as_ref().is_some_and(|candidates| {
                    candidates.exhaustive
                        && match element.location.path().root() {
                            AccessPathRoot::Value(value)
                                if candidates.roots.contains(&value.id()) =>
                            {
                                // A separated destination's member counts only
                                // when its own copy stored it, never through
                                // the source object.
                                candidates
                                    .transfers
                                    .get(&value.id())
                                    .is_none_or(|transfer| {
                                        transfer
                                            .stores
                                            .iter()
                                            .any(|store| element.store_locations.contains(store))
                                    })
                            }
                            _ => false,
                        }
                });
                let admitted_by_root = element.location.path().root() == &root
                    && (return_port.is_none() || stated_by_alternative);
                // A return projection needs producer-stated contents.
                // Merely observing a field does not establish a stored
                // payload to transport into a new return-port location.
                if (return_port.is_some() && !element.has_stored_contents)
                    || !(admitted_by_root || via_alternative)
                    || !selectors_extend(element.location.path().selectors(), &prefix)
                {
                    // A summarized return can include a stored member rooted
                    // at a candidate source. Do not silently complete it if
                    // this projection cannot transport that member.
                    if let Some(candidates) = &candidate_roots {
                        let candidate = match element.location.path().root() {
                            AccessPathRoot::Value(value) => Some(value.id()),
                            _ => None,
                        };
                        // The gap is content: coverage Open plus the snapshot's
                        // untransported-member flag, with no execution marker.
                        // Both paths come from the retained-selector
                        // window, so one at the window's length may have been
                        // cut by that cap and the decision may then depend on
                        // `limits`. That is a real cap and truncates.
                        let path_cap = limits.access_path_length();
                        let gap = if element.location.path().selectors().len() >= path_cap
                            || prefix.len() >= path_cap
                        {
                            &mut truncated
                        } else {
                            &mut untransported_return_member
                        };
                        mark_rejected_return_member_incomplete(
                            gap,
                            element.has_stored_contents,
                            candidate,
                            &candidates.roots,
                        );
                    }
                    continue;
                }
                if let Err(stop) = staged.admit(SemanticWork {
                    values: 1,
                    memory_locations: 1 + usize::from(return_port.is_some()),
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
                    // An exhaustive choice of separated destinations names
                    // each object exactly, so the member is not summarized.
                    _ if summarized && !via_alternative => EvidenceCompleteness::Partial(
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
                // A returned container keeps its members distinct at the
                // exact return event. The call binder already transports
                // return-port locations; collapsing this member into the
                // whole value would erase which returned field held it.
                let (kind, target) = if let Some(port) = return_port.clone() {
                    let port_root = AccessPathRoot::ProcedurePort(port);
                    let object = AbstractObject::new(port_root.clone(), ObjectCardinality::Unknown)
                        .expect("a return port is a valid abstract object root");
                    let path = AccessPath::bounded(
                        port_root,
                        element.location.path().selectors()[prefix.len()..].to_vec(),
                        element.location.path().tail(),
                        limits,
                    )
                    .expect("a member suffix fits the validated access-path bound");
                    let location = AbstractLocation::new(object, path)
                        .expect("the returned member object and path share a root");
                    (
                        ValueFlowRelationKind::NormalReturn,
                        ValueFlowEndpoint::Location(Box::new(location)),
                    )
                } else {
                    (
                        ValueFlowRelationKind::ContainerCollapse,
                        ValueFlowEndpoint::Value(value_handle(procedure, read.value)?),
                    )
                };
                let event = &procedure
                    .semantics()
                    .point(read.point.id())
                    .expect("container read names a validated point")
                    .events[read.event_index as usize];
                let memory_origin = match event.effect {
                    SemanticEffect::MemoryLoad { location, .. } => Some(MemoryRelationOrigin::new(
                        read.point.id(),
                        read.event_index,
                        location,
                        MemoryRelationRole::Supplemental,
                    )),
                    _ => None,
                };
                let draft = FlowRelationDraft {
                    original_cell: None,
                    payload: ValueFlowRelationPayload {
                        point: read.point.clone(),
                        event_index: read.event_index,
                        kind,
                        transfer: None,
                        source: ValueFlowEndpoint::Location(Box::new(element.location.clone())),
                        target,
                        collapse_read: (kind == ValueFlowRelationKind::ContainerCollapse)
                            .then(|| collapse_read.clone())
                            .flatten(),
                        proof,
                        completeness,
                        // Reading a member never overwrites it.
                        strong_update: false,
                        direct_cell_overwrite: false,
                    },
                    memory_origin,
                    evidence: vec![read.evidence.clone()],
                };
                if !push_flow_relation(&mut drafts, &mut retained_evidence, limits, draft) {
                    truncated = true;
                    break 'reads;
                }
            }
        }
    }

    let mut member_receivers = Vec::new();
    if interrupted.is_none() {
        for call in procedure
            .semantics()
            .call_sites()
            .iter()
            .filter(|call| call.member_selection.is_some())
        {
            if let Err(stop) = staged.admit(SemanticWork {
                call_sites: 1,
                nested_entries: 1,
                ..SemanticWork::default()
            }) {
                interrupted = Some(stop);
                break;
            }
            let place = match call
                .member_selection
                .as_ref()
                .and_then(|selection| selection.receiver_place.as_ref())
            {
                Some(crate::analyzer::semantic::SemanticPlace::MemoryLocation(location)) => {
                    match resolve_access_path(
                        *location,
                        origins,
                        limits.access_path_length(),
                        request.cancellation,
                        |id| {
                            procedure
                                .semantics()
                                .memory_location(id)
                                .map(|row| &row.kind)
                        },
                        exact_integer,
                        |work| staged.admit(work),
                    )? {
                        AccessPathResolution::Resolved(path) => {
                            let (location, summary) =
                                materialize_abstract_location(procedure, path, limits)?;
                            (!summary).then(|| ValueFlowEndpoint::Location(Box::new(location)))
                        }
                        AccessPathResolution::Interrupted(stop) => {
                            interrupted = Some(stop);
                            break;
                        }
                    }
                }
                Some(crate::analyzer::semantic::SemanticPlace::LocalBinding(expected)) => {
                    if let Err(stop) = staged.admit(SemanticWork {
                        values: procedure.semantics().values().len(),
                        ..SemanticWork::default()
                    }) {
                        interrupted = Some(stop);
                        break;
                    }
                    let mut values = procedure.semantics().values().iter().filter(|value| {
                        if !matches!(
                            value.kind,
                            SemanticValueKind::Local
                                | SemanticValueKind::Parameter { .. }
                                | SemanticValueKind::Receiver { .. }
                        ) {
                            return false;
                        }
                        let actual = &procedure
                            .semantics()
                            .source_mapping(value.source)
                            .expect("a value source exists")
                            .locator;
                        actual.mount() == expected.mount()
                            && actual.path() == expected.path()
                            && actual.language() == expected.language()
                            && actual.declaration() == expected.declaration()
                            && actual.anchor() == expected.anchor()
                    });
                    match (values.next(), values.next()) {
                        (Some(value), None) => Some(ValueFlowEndpoint::for_value(value_handle(
                            procedure, value.id,
                        )?)),
                        _ => None,
                    }
                }
                None => None,
            };
            let call = procedure
                .call_site_handle(call.id)
                .expect("a projected call exists");
            // What the host admitted while building the flow (the dispatch, the
            // locations query whose answers it reduces to endpoints, the scanned
            // selection events) is scratch and must not stay on the ledger. The
            // flow's own storage endpoints survive into the snapshot, so they
            // are charged as soon as the flow is kept, whether or not the
            // publication below runs to the end (#10530).
            let mark = staged.budget.scratch_mark();
            let outcome = host.member_receiver_flow(
                &call,
                context,
                place,
                &mut staged.request(request.cancellation),
                limits,
            );
            staged.budget.release_scratch_since(&mark);
            let outcome = outcome?;
            staged.work = staged.work.conservative_add(outcome.work());
            match outcome {
                SemanticOutcome::Complete { value, .. } => {
                    execution_dependent |= !value.selection_is_complete();
                    open |= !value.selection_is_complete();
                    if let Err(stop) = staged.admit(SemanticWork {
                        nested_entries: value.retained_entries(),
                        ..SemanticWork::default()
                    }) {
                        interrupted = Some(stop);
                        break;
                    }
                    member_receivers.push(value);
                }
                SemanticOutcome::Cancelled { .. } => {
                    interrupted = Some(Interruption::Cancelled);
                    break;
                }
                SemanticOutcome::ExceededBudget { exceeded, .. } => {
                    interrupted = Some(Interruption::Budget(exceeded));
                    break;
                }
                other => {
                    execution_dependent = true;
                    open = true;
                    if let Some(value) = other.available_value() {
                        if let Err(stop) = staged.admit(SemanticWork {
                            nested_entries: value.retained_entries(),
                            ..SemanticWork::default()
                        }) {
                            interrupted = Some(stop);
                            break;
                        }
                        member_receivers.push(value.clone());
                    }
                }
            }
        }
    }

    // Publish selected receiver dependencies in the ordinary relation arena,
    // so every snapshot consumer observes the same call-side storage effects.
    'receivers: for receiver in &member_receivers {
        for transfer in receiver.transfers() {
            if let Err(stop) = staged.admit(SemanticWork {
                nested_entries: 1,
                ..SemanticWork::default()
            }) {
                interrupted = Some(stop);
                break 'receivers;
            }
            let call = procedure
                .semantics()
                .call_site(receiver.call().id())
                .expect("a projected member call exists");
            let draft = FlowRelationDraft {
                original_cell: None,
                payload: ValueFlowRelationPayload {
                    point: transfer.point,
                    event_index: transfer.event_index,
                    kind: ValueFlowRelationKind::LanguageDefined,
                    transfer: None,
                    source: transfer.source,
                    target: transfer.target,
                    collapse_read: None,
                    proof: transfer.proof,
                    completeness: transfer.completeness,
                    strong_update: false,
                    direct_cell_overwrite: false,
                },
                memory_origin: None,
                evidence: vec![evidence_handle(procedure, call.evidence)?],
            };
            if !push_flow_relation(&mut drafts, &mut retained_evidence, limits, draft) {
                truncated = true;
                break 'receivers;
            }
        }
    }
    // #10989: a closed local container's Keyed contract stores and loads
    // per-key cells at each bound call's normal continuation.
    let mut collection_cells = if interrupted.is_none() && !truncated {
        closed_containers::closed_container_cells(
            host,
            procedure,
            limits,
            &mut staged.request(request.cancellation),
        )?
    } else {
        Vec::new()
    };
    // A bound call's summary no longer applies, so its cell relations are
    // published all together or the binding is dropped with them.
    let cells_start = drafts.len();
    'cells: for binding in &collection_cells {
        let call = procedure
            .semantics()
            .call_site(binding.call().id())
            .expect("a bound container call exists");
        for transfer in binding.transfers() {
            let draft = FlowRelationDraft {
                original_cell: None,
                payload: ValueFlowRelationPayload {
                    point: transfer.point.clone(),
                    event_index: transfer.event_index,
                    kind: ValueFlowRelationKind::LanguageDefined,
                    transfer: None,
                    source: transfer.source.clone(),
                    target: transfer.target.clone(),
                    collapse_read: None,
                    proof: ProofStatus::Proven,
                    completeness: EvidenceCompleteness::Complete,
                    strong_update: false,
                    direct_cell_overwrite: false,
                },
                memory_origin: None,
                evidence: vec![evidence_handle(procedure, call.evidence)?],
            };
            if !push_flow_relation(&mut drafts, &mut retained_evidence, limits, draft) {
                truncated = true;
                drafts.truncate(cells_start);
                collection_cells.clear();
                break 'cells;
            }
        }
    }
    open |= untransported_return_member;
    let has_unproven_relation = drafts.iter().any(|draft| {
        !matches!(draft.payload.proof, ProofStatus::Proven)
            || !matches!(draft.payload.completeness, EvidenceCompleteness::Complete)
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
        limits,
        discharged_gaps,
        unproven_go_builtin_assumptions,
        member_receivers,
        collection_cells,
        execution_dependent,
    )?
    .with_untransported_return_member(untransported_return_member);
    if interrupted.is_none() && request.cancellation.is_cancelled() {
        interrupted = Some(Interruption::Cancelled);
    }
    *request.budget = staged.budget;
    Ok(publish_flow_outcome(
        snapshot,
        interrupted,
        has_unproven_relation,
        gap_quality,
        staged.work,
    ))
}
