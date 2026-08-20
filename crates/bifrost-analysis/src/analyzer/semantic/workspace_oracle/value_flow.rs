//! Bounded value-flow and candidate-specific call-binding materialization.
//!
//! The implementation projects validated semantic IR rows into neutral oracle
//! relations. It never reparses source or matches declarations by text.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use super::WorkspaceSemanticOracle;
use super::common::{
    Interruption, WorkStager, dedup_evidence, evidence_handle, evidence_quality, internal_contract,
    value_handle,
};
use crate::analyzer::semantic::{
    AbstractLocation, AbstractObject, AbstractObjectIdentity, AccessPath, AccessPathRoot,
    AccessPathTail, AccessSelector, AllocationHandle, CallArgumentEndpoint, CallArgumentExpansion,
    CallArgumentGroup, CallArgumentMapping, CallArgumentMember, CallBinding, CallBindings,
    CallPassingMode, CandidateCoverage, CaptureSource, DeclarationSegmentKind, DispatchCandidate,
    EvidenceCompleteness, EvidenceHandle, FormalMultiplicity, IndexSelector, MemoryLocationId,
    MemoryLocationKind, ObjectCardinality, OracleCallContext, OracleCandidate, OracleRelationArena,
    OracleRelationHandle, OracleRelationId, OracleRelationKind, OracleRelationOwner,
    OracleRelationRecord, ProcedureHandle, ProcedurePortHandle, ProgramPointHandle, ProofStatus,
    ScopedSemanticLocator, SemanticCapability, SemanticEffect, SemanticGapImpact, SemanticGapKind,
    SemanticGapSubject, SemanticLocator, SemanticOutcome, SemanticProviderError, SemanticRequest,
    SemanticValueKind, SemanticWork, ValueFlowEndpoint, ValueFlowKind, ValueFlowOracle,
    ValueFlowRelation, ValueFlowRelationKind, ValueFlowSnapshot, ValueHandle, ValueId,
};

#[derive(Debug, Clone, Copy)]
enum GapOutcomeQuality {
    Ambiguous,
    Unproven,
    Unknown,
    Unsupported(SemanticCapability),
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
    source: ValueFlowEndpoint,
    target: ValueFlowEndpoint,
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
    evidence: Vec<EvidenceHandle>,
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
pub(crate) fn value_flow_capabilities_are_open(procedure: &ProcedureHandle) -> bool {
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
pub(crate) fn call_target_refinement_call(
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
pub(crate) fn constructor_call_gap_is_discharged(
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

/// Whether a call's retained allocation result makes an unresolved
/// zero-argument constructor boundary fully modeled for value flow.
pub(crate) fn allocation_call_is_dischargeable(
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
pub(crate) fn gap_impacts_value_flow(gap: &crate::analyzer::semantic::SemanticGap) -> bool {
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
pub(crate) fn abort_paths_run_user_code(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
) -> bool {
    let exceptional_exit = semantics.exceptional_exit_point();
    let mut pending = semantics
        .cfg()
        .edges()
        .iter()
        .filter(|edge| {
            matches!(
                edge.kind,
                crate::analyzer::semantic::ControlEdgeKind::Exceptional
                    | crate::analyzer::semantic::ControlEdgeKind::Cleanup
            ) && edge.target_point != exceptional_exit
        })
        .map(|edge| edge.target_point)
        .collect::<Vec<_>>();
    let mut visited = HashSet::new();
    while let Some(point_id) = pending.pop() {
        if point_id == exceptional_exit || !visited.insert(point_id) {
            continue;
        }
        let Some(point) = semantics.point(point_id) else {
            continue;
        };
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
            return true;
        }
        pending.extend(
            semantics
                .cfg()
                .edges()
                .iter()
                .filter(|edge| edge.source_point == point_id)
                .map(|edge| edge.target_point),
        );
    }
    false
}

/// Whether an implicit-exception gap is discharged because every abort path
/// in this procedure only unwinds.
///
/// Only an `Unsupported` gap qualifies: it states that a represented
/// operation's implicit abort edge is not lowered, which cannot carry a value
/// when aborts run no user code. An `Unknown` exceptional gap (deferred-call
/// panic propagation, destructor unwinding) makes the represented route
/// itself uncertain and always keeps standing, matching the matched-return
/// rule in the ICFG exit profiles.
pub(crate) fn implicit_abort_gap_is_discharged(
    gap: &crate::analyzer::semantic::SemanticGap,
    abort_user_code: bool,
) -> bool {
    gap.capability == SemanticCapability::ExceptionalControlFlow
        && matches!(gap.subject, SemanticGapSubject::Point)
        && gap.kind == SemanticGapKind::Unsupported
        && !abort_user_code
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
/// - Sibling callables outside a declaring type (JavaScript file-level
///   functions, Ruby top-level methods) own a `this`/`self` without sharing
///   it through a bare call.
///
/// Those shapes return `None` and the binding stays honestly open.
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
    (caller_locator.mount() == callee_locator.mount()
        && caller_locator.path() == callee_locator.path()
        && caller_parent == callee_parent
        && caller_parent
            .last()
            .is_some_and(|segment| segment.kind() == DeclarationSegmentKind::Type))
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
    Index(Option<ValueId>),
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

fn memory_load_origins(
    procedure: &ProcedureHandle,
    cancellation: &crate::CancellationToken,
    mut charge: impl FnMut(SemanticWork) -> Result<(), Interruption>,
) -> Result<HashMap<ValueId, LoadOrigin>, Interruption> {
    let mut origins = HashMap::new();
    for point in procedure.semantics().points() {
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
                _ => None,
            };
            if let Some((value, origin)) = origin {
                origins
                    .entry(value)
                    .and_modify(|existing| {
                        if *existing != origin {
                            *existing = LoadOrigin::Ambiguous;
                        }
                    })
                    .or_insert(origin);
            }
        }
    }
    Ok(origins)
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

fn resolve_access_path<'location>(
    location: MemoryLocationId,
    load_origins: &HashMap<ValueId, LoadOrigin>,
    selector_limit: usize,
    cancellation: &crate::CancellationToken,
    location_kind: impl Fn(MemoryLocationId) -> Option<&'location MemoryLocationKind>,
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
            MemoryLocationKind::Index { base, index } => {
                retain_selector(
                    &mut selectors,
                    AccessSelectorDraft::Index(*index),
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

        let mut root_value = base;
        let root = loop {
            match load_origins.get(&root_value) {
                Some(LoadOrigin::Value(next)) if visited_values.insert(root_value) => {
                    root_value = *next;
                }
                Some(LoadOrigin::Unique(next)) if !visited.contains(next) => {
                    current = *next;
                    continue 'locations;
                }
                Some(LoadOrigin::Value(_))
                | Some(LoadOrigin::Unique(_))
                | Some(LoadOrigin::Ambiguous) => {
                    summarized = true;
                    break AccessPathRootDraft::Value(root_value);
                }
                None => break AccessPathRootDraft::Value(root_value),
            }
        };
        break root;
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

/// Whether a bounded location names a non-constant exact index selector.
/// Constant index values are canonicalized by language lowering, while a
/// dynamic index remains an unproven join even when its expression value is
/// reused across accesses.
fn location_has_unproven_exact_index(location: &AbstractLocation) -> bool {
    location.path().selectors().iter().any(|selector| {
        let AccessSelector::Index(IndexSelector::Exact(index)) = selector else {
            return false;
        };
        !index
            .procedure()
            .semantics()
            .value(index.id())
            .is_some_and(|value| matches!(value.kind, SemanticValueKind::Constant))
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
    let selectors = draft
        .selectors
        .into_iter()
        .map(|selector| match selector {
            AccessSelectorDraft::Field(member) => {
                ScopedSemanticLocator::new(Arc::clone(procedure.artifact()), member)
                    .map(AccessSelector::Field)
                    .map_err(|error| internal_contract("invalid field locator", error))
            }
            AccessSelectorDraft::Index(Some(index)) => value_handle(procedure, index)
                .map(IndexSelector::Exact)
                .map(AccessSelector::Index),
            AccessSelectorDraft::Index(None) => Ok(AccessSelector::Index(IndexSelector::Any)),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let path = AccessPath::bounded(root, selectors, draft.tail, limits)
        .map_err(|error| internal_contract("invalid semantic access path", error))?;
    let summary = !path.is_exact();
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

fn materialize_flow_snapshot(
    procedure: &ProcedureHandle,
    context: &OracleCallContext,
    drafts: Vec<FlowRelationDraft>,
    coverage: CandidateCoverage,
    limits: crate::analyzer::semantic::OracleLimits,
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
                source: draft.source,
                target: draft.target,
                proof: draft.proof,
                completeness: draft.completeness,
            })
        })
        .collect::<Result<Vec<_>, SemanticProviderError>>()?;
    ValueFlowSnapshot::new(
        procedure.clone(),
        context.clone(),
        relations,
        coverage,
        limits,
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
        None if snapshot.coverage() == CandidateCoverage::Truncated || has_unproven_relation => {
            SemanticOutcome::Unproven {
                partial: snapshot,
                work,
            }
        }
        None if matches!(gap_quality, Some(GapOutcomeQuality::Unsupported(_))) => {
            let Some(GapOutcomeQuality::Unsupported(capability)) = gap_quality else {
                unreachable!("guard establishes unsupported gap quality")
            };
            SemanticOutcome::Unsupported {
                capability,
                partial: Some(snapshot),
                work,
            }
        }
        None if matches!(gap_quality, Some(GapOutcomeQuality::Unknown)) => {
            SemanticOutcome::Unknown {
                partial: Some(snapshot),
                work,
            }
        }
        None if matches!(gap_quality, Some(GapOutcomeQuality::Unproven)) => {
            SemanticOutcome::Unproven {
                partial: snapshot,
                work,
            }
        }
        None if matches!(gap_quality, Some(GapOutcomeQuality::Ambiguous)) => {
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
                let relevant = gap_impacts_value_flow(gap)
                    && !declared_proven_target_discharges_gap(procedure.semantics(), gap)
                    && !constructor_call_gap_is_discharged(procedure.semantics(), gap)
                    && !implicit_abort_gap_is_discharged(gap, abort_user_code);
                open |= relevant;
                if relevant {
                    gap_quality = merge_gap_quality(gap_quality, gap);
                }
            }
        }

        let load_origins = if interrupted.is_none() {
            match memory_load_origins(procedure, request.cancellation, |work| staged.charge(work)) {
                Ok(origins) => origins,
                Err(stop) => {
                    interrupted = Some(stop);
                    HashMap::new()
                }
            }
        } else {
            HashMap::new()
        };

        let mut drafts = Vec::new();
        let mut retained_evidence = 0usize;
        let mut truncated = false;
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
                    | SemanticEffect::CallableCreation { .. }
                    | SemanticEffect::CallableReference { .. }
                    | SemanticEffect::Invoke { .. }
                    | SemanticEffect::CallContinuation { .. }
                    | SemanticEffect::ProcedureReturn { .. }
                    | SemanticEffect::Throw { value: None }
                    | SemanticEffect::AsyncSuspend { .. }
                    | SemanticEffect::AsyncResume { .. }
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
                // #2453: the extra relations an indexed access publishes, so a
                // label on the array itself is not silently lost at the
                // subscript. They ride the same event, so they carry the same
                // evidence, proof and completeness as the access they derive
                // from.
                let mut smashed: Vec<(
                    ValueFlowRelationKind,
                    ValueFlowEndpoint,
                    ValueFlowEndpoint,
                )> = Vec::new();
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
                        kind: ValueFlowKind::LanguageDefined,
                        source,
                        target,
                    } => (
                        ValueFlowRelationKind::LanguageDefined,
                        ValueFlowEndpoint::Value(value_handle(procedure, *source)?),
                        ValueFlowEndpoint::Value(value_handle(procedure, *target)?),
                        false,
                    ),
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
                            smashed.push((
                                ValueFlowRelationKind::MemoryLoad,
                                ValueFlowEndpoint::Value(base),
                                loaded.clone(),
                            ));
                        }
                        if let Some(container) =
                            indexed_container_endpoint(&location, *self.limits())?
                        {
                            smashed.push((
                                ValueFlowRelationKind::MemoryLoad,
                                container,
                                loaded.clone(),
                            ));
                        }
                        // A subscript the analysis cannot prove reads whatever
                        // any store put in the array, so it reads the wildcard
                        // cell every store also writes. A proven-constant
                        // subscript does not, which is what keeps #2191's
                        // constant-index separation intact.
                        if unproven_index
                            && let Some(cell) = wildcard_index_endpoint(&location, *self.limits())?
                        {
                            smashed.push((ValueFlowRelationKind::MemoryLoad, cell, loaded.clone()));
                        }
                        (
                            ValueFlowRelationKind::MemoryLoad,
                            ValueFlowEndpoint::Location(Box::new(location)),
                            loaded,
                            summary,
                        )
                    }
                    SemanticEffect::MemoryStore { value, .. } => {
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
                            smashed.push((
                                ValueFlowRelationKind::MemoryStore,
                                stored.clone(),
                                cell,
                            ));
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
                            smashed.push((
                                ValueFlowRelationKind::MemoryStore,
                                stored.clone(),
                                container,
                            ));
                        }
                        (
                            ValueFlowRelationKind::MemoryStore,
                            stored,
                            ValueFlowEndpoint::Location(Box::new(location)),
                            summary,
                        )
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
                    SemanticEffect::Throw { value: Some(value) } => (
                        ValueFlowRelationKind::ExceptionalReturn,
                        ValueFlowEndpoint::Value(value_handle(procedure, *value)?),
                        ValueFlowEndpoint::Port(ProcedurePortHandle::exceptional_return(
                            procedure.clone(),
                        )),
                        false,
                    ),
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
                let draft = FlowRelationDraft {
                    point: relation_point.clone(),
                    event_index: relation_event,
                    kind,
                    source,
                    target,
                    proof: proof.clone(),
                    completeness: completeness.clone(),
                    evidence: vec![evidence.clone()],
                };
                if !push_flow_relation(&mut drafts, &mut retained_evidence, *self.limits(), draft) {
                    truncated = true;
                    break 'points;
                }
                // #2453: the smashed-container relations derived from this same
                // access. They are published after the access they derive from
                // so the primary relation is never dropped in favour of one of
                // them when the provenance budget runs out.
                for (kind, source, target) in smashed {
                    let draft = FlowRelationDraft {
                        point: relation_point.clone(),
                        event_index: relation_event,
                        kind,
                        source,
                        target,
                        proof: proof.clone(),
                        completeness: completeness.clone(),
                        evidence: vec![evidence.clone()],
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
        let snapshot =
            materialize_flow_snapshot(procedure, context, drafts, coverage, *self.limits())?;
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
                        || call_row.result == Some(value)
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
                && !implicit_abort_gap_is_discharged(gap, callee_abort_user_code);
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
                } => Some((*ordinal, multiplicity.clone(), value.evidence)),
                _ => None,
            })
            .collect::<Vec<_>>();
        formals.sort_by_key(|(ordinal, _, _)| *ordinal);

        let mut bound_formals = std::collections::HashSet::new();
        if interrupted.is_none()
            && let Some(receiver_row) = callee
                .semantics()
                .values()
                .iter()
                .find(|value| matches!(value.kind, SemanticValueKind::Receiver { .. }))
        {
            // A call that spells no receiver operand can still dispatch on
            // one: a bare call between members of the same declaring type
            // runs on the caller's own `this`. Bind that implicit actual only
            // when the sibling identity is structurally proven; otherwise the
            // missing operand keeps the binding honestly open.
            let (actual, extra_evidence) = match call_row.receiver {
                Some(actual_id) => (Some(actual_id), None),
                None => {
                    match implicit_dispatch_receiver_actual(call.procedure(), callee, receiver_row)
                    {
                        Some(caller_receiver) => (
                            Some(caller_receiver.id),
                            Some(evidence_handle(call.procedure(), caller_receiver.evidence)?),
                        ),
                        None => (None, None),
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
            let selected = if positional_width_unknown {
                None
            } else {
                match &argument.expansion {
                    CallArgumentExpansion::Direct(
                        crate::analyzer::semantic::ArgumentDomain::Positional
                        | crate::analyzer::semantic::ArgumentDomain::PositionalOrKeyword,
                    ) => formals.get(formal_cursor).and_then(
                        |(ordinal, multiplicity, evidence)| match multiplicity {
                            FormalMultiplicity::One => {
                                formal_cursor += 1;
                                Some((*ordinal, evidence, false))
                            }
                            FormalMultiplicity::Rest(
                                crate::analyzer::semantic::ArgumentDomain::Positional
                                | crate::analyzer::semantic::ArgumentDomain::PositionalOrKeyword,
                            ) => Some((*ordinal, evidence, true)),
                            FormalMultiplicity::Rest(_) => None,
                        },
                    ),
                    CallArgumentExpansion::Direct(
                        crate::analyzer::semantic::ArgumentDomain::LanguageDefined(actual),
                    ) => {
                        formals
                            .get(formal_cursor)
                            .and_then(|(ordinal, multiplicity, evidence)| match multiplicity {
                                FormalMultiplicity::Rest(
                                    crate::analyzer::semantic::ArgumentDomain::LanguageDefined(
                                        expected,
                                    ),
                                ) if expected == actual => Some((*ordinal, evidence, true)),
                                FormalMultiplicity::One | FormalMultiplicity::Rest(_) => None,
                            })
                    }
                    CallArgumentExpansion::Spread(_) => {
                        positional_width_unknown = true;
                        None
                    }
                    CallArgumentExpansion::Unclassified
                    | CallArgumentExpansion::Direct(
                        crate::analyzer::semantic::ArgumentDomain::Keyword,
                    ) => None,
                }
            };
            let closure_evidence = vec![call_evidence.clone()];
            let mut relation_evidence = vec![closure_evidence.clone()];
            let mapping = if let Some((ordinal, formal_evidence_id, _rest)) = selected {
                let mapping_evidence = dedup_evidence([
                    call_evidence.clone(),
                    evidence_handle(callee, *formal_evidence_id)?,
                ]);
                relation_evidence.push(mapping_evidence.clone());
                let (proof, completeness) = evidence_quality(&mapping_evidence);
                bound_formals.insert(ordinal);
                Some((
                    mapping_evidence,
                    CallArgumentMapping::new(
                        source_index as u32,
                        CallArgumentMember::Whole,
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

        if formals.iter().any(|(ordinal, multiplicity, _)| {
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
            None if coverage == CandidateCoverage::Truncated || has_unproven_relation => {
                SemanticOutcome::Unproven {
                    partial: bindings,
                    work: staged.work,
                }
            }
            None if matches!(gap_quality, Some(GapOutcomeQuality::Unsupported(_))) => {
                let Some(GapOutcomeQuality::Unsupported(capability)) = gap_quality else {
                    unreachable!("guard establishes unsupported gap quality")
                };
                SemanticOutcome::Unsupported {
                    capability,
                    partial: Some(bindings),
                    work: staged.work,
                }
            }
            None if matches!(gap_quality, Some(GapOutcomeQuality::Unknown)) => {
                SemanticOutcome::Unknown {
                    partial: Some(bindings),
                    work: staged.work,
                }
            }
            None if matches!(gap_quality, Some(GapOutcomeQuality::Unproven)) => {
                SemanticOutcome::Unproven {
                    partial: bindings,
                    work: staged.work,
                }
            }
            None if matches!(gap_quality, Some(GapOutcomeQuality::Ambiguous)) => {
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

    #[test]
    fn ambiguous_load_origin_summarizes_access_path() {
        let base = ValueId::new(0);
        let locations = [MemoryLocationKind::Index { base, index: None }];
        let load_origins = HashMap::from([(base, LoadOrigin::Ambiguous)]);

        let draft = resolve_access_path(
            MemoryLocationId::new(0),
            &load_origins,
            8,
            &crate::CancellationToken::default(),
            |id| locations.get(id.index()),
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
    fn cyclic_load_origins_terminate_with_summary() {
        let first_base = ValueId::new(0);
        let second_base = ValueId::new(1);
        let first_location = MemoryLocationId::new(0);
        let second_location = MemoryLocationId::new(1);
        let locations = [
            MemoryLocationKind::Index {
                base: first_base,
                index: None,
            },
            MemoryLocationKind::Index {
                base: second_base,
                index: None,
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
            },
            MemoryLocationKind::Index {
                base: second_base,
                index: None,
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
