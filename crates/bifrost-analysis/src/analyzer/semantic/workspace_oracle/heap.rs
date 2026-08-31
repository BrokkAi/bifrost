//! Bounded point-sensitive heap, alias, and update-oracle materialization.
//!
//! The implementation follows semantic IR edges and effects only. It does not
//! reparse source, infer identities from names, or upgrade allocation-site
//! identities into runtime singletons.

use super::WorkspaceSemanticOracle;
use super::common::{
    Interruption, WorkStager, dedup_evidence, evidence_handle, evidence_quality, internal_contract,
    value_handle,
};
use super::value_flow::{
    call_target_refinement_call, constructor_allocation_identity_discharges_gap,
    is_go_assignment_conversion,
};
use crate::analyzer::semantic::cfg_algorithms::{
    CfgAlgorithmBudget, CfgAlgorithmError, CfgAlgorithmRequest, forward_reachability, loop_regions,
    reverse_reachability,
};
use crate::analyzer::semantic::{
    AbstractLocation, AbstractObject, AbstractObjectIdentity, AccessPath, AccessPathAtPoint,
    AccessPathRoot, AliasExclusivity, AliasExclusivityWitness, AliasQuery, AliasRelation,
    AliasResult, CallResultHandle, CandidateCoverage, CaptureSource, DispatchOracle, EscapeStatus,
    EscapeWitness, EvidenceCompleteness, EvidenceHandle, FreshObjectPublication,
    FreshObjectPublicationKind, FreshObjectPublicationQuery, FreshObjectPublicationResult,
    HeapOracle, LocationResult, ObjectCardinality, ObservationPhase, OracleCandidate,
    OracleContractError, OracleRelationArena, OracleRelationId, OracleRelationKind,
    OracleRelationOwner, OracleRelationRecord, OracleSet, PointsToResult, ProcedureHandle,
    ProcedurePortHandle, ProofStatus, SemanticCallSite, SemanticCapability, SemanticEffect,
    SemanticGap, SemanticGapDischarge, SemanticGapImpact, SemanticGapSubject, SemanticOutcome,
    SemanticProviderError, SemanticRequest, SemanticValueKind, SemanticWork, StoreAtPoint,
    StrongUpdateEvidence, UpdateEligibility, ValueAtPoint, ValueFlowKind, ValueFlowOracle,
    ValueHandle, WeakUpdateReason,
};
use crate::hash::{HashMap, HashSet};

#[derive(Clone)]
struct ObjectDraft {
    object: AbstractObject,
    evidence: Vec<EvidenceHandle>,
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
}

#[derive(Clone)]
struct LocationDraft {
    location: AbstractLocation,
    evidence: Vec<EvidenceHandle>,
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
}

#[derive(Clone)]
struct PublicationDraft {
    publication: FreshObjectPublication,
    evidence: Vec<EvidenceHandle>,
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
}

struct DraftSet<T> {
    candidates: Vec<T>,
    coverage: CandidateCoverage,
    ambiguous: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TraceState {
    value: crate::analyzer::semantic::ValueId,
    point: crate::analyzer::semantic::ProgramPointId,
    event_limit: usize,
    /// Number of transitive value-flow producers followed from the queried
    /// value. Keeping this in the visited identity bounds value cycles while
    /// allowing a shallower route to the same semantic state to retain facts
    /// that a deeper, truncated route could not reach.
    summary_depth: usize,
}

fn merge_quality(
    left: &(ProofStatus, EvidenceCompleteness),
    right: &(ProofStatus, EvidenceCompleteness),
) -> (ProofStatus, EvidenceCompleteness) {
    let proof = if matches!(left.0, ProofStatus::Proven) {
        right.0.clone()
    } else {
        left.0.clone()
    };
    let completeness = if matches!(left.1, EvidenceCompleteness::Complete) {
        right.1.clone()
    } else {
        left.1.clone()
    };
    (proof, completeness)
}

fn candidate_cardinality_for_root(root: &AccessPathRoot) -> ObjectCardinality {
    match root {
        AccessPathRoot::Static(_) | AccessPathRoot::LexicalCell(_) => ObjectCardinality::Singleton,
        AccessPathRoot::CaptureSlot(_) | AccessPathRoot::TypeSummary(_) => {
            ObjectCardinality::Summary
        }
        AccessPathRoot::Value(_)
        | AccessPathRoot::CallResult(_)
        | AccessPathRoot::ProcedurePort(_)
        | AccessPathRoot::Allocation(_)
        | AccessPathRoot::ModuleObject(_)
        | AccessPathRoot::External(_) => ObjectCardinality::Unknown,
    }
}

fn root_evidence(
    procedure: &ProcedureHandle,
    root: &AccessPathRoot,
) -> Result<Vec<EvidenceHandle>, SemanticProviderError> {
    let evidence = match root {
        AccessPathRoot::Value(value) => procedure
            .semantics()
            .value(value.id())
            .map(|row| row.evidence),
        AccessPathRoot::CallResult(result) => procedure
            .semantics()
            .call_site(result.call().id())
            .map(|row| row.evidence),
        AccessPathRoot::Allocation(allocation) => procedure
            .semantics()
            .allocation(allocation.id())
            .map(|row| row.evidence),
        AccessPathRoot::LexicalCell(location) => procedure
            .semantics()
            .memory_location(location.id())
            .map(|row| row.evidence),
        AccessPathRoot::CaptureSlot(port) => match port.kind() {
            crate::analyzer::semantic::ProcedurePortKind::Capture { slot } => port
                .procedure()
                .semantics()
                .memory_location(slot)
                .map(|row| row.evidence),
            _ => None,
        },
        AccessPathRoot::ProcedurePort(port) => {
            let semantics = port.procedure().semantics();
            match port.kind() {
                crate::analyzer::semantic::ProcedurePortKind::IndexedNormalReturn { ordinal } => {
                    semantics
                        .points()
                        .iter()
                        .flat_map(|point| &point.events)
                        .find_map(|event| match event.effect {
                            SemanticEffect::ValueFlow {
                                kind:
                                    crate::analyzer::semantic::ValueFlowKind::IndexedReturn {
                                        ordinal: actual,
                                    },
                                target,
                                ..
                            } if actual == ordinal => {
                                semantics.value(target).map(|value| value.evidence)
                            }
                            _ => None,
                        })
                }
                kind => semantics
                    .values()
                    .iter()
                    .find(|value| match kind {
                        crate::analyzer::semantic::ProcedurePortKind::Receiver => {
                            matches!(value.kind, SemanticValueKind::Receiver { .. })
                        }
                        crate::analyzer::semantic::ProcedurePortKind::Parameter { ordinal } => {
                            matches!(
                                value.kind,
                                SemanticValueKind::Parameter { ordinal: actual, .. }
                                    if actual == ordinal
                            )
                        }
                        crate::analyzer::semantic::ProcedurePortKind::NormalReturn => {
                            value.kind == SemanticValueKind::Return
                        }
                        crate::analyzer::semantic::ProcedurePortKind::ExceptionalReturn => {
                            value.kind == SemanticValueKind::Exception
                        }
                        crate::analyzer::semantic::ProcedurePortKind::Capture { .. }
                        | crate::analyzer::semantic::ProcedurePortKind::IndexedNormalReturn {
                            ..
                        } => false,
                    })
                    .map(|value| value.evidence),
            }
        }
        AccessPathRoot::Static(_)
        | AccessPathRoot::TypeSummary(_)
        | AccessPathRoot::ModuleObject(_)
        | AccessPathRoot::External(_) => Some(procedure.semantics().evidence()),
    };
    Ok(vec![evidence_handle(
        procedure,
        evidence.unwrap_or_else(|| procedure.semantics().evidence()),
    )?])
}

fn gap_impacts_heap(gap: &SemanticGap) -> bool {
    gap.impacts.contains(SemanticGapImpact::HeapRead)
        || gap.impacts.contains(SemanticGapImpact::HeapWrite)
        || gap.impacts.contains(SemanticGapImpact::Aliasing)
}

/// Whether `gap` can open a heap, alias, or points-to answer at all.
///
/// An adapter's implicit-abort gap states that a runtime operation's edge to
/// the exceptional exit is not lowered. Heap and points-to answers are may
/// analyses, so a missing edge can only remove paths from them -- unless a
/// handler or cleanup body on some abort path runs user code, which is the one
/// way the removed path could have carried a store. That is exactly the rule
/// the value-flow plan already applies to the same gap (#1952); applying it
/// here keeps one rule instead of two, and stops an adapter that scopes its
/// implicit-abort gap to the program point, as JavaScript, C# and Python do,
/// from opening every traced value in the procedure (#2495).
///
/// `abort_user_code` memoizes the CFG walk: the answer is a property of the
/// procedure, and most gaps never reach the question.
fn gap_can_open_heap(
    procedure: &ProcedureHandle,
    gap: &SemanticGap,
    abort_user_code: &mut Option<bool>,
) -> bool {
    if !gap_impacts_heap(gap) {
        return false;
    }
    if gap.capability != SemanticCapability::ExceptionalControlFlow {
        return true;
    }
    let user_code = *abort_user_code
        .get_or_insert_with(|| super::abort_paths_run_user_code(procedure.semantics()));
    !super::implicit_abort_gap_is_discharged(gap, user_code)
}

fn heap_gaps_are_open(
    procedure: &ProcedureHandle,
    staged: &mut WorkStager,
    cancellation: &crate::cancellation::CancellationToken,
    mut relevant: impl FnMut(&SemanticGap) -> bool,
) -> Result<bool, Interruption> {
    let mut open = false;
    let mut abort_user_code = None;
    for gap in procedure.semantics().gaps() {
        if cancellation.is_cancelled() {
            return Err(Interruption::Cancelled);
        }
        staged.charge(SemanticWork {
            gaps: 1,
            ..SemanticWork::default()
        })?;
        open |= relevant(gap) && gap_can_open_heap(procedure, gap, &mut abort_user_code);
    }
    Ok(open)
}

fn traced_gap_affects_value(
    procedure: &ProcedureHandle,
    gap: &SemanticGap,
    value: crate::analyzer::semantic::ValueId,
    staged: &mut WorkStager,
    cancellation: &crate::cancellation::CancellationToken,
) -> Result<bool, InterruptionOrProvider> {
    if cancellation.is_cancelled() {
        return Err(InterruptionOrProvider::Interruption(
            Interruption::Cancelled,
        ));
    }
    Ok(match gap.subject {
        // Procedure gaps are handled before tracing because they apply even
        // when an exact producer cuts the trace short.
        SemanticGapSubject::Procedure => false,
        SemanticGapSubject::Point
        | SemanticGapSubject::CallContinuation { .. }
        | SemanticGapSubject::AsyncContinuation { .. } => true,
        SemanticGapSubject::Value(subject) => subject == value,
        SemanticGapSubject::MemoryLocation(location) => {
            staged
                .charge(SemanticWork {
                    memory_locations: 1,
                    ..SemanticWork::default()
                })
                .map_err(InterruptionOrProvider::Interruption)?;
            let _location = procedure
                .semantics()
                .memory_location(location)
                .ok_or_else(|| {
                    InterruptionOrProvider::Provider(SemanticProviderError::internal(
                        "semantic gap has a stale memory location",
                    ))
                })?;
            // A location's base and index determine which cell an operation
            // addresses; uncertainty about that cell does not flow backward
            // into either operand's own pointee identity. A MemoryLoad opens
            // its result explicitly when this trace reaches the load effect.
            // Location and alias queries retain the gap independently.
            false
        }
        SemanticGapSubject::Capture(capture) => {
            staged
                .charge(SemanticWork {
                    captures: 1,
                    ..SemanticWork::default()
                })
                .map_err(InterruptionOrProvider::Interruption)?;
            let capture = procedure.semantics().capture(capture).ok_or_else(|| {
                InterruptionOrProvider::Provider(SemanticProviderError::internal(
                    "semantic gap has a stale capture binding",
                ))
            })?;
            let captured_value = match capture.captured {
                CaptureSource::Value(captured) => captured == value,
                CaptureSource::Location(location) => {
                    staged
                        .charge(SemanticWork {
                            memory_locations: 1,
                            ..SemanticWork::default()
                        })
                        .map_err(InterruptionOrProvider::Interruption)?;
                    procedure
                        .semantics()
                        .memory_location(location)
                        .is_some_and(|location| location.kind.uses_value(value))
                }
            };
            staged
                .charge(SemanticWork {
                    allocations: 1,
                    ..SemanticWork::default()
                })
                .map_err(InterruptionOrProvider::Interruption)?;
            let environment_value = procedure
                .semantics()
                .allocation(capture.environment)
                .is_some_and(|allocation| allocation.result == value);
            capture.callable == value || captured_value || environment_value
        }
        SemanticGapSubject::CallSite(call_site) => {
            staged
                .charge(SemanticWork {
                    call_sites: 1,
                    ..SemanticWork::default()
                })
                .map_err(InterruptionOrProvider::Interruption)?;
            let call = procedure.semantics().call_site(call_site).ok_or_else(|| {
                InterruptionOrProvider::Provider(SemanticProviderError::internal(
                    "semantic gap has a stale call site",
                ))
            })?;
            // A call-site gap can weaken values produced by the call without
            // weakening caller-side values that were evaluated before it.
            // Adapters attach CallEvaluation explicitly when the callee,
            // receiver, or argument evaluation is itself incomplete.
            if call.normal_result_values().any(|result| result == value)
                || call.thrown == Some(value)
            {
                true
            } else if gap.impacts.contains(SemanticGapImpact::CallEvaluation) {
                if call.callee == value || call.receiver == Some(value) {
                    return Ok(true);
                }
                let mut argument_matches = false;
                for argument in &call.arguments {
                    if cancellation.is_cancelled() {
                        return Err(InterruptionOrProvider::Interruption(
                            Interruption::Cancelled,
                        ));
                    }
                    staged
                        .charge(SemanticWork {
                            nested_entries: 1,
                            ..SemanticWork::default()
                        })
                        .map_err(InterruptionOrProvider::Interruption)?;
                    if argument.value == value {
                        argument_matches = true;
                        break;
                    }
                }
                argument_matches
            } else {
                false
            }
        }
    })
}

/// Whether call-result materialization owns the answer to this refinement gap.
///
/// The backward trace encounters a call's generic target-refinement gap before
/// it invokes `materialize_call_result`. Opening the result at that point would
/// make the later complete dispatch, binding, and callee-flow proof unable to
/// close coverage. Defer only this exact result-value question to the
/// materializer. It retains open coverage for unresolved, external, ambiguous,
/// or otherwise incomplete callees, while gaps on the callee value, receiver,
/// arguments, and thrown value keep their ordinary heap meaning.
fn call_result_materialization_owns_gap(
    procedure: &ProcedureHandle,
    gap: &SemanticGap,
    value: crate::analyzer::semantic::ValueId,
) -> bool {
    call_target_refinement_call(procedure.semantics(), gap)
        .and_then(|call| procedure.semantics().call_site(call))
        .is_some_and(|call| call.normal_result_values().any(|result| result == value))
}

fn points_to_capabilities_are_open(procedure: &ProcedureHandle) -> bool {
    let capabilities = procedure.artifact().capabilities();
    [
        SemanticCapability::Values,
        SemanticCapability::Assignments,
        SemanticCapability::Allocations,
        SemanticCapability::LocalFlow,
        SemanticCapability::ParameterFlow,
        SemanticCapability::ReceiverFlow,
        SemanticCapability::ReturnFlow,
        SemanticCapability::Captures,
    ]
    .into_iter()
    .any(|capability| !capabilities.is_available(capability))
}

pub(super) fn points_to_capability_surface_is_incomplete(procedure: &ProcedureHandle) -> bool {
    let capabilities = procedure.artifact().capabilities();
    [
        SemanticCapability::Values,
        SemanticCapability::Assignments,
        SemanticCapability::Allocations,
        SemanticCapability::LocalFlow,
        SemanticCapability::ParameterFlow,
        SemanticCapability::ReceiverFlow,
        SemanticCapability::ReturnFlow,
        SemanticCapability::Captures,
    ]
    .into_iter()
    .any(|capability| !capabilities.is_complete(capability))
}

fn location_capabilities_are_open(access: &AccessPathAtPoint) -> bool {
    let procedure = access.point().procedure();
    let capabilities = procedure.artifact().capabilities();
    points_to_capabilities_are_open(procedure)
        || matches!(access.path().root(), AccessPathRoot::Static(_))
            && !capabilities.is_available(SemanticCapability::StaticMemory)
        || access
            .path()
            .selectors()
            .iter()
            .any(|selector| match selector {
                crate::analyzer::semantic::AccessSelector::Field(_) => {
                    !capabilities.is_available(SemanticCapability::FieldMemory)
                }
                crate::analyzer::semantic::AccessSelector::Index(_) => {
                    !capabilities.is_available(SemanticCapability::IndexMemory)
                }
            })
}

/// Cyclic control-flow membership for one procedure, derived once per query.
///
/// `loop_regions` (#2102) is the workspace's one loop-membership algorithm and
/// it is SCC-based, so it names an irreducible cycle as well as a natural loop.
/// Membership is the whole allocation-cardinality question: a site inside a
/// cyclic region runs an unbounded number of times per activation, so its
/// abstraction summarizes many runtime objects, while a site outside every
/// cyclic region runs at most once. The region's back edges are the exact
/// evidence for that claim, which a per-allocation reachability walk could only
/// approximate with every edge it happened to visit.
struct CyclicRegions {
    region_by_point: Box<[Option<usize>]>,
    back_edge_evidence: Box<[Box<[crate::analyzer::semantic::EvidenceId]>]>,
}

impl CyclicRegions {
    /// Evidence that the allocation point is inside a cyclic region, or `None`
    /// when it is not.
    fn cycle_evidence(
        &self,
        point: crate::analyzer::semantic::ProgramPointId,
    ) -> Option<&[crate::analyzer::semantic::EvidenceId]> {
        self.region_by_point
            .get(point.index())
            .copied()
            .flatten()
            .map(|region| self.back_edge_evidence[region].as_ref())
    }
}

/// Derive cyclic membership, or `None` when the bounded algorithm could not
/// answer. A caller that receives `None` must not claim a singleton.
fn cyclic_regions(
    procedure: &ProcedureHandle,
    staged: &mut WorkStager,
    cancellation: &crate::cancellation::CancellationToken,
) -> Result<Option<CyclicRegions>, Interruption> {
    let semantics = procedure.semantics();
    staged.charge(SemanticWork {
        program_points: semantics.points().len(),
        control_edges: semantics.control_edges().len(),
        ..SemanticWork::default()
    })?;
    let mut budget = CfgAlgorithmBudget::default();
    let regions = match loop_regions(
        semantics,
        &mut CfgAlgorithmRequest::new(&mut budget, cancellation),
    ) {
        Ok(regions) => regions,
        Err(CfgAlgorithmError::Cancelled { .. }) => return Err(Interruption::Cancelled),
        Err(CfgAlgorithmError::ExceededBudget(_) | CfgAlgorithmError::InvalidNode(_)) => {
            return Ok(None);
        }
    };
    let mut region_by_point = vec![None; semantics.points().len()];
    let mut back_edge_evidence = Vec::with_capacity(regions.regions.len());
    for (index, region) in regions.regions.iter().enumerate() {
        for member in &region.members {
            region_by_point[member.index()] = Some(index);
        }
        back_edge_evidence.push(
            region
                .back_edges
                .iter()
                .filter_map(|edge| semantics.control_edge(*edge).map(|row| row.evidence))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        );
    }
    Ok(Some(CyclicRegions {
        region_by_point: region_by_point.into_boxed_slice(),
        back_edge_evidence: back_edge_evidence.into_boxed_slice(),
    }))
}

/// Whether a closure publishes this allocation outside its own activation.
///
/// A captured allocation is reachable from another procedure's activation, and
/// this procedure's loop and recursion evidence says nothing about how many
/// times that activation ran the site. The same rule already makes a
/// [`AccessPathRoot::CaptureSlot`] root a summary object; applying it to the
/// allocation the capture names keeps the two answers consistent.
fn allocation_is_captured(
    procedure: &ProcedureHandle,
    allocation: crate::analyzer::semantic::AllocationId,
    result: crate::analyzer::semantic::ValueId,
) -> bool {
    procedure.semantics().captures().iter().any(|capture| {
        capture.environment == allocation
            || capture.callable == result
            || match capture.captured {
                CaptureSource::Value(value) => value == result,
                CaptureSource::Location(location) => procedure
                    .semantics()
                    .memory_location(location)
                    .is_some_and(|row| row.kind.uses_value(result)),
            }
    })
}

fn push_object(
    drafts: &mut Vec<ObjectDraft>,
    object: AbstractObject,
    evidence: Vec<EvidenceHandle>,
) {
    let evidence = dedup_evidence(evidence);
    let quality = evidence_quality(&evidence);
    push_object_with_quality(drafts, object, evidence, quality);
}

fn push_object_with_quality(
    drafts: &mut Vec<ObjectDraft>,
    object: AbstractObject,
    evidence: Vec<EvidenceHandle>,
    quality: (ProofStatus, EvidenceCompleteness),
) {
    let evidence = dedup_evidence(evidence);
    let quality = merge_quality(&quality, &evidence_quality(&evidence));
    if let Some(existing) = drafts
        .iter_mut()
        .find(|candidate| candidate.object == object)
    {
        existing.evidence = dedup_evidence(existing.evidence.iter().cloned().chain(evidence));
        let merged = merge_quality(
            &(existing.proof.clone(), existing.completeness.clone()),
            &quality,
        );
        existing.proof = merged.0;
        existing.completeness = merged.1;
    } else {
        drafts.push(ObjectDraft {
            object,
            evidence,
            proof: quality.0,
            completeness: quality.1,
        });
    }
}

fn truncate_object_drafts(
    drafts: &mut Vec<ObjectDraft>,
    limits: crate::analyzer::semantic::OracleLimits,
) {
    drafts.truncate(limits.objects_per_value().min(limits.provenance_records()));
    let mut remaining_evidence = limits.evidence_handles();
    let mut retained = 0usize;
    for draft in drafts.iter_mut() {
        if remaining_evidence == 0 {
            break;
        }
        if draft.evidence.len() > remaining_evidence {
            draft.evidence.truncate(remaining_evidence);
            draft.completeness = EvidenceCompleteness::Partial(
                "points-to provenance was truncated by the oracle evidence limit".into(),
            );
        }
        remaining_evidence = remaining_evidence.saturating_sub(draft.evidence.len());
        retained += 1;
    }
    drafts.truncate(retained);
}

fn symbolic_object(
    procedure: &ProcedureHandle,
    value: ValueHandle,
    evidence: Vec<EvidenceHandle>,
) -> Result<ObjectDraft, SemanticProviderError> {
    let row = procedure
        .semantics()
        .value(value.id())
        .ok_or_else(|| SemanticProviderError::internal("value handle is stale"))?;
    let identity = match &row.kind {
        SemanticValueKind::Parameter { ordinal, .. } => AbstractObjectIdentity::ProcedurePort(
            ProcedurePortHandle::parameter(procedure.clone(), *ordinal)
                .map_err(|error| internal_contract("invalid parameter object", error))?,
        ),
        SemanticValueKind::Receiver { .. } => AbstractObjectIdentity::ProcedurePort(
            ProcedurePortHandle::receiver(procedure.clone())
                .map_err(|error| internal_contract("invalid receiver object", error))?,
        ),
        _ => AbstractObjectIdentity::Value(value),
    };
    let object = AbstractObject::new(identity, ObjectCardinality::Unknown)
        .map_err(|error| internal_contract("invalid symbolic object", error))?;
    let evidence = dedup_evidence(evidence);
    let quality = evidence_quality(&evidence);
    Ok(ObjectDraft {
        object,
        evidence,
        proof: quality.0,
        completeness: quality.1,
    })
}

#[derive(Debug, Default)]
struct CallResultResolution {
    open: bool,
    truncated: bool,
    ambiguous: bool,
}

impl CallResultResolution {
    fn absorb_coverage(&mut self, coverage: CandidateCoverage) {
        match coverage {
            CandidateCoverage::Exhaustive => {}
            CandidateCoverage::Open => self.open = true,
            CandidateCoverage::Truncated => self.truncated = true,
        }
    }
}

fn outcome_is_open<T>(outcome: &SemanticOutcome<T>) -> bool {
    matches!(
        outcome,
        SemanticOutcome::Unknown { .. }
            | SemanticOutcome::Unsupported { .. }
            | SemanticOutcome::Unproven { .. }
    )
}

fn outcome_is_ambiguous<T>(outcome: &SemanticOutcome<T>) -> bool {
    matches!(outcome, SemanticOutcome::Ambiguous { .. })
}

fn outcome_interruption<T>(outcome: &SemanticOutcome<T>) -> Option<Interruption> {
    match outcome {
        SemanticOutcome::ExceededBudget { exceeded, .. } => Some(Interruption::Budget(*exceeded)),
        SemanticOutcome::Cancelled { .. } => Some(Interruption::Cancelled),
        SemanticOutcome::Complete { .. }
        | SemanticOutcome::Ambiguous { .. }
        | SemanticOutcome::Unknown { .. }
        | SemanticOutcome::Unsupported { .. }
        | SemanticOutcome::Unproven { .. } => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn materialize_call_result(
    oracle: &WorkspaceSemanticOracle<'_>,
    query: &ValueAtPoint,
    state: TraceState,
    inherited_evidence: &[EvidenceHandle],
    drafts: &mut Vec<ObjectDraft>,
    limits: crate::analyzer::semantic::OracleLimits,
    staged: &mut WorkStager,
    cancellation: &crate::cancellation::CancellationToken,
) -> Result<Option<CallResultResolution>, InterruptionOrProvider> {
    let procedure = query.point().procedure();
    if cancellation.is_cancelled() {
        return Err(InterruptionOrProvider::Interruption(
            Interruption::Cancelled,
        ));
    }
    let Some(call_ids) = procedure
        .semantics()
        .call_result_site_ids(state.value, state.point)
    else {
        return Ok(None);
    };
    let mut resolution = CallResultResolution {
        ambiguous: call_ids.len() > 1,
        ..CallResultResolution::default()
    };
    for call_id in call_ids {
        if cancellation.is_cancelled() {
            return Err(InterruptionOrProvider::Interruption(
                Interruption::Cancelled,
            ));
        }
        let call_row = procedure.semantics().call_site(*call_id).ok_or_else(|| {
            InterruptionOrProvider::Provider(SemanticProviderError::internal(
                "call-result index reached a stale call site",
            ))
        })?;
        let call_resolution = materialize_one_call_result(
            oracle,
            query,
            state,
            call_row,
            inherited_evidence,
            drafts,
            limits,
            staged,
            cancellation,
        )?;
        resolution.open |= call_resolution.open;
        resolution.truncated |= call_resolution.truncated;
        resolution.ambiguous |= call_resolution.ambiguous;
    }
    Ok(Some(resolution))
}

#[allow(clippy::too_many_arguments)]
fn materialize_one_call_result(
    oracle: &WorkspaceSemanticOracle<'_>,
    query: &ValueAtPoint,
    state: TraceState,
    call_row: &SemanticCallSite,
    inherited_evidence: &[EvidenceHandle],
    drafts: &mut Vec<ObjectDraft>,
    limits: crate::analyzer::semantic::OracleLimits,
    staged: &mut WorkStager,
    cancellation: &crate::cancellation::CancellationToken,
) -> Result<CallResultResolution, InterruptionOrProvider> {
    let procedure = query.point().procedure();
    let call = procedure.call_site_handle(call_row.id).ok_or_else(|| {
        InterruptionOrProvider::Provider(SemanticProviderError::internal(
            "call-result trace reached a stale call site",
        ))
    })?;
    let result = value_handle(procedure, state.value).map_err(InterruptionOrProvider::Provider)?;
    let result_row = procedure
        .semantics()
        .value(state.value)
        .expect("value handles are validated at construction");
    let caller_evidence = dedup_evidence(
        inherited_evidence.iter().cloned().chain([
            evidence_handle(procedure, call_row.evidence)
                .map_err(InterruptionOrProvider::Provider)?,
            evidence_handle(procedure, result_row.evidence)
                .map_err(InterruptionOrProvider::Provider)?,
        ]),
    );
    let initial_candidates = drafts.len();
    let mut resolution = CallResultResolution::default();

    let dispatch_outcome = {
        let mut request = staged.request(cancellation);
        oracle
            .resolve_call(&call, &mut request)
            .map_err(InterruptionOrProvider::Provider)?
    };
    staged.work = staged.work.conservative_add(dispatch_outcome.work());
    if let Some(interruption) = outcome_interruption(&dispatch_outcome) {
        return Err(InterruptionOrProvider::Interruption(interruption));
    }
    resolution.open |= outcome_is_open(&dispatch_outcome);
    resolution.ambiguous |= outcome_is_ambiguous(&dispatch_outcome);
    let Some(dispatch) = dispatch_outcome.available_value() else {
        let draft = symbolic_object(procedure, result, caller_evidence)
            .map_err(InterruptionOrProvider::Provider)?;
        push_object(&mut *drafts, draft.object, draft.evidence);
        resolution.open = true;
        return Ok(resolution);
    };
    resolution.absorb_coverage(dispatch.coverage());
    resolution.open |= !dispatch.boundaries().is_empty();

    for candidate in dispatch.candidates() {
        if cancellation.is_cancelled() {
            return Err(InterruptionOrProvider::Interruption(
                Interruption::Cancelled,
            ));
        }
        let bindings_outcome = {
            let mut request = staged.request(cancellation);
            oracle
                .call_bindings(&call, candidate, query.context(), &mut request)
                .map_err(InterruptionOrProvider::Provider)?
        };
        staged.work = staged.work.conservative_add(bindings_outcome.work());
        if let Some(interruption) = outcome_interruption(&bindings_outcome) {
            return Err(InterruptionOrProvider::Interruption(interruption));
        }
        resolution.open |= outcome_is_open(&bindings_outcome);
        resolution.ambiguous |= outcome_is_ambiguous(&bindings_outcome);
        let Some(bindings) = bindings_outcome.available_value() else {
            resolution.open = true;
            continue;
        };
        resolution.absorb_coverage(bindings.coverage());

        let callee_context = query.context().extended(call.clone(), limits);
        resolution.open |= callee_context.was_truncated();
        let flow_outcome = {
            let mut request = staged.request(cancellation);
            oracle
                .procedure_relations(candidate.target(), &callee_context, &mut request)
                .map_err(InterruptionOrProvider::Provider)?
        };
        staged.work = staged.work.conservative_add(flow_outcome.work());
        if let Some(interruption) = outcome_interruption(&flow_outcome) {
            return Err(InterruptionOrProvider::Interruption(interruption));
        }
        resolution.open |= outcome_is_open(&flow_outcome);
        resolution.ambiguous |= outcome_is_ambiguous(&flow_outcome);
        let Some(flow) = flow_outcome.available_value() else {
            resolution.open = true;
            continue;
        };
        resolution.absorb_coverage(flow.coverage());

        let handle = match CallResultHandle::new(bindings, flow, &result, limits) {
            Ok(handle) => handle,
            Err(OracleContractError::LimitExceeded { .. }) => {
                resolution.truncated = true;
                continue;
            }
            Err(OracleContractError::InvalidAccessRoot(_)) => {
                resolution.open = true;
                continue;
            }
            Err(error) => {
                return Err(InterruptionOrProvider::Provider(internal_contract(
                    "invalid call-result object",
                    error,
                )));
            }
        };
        let mut quality = (candidate.proof().clone(), candidate.completeness().clone());
        for relation in handle.return_relations() {
            quality = merge_quality(
                &quality,
                &(relation.proof.clone(), relation.completeness.clone()),
            );
        }
        let object = AbstractObject::new(
            AbstractObjectIdentity::CallResult(handle),
            ObjectCardinality::Unknown,
        )
        .map_err(|error| {
            InterruptionOrProvider::Provider(internal_contract("invalid call-result object", error))
        })?;
        push_object_with_quality(drafts, object, caller_evidence.clone(), quality);
    }

    if drafts.len() == initial_candidates {
        let draft = symbolic_object(procedure, result, caller_evidence)
            .map_err(InterruptionOrProvider::Provider)?;
        push_object(drafts, draft.object, draft.evidence);
        resolution.open = true;
    }
    Ok(resolution)
}

fn resolve_objects(
    oracle: &WorkspaceSemanticOracle<'_>,
    query: &ValueAtPoint,
    limits: crate::analyzer::semantic::OracleLimits,
    staged: &mut WorkStager,
    cancellation: &crate::cancellation::CancellationToken,
) -> Result<DraftSet<ObjectDraft>, InterruptionOrProvider> {
    let procedure = query.point().procedure();
    staged
        .charge(SemanticWork {
            procedures: 1,
            values: 1,
            ..SemanticWork::default()
        })
        .map_err(InterruptionOrProvider::Interruption)?;
    let gaps_open = heap_gaps_are_open(procedure, staged, cancellation, |gap| {
        gap.subject == SemanticGapSubject::Procedure
    })
    .map_err(InterruptionOrProvider::Interruption)?;
    let mut open = points_to_capabilities_are_open(procedure) || gaps_open;
    open |= query.context().was_truncated();
    let point_row = procedure
        .semantics()
        .point(query.point().id())
        .ok_or_else(|| {
            InterruptionOrProvider::Provider(SemanticProviderError::internal(
                "program-point handle is stale",
            ))
        })?;
    let initial_limit = match query.phase() {
        ObservationPhase::BeforeEffects => 0,
        ObservationPhase::AfterEffects => point_row.events.len(),
    };
    let mut stack = vec![(
        TraceState {
            value: query.value().id(),
            point: query.point().id(),
            event_limit: initial_limit,
            summary_depth: 0,
        },
        Vec::<EvidenceHandle>::new(),
    )];
    let mut visited = HashSet::default();
    let mut drafts = Vec::new();
    let mut truncated = false;
    let mut ambiguous = false;
    let mut abort_user_code = None;
    // Loop membership is a property of the procedure, so the derivation runs at
    // most once per query no matter how many allocations the trace reaches.
    let mut cyclic: Option<Option<CyclicRegions>> = None;

    while let Some((state, inherited_evidence)) = stack.pop() {
        if cancellation.is_cancelled() {
            return Err(InterruptionOrProvider::Interruption(
                Interruption::Cancelled,
            ));
        }
        if !visited.insert(state) {
            continue;
        }
        staged
            .charge(SemanticWork {
                program_points: 1,
                values: 1,
                nested_entries: 1,
                ..SemanticWork::default()
            })
            .map_err(InterruptionOrProvider::Interruption)?;
        let point = procedure.semantics().point(state.point).ok_or_else(|| {
            InterruptionOrProvider::Provider(SemanticProviderError::internal(
                "trace reached a stale program point",
            ))
        })?;
        let mut producer = None;
        for (index, event) in point.events[..state.event_limit].iter().enumerate().rev() {
            staged
                .charge(SemanticWork {
                    events: 1,
                    ..SemanticWork::default()
                })
                .map_err(InterruptionOrProvider::Interruption)?;
            if let SemanticEffect::Gap { gap } = event.effect {
                staged
                    .charge(SemanticWork {
                        gaps: 1,
                        ..SemanticWork::default()
                    })
                    .map_err(InterruptionOrProvider::Interruption)?;
                let gap = procedure.semantics().gap(gap).ok_or_else(|| {
                    InterruptionOrProvider::Provider(SemanticProviderError::internal(
                        "semantic gap event has a stale gap ID",
                    ))
                })?;
                if gap_can_open_heap(procedure, gap, &mut abort_user_code)
                    && traced_gap_affects_value(procedure, gap, state.value, staged, cancellation)?
                    && !call_result_materialization_owns_gap(procedure, gap, state.value)
                    && !constructor_allocation_identity_discharges_gap(
                        procedure.semantics(),
                        gap,
                        state.value,
                    )
                {
                    open = true;
                }
                continue;
            }
            let source = match event.effect {
                SemanticEffect::Assignment { target, value } if target == state.value => {
                    Some(value)
                }
                SemanticEffect::ValueFlow { source, target, .. } if target == state.value => {
                    Some(source)
                }
                _ => None,
            };
            if let Some(source) = source {
                let evidence = dedup_evidence(
                    inherited_evidence.iter().cloned().chain(std::iter::once(
                        evidence_handle(procedure, event.evidence)
                            .map_err(InterruptionOrProvider::Provider)?,
                    )),
                );
                producer = Some((source, index, evidence));
                break;
            }
            if let SemanticEffect::Allocation { allocation } = event.effect {
                let allocation_row =
                    procedure
                        .semantics()
                        .allocation(allocation)
                        .ok_or_else(|| {
                            InterruptionOrProvider::Provider(SemanticProviderError::internal(
                                "allocation effect has a stale allocation ID",
                            ))
                        })?;
                if allocation_row.result == state.value {
                    staged
                        .charge(SemanticWork {
                            allocations: 1,
                            ..SemanticWork::default()
                        })
                        .map_err(InterruptionOrProvider::Interruption)?;
                    if cyclic.is_none() {
                        cyclic = Some(
                            cyclic_regions(procedure, staged, cancellation)
                                .map_err(InterruptionOrProvider::Interruption)?,
                        );
                    }
                    let regions = cyclic
                        .as_ref()
                        .expect("cyclic membership was derived above")
                        .as_ref();
                    let cycle_evidence = regions
                        .and_then(|regions| regions.cycle_evidence(allocation_row.point))
                        .map(<[_]>::to_vec);
                    let handle = procedure.allocation_handle(allocation).ok_or_else(|| {
                        InterruptionOrProvider::Provider(SemanticProviderError::internal(
                            "allocation handle is stale",
                        ))
                    })?;
                    let recursive_context = query
                        .context()
                        .calls()
                        .iter()
                        .any(|call| call.procedure() == procedure);
                    // #2444: an allocation denotes exactly one runtime object
                    // when nothing can run its site twice within the activation
                    // this query names, and when no closure can observe the
                    // object from an activation whose loop and recursion
                    // evidence this query does not hold. `Unknown` remains the
                    // answer when the bounded loop derivation could not run at
                    // all, because absence of a region is then not a proof.
                    let cardinality = if cycle_evidence.is_some() || recursive_context {
                        ObjectCardinality::Summary
                    } else if regions.is_some()
                        && !allocation_is_captured(procedure, allocation, allocation_row.result)
                    {
                        ObjectCardinality::Singleton
                    } else {
                        ObjectCardinality::Unknown
                    };
                    let object = AbstractObject::new(
                        AbstractObjectIdentity::Allocation(handle),
                        cardinality,
                    )
                    .map_err(|error| {
                        InterruptionOrProvider::Provider(internal_contract(
                            "invalid allocation object",
                            error,
                        ))
                    })?;
                    let cycle_evidence = cycle_evidence
                        .unwrap_or_default()
                        .into_iter()
                        .map(|id| evidence_handle(procedure, id))
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(InterruptionOrProvider::Provider)?;
                    let recursive_evidence = query
                        .context()
                        .calls()
                        .iter()
                        .filter(|call| call.procedure() == procedure)
                        .map(|call| {
                            let row = call
                                .procedure()
                                .semantics()
                                .call_site(call.id())
                                .ok_or_else(|| {
                                    SemanticProviderError::internal(
                                        "oracle call context contains a stale call site",
                                    )
                                })?;
                            evidence_handle(call.procedure(), row.evidence)
                        })
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(InterruptionOrProvider::Provider)?;
                    let evidence = dedup_evidence(
                        inherited_evidence
                            .iter()
                            .cloned()
                            .chain([
                                evidence_handle(procedure, event.evidence)
                                    .map_err(InterruptionOrProvider::Provider)?,
                                evidence_handle(procedure, allocation_row.evidence)
                                    .map_err(InterruptionOrProvider::Provider)?,
                            ])
                            .chain(cycle_evidence)
                            .chain(recursive_evidence),
                    );
                    push_object(&mut drafts, object, evidence);
                    producer = Some((state.value, index, Vec::new()));
                    break;
                }
            }
            if matches!(
                event.effect,
                SemanticEffect::MemoryLoad { result, .. } if result == state.value
            ) {
                open = true;
                let value = value_handle(procedure, state.value)
                    .map_err(InterruptionOrProvider::Provider)?;
                let evidence = dedup_evidence(
                    inherited_evidence.iter().cloned().chain(std::iter::once(
                        evidence_handle(procedure, event.evidence)
                            .map_err(InterruptionOrProvider::Provider)?,
                    )),
                );
                let draft = symbolic_object(procedure, value, evidence)
                    .map_err(InterruptionOrProvider::Provider)?;
                push_object(&mut drafts, draft.object, draft.evidence);
                producer = Some((state.value, index, Vec::new()));
                break;
            }
        }
        if producer.is_none()
            && let Some(resolution) = materialize_call_result(
                oracle,
                query,
                state,
                &inherited_evidence,
                &mut drafts,
                limits,
                staged,
                cancellation,
            )?
        {
            open |= resolution.open;
            truncated |= resolution.truncated;
            ambiguous |= resolution.ambiguous;
            producer = Some((state.value, state.event_limit, Vec::new()));
        }
        if let Some((source, event_limit, evidence)) = producer {
            if source != state.value {
                if state.summary_depth >= limits.summary_depth() {
                    // Preserve candidates found along other paths but expose
                    // that this producer chain was not fully explored.
                    truncated = true;
                } else {
                    stack.push((
                        TraceState {
                            value: source,
                            point: state.point,
                            event_limit,
                            summary_depth: state.summary_depth + 1,
                        },
                        evidence,
                    ));
                }
            }
        } else {
            let predecessors = procedure
                .semantics()
                .cfg()
                .predecessor_edges(state.point)
                .map(|(_, edge)| (edge.source_point, edge.evidence))
                .collect::<Vec<_>>();
            staged
                .charge(SemanticWork {
                    control_edges: predecessors.len(),
                    ..SemanticWork::default()
                })
                .map_err(InterruptionOrProvider::Interruption)?;
            if predecessors.is_empty() {
                let value = value_handle(procedure, state.value)
                    .map_err(InterruptionOrProvider::Provider)?;
                let value_row = procedure
                    .semantics()
                    .value(state.value)
                    .expect("value handle is validated");
                let evidence = dedup_evidence(
                    inherited_evidence.into_iter().chain(std::iter::once(
                        evidence_handle(procedure, value_row.evidence)
                            .map_err(InterruptionOrProvider::Provider)?,
                    )),
                );
                let draft = symbolic_object(procedure, value, evidence)
                    .map_err(InterruptionOrProvider::Provider)?;
                open |= !matches!(
                    value_row.kind,
                    SemanticValueKind::Parameter { .. } | SemanticValueKind::Receiver { .. }
                );
                push_object(&mut drafts, draft.object, draft.evidence);
            } else {
                for (predecessor, edge_evidence) in predecessors {
                    let event_limit = procedure
                        .semantics()
                        .point(predecessor)
                        .expect("control-flow edges target validated points")
                        .events
                        .len();
                    stack.push((
                        TraceState {
                            value: state.value,
                            point: predecessor,
                            event_limit,
                            summary_depth: state.summary_depth,
                        },
                        dedup_evidence(
                            inherited_evidence.iter().cloned().chain(std::iter::once(
                                evidence_handle(procedure, edge_evidence)
                                    .map_err(InterruptionOrProvider::Provider)?,
                            )),
                        ),
                    ));
                }
            }
        }
        if drafts.len() > limits.objects_per_value()
            || drafts.len() > limits.provenance_records()
            || drafts
                .iter()
                .map(|draft| draft.evidence.len())
                .sum::<usize>()
                > limits.evidence_handles()
        {
            truncate_object_drafts(&mut drafts, limits);
            truncated = true;
            break;
        }
    }

    Ok(DraftSet {
        candidates: drafts,
        coverage: if truncated {
            CandidateCoverage::Truncated
        } else if open {
            CandidateCoverage::Open
        } else {
            CandidateCoverage::Exhaustive
        },
        ambiguous,
    })
}

enum InterruptionOrProvider {
    Interruption(Interruption),
    Provider(SemanticProviderError),
}

fn materialize_points_to(
    query: &ValueAtPoint,
    drafts: DraftSet<ObjectDraft>,
    limits: crate::analyzer::semantic::OracleLimits,
) -> Result<PointsToResult, SemanticProviderError> {
    let records = drafts
        .candidates
        .iter()
        .map(|draft| {
            OracleRelationRecord::new(OracleRelationKind::PointsTo, draft.evidence.clone(), limits)
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| internal_contract("could not create points-to provenance", error))?;
    let arena = OracleRelationArena::new(
        OracleRelationOwner::PointsTo(Box::new(query.clone())),
        records,
        limits,
    )
    .map_err(|error| internal_contract("could not create points-to arena", error))?;
    let candidates = drafts
        .candidates
        .into_iter()
        .enumerate()
        .map(|(index, draft)| {
            let id = u32::try_from(index)
                .map(OracleRelationId::new)
                .map_err(|_| SemanticProviderError::internal("points-to relation ID overflow"))?;
            OracleCandidate::new(
                draft.object,
                draft.proof,
                draft.completeness,
                [arena
                    .handle(id)
                    .expect("points-to record was inserted into the arena")],
                limits,
            )
            .map_err(|error| internal_contract("invalid points-to candidate", error))
        })
        .collect::<Result<Vec<_>, _>>()?;
    PointsToResult::new(query.clone(), candidates, drafts.coverage, limits)
        .map_err(|error| internal_contract("invalid points-to result", error))
}

fn candidate_publication_work(candidate_count: usize, evidence_count: usize) -> SemanticWork {
    SemanticWork {
        evidence: evidence_count,
        nested_entries: candidate_count,
        ..SemanticWork::default()
    }
}

fn resolve_locations(
    oracle: &WorkspaceSemanticOracle<'_>,
    query: &AccessPathAtPoint,
    limits: crate::analyzer::semantic::OracleLimits,
    staged: &mut WorkStager,
    cancellation: &crate::cancellation::CancellationToken,
) -> Result<DraftSet<LocationDraft>, InterruptionOrProvider> {
    let procedure = query.point().procedure();
    let objects = if let Some(value) = match query.path().root() {
        AccessPathRoot::Value(value) => Some(value.clone()),
        AccessPathRoot::CallResult(result) => Some(result.result().clone()),
        AccessPathRoot::Allocation(allocation) => procedure
            .semantics()
            .allocation(allocation.id())
            .and_then(|row| procedure.value_handle(row.result)),
        AccessPathRoot::ProcedurePort(_)
        | AccessPathRoot::Static(_)
        | AccessPathRoot::LexicalCell(_)
        | AccessPathRoot::CaptureSlot(_)
        | AccessPathRoot::TypeSummary(_)
        | AccessPathRoot::ModuleObject(_)
        | AccessPathRoot::External(_) => None,
    } {
        let value = ValueAtPoint::new(
            value,
            query.point().clone(),
            query.phase(),
            query.context().clone(),
        )
        .map_err(|error| {
            InterruptionOrProvider::Provider(internal_contract("invalid value-root query", error))
        })?;
        let mut objects = resolve_objects(oracle, &value, limits, staged, cancellation)?;
        if let AccessPathRoot::Allocation(expected) = query.path().root() {
            objects.candidates.retain(|candidate| {
                matches!(
                    candidate.object.identity(),
                    AbstractObjectIdentity::Allocation(actual) if actual == expected
                )
            });
            if objects.candidates.is_empty() {
                objects.coverage = CandidateCoverage::Open;
            }
        }
        if let AccessPathRoot::CallResult(expected) = query.path().root() {
            objects.candidates.retain(|candidate| {
                matches!(
                    candidate.object.identity(),
                    AbstractObjectIdentity::CallResult(actual) if actual == expected
                )
            });
            if objects.candidates.is_empty() {
                objects.coverage = CandidateCoverage::Open;
            }
        }
        objects
    } else {
        staged
            .charge(SemanticWork {
                procedures: 1,
                memory_locations: 1,
                ..SemanticWork::default()
            })
            .map_err(InterruptionOrProvider::Interruption)?;
        let gaps_open = heap_gaps_are_open(procedure, staged, cancellation, |_| true)
            .map_err(InterruptionOrProvider::Interruption)?;
        let open =
            location_capabilities_are_open(query) || gaps_open || query.context().was_truncated();
        let evidence = root_evidence(procedure, query.path().root())
            .map_err(InterruptionOrProvider::Provider)?;
        let mut quality = evidence_quality(&evidence);
        if matches!(
            query.path().root(),
            AccessPathRoot::Static(_)
                | AccessPathRoot::CallResult(_)
                | AccessPathRoot::TypeSummary(_)
                | AccessPathRoot::ModuleObject(_)
                | AccessPathRoot::External(_)
        ) {
            quality = (
                ProofStatus::Unproven(
                    "locator root is not backed by a procedure-local memory row".into(),
                ),
                EvidenceCompleteness::Partial(
                    "workspace locator resolution is not yet attached to heap roots".into(),
                ),
            );
        }
        let cardinality = if query.context().was_truncated()
            && matches!(query.path().root(), AccessPathRoot::LexicalCell(_))
        {
            ObjectCardinality::Unknown
        } else {
            candidate_cardinality_for_root(query.path().root())
        };
        let object =
            AbstractObject::new(query.path().root().clone(), cardinality).map_err(|error| {
                InterruptionOrProvider::Provider(internal_contract("invalid access root", error))
            })?;
        DraftSet {
            candidates: vec![ObjectDraft {
                object,
                evidence,
                proof: quality.0,
                completeness: quality.1,
            }],
            coverage: if open {
                CandidateCoverage::Open
            } else {
                CandidateCoverage::Exhaustive
            },
            ambiguous: false,
        }
    };
    let mut candidates = Vec::new();
    let mut truncated = objects.coverage == CandidateCoverage::Truncated;
    let ambiguous = objects.ambiguous;
    for draft in objects.candidates {
        if cancellation.is_cancelled() {
            return Err(InterruptionOrProvider::Interruption(
                Interruption::Cancelled,
            ));
        }
        staged
            .charge(SemanticWork {
                nested_entries: 1,
                ..SemanticWork::default()
            })
            .map_err(InterruptionOrProvider::Interruption)?;
        let path = AccessPath::bounded(
            draft.object.identity().clone(),
            query.path().selectors().to_vec(),
            query.path().tail(),
            limits,
        )
        .map_err(|error| {
            InterruptionOrProvider::Provider(internal_contract(
                "invalid resolved access path",
                error,
            ))
        })?;
        let location = AbstractLocation::new(draft.object, path).map_err(|error| {
            InterruptionOrProvider::Provider(internal_contract("invalid resolved location", error))
        })?;
        candidates.push(LocationDraft {
            location,
            evidence: draft.evidence,
            proof: draft.proof,
            completeness: draft.completeness,
        });
        if candidates.len() > limits.alias_breadth()
            || candidates.len() > limits.provenance_records()
            || candidates
                .iter()
                .map(|candidate| candidate.evidence.len())
                .sum::<usize>()
                > limits.evidence_handles()
        {
            candidates.truncate(limits.alias_breadth().min(limits.provenance_records()));
            truncated = true;
            break;
        }
    }
    Ok(DraftSet {
        candidates,
        coverage: if truncated {
            CandidateCoverage::Truncated
        } else {
            objects.coverage
        },
        ambiguous,
    })
}

fn materialize_locations(
    query: &AccessPathAtPoint,
    drafts: DraftSet<LocationDraft>,
    limits: crate::analyzer::semantic::OracleLimits,
) -> Result<LocationResult, SemanticProviderError> {
    let records = drafts
        .candidates
        .iter()
        .map(|draft| {
            OracleRelationRecord::new(OracleRelationKind::Location, draft.evidence.clone(), limits)
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| internal_contract("could not create location provenance", error))?;
    let arena = OracleRelationArena::new(
        OracleRelationOwner::Locations(Box::new(query.clone())),
        records,
        limits,
    )
    .map_err(|error| internal_contract("could not create location arena", error))?;
    let candidates = drafts
        .candidates
        .into_iter()
        .enumerate()
        .map(|(index, draft)| {
            let id = u32::try_from(index)
                .map(OracleRelationId::new)
                .map_err(|_| SemanticProviderError::internal("location relation ID overflow"))?;
            OracleCandidate::new(
                draft.location,
                draft.proof,
                draft.completeness,
                [arena
                    .handle(id)
                    .expect("location record was inserted into the arena")],
                limits,
            )
            .map_err(|error| internal_contract("invalid location candidate", error))
        })
        .collect::<Result<Vec<_>, _>>()?;
    LocationResult::new(query.clone(), candidates, drafts.coverage, limits)
        .map_err(|error| internal_contract("invalid location result", error))
}

fn candidates_proven_complete<T>(candidates: &[T], quality: impl Fn(&T) -> bool) -> bool {
    candidates.iter().all(quality)
}

fn publish_set_outcome<T>(
    value: T,
    coverage: CandidateCoverage,
    proven_complete: bool,
    ambiguous: bool,
    interruption: Option<Interruption>,
    work: SemanticWork,
) -> SemanticOutcome<T> {
    match interruption {
        Some(Interruption::Budget(exceeded)) => SemanticOutcome::ExceededBudget {
            partial: Some(value),
            exceeded,
            work,
        },
        Some(Interruption::Cancelled) => SemanticOutcome::Cancelled {
            partial: Some(value),
            work,
        },
        None if coverage == CandidateCoverage::Truncated || !proven_complete => {
            SemanticOutcome::Unproven {
                partial: value,
                work,
            }
        }
        None if coverage == CandidateCoverage::Open => SemanticOutcome::Unknown {
            partial: Some(value),
            work,
        },
        None if ambiguous => SemanticOutcome::Ambiguous {
            candidates: value,
            work,
        },
        None => SemanticOutcome::Complete { value, work },
    }
}

fn paths_structurally_disjoint(left: &AbstractLocation, right: &AbstractLocation) -> bool {
    use AbstractObjectIdentity as Identity;
    if left.object().identity() != right.object().identity() {
        return matches!(
            (left.object().identity(), right.object().identity()),
            (Identity::Allocation(_), Identity::Allocation(_))
                | (Identity::LexicalCell(_), Identity::LexicalCell(_))
                | (Identity::CaptureSlot(_), Identity::CaptureSlot(_))
                | (Identity::Static(_), Identity::Static(_))
                | (Identity::Allocation(_), Identity::LexicalCell(_))
                | (Identity::LexicalCell(_), Identity::Allocation(_))
                | (Identity::Allocation(_), Identity::CaptureSlot(_))
                | (Identity::CaptureSlot(_), Identity::Allocation(_))
                | (Identity::LexicalCell(_), Identity::CaptureSlot(_))
                | (Identity::CaptureSlot(_), Identity::LexicalCell(_))
        );
    }
    if !left.path().is_exact() || !right.path().is_exact() {
        return false;
    }
    left.path()
        .selectors()
        .iter()
        .zip(right.path().selectors())
        .find(|(left, right)| left != right)
        .is_some_and(|(left, right)| {
            matches!(
                (left, right),
                (
                    crate::analyzer::semantic::AccessSelector::Field(_),
                    crate::analyzer::semantic::AccessSelector::Field(_)
                )
            )
        })
}

fn alias_relation(
    query: &AliasQuery,
    left: &DraftSet<LocationDraft>,
    right: &DraftSet<LocationDraft>,
) -> AliasRelation {
    let exhaustive = left.coverage == CandidateCoverage::Exhaustive
        && right.coverage == CandidateCoverage::Exhaustive;
    if query.left() == query.right() {
        return AliasRelation::MustAlias;
    }
    if exhaustive
        && left.candidates.len() == 1
        && right.candidates.len() == 1
        && left.candidates[0].location == right.candidates[0].location
        && left.candidates[0].location.path().is_exact()
        && left.candidates[0].location.object().cardinality() == ObjectCardinality::Singleton
    {
        return AliasRelation::MustAlias;
    }
    if exhaustive
        && !left.candidates.is_empty()
        && !right.candidates.is_empty()
        && left.candidates.iter().all(|left| {
            right
                .candidates
                .iter()
                .all(|right| paths_structurally_disjoint(&left.location, &right.location))
        })
    {
        AliasRelation::Disjoint
    } else {
        AliasRelation::MayAlias
    }
}

fn materialize_alias(
    query: &AliasQuery,
    relation: AliasRelation,
    evidence: Vec<EvidenceHandle>,
    quality: (ProofStatus, EvidenceCompleteness),
    limits: crate::analyzer::semantic::OracleLimits,
) -> Result<AliasResult, SemanticProviderError> {
    let record = OracleRelationRecord::new(OracleRelationKind::Alias, evidence, limits)
        .map_err(|error| internal_contract("could not create alias provenance", error))?;
    let arena = OracleRelationArena::new(
        OracleRelationOwner::Alias(Box::new(query.clone())),
        vec![record],
        limits,
    )
    .map_err(|error| internal_contract("could not create alias arena", error))?;
    let answer = OracleCandidate::new(
        relation,
        quality.0,
        quality.1,
        [arena
            .handle(OracleRelationId::new(0))
            .expect("alias record was inserted into the arena")],
        limits,
    )
    .map_err(|error| internal_contract("invalid alias answer", error))?;
    AliasResult::new(query.clone(), answer, limits)
        .map_err(|error| internal_contract("invalid alias result", error))
}

fn direct_weak_reasons(
    coverage: CandidateCoverage,
    locations: &[LocationDraft],
) -> Box<[WeakUpdateReason]> {
    let mut reasons = Vec::new();
    match coverage {
        CandidateCoverage::Exhaustive => {}
        CandidateCoverage::Open => {
            reasons.push(WeakUpdateReason::NonExhaustiveLocations);
            reasons.push(WeakUpdateReason::NonExhaustiveObjects);
        }
        CandidateCoverage::Truncated => {
            reasons.push(WeakUpdateReason::TruncatedLocations);
            reasons.push(WeakUpdateReason::TruncatedObjects);
        }
    }
    if locations.is_empty() {
        reasons.push(WeakUpdateReason::NoLocation);
        reasons.push(WeakUpdateReason::NoObject);
    }
    reasons.sort_unstable_by_key(|reason| *reason as u8);
    reasons.dedup();
    reasons.into_boxed_slice()
}

fn push_publication(
    drafts: &mut Vec<PublicationDraft>,
    publication: FreshObjectPublication,
    evidence: Vec<EvidenceHandle>,
    candidate_identity: bool,
) {
    let evidence = dedup_evidence(evidence);
    let mut quality = evidence_quality(&evidence);
    if candidate_identity {
        quality = merge_quality(
            &quality,
            &(
                ProofStatus::Unproven(
                    "fresh-object identity crosses a Go assignment conversion".into(),
                ),
                EvidenceCompleteness::Partial(
                    "fresh-object identity crosses a Go assignment conversion".into(),
                ),
            ),
        );
    }
    if let Some(existing) = drafts
        .iter_mut()
        .find(|candidate| candidate.publication == publication)
    {
        existing.evidence = dedup_evidence(existing.evidence.iter().cloned().chain(evidence));
        quality = merge_quality(
            &(existing.proof.clone(), existing.completeness.clone()),
            &quality,
        );
        existing.proof = quality.0;
        existing.completeness = quality.1;
    } else {
        drafts.push(PublicationDraft {
            publication,
            evidence,
            proof: quality.0,
            completeness: quality.1,
        });
    }
}

fn fresh_object_seed_value(
    query: &FreshObjectPublicationQuery,
) -> Option<crate::analyzer::semantic::ValueId> {
    let procedure = query.observation().procedure();
    match query.object().identity() {
        AccessPathRoot::Value(value) if value.procedure() == procedure => Some(value.id()),
        AccessPathRoot::Allocation(allocation) if allocation.procedure() == procedure => procedure
            .semantics()
            .allocation(allocation.id())
            .map(|row| row.result),
        AccessPathRoot::CallResult(result) if result.result().procedure() == procedure => {
            Some(result.result().id())
        }
        _ => None,
    }
}

fn call_names_any(
    call: &SemanticCallSite,
    names: &HashSet<crate::analyzer::semantic::ValueId>,
) -> bool {
    names.contains(&call.callee)
        || call.receiver.is_some_and(|value| names.contains(&value))
        || call
            .arguments
            .iter()
            .any(|argument| names.contains(&argument.value))
}

fn first_call_name(
    call: &SemanticCallSite,
    names: &HashSet<crate::analyzer::semantic::ValueId>,
) -> Option<crate::analyzer::semantic::ValueId> {
    std::iter::once(call.callee)
        .chain(call.receiver)
        .chain(call.arguments.iter().map(|argument| argument.value))
        .find(|value| names.contains(value))
}

fn effect_names_any(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    effect: &SemanticEffect,
    names: &HashSet<crate::analyzer::semantic::ValueId>,
) -> bool {
    match effect {
        SemanticEffect::Assignment { target, value } => {
            names.contains(target) || names.contains(value)
        }
        SemanticEffect::ValueFlow { source, target, .. } => {
            names.contains(source) || names.contains(target)
        }
        SemanticEffect::ValueUse { value, .. } => names.contains(value),
        SemanticEffect::MemoryLoad {
            location, result, ..
        } => {
            names.contains(result)
                || semantics
                    .memory_location(*location)
                    .is_some_and(|location| {
                        names.iter().any(|value| location.kind.uses_value(*value))
                    })
        }
        SemanticEffect::MemoryStore {
            location, value, ..
        } => {
            names.contains(value)
                || semantics
                    .memory_location(*location)
                    .is_some_and(|location| {
                        names.iter().any(|value| location.kind.uses_value(*value))
                    })
        }
        SemanticEffect::CallableCreation {
            result, callable, ..
        }
        | SemanticEffect::CallableReference {
            result, callable, ..
        } => {
            names.contains(result)
                || callable
                    .bound_receiver
                    .is_some_and(|receiver| names.contains(&receiver))
        }
        SemanticEffect::CaptureBind { capture } => semantics
            .captures()
            .iter()
            .find(|row| row.id == *capture)
            .is_some_and(|capture| match capture.captured {
                CaptureSource::Value(value) => names.contains(&value),
                CaptureSource::Location(location) => {
                    semantics.memory_location(location).is_some_and(|location| {
                        names.iter().any(|value| location.kind.uses_value(*value))
                    })
                }
            }),
        SemanticEffect::Invoke { call_site }
        | SemanticEffect::CallContinuation { call_site, .. } => semantics
            .call_site(*call_site)
            .is_some_and(|call| call_names_any(call, names)),
        SemanticEffect::ProcedureReturn { value } | SemanticEffect::Throw { value } => {
            value.is_some_and(|value| names.contains(&value))
        }
        SemanticEffect::AsyncSuspend { awaited, .. } => {
            awaited.is_some_and(|value| names.contains(&value))
        }
        SemanticEffect::AsyncResume { result, .. } => {
            result.is_some_and(|value| names.contains(&value))
        }
        SemanticEffect::Entry
        | SemanticEffect::NormalExit
        | SemanticEffect::ExceptionalExit
        | SemanticEffect::Allocation { .. }
        | SemanticEffect::Gap { .. } => false,
    }
}

fn publication_gap_affects_names(
    procedure: &ProcedureHandle,
    gap: &SemanticGap,
    names: &HashSet<crate::analyzer::semantic::ValueId>,
) -> bool {
    let semantics = procedure.semantics();
    match gap.subject {
        SemanticGapSubject::Procedure => true,
        // A point-scoped gap is deliberately broader than its retained
        // events: the missing event may be the operation that publishes the
        // object. Only an explicit adapter-authored discharge can narrow it.
        SemanticGapSubject::Point => true,
        SemanticGapSubject::Value(value) => names.contains(&value),
        SemanticGapSubject::MemoryLocation(location) => semantics
            .memory_location(location)
            .is_some_and(|location| names.iter().any(|value| location.kind.uses_value(*value))),
        SemanticGapSubject::Capture(capture) => semantics
            .captures()
            .iter()
            .find(|row| row.id == capture)
            .is_some_and(|capture| match capture.captured {
                CaptureSource::Value(value) => names.contains(&value),
                CaptureSource::Location(location) => {
                    semantics.memory_location(location).is_some_and(|location| {
                        names.iter().any(|value| location.kind.uses_value(*value))
                    })
                }
            }),
        SemanticGapSubject::CallSite(call_site)
        | SemanticGapSubject::CallContinuation { call_site, .. } => semantics
            .call_site(call_site)
            .is_some_and(|call| call_names_any(call, names)),
        SemanticGapSubject::AsyncContinuation { suspend, .. } => {
            semantics.point(suspend).is_some_and(|point| {
                point
                    .events
                    .iter()
                    .any(|event| effect_names_any(semantics, &event.effect, names))
            })
        }
    }
}

/// Enumerate operations that can publish a fresh object's local aliases on
/// the CFG slice between ownership establishment and one observation.
fn resolve_fresh_object_publications(
    query: &FreshObjectPublicationQuery,
    limits: crate::analyzer::semantic::OracleLimits,
    staged: &mut WorkStager,
    cancellation: &crate::cancellation::CancellationToken,
) -> Result<DraftSet<PublicationDraft>, InterruptionOrProvider> {
    let procedure = query.observation().procedure();
    let semantics = procedure.semantics();
    let Some(seed) = fresh_object_seed_value(query) else {
        return Ok(DraftSet {
            candidates: Vec::new(),
            coverage: CandidateCoverage::Open,
            ambiguous: false,
        });
    };
    if query.context().was_truncated() {
        return Ok(DraftSet {
            candidates: Vec::new(),
            coverage: CandidateCoverage::Open,
            ambiguous: false,
        });
    }

    staged
        .charge(SemanticWork {
            program_points: semantics.points().len().saturating_mul(2),
            control_edges: semantics.control_edges().len().saturating_mul(2),
            ..SemanticWork::default()
        })
        .map_err(InterruptionOrProvider::Interruption)?;
    let mut cfg_budget = CfgAlgorithmBudget::default();
    let from_start = match forward_reachability(
        semantics,
        query.ownership_start().id(),
        &mut CfgAlgorithmRequest::new(&mut cfg_budget, cancellation),
    ) {
        Ok(reachability) => reachability,
        Err(CfgAlgorithmError::Cancelled { .. }) => {
            return Err(InterruptionOrProvider::Interruption(
                Interruption::Cancelled,
            ));
        }
        Err(CfgAlgorithmError::ExceededBudget(_) | CfgAlgorithmError::InvalidNode(_)) => {
            return Ok(DraftSet {
                candidates: Vec::new(),
                coverage: CandidateCoverage::Open,
                ambiguous: false,
            });
        }
    };
    let to_observation = match reverse_reachability(
        semantics,
        query.observation().id(),
        &mut CfgAlgorithmRequest::new(&mut cfg_budget, cancellation),
    ) {
        Ok(reachability) => reachability,
        Err(CfgAlgorithmError::Cancelled { .. }) => {
            return Err(InterruptionOrProvider::Interruption(
                Interruption::Cancelled,
            ));
        }
        Err(CfgAlgorithmError::ExceededBudget(_) | CfgAlgorithmError::InvalidNode(_)) => {
            return Ok(DraftSet {
                candidates: Vec::new(),
                coverage: CandidateCoverage::Open,
                ambiguous: false,
            });
        }
    };
    if !from_start.contains(semantics, query.observation().id()) {
        return Ok(DraftSet {
            candidates: Vec::new(),
            coverage: CandidateCoverage::Exhaustive,
            ambiguous: false,
        });
    }
    let in_slice = |point| {
        point != query.observation().id()
            && from_start.contains(semantics, point)
            && to_observation.contains(semantics, point)
    };

    // Ownership can be established by a guard after the fresh result was
    // copied into its local binding. Build the alias-name closure over every
    // predecessor of the observation, while publication candidates below
    // remain restricted to the post-ownership slice.
    let before_observation =
        |point| point != query.observation().id() && to_observation.contains(semantics, point);
    let root_evidence = root_evidence(procedure, query.object().identity())
        .map_err(InterruptionOrProvider::Provider)?;
    struct NameCopy {
        source: crate::analyzer::semantic::ValueId,
        target: crate::analyzer::semantic::ValueId,
        evidence: EvidenceHandle,
        identity_preserving: bool,
    }
    let mut copies = Vec::new();
    for point in semantics
        .points()
        .iter()
        .filter(|point| before_observation(point.id))
    {
        staged
            .charge(SemanticWork {
                program_points: 1,
                events: point.events.len(),
                ..SemanticWork::default()
            })
            .map_err(InterruptionOrProvider::Interruption)?;
        if cancellation.is_cancelled() {
            return Err(InterruptionOrProvider::Interruption(
                Interruption::Cancelled,
            ));
        }
        for event in &point.events {
            match event.effect {
                SemanticEffect::Assignment { target, value }
                | SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Local,
                    source: value,
                    target,
                } => copies.push(NameCopy {
                    source: value,
                    target,
                    evidence: evidence_handle(procedure, event.evidence)
                        .map_err(InterruptionOrProvider::Provider)?,
                    identity_preserving: true,
                }),
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::LanguageDefined,
                    source,
                    target,
                } if is_go_assignment_conversion(semantics, target) => {
                    copies.push(NameCopy {
                        source,
                        target,
                        evidence: evidence_handle(procedure, event.evidence)
                            .map_err(InterruptionOrProvider::Provider)?,
                        // Go assignment conversion is structured dependence,
                        // not exact resource identity. Retain it as a
                        // candidate so a following field/index store cannot
                        // disappear, while keeping the published relation
                        // explicitly unproven and partial.
                        identity_preserving: false,
                    });
                }
                _ => {}
            }
        }
    }
    let mut name_exactness = HashMap::default();
    name_exactness.insert(seed, true);
    let mut name_evidence = HashMap::default();
    name_evidence.insert(seed, root_evidence);
    let mut pending = vec![seed];
    while let Some(current) = pending.pop() {
        staged
            .charge(SemanticWork {
                values: 1,
                ..SemanticWork::default()
            })
            .map_err(InterruptionOrProvider::Interruption)?;
        let current_exact = *name_exactness
            .get(&current)
            .expect("pending publication name has an exactness row");
        for copy in &copies {
            if copy.source == current {
                let target_exact = current_exact && copy.identity_preserving;
                if name_exactness
                    .get(&copy.target)
                    .is_some_and(|existing| *existing || !target_exact)
                {
                    continue;
                }
                let evidence = dedup_evidence(
                    name_evidence
                        .get(&copy.source)
                        .into_iter()
                        .flatten()
                        .cloned()
                        .chain(std::iter::once(copy.evidence.clone())),
                );
                name_exactness.insert(copy.target, target_exact);
                name_evidence.insert(copy.target, evidence);
                pending.push(copy.target);
            }
        }
    }
    let exact_names = name_exactness
        .iter()
        .filter_map(|(name, exact)| exact.then_some(*name))
        .collect::<HashSet<_>>();
    let candidate_names = name_exactness
        .iter()
        .filter_map(|(name, exact)| (!exact).then_some(*name))
        .collect::<HashSet<_>>();
    let names = exact_names
        .iter()
        .chain(&candidate_names)
        .copied()
        .collect::<HashSet<_>>();

    let mut drafts = Vec::new();
    let mut open = false;
    let mut abort_user_code = None;
    for gap in semantics.gaps().iter().filter(|gap| in_slice(gap.point)) {
        staged
            .charge(SemanticWork {
                gaps: 1,
                ..SemanticWork::default()
            })
            .map_err(InterruptionOrProvider::Interruption)?;
        // Publication asks whether the object crosses an effect boundary, not
        // which resolved target receives it or how retained evaluations are
        // ordered. Those two structured proof obligations are therefore
        // irrelevant; every other gap remains conservative.
        if gap.discharge != SemanticGapDischarge::RetainedEvaluationOrder
            && call_target_refinement_call(semantics, gap).is_none()
            && publication_gap_affects_names(procedure, gap, &names)
            && gap_can_open_heap(procedure, gap, &mut abort_user_code)
        {
            open = true;
        }
    }
    for point in semantics.points().iter().filter(|point| in_slice(point.id)) {
        let point_handle = procedure
            .point_handle(point.id)
            .expect("validated publication slice retains its program point");
        for event in &point.events {
            let publication = match &event.effect {
                SemanticEffect::MemoryStore { value, .. } if names.contains(value) => Some((
                    FreshObjectPublication::at(
                        point_handle.clone(),
                        FreshObjectPublicationKind::MemoryStore,
                    ),
                    *value,
                )),
                SemanticEffect::ProcedureReturn { value }
                    if value.is_some_and(|value| names.contains(&value)) =>
                {
                    Some((
                        FreshObjectPublication::at(
                            point_handle.clone(),
                            FreshObjectPublicationKind::Return,
                        ),
                        value.expect("matched return value"),
                    ))
                }
                SemanticEffect::Throw { value }
                    if value.is_some_and(|value| names.contains(&value)) =>
                {
                    Some((
                        FreshObjectPublication::at(
                            point_handle.clone(),
                            FreshObjectPublicationKind::Throw,
                        ),
                        value.expect("matched throw value"),
                    ))
                }
                SemanticEffect::AsyncSuspend { awaited, .. }
                    if awaited.is_some_and(|value| names.contains(&value)) =>
                {
                    Some((
                        FreshObjectPublication::at(
                            point_handle.clone(),
                            FreshObjectPublicationKind::AsyncSuspend,
                        ),
                        awaited.expect("matched awaited value"),
                    ))
                }
                SemanticEffect::ValueFlow {
                    kind:
                        ValueFlowKind::Parameter
                        | ValueFlowKind::Receiver
                        | ValueFlowKind::Return
                        | ValueFlowKind::IndexedReturn { .. },
                    source,
                    ..
                } if names.contains(source) => Some((
                    FreshObjectPublication::at(
                        point_handle.clone(),
                        FreshObjectPublicationKind::Return,
                    ),
                    *source,
                )),
                SemanticEffect::CallableCreation { callable, .. }
                | SemanticEffect::CallableReference { callable, .. }
                    if callable
                        .bound_receiver
                        .is_some_and(|receiver| names.contains(&receiver)) =>
                {
                    Some((
                        FreshObjectPublication::at(
                            point_handle.clone(),
                            FreshObjectPublicationKind::Capture,
                        ),
                        callable.bound_receiver.expect("matched bound receiver"),
                    ))
                }
                SemanticEffect::CaptureBind { capture } => semantics
                    .captures()
                    .iter()
                    .find(|row| row.id == *capture)
                    .and_then(|capture| match capture.captured {
                        CaptureSource::Value(value) if names.contains(&value) => Some((
                            FreshObjectPublication::at(
                                point_handle.clone(),
                                FreshObjectPublicationKind::Capture,
                            ),
                            value,
                        )),
                        CaptureSource::Value(_) | CaptureSource::Location(_) => None,
                    }),
                SemanticEffect::Invoke { call_site } => semantics
                    .call_site(*call_site)
                    .and_then(|call| {
                        // A call is one publication even when several
                        // operands name the object. Preserve an exact witness
                        // when it coexists with a conversion-derived candidate.
                        first_call_name(call, &exact_names)
                            .or_else(|| first_call_name(call, &candidate_names))
                            .map(|name| (call, name))
                    })
                    .and_then(|(call, name)| {
                        procedure.call_site_handle(call.id).map(|call| {
                            FreshObjectPublication::call(call)
                                .map(|publication| (publication, name))
                        })
                    })
                    .transpose()
                    .map_err(|error| {
                        InterruptionOrProvider::Provider(internal_contract(
                            "could not retain fresh-object call publication",
                            error,
                        ))
                    })?,
                _ => None,
            };
            if let Some((publication, published_name)) = publication {
                let event_evidence = evidence_handle(procedure, event.evidence)
                    .map_err(InterruptionOrProvider::Provider)?;
                let candidate_identity = !name_exactness
                    .get(&published_name)
                    .copied()
                    .expect("published fresh-object name has an exactness row");
                if candidate_identity {
                    // The row is a useful structured positive, but the set of
                    // actual publications remains open because the assignment
                    // conversion did not preserve exact object identity.
                    open = true;
                }
                push_publication(
                    &mut drafts,
                    publication,
                    name_evidence
                        .get(&published_name)
                        .into_iter()
                        .flatten()
                        .cloned()
                        .chain(std::iter::once(event_evidence))
                        .collect(),
                    candidate_identity,
                );
            }
        }
        if drafts.len() > limits.provenance_records()
            || drafts
                .iter()
                .map(|draft| draft.evidence.len())
                .sum::<usize>()
                > limits.evidence_handles()
        {
            drafts.truncate(limits.provenance_records());
            return Ok(DraftSet {
                candidates: drafts,
                coverage: CandidateCoverage::Truncated,
                ambiguous: false,
            });
        }
    }
    Ok(DraftSet {
        candidates: drafts,
        coverage: if open {
            CandidateCoverage::Open
        } else {
            CandidateCoverage::Exhaustive
        },
        ambiguous: false,
    })
}

fn materialize_fresh_object_publications(
    query: &FreshObjectPublicationQuery,
    drafts: DraftSet<PublicationDraft>,
    limits: crate::analyzer::semantic::OracleLimits,
) -> Result<FreshObjectPublicationResult, SemanticProviderError> {
    let records = drafts
        .candidates
        .iter()
        .map(|draft| {
            OracleRelationRecord::new(
                OracleRelationKind::Publication,
                draft.evidence.clone(),
                limits,
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| internal_contract("could not create publication provenance", error))?;
    let arena = OracleRelationArena::new(
        OracleRelationOwner::FreshObjectPublications(Box::new(query.clone())),
        records,
        limits,
    )
    .map_err(|error| internal_contract("could not create publication arena", error))?;
    let candidates = drafts
        .candidates
        .into_iter()
        .enumerate()
        .map(|(index, draft)| {
            let id = u32::try_from(index)
                .map(OracleRelationId::new)
                .map_err(|_| SemanticProviderError::internal("publication relation ID overflow"))?;
            OracleCandidate::new(
                draft.publication,
                draft.proof,
                draft.completeness,
                [arena
                    .handle(id)
                    .expect("publication relation was inserted into the arena")],
                limits,
            )
            .map_err(|error| internal_contract("invalid publication candidate", error))
        })
        .collect::<Result<Vec<_>, _>>()?;
    FreshObjectPublicationResult::new(query.clone(), candidates, drafts.coverage, limits)
        .map_err(|error| internal_contract("invalid fresh-object publication result", error))
}

/// Whether the object a resolved location names can be reached under a name
/// this procedure does not control.
///
/// The answer is a copy closure over the procedure's own value flow. An
/// allocation is fresh, so the only way another name can reach it is if this
/// procedure publishes it: by capturing it in a closure, passing it to a call
/// as callee, receiver or argument, storing it into memory, returning it, or
/// throwing it. Each of those hands the reference to code this query does not
/// analyse. A local copy (`alias = box`) is not a publication -- both names
/// stay inside the procedure, and the flow client already tracks them as
/// separate carriers.
///
/// A lexical cell keeps its established rule: it does not escape while no
/// capture names it. Every other identity has no such proof available here, so
/// it may escape.
fn object_escape_status(
    identity: &AbstractObjectIdentity,
    staged: &mut WorkStager,
    cancellation: &crate::cancellation::CancellationToken,
) -> Result<EscapeStatus, Interruption> {
    let allocation = match identity {
        AbstractObjectIdentity::Allocation(allocation) => allocation,
        AbstractObjectIdentity::LexicalCell(location) => {
            let captured = location
                .procedure()
                .semantics()
                .captures()
                .iter()
                .any(|capture| {
                    matches!(
                        capture.captured,
                        CaptureSource::Location(captured) if captured == location.id()
                    )
                });
            return Ok(if captured {
                EscapeStatus::MayEscape
            } else {
                EscapeStatus::DoesNotEscape
            });
        }
        _ => return Ok(EscapeStatus::MayEscape),
    };
    let procedure = allocation.procedure();
    let semantics = procedure.semantics();
    let Some(row) = semantics.allocation(allocation.id()) else {
        return Ok(EscapeStatus::MayEscape);
    };
    if allocation_is_captured(procedure, allocation.id(), row.result) {
        return Ok(EscapeStatus::MayEscape);
    }

    // One pass collects the copy edges, then a worklist closes over them. A
    // repeated pass per name would be quadratic on a large procedure.
    let mut copies: Vec<(
        crate::analyzer::semantic::ValueId,
        crate::analyzer::semantic::ValueId,
    )> = Vec::new();
    for point in semantics.points() {
        staged.charge(SemanticWork {
            program_points: 1,
            events: point.events.len(),
            ..SemanticWork::default()
        })?;
        if cancellation.is_cancelled() {
            return Err(Interruption::Cancelled);
        }
        for event in &point.events {
            match event.effect {
                SemanticEffect::Assignment { target, value } => copies.push((value, target)),
                SemanticEffect::ValueFlow {
                    kind: crate::analyzer::semantic::ValueFlowKind::Local,
                    source,
                    target,
                } => copies.push((source, target)),
                _ => {}
            }
        }
    }
    let mut names = HashSet::default();
    names.insert(row.result);
    let mut pending = vec![row.result];
    while let Some(current) = pending.pop() {
        staged.charge(SemanticWork {
            values: 1,
            ..SemanticWork::default()
        })?;
        for (source, target) in &copies {
            if *source == current && names.insert(*target) {
                pending.push(*target);
            }
        }
    }

    for point in semantics.points() {
        staged.charge(SemanticWork {
            events: point.events.len(),
            ..SemanticWork::default()
        })?;
        if cancellation.is_cancelled() {
            return Err(Interruption::Cancelled);
        }
        for event in &point.events {
            let published = match event.effect {
                SemanticEffect::MemoryStore { value, .. } => names.contains(&value),
                SemanticEffect::ProcedureReturn { value } | SemanticEffect::Throw { value } => {
                    value.is_some_and(|value| names.contains(&value))
                }
                SemanticEffect::ValueFlow {
                    kind:
                        crate::analyzer::semantic::ValueFlowKind::Return
                        | crate::analyzer::semantic::ValueFlowKind::IndexedReturn { .. }
                        | crate::analyzer::semantic::ValueFlowKind::Parameter
                        | crate::analyzer::semantic::ValueFlowKind::Receiver,
                    source,
                    ..
                } => names.contains(&source),
                SemanticEffect::AsyncSuspend { awaited, .. } => {
                    awaited.is_some_and(|value| names.contains(&value))
                }
                SemanticEffect::Invoke { call_site } => {
                    semantics.call_site(call_site).is_some_and(|call| {
                        names.contains(&call.callee)
                            || call.receiver.is_some_and(|value| names.contains(&value))
                            || call
                                .arguments
                                .iter()
                                .any(|argument| names.contains(&argument.value))
                    })
                }
                _ => false,
            };
            if published {
                return Ok(EscapeStatus::MayEscape);
            }
        }
    }
    Ok(EscapeStatus::DoesNotEscape)
}

fn materialize_update(
    store: &StoreAtPoint,
    drafts: DraftSet<LocationDraft>,
    escape: EscapeStatus,
    limits: crate::analyzer::semantic::OracleLimits,
) -> Result<UpdateEligibility, SemanticProviderError> {
    if drafts.candidates.is_empty() {
        return Ok(UpdateEligibility::Weak(direct_weak_reasons(
            drafts.coverage,
            &drafts.candidates,
        )));
    }
    if drafts.ambiguous || drafts.candidates.len() != 1 {
        let mut reasons = vec![
            WeakUpdateReason::MultipleLocations,
            WeakUpdateReason::MultipleObjects,
            WeakUpdateReason::PotentialAliases,
        ];
        match drafts.coverage {
            CandidateCoverage::Exhaustive => {}
            CandidateCoverage::Open => {
                reasons.push(WeakUpdateReason::NonExhaustiveLocations);
                reasons.push(WeakUpdateReason::NonExhaustiveObjects);
            }
            CandidateCoverage::Truncated => {
                reasons.push(WeakUpdateReason::TruncatedLocations);
                reasons.push(WeakUpdateReason::TruncatedObjects);
            }
        }
        reasons.sort_unstable_by_key(|reason| *reason as u8);
        reasons.dedup();
        return Ok(UpdateEligibility::Weak(reasons.into_boxed_slice()));
    }
    let first = &drafts.candidates[0];
    // Strong-update locations must retain the exact store target, because the
    // certificate is bound to this store's own IR address.
    //
    // A resolved location can differ from that target only in its root:
    // `resolve_locations` copies the query's selectors and tail verbatim and
    // rewrites the root to the object the root value was proven to denote. That
    // refinement is not discarded here. Cardinality is a property of the
    // runtime object, not of the syntactic root that names it, so when the
    // resolution proved the root value denotes one object, the store target
    // names one location -- which is exactly what a strong update needs. The
    // syntactic default stands only when the two paths disagree about more than
    // the root, which resolution does not produce.
    let certificate_location = if first.location.path() == store.target().path() {
        first.location.clone()
    } else {
        let refines_root = first.location.path().selectors() == store.target().path().selectors()
            && first.location.path().tail() == store.target().path().tail();
        let cardinality = if refines_root {
            first.location.object().cardinality()
        } else {
            candidate_cardinality_for_root(store.target().path().root())
        };
        let object = AbstractObject::new(store.target().path().root().clone(), cardinality)
            .map_err(|error| internal_contract("invalid store object", error))?;
        AbstractLocation::new(object, store.target().path().clone())
            .map_err(|error| internal_contract("invalid store location", error))?
    };
    let object = certificate_location.object().clone();
    let evidence = dedup_evidence(
        drafts
            .candidates
            .iter()
            .flat_map(|candidate| candidate.evidence.iter().cloned()),
    );
    let quality = evidence_quality(&evidence);
    let records = [
        OracleRelationKind::Location,
        OracleRelationKind::PointsTo,
        OracleRelationKind::Alias,
        OracleRelationKind::Escape,
    ]
    .into_iter()
    .map(|kind| OracleRelationRecord::new(kind, evidence.clone(), limits))
    .collect::<Result<Vec<_>, _>>()
    .map_err(|error| internal_contract("could not create strong-update provenance", error))?;
    let arena = OracleRelationArena::new(
        OracleRelationOwner::StrongUpdate(Box::new(store.clone())),
        records,
        limits,
    )
    .map_err(|error| internal_contract("could not create strong-update arena", error))?;
    let relation = |index| {
        arena
            .handle(OracleRelationId::new(index))
            .expect("strong-update record was inserted into the arena")
    };
    let location_candidate = OracleCandidate::new(
        certificate_location.clone(),
        quality.0.clone(),
        quality.1.clone(),
        [relation(0)],
        limits,
    )
    .map_err(|error| internal_contract("invalid update location", error))?;
    let object_candidate = OracleCandidate::new(
        object.clone(),
        quality.0.clone(),
        quality.1.clone(),
        [relation(1)],
        limits,
    )
    .map_err(|error| internal_contract("invalid update object", error))?;
    let unique_exact = drafts.coverage == CandidateCoverage::Exhaustive
        && drafts.candidates.len() == 1
        && certificate_location.path().is_exact();
    let alias = OracleCandidate::new(
        AliasExclusivityWitness::new(
            store.clone(),
            certificate_location.clone(),
            if unique_exact {
                AliasExclusivity::Exclusive
            } else {
                AliasExclusivity::PotentialAliases
            },
        )
        .map_err(|error| internal_contract("invalid alias-exclusivity witness", error))?,
        quality.0.clone(),
        quality.1.clone(),
        [relation(2)],
        limits,
    )
    .map_err(|error| internal_contract("invalid alias-exclusivity evidence", error))?;
    let escape = OracleCandidate::new(
        EscapeWitness::new(store.clone(), object.clone(), escape)
            .map_err(|error| internal_contract("invalid escape witness", error))?,
        quality.0,
        quality.1,
        [relation(3)],
        limits,
    )
    .map_err(|error| internal_contract("invalid escape evidence", error))?;
    let evidence = StrongUpdateEvidence::new(
        OracleSet::bounded_locations([location_candidate], drafts.coverage, limits),
        OracleSet::bounded_objects([object_candidate], drafts.coverage, limits),
        alias,
        escape,
        limits,
    )
    .map_err(|error| internal_contract("invalid strong-update evidence", error))?;
    Ok(UpdateEligibility::evaluate(store.clone(), evidence))
}

impl HeapOracle for WorkspaceSemanticOracle<'_> {
    fn pointees(
        &self,
        value: &ValueAtPoint,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<PointsToResult>, SemanticProviderError> {
        if request.cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: SemanticWork::default(),
            });
        }
        let mut staged = WorkStager::new(request);
        let drafts = match resolve_objects(
            self,
            value,
            *self.limits(),
            &mut staged,
            request.cancellation,
        ) {
            Ok(drafts) => drafts,
            Err(InterruptionOrProvider::Provider(error)) => return Err(error),
            Err(InterruptionOrProvider::Interruption(interruption)) => {
                let empty = DraftSet {
                    candidates: Vec::new(),
                    coverage: CandidateCoverage::Open,
                    ambiguous: false,
                };
                let result = materialize_points_to(value, empty, *self.limits())?;
                return Ok(publish_set_outcome(
                    result,
                    CandidateCoverage::Open,
                    true,
                    false,
                    Some(interruption),
                    staged.work,
                ));
            }
        };
        let coverage = drafts.coverage;
        let ambiguous = drafts.ambiguous;
        let proven_complete = candidates_proven_complete(&drafts.candidates, |candidate| {
            matches!(candidate.proof, ProofStatus::Proven)
                && matches!(candidate.completeness, EvidenceCompleteness::Complete)
        });
        let publication = candidate_publication_work(
            drafts.candidates.len(),
            drafts
                .candidates
                .iter()
                .map(|candidate| candidate.evidence.len())
                .sum(),
        );
        if let Err(interruption) = staged.charge(publication) {
            let empty = DraftSet {
                candidates: Vec::new(),
                coverage: CandidateCoverage::Open,
                ambiguous: false,
            };
            let result = materialize_points_to(value, empty, *self.limits())?;
            return Ok(publish_set_outcome(
                result,
                CandidateCoverage::Open,
                true,
                false,
                Some(interruption),
                staged.work,
            ));
        }
        let result = materialize_points_to(value, drafts, *self.limits())?;
        *request.budget = staged.budget;
        Ok(publish_set_outcome(
            result,
            coverage,
            proven_complete,
            ambiguous,
            None,
            staged.work,
        ))
    }

    fn locations(
        &self,
        access: &AccessPathAtPoint,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<LocationResult>, SemanticProviderError> {
        if request.cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: SemanticWork::default(),
            });
        }
        let mut staged = WorkStager::new(request);
        let drafts = match resolve_locations(
            self,
            access,
            *self.limits(),
            &mut staged,
            request.cancellation,
        ) {
            Ok(drafts) => drafts,
            Err(InterruptionOrProvider::Provider(error)) => return Err(error),
            Err(InterruptionOrProvider::Interruption(interruption)) => {
                let empty = DraftSet {
                    candidates: Vec::new(),
                    coverage: CandidateCoverage::Open,
                    ambiguous: false,
                };
                let result = materialize_locations(access, empty, *self.limits())?;
                return Ok(publish_set_outcome(
                    result,
                    CandidateCoverage::Open,
                    true,
                    false,
                    Some(interruption),
                    staged.work,
                ));
            }
        };
        let coverage = drafts.coverage;
        let ambiguous = drafts.ambiguous;
        let proven_complete = candidates_proven_complete(&drafts.candidates, |candidate| {
            matches!(candidate.proof, ProofStatus::Proven)
                && matches!(candidate.completeness, EvidenceCompleteness::Complete)
        });
        let publication = candidate_publication_work(
            drafts.candidates.len(),
            drafts
                .candidates
                .iter()
                .map(|candidate| candidate.evidence.len())
                .sum(),
        );
        if let Err(interruption) = staged.charge(publication) {
            let empty = DraftSet {
                candidates: Vec::new(),
                coverage: CandidateCoverage::Open,
                ambiguous: false,
            };
            let result = materialize_locations(access, empty, *self.limits())?;
            return Ok(publish_set_outcome(
                result,
                CandidateCoverage::Open,
                true,
                false,
                Some(interruption),
                staged.work,
            ));
        }
        let result = materialize_locations(access, drafts, *self.limits())?;
        *request.budget = staged.budget;
        Ok(publish_set_outcome(
            result,
            coverage,
            proven_complete,
            ambiguous,
            None,
            staged.work,
        ))
    }

    fn alias(
        &self,
        query: &AliasQuery,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<AliasResult>, SemanticProviderError> {
        if request.cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: SemanticWork::default(),
            });
        }
        let mut staged = WorkStager::new(request);
        let left = resolve_locations(
            self,
            query.left(),
            *self.limits(),
            &mut staged,
            request.cancellation,
        );
        let right = resolve_locations(
            self,
            query.right(),
            *self.limits(),
            &mut staged,
            request.cancellation,
        );
        let (left, right, interruption) = match (left, right) {
            (Ok(left), Ok(right)) => (left, right, None),
            (Err(InterruptionOrProvider::Provider(error)), _)
            | (_, Err(InterruptionOrProvider::Provider(error))) => return Err(error),
            (Err(InterruptionOrProvider::Interruption(interruption)), _) => (
                DraftSet {
                    candidates: Vec::new(),
                    coverage: CandidateCoverage::Open,
                    ambiguous: false,
                },
                DraftSet {
                    candidates: Vec::new(),
                    coverage: CandidateCoverage::Open,
                    ambiguous: false,
                },
                Some(interruption),
            ),
            (_, Err(InterruptionOrProvider::Interruption(interruption))) => (
                DraftSet {
                    candidates: Vec::new(),
                    coverage: CandidateCoverage::Open,
                    ambiguous: false,
                },
                DraftSet {
                    candidates: Vec::new(),
                    coverage: CandidateCoverage::Open,
                    ambiguous: false,
                },
                Some(interruption),
            ),
        };
        let relation = alias_relation(query, &left, &right);
        let evidence = dedup_evidence(
            left.candidates
                .iter()
                .chain(&right.candidates)
                .flat_map(|candidate| candidate.evidence.iter().cloned()),
        );
        let mut evidence = if evidence.is_empty() {
            root_evidence(query.left().point().procedure(), query.left().path().root())?
        } else {
            evidence
        };
        let evidence_truncated = evidence.len() > self.limits().evidence_handles();
        if evidence_truncated {
            evidence.truncate(self.limits().evidence_handles());
        }
        let mut quality = evidence_quality(&evidence);
        if evidence_truncated {
            quality.1 = EvidenceCompleteness::Partial(
                "alias provenance was truncated by the oracle evidence limit".into(),
            );
        }
        let publication = candidate_publication_work(1, evidence.len());
        if let Err(interruption) = staged.charge(publication) {
            return Ok(match interruption {
                Interruption::Budget(exceeded) => SemanticOutcome::ExceededBudget {
                    partial: None,
                    exceeded,
                    work: staged.work,
                },
                Interruption::Cancelled => SemanticOutcome::Cancelled {
                    partial: None,
                    work: staged.work,
                },
            });
        }
        let result = materialize_alias(query, relation, evidence, quality.clone(), *self.limits())?;
        let coverage = if evidence_truncated
            || left.coverage == CandidateCoverage::Truncated
            || right.coverage == CandidateCoverage::Truncated
        {
            CandidateCoverage::Truncated
        } else if left.coverage == CandidateCoverage::Open
            || right.coverage == CandidateCoverage::Open
        {
            CandidateCoverage::Open
        } else {
            CandidateCoverage::Exhaustive
        };
        if interruption.is_none() {
            *request.budget = staged.budget;
        }
        Ok(publish_set_outcome(
            result,
            coverage,
            matches!(quality.0, ProofStatus::Proven)
                && matches!(quality.1, EvidenceCompleteness::Complete),
            left.ambiguous || right.ambiguous,
            interruption,
            staged.work,
        ))
    }

    fn fresh_object_publications(
        &self,
        query: &FreshObjectPublicationQuery,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<FreshObjectPublicationResult>, SemanticProviderError> {
        if request.cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: SemanticWork::default(),
            });
        }
        let mut staged = WorkStager::new(request);
        let drafts = match resolve_fresh_object_publications(
            query,
            *self.limits(),
            &mut staged,
            request.cancellation,
        ) {
            Ok(drafts) => drafts,
            Err(InterruptionOrProvider::Provider(error)) => return Err(error),
            Err(InterruptionOrProvider::Interruption(interruption)) => {
                let empty = DraftSet {
                    candidates: Vec::new(),
                    coverage: CandidateCoverage::Open,
                    ambiguous: false,
                };
                let result = materialize_fresh_object_publications(query, empty, *self.limits())?;
                return Ok(publish_set_outcome(
                    result,
                    CandidateCoverage::Open,
                    true,
                    false,
                    Some(interruption),
                    staged.work,
                ));
            }
        };
        let coverage = drafts.coverage;
        let proven_complete = candidates_proven_complete(&drafts.candidates, |candidate| {
            matches!(candidate.proof, ProofStatus::Proven)
                && matches!(candidate.completeness, EvidenceCompleteness::Complete)
        });
        let publication = candidate_publication_work(
            drafts.candidates.len(),
            drafts
                .candidates
                .iter()
                .map(|candidate| candidate.evidence.len())
                .sum(),
        );
        if let Err(interruption) = staged.charge(publication) {
            let result = materialize_fresh_object_publications(query, drafts, *self.limits())?;
            return Ok(publish_set_outcome(
                result,
                coverage,
                false,
                false,
                Some(interruption),
                staged.work,
            ));
        }
        let result = materialize_fresh_object_publications(query, drafts, *self.limits())?;
        *request.budget = staged.budget;
        Ok(publish_set_outcome(
            result,
            coverage,
            proven_complete,
            false,
            None,
            staged.work,
        ))
    }

    fn update_eligibility(
        &self,
        store: &StoreAtPoint,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<UpdateEligibility>, SemanticProviderError> {
        if request.cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: SemanticWork::default(),
            });
        }
        let mut staged = WorkStager::new(request);
        let drafts = match resolve_locations(
            self,
            store.target(),
            *self.limits(),
            &mut staged,
            request.cancellation,
        ) {
            Ok(drafts) => drafts,
            Err(InterruptionOrProvider::Provider(error)) => return Err(error),
            Err(InterruptionOrProvider::Interruption(interruption)) => {
                let partial = UpdateEligibility::Weak(
                    [
                        WeakUpdateReason::NonExhaustiveLocations,
                        WeakUpdateReason::NonExhaustiveObjects,
                    ]
                    .into(),
                );
                return Ok(match interruption {
                    Interruption::Budget(exceeded) => SemanticOutcome::ExceededBudget {
                        partial: Some(partial),
                        exceeded,
                        work: staged.work,
                    },
                    Interruption::Cancelled => SemanticOutcome::Cancelled {
                        partial: Some(partial),
                        work: staged.work,
                    },
                });
            }
        };
        let coverage = drafts.coverage;
        let retained_evidence = drafts
            .candidates
            .iter()
            .flat_map(|candidate| candidate.evidence.iter())
            .collect::<HashSet<_>>()
            .len();
        if drafts.candidates.len() == 1
            && (self.limits().provenance_records() < 4
                || retained_evidence.saturating_mul(4) > self.limits().evidence_handles())
        {
            *request.budget = staged.budget;
            return Ok(SemanticOutcome::Unproven {
                partial: UpdateEligibility::Weak(
                    [
                        WeakUpdateReason::TruncatedLocations,
                        WeakUpdateReason::TruncatedObjects,
                        WeakUpdateReason::IncompleteAliasEvidence,
                        WeakUpdateReason::IncompleteEscapeEvidence,
                    ]
                    .into(),
                ),
                work: staged.work,
            });
        }
        let publication = if drafts.candidates.len() == 1 {
            candidate_publication_work(4, retained_evidence.saturating_mul(4))
        } else {
            SemanticWork::default()
        };
        if let Err(interruption) = staged.charge(publication) {
            let partial = UpdateEligibility::Weak(
                [
                    WeakUpdateReason::NonExhaustiveLocations,
                    WeakUpdateReason::NonExhaustiveObjects,
                ]
                .into(),
            );
            return Ok(match interruption {
                Interruption::Budget(exceeded) => SemanticOutcome::ExceededBudget {
                    partial: Some(partial),
                    exceeded,
                    work: staged.work,
                },
                Interruption::Cancelled => SemanticOutcome::Cancelled {
                    partial: Some(partial),
                    work: staged.work,
                },
            });
        }
        // The escape proof is only reachable for a single resolved candidate,
        // and every other shape has already returned weak above, so the walk it
        // costs is never paid for a store that could not be strong anyway.
        let escape = match drafts
            .candidates
            .first()
            .map(|candidate| candidate.location.object().identity())
        {
            Some(identity) => {
                match object_escape_status(identity, &mut staged, request.cancellation) {
                    Ok(escape) => escape,
                    Err(interruption) => {
                        let partial = UpdateEligibility::Weak(
                            [WeakUpdateReason::IncompleteEscapeEvidence].into(),
                        );
                        return Ok(match interruption {
                            Interruption::Budget(exceeded) => SemanticOutcome::ExceededBudget {
                                partial: Some(partial),
                                exceeded,
                                work: staged.work,
                            },
                            Interruption::Cancelled => SemanticOutcome::Cancelled {
                                partial: Some(partial),
                                work: staged.work,
                            },
                        });
                    }
                }
            }
            None => EscapeStatus::MayEscape,
        };
        let eligibility = materialize_update(store, drafts, escape, *self.limits())?;
        *request.budget = staged.budget;
        Ok(match coverage {
            CandidateCoverage::Exhaustive => SemanticOutcome::Complete {
                value: eligibility,
                work: staged.work,
            },
            CandidateCoverage::Open => SemanticOutcome::Unknown {
                partial: Some(eligibility),
                work: staged.work,
            },
            CandidateCoverage::Truncated => SemanticOutcome::Unproven {
                partial: eligibility,
                work: staged.work,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic::{OracleCallContext, SemanticBudget, SemanticRequest};
    use crate::analyzer::{Language, ProjectFile};
    use crate::cancellation::CancellationToken;
    use crate::test_support::AnalyzerFixture;

    #[test]
    fn go_assignment_conversion_retains_a_candidate_field_publication() {
        let fixture = AnalyzerFixture::new_for_language(
            Language::Go,
            &[(
                "main.go",
                r#"package main

type Resource struct{}
type Holder struct { resource *Resource }

func OpenResource() *Resource { return &Resource{} }

func assign(holder *Holder) {
    holder.resource = OpenResource()
    _ = holder.resource
}
"#,
            )],
        );
        let file = ProjectFile::new(fixture.project_root(), "main.go");
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("Go semantic materialization runs")
            .available_value()
            .cloned()
            .expect("Go semantic artifact is available");
        let (semantics, ownership_start, raw_result) = artifact
            .procedures()
            .iter()
            .find_map(|semantics| {
                let conversions = semantics
                    .points()
                    .iter()
                    .flat_map(|point| {
                        point
                            .events
                            .iter()
                            .filter_map(move |event| match event.effect {
                                SemanticEffect::ValueFlow {
                                    kind: ValueFlowKind::LanguageDefined,
                                    source,
                                    target,
                                } if is_go_assignment_conversion(semantics, target) => {
                                    Some((point.id, source, target))
                                }
                                _ => None,
                            })
                    })
                    .collect::<Vec<_>>();
                conversions
                    .into_iter()
                    .find_map(|(point, source, converted)| {
                        semantics
                            .points()
                            .iter()
                            .flat_map(|point| &point.events)
                            .any(|event| {
                                matches!(
                                    event.effect,
                                    SemanticEffect::MemoryStore { value, .. }
                                        if value == converted
                                )
                            })
                            .then_some((semantics, point, source))
                    })
            })
            .expect("assign lowers a converted call result into a field store");
        let procedure = artifact
            .procedure_handle(semantics.id())
            .expect("assign procedure handle");
        let object = AbstractObject::new(
            AccessPathRoot::Value(
                procedure
                    .value_handle(raw_result)
                    .expect("raw call-result value handle"),
            ),
            ObjectCardinality::Unknown,
        )
        .expect("fresh result object");
        let query = FreshObjectPublicationQuery::new(
            object,
            procedure
                .point_handle(ownership_start)
                .expect("conversion program point"),
            procedure
                .point_handle(semantics.normal_exit_point())
                .expect("normal exit point"),
            OracleCallContext::empty(),
        )
        .expect("fresh publication query");
        let mut publication_budget = SemanticBudget::default();
        let outcome = fixture
            .analyzer
            .semantic_oracle_provider()
            .fresh_object_publications(
                &query,
                &mut SemanticRequest::new(&mut publication_budget, &cancellation),
            )
            .expect("fresh publication query runs");
        let SemanticOutcome::Unproven { partial, .. } = outcome else {
            panic!("assignment conversion must remain candidate evidence: {outcome:#?}");
        };
        assert_eq!(partial.publications().coverage(), CandidateCoverage::Open);
        let [publication] = partial.publications().candidates() else {
            panic!("the converted field store is retained: {partial:#?}");
        };
        assert_eq!(
            publication.value().kind(),
            FreshObjectPublicationKind::MemoryStore
        );
        assert!(matches!(publication.proof(), ProofStatus::Unproven(_)));
        assert!(matches!(
            publication.completeness(),
            EvidenceCompleteness::Partial(_)
        ));
    }

    #[test]
    fn unresolved_field_location_does_not_open_its_base_pointees() {
        let fixture = AnalyzerFixture::new_for_language(
            Language::Go,
            &[(
                "main.go",
                r#"package main

type Resource struct{}

func OpenResource() *Resource { return &Resource{} }
func (*Resource) Close() {}

func inspect() {
    resource := OpenResource()
    resource.Close()
}
"#,
            )],
        );
        let file = ProjectFile::new(fixture.project_root(), "main.go");
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("Go semantic materialization runs")
            .available_value()
            .cloned()
            .expect("Go semantic artifact is available");
        let semantics = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .call_sites()
                    .iter()
                    .any(|call| call.receiver.is_some())
            })
            .expect("inspect procedure has a receiver call");
        let call = semantics
            .call_sites()
            .iter()
            .find(|call| call.receiver.is_some())
            .expect("resource.Close call");
        let procedure = artifact
            .procedure_handle(semantics.id())
            .expect("inspect procedure handle");
        let point = procedure
            .point_handle(call.point)
            .expect("call program point");
        let receiver = procedure
            .value_handle(call.receiver.expect("receiver value"))
            .expect("receiver handle");
        let callee = procedure
            .value_handle(call.callee)
            .expect("callee value handle");
        let oracle = fixture.analyzer.semantic_oracle_provider();

        let mut receiver_budget = SemanticBudget::default();
        let receiver_outcome = oracle
            .pointees(
                &ValueAtPoint::new(
                    receiver,
                    point.clone(),
                    ObservationPhase::AfterEffects,
                    OracleCallContext::empty(),
                )
                .expect("receiver observation"),
                &mut SemanticRequest::new(&mut receiver_budget, &cancellation),
            )
            .expect("receiver points-to query runs");
        let SemanticOutcome::Complete {
            value: receiver_result,
            ..
        } = receiver_outcome
        else {
            panic!("the field-location gap must not open its base: {receiver_outcome:#?}");
        };
        assert_eq!(
            receiver_result.objects().coverage(),
            CandidateCoverage::Exhaustive
        );

        let mut callee_budget = SemanticBudget::default();
        let callee_outcome = oracle
            .pointees(
                &ValueAtPoint::new(
                    callee,
                    point,
                    ObservationPhase::AfterEffects,
                    OracleCallContext::empty(),
                )
                .expect("callee observation"),
                &mut SemanticRequest::new(&mut callee_budget, &cancellation),
            )
            .expect("callee points-to query runs");
        assert!(
            matches!(
                &callee_outcome,
                SemanticOutcome::Unknown {
                    partial: Some(result),
                    ..
                } if result.objects().coverage() == CandidateCoverage::Open
            ),
            "the unresolved field load itself remains open: {callee_outcome:#?}"
        );
    }
}
