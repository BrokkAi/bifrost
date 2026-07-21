//! Bounded point-sensitive heap, alias, and update-oracle materialization.
//!
//! The implementation follows semantic IR edges and effects only. It does not
//! reparse source, infer identities from names, or upgrade allocation-site
//! identities into runtime singletons.

use std::collections::VecDeque;

use super::WorkspaceSemanticOracle;
use crate::analyzer::semantic::{
    AbstractLocation, AbstractObject, AbstractObjectIdentity, AccessPath, AccessPathAtPoint,
    AccessPathRoot, AliasExclusivity, AliasExclusivityWitness, AliasQuery, AliasRelation,
    AliasResult, CandidateCoverage, EscapeStatus, EscapeWitness, EvidenceCompleteness,
    EvidenceHandle, HeapOracle, LocationResult, ObjectCardinality, ObservationPhase,
    OracleCandidate, OracleContractError, OracleRelationArena, OracleRelationId,
    OracleRelationKind, OracleRelationOwner, OracleRelationRecord, OracleSet, PointsToResult,
    ProcedureHandle, ProcedurePortHandle, ProofStatus, SemanticEffect, SemanticGapImpact,
    SemanticOutcome, SemanticProviderError, SemanticRequest, SemanticValueKind, SemanticWork,
    StoreAtPoint, StrongUpdateEvidence, UpdateEligibility, ValueAtPoint, ValueHandle,
    WeakUpdateReason,
};
use crate::hash::HashSet;

#[derive(Debug)]
enum Interruption {
    Budget(crate::analyzer::semantic::SemanticBudgetExceeded),
    Cancelled,
}

struct WorkStager {
    budget: crate::analyzer::semantic::SemanticBudget,
    work: SemanticWork,
}

impl WorkStager {
    fn new(request: &SemanticRequest<'_>) -> Self {
        Self {
            budget: request.budget.clone(),
            work: SemanticWork::default(),
        }
    }

    fn charge(&mut self, work: SemanticWork) -> Result<(), Interruption> {
        let reported = self
            .work
            .checked_add(work)
            .unwrap_or_else(|| SemanticWork::uniform(usize::MAX));
        if let Err(exceeded) = self.budget.charge(work) {
            self.work = reported;
            return Err(Interruption::Budget(exceeded));
        }
        self.work = reported;
        Ok(())
    }
}

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

struct DraftSet<T> {
    candidates: Vec<T>,
    coverage: CandidateCoverage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TraceState {
    value: crate::analyzer::semantic::ValueId,
    point: crate::analyzer::semantic::ProgramPointId,
    event_limit: usize,
}

fn internal_contract(context: &str, error: OracleContractError) -> SemanticProviderError {
    SemanticProviderError::internal(format!("{context}: {error}"))
}

fn evidence_handle(
    procedure: &ProcedureHandle,
    id: crate::analyzer::semantic::EvidenceId,
) -> Result<EvidenceHandle, SemanticProviderError> {
    procedure
        .evidence_handle(id)
        .ok_or_else(|| SemanticProviderError::internal("semantic row has no evidence handle"))
}

fn dedup_evidence(evidence: impl IntoIterator<Item = EvidenceHandle>) -> Vec<EvidenceHandle> {
    let mut result = Vec::new();
    for handle in evidence {
        if !result.contains(&handle) {
            result.push(handle);
        }
    }
    result
}

fn evidence_quality(evidence: &[EvidenceHandle]) -> (ProofStatus, EvidenceCompleteness) {
    let proof = evidence
        .iter()
        .find_map(|handle| {
            let row = handle
                .procedure()
                .semantics()
                .evidence_row(handle.id())
                .expect("evidence handles are validated at construction");
            (!matches!(row.proof, ProofStatus::Proven)).then(|| row.proof.clone())
        })
        .unwrap_or(ProofStatus::Proven);
    let completeness = evidence
        .iter()
        .find_map(|handle| {
            let row = handle
                .procedure()
                .semantics()
                .evidence_row(handle.id())
                .expect("evidence handles are validated at construction");
            (!matches!(row.completeness, EvidenceCompleteness::Complete))
                .then(|| row.completeness.clone())
        })
        .unwrap_or(EvidenceCompleteness::Complete);
    (proof, completeness)
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

fn value_handle(
    procedure: &ProcedureHandle,
    id: crate::analyzer::semantic::ValueId,
) -> Result<ValueHandle, SemanticProviderError> {
    procedure
        .value_handle(id)
        .ok_or_else(|| SemanticProviderError::internal("semantic effect has a stale value ID"))
}

fn candidate_cardinality_for_root(root: &AccessPathRoot) -> ObjectCardinality {
    match root {
        AccessPathRoot::Static(_) | AccessPathRoot::LexicalCell(_) => ObjectCardinality::Singleton,
        AccessPathRoot::CaptureSlot(_) | AccessPathRoot::TypeSummary(_) => {
            ObjectCardinality::Summary
        }
        AccessPathRoot::Value(_)
        | AccessPathRoot::ProcedurePort(_)
        | AccessPathRoot::Allocation(_)
        | AccessPathRoot::ModuleObject(_)
        | AccessPathRoot::External(_) => ObjectCardinality::Unknown,
    }
}

fn identity_for_root(root: &AccessPathRoot) -> AbstractObjectIdentity {
    match root {
        AccessPathRoot::Value(value) => AbstractObjectIdentity::Value(value.clone()),
        AccessPathRoot::ProcedurePort(port) => AbstractObjectIdentity::ProcedurePort(port.clone()),
        AccessPathRoot::Allocation(allocation) => {
            AbstractObjectIdentity::Allocation(allocation.clone())
        }
        AccessPathRoot::Static(locator) => AbstractObjectIdentity::Static(locator.clone()),
        AccessPathRoot::LexicalCell(location) => {
            AbstractObjectIdentity::LexicalCell(location.clone())
        }
        AccessPathRoot::CaptureSlot(port) => AbstractObjectIdentity::CaptureSlot(port.clone()),
        AccessPathRoot::TypeSummary(locator) => {
            AbstractObjectIdentity::TypeSummary(locator.clone())
        }
        AccessPathRoot::ModuleObject(locator) => {
            AbstractObjectIdentity::ModuleObject(locator.clone())
        }
        AccessPathRoot::External(locator) => AbstractObjectIdentity::External(locator.clone()),
    }
}

fn root_for_identity(identity: &AbstractObjectIdentity) -> AccessPathRoot {
    match identity {
        AbstractObjectIdentity::Value(value) => AccessPathRoot::Value(value.clone()),
        AbstractObjectIdentity::Allocation(allocation) => {
            AccessPathRoot::Allocation(allocation.clone())
        }
        AbstractObjectIdentity::ProcedurePort(port) => AccessPathRoot::ProcedurePort(port.clone()),
        AbstractObjectIdentity::Static(locator) => AccessPathRoot::Static(locator.clone()),
        AbstractObjectIdentity::LexicalCell(location) => {
            AccessPathRoot::LexicalCell(location.clone())
        }
        AbstractObjectIdentity::CaptureSlot(port) => AccessPathRoot::CaptureSlot(port.clone()),
        AbstractObjectIdentity::TypeSummary(locator) => {
            AccessPathRoot::TypeSummary(locator.clone())
        }
        AbstractObjectIdentity::ModuleObject(locator) => {
            AccessPathRoot::ModuleObject(locator.clone())
        }
        AbstractObjectIdentity::External(locator) => AccessPathRoot::External(locator.clone()),
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
        AccessPathRoot::ProcedurePort(port) => port
            .procedure()
            .semantics()
            .values()
            .iter()
            .find(|value| match port.kind() {
                crate::analyzer::semantic::ProcedurePortKind::Receiver => {
                    value.kind == SemanticValueKind::Receiver
                }
                crate::analyzer::semantic::ProcedurePortKind::Parameter { ordinal } => matches!(
                    value.kind,
                    SemanticValueKind::Parameter { ordinal: actual, .. } if actual == ordinal
                ),
                crate::analyzer::semantic::ProcedurePortKind::NormalReturn => {
                    value.kind == SemanticValueKind::Return
                }
                crate::analyzer::semantic::ProcedurePortKind::ExceptionalReturn => {
                    value.kind == SemanticValueKind::Exception
                }
                crate::analyzer::semantic::ProcedurePortKind::Capture { .. } => false,
            })
            .map(|value| value.evidence),
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

fn gap_opens_heap(
    procedure: &ProcedureHandle,
    staged: &mut WorkStager,
    cancellation: &crate::cancellation::CancellationToken,
) -> Result<bool, Interruption> {
    let mut open = false;
    for gap in procedure.semantics().gaps() {
        if cancellation.is_cancelled() {
            return Err(Interruption::Cancelled);
        }
        staged.charge(SemanticWork {
            gaps: 1,
            ..SemanticWork::default()
        })?;
        open |= gap.impacts.contains(SemanticGapImpact::HeapRead)
            || gap.impacts.contains(SemanticGapImpact::HeapWrite)
            || gap.impacts.contains(SemanticGapImpact::Aliasing);
    }
    Ok(open)
}

fn allocation_is_cyclic(
    procedure: &ProcedureHandle,
    point: crate::analyzer::semantic::ProgramPointId,
    staged: &mut WorkStager,
    cancellation: &crate::cancellation::CancellationToken,
) -> Result<(bool, Vec<crate::analyzer::semantic::EvidenceId>), Interruption> {
    let cfg = procedure.semantics().cfg();
    let mut queue = VecDeque::new();
    let mut visited = HashSet::default();
    let mut evidence = Vec::new();
    for (_, edge) in cfg.successor_edges(point) {
        staged.charge(SemanticWork {
            control_edges: 1,
            ..SemanticWork::default()
        })?;
        if !evidence.contains(&edge.evidence) {
            evidence.push(edge.evidence);
        }
        if edge.target_point == point {
            return Ok((true, evidence));
        }
        if visited.insert(edge.target_point) {
            queue.push_back(edge.target_point);
        }
    }
    while let Some(current) = queue.pop_front() {
        if cancellation.is_cancelled() {
            return Err(Interruption::Cancelled);
        }
        staged.charge(SemanticWork {
            program_points: 1,
            ..SemanticWork::default()
        })?;
        for (_, edge) in cfg.successor_edges(current) {
            staged.charge(SemanticWork {
                control_edges: 1,
                ..SemanticWork::default()
            })?;
            if !evidence.contains(&edge.evidence) {
                evidence.push(edge.evidence);
            }
            if edge.target_point == point {
                return Ok((true, evidence));
            }
            if visited.insert(edge.target_point) {
                queue.push_back(edge.target_point);
            }
        }
    }
    Ok((false, Vec::new()))
}

fn push_object(
    drafts: &mut Vec<ObjectDraft>,
    object: AbstractObject,
    evidence: Vec<EvidenceHandle>,
) {
    let evidence = dedup_evidence(evidence);
    let quality = evidence_quality(&evidence);
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
        SemanticValueKind::Receiver => AbstractObjectIdentity::ProcedurePort(
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

fn resolve_objects(
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
    let mut open = gap_opens_heap(procedure, staged, cancellation)
        .map_err(InterruptionOrProvider::Interruption)?;
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
        },
        Vec::<EvidenceHandle>::new(),
    )];
    let mut visited = HashSet::default();
    let mut drafts = Vec::new();
    let mut truncated = false;

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
                    let (cyclic, cycle_evidence) =
                        allocation_is_cyclic(procedure, allocation_row.point, staged, cancellation)
                            .map_err(InterruptionOrProvider::Interruption)?;
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
                    let object = AbstractObject::new(
                        AbstractObjectIdentity::Allocation(handle),
                        if cyclic || recursive_context {
                            ObjectCardinality::Summary
                        } else {
                            ObjectCardinality::Unknown
                        },
                    )
                    .map_err(|error| {
                        InterruptionOrProvider::Provider(internal_contract(
                            "invalid allocation object",
                            error,
                        ))
                    })?;
                    let cycle_evidence = cycle_evidence
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
        if let Some((source, event_limit, evidence)) = producer {
            if source != state.value {
                stack.push((
                    TraceState {
                        value: source,
                        point: state.point,
                        event_limit,
                    },
                    evidence,
                ));
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
                    SemanticValueKind::Parameter { .. } | SemanticValueKind::Receiver
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
    query: &AccessPathAtPoint,
    limits: crate::analyzer::semantic::OracleLimits,
    staged: &mut WorkStager,
    cancellation: &crate::cancellation::CancellationToken,
) -> Result<DraftSet<LocationDraft>, InterruptionOrProvider> {
    let procedure = query.point().procedure();
    let objects = if let Some(value) = match query.path().root() {
        AccessPathRoot::Value(value) => Some(value.clone()),
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
        let mut objects = resolve_objects(&value, limits, staged, cancellation)?;
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
        objects
    } else {
        staged
            .charge(SemanticWork {
                procedures: 1,
                memory_locations: 1,
                ..SemanticWork::default()
            })
            .map_err(InterruptionOrProvider::Interruption)?;
        let open = gap_opens_heap(procedure, staged, cancellation)
            .map_err(InterruptionOrProvider::Interruption)?
            || query.context().was_truncated();
        let evidence = root_evidence(procedure, query.path().root())
            .map_err(InterruptionOrProvider::Provider)?;
        let mut quality = evidence_quality(&evidence);
        if matches!(
            query.path().root(),
            AccessPathRoot::Static(_)
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
        let object = AbstractObject::new(identity_for_root(query.path().root()), cardinality)
            .map_err(|error| {
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
        }
    };
    let mut candidates = Vec::new();
    let mut truncated = objects.coverage == CandidateCoverage::Truncated;
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
            root_for_identity(draft.object.identity()),
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

fn materialize_update(
    store: &StoreAtPoint,
    drafts: DraftSet<LocationDraft>,
    limits: crate::analyzer::semantic::OracleLimits,
) -> Result<UpdateEligibility, SemanticProviderError> {
    if drafts.candidates.is_empty() {
        return Ok(UpdateEligibility::Weak(direct_weak_reasons(
            drafts.coverage,
            &drafts.candidates,
        )));
    }
    if drafts.candidates.len() != 1 {
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
    // Strong-update locations must retain the exact store target. A refined
    // value-root path is still useful for aliasing, but cannot certify this
    // store because the certificate is intentionally bound to its IR address.
    let certificate_location = if first.location.path() == store.target().path() {
        first.location.clone()
    } else {
        let object = AbstractObject::new(
            identity_for_root(store.target().path().root()),
            candidate_cardinality_for_root(store.target().path().root()),
        )
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
        EscapeWitness::new(
            store.clone(),
            object.clone(),
            if matches!(
                object.identity(),
                AbstractObjectIdentity::LexicalCell(location)
                    if !location.procedure().semantics().captures().iter().any(|capture| {
                        matches!(
                            capture.captured,
                            crate::analyzer::semantic::CaptureSource::Location(captured)
                                if captured == location.id()
                        )
                    })
            ) {
                EscapeStatus::DoesNotEscape
            } else {
                EscapeStatus::MayEscape
            },
        )
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
        let drafts = match resolve_objects(value, *self.limits(), &mut staged, request.cancellation)
        {
            Ok(drafts) => drafts,
            Err(InterruptionOrProvider::Provider(error)) => return Err(error),
            Err(InterruptionOrProvider::Interruption(interruption)) => {
                let empty = DraftSet {
                    candidates: Vec::new(),
                    coverage: CandidateCoverage::Open,
                };
                let result = materialize_points_to(value, empty, *self.limits())?;
                return Ok(publish_set_outcome(
                    result,
                    CandidateCoverage::Open,
                    true,
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
            let empty = DraftSet {
                candidates: Vec::new(),
                coverage: CandidateCoverage::Open,
            };
            let result = materialize_points_to(value, empty, *self.limits())?;
            return Ok(publish_set_outcome(
                result,
                CandidateCoverage::Open,
                true,
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
        let drafts =
            match resolve_locations(access, *self.limits(), &mut staged, request.cancellation) {
                Ok(drafts) => drafts,
                Err(InterruptionOrProvider::Provider(error)) => return Err(error),
                Err(InterruptionOrProvider::Interruption(interruption)) => {
                    let empty = DraftSet {
                        candidates: Vec::new(),
                        coverage: CandidateCoverage::Open,
                    };
                    let result = materialize_locations(access, empty, *self.limits())?;
                    return Ok(publish_set_outcome(
                        result,
                        CandidateCoverage::Open,
                        true,
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
            let empty = DraftSet {
                candidates: Vec::new(),
                coverage: CandidateCoverage::Open,
            };
            let result = materialize_locations(access, empty, *self.limits())?;
            return Ok(publish_set_outcome(
                result,
                CandidateCoverage::Open,
                true,
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
            query.left(),
            *self.limits(),
            &mut staged,
            request.cancellation,
        );
        let right = resolve_locations(
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
                },
                DraftSet {
                    candidates: Vec::new(),
                    coverage: CandidateCoverage::Open,
                },
                Some(interruption),
            ),
            (_, Err(InterruptionOrProvider::Interruption(interruption))) => (
                DraftSet {
                    candidates: Vec::new(),
                    coverage: CandidateCoverage::Open,
                },
                DraftSet {
                    candidates: Vec::new(),
                    coverage: CandidateCoverage::Open,
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
            interruption,
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
        let eligibility = materialize_update(store, drafts, *self.limits())?;
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
