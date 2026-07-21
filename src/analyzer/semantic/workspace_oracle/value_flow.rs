//! Bounded value-flow and candidate-specific call-binding materialization.
//!
//! The implementation projects validated semantic IR rows into neutral oracle
//! relations. It never reparses source or matches declarations by text.

use std::sync::Arc;

use super::WorkspaceSemanticOracle;
use crate::analyzer::semantic::{
    AbstractLocation, AbstractObject, AbstractObjectIdentity, AccessPath, AccessPathRoot,
    AccessSelector, AllocationHandle, CallArgumentEndpoint, CallArgumentExpansion,
    CallArgumentGroup, CallArgumentMapping, CallArgumentMember, CallBinding, CallBindings,
    CallPassingMode, CandidateCoverage, CaptureSource, DispatchCandidate, EvidenceCompleteness,
    EvidenceHandle, FormalMultiplicity, IndexSelector, MemoryLocationHandle, MemoryLocationKind,
    ObjectCardinality, OracleCallContext, OracleCandidate, OracleContractError,
    OracleRelationArena, OracleRelationHandle, OracleRelationId, OracleRelationKind,
    OracleRelationOwner, OracleRelationRecord, ProcedureHandle, ProcedurePortHandle, ProofStatus,
    ScopedSemanticLocator, SemanticCapability, SemanticEffect, SemanticGapImpact, SemanticGapKind,
    SemanticGapSubject, SemanticOutcome, SemanticProviderError, SemanticRequest, SemanticValueKind,
    SemanticWork, ValueFlowEndpoint, ValueFlowKind, ValueFlowOracle, ValueFlowRelation,
    ValueFlowRelationKind, ValueFlowSnapshot, ValueHandle,
};

#[derive(Debug)]
enum Interruption {
    Budget(crate::analyzer::semantic::SemanticBudgetExceeded),
    Cancelled,
}

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
struct FlowRelationDraft {
    kind: ValueFlowRelationKind,
    source: ValueFlowEndpoint,
    target: ValueFlowEndpoint,
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
    evidence: Vec<EvidenceHandle>,
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

fn proven_complete(evidence: &[EvidenceHandle]) -> bool {
    matches!(
        evidence_quality(evidence),
        (ProofStatus::Proven, EvidenceCompleteness::Complete)
    )
}

fn value_handle(
    procedure: &ProcedureHandle,
    id: crate::analyzer::semantic::ValueId,
) -> Result<ValueHandle, SemanticProviderError> {
    procedure
        .value_handle(id)
        .ok_or_else(|| SemanticProviderError::internal("semantic effect has a stale value ID"))
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

fn abstract_location(
    procedure: &ProcedureHandle,
    location: MemoryLocationHandle,
    limits: crate::analyzer::semantic::OracleLimits,
) -> Result<(AbstractLocation, bool), SemanticProviderError> {
    let row = procedure
        .semantics()
        .memory_location(location.id())
        .ok_or_else(|| SemanticProviderError::internal("memory location handle is stale"))?;
    let (identity, root, selectors) = match &row.kind {
        MemoryLocationKind::Field { base, member } => {
            let base = value_handle(procedure, *base)?;
            let member =
                ScopedSemanticLocator::new(Arc::clone(procedure.artifact()), member.clone())
                    .map_err(|error| internal_contract("invalid field locator", error))?;
            (
                AbstractObjectIdentity::Value(base.clone()),
                AccessPathRoot::Value(base),
                vec![AccessSelector::Field(member)],
            )
        }
        MemoryLocationKind::Static { member } => {
            let member =
                ScopedSemanticLocator::new(Arc::clone(procedure.artifact()), member.clone())
                    .map_err(|error| internal_contract("invalid static locator", error))?;
            (
                AbstractObjectIdentity::Static(member.clone()),
                AccessPathRoot::Static(member),
                Vec::new(),
            )
        }
        MemoryLocationKind::Index { base, index } => {
            let base = value_handle(procedure, *base)?;
            let selector = match index {
                Some(index) => IndexSelector::Exact(value_handle(procedure, *index)?),
                None => IndexSelector::Any,
            };
            (
                AbstractObjectIdentity::Value(base.clone()),
                AccessPathRoot::Value(base),
                vec![AccessSelector::Index(selector)],
            )
        }
        MemoryLocationKind::LexicalCell { .. } => (
            AbstractObjectIdentity::LexicalCell(location.clone()),
            AccessPathRoot::LexicalCell(location),
            Vec::new(),
        ),
        MemoryLocationKind::Capture { .. } => {
            let port = ProcedurePortHandle::capture(procedure.clone(), row.id)
                .map_err(|error| internal_contract("invalid capture port", error))?;
            (
                AbstractObjectIdentity::CaptureSlot(port.clone()),
                AccessPathRoot::CaptureSlot(port),
                Vec::new(),
            )
        }
    };
    let path = AccessPath::exact(root, selectors, limits)
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

fn dedup_evidence(evidence: impl IntoIterator<Item = EvidenceHandle>) -> Vec<EvidenceHandle> {
    let mut result = Vec::new();
    for handle in evidence {
        if !result.contains(&handle) {
            result.push(handle);
        }
    }
    result
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

        let mut open = false;
        let mut gap_quality = None;
        if interrupted.is_none() {
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
                let relevant = gap.impacts.contains(SemanticGapImpact::ValueFlow)
                    || gap.impacts.contains(SemanticGapImpact::ReturnTransfer)
                    || gap.impacts.contains(SemanticGapImpact::HeapRead)
                    || gap.impacts.contains(SemanticGapImpact::HeapWrite);
                open |= relevant;
                if relevant {
                    gap_quality = merge_gap_quality(gap_quality, gap);
                }
            }
        }

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
            for event in &point.events {
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
                        let row = procedure
                            .semantics()
                            .memory_location(*location)
                            .ok_or_else(|| {
                                SemanticProviderError::internal(
                                    "memory effect has a stale location ID",
                                )
                            })?;
                        Some(SemanticWork {
                            values: location_value_reads(&row.kind) + 1,
                            memory_locations: 1,
                            evidence: 1,
                            nested_entries: 1,
                            ..SemanticWork::default()
                        })
                    }
                    SemanticEffect::CaptureBind { capture } => {
                        let capture = procedure.semantics().capture(*capture).ok_or_else(|| {
                            SemanticProviderError::internal("capture effect has a stale ID")
                        })?;
                        let (values, memory_locations) = match capture.captured {
                            CaptureSource::Value(_) => (1, 1),
                            CaptureSource::Location(location) => {
                                let source = procedure
                                    .semantics()
                                    .memory_location(location)
                                    .ok_or_else(|| {
                                        SemanticProviderError::internal(
                                            "capture source has a stale location ID",
                                        )
                                    })?;
                                (location_value_reads(&source.kind), 2)
                            }
                        };
                        Some(SemanticWork {
                            procedures: 1,
                            values,
                            memory_locations,
                            captures: 1,
                            evidence: 1,
                            nested_entries: 1,
                            ..SemanticWork::default()
                        })
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
                        let SemanticValueKind::Parameter { ordinal, .. } = source_row.kind else {
                            return Err(SemanticProviderError::internal(
                                "parameter flow source is not a parameter",
                            ));
                        };
                        (
                            ValueFlowRelationKind::Parameter,
                            ValueFlowEndpoint::Port(
                                ProcedurePortHandle::parameter(procedure.clone(), ordinal)
                                    .map_err(|error| {
                                        internal_contract("invalid parameter port", error)
                                    })?,
                            ),
                            ValueFlowEndpoint::Value(value_handle(procedure, *target)?),
                            false,
                        )
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
                        location, result, ..
                    } => {
                        let location =
                            procedure.memory_location_handle(*location).ok_or_else(|| {
                                SemanticProviderError::internal("memory load has a stale location")
                            })?;
                        let (location, summary) =
                            abstract_location(procedure, location, *self.limits())?;
                        (
                            ValueFlowRelationKind::MemoryLoad,
                            ValueFlowEndpoint::Location(Box::new(location)),
                            ValueFlowEndpoint::Value(value_handle(procedure, *result)?),
                            summary,
                        )
                    }
                    SemanticEffect::MemoryStore {
                        location, value, ..
                    } => {
                        let location =
                            procedure.memory_location_handle(*location).ok_or_else(|| {
                                SemanticProviderError::internal("memory store has a stale location")
                            })?;
                        let (location, summary) =
                            abstract_location(procedure, location, *self.limits())?;
                        (
                            ValueFlowRelationKind::MemoryStore,
                            ValueFlowEndpoint::Value(value_handle(procedure, *value)?),
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
                            CaptureSource::Location(location) => {
                                let location = procedure
                                    .memory_location_handle(location)
                                    .ok_or_else(|| {
                                        SemanticProviderError::internal(
                                            "capture source location is stale",
                                        )
                                    })?;
                                ValueFlowEndpoint::Location(Box::new(
                                    abstract_location(procedure, location, *self.limits())?.0,
                                ))
                            }
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
                }
                let draft = FlowRelationDraft {
                    kind,
                    source,
                    target,
                    proof,
                    completeness,
                    evidence: vec![evidence],
                };
                if !push_flow_relation(&mut drafts, &mut retained_evidence, *self.limits(), draft) {
                    truncated = true;
                    break 'points;
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
                    || gap.impacts.contains(SemanticGapImpact::ValueFlow));
            build.open |= relevant;
            if relevant {
                build.gap_quality = merge_gap_quality(build.gap_quality, gap);
            }
        }
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
            let relevant = gap.impacts.contains(SemanticGapImpact::CallEvaluation)
                || gap.impacts.contains(SemanticGapImpact::ReturnTransfer)
                || gap.impacts.contains(SemanticGapImpact::ValueFlow);
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
            && let Some(actual_id) = call_row.receiver
            && let Some(receiver_row) = callee
                .semantics()
                .values()
                .iter()
                .find(|value| value.kind == SemanticValueKind::Receiver)
        {
            if request.cancellation.is_cancelled() {
                interrupted = Some(Interruption::Cancelled);
            } else {
                let evidence = dedup_evidence([
                    call_evidence.clone(),
                    evidence_handle(callee, receiver_row.evidence)?,
                ]);
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
            }
        } else if interrupted.is_none()
            && callee
                .semantics()
                .values()
                .iter()
                .any(|value| value.kind == SemanticValueKind::Receiver)
        {
            build.open = true;
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
