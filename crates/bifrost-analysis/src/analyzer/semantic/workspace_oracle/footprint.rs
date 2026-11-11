//! Query-local proof that two formal referents cannot be connected by a callee.
// Lane C wires the consumer after the lowering admission and projection compose.
#![allow(dead_code)]

use std::collections::{HashMap, HashSet, VecDeque};

use super::WorkspaceSemanticOracle;
use super::common::WorkStager;
use crate::analyzer::semantic::{
    CallArgumentEndpoint, CallBinding, CallInvocationMode, CallSiteHandle, CandidateCoverage,
    DispatchOracle, EvidenceCompleteness, ExecutionTiming, FootprintAdmission, MemoryLocationKind,
    OracleCallContext, ProcedureHandle, ProcedurePortKind, ProofStatus, SemanticArtifactKey,
    SemanticEffect, SemanticGapSubject, SemanticProviderError, SemanticRequest, SemanticValueKind,
    SemanticWork, ValueFlowKind, ValueFlowOracle, ValueId, ValueUseKind, call_target_gap_pair,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormalFootprintCertificate {
    pub verdict: FootprintVerdict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FootprintVerdict {
    Proven,
    Unknown(FootprintUnknown),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FootprintUnknown {
    AdmissionRefused,
    Budget,
    Cancelled,
    OpenDispatch,
    NonLocalCandidate,
    IncompleteBinding,
    UnmappedPosition,
    RecursiveCall,
    UnclassifiedUse,
    MemoryAccess,
    Publication,
    AmbientEffect,
    UnaccountedGap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Phase {
    BeforeEffects,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Exit {
    NormalAndExceptional,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlowClass {
    ExactLocal,
    PortAnnotation,
    Refuse,
}

fn classify_flow(kind: ValueFlowKind) -> FlowClass {
    match kind {
        ValueFlowKind::Local => FlowClass::ExactLocal,
        ValueFlowKind::Parameter | ValueFlowKind::Receiver => FlowClass::PortAnnotation,
        ValueFlowKind::Transfer(_)
        | ValueFlowKind::OwnershipUnknown
        | ValueFlowKind::BackingStore { .. }
        | ValueFlowKind::IntegerOffset { .. }
        | ValueFlowKind::BackingStoreAlternative { .. }
        | ValueFlowKind::Return
        | ValueFlowKind::IndexedReturn { .. }
        | ValueFlowKind::ReferenceBoxing
        | ValueFlowKind::ReferenceUnboxing
        | ValueFlowKind::LanguageDefined
        | ValueFlowKind::ByValueCapture => FlowClass::Refuse,
    }
}

fn memo_mapping_matches<T: PartialEq>(cached: Option<&Option<T>>, current: &T) -> bool {
    cached.and_then(Option::as_ref) == Some(current)
}

fn value_use_refusal(kind: ValueUseKind) -> FootprintUnknown {
    match kind {
        ValueUseKind::Dereference | ValueUseKind::Unbind => FootprintUnknown::UnclassifiedUse,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MemoKey {
    artifact: SemanticArtifactKey,
    procedure: crate::analyzer::semantic::ProcedureId,
    context: OracleCallContext,
    d1: Vec<ProcedurePortKind>,
    d2: Vec<ProcedurePortKind>,
    phase: Phase,
    exit: Exit,
}

impl MemoKey {
    fn new(
        procedure: &ProcedureHandle,
        context: OracleCallContext,
        mut d1: Vec<ProcedurePortKind>,
        mut d2: Vec<ProcedurePortKind>,
    ) -> Self {
        d1.sort_by_key(port_order);
        d1.dedup();
        d2.sort_by_key(port_order);
        d2.dedup();
        Self {
            artifact: procedure.artifact().key().clone(),
            procedure: procedure.id(),
            context,
            d1,
            d2,
            phase: Phase::BeforeEffects,
            exit: Exit::NormalAndExceptional,
        }
    }
}

fn port_order(port: &ProcedurePortKind) -> (u8, u32) {
    match port {
        ProcedurePortKind::Receiver => (0, 0),
        ProcedurePortKind::Parameter { ordinal } => (1, *ordinal),
        ProcedurePortKind::NormalReturn => (2, 0),
        ProcedurePortKind::IndexedNormalReturn { ordinal } => (3, *ordinal),
        ProcedurePortKind::ExceptionalReturn => (4, 0),
        ProcedurePortKind::Capture { slot } => (5, slot.index() as u32),
    }
}

#[derive(Clone)]
struct Child {
    procedure: ProcedureHandle,
    key: MemoKey,
    stamp: MappingStamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MappingStamp {
    call: CallSiteHandle,
    candidate: (SemanticArtifactKey, crate::analyzer::semantic::ProcedureId),
    positions: Vec<(BindingPosition, ValueId, ProcedurePortKind)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum BindingPosition {
    Receiver,
    Argument(u32),
    Implicit(u32),
}

struct Frame {
    key: MemoKey,
    children: Vec<Child>,
    next: usize,
    stamp: Option<MappingStamp>,
}

/// The certificate is valid only for this exact selected call and caller context.
#[allow(clippy::too_many_arguments)]
pub(crate) fn formal_footprint_certificate(
    oracle: &WorkspaceSemanticOracle<'_>,
    call: &CallSiteHandle,
    candidate: &ProcedureHandle,
    context: &OracleCallContext,
    tracked_formal: usize,
    other_formal: usize,
    request: &mut SemanticRequest<'_>,
) -> Result<FormalFootprintCertificate, SemanticProviderError> {
    let (Ok(tracked_formal), Ok(other_formal)) =
        (u32::try_from(tracked_formal), u32::try_from(other_formal))
    else {
        return Ok(FormalFootprintCertificate {
            verdict: FootprintVerdict::Unknown(FootprintUnknown::UnmappedPosition),
        });
    };
    let root = MemoKey::new(
        candidate,
        context.clone(),
        vec![ProcedurePortKind::Parameter {
            ordinal: tracked_formal,
        }],
        vec![ProcedurePortKind::Parameter {
            ordinal: other_formal,
        }],
    );
    let mark = request.budget.scratch_mark();
    let mut staged = WorkStager::new(request);
    let verdict = prove(oracle, call, candidate.clone(), root, &mut staged, request)?;
    if matches!(verdict, FootprintVerdict::Unknown(FootprintUnknown::Budget)) {
        request.budget.retain_performed_work(&staged.budget);
    } else {
        // The certificate is a verdict. Every row the scan counted, and the
        // bindings it rebuilt, are gone with the proof, so nothing of it may
        // stay on the caller's ledger (#10530).
        staged.budget.release_scratch_since(&mark);
        *request.budget = staged.budget;
    }
    Ok(FormalFootprintCertificate { verdict })
}

fn prove(
    oracle: &WorkspaceSemanticOracle<'_>,
    call: &CallSiteHandle,
    root_procedure: ProcedureHandle,
    root_key: MemoKey,
    staged: &mut WorkStager,
    request: &SemanticRequest<'_>,
) -> Result<FootprintVerdict, SemanticProviderError> {
    let mut memo = HashMap::<MemoKey, Option<MappingStamp>>::new();
    let mut active = HashSet::new();
    let mut stack = Vec::new();
    let first = match scan(oracle, &root_procedure, &root_key, staged, request)? {
        Ok(children) => children,
        Err(reason) => return Ok(FootprintVerdict::Unknown(reason)),
    };
    if let Err(reason) =
        verify_root_binding(oracle, call, &root_procedure, &root_key, staged, request)?
    {
        return Ok(FootprintVerdict::Unknown(reason));
    }
    active.insert(root_procedure.durable_key());
    stack.push(Frame {
        key: root_key,
        children: first,
        next: 0,
        stamp: None,
    });
    while let Some(frame) = stack.last_mut() {
        if let Some(reason) = interrupted(request) {
            return Ok(FootprintVerdict::Unknown(reason));
        }
        if frame.next == frame.children.len() {
            let done = stack.pop().expect("active frame exists");
            active.remove(&(done.key.artifact.clone(), done.key.procedure));
            memo.insert(done.key, done.stamp);
            continue;
        }
        let child = frame.children[frame.next].clone();
        frame.next += 1;
        // The caller's exact dispatch and bindings were reconstructed by scan
        // before consulting this memo. A key alone never validates a call mapping.
        if active.contains(&child.procedure.durable_key()) {
            return Ok(FootprintVerdict::Unknown(FootprintUnknown::RecursiveCall));
        }
        if memo_mapping_matches(memo.get(&child.key), &child.stamp) {
            continue;
        }
        let children = match scan(oracle, &child.procedure, &child.key, staged, request)? {
            Ok(children) => children,
            Err(reason) => return Ok(FootprintVerdict::Unknown(reason)),
        };
        active.insert(child.procedure.durable_key());
        stack.push(Frame {
            key: child.key.clone(),
            children,
            next: 0,
            stamp: Some(child.stamp),
        });
    }
    Ok(FootprintVerdict::Proven)
}

fn verify_root_binding(
    oracle: &WorkspaceSemanticOracle<'_>,
    call: &CallSiteHandle,
    candidate: &ProcedureHandle,
    key: &MemoKey,
    staged: &mut WorkStager,
    request: &SemanticRequest<'_>,
) -> Result<Result<(), FootprintUnknown>, SemanticProviderError> {
    let dispatch = DispatchOracle::resolve_call_in_context(
        oracle,
        call,
        &key.context,
        &mut staged.request(request.cancellation),
    )?;
    let crate::analyzer::semantic::SemanticOutcome::Complete {
        value: dispatch, ..
    } = dispatch
    else {
        return Ok(Err(FootprintUnknown::OpenDispatch));
    };
    if dispatch.coverage() != CandidateCoverage::Exhaustive
        || !dispatch.boundaries().is_empty()
        || dispatch.candidates().len() != 1
        || dispatch.candidates()[0].target() != candidate
    {
        return Ok(Err(FootprintUnknown::OpenDispatch));
    }
    let selected = &dispatch.candidates()[0];
    if !matches!(selected.proof(), ProofStatus::Proven)
        || !matches!(selected.completeness(), EvidenceCompleteness::Complete)
    {
        return Ok(Err(FootprintUnknown::OpenDispatch));
    }
    let bindings = ValueFlowOracle::call_bindings(
        oracle,
        call,
        selected,
        &key.context,
        &mut staged.request(request.cancellation),
    )?;
    let crate::analyzer::semantic::SemanticOutcome::Complete {
        value: bindings, ..
    } = bindings
    else {
        return Ok(Err(FootprintUnknown::IncompleteBinding));
    };
    if bindings.coverage() != CandidateCoverage::Exhaustive {
        return Ok(Err(FootprintUnknown::IncompleteBinding));
    }
    let mut mapped = HashSet::new();
    for binding in bindings.bindings() {
        match binding {
            CallBinding::Receiver { formal, .. } | CallBinding::ImplicitArgument { formal, .. } => {
                mapped.insert(formal.kind());
            }
            CallBinding::ArgumentGroup(group) => {
                if group.coverage() != CandidateCoverage::Exhaustive {
                    return Ok(Err(FootprintUnknown::IncompleteBinding));
                }
                for mapping in group.mappings() {
                    if !mapping.is_proven_complete()
                        || !mapping.value().preserves_reference_identity()
                    {
                        return Ok(Err(FootprintUnknown::IncompleteBinding));
                    }
                    mapped.insert(mapping.value().formal().kind());
                }
            }
            CallBinding::NormalReturn { .. } | CallBinding::ExceptionalReturn { .. } => {}
        }
    }
    if key
        .d1
        .iter()
        .chain(&key.d2)
        .any(|port| !mapped.contains(port))
    {
        return Ok(Err(FootprintUnknown::UnmappedPosition));
    }
    Ok(Ok(()))
}

fn interrupted(request: &SemanticRequest<'_>) -> Option<FootprintUnknown> {
    if request.cancellation.is_cancelled() || request.cancellation.soft_deadline_passed() {
        Some(FootprintUnknown::Cancelled)
    } else if request.budget.first_refusal().is_some() {
        Some(FootprintUnknown::Budget)
    } else {
        None
    }
}

fn scan(
    oracle: &WorkspaceSemanticOracle<'_>,
    procedure: &ProcedureHandle,
    key: &MemoKey,
    staged: &mut WorkStager,
    request: &SemanticRequest<'_>,
) -> Result<Result<Vec<Child>, FootprintUnknown>, SemanticProviderError> {
    if let Some(reason) = interrupted(request) {
        return Ok(Err(reason));
    }
    oracle
        .workspace()
        .analyzer()
        .record_read(crate::analyzer::ReadKey::semantic_artifact(
            procedure.artifact().key(),
        ));
    let admission = oracle
        .workspace()
        .stored_footprint_coverage(procedure, &mut staged.request(request.cancellation))?;
    let FootprintAdmission::Admitted {
        call_target_obligations,
    } = admission
    else {
        return Ok(Err(FootprintUnknown::AdmissionRefused));
    };
    let semantics = procedure.semantics();
    let mut d1 = HashSet::new();
    let mut d2 = HashSet::new();
    let mut found_ports = HashSet::new();
    for value in semantics.values() {
        if staged
            .admit(SemanticWork {
                values: 1,
                ..SemanticWork::default()
            })
            .is_err()
        {
            return Ok(Err(FootprintUnknown::Budget));
        }
        let port = match value.kind {
            SemanticValueKind::Parameter { ordinal, .. } => {
                Some(ProcedurePortKind::Parameter { ordinal })
            }
            SemanticValueKind::Receiver { .. } => Some(ProcedurePortKind::Receiver),
            SemanticValueKind::Local
            | SemanticValueKind::DefaultArgument { .. }
            | SemanticValueKind::Return
            | SemanticValueKind::Temporary
            | SemanticValueKind::Address
            | SemanticValueKind::Null
            | SemanticValueKind::Boolean(_)
            | SemanticValueKind::UnsignedInteger(_)
            | SemanticValueKind::SignedInteger(_)
            | SemanticValueKind::FloatingPoint { .. }
            | SemanticValueKind::Constant
            | SemanticValueKind::ConstantString(_)
            | SemanticValueKind::Exception
            | SemanticValueKind::Callable
            | SemanticValueKind::AwaitResult
            | SemanticValueKind::LanguageDefined(_) => None,
        };
        if let Some(port) = port {
            found_ports.insert(port);
            if key.d1.contains(&port) {
                d1.insert(value.id);
            }
            if key.d2.contains(&port) {
                d2.insert(value.id);
            }
        }
    }
    if key
        .d1
        .iter()
        .chain(&key.d2)
        .any(|port| !found_ports.contains(port))
    {
        return Ok(Err(FootprintUnknown::UnmappedPosition));
    }
    let mut obligation_gaps = HashSet::new();
    for obligation in &call_target_obligations {
        if staged
            .admit(SemanticWork {
                gaps: 1,
                call_sites: 1,
                ..SemanticWork::default()
            })
            .is_err()
        {
            return Ok(Err(FootprintUnknown::Budget));
        }
        let Some(gap) = semantics.gap(obligation.gap) else {
            return Ok(Err(FootprintUnknown::UnaccountedGap));
        };
        let Some(call) = semantics.call_site(obligation.call) else {
            return Ok(Err(FootprintUnknown::UnaccountedGap));
        };
        // The writer derives each obligation from this pair, so both of its
        // gaps are accounted for, and nothing else is.
        let Some((resolution, callable)) = call_target_gap_pair(call, semantics.gaps()) else {
            return Ok(Err(FootprintUnknown::UnaccountedGap));
        };
        if gap.subject != SemanticGapSubject::CallSite(obligation.call)
            || gap.impacts != obligation.impacts
            || resolution.id != obligation.gap
        {
            return Ok(Err(FootprintUnknown::UnaccountedGap));
        }
        obligation_gaps.insert(resolution.id);
        obligation_gaps.insert(callable.id);
    }
    // Revisit rows when a MAY set grows; every revisit is charged.
    let points = semantics.points();
    let mut pending = (0..points.len()).collect::<VecDeque<_>>();
    let mut queued = vec![true; points.len()];
    while let Some(point_index) = pending.pop_front() {
        queued[point_index] = false;
        let mut changed = false;
        let point = &points[point_index];
        if staged
            .admit(SemanticWork {
                program_points: 1,
                ..SemanticWork::default()
            })
            .is_err()
        {
            return Ok(Err(FootprintUnknown::Budget));
        }
        for (index, event) in point.events.iter().enumerate() {
            if staged
                .admit(SemanticWork {
                    events: 1,
                    ..SemanticWork::default()
                })
                .is_err()
            {
                return Ok(Err(FootprintUnknown::Budget));
            }
            if let Some(reason) = interrupted(request) {
                return Ok(Err(reason));
            }
            match event.effect {
                SemanticEffect::Assignment { target, value } => {
                    if point.assignment_has_transfer_marker(index) {
                        continue;
                    }
                    if d1.contains(&value) {
                        changed |= d1.insert(target);
                    }
                    if d2.contains(&value) {
                        changed |= d2.insert(target);
                    }
                }
                SemanticEffect::ValueFlow {
                    kind,
                    source,
                    target,
                } => match classify_flow(kind) {
                    FlowClass::ExactLocal => {
                        if d1.contains(&source) {
                            changed |= d1.insert(target);
                        }
                        if d2.contains(&source) {
                            changed |= d2.insert(target);
                        }
                    }
                    FlowClass::PortAnnotation => {
                        // Port metadata is identity-preserving only when
                        // the same point has the exact local assignment.
                        if d1.contains(&source) || d2.contains(&source) {
                            if !point.events.iter().any(|event| {
                                matches!(event.effect,
                                    SemanticEffect::Assignment { target: assigned, value }
                                        if assigned == target && value == source)
                            }) {
                                return Ok(Err(FootprintUnknown::UnclassifiedUse));
                            }
                            if d1.contains(&source) {
                                changed |= d1.insert(target);
                            }
                            if d2.contains(&source) {
                                changed |= d2.insert(target);
                            }
                        }
                    }
                    FlowClass::Refuse => {
                        if d1.contains(&source) || d2.contains(&source) {
                            return Ok(Err(FootprintUnknown::UnclassifiedUse));
                        }
                    }
                },
                SemanticEffect::Entry
                | SemanticEffect::NormalExit
                | SemanticEffect::ExceptionalExit
                | SemanticEffect::Allocation { .. }
                | SemanticEffect::Invoke { .. }
                | SemanticEffect::CallContinuation { .. }
                | SemanticEffect::CallableCreation { .. }
                | SemanticEffect::CallableReference { .. } => {}
                SemanticEffect::ValueUse { kind, value } => {
                    if d1.contains(&value) || d2.contains(&value) {
                        return Ok(Err(value_use_refusal(kind)));
                    }
                }
                SemanticEffect::AggregateInitializer {
                    aggregate, value, ..
                } => {
                    if [aggregate, value]
                        .iter()
                        .any(|v| d1.contains(v) || d2.contains(v))
                    {
                        return Ok(Err(FootprintUnknown::UnclassifiedUse));
                    }
                }
                SemanticEffect::MemoryLoad { location, .. } => {
                    if staged
                        .admit(SemanticWork {
                            memory_locations: 1,
                            ..SemanticWork::default()
                        })
                        .is_err()
                    {
                        return Ok(Err(FootprintUnknown::Budget));
                    }
                    let Some(location) = semantics.memory_location(location) else {
                        return Ok(Err(FootprintUnknown::MemoryAccess));
                    };
                    match &location.kind {
                        MemoryLocationKind::Static { .. } | MemoryLocationKind::Capture { .. } => {
                            return Ok(Err(FootprintUnknown::AmbientEffect));
                        }
                        // Without reaching-writer authority, even an
                        // unrelated base could load a tracked referent.
                        MemoryLocationKind::Field { .. }
                        | MemoryLocationKind::Property { .. }
                        | MemoryLocationKind::Index { .. }
                        | MemoryLocationKind::Dereference { .. }
                        | MemoryLocationKind::LexicalCell { .. } => {
                            return Ok(Err(FootprintUnknown::MemoryAccess));
                        }
                    }
                }
                SemanticEffect::MemoryStore {
                    location, value, ..
                } => {
                    if d1.contains(&value) {
                        return Ok(Err(FootprintUnknown::Publication));
                    }
                    if staged
                        .admit(SemanticWork {
                            memory_locations: 1,
                            ..SemanticWork::default()
                        })
                        .is_err()
                    {
                        return Ok(Err(FootprintUnknown::Budget));
                    }
                    if semantics.is_formal_cell_initialization(point.id, &event.effect) {
                        continue;
                    }
                    let Some(location) = semantics.memory_location(location) else {
                        return Ok(Err(FootprintUnknown::MemoryAccess));
                    };
                    match &location.kind {
                        MemoryLocationKind::Static { .. } | MemoryLocationKind::Capture { .. } => {
                            return Ok(Err(FootprintUnknown::AmbientEffect));
                        }
                        MemoryLocationKind::Field { .. }
                        | MemoryLocationKind::Property { .. }
                        | MemoryLocationKind::Index { .. }
                        | MemoryLocationKind::Dereference { .. }
                        | MemoryLocationKind::LexicalCell { .. } => {
                            return Ok(Err(FootprintUnknown::MemoryAccess));
                        }
                    }
                }
                SemanticEffect::Synchronization { .. }
                | SemanticEffect::AsyncSuspend { .. }
                | SemanticEffect::AsyncResume { .. } => {
                    return Ok(Err(FootprintUnknown::AmbientEffect));
                }
                SemanticEffect::CaptureBind { .. } => {
                    return Ok(Err(FootprintUnknown::AmbientEffect));
                }
                SemanticEffect::ProcedureReturn { value } | SemanticEffect::Throw { value } => {
                    if value.is_some_and(|v| d1.contains(&v) || d2.contains(&v)) {
                        return Ok(Err(FootprintUnknown::Publication));
                    }
                }
                // Only a call-target obligation accounts for a persisted gap effect.
                SemanticEffect::Gap { gap } => {
                    if !obligation_gaps.contains(&gap) {
                        return Ok(Err(FootprintUnknown::UnaccountedGap));
                    }
                }
            }
        }
        if changed {
            for (index, is_queued) in queued.iter_mut().enumerate() {
                if !*is_queued {
                    pending.push_back(index);
                    *is_queued = true;
                }
            }
        }
    }
    let mut children = Vec::new();
    let mut discharged = HashSet::new();
    for call_row in semantics.call_sites() {
        if staged
            .admit(SemanticWork {
                call_sites: 1,
                ..SemanticWork::default()
            })
            .is_err()
        {
            return Ok(Err(FootprintUnknown::Budget));
        }
        if let Some(reason) = interrupted(request) {
            return Ok(Err(reason));
        }
        if call_row.invocation_mode != CallInvocationMode::Ordinary
            || !matches!(
                call_row.execution_timing,
                ExecutionTiming::SameEvaluation | ExecutionTiming::SameInvocation
            )
        {
            return Ok(Err(FootprintUnknown::AmbientEffect));
        }
        if d1.contains(&call_row.callee) || d2.contains(&call_row.callee) {
            return Ok(Err(FootprintUnknown::UnclassifiedUse));
        }
        let Some(call) = procedure.call_site_handle(call_row.id) else {
            return Ok(Err(FootprintUnknown::UnclassifiedUse));
        };
        let dispatch = DispatchOracle::resolve_call_in_context(
            oracle,
            &call,
            &key.context,
            &mut staged.request(request.cancellation),
        )?;
        let crate::analyzer::semantic::SemanticOutcome::Complete {
            value: dispatch, ..
        } = dispatch
        else {
            return Ok(Err(FootprintUnknown::OpenDispatch));
        };
        if dispatch.coverage() != CandidateCoverage::Exhaustive
            || !dispatch.boundaries().is_empty()
            || dispatch.candidates().is_empty()
        {
            return Ok(Err(FootprintUnknown::OpenDispatch));
        }
        for candidate in dispatch.candidates() {
            if candidate.target().artifact().key().mount()
                != crate::analyzer::semantic::WorkspaceMountId::from_root(
                    oracle.workspace().analyzer().project().root(),
                )
            {
                return Ok(Err(FootprintUnknown::NonLocalCandidate));
            }
            if !matches!(candidate.proof(), ProofStatus::Proven)
                || !matches!(candidate.completeness(), EvidenceCompleteness::Complete)
            {
                return Ok(Err(FootprintUnknown::OpenDispatch));
            }
            let bindings = ValueFlowOracle::call_bindings(
                oracle,
                &call,
                candidate,
                &key.context,
                &mut staged.request(request.cancellation),
            )?;
            let crate::analyzer::semantic::SemanticOutcome::Complete {
                value: bindings, ..
            } = bindings
            else {
                return Ok(Err(FootprintUnknown::IncompleteBinding));
            };
            if bindings.coverage() != CandidateCoverage::Exhaustive {
                return Ok(Err(FootprintUnknown::IncompleteBinding));
            }
            let mut child_d1 = Vec::new();
            let mut child_d2 = Vec::new();
            let mut receiver_mapped = false;
            let mut argument_positions = HashSet::new();
            let mut positions = Vec::new();
            for binding in bindings.bindings() {
                match binding {
                    CallBinding::Receiver { actual, formal, .. } => {
                        if call_row.receiver != Some(actual.id())
                            || formal.procedure() != candidate.target()
                        {
                            return Ok(Err(FootprintUnknown::UnmappedPosition));
                        }
                        receiver_mapped = true;
                        positions.push((BindingPosition::Receiver, actual.id(), formal.kind()));
                        if d1.contains(&actual.id()) {
                            child_d1.push(formal.kind());
                        }
                        if d2.contains(&actual.id()) {
                            child_d2.push(formal.kind());
                        }
                    }
                    CallBinding::ArgumentGroup(group) => {
                        if group.coverage() != CandidateCoverage::Exhaustive {
                            return Ok(Err(FootprintUnknown::IncompleteBinding));
                        }
                        for mapping in group.mappings() {
                            if !mapping.is_proven_complete()
                                || !mapping.value().preserves_reference_identity()
                            {
                                return Ok(Err(FootprintUnknown::IncompleteBinding));
                            }
                            let actual = match mapping.value().actual() {
                                CallArgumentEndpoint::Value(value) => value.id(),
                                CallArgumentEndpoint::Location { .. } => {
                                    return Ok(Err(FootprintUnknown::UnmappedPosition));
                                }
                            };
                            if call_row
                                .arguments
                                .get(mapping.value().source_index() as usize)
                                .is_none_or(|argument| argument.value != actual)
                                || mapping.value().formal().procedure() != candidate.target()
                            {
                                return Ok(Err(FootprintUnknown::UnmappedPosition));
                            }
                            argument_positions.insert(mapping.value().source_index());
                            positions.push((
                                BindingPosition::Argument(mapping.value().source_index()),
                                actual,
                                mapping.value().formal().kind(),
                            ));
                            if d1.contains(&actual) {
                                child_d1.push(mapping.value().formal().kind());
                            }
                            if d2.contains(&actual) {
                                child_d2.push(mapping.value().formal().kind());
                            }
                        }
                    }
                    CallBinding::ImplicitArgument {
                        source,
                        formal,
                        formal_ordinal,
                        ..
                    } => {
                        positions.push((
                            BindingPosition::Implicit(*formal_ordinal),
                            source.id(),
                            formal.kind(),
                        ));
                        if d1.contains(&source.id()) {
                            child_d1.push(formal.kind());
                        }
                        if d2.contains(&source.id()) {
                            child_d2.push(formal.kind());
                        }
                    }
                    CallBinding::NormalReturn { .. } | CallBinding::ExceptionalReturn { .. } => {}
                }
            }
            if (call_row.receiver.is_some() && !receiver_mapped)
                || call_row
                    .arguments
                    .iter()
                    .enumerate()
                    .any(|(index, _)| !argument_positions.contains(&(index as u32)))
            {
                return Ok(Err(FootprintUnknown::UnmappedPosition));
            }
            // The child scan refuses any return or throw of a tracked port,
            // including both the normal and exceptional call continuations.
            positions.sort_by_key(|(position, value, formal)| {
                (*position, value.index(), port_order(formal))
            });
            children.push(Child {
                procedure: candidate.target().clone(),
                key: MemoKey::new(
                    candidate.target(),
                    key.context.extended(call.clone(), *oracle.limits()),
                    child_d1,
                    child_d2,
                ),
                stamp: MappingStamp {
                    call: call.clone(),
                    candidate: candidate.target().durable_key(),
                    positions,
                },
            });
        }
        discharged.insert(call_row.id);
    }
    if call_target_obligations
        .iter()
        .any(|obligation| !discharged.contains(&obligation.call))
    {
        return Ok(Err(FootprintUnknown::OpenDispatch));
    }
    Ok(Ok(children))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic::{
        AllocationId, BackingStoreOffset, SignedIntegerMagnitude, TransferKind, TransferOperation,
        ValueTransfer,
    };

    #[test]
    fn footprint_transport_refusal_table() {
        assert_eq!(classify_flow(ValueFlowKind::Local), FlowClass::ExactLocal);
        for kind in [ValueFlowKind::Parameter, ValueFlowKind::Receiver] {
            assert_eq!(classify_flow(kind), FlowClass::PortAnnotation);
        }
        let refused = [
            ValueFlowKind::Transfer(ValueTransfer {
                kind: TransferKind::Copy,
                operation: TransferOperation::None,
            }),
            ValueFlowKind::BackingStore {
                offset: BackingStoreOffset::Zero,
            },
            ValueFlowKind::IntegerOffset {
                offset: SignedIntegerMagnitude::from_i128(1),
            },
            ValueFlowKind::BackingStoreAlternative {
                offset: BackingStoreOffset::Zero,
                allocation: AllocationId::new(0),
            },
            ValueFlowKind::Return,
            ValueFlowKind::IndexedReturn { ordinal: 0 },
            ValueFlowKind::ReferenceBoxing,
            ValueFlowKind::ReferenceUnboxing,
            ValueFlowKind::LanguageDefined,
        ];
        for kind in refused {
            assert_eq!(classify_flow(kind), FlowClass::Refuse, "{kind:?}");
        }
        for kind in [ValueUseKind::Dereference, ValueUseKind::Unbind] {
            assert_eq!(value_use_refusal(kind), FootprintUnknown::UnclassifiedUse);
        }
    }

    #[test]
    fn footprint_tiny_budget_is_unknown() {
        let mut budget =
            crate::analyzer::semantic::SemanticBudget::uniform(1).expect("positive budget");
        assert!(
            budget
                .admit(SemanticWork {
                    program_points: 2,
                    ..SemanticWork::default()
                })
                .is_err()
        );
        let cancellation = crate::analyzer::semantic::CancellationToken::default();
        let request = SemanticRequest::new(&mut budget, &cancellation);
        assert_eq!(interrupted(&request), Some(FootprintUnknown::Budget));
    }

    #[test]
    fn footprint_memo_requires_exact_call_candidate_and_position_mapping() {
        let original = (7_u32, 11_u32, [(0_u32, 3_u32, 1_u32)]);
        let saved = Some(original);
        assert!(memo_mapping_matches(Some(&saved), &original));
        assert!(!memo_mapping_matches(Some(&saved), &(8, 11, [(0, 3, 1)])));
        assert!(!memo_mapping_matches(Some(&saved), &(7, 12, [(0, 3, 1)])));
        assert!(!memo_mapping_matches(Some(&saved), &(7, 11, [(0, 3, 2)])));
        assert!(!memo_mapping_matches::<_>(None, &original));
    }
}
