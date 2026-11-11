//! Candidate-specific subject transport across one call boundary.

use crate::analyzer::semantic::partial_flow::PartialFlowPort;
use crate::analyzer::semantic::{
    CallBinding, CallBindings, CandidateCoverage, DispatchResult, EvidenceCompleteness,
    ObservationPhase, OracleCallContext, PointsToResult, ProcedurePortKind, ProgramPointId,
    ProofStatus, SemanticEffect, SemanticOutcome, SemanticValueKind, ValueAtPoint, ValueId,
};
use crate::taint::compose::{CallObjectContinuity, HopQuality};
use crate::value_flow::{DurableCallSiteKey, DurableProcedureKey};

use super::{
    BoundTypestateSubject, TypestateComposeFunction, TypestateSubjectId, TypestateUncertainty,
};

#[derive(Clone)]
pub struct SubjectAssociation {
    call: DurableCallSiteKey,
    callee: DurableProcedureKey,
    context: OracleCallContext,
    from: PartialFlowPort,
    to: PartialFlowPort,
    point: ProgramPointId,
    phase: ObservationPhase,
    actual: ValueId,
    subject: TypestateSubjectId,
}

impl SubjectAssociation {
    pub(crate) fn identifies(
        &self,
        call: &DurableCallSiteKey,
        callee: &DurableProcedureKey,
        context: &OracleCallContext,
        subject: TypestateSubjectId,
        to: &PartialFlowPort,
    ) -> bool {
        self.call == *call
            && self.callee == *callee
            && self.context == *context
            && self.subject == subject
            && &self.to == to
            && matches!(&self.from, PartialFlowPort::CallArgument { .. })
            && self.phase == ObservationPhase::BeforeEffects
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SubjectUnprovenPort {
    call: DurableCallSiteKey,
    callee: DurableProcedureKey,
    context: OracleCallContext,
    from: PartialFlowPort,
    to: PartialFlowPort,
    point: ProgramPointId,
    phase: ObservationPhase,
    actual: ValueId,
    subject: TypestateSubjectId,
}

impl SubjectUnprovenPort {
    pub(crate) fn subject(&self) -> TypestateSubjectId {
        self.subject
    }
    pub(crate) fn source(&self) -> &PartialFlowPort {
        &self.from
    }
    pub(crate) fn site(&self) -> &DurableCallSiteKey {
        &self.call
    }
    pub(crate) fn continuation(&self) -> &PartialFlowPort {
        &self.to
    }
    pub(crate) fn remap_subject(&mut self, to: TypestateSubjectId) {
        self.subject = to;
    }
    pub(crate) fn same_observation(&self, associated: &SubjectAssociation) -> bool {
        self.point == associated.point
            && self.phase == associated.phase
            && self.actual != associated.actual
    }
    pub(crate) fn identifies(
        &self,
        call: &DurableCallSiteKey,
        callee: &DurableProcedureKey,
        context: &OracleCallContext,
        to: &PartialFlowPort,
    ) -> bool {
        self.call == *call
            && self.callee == *callee
            && self.context == *context
            && &self.to == to
            && matches!(&self.from, PartialFlowPort::CallArgument { .. })
            && self.phase == ObservationPhase::BeforeEffects
    }
}

#[derive(Clone)]
pub enum CallSubjectMapping {
    Associated(SubjectAssociation),
    SubjectUnproven(SubjectUnprovenPort),
    SeparationCandidate(SubjectUnprovenPort),
    Incomplete,
}

impl CallSubjectMapping {
    pub fn compose(&self) -> (TypestateComposeFunction, HopQuality) {
        match self {
            Self::Associated(_) => (TypestateComposeFunction::identity(), HopQuality::CERTAIN),
            Self::SubjectUnproven(port) => (
                TypestateComposeFunction::first_unproven(super::FirstUnprovenRelation::handoff(
                    port.clone(),
                ))
                .then(TypestateComposeFunction::incomplete(
                    TypestateUncertainty::IncompleteAnalysis,
                )),
                HopQuality::UNCERTAIN,
            ),
            Self::SeparationCandidate(_) | Self::Incomplete => (
                TypestateComposeFunction::incomplete(TypestateUncertainty::IncompleteAnalysis),
                HopQuality::UNCERTAIN,
            ),
        }
    }
}

/// An exact map preserves the globally bound tracked subject. The binding
/// plan has already associated that subject with its observed object. The
/// The points-to set or a formal-entry reborrow must identify it at this
/// boundary; the selected call must transport the corresponding port uniquely.
/// Any missing axis retains an incomplete label and quality.
pub struct CallSubjectMapSelection<'a> {
    pub call: &'a DurableCallSiteKey,
    pub callee: &'a DurableProcedureKey,
    pub context: &'a OracleCallContext,
    pub port_query: Option<&'a ValueAtPoint>,
    pub port_objects: Option<&'a PointsToResult>,
    pub continuity: CallObjectContinuity,
    pub tracked_formal: Option<(&'a DurableProcedureKey, &'a PartialFlowPort)>,
    /// Formal-entry only: exact selected Move binding plus exclusive origin
    /// from that formal. Root results still require a points-to match.
    pub exact_owned_origin: bool,
}

/// A formal-entry summary's object is the referent of its own formal. Rust's
/// whole-argument reborrow lowers to an Address assigned directly from that
/// formal (also after exact local-alias peeling). Its caller-dependent
/// points-to set is irrelevant to this one structural identity proof.
pub(crate) fn exact_formal_reborrow(
    query: &ValueAtPoint,
    from: &PartialFlowPort,
    tracked_formal: Option<(&DurableProcedureKey, &PartialFlowPort)>,
) -> bool {
    if !matches!(from, PartialFlowPort::CallArgument { .. }) {
        return false;
    }
    let Some((procedure_key, PartialFlowPort::Parameter { ordinal })) = tracked_formal else {
        return false;
    };
    let procedure = query.point().procedure();
    if procedure.durable_key() != *procedure_key
        || !procedure
            .semantics()
            .value(query.value().id())
            .is_some_and(|value| value.kind == SemanticValueKind::Address)
    {
        return false;
    }
    let mut formals = procedure.semantics().values().iter().filter(|value| {
        matches!(value.kind, SemanticValueKind::Parameter { ordinal: actual, .. } if actual == *ordinal)
    });
    let Some(formal) = formals.next() else {
        return false;
    };
    if formals.next().is_some() {
        return false;
    }
    let mut associations = procedure
        .semantics()
        .points()
        .iter()
        .flat_map(|point| &point.events)
        .filter(|event| {
            matches!(event.effect, SemanticEffect::Assignment { target, .. } if target == query.value().id())
        });
    let Some(association) = associations.next() else {
        return false;
    };
    if associations.next().is_some() {
        return false;
    }
    matches!(association.effect, SemanticEffect::Assignment { value, .. } if value == formal.id)
        && procedure
            .semantics()
            .evidence_row(association.evidence)
            .is_some_and(|evidence| {
                evidence
                    .proof
                    .establishes_complete_evidence(&evidence.completeness)
            })
}

pub fn call_subject_map(
    answer: &SemanticOutcome<DispatchResult>,
    bindings: &CallBindings,
    selection: CallSubjectMapSelection<'_>,
    subject: &BoundTypestateSubject,
    from: &PartialFlowPort,
    to: &PartialFlowPort,
) -> CallSubjectMapping {
    let CallSubjectMapSelection {
        call,
        callee,
        context,
        port_query,
        port_objects,
        continuity,
        tracked_formal,
        exact_owned_origin,
    } = selection;
    let incomplete = || CallSubjectMapping::Incomplete;
    let Some(dispatch) = answer.available_value() else {
        return incomplete();
    };
    let Some(port_query) = port_query else {
        return incomplete();
    };
    let call_row = bindings
        .call()
        .procedure()
        .semantics()
        .call_site(bindings.call().id())
        .expect("validated call binding names a call row");
    let projected_object =
        match crate::analyzer::semantic::workspace_oracle::heap::rehome_object_at_point(
            subject.object().clone(),
            port_query,
        ) {
            Ok(Some(object)) => object,
            Err(_) => return incomplete(),
            Ok(None) => return incomplete(),
        };
    let candidate_membership = port_objects.is_some_and(|points| {
        points
            .objects()
            .candidates()
            .iter()
            .any(|candidate| candidate.value() == &projected_object)
    });
    let point_match =
        if exact_owned_origin || exact_formal_reborrow(port_query, from, tracked_formal) {
            true
        } else {
            port_objects.is_some_and(|points| {
                let objects = points.objects();
                matches!(objects.candidates(), [object]
                if objects.coverage().is_exhaustive()
                    && object.is_proven_complete()
                    && object.value() == &projected_object)
            })
        };
    let boundary_point = match from {
        PartialFlowPort::CallReceiver { .. } | PartialFlowPort::CallArgument { .. } => {
            Some(call_row.point)
        }
        PartialFlowPort::NormalReturn | PartialFlowPort::IndexedNormalReturn { .. } => {
            call_row.normal_continuation.target()
        }
        PartialFlowPort::ExceptionalReturn => call_row.exceptional_continuation.target(),
        _ => None,
    };
    if !answer.is_complete()
        || dispatch.coverage() != CandidateCoverage::Exhaustive
        || !dispatch.boundaries().is_empty()
        || dispatch.candidates().len() != 1
        || dispatch.candidates()[0] != *bindings.candidate()
        || bindings.call().id() != call.1
        || bindings.call().procedure().durable_key() != call.0
        || bindings.callee().durable_key() != *callee
        || bindings.context() != context
        || context.was_truncated()
        || !continuity.is_exact()
        || bindings.coverage() != CandidateCoverage::Exhaustive
        || !subject.quality().is_definitive()
        || port_query.context() != context
        || port_query.phase() != ObservationPhase::BeforeEffects
        || boundary_point != Some(port_query.point().id())
        || !matches!(bindings.candidate().proof(), ProofStatus::Proven)
        || !matches!(
            bindings.candidate().completeness(),
            EvidenceCompleteness::Complete
        )
    {
        return incomplete();
    }
    let matches = bindings.bindings().iter().filter(|binding| match binding {
        CallBinding::Receiver { relation, actual, formal } =>
            relation.record().is_proven_complete()
                && port_query.value() == actual
                && matches!(from, PartialFlowPort::CallReceiver { call: id } if *id == call.1)
                && matches!(to, PartialFlowPort::Receiver)
                && formal.kind() == ProcedurePortKind::Receiver,
        CallBinding::ArgumentGroup(group) =>
            group.coverage().is_exhaustive()
                && group.closure_relation().record().is_proven_complete()
                && group.mappings().iter().filter(|mapping| {
                    mapping.is_proven_complete()
                        && mapping.value().preserves_reference_identity()
                        && port_query.value() == mapping.value().actual().value()
                        && matches!(from, PartialFlowPort::CallArgument { call: id, ordinal }
                            if *id == call.1 && *ordinal == mapping.value().source_index())
                        && matches!(to, PartialFlowPort::Parameter { ordinal }
                            if mapping.value().formal().kind() == ProcedurePortKind::Parameter { ordinal: *ordinal })
                }).count() == 1,
        CallBinding::NormalReturn { relation, formal, result } =>
            relation.record().is_proven_complete()
                && port_query.value() == result
                && matches!(from, PartialFlowPort::NormalReturn | PartialFlowPort::IndexedNormalReturn { .. })
                && match (from, formal.kind()) {
                    (PartialFlowPort::NormalReturn, ProcedurePortKind::NormalReturn) =>
                        matches!(to, PartialFlowPort::CallResult { call: id, ordinal: None } if *id == call.1),
                    (
                        PartialFlowPort::IndexedNormalReturn { ordinal: actual },
                        ProcedurePortKind::IndexedNormalReturn { ordinal: formal },
                    ) => *actual == formal
                        && matches!(to, PartialFlowPort::CallResult { call: id, ordinal: Some(result) }
                            if *id == call.1 && *result == formal),
                    _ => false,
                },
        CallBinding::ExceptionalReturn { relation, formal, result } =>
            relation.record().is_proven_complete()
                && port_query.value() == result
                && matches!(from, PartialFlowPort::ExceptionalReturn)
                && matches!(to, PartialFlowPort::CallThrown { call: id } if *id == call.1)
                && formal.kind() == ProcedurePortKind::ExceptionalReturn,
        CallBinding::ImplicitArgument { .. } => false,
    }).count();
    if matches != 1 {
        return incomplete();
    }
    debug_assert_eq!(port_query.phase(), ObservationPhase::BeforeEffects);
    debug_assert!(
        !matches!(
            from,
            PartialFlowPort::CallArgument { .. } | PartialFlowPort::CallReceiver { .. }
        ) || port_query.point().id() == call_row.point
    );
    if point_match {
        CallSubjectMapping::Associated(SubjectAssociation {
            call: call.clone(),
            callee: callee.clone(),
            context: context.clone(),
            from: from.clone(),
            to: to.clone(),
            point: port_query.point().id(),
            phase: port_query.phase(),
            actual: port_query.value().id(),
            subject: subject.id(),
        })
    } else {
        let port = SubjectUnprovenPort {
            call: call.clone(),
            callee: callee.clone(),
            context: context.clone(),
            from: from.clone(),
            to: to.clone(),
            point: port_query.point().id(),
            phase: port_query.phase(),
            actual: port_query.value().id(),
            subject: subject.id(),
        };
        if candidate_membership {
            CallSubjectMapping::SubjectUnproven(port)
        } else {
            CallSubjectMapping::SeparationCandidate(port)
        }
    }
}
