use crate::analyzer::resolution::{
    AnswerMap, ArgumentFormalBinding, CallApplicabilityAdapter, CallTypeSubstitution,
    CandidateAssessment, FactEvaluation, LoweredCallApplicabilityObligation,
    LoweredCallableSignatureProperty, MappingAssessment, ResolutionCompletion, SemanticId,
    StateMap, TypeInCallPosition,
};
use crate::analyzer::store::Result;
use brokk_bifrost_core::analyzer::structural::callable::CallableRejectionReason;

pub(super) static GO_CALL_APPLICABILITY_ADAPTER: GoCallApplicabilityAdapter =
    GoCallApplicabilityAdapter;

pub(crate) struct GoCallApplicabilityAdapter;

impl CallApplicabilityAdapter for GoCallApplicabilityAdapter {
    fn type_in_call_position(&self) -> TypeInCallPosition {
        TypeInCallPosition::Conversion
    }

    fn has_receiver_binding_obligation(&self) -> bool {
        true
    }

    fn receiver_binding_completion(
        &self,
        evaluation: &mut FactEvaluation<'_, '_>,
        candidate: SemanticId,
        call: &LoweredCallApplicabilityObligation,
        signature: &LoweredCallableSignatureProperty,
    ) -> Result<Option<ResolutionCompletion>> {
        evaluation.go_receiver_binding_completion(candidate, call, signature)
    }

    fn map_arguments(
        &self,
        call: &LoweredCallApplicabilityObligation,
        signature: &LoweredCallableSignatureProperty,
    ) -> MappingAssessment {
        crate::analyzer::resolution::map_call_shape(
            call,
            signature,
            false,
            false,
            CallableRejectionReason::ArityBelowRequired,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn assess_candidate(
        &self,
        evaluation: &mut FactEvaluation<'_, '_>,
        candidate: SemanticId,
        call: &LoweredCallApplicabilityObligation,
        signature: &LoweredCallableSignatureProperty,
        call_inventory_complete: bool,
        previous_answers: &AnswerMap,
        previous_states: &StateMap,
        _completion: &mut ResolutionCompletion,
    ) -> Result<Option<CandidateAssessment>> {
        let Some(signature_types_complete) =
            evaluation.go_signature_type_inventory_complete(signature)?
        else {
            return Ok(None);
        };
        if !call_inventory_complete
            || !signature_types_complete
            || call.explicit_type_argument_count() != 0
            || signature.type_parameter_count() != 0
        {
            return Ok(Some(CandidateAssessment::unknown(candidate)));
        }
        let Some(substitutions) = evaluation.go_receiver_type_substitutions(
            candidate,
            call.receiver_slot(),
            previous_answers,
            previous_states,
        )?
        else {
            return Ok(None);
        };
        let Some(substitutions) = substitutions else {
            return Ok(Some(CandidateAssessment::unknown(candidate)));
        };
        let mapping = self.map_arguments(call, signature);
        match mapping {
            MappingAssessment::Mapped {
                bindings,
                used_vararg,
                ..
            } => evaluation.assess_mapped_go_candidate(
                candidate,
                call,
                signature,
                &bindings,
                used_vararg,
                &substitutions,
                previous_states,
            ),
            MappingAssessment::Inapplicable(reason) => {
                Ok(Some(CandidateAssessment::inapplicable(candidate, reason)))
            }
            MappingAssessment::Unknown => Ok(Some(CandidateAssessment::unknown(candidate))),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn assess_mapped_candidate(
        &self,
        evaluation: &mut FactEvaluation<'_, '_>,
        candidate: SemanticId,
        call: &LoweredCallApplicabilityObligation,
        signature: &LoweredCallableSignatureProperty,
        bindings: &[ArgumentFormalBinding],
        used_vararg: bool,
        type_substitution: &CallTypeSubstitution,
        previous_answers: &AnswerMap,
        previous_states: &StateMap,
        completion: &mut ResolutionCompletion,
    ) -> Result<Option<CandidateAssessment>> {
        evaluation.assess_mapped_exact_candidate(
            candidate,
            call,
            signature,
            bindings,
            used_vararg,
            type_substitution,
            previous_answers,
            previous_states,
            completion,
        )
    }
}
