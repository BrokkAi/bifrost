use crate::analyzer::resolution::{
    AnswerMap, CallApplicabilityAdapter, CallCandidateApplicability, CandidateAssessment,
    ConversionEvidence, FactEvaluation, InternedFactRow, LoweredCallApplicabilityObligation,
    LoweredCallableSignatureProperty, MappingAssessment, PartialOrder, ResolutionAnswer,
    ResolutionCompletion, SelectedTypedRow, SemanticId, StateMap,
};
use crate::analyzer::store::Result;
use crate::hash::HashMap;
use brokk_bifrost_core::analyzer::structural::callable::CallableRejectionReason;

pub(super) static JAVA_CALL_APPLICABILITY_ADAPTER: JavaCallApplicabilityAdapter =
    JavaCallApplicabilityAdapter;

pub(crate) struct JavaCallApplicabilityAdapter;

impl CallApplicabilityAdapter for JavaCallApplicabilityAdapter {
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
        _previous_answers: &AnswerMap,
        previous_states: &StateMap,
        completion: &mut ResolutionCompletion,
    ) -> Result<Option<CandidateAssessment>> {
        if signature.completion() != &ResolutionCompletion::Complete
            || call.explicit_type_argument_count() != 0
            || signature.type_parameter_count() != 0
            || (!call_inventory_complete && call.arguments().is_empty())
        {
            return Ok(Some(CandidateAssessment::unknown(candidate)));
        }
        match self.map_arguments(call, signature) {
            MappingAssessment::Mapped {
                bindings,
                used_vararg,
                ..
            } => evaluation.assess_legacy_call_candidate(
                candidate,
                call,
                signature,
                &bindings,
                used_vararg,
                previous_states,
                completion,
            ),
            MappingAssessment::Inapplicable(reason) => {
                Ok(Some(CandidateAssessment::inapplicable(candidate, reason)))
            }
            MappingAssessment::Unknown => Ok(Some(CandidateAssessment::unknown(candidate))),
        }
    }

    fn compare_conversion(
        &self,
        left: ConversionEvidence,
        right: ConversionEvidence,
        _subtype_relations: &HashMap<(SemanticId, SemanticId), bool>,
    ) -> PartialOrder {
        if left == right {
            PartialOrder::Equal
        } else {
            PartialOrder::Incomparable
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn prefilter_candidates(
        &self,
        evaluation: &mut FactEvaluation<'_, '_>,
        answer: ResolutionAnswer,
        obligation: &LoweredCallApplicabilityObligation,
        signatures: &HashMap<
            SemanticId,
            InternedFactRow<SelectedTypedRow<LoweredCallableSignatureProperty>>,
        >,
        previous_states: &StateMap,
    ) -> Result<Option<(ResolutionAnswer, Option<SemanticId>)>> {
        let Some(implicit_receiver_gap_reason) =
            evaluation.find_implicit_receiver_gap_reason(&answer, obligation.callee_reference())?
        else {
            return Ok(None);
        };
        let argument_receiver_gap_reason = if let Some(reason) = implicit_receiver_gap_reason {
            match evaluation.call_targets_prove_static_method_access(answer.targets())? {
                Some(true) => Some(reason),
                Some(false) | None => None,
            }
        } else {
            None
        };
        let Some(answer) =
            evaluation.filter_java_inherited_methods(answer, signatures, previous_states)?
        else {
            return Ok(None);
        };
        let Some(answer) = evaluation.filter_java_boxing_after_strict_invocation(
            answer,
            obligation,
            signatures,
            previous_states,
            argument_receiver_gap_reason,
        )?
        else {
            return Ok(None);
        };
        let Some(answer) = evaluation.filter_java_primitive_less_specific(
            answer,
            obligation,
            signatures,
            previous_states,
            argument_receiver_gap_reason,
        )?
        else {
            return Ok(None);
        };
        let Some(answer) = evaluation.filter_java_reference_inapplicable(
            answer,
            obligation,
            signatures,
            previous_states,
            argument_receiver_gap_reason,
        )?
        else {
            return Ok(None);
        };
        let implicit_receiver_gap_reason = if let Some(reason) = implicit_receiver_gap_reason {
            match evaluation.call_targets_prove_static_method_access(answer.targets())? {
                Some(true) => Some(reason),
                Some(false) => None,
                None => return Ok(None),
            }
        } else {
            None
        };
        Ok(Some((answer, implicit_receiver_gap_reason)))
    }

    fn classify_primitive_pairs(
        &self,
        evaluation: &mut FactEvaluation<'_, '_>,
        pairs: &[(SemanticId, SemanticId)],
    ) -> Result<Option<CallCandidateApplicability>> {
        evaluation.classify_java_primitive_pairs(pairs)
    }
}
