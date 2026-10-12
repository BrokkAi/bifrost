use crate::analyzer::resolution::{
    AnswerMap, CallApplicabilityAdapter, CandidateAssessment, ConversionEvidence, ConversionKind,
    FactEvaluation, LoweredCallApplicabilityObligation, LoweredCallableSignatureProperty,
    MappingAssessment, PartialOrder, ResolutionCompletion, SemanticId, StateMap,
    TypeInCallPosition,
};
use crate::analyzer::store::Result;
use crate::hash::HashMap;
use brokk_bifrost_core::analyzer::structural::callable::CallableRejectionReason;

pub(super) static KOTLIN_CALL_APPLICABILITY_ADAPTER: KotlinCallApplicabilityAdapter =
    KotlinCallApplicabilityAdapter;

pub(crate) struct KotlinCallApplicabilityAdapter;

impl CallApplicabilityAdapter for KotlinCallApplicabilityAdapter {
    fn type_in_call_position(&self) -> TypeInCallPosition {
        TypeInCallPosition::Constructors
    }

    fn map_arguments(
        &self,
        call: &LoweredCallApplicabilityObligation,
        signature: &LoweredCallableSignatureProperty,
    ) -> MappingAssessment {
        crate::analyzer::resolution::map_call_shape(
            call,
            signature,
            true,
            true,
            CallableRejectionReason::MissingRequiredArgument,
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
        if !call_inventory_complete
            || signature.completion() != &ResolutionCompletion::Complete
            || call.explicit_type_argument_count() != 0
            || signature.type_parameter_count() != 0
        {
            return Ok(Some(CandidateAssessment::unknown(candidate)));
        }
        match self.map_arguments(call, signature) {
            MappingAssessment::Mapped {
                bindings,
                used_defaults,
                used_vararg,
                ..
            } => {
                let Some(mut assessment) = evaluation.assess_kotlin_call_candidate(
                    candidate,
                    call,
                    signature,
                    &bindings,
                    used_vararg,
                    previous_states,
                    completion,
                )?
                else {
                    return Ok(None);
                };
                assessment.used_defaults = used_defaults;
                Ok(Some(assessment))
            }
            MappingAssessment::Inapplicable(reason) => {
                let Some(()) = evaluation.record_kotlin_candidate_owner(
                    candidate,
                    call,
                    signature,
                    previous_states,
                    completion,
                )?
                else {
                    return Ok(None);
                };
                Ok(Some(CandidateAssessment::inapplicable(candidate, reason)))
            }
            MappingAssessment::Unknown => Ok(Some(CandidateAssessment::unknown(candidate))),
        }
    }

    fn compare_conversion(
        &self,
        left: ConversionEvidence,
        right: ConversionEvidence,
        subtype_relations: &HashMap<(SemanticId, SemanticId), bool>,
    ) -> PartialOrder {
        if left.kind == ConversionKind::Unknown || right.kind == ConversionKind::Unknown {
            return PartialOrder::Unknown;
        }
        let (Some(left_source), Some(right_source), Some(left_target), Some(right_target)) = (
            left.source_type,
            right.source_type,
            left.target_type,
            right.target_type,
        ) else {
            return PartialOrder::Unknown;
        };
        if left_source != right_source {
            return PartialOrder::Incomparable;
        }
        if left_target == right_target {
            return PartialOrder::Equal;
        }
        if subtype_relations.contains_key(&(left_target, right_target)) {
            PartialOrder::Better
        } else if subtype_relations.contains_key(&(right_target, left_target)) {
            PartialOrder::Worse
        } else {
            PartialOrder::Incomparable
        }
    }

    fn compare_specificity(
        &self,
        left: &CandidateAssessment,
        right: &CandidateAssessment,
    ) -> PartialOrder {
        match (left.used_vararg, right.used_vararg) {
            (false, true) => PartialOrder::Better,
            (true, false) => PartialOrder::Worse,
            _ => match left.used_defaults.cmp(&right.used_defaults) {
                std::cmp::Ordering::Less => PartialOrder::Better,
                std::cmp::Ordering::Equal => PartialOrder::Equal,
                std::cmp::Ordering::Greater => PartialOrder::Worse,
            },
        }
    }
}
