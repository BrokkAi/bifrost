use crate::analyzer::resolution::{
    AnswerMap, CallApplicabilityAdapter, CandidateAssessment, ConversionEvidence, ConversionKind,
    FactEvaluation, ImplicitReceiverLookup, ImplicitReceiverScopeKind,
    LoweredCallApplicabilityObligation, LoweredCallableSignatureProperty, MappingAssessment,
    PartialOrder, ResolutionCompletion, ResolutionSlotValue, ResolutionTypeRef, SemanticId,
    StateMap, TypeInCallPosition, TypedFrontierState,
};
use crate::analyzer::store::Result;
use crate::hash::HashMap;
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeKind;
use brokk_bifrost_core::analyzer::structural::callable::CallableRejectionReason;

pub(super) static KOTLIN_CALL_APPLICABILITY_ADAPTER: KotlinCallApplicabilityAdapter =
    KotlinCallApplicabilityAdapter;

pub(crate) struct KotlinCallApplicabilityAdapter;

impl CallApplicabilityAdapter for KotlinCallApplicabilityAdapter {
    fn implicit_receiver_lookup(&self) -> Option<ImplicitReceiverLookup> {
        Some(ImplicitReceiverLookup::FirstApplicable)
    }

    fn implicit_receiver_scope_kind(
        &self,
        kind: ResolutionScopeKind,
    ) -> Option<ImplicitReceiverScopeKind> {
        match kind {
            ResolutionScopeKind::TypeBody => Some(ImplicitReceiverScopeKind::Dispatch),
            ResolutionScopeKind::Executable => Some(ImplicitReceiverScopeKind::Extension),
            _ => None,
        }
    }

    fn has_independent_receiver_bounds(&self) -> bool {
        true
    }

    fn receiver_runtime_type(&self, state: &TypedFrontierState) -> Option<ResolutionTypeRef> {
        match state.possible_values() {
            [ResolutionSlotValue::Runtime { ty, .. }] => Some(*ty),
            _ => None,
        }
    }

    fn receiver_formal_type(&self, state: &TypedFrontierState) -> Option<ResolutionTypeRef> {
        match state.possible_values() {
            [ResolutionSlotValue::TypeObject(ty)] => Some(*ty),
            _ => None,
        }
    }

    fn receiver_is_subtype(
        &self,
        evaluation: &mut FactEvaluation<'_, '_>,
        subtype: SemanticId,
        supertype: SemanticId,
        states: &StateMap,
    ) -> Result<Option<bool>> {
        evaluation.kotlin_type_is_subtype(subtype, supertype, states)
    }

    fn result_application_member_names(&self) -> &'static [&'static str] {
        &["invoke"]
    }

    fn declared_result_application_member_names(&self) -> &'static [&'static str] {
        // Selected declaration facts do not prove operator eligibility yet.
        // FunctionN intrinsic application has its own structured signature.
        &[]
    }

    fn has_scoped_receiver_extensions(&self) -> bool {
        true
    }

    fn retains_extensions_without_receiver_evidence(&self, state: &TypedFrontierState) -> bool {
        state.possible_values().is_empty()
    }

    fn scoped_extensions_follow_member_selection(&self) -> bool {
        true
    }

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

    fn unresolved_conversion_completion(
        &self,
        assessment: &CandidateAssessment,
        call: &LoweredCallApplicabilityObligation,
        signature: &LoweredCallableSignatureProperty,
        states: &StateMap,
    ) -> Option<ResolutionCompletion> {
        crate::analyzer::resolution::unresolved_argument_conversion_completion(
            assessment, call, signature, states,
        )
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
