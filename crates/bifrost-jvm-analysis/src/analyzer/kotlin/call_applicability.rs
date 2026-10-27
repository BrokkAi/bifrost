use brokk_bifrost_analysis::analyzer::resolution::typed_fact_lowering::LoweredCallableParameterApplicability;

use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::AnswerMap;

use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::call_applicability::CallApplicabilityAdapter;

use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::call_applicability::CandidateAssessment;

use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::call_applicability::ConversionEvidence;

use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::FactEvaluation;

use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::call_applicability::ImplicitReceiverLookup;

use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::call_applicability::ImplicitReceiverScopeKind;

use brokk_bifrost_analysis::analyzer::resolution::typed_fact_lowering::LoweredCallApplicabilityObligation;

use brokk_bifrost_analysis::analyzer::resolution::typed_fact_lowering::LoweredCallableSignatureProperty;

use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::call_applicability::MappingAssessment;

use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::call_applicability::PartialOrder;

use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionCompletion;

use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionSlotValue;

use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionTypeRef;

use brokk_bifrost_analysis::analyzer::resolution::model::SemanticId;

use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::StateMap;

use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::call_applicability::TypeInCallPosition;

use brokk_bifrost_analysis::analyzer::resolution::model::TypedFrontierState;

use brokk_bifrost_analysis::analyzer::store::Result;

use brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeKind;
use brokk_bifrost_core::analyzer::structural::callable::CallableRejectionReason;
use brokk_bifrost_core::hash::HashMap;

pub(crate) static KOTLIN_CALL_APPLICABILITY_ADAPTER: KotlinCallApplicabilityAdapter =
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
            [ResolutionSlotValue::TypeObject(ty, _)] => Some(*ty),
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

    fn function_like_candidates_precede_values(&self) -> bool {
        true
    }

    fn intrinsic_function_arity(&self, spelling: &str) -> Option<u32> {
        self.nominal_function_type_prefixes()
            .iter()
            .find_map(|prefix| spelling.strip_prefix(prefix)?.parse().ok())
    }

    fn extensions_can_supply_value_application(&self) -> bool {
        true
    }

    fn nominal_function_type_prefixes(&self) -> &'static [&'static str] {
        &["kotlin.Function", "kotlin.reflect.KFunction"]
    }

    fn intrinsic_function_applicability(
        &self,
        arity: u32,
    ) -> Option<Vec<LoweredCallableParameterApplicability>> {
        Some(
            (0..arity)
                .map(|ordinal| {
                    LoweredCallableParameterApplicability::new(ordinal, 0, None, false, true)
                })
                .collect(),
        )
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
        brokk_bifrost_analysis::analyzer::resolution::fact_resolution::call_applicability::map_call_shape(
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
        brokk_bifrost_analysis::analyzer::resolution::fact_resolution::call_applicability::unresolved_argument_conversion_completion(
            assessment, call, signature, states,
        )
    }

    fn candidate_formal_is_subtype(
        &self,
        evaluation: &mut FactEvaluation<'_, '_>,
        subtype: SemanticId,
        supertype: SemanticId,
        states: &StateMap,
    ) -> Result<Option<bool>> {
        evaluation.kotlin_type_is_subtype(subtype, supertype, states)
    }

    fn compare_conversion(
        &self,
        left: ConversionEvidence,
        right: ConversionEvidence,
        subtype_relations: &HashMap<(SemanticId, SemanticId), bool>,
    ) -> PartialOrder {
        brokk_bifrost_analysis::analyzer::resolution::fact_resolution::call_applicability::compare_formal_types(
            left, right, subtype_relations,
        )
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
