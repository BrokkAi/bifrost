use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::call_applicability::compare_formal_types;
use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionSlotValue;

use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::AnswerMap;

use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::call_applicability::CallApplicabilityAdapter;

use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::CallTypeSubstitution;

use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::call_applicability::CandidateAssessment;

use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::call_applicability::ConversionEvidence;

use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::FactEvaluation;

use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::call_applicability::ImplicitReceiverLookup;

use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::call_applicability::ImplicitReceiverScopeKind;

use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::InternedFactRow;

use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::call_applicability::IntrinsicCallType;

use brokk_bifrost_analysis::analyzer::resolution::typed_fact_lowering::LoweredCallApplicabilityObligation;

use brokk_bifrost_analysis::analyzer::resolution::typed_fact_lowering::LoweredCallableSignatureProperty;

use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::call_applicability::MappingAssessment;

use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::call_applicability::PartialOrder;

use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionAnswer;

use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionCompletion;

use brokk_bifrost_analysis::analyzer::resolution::fact_source::SelectedTypedRow;

use brokk_bifrost_analysis::analyzer::resolution::model::SemanticId;

use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::StateMap;

use brokk_bifrost_analysis::analyzer::store::Result;

use brokk_bifrost_core::analyzer::resolution_facts::IntrinsicTypeKind;
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeKind;
use brokk_bifrost_core::analyzer::structural::callable::ApplicabilityVerdict;
use brokk_bifrost_core::analyzer::structural::callable::CallableRejectionReason;
use brokk_bifrost_core::analyzer::structural::callable::FailingArgument;
use brokk_bifrost_core::analyzer::structural::callable::InvocationPhase;
use brokk_bifrost_core::hash::HashMap;

pub(crate) static JAVA_CALL_APPLICABILITY_ADAPTER: JavaCallApplicabilityAdapter =
    JavaCallApplicabilityAdapter;

pub(crate) struct JavaCallApplicabilityAdapter;

impl CallApplicabilityAdapter for JavaCallApplicabilityAdapter {
    fn implicit_receiver_lookup(&self) -> Option<ImplicitReceiverLookup> {
        Some(ImplicitReceiverLookup::FirstMemberName)
    }

    fn implicit_receiver_scope_kind(
        &self,
        kind: ResolutionScopeKind,
    ) -> Option<ImplicitReceiverScopeKind> {
        match kind {
            ResolutionScopeKind::TypeBody => Some(ImplicitReceiverScopeKind::Dispatch),
            _ => None,
        }
    }

    fn has_intrinsic_call_type_table(&self) -> bool {
        true
    }

    fn intrinsic_call_type(
        &self,
        kind: IntrinsicTypeKind,
        spelling: &str,
    ) -> Option<IntrinsicCallType> {
        if kind == IntrinsicTypeKind::LanguageBuiltin && spelling == "java.lang.String" {
            return Some(IntrinsicCallType::String);
        }
        if kind != IntrinsicTypeKind::Primitive {
            return None;
        }

        use brokk_bifrost_jvm::java::primitives::JavaPrimitive;
        Some(
            match brokk_bifrost_jvm::java::primitives::primitive_for_name(spelling)? {
                JavaPrimitive::Boolean => IntrinsicCallType::Boolean,
                JavaPrimitive::Byte => IntrinsicCallType::Byte,
                JavaPrimitive::Short => IntrinsicCallType::Short,
                JavaPrimitive::Char => IntrinsicCallType::Char,
                JavaPrimitive::Int => IntrinsicCallType::Int,
                JavaPrimitive::Long => IntrinsicCallType::Long,
                JavaPrimitive::Float => IntrinsicCallType::Float,
                JavaPrimitive::Double => IntrinsicCallType::Double,
            },
        )
    }

    fn intrinsic_call_type_converts(
        &self,
        source: IntrinsicCallType,
        target: IntrinsicCallType,
    ) -> bool {
        crate::analyzer::jvm::intrinsic_call_type_converts(source, target)
    }

    // Java producer slots carry the repeated component type. One actual may
    // instead supply the whole array under fixed-arity invocation (JLS 15.12.2).
    #[allow(clippy::too_many_arguments)]
    fn repeated_parameter_type(
        &self,
        evaluation: &mut FactEvaluation<'_, '_>,
        actual_slot: SemanticId,
        formal_slot: SemanticId,
        actual: brokk_bifrost_analysis::analyzer::resolution::model::ResolutionTypeRef,
        component: brokk_bifrost_analysis::analyzer::resolution::model::ResolutionTypeRef,
        repeated_actual_count: usize,
        states: &StateMap,
    ) -> Result<Option<brokk_bifrost_analysis::analyzer::resolution::model::ResolutionTypeRef>>
    {
        if repeated_actual_count == 1 {
            evaluation.jvm_repeated_sequence_parameter_type(
                actual_slot,
                formal_slot,
                actual,
                component,
                states,
            )
        } else {
            Ok(Some(component))
        }
    }

    fn map_arguments(
        &self,
        call: &LoweredCallApplicabilityObligation,
        signature: &LoweredCallableSignatureProperty,
    ) -> MappingAssessment {
        brokk_bifrost_analysis::analyzer::resolution::fact_resolution::call_applicability::map_call_shape(
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
        completion: &mut ResolutionCompletion,
    ) -> Result<Option<CandidateAssessment>> {
        if signature.completion() != &ResolutionCompletion::Complete
            || (call.explicit_type_argument_count() != 0
                && (signature.type_parameter_count() != 0
                    || !evaluation.callable_type_parameter_count_is_known(signature.definition())))
            || (!call_inventory_complete && call.arguments().is_empty())
        {
            return Ok(Some(CandidateAssessment::unknown(candidate)));
        }
        match self.map_arguments(call, signature) {
            MappingAssessment::Mapped {
                bindings,
                used_vararg,
                ..
            } => {
                let Some(mut assessment) = evaluation.assess_mapped_exact_candidate(
                    candidate,
                    call,
                    signature,
                    &bindings,
                    used_vararg,
                    &CallTypeSubstitution::empty(),
                    previous_answers,
                    previous_states,
                    completion,
                )?
                else {
                    return Ok(None);
                };
                if let Some(parameter) = signature.parameters().last().filter(|p| p.repeated()) {
                    // The source signature publishes the repeated component. A
                    // proved array actual replaces that component in conversion
                    // evidence, admitting the method in the fixed-arity phase.
                    let fixed_arity = bindings.len() == signature.parameters().len()
                        && assessment.conversions.last().is_some_and(|conversion| {
                            let Some(state) = previous_states.get(&parameter.slot()) else {
                                return false;
                            };
                            matches!(state.possible_values(), [ResolutionSlotValue::Runtime { ty, .. }]
                                if state.completion() == &ResolutionCompletion::Complete
                                    && conversion.source_type == conversion.target_type
                                    && conversion.target_type.is_some_and(|target| target != ty.identity()))
                        });
                    assessment.used_vararg = !fixed_arity;
                }
                Ok(Some(assessment))
            }
            MappingAssessment::Inapplicable(reason) => {
                Ok(Some(CandidateAssessment::inapplicable(candidate, reason)))
            }
            MappingAssessment::Unknown => Ok(Some(CandidateAssessment::unknown(candidate))),
        }
    }

    fn proves_reference_conversion(
        &self,
        evaluation: &mut FactEvaluation<'_, '_>,
        operand_slots: [SemanticId; 2],
        source: brokk_bifrost_analysis::analyzer::resolution::model::ResolutionTypeRef,
        target: brokk_bifrost_analysis::analyzer::resolution::model::ResolutionTypeRef,
        states: &StateMap,
    ) -> Result<Option<bool>> {
        evaluation.java_strict_reference_conversion(operand_slots, source, target, states)
    }

    fn candidate_formal_is_subtype(
        &self,
        evaluation: &mut FactEvaluation<'_, '_>,
        subtype: SemanticId,
        supertype: SemanticId,
        states: &StateMap,
    ) -> Result<Option<bool>> {
        evaluation.java_reference_type_is_subtype(subtype, supertype, states)
    }

    fn invocation_phase(&self, candidate: &CandidateAssessment) -> Option<InvocationPhase> {
        // The source assessor currently proves strict conversions only. Loose
        // boxing/unboxing candidates remain Unknown and bypass phase filtering.
        Some(if candidate.used_vararg {
            InvocationPhase::VariableArity
        } else {
            InvocationPhase::Strict
        })
    }

    fn reports_less_specific_candidates(&self) -> bool {
        true
    }

    /// The deciding phase and first failing argument of one assessed
    /// candidate. An applicable candidate carries the phase the shared
    /// selection compares. A primitive mismatch failed the strict test at one
    /// argument. An arity rejection fails potential applicability (JLS
    /// 15.12.2.1) before any phase and records neither.
    fn invocation_evidence(
        &self,
        evaluation: &mut FactEvaluation<'_, '_>,
        assessment: &CandidateAssessment,
    ) -> Result<Option<(Option<InvocationPhase>, Option<FailingArgument>)>> {
        Ok(Some(match (assessment.verdict, assessment.reason) {
            (ApplicabilityVerdict::Applicable, _) => (self.invocation_phase(assessment), None),
            (
                ApplicabilityVerdict::Inapplicable,
                Some(CallableRejectionReason::PrimitiveTypeMismatch),
            ) => {
                let Some(argument) =
                    evaluation.java_primitive_mismatch_argument(&assessment.conversions)?
                else {
                    return Ok(None);
                };
                (Some(InvocationPhase::Strict), argument)
            }
            _ => (None, None),
        }))
    }

    fn compare_conversion(
        &self,
        left: ConversionEvidence,
        right: ConversionEvidence,
        subtype_relations: &HashMap<(SemanticId, SemanticId), bool>,
    ) -> PartialOrder {
        match compare_formal_types(left, right, subtype_relations) {
            PartialOrder::Unknown => PartialOrder::Incomparable,
            order => order,
        }
    }

    fn refine_member_inheritance(
        &self,
        evaluation: &mut FactEvaluation<'_, '_>,
        answer: ResolutionAnswer,
        reference: SemanticId,
        signatures: &HashMap<
            SemanticId,
            InternedFactRow<SelectedTypedRow<LoweredCallableSignatureProperty>>,
        >,
        previous_states: &StateMap,
    ) -> Result<Option<ResolutionAnswer>> {
        evaluation.filter_java_inherited_methods(answer, reference, signatures, previous_states)
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
        let Some(answer) = self.refine_member_inheritance(
            evaluation,
            answer,
            obligation.callee_reference(),
            signatures,
            previous_states,
        )?
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
}
