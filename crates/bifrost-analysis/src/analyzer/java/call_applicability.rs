use crate::analyzer::resolution::{
    AnswerMap, CallApplicabilityAdapter, CallTypeSubstitution, CandidateAssessment,
    ConversionEvidence, FactEvaluation, InternedFactRow, IntrinsicCallType,
    LoweredCallApplicabilityObligation, LoweredCallableSignatureProperty, MappingAssessment,
    PartialOrder, ResolutionAnswer, ResolutionCompletion, SelectedTypedRow, SemanticId, StateMap,
};
use crate::analyzer::store::Result;
use crate::hash::HashMap;
use brokk_bifrost_core::analyzer::resolution_facts::IntrinsicTypeKind;
use brokk_bifrost_core::analyzer::structural::callable::CallableRejectionReason;

pub(super) static JAVA_CALL_APPLICABILITY_ADAPTER: JavaCallApplicabilityAdapter =
    JavaCallApplicabilityAdapter;

pub(crate) struct JavaCallApplicabilityAdapter;

impl CallApplicabilityAdapter for JavaCallApplicabilityAdapter {
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
        use crate::analyzer::usages::call_conversion::JavaPrimitive;
        Some(match crate::analyzer::java::primitive_for_name(spelling)? {
            JavaPrimitive::Boolean => IntrinsicCallType::Boolean,
            JavaPrimitive::Byte => IntrinsicCallType::Byte,
            JavaPrimitive::Short => IntrinsicCallType::Short,
            JavaPrimitive::Char => IntrinsicCallType::Char,
            JavaPrimitive::Int => IntrinsicCallType::Int,
            JavaPrimitive::Long => IntrinsicCallType::Long,
            JavaPrimitive::Float => IntrinsicCallType::Float,
            JavaPrimitive::Double => IntrinsicCallType::Double,
        })
    }

    fn intrinsic_call_type_converts(
        &self,
        source: IntrinsicCallType,
        target: IntrinsicCallType,
    ) -> bool {
        use IntrinsicCallType::{Boolean, Byte, Char, Double, Float, Int, Long, Short, String};
        match (source, target) {
            (String, String) | (Boolean, Boolean) => true,
            (String, _) | (_, String) | (Boolean, _) | (_, Boolean) => false,
            (Byte, Byte | Short | Int | Long | Float | Double)
            | (Short, Short | Int | Long | Float | Double)
            | (Char, Char | Int | Long | Float | Double)
            | (Int, Int | Long | Float | Double)
            | (Long, Long | Float | Double)
            | (Float, Float | Double)
            | (Double, Double) => crate::analyzer::java::primitive_converts(
                java_primitive(source),
                java_primitive(target),
            ),
            _ => false,
        }
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
                &CallTypeSubstitution::empty(),
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

fn java_primitive(
    value: IntrinsicCallType,
) -> crate::analyzer::usages::call_conversion::JavaPrimitive {
    use crate::analyzer::usages::call_conversion::JavaPrimitive;
    match value {
        IntrinsicCallType::Boolean => JavaPrimitive::Boolean,
        IntrinsicCallType::Byte => JavaPrimitive::Byte,
        IntrinsicCallType::Short => JavaPrimitive::Short,
        IntrinsicCallType::Char => JavaPrimitive::Char,
        IntrinsicCallType::Int => JavaPrimitive::Int,
        IntrinsicCallType::Long => JavaPrimitive::Long,
        IntrinsicCallType::Float => JavaPrimitive::Float,
        IntrinsicCallType::Double => JavaPrimitive::Double,
        IntrinsicCallType::String => unreachable!("String is not a Java primitive"),
    }
}
