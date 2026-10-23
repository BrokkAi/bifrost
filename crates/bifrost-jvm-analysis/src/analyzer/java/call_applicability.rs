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
use brokk_bifrost_core::analyzer::structural::callable::CallableRejectionReason;
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
        use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::call_applicability::IntrinsicCallType::Boolean as Boolean;

        use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::call_applicability::IntrinsicCallType::Byte as Byte;

        use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::call_applicability::IntrinsicCallType::Char as Char;

        use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::call_applicability::IntrinsicCallType::Double as Double;

        use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::call_applicability::IntrinsicCallType::Float as Float;

        use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::call_applicability::IntrinsicCallType::Int as Int;

        use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::call_applicability::IntrinsicCallType::Long as Long;

        use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::call_applicability::IntrinsicCallType::Short as Short;

        use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::call_applicability::IntrinsicCallType::String as String;
        match (source, target) {
            (String, String) | (Boolean, Boolean) => true,
            (String, _) | (_, String) | (Boolean, _) | (_, Boolean) => false,
            (Byte, Byte | Short | Int | Long | Float | Double)
            | (Short, Short | Int | Long | Float | Double)
            | (Char, Char | Int | Long | Float | Double)
            | (Int, Int | Long | Float | Double)
            | (Long, Long | Float | Double)
            | (Float, Float | Double)
            | (Double, Double) => brokk_bifrost_jvm::java::primitives::primitive_converts(
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

fn java_primitive(value: IntrinsicCallType) -> brokk_bifrost_jvm::java::primitives::JavaPrimitive {
    use brokk_bifrost_jvm::java::primitives::JavaPrimitive;
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
