use crate::analyzer::resolution::AnswerMap;
use crate::analyzer::resolution::{
    ArgumentFormalBinding, CallApplicabilityAdapter, CallTypeSubstitution, CandidateAssessment,
    FactEvaluation, IntrinsicCallType, LoweredCallApplicabilityObligation,
    LoweredCallableSignatureProperty, MappingAssessment, ResolutionCompletion, SemanticId,
    StateMap, TypeInCallPosition,
};
use crate::analyzer::store::Result;
use brokk_bifrost_core::analyzer::resolution_facts::IntrinsicTypeKind;
use brokk_bifrost_core::analyzer::structural::callable::CallableRejectionReason;

pub(super) static SCALA_CALL_APPLICABILITY_ADAPTER: ScalaCallApplicabilityAdapter =
    ScalaCallApplicabilityAdapter;

pub(crate) struct ScalaCallApplicabilityAdapter;

impl CallApplicabilityAdapter for ScalaCallApplicabilityAdapter {
    fn has_intrinsic_call_type_table(&self) -> bool {
        true
    }

    fn intrinsic_call_type(
        &self,
        kind: IntrinsicTypeKind,
        spelling: &str,
    ) -> Option<IntrinsicCallType> {
        if kind != IntrinsicTypeKind::LanguageBuiltin {
            return None;
        }
        Some(match spelling {
            "scala.Boolean" => IntrinsicCallType::Boolean,
            "java.lang.String" | "scala.Predef.String" | "kotlin.String" => {
                IntrinsicCallType::String
            }
            "scala.Byte" => IntrinsicCallType::Byte,
            "scala.Short" => IntrinsicCallType::Short,
            "scala.Char" => IntrinsicCallType::Char,
            "scala.Int" => IntrinsicCallType::Int,
            "scala.Long" => IntrinsicCallType::Long,
            "scala.Float" => IntrinsicCallType::Float,
            "scala.Double" => IntrinsicCallType::Double,
            _ => return None,
        })
    }

    fn intrinsic_call_type_converts(
        &self,
        source: IntrinsicCallType,
        target: IntrinsicCallType,
    ) -> bool {
        use IntrinsicCallType::{Boolean, Byte, Char, Double, Float, Int, Long, Short, String};
        matches!(
            (source, target),
            (Boolean, Boolean)
                | (String, String)
                | (Byte, Byte | Short | Int | Long | Float | Double)
                | (Short, Short | Int | Long | Float | Double)
                | (Char, Char | Int | Long | Float | Double)
                | (Int, Int | Long | Float | Double)
                | (Long, Long | Float | Double)
                | (Float, Float | Double)
                | (Double, Double)
        )
    }

    fn type_in_call_position(&self) -> TypeInCallPosition {
        TypeInCallPosition::ApplyMembers
    }

    fn result_application_member_names(&self) -> &'static [&'static str] {
        &["apply"]
    }

    fn map_arguments(
        &self,
        call: &LoweredCallApplicabilityObligation,
        signature: &LoweredCallableSignatureProperty,
    ) -> MappingAssessment {
        crate::analyzer::resolution::map_scala_call_shape(
            call,
            signature,
            true,
            true,
            CallableRejectionReason::ArityBelowRequired,
        )
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
