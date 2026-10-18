use crate::analyzer::resolution::AnswerMap;
use crate::analyzer::resolution::{
    ArgumentFormalBinding, CallApplicabilityAdapter, CallTypeSubstitution, CandidateAssessment,
    FactEvaluation, IntrinsicCallType, LoweredCallApplicabilityObligation,
    LoweredCallableSignatureProperty, MappingAssessment, ResolutionCompletion, SemanticId,
    StateMap, TypeInCallPosition,
};
use crate::analyzer::store::Result;
use brokk_bifrost_core::analyzer::resolution_facts::{IntrinsicTypeKind, ResolutionEngineRuleKind};
use brokk_bifrost_core::analyzer::structural::callable::CallableRejectionReason;

pub(super) static SCALA_CALL_APPLICABILITY_ADAPTER: ScalaCallApplicabilityAdapter =
    ScalaCallApplicabilityAdapter;

pub(crate) struct ScalaCallApplicabilityAdapter;

impl CallApplicabilityAdapter for ScalaCallApplicabilityAdapter {
    fn has_scoped_receiver_extensions(&self) -> bool {
        true
    }

    fn retains_unmodeled_receiver_callables(&self) -> bool {
        false
    }

    fn missing_receiver_extension_reason(&self) -> Option<&'static [u8]> {
        Some(b"scala-given-extension-discovery-unavailable")
    }

    fn unmatched_construction_reason(&self) -> Option<&'static [u8]> {
        Some(b"scala-constructor-applicability-unproven")
    }

    fn scoped_extensions_follow_member_selection(&self) -> bool {
        true
    }

    fn has_intrinsic_call_type_table(&self) -> bool {
        true
    }

    fn intrinsic_call_type(
        &self,
        kind: IntrinsicTypeKind,
        spelling: &str,
    ) -> Option<IntrinsicCallType> {
        if kind == IntrinsicTypeKind::Primitive {
            return crate::analyzer::languages::language_support(crate::analyzer::Language::Java)
                .and_then(|support| support.call_applicability_adapter())
                .and_then(|adapter| adapter.intrinsic_call_type(kind, spelling));
        }
        if kind != IntrinsicTypeKind::LanguageBuiltin {
            return None;
        }
        Some(match spelling {
            "scala.Boolean" | "kotlin.Boolean" => IntrinsicCallType::Boolean,
            "java.lang.String" | "scala.Predef.String" | "kotlin.String" => {
                IntrinsicCallType::String
            }
            "scala.Byte" | "kotlin.Byte" => IntrinsicCallType::Byte,
            "scala.Short" | "kotlin.Short" => IntrinsicCallType::Short,
            "scala.Char" | "kotlin.Char" => IntrinsicCallType::Char,
            "scala.Int" | "kotlin.Int" => IntrinsicCallType::Int,
            "scala.Long" | "kotlin.Long" => IntrinsicCallType::Long,
            "scala.Float" | "kotlin.Float" => IntrinsicCallType::Float,
            "scala.Double" | "kotlin.Double" => IntrinsicCallType::Double,
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

    fn no_applicable_call_diagnostic(&self) -> Option<&'static str> {
        Some("no_applicable_scala_callable")
    }

    fn result_application_member_names(&self) -> &'static [&'static str] {
        &["apply"]
    }

    fn map_arguments(
        &self,
        call: &LoweredCallApplicabilityObligation,
        signature: &LoweredCallableSignatureProperty,
    ) -> MappingAssessment {
        let omitted_arguments;
        let call = if call
            .eligible_rules()
            .contains(&ResolutionEngineRuleKind::DefaultConstruction)
        {
            if signature.parameter_lists().is_empty() {
                // A constructor declared without a parameter list takes `new C`,
                // but not `new C()`. This is not application of its result.
                return if call.argument_lists().is_empty() {
                    debug_assert!(call.arguments().is_empty());
                    debug_assert!(signature.parameters().is_empty());
                    MappingAssessment::Mapped {
                        bindings: Vec::new(),
                        used_defaults: 0,
                        used_vararg: false,
                        result_application_lists: Vec::new(),
                    }
                } else {
                    MappingAssessment::Inapplicable(CallableRejectionReason::ListShapeMismatch)
                };
            }
            if call.argument_lists().is_empty() {
                // Scala also permits omission of an empty constructor list.
                // Map it as zero arguments through the existing assessor, so
                // required parameters, defaults and contextual lists still apply.
                omitted_arguments =
                    call.clone()
                        .with_argument_shape(call.language(), Vec::new(), vec![0]);
                &omitted_arguments
            } else {
                call
            }
        } else {
            call
        };
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
