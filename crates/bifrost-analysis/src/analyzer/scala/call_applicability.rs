use crate::analyzer::resolution::{
    ArgumentFormalBinding, CallApplicabilityAdapter, CandidateAssessment, FactEvaluation,
    LoweredCallApplicabilityObligation, LoweredCallableSignatureProperty, MappingAssessment,
    ResolutionCompletion, SemanticId, StateMap, TypeInCallPosition,
};
use crate::analyzer::store::Result;
use brokk_bifrost_core::analyzer::structural::callable::CallableRejectionReason;

pub(super) static SCALA_CALL_APPLICABILITY_ADAPTER: ScalaCallApplicabilityAdapter =
    ScalaCallApplicabilityAdapter;

pub(crate) struct ScalaCallApplicabilityAdapter;

impl CallApplicabilityAdapter for ScalaCallApplicabilityAdapter {
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
            false,
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
        previous_states: &StateMap,
        completion: &mut ResolutionCompletion,
    ) -> Result<Option<CandidateAssessment>> {
        evaluation.assess_mapped_exact_candidate(
            candidate,
            call,
            signature,
            bindings,
            used_vararg,
            previous_states,
            completion,
        )
    }
}
