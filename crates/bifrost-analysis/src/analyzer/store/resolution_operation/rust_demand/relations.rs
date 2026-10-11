//! Rust-only bookkeeping attached to the shared closed demand relations.

use super::super::*;
use crate::analyzer::resolution::{
    CandidatePathIdentity, EndpointSignature, ResolutionCompletion, SemanticId,
};

pub(crate) use super::super::demand::ClosedRelations;

pub(crate) struct ClosedEndpointRegistration {
    pub(crate) blueprint: SelectedFactOperationBlueprint,
    pub(crate) completion: ResolutionCompletion,
}

#[derive(Default)]
pub(crate) struct RustDemandRelationState {
    pub(crate) registrations: HashMap<EndpointSignature, ClosedEndpointRegistration>,
    pub(crate) generated_base_endings:
        HashMap<(SemanticId, SemanticId), Vec<CandidatePathIdentity>>,
    pub(crate) generated_base_suppressed: HashSet<CandidatePathIdentity>,
}

impl ClosedRelations {
    pub(crate) fn generated_base_completion(
        &self,
        endpoint: &EndpointSignature,
        session: &ResolutionSession,
    ) -> Option<(ResolutionCompletion, bool)> {
        let fixed = endpoint.symbols().fixed();
        let key = (fixed.first()?.symbol(), fixed.get(1)?.symbol());
        let mut completion: Option<ResolutionCompletion> = None;
        let mut use_base = None;
        for id in self.rust.generated_base_endings.get(&key)? {
            let path = &self.paths[id];
            if endpoint
                .can_concatenate_with_poll(path.end(), &mut || !session.scope_step())?
                .is_ok()
            {
                let candidate_uses_base = !self.rust.generated_base_suppressed.contains(id);
                assert!(
                    use_base.is_none_or(|previous| previous == candidate_uses_base),
                    "one generated endpoint cannot mix base and closed-empty authority"
                );
                use_base = Some(candidate_uses_base);
                completion = Some(completion.map_or_else(
                    || path.completion().clone(),
                    |previous| previous.combine(path.completion()),
                ));
            }
        }
        completion.map(|completion| (completion, use_base.unwrap()))
    }
}
