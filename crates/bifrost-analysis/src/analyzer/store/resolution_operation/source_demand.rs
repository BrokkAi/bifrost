//! Source ownership for selected root demands, independent of language policy.
use super::*;
use crate::analyzer::resolution::{BatchCandidateRequest, EndpointSignature};

/// Proven by an admitted source half, never inferred from a spelling.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct SourceDemandKey {
    pub(crate) fragment: BindingFragmentId,
    pub(crate) token: SemanticId,
    pub(crate) demand: SemanticId,
}

pub(super) fn root_source_key(
    ready: &ReadySelectedResolution<'_, '_>,
    base: &dyn BatchResolutionFragmentSource,
    endpoint: &EndpointSignature,
    session: &ResolutionSession,
    cancellation: &CancellationToken,
) -> Result<Option<SourceDemandKey>> {
    Ok(root_source_half(ready, base, endpoint, session, cancellation)?.map(|(key, _)| key))
}

pub(super) fn root_source_half(
    ready: &ReadySelectedResolution<'_, '_>,
    base: &dyn BatchResolutionFragmentSource,
    endpoint: &EndpointSignature,
    session: &ResolutionSession,
    cancellation: &CancellationToken,
) -> Result<Option<(SourceDemandKey, SelectedRootPathHalf)>> {
    if endpoint.node() != BindingNodeId::universal_root() {
        return Ok(None);
    }
    // A first symbol the operation had not issued used to be rejected
    // here, because the store's candidate reader required registered
    // provenance and raised an invalid-fact error without it. Every
    // runtime semantic now decodes: a fragment-local one names its mount
    // in its own bytes and a whole digest is a shared identity the store
    // seeks by digest, which finds nothing for a symbol no blob published.
    // The condition the guard prevented can no longer arise.
    // The source-half classifier requires a closed empty scope stack.
    // Fixed scopes cannot unify with it; an open empty scope tail can.
    // Project only the coarse store probe, retaining the original endpoint
    // for the canonical unification check below.
    if !endpoint.scopes().fixed().is_empty() {
        return Ok(None);
    }
    let probe = EndpointSignature::new_scoped(
        endpoint.node(),
        endpoint.symbols().clone(),
        crate::analyzer::resolution::StackPattern::closed([]),
    );
    let mut key = None;
    let mut selected_half = None;
    let mut ambiguous = false;
    // Which anchor a root route starts with is the owning blob's answer.
    let anchors = ready.lexical_source();
    // A keyed root probe names an issued first symbol, so the store seeks
    // it by identity rather than by mount; the whole selection is in
    // scope, and naming it would be a vector as long as the workspace.
    let outcome = base.visit_reverse_root_candidate_match_pages(
        &[BatchCandidateRequest::new(0, probe)],
        None,
        cancellation,
        &mut |page| {
            let identities = page.iter().map(|item| item.candidate()).collect::<Vec<_>>();
            for (identity, path) in base.hydrate_candidate_paths(&identities, cancellation)? {
                if !session.scope_step() {
                    return Ok(false);
                }
                let Some(half) =
                    classify_selected_root_path_half(&anchors, identity, &path, cancellation)?
                else {
                    continue;
                };
                let candidate = match &half {
                    SelectedRootPathHalf::Import { token, demand, .. }
                    | SelectedRootPathHalf::Reference { token, demand, .. } => SourceDemandKey {
                        fragment: identity.fragment(),
                        token: *token,
                        demand: *demand,
                    },
                    _ => continue,
                };
                let Some(compatible) =
                    endpoint.can_concatenate_with_poll(path.end(), &mut || !session.scope_step())
                else {
                    return Ok(false);
                };
                if compatible.is_ok() {
                    ambiguous |= key.is_some_and(|previous| previous != candidate);
                    key = Some(candidate);
                    selected_half = Some(half);
                }
            }
            Ok(true)
        },
    )?;
    if ambiguous
        || outcome
            .unconditional_completion()
            .contains_reason(ResolutionIncompleteReason::Cancelled)
        || cancellation.is_cancelled()
        || !session.observe_cancellation()
    {
        return Ok(None);
    }
    Ok(key.zip(selected_half))
}
