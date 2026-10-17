//! Source ownership for selected root demands, independent of language policy.
use super::*;
use crate::analyzer::resolution::{BatchCandidateRequest, EndpointSignature};

const MAX_REVERSE_ROOT_CANDIDATE_KEYS_PER_BATCH: usize = 64;

/// Proven by an admitted source half, never inferred from a spelling.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct SourceDemandKey {
    pub(crate) fragment: BindingFragmentId,
    pub(crate) token: SemanticId,
    pub(crate) demand: SemanticId,
}

#[derive(Debug)]
pub(super) struct SelectedRootSource {
    pub(super) key: SourceDemandKey,
    pub(super) half: SelectedRootPathHalf,
    pub(super) completion: ResolutionCompletion,
}

pub(super) fn root_source_key(
    ready: &ReadySelectedResolution<'_, '_>,
    base: &dyn BatchResolutionFragmentSource,
    endpoint: &EndpointSignature,
    session: &ResolutionSession,
    cancellation: &CancellationToken,
) -> Result<Option<SourceDemandKey>> {
    Ok(
        root_source_half(ready, base, endpoint, None, session, cancellation)?
            .map(|source| source.key),
    )
}

/// `None` is used by Rust and JVM root-source lookup, whose callers do not
/// supply a finite admitted-mount set, and Go forward demand, whose package
/// set can grow as roots are discovered.
pub(super) fn root_source_half(
    ready: &ReadySelectedResolution<'_, '_>,
    base: &dyn BatchResolutionFragmentSource,
    endpoint: &EndpointSignature,
    mounts: Option<&[SelectedResolutionMountOrdinal]>,
    session: &ResolutionSession,
    cancellation: &CancellationToken,
) -> Result<Option<SelectedRootSource>> {
    root_source_half_in_mounts(ready, base, endpoint, mounts, session, cancellation)
}

/// `root_source_half` restricted to the mounts that can hold the endpoint's
/// source half. `None` reads the whole selection.
pub(super) fn root_source_half_in_mounts(
    ready: &ReadySelectedResolution<'_, '_>,
    base: &dyn BatchResolutionFragmentSource,
    endpoint: &EndpointSignature,
    mounts: Option<&[SelectedResolutionMountOrdinal]>,
    session: &ResolutionSession,
    cancellation: &CancellationToken,
) -> Result<Option<SelectedRootSource>> {
    Ok(root_source_halves_in_mounts(
        ready,
        base,
        std::slice::from_ref(endpoint),
        mounts,
        session,
        cancellation,
    )?
    .pop()
    .expect("one endpoint produces one source-half result"))
}

/// Read universal-root source halves for one bounded batch of endpoints.
/// Candidate keys are sent together so each blob's reverse resolution-path
/// reader can use its JSON array seek instead of repeating a singleton query.
/// `mounts` restricts the read to the mounts that can hold the endpoints'
/// source halves; `None` reads the whole selection.
pub(super) fn root_source_halves_in_mounts(
    ready: &ReadySelectedResolution<'_, '_>,
    base: &dyn BatchResolutionFragmentSource,
    endpoints: &[EndpointSignature],
    mounts: Option<&[SelectedResolutionMountOrdinal]>,
    session: &ResolutionSession,
    cancellation: &CancellationToken,
) -> Result<Vec<Option<SelectedRootSource>>> {
    let mut results = std::iter::repeat_with(|| None)
        .take(endpoints.len())
        .collect::<Vec<_>>();
    let mut eligible = Vec::new();
    for (position, endpoint) in endpoints.iter().enumerate() {
        if endpoint.node() != BindingNodeId::universal_root()
            || !endpoint.scopes().fixed().is_empty()
        {
            continue;
        }
        // Runtime semantics decode without registration: a local identity
        // names its mount in its own bytes, while an unpublished shared name
        // simply has no matching candidate rows.
        // Probe with a closed scope stack, while retaining the original
        // endpoint for canonical compatibility below.
        let probe = EndpointSignature::new_scoped(
            endpoint.node(),
            endpoint.symbols().clone(),
            crate::analyzer::resolution::StackPattern::closed([]),
        );
        eligible.push((position, probe));
    }
    if eligible.is_empty() {
        return Ok(results);
    }

    let anchors = ready.lexical_source();
    for eligible_batch in eligible.chunks(MAX_REVERSE_ROOT_CANDIDATE_KEYS_PER_BATCH) {
        let requests = eligible_batch
            .iter()
            .enumerate()
            .map(|(ordinal, (_, probe))| BatchCandidateRequest::new(ordinal, probe.clone()))
            .collect::<Vec<_>>();
        let mut candidates = (0..eligible_batch.len())
            .map(|_| {
                (
                    None::<SourceDemandKey>,
                    None::<SelectedRootPathHalf>,
                    None::<ResolutionCompletion>,
                    false,
                )
            })
            .collect::<Vec<_>>();
        let outcome = base.visit_reverse_root_candidate_match_pages(
            &requests,
            mounts,
            cancellation,
            &mut |page| {
                let mut identities = Vec::new();
                let mut owners = HashMap::<CandidatePathIdentity, Vec<usize>>::default();
                for item in page {
                    let identity = item.candidate();
                    let request = item.request_ordinal();
                    assert!(request < eligible_batch.len());
                    owners
                        .entry(identity)
                        .or_insert_with(|| {
                            identities.push(identity);
                            Vec::new()
                        })
                        .push(request);
                }
                for (identity, path) in base.hydrate_candidate_paths(&identities, cancellation)? {
                    let request_owners = owners
                        .get(&identity)
                        .expect("hydrated candidate came from this reverse page");
                    for &request in request_owners {
                        if !session.scope_step() {
                            return Ok(false);
                        }
                        let endpoint = &endpoints[eligible_batch[request].0];
                        let Some(half) = classify_selected_root_path_half(
                            &anchors,
                            identity,
                            &path,
                            cancellation,
                        )?
                        else {
                            continue;
                        };
                        let candidate = match &half {
                            SelectedRootPathHalf::Import { token, demand, .. }
                            | SelectedRootPathHalf::Reference { token, demand, .. } => {
                                SourceDemandKey {
                                    fragment: identity.fragment(),
                                    token: *token,
                                    demand: *demand,
                                }
                            }
                            _ => continue,
                        };
                        let Some(compatible) = endpoint
                            .can_concatenate_with_poll(path.end(), &mut || !session.scope_step())
                        else {
                            return Ok(false);
                        };
                        if compatible.is_ok() {
                            let (key, selected_half, completion, ambiguous) =
                                &mut candidates[request];
                            *ambiguous |= key.is_some_and(|previous| previous != candidate);
                            *key = Some(candidate);
                            *selected_half = Some(half);
                            *completion = Some(path.completion().clone());
                        }
                    }
                }
                Ok(true)
            },
        )?;
        if outcome
            .unconditional_completion()
            .contains_reason(ResolutionIncompleteReason::Cancelled)
            || cancellation.is_cancelled()
            || !session.observe_cancellation()
        {
            return Ok(results);
        }
        for (local, &(position, _)) in eligible_batch.iter().enumerate() {
            let (key, half, completion, ambiguous) = std::mem::take(&mut candidates[local]);
            if !ambiguous {
                results[position] =
                    key.zip(half)
                        .zip(completion)
                        .map(|((key, half), completion)| SelectedRootSource {
                            key,
                            half,
                            completion,
                        });
            }
        }
    }
    Ok(results)
}
