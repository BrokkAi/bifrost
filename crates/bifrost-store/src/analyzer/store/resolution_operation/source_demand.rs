//! Source ownership for selected root demands, independent of language policy.
use super::demand_closure::Read;
use super::*;
use crate::analyzer::resolution::{BatchCandidateRequest, EndpointSignature};

const MAX_REVERSE_ROOT_CANDIDATE_KEYS_PER_BATCH: usize = 64;

/// Source halves live where a demand originated, independently of the units
/// that can export its answer. The vector dies with this discovery batch.
#[doc(hidden)]
pub enum RootSourceHorizon {
    Bounded(Vec<SelectedResolutionMountOrdinal>),
    Universal,
}

#[doc(hidden)]
pub fn root_source_horizon(
    ready: &ReadySelectedResolution<'_, '_>,
    endpoint: &EndpointSignature,
    cancellation: &CancellationToken,
    transient_languages: &mut HashMap<Language, bool>,
) -> Result<RootSourceHorizon> {
    let lexical = ready.lexical_source();
    if let Some(first) = endpoint.symbols().fixed().first()
        && matches!(
            lexical.semantic_provenance(first.symbol(), cancellation)?,
            Some(SelectedSemanticProvenance::Shared(_))
        )
        && crate::analyzer::resolution::selected_root_source_anchor(
            &lexical,
            endpoint,
            cancellation,
        )?
        .is_none()
    {
        // Both Import and Reference classification require this exact anchor
        // guard. When a Shared head fails that guard, neither classifier can
        // accept a source half, regardless of the remaining symbol stack.
        // There is nothing to probe; target lookup and closure are unaffected.
        return Ok(RootSourceHorizon::Bounded(Vec::new()));
    }
    let source = match endpoint.symbols().fixed().first() {
        Some(symbol) => match lexical.semantic_provenance(symbol.symbol(), cancellation)? {
            Some(SelectedSemanticProvenance::FragmentLocal(provenance)) => Some(provenance.mount()),
            Some(SelectedSemanticProvenance::Stage(provenance)) => Some(provenance.mount()),
            Some(SelectedSemanticProvenance::Shared(_)) | None => None,
        },
        None => None,
    };
    let Some(source) = source else {
        return Ok(RootSourceHorizon::Universal);
    };
    let record = ready.inventory.mount_record_by_ordinal(source.ordinal())?;
    let language = record.semantic_language();
    let Some(support) = crate::analyzer::store::store_language_support_for_hook(
        language,
        "root_source_horizon_follows_provenance",
    ) else {
        return Ok(RootSourceHorizon::Universal);
    };
    if !support.root_source_horizon_follows_provenance() {
        return Ok(RootSourceHorizon::Universal);
    }
    let transient = if let Some(transient) = transient_languages.get(&language) {
        *transient
    } else {
        // Even a placed unsaved replacement keeps the conservative discovery
        // path. Overlay masks can also remove a source without replacing it.
        let storage_language = record.storage_language();
        let transient = ready.inventory.connection().query_row(
            "SELECT EXISTS(SELECT 1 FROM temp.selected_resolution_mounts
                           WHERE storage_language=?1 AND file_version_id IS NULL)
                 OR EXISTS(SELECT 1 FROM temp.selected_resolution_overlay_masks
                           WHERE storage_language=?1)",
            [storage_language],
            |row| row.get::<_, bool>(0),
        )?;
        transient_languages.insert(language, transient);
        transient
    };
    Ok(if transient {
        RootSourceHorizon::Universal
    } else {
        RootSourceHorizon::Bounded(vec![source.ordinal()])
    })
}

/// Proven by an admitted source half, never inferred from a spelling.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[doc(hidden)]
pub struct SourceDemandKey {
    pub(crate) fragment: BindingFragmentId,
    pub(crate) token: SemanticId,
    pub(crate) demand: SemanticId,
}

impl SourceDemandKey {
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn new(fragment: BindingFragmentId, demand: SemanticId, token: SemanticId) -> Self {
        Self {
            fragment,
            demand,
            token,
        }
    }
}

#[derive(Debug)]
pub(super) struct SelectedRootSource {
    pub(super) key: SourceDemandKey,
    pub(super) half: SelectedRootPathHalf,
    pub(super) completion: ResolutionCompletion,
}

/// Every compatible half for one proved source key, in candidate read order.
/// Completion on each half stays with its source path's evaluator.
#[doc(hidden)]
pub struct SelectedRootSources {
    pub(super) key: SourceDemandKey,
    pub(super) halves: Vec<SelectedRootSource>,
}

#[doc(hidden)]
pub fn root_source_set(
    ready: &ReadySelectedResolution<'_, '_>,
    base: &dyn BatchResolutionFragmentSource,
    endpoint: &EndpointSignature,
    mounts: Option<&[SelectedResolutionMountOrdinal]>,
    session: &ResolutionSession,
    cancellation: &CancellationToken,
) -> Result<Read<Option<SelectedRootSources>>> {
    Ok(root_source_sets_in_mounts(
        ready,
        base,
        std::slice::from_ref(endpoint),
        mounts,
        session,
        cancellation,
    )?
    .pop()
    .expect("one endpoint produces one source-set result"))
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

/// An explicit mount set is an existing caller admission bound. Languages
/// may additionally prove a smaller source-provenance horizon below.
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
    Ok(
        root_source_sets_in_mounts(ready, base, endpoints, mounts, session, cancellation)?
            .into_iter()
            .map(|result| match result {
                Read::Ready { value, .. } => value.and_then(|mut source| source.halves.pop()),
                Read::Unavailable { .. } | Read::Cancelled(_) => None,
            })
            .collect(),
    )
}

fn root_source_sets_in_mounts(
    ready: &ReadySelectedResolution<'_, '_>,
    base: &dyn BatchResolutionFragmentSource,
    endpoints: &[EndpointSignature],
    mounts: Option<&[SelectedResolutionMountOrdinal]>,
    session: &ResolutionSession,
    cancellation: &CancellationToken,
) -> Result<Vec<Read<Option<SelectedRootSources>>>> {
    let mut results = std::iter::repeat_with(|| Read::ready(None))
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
    let mut transient_languages = HashMap::default();
    for eligible_batch in eligible.chunks(MAX_REVERSE_ROOT_CANDIDATE_KEYS_PER_BATCH) {
        let mut bounded_mounts = Vec::new();
        let mut universal = false;
        let mut source_batch = Vec::new();
        for (position, probe) in eligible_batch {
            let horizon = root_source_horizon(
                ready,
                &endpoints[*position],
                cancellation,
                &mut transient_languages,
            )?;
            crate::analyzer::resolution::seam_profile::record_root_source_horizon(matches!(
                horizon,
                RootSourceHorizon::Bounded(_)
            ));
            match horizon {
                // A structurally rejected root must not become a probe key
                // merely because another root in this batch has a source.
                RootSourceHorizon::Bounded(sources) if sources.is_empty() => continue,
                RootSourceHorizon::Bounded(sources) => bounded_mounts.extend(sources),
                RootSourceHorizon::Universal => universal = true,
            }
            source_batch.push((*position, probe));
        }
        if source_batch.is_empty() {
            continue;
        }
        let eligible_batch = source_batch.as_slice();
        bounded_mounts.sort_unstable();
        bounded_mounts.dedup();
        // Preserve the caller's admission bound. A provenance proof only
        // narrows it; an unknown proof leaves today's universal scan intact.
        let discovery_mounts = if universal {
            mounts
        } else {
            if let Some(admitted) = mounts {
                bounded_mounts.retain(|mount| admitted.contains(mount));
            }
            Some(bounded_mounts.as_slice())
        };
        let requests = eligible_batch
            .iter()
            .enumerate()
            .map(|(ordinal, (_, probe))| BatchCandidateRequest::new(ordinal, (*probe).clone()))
            .collect::<Vec<_>>();
        let mut candidates = (0..eligible_batch.len())
            .map(|_| {
                (
                    None::<SourceDemandKey>,
                    Vec::<SelectedRootSource>::new(),
                    false,
                )
            })
            .collect::<Vec<_>>();
        let outcome = base.visit_reverse_root_candidate_match_pages(
            &requests,
            discovery_mounts,
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
                            let (key, selected_halves, ambiguous) = &mut candidates[request];
                            *ambiguous |= key.is_some_and(|previous| previous != candidate);
                            *key = Some(candidate);
                            selected_halves.push(SelectedRootSource {
                                key: candidate,
                                half,
                                completion: path.completion().clone(),
                            });
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
            let completion = outcome
                .unconditional_completion()
                .combine(&crate::analyzer::resolution::cancelled_completion());
            for &(position, _) in eligible_batch {
                results[position] = Read::Cancelled(completion.clone());
            }
            return Ok(results);
        }
        for (local, &(position, _)) in eligible_batch.iter().enumerate() {
            let (key, halves, ambiguous) = std::mem::take(&mut candidates[local]);
            results[position] = if ambiguous {
                Read::Unavailable {
                    reason: crate::analyzer::resolution::DemandRootUnavailableReason::MissingSourceProvenance,
                    completion: ResolutionCompletion::Complete,
                }
            } else {
                Read::ready(key.map(|key| SelectedRootSources { key, halves }))
            };
        }
    }
    Ok(results)
}
