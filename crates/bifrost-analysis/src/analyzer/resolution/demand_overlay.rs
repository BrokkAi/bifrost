//! Explicit context tokens for query-owned demanded endpoint relations.

use super::{
    BatchCandidateCompletionOutcome, BatchCandidateMatch, BatchCandidateRequest,
    BatchResolutionFragmentSource, CandidatePathIdentity, MAX_SOURCE_ROWS_PER_BATCH, PartialPath,
    SelectedContextPathSource, SelectedContextPathToken,
};
use crate::CancellationToken;
use crate::analyzer::store::{Result as StoreResult, StoreError};
use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
use std::cell::RefCell;
use std::collections::HashSet;

type DemandContextPaths = Vec<(CandidatePathIdentity, PartialPath)>;

/// The candidate relation remains in request-owned SQL; closure owns its
/// separately enumerated cells only for the current query's algorithm.
#[doc(hidden)]
pub struct DemandSelectedOverlayBlueprint {
    token: SelectedContextPathToken,
    // Only identical cells from this query's immutable base are recorded here.
    // They are omitted from publication and both candidate-stream directions.
    reused_base: RefCell<HashSet<CandidatePathIdentity>>,
}

impl DemandSelectedOverlayBlueprint {
    pub(crate) fn new(token: SelectedContextPathToken) -> Self {
        Self {
            token,
            reused_base: RefCell::default(),
        }
    }

    pub(crate) fn added_candidate_paths(
        &self,
        paths: &dyn SelectedContextPathSource,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<DemandContextPaths>> {
        paths.context_paths(self.token, cancellation)
    }

    /// A demanded relation may share invariant cells with its initial context.
    /// Compare complete cells before admitting reuse; never replace base evidence.
    pub(crate) fn delta(
        token: SelectedContextPathToken,
        paths: &dyn SelectedContextPathSource,
        base_context: SelectedContextPathToken,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<(Self, DemandContextPaths)>> {
        let relation = Self::new(token);
        let Some(mut candidates) = relation.added_candidate_paths(paths, cancellation)? else {
            return Ok(None);
        };
        for page in candidates.chunks(MAX_SOURCE_ROWS_PER_BATCH) {
            let ids = page.iter().map(|(id, _)| *id).collect::<Vec<_>>();
            // Compiled cells use the request-owned identity domain. Only the
            // initial context can contain them, never the ordinary blob paths.
            assert!(ids.iter().all(|id| id.path().is_context_local()));
            let Some(base_cells) = paths.hydrate_context_paths(base_context, &ids, cancellation)?
            else {
                return Ok(None);
            };
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            relation.verify_base_cells(page, &base_cells)?;
        }
        candidates.retain(|(id, _)| !relation.reused_base.borrow().contains(id));
        Ok(Some((relation, candidates)))
    }

    fn verify_base_cells(
        &self,
        context: &[(CandidatePathIdentity, PartialPath)],
        base: &[(CandidatePathIdentity, PartialPath)],
    ) -> StoreResult<()> {
        let mut collisions = Vec::new();
        let mut reused = self.reused_base.borrow_mut();
        for base_cell in base {
            let context_cell = context
                .iter()
                .find(|(id, _)| *id == base_cell.0)
                .expect("base hydration returns only requested context candidates");
            if context_cell != base_cell {
                collisions.push((context_cell.clone(), base_cell.clone()));
            } else {
                debug_assert_eq!(
                    context_cell, base_cell,
                    "identical-cell reuse preserves identity, target and completion"
                );
                reused.insert(base_cell.0);
            }
        }
        if !collisions.is_empty() {
            return Err(StoreError::new(format!(
                "demand context collides with base paths: {collisions:?}"
            )));
        }
        Ok(())
    }

    pub(crate) fn check_base_candidates(
        &self,
        paths: &dyn SelectedContextPathSource,
        base: &dyn BatchResolutionFragmentSource,
        candidates: &[CandidatePathIdentity],
        cancellation: &CancellationToken,
    ) -> StoreResult<bool> {
        let Some(collisions) = paths.hydrate_context_paths(self.token, candidates, cancellation)?
        else {
            return Ok(false);
        };
        if !collisions.is_empty() {
            let ids = collisions.iter().map(|(id, _)| *id).collect::<Vec<_>>();
            let base_cells = base.hydrate_candidate_paths(&ids, cancellation)?;
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            assert_eq!(
                base_cells.len(),
                collisions.len(),
                "base matches have immutable cells"
            );
            self.verify_base_cells(&collisions, &base_cells)?;
        }
        Ok(true)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn visit_forward_additions(
        &self,
        paths: &dyn SelectedContextPathSource,
        requests: &[BatchCandidateRequest],
        completion: BatchCandidateCompletionOutcome,
        maximum_page_rows: usize,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<BatchCandidateCompletionOutcome> {
        paths.visit_context_forward_additions(
            self.token,
            requests,
            completion,
            maximum_page_rows,
            cancellation,
            Some(session),
            &mut |page| {
                let disjoint = self.reused_base.borrow().is_empty();
                if disjoint {
                    return visitor(page);
                }
                let delta = page
                    .iter()
                    .copied()
                    .filter(|row| !self.reused_base.borrow().contains(&row.candidate()))
                    .collect::<Vec<_>>();
                if delta.is_empty() {
                    Ok(true)
                } else {
                    visitor(&delta)
                }
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn visit_reverse_additions(
        &self,
        paths: &dyn SelectedContextPathSource,
        requests: &[BatchCandidateRequest],
        completion: BatchCandidateCompletionOutcome,
        maximum_page_rows: usize,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<BatchCandidateCompletionOutcome> {
        paths.visit_context_reverse_additions(
            self.token,
            requests,
            completion,
            maximum_page_rows,
            cancellation,
            Some(session),
            &mut |page| {
                let disjoint = self.reused_base.borrow().is_empty();
                if disjoint {
                    return visitor(page);
                }
                let delta = page
                    .iter()
                    .copied()
                    .filter(|row| !self.reused_base.borrow().contains(&row.candidate()))
                    .collect::<Vec<_>>();
                if delta.is_empty() {
                    Ok(true)
                } else {
                    visitor(&delta)
                }
            },
        )
    }
}
