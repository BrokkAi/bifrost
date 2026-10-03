//! Explicit context tokens for query-owned demanded endpoint relations.

use super::{
    BatchCandidateCompletionOutcome, BatchCandidateMatch, BatchCandidateRequest,
    CandidatePathIdentity, PartialPath, SelectedContextPathSource, SelectedContextPathToken,
};
use crate::CancellationToken;
use crate::analyzer::store::{Result as StoreResult, StoreError};
use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;

/// The candidate relation remains in request-owned SQL; closure owns its
/// separately enumerated cells only for the current query's algorithm.
pub(crate) struct DemandSelectedOverlayBlueprint {
    token: SelectedContextPathToken,
}

impl DemandSelectedOverlayBlueprint {
    pub(crate) fn new(token: SelectedContextPathToken) -> Self {
        Self { token }
    }

    pub(crate) fn added_candidate_paths(
        &self,
        paths: &dyn SelectedContextPathSource,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<(CandidatePathIdentity, PartialPath)>>> {
        paths.context_paths(self.token, cancellation)
    }

    pub(crate) fn check_base_candidates(
        &self,
        paths: &dyn SelectedContextPathSource,
        candidates: &[CandidatePathIdentity],
        cancellation: &CancellationToken,
    ) -> StoreResult<bool> {
        let Some(collisions) = paths.hydrate_context_paths(self.token, candidates, cancellation)?
        else {
            return Ok(false);
        };
        if !collisions.is_empty() {
            return Err(StoreError::new(format!(
                "demand context collides with base paths: {collisions:?}"
            )));
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
            visitor,
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
            visitor,
        )
    }
}
