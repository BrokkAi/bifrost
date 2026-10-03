//! Closed demand relations and the source that reads them.
//!
//! A closed endpoint relation is immutable: it is published once, it may add
//! candidate cells, and it may never rewrite a cell another relation already
//! published. `ClosedForwardSource` layers the published relations over the
//! operation's ordinary base source, so every answer is still composed from
//! persisted candidates and the base's own coverage.

use super::super::*;
use crate::analyzer::resolution::{
    BatchCandidateCompletionOutcome, BatchCandidateMatch, BatchCandidateOutcome,
    BatchCandidateRequest, BatchDefinitionNode, BatchEndpointClassification,
    DemandSelectedOverlayBlueprint, EndpointSignature, PartialPath, ReferenceSeed,
    ReferenceSeedBatch, ReferenceSeedReadOutcome, ResolutionCompletionAccumulator, ResolutionQuery,
    ReverseReferenceSeedRequest, SelectedContextPathSource, TypeTransferRule,
};

pub(crate) struct ClosedEndpointRegistration {
    pub(crate) blueprint: SelectedFactOperationBlueprint,
    pub(crate) completion: ResolutionCompletion,
}

#[derive(Default)]
pub(crate) struct ClosedRelations {
    pub(crate) registrations: HashMap<EndpointSignature, ClosedEndpointRegistration>,
    pub(crate) endpoints: HashMap<EndpointSignature, DemandSelectedOverlayBlueprint>,
    pub(crate) paths: HashMap<CandidatePathIdentity, PartialPath>,
    /// Equal cells can belong to several endpoint relations. Reverse reads
    /// emit the cell only through the first relation that published it.
    path_owners: HashMap<CandidatePathIdentity, EndpointSignature>,
    pub(crate) generated_base_endings:
        HashMap<(SemanticId, SemanticId), Vec<CandidatePathIdentity>>,
    pub(crate) generated_base_suppressed: HashSet<CandidatePathIdentity>,
    pub(crate) base_ready: HashSet<EndpointSignature>,
    pub(crate) empty_ready: HashSet<EndpointSignature>,
    pub(crate) unconditional: Option<ResolutionCompletion>,
    /// Reverse candidate coverage is a different relation from forward
    /// candidate coverage: it carries the reverse inventory's own gaps, which
    /// a forward read never sees. The two therefore share the arena but not
    /// one unconditional cell.
    pub(crate) unconditional_reverse: Option<ResolutionCompletion>,
    /// Reverse targets whose candidate domain was discovered and completely
    /// forward-validated. A reverse candidate read before any of them is a
    /// read the demand relations do not justify.
    pub(crate) reverse_targets: HashSet<SemanticId>,
    pub(crate) reverse_endpoints: HashSet<EndpointSignature>,
    #[cfg(test)]
    pub(crate) reads: Vec<EndpointSignature>,
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
        for id in self.generated_base_endings.get(&key)? {
            let path = &self.paths[id];
            if endpoint
                .can_concatenate_with_poll(path.end(), &mut || !session.scope_step())?
                .is_ok()
            {
                let candidate_uses_base = !self.generated_base_suppressed.contains(id);
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

    pub(crate) fn publish(
        &mut self,
        endpoint: EndpointSignature,
        relation: DemandSelectedOverlayBlueprint,
        paths: Vec<(CandidatePathIdentity, PartialPath)>,
    ) {
        assert!(
            !self.endpoints.contains_key(&endpoint),
            "a closed relation is immutable"
        );
        // Validate every cell before publishing any part of this relation.
        for (id, path) in &paths {
            if let Some(previous) = self.paths.get(id) {
                assert_eq!(
                    previous, path,
                    "one candidate identity must have one immutable cell"
                );
            }
        }
        for (id, path) in &paths {
            self.paths.entry(*id).or_insert_with(|| path.clone());
            self.path_owners
                .entry(*id)
                .or_insert_with(|| endpoint.clone());
        }
        self.endpoints.insert(endpoint, relation);
    }

    pub(crate) fn observe_coverage(&mut self, completion: &ResolutionCompletion) {
        if completion.contains_reason(ResolutionIncompleteReason::Cancelled) {
            return;
        }
        match &self.unconditional {
            Some(previous) => assert_eq!(
                previous, completion,
                "all endpoint and local reads share operation-wide unconditional coverage"
            ),
            None => self.unconditional = Some(completion.clone()),
        }
    }

    pub(crate) fn observe_reverse_coverage(&mut self, completion: &ResolutionCompletion) {
        if completion.contains_reason(ResolutionIncompleteReason::Cancelled) {
            return;
        }
        match &self.unconditional_reverse {
            Some(previous) => assert_eq!(
                previous, completion,
                "all reverse candidate reads share operation-wide unconditional coverage"
            ),
            None => self.unconditional_reverse = Some(completion.clone()),
        }
    }
}

pub(crate) struct ClosedForwardSource<'a> {
    pub(crate) base: &'a dyn BatchResolutionFragmentSource,
    pub(crate) paths: &'a dyn SelectedContextPathSource,
    pub(crate) arena: &'a RefCell<ClosedRelations>,
    pub(crate) session: &'a ResolutionSession,
}

impl<'a> ClosedForwardSource<'a> {
    pub(crate) fn new(
        base: &'a dyn BatchResolutionFragmentSource,
        paths: &'a dyn SelectedContextPathSource,
        arena: &'a RefCell<ClosedRelations>,
        session: &'a ResolutionSession,
    ) -> Self {
        Self {
            base,
            paths,
            arena,
            session,
        }
    }
}

impl ClosedForwardSource<'_> {
    /// Reverse mirror of `visit_forward_candidate_match_pages_limited`.
    ///
    /// The reverse readiness law is not the forward one. A forward read names
    /// the endpoint its own relation was closed under, so a missing key is a
    /// read before closure. A reverse read walks the other way: it names the
    /// *end* of a bridge, whose forward closure is keyed by its start.
    /// Production readiness exhausts the exact reverse endpoint's dependencies
    /// before this read. The test oracle also supports whole-target closure.
    /// Every published relation then filters the base rows and contributes its
    /// own reverse additions, without reopening the base; each retained base
    /// row is charged one session step exactly as the forward page visitor
    /// charges it.
    fn visit_reverse_candidate_match_pages_limited(
        &self,
        requests: &[BatchCandidateRequest],
        limit: usize,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> Result<bool>,
    ) -> Result<BatchCandidateCompletionOutcome> {
        assert!(requests.len() <= MAX_SOURCE_ROWS_PER_BATCH);
        assert!((1..=MAX_SOURCE_ROWS_PER_BATCH).contains(&limit));
        for (ordinal, request) in requests.iter().enumerate() {
            assert_eq!(request.request_ordinal(), ordinal);
        }
        if self.arena.borrow().reverse_targets.is_empty()
            && requests.iter().any(|request| {
                !self
                    .arena
                    .borrow()
                    .reverse_endpoints
                    .contains(request.endpoint())
            })
        {
            return Err(StoreError::new(
                "selected reverse candidate read before its target was materialized".to_owned(),
            ));
        }
        let mut stopped = false;
        let mut cancellation_observed = false;
        let mut coverage =
            self.base
                .visit_reverse_candidate_match_pages(requests, cancellation, &mut |page| {
                    assert!(!stopped, "base emitted after its visitor stopped");
                    let mut retained = Vec::with_capacity(page.len());
                    {
                        let arena = self.arena.borrow();
                        let candidates = page
                            .iter()
                            .map(|row| row.candidate())
                            .collect::<BTreeSet<_>>()
                            .into_iter()
                            .collect::<Vec<_>>();
                        for relation in arena.endpoints.values() {
                            if !relation.check_base_candidates(
                                self.paths,
                                &candidates,
                                cancellation,
                            )? {
                                cancellation_observed = true;
                                stopped = true;
                                return Ok(false);
                            }
                        }
                        for row in page {
                            if cancellation.is_cancelled() || !self.session.scope_step() {
                                cancellation_observed = true;
                                stopped = true;
                                return Ok(false);
                            }
                            retained.push(*row);
                        }
                    }
                    if !retained.is_empty() {
                        stopped = !visitor(&retained)?;
                    }
                    Ok(!stopped)
                })?;
        if cancellation_observed {
            coverage = BatchCandidateCompletionOutcome::new(
                requests.len(),
                coverage
                    .unconditional_completion()
                    .combine(&ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::Cancelled,
                    ])),
                coverage.branch_completions().iter().cloned(),
            );
        }
        {
            let mut arena = self.arena.borrow_mut();
            arena.observe_reverse_coverage(coverage.unconditional_completion());
            #[cfg(test)]
            arena
                .reads
                .extend(requests.iter().map(|request| request.endpoint().clone()));
        }
        assert_eq!(coverage.branch_completions().len(), requests.len());
        if stopped
            || coverage
                .unconditional_completion()
                .contains_reason(ResolutionIncompleteReason::Cancelled)
        {
            return Ok(coverage);
        }
        let mut unconditional = ResolutionCompletionAccumulator::default();
        unconditional.include(coverage.unconditional_completion());
        'requests: for (ordinal, request) in requests.iter().enumerate() {
            let arena = self.arena.borrow();
            for (endpoint, relation) in &arena.endpoints {
                let local = [BatchCandidateRequest::new(0, request.endpoint().clone())];
                let local_coverage = BatchCandidateCompletionOutcome::new(
                    1,
                    ResolutionCompletion::Complete,
                    [coverage.branch_completions()[ordinal].clone()],
                );
                let added = relation.visit_reverse_additions(
                    self.paths,
                    &local,
                    local_coverage,
                    limit,
                    cancellation,
                    self.session,
                    &mut |page| {
                        assert!(!stopped, "overlay emitted after its visitor stopped");
                        let remapped = page
                            .iter()
                            .filter(|row| &arena.path_owners[&row.candidate()] == endpoint)
                            .map(|row| BatchCandidateMatch::new(row.candidate(), ordinal))
                            .collect::<Vec<_>>();
                        if !remapped.is_empty() {
                            stopped = !visitor(&remapped)?;
                        }
                        Ok(!stopped)
                    },
                )?;
                unconditional.include(added.unconditional_completion());
                assert_eq!(
                    added.branch_completions(),
                    &coverage.branch_completions()[ordinal..=ordinal]
                );
                if stopped
                    || added
                        .unconditional_completion()
                        .contains_reason(ResolutionIncompleteReason::Cancelled)
                {
                    break 'requests;
                }
            }
        }
        Ok(BatchCandidateCompletionOutcome::new(
            requests.len(),
            unconditional.finish(),
            coverage.branch_completions().iter().cloned(),
        ))
    }
}

impl BatchResolutionFragmentSource for ClosedForwardSource<'_> {
    /// The persisted selection behind this source names the authority.
    ///
    /// This source also serves the relations the provider has closed, and that
    /// arena grows while the operation runs, so the authority alone does not
    /// say what this source will answer at an arbitrary moment. It does say it
    /// for the answers a caller may memoize: a closed relation is immutable,
    /// and the readiness gate holds every frame until each endpoint it
    /// requested has a closed relation, so a reference's answer is the same
    /// whenever inside one operation it is computed.
    fn selection_authority(&self) -> Option<crate::analyzer::resolution::SeedReadAuthority> {
        self.base.selection_authority()
    }

    fn admits_reverse_reference(&self, reference: SemanticId) -> bool {
        self.base.admits_reverse_reference(reference)
    }

    fn scope_reverse_inventory_completion(
        &self,
        completion: &ResolutionCompletion,
    ) -> ResolutionCompletion {
        self.base.scope_reverse_inventory_completion(completion)
    }

    fn reference_seed(
        &self,
        query: ResolutionQuery,
        cancellation: &CancellationToken,
    ) -> Result<Option<ReferenceSeed>> {
        self.base.reference_seed(query, cancellation)
    }
    fn lookup_reference_seeds(
        &self,
        queries: &[ResolutionQuery],
        cancellation: &CancellationToken,
    ) -> Result<ReferenceSeedReadOutcome> {
        self.base.lookup_reference_seeds(queries, cancellation)
    }
    fn lookup_definition_node(
        &self,
        definition: SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<Option<BindingNodeId>> {
        self.base.lookup_definition_node(definition, cancellation)
    }
    fn lookup_definition_nodes(
        &self,
        definitions: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> Result<Vec<BatchDefinitionNode>> {
        self.base.lookup_definition_nodes(definitions, cancellation)
    }
    fn issue_reverse_reference_seeds(
        &self,
        requests: &[ReverseReferenceSeedRequest],
        cancellation: &CancellationToken,
    ) -> Result<Vec<ReferenceSeed>> {
        // A reverse seed is read from the persisted and transient lexical
        // stores by reference semantic. No closed relation participates, so
        // this delegates exactly like `lookup_definition_nodes`.
        self.base
            .issue_reverse_reference_seeds(requests, cancellation)
    }
    fn visit_reference_seed_batches(
        &self,
        size: usize,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&ReferenceSeedBatch) -> Result<bool>,
    ) -> Result<ResolutionCompletion> {
        self.base
            .visit_reference_seed_batches(size, cancellation, visitor)
    }
    fn classify_endpoint_nodes(
        &self,
        nodes: &[BindingNodeId],
        cancellation: &CancellationToken,
    ) -> Result<Vec<BatchEndpointClassification>> {
        self.base.classify_endpoint_nodes(nodes, cancellation)
    }
    fn match_forward_candidates(
        &self,
        requests: &[BatchCandidateRequest],
        cancellation: &CancellationToken,
    ) -> Result<BatchCandidateOutcome> {
        let mut matches = Vec::new();
        let coverage =
            self.visit_forward_candidate_match_pages(requests, cancellation, &mut |page| {
                matches.extend_from_slice(page);
                Ok(true)
            })?;
        Ok(BatchCandidateOutcome::new(
            requests.len(),
            matches,
            coverage.unconditional_completion().clone(),
            coverage.branch_completions().iter().cloned(),
        ))
    }
    fn visit_forward_candidate_match_pages(
        &self,
        requests: &[BatchCandidateRequest],
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> Result<bool>,
    ) -> Result<BatchCandidateCompletionOutcome> {
        self.visit_forward_candidate_match_pages_limited(
            requests,
            MAX_SOURCE_ROWS_PER_BATCH,
            Some(self.session),
            cancellation,
            visitor,
        )
    }
    fn visit_forward_candidate_match_pages_limited(
        &self,
        requests: &[BatchCandidateRequest],
        limit: usize,
        session: Option<&ResolutionSession>,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> Result<bool>,
    ) -> Result<BatchCandidateCompletionOutcome> {
        assert!(requests.len() <= MAX_SOURCE_ROWS_PER_BATCH);
        assert!((1..=MAX_SOURCE_ROWS_PER_BATCH).contains(&limit));
        // Validate the whole readiness domain before any candidate read. A
        // later missing key must not become an empty branch after a stop.
        for (ordinal, request) in requests.iter().enumerate() {
            assert_eq!(request.request_ordinal(), ordinal);
            if request.endpoint().node() == BindingNodeId::universal_root() && {
                let arena = self.arena.borrow();
                !arena.endpoints.contains_key(request.endpoint())
                    && !arena.base_ready.contains(request.endpoint())
                    && !arena.empty_ready.contains(request.endpoint())
            } {
                return Err(StoreError::new(format!(
                    "selected root relation read before closure: {:?}",
                    request.endpoint()
                )));
            }
        }
        let mut stopped = false;
        let mut cancellation_observed = false;
        // One canonical base visit returns coverage for *all* requests even
        // when the visitor stops. Only a bounded output page is retained.
        let mut coverage = self.base.visit_forward_candidate_match_pages_limited(
            requests,
            limit,
            session,
            cancellation,
            &mut |page| {
                assert!(!stopped, "base emitted after its visitor stopped");
                let mut retained = Vec::with_capacity(page.len());
                {
                    let arena = self.arena.borrow();
                    for (ordinal, request) in requests.iter().enumerate() {
                        let Some(relation) = arena.endpoints.get(request.endpoint()) else {
                            continue;
                        };
                        let candidates = page
                            .iter()
                            .filter(|row| row.request_ordinal() == ordinal)
                            .map(|row| row.candidate())
                            .collect::<BTreeSet<_>>()
                            .into_iter()
                            .collect::<Vec<_>>();
                        if !candidates.is_empty()
                            && !relation.check_base_candidates(
                                self.paths,
                                &candidates,
                                cancellation,
                            )?
                        {
                            cancellation_observed = true;
                            stopped = true;
                            return Ok(false);
                        }
                    }
                    for row in page {
                        let request = &requests[row.request_ordinal()];
                        let keep = if arena.empty_ready.contains(request.endpoint()) {
                            if cancellation.is_cancelled()
                                || !session.unwrap_or(self.session).scope_step()
                            {
                                cancellation_observed = true;
                                stopped = true;
                                return Ok(false);
                            }
                            false
                        } else {
                            match arena.endpoints.get(request.endpoint()) {
                                Some(_) => {
                                    // Match the canonical overlay's pre-filter
                                    // row charge, without mutating the caller token.
                                    if cancellation.is_cancelled()
                                        || !session.unwrap_or(self.session).scope_step()
                                    {
                                        cancellation_observed = true;
                                        stopped = true;
                                        return Ok(false);
                                    }
                                    true
                                }
                                None => true,
                            }
                        };
                        if keep {
                            retained.push(*row);
                        }
                    }
                }
                if !retained.is_empty() {
                    stopped = !visitor(&retained)?;
                }
                Ok(!stopped)
            },
        )?;
        if cancellation_observed {
            coverage = BatchCandidateCompletionOutcome::new(
                requests.len(),
                coverage
                    .unconditional_completion()
                    .combine(&ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::Cancelled,
                    ])),
                coverage.branch_completions().iter().cloned(),
            );
        }
        {
            let mut arena = self.arena.borrow_mut();
            arena.observe_coverage(coverage.unconditional_completion());
            #[cfg(test)]
            arena
                .reads
                .extend(requests.iter().map(|request| request.endpoint().clone()));
        }
        assert_eq!(coverage.branch_completions().len(), requests.len());
        if stopped
            || coverage
                .unconditional_completion()
                .contains_reason(ResolutionIncompleteReason::Cancelled)
        {
            return Ok(coverage);
        }
        let mut unconditional = ResolutionCompletionAccumulator::default();
        unconditional.include(coverage.unconditional_completion());
        for (ordinal, request) in requests.iter().enumerate() {
            // The callback below never visits the base source. It reuses the
            // canonical overlay cursor against exactly this immutable key.
            let arena = self.arena.borrow();
            let Some(relation) = arena.endpoints.get(request.endpoint()) else {
                continue;
            };
            let local = [BatchCandidateRequest::new(0, request.endpoint().clone())];
            let local_coverage = BatchCandidateCompletionOutcome::new(
                1,
                ResolutionCompletion::Complete,
                [coverage.branch_completions()[ordinal].clone()],
            );
            let added = relation.visit_forward_additions(
                self.paths,
                &local,
                local_coverage,
                limit,
                cancellation,
                self.session,
                &mut |page| {
                    assert!(!stopped, "overlay emitted after its visitor stopped");
                    let remapped = page
                        .iter()
                        .map(|row| BatchCandidateMatch::new(row.candidate(), ordinal))
                        .collect::<Vec<_>>();
                    stopped = !visitor(&remapped)?;
                    Ok(!stopped)
                },
            )?;
            unconditional.include(added.unconditional_completion());
            assert_eq!(
                added.branch_completions(),
                &coverage.branch_completions()[ordinal..=ordinal]
            );
            if stopped
                || added
                    .unconditional_completion()
                    .contains_reason(ResolutionIncompleteReason::Cancelled)
            {
                break;
            }
        }
        Ok(BatchCandidateCompletionOutcome::new(
            requests.len(),
            unconditional.finish(),
            coverage.branch_completions().iter().cloned(),
        ))
    }
    fn visit_reverse_candidate_match_pages(
        &self,
        requests: &[BatchCandidateRequest],
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> Result<bool>,
    ) -> Result<BatchCandidateCompletionOutcome> {
        self.visit_reverse_candidate_match_pages_limited(
            requests,
            MAX_SOURCE_ROWS_PER_BATCH,
            cancellation,
            visitor,
        )
    }
    fn match_reverse_candidates(
        &self,
        requests: &[BatchCandidateRequest],
        cancellation: &CancellationToken,
    ) -> Result<BatchCandidateOutcome> {
        let mut matches = Vec::new();
        let coverage = self.visit_reverse_candidate_match_pages_limited(
            requests,
            MAX_SOURCE_ROWS_PER_BATCH,
            cancellation,
            &mut |page| {
                matches.extend_from_slice(page);
                Ok(true)
            },
        )?;
        Ok(BatchCandidateOutcome::new(
            requests.len(),
            matches,
            coverage.unconditional_completion().clone(),
            coverage.branch_completions().iter().cloned(),
        ))
    }
    fn hydrate_candidate_paths(
        &self,
        candidates: &[CandidatePathIdentity],
        cancellation: &CancellationToken,
    ) -> Result<Vec<(CandidatePathIdentity, PartialPath)>> {
        assert!(candidates.len() <= MAX_SOURCE_ROWS_PER_BATCH);
        let arena = self.arena.borrow();
        let mut persisted = Vec::new();
        let mut rows = Vec::new();
        for id in candidates {
            if cancellation.is_cancelled() {
                return Ok(rows);
            }
            match arena.paths.get(id) {
                Some(path) => rows.push((*id, path.clone())),
                None => persisted.push(*id),
            }
        }
        rows.extend(
            self.base
                .hydrate_candidate_paths(&persisted, cancellation)?,
        );
        Ok(rows)
    }
    fn visit_type_transfer_rules(
        &self,
        source_slot: SemanticId,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&TypeTransferRule) -> Result<bool>,
    ) -> Result<ResolutionCompletion> {
        self.base
            .visit_type_transfer_rules(source_slot, cancellation, visitor)
    }
}
