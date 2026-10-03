//! Query-local Java hierarchy branches, replayed before lexical memo publication.
use super::super::fact_source::MAX_TYPED_FACT_REQUESTS_PER_BATCH;
use super::*;

pub(super) struct PendingLexicalHierarchy {
    answers: Vec<(SemanticId, SharedAnswer)>,
    completion: ResolutionCompletion,
    cursor: usize,
    replay: Option<JavaLexicalReplay>,
}

struct JavaLexicalReplay {
    seed: ReferenceSeed,
    /// The overlay composition of the live re-evaluation, memoized on finish.
    rerun_key: Option<JavaLexicalRerunKey>,
    /// Whether the answer being replayed already binds a target.
    resolved: bool,
    shape: HierarchyLookupShape,
    branches: Vec<(SemanticId, CandidatePathIdentity, PartialPath)>,
    cursor: usize,
    group: Option<DemandQualifiedHierarchyGroup>,
    additions: Vec<(CandidatePathIdentity, PartialPath)>,
    removals: Vec<CandidatePathIdentity>,
    overlay: Option<Box<SelectedContextOverlayFragmentSourceBlueprint>>,
    active: Option<DemandForwardBatchFrame>,
}

impl PendingLexicalHierarchy {
    pub(super) fn new(
        answers: Vec<(SemanticId, SharedAnswer)>,
        completion: ResolutionCompletion,
    ) -> Self {
        Self {
            answers,
            completion,
            cursor: 0,
            replay: None,
        }
    }

    pub(super) fn is_finished(&self) -> bool {
        self.cursor == self.answers.len()
    }

    pub(super) fn into_answers(self) -> (Vec<(SemanticId, SharedAnswer)>, ResolutionCompletion) {
        (self.answers, self.completion)
    }

    pub(super) fn current_reference(&self) -> SemanticId {
        self.answers[self.cursor].0
    }

    pub(super) fn pending_requests(&self) -> &[BatchCandidateRequest] {
        self.replay
            .as_ref()
            .map_or(&[], JavaLexicalReplay::pending_requests)
    }

    pub(super) fn active_forward_frame(&mut self) -> Option<&mut DemandForwardBatchFrame> {
        // Overlay replay must not consume base-source prefetched candidate rows.
        let group = self.replay.as_mut()?.group.as_mut()?;
        group.inherited.as_mut()?.active_forward_frame()
    }

    pub(super) fn cancel(mut self, evaluation: &mut FactEvaluation<'_, '_>) {
        evaluation.observe_cancellation_completion(&self.completion);
        for (_, answer) in &self.answers {
            evaluation.observe_resolution_answer_cancellation_evidence(answer);
        }
        if let Some(replay) = self.replay.take() {
            replay.cancel(evaluation);
        }
    }

    pub(super) fn poll(
        &mut self,
        evaluation: &mut FactEvaluation<'_, '_>,
        readiness: &mut impl FnMut(&[BatchCandidateRequest]) -> StoreResult<DemandForwardReadiness>,
    ) -> StoreResult<DemandFactEvaluationPoll> {
        if evaluation.poll_cancelled() {
            return Ok(DemandFactEvaluationPoll::ready(
                evaluation.cancelled_answer(None),
            ));
        }
        if self.is_finished() {
            return Ok(DemandFactEvaluationPoll::Continue);
        }
        let (reference, answer) = &self.answers[self.cursor];
        if self.replay.is_none() {
            self.replay = JavaLexicalReplay::prepare(evaluation, *reference, answer)?;
            if self.replay.is_none() {
                self.cursor += 1;
                return Ok(DemandFactEvaluationPoll::Continue);
            }
        }
        match self.replay.as_mut().unwrap().poll(evaluation, readiness)? {
            DemandQualifiedPoll::Continue => Ok(DemandFactEvaluationPoll::Continue),
            DemandQualifiedPoll::AwaitingDependencies => {
                Ok(DemandFactEvaluationPoll::AwaitingDependencies)
            }
            DemandQualifiedPoll::AwaitingHierarchyReferences(references) => Ok(
                DemandFactEvaluationPoll::AwaitingHierarchyReferences(references),
            ),
            DemandQualifiedPoll::Ready(answer) => {
                if let Some(answer) = answer {
                    self.answers[self.cursor].1 = Arc::new(answer);
                }
                let replay = self.replay.take().unwrap();
                if evaluation.cancellation_observed {
                    replay.cancel(evaluation);
                }
                self.cursor += 1;
                Ok(DemandFactEvaluationPoll::Continue)
            }
        }
    }
}

impl JavaLexicalReplay {
    fn prepare(
        evaluation: &mut FactEvaluation<'_, '_>,
        reference: SemanticId,
        answer: &ResolutionAnswer,
    ) -> StoreResult<Option<Self>> {
        if !evaluation
            .session
            .typed_source
            .selection_has_java_semantics()
        {
            return Ok(None);
        }
        let ResolutionCompletion::Incomplete(reasons) = answer.completion() else {
            return Ok(None);
        };
        let reasons = reasons
            .iter()
            .filter_map(|reason| match reason {
                ResolutionIncompleteReason::UnsupportedSemantic(reason) => Some(*reason),
                _ => None,
            })
            .collect::<Vec<_>>();
        if reasons.is_empty() {
            return Ok(None);
        }
        let read = evaluation
            .session
            .gap_reason_provenance_for_reasons(&reasons)?;
        let Some(provenance) = evaluation.accept_session_read(read) else {
            return Ok(None);
        };
        let gaps = provenance
            .into_iter()
            .map(|row| *row.get(evaluation.session))
            .filter(|row| {
                row.origin()
                    == LoweringGapOrigin::Extracted(
                        ResolutionGapKind::UnsupportedHierarchyTraversal,
                    )
            })
            .collect::<Vec<_>>();
        if gaps.is_empty() {
            return Ok(None);
        }
        let mut owners = HashMap::<SemanticId, BTreeSet<SemanticId>>::default();
        let mut reason_keys = gaps.iter().map(|gap| gap.reason()).collect::<Vec<_>>();
        reason_keys.sort_unstable();
        reason_keys.dedup();
        for chunk in reason_keys.chunks(MAX_TYPED_FACT_REQUESTS_PER_BATCH) {
            let mut callback = |page: &[SelectedTypedRow<LoweredDefinitionPropertyGap>]| {
                for row in page {
                    if row.row().kind() == ResolutionGapKind::UnsupportedHierarchyTraversal {
                        owners
                            .entry(row.row().reason_semantic())
                            .or_default()
                            .insert(row.row().definition());
                    }
                }
                Ok(!evaluation.cancellation.is_cancelled())
            };
            let mut visitor = match evaluation.session.resolution_session {
                Some(session) => TypedFactPageVisitor::with_maximum_rows_in_session(
                    &mut callback,
                    MAX_TYPED_FACT_ROWS_PER_PAGE,
                    session,
                ),
                None => TypedFactPageVisitor::new(&mut callback),
            };
            let outcome = evaluation
                .session
                .typed_source
                .visit_definition_property_gap_pages_for_reasons(
                    TypedFactRequest::new(chunk),
                    evaluation.cancellation,
                    &mut visitor,
                )?;
            evaluation.observe_cancellation_completion(outcome.evidence());
            if !outcome.is_exhausted() {
                evaluation.cancellation_observed = true;
                return Ok(None);
            }
        }
        let mut definitions = owners.values().flatten().copied().collect::<Vec<_>>();
        definitions.sort_unstable();
        definitions.dedup();
        let Some(java) = evaluation
            .session
            .typed_source
            .java_inheritance_declarations(&definitions, evaluation.cancellation)?
        else {
            evaluation.cancellation_observed = true;
            return Ok(None);
        };
        let java = java
            .into_iter()
            .map(|row| row.definition)
            .collect::<HashSet<_>>();
        owners.retain(|_, candidates| {
            candidates.retain(|owner| java.contains(owner));
            !candidates.is_empty()
        });
        if owners.is_empty() {
            return Ok(None);
        }
        let Some(seed) = evaluation
            .session
            .lexical_source
            .reference_seed(ResolutionQuery::new(reference), evaluation.cancellation)?
        else {
            return Ok(None);
        };
        let Some(metadata) = seed.site_metadata() else {
            return Ok(None);
        };
        if !metadata.unqualified()
            || !matches!(
                metadata.namespace(),
                ResolutionNamespace::Type | ResolutionNamespace::Value
            )
        {
            return Ok(None);
        }
        // Source-issued reference paths carry the lookup symbol. Never recover it
        // from spelling or turn the whole reference into an enclosing-type lookup.
        let paths = evaluation.lexical_paths_at(closed_endpoint(seed.node(), []))?;
        let mut lookups = BTreeSet::new();
        for (_, path) in paths {
            if let [symbol] = path.end().symbols().fixed()
                && symbol.scopes().is_none()
            {
                lookups.insert(symbol.symbol());
            }
        }
        if lookups.len() != 1 {
            return Ok(None);
        }
        let lookup = lookups.pop_first().unwrap();
        let mut branches = Vec::new();
        for chunk in gaps.chunks(MAX_TYPED_FACT_REQUESTS_PER_BATCH) {
            let Some(terminals) = evaluation
                .session
                .typed_source
                .hierarchy_terminal_nodes(chunk, evaluation.cancellation)?
            else {
                evaluation.cancellation_observed = true;
                return Ok(None);
            };
            for (reason, terminal) in terminals {
                let Some(candidates) = owners.get(&reason) else {
                    continue;
                };
                let definitions = candidates.iter().copied().collect::<Vec<_>>();
                let read = evaluation
                    .session
                    .member_scopes_for_definitions(&definitions)?;
                let Some(scopes) = evaluation.accept_session_read(read) else {
                    return Ok(None);
                };
                for scope in scopes {
                    if evaluation.poll_cancelled() {
                        return Ok(None);
                    }
                    let row = scope.get(evaluation.session).row();
                    let owner = row.definition();
                    let head = row.scope_head();
                    // A forward point operation has no reverse inventory. This
                    // exact head/lookup seek reuses the already visited lexical
                    // relation; the terminal distinguishes the source obligation.
                    for (identity, path) in
                        evaluation.lexical_paths_at(closed_endpoint(head, [lookup]))?
                    {
                        if path.end().node() == terminal {
                            assert_eq!(path.start().node(), head);
                            evaluation.observe_cancellation_completion(path.completion());
                            branches.push((owner, identity, path));
                        }
                    }
                }
            }
        }
        if branches.is_empty() || evaluation.poll_cancelled() {
            return Ok(None);
        }
        branches.sort_unstable_by_key(|(_, identity, _)| *identity);
        branches.dedup_by_key(|(_, identity, _)| *identity);
        Ok(Some(Self {
            seed,
            rerun_key: None,
            resolved: !answer.targets().is_empty(),
            shape: HierarchyLookupShape::new(
                lookup,
                metadata.namespace(),
                if metadata.namespace() == ResolutionNamespace::Type {
                    QualifierCategory::Type
                } else {
                    QualifierCategory::Runtime
                },
                0,
            ),
            branches,
            cursor: 0,
            group: None,
            additions: Vec::new(),
            removals: Vec::new(),
            overlay: None,
            active: None,
        }))
    }

    fn pending_requests(&self) -> &[BatchCandidateRequest] {
        if let Some(group) = &self.group {
            return group.inherited.as_ref().map_or_else(
                || group.local.pending_requests(),
                |frame| frame.pending_requests(),
            );
        }
        self.active
            .as_ref()
            .map_or(&[], DemandForwardBatchFrame::pending_requests)
    }

    fn cancel(self, evaluation: &mut FactEvaluation<'_, '_>) {
        for (_, _, path) in &self.branches {
            evaluation.observe_cancellation_completion(path.completion());
        }
        for (_, path) in &self.additions {
            evaluation.observe_cancellation_completion(path.completion());
        }
        if let Some(group) = self.group
            && let Some(inherited) = group.inherited
        {
            inherited.cancel(evaluation);
        }
        if let Some(active) = self.active {
            let (answers, completion, metrics) = active.cancel().into_parts();
            evaluation.binding_metrics.accumulate(metrics);
            evaluation.observe_cancellation_completion(&completion);
            for answer in answers.into_vec() {
                evaluation.observe_resolution_answer_cancellation_evidence(&answer.into_parts().1);
            }
        }
    }

    fn poll(
        &mut self,
        evaluation: &mut FactEvaluation<'_, '_>,
        readiness: &mut impl FnMut(&[BatchCandidateRequest]) -> StoreResult<DemandForwardReadiness>,
    ) -> StoreResult<DemandQualifiedPoll> {
        use DemandQualifiedPoll::{
            AwaitingDependencies, AwaitingHierarchyReferences, Continue, Ready,
        };
        if let Some(group) = &mut self.group {
            let selected = if let Some(inherited) = &mut group.inherited {
                match inherited.poll(evaluation, readiness)? {
                    DemandHierarchySelectionPoll::Continue => return Ok(Continue),
                    DemandHierarchySelectionPoll::AwaitingDependencies => {
                        return Ok(AwaitingDependencies);
                    }
                    DemandHierarchySelectionPoll::AwaitingHierarchyReferences(refs) => {
                        return Ok(AwaitingHierarchyReferences(refs));
                    }
                    DemandHierarchySelectionPoll::Ready(None) => return Ok(Ready(None)),
                    DemandHierarchySelectionPoll::Ready(Some(selected)) => selected,
                }
            } else {
                match group.local.poll(evaluation, readiness)? {
                    DemandHierarchyLocalPoll::Continue => return Ok(Continue),
                    DemandHierarchyLocalPoll::AwaitingDependencies => {
                        return Ok(AwaitingDependencies);
                    }
                    DemandHierarchyLocalPoll::AwaitingHierarchyReferences(refs) => {
                        return Ok(AwaitingHierarchyReferences(refs));
                    }
                    DemandHierarchyLocalPoll::Ready(false) => return Ok(Ready(None)),
                    DemandHierarchyLocalPoll::Ready(true) => match evaluation
                        .select_direct_hierarchy_candidates(group.roots.take().unwrap())
                    {
                        None => return Ok(Ready(None)),
                        Some(DirectHierarchySelection::Ready(selected)) => selected,
                        Some(DirectHierarchySelection::Inherited(roots)) => {
                            group.inherited = DemandInheritedHierarchyFrame::new(evaluation, roots);
                            return Ok(Continue);
                        }
                    },
                }
            };
            let HierarchySelectionState::Ready(selected) =
                evaluation.materialize_hierarchy_candidate_expressions(selected)?
            else {
                return Ok(Ready(None));
            };
            let (owner, identity, branch) = &self.branches[self.cursor];
            // JLS 4.3.2: java.lang.Object declares methods only. A member-type
            // lookup whose inherited walk is sealed except for the implicit
            // unindexed Object superclass has an exhaustive negative answer at
            // this owner, so the raw hierarchy branch is retired without a
            // replacement. Only a resolved answer can become complete this way:
            // a lookup nothing answers still reaches the compilation unit's
            // placement boundary, so it keeps this reason conservatively and
            // is not re-evaluated.
            if self.resolved
                && (selected.owners.is_empty()
                    || self.shape.namespace == ResolutionNamespace::Value)
            {
                let Some(only_object) =
                    evaluation.java_hierarchy_open_only_at_implicit_object(*owner)?
                else {
                    return Ok(Ready(None));
                };
                if only_object {
                    self.removals.push(*identity);
                    self.group = None;
                    self.cursor += 1;
                    return Ok(Continue);
                }
            }
            let (paths, remove_branch) =
                evaluation.java_lexical_bridges(self.shape, *identity, branch, selected)?;
            if remove_branch {
                self.removals.push(*identity);
            }
            self.additions.extend(paths);
            self.group = None;
            self.cursor += 1;
            return Ok(Continue);
        }
        if self.cursor < self.branches.len() {
            let owner = self.branches[self.cursor].0;
            let roots = [HierarchyRoot {
                owner,
                value: ResolutionSlotValue::type_object(ResolutionTypeRef::new(owner, 0)),
                route_ordinal: 0,
            }];
            let Some(roots) = evaluation.prepare_hierarchy_roots(self.shape, &roots) else {
                return Ok(Ready(None));
            };
            let Some(local) = DemandHierarchyLocalFrame::new(evaluation, &roots.root_keys) else {
                return Ok(Ready(None));
            };
            self.group = Some(DemandQualifiedHierarchyGroup {
                precedence: 0,
                shape: self.shape,
                roots: Some(roots),
                local,
                inherited: None,
            });
            return Ok(Continue);
        }
        if self.overlay.is_none() {
            // A retired branch can be the maximal terminal that kept a later
            // terminal open, so removals are re-evaluated exactly, never
            // subtracted from the previous answer.
            if self.additions.is_empty() && self.removals.is_empty() {
                return Ok(Ready(None));
            }
            self.additions
                .sort_unstable_by_key(|(identity, _)| *identity);
            self.removals.sort_unstable();
            self.removals.dedup();
            let key = JavaLexicalRerunKey {
                reference: self.seed.reference(),
                removals: self.removals.clone().into_boxed_slice(),
                additions: self
                    .additions
                    .iter()
                    .map(|(identity, _)| *identity)
                    .collect(),
            };
            if let Some(answer) = evaluation.hierarchy.java_lexical_reruns.get(&key).cloned() {
                self.removals.clear();
                self.additions.clear();
                evaluation.observe_resolution_answer_cancellation_evidence(&answer);
                return Ok(Ready(Some(answer)));
            }
            self.rerun_key = Some(key);
            let construction = SelectedContextOverlayFragmentSourceBlueprint::from_parts(
                std::mem::take(&mut self.removals).into_boxed_slice(),
                Box::new([]),
                std::mem::take(&mut self.additions).into_boxed_slice(),
                Box::new([]),
                Box::new([]),
                ResolutionCompletion::Complete,
                evaluation.cancellation,
            )?;
            match construction {
                SelectedContextOverlayFragmentSourceBlueprintConstruction::Ready(overlay) => {
                    self.overlay = Some(overlay)
                }
                SelectedContextOverlayFragmentSourceBlueprintConstruction::Cancelled {
                    cancellation_completion,
                    ..
                } => {
                    evaluation.observe_cancellation_completion(&cancellation_completion);
                    evaluation.cancellation_observed = true;
                    return Ok(Ready(None));
                }
            }
            let source = self
                .overlay
                .as_ref()
                .unwrap()
                .open(evaluation.session.lexical_source);
            let engine = BatchResolutionEngine::maybe_bounded(
                &source,
                evaluation.session.resolution_session,
            );
            match DemandForwardBatchFrame::start_reference_batch(
                &engine,
                &ReferenceSeedBatch::single(self.seed.clone()),
                evaluation.cancellation,
            ) {
                DemandForwardBatchStart::Running(active) => {
                    self.active = Some(*active);
                    return Ok(Continue);
                }
                DemandForwardBatchStart::Ready(answer) => return self.finish(evaluation, answer),
            }
        }
        let source = self
            .overlay
            .as_ref()
            .unwrap()
            .open(evaluation.session.lexical_source);
        let engine =
            BatchResolutionEngine::maybe_bounded(&source, evaluation.session.resolution_session);
        match self.active.as_mut().unwrap().poll(
            &engine,
            None,
            evaluation.cancellation,
            readiness,
        )? {
            DemandForwardBatchPoll::Continue => Ok(Continue),
            DemandForwardBatchPoll::AwaitingDependencies => Ok(AwaitingDependencies),
            DemandForwardBatchPoll::Ready(answer) => {
                self.active = None;
                self.finish(evaluation, answer)
            }
        }
    }

    fn finish(
        &self,
        evaluation: &mut FactEvaluation<'_, '_>,
        batch: super::super::batch::ReferenceBatchAnswer,
    ) -> StoreResult<DemandQualifiedPoll> {
        let (answers, completion, metrics) = batch.into_parts();
        evaluation.binding_metrics.accumulate(metrics);
        evaluation.observe_cancellation_completion(&completion);
        assert_eq!(answers.len(), 1);
        let (reference, answer) = answers.into_vec().pop().unwrap().into_parts();
        assert_eq!(reference, self.seed.reference());
        evaluation.observe_resolution_answer_cancellation_evidence(&answer);
        if !evaluation.cancellation_observed {
            let key = self
                .rerun_key
                .clone()
                .expect("a re-evaluation records its overlay composition");
            evaluation
                .hierarchy
                .java_lexical_reruns
                .insert(key, answer.clone());
        }
        Ok(DemandQualifiedPoll::Ready(Some(answer)))
    }
}

impl FactEvaluation<'_, '_> {
    // The eager source is already assembled. Drive the same provisional frame
    // before caching the answer, while hierarchy dependencies still use the
    // iterative task scheduler rather than recursive eager evaluation.
    pub(super) fn replay_eager_java_lexical(
        &mut self,
        reference: SemanticId,
        answer: SharedAnswer,
    ) -> StoreResult<Option<SharedAnswer>> {
        if !matches!(answer.completion(), ResolutionCompletion::Incomplete(reasons)
            if reasons.iter().any(|reason| matches!(reason, ResolutionIncompleteReason::UnsupportedSemantic(_))))
        {
            return Ok(Some(answer));
        }
        let mut frame =
            PendingLexicalHierarchy::new(vec![(reference, answer)], ResolutionCompletion::Complete);
        while !frame.is_finished() {
            let result = frame.poll(self, &mut |_| Ok(DemandForwardReadiness::Ready))?;
            if self.cancellation_observed || self.cancellation.is_cancelled() {
                frame.cancel(self);
                return Ok(None);
            }
            match result {
                DemandFactEvaluationPoll::Continue => {}
                DemandFactEvaluationPoll::AwaitingHierarchyReferences(references) => {
                    if !self.ensure_qualified_hierarchy_reference_answers(
                        &references.into_iter().collect(),
                    )? {
                        frame.cancel(self);
                        return Ok(None);
                    }
                }
                DemandFactEvaluationPoll::AwaitingDependencies => {
                    unreachable!("assembled lexical source dependencies are ready")
                }
                DemandFactEvaluationPoll::AwaitingDemandedReference(_) => {
                    unreachable!("lexical replay does not claim demanded references")
                }
                DemandFactEvaluationPoll::Ready(_) => {
                    unreachable!("lexical replay returns a terminal only on cancellation")
                }
            }
        }
        let (mut answers, _) = frame.into_answers();
        assert_eq!(answers.len(), 1);
        let (returned_reference, answer) = answers.pop().unwrap();
        assert_eq!(returned_reference, reference);
        Ok(Some(answer))
    }

    fn lexical_paths_at(
        &mut self,
        endpoint: EndpointSignature,
    ) -> StoreResult<Vec<(CandidatePathIdentity, PartialPath)>> {
        let matches = self.session.lexical_source.match_forward_candidates(
            &[BatchCandidateRequest::new(0, endpoint)],
            self.cancellation,
        )?;
        self.observe_cancellation_completion(matches.unconditional_completion());
        for completion in matches.branch_completions() {
            self.observe_cancellation_completion(completion);
        }
        let candidates = matches
            .matches()
            .iter()
            .map(|row| row.candidate())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let mut paths = Vec::new();
        for chunk in candidates.chunks(MAX_SOURCE_ROWS_PER_BATCH) {
            if !self.session.charge_scope_steps(chunk.len()) || self.poll_cancelled() {
                self.cancellation_observed = true;
                break;
            }
            let returned = self
                .session
                .lexical_source
                .hydrate_candidate_paths(chunk, self.cancellation)?;
            // A source can return evidence together with cancellation. Ledger
            // every returned path before any caller abandons provisional work.
            for (_, path) in &returned {
                self.observe_cancellation_completion(path.completion());
            }
            paths.extend(returned);
        }
        Ok(paths)
    }

    /// A transferred single frontier must name the source node that owns its
    /// remaining request. Equal diagnostic reasons alone are not lookup identity.
    /// Compound evidence does not identify one endpoint and retains its branch.
    pub(super) fn java_inherited_frontier_endpoint(
        &mut self,
        original: &EndpointSignature,
        completion: &ResolutionCompletion,
    ) -> StoreResult<Option<EndpointSignature>> {
        let ResolutionCompletion::Incomplete(reasons) = completion else {
            return Ok(Some(original.clone()));
        };
        let mut reasons = reasons.iter();
        let Some(&ResolutionIncompleteReason::UnsupportedSemantic(reason)) = reasons.next() else {
            return Ok(Some(original.clone()));
        };
        if reasons.next().is_some() {
            return Ok(Some(original.clone()));
        }
        let read = self.session.gap_reason_provenance_for_reasons(&[reason])?;
        let Some(provenance) = self.accept_session_read(read) else {
            return Ok(None);
        };
        let provenance = provenance
            .into_iter()
            .map(|row| *row.get(self.session))
            .filter(|row| {
                row.origin()
                    == LoweringGapOrigin::Extracted(
                        ResolutionGapKind::UnsupportedHierarchyTraversal,
                    )
            })
            .collect::<Vec<_>>();
        let Some(terminals) = self
            .session
            .typed_source
            .hierarchy_terminal_nodes(&provenance, self.cancellation)?
        else {
            self.cancellation_observed = true;
            return Ok(None);
        };
        let [(_, node)] = terminals.as_slice() else {
            return Ok(Some(original.clone()));
        };
        Ok(Some(EndpointSignature::new_scoped(
            *node,
            original.symbols().clone(),
            original.scopes().clone(),
        )))
    }

    /// Returns the replacement paths for one source-owned hierarchy branch and
    /// whether that branch is retired.
    fn java_lexical_bridges(
        &mut self,
        shape: HierarchyLookupShape,
        branch_identity: CandidatePathIdentity,
        branch: &PartialPath,
        selection: HierarchySelection,
    ) -> StoreResult<(Vec<(CandidatePathIdentity, PartialPath)>, bool)> {
        let mut additions = Vec::new();
        let Some(transfer) =
            self.hierarchy
                .transfers
                .flatten(&selection.transfer, u32::MAX, &mut || {
                    poll_cancelled(self.cancellation, &mut self.work)
                })
        else {
            self.cancellation_observed = true;
            return Ok((additions, false));
        };
        let mut transferred = BTreeSet::new();
        if let ResolutionCompletion::Incomplete(reasons) = transfer {
            for reason in reasons.iter() {
                if self.poll_cancelled() {
                    return Ok((additions, false));
                }
                let ResolutionIncompleteReason::UnsupportedSemantic(reason) = reason else {
                    unreachable!("hierarchy transfers contain only semantic reasons");
                };
                transferred.insert(*reason);
            }
        }
        // Transfer applies only to this exact source-owned branch. Its residual
        // reasons and the selected hierarchy evidence remain on each replacement.
        let Some(branch_completion) =
            self.completion_after_hierarchy_transfer(branch.completion(), &transferred)
        else {
            return Ok((additions, false));
        };
        let replaces_branch = branch_completion != *branch.completion();
        let Some(completion) =
            self.hierarchy
                .evidence
                .flatten(&selection.evidence, u32::MAX, &mut || {
                    poll_cancelled(self.cancellation, &mut self.work)
                })
        else {
            self.cancellation_observed = true;
            return Ok((additions, false));
        };
        // An inherited lookup can reach a different unresolved frontier without
        // finding a declaration. Preserve that frontier on the same lexical
        // branch instead of retaining the already-traversed subtype's gap.
        // This is not a proof of absence: only incomplete evidence is replayed.
        if selection.owners.is_empty() && replaces_branch {
            let normalized = branch_completion.combine(&completion);
            if normalized != *branch.completion() && normalized != ResolutionCompletion::Complete {
                let Some(endpoint) =
                    self.java_inherited_frontier_endpoint(branch.end(), &normalized)?
                else {
                    return Ok((additions, false));
                };
                let Some(path) = PartialPath::new_with_poll(
                    branch.start().clone(),
                    endpoint,
                    branch.precedence().to_vec().into_boxed_slice(),
                    branch.witness().to_vec().into_boxed_slice(),
                    normalized,
                    &mut || self.poll_cancelled(),
                ) else {
                    return Ok((additions, false));
                };
                let mut hash = CanonicalHasher::new(b"bifrost-java-lexical-hierarchy-frontier:v1");
                hash.field("branch", &branch_identity.path().as_bytes());
                hash.field("branch-fragment", &branch_identity.fragment().as_bytes());
                hash.field("lookup", &shape.lookup.as_bytes());
                let path_id = self.hierarchy.operation_path(hash.finish());
                additions.push((
                    CandidatePathIdentity::new(branch_identity.fragment(), path_id),
                    path,
                ));
            }
        }
        // Do not erase an unresolved branch merely because another path binds.
        // Replacement requires exact transfer ownership and a reconstructed
        // declaration path. Unknown superclass evidence survives in completion.
        for selected in selection.owners {
            if self.poll_cancelled() {
                break;
            }
            let scope_read = self
                .session
                .member_scopes_for_definitions(&[selected.owner])?;
            let Some(scopes) = self.accept_session_read(scope_read) else {
                break;
            };
            for scope in scopes {
                let head = scope.get(self.session).row().scope_head();
                let paths = self.lexical_paths_at(closed_endpoint(head, [shape.lookup]))?;
                for (identity, path) in paths {
                    if self.poll_cancelled() {
                        return Ok((additions, false));
                    }
                    let mut witness = branch.witness().to_vec();
                    for &ancestor in selected.ancestry.iter() {
                        if self.poll_cancelled() {
                            return Ok((additions, false));
                        }
                        witness.push(WitnessStep::Candidate {
                            semantic: ancestor,
                            outcome: CandidateOutcome::Selected,
                        });
                    }
                    let prefix = PartialPath::new(
                        closed_endpoint(branch.start().node(), [shape.lookup]),
                        closed_endpoint(head, [shape.lookup]),
                        branch.precedence().to_vec(),
                        witness,
                        branch_completion.clone(),
                    );
                    let prefix = prefix.with_additional_completion(&completion);
                    let Some(Ok(composed)) =
                        prefix.concatenate_with_poll(&path, &mut || self.poll_cancelled())
                    else {
                        continue;
                    };
                    if !endpoint_is_balanced(composed.end()) {
                        continue;
                    }
                    let classifications = self
                        .session
                        .lexical_source
                        .classify_endpoint_nodes(&[composed.end().node()], self.cancellation)?;
                    if self.poll_cancelled() {
                        return Ok((additions, false));
                    }
                    assert_eq!(classifications.len(), 1);
                    assert_eq!(classifications[0].node(), composed.end().node());
                    let Some(definition) = classifications[0].definition() else {
                        continue;
                    };
                    let local = &self.hierarchy.local_nodes[&HierarchyNodeKey {
                        shape,
                        owner: selected.owner,
                    }];
                    if !local.direct_definitions.contains(&definition) {
                        continue;
                    }
                    let mut hash =
                        CanonicalHasher::new(b"bifrost-java-lexical-hierarchy-bridge:v1");
                    hash.field("branch", &branch_identity.path().as_bytes());
                    hash.field("branch-fragment", &branch_identity.fragment().as_bytes());
                    hash.field("candidate", &identity.path().as_bytes());
                    hash.field("candidate-fragment", &identity.fragment().as_bytes());
                    hash.field("lookup", &shape.lookup.as_bytes());
                    let path_id = self.hierarchy.operation_path(hash.finish());
                    additions.push((
                        CandidatePathIdentity::new(branch_identity.fragment(), path_id),
                        composed,
                    ));
                }
            }
        }
        let remove_branch = replaces_branch && !additions.is_empty();
        Ok((additions, remove_branch))
    }

    /// Whether every supertype edge reachable from `owner` is resolved, apart
    /// from implicit `java.lang.Object` superclass edges whose absolute route
    /// is unindexed. `None` reports cancellation. An owner without a sealed
    /// edge node, an ambiguous edge, or an unresolved authored supertype makes
    /// this `false`.
    fn java_hierarchy_open_only_at_implicit_object(
        &mut self,
        owner: SemanticId,
    ) -> StoreResult<Option<bool>> {
        let mut pending = vec![owner];
        let mut visited = HashSet::default();
        while let Some(current) = pending.pop() {
            if self.poll_cancelled() {
                return Ok(None);
            }
            if !visited.insert(current) {
                continue;
            }
            let Some(node) = self.hierarchy.edge_node_snapshot(current) else {
                return Ok(Some(false));
            };
            if !matches!(node.evidence, HierarchyEvidence::Complete) {
                return Ok(Some(false));
            }
            let mut unresolved = Vec::new();
            for ordinal in 0..node.edge_count {
                if self.poll_cancelled() {
                    return Ok(None);
                }
                let edge = self.hierarchy.edge_snapshot(current, ordinal);
                match edge.target_count {
                    1 => pending.push(self.hierarchy.edge_target(current, ordinal, 0)),
                    0 => unresolved.push(edge.reference),
                    _ => return Ok(Some(false)),
                }
            }
            if unresolved.is_empty() {
                continue;
            }
            let read = self.session.supertypes_for_definitions(&[current])?;
            let Some(supertypes) = self.accept_session_read(read) else {
                return Ok(None);
            };
            let implicit = supertypes
                .iter()
                .map(|row| row.get(self.session).row())
                .filter(|row| row.kind() == ResolutionSupertypeKind::ImplicitSuperclass)
                .map(|row| row.reference())
                .collect::<HashSet<_>>();
            if unresolved
                .iter()
                .any(|reference| !implicit.contains(reference))
            {
                return Ok(Some(false));
            }
        }
        Ok(Some(true))
    }
}
