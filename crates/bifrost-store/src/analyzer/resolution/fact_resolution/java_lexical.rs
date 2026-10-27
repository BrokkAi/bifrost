//! Query-local JVM hierarchy branches, replayed before lexical memo publication.
use super::super::fact_source::{
    MAX_TYPED_FACT_REQUESTS_PER_BATCH, language_uses_enclosing_companion_members,
};
use super::*;
use crate::analyzer::resolution::language_has_jvm_semantics;

#[derive(Debug)]
pub(super) struct JavaLexicalMemberOrigin {
    pub(super) owner: FactMemberOwner,
    pub(super) steps: Box<[WitnessStep]>,
}

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
    /// Whether the lookup selected a source, external or intrinsic binding.
    resolved: bool,
    branches: Vec<(
        HierarchyLookupShape,
        SemanticId,
        CandidatePathIdentity,
        PartialPath,
    )>,
    cursor: usize,
    group: Option<DemandHierarchyOwnerFrame>,
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
        let has_jvm_selection = evaluation
            .session
            .typed_source
            .selection_has_jvm_semantics();
        let read = evaluation
            .session
            .gap_reason_provenance_for_reasons(&reasons)?;
        let Some(provenance) = evaluation.accept_session_read(read) else {
            return Ok(None);
        };
        let provenance = provenance
            .into_iter()
            .map(|row| *row.get(evaluation.session))
            .collect::<Vec<_>>();
        let call_applicability_reasons = provenance
            .iter()
            .filter(|row| {
                row.origin()
                    == LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedCallApplicability)
            })
            .map(|row| row.reason())
            .collect::<BTreeSet<_>>();
        let gaps = provenance
            .iter()
            .copied()
            .filter(|row| {
                row.origin()
                    == LoweringGapOrigin::Extracted(
                        ResolutionGapKind::UnsupportedHierarchyTraversal,
                    )
            })
            .collect::<Vec<_>>();
        if gaps.is_empty() && call_applicability_reasons.is_empty() {
            return Ok(None);
        }
        let read = evaluation.session.calls_for_references(&[reference])?;
        let Some(calls) = evaluation.accept_session_read(read) else {
            return Ok(None);
        };
        if calls.iter().any(|call| {
            let call = call.get(evaluation.session).row();
            call.callee_reference() == reference && implicit_receiver_call(call)
        }) {
            return Ok(None);
        }
        let has_jvm_call = calls.iter().any(|call| {
            let call = call.get(evaluation.session).row();
            call.callee_reference() == reference
                && (language_has_jvm_semantics(call.language())
                    || (call.language() == Language::None && has_jvm_selection))
        });
        let applicability_call = calls.iter().any(|call| {
            let call = call.get(evaluation.session).row();
            call.callee_reference() == reference
                && call_applicability_reasons.contains(&call.applicability_reason())
                && matches!(call.language(), Language::Kotlin | Language::Scala)
        });
        let companion_member_call = calls.iter().any(|call| {
            let call = call.get(evaluation.session).row();
            call.callee_reference() == reference
                && language_uses_enclosing_companion_members(call.language())
        });
        if gaps.is_empty() && !applicability_call {
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
        if !gaps.is_empty() {
            let definitions = owners.values().flatten().copied().collect::<Vec<_>>();
            let Some(jvm_declarations) = evaluation
                .session
                .typed_source
                .java_inheritance_declarations(&definitions, evaluation.cancellation)?
            else {
                evaluation.cancellation_observed = true;
                return Ok(None);
            };
            let jvm_declarations = jvm_declarations
                .into_iter()
                .map(|row| row.definition)
                .collect::<HashSet<_>>();
            owners.retain(|_, candidates| {
                candidates.retain(|owner| jvm_declarations.contains(owner));
                !candidates.is_empty()
            });
            if owners.is_empty() {
                return Ok(None);
            }
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
                ResolutionNamespace::Type
                    | ResolutionNamespace::Value
                    | ResolutionNamespace::Callable
                    | ResolutionNamespace::TypeOrValue
            )
        {
            return Ok(None);
        }
        if gaps.is_empty()
            && !matches!(
                metadata.namespace(),
                ResolutionNamespace::Value | ResolutionNamespace::Callable
            )
        {
            return Ok(None);
        }
        let lookups = evaluation.reference_lookup_symbols(seed.node())?;
        if lookups.is_empty() {
            return Ok(None);
        }
        // Traversal and applicability placeholders do not change the enclosing
        // template's nominal identity. Infer it from declaration ownership even
        // while those later phases are pending.
        let mut current_type = {
            // This replay has the reference seed, but it does not add it to the
            // evaluation's root or qualified-seed metadata cache.
            let Some(Some(reference_owner)) = metadata.reference_owner() else {
                return Ok(None);
            };
            let scope_read = evaluation
                .session
                .member_scopes_for_definitions(&[reference_owner])?;
            let Some(scopes) = evaluation.accept_session_read(scope_read) else {
                return Ok(None);
            };
            let owner_read = evaluation
                .session
                .member_owners_for_definitions(&[reference_owner])?;
            let Some(owners) = evaluation.accept_session_read(owner_read) else {
                return Ok(None);
            };
            if scopes.len() == 1
                && scopes[0].get(evaluation.session).row().definition() == reference_owner
            {
                Some(reference_owner)
            } else if !scopes.is_empty()
                || owners.len() != 1
                || owners[0].get(evaluation.session).row().definition() != reference_owner
            {
                None
            } else {
                Some(owners[0].get(evaluation.session).row().owner_definition())
            }
        };
        if let Some(owner) = current_type
            && provenance.iter().any(|gap| {
                gap.origin()
                    == LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedScopeOrBinder)
                    && super::super::fact_lowering::site_semantic(gap.fragment(), gap.source_site())
                        == owner
            })
        {
            current_type = None;
        }
        let current_type_is_jvm = if let Some(current_type) = current_type {
            let Some(jvm_declarations) = evaluation
                .session
                .typed_source
                .java_inheritance_declarations(&[current_type], evaluation.cancellation)?
            else {
                evaluation.cancellation_observed = true;
                return Ok(None);
            };
            jvm_declarations
                .iter()
                .any(|declaration| declaration.definition == current_type)
        } else {
            false
        };
        if gaps.is_empty() && !current_type_is_jvm {
            return Ok(None);
        }
        if !current_type_is_jvm {
            current_type = None;
        }
        if lookups.len() != 1
            && (!matches!(
                metadata.namespace(),
                ResolutionNamespace::Value
                    | ResolutionNamespace::Callable
                    | ResolutionNamespace::TypeOrValue
            ) || (!matches!(metadata.namespace(), ResolutionNamespace::TypeOrValue)
                && !calls.iter().any(|call| {
                    let call = call.get(evaluation.session).row();
                    call.callee_reference() == reference
                        && matches!(call.language(), Language::Kotlin | Language::Scala)
                })))
        {
            return Ok(None);
        }
        let callable_overload_set = has_jvm_call;
        if metadata.namespace() == ResolutionNamespace::Callable && !callable_overload_set {
            return Ok(None);
        }
        let call_namespace_ladder = calls.iter().any(|call| {
            let call = call.get(evaluation.session).row();
            call.callee_reference() == reference
                && super::super::fact_lowering::call_target_lookup_routes(call.language(), true)
                    .is_some()
        });
        let mut shapes = Vec::with_capacity(lookups.len());
        for lookup in lookups {
            // Scala calls carry Callable, Value and Type lookup routes. Each
            // route keeps its own namespace, including singleton Value fields.
            let namespace = if metadata.namespace() == ResolutionNamespace::TypeOrValue
                || call_namespace_ladder
            {
                let Some(namespace) = evaluation
                    .session
                    .typed_source
                    .lookup_namespace(lookup, evaluation.cancellation)?
                else {
                    return Ok(None);
                };
                namespace
            } else {
                metadata.namespace()
            };
            let shape = HierarchyLookupShape::new(
                lookup,
                namespace,
                if namespace == ResolutionNamespace::Type {
                    QualifierCategory::Type
                } else {
                    QualifierCategory::Runtime
                },
                0,
            );
            shapes.push(
                if callable_overload_set
                    && (!call_namespace_ladder || namespace == ResolutionNamespace::Callable)
                {
                    shape.with_callable_overload_set()
                } else {
                    shape
                },
            );
        }
        let mut branches = Vec::new();
        let mut enclosing_type_branches = Vec::new();
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
                    for &shape in &shapes {
                        for (identity, path) in
                            evaluation.lexical_paths_at(closed_endpoint(head, [shape.lookup]))?
                        {
                            if path.end().node() == terminal {
                                assert_eq!(path.start().node(), head);
                                evaluation.observe_cancellation_completion(path.completion());
                                branches.push((shape, owner, identity, path));
                            }
                        }
                    }
                }
            }
        }
        if applicability_call && current_type_is_jvm {
            let owner = current_type.expect("a selected JVM current type exists");
            let read = evaluation.session.member_scopes_for_definitions(&[owner])?;
            let Some(scopes) = evaluation.accept_session_read(read) else {
                return Ok(None);
            };
            for scope in scopes {
                if evaluation.poll_cancelled() {
                    return Ok(None);
                }
                let row = scope.get(evaluation.session).row();
                assert_eq!(row.definition(), owner);
                let head = row.scope_head();
                for &shape in &shapes {
                    let paths =
                        evaluation.lexical_paths_at(closed_endpoint(head, [shape.lookup]))?;
                    enclosing_type_branches.extend(
                        paths
                            .iter()
                            .map(|(identity, path)| (shape, *identity, path.clone())),
                    );
                    let nodes = paths
                        .iter()
                        .map(|(_, path)| path.end().node())
                        .collect::<Vec<_>>();
                    let classifications = evaluation
                        .session
                        .lexical_source
                        .classify_endpoint_nodes(&nodes, evaluation.cancellation)?;
                    assert_eq!(
                        classifications.len(),
                        paths.len(),
                        "every selected member-scope path has one endpoint classification"
                    );
                    for ((identity, path), classification) in paths.into_iter().zip(classifications)
                    {
                        if classification
                            .definition()
                            .is_some_and(|definition| answer.targets().contains(&definition))
                        {
                            assert_eq!(path.start().node(), head);
                            evaluation.observe_cancellation_completion(path.completion());
                            branches.push((shape, owner, identity, path));
                        }
                    }
                }
            }
            if companion_member_call {
                let Some(companions) = evaluation.enclosing_companion_types(owner)? else {
                    return Ok(None);
                };
                for companion in companions {
                    for (shape, identity, path) in &enclosing_type_branches {
                        branches.push((*shape, companion, *identity, path.clone()));
                    }
                }
            }
        }
        if branches.is_empty() || evaluation.poll_cancelled() {
            return Ok(None);
        }
        branches.sort_unstable_by_key(|(shape, _, identity, _)| (shape.lookup, *identity));
        branches.dedup_by_key(|(shape, _, identity, _)| (shape.lookup, *identity));
        Ok(Some(Self {
            seed,
            rerun_key: None,
            resolved: !answer.targets().is_empty()
                || evaluation
                    .session
                    .jvm_external_provider_type_identity_for_reference(reference)
                    .is_some_and(|identity| {
                        evaluation.session.is_jvm_external_type_identity(identity)
                    }),
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
        for (_, _, _, path) in &self.branches {
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
            let (answers, completion, metrics) =
                active.cancel(&evaluation.candidate_paths).into_parts();
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
            let selected = match group.poll(evaluation, readiness)? {
                DemandHierarchySelectionPoll::Continue => return Ok(Continue),
                DemandHierarchySelectionPoll::AwaitingDependencies => {
                    return Ok(AwaitingDependencies);
                }
                DemandHierarchySelectionPoll::AwaitingHierarchyReferences(references) => {
                    return Ok(DemandQualifiedPoll::AwaitingHierarchyReferences(references));
                }
                DemandHierarchySelectionPoll::Ready(None) => return Ok(Ready(None)),
                DemandHierarchySelectionPoll::Ready(Some(selected)) => selected,
            };
            let HierarchySelectionState::Ready(selected) =
                evaluation.materialize_hierarchy_candidate_expressions(selected)?
            else {
                return Ok(Ready(None));
            };
            let (shape, owner, identity, branch) = &self.branches[self.cursor];
            // A lookup whose inherited walk is sealed except for the implicit
            // root supertype (Java's unindexed `Object` edge, or no edge at
            // all for Kotlin's `Any` and Scala's `Any` and `AnyRef`) has an
            // exhaustive negative answer at this owner when the root declares
            // no member of that name (`language_implicit_root_member_names`).
            // The raw hierarchy branch is then retired without a replacement.
            // A lookup that finds no owner is absent from the indexed
            // ancestry only when every authored edge and member inventory is
            // complete. The language-defined implicit root may stay unindexed
            // for a lookup outside its member-name table. Unknown authored
            // parents remain open. A selected external or intrinsic identity
            // answers the lookup even without a source declaration target.
            // Only an answered lookup can become complete:
            // a lookup nothing answers still reaches the compilation unit's
            // placement boundary, so it keeps this reason conservatively and
            // is not re-evaluated. A selected declaration in any namespace
            // must keep its hierarchy branch until the member bridges below
            // are added; otherwise an inherited field can lose to an enclosing
            // class's declaration (JLS 6.4.1).
            // Reuse the published shape proof. Raw reference residuals may
            // retain structural gaps already transferred by indexed lookup;
            // the shared closure still rejects unindexed authored parents.
            if self.resolved
                && selected.owners.is_empty()
                && evaluation.hierarchy.hierarchy_closed(*shape, *owner)
            {
                let Some(outside_root) = evaluation
                    .lookup_is_outside_implicit_root(identity.fragment(), shape.lookup)?
                else {
                    return Ok(Ready(None));
                };
                if outside_root {
                    self.removals.push(*identity);
                    self.group = None;
                    self.cursor += 1;
                    return Ok(Continue);
                }
            }
            let (paths, remove_branch) = evaluation.java_lexical_bridges(
                self.seed.reference(),
                *shape,
                *identity,
                branch,
                selected,
            )?;
            if remove_branch {
                self.removals.push(*identity);
            }
            self.additions.extend(paths);
            self.group = None;
            self.cursor += 1;
            return Ok(Continue);
        }
        if self.cursor < self.branches.len() {
            let (shape, owner, _, _) = &self.branches[self.cursor];
            let owner = *owner;
            let roots = [HierarchyRoot {
                owner_path_prefix: None,
                owner,
                value: ResolutionSlotValue::type_object(ResolutionTypeRef::new(owner, 0)),
                route_ordinal: 0,
            }];
            let Some(roots) = evaluation.prepare_hierarchy_roots(*shape, &roots) else {
                return Ok(Ready(None));
            };
            let Some(local) = DemandHierarchyLocalFrame::new(evaluation, &roots.root_keys) else {
                return Ok(Ready(None));
            };
            self.group = Some(DemandHierarchyOwnerFrame {
                precedence: 0,
                shape: *shape,
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
            &mut evaluation.candidate_paths,
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
                DemandFactEvaluationPoll::AwaitingTypedConstruction(_)
                | DemandFactEvaluationPoll::AwaitingTypedReference(_) => {
                    unreachable!("lexical replay does not request typed prerequisites")
                }
                DemandFactEvaluationPoll::AwaitingQualifiedMember(_) => {
                    unreachable!("Java fixture has no registered qualified-member policy")
                }
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

    pub(super) fn enclosing_companion_types(
        &mut self,
        owner: SemanticId,
    ) -> StoreResult<Option<Vec<SemanticId>>> {
        let support = hierarchy_support_read_identity(
            self.session,
            &*self.hierarchy,
            b"companion-relation-by-enclosing-type",
            &[owner],
        )?;
        let read = self
            .session
            .companion_relations_for_enclosing_types(&[owner])?;
        let Some(relations) = self.accept_hierarchy_session_read(support, read) else {
            return Ok(None);
        };
        let mut companions = Vec::with_capacity(relations.len());
        for relation in relations {
            if self.poll_cancelled() {
                return Ok(None);
            }
            let relation = relation.get(self.session).row();
            assert_eq!(
                relation.enclosing_type(),
                owner,
                "selected companion relation belongs to the requested class body"
            );
            companions.push(relation.companion_type());
        }
        Ok(Some(companions))
    }

    pub(super) fn lexical_paths_at(
        &mut self,
        endpoint: EndpointSignature,
    ) -> StoreResult<Vec<(CandidatePathIdentity, PartialPath)>> {
        let (matches, unconditional, branches) = read_forward_candidate_artifacts(
            self.session.lexical_source,
            self.forward_candidate_artifacts.as_deref_mut(),
            &[BatchCandidateRequest::new(0, endpoint)],
            self.cancellation,
            self.session.resolution_session,
            &mut self.work,
            &mut self.cancellation_observed,
        )?;
        self.observe_cancellation_completion(&unconditional);
        for completion in &branches {
            self.observe_cancellation_completion(completion);
        }
        let candidates = matches
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
            let returned = if self.forward_candidate_artifacts.is_some() {
                let (returned, evidence) = read_hydrated_candidate_artifacts(
                    self.session.lexical_source,
                    &mut self.candidate_paths,
                    chunk,
                    self.cancellation,
                    &mut self.work,
                    &mut self.cancellation_observed,
                )?;
                let (evidence, cancelled) = evidence.finish(
                    self.cancellation_observed,
                    self.cancellation,
                    &mut self.work,
                );
                self.observe_cancellation_completion(&evidence);
                self.cancellation_observed |= cancelled;
                returned
            } else {
                self.session
                    .lexical_source
                    .hydrate_candidate_paths(chunk, self.cancellation)?
            };
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
    pub(super) fn java_lexical_bridges(
        &mut self,
        reference: SemanticId,
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
        // Replay retires closed-empty branches for selected source, external
        // and intrinsic bindings before bridging, with the implicit-root proof.
        // A complete empty search discharges the source-owned hierarchy
        // placeholder too: finding no member is not an unsupported traversal.
        // Other lexical branches retain their independent placement uncertainty.
        if selection.owners.is_empty() && replaces_branch {
            let normalized = branch_completion.combine(&completion);
            if normalized == ResolutionCompletion::Complete {
                return Ok((additions, true));
            }
            if normalized != *branch.completion() {
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
                let mut descriptor = CanonicalIdentityDescriptor::new(
                    b"bifrost-java-lexical-hierarchy-frontier:v1",
                    |key| self.session.identity_digest(self.hierarchy, key),
                );
                descriptor.field(
                    "branch",
                    CanonicalIdentityPart::identity(branch_identity.path()),
                )?;
                descriptor.field(
                    "branch-fragment",
                    CanonicalIdentityPart::identity(branch_identity.fragment()),
                )?;
                descriptor.field("lookup", CanonicalIdentityPart::identity(shape.lookup))?;
                let path_id = self.hierarchy.operation_path(descriptor.finish());
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
                let scope = scope.get(self.session).row();
                if scope.external_coverage().is_some() {
                    // The typed hierarchy owns external inventory routes. They
                    // carry provider-qualified identities, never source heads.
                    assert!(
                        self.session
                            .context_identities
                            .as_ref()
                            .is_some_and(|identities| identities
                                .external_owner_identity(scope.definition())
                                .is_some())
                    );
                    for definition in self.hierarchy.local_nodes[&HierarchyNodeKey {
                        shape,
                        owner: selected.owner,
                    }]
                        .direct_definitions
                        .clone()
                    {
                        self.record_member_owner_with_route_kind(
                            definition,
                            shape
                                .inherited_member_kind()
                                .unwrap_or(ResolutionMemberKind::Method),
                            selected.owner_path.clone(),
                            false,
                            FactMemberRouteKind::Member,
                        );
                    }
                    // Inventory identity does not provide a source declaration
                    // endpoint. Keep this exact external route open instead of
                    // replaying it as a closed source-scope miss.
                    let external_completion = branch_completion.combine(&completion).combine(
                        &ResolutionCompletion::incomplete([ResolutionIncompleteReason::OpenBoundary {
                            semantic: selected.owner,
                            status: crate::analyzer::structural::BoundaryStatus::ExternalDeclaredUnindexed,
                        }]),
                    );
                    let mut steps = branch.witness().to_vec();
                    steps.extend(selected.ancestry.iter().map(|&semantic| {
                        WitnessStep::Candidate {
                            semantic,
                            outcome: CandidateOutcome::Selected,
                        }
                    }));
                    steps.push(WitnessStep::Boundary {
                        semantic: selected.owner,
                        status:
                            crate::analyzer::structural::BoundaryStatus::ExternalDeclaredUnindexed,
                    });
                    let mut descriptor = CanonicalIdentityDescriptor::new(
                        b"bifrost-java-lexical-external-owner-route:v1",
                        |key| self.session.identity_digest(self.hierarchy, key),
                    );
                    descriptor.field(
                        "branch",
                        CanonicalIdentityPart::identity(branch_identity.path()),
                    )?;
                    descriptor.field(
                        "branch-fragment",
                        CanonicalIdentityPart::identity(branch_identity.fragment()),
                    )?;
                    descriptor.field("owner", CanonicalIdentityPart::identity(selected.owner))?;
                    descriptor.field("lookup", CanonicalIdentityPart::identity(shape.lookup))?;
                    let identity = CandidatePathIdentity::new(
                        branch_identity.fragment(),
                        self.hierarchy.operation_path(descriptor.finish()),
                    );
                    additions.push((
                        identity,
                        PartialPath::new(
                            branch.start().clone(),
                            branch.end().clone(),
                            branch.precedence().to_vec(),
                            steps,
                            external_completion,
                        ),
                    ));
                    continue;
                }
                let head = scope.scope_head();
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
                    if shape.namespace == ResolutionNamespace::Callable
                        && shape.inherited_member_kind() == Some(ResolutionMemberKind::Method)
                        && let Some(ExactMemberOwnerMetadata::Unique(property)) =
                            self.hierarchy.member_owner_metadata.get(&definition)
                    {
                        let property = property.get(self.session).row();
                        if property.kind() == ResolutionMemberKind::Field
                            && property.owner_definition() == selected.owner
                            && property.owner_scope_head() == head
                            && qualifier_compatible(
                                property.qualifier_compatibility(),
                                shape.category,
                            )
                        {
                            let origin = CallableValueAliasOrigin {
                                key: HierarchyNodeKey {
                                    shape,
                                    owner: selected.owner,
                                },
                                scope_head: head,
                            };
                            let origins = self
                                .callable_value_alias_origins
                                .entry((reference, definition))
                                .or_default();
                            if !origins.contains(&origin) {
                                origins.push(origin);
                            }
                        }
                    }
                    if shape.namespace == ResolutionNamespace::Callable {
                        let owner = self.fact_member_owner(
                            definition,
                            ResolutionMemberKind::Method,
                            selected.owner_path.clone(),
                            false,
                        );
                        let origins = self
                            .hierarchy
                            .java_lexical_member_owners
                            .entry((reference, definition))
                            .or_default();
                        if !origins.iter().any(|origin| {
                            origin.owner == owner && origin.steps.as_ref() == composed.witness()
                        }) {
                            origins.push(JavaLexicalMemberOrigin {
                                owner,
                                steps: composed.witness().to_vec().into_boxed_slice(),
                            });
                        }
                    }
                    let mut descriptor = CanonicalIdentityDescriptor::new(
                        b"bifrost-java-lexical-hierarchy-bridge:v1",
                        |key| self.session.identity_digest(self.hierarchy, key),
                    );
                    descriptor.field(
                        "branch",
                        CanonicalIdentityPart::identity(branch_identity.path()),
                    )?;
                    descriptor.field(
                        "branch-fragment",
                        CanonicalIdentityPart::identity(branch_identity.fragment()),
                    )?;
                    descriptor.field(
                        "candidate",
                        CanonicalIdentityPart::identity(identity.path()),
                    )?;
                    descriptor.field(
                        "candidate-fragment",
                        CanonicalIdentityPart::identity(identity.fragment()),
                    )?;
                    descriptor.field("lookup", CanonicalIdentityPart::identity(shape.lookup))?;
                    descriptor.field(
                        "receiver-root",
                        CanonicalIdentityPart::identity(selected.root.owner),
                    )?;
                    let path_id = self.hierarchy.operation_path(descriptor.finish());
                    additions.push((
                        CandidatePathIdentity::new(branch_identity.fragment(), path_id),
                        composed,
                    ));
                }
            }
        }
        // Closed-empty retirement for a selected binding is proved by replay;
        // all other replacements still require a reconstructed frontier or member.
        let remove_branch = replaces_branch && !additions.is_empty();
        Ok((additions, remove_branch))
    }

    /// Whether the lookup `lookup`, filed in `fragment`, spells no member of
    /// its language's implicit root supertype. `None` reports cancellation.
    pub(super) fn lookup_is_outside_implicit_root(
        &mut self,
        fragment: BindingFragmentId,
        lookup: SemanticId,
    ) -> StoreResult<Option<bool>> {
        let Some(outside) = self
            .session
            .typed_source
            .lookups_outside_implicit_root(&[(fragment, lookup)], self.cancellation)?
        else {
            self.cancellation_observed = true;
            return Ok(None);
        };
        Ok(Some(outside.contains(&lookup)))
    }

    /// Whether every supertype edge reachable from `owner` is resolved, apart
    /// from implicit superclass edges (Java's `java.lang.Object`) whose
    /// absolute route is unindexed. The references of those implicit edges
    /// are returned. `None` reports cancellation. An owner without a sealed
    /// edge node, an ambiguous edge, or an unresolved authored supertype makes
    /// this `Some(None)`. Local member inventories must also be indexed and
    /// complete; a minted external identity is not an empty source class.
    pub(super) fn jvm_hierarchy_implicit_root_gap_references(
        &mut self,
        shape: HierarchyLookupShape,
        owner: SemanticId,
    ) -> StoreResult<Option<Option<BTreeSet<SemanticId>>>> {
        // A missing receiver scope is not an exhaustive empty inventory. The
        // generic hierarchy already proves closure for this exact lookup;
        // retain every other local/edge operand while accounting for the
        // explicitly marked language-root gaps below.
        if !self.hierarchy.hierarchy_closed(shape, owner) {
            return Ok(Some(None));
        }
        let policy = self.hierarchy_policy;
        let local_inventory_complete = |hierarchy: &HierarchyOperationArena, owner| {
            hierarchy
                .edge_nodes
                .get(&HierarchyOwnerKey { owner, policy })
                .is_some_and(|node| {
                    node.indexed
                        && node.hierarchy_inventory_complete
                        && matches!(node.evidence, HierarchyEvidence::Complete)
                })
                && hierarchy
                    .local_nodes
                    .get(&HierarchyNodeKey { shape, owner })
                    .is_some_and(|local| matches!(local.evidence, HierarchyEvidence::Complete))
        };
        let mut pending = vec![owner];
        let mut visited = HashSet::default();
        let mut implicit_root_references = BTreeSet::new();
        while let Some(current) = pending.pop() {
            if self.poll_cancelled() {
                return Ok(None);
            }
            if !visited.insert(current) {
                continue;
            }
            let Some(node) = self.hierarchy.edge_node_snapshot(HierarchyOwnerKey {
                owner: current,
                policy: self.hierarchy_policy,
            }) else {
                return Ok(Some(None));
            };
            if !local_inventory_complete(self.hierarchy, current) {
                return Ok(Some(None));
            }
            let mut unresolved = Vec::new();
            for ordinal in 0..node.edge_count {
                if self.poll_cancelled() {
                    return Ok(None);
                }
                let edge = self.hierarchy.edge_snapshot(
                    HierarchyOwnerKey {
                        owner: current,
                        policy: self.hierarchy_policy,
                    },
                    ordinal,
                );
                match edge.target_count {
                    1 => {
                        let target = self.hierarchy.edge_target(
                            HierarchyOwnerKey {
                                owner: current,
                                policy: self.hierarchy_policy,
                            },
                            ordinal,
                            0,
                        );
                        if local_inventory_complete(self.hierarchy, target) {
                            pending.push(target);
                        } else {
                            // An indexed child may name an unindexed implicit
                            // root. Only that marked edge can be discharged.
                            unresolved.push(edge.reference);
                        }
                    }
                    0 => unresolved.push(edge.reference),
                    _ => return Ok(Some(None)),
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
                .filter(|row| {
                    row.source_kind() == Some(ResolutionSupertypeKind::ImplicitSuperclass)
                })
                .map(|row| row.reference())
                .collect::<HashSet<_>>();
            if unresolved
                .iter()
                .any(|reference| !implicit.contains(reference))
            {
                return Ok(Some(None));
            }
            implicit_root_references.extend(unresolved);
        }
        Ok(Some(Some(implicit_root_references)))
    }
}
