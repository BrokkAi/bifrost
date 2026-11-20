//! Call-stack-only permission for resumed or carried receiver products.
//!
//! Captured receipts are immutable during one selected attempt. Checkpoints
//! only move evaluator bookkeeping; replay under the current consumer scope
//! must precede every positive use. A future mutable receipt/source contract
//! must revisit this invariant rather than silently admitting old products.
use super::super::fact_source::UsableReceiverProofReceipt;
use super::receiver_proof::ReceiverProofQuery;
use super::*;

pub(super) struct CurrentReceiverUses {
    uses: Vec<(
        TypedWorkItem,
        ReceiverProofQuery,
        UsableReceiverProofReceipt,
    )>,
}
impl CurrentReceiverUses {
    pub(super) fn admit_projection_pairs(
        &self,
        projections: &HashMap<SemanticId, GenericTypeProjectionEntry>,
    ) -> StoreResult<()> {
        for (&slot, entry) in projections {
            if matches!(entry, GenericTypeProjectionEntry::Established(_))
                && !self.uses.iter().any(|(consumer, query, _receipt)| {
                    *consumer == TypedWorkItem::Slot(slot)
                        && matches!(query, ReceiverProofQuery::BaseReceiverContext { .. })
                })
            {
                return Err(StoreError::new(format!(
                    "Established receiver projection has no current composite receipt: consumer={:?}",
                    TypedWorkItem::Slot(slot)
                )));
            }
        }
        Ok(())
    }

    pub(super) fn admit_clean_states(
        &self,
        projections: &HashMap<SemanticId, GenericTypeProjectionEntry>,
        previous: &StateMap,
        dirty: &HashSet<SemanticId>,
        states: &mut StateMap,
    ) -> StoreResult<()> {
        self.admit_projection_pairs(projections)?;
        for (&slot, state) in previous.iter() {
            if !dirty.contains(&slot) {
                assert!(states.insert(slot, Arc::clone(state)).is_none());
            }
        }
        Ok(())
    }
}

impl FactEvaluation<'_, '_> {
    pub(super) fn reacquire_current_receiver_uses(
        &mut self,
        answers: &AnswerMap,
        states: &StateMap,
    ) -> StoreResult<Option<CurrentReceiverUses>> {
        // Snapshot only actual subscriptions. All-query readers share each
        // question with its explicit readers, retaining per-item attribution.
        let whole = self.typed_worklist.readers.get(&TypedInput::AllQueryNodes);
        let mut consumers = HashMap::<TypedWorkItem, HashSet<[u8; 32]>>::default();
        for (input, readers) in &self.typed_worklist.readers {
            let TypedInput::QueryNode(QueryNode::SelectedInputQuestion(digest)) = input else {
                continue;
            };
            for &reader in readers.iter().chain(whole.into_iter().flatten()) {
                consumers.entry(reader).or_default().insert(*digest);
            }
        }
        if let Some(whole) = whole {
            for digest in self.query_obligations.selected_input_questions() {
                for &reader in whole {
                    consumers.entry(reader).or_default().insert(digest);
                }
            }
        }
        // Capture the prior semantic classification before replay may refuse
        // and remove a memo. This is not a second authority ledger.
        let snapshots = consumers
            .into_iter()
            .map(|(consumer, digests)| {
                let questions = digests
                    .into_iter()
                    .map(|digest| {
                        let prior = self
                            .session
                            .receiver_proof_memos
                            .iter()
                            .find(|(question, _)| question.canonical_digest().as_bytes() == &digest)
                            .map(|(question, memo)| {
                                (
                                    question.clone(),
                                    memo.query,
                                    memo.supplied_positive_authority(),
                                )
                            });
                        (digest, prior)
                    })
                    .collect::<Vec<_>>();
                (consumer, questions)
            })
            .collect::<Vec<_>>();
        let mut current = CurrentReceiverUses { uses: Vec::new() };
        if self.cancellation.is_cancelled() || self.session.resolution_stopped() {
            return Ok(None);
        }
        if snapshots.is_empty() {
            current.admit_projection_pairs(&self.generic_type_projections)?;
            return Ok(Some(current));
        }
        let mut refused = Vec::new();
        for (consumer, questions) in snapshots {
            if self.cancellation.is_cancelled()
                || self.session.resolution_stopped()
                || self.poll_cancelled()
            {
                return Ok(None);
            }
            let output = match consumer {
                TypedWorkItem::Slot(output)
                | TypedWorkItem::Reference(output)
                | TypedWorkItem::Qualified(output) => output,
            };
            let mut reads = HashMap::default();
            {
                let _scope = TypedSlotReadScope::new(
                    answers,
                    states,
                    &self.query_obligations,
                    [output],
                    &mut reads,
                );
                for (digest, prior) in questions {
                    let proof = self.session.replay_receiver_proof_node_use(&digest)?;
                    self.query_obligations
                        .scope(QueryNode::SelectedInputQuestion(digest));
                    for child in self.session.pending_receiver_proof_nodes.drain(..) {
                        self.query_obligations
                            .scope(QueryNode::SelectedInputQuestion(child));
                    }
                    if let Some((question, query, affirmative)) = prior
                        && affirmative
                    {
                        match proof.usable_receipt {
                            Some(receipt) => {
                                #[cfg(any(test, feature = "test-support"))]
                                super::receiver_proof_tests::with_receiver_proof_test_decorator(
                                    |decorator| decorator.checkpoint_receipt_replayed(&question),
                                );
                                current.uses.push((consumer, query, receipt));
                            }
                            None => refused.push((
                                consumer,
                                question,
                                proof.receipt,
                                proof.owner_application_receipt,
                            )),
                        }
                    }
                }
            }
            if let Some(reads) = reads.remove(&output) {
                self.typed_worklist.add_reads(consumer, reads);
            }
        }
        if self.cancellation.is_cancelled()
            || self.session.resolution_stopped()
            || self.poll_cancelled()
        {
            return Ok(None);
        }
        if !refused.is_empty() {
            return Err(StoreError::new(format!(
                "Previously affirmative receiver authority refused during scoped replay: {refused:?}"
            )));
        }
        current.admit_projection_pairs(&self.generic_type_projections)?;
        Ok(Some(current))
    }
}

impl<'source> DemandFactEvaluationTask<'source> {
    pub(super) fn reacquire_receiver_uses(
        &mut self,
        operation: &mut demand_scheduler::Resources<'_, 'source>,
    ) -> StoreResult<Option<CurrentReceiverUses>> {
        let state = self
            .evaluation
            .take()
            .expect("receiver use is between polls");
        let mut evaluation = FactEvaluation::new_with_forward_artifacts(
            operation.session,
            operation.hierarchy,
            operation.forward_candidate_artifacts,
            operation.candidate_paths,
            state.root,
        );
        evaluation.replace_with_checkpoint_state(state)?;
        let result = evaluation.reacquire_current_receiver_uses(&self.answers, &self.states);
        self.evaluation = Some(evaluation.into_checkpoint_state());
        result
    }

    pub(super) fn install_typed_reference_answer(
        &mut self,
        reference: SemanticId,
        answer: SharedAnswer,
        scope: &super::super::QueryObligations,
        _uses: &CurrentReceiverUses,
    ) {
        self.evaluation
            .as_mut()
            .expect("held typed evaluator")
            .query_obligations
            .node(QueryNode::Hierarchy(reference))
            .union(scope);
        assert!(
            self.typed_reference_answers
                .insert(reference, answer)
                .is_none(),
            "typed reference answer is inserted only once"
        );
    }
}

#[cfg(any(test, feature = "test-support"))]
impl FactReadSession<'_> {
    pub(crate) fn with_clean_owner_reuse_for_test<R>(
        &mut self,
        reference: SemanticId,
        application: SemanticId,
        exercise: impl FnOnce(&mut dyn FnMut() -> StoreResult<Option<Vec<ResolutionSlotValue>>>) -> R,
    ) -> StoreResult<R> {
        let mut hierarchy = HierarchyOperationArena::default();
        let mut evaluation = FactEvaluation::new(self, &mut hierarchy, reference);
        evaluation.demanded_slots.insert(application);
        let answers = AnswerMap::default();
        let Some(states) = evaluation.evaluate_states_with_constructed(
            &StateMap::default(),
            &answers,
            &HashMap::default(),
        )?
        else {
            panic!("real owner seed fill exhausted");
        };
        assert!(
            states.get(&application).is_some_and(|state| state
                .possible_values()
                .iter()
                .any(|value| matches!(value, ResolutionSlotValue::TypeObject(_, _)))),
            "the initial normal evaluator must install an affirmative TypeObject"
        );
        assert!(
            !evaluation
                .typed_worklist
                .dirty
                .contains(&TypedWorkItem::Slot(application)),
            "the second pass must exercise clean admission, not rebuild a dirty slot"
        );
        // Use the ordinary move/restore boundary, not a forged previous state.
        let checkpoint = evaluation.into_checkpoint_state();
        let mut evaluation = FactEvaluation::new(self, &mut hierarchy, reference);
        evaluation.replace_with_checkpoint_state(checkpoint)?;
        Ok(exercise(&mut || {
            let next = evaluation.evaluate_states_with_constructed(
                &states,
                &answers,
                &HashMap::default(),
            )?;
            Ok(next.map(|next| {
                next.get(&application)
                    .expect("same demanded owner slot")
                    .possible_values()
                    .to_vec()
            }))
        }))
    }
}
