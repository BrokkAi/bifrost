//! Query-local base continuation. Source authority and runtime activation are
//! separate prerequisites: an edge selection alone never discharges a gap.
use super::super::fact_source::UsableReceiverProofReceipt;
use super::*;

/// Affirmatively selected source context for one deferred Super receiver.
/// Construct only after the ordinary context and owner-application questions
/// have been consumed under the receiver's typed read scope.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct DeferredBaseReceiverRequest {
    pub receiver_slot: SemanticId,
    pub source_reference: SemanticId,
    pub owner: SemanticId,
    pub owner_application: SemanticId,
    pub completion: ResolutionCompletion,
    pub provisional_reasons: BTreeSet<SemanticId>,
}

/// Authority-bearing query input. Only `BaseReceiverProof::establish` in this
/// module constructs this wrapper outside tests. A staged raw projection is not
/// sufficient: the proof it is built from carries both receipts.
#[derive(Debug, Clone)]
pub(super) struct EstablishedGenericProjection {
    projection: GenericTypeProjection,
}
impl EstablishedGenericProjection {
    pub(super) fn raw(&self) -> &GenericTypeProjection {
        &self.projection
    }
}

/// Why a deferred Super receiver is not admitted. Each variant is a named
/// Open outcome: the caller keeps the provisional gap, it never guesses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaseReceiverRejection {
    /// The context proof has no usable captured or replayed read receipt.
    ContextUnretained,
    ReceiverMismatch,
    SourceInventoryOpen,
    ReceiverSourceOpen,
    OwnerUnknown,
    OwnerNotKnownNonStatic,
    /// Partial, or no complete modifier evidence for the owner.
    OwnerPartial,
    /// Struct, interface and enum owners keep `base` Open in this slice.
    OwnerNotClass,
    /// The owner application proof has no usable captured or replayed receipt.
    ApplicationUnretained,
    /// Open, ambiguous, unsupported (nested in a generic outer type) or
    /// positionally incomplete owner application.
    ApplicationOpen,
}

/// Stack-only proof that both genuine receiver proofs (`BaseReceiverContext`
/// and the distinct `OwnerApplication`) were consumed under the receiver's
/// typed read scope with usable read receipts. It is neither `Clone` nor
/// stored in any checkpoint, memo or registry: a later use re-admits, which
/// replays both receipts under the current consumer scope.
#[derive(Debug)]
#[cfg_attr(
    not(any(test, feature = "test-support")),
    expect(dead_code, reason = "#11894 B2 installs the evaluator consumer")
)]
pub(super) struct BaseReceiverProof {
    request: DeferredBaseReceiverRequest,
    _context: UsableReceiverProofReceipt,
    _owner_application: UsableReceiverProofReceipt,
}

#[cfg_attr(
    not(any(test, feature = "test-support")),
    expect(dead_code, reason = "#11894 B2 installs the evaluator consumer")
)]
impl BaseReceiverProof {
    pub(super) fn request(&self) -> &DeferredBaseReceiverRequest {
        &self.request
    }

    /// The only production constructor of an established projection. The raw
    /// projection binds the owner's formals to its own application slots
    /// (`dense_formal_slot_substitutions`); it never names a runtime `B<T>`.
    pub(super) fn establish(&self, raw: GenericTypeProjection) -> EstablishedGenericProjection {
        EstablishedGenericProjection { projection: raw }
    }
}

fn retained(receipt: super::super::fact_source::SelectedReceiverProofReceipt) -> bool {
    use super::super::fact_source::SelectedReceiverProofReceipt::{Captured, Replayed, Unretained};
    match receipt {
        Captured | Replayed => true,
        Unretained => false,
    }
}

impl FactEvaluation<'_, '_> {
    /// Subscribe the receiver slot to every proof question just consumed, so a
    /// later scoped replay (`reacquire_current_receiver_uses`) finds this
    /// consumer's receipts. Same registration as the other proof consumers.
    fn register_consumed_receiver_proofs(&mut self, receiver_slot: SemanticId) {
        for digest in self.session.pending_receiver_proof_nodes.drain(..) {
            self.session
                .receiver_proof_consumers
                .entry(receiver_slot)
                .or_default()
                .insert(digest);
            self.query_obligations
                .scope(QueryNode::SelectedInputQuestion(digest));
        }
    }

    /// Factory for one deferred Super receiver. Call it inside the receiver's
    /// `TypedSlotReadScope` so both proof reads are attributed to that slot.
    /// Admission needs: usable receipts on both proofs, complete source and
    /// application inventories, a `KnownNonStatic`, non-partial class owner and
    /// exactly one supported owner application. It starts no hierarchy walk and
    /// retires no gap; those belong to the activation slice.
    #[cfg_attr(
        not(any(test, feature = "test-support")),
        expect(dead_code, reason = "#11894 B2 installs the evaluator consumer")
    )]
    pub(super) fn admit_base_receiver(
        &mut self,
        receiver_slot: SemanticId,
        source_reference: SemanticId,
    ) -> StoreResult<Result<BaseReceiverProof, BaseReceiverRejection>> {
        use super::super::TypedFactInventoryEvidence;
        use super::super::fact_source::OwnerStaticAuthority;
        use BaseReceiverRejection::*;
        use brokk_bifrost_core::analyzer::model::ClassLikeKind;
        let context = self
            .session
            .consume_base_receiver_context_proof_with_receipt(source_reference)?;
        self.register_consumed_receiver_proofs(receiver_slot);
        let (context_receipt, context_disposition) = (context.usable_receipt, context.receipt);
        let base = context.observation;
        if base.receiver_slot != Some(receiver_slot) {
            return Ok(Err(ReceiverMismatch));
        }
        if base.source_inventory
            != TypedFactInventoryEvidence::Established(ResolutionCompletion::Complete)
        {
            return Ok(Err(SourceInventoryOpen));
        }
        let Some(source_completion) = base.receiver_source_completion.as_ref() else {
            return Ok(Err(ReceiverSourceOpen));
        };
        if source_completion != &ResolutionCompletion::Complete {
            return Ok(Err(ReceiverSourceOpen));
        }
        if base.owner_partial != Some(false) {
            return Ok(Err(OwnerPartial));
        }
        let (Some(owner), Some(owner_application), Some(owner_kind)) =
            (base.owner, base.owner_application, base.owner_kind)
        else {
            return Ok(Err(OwnerUnknown));
        };
        if base.owner_staticness != OwnerStaticAuthority::KnownNonStatic {
            return Ok(Err(OwnerNotKnownNonStatic));
        }
        if owner_kind != ClassLikeKind::Class {
            return Ok(Err(OwnerNotClass));
        }
        let application = self
            .session
            .consume_owner_application_proof_with_receipt(owner_application)?;
        self.register_consumed_receiver_proofs(receiver_slot);
        let inputs = application.observation.inputs;
        let supported = inputs.outcome.is_exhausted()
            && inputs.outcome.evidence() == &ResolutionCompletion::Complete
            && !inputs.ambiguous_application
            && !inputs.unsupported_implicit_receiver
            && matches!(
                inputs.application,
                Some(found) if found.owner == owner
                    && found.partial == Some(false)
                    && found.complete_positions
            );
        if !supported {
            return Ok(Err(ApplicationOpen));
        }
        // Semantic evidence is judged first so a refusal names its cause; the
        // receipts are then the permission to use it at all.
        let (Some(context_receipt), true) = (context_receipt, retained(context_disposition)) else {
            return Ok(Err(ContextUnretained));
        };
        let (Some(application_receipt), true) =
            (application.usable_receipt, retained(application.receipt))
        else {
            return Ok(Err(ApplicationUnretained));
        };
        Ok(Ok(BaseReceiverProof {
            request: DeferredBaseReceiverRequest {
                receiver_slot,
                source_reference,
                owner,
                owner_application,
                completion: source_completion.combine(inputs.outcome.evidence()),
                provisional_reasons: base.provisional_reasons,
            },
            _context: context_receipt,
            _owner_application: application_receipt,
        }))
    }
}

/// Real-proof entry for end-to-end tests: admits through a fresh evaluation
/// under the receiver's read scope, then reports what the proof would publish.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn admit_base_receiver_for_test(
    session: &mut FactReadSession<'_>,
    source_reference: SemanticId,
) -> StoreResult<Result<DeferredBaseReceiverRequest, BaseReceiverRejection>> {
    let Some(receiver_slot) = session
        .read_base_receiver_context_observation(source_reference)?
        .receiver_slot
    else {
        return Ok(Err(BaseReceiverRejection::OwnerUnknown));
    };
    let mut hierarchy = HierarchyOperationArena::default();
    let mut evaluation = FactEvaluation::new(session, &mut hierarchy, receiver_slot);
    let answers = AnswerMap::default();
    let states = StateMap::default();
    let mut reads = HashMap::default();
    let raw = |slot| GenericTypeProjection {
        source_slot: slot,
        substitutions: HashMap::default(),
    };
    let admitted = {
        let _scope = TypedSlotReadScope::new(
            &answers,
            &states,
            &evaluation.query_obligations,
            [receiver_slot],
            &mut reads,
        );
        evaluation.admit_base_receiver(receiver_slot, source_reference)?
    };
    let proof = match admitted {
        Ok(proof) => proof,
        Err(rejection) => return Ok(Err(rejection)),
    };
    // Publication: the genuine proof alone yields the established entry; a
    // neighbouring legacy entry stays Existing.
    let neighbor = SemanticId::for_test(b"base-neighbor-existing-output");
    evaluation.generic_type_projections.insert(
        receiver_slot,
        GenericTypeProjectionEntry::Established(proof.establish(raw(receiver_slot))),
    );
    evaluation.generic_type_projections.insert(
        neighbor,
        GenericTypeProjectionEntry::Existing(raw(neighbor)),
    );
    // Without the receiver's scoped reads no consumer holds the question, so
    // reacquisition has no composite receipt and refuses the pair.
    assert!(
        evaluation
            .reacquire_current_receiver_uses(&answers, &states)
            .is_err(),
        "an Established entry without a subscribed receipt is refused"
    );
    // Replay: with the consumer subscribed, scoped replay under the current
    // read scope yields a fresh receipt for the same question and admits it.
    for (slot, reads) in reads {
        evaluation
            .typed_worklist
            .add_reads(TypedWorkItem::Slot(slot), reads);
    }
    let uses = evaluation
        .reacquire_current_receiver_uses(&answers, &states)?
        .expect("uncancelled replay");
    uses.admit_projection_pairs(&evaluation.generic_type_projections)?;
    // The replayed proof admits again from the same question.
    let readmitted = {
        let mut reads = HashMap::default();
        let _scope = TypedSlotReadScope::new(
            &answers,
            &states,
            &evaluation.query_obligations,
            [receiver_slot],
            &mut reads,
        );
        evaluation.admit_base_receiver(receiver_slot, source_reference)?
    };
    assert_eq!(
        readmitted
            .expect("replayed proof admits")
            .request()
            .owner_application,
        proof.request().owner_application
    );
    // Retraction: a dirty receiver drops its Established entry and keeps the
    // neighbour's Existing entry.
    reset_existing_generic_projections(
        &mut evaluation.generic_type_projections,
        [(neighbor, raw(neighbor))].into_iter().collect(),
        HashMap::default(),
        &[receiver_slot].into_iter().collect(),
    );
    assert!(
        !evaluation
            .generic_type_projections
            .contains_key(&receiver_slot)
    );
    assert!(matches!(
        evaluation.generic_type_projections.get(&neighbor),
        Some(GenericTypeProjectionEntry::Existing(_))
    ));
    Ok(Ok(proof.request().clone()))
}

#[cfg(test)]
pub(super) fn established_projection_for_test(
    projection: GenericTypeProjection,
) -> EstablishedGenericProjection {
    // Shape-admission fixture only, never a source/receiver proof.
    EstablishedGenericProjection { projection }
}

/// A prepared edge is not a runtime value. Keep the complete frontier and all
/// source evidence until typed evaluation and generic projection can consume it.
pub(super) struct PreparedBaseReceiver {
    pub(super) request: DeferredBaseReceiverRequest,
    parents: NormalizedDirectParents,
    class_parent: Option<NormalizedDirectParent>,
    frontier_state: Option<SharedState>,
    runtime: Option<TypedFrontierState>,
    projection: Option<GenericTypeProjection>,
}

pub(super) struct DemandBaseReceiverFrame {
    pub(super) request: DeferredBaseReceiverRequest,
    edges: DemandHierarchyEdgeFrame,
}

impl DemandBaseReceiverFrame {
    pub(super) fn new(
        evaluation: &mut FactEvaluation<'_, '_>,
        request: DeferredBaseReceiverRequest,
    ) -> Option<Self> {
        Some(Self {
            edges: DemandHierarchyEdgeFrame::new(evaluation, &[request.owner])?,
            request,
        })
    }

    pub(super) fn pending_requests(&self) -> &[BatchCandidateRequest] {
        self.edges.pending_requests()
    }
    pub(super) fn request_owner(&self, request: &BatchCandidateRequest) -> SemanticId {
        self.edges.request_owner(request)
    }
    pub(super) fn active_forward_frame(&mut self) -> Option<&mut DemandForwardBatchFrame> {
        self.edges.active_forward_frame()
    }
    pub(super) fn cancel(self, evaluation: &mut FactEvaluation<'_, '_>) {
        self.edges.cancel(evaluation);
    }
    pub(super) fn abandon(self, evaluation: &mut FactEvaluation<'_, '_>) {
        self.edges.abandon(evaluation);
    }

    pub(super) fn poll(
        &mut self,
        evaluation: &mut FactEvaluation<'_, '_>,
        readiness: &mut impl FnMut(
            &[OwnedBatchCandidateRequest<'_>],
        ) -> StoreResult<DemandForwardReadiness>,
    ) -> StoreResult<DemandHierarchyLocalPoll> {
        self.edges.poll(evaluation, readiness)
    }

    pub(super) fn finish(
        self,
        evaluation: &mut FactEvaluation<'_, '_>,
    ) -> StoreResult<PreparedBaseReceiver> {
        let parents = evaluation.normalized_direct_parent_result(self.request.owner)?;
        let class_parent = if self.request.completion == ResolutionCompletion::Complete {
            unique_complete_class_parent(&parents).cloned()
        } else {
            None
        };
        Ok(PreparedBaseReceiver {
            request: self.request,
            parents,
            class_parent,
            frontier_state: None,
            runtime: None,
            projection: None,
        })
    }
}

impl PreparedBaseReceiver {
    /// Stage a whole-frontier conversion only. Publication and provisional-gap
    /// retirement require the independent, genuinely recorded source proof.
    pub(super) fn prepare_runtime(
        &mut self,
        evaluation: &mut FactEvaluation<'_, '_>,
        states: &StateMap,
    ) -> StoreResult<()> {
        self.runtime = None;
        self.projection = None;
        self.frontier_state = None;
        evaluation
            .query_obligations
            .scope(QueryNode::Hierarchy(self.request.owner));
        let Some(parent) = &self.class_parent else {
            return Ok(());
        };
        evaluation.demand_slot(parent.frontier);
        let Some(frontier) = states.get(&parent.frontier) else {
            return Ok(());
        };
        self.frontier_state = Some(Arc::clone(frontier));
        if frontier.completion() != &ResolutionCompletion::Complete
            || !matches!(
                frontier.possible_values(),
                [ResolutionSlotValue::TypeObject(..)]
            )
        {
            return Ok(());
        }
        let rule = TypeTransferRule::new_with_reference_indirection(
            self.request.source_reference,
            self.request.receiver_slot,
            0,
            0,
            TypeTransferValueTransform::ToRuntime { addressable: false },
            self.request.completion.combine(&self.parents.completion),
        );
        let (mut alternatives, completion) = apply_type_transfer_rules(
            frontier,
            vec![EvaluatedTypeTransfer::Other(rule)],
            parent.completion.clone(),
            evaluation.cancellation,
        )?;
        evaluation.observe_cancellation_completion(&completion);
        if !evaluation.poll_cancelled() {
            assert_eq!(
                alternatives.len(),
                1,
                "one receiver transform produces one frontier"
            );
            self.runtime = alternatives.pop();
            self.projection = self.prepare_projection(evaluation, states)?;
        }
        Ok(())
    }
    fn prepare_projection(
        &self,
        evaluation: &mut FactEvaluation<'_, '_>,
        states: &StateMap,
    ) -> StoreResult<Option<GenericTypeProjection>> {
        use super::super::TypedFactInventoryEvidence;
        let complete_inventory =
            TypedFactInventoryEvidence::Established(ResolutionCompletion::Complete);
        let read = evaluation
            .session
            .generic_formals_for_owners(&[self.request.owner])?;
        let evidence = TypedArgumentReadEvidence::from_read(&read);
        let Some(rows) = evaluation.accept_session_read(read) else {
            return Ok(None);
        };
        let evidence = evidence.expect("accepted formal read exhausted");
        if evidence.inventory != complete_inventory
            || evidence.completion != ResolutionCompletion::Complete
        {
            return Ok(None);
        }
        let formals = rows
            .iter()
            .map(|row| *row.get(evaluation.session).row())
            .collect::<Vec<_>>();
        let Some(arguments) =
            evaluation.written_application_arguments_observation(self.request.owner_application)?
        else {
            return Ok(None);
        };
        if arguments.inventory() != complete_inventory
            || arguments.legacy_completion() != ResolutionCompletion::Complete
        {
            return Ok(None);
        }
        let mut actuals = Vec::with_capacity(arguments.positions.len());
        for argument in arguments.positions {
            let Some(argument) = argument else {
                return Ok(None);
            };
            if argument.indirection_delta != 0 || argument.reference_indirection_delta != 0 {
                return Ok(None);
            }
            evaluation.demand_slot(argument.slot);
            let Some(state) = states.get(&argument.slot) else {
                return Ok(None);
            };
            if state.completion() != &ResolutionCompletion::Complete {
                return Ok(None);
            }
            actuals.push(argument.slot);
        }
        let Some(substitutions) =
            dense_formal_slot_substitutions(self.request.owner, formals, &actuals)
        else {
            return Ok(None);
        };
        // The affirmed current-owner application is symbolic: each actual slot
        // must still denote its exact formal, rather than an invented C<U>.
        for (&formal, &actual) in &substitutions {
            let Some(state) = states.get(&actual) else {
                return Ok(None);
            };
            if !matches!(state.possible_values(), [ResolutionSlotValue::TypeObject(ty, None)] if ty.identity() == formal && ty.indirection() == 0 && ty.reference_indirection() == 0)
            {
                return Ok(None);
            }
        }
        Ok(Some(GenericTypeProjection {
            source_slot: self
                .class_parent
                .as_ref()
                .expect("projection follows a selected class parent")
                .frontier,
            substitutions,
        }))
    }
}

fn unique_complete_class_parent(
    parents: &NormalizedDirectParents,
) -> Option<&NormalizedDirectParent> {
    use super::super::NominalSupertypeKind;
    if parents.completion != ResolutionCompletion::Complete {
        return None;
    }
    let mut class_parent = None;
    for parent in &parents.parents {
        if parent.completion != ResolutionCompletion::Complete || parent.targets.len() != 1 {
            return None;
        }
        match parent.kind? {
            NominalSupertypeKind::Superclass | NominalSupertypeKind::ImplicitSuperclass => {
                if class_parent.replace(parent).is_some() {
                    return None;
                }
            }
            NominalSupertypeKind::Interface => {}
            NominalSupertypeKind::GoInterfaceElement | NominalSupertypeKind::SelfType => {
                return None;
            }
        }
    }
    class_parent
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn established_shape_entry_never_unlocks_neighbor_existing_entries_and_is_revoked() {
        let source = PreloadedFactResolutionService::from_lowered_fragments([], []);
        let cancellation = CancellationToken::new();
        let mut session = FactReadSession::new(&source, &cancellation);
        let mut hierarchy = HierarchyOperationArena::default();
        let root = SemanticId::for_test(b"projection-root");
        let established = SemanticId::for_test(b"established-output");
        let existing = SemanticId::for_test(b"existing-rust-output");
        let raw = |slot| GenericTypeProjection {
            source_slot: slot,
            substitutions: HashMap::default(),
        };
        let mut evaluation = FactEvaluation::new(&mut session, &mut hierarchy, root);
        let mut states = StateMap::default();
        for output in [established, existing] {
            states.insert(
                output,
                Arc::new(TypedFrontierState::new(
                    output,
                    vec![ResolutionSlotValue::runtime(
                        ResolutionTypeRef::new(output, 0),
                        false,
                    )],
                    ResolutionCompletion::Complete,
                )),
            );
        }
        evaluation.generic_type_projections.insert(
            existing,
            GenericTypeProjectionEntry::Existing(raw(existing)),
        );
        assert!(
            evaluation
                .projected_type_shapes(&[existing], &states)
                .unwrap()
                .unwrap()
                .is_empty(),
            "legacy non-Go map remains suppressed"
        );
        evaluation.generic_type_projections.insert(
            established,
            GenericTypeProjectionEntry::Established(established_projection_for_test(raw(
                established,
            ))),
        );
        for outputs in [[existing, established], [established, existing]] {
            let shapes = evaluation
                .projected_type_shapes(&outputs, &states)
                .unwrap()
                .unwrap();
            assert_eq!(shapes.len(), 1);
            assert_eq!(shapes[0].output_slot(), established);
        }
        // A dirty/missing source proof rebuild cannot retain an established
        // environment, even when neighboring legacy results are carried.
        reset_existing_generic_projections(
            &mut evaluation.generic_type_projections,
            [(existing, raw(existing))].into_iter().collect(),
            HashMap::default(),
            &[established].into_iter().collect(),
        );
        assert!(
            !evaluation
                .generic_type_projections
                .contains_key(&established)
        );
        assert!(
            evaluation
                .projected_type_shapes(&[existing], &states)
                .unwrap()
                .unwrap()
                .is_empty()
        );
        evaluation.generic_type_projections.insert(
            established,
            GenericTypeProjectionEntry::Established(established_projection_for_test(raw(
                established,
            ))),
        );
        let mut checkpoint = evaluation.into_checkpoint_state();
        let mut evaluation = FactEvaluation::new(&mut session, &mut hierarchy, root);
        evaluation.swap_checkpoint_state(&mut checkpoint);
        assert!(evaluation.generic_type_projections.contains_key(&existing));
        assert!(
            evaluation
                .generic_type_projections
                .contains_key(&established)
        );
        assert!(
            matches!(
                evaluation.reacquire_current_receiver_uses(&AnswerMap::default(), &states),
                Err(error) if error.to_string().contains("no current composite receipt")
            ),
            "raw checkpoint staging is never permission to use an Established pair"
        );
        assert!(
            evaluation
                .generic_type_projections
                .contains_key(&established),
            "refused admission does not drop only the projection half"
        );
        assert!(
            evaluation
                .projected_type_shapes(&[existing], &states)
                .unwrap()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn existing_projection_shape_eligibility_matches_legacy_capabilities() {
        let raw = GenericTypeProjection {
            source_slot: SemanticId::for_test(b"legacy-output"),
            substitutions: HashMap::default(),
        };
        let entry = GenericTypeProjectionEntry::Existing(raw);
        for direct in [false, true] {
            for go_universe in [false, true] {
                assert_eq!(
                    entry
                        .for_shape(GenericShapeCapabilities {
                            direct,
                            go_universe
                        })
                        .is_some(),
                    direct || go_universe
                );
            }
        }
    }

    #[test]
    fn argument_observation_keeps_inventory_and_legacy_axes_independent() {
        use super::super::super::TypedFactInventoryEvidence;
        let complete = TypedFactInventoryEvidence::Established(ResolutionCompletion::Complete);
        let gap =
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                SemanticId::for_test(b"argument-inventory-gap"),
            )]);
        let open = TypedFactInventoryEvidence::Established(gap.clone());
        for application in [
            complete.clone(),
            open.clone(),
            TypedFactInventoryEvidence::Unestablished,
        ] {
            for declared in [
                complete.clone(),
                open.clone(),
                TypedFactInventoryEvidence::Unestablished,
            ] {
                let read: SessionFactRead<
                    super::super::super::SelectedTypedRow<
                        super::super::super::typed_fact_lowering::LoweredTypeArgument,
                    >,
                > = SessionFactRead::Exhausted {
                    rows: Vec::new(),
                    evidence: ResolutionCompletion::Complete,
                    inventory_evidence: application.clone(),
                };
                let observation = WrittenApplicationArgumentsObservation {
                    positions: Vec::new(),
                    application: TypedArgumentReadEvidence::from_read(&read).unwrap(),
                    declared: TypedArgumentReadEvidence {
                        completion: ResolutionCompletion::Complete,
                        inventory: declared.clone(),
                    },
                };
                assert_eq!(observation.inventory(), application.combine(&declared));
                assert_eq!(
                    observation.legacy_completion(),
                    ResolutionCompletion::Complete
                );
                assert_eq!(
                    observation.inventory() == complete,
                    application == complete && declared == complete,
                    "empty positions alone never establish zero arity"
                );
            }
        }
        let observation = WrittenApplicationArgumentsObservation {
            positions: Vec::new(),
            application: TypedArgumentReadEvidence {
                completion: gap.clone(),
                inventory: complete.clone(),
            },
            declared: TypedArgumentReadEvidence {
                completion: ResolutionCompletion::Complete,
                inventory: complete.clone(),
            },
        };
        assert_eq!(observation.inventory(), complete);
        assert_eq!(observation.legacy_completion(), gap);
        let cancelled: SessionFactRead<
            super::super::super::SelectedTypedRow<
                super::super::super::typed_fact_lowering::LoweredTypeArgument,
            >,
        > = SessionFactRead::Cancelled(incomplete_cancelled());
        assert!(TypedArgumentReadEvidence::from_read(&cancelled).is_none());
    }

    #[test]
    fn base_runtime_preparation_tracks_frontier_without_retiring_source_gaps() {
        let source = PreloadedFactResolutionService::from_lowered_fragments([], []);
        let cancellation = CancellationToken::new();
        let mut session = FactReadSession::new(&source, &cancellation);
        let mut hierarchy = HierarchyOperationArena::default();
        let receiver = SemanticId::for_test(b"base-receiver");
        let frontier = SemanticId::for_test(b"base-parent-frontier");
        let provisional = SemanticId::for_test(b"base-provisional-gap");
        let owner = SemanticId::for_test(b"base-owner");
        let ty = ResolutionTypeRef::new_with_reference_indirection(
            SemanticId::for_test(b"parent-application"),
            2,
            1,
        );
        let parent = NormalizedDirectParent {
            kind: Some(super::super::super::NominalSupertypeKind::Superclass),
            ordinal: 0,
            reference: owner,
            frontier,
            targets: vec![owner].into_boxed_slice(),
            completion: ResolutionCompletion::Complete,
        };
        let request = DeferredBaseReceiverRequest {
            receiver_slot: receiver,
            source_reference: receiver,
            owner,
            owner_application: owner,
            completion: ResolutionCompletion::Complete,
            provisional_reasons: BTreeSet::from([provisional]),
        };
        let mut prepared = PreparedBaseReceiver {
            request,
            parents: NormalizedDirectParents {
                parents: vec![parent.clone()],
                completion: ResolutionCompletion::Complete,
            },
            class_parent: Some(parent),
            frontier_state: None,
            runtime: None,
            projection: None,
        };
        let mut evaluation = FactEvaluation::new(&mut session, &mut hierarchy, receiver);
        let answers = AnswerMap::default();
        let mut states = StateMap::default();
        let mut reads = HashMap::default();
        {
            let _scope = TypedSlotReadScope::new(
                &answers,
                &states,
                &evaluation.query_obligations,
                [receiver],
                &mut reads,
            );
            prepared.prepare_runtime(&mut evaluation, &states).unwrap();
        }
        assert!(prepared.runtime.is_none());
        assert!(evaluation.demanded_slots.contains(&frontier));
        assert!(reads[&receiver].states.contains(&frontier));
        states.insert(
            frontier,
            Arc::new(TypedFrontierState::new(
                frontier,
                vec![ResolutionSlotValue::type_object(ty)],
                ResolutionCompletion::Complete,
            )),
        );
        prepared.prepare_runtime(&mut evaluation, &states).unwrap();
        assert_eq!(
            prepared.runtime.as_ref().unwrap().possible_values(),
            &[ResolutionSlotValue::runtime(ty, false)]
        );
        assert_eq!(prepared.frontier_state.as_ref().unwrap().slot(), frontier);
        assert_eq!(
            prepared.request.provisional_reasons,
            BTreeSet::from([provisional])
        );
        states.insert(
            frontier,
            Arc::new(TypedFrontierState::new(
                frontier,
                vec![ResolutionSlotValue::type_object(ty)],
                incomplete_cancelled(),
            )),
        );
        prepared.prepare_runtime(&mut evaluation, &states).unwrap();
        assert!(prepared.runtime.is_none());
        assert_eq!(
            prepared.frontier_state.as_ref().unwrap().completion(),
            &incomplete_cancelled()
        );
    }

    #[test]
    fn dense_formal_projection_binds_actual_slots_in_positional_order() {
        use super::super::super::typed_fact_lowering::LoweredGenericFormal;
        let owner = SemanticId::for_test(b"generic-owner");
        let first = SemanticId::for_test(b"formal-0");
        let second = SemanticId::for_test(b"formal-1");
        let actuals = [
            SemanticId::for_test(b"actual-slot-0"),
            SemanticId::for_test(b"actual-slot-1"),
        ];
        let formals = vec![
            LoweredGenericFormal::new(owner, 1, second),
            LoweredGenericFormal::new(owner, 0, first),
        ];
        assert_eq!(
            dense_formal_slot_substitutions(owner, formals.clone(), &actuals),
            Some(
                [(first, actuals[0]), (second, actuals[1])]
                    .into_iter()
                    .collect()
            )
        );
        assert!(dense_formal_slot_substitutions(owner, formals, &actuals[..1]).is_none());
    }

    #[test]
    pub(super) fn base_parent_selection_requires_complete_unique_class_evidence() {
        let parent = |kind| NormalizedDirectParent {
            kind,
            ordinal: 0,
            reference: SemanticId::for_test(b"reference"),
            frontier: SemanticId::for_test(b"frontier"),
            targets: vec![SemanticId::for_test(b"target")].into_boxed_slice(),
            completion: ResolutionCompletion::Complete,
        };
        let class = parent(Some(super::super::super::NominalSupertypeKind::Superclass));
        let interface = parent(Some(super::super::super::NominalSupertypeKind::Interface));
        let mut parents = NormalizedDirectParents {
            parents: vec![interface.clone(), class.clone()],
            completion: ResolutionCompletion::Complete,
        };
        assert_eq!(
            unique_complete_class_parent(&parents).unwrap().frontier,
            class.frontier
        );
        parents.parents.reverse();
        assert!(unique_complete_class_parent(&parents).is_some());
        parents.parents.push(class);
        assert!(unique_complete_class_parent(&parents).is_none());
        parents.parents = vec![interface, parent(None)];
        assert!(unique_complete_class_parent(&parents).is_none());
        parents.parents = vec![parent(Some(
            super::super::super::NominalSupertypeKind::ImplicitSuperclass,
        ))];
        assert!(unique_complete_class_parent(&parents).is_some());
        parents.completion = incomplete_cancelled();
        assert!(unique_complete_class_parent(&parents).is_none());
        parents.completion = ResolutionCompletion::Complete;
        parents.parents[0].targets = Vec::new().into_boxed_slice();
        assert!(unique_complete_class_parent(&parents).is_none());
        parents.parents.clear();
        assert!(unique_complete_class_parent(&parents).is_none());
    }
}
