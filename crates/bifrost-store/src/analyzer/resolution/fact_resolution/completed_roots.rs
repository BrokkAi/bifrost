//! Completed demand roots and their identity authority for one selected query.

use super::*;
use std::sync::Mutex;

#[derive(Debug, Default)]
#[doc(hidden)]
pub struct SelectedDemandState {
    pub(super) identities: Arc<Mutex<crate::analyzer::resolution::CanonicalIdentityNumbers>>,
    pub(super) service_reasons: Arc<Mutex<HashMap<SemanticId, ServiceReasonDetails>>>,
    roots: Mutex<HashMap<RootMemoKey, FactResolutionAnswer>>,
    #[cfg(test)]
    last_hit: Mutex<Option<DemandReferenceKey>>,
    #[cfg(any(test, feature = "test-support"))]
    hits: std::sync::atomic::AtomicUsize,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct RootMemoKey {
    declaration_access: u64,
    context: [u8; 32],
    // The environment is request-local; authority and context remain part of
    // this key and must describe the resources used to produce the answer.
    reference: DemandReferenceKey,
    fragment: BindingFragmentId,
    site: FactReferenceSiteMetadata,
    request: u64,
    epoch: u64,
    scope: [u8; 32],
    budget: Option<ReceiverAnalysisBudget>,
}

impl RootMemoKey {
    pub(super) fn new(
        session: &FactReadSession<'_>,
        root: DemandReferenceKey,
        seed: &ReferenceSeed,
        declaration_access: u64,
        context: [u8; 32],
    ) -> Option<Self> {
        let authority = session.lexical_source.selection_authority()?;
        Some(Self {
            declaration_access,
            context,
            reference: root,
            fragment: seed.fragment(),
            site: seed.site_metadata()?,
            request: authority.request,
            epoch: authority.content_epoch,
            scope: authority.scope,
            budget: session
                .resolution_session
                .and_then(ResolutionSession::remaining_budget),
        })
    }

    fn matches_authority(&self, session: &FactReadSession<'_>) -> bool {
        session
            .lexical_source
            .selection_authority()
            .is_some_and(|authority| {
                (self.request, self.epoch, self.scope)
                    == (authority.request, authority.content_epoch, authority.scope)
            })
    }
}

impl SelectedDemandState {
    pub(crate) fn identity_digest(&self, number: u64) -> Option<[u8; 32]> {
        self.identities
            .lock()
            .expect("selected demand identities are not poisoned")
            .digest(number)
    }

    pub(crate) fn intern_identity(&self, digest: [u8; 32]) -> u64 {
        self.identities
            .lock()
            .expect("selected demand identities are not poisoned")
            .number(digest)
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn hits_for_test(&self) -> usize {
        self.hits.load(std::sync::atomic::Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(super) fn last_hit_for_test(&self) -> Option<DemandReferenceKey> {
        *self
            .last_hit
            .lock()
            .expect("memo hit observation is not poisoned")
    }

    pub(super) fn lookup(
        &self,
        key: &RootMemoKey,
        session: &FactReadSession<'_>,
    ) -> Option<FactResolutionAnswer> {
        if session.cancellation.is_cancelled() || session.resolution_stopped() {
            return None;
        }
        let answer = self
            .roots
            .lock()
            .expect("completed roots are not poisoned")
            .get(key)
            .cloned();
        record_resolution_work(
            if answer.is_some() {
                ResolutionWork::CompletedRootMemoHit
            } else {
                ResolutionWork::CompletedRootMemoMiss
            },
            1,
        );
        crate::profiling::note_with(|| {
            format!(
                "typed_root_memo request={} root={:?} hit={} miss={}",
                key.request,
                key.reference,
                usize::from(answer.is_some()),
                usize::from(answer.is_none())
            )
        });
        if let Some(answer) = &answer {
            #[cfg(test)]
            {
                *self
                    .last_hit
                    .lock()
                    .expect("memo hit observation is not poisoned") = Some(key.reference);
            }
            #[cfg(any(test, feature = "test-support"))]
            crate::analyzer::resolution::query_obligations::replay_observations::record(
                crate::analyzer::resolution::query_obligations::replay_observations::Path::CompletedRoot,
                &answer.query_obligations,
            );
            #[cfg(any(test, feature = "test-support"))]
            self.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            debug_assert!(
                self.owns_answer(answer, session),
                "memoized root identities belong to this selected operation"
            );
        }
        answer
    }

    pub(super) fn retain(
        &self,
        key: &RootMemoKey,
        answer: &FactResolutionAnswer,
        session: &FactReadSession<'_>,
    ) {
        // Only an exhausted scheduler publishes. Stage mutations during the
        // solve invalidate the entry's original authority, including macros.
        if session.cancellation.is_cancelled()
            || session.resolution_stopped()
            || !key.matches_authority(session)
        {
            return;
        }
        let stopped = |completion: &ResolutionCompletion| matches!(completion, ResolutionCompletion::Incomplete(reasons) if reasons.iter().any(ResolutionIncompleteReason::is_execution_stop));
        // Keep this destructure exhaustive so every new answer field gets an
        // explicit memo-admission decision.
        let FactResolutionAnswer {
            query_obligations: _,
            site_metadata: _,
            callable_receiver_dispositions: _,
            callable_candidate_applicability: _,
            call_target_boundary,
            application_completion,
            member_owners: _,
            member_rejections: _,
            model_member_selection,
            absent_member: _,
            type_bound_receiver: _,
            observed_type_identity: _,
            binding,
            root_projections: _,
            projected_frontiers,
            projected_type_shapes: _,
            completion,
            external_argument_reasons: _,
            external_call_binding_reasons: _,
            external_constructor_hierarchy_reasons: _,
        } = answer;
        // Request-minted model candidate identities and metadata are a
        // projection for this operation, never completed-root memo payload.
        if model_member_selection.is_some()
            || stopped(completion)
            || stopped(binding.completion())
            || stopped(call_target_boundary)
            || application_completion.as_ref().is_some_and(stopped)
            || binding
                .witnesses()
                .iter()
                .any(|witness| stopped(witness.completion()))
            || projected_frontiers
                .iter()
                .any(|frontier| stopped(frontier.completion()))
            || answer
                .projected_type_shapes()
                .iter()
                .any(|shape| stopped(shape.completion()))
        {
            return;
        }
        self.roots
            .lock()
            .expect("completed roots are not poisoned")
            .insert(key.clone(), answer.clone());
    }

    fn owns_answer(&self, answer: &FactResolutionAnswer, session: &FactReadSession<'_>) -> bool {
        // Keep this match exhaustive: adding an answer field must also decide
        // how to check any identities it carries.
        let FactResolutionAnswer {
            query_obligations: _,
            site_metadata,
            callable_receiver_dispositions,
            callable_candidate_applicability,
            call_target_boundary,
            application_completion,
            external_argument_reasons,
            external_call_binding_reasons,
            external_constructor_hierarchy_reasons,
            member_owners,
            member_rejections,
            model_member_selection,
            absent_member,
            type_bound_receiver: _,
            observed_type_identity,
            binding,
            root_projections,
            projected_frontiers,
            projected_type_shapes: _,
            completion: answer_completion,
        } = answer;
        // Operation and selected-context identities occupy disjoint halves.
        // The context registry remains separate; both checks only look up ids.
        let numbers = self
            .identities
            .lock()
            .expect("operation identities are not poisoned");
        let semantic = |id: SemanticId| {
            id.operation_local_number().is_none_or(|number| {
                if id.is_context_local() {
                    session
                        .context_identities
                        .as_ref()
                        .is_some_and(|context| context.contains_operation_number(number))
                } else {
                    numbers.digest(number).is_some()
                }
            })
        };
        let path = |id: PartialPathId| {
            id.operation_local_number().is_none_or(|number| {
                if id.is_context_local() {
                    session
                        .context_identities
                        .as_ref()
                        .is_some_and(|context| context.contains_operation_number(number))
                } else {
                    numbers.digest(number).is_some()
                }
            })
        };
        let completion = |completion: &ResolutionCompletion| match completion {
            ResolutionCompletion::Complete => true,
            ResolutionCompletion::Incomplete(reasons) => {
                reasons.iter().all(|reason| match *reason {
                    ResolutionIncompleteReason::Cancelled
                    | ResolutionIncompleteReason::UnmountedFile { .. } => true,
                    ResolutionIncompleteReason::CyclicExpansion(id) => path(id),
                    ResolutionIncompleteReason::CyclicPrefixDependency(id)
                    | ResolutionIncompleteReason::InconsistentPrecedence(id)
                    | ResolutionIncompleteReason::OpenBoundary { semantic: id, .. }
                    | ResolutionIncompleteReason::UnsupportedSemantic(id)
                    | ResolutionIncompleteReason::ReceiverSubclassObligation(id)
                    | ResolutionIncompleteReason::ReceiverBudgetExhausted(id)
                    | ResolutionIncompleteReason::TimeBudgetExceeded(id) => semantic(id),
                })
            }
        };
        let owner = |owner: &FactMemberOwner| {
            semantic(owner.target)
                && semantic(owner.owner)
                && semantic(owner.receiver)
                && owner.owner_path.iter().copied().all(semantic)
        };
        model_member_selection.is_none()
            && site_metadata
                .is_none_or(|site| site.reference_owner().flatten().is_none_or(semantic))
            && callable_receiver_dispositions
                .iter()
                .all(|row| semantic(row.target))
            && callable_candidate_applicability
                .iter()
                .all(|row| semantic(row.target))
            && external_argument_reasons.iter().copied().all(semantic)
            && external_call_binding_reasons.iter().copied().all(semantic)
            && external_constructor_hierarchy_reasons
                .iter()
                .copied()
                .all(semantic)
            && member_owners.iter().all(owner)
            && member_rejections.iter().all(|row| owner(&row.owner))
            && absent_member
                .as_ref()
                .is_none_or(|row| row.owners.iter().copied().all(semantic))
            && observed_type_identity.is_none_or(semantic)
            && binding.targets().iter().copied().all(semantic)
            && completion(binding.completion())
            && completion(call_target_boundary)
            && application_completion.as_ref().is_none_or(completion)
            && binding.witnesses().iter().all(|witness| {
                semantic(witness.reference())
                    && semantic(witness.target())
                    && completion(witness.completion())
                    && witness.steps().iter().all(|step| match *step {
                        WitnessStep::Node(id) => id.operation_local_number().is_none_or(|number| {
                            if id.is_context_local() {
                                session.context_identities.as_ref().is_some_and(|context| {
                                    context.contains_operation_number(number)
                                })
                            } else {
                                numbers.digest(number).is_some()
                            }
                        }),
                        WitnessStep::Candidate { semantic: id, .. }
                        | WitnessStep::Boundary { semantic: id, .. } => semantic(id),
                    })
            })
            && root_projections
                .iter()
                .all(|row| semantic(row.reference()) && semantic(row.output_slot()))
            && projected_frontiers.iter().all(|row| {
                semantic(row.slot())
                    && row
                        .possible_values()
                        .iter()
                        .all(|value| semantic(value.ty().identity()))
                    && completion(row.completion())
            })
            && answer.projected_type_shapes().iter().all(|shape| {
                semantic(shape.output_slot)
                    && semantic(shape.root_slot)
                    && completion(&shape.completion)
                    && shape.nodes.iter().all(|node| {
                        semantic(node.slot)
                            && semantic(node.identity)
                            && match &node.form {
                                FactProjectedTypeNodeForm::Alias(id)
                                | FactProjectedTypeNodeForm::Slice(id)
                                | FactProjectedTypeNodeForm::Array(id) => semantic(*id),
                                FactProjectedTypeNodeForm::Channel { element, .. } => {
                                    semantic(*element)
                                }
                                FactProjectedTypeNodeForm::Map { key, value } => {
                                    semantic(*key) && semantic(*value)
                                }
                                FactProjectedTypeNodeForm::Applied(ids) => {
                                    ids.iter().copied().all(semantic)
                                }
                                FactProjectedTypeNodeForm::Leaf
                                | FactProjectedTypeNodeForm::Unsupported => true,
                            }
                    })
            })
            && completion(answer_completion)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId;

    #[test]
    fn completed_roots_reject_execution_stops_in_nested_completions() {
        let source = PreloadedFactResolutionService::from_lowered_fragments([], []);
        let observed = ObservedBatchSource::new(&source);
        let cancellation = CancellationToken::new();
        let session = FactReadSession::from_split_sources(&observed, &source, &cancellation);
        let reference =
            SemanticId::shared_name(crate::analyzer::resolution::SharedNameId::interned(1));
        let stop =
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::CyclicPrefixDependency(
                reference,
            )]);
        let content_gap =
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                reference,
            )]);
        let authority = PRELOADED_FIXTURE_AUTHORITY;
        let key = RootMemoKey {
            declaration_access: 0,
            context: [0; 32],
            reference: DemandReferenceKey::caller(reference),
            fragment: BindingFragmentId::for_test(b"completed-root-fragment"),
            site: FactReferenceSiteMetadata::new(
                ResolutionSiteId::new(0),
                ResolutionNamespace::Value,
                ResolutionSiteKind::ValueReference,
                0,
                0,
                true,
                None,
                None,
            ),
            request: authority.request,
            epoch: authority.content_epoch,
            scope: authority.scope,
            budget: None,
        };
        let memo = SelectedDemandState::default();
        for placement in 0..4 {
            let mut answer = empty_fact_resolution_answer(
                if placement == 0 {
                    stop.clone()
                } else {
                    ResolutionCompletion::Complete
                },
                &cancellation,
            );
            match placement {
                1 => answer.application_completion = Some(stop.clone()),
                2 => {
                    answer.projected_frontiers = vec![TypedFrontierState::new(
                        reference,
                        Vec::<ResolutionSlotValue>::new(),
                        stop.clone(),
                    )]
                    .into_boxed_slice()
                }
                3 => answer.application_completion = Some(content_gap.clone()),
                _ => {}
            }
            memo.retain(&key, &answer, &session);
            let later_session =
                FactReadSession::from_split_sources(&observed, &source, &cancellation);
            assert_eq!(memo.lookup(&key, &later_session).is_some(), placement == 3);
            assert_eq!(memo.hits_for_test(), usize::from(placement == 3));
        }
    }
}
