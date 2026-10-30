//! Completed demand roots and their identity authority for one selected query.

use super::*;
use std::sync::Mutex;

#[derive(Debug, Default)]
#[doc(hidden)]
pub struct SelectedDemandState {
    pub(super) identities: Arc<Mutex<crate::analyzer::resolution::CanonicalIdentityNumbers>>,
    pub(super) service_reasons: Arc<Mutex<HashMap<SemanticId, ServiceReasonDetails>>>,
    roots: Mutex<HashMap<RootMemoKey, FactResolutionAnswer>>,
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
        let stopped = |completion: &ResolutionCompletion| {
            matches!(completion, ResolutionCompletion::Incomplete(reasons) if reasons.iter().any(|reason| matches!(reason,
                ResolutionIncompleteReason::Cancelled | ResolutionIncompleteReason::ReceiverBudgetExhausted(_) | ResolutionIncompleteReason::TimeBudgetExceeded(_))))
        };
        // Request-minted model candidate identities and metadata are a
        // projection for this operation, never completed-root memo payload.
        if answer.model_member_selection.is_some()
            || stopped(answer.completion())
            || stopped(answer.binding().completion())
            || stopped(&answer.call_target_boundary)
            || answer
                .binding()
                .witnesses()
                .iter()
                .any(|witness| stopped(witness.completion()))
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
            site_metadata,
            callable_receiver_dispositions,
            callable_candidate_applicability,
            call_target_boundary,
            application_completion,
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
