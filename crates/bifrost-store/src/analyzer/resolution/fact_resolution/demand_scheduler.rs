//! Operation-owned demand execution shared by forward and reverse consumers.
//!
//! Discovery and materialization run only between evaluator polls. An exact
//! endpoint becomes readable once, after all of its positioned prefix tasks
//! finish. Cyclic selected-root dependencies remain incomplete.

use super::completed_roots::RootMemoKey;
use super::*;
use crate::analyzer::resolution::QualifiedMemberRegistration;

/// Identity of an execution environment inside one selected request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[doc(hidden)]
pub struct EnvironmentId(pub usize);

pub(crate) const CALLER_ENVIRONMENT: EnvironmentId = EnvironmentId(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[doc(hidden)]
pub struct ReferenceKey {
    pub(crate) reference: SemanticId,
    pub(crate) environment: EnvironmentId,
}

impl ReferenceKey {
    pub(crate) fn caller(reference: SemanticId) -> Self {
        Self {
            reference,
            environment: CALLER_ENVIRONMENT,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[doc(hidden)]
pub struct RelationKey {
    pub(crate) endpoint: EndpointSignature,
    pub(crate) environment: EnvironmentId,
}

impl RelationKey {
    pub(crate) fn caller(endpoint: EndpointSignature) -> Self {
        Self {
            endpoint,
            environment: CALLER_ENVIRONMENT,
        }
    }
}

impl std::ops::Deref for RelationKey {
    type Target = EndpointSignature;

    fn deref(&self) -> &Self::Target {
        &self.endpoint
    }
}

pub(super) struct Resources<'resources, 'source> {
    pub(super) session: &'resources mut FactReadSession<'source>,
    pub(super) hierarchy: &'resources mut HierarchyOperationArena,
    pub(super) completed_roots: Option<(&'resources SelectedDemandState, u64, [u8; 32])>,
    pub(super) forward_candidate_artifacts: &'resources mut ForwardCandidateArtifactCache,
    pub(super) candidate_paths: &'resources mut CandidatePathStore,
}

impl Resources<'_, '_> {
    fn include_hierarchy_cancellation_evidence(
        &mut self,
        target: &mut CancellationEvidenceLedger,
        work: &mut usize,
    ) {
        super::include_hierarchy_cancellation(self.hierarchy, self.session, target, work);
    }
}

/// A relation can select the declaring owners of a member after its receiver
/// references finish. Exact projected values also permit type-projection owners;
/// this capability is independent of the syntax that requested the relation.
#[derive(Debug)]
#[doc(hidden)]
pub struct MemberSelectionRequest {
    pub(crate) policy: &'static dyn HierarchyPolicy,
    pub(crate) order: Option<HierarchyOrderRequest>,
    pub(crate) reference: SemanticId,
    pub(crate) values: Vec<ResolutionSlotValue>,
    pub(crate) lookup: SemanticId,
    pub(crate) namespace: ResolutionNamespace,
    pub(crate) language: Language,
}

/// One qualified member group from evaluated slots, without a lexical ROOT.
#[derive(Clone, Debug)]
pub(crate) struct QualifiedMemberInput {
    pub(crate) reference: ReferenceKey,
    pub(crate) route_ordinal: usize,
    pub(crate) precedence: u32,
    pub(crate) fragment: BindingFragmentId,
    pub(crate) source_lookup: SemanticId,
    pub(crate) lookup: SemanticId,
    pub(crate) namespace: ResolutionNamespace,
    pub(crate) values: Vec<ResolutionSlotValue>,
    pub(crate) completion: ResolutionCompletion,
    pub(crate) registration: QualifiedMemberRegistration,
}

/// Request-local identity; unlike reference keys it is never an answer memo key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct QualifiedMemberId(CloseContinuationId);
impl QualifiedMemberId {
    fn issue(view: HierarchyProvenanceView<'_>) -> Self {
        Self(CloseContinuationId::issue(view))
    }
    pub(crate) fn assert_current(self, view: HierarchyProvenanceView<'_>) {
        self.0.assert_current(view);
    }
}

/// A real call-result projection and its completed selected callee binding.
#[derive(Clone, Debug)]
pub(crate) struct TypedConstructionInput {
    pub(crate) reference: ReferenceKey,
    pub(crate) output: SemanticId,
    pub(crate) language: Language,
    pub(crate) binding: ResolutionAnswer,
}

enum TypedPrerequisiteInput {
    Member(QualifiedMemberInput),
    Construction(TypedConstructionInput),
}
impl TypedPrerequisiteInput {
    fn reference(&self) -> ReferenceKey {
        match self {
            Self::Member(input) => input.reference,
            Self::Construction(input) => input.reference,
        }
    }
    fn member(&self) -> &QualifiedMemberInput {
        let Self::Member(input) = self else {
            panic!("member preparation owns a member input")
        };
        input
    }
}

/// An optional provider view owns prepared language data and shared row slots.
/// Default languages need no associated context/row types or allocations.
pub(crate) trait QualifiedMemberProvider {
    fn poll_construction(
        &mut self,
        _input: &TypedConstructionInput,
        _provenance: HierarchyProvenanceView<'_>,
        _resume: CloseResume<'_>,
    ) -> StoreResult<CloseProgress<Option<ResolutionSlotValue>>> {
        Ok(CloseProgress::Ready(None))
    }

    fn prepare_qualified_member(
        &mut self,
        id: QualifiedMemberId,
        input: &QualifiedMemberInput,
        provenance: HierarchyProvenanceView<'_>,
        resume: CloseResume<'_>,
    ) -> StoreResult<CloseProgress<MemberSelectionOutcome>>;
    fn poll_qualified_member(
        &mut self,
        id: QualifiedMemberId,
        selection: &MemberSelection,
        provenance: HierarchyProvenanceView<'_>,
        resume: CloseResume<'_>,
    ) -> StoreResult<
        CloseProgress<
            crate::analyzer::store::resolution_operation::demand_closure::Read<
                crate::analyzer::store::resolution_operation::member_access::MemberAccessResult,
            >,
        >,
    >;
    fn cancel_qualified_member(&mut self, id: QualifiedMemberId);
}

/// One outstanding source closure suspension, scoped to its relation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct CloseContinuationId {
    identity: hierarchy_provenance::HierarchyRequestIdentity,
    serial: u64,
}
impl CloseContinuationId {
    pub(crate) fn issue(view: HierarchyProvenanceView<'_>) -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        Self {
            identity: view.identity(),
            serial: NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        }
    }
    pub(crate) fn assert_current(self, view: HierarchyProvenanceView<'_>) {
        view.assert_identity(self.identity);
    }
}

pub(crate) enum CloseResume<'a> {
    Start,
    Reference {
        continuation: CloseContinuationId,
        key: ReferenceKey,
        answer: &'a FactResolutionAnswer,
    },
    Members {
        continuation: CloseContinuationId,
        selection: &'a MemberSelection,
    },
}

pub(crate) enum CloseProgress<T> {
    Ready(T),
    Reference {
        continuation: CloseContinuationId,
        key: ReferenceKey,
        completion: ResolutionCompletion,
    },
    Members {
        continuation: CloseContinuationId,
        request: MemberSelectionRequest,
        completion: ResolutionCompletion,
    },
    Cancelled(ResolutionCompletion),
}

impl<T> CloseProgress<T> {
    fn map<U>(self, convert: impl FnOnce(T) -> U) -> CloseProgress<U> {
        match self {
            Self::Ready(value) => CloseProgress::Ready(convert(value)),
            Self::Reference {
                continuation,
                key,
                completion,
            } => CloseProgress::Reference {
                continuation,
                key,
                completion,
            },
            Self::Members {
                continuation,
                request,
                completion,
            } => CloseProgress::Members {
                continuation,
                request,
                completion,
            },
            Self::Cancelled(completion) => CloseProgress::Cancelled(completion),
        }
    }
}

enum TypedPrerequisiteAnswer {
    Member(
        crate::analyzer::store::resolution_operation::demand_closure::Read<
            crate::analyzer::store::resolution_operation::member_access::MemberAccessResult,
        >,
    ),
    Construction(Option<ResolutionSlotValue>),
}

/// Readiness of the member request is separate from its semantic coverage.
#[derive(Debug)]
pub(crate) enum MemberSelectionOutcome {
    QualifierIsNamespace,
    Ready {
        request: Option<MemberSelectionRequest>,
        completion: ResolutionCompletion,
    },
    Unavailable(ResolutionCompletion),
    Cancelled(ResolutionCompletion),
}

#[derive(Clone, Debug)]
#[doc(hidden)]
pub struct MemberSelection {
    pub(crate) order: Option<HierarchyOrderOutcomeId>,
    pub(crate) provenance: HierarchySelectionProvenance,
    pub(crate) owners: Vec<SemanticId>,
    pub(crate) completion: ResolutionCompletion,
    /// Negative provider proofs from this selection's exact hierarchy requests.
    pub(crate) discharged_provider_reasons: BTreeSet<SemanticId>,
}

struct MemberSelectionFrame<'source> {
    order: Option<HierarchyOrderState>,
    provenance: HierarchyProvenanceId,
    evaluation: Option<FactEvaluationState<'source>>,
    groups: BTreeMap<HierarchyLookupShape, Vec<HierarchyRoot>>,
    active: Option<DemandHierarchyOwnerFrame>,
    owners: BTreeSet<SemanticId>,
    completion: ResolutionCompletion,
    discharged_provider_reasons: BTreeSet<SemanticId>,
}

enum MemberSelectionPoll {
    Continue,
    AwaitingDependencies(Vec<EndpointSignature>),
    AwaitingHierarchyReferences(Vec<SemanticId>),
    Ready(MemberSelection),
    Cancelled,
}

impl<'source> MemberSelectionFrame<'source> {
    fn new(
        operation: &mut Resources<'_, 'source>,
        request: MemberSelectionRequest,
    ) -> Option<Self> {
        assert!(
            matches!(
                request.namespace,
                ResolutionNamespace::Type
                    | ResolutionNamespace::Value
                    | ResolutionNamespace::Callable
            ),
            "a member selection requests a member namespace"
        );
        let mut evaluation = FactEvaluation::new_with_forward_artifacts(
            operation.session,
            operation.hierarchy,
            operation.forward_candidate_artifacts,
            operation.candidate_paths,
            request.reference,
        );
        evaluation.hierarchy_policy = evaluation.hierarchy.register_policy(request.policy);
        evaluation.selected_route_language = request.language;
        let namespace = if request.namespace == ResolutionNamespace::Callable
            && super::super::fact_source::language_callables_occupy_value_namespace(
                request.language,
            ) {
            ResolutionNamespace::Value
        } else {
            request.namespace
        };
        let order = request.order.map(|request| {
            HierarchyOrderState::new(request, HierarchyProvenanceView::new(evaluation.hierarchy))
        });
        let mut groups = BTreeMap::<HierarchyLookupShape, Vec<HierarchyRoot>>::new();
        for value in request.values {
            if evaluation.poll_cancelled() {
                return None;
            }
            let mut shape = HierarchyLookupShape::new(
                request.lookup,
                namespace,
                QualifierCategory::of(value),
                i64::from(value.ty().indirection()),
            );
            shape.policy = evaluation.hierarchy_policy;
            if namespace == ResolutionNamespace::Value {
                shape.namespace_aliases =
                    super::super::fact_source::language_value_member_aliases(request.language);
            }
            if request.namespace == ResolutionNamespace::Callable
                && language_uses_qualified_callable_hierarchy_replay(request.language)
            {
                shape = shape.with_callable_overload_set();
            }
            groups.entry(shape).or_default().push(HierarchyRoot {
                owner_path_prefix: None,
                owner: value.ty().identity(),
                value,
                route_ordinal: 0,
            });
        }
        Some(Self {
            order,
            evaluation: Some(evaluation.into_checkpoint_state()),
            provenance: HierarchyProvenanceId::default(),
            groups,
            active: None,
            owners: BTreeSet::new(),
            completion: ResolutionCompletion::Complete,
            discharged_provider_reasons: BTreeSet::new(),
        })
    }

    fn poll(
        &mut self,
        operation: &mut Resources<'_, 'source>,
        readiness: &mut impl FnMut(&[BatchCandidateRequest]) -> StoreResult<DemandForwardReadiness>,
    ) -> StoreResult<MemberSelectionPoll> {
        let state = self
            .evaluation
            .take()
            .expect("member phase is between polls");
        let mut evaluation = FactEvaluation::new_with_forward_artifacts(
            operation.session,
            operation.hierarchy,
            operation.forward_candidate_artifacts,
            operation.candidate_paths,
            state.root,
        );
        evaluation.replace_with_checkpoint_state(state);
        let result = self.poll_selection(&mut evaluation, readiness);
        self.evaluation = Some(evaluation.into_checkpoint_state());
        result
    }

    fn poll_selection(
        &mut self,
        evaluation: &mut FactEvaluation<'_, 'source>,
        readiness: &mut impl FnMut(&[BatchCandidateRequest]) -> StoreResult<DemandForwardReadiness>,
    ) -> StoreResult<MemberSelectionPoll> {
        if evaluation.poll_cancelled() {
            return Ok(MemberSelectionPoll::Cancelled);
        }
        if let Some(active) = &mut self.active {
            match active.poll(evaluation, readiness)? {
                DemandHierarchySelectionPoll::Continue => return Ok(MemberSelectionPoll::Continue),
                DemandHierarchySelectionPoll::AwaitingDependencies => {
                    let requests = active.inherited.as_ref().map_or_else(
                        || active.local.pending_requests(),
                        DemandInheritedHierarchyFrame::pending_requests,
                    );
                    assert!(
                        !requests.is_empty(),
                        "a suspended member phase retains its requests"
                    );
                    return Ok(MemberSelectionPoll::AwaitingDependencies(
                        requests
                            .iter()
                            .map(|request| request.endpoint().clone())
                            .collect(),
                    ));
                }
                DemandHierarchySelectionPoll::AwaitingHierarchyReferences(references) => {
                    return Ok(MemberSelectionPoll::AwaitingHierarchyReferences(references));
                }
                DemandHierarchySelectionPoll::Ready(None) => {
                    return Ok(MemberSelectionPoll::Cancelled);
                }
                DemandHierarchySelectionPoll::Ready(Some(selected)) => {
                    let HierarchySelectionState::Ready(selected) =
                        evaluation.materialize_hierarchy_candidate_expressions(selected)?
                    else {
                        return Ok(MemberSelectionPoll::Cancelled);
                    };
                    if let Some(order) = &mut self.order {
                        for &(expression, owner) in &selected.order {
                            order.root(expression, owner);
                        }
                    }
                    self.provenance = evaluation
                        .hierarchy
                        .provenance
                        .join(self.provenance, selected.provenance);
                    self.owners
                        .extend(selected.owners.iter().map(|owner| owner.owner));
                    let cancellation = evaluation.cancellation;
                    let work = &mut evaluation.work;
                    let Some(completion) = evaluation.hierarchy.evidence.flatten(
                        &selected.evidence,
                        u32::MAX,
                        &mut || poll_cancelled(cancellation, work),
                    ) else {
                        return Ok(MemberSelectionPoll::Cancelled);
                    };
                    self.completion = self.completion.combine(&completion);
                    self.active = None;
                }
            }
        }
        if let Some((shape, roots)) = self.groups.pop_first() {
            let Some(prepared) = evaluation.prepare_hierarchy_roots(shape, &roots) else {
                return Ok(MemberSelectionPoll::Cancelled);
            };
            let Some(local) = DemandHierarchyLocalFrame::new(evaluation, &prepared.root_keys)
            else {
                return Ok(MemberSelectionPoll::Cancelled);
            };
            self.active = Some(DemandHierarchyOwnerFrame {
                precedence: 0,
                shape,
                roots: Some(prepared),
                local,
                inherited: None,
            });
            return Ok(MemberSelectionPoll::Continue);
        }
        let order = if let Some(order) = &mut self.order {
            let cancellation = evaluation.cancellation;
            let work = &mut evaluation.work;
            let limit = evaluation.session.resolution_session.map_or(
                brokk_bifrost_core::analyzer::usages::receiver_analysis::DEFAULT_RECEIVER_MAX_HIERARCHY_ORDER_STEPS,
                ResolutionSession::hierarchy_order_limit,
            );
            let remaining = limit.saturating_sub(evaluation.hierarchy.order_work);
            let view = HierarchyProvenanceView::new(evaluation.hierarchy);
            let mut steps = 0;
            let outcome = order.poll(
                &evaluation.hierarchy.order,
                view,
                &mut || {
                    if poll_cancelled(cancellation, work) || steps == remaining {
                        return false;
                    }
                    steps += 1;
                    super::super::seam_profile::record_hierarchy_order_step();
                    true
                },
                &mut || cancellation.is_cancelled(),
            );
            evaluation.hierarchy.order_work += steps;
            let outcome = outcome?;
            let Some(outcome) = outcome else {
                return Ok(MemberSelectionPoll::Cancelled);
            };
            Some(HierarchyOrderOutcomeId::retain(
                evaluation.hierarchy,
                outcome,
            ))
        } else {
            None
        };
        Ok(MemberSelectionPoll::Ready(MemberSelection {
            order,
            provenance: HierarchyProvenanceView::new(evaluation.hierarchy)
                .selection(self.provenance),
            owners: std::mem::take(&mut self.owners).into_iter().collect(),
            completion: std::mem::replace(&mut self.completion, ResolutionCompletion::Complete),
            discharged_provider_reasons: std::mem::take(&mut self.discharged_provider_reasons),
        }))
    }

    fn cancel(mut self, operation: &mut Resources<'_, 'source>) {
        let state = self
            .evaluation
            .take()
            .expect("member phase is between polls");
        let mut evaluation =
            FactEvaluation::new(operation.session, operation.hierarchy, state.root)
                .with_candidate_paths(operation.candidate_paths);
        evaluation.replace_with_checkpoint_state(state);
        if let Some(active) = self.active.take()
            && let Some(inherited) = active.inherited
        {
            inherited.cancel(&mut evaluation);
        }
    }

    fn abandon(mut self, operation: &mut Resources<'_, 'source>) {
        let state = self
            .evaluation
            .take()
            .expect("member phase is between polls");
        let mut evaluation =
            FactEvaluation::new(operation.session, operation.hierarchy, state.root)
                .with_candidate_paths(operation.candidate_paths);
        evaluation.replace_with_checkpoint_state(state);
        if let Some(active) = self.active.take()
            && let Some(inherited) = active.inherited
        {
            inherited.abandon(&mut evaluation);
        }
    }
}

#[derive(Debug)]
pub(crate) struct RootPlan {
    pub(crate) prefixes: Vec<ReferenceKey>,
    pub(crate) completion: ResolutionCompletion,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[doc(hidden)]
pub struct ClosureDischarges {
    pub(crate) reasons: BTreeSet<SemanticId>,
    /// Exact providers closed by stronger binding precedence or a complete
    /// name inventory that excludes this spelling. Negative inventory proof
    /// applies even when no positive target survives.
    pub(crate) discharged_provider_reasons: BTreeSet<SemanticId>,
    /// These providers lose only if this exact certified target survives alone.
    /// Before selection they remain open, including on an empty answer.
    pub(crate) positive_binding_providers: BTreeMap<SemanticId, BTreeSet<SemanticId>>,
    /// The selected prefix provider has evidence to retire operation-local
    /// hierarchy placeholders after the closed route binds a target.
    pub(crate) operation_local_placeholders: bool,
    /// A closed selected route's exact terminal targets, including an empty
    /// set when the provider exhausted the route and proved no target exists.
    pub(crate) selected_targets: Option<BTreeSet<SemanticId>>,
    /// The selected route may remove the listed gaps on its own empty answer.
    pub(crate) authoritative_empty_result: bool,
    /// A type-prefix proof also closes the same exact prefix reference's gap.
    pub(crate) prefix_reference: Option<SemanticId>,
    pub(crate) prefix_reasons: BTreeSet<SemanticId>,
    pub(crate) prefix_operation_local_placeholders: bool,
}

impl ClosureDischarges {
    pub(crate) fn exact(reasons: impl IntoIterator<Item = SemanticId>) -> Self {
        Self {
            reasons: reasons.into_iter().collect(),
            discharged_provider_reasons: BTreeSet::new(),
            positive_binding_providers: BTreeMap::new(),
            operation_local_placeholders: false,
            selected_targets: None,
            authoritative_empty_result: false,
            prefix_reference: None,
            prefix_reasons: BTreeSet::new(),
            prefix_operation_local_placeholders: false,
        }
    }

    pub(crate) fn with_operation_local_placeholders(
        reasons: impl IntoIterator<Item = SemanticId>,
    ) -> Self {
        Self {
            reasons: reasons.into_iter().collect(),
            discharged_provider_reasons: BTreeSet::new(),
            positive_binding_providers: BTreeMap::new(),
            operation_local_placeholders: true,
            selected_targets: None,
            authoritative_empty_result: false,
            prefix_reference: None,
            prefix_reasons: BTreeSet::new(),
            prefix_operation_local_placeholders: false,
        }
    }

    pub(crate) fn with_discharged_provider_reasons(
        mut self,
        reasons: impl IntoIterator<Item = SemanticId>,
    ) -> Self {
        self.discharged_provider_reasons.extend(reasons);
        self
    }

    pub(crate) fn with_selected_targets(
        mut self,
        targets: impl IntoIterator<Item = SemanticId>,
    ) -> Self {
        let targets = targets.into_iter().collect::<BTreeSet<_>>();
        if let Some(selected) = &mut self.selected_targets {
            selected.extend(targets);
        } else {
            self.selected_targets = Some(targets);
        }
        self
    }

    pub(crate) fn with_authoritative_empty_result(mut self) -> Self {
        self.selected_targets = Some(BTreeSet::new());
        self.authoritative_empty_result = true;
        self
    }

    pub(crate) fn for_prefix(
        mut self,
        reference: SemanticId,
        reasons: impl IntoIterator<Item = SemanticId>,
        operation_local_placeholders: bool,
    ) -> Self {
        assert!(
            self.prefix_reference.is_none() || self.prefix_reference == Some(reference),
            "one closed route has one selected prefix reference"
        );
        self.prefix_reference = Some(reference);
        self.prefix_reasons.extend(reasons);
        self.prefix_operation_local_placeholders |= operation_local_placeholders;
        self
    }

    pub(crate) fn for_prefix_only(&self) -> Option<(SemanticId, Self)> {
        self.prefix_reference.map(|reference| {
            (
                reference,
                Self {
                    reasons: self.prefix_reasons.clone(),
                    operation_local_placeholders: self.prefix_operation_local_placeholders,
                    ..Self::default()
                },
            )
        })
    }

    pub(crate) fn without_prefix(self) -> Self {
        Self {
            prefix_reference: None,
            prefix_reasons: BTreeSet::new(),
            prefix_operation_local_placeholders: false,
            ..self
        }
    }

    pub(crate) fn merge(&mut self, other: Self) {
        self.reasons.extend(other.reasons);
        self.discharged_provider_reasons
            .extend(other.discharged_provider_reasons);
        for (target, reasons) in other.positive_binding_providers {
            self.positive_binding_providers
                .entry(target)
                .or_default()
                .extend(reasons);
        }
        self.operation_local_placeholders |= other.operation_local_placeholders;
        if let Some(targets) = other.selected_targets {
            self.selected_targets
                .get_or_insert_with(BTreeSet::new)
                .extend(targets);
        }
        self.authoritative_empty_result |= other.authoritative_empty_result;
        if let Some(reference) = other.prefix_reference {
            assert!(
                self.prefix_reference.is_none() || self.prefix_reference == Some(reference),
                "merged closed routes agree on their selected prefix reference"
            );
            self.prefix_reference = Some(reference);
        }
        self.prefix_reasons.extend(other.prefix_reasons);
        self.prefix_operation_local_placeholders |= other.prefix_operation_local_placeholders;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum RootUnavailableReason {
    MissingSourceProvenance,
    IncompletePreparation,
}

/// Discovery readiness is separate from semantic coverage. Incomplete
/// preparation cannot authorize an empty candidate relation; a ready plan can
/// still carry genuine incomplete coverage from its exhausted source reads.
#[derive(Debug)]
pub(crate) enum RootDiscovery {
    /// This exact endpoint is already served by the immutable base source.
    /// No selected relation may be installed over it by this scheduler.
    /// Its coverage must also be carried by ordinary source candidate reads.
    AlreadyReady {
        completion: ResolutionCompletion,
    },
    Ready(RootPlan),
    Unavailable {
        reason: RootUnavailableReason,
        completion: ResolutionCompletion,
    },
    Cancelled(ResolutionCompletion),
}

pub(crate) trait RootProvider {
    fn qualified_members(&mut self) -> Option<&mut dyn QualifiedMemberProvider> {
        None
    }

    fn cancel_close(&mut self, _endpoint: &RelationKey) {}

    /// Resume source closure without running a hierarchy walk in a provider.
    /// The default preserves the original close call and work for old readers.
    fn poll_close(
        &mut self,
        endpoint: &RelationKey,
        inputs: &[(ReferenceKey, &FactResolutionAnswer)],
        initial_members: Option<&MemberSelection>,
        member_completion: &ResolutionCompletion,
        _provenance: HierarchyProvenanceView<'_>,
        resume: CloseResume<'_>,
    ) -> StoreResult<CloseProgress<ResolutionCompletion>> {
        assert!(
            matches!(resume, CloseResume::Start),
            "only a suspended provider resumes"
        );
        let completion = if let Some(selection) = initial_members {
            self.close_selected_members(endpoint, inputs, selection)?
        } else {
            self.close_with_member_completion(endpoint, inputs, member_completion)?
        };
        Ok(CloseProgress::Ready(completion))
    }

    fn reverse_dependencies(&mut self, _endpoint: &RelationKey) -> StoreResult<Vec<RelationKey>> {
        Ok(Vec::new())
    }

    fn close_reverse(&mut self, _endpoint: &RelationKey) {}

    /// Discover the exhaustive plan for this full endpoint under the enclosing
    /// operation's fixed selection. No evaluator may run inside this call.
    fn discover(&mut self, endpoint: &RelationKey) -> StoreResult<RootDiscovery>;

    /// Whether this provider can prepare keyed root reads for all pending
    /// endpoints in a scheduler round. Providers that do not opt in retain the
    /// original interleaved discover-and-admit order.
    fn supports_batched_discoveries(&self) -> bool {
        false
    }

    /// Discover a set of independent pending endpoints. Providers with a
    /// keyed batch source can prepare the reads together; the default keeps
    /// existing providers scalar.
    fn discover_many(&mut self, endpoints: &[RelationKey]) -> StoreResult<Vec<RootDiscovery>> {
        endpoints
            .iter()
            .map(|endpoint| self.discover(endpoint))
            .collect()
    }

    /// Install one immutable relation from complete root-specific evaluations.
    /// This is not permission to mutate previously closed endpoint relations.
    /// The installed lexical relation must carry its plan and materialization
    /// coverage so successful answers observe it through ordinary candidates.
    /// Returned completion is also retained for cancellation, not globally
    /// attached to unrelated successful roots by this scheduler.
    fn close(
        &mut self,
        endpoint: &RelationKey,
        inputs: &[(ReferenceKey, &FactResolutionAnswer)],
    ) -> StoreResult<ResolutionCompletion>;

    /// Request structural member-owner selection after positioned receivers
    /// finish. The scheduler owns its hierarchy and source dependencies. This
    /// capability can serve imports or projection owners; no request preserves
    /// the provider's ordinary close behavior.
    fn member_selection(
        &mut self,
        _endpoint: &RelationKey,
        _inputs: &[(ReferenceKey, &FactResolutionAnswer)],
    ) -> StoreResult<MemberSelectionOutcome> {
        Ok(MemberSelectionOutcome::Ready {
            request: None,
            completion: ResolutionCompletion::Complete,
        })
    }

    /// Retain member-reader evidence before a publishing provider memoizes closure.
    fn close_with_member_completion(
        &mut self,
        endpoint: &RelationKey,
        inputs: &[(ReferenceKey, &FactResolutionAnswer)],
        member_completion: &ResolutionCompletion,
    ) -> StoreResult<ResolutionCompletion> {
        Ok(self.close(endpoint, inputs)?.combine(member_completion))
    }

    /// Install the relation after its requested member selection has completed.
    fn close_selected_members(
        &mut self,
        _endpoint: &RelationKey,
        _inputs: &[(ReferenceKey, &FactResolutionAnswer)],
        _selection: &MemberSelection,
    ) -> StoreResult<ResolutionCompletion> {
        unreachable!("a provider requesting member selection installs its result")
    }

    /// Borrow only provider proofs, without cloning unrelated closure metadata.
    fn discharged_provider_reasons(
        &self,
        _endpoint: &RelationKey,
    ) -> Option<&BTreeSet<SemanticId>> {
        None
    }

    /// Preserve the requesting relation's member proofs for scalar preparation
    /// and subsequent reads of this already-closed endpoint in the same request.
    fn retain_member_provider_reasons(
        &mut self,
        _endpoint: &RelationKey,
        _reasons: &BTreeSet<SemanticId>,
    ) {
        unreachable!("a provider with member proofs retains them")
    }

    /// The placeholder reasons a closed relation proved dead for the lookup it
    /// continued. `Some` says the closure answered the boundary question its
    /// endpoint asked with its own positive witness: the requesting reference's
    /// selected route reasons and the listed placeholder reasons no longer
    /// describe an open branch. It can also allow operation-local placeholders
    /// to retire once that route binds selected targets. `None` says the closure
    /// decided nothing beyond its candidate paths.
    fn resolved_closure_discharges(&self, _endpoint: &RelationKey) -> Option<ClosureDischarges> {
        None
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Unsupported {
    /// The finite task/relation dependency graph closed a cycle: every
    /// discovery returned, every runnable task drained, and the roots below
    /// still wait on relations that wait on them.
    ///
    /// No cyclic relation is published. `completion` names unanswered roots
    /// with `CyclicPrefixDependency`; `root_answers` retains independent results
    /// and per-root incomplete evidence for production consumers.
    CyclicPrefixDependency {
        pending_roots: Vec<SemanticId>,
        pending_endpoints: Vec<EndpointSignature>,
        completion: ResolutionCompletion,
        root_answers: Vec<FactResolutionAnswer>,
    },
}

// `Ready` is the common outcome of every scheduled root, so boxing its answer
// would add one allocation per resolved reference on the hot path to satisfy
// the size-difference lint; the other variants are rare terminal states.
#[allow(clippy::large_enum_variant)]
pub(crate) enum Outcome {
    Ready(FactResolutionAnswer),
    Cancelled(ResolutionCompletion),
    /// No unavailable relation is published. Completion retains the scheduler's
    /// diagnostic evidence; `root_answers` retains the input's own evidence.
    Unavailable {
        endpoint: EndpointSignature,
        reason: RootUnavailableReason,
        completion: ResolutionCompletion,
        root_seed_completions: Vec<(SemanticId, ResolutionCompletion)>,
        root_answers: Vec<FactResolutionAnswer>,
    },
    Unsupported(Unsupported),
}

/// What one root of a resolved batch got back.
pub(crate) struct RootResolution {
    pub(crate) answer: FactResolutionAnswer,
    /// The metrics of this root's own frames. The frames of the prefix tasks
    /// belong to the batch that admitted them, not to whichever root reached
    /// them first, so they are reported separately.
    pub(crate) metrics: ResolutionBatchMetrics,
}

/// The batch counterpart of [`Outcome`].
///
/// Cancellation stops the whole operation. Unavailable endpoints and cycles
/// retain one answer per input after all independent work has finished; the raw
/// failure variant also keeps the scheduler's diagnostic evidence.
pub(crate) enum BatchOutcome {
    /// One resolution per input root, in input order.
    Ready(Vec<RootResolution>),
    Cancelled(ResolutionCompletion),
    Unavailable {
        endpoint: EndpointSignature,
        reason: RootUnavailableReason,
        completion: ResolutionCompletion,
        root_seed_completions: Vec<(SemanticId, ResolutionCompletion)>,
        root_answers: Vec<FactResolutionAnswer>,
    },
    Unsupported(Unsupported),
}

struct Task<'a> {
    root: ReferenceKey,
    memo_key: Option<RootMemoKey>,
    frame: Option<DemandFactEvaluationTask<'a>>,
    answer: Option<FactResolutionAnswer>,
    /// This task's own frame metrics, mirrored after every poll of it.
    metrics: ResolutionBatchMetrics,
    waiting: usize,
    /// The relations this task registered a wait on while `waiting` is
    /// nonzero. The wait-cycle walk follows these; a relation that closed
    /// while other waits are outstanding stays here and is skipped there.
    waits_on: Vec<usize>,
    /// The demanded references this task owns in `Scheduler::claims`: the
    /// ones its live lexical frame is evaluating, bounded by that frame.
    claims: Vec<ReferenceKey>,
    /// The demanded reference this task is waiting for another task to finish.
    claim_wait: Option<ReferenceKey>,
    dependents: Vec<usize>,
    /// Full qualified supertype tasks this task awaits. Query lifetime only.
    hierarchy_waits: Vec<usize>,
    /// Tasks waiting for this root's completed qualified type binding.
    hierarchy_dependents: Vec<usize>,
    hierarchy_answer_needed: bool,
}

/// One demanded reference a live task of this scheduler is evaluating now.
///
/// The operation's memo answers a second task only once the first has finished
/// the reference, so two tasks that reach it before either finishes both miss
/// and both pay for every read behind it. `waiters` are the tasks that stopped
/// instead. `bypass` names the tasks that may not stop, because waiting would
/// close a cycle in the wait graph; those evaluate the reference themselves,
/// which is what every task did before this claim existed.
struct DemandedReferenceOwner {
    owner: usize,
    waiters: Vec<usize>,
    bypass: HashSet<usize>,
}

struct Relation<'source> {
    endpoint: RelationKey,
    dependencies: Vec<usize>,
    pending: usize,
    waiters: Vec<usize>,
    closed: bool,
    member_selection: Option<Box<MemberSelectionFrame<'source>>>,
    selected_members: Option<MemberSelection>,
    continuation_members: Option<MemberSelection>,
    close_continuation: Option<CloseContinuationId>,
    close_reference: Option<(ReferenceKey, usize)>,
    member_requested: bool,
    prefix_charged: bool,
    member_completion: ResolutionCompletion,
    completion: Option<ResolutionCompletion>,
    /// Initial positioned receivers remain distinct from ancestor tasks.
    prefix_count: usize,
    /// Relations whose candidate reads this member phase awaits.
    waits_on: Vec<usize>,
    /// Other member phases waiting for this relation to close.
    relation_waiters: Vec<usize>,
    // Unplaceable endpoints stay in the wait graph, without becoming readable.
    // Their dependents stop, while unrelated tasks continue in this batch.
    unavailable: Option<(RootUnavailableReason, ResolutionCompletion)>,
}

/// Task-side state for one registered qualified group. Language rows stay in
/// the provider; this state owns only scheduler frames and exact reply keys.
struct QualifiedMemberWait<'source> {
    id: QualifiedMemberId,
    input: TypedPrerequisiteInput,
    member_selection: Option<Box<MemberSelectionFrame<'source>>>,
    selection: Option<MemberSelection>,
    continuation_members: Option<MemberSelection>,
    close_continuation: Option<CloseContinuationId>,
    close_reference: Option<(ReferenceKey, usize)>,
    completion: ResolutionCompletion,
    phase: QualifiedMemberPhase,
}

#[derive(Clone, Copy)]
enum QualifiedMemberPhase {
    Constructing,
    Preparing,
    Selecting,
    Access,
}

enum RelationAdmission {
    Ready(usize),
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Runnable {
    Task(usize),
    Relation(usize),
}

/// Each task and relation is admitted once. Waiting does not poll a task or
/// repeat its already charged reads. The queue contains only runnable tasks;
/// relation discovery is synchronous and exhausted before it enters the arena.
struct Scheduler<'a> {
    close_waiters: HashSet<RelationKey>,
    access_reference_answers: HashMap<MemberConsumerId, Box<FactResolutionAnswer>>,
    tasks: Vec<Task<'a>>,
    task_ids: HashMap<ReferenceKey, usize>,
    runnable: VecDeque<Runnable>,
    relations: Vec<Relation<'a>>,
    relation_ids: HashMap<RelationKey, usize>,
    qualified_members: HashMap<usize, QualifiedMemberWait<'a>>,
    typed_references: HashMap<usize, (SemanticId, usize)>,
    qualified_dependents: HashMap<usize, Vec<usize>>,
    qualified_evidence: HashMap<
        QualifiedMemberId,
        crate::analyzer::store::resolution_operation::member_access::MemberAccessEvidence,
    >,
    /// The demanded references this scheduler's live tasks are evaluating.
    /// Bounded by the tasks, and dropped with the scheduler.
    claims: HashMap<ReferenceKey, DemandedReferenceOwner>,
    /// Placeholder reasons each closed relation retired for the lookups it
    /// continued, handed to a waiting task before its next poll.
    closure_discharges: HashMap<RelationKey, ClosureDischarges>,
    evidence: CancellationEvidenceLedger,
    work: usize,
    completed_prefix: usize,
}

impl<'a> Scheduler<'a> {
    fn unavailable(
        mut self,
        operation: &mut Resources<'_, 'a>,
        endpoint: EndpointSignature,
        reason: RootUnavailableReason,
        root_seed_completions: Vec<(SemanticId, ResolutionCompletion)>,
    ) -> SchedulerOutcome<'a> {
        let cancellation = operation.session.cancellation;
        for task in &self.tasks {
            if !operation.session.charge_scope_steps(1) {
                return SchedulerOutcome::Terminal(self.cancelled(operation));
            }
            let Some(frame) = &task.frame else {
                // Completed answers are already in the scheduler ledger.
                continue;
            };
            let state = frame.evaluation.as_ref().expect("task is between polls");
            state.cancellation_reasons.include_retained_evidence(
                &mut self.evidence,
                cancellation,
                &mut self.work,
            );
            if state.cancellation_observed {
                return SchedulerOutcome::Terminal(self.cancelled(operation));
            }
        }
        for relation in &self.relations {
            if let Some(frame) = &relation.member_selection {
                frame
                    .evaluation
                    .as_ref()
                    .expect("member phase is between polls")
                    .cancellation_reasons
                    .include_retained_evidence(&mut self.evidence, cancellation, &mut self.work);
                self.evidence
                    .include(&frame.completion, cancellation, &mut self.work);
            }
            if let Some(selected) = &relation.selected_members {
                self.evidence
                    .include(&selected.completion, cancellation, &mut self.work);
            }
        }
        operation.include_hierarchy_cancellation_evidence(&mut self.evidence, &mut self.work);
        if cancellation.is_cancelled()
            || operation.session.resolution_stopped()
            || self.evidence.cancellation_observed()
        {
            return SchedulerOutcome::Terminal(self.cancelled(operation));
        }
        // Do not finalize live batches or cancel frames merely to manufacture
        // a terminal union. Their not-yet-ledgered operands stay unfinished.
        // If actual cancellation arrives during this observational finish,
        // restore the retained union before the full cancellation drain.
        let (completion, cancelled) =
            std::mem::take(&mut self.evidence).finish(false, cancellation, &mut self.work);
        if cancelled || cancellation.is_cancelled() || operation.session.resolution_stopped() {
            self.evidence
                .include(&completion, cancellation, &mut self.work);
            return SchedulerOutcome::Terminal(self.cancelled(operation));
        }
        let outcome = BatchOutcome::Unavailable {
            endpoint,
            reason,
            completion,
            root_seed_completions,
            root_answers: Vec::new(),
        };
        SchedulerOutcome::Incomplete(Box::new(self), outcome)
    }

    /// The dependency component belongs to one query; no solved index survives it.
    fn blocked_task_component(
        &self,
        id: usize,
    ) -> (
        HashSet<Runnable>,
        ResolutionCompletion,
        Vec<SemanticId>,
        bool,
    ) {
        let mut stack = vec![Runnable::Task(id)];
        let mut seen = HashSet::default();
        let mut reasons = ResolutionCompletion::Complete;
        let mut pending = Vec::new();
        let mut unavailable = false;
        while let Some(node) = stack.pop() {
            if !seen.insert(node) {
                continue;
            }
            match node {
                Runnable::Task(id) => {
                    let task = &self.tasks[id];
                    if task.answer.is_some() {
                        continue;
                    }
                    pending.push(task.root.reference);
                    if let Some(wait) = self.qualified_members.get(&id) {
                        reasons = reasons.combine(&wait.completion);
                        if let Some(frame) = &wait.member_selection {
                            reasons = reasons.combine(&frame.completion);
                        }
                    }
                    stack.extend(task.waits_on.iter().copied().map(Runnable::Relation));
                    stack.extend(task.hierarchy_waits.iter().copied().map(Runnable::Task));
                    if let Some(reference) = task.claim_wait {
                        let claim = self
                            .claims
                            .get(&reference)
                            .expect("a blocked claim retains its owner");
                        stack.push(Runnable::Task(claim.owner));
                    }
                }
                Runnable::Relation(id) => {
                    let relation = &self.relations[id];
                    if relation.closed {
                        continue;
                    }
                    reasons = reasons.combine(&relation.member_completion);
                    if let Some(frame) = &relation.member_selection {
                        reasons = reasons.combine(&frame.completion);
                        pending.push(
                            frame
                                .evaluation
                                .as_ref()
                                .expect("member phase is between polls")
                                .root,
                        );
                    }
                    if let Some((_, completion)) = &relation.unavailable {
                        unavailable = true;
                        reasons = reasons.combine(completion);
                    }
                    stack.extend(relation.dependencies.iter().copied().map(Runnable::Task));
                    stack.extend(relation.waits_on.iter().copied().map(Runnable::Relation));
                }
            }
        }
        (seen, reasons, pending, unavailable)
    }

    /// Only an access row receives this local terminal reply. The blocked task,
    /// prefix waits and relation publication retain their existing state.
    fn resume_drained_access_references(&mut self, operation: &Resources<'_, 'a>) -> bool {
        let cancellation = operation.session.cancellation;
        if cancellation.is_cancelled() || operation.session.resolution_stopped() {
            return false;
        }
        let mut waits = self
            .relations
            .iter()
            .enumerate()
            .filter_map(|(id, relation)| {
                relation
                    .close_reference
                    .filter(|(_, target)| self.tasks[*target].answer.is_none())
                    .map(|(_, target)| (MemberConsumerId::Relation(id), target))
            })
            .chain(self.qualified_members.iter().filter_map(|(&id, wait)| {
                matches!(wait.phase, QualifiedMemberPhase::Access)
                    .then_some(wait.close_reference)
                    .flatten()
                    .filter(|(_, target)| self.tasks[*target].answer.is_none())
                    .map(|(_, target)| (MemberConsumerId::QualifiedTask(id), target))
            }))
            .collect::<Vec<_>>();
        waits.sort_unstable();
        // Compute all component evidence before detaching any access edge.
        let replies = waits
            .into_iter()
            .map(|(consumer, target)| {
                let (nodes, mut completion, pending, unavailable) =
                    self.blocked_task_component(target);
                for node in &nodes {
                    if let Runnable::Task(id) = *node
                        && let Some(frame) = &self.tasks[id].frame
                    {
                        if let Some(state) = &frame.evaluation {
                            if let Some(seed) = &state.root_seed {
                                completion = completion.combine(seed.completion());
                            }
                            for gap in state
                                .forced_reference_gaps
                                .values()
                                .chain(state.forced_slot_gaps.values())
                            {
                                completion = completion.combine(gap);
                            }
                        }
                        for answer in frame.answers.values() {
                            completion = completion.combine(answer.completion());
                        }
                        for state in frame.states.values() {
                            completion = completion.combine(state.completion());
                        }
                    }
                }
                let consumer_node = match consumer {
                    MemberConsumerId::Relation(id) => Runnable::Relation(id),
                    MemberConsumerId::QualifiedTask(id) => Runnable::Task(id),
                };
                if nodes.contains(&consumer_node) || !unavailable {
                    completion = completion.combine(&ResolutionCompletion::incomplete(
                        pending
                            .into_iter()
                            .map(ResolutionIncompleteReason::CyclicPrefixDependency),
                    ));
                }
                if completion == ResolutionCompletion::Complete {
                    completion = unavailable_reference_completion(
                        &completion,
                        self.tasks[target].root.reference,
                        &[],
                    );
                }
                assert_ne!(
                    completion,
                    ResolutionCompletion::Complete,
                    "a drained access prerequisite is never a completeness proof"
                );
                let metadata = self.tasks[target]
                    .frame
                    .as_ref()
                    .and_then(|frame| frame.evaluation.as_ref())
                    .and_then(|state| {
                        state.root_site_metadata.or_else(|| {
                            state
                                .root_seed
                                .as_ref()
                                .and_then(ReferenceSeed::site_metadata)
                        })
                    });
                (
                    consumer,
                    target,
                    Box::new(incomplete_fact_resolution_answer(
                        metadata,
                        completion,
                        cancellation,
                    )),
                )
            })
            .collect::<Vec<_>>();
        if cancellation.is_cancelled() || operation.session.resolution_stopped() {
            return false;
        }
        let resumed = !replies.is_empty();
        for (consumer, target, reply) in replies {
            assert!(
                self.access_reference_answers
                    .insert(consumer, reply)
                    .is_none(),
                "one terminal reply per held access wait"
            );
            match consumer {
                MemberConsumerId::Relation(id) => {
                    self.tasks[target].dependents.retain(|&waiter| waiter != id);
                    assert!(self.relations[id].pending > 0);
                    self.relations[id].pending -= 1;
                }
                MemberConsumerId::QualifiedTask(id) => {
                    self.qualified_dependents
                        .get_mut(&target)
                        .expect("registered access dependency")
                        .retain(|&waiter| waiter != id);
                    assert!(self.tasks[id].waiting > 0);
                    self.tasks[id].waiting -= 1;
                }
            }
            if consumer.pending(self) == 0 {
                consumer.enqueue(self);
            }
        }
        resumed
    }

    /// Finalize only input roots left blocked after all runnable work drained.
    /// Walk each task's recorded waits, so a failed endpoint contributes evidence
    /// only to its dependency component. This state lives for this batch only.
    fn finish_incomplete_roots(
        &mut self,
        operation: &mut Resources<'_, 'a>,
        root_task_count: usize,
    ) -> StoreResult<()> {
        self.retain_completed_roots(operation);
        let completions = self.tasks[..root_task_count]
            .iter()
            .enumerate()
            .map(|(id, task)| {
                if task.answer.is_some() {
                    return None;
                }
                let (_, reasons, pending, unavailable) = self.blocked_task_component(id);
                Some(if unavailable {
                    let seed_completion = task
                        .frame
                        .as_ref()
                        .and_then(|frame| frame.evaluation.as_ref())
                        .and_then(|state| state.root_seed.as_ref())
                        .map_or(ResolutionCompletion::Complete, |seed| {
                            seed.completion().clone()
                        });
                    unavailable_reference_completion(
                        &reasons,
                        task.root.reference,
                        &[(task.root.reference, seed_completion)],
                    )
                } else {
                    reasons.combine(&ResolutionCompletion::incomplete(
                        pending
                            .into_iter()
                            .map(ResolutionIncompleteReason::CyclicPrefixDependency),
                    ))
                })
            })
            .collect::<Vec<_>>();
        for (task, completion) in self.tasks[..root_task_count].iter_mut().zip(completions) {
            let Some(completion) = completion else {
                continue;
            };
            let state = task
                .frame
                .as_ref()
                .expect("a blocked task retains its frame")
                .evaluation
                .as_ref()
                .expect("task is between polls");
            let metadata = state.root_site_metadata.or_else(|| {
                state
                    .root_seed
                    .as_ref()
                    .and_then(ReferenceSeed::site_metadata)
            });
            let completion = state.root_seed.as_ref().map_or(completion.clone(), |seed| {
                completion.combine(seed.completion())
            });
            let mut answer = incomplete_fact_resolution_answer(
                metadata,
                completion,
                operation.session.cancellation,
            );
            if let Some(binding) = state.lexical_answers.get(&task.root.reference) {
                answer.binding = ResolutionAnswer::new(
                    binding.targets().to_vec(),
                    binding.witnesses().to_vec(),
                    binding.completion().combine(answer.binding.completion()),
                );
                answer.completion = answer.completion.combine(binding.completion());
                if metadata.is_some_and(FactReferenceSiteMetadata::is_callable_reference) {
                    // Lexical targets are retained evidence, but the blocked
                    // evaluation has not certified target-local receiver
                    // admission. Keep those channels explicitly unresolved.
                    answer.callable_receiver_dispositions = binding
                        .targets()
                        .iter()
                        .map(|&target| {
                            FactCallableReceiverTargetDisposition::new(
                                target,
                                FactCallableReceiverDisposition::unresolved(
                                    FactReferenceReceiverGap::UnresolvedReceiver,
                                ),
                            )
                        })
                        .collect();
                }
            }
            task.answer = Some(answer);
            task.frame = None;
        }
        Ok(())
    }

    /// Admit one task per distinct root, at most once per scheduler.
    ///
    /// `seed` is the root's source seed when the caller already read it, which
    /// is how a batch reads all of its roots' seeds in one statement set. A
    /// task admitted without one, which is every prefix task discovered inside
    /// the loop, is seeded by the round that first polls it, or reads its own
    /// seed in its first lexical frame when it is the only task that round
    /// admitted.
    fn admit(
        &mut self,
        operation: &mut Resources<'_, 'a>,
        root: ReferenceKey,
        seed: Option<ReferenceSeed>,
    ) -> Option<usize> {
        if let Some(&id) = self.task_ids.get(&root) {
            return Some(id);
        }
        if !operation.session.charge_scope_steps(1) {
            return None;
        }
        let mut evaluation = FactEvaluation::new_with_forward_artifacts(
            operation.session,
            operation.hierarchy,
            operation.forward_candidate_artifacts,
            operation.candidate_paths,
            root.reference,
        );
        if let Some(seed) = seed {
            evaluation.install_batched_root_seed(seed);
        }
        let state = evaluation.into_checkpoint_state();
        let id = self.tasks.len();
        self.tasks.push(Task {
            root,
            memo_key: None,
            frame: Some(DemandFactEvaluationTask::new(state)),
            answer: None,
            metrics: ResolutionBatchMetrics::default(),
            waiting: 0,
            waits_on: Vec::new(),
            claims: Vec::new(),
            claim_wait: None,
            dependents: Vec::new(),
            hierarchy_waits: Vec::new(),
            hierarchy_dependents: Vec::new(),
            hierarchy_answer_needed: false,
        });
        assert!(self.task_ids.insert(root, id).is_none());
        self.runnable.push_back(Runnable::Task(id));
        Some(id)
    }

    /// Install a discovered endpoint once; both reference tasks and relation
    /// member phases use the same prefix admission and completion ledger.
    fn install_relation(
        &mut self,
        operation: &mut Resources<'_, 'a>,
        endpoint: RelationKey,
        discovery: RootDiscovery,
    ) -> RelationAdmission {
        let completion = match &discovery {
            RootDiscovery::Ready(plan) => &plan.completion,
            RootDiscovery::AlreadyReady { completion }
            | RootDiscovery::Unavailable { completion, .. }
            | RootDiscovery::Cancelled(completion) => completion,
        };
        self.evidence
            .include(completion, operation.session.cancellation, &mut self.work);
        if operation.session.cancellation.is_cancelled()
            || operation.session.resolution_stopped()
            || self.evidence.cancellation_observed()
        {
            return RelationAdmission::Cancelled;
        }
        let initial_completion = completion.clone();
        let mut unavailable = None;
        let (prefixes, closed) = match discovery {
            RootDiscovery::AlreadyReady { .. } => (Vec::new(), true),
            RootDiscovery::Ready(plan) => (plan.prefixes, false),
            RootDiscovery::Unavailable { reason, completion } => {
                unavailable = Some((reason, completion));
                (Vec::new(), false)
            }
            RootDiscovery::Cancelled(_) => return RelationAdmission::Cancelled,
        };
        let mut dependencies = Vec::new();
        let mut seen = HashSet::default();
        for prefix in prefixes {
            if !operation.session.charge_scope_steps(1) {
                return RelationAdmission::Cancelled;
            }
            let Some(dependency) = self.admit(operation, prefix, None) else {
                return RelationAdmission::Cancelled;
            };
            if seen.insert(dependency) {
                dependencies.push(dependency);
            }
        }
        let id = self.relations.len();
        assert!(self.relation_ids.insert(endpoint.clone(), id).is_none());
        let mut pending = 0;
        for &dependency in &dependencies {
            if self.tasks[dependency].answer.is_none() {
                self.tasks[dependency].dependents.push(id);
                pending += 1;
            }
        }
        self.relations.push(Relation {
            endpoint,
            prefix_count: dependencies.len(),
            dependencies,
            pending,
            waiters: Vec::new(),
            closed,
            member_selection: None,
            selected_members: None,
            continuation_members: None,
            close_continuation: None,
            close_reference: None,
            member_requested: false,
            prefix_charged: false,
            member_completion: ResolutionCompletion::Complete,
            completion: closed.then_some(initial_completion),
            waits_on: Vec::new(),
            relation_waiters: Vec::new(),
            unavailable,
        });
        if !closed && pending == 0 && self.relations[id].unavailable.is_none() {
            self.runnable.push_back(Runnable::Relation(id));
        }
        RelationAdmission::Ready(id)
    }

    /// Retain only the negative provider proofs consumed by this selection.
    /// A closed endpoint can predate this scheduler, so consult its provider
    /// when the scheduler has no local discharge record.
    fn member_readiness(
        &self,
        requests: &[BatchCandidateRequest],
        environment: EnvironmentId,
        provider: &(impl RootProvider + ?Sized),
        discharged_provider_reasons: &mut BTreeSet<SemanticId>,
    ) -> DemandForwardReadiness {
        for request in requests {
            let endpoint = RelationKey {
                endpoint: request.endpoint().clone(),
                environment,
            };
            if !self
                .relation_ids
                .get(&endpoint)
                .is_some_and(|&id| self.relations[id].closed)
            {
                return DemandForwardReadiness::AwaitingDependencies;
            }
            if let Some(discharges) = self.closure_discharges.get(&endpoint) {
                discharged_provider_reasons
                    .extend(discharges.discharged_provider_reasons.iter().copied());
            } else if let Some(reasons) = provider.discharged_provider_reasons(&endpoint) {
                discharged_provider_reasons.extend(reasons.iter().copied());
            }
        }
        DemandForwardReadiness::Ready
    }

    fn retain_completed_roots(&self, operation: &Resources<'_, '_>) {
        if let Some((memo, _, _)) = operation.completed_roots {
            for task in &self.tasks {
                if let (Some(key), Some(answer)) = (&task.memo_key, &task.answer) {
                    memo.retain(key, answer, operation.session);
                }
            }
        }
    }

    /// One resolution per input root, in input order.
    ///
    /// Duplicate roots share one task, so the first input position at a task
    /// moves that task's one answer out and every later position repeats it.
    /// The tasks above the roots are the prefixes this batch admitted; their
    /// frames are the batch's shared work and their metrics go to `metrics`.
    fn take_root_resolutions(
        &mut self,
        root_tasks: &[usize],
        root_task_count: usize,
        metrics: &mut ResolutionBatchMetrics,
    ) -> Vec<RootResolution> {
        for task in &self.tasks[root_task_count..] {
            metrics.accumulate(task.metrics);
        }
        let mut resolutions = Vec::with_capacity(root_tasks.len());
        let mut moved = HashMap::default();
        let mut repeated = Vec::new();
        for (position, &id) in root_tasks.iter().enumerate() {
            if let Some(&source) = moved.get(&id) {
                repeated.push((position, source));
                resolutions.push(None);
                continue;
            }
            assert!(moved.insert(id, position).is_none());
            let task = &mut self.tasks[id];
            resolutions.push(Some(RootResolution {
                answer: task
                    .answer
                    .take()
                    .expect("an answered root task retains its answer"),
                metrics: task.metrics,
            }));
        }
        for (position, source) in repeated {
            let shared = resolutions[source]
                .as_ref()
                .expect("a repeated root reads the position that moved its answer");
            resolutions[position] = Some(RootResolution {
                answer: shared.answer.clone(),
                metrics: shared.metrics,
            });
        }
        resolutions
            .into_iter()
            .map(|resolution| resolution.expect("every input root has one resolution"))
            .collect()
    }

    fn cancelled(mut self, operation: &mut Resources<'_, 'a>) -> BatchOutcome {
        for task in &mut self.tasks {
            let answer = match task.frame.take() {
                Some(mut frame) => frame.cancel(
                    operation.session,
                    operation.hierarchy,
                    operation.candidate_paths,
                ),
                None => task
                    .answer
                    .take()
                    .expect("terminal task retains its answer"),
            };
            include_fact_answer_cancellation_evidence(
                &mut self.evidence,
                &answer,
                operation.session.cancellation,
                &mut self.work,
            );
        }
        for (_, mut wait) in self.qualified_members.drain() {
            self.evidence.include(
                &wait.completion,
                operation.session.cancellation,
                &mut self.work,
            );
            if let Some(frame) = wait.member_selection.take() {
                frame
                    .evaluation
                    .as_ref()
                    .expect("member phase is between polls")
                    .cancellation_reasons
                    .include_retained_evidence(
                        &mut self.evidence,
                        operation.session.cancellation,
                        &mut self.work,
                    );
                self.evidence.include(
                    &frame.completion,
                    operation.session.cancellation,
                    &mut self.work,
                );
                frame.cancel(operation);
            }
        }
        for relation in &mut self.relations {
            if relation.member_completion != ResolutionCompletion::Complete {
                self.evidence.include(
                    &relation.member_completion,
                    operation.session.cancellation,
                    &mut self.work,
                );
            }
            if let Some(frame) = relation.member_selection.take() {
                let state = frame
                    .evaluation
                    .as_ref()
                    .expect("member phase is between polls");
                state.cancellation_reasons.include_retained_evidence(
                    &mut self.evidence,
                    operation.session.cancellation,
                    &mut self.work,
                );
                self.evidence.include(
                    &frame.completion,
                    operation.session.cancellation,
                    &mut self.work,
                );
                frame.cancel(operation);
            }
            if let Some(selected) = &relation.selected_members {
                self.evidence.include(
                    &selected.completion,
                    operation.session.cancellation,
                    &mut self.work,
                );
            }
        }
        operation.include_hierarchy_cancellation_evidence(&mut self.evidence, &mut self.work);
        let (completion, _) =
            self.evidence
                .finish(true, operation.session.cancellation, &mut self.work);
        BatchOutcome::Cancelled(completion)
    }
}

pub(super) fn resolve<'a>(
    operation: &mut Resources<'_, 'a>,
    root: SemanticId,
    provider: &mut (impl RootProvider + ?Sized),
) -> StoreResult<Outcome> {
    resolve_with_metrics(
        operation,
        root,
        provider,
        &mut ResolutionBatchMetrics::default(),
    )
}

pub(super) fn resolve_with_metrics<'a>(
    operation: &mut Resources<'_, 'a>,
    root: SemanticId,
    provider: &mut (impl RootProvider + ?Sized),
    metrics: &mut ResolutionBatchMetrics,
) -> StoreResult<Outcome> {
    // One root is the batch of one. This route reports the root task's own
    // frames and nothing else, which is exactly what it reported when it
    // mirrored task zero's metrics, so the prefix tasks this root's own
    // discovery admits stay out of `metrics` as they always have.
    let mut prefixes = ResolutionBatchMetrics::default();
    Ok(
        match resolve_batch_with_metrics(operation, &[root], provider, &mut prefixes)? {
            BatchOutcome::Ready(resolutions) => {
                let mut resolutions = resolutions.into_iter();
                let resolution = resolutions
                    .next()
                    .expect("a one-root batch answers its root");
                assert!(resolutions.next().is_none());
                *metrics = resolution.metrics;
                Outcome::Ready(resolution.answer)
            }
            BatchOutcome::Cancelled(completion) => Outcome::Cancelled(completion),
            BatchOutcome::Unavailable {
                endpoint,
                reason,
                completion,
                root_seed_completions,
                root_answers,
            } => Outcome::Unavailable {
                endpoint,
                reason,
                completion,
                root_seed_completions,
                root_answers,
            },
            BatchOutcome::Unsupported(unsupported) => Outcome::Unsupported(unsupported),
        },
    )
}

/// Resolve one whole reference batch under one scheduler, reading the roots'
/// seeds first.
///
/// This is the entry point for a caller that holds references and no seeds:
/// the point route and the tests. A caller that already holds the seeds, which
/// the reference enumeration does, calls
/// [`resolve_seeded_batch_with_metrics`] and pays for no seed read at all.
pub(super) fn resolve_batch_with_metrics<'a>(
    operation: &mut Resources<'_, 'a>,
    roots: &[SemanticId],
    provider: &mut (impl RootProvider + ?Sized),
    metrics: &mut ResolutionBatchMetrics,
) -> StoreResult<BatchOutcome> {
    let mut scheduler = new_scheduler();
    assert_batch_arity(roots.len());
    let roots = roots
        .iter()
        .copied()
        .map(ReferenceKey::caller)
        .collect::<Vec<_>>();
    let mut seeds = match read_root_seeds(operation, &roots, &mut scheduler)? {
        Some(seeds) => seeds,
        None => return Ok(scheduler.cancelled(operation)),
    };
    let admitted = roots
        .iter()
        .map(|&root| (root, seeds.remove(&root)))
        .collect::<Vec<_>>();
    resolve_admitted_batch(operation, scheduler, admitted, provider, metrics)
}

/// Resolve one whole reference batch whose roots' seeds the caller already
/// holds.
///
/// The reference enumeration builds its batches by reading exactly these seeds
/// (`visit_reference_inventory` calls the same `persisted_reference_seeds` the
/// scalar and batched seams call), so reading them again here would be a
/// duplicate of a read that just happened. Nothing else differs from
/// [`resolve_batch_with_metrics`].
pub(super) fn resolve_seeded_batch_with_metrics<'a>(
    operation: &mut Resources<'_, 'a>,
    seeds: &[ReferenceSeed],
    provider: &mut (impl RootProvider + ?Sized),
    metrics: &mut ResolutionBatchMetrics,
) -> StoreResult<BatchOutcome> {
    assert_batch_arity(seeds.len());
    let admitted = seeds
        .iter()
        .map(|seed| (ReferenceKey::caller(seed.reference()), Some(seed.clone())))
        .collect::<Vec<_>>();
    resolve_admitted_batch(operation, new_scheduler(), admitted, provider, metrics)
}

/// Poll a prerequisite without a requested root and without root finalization.
/// This uses the ordinary task/relation loop and exposes whether the task
/// actually became Ready, rather than receiving a finalized partial answer.
#[cfg(any(test, feature = "test-support"))]
pub(super) fn resolve_prerequisite_for_test(
    operation: &mut Resources<'_, '_>,
    reference: SemanticId,
    provider: &mut impl RootProvider,
) -> StoreResult<Option<FactResolutionAnswer>> {
    let mut scheduler = new_scheduler();
    let Some(id) = scheduler.admit(operation, ReferenceKey::caller(reference), None) else {
        return Ok(None);
    };
    match drive_scheduler(operation, scheduler, provider, Vec::new(), |scheduler| {
        scheduler.tasks[id].answer.is_some()
    })? {
        SchedulerOutcome::Ready(mut scheduler) => Ok(scheduler.tasks[id].answer.take()),
        SchedulerOutcome::Incomplete(_, _) | SchedulerOutcome::Terminal(_) => Ok(None),
    }
}

fn new_scheduler<'a>() -> Scheduler<'a> {
    Scheduler {
        close_waiters: HashSet::default(),
        access_reference_answers: HashMap::default(),
        tasks: Vec::new(),
        task_ids: HashMap::default(),
        runnable: VecDeque::new(),
        relations: Vec::new(),
        relation_ids: HashMap::default(),
        qualified_members: HashMap::default(),
        typed_references: HashMap::default(),
        qualified_dependents: HashMap::default(),
        qualified_evidence: HashMap::default(),
        claims: HashMap::default(),
        closure_discharges: HashMap::default(),
        evidence: CancellationEvidenceLedger::default(),
        work: 0,
        completed_prefix: 0,
    }
}

/// Shared member prerequisite consumer. Task IDs here always name a held
/// qualified group; ordinary typed task polling remains unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum MemberConsumerId {
    Relation(usize),
    QualifiedTask(usize),
}
impl MemberConsumerId {
    fn environment(self, scheduler: &Scheduler<'_>) -> EnvironmentId {
        match self {
            Self::Relation(id) => scheduler.relations[id].endpoint.environment,
            Self::QualifiedTask(id) => scheduler.tasks[id].root.environment,
        }
    }
    fn pending(self, scheduler: &Scheduler<'_>) -> usize {
        match self {
            Self::Relation(id) => scheduler.relations[id].pending,
            Self::QualifiedTask(id) => scheduler.tasks[id].waiting,
        }
    }
    fn enqueue(self, scheduler: &mut Scheduler<'_>) {
        scheduler.runnable.push_back(match self {
            Self::Relation(id) => Runnable::Relation(id),
            Self::QualifiedTask(id) => Runnable::Task(id),
        });
    }
    fn await_task(self, scheduler: &mut Scheduler<'_>, dependency: usize) {
        match self {
            Self::Relation(id) => {
                if !scheduler.relations[id].dependencies.contains(&dependency) {
                    scheduler.relations[id].dependencies.push(dependency);
                    scheduler.tasks[dependency].dependents.push(id);
                    scheduler.relations[id].pending += 1;
                }
            }
            Self::QualifiedTask(id) => {
                if !scheduler.tasks[id].hierarchy_waits.contains(&dependency) {
                    scheduler.tasks[id].hierarchy_waits.push(dependency);
                    scheduler
                        .qualified_dependents
                        .entry(dependency)
                        .or_default()
                        .push(id);
                    scheduler.tasks[id].waiting += 1;
                }
            }
        }
    }
    fn await_relation(self, scheduler: &mut Scheduler<'_>, dependency: usize) {
        match self {
            Self::Relation(id) => {
                scheduler.relations[dependency].relation_waiters.push(id);
                scheduler.relations[id].waits_on.push(dependency);
                scheduler.relations[id].pending += 1;
            }
            Self::QualifiedTask(id) => {
                scheduler.relations[dependency].waiters.push(id);
                scheduler.tasks[id].waits_on.push(dependency);
                scheduler.tasks[id].waiting += 1;
            }
        }
    }
}

fn suspend_access_reference<'source>(
    operation: &mut Resources<'_, 'source>,
    scheduler: &mut Scheduler<'source>,
    consumer: MemberConsumerId,
    continuation: CloseContinuationId,
    key: ReferenceKey,
) -> bool {
    continuation.assert_current(HierarchyProvenanceView::new(operation.hierarchy));
    assert_eq!(
        key.environment,
        consumer.environment(scheduler),
        "access prerequisites stay in the selected environment"
    );
    if !operation.session.charge_scope_steps(1) {
        return false;
    }
    let Some(task) = scheduler.admit(operation, key, None) else {
        return false;
    };
    match consumer {
        MemberConsumerId::Relation(id) => {
            scheduler.relations[id].close_continuation = Some(continuation);
            scheduler.relations[id].close_reference = Some((key, task));
        }
        MemberConsumerId::QualifiedTask(id) => {
            let wait = scheduler
                .qualified_members
                .get_mut(&id)
                .expect("held qualified group");
            wait.close_continuation = Some(continuation);
            wait.close_reference = Some((key, task));
        }
    }
    await_access_reference(scheduler, consumer, task);
    true
}

/// Shared Reference continuation bookkeeping for member access and typed seeds.
/// Admission always uses the caller's exact ReferenceKey before reaching here.
fn await_access_reference(scheduler: &mut Scheduler<'_>, consumer: MemberConsumerId, task: usize) {
    if scheduler.tasks[task].answer.is_some() {
        consumer.enqueue(scheduler);
    } else {
        consumer.await_task(scheduler, task);
    }
}

fn suspend_access_members<'source>(
    operation: &mut Resources<'_, 'source>,
    scheduler: &mut Scheduler<'source>,
    consumer: MemberConsumerId,
    continuation: CloseContinuationId,
    request: MemberSelectionRequest,
) -> bool {
    continuation.assert_current(HierarchyProvenanceView::new(operation.hierarchy));
    let Some(frame) = MemberSelectionFrame::new(operation, request) else {
        return false;
    };
    match consumer {
        MemberConsumerId::Relation(id) => {
            scheduler.relations[id].close_continuation = Some(continuation);
            scheduler.relations[id].member_selection = Some(Box::new(frame));
        }
        MemberConsumerId::QualifiedTask(id) => {
            let wait = scheduler
                .qualified_members
                .get_mut(&id)
                .expect("held qualified group");
            wait.close_continuation = Some(continuation);
            wait.member_selection = Some(Box::new(frame));
        }
    }
    consumer.enqueue(scheduler);
    true
}

enum MemberConsumerPoll {
    Pending,
    Ready(MemberSelection),
    Cancelled,
}

/// One selection/order driver and one prerequisite admission algorithm for
/// source relations and typed qualified groups.
fn poll_member_consumer<'source>(
    operation: &mut Resources<'_, 'source>,
    scheduler: &mut Scheduler<'source>,
    provider: &mut (impl RootProvider + ?Sized),
    consumer: MemberConsumerId,
    frame: &mut MemberSelectionFrame<'source>,
) -> StoreResult<MemberConsumerPoll> {
    let environment = consumer.environment(scheduler);
    let mut discharged_provider_reasons = BTreeSet::new();
    let polled = frame.poll(operation, &mut |requests| {
        Ok(scheduler.member_readiness(
            requests,
            environment,
            provider,
            &mut discharged_provider_reasons,
        ))
    })?;
    frame
        .discharged_provider_reasons
        .extend(discharged_provider_reasons);
    match polled {
        MemberSelectionPoll::Ready(selection) => return Ok(MemberConsumerPoll::Ready(selection)),
        MemberSelectionPoll::Cancelled => return Ok(MemberConsumerPoll::Cancelled),
        MemberSelectionPoll::Continue => consumer.enqueue(scheduler),
        MemberSelectionPoll::AwaitingHierarchyReferences(references) => {
            assert!(!references.is_empty());
            for reference in references {
                let Some(dependency) = scheduler.admit(
                    operation,
                    ReferenceKey {
                        reference,
                        environment,
                    },
                    None,
                ) else {
                    return Ok(MemberConsumerPoll::Cancelled);
                };
                if let Some(answer) = &scheduler.tasks[dependency].answer {
                    let mut evaluation =
                        FactEvaluation::new(operation.session, operation.hierarchy, reference);
                    if !evaluation.publish_qualified_hierarchy_reference(reference, answer)? {
                        return Ok(MemberConsumerPoll::Cancelled);
                    }
                } else {
                    scheduler.tasks[dependency].hierarchy_answer_needed = true;
                    consumer.await_task(scheduler, dependency);
                }
            }
            if consumer.pending(scheduler) == 0 {
                consumer.enqueue(scheduler);
            }
        }
        MemberSelectionPoll::AwaitingDependencies(endpoints) => {
            let mut seen = HashSet::default();
            for endpoint in endpoints {
                let endpoint = RelationKey {
                    endpoint,
                    environment,
                };
                if !operation.session.charge_scope_steps(1) {
                    return Ok(MemberConsumerPoll::Cancelled);
                }
                let dependency = if let Some(&dependency) = scheduler.relation_ids.get(&endpoint) {
                    dependency
                } else {
                    let discovery = provider.discover(&endpoint)?;
                    match scheduler.install_relation(operation, endpoint, discovery) {
                        RelationAdmission::Ready(id) => id,
                        RelationAdmission::Cancelled => return Ok(MemberConsumerPoll::Cancelled),
                    }
                };
                if !scheduler.relations[dependency].closed && seen.insert(dependency) {
                    consumer.await_relation(scheduler, dependency);
                }
            }
            if consumer.pending(scheduler) == 0 {
                consumer.enqueue(scheduler);
            }
        }
    }
    Ok(MemberConsumerPoll::Pending)
}

/// Run preparation, owner selection, and access through the same parked
/// prerequisite state. A poll never calls another evaluator.
fn poll_qualified_member_consumer<'source>(
    operation: &mut Resources<'_, 'source>,
    scheduler: &mut Scheduler<'source>,
    provider: &mut (impl RootProvider + ?Sized),
    task: usize,
    active: &mut HashSet<QualifiedMemberId>,
) -> StoreResult<bool> {
    use crate::analyzer::store::resolution_operation::demand_closure::Read;
    let mut wait = scheduler
        .qualified_members
        .remove(&task)
        .expect("held qualified group");
    if let Some(mut frame) = wait.member_selection.take() {
        let polled = poll_member_consumer(
            operation,
            scheduler,
            provider,
            MemberConsumerId::QualifiedTask(task),
            &mut frame,
        )?;
        match polled {
            MemberConsumerPoll::Ready(mut selection) => {
                selection
                    .discharged_provider_reasons
                    .extend(frame.discharged_provider_reasons);
                frame
                    .evaluation
                    .as_ref()
                    .expect("member phase is between polls")
                    .cancellation_reasons
                    .include_retained_evidence(
                        &mut scheduler.evidence,
                        operation.session.cancellation,
                        &mut scheduler.work,
                    );
                selection.completion = selection.completion.combine(&wait.completion);
                match wait.phase {
                    QualifiedMemberPhase::Selecting => {
                        wait.selection = Some(selection);
                        wait.phase = QualifiedMemberPhase::Access;
                    }
                    QualifiedMemberPhase::Preparing
                    | QualifiedMemberPhase::Access
                    | QualifiedMemberPhase::Constructing => {
                        assert!(wait.close_continuation.is_some());
                        wait.continuation_members = Some(selection);
                    }
                }
                scheduler.qualified_members.insert(task, wait);
                scheduler.runnable.push_back(Runnable::Task(task));
            }
            MemberConsumerPoll::Pending => {
                wait.member_selection = Some(frame);
                scheduler.qualified_members.insert(task, wait);
            }
            MemberConsumerPoll::Cancelled => {
                wait.member_selection = Some(frame);
                scheduler.qualified_members.insert(task, wait);
                return Ok(false);
            }
        }
        return Ok(true);
    }
    let provenance = HierarchyProvenanceView::new(operation.hierarchy);
    wait.id.assert_current(provenance);
    let reference_reply = wait.close_reference.take();
    let terminal_reference = reference_reply.and_then(|_| {
        scheduler
            .access_reference_answers
            .remove(&MemberConsumerId::QualifiedTask(task))
    });
    let members_reply = wait.continuation_members.take();
    let resume = match (
        wait.close_continuation.take(),
        members_reply.as_ref(),
        reference_reply,
    ) {
        (None, None, None) => CloseResume::Start,
        (Some(continuation), Some(selection), None) => {
            continuation.assert_current(provenance);
            CloseResume::Members {
                continuation,
                selection,
            }
        }
        (Some(continuation), None, Some((key, dependency))) => {
            continuation.assert_current(provenance);
            assert_eq!(scheduler.tasks[dependency].root, key);
            CloseResume::Reference {
                continuation,
                key,
                answer: terminal_reference
                    .as_deref()
                    .or_else(|| scheduler.tasks[dependency].answer.as_ref())
                    .expect("reference prerequisite is terminal"),
            }
        }
        _ => panic!("one exact qualified continuation receives one reply"),
    };
    let hook = provider
        .qualified_members()
        .expect("registered group retains its provider");
    let progress = if let TypedPrerequisiteInput::Construction(input) = &wait.input {
        hook.poll_construction(input, provenance, resume)?
            .map(TypedPrerequisiteAnswer::Construction)
    } else {
        let progress = match wait.phase {
            QualifiedMemberPhase::Preparing => {
                match hook.prepare_qualified_member(
                    wait.id,
                    wait.input.member(),
                    provenance,
                    resume,
                )? {
                    CloseProgress::Ready(MemberSelectionOutcome::QualifierIsNamespace) => {
                        scheduler.tasks[task]
                            .frame
                            .as_mut()
                            .expect("held typed task")
                            .resume_qualified_namespace(
                                wait.input.reference().reference,
                                wait.input.member().route_ordinal,
                            );
                        hook.cancel_qualified_member(wait.id);
                        active.remove(&wait.id);
                        scheduler.tasks[task].hierarchy_waits.clear();
                        scheduler.tasks[task].waits_on.clear();
                        scheduler.runnable.push_back(Runnable::Task(task));
                        return Ok(true);
                    }
                    CloseProgress::Ready(MemberSelectionOutcome::Ready {
                        request: Some(request),
                        completion,
                    }) => {
                        assert_eq!(
                            request.policy.identity().0,
                            wait.input.member().registration.hierarchy_identity,
                            "executable hierarchy policy matches the language registration"
                        );
                        assert_eq!(request.reference, wait.input.reference().reference);
                        assert_eq!(
                            request.language,
                            wait.input.member().registration.language,
                            "owner selection uses the registered provenance language"
                        );
                        wait.completion = wait.completion.combine(&completion);
                        let Some(frame) = MemberSelectionFrame::new(operation, request) else {
                            scheduler.qualified_members.insert(task, wait);
                            return Ok(false);
                        };
                        wait.member_selection = Some(Box::new(frame));
                        wait.phase = QualifiedMemberPhase::Selecting;
                        scheduler.qualified_members.insert(task, wait);
                        scheduler.runnable.push_back(Runnable::Task(task));
                        return Ok(true);
                    }
                    CloseProgress::Ready(
                        MemberSelectionOutcome::Ready {
                            request: None,
                            completion,
                        }
                        | MemberSelectionOutcome::Unavailable(completion),
                    ) => CloseProgress::Ready(Read::Unavailable {
                        reason: RootUnavailableReason::IncompletePreparation,
                        completion,
                    }),
                    CloseProgress::Ready(MemberSelectionOutcome::Cancelled(completion))
                    | CloseProgress::Cancelled(completion) => CloseProgress::Cancelled(completion),
                    CloseProgress::Members {
                        continuation,
                        request,
                        completion,
                    } => CloseProgress::Members {
                        continuation,
                        request,
                        completion,
                    },
                    CloseProgress::Reference {
                        continuation,
                        key,
                        completion,
                    } => CloseProgress::Reference {
                        continuation,
                        key,
                        completion,
                    },
                }
            }
            QualifiedMemberPhase::Access => hook.poll_qualified_member(
                wait.id,
                wait.selection
                    .as_ref()
                    .expect("access retains its original owner selection"),
                provenance,
                resume,
            )?,
            QualifiedMemberPhase::Constructing => unreachable!("construction uses its value hook"),
            QualifiedMemberPhase::Selecting => unreachable!("selection phase retains its frame"),
        };
        progress.map(TypedPrerequisiteAnswer::Member)
    };
    let progress = match progress {
        CloseProgress::Ready(TypedPrerequisiteAnswer::Construction(value)) => {
            let TypedPrerequisiteInput::Construction(input) = wait.input else {
                unreachable!("a construction reply retains its construction input")
            };
            scheduler.tasks[task]
                .frame
                .as_mut()
                .expect("held typed task")
                .constructed_values
                .insert((input.output, input.binding.targets()[0]), value);
            scheduler.tasks[task].hierarchy_waits.clear();
            scheduler.tasks[task].waits_on.clear();
            active.remove(&wait.id);
            scheduler.runnable.push_back(Runnable::Task(task));
            return Ok(true);
        }
        other => other.map(|answer| match answer {
            TypedPrerequisiteAnswer::Member(result) => result,
            TypedPrerequisiteAnswer::Construction(_) => {
                unreachable!("construction reply handled above")
            }
        }),
    };
    match progress {
        CloseProgress::Members {
            continuation,
            request,
            completion,
        } => {
            wait.completion = wait.completion.combine(&completion);
            scheduler.evidence.include(
                &completion,
                operation.session.cancellation,
                &mut scheduler.work,
            );
            scheduler.qualified_members.insert(task, wait);
            Ok(suspend_access_members(
                operation,
                scheduler,
                MemberConsumerId::QualifiedTask(task),
                continuation,
                request,
            ))
        }
        CloseProgress::Reference {
            continuation,
            key,
            completion,
        } => {
            wait.completion = wait.completion.combine(&completion);
            scheduler.evidence.include(
                &completion,
                operation.session.cancellation,
                &mut scheduler.work,
            );
            scheduler.qualified_members.insert(task, wait);
            Ok(suspend_access_reference(
                operation,
                scheduler,
                MemberConsumerId::QualifiedTask(task),
                continuation,
                key,
            ))
        }
        CloseProgress::Cancelled(completion)
        | CloseProgress::Ready(Read::Cancelled(completion)) => {
            wait.completion = wait.completion.combine(&completion);
            scheduler.qualified_members.insert(task, wait);
            Ok(false)
        }
        CloseProgress::Ready(result) => {
            let answer = match result {
                Read::Ready {
                    mut value,
                    completion,
                } => {
                    wait.completion = wait.completion.combine(&completion);
                    // The provider may discharge its own hierarchy evidence,
                    // but never the typed input or prerequisite obligations.
                    value.completion = value.completion.combine(&wait.completion);
                    match value.into_typed_answer(
                        wait.input.reference().reference,
                        operation.session.resolution_session,
                        operation.session.cancellation,
                    )? {
                        Read::Ready {
                            value: (answer, evidence),
                            ..
                        } => {
                            scheduler.qualified_evidence.insert(wait.id, evidence);
                            answer
                        }
                        Read::Cancelled(completion) => {
                            wait.completion = wait.completion.combine(&completion);
                            scheduler.qualified_members.insert(task, wait);
                            return Ok(false);
                        }
                        Read::Unavailable { .. } => {
                            unreachable!("binding adaptation performs no unavailable reads")
                        }
                    }
                }
                Read::Unavailable { completion, .. } => {
                    wait.completion = wait.completion.combine(&completion);
                    registered_qualified_open_answer(
                        operation.session,
                        operation.hierarchy,
                        wait.input.reference().reference,
                        &wait.completion,
                    )?
                }
                Read::Cancelled(_) => unreachable!("cancelled read handled above"),
            };
            assert_eq!(scheduler.tasks[task].waiting, 0);
            scheduler.tasks[task].hierarchy_waits.clear();
            scheduler.tasks[task].waits_on.clear();
            let complete = scheduler.tasks[task]
                .frame
                .as_mut()
                .expect("held typed task")
                .resume_qualified_answer(
                    operation.session,
                    operation.hierarchy,
                    operation.forward_candidate_artifacts,
                    operation.candidate_paths,
                    wait.input.reference().reference,
                    answer,
                )?;
            hook.cancel_qualified_member(wait.id);
            active.remove(&wait.id);
            if complete {
                scheduler.runnable.push_back(Runnable::Task(task));
            }
            Ok(complete)
        }
    }
}

fn assert_batch_arity(roots: usize) {
    assert!(roots > 0, "a demand batch resolves at least one root");
    assert!(
        roots <= MAX_REFERENCE_SEEDS_PER_BATCH,
        "a demand batch has {roots} roots; maximum is {MAX_REFERENCE_SEEDS_PER_BATCH}"
    );
}

/// Admit every root before the first poll, then run the FIFO loop.
///
/// Because every root is live before anything is polled, a prefix reference
/// that many of the batch's roots share is admitted, seeded and evaluated once
/// for the batch instead of once per dependent root, and two input positions
/// naming the same reference share one task and repeat its one answer. A task
/// admitted without a seed, which is every prefix task discovered inside the
/// loop, is seeded by the round that first polls it.
///
/// `metrics` receives the batch's shared work: the frames of the tasks that are
/// not roots of this batch. Each root's own frames stay with its resolution.
fn resolve_admitted_batch<'a>(
    operation: &mut Resources<'_, 'a>,
    mut scheduler: Scheduler<'a>,
    admitted: Vec<(ReferenceKey, Option<ReferenceSeed>)>,
    provider: &mut (impl RootProvider + ?Sized),
    metrics: &mut ResolutionBatchMetrics,
) -> StoreResult<BatchOutcome> {
    let root_seed_completions = admitted
        .iter()
        .filter_map(|(root, seed)| {
            let seed = seed.as_ref()?;
            matches!(seed.completion(), ResolutionCompletion::Incomplete(_))
                .then(|| (root.reference, seed.completion().clone()))
        })
        .collect::<Vec<_>>();
    let mut root_tasks = Vec::with_capacity(admitted.len());
    for (root, seed) in admitted {
        let Some(id) = scheduler.admit(operation, root, seed) else {
            return Ok(scheduler.cancelled(operation));
        };
        root_tasks.push(id);
    }
    // Roots are admitted before anything else, so a task id below this count is
    // a root of this batch and every id at or above it is a shared prefix.
    let root_task_count = scheduler.tasks.len();
    match drive_scheduler(
        operation,
        scheduler,
        provider,
        root_seed_completions,
        |scheduler| scheduler.completed_prefix >= root_task_count,
    )? {
        SchedulerOutcome::Ready(mut scheduler) => {
            scheduler.retain_completed_roots(operation);
            Ok(BatchOutcome::Ready(scheduler.take_root_resolutions(
                &root_tasks,
                root_task_count,
                metrics,
            )))
        }
        SchedulerOutcome::Incomplete(mut scheduler, mut outcome) => {
            scheduler.finish_incomplete_roots(operation, root_task_count)?;
            if operation.session.cancellation.is_cancelled()
                || operation.session.resolution_stopped()
            {
                return Ok(scheduler.cancelled(operation));
            }
            // Incomplete roots are request-local; only independently completed
            // roots were eligible for memo retention before finalization.
            let answers = scheduler
                .take_root_resolutions(&root_tasks, root_task_count, metrics)
                .into_iter()
                .map(|resolution| {
                    metrics.accumulate(resolution.metrics);
                    resolution.answer
                })
                .collect();
            match &mut outcome {
                BatchOutcome::Unavailable { root_answers, .. }
                | BatchOutcome::Unsupported(Unsupported::CyclicPrefixDependency {
                    root_answers,
                    ..
                }) => *root_answers = answers,
                _ => unreachable!("an incomplete scheduler retains its failure"),
            }
            Ok(outcome)
        }
        SchedulerOutcome::Terminal(outcome) => Ok(outcome),
    }
}

enum SchedulerOutcome<'source> {
    Ready(Box<Scheduler<'source>>),
    Terminal(BatchOutcome),
    Incomplete(Box<Scheduler<'source>>, BatchOutcome),
}

/// Drive reference tasks and relation member selection in one dependency graph.
/// The completion predicate chooses the caller's requested roots or endpoint;
/// both use the same admission, cancellation and cycle handling.
fn drive_scheduler<'source>(
    operation: &mut Resources<'_, 'source>,
    mut scheduler: Scheduler<'source>,
    provider: &mut (impl RootProvider + ?Sized),
    root_seed_completions: Vec<(SemanticId, ResolutionCompletion)>,
    is_complete: impl Fn(&Scheduler<'source>) -> bool,
) -> StoreResult<SchedulerOutcome<'source>> {
    let mut active_closes = std::mem::take(&mut scheduler.close_waiters);
    let mut active_qualified = HashSet::default();
    let mut result = drive_scheduler_inner(
        operation,
        scheduler,
        provider,
        root_seed_completions,
        is_complete,
        &mut active_closes,
        &mut active_qualified,
    );
    if !active_qualified.is_empty() {
        if let Ok(SchedulerOutcome::Ready(scheduler) | SchedulerOutcome::Incomplete(scheduler, _)) =
            &mut result
        {
            for (&id, wait) in &mut scheduler.qualified_members {
                for dependency in std::mem::take(&mut scheduler.tasks[id].waits_on) {
                    scheduler.relations[dependency]
                        .waiters
                        .retain(|waiter| *waiter != id);
                }
                for dependency in std::mem::take(&mut scheduler.tasks[id].hierarchy_waits) {
                    if let Some(waiters) = scheduler.qualified_dependents.get_mut(&dependency) {
                        waiters.retain(|waiter| *waiter != id);
                    }
                }
                wait.close_continuation = None;
                wait.continuation_members = None;
                wait.close_reference = None;
                if let Some(frame) = wait.member_selection.take() {
                    frame
                        .evaluation
                        .as_ref()
                        .expect("member phase is between polls")
                        .cancellation_reasons
                        .include_retained_evidence(
                            &mut scheduler.evidence,
                            operation.session.cancellation,
                            &mut scheduler.work,
                        );
                    wait.completion = wait.completion.combine(&frame.completion);
                    frame.abandon(operation);
                }
            }
        }
        let hook = provider
            .qualified_members()
            .expect("an active qualified slot has a provider");
        for id in active_qualified {
            hook.cancel_qualified_member(id);
        }
    }
    if !active_closes.is_empty() {
        if let Ok(SchedulerOutcome::Ready(scheduler) | SchedulerOutcome::Incomplete(scheduler, _)) =
            &mut result
        {
            // Remove each waiter before invalidating its provider-side token.
            for id in 0..scheduler.relations.len() {
                if !active_closes.contains(&scheduler.relations[id].endpoint) {
                    continue;
                }
                for dependency in std::mem::take(&mut scheduler.relations[id].waits_on) {
                    scheduler.relations[dependency]
                        .relation_waiters
                        .retain(|waiter| *waiter != id);
                }
                for dependency in &scheduler.relations[id].dependencies {
                    scheduler.tasks[*dependency]
                        .dependents
                        .retain(|waiter| *waiter != id);
                }
                scheduler.relations[id].close_continuation = None;
                scheduler.relations[id].continuation_members = None;
                scheduler.relations[id].close_reference = None;
                if let Some(frame) = scheduler.relations[id].member_selection.take() {
                    frame
                        .evaluation
                        .as_ref()
                        .expect("member phase is between polls")
                        .cancellation_reasons
                        .include_retained_evidence(
                            &mut scheduler.evidence,
                            operation.session.cancellation,
                            &mut scheduler.work,
                        );
                    scheduler.evidence.include(
                        &frame.completion,
                        operation.session.cancellation,
                        &mut scheduler.work,
                    );
                    frame.abandon(operation);
                }
            }
        }
        for endpoint in active_closes {
            provider.cancel_close(&endpoint);
        }
    }
    result
}

fn drive_scheduler_inner<'source>(
    operation: &mut Resources<'_, 'source>,
    mut scheduler: Scheduler<'source>,
    provider: &mut (impl RootProvider + ?Sized),
    root_seed_completions: Vec<(SemanticId, ResolutionCompletion)>,
    is_complete: impl Fn(&Scheduler<'source>) -> bool,
    active_closes: &mut HashSet<RelationKey>,
    active_qualified: &mut HashSet<QualifiedMemberId>,
) -> StoreResult<SchedulerOutcome<'source>> {
    // The round: the leading run of runnable tasks, drained together so one
    // statement per keyed reader can carry all of their keys. Draining a FIFO
    // prefix and polling it in order, pushing every new runnable to the back,
    // is the same order a one-at-a-time loop uses.
    let mut round = Vec::new();
    loop {
        let cancellation = operation.session.cancellation;
        if cancellation.is_cancelled()
            || operation.session.resolution_stopped()
            || scheduler.evidence.cancellation_observed()
        {
            return Ok(SchedulerOutcome::Terminal(scheduler.cancelled(operation)));
        }
        if is_complete(&scheduler) {
            return Ok(SchedulerOutcome::Ready(Box::new(scheduler)));
        }
        round.clear();
        while let Some(&Runnable::Task(id)) = scheduler.runnable.front() {
            scheduler.runnable.pop_front();
            round.push(id);
        }
        if !round.is_empty() {
            merge_round_reads(operation, &mut scheduler, &round)?;
            match poll_round(
                operation,
                &mut scheduler,
                &round,
                provider,
                &is_complete,
                active_qualified,
            )? {
                RoundOutcome::Continue => continue,
                RoundOutcome::Ready => return Ok(SchedulerOutcome::Ready(Box::new(scheduler))),
                RoundOutcome::Cancelled => {
                    return Ok(SchedulerOutcome::Terminal(scheduler.cancelled(operation)));
                }
            }
        }
        let Some(runnable) = scheduler.runnable.pop_front() else {
            if scheduler.resume_drained_access_references(operation) {
                continue;
            }
            if let Some((endpoint, reason)) = scheduler.relations.iter().find_map(|relation| {
                relation
                    .unavailable
                    .as_ref()
                    .map(|(reason, _)| (relation.endpoint.clone(), *reason))
            }) {
                return Ok(scheduler.unavailable(
                    operation,
                    endpoint.endpoint,
                    reason,
                    root_seed_completions,
                ));
            }
            // Every discover call has returned and every runnable task has
            // drained. The remaining finite dependency graph is cyclic. Keep
            // independently completed answers and name the blocked roots.
            // No cyclic relation is published.
            let mut pending_roots = scheduler
                .tasks
                .iter()
                .filter(|task| task.answer.is_none())
                .map(|task| task.root.reference)
                .collect::<Vec<_>>();
            // A member-selection cycle can leave all positioned receivers
            // terminal while only relation-to-relation edges remain blocked.
            // Name those selections' source references instead of assuming a
            // live ordinary reference task must still exist.
            for relation in &scheduler.relations {
                if let Some(frame) = &relation.member_selection {
                    let reference = frame
                        .evaluation
                        .as_ref()
                        .expect("member phase is between polls")
                        .root;
                    if !pending_roots.contains(&reference) {
                        pending_roots.push(reference);
                    }
                }
            }
            assert!(
                !pending_roots.is_empty(),
                "a drained scheduler with no pending root has an answer"
            );
            let mut completion = ResolutionCompletion::incomplete(
                pending_roots
                    .iter()
                    .map(|&root| ResolutionIncompleteReason::CyclicPrefixDependency(root)),
            );
            for relation in &scheduler.relations {
                completion = completion.combine(&relation.member_completion);
                if let Some(frame) = &relation.member_selection {
                    completion = completion.combine(&frame.completion);
                }
            }
            for wait in scheduler.qualified_members.values() {
                completion = completion.combine(&wait.completion);
                if let Some(frame) = &wait.member_selection {
                    completion = completion.combine(&frame.completion);
                }
            }
            let outcome = BatchOutcome::Unsupported(Unsupported::CyclicPrefixDependency {
                pending_roots,
                pending_endpoints: scheduler
                    .relations
                    .iter()
                    .filter(|relation| !relation.closed)
                    .map(|relation| relation.endpoint.endpoint.clone())
                    .collect(),
                completion,
                root_answers: Vec::new(),
            });
            return Ok(SchedulerOutcome::Incomplete(Box::new(scheduler), outcome));
        };
        if !operation.session.charge_scope_steps(1) {
            return Ok(SchedulerOutcome::Terminal(scheduler.cancelled(operation)));
        }
        // The round above drained every leading runnable task, so the only
        // runnable this loop still takes one at a time is a relation.
        let Runnable::Relation(id) = runnable else {
            unreachable!("a drained round leaves no leading runnable task")
        };
        // Only the final dependency completion queues this work. No
        // whole-arena rescans occur between evaluator polls.
        assert!(!scheduler.relations[id].closed && scheduler.relations[id].pending == 0);
        let endpoint = scheduler.relations[id].endpoint.clone();
        let environment = endpoint.environment;
        if !scheduler.relations[id].member_requested
            && scheduler.relations[id].member_selection.is_none()
            && scheduler.relations[id].selected_members.is_none()
        {
            scheduler.relations[id].member_requested = true;
            let relation = &scheduler.relations[id];
            let inputs = relation.dependencies[..relation.prefix_count]
                .iter()
                .map(|&id| {
                    (
                        scheduler.tasks[id].root,
                        scheduler.tasks[id]
                            .answer
                            .as_ref()
                            .expect("positioned input is terminal"),
                    )
                })
                .collect::<Vec<_>>();
            let request = match provider.member_selection(&endpoint, &inputs)? {
                MemberSelectionOutcome::Ready {
                    request,
                    completion,
                } => {
                    if completion != ResolutionCompletion::Complete {
                        scheduler
                            .evidence
                            .include(&completion, cancellation, &mut scheduler.work);
                    }
                    scheduler.relations[id].member_completion = completion;
                    request
                }
                MemberSelectionOutcome::QualifierIsNamespace => {
                    unreachable!("namespace classification belongs to registered preparation")
                }
                MemberSelectionOutcome::Unavailable(completion) => {
                    scheduler
                        .evidence
                        .include(&completion, cancellation, &mut scheduler.work);
                    scheduler.relations[id].unavailable =
                        Some((RootUnavailableReason::IncompletePreparation, completion));
                    continue;
                }
                MemberSelectionOutcome::Cancelled(completion) => {
                    scheduler
                        .evidence
                        .include(&completion, cancellation, &mut scheduler.work);
                    return Ok(SchedulerOutcome::Terminal(scheduler.cancelled(operation)));
                }
            };
            if let Some(request) = request {
                assert_eq!(
                    environment, CALLER_ENVIRONMENT,
                    "G0 does not enable remote member selection"
                );
                let Some(frame) = MemberSelectionFrame::new(operation, request) else {
                    return Ok(SchedulerOutcome::Terminal(scheduler.cancelled(operation)));
                };
                scheduler.relations[id].member_selection = Some(Box::new(frame));
            }
        }
        if let Some(mut frame) = scheduler.relations[id].member_selection.take() {
            let polled = poll_member_consumer(
                operation,
                &mut scheduler,
                provider,
                MemberConsumerId::Relation(id),
                &mut frame,
            )?;
            scheduler.relations[id].member_selection = Some(frame);
            match polled {
                MemberConsumerPoll::Pending => continue,
                MemberConsumerPoll::Cancelled => {
                    return Ok(SchedulerOutcome::Terminal(scheduler.cancelled(operation)));
                }
                MemberConsumerPoll::Ready(mut selection) => {
                    let frame = scheduler.relations[id]
                        .member_selection
                        .take()
                        .expect("completed member phase");
                    selection
                        .discharged_provider_reasons
                        .extend(frame.discharged_provider_reasons);
                    if !selection.discharged_provider_reasons.is_empty() {
                        scheduler
                            .closure_discharges
                            .entry(scheduler.relations[id].endpoint.clone())
                            .or_default()
                            .discharged_provider_reasons
                            .extend(selection.discharged_provider_reasons.iter().copied());
                    }
                    selection.completion = selection
                        .completion
                        .combine(&scheduler.relations[id].member_completion);
                    frame
                        .evaluation
                        .as_ref()
                        .expect("member phase is between polls")
                        .cancellation_reasons
                        .include_retained_evidence(
                            &mut scheduler.evidence,
                            cancellation,
                            &mut scheduler.work,
                        );
                    if scheduler.relations[id].close_continuation.is_some() {
                        scheduler.relations[id].continuation_members = Some(selection);
                    } else {
                        scheduler.relations[id].selected_members = Some(selection);
                    }
                }
            }
        }
        if cancellation.is_cancelled()
            || operation.session.resolution_stopped()
            || scheduler.evidence.cancellation_observed()
        {
            return Ok(SchedulerOutcome::Terminal(scheduler.cancelled(operation)));
        }
        let relation = &mut scheduler.relations[id];
        if !relation.prefix_charged {
            if !operation.session.charge_scope_steps(relation.prefix_count) {
                return Ok(SchedulerOutcome::Terminal(scheduler.cancelled(operation)));
            }
            relation.prefix_charged = true;
        }
        let inputs = relation.dependencies[..relation.prefix_count]
            .iter()
            .map(|&id| {
                (
                    scheduler.tasks[id].root,
                    scheduler.tasks[id]
                        .answer
                        .as_ref()
                        .expect("positioned input is terminal"),
                )
            })
            .collect::<Vec<_>>();
        // Consume the outstanding suspension before invoking any resume code.
        let continuation = relation.close_continuation.take();
        let resumed = relation.continuation_members.take();
        let reference_reply = relation.close_reference.take();
        let terminal_reference = reference_reply.and_then(|_| {
            scheduler
                .access_reference_answers
                .remove(&MemberConsumerId::Relation(id))
        });
        let provenance = HierarchyProvenanceView::new(operation.hierarchy);
        let resume = match (continuation, resumed.as_ref(), reference_reply) {
            (None, None, None) => CloseResume::Start,
            (Some(continuation), None, Some((key, task))) => {
                continuation.assert_current(provenance);
                assert_eq!(scheduler.tasks[task].root, key);
                CloseResume::Reference {
                    continuation,
                    key,
                    answer: terminal_reference
                        .as_deref()
                        .or_else(|| scheduler.tasks[task].answer.as_ref())
                        .expect("reference wait is terminal"),
                }
            }
            (Some(continuation), Some(selection), None) => {
                continuation.assert_current(provenance);
                CloseResume::Members {
                    continuation,
                    selection,
                }
            }
            _ => panic!("a continuation and its exact member reply become ready together"),
        };
        let completion = match provider.poll_close(
            &endpoint,
            &inputs,
            relation.selected_members.as_ref(),
            &relation.member_completion,
            provenance,
            resume,
        )? {
            CloseProgress::Ready(completion) => completion,
            CloseProgress::Cancelled(completion) => {
                scheduler
                    .evidence
                    .include(&completion, cancellation, &mut scheduler.work);
                return Ok(SchedulerOutcome::Terminal(scheduler.cancelled(operation)));
            }
            CloseProgress::Reference {
                continuation,
                key,
                completion,
            } => {
                continuation.assert_current(provenance);
                assert_eq!(
                    key.environment, environment,
                    "access prerequisites stay in the selected environment"
                );
                scheduler
                    .evidence
                    .include(&completion, cancellation, &mut scheduler.work);
                active_closes.insert(endpoint.clone());
                if !suspend_access_reference(
                    operation,
                    &mut scheduler,
                    MemberConsumerId::Relation(id),
                    continuation,
                    key,
                ) {
                    return Ok(SchedulerOutcome::Terminal(scheduler.cancelled(operation)));
                }
                continue;
            }
            CloseProgress::Members {
                continuation,
                request,
                completion,
            } => {
                continuation.assert_current(provenance);
                scheduler
                    .evidence
                    .include(&completion, cancellation, &mut scheduler.work);
                active_closes.insert(endpoint.clone());
                if !suspend_access_members(
                    operation,
                    &mut scheduler,
                    MemberConsumerId::Relation(id),
                    continuation,
                    request,
                ) {
                    return Ok(SchedulerOutcome::Terminal(scheduler.cancelled(operation)));
                }
                continue;
            }
        };
        let completion = completion.combine(&relation.member_completion);
        if let Some(discharges) = scheduler.closure_discharges.get(&relation.endpoint)
            && !discharges.discharged_provider_reasons.is_empty()
        {
            provider.retain_member_provider_reasons(
                &relation.endpoint,
                &discharges.discharged_provider_reasons,
            );
        }
        if let Some(retired) = provider.resolved_closure_discharges(&relation.endpoint) {
            scheduler
                .closure_discharges
                .entry(relation.endpoint.clone())
                .or_default()
                .merge(retired);
        }
        scheduler
            .evidence
            .include(&completion, cancellation, &mut scheduler.work);
        if cancellation.is_cancelled()
            || operation.session.resolution_stopped()
            || scheduler.evidence.cancellation_observed()
        {
            return Ok(SchedulerOutcome::Terminal(scheduler.cancelled(operation)));
        }
        active_closes.remove(&relation.endpoint);
        relation.completion = Some(completion);
        relation.closed = true;
        let relation_waiters = std::mem::take(&mut relation.relation_waiters);
        for waiter in std::mem::take(&mut relation.waiters) {
            if !operation.session.charge_scope_steps(1) {
                return Ok(SchedulerOutcome::Terminal(scheduler.cancelled(operation)));
            }
            let task = &mut scheduler.tasks[waiter];
            assert!(task.waiting > 0);
            task.waiting -= 1;
            if task.waiting == 0 {
                task.waits_on.clear();
                scheduler.runnable.push_back(Runnable::Task(waiter));
            }
        }
        for waiter in relation_waiters {
            if !operation.session.charge_scope_steps(1) {
                return Ok(SchedulerOutcome::Terminal(scheduler.cancelled(operation)));
            }
            let relation = &mut scheduler.relations[waiter];
            assert!(relation.pending > 0);
            relation.pending -= 1;
            if relation.pending == 0 {
                relation.waits_on.clear();
                scheduler.runnable.push_back(Runnable::Relation(waiter));
            }
        }
    }
}

/// How one round of polls ended.
enum RoundOutcome {
    /// Every task of the round was polled and the scheduler loop continues.
    Continue,
    /// Every root of this batch now has an answer.
    Ready,
    /// The scheduler must drain its retained evidence and stop.
    Cancelled,
}

/// Poll every task of one round, in the FIFO order it was drained in.
///
/// This is the body a one-at-a-time loop ran per dequeued task, unchanged:
/// each task pays its own dequeue step, is polled once, and its outcome is
/// handled before the next task is polled. The checks the scheduler loop makes
/// before a dequeue are repeated before every poll, so a stop or a completed
/// batch ends the round exactly where it would have ended the loop.
fn poll_round<'a>(
    operation: &mut Resources<'_, 'a>,
    scheduler: &mut Scheduler<'a>,
    round: &[usize],
    provider: &mut (impl RootProvider + ?Sized),
    is_complete: &impl Fn(&Scheduler<'a>) -> bool,
    active_qualified: &mut HashSet<QualifiedMemberId>,
) -> StoreResult<RoundOutcome> {
    let mut awaiting_dependencies = Vec::new();
    for &id in round {
        let cancellation = operation.session.cancellation;
        if cancellation.is_cancelled()
            || operation.session.resolution_stopped()
            || scheduler.evidence.cancellation_observed()
        {
            return Ok(RoundOutcome::Cancelled);
        }
        if is_complete(scheduler) {
            return Ok(RoundOutcome::Ready);
        }
        if !operation.session.charge_scope_steps(1) {
            return Ok(RoundOutcome::Cancelled);
        }
        let environment = scheduler.tasks[id].root.environment;
        assert_eq!(
            environment, CALLER_ENVIRONMENT,
            "G0 does not enable remote task execution"
        );
        if let Some((reference, dependency)) = scheduler.typed_references.remove(&id) {
            let answer = scheduler.tasks[dependency]
                .answer
                .as_ref()
                .expect("a resumed typed prerequisite has its selected answer")
                .binding()
                .clone();
            scheduler.tasks[id]
                .frame
                .as_mut()
                .expect("held typed task")
                .typed_reference_answers
                .insert(reference, Arc::new(answer));
            assert_eq!(scheduler.tasks[id].waiting, 0);
            scheduler.tasks[id].hierarchy_waits.clear();
        }
        if scheduler.qualified_members.contains_key(&id) {
            if !poll_qualified_member_consumer(
                operation,
                scheduler,
                provider,
                id,
                active_qualified,
            )? {
                return Ok(RoundOutcome::Cancelled);
            }
            continue;
        }
        let mut granted = Vec::new();
        scheduler.tasks[id]
            .frame
            .as_mut()
            .expect("runnable task is live")
            .inject_closure_discharges(&scheduler.closure_discharges, environment);
        let cached = if let Some((memo, access, context)) = operation.completed_roots {
            let task = &mut scheduler.tasks[id];
            let evaluation = task
                .frame
                .as_ref()
                .expect("runnable task is live")
                .evaluation
                .as_ref()
                .expect("task is between polls");
            if task.memo_key.is_none() {
                task.memo_key = evaluation.root_seed.as_ref().and_then(|seed| {
                    RootMemoKey::new(operation.session, task.root, seed, access, context)
                });
                task.memo_key
                    .as_ref()
                    .and_then(|key| memo.lookup(key, operation.session))
            } else {
                None
            }
        } else {
            None
        };
        let polled = if let Some(answer) = cached {
            Ok(DemandFactEvaluationPoll::Ready(Box::new(answer)))
        } else {
            let relations = &scheduler.relations;
            let relation_ids = &scheduler.relation_ids;
            let claims = &mut scheduler.claims;
            scheduler.tasks[id]
                .frame
                .as_mut()
                .expect("runnable task is live")
                .poll_with_dependencies(
                    operation.session,
                    operation.hierarchy,
                    operation.forward_candidate_artifacts,
                    operation.candidate_paths,
                    &mut |requests| {
                        Ok(
                            if requests.iter().all(|request| {
                                relation_ids
                                    .get(&RelationKey {
                                        endpoint: request.endpoint().clone(),
                                        environment,
                                    })
                                    .is_some_and(|&id| relations[id].closed)
                            }) {
                                DemandForwardReadiness::Ready
                            } else {
                                DemandForwardReadiness::AwaitingDependencies
                            },
                        )
                    },
                    &mut |reference| {
                        let reference = ReferenceKey {
                            reference,
                            environment,
                        };
                        match claims.get(&reference) {
                            Some(claim) if claim.owner == id || claim.bypass.contains(&id) => {
                                DemandedReferenceClaim::Claimed
                            }
                            Some(_) => DemandedReferenceClaim::AwaitOwner,
                            None => {
                                claims.insert(
                                    reference,
                                    DemandedReferenceOwner {
                                        owner: id,
                                        waiters: Vec::new(),
                                        bypass: HashSet::default(),
                                    },
                                );
                                granted.push(reference);
                                DemandedReferenceClaim::Claimed
                            }
                        }
                    },
                )
        };
        scheduler.tasks[id].metrics = scheduler.tasks[id]
            .frame
            .as_ref()
            .expect("polled task retains its checkpoint")
            .evaluation
            .as_ref()
            .expect("task is between polls")
            .binding_metrics;
        // Error polls are terminal too. Propagate them before claim release
        // can turn the error into a cancellation that drains this frame.
        let polled = polled?;
        let task = &mut scheduler.tasks[id];
        assert!(
            granted.is_empty() || task.claims.is_empty(),
            "a task claims references only when it opens a lexical frame"
        );
        task.claims.extend(granted);
        if !matches!(polled, DemandFactEvaluationPoll::Ready(_))
            && !release_task_claims(operation, scheduler, id)
        {
            return Ok(RoundOutcome::Cancelled);
        }
        match polled {
            DemandFactEvaluationPoll::Continue => scheduler.runnable.push_back(Runnable::Task(id)),
            DemandFactEvaluationPoll::Ready(mut answer) => {
                select_universe_binding(
                    operation.session,
                    scheduler.tasks[id]
                        .frame
                        .as_ref()
                        .and_then(|frame| frame.evaluation.as_ref())
                        .map_or(Language::None, |state| {
                            if state.selected_route_language != Language::None {
                                state.selected_route_language
                            } else {
                                state
                                    .root_seed
                                    .as_ref()
                                    .map_or(Language::None, ReferenceSeed::language)
                            }
                        }),
                    scheduler.tasks[id].root.reference,
                    &mut answer,
                )?;
                include_fact_answer_cancellation_evidence(
                    &mut scheduler.evidence,
                    &answer,
                    cancellation,
                    &mut scheduler.work,
                );
                let cancelled = cancellation.is_cancelled()
                    || operation.session.resolution_stopped()
                    || answer
                        .completion()
                        .contains_reason(ResolutionIncompleteReason::Cancelled);
                // Claim release is cancellable work, so retire the terminal
                // frame and retain its answer first. The cancellation drain
                // must never cancel it twice or lose its answer's evidence.
                scheduler.tasks[id].frame = None;
                scheduler.tasks[id].answer = Some(*answer);
                if !release_task_claims(operation, scheduler, id) {
                    return Ok(RoundOutcome::Cancelled);
                }
                if !cancelled
                    && (scheduler.tasks[id].hierarchy_answer_needed
                        || !scheduler.tasks[id].hierarchy_dependents.is_empty())
                {
                    let root = scheduler.tasks[id].root.reference;
                    let mut evaluation =
                        FactEvaluation::new(operation.session, operation.hierarchy, root);
                    if !evaluation.publish_qualified_hierarchy_reference(
                        root,
                        scheduler.tasks[id].answer.as_ref().unwrap(),
                    )? {
                        return Ok(RoundOutcome::Cancelled);
                    }
                }
                while scheduler
                    .tasks
                    .get(scheduler.completed_prefix)
                    .is_some_and(|task| task.answer.is_some())
                {
                    scheduler.completed_prefix += 1;
                }
                if cancelled {
                    return Ok(RoundOutcome::Cancelled);
                }
                for waiter in std::mem::take(&mut scheduler.tasks[id].hierarchy_dependents) {
                    if !operation.session.charge_scope_steps(1) {
                        return Ok(RoundOutcome::Cancelled);
                    }
                    let task = &mut scheduler.tasks[waiter];
                    assert!(task.waiting > 0);
                    task.waiting -= 1;
                    if task.waiting == 0 {
                        task.hierarchy_waits.clear();
                        scheduler.runnable.push_back(Runnable::Task(waiter));
                    }
                }
                if let Some(waiters) = scheduler.qualified_dependents.remove(&id) {
                    for waiter in waiters {
                        if !operation.session.charge_scope_steps(1) {
                            return Ok(RoundOutcome::Cancelled);
                        }
                        let task = &mut scheduler.tasks[waiter];
                        assert!(task.waiting > 0);
                        task.waiting -= 1;
                        if task.waiting == 0 {
                            task.hierarchy_waits.clear();
                            scheduler.runnable.push_back(Runnable::Task(waiter));
                        }
                    }
                }
                for dependent in std::mem::take(&mut scheduler.tasks[id].dependents) {
                    if !operation.session.charge_scope_steps(1) {
                        return Ok(RoundOutcome::Cancelled);
                    }
                    let relation = &mut scheduler.relations[dependent];
                    assert!(relation.pending > 0);
                    relation.pending -= 1;
                    if relation.pending == 0 {
                        relation.waits_on.clear();
                        scheduler.runnable.push_back(Runnable::Relation(dependent));
                    }
                }
            }
            DemandFactEvaluationPoll::AwaitingQualifiedMember(mut input) => {
                input.reference.environment = environment;
                if provider.qualified_members().is_none() {
                    let answer = registered_qualified_open_answer(
                        operation.session,
                        operation.hierarchy,
                        input.reference.reference,
                        &input.completion,
                    )?;
                    if !scheduler.tasks[id]
                        .frame
                        .as_mut()
                        .expect("held typed task")
                        .resume_qualified_answer(
                            operation.session,
                            operation.hierarchy,
                            operation.forward_candidate_artifacts,
                            operation.candidate_paths,
                            input.reference.reference,
                            answer,
                        )?
                    {
                        return Ok(RoundOutcome::Cancelled);
                    }
                    scheduler.runnable.push_back(Runnable::Task(id));
                    continue;
                }
                let request_id =
                    QualifiedMemberId::issue(HierarchyProvenanceView::new(operation.hierarchy));
                assert!(
                    scheduler
                        .qualified_members
                        .insert(
                            id,
                            QualifiedMemberWait {
                                id: request_id,
                                completion: input.completion.clone(),
                                input: TypedPrerequisiteInput::Member(*input),
                                member_selection: None,
                                selection: None,
                                continuation_members: None,
                                close_continuation: None,
                                close_reference: None,
                                phase: QualifiedMemberPhase::Preparing,
                            }
                        )
                        .is_none()
                );
                active_qualified.insert(request_id);
                scheduler.runnable.push_back(Runnable::Task(id));
            }
            DemandFactEvaluationPoll::AwaitingTypedConstruction(mut input) => {
                input.reference.environment = environment;
                let Some(_) = provider.qualified_members() else {
                    scheduler.tasks[id]
                        .frame
                        .as_mut()
                        .expect("held typed task")
                        .constructed_values
                        .insert((input.output, input.binding.targets()[0]), None);
                    scheduler.runnable.push_back(Runnable::Task(id));
                    continue;
                };
                let request_id =
                    QualifiedMemberId::issue(HierarchyProvenanceView::new(operation.hierarchy));
                assert!(
                    scheduler
                        .qualified_members
                        .insert(
                            id,
                            QualifiedMemberWait {
                                id: request_id,
                                completion: input.binding.completion().clone(),
                                input: TypedPrerequisiteInput::Construction(*input),
                                member_selection: None,
                                selection: None,
                                continuation_members: None,
                                close_continuation: None,
                                close_reference: None,
                                phase: QualifiedMemberPhase::Constructing,
                            }
                        )
                        .is_none()
                );
                active_qualified.insert(request_id);
                scheduler.runnable.push_back(Runnable::Task(id));
            }
            DemandFactEvaluationPoll::AwaitingTypedReference(reference) => {
                if !operation.session.charge_scope_steps(1) {
                    return Ok(RoundOutcome::Cancelled);
                }
                let Some(dependency) = scheduler.admit(
                    operation,
                    ReferenceKey {
                        reference,
                        environment,
                    },
                    None,
                ) else {
                    return Ok(RoundOutcome::Cancelled);
                };
                assert!(
                    scheduler
                        .typed_references
                        .insert(id, (reference, dependency))
                        .is_none()
                );
                await_access_reference(scheduler, MemberConsumerId::QualifiedTask(id), dependency);
            }
            DemandFactEvaluationPoll::AwaitingHierarchyReferences(references) => {
                assert!(!references.is_empty());
                assert_eq!(scheduler.tasks[id].waiting, 0);
                assert!(scheduler.tasks[id].hierarchy_waits.is_empty());
                for reference in references {
                    let Some(dependency) = scheduler.admit(
                        operation,
                        ReferenceKey {
                            reference,
                            environment,
                        },
                        None,
                    ) else {
                        return Ok(RoundOutcome::Cancelled);
                    };
                    if let Some(answer) = &scheduler.tasks[dependency].answer {
                        let mut evaluation =
                            FactEvaluation::new(operation.session, operation.hierarchy, reference);
                        if !evaluation.publish_qualified_hierarchy_reference(reference, answer)? {
                            return Ok(RoundOutcome::Cancelled);
                        }
                    } else {
                        scheduler.tasks[dependency].hierarchy_dependents.push(id);
                        scheduler.tasks[id].hierarchy_waits.push(dependency);
                        scheduler.tasks[id].waiting += 1;
                    }
                }
                if scheduler.tasks[id].waiting == 0 {
                    scheduler.runnable.push_back(Runnable::Task(id));
                }
            }
            DemandFactEvaluationPoll::AwaitingDemandedReference(reference) => {
                let reference = ReferenceKey {
                    reference,
                    environment,
                };
                if !operation.session.charge_scope_steps(1) {
                    return Ok(RoundOutcome::Cancelled);
                }
                let owner = scheduler
                    .claims
                    .get(&reference)
                    .expect("an awaited demanded reference has a live owner")
                    .owner;
                assert_ne!(owner, id, "a task never waits on its own claim");
                let closes_a_cycle = demanded_reference_wait_closes_a_cycle(scheduler, id, owner);
                let claim = scheduler
                    .claims
                    .get_mut(&reference)
                    .expect("an awaited demanded reference has a live owner");
                if closes_a_cycle {
                    // The owner already waits, directly or through relations,
                    // on this task. Evaluating the reference here is what
                    // every task did before the claim existed.
                    claim.bypass.insert(id);
                    scheduler.runnable.push_back(Runnable::Task(id));
                } else {
                    claim.waiters.push(id);
                    scheduler.tasks[id].waiting += 1;
                    assert!(scheduler.tasks[id].claim_wait.replace(reference).is_none());
                }
            }
            DemandFactEvaluationPoll::AwaitingDependencies => {
                let endpoints = scheduler.tasks[id]
                    .frame
                    .as_ref()
                    .unwrap()
                    .pending_requests()
                    .iter()
                    .map(|request| RelationKey {
                        endpoint: request.endpoint().clone(),
                        environment,
                    })
                    .collect::<Vec<_>>();
                assert!(
                    !endpoints.is_empty(),
                    "pending task retains exact endpoint requests"
                );
                if provider.supports_batched_discoveries() {
                    awaiting_dependencies.push((id, endpoints));
                    continue;
                }
                let mut waiting = HashSet::default();
                for endpoint in endpoints {
                    if !operation.session.charge_scope_steps(1) {
                        return Ok(RoundOutcome::Cancelled);
                    }
                    let relation_id =
                        if let Some(&relation_id) = scheduler.relation_ids.get(&endpoint) {
                            relation_id
                        } else {
                            if !operation.session.charge_scope_steps(1) {
                                return Ok(RoundOutcome::Cancelled);
                            }
                            let discovery = provider.discover(&endpoint)?;
                            match scheduler.install_relation(operation, endpoint, discovery) {
                                RelationAdmission::Ready(id) => id,
                                RelationAdmission::Cancelled => return Ok(RoundOutcome::Cancelled),
                            }
                        };
                    if !scheduler.relations[relation_id].closed && waiting.insert(relation_id) {
                        scheduler.relations[relation_id].waiters.push(id);
                        scheduler.tasks[id].waiting += 1;
                        scheduler.tasks[id].waits_on.push(relation_id);
                    }
                }
                if scheduler.tasks[id].waiting == 0 {
                    scheduler.runnable.push_back(Runnable::Task(id));
                }
            }
        }
    }
    if awaiting_dependencies.is_empty() {
        return Ok(RoundOutcome::Continue);
    }

    // Discover all new endpoints from this poll round together. Languages
    // with a keyed source can then batch those reads per blob while the
    // scheduler still installs relations in task and request order below.
    let mut new_endpoints = Vec::new();
    let mut seen_endpoints = HashSet::default();
    for (_, endpoints) in &awaiting_dependencies {
        for endpoint in endpoints {
            if !operation.session.charge_scope_steps(1) {
                return Ok(RoundOutcome::Cancelled);
            }
            if !scheduler.relation_ids.contains_key(endpoint)
                && seen_endpoints.insert(endpoint.clone())
            {
                if !operation.session.charge_scope_steps(1) {
                    return Ok(RoundOutcome::Cancelled);
                }
                new_endpoints.push(endpoint.clone());
            }
        }
    }
    let discovered = provider.discover_many(&new_endpoints)?;
    assert_eq!(
        discovered.len(),
        new_endpoints.len(),
        "batched root discovery returns one result per endpoint"
    );
    let mut discovered = new_endpoints
        .into_iter()
        .zip(discovered)
        .collect::<HashMap<_, _>>();

    for (id, endpoints) in awaiting_dependencies {
        let mut waiting = HashSet::default();
        for endpoint in endpoints {
            let relation_id = if let Some(&relation_id) = scheduler.relation_ids.get(&endpoint) {
                relation_id
            } else {
                let discovery = discovered
                    .remove(&endpoint)
                    .expect("every new pending endpoint was batch-discovered");
                match scheduler.install_relation(operation, endpoint, discovery) {
                    RelationAdmission::Ready(id) => id,
                    RelationAdmission::Cancelled => return Ok(RoundOutcome::Cancelled),
                }
            };
            if !scheduler.relations[relation_id].closed && waiting.insert(relation_id) {
                scheduler.relations[relation_id].waiters.push(id);
                scheduler.tasks[id].waiting += 1;
                scheduler.tasks[id].waits_on.push(relation_id);
            }
        }
        // The readiness gate covered the complete lexical frontier.
        // Discovery may certify every endpoint as already served by the base
        // source, leaving no selected relation to await.
        if scheduler.tasks[id].waiting == 0 {
            scheduler.runnable.push_back(Runnable::Task(id));
        }
    }
    Ok(RoundOutcome::Continue)
}

// A claim lasts exactly as long as the lexical frame that took it. One
// frame answers every reference it claimed when it finishes; leaving that
// frame is what the waiters were waiting for. Ready tasks retire first.
fn release_task_claims<'a>(
    operation: &mut Resources<'_, 'a>,
    scheduler: &mut Scheduler<'a>,
    id: usize,
) -> bool {
    let task = &mut scheduler.tasks[id];
    if !task.claims.is_empty()
        && !task
            .frame
            .as_ref()
            .is_some_and(DemandFactEvaluationTask::holds_demanded_reference_claims)
    {
        for reference in std::mem::take(&mut task.claims) {
            if !release_demanded_reference(operation, scheduler, reference) {
                return false;
            }
        }
    }
    true
}

/// Release the demanded reference this task owned and wake what waited on it.
///
/// A waiter resumes as a miss. The owner publishes the operation's memo when
/// it finishes the reference cleanly and publishes nothing when it is
/// cancelled, so the waiter takes the memo in the first case and evaluates the
/// reference itself in the second. Returns false when waking the waiters
/// exhausted the request budget.
fn release_demanded_reference<'a>(
    operation: &mut Resources<'_, 'a>,
    scheduler: &mut Scheduler<'a>,
    reference: ReferenceKey,
) -> bool {
    let Some(claim) = scheduler.claims.remove(&reference) else {
        return true;
    };
    for waiter in claim.waiters {
        if !operation.session.charge_scope_steps(1) {
            return false;
        }
        let task = &mut scheduler.tasks[waiter];
        assert_eq!(task.claim_wait.take(), Some(reference));
        assert!(task.waiting > 0);
        task.waiting -= 1;
        if task.waiting == 0 {
            task.waits_on.clear();
            scheduler.runnable.push_back(Runnable::Task(waiter));
        }
    }
    true
}

/// Would this task waiting on that one close a cycle in the wait graph?
///
/// A task waits on the relations it registered for and on at most one demanded
/// reference another task owns; a relation waits on its prefix tasks that have
/// no answer yet. Walk those edges from the owner with an explicit stack: if
/// they reach the waiter, the wait would deadlock, and the waiter evaluates
/// the reference itself instead.
fn demanded_reference_wait_closes_a_cycle(
    scheduler: &Scheduler<'_>,
    waiter: usize,
    owner: usize,
) -> bool {
    let mut seen = HashSet::default();
    let mut stack = vec![Runnable::Task(owner)];
    while let Some(node) = stack.pop() {
        if node == Runnable::Task(waiter) {
            return true;
        }
        if !seen.insert(node) {
            continue;
        }
        match node {
            Runnable::Task(task) => {
                stack.extend(
                    scheduler.tasks[task]
                        .waits_on
                        .iter()
                        .copied()
                        .map(Runnable::Relation),
                );
                for &dependency in &scheduler.tasks[task].hierarchy_waits {
                    if scheduler.tasks[dependency].answer.is_none() {
                        stack.push(Runnable::Task(dependency));
                    }
                }
                if let Some(reference) = scheduler.tasks[task].claim_wait
                    && let Some(claim) = scheduler.claims.get(&reference)
                {
                    stack.push(Runnable::Task(claim.owner));
                }
            }
            Runnable::Relation(relation) => {
                let relation = &scheduler.relations[relation];
                if !relation.closed {
                    stack.extend(relation.waits_on.iter().copied().map(Runnable::Relation));
                    for &dependency in &relation.dependencies {
                        if scheduler.tasks[dependency].answer.is_none() {
                            stack.push(Runnable::Task(dependency));
                        }
                    }
                }
            }
        }
    }
    false
}

/// Read this round's keyed source rows once for the whole round.
///
/// Every frame of a round asks the same three keyed statements for its own one
/// or two keys, so a round's width is spent one key at a time. This collects
/// the keys of the frames that are ready for them, reads each statement once
/// for the deduplicated union, and publishes the rows to the operation's
/// artifact cache, which is where each frame's own poll then finds exactly its
/// own keys.
///
/// What stays per frame: readiness, so a frame whose endpoints are not closed
/// is left out of the merged read and polled unchanged; the budget, because
/// nothing here charges the session and each frame still charges the keys it
/// contributed when it takes them; and cancellation, because a merged read
/// that observes it publishes nothing and every frame then reads and retains
/// its own evidence. No frame's answer is built from another frame's rows.
///
/// Retention: the collected keys and the rows they return live for this call.
/// What outlives it is the operation's artifact cache, which already held
/// exactly these artifacts for its own lifetime.
fn merge_round_reads<'a>(
    operation: &mut Resources<'_, 'a>,
    scheduler: &mut Scheduler<'a>,
    round: &[usize],
) -> StoreResult<()> {
    if round.len() < 2 {
        return Ok(());
    }
    for &id in round {
        assert_eq!(
            scheduler.tasks[id].root.environment, CALLER_ENVIRONMENT,
            "G0 does not enable remote round reads"
        );
    }
    // One seed read for every task this round admitted. A prefix task arrives
    // without a seed and would otherwise read its own in its first lexical
    // frame; a root arrives with the one its batch already read.
    let unseeded = round
        .iter()
        .filter(|&&id| {
            scheduler.tasks[id]
                .frame
                .as_ref()
                .expect("runnable task is live")
                .unseeded_root()
        })
        .map(|&id| scheduler.tasks[id].root)
        .collect::<Vec<_>>();
    if unseeded.len() > 1 {
        for group in unseeded.chunks(MAX_REFERENCE_SEEDS_PER_BATCH) {
            let Some(mut seeds) = read_root_seeds(operation, group, scheduler)? else {
                return Ok(());
            };
            for &id in round {
                if let Some(seed) = seeds.remove(&scheduler.tasks[id].root) {
                    scheduler.tasks[id]
                        .frame
                        .as_mut()
                        .expect("runnable task is live")
                        .install_round_root_seed(seed);
                }
            }
        }
    }
    let cancellation = operation.session.cancellation;
    let maximum_page_rows =
        operation
            .session
            .resolution_session
            .map_or(MAX_SOURCE_ROWS_PER_BATCH, |session| {
                session
                    .scope_lookahead_limit()
                    .clamp(1, MAX_SOURCE_ROWS_PER_BATCH)
            });
    let Scheduler {
        tasks,
        relations,
        relation_ids,
        work,
        ..
    } = scheduler;
    let mut endpoints = Vec::new();
    let mut nodes = Vec::new();
    let mut hydrations = Vec::new();
    for &id in round {
        let environment = tasks[id].root.environment;
        let Some(frame) = tasks[id]
            .frame
            .as_mut()
            .and_then(DemandFactEvaluationTask::active_forward_frame)
        else {
            continue;
        };
        frame.round_endpoint_classifications(operation.forward_candidate_artifacts, &mut nodes);
        frame.round_candidate_hydrations(operation.candidate_paths, &mut hydrations);
        // Building the page is the work this frame's own poll does, and the
        // page its poll then reads is this one.
        let page = frame.round_request_page(cancellation);
        if page.is_empty()
            || !page.iter().all(|request| {
                relation_ids
                    .get(&RelationKey {
                        endpoint: request.endpoint().clone(),
                        environment,
                    })
                    .is_some_and(|&relation| relations[relation].closed)
            })
        {
            continue;
        }
        for request in page {
            let Some(endpoint) = request
                .endpoint()
                .clone_with_poll(&mut || poll_cancelled(cancellation, work))
            else {
                return Ok(());
            };
            endpoints.push(endpoint);
        }
    }
    prefetch_endpoint_classifications(
        operation.session.lexical_source,
        operation.forward_candidate_artifacts,
        &nodes,
        cancellation,
        work,
        &mut |definitions| operation.session.classification_member_owners(definitions),
    )?;
    prefetch_forward_candidate_artifacts(
        operation.session.lexical_source,
        operation.forward_candidate_artifacts,
        endpoints,
        maximum_page_rows,
        cancellation,
        work,
    )?;
    prefetch_candidate_hydrations(
        operation.session.lexical_source,
        operation.candidate_paths,
        &hydrations,
        cancellation,
        work,
    )?;
    Ok(())
}

/// Read every distinct root's seed in one batched statement set.
///
/// `None` means the read was cancelled: its evidence is already in the
/// scheduler's ledger and the caller must drain the scheduler. A root the
/// exhausted read reports absent is simply missing from the map; its task then
/// reads its own seed, which is the path that has always produced that root's
/// exhausted-absence lexical answer.
fn read_root_seeds<'a>(
    operation: &mut Resources<'_, 'a>,
    roots: &[ReferenceKey],
    scheduler: &mut Scheduler<'a>,
) -> StoreResult<Option<HashMap<ReferenceKey, ReferenceSeed>>> {
    let cancellation = operation.session.cancellation;
    let source = operation.session.lexical_source;
    let mut queries = Vec::with_capacity(roots.len());
    let mut queried = HashMap::default();
    for &root in roots {
        assert_eq!(
            root.environment, CALLER_ENVIRONMENT,
            "G0 does not enable remote source reads"
        );
        if queried.insert(root.reference, root).is_none() {
            queries.push(ResolutionQuery::new(root.reference));
        }
    }
    let outcome = source.lookup_reference_seeds(&queries, cancellation)?;
    let (rows, terminal, evidence) = outcome.into_parts();
    if terminal == ReferenceSeedReadTerminal::Cancelled {
        assert!(rows.is_empty(), "cancelled seed reads publish no rows");
        scheduler
            .evidence
            .include(&evidence, cancellation, &mut scheduler.work);
        scheduler
            .evidence
            .include_reason(ResolutionIncompleteReason::Cancelled);
        return Ok(None);
    }
    super::validate_reference_seed_rows(&rows, &queries, "demand batch seed read")?;
    let mut seeds = HashMap::default();
    for row in rows.into_vec() {
        let reference = row.query().reference();
        if let Some(seed) = row.into_seed() {
            assert!(
                seeds.insert(queried[&reference], seed).is_none(),
                "one batched seed read answers each reference once"
            );
        }
    }
    Ok(Some(seeds))
}

pub(super) enum EndpointPreparation {
    Ready(ResolutionCompletion),
    Incomplete(ResolutionCompletion),
}

/// Close one endpoint between evaluator polls. Its positioned prefix tasks run
/// through the same iterative scheduler as a point query.
pub(super) fn prepare_forward(
    resources: &mut Resources<'_, '_>,
    provider: &mut (impl RootProvider + ?Sized),
    endpoint: &RelationKey,
    target: SemanticId,
) -> StoreResult<EndpointPreparation> {
    let plan = match provider.discover(endpoint)? {
        RootDiscovery::AlreadyReady { completion } => {
            return Ok(EndpointPreparation::Ready(completion));
        }
        RootDiscovery::Ready(plan) => plan,
        RootDiscovery::Cancelled(completion) => {
            return Ok(EndpointPreparation::Incomplete(completion));
        }
        RootDiscovery::Unavailable { completion, .. } => {
            return Ok(EndpointPreparation::Incomplete(completion.combine(
                &ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(target),
                ]),
            )));
        }
    };
    let mut answers = Vec::new();
    for root in plan.prefixes {
        assert_eq!(
            root.environment, CALLER_ENVIRONMENT,
            "G0 does not enable remote prefix execution"
        );
        match resolve(resources, root.reference, provider)? {
            Outcome::Ready(answer) => answers.push((root, answer)),
            Outcome::Unavailable { completion, .. } => {
                return Ok(EndpointPreparation::Incomplete(completion.combine(
                    &ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(root.reference),
                    ]),
                )));
            }
            Outcome::Cancelled(completion)
            | Outcome::Unsupported(Unsupported::CyclicPrefixDependency { completion, .. }) => {
                return Ok(EndpointPreparation::Incomplete(completion));
            }
        }
    }
    let inputs = answers
        .iter()
        .map(|(root, answer)| (*root, answer))
        .collect::<Vec<_>>();
    let (request, member_completion) = match provider.member_selection(endpoint, &inputs)? {
        MemberSelectionOutcome::Ready {
            request,
            completion,
        } => (request, completion),
        MemberSelectionOutcome::QualifierIsNamespace => {
            unreachable!("namespace classification belongs to registered preparation")
        }
        MemberSelectionOutcome::Unavailable(completion)
        | MemberSelectionOutcome::Cancelled(completion) => {
            let completion = inputs.iter().fold(
                plan.completion.combine(&completion),
                |completion, (_, answer)| completion.combine(answer.completion()),
            );
            return Ok(EndpointPreparation::Incomplete(completion));
        }
    };
    let completion = if let Some(request) = request {
        return prepare_selected_member_relation(
            resources,
            provider,
            endpoint,
            answers,
            plan.completion.combine(&member_completion),
            request,
            member_completion,
            None,
        );
    } else {
        let provenance = HierarchyProvenanceView::new(resources.hierarchy);
        match provider.poll_close(
            endpoint,
            &inputs,
            None,
            &member_completion,
            provenance,
            CloseResume::Start,
        )? {
            CloseProgress::Ready(completion) => completion,
            CloseProgress::Cancelled(completion) => {
                return Ok(EndpointPreparation::Incomplete(completion));
            }
            CloseProgress::Reference {
                continuation,
                key,
                completion,
            } => {
                continuation.assert_current(provenance);
                return prepare_reference_relation(
                    resources,
                    provider,
                    endpoint,
                    answers,
                    plan.completion.combine(&completion),
                    key,
                    member_completion,
                    continuation,
                );
            }
            CloseProgress::Members {
                continuation,
                request,
                completion,
            } => {
                continuation.assert_current(provenance);
                return prepare_selected_member_relation(
                    resources,
                    provider,
                    endpoint,
                    answers,
                    plan.completion.combine(&completion),
                    request,
                    member_completion,
                    Some(continuation),
                );
            }
        }
    };
    if resources.session.cancellation.is_cancelled() || resources.session.resolution_stopped() {
        return Ok(EndpointPreparation::Incomplete(completion.combine(
            &ResolutionCompletion::incomplete([ResolutionIncompleteReason::Cancelled]),
        )));
    }
    Ok(EndpointPreparation::Ready(completion))
}

/// Endpoint preparation has already exhausted its positioned receiver answers.
/// Only a requested member selection creates a relation scheduler here; ordinary
/// providers retain their previous prefix order, duplicates and close behavior.
// Keep the selected prefix evidence and optional continuation lease explicit.
#[allow(clippy::too_many_arguments)]
fn seed_close_scheduler<'source>(
    resources: &mut Resources<'_, 'source>,
    endpoint: &RelationKey,
    answers: Vec<(ReferenceKey, FactResolutionAnswer)>,
    completion: ResolutionCompletion,
) -> (Scheduler<'source>, RelationAdmission) {
    let mut scheduler = new_scheduler();
    for (_, answer) in &answers {
        include_fact_answer_cancellation_evidence(
            &mut scheduler.evidence,
            answer,
            resources.session.cancellation,
            &mut scheduler.work,
        );
    }
    let prefixes = answers.iter().map(|(root, _)| *root).collect::<Vec<_>>();
    let discovery = RootDiscovery::Ready(RootPlan {
        prefixes,
        completion,
    });
    let admission = scheduler.install_relation(resources, endpoint.clone(), discovery);
    let RelationAdmission::Ready(relation) = admission else {
        return (scheduler, admission);
    };
    // These are immutable, terminal evaluations from this same Resources. The
    // newly admitted frame has not performed reads and is replaced by its answer.
    for (reference, answer) in answers {
        let id = scheduler.task_ids[&reference];
        scheduler.tasks[id].frame = None;
        scheduler.tasks[id].answer = Some(answer);
        scheduler.tasks[id].dependents.clear();
    }
    scheduler.completed_prefix = scheduler.tasks.len();
    scheduler.runnable.clear();
    scheduler.relations[relation].pending = 0;
    (scheduler, RelationAdmission::Ready(relation))
}

#[allow(clippy::too_many_arguments)]
fn prepare_reference_relation(
    resources: &mut Resources<'_, '_>,
    provider: &mut (impl RootProvider + ?Sized),
    endpoint: &RelationKey,
    answers: Vec<(ReferenceKey, FactResolutionAnswer)>,
    completion: ResolutionCompletion,
    key: ReferenceKey,
    member_completion: ResolutionCompletion,
    continuation: CloseContinuationId,
) -> StoreResult<EndpointPreparation> {
    assert_eq!(
        key.environment, endpoint.environment,
        "reference prerequisite environment"
    );
    let (mut scheduler, admission) = seed_close_scheduler(resources, endpoint, answers, completion);
    let relation = match admission {
        RelationAdmission::Ready(id) => id,
        RelationAdmission::Cancelled => {
            provider.cancel_close(endpoint);
            let BatchOutcome::Cancelled(completion) = scheduler.cancelled(resources) else {
                unreachable!("cancel ledger");
            };
            return Ok(EndpointPreparation::Incomplete(completion));
        }
    };
    if !resources.session.charge_scope_steps(1) {
        provider.cancel_close(endpoint);
        let BatchOutcome::Cancelled(completion) = scheduler.cancelled(resources) else {
            unreachable!("cancel ledger");
        };
        return Ok(EndpointPreparation::Incomplete(completion));
    }
    let Some(task) = scheduler.admit(resources, key, None) else {
        provider.cancel_close(endpoint);
        let BatchOutcome::Cancelled(completion) = scheduler.cancelled(resources) else {
            unreachable!("cancel ledger");
        };
        return Ok(EndpointPreparation::Incomplete(completion));
    };
    scheduler.relations[relation].member_completion = member_completion;
    scheduler.relations[relation].member_requested = true;
    scheduler.relations[relation].close_continuation = Some(continuation);
    scheduler.relations[relation].close_reference = Some((key, task));
    scheduler.close_waiters.insert(endpoint.clone());
    if scheduler.tasks[task].answer.is_some() {
        scheduler.runnable.push_back(Runnable::Relation(relation));
    } else {
        if !scheduler.relations[relation].dependencies.contains(&task) {
            scheduler.relations[relation].dependencies.push(task);
        }
        scheduler.tasks[task].dependents.push(relation);
        scheduler.relations[relation].pending += 1;
    }
    finish_prepared_relation(resources, scheduler, provider, relation)
}

#[allow(clippy::too_many_arguments)] // Explicit retained suspension inputs.
fn prepare_selected_member_relation(
    resources: &mut Resources<'_, '_>,
    provider: &mut (impl RootProvider + ?Sized),
    endpoint: &RelationKey,
    answers: Vec<(ReferenceKey, FactResolutionAnswer)>,
    completion: ResolutionCompletion,
    request: MemberSelectionRequest,
    member_completion: ResolutionCompletion,
    continuation: Option<CloseContinuationId>,
) -> StoreResult<EndpointPreparation> {
    let (mut scheduler, admission) = seed_close_scheduler(resources, endpoint, answers, completion);
    let relation = match admission {
        RelationAdmission::Ready(id) => id,
        RelationAdmission::Cancelled => {
            if continuation.is_some() {
                provider.cancel_close(endpoint);
            }
            let BatchOutcome::Cancelled(completion) = scheduler.cancelled(resources) else {
                unreachable!("cancellation returns ledger");
            };
            return Ok(EndpointPreparation::Incomplete(completion));
        }
    };
    let Some(frame) = MemberSelectionFrame::new(resources, request) else {
        if continuation.is_some() {
            provider.cancel_close(endpoint);
        }
        let BatchOutcome::Cancelled(completion) = scheduler.cancelled(resources) else {
            unreachable!("cancellation returns its ledger");
        };
        return Ok(EndpointPreparation::Incomplete(completion));
    };
    scheduler.relations[relation].member_completion = member_completion;
    scheduler.relations[relation].close_continuation = continuation;
    if continuation.is_some() {
        scheduler.close_waiters.insert(endpoint.clone());
    }
    scheduler.relations[relation].member_requested = true;
    // The scalar root charged no prefix work before handing off; the scheduler
    // performs the original charge once before it invokes the resume.
    scheduler.relations[relation].member_selection = Some(Box::new(frame));
    scheduler.runnable.push_back(Runnable::Relation(relation));
    finish_prepared_relation(resources, scheduler, provider, relation)
}

fn finish_prepared_relation<'source>(
    resources: &mut Resources<'_, 'source>,
    scheduler: Scheduler<'source>,
    provider: &mut (impl RootProvider + ?Sized),
    relation: usize,
) -> StoreResult<EndpointPreparation> {
    match drive_scheduler(resources, scheduler, provider, Vec::new(), |scheduler| {
        scheduler.relations[relation].closed
    })? {
        SchedulerOutcome::Ready(scheduler) => {
            scheduler.retain_completed_roots(resources);
            Ok(EndpointPreparation::Ready(
                scheduler.relations[relation]
                    .completion
                    .clone()
                    .expect("closed relation retains its completion"),
            ))
        }
        SchedulerOutcome::Terminal(outcome) | SchedulerOutcome::Incomplete(_, outcome) => {
            let completion = match outcome {
                BatchOutcome::Cancelled(completion)
                | BatchOutcome::Unavailable { completion, .. }
                | BatchOutcome::Unsupported(Unsupported::CyclicPrefixDependency {
                    completion,
                    ..
                }) => completion,
                BatchOutcome::Ready(_) => unreachable!("driver returns its scheduler on success"),
            };
            Ok(EndpointPreparation::Incomplete(completion))
        }
    }
}

/// Close only the forward relations an exact reverse endpoint admits.
pub(super) fn prepare_reverse(
    resources: &mut Resources<'_, '_>,
    provider: &mut (impl RootProvider + ?Sized),
    endpoint: &RelationKey,
    target: SemanticId,
) -> StoreResult<EndpointPreparation> {
    let mut completion = ResolutionCompletionAccumulator::default();
    for dependency in provider.reverse_dependencies(endpoint)? {
        match prepare_forward(resources, provider, &dependency, target)? {
            EndpointPreparation::Ready(evidence) => completion.include(&evidence),
            EndpointPreparation::Incomplete(evidence) => {
                completion.include(&evidence);
                return Ok(EndpointPreparation::Incomplete(completion.finish()));
            }
        }
    }
    if resources.session.cancellation.is_cancelled() || resources.session.resolution_stopped() {
        return Ok(EndpointPreparation::Incomplete(
            completion
                .finish()
                .combine(&ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::Cancelled,
                ])),
        ));
    }
    provider.close_reverse(endpoint);
    Ok(EndpointPreparation::Ready(completion.finish()))
}

/// A complete lexical certificate remains useful when independent typed or
/// receiver prerequisites stay open. Retain those whole-answer frontiers;
/// replace only the otherwise empty binding through the shared universe rule.
fn select_universe_binding(
    session: &FactReadSession<'_>,
    language: Language,
    reference: SemanticId,
    answer: &mut FactResolutionAnswer,
) -> StoreResult<()> {
    if session.resolution_stopped() || session.cancellation.is_cancelled() {
        return Ok(());
    }
    if let Some(binding) = super::super::batch::selected_universe_binding(
        session.lexical_source,
        language,
        reference,
        session.cancellation,
    )? {
        if !answer.binding.targets().is_empty() && answer.binding.targets() != binding.targets() {
            return Ok(());
        }
        // A typed evaluation can retain unrelated runtime/type obligations on
        // the same intrinsic target. The published lexical certificate proves
        // this binding, while the answer's other channels retain their gaps.
        if answer
            .site_metadata
            .is_some_and(FactReferenceSiteMetadata::is_callable_reference)
        {
            answer.callable_receiver_dispositions = binding
                .targets()
                .iter()
                .map(|&target| {
                    FactCallableReceiverTargetDisposition::new(
                        target,
                        FactCallableReceiverDisposition::unresolved(
                            FactReferenceReceiverGap::UnresolvedReceiver,
                        ),
                    )
                })
                .collect();
        }
        answer.binding = binding;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::resolution::StackPattern;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId;

    fn with_resources(run: impl FnOnce(&mut Resources<'_, '_>)) {
        with_resources_in_session(None, run);
    }

    fn with_resources_in_session(
        resolution_session: Option<&ResolutionSession>,
        run: impl FnOnce(&mut Resources<'_, '_>),
    ) {
        let source = PreloadedFactResolutionService::from_lowered_fragments([], []);
        with_source_resources(&source, resolution_session, run);
    }

    fn with_source_resources(
        source: &PreloadedFactResolutionService,
        resolution_session: Option<&ResolutionSession>,
        run: impl FnOnce(&mut Resources<'_, '_>),
    ) {
        let cancellation = CancellationToken::new();
        let mut session = FactReadSession::from_split_sources(source, source, &cancellation);
        session.resolution_session = resolution_session;
        let mut hierarchy = HierarchyOperationArena::default();
        let mut forward_candidate_artifacts = ForwardCandidateArtifactCache::default();
        let mut candidate_paths = CandidatePathStore::default();
        run(&mut Resources {
            session: &mut session,
            hierarchy: &mut hierarchy,
            completed_roots: None,
            forward_candidate_artifacts: &mut forward_candidate_artifacts,
            candidate_paths: &mut candidate_paths,
        });
    }

    fn member_endpoint() -> RelationKey {
        RelationKey::caller(EndpointSignature::new(
            BindingNodeId::universal_root(),
            StackPattern::closed([SemanticId::for_test("review-member-lookup")]),
            StackPattern::closed(Vec::<BindingNodeId>::new()),
        ))
    }

    struct MemberProvider<'a> {
        member: ResolutionCompletion,
        plan: ResolutionCompletion,
        memo: Option<ResolutionCompletion>,
        exhaust: Option<&'a ResolutionSession>,
        reads: usize,
    }
    impl RootProvider for MemberProvider<'_> {
        fn discover(&mut self, _: &RelationKey) -> StoreResult<RootDiscovery> {
            Ok(if let Some(completion) = &self.memo {
                RootDiscovery::AlreadyReady {
                    completion: completion.clone(),
                }
            } else {
                RootDiscovery::Ready(RootPlan {
                    prefixes: Vec::new(),
                    completion: self.plan.clone(),
                })
            })
        }
        fn close(
            &mut self,
            _: &RelationKey,
            _: &[(ReferenceKey, &FactResolutionAnswer)],
        ) -> StoreResult<ResolutionCompletion> {
            panic!("the scheduler must send member evidence before publication")
        }
        fn close_with_member_completion(
            &mut self,
            _: &RelationKey,
            _: &[(ReferenceKey, &FactResolutionAnswer)],
            member: &ResolutionCompletion,
        ) -> StoreResult<ResolutionCompletion> {
            self.memo = Some(self.plan.combine(member));
            Ok(self.memo.clone().unwrap())
        }
        fn member_selection(
            &mut self,
            _: &RelationKey,
            _: &[(ReferenceKey, &FactResolutionAnswer)],
        ) -> StoreResult<MemberSelectionOutcome> {
            self.reads += 1;
            let request = self.exhaust.map(|session| {
                assert!(
                    !session.scope_steps(usize::MAX),
                    "exhaust only after member read"
                );
                MemberSelectionRequest {
                    policy: &crate::analyzer::resolution::DEFAULT_HIERARCHY_POLICY,
                    order: None,
                    reference: SemanticId::for_test("review-member-reference"),
                    values: vec![ResolutionSlotValue::runtime(
                        ResolutionTypeRef::new(SemanticId::for_test("review-owner"), 0),
                        false,
                    )],
                    lookup: SemanticId::for_test("review-member-lookup"),
                    namespace: ResolutionNamespace::Value,
                    language: brokk_bifrost_core::analyzer::Language::Scala,
                }
            });
            Ok(MemberSelectionOutcome::Ready {
                request,
                completion: self.member.clone(),
            })
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#5658: independent review ad985610 found Ready member evidence vanished on budget exhaustion, cycles and blocked roots"
    )]
    fn shared_closer_member_read_terminal_evidence() {
        let gap = ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::for_test(
            "ready-member-gap",
        ));
        let member = ResolutionCompletion::incomplete([gap]);
        let bounded = ResolutionSession::bounded(
            ReceiverAnalysisBudget {
                max_scope_nodes: 10000,
                ..ReceiverAnalysisBudget::default()
            },
            None,
        );
        with_resources_in_session(Some(&bounded), |resources| {
            let endpoint = member_endpoint();
            let mut provider = MemberProvider {
                member: member.clone(),
                plan: ResolutionCompletion::Complete,
                memo: None,
                exhaust: Some(&bounded),
                reads: 0,
            };
            let mut scheduler = new_scheduler();
            let discovery = provider.discover(&endpoint).unwrap();
            assert!(matches!(
                scheduler.install_relation(resources, endpoint, discovery),
                RelationAdmission::Ready(_)
            ));
            let SchedulerOutcome::Terminal(BatchOutcome::Cancelled(completion)) =
                drive_scheduler(resources, scheduler, &mut provider, Vec::new(), |_| false)
                    .unwrap()
            else {
                panic!("member frame exhausted its budget")
            };
            assert_eq!(provider.reads, 1);
            assert!(completion.contains_reason(gap));
        });
        with_resources(|resources| {
            let endpoint = member_endpoint();
            let mut scheduler = new_scheduler();
            let RelationAdmission::Ready(id) = scheduler.install_relation(
                resources,
                endpoint,
                RootDiscovery::Ready(RootPlan {
                    prefixes: Vec::new(),
                    completion: ResolutionCompletion::Complete,
                }),
            ) else {
                panic!("relation admission")
            };
            let root = SemanticId::for_test("blocked-member-root");
            let task = scheduler
                .admit(resources, ReferenceKey::caller(root), None)
                .unwrap();
            scheduler.tasks[task].waits_on.push(id);
            scheduler.relations[id].member_completion = member.clone();
            scheduler.relations[id].member_selection = Some(Box::new(
                MemberSelectionFrame::new(
                    resources,
                    MemberSelectionRequest {
                        policy: &crate::analyzer::resolution::DEFAULT_HIERARCHY_POLICY,
                        order: None,
                        reference: root,
                        values: Vec::new(),
                        lookup: SemanticId::for_test("cycle-lookup"),
                        namespace: ResolutionNamespace::Value,
                        language: brokk_bifrost_core::analyzer::Language::Scala,
                    },
                )
                .unwrap(),
            ));
            scheduler.relations[id].waits_on.push(id);
            scheduler.runnable.clear();
            scheduler.finish_incomplete_roots(resources, 1).unwrap();
            assert!(
                scheduler.tasks[task]
                    .answer
                    .as_ref()
                    .unwrap()
                    .completion()
                    .contains_reason(gap),
                "blocked-root reduction retains ready member evidence"
            );
            let SchedulerOutcome::Incomplete(
                _,
                BatchOutcome::Unsupported(Unsupported::CyclicPrefixDependency {
                    completion, ..
                }),
            ) = drive_scheduler(
                resources,
                scheduler,
                &mut MemberProvider {
                    member: member.clone(),
                    plan: ResolutionCompletion::Complete,
                    memo: None,
                    exhaust: None,
                    reads: 0,
                },
                Vec::new(),
                |_| false,
            )
            .unwrap()
            else {
                panic!("relation-to-relation cycle")
            };
            assert!(
                completion.contains_reason(gap),
                "global cycle reduction retains ready member evidence"
            );
        });
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#5658: owner review found both scheduler entries lost Ready(None,incomplete) on repeated publication"
    )]
    fn shared_closer_member_none_memo_reuses_exact_completion() {
        let gap =
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                SemanticId::for_test("none-member-gap"),
            )]);
        for scalar in [false, true] {
            with_resources(|resources| {
                let endpoint = member_endpoint();
                let mut provider = MemberProvider {
                    member: gap.clone(),
                    plan: ResolutionCompletion::Complete,
                    memo: None,
                    exhaust: None,
                    reads: 0,
                };
                for _ in 0..2 {
                    let completion = if scalar {
                        match prepare_forward(
                            resources,
                            &mut provider,
                            &endpoint,
                            SemanticId::for_test("unused-target"),
                        )
                        .unwrap()
                        {
                            EndpointPreparation::Ready(c) | EndpointPreparation::Incomplete(c) => c,
                        }
                    } else {
                        let mut scheduler = new_scheduler();
                        let discovery = provider.discover(&endpoint).unwrap();
                        let RelationAdmission::Ready(id) =
                            scheduler.install_relation(resources, endpoint.clone(), discovery)
                        else {
                            panic!("relation admission")
                        };
                        let SchedulerOutcome::Ready(scheduler) =
                            drive_scheduler(resources, scheduler, &mut provider, Vec::new(), |s| {
                                s.relations[id].closed
                            })
                            .unwrap()
                        else {
                            panic!("ordinary relation closes")
                        };
                        scheduler.relations[id].completion.clone().unwrap()
                    };
                    assert_eq!(
                        completion, gap,
                        "both entries and positive memo retain exactly the read evidence"
                    );
                }
                assert_eq!(
                    provider.reads, 1,
                    "positive memo does not poll the member hook"
                );
            });
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#5658: independent review ad985610 found scalar member terminal returns dropped discovery evidence"
    )]
    fn shared_closer_scalar_member_terminal_keeps_discovery() {
        struct TerminalProvider(
            ResolutionCompletion,
            ResolutionCompletion,
            bool,
            ReferenceKey,
            Option<ResolutionCompletion>,
        );
        impl RootProvider for TerminalProvider {
            fn discover(&mut self, endpoint: &RelationKey) -> StoreResult<RootDiscovery> {
                // The prefix's own source boundary is already closed. Only
                // the outer member endpoint owns a plan with this prefix.
                if endpoint != &member_endpoint() {
                    return Ok(RootDiscovery::AlreadyReady {
                        completion: ResolutionCompletion::incomplete([
                            ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::for_test(
                                "scalar-prefix-provider-gap",
                            )),
                        ]),
                    });
                }
                Ok(RootDiscovery::Ready(RootPlan {
                    prefixes: vec![self.3],
                    completion: self.0.clone(),
                }))
            }
            fn close(
                &mut self,
                _: &RelationKey,
                _: &[(ReferenceKey, &FactResolutionAnswer)],
            ) -> StoreResult<ResolutionCompletion> {
                unreachable!("unavailable member proof cannot publish")
            }
            fn member_selection(
                &mut self,
                _: &RelationKey,
                inputs: &[(ReferenceKey, &FactResolutionAnswer)],
            ) -> StoreResult<MemberSelectionOutcome> {
                let [(key, prefix)] = inputs else {
                    panic!("one resolved positioned prefix")
                };
                assert_eq!(*key, self.3);
                self.4 = Some(prefix.completion().clone());
                Ok(if self.2 {
                    MemberSelectionOutcome::Cancelled(self.1.clone())
                } else {
                    MemberSelectionOutcome::Unavailable(self.1.clone())
                })
            }
        }
        let plan =
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                SemanticId::for_test("scalar-plan-gap"),
            )]);
        let member =
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                SemanticId::for_test("scalar-member-gap"),
            )]);
        use brokk_bifrost_core::analyzer::resolution_facts::{
            FileResolutionFacts, PositionedIdentifierFact, ResolutionGapKind,
            ResolutionIdentifierRole, ResolutionNameFact, ResolutionNameId, ResolutionScopeFact,
            ResolutionScopeId, ResolutionScopeInheritance, ResolutionScopeKind, ResolutionSiteKind,
        };
        let mut facts = FileResolutionFacts::default();
        let scope = ResolutionScopeId::new(0);
        facts.scopes.push(ResolutionScopeFact {
            id: scope,
            parent: None,
            owner: None,
            kind: ResolutionScopeKind::CompilationUnit,
            inheritance: ResolutionScopeInheritance::Root,
            start_byte: 0,
            end_byte: 3,
        });
        let site = facts.add_site(scope, ResolutionSiteKind::ValueReference, 2, 3);
        facts.names.push(ResolutionNameFact {
            id: ResolutionNameId::new(0),
            spelling: "prefix".into(),
        });
        facts.identifiers.push(PositionedIdentifierFact {
            site,
            name: ResolutionNameId::new(0),
            role: ResolutionIdentifierRole::Reference,
            namespace: ResolutionNamespace::Value,
            qualifier: None,
        });
        let declaration = facts.add_site(scope, ResolutionSiteKind::ValueDeclaration, 0, 1);
        facts.identifiers.push(PositionedIdentifierFact {
            site: declaration,
            name: ResolutionNameId::new(0),
            role: ResolutionIdentifierRole::Declaration,
            namespace: ResolutionNamespace::Value,
            qualifier: None,
        });
        facts.binders.push(
            brokk_bifrost_core::analyzer::resolution_facts::ResolutionBinderFact::scope_wide(
                declaration,
                brokk_bifrost_core::analyzer::resolution_facts::ResolutionBinderKind::Local,
                facts.scopes[0],
            ),
        );
        facts.add_gap(site, ResolutionGapKind::UnsupportedExpression);
        let fragment = BindingFragmentId::for_test("member-terminal-prefix");
        let lowered = super::super::super::fact_lowering::lower_for_test(
            fragment,
            brokk_bifrost_core::analyzer::Language::Rust,
            &facts,
        );
        let prefix = ReferenceKey::caller(
            lowered
                .lexical()
                .semantics()
                .iter()
                .find(|semantic| {
                    semantic.site() == site
                        && semantic.role() == super::super::super::LoweredSemanticRole::Reference
                })
                .expect("the prefix is a lowered reference")
                .semantic(),
        );
        let source = PreloadedFactResolutionService::from_lowered_fragments(
            [lowered.lexical().clone()],
            [lowered.typed().clone()],
        );
        for cancelled in [false, true] {
            with_source_resources(&source, None, |resources| {
                let mut provider =
                    TerminalProvider(plan.clone(), member.clone(), cancelled, prefix, None);
                let EndpointPreparation::Incomplete(completion) = prepare_forward(
                    resources,
                    &mut provider,
                    &member_endpoint(),
                    SemanticId::for_test("unused-target"),
                )
                .unwrap() else {
                    panic!("terminal member read")
                };
                let prefix = provider
                    .4
                    .expect("prefix resolved before member terminal outcome");
                assert_ne!(
                    prefix,
                    ResolutionCompletion::Complete,
                    "positioned prefix carries independent reason B"
                );
                assert_ne!(prefix, plan);
                assert_ne!(prefix, member);
                assert_eq!(
                    completion,
                    plan.combine(&prefix).combine(&member),
                    "retain discovery A, prefix B and member C"
                );
            });
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#5658: member provider proof was stranded on its endpoint instead of the requesting relation"
    )]
    fn shared_member_selection_scopes_provider_witnesses_to_requesting_relation() {
        struct Provider {
            endpoint: RelationKey,
            witness: SemanticId,
            witnesses: BTreeSet<SemanticId>,
            reason: SemanticId,
            selected: bool,
            retained: HashMap<RelationKey, BTreeSet<SemanticId>>,
        }
        impl RootProvider for Provider {
            fn discover(&mut self, _: &RelationKey) -> StoreResult<RootDiscovery> {
                unreachable!("the fixture supplies terminal dependency admission")
            }
            fn close(
                &mut self,
                _: &RelationKey,
                _: &[(ReferenceKey, &FactResolutionAnswer)],
            ) -> StoreResult<ResolutionCompletion> {
                Ok(ResolutionCompletion::Complete)
            }
            fn close_selected_members(
                &mut self,
                _: &RelationKey,
                _: &[(ReferenceKey, &FactResolutionAnswer)],
                selection: &MemberSelection,
            ) -> StoreResult<ResolutionCompletion> {
                assert_eq!(
                    selection.discharged_provider_reasons,
                    BTreeSet::from([self.witness])
                );
                self.selected = true;
                Ok(ResolutionCompletion::Complete)
            }
            fn retain_member_provider_reasons(
                &mut self,
                endpoint: &RelationKey,
                reasons: &BTreeSet<SemanticId>,
            ) {
                self.retained
                    .entry(endpoint.clone())
                    .or_default()
                    .extend(reasons);
            }
            fn discharged_provider_reasons(
                &self,
                endpoint: &RelationKey,
            ) -> Option<&BTreeSet<SemanticId>> {
                (*endpoint == self.endpoint).then_some(&self.witnesses)
            }
            fn resolved_closure_discharges(
                &self,
                endpoint: &RelationKey,
            ) -> Option<ClosureDischarges> {
                Some(if *endpoint == self.endpoint {
                    // Only the provider proof may cross the selection boundary.
                    ClosureDischarges::exact([self.witness])
                        .with_discharged_provider_reasons([self.witness])
                        .with_authoritative_empty_result()
                } else {
                    ClosureDischarges::exact([self.reason]).with_discharged_provider_reasons(
                        self.retained.get(endpoint).into_iter().flatten().copied(),
                    )
                })
            }
        }
        // Exercise both a provider closed here and a previously closed provider.
        for local in [true, false] {
            with_resources(|resources| {
                let endpoint = |name| {
                    RelationKey::caller(EndpointSignature::new(
                        BindingNodeId::universal_root(),
                        StackPattern::closed([SemanticId::for_test(name)]),
                        StackPattern::closed(Vec::<BindingNodeId>::new()),
                    ))
                };
                let requested = endpoint("witness-requested");
                let unrelated = endpoint("witness-unrelated");
                let dependency = endpoint("witness-provider");
                let witness = SemanticId::for_test("negative-provider-witness");
                let reason = SemanticId::for_test("terminal-reason");
                let mut provider = Provider {
                    endpoint: dependency.clone(),
                    witness,
                    witnesses: BTreeSet::from([witness]),
                    reason,
                    selected: false,
                    retained: HashMap::default(),
                };
                let mut scheduler = new_scheduler();
                let mut ids = Vec::new();
                for key in [&requested, &unrelated] {
                    let RelationAdmission::Ready(id) = scheduler.install_relation(
                        resources,
                        key.clone(),
                        RootDiscovery::Ready(RootPlan {
                            prefixes: Vec::new(),
                            completion: ResolutionCompletion::Complete,
                        }),
                    ) else {
                        panic!("admitted relation")
                    };
                    ids.push(id);
                }
                assert!(matches!(
                    scheduler.install_relation(
                        resources,
                        dependency.clone(),
                        RootDiscovery::AlreadyReady {
                            completion: ResolutionCompletion::Complete,
                        },
                    ),
                    RelationAdmission::Ready(_)
                ));
                if local {
                    scheduler.closure_discharges.insert(
                        dependency.clone(),
                        provider.resolved_closure_discharges(&dependency).unwrap(),
                    );
                }
                // The sibling has its own provider proof; it must never enter
                // the requesting selection merely because it shares a request.
                let sibling_witness = SemanticId::for_test("sibling-provider-witness");
                scheduler.closure_discharges.insert(
                    unrelated.clone(),
                    ClosureDischarges::default()
                        .with_discharged_provider_reasons([sibling_witness]),
                );
                let mut witnesses = BTreeSet::new();
                assert!(matches!(
                    scheduler.member_readiness(
                        &[BatchCandidateRequest::new(0, dependency.endpoint.clone())],
                        CALLER_ENVIRONMENT,
                        &provider,
                        &mut witnesses,
                    ),
                    DemandForwardReadiness::Ready
                ));
                let evaluation = FactEvaluation::new_with_forward_artifacts(
                    resources.session,
                    resources.hierarchy,
                    resources.forward_candidate_artifacts,
                    resources.candidate_paths,
                    SemanticId::for_test("selection-reference"),
                )
                .into_checkpoint_state();
                // Start at the aggregate boundary after its exact provider
                // dependency, without invoking any language adapter or hook.
                scheduler.relations[ids[0]].member_requested = true;
                scheduler.relations[ids[0]].member_selection =
                    Some(Box::new(MemberSelectionFrame {
                        order: None,
                        provenance: HierarchyProvenanceId::default(),
                        evaluation: Some(evaluation),
                        groups: BTreeMap::new(),
                        active: None,
                        owners: BTreeSet::new(),
                        completion: ResolutionCompletion::Complete,
                        discharged_provider_reasons: witnesses,
                    }));
                let SchedulerOutcome::Ready(scheduler) = drive_scheduler(
                    resources,
                    scheduler,
                    &mut provider,
                    Vec::new(),
                    |scheduler| ids.iter().all(|&id| scheduler.relations[id].closed),
                )
                .unwrap() else {
                    panic!("both relations close")
                };
                assert!(provider.selected);
                assert_eq!(
                    provider.resolved_closure_discharges(&requested),
                    Some(
                        ClosureDischarges::exact([reason])
                            .with_discharged_provider_reasons([witness])
                    )
                );
                assert_eq!(
                    scheduler.closure_discharges[&requested],
                    ClosureDischarges::exact([reason]).with_discharged_provider_reasons([witness])
                );
                assert_eq!(
                    scheduler.closure_discharges[&unrelated],
                    ClosureDischarges::exact([reason])
                        .with_discharged_provider_reasons([sibling_witness])
                );
            });
        }
    }

    #[test]
    fn demand_scheduler_environment_keys_keep_answers_and_relations_separate() {
        struct Provider {
            closed: HashMap<RelationKey, FactResolutionAnswer>,
        }
        impl RootProvider for Provider {
            fn discover(&mut self, _: &RelationKey) -> StoreResult<RootDiscovery> {
                unreachable!("the test admits both root plans before driving closure")
            }

            fn close(
                &mut self,
                endpoint: &RelationKey,
                inputs: &[(ReferenceKey, &FactResolutionAnswer)],
            ) -> StoreResult<ResolutionCompletion> {
                assert_eq!(inputs.len(), 1);
                assert_eq!(inputs[0].0.environment, endpoint.environment);
                assert!(
                    self.closed
                        .insert(endpoint.clone(), inputs[0].1.clone())
                        .is_none()
                );
                Ok(ResolutionCompletion::Complete)
            }

            fn resolved_closure_discharges(
                &self,
                endpoint: &RelationKey,
            ) -> Option<ClosureDischarges> {
                Some(ClosureDischarges::exact(
                    self.closed[endpoint].binding().targets().iter().copied(),
                ))
            }
        }
        with_resources(|resources| {
            let reference = SemanticId::for_test("environment-reference");
            let endpoint = EndpointSignature::new(
                BindingNodeId::universal_root(),
                StackPattern::closed([SemanticId::for_test("environment-lookup")]),
                StackPattern::closed(Vec::<BindingNodeId>::new()),
            );
            let keys = [CALLER_ENVIRONMENT, EnvironmentId(1)].map(|environment| ReferenceKey {
                reference,
                environment,
            });
            let relations = keys.map(|key| RelationKey {
                endpoint: endpoint.clone(),
                environment: key.environment,
            });
            let targets = [
                SemanticId::for_test("environment-target-zero"),
                SemanticId::for_test("environment-target-one"),
            ];
            let mut scheduler = new_scheduler();
            for (key, relation) in keys.into_iter().zip(&relations) {
                assert!(matches!(
                    scheduler.install_relation(
                        resources,
                        relation.clone(),
                        RootDiscovery::Ready(RootPlan {
                            prefixes: vec![key, key],
                            completion: ResolutionCompletion::Complete,
                        })
                    ),
                    RelationAdmission::Ready(_)
                ));
            }
            assert_eq!(scheduler.tasks.len(), 2);
            assert_eq!(scheduler.relations.len(), 2);
            assert_eq!(scheduler.task_ids.len(), 2);
            for (key, target) in keys.into_iter().zip(targets) {
                let id = scheduler.task_ids[&key];
                assert_eq!(scheduler.admit(resources, key, None), Some(id));
                let mut answer = empty_fact_resolution_answer(
                    ResolutionCompletion::Complete,
                    resources.session.cancellation,
                );
                answer.binding =
                    ResolutionAnswer::new(vec![target], Vec::new(), ResolutionCompletion::Complete);
                scheduler.tasks[id].frame = None;
                scheduler.tasks[id].answer = Some(answer);
            }
            // G0 has no remote source reader. Supply terminal answers directly,
            // then exercise the real relation driver and provider callbacks.
            scheduler.runnable.clear();
            for (id, relation) in scheduler.relations.iter_mut().enumerate() {
                assert_eq!(relation.dependencies.len(), 1);
                relation.pending = 0;
                scheduler.runnable.push_back(Runnable::Relation(id));
            }
            let mut provider = Provider {
                closed: HashMap::default(),
            };
            let SchedulerOutcome::Ready(scheduler) = drive_scheduler(
                resources,
                scheduler,
                &mut provider,
                Vec::new(),
                |scheduler| scheduler.relations.iter().all(|relation| relation.closed),
            )
            .unwrap() else {
                panic!("both environment relations close independently");
            };
            for (relation, target) in relations.iter().zip(targets) {
                assert_eq!(provider.closed[relation].binding().targets(), &[target]);
                assert_eq!(
                    scheduler.closure_discharges[relation],
                    ClosureDischarges::exact([target])
                );
            }
        });
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#6572: a budget stop while releasing claims cancelled a finished task's Terminal frame"
    )]
    fn ready_task_claim_release_budget_cutoffs_retire_before_cancellation() {
        let mut release_cutoff = None;
        for cap in 0..128 {
            let budget = ResolutionSession::bounded(
                ReceiverAnalysisBudget {
                    max_scope_nodes: cap,
                    ..ReceiverAnalysisBudget::default()
                },
                None,
            );
            with_resources_in_session(Some(&budget), |resources| {
                let resolution_session = resources.session.resolution_session.take();
                let mut scheduler = new_scheduler();
                let owner_root = ReferenceKey::caller(SemanticId::for_test("finished-owner"));
                let waiter_root = ReferenceKey::caller(SemanticId::for_test("claim-waiter"));
                let reference = ReferenceKey::caller(SemanticId::for_test("shared-reference"));
                let owner = scheduler.admit(resources, owner_root, None).unwrap();
                let waiter = scheduler.admit(resources, waiter_root, None).unwrap();
                // Resume a task at the end of a lexical round, with another
                // task waiting for the reference that round owned. Empty
                // inputs make the fixed point deterministic and immediately
                // ready, without a language adapter or corpus dependency.
                let frame = scheduler.tasks[owner].frame.as_mut().unwrap();
                frame.phase = super::super::DemandFactEvaluationPhase::Round;
                let reason = ResolutionIncompleteReason::UnsupportedSemantic(owner_root.reference);
                let state = frame.evaluation.as_mut().unwrap();
                state.cancellation_reasons.include_reason_with_poll(
                    reason,
                    state.cancellation,
                    &mut state.work,
                    &mut state.cancellation_observed,
                );
                assert!(matches!(
                    frame
                        .poll_with_dependencies(
                            resources.session,
                            resources.hierarchy,
                            resources.forward_candidate_artifacts,
                            resources.candidate_paths,
                            &mut |_| panic!("empty round has no dependencies"),
                            &mut |_| panic!("empty round opens no lexical frame"),
                        )
                        .unwrap(),
                    DemandFactEvaluationPoll::Continue
                ));
                assert!(frame.references.as_ref().unwrap().references.is_empty());
                let binding = Arc::new(ResolutionAnswer::new(
                    Vec::new(),
                    Vec::new(),
                    ResolutionCompletion::incomplete([reason]),
                ));
                frame
                    .answers
                    .insert(owner_root.reference, Arc::clone(&binding));
                frame
                    .references
                    .as_mut()
                    .unwrap()
                    .answers
                    .insert(owner_root.reference, binding);
                scheduler.tasks[owner].claims.push(reference);
                scheduler.claims.insert(
                    reference,
                    DemandedReferenceOwner {
                        owner,
                        waiters: vec![waiter],
                        bypass: HashSet::default(),
                    },
                );
                scheduler.tasks[waiter].waiting = 1;
                scheduler.tasks[waiter].claim_wait = Some(reference);
                resources.session.resolution_session = resolution_session;
                let outcome = poll_round(
                    resources,
                    &mut scheduler,
                    &[owner],
                    &mut SourceProvider::new(),
                    &|_| false,
                    &mut HashSet::default(),
                )
                .unwrap();
                if matches!(outcome, RoundOutcome::Cancelled) {
                    let released = !scheduler.claims.contains_key(&reference);
                    let retired = scheduler.tasks[owner].frame.is_none();
                    let answer_stored = scheduler.tasks[owner].answer.is_some();
                    if released {
                        release_cutoff = Some(cap);
                        assert_eq!(scheduler.tasks[waiter].claim_wait, Some(reference));
                        assert_eq!(scheduler.tasks[waiter].waiting, 1);
                    }
                    let BatchOutcome::Cancelled(completion) = scheduler.cancelled(resources) else {
                        panic!("the cancellation drain must retain a cancelled outcome");
                    };
                    assert!(completion.contains_reason(reason));
                    if released {
                        assert!(retired && answer_stored);
                    }
                }
            });
        }
        assert!(
            release_cutoff.is_some(),
            "the sweep must stop during claim release"
        );
        eprintln!("claim-release cutoff: {release_cutoff:?}");
    }

    #[test]
    fn demand_scheduler_environment_claim_wait_and_cycle_edges_are_separate() {
        with_resources(|resources| {
            let mut scheduler = new_scheduler();
            let reference = SemanticId::for_test("claimed-environment-reference");
            let waiting_reference = SemanticId::for_test("waiting-environment-reference");
            let keys = [CALLER_ENVIRONMENT, EnvironmentId(1)].map(|environment| ReferenceKey {
                reference,
                environment,
            });
            let owners = keys.map(|key| scheduler.admit(resources, key, None).unwrap());
            let waiters = keys.map(|key| {
                scheduler
                    .admit(
                        resources,
                        ReferenceKey {
                            reference: waiting_reference,
                            ..key
                        },
                        None,
                    )
                    .unwrap()
            });
            scheduler.runnable.clear();
            for ((key, owner), waiter) in keys.into_iter().zip(owners).zip(waiters) {
                assert!(
                    scheduler
                        .claims
                        .insert(
                            key,
                            DemandedReferenceOwner {
                                owner,
                                waiters: vec![waiter],
                                bypass: HashSet::default()
                            }
                        )
                        .is_none()
                );
                scheduler.tasks[owner].claims.push(key);
                scheduler.tasks[waiter].claim_wait = Some(key);
                scheduler.tasks[waiter].waiting = 1;
            }
            assert!(demanded_reference_wait_closes_a_cycle(
                &scheduler, owners[0], waiters[0]
            ));
            assert!(!demanded_reference_wait_closes_a_cycle(
                &scheduler, owners[0], waiters[1]
            ));
            assert!(demanded_reference_wait_closes_a_cycle(
                &scheduler, owners[1], waiters[1]
            ));
            assert!(!demanded_reference_wait_closes_a_cycle(
                &scheduler, owners[1], waiters[0]
            ));
            assert!(release_demanded_reference(
                resources,
                &mut scheduler,
                keys[0]
            ));
            assert!(scheduler.tasks[waiters[0]].claim_wait.is_none());
            assert_eq!(scheduler.tasks[waiters[0]].waiting, 0);
            assert_eq!(scheduler.tasks[waiters[1]].claim_wait, Some(keys[1]));
            assert_eq!(scheduler.tasks[waiters[1]].waiting, 1);
            assert_eq!(scheduler.claims.len(), 1);
            assert_eq!(
                scheduler.runnable.pop_front(),
                Some(Runnable::Task(waiters[0]))
            );
            assert!(release_demanded_reference(
                resources,
                &mut scheduler,
                keys[1]
            ));
            assert_eq!(
                scheduler.runnable.pop_front(),
                Some(Runnable::Task(waiters[1]))
            );
            assert!(scheduler.claims.is_empty());
        });
    }

    #[test]
    fn demand_scheduler_environment_memo_keeps_authority_and_answers_separate() {
        with_resources(|resources| {
            let reference = SemanticId::for_test("environment-memo-reference");
            let seed = ReferenceSeed::new_with_site_metadata(
                BindingFragmentId::for_test("environment-memo-fragment"),
                ResolutionQuery::new(reference),
                BindingNodeId::for_test("environment-memo-node"),
                Some(FactReferenceSiteMetadata::new(
                    ResolutionSiteId::new(1),
                    ResolutionNamespace::Value,
                    ResolutionSiteKind::ValueReference,
                    0,
                    1,
                    true,
                    Some(None),
                    None,
                )),
                ResolutionCompletion::Complete,
            );
            let keys = [CALLER_ENVIRONMENT, EnvironmentId(1)].map(|environment| {
                RootMemoKey::new(
                    resources.session,
                    ReferenceKey {
                        reference,
                        environment,
                    },
                    &seed,
                    7,
                    [0x42; 32],
                )
                .unwrap()
            });
            let memo = SelectedDemandState::default();
            let gaps = [[0x51; 32], [0x52; 32]]
                .map(|digest| SemanticId::operation_local(memo.intern_identity(digest)));
            for (key, gap) in keys.iter().zip(gaps) {
                let answer = empty_fact_resolution_answer(
                    ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(gap),
                    ]),
                    resources.session.cancellation,
                );
                memo.retain(key, &answer, resources.session);
            }
            for (key, gap) in keys.iter().zip(gaps) {
                assert_eq!(
                    memo.lookup(key, resources.session).unwrap().completion(),
                    &ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(gap)
                    ])
                );
            }
            for (access, context) in [(8, [0x42; 32]), (7, [0x43; 32])] {
                let key = RootMemoKey::new(
                    resources.session,
                    ReferenceKey::caller(reference),
                    &seed,
                    access,
                    context,
                )
                .unwrap();
                assert!(memo.lookup(&key, resources.session).is_none());
            }
        });
    }
    struct SourceProvider {
        cancel_on_yield: Option<CancellationToken>,
        values: Vec<ResolutionSlotValue>,
        outstanding: Option<CloseContinuationId>,
        polls: usize,
        initial_reads: usize,
        cancelled: usize,
        error_at: Option<usize>,
        published: bool,
    }
    impl SourceProvider {
        fn new() -> Self {
            Self {
                cancel_on_yield: None,
                values: Vec::new(),
                outstanding: None,
                polls: 0,
                initial_reads: 0,
                cancelled: 0,
                error_at: None,
                published: false,
            }
        }
    }
    impl RootProvider for SourceProvider {
        fn discover(&mut self, _: &RelationKey) -> StoreResult<RootDiscovery> {
            Ok(RootDiscovery::Ready(RootPlan {
                prefixes: Vec::new(),
                completion: ResolutionCompletion::Complete,
            }))
        }
        fn close(
            &mut self,
            _: &RelationKey,
            _: &[(ReferenceKey, &FactResolutionAnswer)],
        ) -> StoreResult<ResolutionCompletion> {
            panic!("source continuations close through the one scheduler protocol")
        }
        fn member_selection(
            &mut self,
            _: &RelationKey,
            _: &[(ReferenceKey, &FactResolutionAnswer)],
        ) -> StoreResult<MemberSelectionOutcome> {
            self.initial_reads += 1;
            Ok(MemberSelectionOutcome::Ready {
                request: None,
                completion: ResolutionCompletion::Complete,
            })
        }
        fn cancel_close(&mut self, _: &RelationKey) {
            self.outstanding.take();
            self.cancelled += 1;
        }
        fn poll_close(
            &mut self,
            _: &RelationKey,
            _: &[(ReferenceKey, &FactResolutionAnswer)],
            _: Option<&MemberSelection>,
            _: &ResolutionCompletion,
            view: HierarchyProvenanceView<'_>,
            resume: CloseResume<'_>,
        ) -> StoreResult<CloseProgress<ResolutionCompletion>> {
            self.polls += 1;
            match resume {
                CloseResume::Start => assert!(self.outstanding.is_none()),
                CloseResume::Reference { .. } => {
                    panic!("member fixture never requests a reference")
                }
                CloseResume::Members {
                    continuation,
                    selection,
                } => {
                    continuation.assert_current(view);
                    assert_eq!(self.outstanding.take(), Some(continuation));
                    assert!(selection.owners.is_empty());
                    assert_eq!(selection.completion, ResolutionCompletion::Complete);
                }
            }
            if self.error_at == Some(self.polls) {
                return Err(StoreError::new("source continuation fault"));
            }
            if self.polls == 3 {
                self.published = true;
                return Ok(CloseProgress::Ready(ResolutionCompletion::Complete));
            }
            if let Some(cancellation) = self.cancel_on_yield.take() {
                cancellation.cancel();
            }
            let continuation = CloseContinuationId::issue(view);
            self.outstanding = Some(continuation);
            Ok(CloseProgress::Members {
                continuation,
                request: MemberSelectionRequest {
                    policy: &crate::analyzer::resolution::DEFAULT_HIERARCHY_POLICY,
                    order: None,
                    reference: SemanticId::for_test("source-continuation-reference"),
                    values: self.values.clone(),
                    lookup: SemanticId::for_test("source-continuation-lookup"),
                    namespace: ResolutionNamespace::Type,
                    language: Language::Scala,
                },
                completion: ResolutionCompletion::Complete,
            })
        }
    }
    #[test]
    fn shared_closer_source_continuations_share_scalar_and_batch_scheduling() {
        with_resources(|resources| {
            let mut provider = SourceProvider::new();
            assert!(matches!(
                prepare_forward(
                    resources,
                    &mut provider,
                    &member_endpoint(),
                    SemanticId::for_test("source-target")
                )
                .unwrap(),
                EndpointPreparation::Ready(ResolutionCompletion::Complete)
            ));
            assert_eq!(
                (provider.polls, provider.initial_reads, provider.cancelled),
                (3, 1, 0)
            );
            assert!(provider.published && provider.outstanding.is_none());
        });
        with_resources(|resources| {
            let mut provider = SourceProvider::new();
            let mut scheduler = new_scheduler();
            let endpoint = member_endpoint();
            let discovery = provider.discover(&endpoint).unwrap();
            let RelationAdmission::Ready(id) =
                scheduler.install_relation(resources, endpoint, discovery)
            else {
                panic!("admitted source root");
            };
            let SchedulerOutcome::Ready(scheduler) = drive_scheduler(
                resources,
                scheduler,
                &mut provider,
                Vec::new(),
                |scheduler| scheduler.relations[id].closed,
            )
            .unwrap() else {
                panic!("source root finishes through member waits");
            };
            assert!(scheduler.relations[id].prefix_charged);
            assert!(scheduler.relations[id].close_continuation.is_none());
            assert!(scheduler.relations[id].waits_on.is_empty());
            assert_eq!(
                (provider.polls, provider.initial_reads, provider.cancelled),
                (3, 1, 0)
            );
            assert!(provider.published && provider.outstanding.is_none());
        });
    }
    #[test]
    fn shared_closer_source_continuation_error_invalidates_outstanding_state() {
        with_resources(|resources| {
            let mut provider = SourceProvider::new();
            provider.error_at = Some(2);
            assert!(
                prepare_forward(
                    resources,
                    &mut provider,
                    &member_endpoint(),
                    SemanticId::for_test("source-target")
                )
                .is_err()
            );
            assert!(!provider.published);
            assert!(provider.outstanding.is_none());
            assert_eq!(provider.cancelled, 1);
        });
    }

    #[test]
    fn shared_closer_source_continuation_cycle_removes_waiters_and_token() {
        with_resources(|resources| {
            let mut provider = SourceProvider::new();
            let endpoint = member_endpoint();
            let view = HierarchyProvenanceView::new(resources.hierarchy);
            let CloseProgress::Members {
                continuation,
                request,
                ..
            } = provider
                .poll_close(
                    &endpoint,
                    &[],
                    None,
                    &ResolutionCompletion::Complete,
                    view,
                    CloseResume::Start,
                )
                .unwrap()
            else {
                panic!("source yields");
            };
            let mut scheduler = new_scheduler();
            let discovery = provider.discover(&endpoint).unwrap();
            let RelationAdmission::Ready(id) =
                scheduler.install_relation(resources, endpoint.clone(), discovery)
            else {
                panic!("admitted");
            };
            scheduler.relations[id].member_selection = Some(Box::new(
                MemberSelectionFrame::new(resources, request).unwrap(),
            ));
            scheduler.relations[id].close_continuation = Some(continuation);
            scheduler.relations[id].member_requested = true;
            scheduler.relations[id].waits_on.push(id);
            scheduler.relations[id].relation_waiters.push(id);
            scheduler.relations[id].pending = 1;
            scheduler.close_waiters.insert(endpoint);
            scheduler.runnable.clear();
            let SchedulerOutcome::Incomplete(
                scheduler,
                BatchOutcome::Unsupported(Unsupported::CyclicPrefixDependency { .. }),
            ) = drive_scheduler(resources, scheduler, &mut provider, Vec::new(), |_| false)
                .unwrap()
            else {
                panic!("a source member dependency cycle stays incomplete");
            };
            assert!(scheduler.relations[id].waits_on.is_empty());
            assert!(scheduler.relations[id].relation_waiters.is_empty());
            assert!(scheduler.relations[id].member_selection.is_none());
            assert!(scheduler.relations[id].close_continuation.is_none());
            assert!(provider.outstanding.is_none() && !provider.published);
            assert_eq!(provider.cancelled, 1);
        });
    }
    #[test]
    fn shared_closer_source_continuation_cancel_keeps_both_ledgers() {
        with_resources(|resources| {
            let mut provider = SourceProvider::new();
            let endpoint = member_endpoint();
            let view = HierarchyProvenanceView::new(resources.hierarchy);
            let CloseProgress::Members {
                continuation,
                request,
                ..
            } = provider
                .poll_close(
                    &endpoint,
                    &[],
                    None,
                    &ResolutionCompletion::Complete,
                    view,
                    CloseResume::Start,
                )
                .unwrap()
            else {
                panic!("source yields");
            };
            let mut scheduler = new_scheduler();
            let discovery = provider.discover(&endpoint).unwrap();
            let RelationAdmission::Ready(id) =
                scheduler.install_relation(resources, endpoint.clone(), discovery)
            else {
                panic!("admitted");
            };
            let source_gap = ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::for_test(
                "source-read-gap",
            ));
            let member_gap = ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::for_test(
                "hierarchy-read-gap",
            ));
            let mut frame = MemberSelectionFrame::new(resources, request).unwrap();
            frame.completion = ResolutionCompletion::incomplete([member_gap]);
            scheduler.evidence.include(
                &ResolutionCompletion::incomplete([source_gap]),
                resources.session.cancellation,
                &mut scheduler.work,
            );
            scheduler.relations[id].member_selection = Some(Box::new(frame));
            scheduler.relations[id].close_continuation = Some(continuation);
            scheduler.relations[id].member_requested = true;
            scheduler.close_waiters.insert(endpoint);
            resources.session.cancellation.cancel();
            let SchedulerOutcome::Terminal(BatchOutcome::Cancelled(completion)) =
                drive_scheduler(resources, scheduler, &mut provider, Vec::new(), |_| false)
                    .unwrap()
            else {
                panic!("source continuation cancellation is terminal");
            };
            assert!(completion.contains_reason(source_gap));
            assert!(completion.contains_reason(member_gap));
            assert!(completion.contains_reason(ResolutionIncompleteReason::Cancelled));
            assert!(provider.outstanding.is_none() && !provider.published);
            assert_eq!(provider.cancelled, 1);
        });
    }
    #[test]
    fn shared_closer_source_cancellation_before_member_frame_cleans_up() {
        with_resources(|resources| {
            let mut provider = SourceProvider::new();
            provider.cancel_on_yield = Some(resources.session.cancellation.clone());
            provider
                .values
                .push(ResolutionSlotValue::type_object(ResolutionTypeRef::new(
                    SemanticId::for_test("cancel-owner"),
                    0,
                )));
            let outcome = prepare_forward(
                resources,
                &mut provider,
                &member_endpoint(),
                SemanticId::for_test("cancel-target"),
            )
            .unwrap();
            assert!(matches!(outcome, EndpointPreparation::Incomplete(_)));
            assert!(provider.outstanding.is_none() && !provider.published);
            assert_eq!(provider.cancelled, 1);
        });
        with_resources(|resources| {
            let mut provider = SourceProvider::new();
            provider.cancel_on_yield = Some(resources.session.cancellation.clone());
            provider
                .values
                .push(ResolutionSlotValue::type_object(ResolutionTypeRef::new(
                    SemanticId::for_test("cancel-owner"),
                    0,
                )));
            let endpoint = member_endpoint();
            let mut scheduler = new_scheduler();
            let discovery = provider.discover(&endpoint).unwrap();
            let RelationAdmission::Ready(_) =
                scheduler.install_relation(resources, endpoint, discovery)
            else {
                panic!("admitted source");
            };
            assert!(matches!(
                drive_scheduler(resources, scheduler, &mut provider, Vec::new(), |_| false)
                    .unwrap(),
                SchedulerOutcome::Terminal(BatchOutcome::Cancelled(_))
            ));
            assert!(provider.outstanding.is_none() && !provider.published);
            assert_eq!(provider.cancelled, 1);
        });
    }
    #[derive(Debug)]
    struct RepairOrder;
    impl HierarchyLinearizationPolicy for RepairOrder {
        fn identity(&self) -> HierarchyOrderPolicyId {
            HierarchyOrderPolicyId(5658)
        }
        fn next(
            &self,
            frontier: &HierarchyOrderFrontier<'_>,
            _: &mut HierarchyOrderBudget<'_>,
        ) -> StoreResult<HierarchyOrderDecision> {
            let first = &frontier.heads[0];
            Ok(HierarchyOrderDecision::Emit {
                owner: first.owner,
                advance: frontier
                    .heads
                    .iter()
                    .filter(|head| head.owner == first.owner)
                    .map(|head| head.sequence)
                    .collect(),
                provenance: first.provenance,
            })
        }
    }
    static REPAIR_ORDER: RepairOrder = RepairOrder;

    struct OrderFixtureResult {
        owners: Vec<SemanticId>,
        completion: ResolutionCompletion,
        work: brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisWork,
        complete: Option<bool>,
        ordered: Vec<SemanticId>,
        order_work: usize,
    }
    fn order_fixture(enabled: bool, cap: usize, bases: bool, cancel: bool) -> OrderFixtureResult {
        let session = ResolutionSession::bounded(
            ReceiverAnalysisBudget {
                max_scope_nodes: 1,
                max_hierarchy_order_steps: cap,
                ..ReceiverAnalysisBudget::default()
            },
            None,
        );
        assert!(session.scope_step()); // The aggregate consumes its entire finite allowance.
        let mut result = None;
        with_resources_in_session(Some(&session), |resources| {
            let root = SemanticId::for_test("repair-order-root");
            let base = SemanticId::for_test("repair-order-base");
            let mut frame = MemberSelectionFrame::new(
                resources,
                MemberSelectionRequest {
                    policy: &crate::analyzer::resolution::DEFAULT_HIERARCHY_POLICY,
                    order: enabled.then_some(HierarchyOrderRequest {
                        policy: &REPAIR_ORDER,
                        start_after: None,
                    }),
                    reference: root,
                    values: Vec::new(),
                    lookup: root,
                    namespace: ResolutionNamespace::Type,
                    language: Language::Scala,
                },
            )
            .unwrap();
            // This fixture starts at the completed aggregate boundary, including
            // independent provider reasons, then enables optional discharge order.
            frame.owners.insert(root);
            frame.completion = ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(root),
                ResolutionIncompleteReason::UnsupportedSemantic(base),
            ]);
            let leaf = resources.hierarchy.order.owner(
                base,
                Vec::new(),
                HierarchyProvenanceId::default(),
                false,
            );
            let expression = resources.hierarchy.order.owner(
                root,
                if bases {
                    vec![HierarchyOrderedBase {
                        expression: leaf,
                        reference: base,
                        kind: None,
                        ordinal: 0,
                    }]
                } else {
                    Vec::new()
                },
                HierarchyProvenanceId::default(),
                false,
            );
            if let Some(order) = &mut frame.order {
                order.root(expression, root);
            }
            if cancel {
                resources.session.cancellation.cancel();
            }
            let outcome = frame
                .poll(resources, &mut |_| {
                    unreachable!("aggregate is already complete")
                })
                .unwrap();
            if cancel {
                assert!(matches!(outcome, MemberSelectionPoll::Cancelled));
                return;
            }
            let MemberSelectionPoll::Ready(selection) = outcome else {
                panic!("optional ordering must retain the aggregate");
            };
            let view = HierarchyProvenanceView::new(resources.hierarchy);
            let mut ordered = Vec::new();
            let complete = selection.order.map(|id| {
                assert!(
                    view.visit_order(id, &mut || false, &mut |owner| {
                        ordered.push(owner.owner);
                        Ok(())
                    })
                    .unwrap()
                );
                view.order_status(id).complete
            });
            let BoundedResolution::Complete { work, .. } = session.finish(()) else {
                panic!("ordering must not stop the aggregate budget");
            };
            result = Some(OrderFixtureResult {
                owners: selection.owners,
                completion: selection.completion,
                work,
                complete,
                ordered,
                order_work: resources.hierarchy.order_work,
            });
        });
        result.unwrap_or_else(|| OrderFixtureResult {
            owners: Vec::new(),
            completion: ResolutionCompletion::Complete,
            work: session.finish(()).work(),
            complete: None,
            ordered: Vec::new(),
            order_work: 0,
        })
    }
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#5658: optional ordering consumed aggregate scope and cancelled completed member selection"
    )]
    fn shared_closer_order_preserves_finite_aggregate_and_scope() {
        let plain = order_fixture(false, 100, true, false);
        let ordered = order_fixture(true, 100, true, false);
        assert_eq!(plain.owners, ordered.owners);
        assert_eq!(plain.completion, ordered.completion);
        assert_eq!(plain.work, ordered.work);
        assert_eq!(ordered.complete, Some(true));
        assert!(ordered.order_work > 0);
    }
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#5658: order exhaustion must discard provisional discharges and retain aggregate reasons"
    )]
    fn shared_closer_order_cap_discards_prefix_and_preserves_aggregate() {
        let plain = order_fixture(false, 0, true, false);
        for cap in 0..12 {
            let stopped = order_fixture(true, cap, true, false);
            assert_eq!(plain.owners, stopped.owners);
            assert_eq!(plain.completion, stopped.completion);
            assert_eq!(plain.work, stopped.work);
            assert!(stopped.order_work <= cap);
            if cap == 0 {
                assert_eq!(stopped.complete, Some(false));
            }
            if stopped.complete == Some(false) {
                assert!(stopped.ordered.is_empty());
            }
        }
    }
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#5658: no-base member ordering charged aggregate work before the policy could finish"
    )]
    fn shared_closer_order_no_bases_is_done_without_work() {
        let done = order_fixture(true, 0, false, false);
        assert_eq!(done.complete, Some(true));
        assert_eq!(done.order_work, 0);
        assert_eq!(
            done.ordered,
            vec![SemanticId::for_test("repair-order-root")]
        );
        assert_eq!(done.work.scope_nodes, 1);
    }
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#5658: real order cancellation must remain distinct from optional-order cap exhaustion"
    )]
    fn shared_closer_order_real_cancellation_is_cancelled() {
        order_fixture(true, 100, true, true);
    }
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#5658: unanswered access rows lost declarations and mixed downstream-cycle evidence"
    )]
    fn shared_reference_close_wait_reuses_terminal_task_and_preserves_cycles_and_admission_cancellation()
     {
        struct Provider<'a> {
            key: ReferenceKey,
            cancellation: &'a CancellationToken,
            cancel_at_admission: bool,
            resumes: usize,
            abandoned: bool,
            incomplete_reason: Option<ResolutionIncompleteReason>,
            additional_reason: Option<ResolutionIncompleteReason>,
        }
        impl RootProvider for Provider<'_> {
            fn discover(&mut self, _: &RelationKey) -> StoreResult<RootDiscovery> {
                unreachable!("test supplies root plan");
            }
            fn close(
                &mut self,
                _: &RelationKey,
                _: &[(ReferenceKey, &FactResolutionAnswer)],
            ) -> StoreResult<ResolutionCompletion> {
                unreachable!("poll protocol owns close");
            }
            fn cancel_close(&mut self, _: &RelationKey) {
                self.abandoned = true;
            }
            fn poll_close(
                &mut self,
                _: &RelationKey,
                _: &[(ReferenceKey, &FactResolutionAnswer)],
                _: Option<&MemberSelection>,
                _: &ResolutionCompletion,
                provenance: HierarchyProvenanceView<'_>,
                resume: CloseResume<'_>,
            ) -> StoreResult<CloseProgress<ResolutionCompletion>> {
                match resume {
                    CloseResume::Start => {
                        if self.cancel_at_admission {
                            self.cancellation.cancel();
                        }
                        Ok(CloseProgress::Reference {
                            continuation: CloseContinuationId::issue(provenance),
                            key: self.key,
                            completion: ResolutionCompletion::Complete,
                        })
                    }
                    CloseResume::Reference {
                        continuation,
                        key,
                        answer,
                    } => {
                        continuation.assert_current(provenance);
                        assert_eq!(key, self.key);
                        if let Some(reason) = self.incomplete_reason {
                            assert!(answer.binding().targets().is_empty());
                            assert_ne!(answer.completion(), &ResolutionCompletion::Complete);
                            assert!(answer.completion().contains_reason(reason));
                            if let Some(additional) = self.additional_reason {
                                assert!(answer.completion().contains_reason(additional));
                            }
                        } else {
                            assert_eq!(
                                answer.binding().targets(),
                                &[SemanticId::for_test("selected-reference-target")]
                            );
                        }
                        self.resumes += 1;
                        Ok(CloseProgress::Ready(answer.completion().clone()))
                    }
                    CloseResume::Members { .. } => {
                        panic!("reference wait never consumes a member selection")
                    }
                }
            }
        }
        for mode in 0..5 {
            with_resources(|resources| {
                let key =
                    ReferenceKey::caller(SemanticId::for_test("selected-reference-prerequisite"));
                let endpoint = RelationKey::caller(EndpointSignature::new(
                    BindingNodeId::universal_root(),
                    StackPattern::closed([SemanticId::for_test("reference-close-lookup")]),
                    StackPattern::closed(Vec::<BindingNodeId>::new()),
                ));
                let mut scheduler = new_scheduler();
                let RelationAdmission::Ready(relation) = scheduler.install_relation(
                    resources,
                    endpoint.clone(),
                    RootDiscovery::Ready(RootPlan {
                        prefixes: vec![],
                        completion: ResolutionCompletion::Complete,
                    }),
                ) else {
                    panic!("root admitted");
                };
                let task = scheduler.admit(resources, key, None).unwrap();
                if mode == 0 {
                    let mut answer = empty_fact_resolution_answer(
                        ResolutionCompletion::Complete,
                        resources.session.cancellation,
                    );
                    answer.binding = ResolutionAnswer::new(
                        vec![SemanticId::for_test("selected-reference-target")],
                        Vec::new(),
                        ResolutionCompletion::Complete,
                    );
                    scheduler.tasks[task].frame = None;
                    scheduler.tasks[task].answer = Some(answer);
                } else if mode == 1 {
                    scheduler.tasks[task].waiting = 1;
                    scheduler.tasks[task].waits_on.push(relation);
                    scheduler.relations[relation].waiters.push(task);
                }
                let missing = SemanticId::for_test("missing-nested-access-source");
                if mode == 3 || mode == 4 {
                    let nested =
                        ReferenceKey::caller(SemanticId::for_test("nested-access-reference"));
                    let nested_task = scheduler.admit(resources, nested, None).unwrap();
                    let nested_endpoint = RelationKey::caller(EndpointSignature::new(
                        BindingNodeId::universal_root(),
                        StackPattern::closed([nested.reference]),
                        StackPattern::closed(Vec::<BindingNodeId>::new()),
                    ));
                    let RelationAdmission::Ready(nested_relation) = scheduler.install_relation(
                        resources,
                        nested_endpoint,
                        RootDiscovery::Ready(RootPlan {
                            prefixes: vec![nested],
                            completion: ResolutionCompletion::Complete,
                        }),
                    ) else {
                        panic!("nested relation admitted")
                    };
                    if mode == 3 {
                        let missing_endpoint = RelationKey::caller(EndpointSignature::new(
                            BindingNodeId::universal_root(),
                            StackPattern::closed([missing]),
                            StackPattern::closed(Vec::<BindingNodeId>::new()),
                        ));
                        let RelationAdmission::Ready(missing_relation) = scheduler
                            .install_relation(
                                resources,
                                missing_endpoint,
                                RootDiscovery::Unavailable {
                                    reason: RootUnavailableReason::MissingSourceProvenance,
                                    completion: ResolutionCompletion::incomplete([
                                        ResolutionIncompleteReason::UnsupportedSemantic(missing),
                                    ]),
                                },
                            )
                        else {
                            panic!("unavailable relation stays in graph")
                        };
                        scheduler.tasks[nested_task].waiting = 1;
                        scheduler.tasks[nested_task].waits_on.push(missing_relation);
                        scheduler.relations[missing_relation]
                            .waiters
                            .push(nested_task);
                    } else {
                        // This cycle is downstream of the access consumer and
                        // already has a real incomplete member observation.
                        scheduler.relations[nested_relation].member_completion =
                            ResolutionCompletion::incomplete([
                                ResolutionIncompleteReason::UnsupportedSemantic(missing),
                            ]);
                        scheduler.tasks[nested_task].waiting = 1;
                        scheduler.tasks[nested_task].waits_on.push(nested_relation);
                        scheduler.relations[nested_relation]
                            .waiters
                            .push(nested_task);
                    }
                    scheduler.tasks[task].waiting = 1;
                    scheduler.tasks[task].waits_on.push(nested_relation);
                    scheduler.relations[nested_relation].waiters.push(task);
                }
                scheduler.runnable.clear();
                scheduler.runnable.push_back(Runnable::Relation(relation));
                let mut provider = Provider {
                    key,
                    cancellation: resources.session.cancellation,
                    cancel_at_admission: mode == 2,
                    resumes: 0,
                    abandoned: false,
                    incomplete_reason: match mode {
                        1 | 4 => Some(ResolutionIncompleteReason::CyclicPrefixDependency(
                            key.reference,
                        )),
                        3 => Some(ResolutionIncompleteReason::UnsupportedSemantic(missing)),
                        _ => None,
                    },
                    additional_reason: (mode == 4)
                        .then_some(ResolutionIncompleteReason::UnsupportedSemantic(missing)),
                };
                let outcome =
                    drive_scheduler(resources, scheduler, &mut provider, Vec::new(), |s| {
                        s.relations[relation].closed
                    })
                    .unwrap();
                match (mode, outcome) {
                    (0, SchedulerOutcome::Ready(s)) => {
                        assert_eq!(s.task_ids.len(), 1);
                        assert_eq!(provider.resumes, 1);
                        assert!(!provider.abandoned);
                    }
                    (1 | 3 | 4, SchedulerOutcome::Ready(s)) => {
                        assert!(
                            s.tasks[task].answer.is_none(),
                            "terminal access replies never publish a dependency answer"
                        );
                        assert!(s.relations[relation].close_reference.is_none());
                        assert!(s.relations[relation].close_continuation.is_none());
                        assert!(
                            s.access_reference_answers.is_empty(),
                            "reply consumed exactly once"
                        );
                        assert!(!provider.abandoned);
                        assert_eq!(provider.resumes, 1);
                    }
                    (2, SchedulerOutcome::Terminal(BatchOutcome::Cancelled(_))) => {
                        assert!(provider.abandoned);
                        assert_eq!(provider.resumes, 0);
                    }
                    _ => panic!(
                        "expected terminal memo, cyclic incompleteness or admission cancellation"
                    ),
                }
            });
        }
    }
    #[test]
    fn qualified_preparation_shares_reference_member_waits_memo_cycles_and_cancellation() {
        use crate::analyzer::store::resolution_operation::demand_closure::Read;
        use crate::analyzer::store::resolution_operation::member_access::MemberAccessResult;
        struct Provider<'a> {
            key: ReferenceKey,
            cancel_at_yield: bool,
            cancellation: &'a CancellationToken,
            context_reads: usize,
            preparations: usize,
            accesses: usize,
            abandoned: bool,
        }
        impl RootProvider for Provider<'_> {
            fn qualified_members(&mut self) -> Option<&mut dyn QualifiedMemberProvider> {
                Some(self)
            }
            fn discover(&mut self, _: &RelationKey) -> StoreResult<RootDiscovery> {
                panic!("fixture has no lexical endpoint prerequisites")
            }
            fn close(
                &mut self,
                _: &RelationKey,
                _: &[(ReferenceKey, &FactResolutionAnswer)],
            ) -> StoreResult<ResolutionCompletion> {
                panic!("typed group is not a ROOT close")
            }
        }
        impl QualifiedMemberProvider for Provider<'_> {
            fn prepare_qualified_member(
                &mut self,
                id: QualifiedMemberId,
                input: &QualifiedMemberInput,
                view: HierarchyProvenanceView<'_>,
                resume: CloseResume<'_>,
            ) -> StoreResult<CloseProgress<MemberSelectionOutcome>> {
                id.assert_current(view);
                self.preparations += 1;
                let continuation = CloseContinuationId::issue(view);
                match resume {
                    CloseResume::Start => {
                        self.context_reads += 1;
                        if self.cancel_at_yield {
                            self.cancellation.cancel();
                        }
                        Ok(CloseProgress::Reference {
                            continuation,
                            key: self.key,
                            completion: input.completion.clone(),
                        })
                    }
                    CloseResume::Reference { key, answer, .. } => {
                        assert_eq!(key, self.key);
                        assert_eq!(
                            answer.binding().targets(),
                            &[SemanticId::for_test("qualified-prerequisite-target")]
                        );
                        Ok(CloseProgress::Members {
                            continuation,
                            request: MemberSelectionRequest {
                                policy: &DEFAULT_HIERARCHY_POLICY,
                                order: None,
                                reference: input.reference.reference,
                                values: Vec::new(),
                                lookup: input.lookup,
                                namespace: input.namespace,
                                language: input.registration.language,
                            },
                            completion: ResolutionCompletion::Complete,
                        })
                    }
                    CloseResume::Members { selection, .. } => {
                        assert!(selection.owners.is_empty());
                        Ok(CloseProgress::Ready(MemberSelectionOutcome::Ready {
                            request: Some(MemberSelectionRequest {
                                policy: &DEFAULT_HIERARCHY_POLICY,
                                order: None,
                                reference: input.reference.reference,
                                values: Vec::new(),
                                lookup: input.lookup,
                                namespace: input.namespace,
                                language: input.registration.language,
                            }),
                            completion: ResolutionCompletion::Complete,
                        }))
                    }
                }
            }
            fn poll_qualified_member(
                &mut self,
                _: QualifiedMemberId,
                selection: &MemberSelection,
                view: HierarchyProvenanceView<'_>,
                resume: CloseResume<'_>,
            ) -> StoreResult<CloseProgress<Read<MemberAccessResult>>> {
                assert!(selection.owners.is_empty());
                self.accesses += 1;
                match resume {
                    CloseResume::Start => Ok(CloseProgress::Reference {
                        continuation: CloseContinuationId::issue(view),
                        key: self.key,
                        completion: ResolutionCompletion::Complete,
                    }),
                    CloseResume::Reference { key, answer, .. } => {
                        assert_eq!(key, self.key);
                        assert_eq!(
                            answer.binding().targets(),
                            &[SemanticId::for_test("qualified-prerequisite-target")]
                        );
                        Ok(CloseProgress::Ready(Read::Unavailable {
                            reason: RootUnavailableReason::IncompletePreparation,
                            completion: incomplete(SemanticId::for_test("access-gap")),
                        }))
                    }
                    CloseResume::Members { .. } => {
                        panic!("access requests only the memoized reference")
                    }
                }
            }
            fn cancel_qualified_member(&mut self, _: QualifiedMemberId) {
                self.abandoned = true;
            }
        }
        // This is a scheduler-protocol fixture, not expression-type evidence:
        // no receiver values are injected and no Python result is asserted.
        for mode in 0..3 {
            with_resources(|resources| {
                let root = ReferenceKey::caller(SemanticId::for_test("held-qualified-reference"));
                let mut scheduler = new_scheduler();
                let task = scheduler.admit(resources, root, None).unwrap();
                let key = if mode == 1 {
                    root
                } else {
                    ReferenceKey::caller(SemanticId::for_test("qualified-reference-prerequisite"))
                };
                if mode == 0 {
                    let dependency = scheduler.admit(resources, key, None).unwrap();
                    let mut answer = empty_fact_resolution_answer(
                        ResolutionCompletion::Complete,
                        resources.session.cancellation,
                    );
                    answer.binding = ResolutionAnswer::new(
                        [SemanticId::for_test("qualified-prerequisite-target")],
                        [],
                        ResolutionCompletion::Complete,
                    );
                    scheduler.tasks[dependency].frame = None;
                    scheduler.tasks[dependency].answer = Some(answer);
                }
                let frame = scheduler.tasks[task].frame.as_mut().unwrap();
                frame.phase = DemandFactEvaluationPhase::References;
                frame.references = Some(DemandReferenceEvaluationFrame {
                    references: vec![root.reference],
                    cursor: 0,
                    routes: HashMap::default(),
                    calls: HashMap::default(),
                    answers: HashMap::default(),
                    literal_keys: Default::default(),
                    expression_reference: None,
                    active: None,
                    qualified: None,
                    registered_qualified: Some(Box::new(RegisteredQualifiedFrame {
                        pending: VecDeque::new(),
                        active: Some(ActiveRegisteredQualifiedGroup::Members { precedence: 0 }),
                        answers: Vec::new(),
                        pending_dependency: false,
                    })),
                    scheduler_members: true,
                    root_metadata: None,
                    lexical_hierarchy: None,
                    implicit: None,
                    implicit_answer: None,
                    applied_members: None,
                    applied_hierarchy: None,
                });
                let id =
                    QualifiedMemberId::issue(HierarchyProvenanceView::new(resources.hierarchy));
                let input = QualifiedMemberInput {
                    reference: root,
                    route_ordinal: 0,
                    precedence: 0,
                    fragment: BindingFragmentId::for_test("qualified-fixture-fragment"),
                    source_lookup: SemanticId::for_test("qualified-lookup"),
                    lookup: SemanticId::for_test("qualified-lookup"),
                    namespace: ResolutionNamespace::Value,
                    values: Vec::new(),
                    completion: incomplete(SemanticId::for_test("retained-receiver-obligation")),
                    registration: QualifiedMemberRegistration {
                        language: Language::Rust,
                        hierarchy_identity: 0,
                        member_access: true,
                    },
                };
                scheduler.qualified_members.insert(
                    task,
                    QualifiedMemberWait {
                        id,
                        completion: input.completion.clone(),
                        input: TypedPrerequisiteInput::Member(input),
                        member_selection: None,
                        selection: None,
                        continuation_members: None,
                        close_continuation: None,
                        close_reference: None,
                        phase: QualifiedMemberPhase::Preparing,
                    },
                );
                scheduler.runnable.clear();
                scheduler.runnable.push_back(Runnable::Task(task));
                // Register the already-parked provider slot before the driver owns it.
                let mut active = HashSet::from_iter([id]);
                let mut provider = Provider {
                    key,
                    cancel_at_yield: mode == 2,
                    cancellation: resources.session.cancellation,
                    context_reads: 0,
                    preparations: 0,
                    accesses: 0,
                    abandoned: false,
                };
                let outcome = drive_scheduler_inner(
                    resources,
                    scheduler,
                    &mut provider,
                    Vec::new(),
                    |scheduler| scheduler.qualified_members.is_empty(),
                    &mut HashSet::default(),
                    &mut active,
                )
                .unwrap();
                match (mode, outcome) {
                    (0, SchedulerOutcome::Ready(scheduler)) => {
                        assert_eq!(
                            (
                                provider.context_reads,
                                provider.preparations,
                                provider.accesses
                            ),
                            (1, 3, 2)
                        );
                        assert_eq!(
                            scheduler.task_ids.len(),
                            2,
                            "both phases reuse the terminal reference task"
                        );
                        assert!(scheduler.tasks[task].hierarchy_waits.is_empty());
                        let group = scheduler.tasks[task]
                            .frame
                            .as_ref()
                            .unwrap()
                            .references
                            .as_ref()
                            .unwrap()
                            .registered_qualified
                            .as_ref()
                            .unwrap();
                        assert_eq!(group.answers.len(), 1);
                        assert!(group.answers[0].1.completion().contains_reason(
                            ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::for_test(
                                "retained-receiver-obligation"
                            ))
                        ));
                        assert!(active.is_empty());
                        assert!(provider.abandoned);
                    }
                    (
                        1,
                        SchedulerOutcome::Incomplete(
                            scheduler,
                            BatchOutcome::Unsupported(Unsupported::CyclicPrefixDependency {
                                completion,
                                ..
                            }),
                        ),
                    ) => {
                        assert_eq!(provider.context_reads, 1);
                        assert_eq!(provider.accesses, 0);
                        assert!(demanded_reference_wait_closes_a_cycle(
                            &scheduler, task, task
                        ));
                        assert!(completion.contains_reason(
                            ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::for_test(
                                "retained-receiver-obligation"
                            ))
                        ));
                    }
                    (2, SchedulerOutcome::Terminal(BatchOutcome::Cancelled(_))) => {
                        assert_eq!(provider.context_reads, 1);
                        assert_eq!(provider.accesses, 0);
                    }
                    _ => panic!("expected memo reuse, cycle, or admission cancellation"),
                }
                for id in active {
                    provider.cancel_qualified_member(id);
                }
            });
        }
    }
}
