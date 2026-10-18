//! Operation-owned demand execution shared by forward and reverse consumers.
//!
//! Discovery and materialization run only between evaluator polls. An exact
//! endpoint becomes readable once, after all of its positioned prefix tasks
//! finish. Cyclic selected-root dependencies remain incomplete.

use super::completed_roots::RootMemoKey;
use super::*;

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
pub(crate) struct MemberSelectionRequest {
    pub(crate) reference: SemanticId,
    pub(crate) values: Vec<ResolutionSlotValue>,
    pub(crate) lookup: SemanticId,
    pub(crate) namespace: ResolutionNamespace,
    pub(crate) language: Language,
}

#[derive(Debug)]
pub(crate) struct MemberSelection {
    pub(crate) owners: Vec<SemanticId>,
    pub(crate) completion: ResolutionCompletion,
}

struct MemberSelectionFrame<'source> {
    evaluation: Option<FactEvaluationState<'source>>,
    groups: BTreeMap<HierarchyLookupShape, Vec<HierarchyRoot>>,
    active: Option<DemandHierarchyOwnerFrame>,
    owners: BTreeSet<SemanticId>,
    completion: ResolutionCompletion,
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
        let namespace = if request.namespace == ResolutionNamespace::Callable
            && super::super::fact_source::language_callables_occupy_value_namespace(
                request.language,
            ) {
            ResolutionNamespace::Value
        } else {
            request.namespace
        };
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
                owner: value.ty().identity(),
                value,
                route_ordinal: 0,
            });
        }
        Some(Self {
            evaluation: Some(evaluation.into_checkpoint_state()),
            groups,
            active: None,
            owners: BTreeSet::new(),
            completion: ResolutionCompletion::Complete,
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
        Ok(MemberSelectionPoll::Ready(MemberSelection {
            owners: std::mem::take(&mut self.owners).into_iter().collect(),
            completion: std::mem::replace(&mut self.completion, ResolutionCompletion::Complete),
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
}

#[derive(Debug)]
pub(crate) struct RootPlan {
    pub(crate) prefixes: Vec<SemanticId>,
    pub(crate) completion: ResolutionCompletion,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ClosureDischarges {
    pub(crate) reasons: BTreeSet<SemanticId>,
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
            operation_local_placeholders: true,
            selected_targets: None,
            authoritative_empty_result: false,
            prefix_reference: None,
            prefix_reasons: BTreeSet::new(),
            prefix_operation_local_placeholders: false,
        }
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
pub(crate) enum RootUnavailableReason {
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
    fn reverse_dependencies(
        &mut self,
        _endpoint: &EndpointSignature,
    ) -> StoreResult<Vec<EndpointSignature>> {
        Ok(Vec::new())
    }

    fn close_reverse(&mut self, _endpoint: &EndpointSignature) {}

    /// Discover the exhaustive plan for this full endpoint under the enclosing
    /// operation's fixed selection. No evaluator may run inside this call.
    fn discover(&mut self, endpoint: &EndpointSignature) -> StoreResult<RootDiscovery>;

    /// Whether this provider can prepare keyed root reads for all pending
    /// endpoints in a scheduler round. Providers that do not opt in retain the
    /// original interleaved discover-and-admit order.
    fn supports_batched_discoveries(&self) -> bool {
        false
    }

    /// Discover a set of independent pending endpoints. Providers with a
    /// keyed batch source can prepare the reads together; the default keeps
    /// existing providers scalar.
    fn discover_many(
        &mut self,
        endpoints: &[EndpointSignature],
    ) -> StoreResult<Vec<RootDiscovery>> {
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
        endpoint: &EndpointSignature,
        inputs: &[(SemanticId, &FactResolutionAnswer)],
    ) -> StoreResult<ResolutionCompletion>;

    /// Request structural member-owner selection after positioned receivers
    /// finish. The scheduler owns its hierarchy and source dependencies. This
    /// capability can serve imports or projection owners; no request preserves
    /// the provider's ordinary close behavior.
    fn member_selection(
        &mut self,
        _endpoint: &EndpointSignature,
        _inputs: &[(SemanticId, &FactResolutionAnswer)],
    ) -> StoreResult<Option<MemberSelectionRequest>> {
        Ok(None)
    }

    /// Install the relation after its requested member selection has completed.
    fn close_selected_members(
        &mut self,
        _endpoint: &EndpointSignature,
        _inputs: &[(SemanticId, &FactResolutionAnswer)],
        _selection: &MemberSelection,
    ) -> StoreResult<ResolutionCompletion> {
        unreachable!("a provider requesting member selection installs its result")
    }

    /// The placeholder reasons a closed relation proved dead for the lookup it
    /// continued. `Some` says the closure answered the boundary question its
    /// endpoint asked with its own positive witness: the requesting reference's
    /// selected route reasons and the listed placeholder reasons no longer
    /// describe an open branch. It can also allow operation-local placeholders
    /// to retire once that route binds selected targets. `None` says the closure
    /// decided nothing beyond its candidate paths.
    fn resolved_closure_discharges(
        &self,
        _endpoint: &EndpointSignature,
    ) -> Option<ClosureDischarges> {
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
    root: SemanticId,
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
    claims: Vec<SemanticId>,
    /// The demanded reference this task is waiting for another task to finish.
    claim_wait: Option<SemanticId>,
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
    endpoint: EndpointSignature,
    dependencies: Vec<usize>,
    pending: usize,
    waiters: Vec<usize>,
    closed: bool,
    member_selection: Option<Box<MemberSelectionFrame<'source>>>,
    selected_members: Option<MemberSelection>,
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

enum RelationAdmission {
    Ready(usize),
    Cancelled,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Runnable {
    Task(usize),
    Relation(usize),
}

/// Each task and relation is admitted once. Waiting does not poll a task or
/// repeat its already charged reads. The queue contains only runnable tasks;
/// relation discovery is synchronous and exhausted before it enters the arena.
struct Scheduler<'a> {
    tasks: Vec<Task<'a>>,
    task_ids: HashMap<SemanticId, usize>,
    runnable: VecDeque<Runnable>,
    relations: Vec<Relation<'a>>,
    relation_ids: HashMap<EndpointSignature, usize>,
    /// The demanded references this scheduler's live tasks are evaluating.
    /// Bounded by the tasks, and dropped with the scheduler.
    claims: HashMap<SemanticId, DemandedReferenceOwner>,
    /// Placeholder reasons each closed relation retired for the lookups it
    /// continued, handed to a waiting task before its next poll.
    closure_discharges: HashMap<EndpointSignature, ClosureDischarges>,
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
            if let Some(cycle) = &frame.cycle {
                cycle
                    .origin
                    .evaluation
                    .cancellation_reasons
                    .include_retained_evidence(&mut self.evidence, cancellation, &mut self.work);
                if cycle.origin.evaluation.cancellation_observed {
                    return SchedulerOutcome::Terminal(self.cancelled(operation));
                }
            }
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

    /// Finalize only input roots left blocked after all runnable work drained.
    /// Walk each task's recorded waits, so a failed endpoint contributes evidence
    /// only to its dependency component. This state lives for this batch only.
    fn finish_incomplete_roots(
        &mut self,
        operation: &mut Resources<'_, 'a>,
        root_task_count: usize,
    ) {
        self.retain_completed_roots(operation);
        let completions = self.tasks[..root_task_count]
            .iter()
            .enumerate()
            .map(|(id, task)| {
                if task.answer.is_some() {
                    return None;
                }
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
                            pending.push(task.root);
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
                        task.root,
                        &[(task.root, seed_completion)],
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
            if let Some(binding) = state.lexical_answers.get(&task.root) {
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
        root: SemanticId,
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
            root,
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
        endpoint: EndpointSignature,
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
        for relation in &mut self.relations {
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
    let mut seeds = match read_root_seeds(operation, roots, &mut scheduler)? {
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
        .map(|seed| (seed.reference(), Some(seed.clone())))
        .collect::<Vec<_>>();
    resolve_admitted_batch(operation, new_scheduler(), admitted, provider, metrics)
}

fn new_scheduler<'a>() -> Scheduler<'a> {
    Scheduler {
        tasks: Vec::new(),
        task_ids: HashMap::default(),
        runnable: VecDeque::new(),
        relations: Vec::new(),
        relation_ids: HashMap::default(),
        claims: HashMap::default(),
        closure_discharges: HashMap::default(),
        evidence: CancellationEvidenceLedger::default(),
        work: 0,
        completed_prefix: 0,
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
    admitted: Vec<(SemanticId, Option<ReferenceSeed>)>,
    provider: &mut (impl RootProvider + ?Sized),
    metrics: &mut ResolutionBatchMetrics,
) -> StoreResult<BatchOutcome> {
    let root_seed_completions = admitted
        .iter()
        .filter_map(|(root, seed)| {
            let seed = seed.as_ref()?;
            matches!(seed.completion(), ResolutionCompletion::Incomplete(_))
                .then(|| (*root, seed.completion().clone()))
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
            scheduler.finish_incomplete_roots(operation, root_task_count);
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
            match poll_round(operation, &mut scheduler, &round, provider, &is_complete)? {
                RoundOutcome::Continue => continue,
                RoundOutcome::Ready => return Ok(SchedulerOutcome::Ready(Box::new(scheduler))),
                RoundOutcome::Cancelled => {
                    return Ok(SchedulerOutcome::Terminal(scheduler.cancelled(operation)));
                }
            }
        }
        let Some(runnable) = scheduler.runnable.pop_front() else {
            if let Some((endpoint, reason)) = scheduler.relations.iter().find_map(|relation| {
                relation
                    .unavailable
                    .as_ref()
                    .map(|(reason, _)| (relation.endpoint.clone(), *reason))
            }) {
                return Ok(scheduler.unavailable(
                    operation,
                    endpoint,
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
                .map(|task| task.root)
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
                if let Some(frame) = &relation.member_selection {
                    completion = completion.combine(&frame.completion);
                }
            }
            let outcome = BatchOutcome::Unsupported(Unsupported::CyclicPrefixDependency {
                pending_roots,
                pending_endpoints: scheduler
                    .relations
                    .iter()
                    .filter(|relation| !relation.closed)
                    .map(|relation| relation.endpoint.clone())
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
        if scheduler.relations[id].member_selection.is_none()
            && scheduler.relations[id].selected_members.is_none()
        {
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
            if let Some(request) = provider.member_selection(&endpoint, &inputs)? {
                let Some(frame) = MemberSelectionFrame::new(operation, request) else {
                    return Ok(SchedulerOutcome::Terminal(scheduler.cancelled(operation)));
                };
                scheduler.relations[id].member_selection = Some(Box::new(frame));
            }
        }
        if let Some(mut frame) = scheduler.relations[id].member_selection.take() {
            let polled = frame.poll(operation, &mut |requests| {
                Ok(
                    if requests.iter().all(|request| {
                        scheduler
                            .relation_ids
                            .get(request.endpoint())
                            .is_some_and(|&id| scheduler.relations[id].closed)
                    }) {
                        DemandForwardReadiness::Ready
                    } else {
                        DemandForwardReadiness::AwaitingDependencies
                    },
                )
            })?;
            scheduler.relations[id].member_selection = Some(frame);
            match polled {
                MemberSelectionPoll::Continue => {
                    scheduler.runnable.push_back(Runnable::Relation(id));
                    continue;
                }
                MemberSelectionPoll::Cancelled => {
                    return Ok(SchedulerOutcome::Terminal(scheduler.cancelled(operation)));
                }
                MemberSelectionPoll::Ready(selection) => {
                    let frame = scheduler.relations[id]
                        .member_selection
                        .take()
                        .expect("completed member phase");
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
                    scheduler.relations[id].selected_members = Some(selection);
                }
                MemberSelectionPoll::AwaitingHierarchyReferences(references) => {
                    assert!(!references.is_empty());
                    for reference in references {
                        let Some(dependency) = scheduler.admit(operation, reference, None) else {
                            return Ok(SchedulerOutcome::Terminal(scheduler.cancelled(operation)));
                        };
                        if let Some(answer) = &scheduler.tasks[dependency].answer {
                            let mut evaluation = FactEvaluation::new(
                                operation.session,
                                operation.hierarchy,
                                reference,
                            );
                            if !evaluation
                                .publish_qualified_hierarchy_reference(reference, answer)?
                            {
                                return Ok(SchedulerOutcome::Terminal(
                                    scheduler.cancelled(operation),
                                ));
                            }
                        } else {
                            scheduler.tasks[dependency].hierarchy_answer_needed = true;
                            if !scheduler.relations[id].dependencies.contains(&dependency) {
                                scheduler.relations[id].dependencies.push(dependency);
                                scheduler.tasks[dependency].dependents.push(id);
                                scheduler.relations[id].pending += 1;
                            }
                        }
                    }
                    if scheduler.relations[id].pending == 0 {
                        scheduler.runnable.push_back(Runnable::Relation(id));
                    }
                    continue;
                }
                MemberSelectionPoll::AwaitingDependencies(endpoints) => {
                    let mut seen = HashSet::default();
                    for endpoint in endpoints {
                        if !operation.session.charge_scope_steps(1) {
                            return Ok(SchedulerOutcome::Terminal(scheduler.cancelled(operation)));
                        }
                        let dependency =
                            if let Some(&dependency) = scheduler.relation_ids.get(&endpoint) {
                                dependency
                            } else {
                                let discovery = provider.discover(&endpoint)?;
                                match scheduler.install_relation(operation, endpoint, discovery) {
                                    RelationAdmission::Ready(id) => id,
                                    RelationAdmission::Cancelled => {
                                        return Ok(SchedulerOutcome::Terminal(
                                            scheduler.cancelled(operation),
                                        ));
                                    }
                                }
                            };
                        if !scheduler.relations[dependency].closed && seen.insert(dependency) {
                            scheduler.relations[dependency].relation_waiters.push(id);
                            scheduler.relations[id].waits_on.push(dependency);
                            scheduler.relations[id].pending += 1;
                        }
                    }
                    if scheduler.relations[id].pending == 0 {
                        scheduler.runnable.push_back(Runnable::Relation(id));
                    }
                    continue;
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
        if !operation.session.charge_scope_steps(relation.prefix_count) {
            return Ok(SchedulerOutcome::Terminal(scheduler.cancelled(operation)));
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
        let completion = if let Some(selection) = &relation.selected_members {
            provider.close_selected_members(&endpoint, &inputs, selection)?
        } else {
            provider.close(&endpoint, &inputs)?
        };
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
        let mut granted = Vec::new();
        scheduler.tasks[id]
            .frame
            .as_mut()
            .expect("runnable task is live")
            .inject_closure_discharges(&scheduler.closure_discharges);
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
                                    .get(request.endpoint())
                                    .is_some_and(|&id| relations[id].closed)
                            }) {
                                DemandForwardReadiness::Ready
                            } else {
                                DemandForwardReadiness::AwaitingDependencies
                            },
                        )
                    },
                    &mut |reference| match claims.get(&reference) {
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
        // A claim lasts exactly as long as the lexical frame that took it.
        // One frame evaluates every reference it claimed and answers them all
        // when it finishes, so the poll either kept that frame or left it, and
        // leaving it is what the waiters were waiting for.
        let task = &mut scheduler.tasks[id];
        assert!(
            granted.is_empty() || task.claims.is_empty(),
            "a task claims references only when it opens a lexical frame"
        );
        task.claims.extend(granted);
        if !task.claims.is_empty()
            && !task
                .frame
                .as_ref()
                .is_some_and(DemandFactEvaluationTask::holds_demanded_reference_claims)
        {
            for reference in std::mem::take(&mut task.claims) {
                if !release_demanded_reference(operation, scheduler, reference) {
                    return Ok(RoundOutcome::Cancelled);
                }
            }
        }
        match polled? {
            DemandFactEvaluationPoll::Continue => scheduler.runnable.push_back(Runnable::Task(id)),
            DemandFactEvaluationPoll::Ready(answer) => {
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
                // Retire the terminal frame before any further cancellable
                // work. The cancellation drain must never cancel it twice.
                scheduler.tasks[id].frame = None;
                scheduler.tasks[id].answer = Some(*answer);
                if !cancelled
                    && (scheduler.tasks[id].hierarchy_answer_needed
                        || !scheduler.tasks[id].hierarchy_dependents.is_empty())
                {
                    let root = scheduler.tasks[id].root;
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
            DemandFactEvaluationPoll::AwaitingHierarchyReferences(references) => {
                assert!(!references.is_empty());
                assert_eq!(scheduler.tasks[id].waiting, 0);
                assert!(scheduler.tasks[id].hierarchy_waits.is_empty());
                for reference in references {
                    let Some(dependency) = scheduler.admit(operation, reference, None) else {
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
                    .map(|request| request.endpoint().clone())
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
    reference: SemanticId,
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
                    .get(request.endpoint())
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
    roots: &[SemanticId],
    scheduler: &mut Scheduler<'a>,
) -> StoreResult<Option<HashMap<SemanticId, ReferenceSeed>>> {
    let cancellation = operation.session.cancellation;
    let source = operation.session.lexical_source;
    let mut queries = Vec::with_capacity(roots.len());
    let mut queried = HashSet::default();
    for &root in roots {
        if queried.insert(root) {
            queries.push(ResolutionQuery::new(root));
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
                seeds.insert(reference, seed).is_none(),
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
    endpoint: &EndpointSignature,
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
        match resolve(resources, root, provider)? {
            Outcome::Ready(answer) => answers.push((root, answer)),
            Outcome::Unavailable { completion, .. } => {
                return Ok(EndpointPreparation::Incomplete(completion.combine(
                    &ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(root),
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
    let completion = if let Some(request) = provider.member_selection(endpoint, &inputs)? {
        return prepare_selected_member_relation(
            resources,
            provider,
            endpoint,
            answers,
            plan.completion,
            request,
        );
    } else {
        provider.close(endpoint, &inputs)?
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
fn prepare_selected_member_relation(
    resources: &mut Resources<'_, '_>,
    provider: &mut (impl RootProvider + ?Sized),
    endpoint: &EndpointSignature,
    answers: Vec<(SemanticId, FactResolutionAnswer)>,
    completion: ResolutionCompletion,
    request: MemberSelectionRequest,
) -> StoreResult<EndpointPreparation> {
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
    let relation = match scheduler.install_relation(resources, endpoint.clone(), discovery) {
        RelationAdmission::Ready(id) => id,
        RelationAdmission::Cancelled => {
            let BatchOutcome::Cancelled(completion) = scheduler.cancelled(resources) else {
                unreachable!("cancellation returns its ledger");
            };
            return Ok(EndpointPreparation::Incomplete(completion));
        }
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
    let Some(frame) = MemberSelectionFrame::new(resources, request) else {
        let BatchOutcome::Cancelled(completion) = scheduler.cancelled(resources) else {
            unreachable!("cancellation returns its ledger");
        };
        return Ok(EndpointPreparation::Incomplete(completion));
    };
    scheduler.relations[relation].member_selection = Some(Box::new(frame));
    scheduler.runnable.push_back(Runnable::Relation(relation));
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
    endpoint: &EndpointSignature,
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
