//! Ordered implicit receivers over source lexical paths and shared hierarchy selection.
//! Everything retained here belongs to one query and one typed evaluation round.
use super::super::LoweredQualifiedSeededRoute;
use super::super::fact_source::language_uses_enclosing_companion_members;
use super::call_applicability::{ImplicitReceiverLookup, ImplicitReceiverScopeKind};
use super::*;
use crate::analyzer::store::language_support::{
    SelectedReceiverInstantiation, SelectedReceiverSlotRead, SelectedReceiverStepRead,
    SelectedReceiverStepRequest, SelectedReceiverStepSource, SelectedTypeHeadSource,
};
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeKind;

#[derive(Debug, Clone, Copy)]
pub(super) struct ImplicitReceiverProof {
    pub(super) extension: Option<ResolutionTypeRef>,
    pub(super) dispatch: Option<ResolutionTypeRef>,
}

// Receiver levels are query-local views of the source-issued lexical chain.
// Scope ownership says which declaration a head belongs to; the lexical paths
// retain evaluation order and the exact branch that a successful level replaces.
struct ImplicitReceiverScope {
    owner: Option<LoweredMemberScopeProperty>,
    paths: Vec<(CandidatePathIdentity, PartialPath)>,
    prefixes: Vec<PartialPath>,
    outward: Option<(CandidatePathIdentity, PartialPath)>,
}

fn is_lexical_scope_continuation(path: &PartialPath) -> bool {
    path.completion() == &ResolutionCompletion::Complete
        && path.start().symbols() == path.end().symbols()
        && path.start().symbols().fixed().is_empty()
        && path.start().symbols().tail().is_some()
        && path.start().scopes().fixed().is_empty()
        && path.start().scopes().tail().is_none()
        && path.end().scopes().fixed().is_empty()
        && path.end().scopes().tail().is_none()
        && !path.precedence().is_empty()
        && path
            .precedence()
            .iter()
            .all(|step| step.tier == PrecedenceTier::LexicalBinding)
        && path.witness() == [WitnessStep::Node(path.end().node())]
}

// The source can issue several namespace roots for one reference. Keep each
// prefix and request its endpoint; a callable local may exist on only one.
struct ReceiverLexicalFrame {
    requests: Vec<BatchCandidateRequest>,
    prefixes: Vec<PartialPath>,
    scopes: Vec<ImplicitReceiverScope>,
    lookups: BTreeSet<SemanticId>,
    visited: HashSet<BindingNodeId>,
}

impl ReceiverLexicalFrame {
    fn new(seed: &ReferenceSeed) -> Self {
        Self {
            requests: vec![BatchCandidateRequest::new(
                0,
                closed_endpoint(seed.node(), []),
            )],
            prefixes: Vec::new(),
            scopes: Vec::new(),
            lookups: BTreeSet::new(),
            visited: HashSet::default(),
        }
    }

    fn poll(
        &mut self,
        evaluation: &mut FactEvaluation<'_, '_>,
        readiness: &mut impl FnMut(&[BatchCandidateRequest]) -> StoreResult<DemandForwardReadiness>,
    ) -> StoreResult<bool> {
        if readiness(&self.requests)? == DemandForwardReadiness::AwaitingDependencies {
            return Ok(false);
        }
        let mut paths = BTreeMap::new();
        for request in &self.requests {
            for (identity, path) in evaluation.lexical_paths_at(request.endpoint().clone())? {
                paths.insert(identity, path);
            }
        }
        if self.scopes.is_empty() && self.prefixes.is_empty() {
            for (_, path) in paths {
                let start = self.requests[0].endpoint().clone();
                let identity = PartialPath::new(
                    start.clone(),
                    start,
                    Vec::new(),
                    Vec::new(),
                    ResolutionCompletion::Complete,
                );
                let Some(Ok(path)) =
                    identity.concatenate_with_poll(&path, &mut || evaluation.poll_cancelled())
                else {
                    continue;
                };
                if let [symbol] = path.end().symbols().fixed()
                    && symbol.scopes().is_none()
                    && path.end().symbols().tail().is_none()
                    && path.end().scopes().fixed().is_empty()
                    && path.end().scopes().tail().is_none()
                {
                    self.lookups.insert(symbol.symbol());
                    self.prefixes.push(path);
                }
            }
        } else {
            let head = self.prefixes[0].end().node();
            assert!(self.visited.insert(head), "acyclic lexical scope chain");
            assert!(
                self.prefixes
                    .iter()
                    .all(|prefix| prefix.end().node() == head),
                "namespace roots share their lexical chain"
            );
            let mut outward = None;
            for (identity, path) in &paths {
                if is_lexical_scope_continuation(path) {
                    assert!(
                        outward.replace((*identity, path.clone())).is_none(),
                        "one outward lexical scope continuation"
                    );
                }
            }
            let mut next = Vec::new();
            if let Some((_, outward)) = &outward {
                for prefix in &self.prefixes {
                    if let Some(Ok(path)) =
                        prefix.concatenate_with_poll(outward, &mut || evaluation.poll_cancelled())
                    {
                        next.push(path);
                    }
                }
            }
            self.scopes.push(ImplicitReceiverScope {
                owner: None,
                prefixes: std::mem::replace(&mut self.prefixes, next),
                paths: paths.into_iter().collect(),
                outward,
            });
        }
        self.requests = self
            .prefixes
            .iter()
            .enumerate()
            .map(|(ordinal, prefix)| BatchCandidateRequest::new(ordinal, prefix.end().clone()))
            .collect();
        Ok(true)
    }

    fn finish(
        mut self,
        evaluation: &mut FactEvaluation<'_, '_>,
    ) -> StoreResult<(Vec<ImplicitReceiverScope>, BTreeSet<SemanticId>)> {
        let heads = self
            .scopes
            .iter()
            .map(|scope| scope.prefixes[0].end().node())
            .collect::<Vec<_>>();
        let mut owners = HashMap::default();
        for chunk in heads.chunks(MAX_SOURCE_ROWS_PER_BATCH) {
            if !evaluation.session.charge_scope_steps(chunk.len()) || evaluation.poll_cancelled() {
                evaluation.cancellation_observed = true;
                break;
            }
            for row in evaluation
                .session
                .lexical_source
                .scope_owners_for_heads(chunk, evaluation.cancellation)?
            {
                assert!(
                    chunk.contains(&row.scope_head()),
                    "requested lexical scope head"
                );
                assert!(
                    owners.insert(row.scope_head(), row).is_none(),
                    "unique scope head owner"
                );
            }
        }
        for scope in &mut self.scopes {
            scope.owner = owners.remove(&scope.prefixes[0].end().node());
        }
        Ok((self.scopes, self.lookups))
    }
}

pub(super) fn implicit_receiver_call(call: &LoweredCallApplicabilityObligation) -> bool {
    call.receiver_slot().is_none()
        && !call
            .eligible_rules()
            .contains(&ResolutionEngineRuleKind::DefaultConstruction)
        && call_applicability_adapter(call.language())
            .implicit_receiver_lookup()
            .is_some()
}

enum ReceiverLevelOrigin {
    Lexical {
        scope: usize,
    },
    Explicit {
        frontier: Vec<ExplicitReceiverContext>,
    },
}

impl ReceiverLevelOrigin {
    fn lexical_scope(&self) -> usize {
        let Self::Lexical { scope } = self else {
            unreachable!("lexical setup and bridges require a lexical level");
        };
        *scope
    }
}

#[derive(Clone)]
struct ExplicitReceiverContext {
    receiver_slot: SemanticId,
    value: ResolutionSlotValue,
    instantiation: SelectedReceiverInstantiation,
    completion: ResolutionCompletion,
}

// A fully evaluated level retains witnesses as well as its selected targets.
// Lexical inventories are populated eagerly; their answer arrives after bridge
// replay. Explicit inventories are populated by the qualified continuation.
struct ReceiverLevelResult {
    answer: ResolutionAnswer,
    matched_receivers: HashSet<ResolutionSlotValue>,
}

struct ReceiverLevel {
    origin: ReceiverLevelOrigin,
    ty: Option<ResolutionTypeRef>,
    completion: ResolutionCompletion,
    members: HashSet<SemanticId>,
    result: Option<ReceiverLevelResult>,
    additions: Vec<(CandidatePathIdentity, PartialPath)>,
    removals: Vec<CandidatePathIdentity>,
}

pub(super) struct DemandImplicitReceiverFrame {
    seed: ReferenceSeed,
    // Absent for a non-invoking value reference.
    call: Option<InternedFactRow<SelectedTypedRow<LoweredCallApplicabilityObligation>>>,
    raw: SharedAnswer,
    rule: ImplicitReceiverLookup,
    chain: Vec<ImplicitReceiverScope>,
    lexical: Option<ReceiverLexicalFrame>,
    selected: Option<HierarchySelection>,
    bridge_requests: Vec<BatchCandidateRequest>,
    shapes: Vec<HierarchyLookupShape>,
    levels: Vec<ReceiverLevel>,
    level: usize,
    shape: usize,
    group: Option<DemandHierarchyOwnerFrame>,
    overlay: Option<Box<SelectedContextOverlayFragmentSourceBlueprint>>,
    active: Option<DemandForwardBatchFrame>,
    allowed: Option<HashSet<SemanticId>>,
    lexical_removals: Vec<CandidatePathIdentity>,
    completion: ResolutionCompletion,
}

impl DemandImplicitReceiverFrame {
    pub(super) fn new(
        evaluation: &mut FactEvaluation<'_, '_>,
        reference: SemanticId,
        call: Option<InternedFactRow<SelectedTypedRow<LoweredCallApplicabilityObligation>>>,
        raw: SharedAnswer,
    ) -> StoreResult<Option<Self>> {
        if let Some(call) = call {
            let call = call.get(evaluation.session).row();
            assert_eq!(
                reference,
                call.callee_reference(),
                "one implicit lookup site"
            );
            if !implicit_receiver_call(call) {
                return Ok(None);
            }
        }
        if evaluation.forced_reference_gaps.contains_key(&reference) {
            return Ok(None);
        }
        let Some(seed) = evaluation
            .session
            .lexical_source
            .reference_seed(ResolutionQuery::new(reference), evaluation.cancellation)?
        else {
            return Ok(None);
        };
        let adapter = call_applicability_adapter(seed.language());
        let Some(rule) = adapter.implicit_receiver_lookup() else {
            return Ok(None);
        };
        if !seed.site_metadata().is_some_and(|metadata| {
            metadata.unqualified()
                && (call.is_some()
                    || (adapter.implicit_receiver_value_lookup()
                        && metadata.site_kind() == ResolutionSiteKind::ValueReference
                        && matches!(
                            metadata.namespace(),
                            ResolutionNamespace::Value | ResolutionNamespace::TypeOrValue
                        )))
        }) {
            return Ok(None);
        }
        let lexical = Some(ReceiverLexicalFrame::new(&seed));
        Ok(Some(Self {
            seed,
            call,
            raw,
            rule,
            lexical,
            chain: Vec::new(),
            shapes: Vec::new(),
            levels: Vec::new(),
            selected: None,
            bridge_requests: Vec::new(),
            level: 0,
            shape: 0,
            group: None,
            overlay: None,
            active: None,
            allowed: None,
            lexical_removals: Vec::new(),
            completion: ResolutionCompletion::Complete,
        }))
    }

    fn initialize_levels(
        &mut self,
        evaluation: &mut FactEvaluation<'_, '_>,
        previous_states: &StateMap,
    ) -> StoreResult<bool> {
        let (chain, lookups) = self.lexical.take().unwrap().finish(evaluation)?;
        let language = self.seed.language();
        let adapter = call_applicability_adapter(language);
        let mut levels = Vec::new();
        let mut seen = HashSet::default();
        for (scope, node) in chain.iter().enumerate() {
            let Some(owner) = &node.owner else { continue };
            let Some(kind) = adapter.implicit_receiver_scope_kind(owner.scope_kind()) else {
                continue;
            };
            if !seen.insert((owner.definition(), owner.scope_kind())) {
                continue;
            }
            let mut completion = ResolutionCompletion::Complete;
            let ty = match kind {
                ImplicitReceiverScopeKind::Dispatch => {
                    Some(ResolutionTypeRef::new(owner.definition(), 0))
                }
                ImplicitReceiverScopeKind::Extension => {
                    let read = evaluation
                        .session
                        .signatures_for_definitions(&[owner.definition()])?;
                    let Some(signatures) = evaluation.accept_session_read(read) else {
                        return Ok(false);
                    };
                    let slot = signatures.iter().find_map(|signature| {
                        signature.get(evaluation.session).row().extension_receiver()
                    });
                    let Some(slot) = slot else { continue };
                    evaluation.demand_slot(slot);
                    previous_states.get(&slot).and_then(|state| {
                        completion = completion.combine(state.completion());
                        exact_singleton_type_ref(state)
                    })
                }
            };
            let companions = if kind == ImplicitReceiverScopeKind::Dispatch
                && language_uses_enclosing_companion_members(language)
            {
                let Some(companions) = evaluation.enclosing_companion_types(owner.definition())?
                else {
                    return Ok(false);
                };
                companions
            } else {
                Vec::new()
            };
            // A companion contributes its own receiver to this lexical lookup.
            // It never borrows the enclosing instance's dispatch proof or label.
            let receivers = std::iter::once(ty).chain(
                companions
                    .into_iter()
                    .filter(|companion| seen.insert((*companion, ResolutionScopeKind::TypeBody)))
                    .map(|companion| Some(ResolutionTypeRef::new(companion, 0))),
            );
            for ty in receivers {
                levels.push(ReceiverLevel {
                    origin: ReceiverLevelOrigin::Lexical { scope },
                    ty,
                    completion: completion.clone(),
                    members: HashSet::default(),
                    result: None,
                    additions: Vec::new(),
                    removals: Vec::new(),
                });
            }
        }
        let mut shapes = Vec::new();
        for lookup in lookups {
            let Some(namespace) = evaluation
                .session
                .typed_source
                .lookup_namespace(lookup, evaluation.cancellation)?
            else {
                return Ok(false);
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
            shapes.push(if self.call.is_some() {
                shape.with_callable_overload_set()
            } else {
                shape
            });
        }
        self.chain = chain;
        self.levels = levels;
        self.shapes = shapes;
        Ok(true)
    }

    pub(super) fn pending_requests(&self) -> &[BatchCandidateRequest] {
        if let Some(lexical) = &self.lexical {
            return &lexical.requests;
        }
        if self.selected.is_some() {
            return &self.bridge_requests;
        }
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

    pub(super) fn active_forward_frame(&mut self) -> Option<&mut DemandForwardBatchFrame> {
        // Overlay reads must not consume artifacts keyed to the base source.
        self.group
            .as_mut()?
            .inherited
            .as_mut()?
            .active_forward_frame()
    }

    pub(super) fn cancel(self, evaluation: &mut FactEvaluation<'_, '_>) {
        evaluation.observe_resolution_answer_cancellation_evidence(&self.raw);
        for level in self.levels {
            evaluation.observe_cancellation_completion(&level.completion);
            for (_, path) in level.additions {
                evaluation.observe_cancellation_completion(path.completion());
            }
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

    pub(super) fn poll(
        &mut self,
        evaluation: &mut FactEvaluation<'_, '_>,
        previous_states: &StateMap,
        readiness: &mut impl FnMut(&[BatchCandidateRequest]) -> StoreResult<DemandForwardReadiness>,
    ) -> StoreResult<DemandQualifiedPoll> {
        use DemandQualifiedPoll::{
            AwaitingDependencies, AwaitingHierarchyReferences, Continue, Ready,
        };
        if let Some(lexical) = &mut self.lexical {
            if !lexical.poll(evaluation, readiness)? {
                return Ok(AwaitingDependencies);
            }
            if !lexical.requests.is_empty() {
                return Ok(Continue);
            }
            if !self.initialize_levels(evaluation, previous_states)? {
                return Ok(Ready(None));
            }
            if self.levels.is_empty() {
                return Ok(Ready(Some((*self.raw).clone())));
            }
            return Ok(Continue);
        }
        if self.selected.is_some() {
            if !self.bridge_requests.is_empty()
                && readiness(&self.bridge_requests)? == DemandForwardReadiness::AwaitingDependencies
            {
                return Ok(AwaitingDependencies);
            }
            let selection = self.selected.take().unwrap();
            self.retain_members(evaluation, selection)?;
            self.bridge_requests.clear();
            self.shape += 1;
            return Ok(Continue);
        }
        if let Some(group) = &mut self.group {
            let selected = match group.poll(evaluation, readiness)? {
                DemandHierarchySelectionPoll::Continue => return Ok(Continue),
                DemandHierarchySelectionPoll::AwaitingDependencies => {
                    return Ok(AwaitingDependencies);
                }
                DemandHierarchySelectionPoll::AwaitingHierarchyReferences(references) => {
                    return Ok(AwaitingHierarchyReferences(references));
                }
                DemandHierarchySelectionPoll::Ready(None) => return Ok(Ready(None)),
                DemandHierarchySelectionPoll::Ready(Some(selected)) => selected,
            };
            let HierarchySelectionState::Ready(selection) =
                evaluation.materialize_hierarchy_candidate_expressions(selected)?
            else {
                return Ok(Ready(None));
            };
            let shape = self.shapes[self.shape];
            let owner = self.chain[self.levels[self.level].origin.lexical_scope()]
                .owner
                .as_ref()
                .unwrap();
            let mut heads = BTreeSet::new();
            if owner.scope_kind() == ResolutionScopeKind::TypeBody {
                heads.insert(owner.scope_head());
            }
            for selected in &selection.owners {
                if owner.scope_kind() == ResolutionScopeKind::TypeBody
                    && selected.owner == owner.definition()
                {
                    continue;
                }
                let read = evaluation
                    .session
                    .member_scopes_for_definitions(&[selected.owner])?;
                let Some(scopes) = evaluation.accept_session_read(read) else {
                    return Ok(Ready(None));
                };
                for scope in scopes {
                    let scope = scope.get(evaluation.session).row();
                    if scope.external_coverage().is_some() {
                        // External inventories are selected by owner identity in
                        // the hierarchy; only source scopes need lexical demand.
                        assert!(evaluation.session.context_identities.as_ref().is_some_and(
                            |identities| {
                                identities
                                    .external_owner_identity(scope.definition())
                                    .is_some()
                            }
                        ));
                    } else {
                        heads.insert(scope.scope_head());
                    }
                }
            }
            self.bridge_requests = heads
                .into_iter()
                .enumerate()
                .map(|(ordinal, head)| {
                    BatchCandidateRequest::new(ordinal, closed_endpoint(head, [shape.lookup]))
                })
                .collect();
            self.selected = Some(selection);
            self.group = None;
            return Ok(Continue);
        }
        if self.level < self.levels.len() {
            if self.shape == self.shapes.len() {
                self.level += 1;
                self.shape = 0;
                return Ok(Continue);
            }
            let level = &self.levels[self.level];
            let Some(ty) = level.ty else {
                // The extension receiver's type is a fixed-point dependency.
                // No outer receiver can prove the reference while it remains open.
                self.level += 1;
                self.shape = 0;
                return Ok(Continue);
            };
            let shape = self.shapes[self.shape];
            // A non-invoking value cannot bind a callable-only inventory entry.
            // A closed inventory can prove absence here; unknown inventories
            // still go through the shared hierarchy and retain their evidence.
            if self.call.is_none()
                && let Some(super::super::universe::IntrinsicMemberInventory::Jvm(members)) =
                    evaluation.session.closed_member_inventory(ty.identity())?
                && let Some(digest) = evaluation
                    .session
                    .lexical_source
                    .shared_name_digest_for_identity(shape.lookup, evaluation.cancellation)?
                && !members.iter().any(|member| {
                    member.kind == brokk_bifrost_jvm::intrinsics::ClosedMemberKind::Value
                        && super::super::ResolutionLookupSemanticRecipe::new(
                            self.seed.language(),
                            shape.namespace,
                            member.name,
                        )
                        .name_digest()
                            == digest
                })
            {
                self.shape += 1;
                return Ok(Continue);
            }
            // A directly declared classifier shadows inherited names in its
            // dispatch body. The aggregate lexical answer can still carry open
            // imports, so use its complete witnesses and exact member ownership.
            // Cut only this owner's inherited continuation, retaining any open
            // inner receiver level and unrelated lexical uncertainty.
            if self.call.is_none() && !self.raw.targets().is_empty() {
                let scope = &self.chain[level.origin.lexical_scope()];
                if scope.owner.as_ref().is_some_and(|owner| {
                    owner.scope_kind() == ResolutionScopeKind::TypeBody
                        && owner.definition() == ty.identity()
                }) {
                    let read = evaluation
                        .session
                        .member_owners_for_definitions(self.raw.targets())?;
                    let Some(members) = evaluation.accept_session_read(read) else {
                        return Ok(Ready(None));
                    };
                    let classifiers = members
                        .iter()
                        .filter_map(|member| {
                            let member = member.get(evaluation.session).row();
                            (member.owner_definition() == ty.identity()
                                && member.kind() == ResolutionMemberKind::NestedType
                                && self.raw.witnesses().iter().any(|witness| {
                                    witness.target() == member.definition()
                                        && witness.completion() == &ResolutionCompletion::Complete
                                }))
                            .then_some(member.definition())
                        })
                        .collect::<HashSet<_>>();
                    if self
                        .raw
                        .targets()
                        .iter()
                        .all(|target| classifiers.contains(target))
                    {
                        let read = evaluation
                            .session
                            .property_gaps_for_definitions(&[ty.identity()])?;
                        let Some(gaps) = evaluation.accept_session_read(read) else {
                            return Ok(Ready(None));
                        };
                        let reasons = gaps
                            .iter()
                            .filter_map(|gap| {
                                let gap = gap.get(evaluation.session).row();
                                (gap.kind() == ResolutionGapKind::UnsupportedHierarchyTraversal)
                                    .then_some(gap.reason_semantic())
                            })
                            .collect::<HashSet<_>>();
                        let removals = scope
                            .paths
                            .iter()
                            .filter_map(|(identity, path)| {
                                matches!(path.completion(), ResolutionCompletion::Incomplete(found)
                                if found.iter().any(|reason| matches!(reason,
                                    ResolutionIncompleteReason::UnsupportedSemantic(reason)
                                        if reasons.contains(reason))))
                                .then_some(*identity)
                            })
                            .collect::<Vec<_>>();
                        self.levels[self.level].removals.extend(removals);
                        self.levels[self.level].members.extend(classifiers);
                        self.shape = self.shapes.len();
                        return Ok(Continue);
                    }
                }
            }
            let roots = [HierarchyRoot {
                owner_path_prefix: None,
                owner: ty.identity(),
                value: ResolutionSlotValue::runtime(ty, false),
                route_ordinal: 0,
            }];
            let Some(roots) = evaluation.prepare_hierarchy_roots(shape, &roots) else {
                return Ok(Ready(None));
            };
            let Some(local) = DemandHierarchyLocalFrame::new(evaluation, &roots.root_keys) else {
                return Ok(Ready(None));
            };
            self.group = Some(DemandHierarchyOwnerFrame {
                precedence: 0,
                shape,
                roots: Some(roots),
                local,
                inherited: None,
            });
            return Ok(Continue);
        }
        if self.overlay.is_none() {
            let Some(allowed) = self.select_level(evaluation, previous_states)? else {
                return Ok(Ready(None));
            };
            self.allowed = Some(allowed);
            let mut additions = Vec::new();
            let mut removals = std::mem::take(&mut self.lexical_removals);
            for level in &mut self.levels {
                additions.append(&mut level.additions);
                removals.append(&mut level.removals);
            }
            additions.sort_unstable_by_key(|(identity, _)| *identity);
            additions.dedup_by_key(|(identity, _)| *identity);
            removals.sort_unstable();
            removals.dedup();
            let construction = SelectedContextOverlayFragmentSourceBlueprint::from_parts(
                removals.into_boxed_slice(),
                Box::new([]),
                additions.into_boxed_slice(),
                Box::new([]),
                Box::new([]),
                ResolutionCompletion::Complete,
                evaluation.cancellation,
            )?;
            match construction {
                SelectedContextOverlayFragmentSourceBlueprintConstruction::Ready(overlay) => {
                    self.overlay = Some(overlay.with_external_definitions(
                        &evaluation.hierarchy.external_lexical_definitions,
                    ))
                }
                SelectedContextOverlayFragmentSourceBlueprintConstruction::Cancelled {
                    cancellation_completion,
                    ..
                } => {
                    evaluation.observe_cancellation_completion(&cancellation_completion);
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
                DemandForwardBatchStart::Running(mut frame) => {
                    frame.allow_only_targets(self.allowed.take().unwrap());
                    self.active = Some(*frame);
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
        &mut self,
        evaluation: &mut FactEvaluation<'_, '_>,
        batch: super::super::batch::ReferenceBatchAnswer,
    ) -> StoreResult<DemandQualifiedPoll> {
        let (answers, completion, metrics) = batch.into_parts();
        evaluation.binding_metrics.accumulate(metrics);
        evaluation.observe_cancellation_completion(&completion);
        let [answer] = answers
            .into_vec()
            .try_into()
            .expect("one implicit receiver reference");
        let (reference, answer) = answer.into_parts();
        assert_eq!(reference, self.seed.reference());
        let (targets, witnesses, completion) = answer.into_parts();
        let answer =
            ResolutionAnswer::new(targets, witnesses, completion.combine(&self.completion));
        for level in &mut self.levels {
            if answer
                .targets()
                .iter()
                .any(|target| level.members.contains(target))
            {
                level.result = Some(ReceiverLevelResult {
                    answer: answer.clone(),
                    matched_receivers: level
                        .ty
                        .into_iter()
                        .map(|ty| ResolutionSlotValue::runtime(ty, false))
                        .collect(),
                });
            }
        }
        Ok(DemandQualifiedPoll::Ready(Some(answer)))
    }

    fn retain_members(
        &mut self,
        evaluation: &mut FactEvaluation<'_, '_>,
        selection: HierarchySelection,
    ) -> StoreResult<()> {
        let shape = self.shapes[self.shape];
        let level = &mut self.levels[self.level];
        let scope = &self.chain[level.origin.lexical_scope()];
        let ty = level.ty.expect("a searched receiver has a type");
        let Some(mut completion) =
            evaluation
                .hierarchy
                .evidence
                .flatten(&selection.evidence, u32::MAX, &mut || {
                    poll_cancelled(evaluation.cancellation, &mut evaluation.work)
                })
        else {
            evaluation.cancellation_observed = true;
            return Ok(());
        };
        if selection.owners.is_empty()
            && evaluation
                .jvm_hierarchy_implicit_root_gap_references(shape, ty.identity())?
                .is_some_and(|gaps| gaps.is_some())
            && evaluation.lookup_is_outside_implicit_root(self.seed.fragment(), shape.lookup)?
                == Some(true)
        {
            completion = ResolutionCompletion::Complete;
        }
        level.completion = level.completion.combine(&completion);
        for owner in &selection.owners {
            let local = &evaluation.hierarchy.local_nodes[&HierarchyNodeKey {
                shape,
                owner: owner.owner,
            }];
            level
                .members
                .extend(local.direct_definitions.iter().copied());
        }
        let owner = scope.owner.as_ref().expect("a receiver scope has an owner");
        // A dispatch body's direct binders are already reachable at this
        // lexical head. Re-entering that head through a bridge creates a
        // precedence cycle. Extension bodies need the receiver's own members
        // bridged because their executable head is a different scope.
        let mut selection = selection;
        if owner.scope_kind() == ResolutionScopeKind::TypeBody {
            selection.owners = selection
                .owners
                .into_vec()
                .into_iter()
                .filter(|selected| selected.owner != owner.definition())
                .collect();
        }
        let mut branches = Vec::new();
        if owner.scope_kind() == ResolutionScopeKind::TypeBody {
            let read = evaluation
                .session
                .property_gaps_for_definitions(&[owner.definition()])?;
            let Some(gaps) = evaluation.accept_session_read(read) else {
                return Ok(());
            };
            let reasons = gaps
                .iter()
                .filter_map(|gap| {
                    let gap = gap.get(evaluation.session).row();
                    (gap.kind() == ResolutionGapKind::UnsupportedHierarchyTraversal)
                        .then_some(gap.reason_semantic())
                })
                .collect::<HashSet<_>>();
            for (identity, path) in
                evaluation.lexical_paths_at(closed_endpoint(owner.scope_head(), [shape.lookup]))?
            {
                if matches!(path.completion(), ResolutionCompletion::Incomplete(found)
                    if found.iter().any(|reason| matches!(reason, ResolutionIncompleteReason::UnsupportedSemantic(reason) if reasons.contains(reason))))
                {
                    branches.push((identity, path, true));
                }
            }
        }
        if branches.is_empty()
            && let Some((identity, path)) = &scope.outward
        {
            branches.push((*identity, path.clone(), false));
        }
        for (identity, branch, hierarchy) in branches {
            let (paths, remove) = evaluation.java_lexical_bridges(
                self.seed.reference(),
                shape,
                identity,
                &branch,
                selection.clone(),
            )?;
            if hierarchy || remove {
                level.removals.push(identity);
            }
            level.additions.extend(paths);
        }
        Ok(())
    }

    fn select_level(
        &mut self,
        evaluation: &mut FactEvaluation<'_, '_>,
        previous_states: &StateMap,
    ) -> StoreResult<Option<HashSet<SemanticId>>> {
        let mut candidates = self
            .raw
            .witnesses()
            .iter()
            .map(ResolutionWitness::target)
            .collect::<HashSet<_>>();
        candidates.extend(self.raw.targets().iter().copied());
        candidates.extend(
            self.levels
                .iter()
                .flat_map(|level| level.members.iter().copied()),
        );
        // Java sees JVM methods with an extension receiver as ordinary
        // members. Only the language rule with an extension phase separates
        // them from the current level's ordinary member inventory.
        let extensions =
            if self.call.is_some() && self.rule == ImplicitReceiverLookup::FirstApplicable {
                let definitions = candidates.iter().copied().collect::<Vec<_>>();
                let read = evaluation
                    .session
                    .signatures_for_definitions(&definitions)?;
                let Some(signatures) = evaluation.accept_session_read(read) else {
                    return Ok(None);
                };
                signatures
                    .iter()
                    .filter_map(|signature| {
                        let signature = signature.get(evaluation.session).row();
                        signature
                            .extension_receiver()
                            .map(|_| signature.definition())
                    })
                    .collect::<HashSet<_>>()
            } else {
                HashSet::default()
            };
        // A local lexical binding keeps priority over every implicit receiver.
        // Use the source-issued binder paths, not names or dense node ordering.
        if let Some(outermost_executable) = self.chain.iter().rposition(|scope| {
            scope
                .owner
                .as_ref()
                .is_some_and(|owner| owner.scope_kind() == ResolutionScopeKind::Executable)
        }) {
            for scope_index in 0..=outermost_executable {
                let scope = &self.chain[scope_index];
                let mut local = HashSet::default();
                for (prefix, (_, path)) in scope
                    .prefixes
                    .iter()
                    .flat_map(|prefix| scope.paths.iter().map(move |path| (prefix, path)))
                {
                    let Some(Ok(path)) =
                        prefix.concatenate_with_poll(path, &mut || evaluation.poll_cancelled())
                    else {
                        continue;
                    };
                    if !endpoint_is_balanced(path.end()) {
                        continue;
                    }
                    let nodes = evaluation
                        .session
                        .lexical_source
                        .classify_endpoint_nodes(&[path.end().node()], evaluation.cancellation)?;
                    if let Some(target) = nodes[0].definition()
                        && !extensions.contains(&target)
                    {
                        local.insert(target);
                    }
                }
                let read = evaluation
                    .session
                    .member_owners_for_definitions(&local.iter().copied().collect::<Vec<_>>())?;
                let Some(members) = evaluation.accept_session_read(read) else {
                    return Ok(None);
                };
                for member in members {
                    local.remove(&member.get(evaluation.session).row().definition());
                }
                let Some(probe) = self.probe(evaluation, &local, None, previous_states)? else {
                    return Ok(None);
                };
                if !probe.allowed.is_empty() {
                    // A lexical binder closes this search before any receiver
                    // scope. Unexamined outer hierarchies are unreachable.
                    if let Some((identity, _)) = &scope.outward {
                        self.lexical_removals.push(*identity);
                    }
                    self.completion = probe.completion;
                    return Ok(Some(probe.allowed));
                }
                if probe.completion != ResolutionCompletion::Complete {
                    self.completion = probe.completion;
                    return Ok(Some(HashSet::default()));
                }
            }
        }

        let mut selection = ReceiverLevelSelection::new(ResolutionCompletion::Complete);
        for index in 0..self.levels.len() {
            let level = &self.levels[index];
            let Some(ty) = level.ty else {
                selection.completion = selection
                    .completion
                    .combine(&self.blocked_completion(evaluation)?)
                    .combine(&level.completion);
                continue;
            };
            let members = level
                .members
                .difference(&extensions)
                .copied()
                .collect::<HashSet<_>>();
            let proof = ImplicitReceiverProof {
                extension: None,
                dispatch: Some(ty),
            };
            if self.rule == ImplicitReceiverLookup::FirstMemberName && !members.is_empty() {
                selection.select_level(&level.completion, &ResolutionCompletion::Complete, true);
                self.completion = selection.completion;
                self.cut_outer(index);
                return Ok(Some(members));
            }
            let Some(probe) = self.probe(evaluation, &members, Some(proof), previous_states)?
            else {
                return Ok(None);
            };
            if selection.select_level(
                &self.levels[index].completion,
                &probe.completion,
                !probe.allowed.is_empty(),
            ) {
                self.completion = selection.completion;
                self.install_proofs(evaluation, probe.proofs);
                self.cut_outer(index);
                return Ok(Some(probe.allowed));
            }
            // Retain outer candidates as best-effort answers, carrying every
            // unexamined inner frontier so none can become a proven answer.
            if self.call.is_none() || self.rule == ImplicitReceiverLookup::FirstMemberName {
                continue;
            }
            let mut allowed = HashSet::default();
            let mut proofs = Vec::new();
            let mut extension_inventory = self
                .levels
                .iter()
                .fold(ResolutionCompletion::Complete, |completion, level| {
                    completion.combine(&level.completion)
                });
            for &extension in &extensions {
                // A member extension has a distinct dispatch proof. Its
                // extension receiver is this level, even when dispatch is outer.
                let dispatch = self
                    .levels
                    .iter()
                    .find(|level| level.members.contains(&extension));
                let proof = ImplicitReceiverProof {
                    extension: Some(ty),
                    dispatch: dispatch.and_then(|level| level.ty),
                };
                let Some(probe) = self.probe(
                    evaluation,
                    &std::iter::once(extension).collect(),
                    Some(proof),
                    previous_states,
                )?
                else {
                    return Ok(None);
                };
                extension_inventory = extension_inventory.combine(&probe.completion);
                if !probe.allowed.is_empty() {
                    if let Some(dispatch) = dispatch {
                        extension_inventory = extension_inventory.combine(&dispatch.completion);
                    }
                    allowed.extend(probe.allowed);
                    proofs.extend(probe.proofs);
                }
            }
            if selection.select_level(
                &extension_inventory,
                &ResolutionCompletion::Complete,
                !allowed.is_empty(),
            ) {
                self.completion = selection.completion;
                self.install_proofs(evaluation, proofs);
                return Ok(Some(allowed));
            }
        }
        // No receiver claims the name: resume the original lexical/import
        // precedence after excluding the examined member and extension routes.
        for level in &self.levels {
            for member in &level.members {
                candidates.remove(member);
            }
        }
        for extension in extensions {
            candidates.remove(&extension);
        }
        // This root lookup can be an unresolved placement boundary. Keep its
        // original evidence; no synthetic successful answer is fabricated.
        self.completion = self.completion.combine(&selection.completion);
        Ok(Some(candidates))
    }

    fn cut_outer(&mut self, level: usize) {
        let ReceiverLevelOrigin::Lexical { scope } = self.levels[level].origin else {
            return;
        };
        if let Some((identity, _)) = &self.chain[scope].outward {
            self.levels[level].removals.push(*identity);
        }
    }

    fn blocked_completion(
        &self,
        evaluation: &FactEvaluation<'_, '_>,
    ) -> StoreResult<ResolutionCompletion> {
        // Applicability refinement may discharge its own pending reason. An
        // unknown receiver level must independently keep outer lookup open.
        Ok(ResolutionCompletion::incomplete([
            ResolutionIncompleteReason::UnsupportedSemantic(canonical_service_reason(
                evaluation.session,
                evaluation.hierarchy,
                b"implicit-receiver-type-unavailable",
                &[CanonicalIdentityPart::identity(self.seed.reference())],
            )?),
        ]))
    }

    fn install_proofs(
        &self,
        evaluation: &mut FactEvaluation<'_, '_>,
        proofs: Vec<(SemanticId, ImplicitReceiverProof)>,
    ) {
        for (candidate, proof) in proofs {
            evaluation
                .implicit_receiver_proofs
                .insert((self.seed.reference(), candidate), proof);
        }
    }

    fn probe(
        &self,
        evaluation: &mut FactEvaluation<'_, '_>,
        targets: &HashSet<SemanticId>,
        proof: Option<ImplicitReceiverProof>,
        previous_states: &StateMap,
    ) -> StoreResult<Option<ReceiverProbe>> {
        let mut result = ReceiverProbe {
            allowed: HashSet::default(),
            proofs: Vec::new(),
            completion: ResolutionCompletion::Complete,
        };
        let reference = self.seed.reference();
        // Value lookup selects bindings, without invoking them or testing a
        // callable signature. Locals and receiver properties use the same
        // lexical paths and hierarchy completeness as calls.
        let Some(call) = self.call else {
            result.allowed.extend(targets.iter().copied());
            return Ok(Some(result));
        };
        let call_row = call;
        let call = call.get(evaluation.session).row().clone();
        let adapter = call_applicability_adapter(call.language());
        let mut targets = targets.iter().copied().collect::<Vec<_>>();
        targets.sort_unstable();
        let Some((priority_targets, values)) =
            evaluation.call_target_priority(adapter, &targets)?
        else {
            return Ok(None);
        };
        let mut function_applicable = false;
        for target in priority_targets {
            if function_applicable && values.contains(&target) {
                continue;
            }
            if evaluation.poll_cancelled() {
                return Ok(None);
            }
            let mut projected = std::iter::once((
                reference,
                Arc::new(ResolutionAnswer::new(
                    vec![target],
                    Vec::new(),
                    ResolutionCompletion::Complete,
                )),
            ))
            .collect::<HashMap<_, _>>();
            if evaluation
                .expand_types_in_call_position(
                    &[reference],
                    &std::iter::once((reference, call_row)).collect(),
                    &mut projected,
                )?
                .is_none()
            {
                return Ok(None);
            }
            let expanded = projected.remove(&reference).expect("one projected call");
            let read = evaluation
                .session
                .signatures_for_definitions(expanded.targets())?;
            let Some(signatures) = evaluation.accept_session_read(read) else {
                return Ok(None);
            };
            let mut possible = false;
            for &candidate in expanded.targets() {
                let signature = signatures.iter().find(|signature| {
                    signature.get(evaluation.session).row().definition() == candidate
                });
                let Some(signature) = signature else {
                    let answers = Arc::clone(&evaluation.member_applicability_answers);
                    let Some(assessment) = evaluation.assess_value_application(
                        candidate,
                        &call,
                        &answers,
                        previous_states,
                        &mut result.completion,
                    )?
                    else {
                        return Ok(None);
                    };
                    if !matches!(
                        assessment,
                        super::call_applicability::ResultApplicationAssessment::Inapplicable(_)
                    ) {
                        possible = true;
                        if matches!(
                            assessment,
                            super::call_applicability::ResultApplicationAssessment::Unknown
                        ) {
                            result.completion = result
                                .completion
                                .combine(&self.blocked_completion(evaluation)?);
                        }
                        if let Some(proof) = proof {
                            result.proofs.push((candidate, proof));
                        }
                    }
                    continue;
                };
                let Some(signature) =
                    signature
                        .get(evaluation.session)
                        .row()
                        .clone_with_poll(&mut || {
                            poll_cancelled(evaluation.cancellation, &mut evaluation.work)
                        })
                else {
                    return Ok(None);
                };
                for parameter in signature.parameters() {
                    if evaluation.poll_cancelled() {
                        return Ok(None);
                    }
                    evaluation.demand_slot(parameter.slot());
                }
                let old_owner = evaluation.member_owner_by_target.get(&candidate).cloned();
                let old_proof = proof.and_then(|proof| {
                    evaluation
                        .implicit_receiver_proofs
                        .insert((reference, candidate), proof)
                });
                let mut completion = ResolutionCompletion::Complete;
                let inventory_complete = completion_without_unsupported_semantic(
                    call.completion(),
                    call.applicability_reason(),
                ) == ResolutionCompletion::Complete;
                let assessed = adapter.assess_candidate(
                    evaluation,
                    candidate,
                    &call,
                    &signature,
                    inventory_complete,
                    &HashMap::default(),
                    previous_states,
                    &mut completion,
                );
                match old_owner {
                    Some(owner) => {
                        evaluation.member_owner_by_target.insert(candidate, owner);
                    }
                    None => {
                        evaluation.member_owner_by_target.remove(&candidate);
                    }
                }
                if proof.is_some() {
                    match old_proof {
                        Some(proof) => {
                            evaluation
                                .implicit_receiver_proofs
                                .insert((reference, candidate), proof);
                        }
                        None => {
                            evaluation
                                .implicit_receiver_proofs
                                .remove(&(reference, candidate));
                        }
                    }
                }
                let Some(assessed) = assessed? else {
                    return Ok(None);
                };
                if assessed.verdict != ApplicabilityVerdict::Inapplicable {
                    result.completion = result.completion.combine(&completion);
                    // Receiver conformance is a binding proof. Unknown ordinary
                    // argument conversions may leave a possible overload, but
                    // an unproved receiver must not contribute that declaration.
                    if assessed.conversions.iter().any(|conversion| {
                        conversion.argument_ordinal == u32::MAX
                            && conversion.parameter_ordinal == u32::MAX
                            && conversion.kind == ConversionKind::Unknown
                    }) {
                        continue;
                    }
                    possible = true;
                    function_applicable |= assessed.verdict == ApplicabilityVerdict::Applicable
                        && !values.contains(&target);
                    if let Some(proof) = proof {
                        result.proofs.push((candidate, proof));
                    }
                }
            }
            if possible {
                result.allowed.insert(target);
            }
        }
        Ok(Some(result))
    }
}

struct ReceiverProbe {
    allowed: HashSet<SemanticId>,
    proofs: Vec<(SemanticId, ImplicitReceiverProof)>,
    completion: ResolutionCompletion,
}

impl DemandReferenceEvaluationFrame {
    pub(super) fn poll_implicit(
        &mut self,
        evaluation: &mut FactEvaluation<'_, '_>,
        previous_states: &StateMap,
        readiness: &mut impl FnMut(&[BatchCandidateRequest]) -> StoreResult<DemandForwardReadiness>,
    ) -> StoreResult<DemandFactEvaluationPoll> {
        let reference = self.references[self.cursor];
        if self.implicit.is_none() {
            self.implicit = DemandImplicitReceiverFrame::new(
                evaluation,
                reference,
                self.calls.get(&reference).copied(),
                Arc::clone(self.implicit_answer.as_ref().unwrap()),
            )?;
            if self.implicit.is_none() {
                self.implicit_answer = None;
                self.cursor += 1;
                return Ok(DemandFactEvaluationPoll::Continue);
            }
        }
        let result =
            self.implicit
                .as_mut()
                .unwrap()
                .poll(evaluation, previous_states, readiness)?;
        // A suspended frame has performed no work. Repeated polls must retain
        // its exact endpoints and accounting until the provider admits them.
        if matches!(result, DemandQualifiedPoll::AwaitingDependencies)
            && !evaluation.cancellation_observed
            && !evaluation.cancellation.is_cancelled()
        {
            return Ok(DemandFactEvaluationPoll::AwaitingDependencies);
        }
        if evaluation.poll_cancelled() {
            self.implicit.take().unwrap().cancel(evaluation);
            return Ok(DemandFactEvaluationPoll::ready(
                evaluation.cancelled_answer(None),
            ));
        }
        match result {
            DemandQualifiedPoll::Continue => Ok(DemandFactEvaluationPoll::Continue),
            DemandQualifiedPoll::AwaitingDependencies => {
                Ok(DemandFactEvaluationPoll::AwaitingDependencies)
            }
            DemandQualifiedPoll::AwaitingHierarchyReferences(references) => Ok(
                DemandFactEvaluationPoll::AwaitingHierarchyReferences(references),
            ),
            DemandQualifiedPoll::Ready(answer) => {
                if let Some(answer) = answer {
                    self.answers.insert(reference, Arc::new(answer));
                }
                self.implicit = None;
                self.implicit_answer = None;
                self.cursor += 1;
                Ok(DemandFactEvaluationPoll::Continue)
            }
        }
    }
}

impl FactEvaluation<'_, '_> {
    pub(super) fn uses_implicit_receiver_lookup(
        &self,
        reference: SemanticId,
        call: Option<InternedFactRow<SelectedTypedRow<LoweredCallApplicabilityObligation>>>,
    ) -> StoreResult<bool> {
        if let Some(call) = call {
            return Ok(implicit_receiver_call(call.get(self.session).row()));
        }
        // Dependencies may belong to a different language from the root query.
        // A source without language metadata has not opted into value lookup.
        let language = self
            .session
            .lexical_source
            .semantic_language_of(reference, self.cancellation)?;
        Ok(language.is_some_and(|language| {
            call_applicability_adapter(language).implicit_receiver_value_lookup()
        }))
    }

    pub(super) fn replay_eager_implicit_receivers(
        &mut self,
        reference: SemanticId,
        call: Option<InternedFactRow<SelectedTypedRow<LoweredCallApplicabilityObligation>>>,
        raw: SharedAnswer,
        previous_states: &StateMap,
    ) -> StoreResult<Option<ResolutionAnswer>> {
        let Some(mut frame) = DemandImplicitReceiverFrame::new(self, reference, call, raw)? else {
            return Ok(None);
        };
        loop {
            if self.poll_cancelled() {
                frame.cancel(self);
                return Ok(None);
            }
            match frame.poll(self, previous_states, &mut |_| {
                Ok(DemandForwardReadiness::Ready)
            })? {
                DemandQualifiedPoll::Continue => {}
                DemandQualifiedPoll::AwaitingDependencies => {
                    unreachable!("assembled source dependencies are ready")
                }
                DemandQualifiedPoll::AwaitingHierarchyReferences(references) => {
                    if !self.ensure_qualified_hierarchy_reference_answers(
                        &references.into_iter().collect(),
                    )? {
                        frame.cancel(self);
                        return Ok(None);
                    }
                }
                DemandQualifiedPoll::Ready(answer) => return Ok(answer),
            }
        }
    }
}

// rustc rejects recursive receiver expansion. Real receiver chains are short;
// eight derived steps bound work even when every step changes generic arguments.
const MAX_EXPLICIT_RECEIVER_STEPS: usize = 8;

/// Ordered selection is independent of how a level obtains its members. Empty
/// inner levels retain their completion in the first successful outer answer.
struct ReceiverLevelSelection {
    completion: ResolutionCompletion,
    selected: bool,
}

impl ReceiverLevelSelection {
    fn new(completion: ResolutionCompletion) -> Self {
        Self {
            completion,
            selected: false,
        }
    }

    fn select_level(
        &mut self,
        level: &ResolutionCompletion,
        applicability: &ResolutionCompletion,
        has_members: bool,
    ) -> bool {
        assert!(
            !self.selected,
            "a successful receiver stops its ordered search"
        );
        self.completion = self.completion.combine(level).combine(applicability);
        self.selected = has_members;
        self.selected
    }
}

struct ExplicitReceiverCursor {
    context: ExplicitReceiverContext,
    selection: ReceiverLevelSelection,
    visited: HashSet<(ResolutionTypeRef, SelectedReceiverInstantiation)>,
    steps: usize,
}

/// The first continuation searches the original frontier as one unit. Subsequent
/// continuations search one derived receiver at a time. Alternative receivers
/// are unioned; only levels of the same alternative have first-success order.
/// All retained state dies with this query.
pub(super) struct DemandQualifiedFrame {
    frame: Option<QualifiedReceiverFrame>,
    template: PreparedQualifiedSeed,
    literal_struct_field: bool,
    call: Option<InternedFactRow<SelectedTypedRow<LoweredCallApplicabilityObligation>>>,
    level: ReceiverLevel,
    cursors: VecDeque<ExplicitReceiverCursor>,
    cursor: Option<ExplicitReceiverCursor>,
    states: Option<StateMap>,
    answer: Option<ResolutionAnswer>,
    advanced: bool,
    closed: bool,
}

impl DemandQualifiedFrame {
    pub(super) fn new(frame: QualifiedReceiverFrame, states: &StateMap) -> Self {
        let template = frame
            .prepared
            .as_ref()
            .expect("initial qualified seed")
            .clone();
        let mut seen = HashSet::default();
        let mut frontier = Vec::new();
        for route in &template.routes {
            let slot = route.row().qualifier_slot();
            if let Some(state) = states.get(&slot) {
                for &value in state.possible_values() {
                    if seen.insert((slot, value)) {
                        frontier.push(ExplicitReceiverContext {
                            receiver_slot: slot,
                            value,
                            instantiation: SelectedReceiverInstantiation {
                                application_slot: slot,
                                substitutions: Vec::new(),
                            },
                            completion: state.completion().clone(),
                        });
                    }
                }
            }
        }
        Self {
            template,
            literal_struct_field: frame.literal_struct_field,
            call: frame.call,
            frame: Some(frame),
            level: ReceiverLevel {
                origin: ReceiverLevelOrigin::Explicit { frontier },
                ty: None,
                completion: ResolutionCompletion::Complete,
                members: HashSet::default(),
                result: None,
                additions: Vec::new(),
                removals: Vec::new(),
            },
            cursors: VecDeque::new(),
            cursor: None,
            states: None,
            answer: None,
            advanced: false,
            closed: true,
        }
    }

    #[cfg(test)]
    pub(super) fn receiver_frame(&self) -> Option<&QualifiedReceiverFrame> {
        self.frame.as_ref()
    }

    #[cfg(test)]
    pub(super) fn receiver_frame_mut(&mut self) -> Option<&mut QualifiedReceiverFrame> {
        self.frame.as_mut()
    }

    pub(super) fn pending_requests(&self) -> &[BatchCandidateRequest] {
        self.frame
            .as_ref()
            .map_or(&[], QualifiedReceiverFrame::pending_requests)
    }

    pub(super) fn active_forward_frame(&mut self) -> Option<&mut DemandForwardBatchFrame> {
        self.frame.as_mut()?.active_forward_frame()
    }

    pub(super) fn cancel(self, evaluation: &mut FactEvaluation<'_, '_>) {
        if let Some(frame) = self.frame {
            frame.cancel(evaluation);
        }
        if let Some(answer) = self.answer {
            evaluation.observe_resolution_answer_cancellation_evidence(&answer);
        }
        if let Some(result) = self.level.result {
            evaluation.observe_resolution_answer_cancellation_evidence(&result.answer);
        }
        for cursor in self.cursors.into_iter().chain(self.cursor) {
            evaluation.observe_cancellation_completion(&cursor.selection.completion);
        }
    }

    pub(super) fn poll(
        &mut self,
        reference: SemanticId,
        evaluation: &mut FactEvaluation<'_, '_>,
        previous_states: &StateMap,
        readiness: &mut impl FnMut(&[BatchCandidateRequest]) -> StoreResult<DemandForwardReadiness>,
    ) -> StoreResult<DemandQualifiedPoll> {
        use DemandQualifiedPoll::{Continue, Ready};
        loop {
            if let Some(frame) = &mut self.frame {
                let result = frame.poll(
                    reference,
                    evaluation,
                    self.states.as_ref().unwrap_or(previous_states),
                    readiness,
                )?;
                let Ready(Some(answer)) = result else {
                    return Ok(result);
                };
                self.frame = None;
                let matched_receivers = answer
                    .targets()
                    .iter()
                    .flat_map(|target| {
                        evaluation
                            .receiver_level_matches
                            .get(&(reference, *target))
                            .into_iter()
                            .flat_map(|values| values.iter().copied())
                    })
                    .collect();
                self.level.result = Some(ReceiverLevelResult {
                    answer,
                    matched_receivers,
                });
                let result = self.level.result.as_ref().unwrap();
                if let Some(cursor) = &mut self.cursor {
                    let success = cursor.selection.select_level(
                        result.answer.completion(),
                        &ResolutionCompletion::Complete,
                        !result.answer.targets().is_empty(),
                    );
                    if success {
                        let cursor = self.cursor.take().unwrap();
                        let result = self.level.result.take().unwrap();
                        self.closed &= result.answer.completion()
                            == &ResolutionCompletion::Complete
                            && cursor.context.completion == ResolutionCompletion::Complete;
                        self.states = None;
                        let (targets, witnesses, _) = result.answer.into_parts();
                        let answer =
                            ResolutionAnswer::new(targets, witnesses, cursor.selection.completion);
                        let Some(answer) =
                            evaluation.merge_qualified_answers(self.answer.take().unwrap(), answer)
                        else {
                            return Ok(Ready(None));
                        };
                        self.answer = Some(answer);
                    }
                } else {
                    let ReceiverLevelOrigin::Explicit { frontier } = &self.level.origin else {
                        unreachable!("qualified search has explicit receivers");
                    };
                    for context in frontier {
                        if !result.matched_receivers.contains(&context.value) {
                            self.cursors.push_back(ExplicitReceiverCursor {
                                context: context.clone(),
                                selection: ReceiverLevelSelection::new(
                                    result.answer.completion().clone(),
                                ),
                                visited: std::iter::once((
                                    context.value.ty(),
                                    context.instantiation.clone(),
                                ))
                                .collect(),
                                steps: 0,
                            });
                        }
                    }
                    // Preserve the exact step-zero bytes when no hook advances.
                    self.answer = Some(self.level.result.take().unwrap().answer);
                }
            }
            if self.cursor.is_none() {
                self.cursor = self.cursors.pop_front();
            }
            let Some(cursor) = &mut self.cursor else {
                let answer = self.answer.take().expect("step-zero answer");
                return Ok(Ready(if self.advanced && self.closed {
                    evaluation
                        .refine_direct_qualified_binding(&answer, &self.template.route_gap_reasons)
                } else {
                    Some(answer)
                }));
            };
            let language = self
                .template
                .routes
                .first()
                .expect("qualified routes")
                .language();
            let Some(support) = crate::analyzer::store::store_language_support(language) else {
                self.finish_cursor();
                continue;
            };
            let call = self
                .call
                .map(|call| call.get(evaluation.session).row().call());
            let request = SelectedReceiverStepRequest {
                reference,
                call,
                qualifier_slot: cursor.context.receiver_slot,
                value: cursor.context.value,
                instantiation: &cursor.context.instantiation,
            };
            let step = support.selected_receiver_step(
                request,
                &mut ReceiverStepReads {
                    evaluation,
                    states: self.states.as_ref().unwrap_or(previous_states),
                },
            )?;
            let step = match step {
                SelectedReceiverStepRead::Pending => return Ok(Ready(None)),
                SelectedReceiverStepRead::Cancelled => {
                    evaluation.cancellation_observed = true;
                    return Ok(Ready(None));
                }
                SelectedReceiverStepRead::ReadyNone => {
                    self.finish_cursor();
                    continue;
                }
                SelectedReceiverStepRead::ReadyStep(step) => step,
            };
            if evaluation.poll_cancelled() {
                return Ok(Ready(None));
            }
            cursor.selection.completion = cursor.selection.completion.combine(&step.completion);
            let reason: Option<&'static [u8]> = if let Some(reason) = step.stop_reason {
                Some(reason.as_bytes())
            } else if step.values.len() != 1 {
                Some(b"receiver-step-target-not-singleton".as_slice())
            } else if cursor.steps == MAX_EXPLICIT_RECEIVER_STEPS {
                Some(b"receiver-step-budget-exhausted".as_slice())
            } else if !cursor
                .visited
                .insert((step.values[0].ty(), step.instantiation.clone()))
            {
                Some(b"receiver-step-cycle".as_slice())
            } else {
                None
            };
            if let Some(reason) = reason {
                let reason = if let Some(identities) = &evaluation.session.context_identities {
                    let mut hash = CanonicalHasher::new(b"bifrost-explicit-receiver-stop:v1");
                    hash.field("kind", reason);
                    hash.identity_field("reference", reference, |key| {
                        evaluation
                            .session
                            .identity_digest(evaluation.hierarchy, key)
                    })?;
                    let name = std::str::from_utf8(reason).expect("receiver stop names are ASCII");
                    identities.named_semantic(hash.finish(), name, name)
                } else {
                    canonical_service_reason(
                        evaluation.session,
                        evaluation.hierarchy,
                        reason,
                        &[CanonicalIdentityPart::identity(reference)],
                    )?
                };
                cursor.selection.completion =
                    cursor
                        .selection
                        .completion
                        .combine(&ResolutionCompletion::incomplete([
                            ResolutionIncompleteReason::UnsupportedSemantic(reason),
                        ]));
                self.finish_cursor();
                continue;
            }
            self.advanced = true;
            cursor.steps += 1;
            cursor.context.value = step.values[0];
            cursor.context.instantiation = step.instantiation;
            cursor.context.completion = cursor.context.completion.combine(&step.completion);
            let mut states = previous_states.clone();
            for &(formal, actual) in &cursor.context.instantiation.substitutions {
                if let Some(state) = previous_states.get(&actual) {
                    states.insert(
                        formal,
                        Arc::new(TypedFrontierState::new(
                            formal,
                            state.possible_values().to_vec(),
                            state.completion().clone(),
                        )),
                    );
                }
            }
            let application = cursor.context.instantiation.application_slot;
            for slot in [cursor.context.receiver_slot, application] {
                states.insert(
                    slot,
                    Arc::new(TypedFrontierState::new(
                        slot,
                        vec![cursor.context.value],
                        cursor.context.completion.clone(),
                    )),
                );
            }
            let mut prepared = self.template.clone();
            prepared
                .routes
                .retain(|route| route.row().qualifier_slot() == cursor.context.receiver_slot);
            for route in &mut prepared.routes {
                let row = route.row();
                let replacement = LoweredQualifiedSeededRoute::new_with_source_lookup(
                    row.reference(),
                    application,
                    row.lookup(),
                    row.namespace(),
                    row.source_lookup(),
                    row.precedence_ordinal(),
                    row.projection_output_slot(),
                    row.projection_kind(),
                    row.coarse_gap_reason(),
                    row.open_member_surface(),
                );
                *route = SourceSelectedQualifiedRoute::new(
                    route.fragment(),
                    route.reference_node(),
                    replacement,
                )
                .with_language(route.language());
            }
            self.level = ReceiverLevel {
                origin: ReceiverLevelOrigin::Explicit {
                    frontier: vec![cursor.context.clone()],
                },
                ty: Some(cursor.context.value.ty()),
                completion: cursor.context.completion.clone(),
                members: HashSet::default(),
                result: None,
                additions: Vec::new(),
                removals: Vec::new(),
            };
            self.frame = Some(QualifiedReceiverFrame {
                literal_struct_field: self.literal_struct_field,
                call: self.call,
                suffix_request: None,
                direct: Some(Arc::new(ResolutionAnswer::new(
                    Vec::new(),
                    Vec::new(),
                    prepared.route_seed.completion().clone(),
                ))),
                prepared: Some(prepared),
                replay: None,
                active: None,
                members: None,
                origins: None,
                hierarchy_group: None,
                supertraits: None,
                member_closure: None,
            });
            self.states = Some(states);
            return Ok(Continue);
        }
    }

    fn finish_cursor(&mut self) {
        let cursor = self.cursor.take().expect("one active receiver cursor");
        self.states = None;
        self.closed = false;
        if cursor.steps == 0
            && self.answer.as_ref().expect("step-zero answer").completion()
                == &cursor.selection.completion
        {
            return;
        }
        let answer = self.answer.take().expect("step-zero answer");
        let (targets, witnesses, completion) = answer.into_parts();
        self.answer = Some(ResolutionAnswer::new(
            targets,
            witnesses,
            completion.combine(&cursor.selection.completion),
        ));
    }
}

struct ReceiverStepReads<'evaluation, 'resources, 'source> {
    evaluation: &'evaluation mut FactEvaluation<'resources, 'source>,
    states: &'evaluation StateMap,
}

impl SelectedReceiverStepSource for ReceiverStepReads<'_, '_, '_> {
    fn rust_impl_targets(&mut self, owner: SemanticId) -> StoreResult<Vec<SemanticId>> {
        let session = &mut self.evaluation.session;
        if let Some(targets) = session.rust_receiver_impl_targets.get(&owner) {
            return Ok(targets.clone());
        }
        let targets = session
            .typed_source
            .rust_receiver_impl_targets(owner, self.evaluation.cancellation)?;
        if !self.evaluation.cancellation.is_cancelled() {
            session
                .rust_receiver_impl_targets
                .insert(owner, targets.clone());
        }
        Ok(targets)
    }

    fn impl_owner(
        &mut self,
        target: SemanticId,
    ) -> StoreResult<Option<LoweredDeferredMemberOwner>> {
        let read = self
            .evaluation
            .session
            .deferred_member_owners_for_definitions(&[target])?;
        Ok(self.evaluation.accept_session_read(read).and_then(|rows| {
            assert!(rows.len() <= 1, "one associated type has one impl owner");
            rows.first()
                .map(|row| *row.get(self.evaluation.session).row())
        }))
    }

    fn applicability(
        &mut self,
        owner: LoweredDeferredMemberOwner,
        request: &SelectedReceiverStepRequest<'_>,
    ) -> StoreResult<Option<ResolutionCompletion>> {
        let evaluation = &mut self.evaluation;
        let answers = Arc::clone(&evaluation.member_applicability_answers);
        Ok(evaluation
            .impl_subject_selection(
                owner.owner_frontier(),
                request.instantiation.application_slot,
                owner.definition(),
                &answers,
                self.states,
            )?
            .and_then(|selection| match selection.applicability {
                ImplSubjectApplicability::Applies => Some(ResolutionCompletion::Complete),
                ImplSubjectApplicability::Unknown => Some(incomplete(owner.definition())),
                ImplSubjectApplicability::DoesNotApply => None,
            }))
    }

    fn activation(
        &mut self,
        reference: SemanticId,
        target: SemanticId,
    ) -> StoreResult<DeclarationAccessDecision> {
        let session = &mut self.evaluation.session;
        let Some(policy) = session.declaration_access_source else {
            return Ok(DeclarationAccessDecision::UnknownActivation);
        };
        let request = DeclarationAccessRequest {
            reference,
            definition: target,
        };
        let loaded = FactEvaluation::ensure_declaration_access_rows(
            policy,
            session.typed_source,
            session.resolution_session,
            session.cancellation,
            &mut session.declaration_access,
            &[request],
            |_| {},
        )?;
        if !loaded {
            self.evaluation.cancellation_observed = true;
            return Ok(DeclarationAccessDecision::UnknownActivation);
        }
        Ok(session.declaration_access[&request].decision)
    }

    fn target(
        &mut self,
        target: SemanticId,
        request: &SelectedReceiverStepRequest<'_>,
    ) -> StoreResult<SelectedReceiverSlotRead> {
        let Some(properties) = self.declared_types(target)? else {
            return Ok(SelectedReceiverSlotRead::Cancelled);
        };
        let Some(property) = properties
            .iter()
            .find(|property| property.role() == DeclarationTypeRole::Identity)
        else {
            return Ok(SelectedReceiverSlotRead::Ready(TypedFrontierState::new(
                target,
                Vec::new(),
                incomplete(target),
            )));
        };
        let slot = property.slot();
        let Some(owner) = self.impl_owner(target)? else {
            return self.slot(slot);
        };
        let evaluation = &mut self.evaluation;
        let answers = Arc::clone(&evaluation.member_applicability_answers);
        let Some(selection) = evaluation.impl_subject_selection(
            owner.owner_frontier(),
            request.instantiation.application_slot,
            target,
            &answers,
            self.states,
        )?
        else {
            return Ok(SelectedReceiverSlotRead::Cancelled);
        };
        let substitution = CallTypeSubstitution {
            parameters: selection.substitutions.keys().copied().collect(),
            replacements: selection
                .substitutions
                .into_iter()
                .map(|(formal, (actual, _))| (formal, actual))
                .collect(),
        };
        let Some(instantiated) =
            evaluation.instantiated_bare_formal(slot, &substitution, &answers, self.states)?
        else {
            return Ok(SelectedReceiverSlotRead::Cancelled);
        };
        if let Some((actual, _)) = instantiated {
            return Ok(SelectedReceiverSlotRead::Ready(TypedFrontierState::new(
                slot,
                [ResolutionSlotValue::type_object(actual)],
                ResolutionCompletion::Complete,
            )));
        }
        self.slot(slot)
    }

    fn has_type_arguments(
        &mut self,
        application: SemanticId,
        nominal: SemanticId,
    ) -> StoreResult<Option<bool>> {
        let answers = Arc::clone(&self.evaluation.member_applicability_answers);
        Ok(self
            .evaluation
            .sparse_type_arguments_from_value(application, nominal, &answers, self.states)?
            .map(|selection| match selection {
                SparseReceiverOwnerTypeArguments::Known { arguments, .. } => !arguments.is_empty(),
                // An unknown application cannot prove that choosing either
                // Target's application slot would preserve its arguments.
                SparseReceiverOwnerTypeArguments::Unknown => true,
            }))
    }

    fn type_head_source(&mut self) -> &mut dyn SelectedTypeHeadSource {
        self.evaluation.session
    }

    fn poll_cancelled(&mut self) -> bool {
        self.evaluation.poll_cancelled()
    }

    fn slot(&mut self, slot: SemanticId) -> StoreResult<SelectedReceiverSlotRead> {
        if self.evaluation.poll_cancelled() {
            return Ok(SelectedReceiverSlotRead::Cancelled);
        }
        self.evaluation.demand_slot(slot);
        Ok(self
            .states
            .get(&slot)
            .map_or(SelectedReceiverSlotRead::Pending, |state| {
                SelectedReceiverSlotRead::Ready((**state).clone())
            }))
    }

    fn gap_origins(
        &mut self,
        reasons: &[SemanticId],
    ) -> StoreResult<Option<Vec<super::super::SelectedGapReasonProvenance>>> {
        let read = self
            .evaluation
            .session
            .gap_reason_provenance_for_reasons(reasons)?;
        Ok(self.evaluation.accept_session_read(read).map(|rows| {
            rows.into_iter()
                .map(|row| *row.get(self.evaluation.session))
                .collect()
        }))
    }

    fn declared_types(
        &mut self,
        definition: SemanticId,
    ) -> StoreResult<Option<Vec<LoweredDeclarationTypeProperty>>> {
        let read = self
            .evaluation
            .session
            .declaration_types_for_definitions(&[definition])?;
        Ok(self.evaluation.accept_session_read(read).map(|rows| {
            rows.into_iter()
                .map(|row| *row.get(self.evaluation.session).row())
                .collect()
        }))
    }
}
