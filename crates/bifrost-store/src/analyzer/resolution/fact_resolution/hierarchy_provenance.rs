//! Provider-qualified observations for one hierarchy operation.
//!
//! This graph is additive to HierarchyEvidence. In particular a complete read
//! has an observation even though its completion evidence is the neutral value.
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_PROVENANCE_GENERATION: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) struct HierarchyRequestIdentity {
    generation: u64,
    selection: usize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) struct HierarchyProvenanceId(usize);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum HierarchyProviderAuthority {
    Typed(super::super::fact_source::SelectedTypedRowIdentity),
    Context {
        mount: u32,
        version: i64,
        order: u32,
        blob: Option<BindingFragmentId>,
    },
    Intrinsic {
        descriptor: SemanticId,
    },
    /// Membership proven by the selected source declaration read.
    Declaration(SemanticId),
    Reference(SemanticId),
    /// Identifies an unanswered boundary, never a complete provider inventory.
    Boundary(SemanticId),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum HierarchyProviderOperand {
    NamespaceInventory,
    NamespaceScope,
    ReferenceResidual { reference: SemanticId },
    SupertypeTransfer { reference: SemanticId, ordinal: u32 },
    InventoryExclusion { reference: SemanticId, ordinal: u32 },
    SupertypeInventory,
    SupertypeEdge { reference: SemanticId, ordinal: u32 },
    CandidateInventory,
    PackageInventory,
    Definition { definition: SemanticId },
    Access { target: SemanticId },
    Transfer,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct HierarchyProviderKey {
    pub(crate) owner: SemanticId,
    pub(crate) lookup: SemanticId,
    pub(crate) namespace: ResolutionNamespace,
    pub(crate) authority: HierarchyProviderAuthority,
    pub(crate) operand: HierarchyProviderOperand,
    shape: Option<HierarchyLookupShape>,
    step: u32,
    /// Native occurrence identity, not an observation ID or a reason.
    occurrence: SemanticId,
}
impl HierarchyProviderKey {
    pub(crate) fn occurrence(&self) -> SemanticId {
        self.occurrence
    }
    /// A row authority from a source/package/access reader. The caller supplies
    /// structured coordinates, never a rendered FQN as a substitute for them.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn source(
        owner: SemanticId,
        lookup: SemanticId,
        namespace: ResolutionNamespace,
        authority: HierarchyProviderAuthority,
        operand: HierarchyProviderOperand,
        occurrence: SemanticId,
        step: u32,
    ) -> Self {
        Self {
            owner,
            lookup,
            namespace,
            authority,
            operand,
            shape: None,
            occurrence,
            step,
        }
    }

    pub(super) fn with_operand(&self, operand: HierarchyProviderOperand) -> Self {
        Self {
            operand,
            ..self.clone()
        }
    }

    pub(super) fn new(
        key: HierarchyNodeKey,
        authority: HierarchyProviderAuthority,
        operand: HierarchyProviderOperand,
    ) -> Self {
        Self {
            owner: key.owner,
            lookup: key.shape.lookup,
            namespace: key.shape.namespace,
            authority,
            operand,
            shape: Some(key.shape),
            step: 0,
            occurrence: match operand {
                HierarchyProviderOperand::SupertypeEdge { reference, .. }
                | HierarchyProviderOperand::SupertypeTransfer { reference, .. }
                | HierarchyProviderOperand::ReferenceResidual { reference }
                | HierarchyProviderOperand::InventoryExclusion { reference, .. } => reference,
                _ => key.owner,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum HierarchyProviderVisit {
    Observed,
    Cutoff,
    NotSearched,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct HierarchyProviderObservation {
    pub(crate) provider: HierarchyProviderKey,
    pub(crate) visit: HierarchyProviderVisit,
    pub(crate) completion: ResolutionCompletion,
    pub(crate) inventory_complete: Option<bool>,
}

#[derive(Debug)]
enum ProviderEvidence {
    Resolution(HierarchyEvidence),
    Transfer(HierarchyEvidence),
}

#[derive(Debug)]
enum ProvenanceNode {
    Exact(HierarchyProviderObservation),
    Empty,
    Observation {
        provider: HierarchyProviderKey,
        visit: HierarchyProviderVisit,
        evidence: ProviderEvidence,
        inventory_complete: Option<bool>,
    },
    Join(HierarchyProvenanceId, HierarchyProvenanceId),
    Shift {
        ticks: u32,
        child: HierarchyProvenanceId,
    },
    Select {
        cutoff_tick: u32,
        child: HierarchyProvenanceId,
    },
}

#[derive(Debug)]
pub(super) struct HierarchyProvenanceArena {
    generation: u64,
    nodes: Vec<ProvenanceNode>,
    joins: HashMap<(HierarchyProvenanceId, HierarchyProvenanceId), HierarchyProvenanceId>,
}
impl Default for HierarchyProvenanceArena {
    fn default() -> Self {
        Self {
            generation: NEXT_PROVENANCE_GENERATION.fetch_add(1, Ordering::Relaxed),
            nodes: vec![ProvenanceNode::Empty],
            joins: HashMap::default(),
        }
    }
}
impl HierarchyProvenanceArena {
    fn push(&mut self, node: ProvenanceNode) -> HierarchyProvenanceId {
        let id = HierarchyProvenanceId(self.nodes.len());
        self.nodes.push(node);
        id
    }
    pub(super) fn exact(
        &mut self,
        observation: HierarchyProviderObservation,
    ) -> HierarchyProvenanceId {
        self.push(ProvenanceNode::Exact(observation))
    }

    pub(super) fn observe(
        &mut self,
        provider: HierarchyProviderKey,
        visit: HierarchyProviderVisit,
        evidence: HierarchyEvidence,
    ) -> HierarchyProvenanceId {
        self.push(ProvenanceNode::Observation {
            provider,
            visit,
            evidence: ProviderEvidence::Resolution(evidence),
            inventory_complete: None,
        })
    }
    pub(super) fn observe_transfer(
        &mut self,
        provider: HierarchyProviderKey,
        visit: HierarchyProviderVisit,
        evidence: HierarchyEvidence,
    ) -> HierarchyProvenanceId {
        self.push(ProvenanceNode::Observation {
            provider,
            visit,
            evidence: ProviderEvidence::Transfer(evidence),
            inventory_complete: None,
        })
    }
    pub(super) fn observe_inventory(
        &mut self,
        provider: HierarchyProviderKey,
        complete: bool,
        evidence: HierarchyEvidence,
    ) -> HierarchyProvenanceId {
        self.push(ProvenanceNode::Observation {
            provider,
            visit: HierarchyProviderVisit::Observed,
            evidence: ProviderEvidence::Resolution(evidence),
            inventory_complete: Some(complete),
        })
    }
    pub(super) fn authority(
        &self,
        id: HierarchyProvenanceId,
    ) -> Option<HierarchyProviderAuthority> {
        match &self.nodes[id.0] {
            ProvenanceNode::Observation { provider, .. } => Some(provider.authority.clone()),
            ProvenanceNode::Exact(observation) => Some(observation.provider.authority.clone()),
            _ => None,
        }
    }
    pub(super) fn join(
        &mut self,
        left: HierarchyProvenanceId,
        right: HierarchyProvenanceId,
    ) -> HierarchyProvenanceId {
        if left == HierarchyProvenanceId::default() || left == right {
            return right;
        }
        if right == HierarchyProvenanceId::default() {
            return left;
        }
        if let Some(&id) = self.joins.get(&(left, right)) {
            return id;
        }
        let id = self.push(ProvenanceNode::Join(left, right));
        self.joins.insert((left, right), id);
        id
    }
    pub(super) fn shift(
        &mut self,
        child: HierarchyProvenanceId,
        ticks: u32,
    ) -> HierarchyProvenanceId {
        if ticks == 0 || child == HierarchyProvenanceId::default() {
            return child;
        }
        self.push(ProvenanceNode::Shift { ticks, child })
    }
    pub(super) fn select(
        &mut self,
        child: HierarchyProvenanceId,
        cutoff_tick: u32,
    ) -> HierarchyProvenanceId {
        if child == HierarchyProvenanceId::default() || cutoff_tick == u32::MAX {
            return child;
        }
        self.push(ProvenanceNode::Select { cutoff_tick, child })
    }
}

#[derive(Clone, Copy, Debug, Default)]
#[doc(hidden)]
pub struct HierarchySelectionProvenance {
    pub(super) root: HierarchyProvenanceId,
    identity: HierarchyRequestIdentity,
}

#[derive(Default)]
pub(crate) struct ProviderObservationStore {
    observations: HashMap<HierarchyProviderKey, HierarchyProviderObservation>,
    order: Vec<HierarchyProviderKey>,
}
impl ProviderObservationStore {
    pub(crate) fn get(&self, key: &HierarchyProviderKey) -> Option<&HierarchyProviderObservation> {
        self.observations.get(key)
    }
    pub(crate) fn retain(
        &mut self,
        observation: HierarchyProviderObservation,
        cancelled: &mut dyn FnMut() -> bool,
    ) -> bool {
        if let Some(previous) = self.observations.get_mut(&observation.provider) {
            // NotSearched has no completion snapshot to compare. All
            // actual reads for one exact occurrence must agree.
            if previous.visit != HierarchyProviderVisit::NotSearched
                && observation.visit != HierarchyProviderVisit::NotSearched
            {
                let Some(equal) = completions_equal_with_poll(
                    &previous.completion,
                    &observation.completion,
                    cancelled,
                ) else {
                    return false;
                };
                assert!(
                    equal,
                    "one exact provider occurrence has conflicting completions for {:?}: previous={:?}, current={:?}",
                    observation.provider, previous.completion, observation.completion
                );
                assert_eq!(
                    previous.inventory_complete, observation.inventory_complete,
                    "one exact provider occurrence has conflicting inventory snapshots"
                );
            }
            let precedence = |state| match state {
                HierarchyProviderVisit::NotSearched => 0,
                HierarchyProviderVisit::Cutoff => 1,
                HierarchyProviderVisit::Observed => 2,
            };
            if precedence(observation.visit) > precedence(previous.visit) {
                *previous = observation;
            }
        } else {
            self.order.push(observation.provider.clone());
            self.observations
                .insert(observation.provider.clone(), observation);
        }
        true
    }
    pub(crate) fn visit(
        &self,
        cancelled: &mut dyn FnMut() -> bool,
        visitor: &mut dyn FnMut(&HierarchyProviderObservation) -> StoreResult<()>,
    ) -> StoreResult<bool> {
        for key in &self.order {
            if cancelled() {
                return Ok(false);
            }
            visitor(&self.observations[key])?;
        }
        Ok(true)
    }
    pub(crate) fn finish(
        mut self,
        cancelled: &mut dyn FnMut() -> bool,
    ) -> Option<Box<[HierarchyProviderObservation]>> {
        let mut observations = Vec::with_capacity(self.order.len());
        for key in self.order {
            if cancelled() {
                return None;
            }
            observations.push(
                self.observations
                    .remove(&key)
                    .expect("one provider observation per exact key"),
            );
        }
        Some(observations.into_boxed_slice())
    }
}

/// A borrowed capability cannot expand hierarchy edges or mutate the operation.
#[derive(Clone, Copy)]
#[doc(hidden)]
pub struct HierarchyProvenanceView<'a> {
    pub(super) hierarchy: &'a HierarchyOperationArena,
}
impl<'a> HierarchyProvenanceView<'a> {
    pub(super) fn new(hierarchy: &'a HierarchyOperationArena) -> Self {
        Self { hierarchy }
    }
    pub(crate) fn identity(&self) -> HierarchyRequestIdentity {
        // This request-owned authority is tied to the fixed selected operation.
        // The address is only a lease discriminator; it is never a semantic ID.
        HierarchyRequestIdentity {
            generation: self.hierarchy.provenance.generation,
            selection: Arc::as_ptr(&self.hierarchy.operation_identities) as usize,
        }
    }
    pub(super) fn selection(&self, root: HierarchyProvenanceId) -> HierarchySelectionProvenance {
        HierarchySelectionProvenance {
            root,
            identity: self.identity(),
        }
    }
    pub(crate) fn assert_selection(&self, selection: HierarchySelectionProvenance) {
        self.assert_identity(selection.identity);
        assert!(
            selection.root.0 < self.hierarchy.provenance.nodes.len(),
            "a provenance handle names a current expression"
        );
    }
    pub(crate) fn assert_identity(&self, identity: HierarchyRequestIdentity) {
        assert_eq!(
            identity,
            self.identity(),
            "hierarchy handle escaped its request or selection"
        );
    }
    pub(crate) fn visit(
        &self,
        selection: HierarchySelectionProvenance,
        cancelled: &mut dyn FnMut() -> bool,
        visitor: &mut dyn FnMut(&HierarchyProviderObservation) -> StoreResult<()>,
    ) -> StoreResult<bool> {
        self.assert_identity(selection.identity);
        let mut observations = ProviderObservationStore::default();
        let mut pending = vec![(selection.root, 0_u32, u32::MAX)];
        let mut visited = HashSet::default();
        while let Some((id, ticks, cutoff)) = pending.pop() {
            if cancelled() {
                return Ok(false);
            }
            if !visited.insert((id, ticks, cutoff)) {
                continue;
            }
            match &self.hierarchy.provenance.nodes[id.0] {
                ProvenanceNode::Exact(observation) => {
                    let mut observation = observation.clone();
                    if ticks > cutoff && observation.visit == HierarchyProviderVisit::Observed {
                        observation.visit = HierarchyProviderVisit::Cutoff;
                    }
                    if !observations.retain(observation, cancelled) {
                        return Ok(false);
                    }
                }
                ProvenanceNode::Empty => {}
                ProvenanceNode::Join(left, right) => {
                    pending.push((*right, ticks, cutoff));
                    pending.push((*left, ticks, cutoff));
                }
                ProvenanceNode::Shift {
                    ticks: shift,
                    child,
                } => pending.push((
                    *child,
                    ticks
                        .checked_add(*shift)
                        .expect("hierarchy provenance depth fits u32"),
                    cutoff,
                )),
                ProvenanceNode::Select { cutoff_tick, child } => pending.push((
                    *child,
                    ticks,
                    cutoff.min(ticks.saturating_add(*cutoff_tick)),
                )),
                ProvenanceNode::Observation {
                    provider,
                    visit,
                    evidence,
                    inventory_complete,
                } => {
                    let completion =
                        match evidence {
                            ProviderEvidence::Resolution(evidence) => self
                                .hierarchy
                                .evidence
                                .flatten(evidence, u32::MAX, cancelled),
                            ProviderEvidence::Transfer(evidence) => self
                                .hierarchy
                                .transfers
                                .flatten(evidence, u32::MAX, cancelled),
                        };
                    let Some(completion) = completion else {
                        return Ok(false);
                    };
                    let visit = if *visit == HierarchyProviderVisit::Observed && ticks > cutoff {
                        HierarchyProviderVisit::Cutoff
                    } else {
                        *visit
                    };
                    let observation = HierarchyProviderObservation {
                        provider: provider.clone(),
                        visit,
                        completion,
                        inventory_complete: *inventory_complete,
                    };
                    if !observations.retain(observation, cancelled) {
                        return Ok(false);
                    }
                }
            }
        }
        observations.visit(cancelled, visitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> HierarchyProviderKey {
        let owner = SemanticId::for_test("provenance-owner");
        HierarchyProviderKey::new(
            HierarchyNodeKey {
                owner,
                shape: HierarchyLookupShape::new(
                    SemanticId::for_test("provenance-lookup"),
                    ResolutionNamespace::Type,
                    QualifierCategory::Type,
                    0,
                ),
            },
            HierarchyProviderAuthority::Declaration(owner),
            HierarchyProviderOperand::NamespaceInventory,
        )
    }

    #[test]
    fn shared_closer_empty_cached_summary_keeps_distinct_provider_snapshots() {
        let mut arena = HierarchyOperationArena::default();
        let key = key();
        let first = arena.provenance.observe(
            key.clone(),
            HierarchyProviderVisit::Observed,
            HierarchyEvidence::Complete,
        );
        let mut other = key.clone();
        other.authority = HierarchyProviderAuthority::Context {
            mount: 1,
            version: 7,
            order: 2,
            blob: None,
        };
        let reason =
            ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::for_test("provider-gap"));
        let evidence = arena
            .evidence
            .one(
                SemanticId::for_test("provider-atom"),
                ResolutionCompletion::incomplete([reason]),
                &mut || false,
            )
            .unwrap();
        let skipped = arena.provenance.observe(
            other.clone(),
            HierarchyProviderVisit::NotSearched,
            HierarchyEvidence::Complete,
        );
        let read =
            arena
                .provenance
                .observe(other, HierarchyProviderVisit::Observed, evidence.clone());
        let joined = arena.provenance.join(first, skipped);
        let joined = arena.provenance.join(joined, read);
        let node = HierarchyNodeKey {
            owner: key.owner,
            shape: key.shape.unwrap(),
        };
        let order = arena.order.owner(key.owner, Vec::new(), joined, false);
        arena.stage_summary(
            1,
            node,
            HierarchyStructuralSummary {
                order,
                provenance: joined,
                candidate_distance: None,
                candidates: None,
                evidence,
                transfer: HierarchyEvidence::Complete,
                retains_global_evidence: false,
            },
        );
        arena.commit_publication(1);
        let cached = arena.summary(node).unwrap();
        assert!(cached.candidates.is_none());
        let view = HierarchyProvenanceView::new(&arena);
        let mut seen = Vec::new();
        assert!(
            view.visit(
                view.selection(cached.provenance),
                &mut || false,
                &mut |observation| {
                    seen.push((
                        observation.provider.clone(),
                        observation.visit,
                        observation.completion.clone(),
                    ));
                    Ok(())
                }
            )
            .unwrap()
        );
        assert_eq!(
            seen.len(),
            2,
            "same owner and lookup do not merge distinct authorities"
        );
        assert_eq!(seen[0].2, ResolutionCompletion::Complete);
        assert_eq!(seen[1].1, HierarchyProviderVisit::Observed);
        assert_eq!(seen[1].2, ResolutionCompletion::incomplete([reason]));
    }

    #[test]
    #[should_panic(expected = "conflicting completions")]
    fn shared_closer_provider_snapshot_conflict_is_not_visit_precedence() {
        let mut arena = HierarchyOperationArena::default();
        let key = key();
        let closed = arena.provenance.observe(
            key.clone(),
            HierarchyProviderVisit::Observed,
            HierarchyEvidence::Complete,
        );
        let evidence = arena
            .evidence
            .one(
                SemanticId::for_test("conflicting-provider-atom"),
                ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::for_test(
                        "conflicting-provider-gap",
                    )),
                ]),
                &mut || false,
            )
            .unwrap();
        let open = arena
            .provenance
            .observe(key, HierarchyProviderVisit::Observed, evidence);
        let joined = arena.provenance.join(closed, open);
        let view = HierarchyProvenanceView::new(&arena);
        view.visit(view.selection(joined), &mut || false, &mut |_| Ok(()))
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "escaped its request or selection")]
    fn shared_closer_provider_handle_cannot_cross_requests() {
        let first = HierarchyOperationArena::default();
        let handle =
            HierarchyProvenanceView::new(&first).selection(HierarchyProvenanceId::default());
        let second = HierarchyOperationArena::default();
        HierarchyProvenanceView::new(&second)
            .visit(handle, &mut || false, &mut |_| Ok(()))
            .unwrap();
    }
}
