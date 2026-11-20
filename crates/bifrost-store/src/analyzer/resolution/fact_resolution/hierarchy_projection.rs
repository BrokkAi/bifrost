//! Request-local drain of one hierarchy-only walk. Identities and evidence
//! belong to the operation that ran the walk; nothing here outlives it.
use super::*;

/// One declared or implicit base of an owner, with every target the walk bound.
#[derive(Debug)]
#[doc(hidden)]
pub struct HierarchyEdgeProjection {
    pub implicit: bool,
    pub kind: Option<crate::analyzer::resolution::NominalSupertypeKind>,
    pub implicit_undecided: bool,
    pub implicit_external: bool,
    pub ordinal: u32,
    pub reference: SemanticId,
    pub targets: Vec<SemanticId>,
    /// What keeps the base's binding from being exact. A bound target makes the
    /// shared member walk ignore it; an unbound edge is open because of it.
    pub binding: ResolutionCompletion,
    /// Evidence about the reference that holds whether or not it bound.
    pub residual: ResolutionCompletion,
    /// Type-argument transfer evidence.
    pub transfer: ResolutionCompletion,
}

/// An owner reached by the walk. `expanded` is false when the walk stopped
/// before reading this owner's edges.
#[derive(Debug)]
#[doc(hidden)]
pub struct HierarchyNodeProjection {
    pub owner: SemanticId,
    pub expanded: bool,
    pub inventory_complete: bool,
    pub cyclic: bool,
    pub completion: ResolutionCompletion,
    pub edges: Vec<HierarchyEdgeProjection>,
}

#[derive(Debug)]
#[doc(hidden)]
pub struct HierarchyProjection {
    pub stop: Option<HierarchyStop>,
    pub root: SemanticId,
    /// The selected linearization, root first. Empty unless the order is complete
    /// and one was requested; a direct-bases request has no order and its
    /// `nodes` holds only the root.
    pub order: Vec<SemanticId>,
    pub order_complete: bool,
    pub order_completion: ResolutionCompletion,
    /// Every owner the walk reached, depth first in edge order from the root.
    pub nodes: Vec<HierarchyNodeProjection>,
    /// The walk's aggregate evidence, including budget and cancellation stops.
    pub completion: ResolutionCompletion,
}

impl FactResolutionOperation<'_> {
    pub(crate) fn prove_guard_by_demand(
        &mut self,
        request: demand_scheduler::HierarchyDemandRequest,
        rule: crate::analyzer::resolution::BasePreservationRule,
        provider: &mut (impl DemandRootProvider + ?Sized),
    ) -> StoreResult<bool> {
        self.with_demand_resources(|resources| {
            demand_scheduler::prove_guard(resources, provider, request, rule)
        })
    }

    /// Source operands whose copies support the effective base binding.
    pub(crate) fn hierarchy_alias_sources(&self, reference: SemanticId) -> &[SemanticId] {
        self.hierarchy
            .alias_source_references
            .get(&reference)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// Select a class's declared bases and ordered ancestry without a member
    /// lookup, and drain the result before this operation's arena ends.
    pub(crate) fn resolve_hierarchy_by_demand(
        &mut self,
        request: demand_scheduler::HierarchyDemandRequest,
        provider: &mut (impl DemandRootProvider + ?Sized),
    ) -> StoreResult<Option<HierarchyProjection>> {
        let root = request.root;
        let policy = request.policy.identity();
        let (selection, completion, stop) = self.with_demand_resources(|resources| {
            demand_scheduler::select_hierarchy(resources, provider, request)
        })?;
        debug_assert_eq!(
            selection.is_none(),
            stop.is_some(),
            "unselected hierarchy has a typed stop"
        );
        let cancellation = self.session.cancellation;
        let mut owners = Vec::new();
        // A request with no order reads the root's own edges and nothing else.
        let order = selection.and_then(|selection| selection.order);
        let ordered = order.is_some();
        let status = if let Some(order) = order {
            let view = HierarchyProvenanceView::new(&self.hierarchy);
            let status = view.order_status(order);
            let (complete, completion) = (status.complete, status.completion.clone());
            if !view.visit_order(order, &mut || cancellation.is_cancelled(), &mut |entry| {
                debug_assert_eq!(entry.root, root);
                owners.push(entry.owner);
                Ok(())
            })? {
                return Ok(None);
            }
            (complete, completion)
        } else {
            (false, ResolutionCompletion::Complete)
        };
        let mut nodes = Vec::new();
        let mut seen = HashSet::default();
        let mut pending = vec![root];
        seen.insert(root);
        while let Some(owner) = pending.pop() {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let key = HierarchyOwnerKey { owner, policy };
            let cyclic = self.hierarchy.cycle(key).is_some();
            let Some(stored) = self.hierarchy.edge_nodes.get(&key) else {
                nodes.push(HierarchyNodeProjection {
                    owner,
                    expanded: false,
                    inventory_complete: false,
                    cyclic,
                    completion: ResolutionCompletion::Complete,
                    edges: Vec::new(),
                });
                continue;
            };
            let flatten = |evidence: &HierarchyEvidence, arena: &HierarchyEvidenceArena| {
                arena.flatten(evidence, u32::MAX, &mut || cancellation.is_cancelled())
            };
            let Some(completion) = flatten(&stored.evidence, &self.hierarchy.evidence) else {
                return Ok(None);
            };
            let inventory_complete = stored.hierarchy_inventory_complete;
            let mut edges = Vec::with_capacity(stored.edges.len());
            for nominal in stored.edges.nominal() {
                let edge = &nominal.edge;
                let (Some(residual), Some(hierarchy), Some(transfer)) = (
                    flatten(&edge.residual_evidence, &self.hierarchy.evidence),
                    flatten(&edge.hierarchy_evidence, &self.hierarchy.evidence),
                    flatten(&edge.transfer, &self.hierarchy.transfers),
                ) else {
                    return Ok(None);
                };
                edges.push(HierarchyEdgeProjection {
                    implicit: matches!(edge.authority, HierarchyBaseOrigin::Implicit { .. }),
                    implicit_external: matches!(
                        edge.authority,
                        HierarchyBaseOrigin::Implicit { external: true, .. }
                    ),
                    implicit_undecided: matches!(
                        edge.authority,
                        HierarchyBaseOrigin::Implicit {
                            definite: false,
                            ..
                        }
                    ),
                    kind: nominal.kind,
                    ordinal: edge.parent_ordinal,
                    reference: edge.reference,
                    targets: edge.targets.to_vec(),
                    binding: hierarchy,
                    residual,
                    transfer,
                });
            }
            if ordered {
                for edge in edges.iter().rev() {
                    for &target in edge.targets.iter().rev() {
                        if seen.insert(target) {
                            pending.push(target);
                        }
                    }
                }
            }
            nodes.push(HierarchyNodeProjection {
                owner,
                expanded: true,
                inventory_complete,
                cyclic,
                completion,
                edges,
            });
        }
        Ok(Some(HierarchyProjection {
            stop,
            root,
            order: owners,
            order_complete: status.0,
            order_completion: status.1,
            nodes,
            completion,
        }))
    }
}
