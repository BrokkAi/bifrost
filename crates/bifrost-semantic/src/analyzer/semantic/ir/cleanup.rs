//! Procedure-local immutable cleanup chains. Nodes own only their new entries.
use super::{
    ControlEdgeKind, LifecycleIncompleteReason, PointerInvalidationCause,
    PointerInvalidationTarget, PointerRelationStrength, SemanticPlace,
};
use crate::analyzer::semantic::cfg::{CleanupRegionId, CompletionKind, ScopeCleanupAction};
use crate::analyzer::semantic::ids::{EvidenceId, ProgramPointId, SourceMappingId, ValueId};
use brokk_bifrost_core::hash::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CleanupChainNodeId(u32);
impl CleanupChainNodeId {
    pub fn new(raw: u32) -> Self {
        Self(raw)
    }
    pub fn index(self) -> usize {
        self.0 as usize
    }
}

/// Stable reference to one action in an immutable procedure-local chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CleanupActionCursor {
    node: CleanupChainNodeId,
    ordinal: u32,
}
impl CleanupActionCursor {
    pub fn node(self) -> CleanupChainNodeId {
        self.node
    }
    pub fn ordinal(self) -> usize {
        self.ordinal as usize
    }
}

/// Canonical procedure-local selected-action projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CleanupProjectionId(u32);
impl CleanupProjectionId {
    pub fn new(raw: u32) -> Self {
        Self(raw)
    }
    pub fn index(self) -> usize {
        self.0 as usize
    }
}

/// Inclusive head and exclusive ancestor stop. None is the empty sentinel.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CleanupSegment {
    pub head: Option<CleanupChainNodeId>,
    pub stop: Option<CleanupChainNodeId>,
}
impl CleanupSegment {
    pub fn is_empty(self) -> bool {
        self.head == self.stop
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CleanupActionIncomplete {
    pub reason: LifecycleIncompleteReason,
    pub evidence: EvidenceId,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CleanupActionEntry {
    pub action: ScopeCleanupAction,
    pub incomplete: Option<CleanupActionIncomplete>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CleanupOwnerLifecycle {
    None,
    ScopeEnd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CleanupOwnerInvalidation {
    pub target: PointerInvalidationTarget,
    pub cause: PointerInvalidationCause,
    pub strength: PointerRelationStrength,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CleanupOwnerEntry {
    pub value: ValueId,
    pub place: SemanticPlace,
    pub lifecycle: CleanupOwnerLifecycle,
    pub invalidation: Option<CleanupOwnerInvalidation>,
    pub source: SourceMappingId,
    pub evidence: EvidenceId,
}

/// Entry order is the producer's order, followed by this node's region boundary.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CleanupChainNode {
    pub parent: Option<CleanupChainNodeId>,
    pub region: Option<CleanupRegionId>,
    pub actions: Box<[CleanupActionEntry]>,
    pub owners: Box<[CleanupOwnerEntry]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CleanupAnchorPurpose {
    Completion,
    LifetimeEnd,
    Exit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CleanupAnchor {
    pub point: ProgramPointId,
    pub segment: CleanupSegment,
    pub destination: ProgramPointId,
    pub destination_kind: CompletionKind,
    pub edge_kind: ControlEdgeKind,
    pub purpose: CleanupAnchorPurpose,
    pub projection: Option<CleanupProjectionId>,
    /// Counts of direct rows at publication, used to merge logical fact order.
    pub drop_offset: u32,
    pub scope_end_offset: u32,
    pub incomplete_offset: u32,
    pub pointer_invalidation_offset: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupRegionKind {
    ImplicitLifetime,
    Explicit,
}

#[derive(Default, Clone)]
struct CleanupMembership {
    ancestor_intervals: Box<[(usize, usize)]>,
    owner_introductions: Box<[(ValueId, CleanupChainNodeId)]>,
    // Owner entries on each node's path to its root, inclusive. A segment's
    // head path minus its stop path is the segment, so nonemptiness is O(1).
    owner_path_counts: Box<[usize]>,
}
impl CleanupMembership {
    fn new(
        nodes: &[CleanupChainNode],
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
        validation_steps: &mut usize,
    ) -> Result<Self, CleanupChainsError> {
        // Build the procedure-local ancestry view once, with no recursive walk.
        let mut children = vec![Vec::new(); nodes.len()];
        let mut roots = Vec::new();
        for (index, node) in nodes.iter().enumerate() {
            *validation_steps += 1;
            if cancellation.is_cancelled() {
                return Err(CleanupChainsError::Cancelled);
            }
            if let Some(parent) = node.parent {
                children[parent.index()].push(index);
            } else {
                roots.push(index);
            }
        }
        let mut ancestor_intervals = vec![(0, 0); nodes.len()];
        let mut owner_path_counts = vec![0; nodes.len()];
        let mut clock = 0;
        let mut stack = Vec::new();
        for root in roots {
            stack.push((root, false));
            while let Some((index, exiting)) = stack.pop() {
                *validation_steps += 1;
                if cancellation.is_cancelled() {
                    return Err(CleanupChainsError::Cancelled);
                }
                if exiting {
                    ancestor_intervals[index].1 = clock;
                } else {
                    ancestor_intervals[index].0 = clock;
                    clock += 1;
                    // Preorder enters a parent before its children.
                    owner_path_counts[index] = nodes[index].owners.len()
                        + nodes[index]
                            .parent
                            .map_or(0, |parent| owner_path_counts[parent.index()]);
                    stack.push((index, true));
                    stack.extend(children[index].iter().rev().map(|child| (*child, false)));
                }
            }
        }
        let mut owner_introductions = Vec::new();
        for (index, node) in nodes.iter().enumerate() {
            *validation_steps += 1;
            for owner in &node.owners {
                *validation_steps += 1;
                if cancellation.is_cancelled() {
                    return Err(CleanupChainsError::Cancelled);
                }
                owner_introductions.push((owner.value, CleanupChainNodeId::new(index as u32)));
            }
        }
        owner_introductions.sort_unstable_by_key(|(owner, node)| (*owner, node.index()));
        owner_introductions.dedup();
        Ok(Self {
            ancestor_intervals: ancestor_intervals.into_boxed_slice(),
            owner_introductions: owner_introductions.into_boxed_slice(),
            owner_path_counts: owner_path_counts.into_boxed_slice(),
        })
    }
    fn has_owners(&self, segment: CleanupSegment) -> bool {
        debug_assert!(self.is_ancestor(segment.stop, segment.head));
        let count = |node: Option<CleanupChainNodeId>| {
            node.map_or(0, |node| self.owner_path_counts[node.index()])
        };
        count(segment.head) > count(segment.stop)
    }
    /// The empty sentinel is an ancestor of every node.
    pub fn is_ancestor(
        &self,
        ancestor: Option<CleanupChainNodeId>,
        descendant: Option<CleanupChainNodeId>,
    ) -> bool {
        match (ancestor, descendant) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(ancestor), Some(descendant)) => {
                let (start, end) = self.ancestor_intervals[ancestor.index()];
                let (point, _) = self.ancestor_intervals[descendant.index()];
                start <= point && point < end
            }
        }
    }
    pub fn contains_owner(&self, segment: CleanupSegment, owner: ValueId) -> bool {
        let start = self
            .owner_introductions
            .partition_point(|(value, _)| *value < owner);
        self.owner_introductions[start..]
            .iter()
            .take_while(|(value, _)| *value == owner)
            .any(|(_, node)| {
                self.is_ancestor(Some(*node), segment.head)
                    && !self.is_ancestor(Some(*node), segment.stop)
            })
    }
}

/// Canonicalization is construction-only; immutable artifacts retain no hash table.
#[derive(Default)]
pub struct CleanupChainBuilder {
    membership: Option<CleanupMembership>,
    pub(crate) construction_steps: usize,
    nodes: Vec<CleanupChainNode>,
    region_kinds: HashMap<CleanupRegionId, CleanupRegionKind>,
    route_prefix: Vec<[usize; 3]>,
    projection_counts: Vec<[usize; 2]>,
    canonical: HashMap<CleanupChainNode, CleanupChainNodeId>,
    anchors: Vec<CleanupAnchor>,
    projections: Vec<Box<[CleanupActionCursor]>>,
    projection_keys: HashMap<Vec<CleanupActionCursor>, CleanupProjectionId>,
}
impl CleanupChainBuilder {
    pub fn mark_implicit_lifetime_region(&mut self, region: CleanupRegionId) {
        assert!(
            !self.region_kinds.contains_key(&region),
            "mark before interning region"
        );
        self.region_kinds
            .insert(region, CleanupRegionKind::ImplicitLifetime);
    }
    pub fn route_counts(
        &self,
        segment: CleanupSegment,
        projection: Option<CleanupProjectionId>,
    ) -> [usize; 3] {
        let count =
            |id: Option<CleanupChainNodeId>| id.map_or([0; 3], |id| self.route_prefix[id.index()]);
        let head = count(segment.head);
        let stop = count(segment.stop);
        let mut result = std::array::from_fn(|i| head[i] - stop[i]);
        if let Some(id) = projection {
            result[..2].copy_from_slice(&self.projection_counts[id.index()]);
        }
        result
    }
    pub fn pending_membership_entries(&self) -> usize {
        if self.membership.is_some() {
            return 0;
        }
        // Intervals, DFS adjacency/stack and introduction postings are all
        // bounded by these procedure-local node and owner counts.
        6 * self.nodes.len()
            + self
                .nodes
                .iter()
                .map(|node| node.owners.len())
                .sum::<usize>()
    }

    pub fn contains_owner(&mut self, segment: CleanupSegment, owner: ValueId) -> bool {
        let chains = self.membership.get_or_insert_with(|| {
            CleanupMembership::new(
                &self.nodes,
                &brokk_bifrost_core::cancellation::CancellationToken::default(),
                &mut self.construction_steps,
            )
            .expect("the default cancellation token is never cancelled")
        });
        chains.contains_owner(segment, owner)
    }

    pub fn intern(&mut self, node: CleanupChainNode) -> CleanupChainNodeId {
        self.construction_steps += 1 + node.actions.len() + node.owners.len();
        if let Some(id) = self.canonical.get(&node) {
            return *id;
        }
        self.membership = None;
        if let Some(parent) = node.parent {
            assert!(parent.index() < self.nodes.len());
        }
        let id = CleanupChainNodeId::new(
            u32::try_from(self.nodes.len()).expect("cleanup arena fits u32"),
        );
        let mut prefix = node
            .parent
            .map_or([0; 3], |id| self.route_prefix[id.index()]);
        for entry in &node.actions {
            self.construction_steps += 1;
            prefix[0] += usize::from(matches!(
                entry.action,
                ScopeCleanupAction::Drop {
                    behavior: crate::analyzer::semantic::DropBehavior::Destructor(_),
                    ..
                }
            ));
            prefix[1] += usize::from(entry.incomplete.is_some());
        }
        if let Some(region) = node.region {
            prefix[2] += usize::from(
                *self
                    .region_kinds
                    .entry(region)
                    .or_insert(CleanupRegionKind::Explicit)
                    == CleanupRegionKind::Explicit,
            );
        }
        self.route_prefix.push(prefix);
        self.canonical.insert(node.clone(), id);
        self.nodes.push(node);
        id
    }
    /// Logical registration order within each scope, followed by its boundary.
    pub fn entries(&self, segment: CleanupSegment) -> CleanupEntries<'_> {
        CleanupEntries {
            nodes: &self.nodes,
            cursor: segment.head,
            stop: segment.stop,
            chunks: Vec::new(),
            current: None,
            current_id: None,
            action: 0,
            owner: 0,
            region: None,
        }
    }
    pub fn route_entries(
        &self,
        segment: CleanupSegment,
        projection: Option<CleanupProjectionId>,
    ) -> CleanupRouteEntries<'_> {
        CleanupRouteEntries {
            entries: self.entries(segment),
            selected: projection.map(|id| self.projection(id)),
            position: 0,
        }
    }
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
    pub fn node(&self, id: CleanupChainNodeId) -> &CleanupChainNode {
        &self.nodes[id.index()]
    }
    pub fn action_cursor(&self, node: CleanupChainNodeId, ordinal: usize) -> CleanupActionCursor {
        assert!(
            ordinal < self.node(node).actions.len(),
            "cleanup action ordinal exists"
        );
        CleanupActionCursor {
            node,
            ordinal: u32::try_from(ordinal).expect("cleanup ordinal fits u32"),
        }
    }
    pub fn action(&self, cursor: CleanupActionCursor) -> &CleanupActionEntry {
        &self.node(cursor.node).actions[cursor.ordinal()]
    }
    pub fn intern_projection(&mut self, actions: Vec<CleanupActionCursor>) -> CleanupProjectionId {
        self.construction_steps += 1 + actions.len();
        if let Some(id) = self.projection_keys.get(&actions) {
            return *id;
        }
        let id = CleanupProjectionId::new(
            u32::try_from(self.projections.len()).expect("projection arena fits u32"),
        );
        let mut counts = [0; 2];
        for cursor in &actions {
            self.construction_steps += 1;
            let entry = self.action(*cursor);
            counts[0] += usize::from(matches!(
                entry.action,
                ScopeCleanupAction::Drop {
                    behavior: crate::analyzer::semantic::DropBehavior::Destructor(_),
                    ..
                }
            ));
            counts[1] += usize::from(entry.incomplete.is_some());
        }
        self.projection_counts.push(counts);
        self.projections.push(actions.clone().into_boxed_slice());
        self.projection_keys.insert(actions, id);
        id
    }
    pub fn projection(&self, id: CleanupProjectionId) -> &[CleanupActionCursor] {
        &self.projections[id.index()]
    }
    pub fn projection_entries(&self) -> usize {
        self.projections.len()
            + self
                .projections
                .iter()
                .map(|projection| projection.len())
                .sum::<usize>()
    }
    pub fn append_anchor(&mut self, anchor: CleanupAnchor) {
        self.anchors.push(anchor);
    }
    pub fn finish(
        self,
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> Result<CleanupChains, CleanupChainsError> {
        let mut chains =
            CleanupChains::checked(self.nodes, self.anchors, self.projections, cancellation)?;
        chains.construction_steps += self.construction_steps;
        Ok(chains)
    }
}

/// Why stored cleanup rows cannot form an arena. Indexes are positions in the
/// rows passed to CleanupChains::hydrate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupChainsError {
    Cancelled,
    InvalidSegmentNode,
    InvalidSegmentAncestry,
    ParentAfterChild {
        node: usize,
    },
    MissingSegmentNode {
        anchor: usize,
    },
    MissingProjection {
        anchor: usize,
    },
    StopNotAncestor {
        anchor: usize,
    },
    MissingProjectionAction {
        projection: usize,
        member: usize,
    },
    /// A projected anchor selects an action outside its segment or out of
    /// the segment's entry order.
    ProjectionOutsideSegment {
        anchor: usize,
    },
}

#[derive(Default, Clone)]
pub struct CleanupChains {
    // Construction telemetry only: zero after hydration, outside identity and census.
    construction_steps: usize,
    nodes: Box<[CleanupChainNode]>,
    anchors: Box<[CleanupAnchor]>,
    projections: Box<[Box<[CleanupActionCursor]>]>,
    region_prefix: Box<[usize]>,
    membership: CleanupMembership,
}
impl std::fmt::Debug for CleanupChains {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CleanupChains")
            .field("nodes", &self.nodes)
            .field("anchors", &self.anchors)
            .field("projections", &self.projections)
            .field("region_prefix", &self.region_prefix)
            .field("ancestor_intervals", &self.membership.ancestor_intervals)
            .finish()
    }
}
impl CleanupChains {
    /// Actual builder steps; zero for hydrated relations. Not budget or identity input.
    pub fn construction_steps(&self) -> usize {
        self.construction_steps
    }
    /// Finalize entry metadata without changing chain structure or cursor identity.
    pub fn map_entry_metadata(
        mut self,
        mut owner: impl FnMut(&CleanupOwnerEntry) -> CleanupOwnerEntry,
        mut action: impl FnMut(&CleanupActionEntry) -> CleanupActionEntry,
    ) -> Self {
        for node in &mut self.nodes {
            for entry in &mut node.owners {
                let mapped = owner(entry);
                debug_assert_eq!(entry.value, mapped.value);
                debug_assert_eq!(entry.place, mapped.place);
                *entry = mapped;
            }
            for entry in &mut node.actions {
                let mapped = action(entry);
                debug_assert!(
                    match (&entry.action, &mapped.action) {
                        (
                            ScopeCleanupAction::Drop {
                                place: a,
                                behavior: x,
                                ..
                            },
                            ScopeCleanupAction::Drop {
                                place: b,
                                behavior: y,
                                ..
                            },
                        ) => a == b && x == y,
                        (
                            ScopeCleanupAction::ScopeEnd { place: a, .. },
                            ScopeCleanupAction::ScopeEnd { place: b, .. },
                        ) => a == b,
                        _ => false,
                    },
                    "metadata mapping preserves action structure"
                );
                *entry = mapped;
            }
        }
        // Only entries were assigned: node IDs, topology, entry ordering,
        // anchors, offsets, projections and their indexes remain untouched.
        self
    }
    /// Hydration uses the same parent-before-child and segment checks as lowering.
    pub fn new(nodes: Vec<CleanupChainNode>, anchors: Vec<CleanupAnchor>) -> Self {
        Self::with_projections(nodes, anchors, Vec::new())
    }
    pub fn with_projections(
        nodes: Vec<CleanupChainNode>,
        anchors: Vec<CleanupAnchor>,
        projections: Vec<Box<[CleanupActionCursor]>>,
    ) -> Self {
        Self::checked(
            nodes,
            anchors,
            projections,
            &brokk_bifrost_core::cancellation::CancellationToken::default(),
        )
        .expect("lowering builds a valid cleanup arena")
    }

    /// Rebuild an arena from stored rows. Projection members arrive as raw
    /// (node, action ordinal) pairs; the shared checks below reject any pair
    /// that names no action. Damaged rows return an error instead of panicking.
    pub fn hydrate(
        nodes: Vec<CleanupChainNode>,
        anchors: Vec<CleanupAnchor>,
        projections: Vec<Vec<(CleanupChainNodeId, u32)>>,
    ) -> Result<Self, CleanupChainsError> {
        let projections = projections
            .into_iter()
            .map(|members| {
                members
                    .into_iter()
                    .map(|(node, ordinal)| CleanupActionCursor { node, ordinal })
                    .collect()
            })
            .collect();
        Self::checked(
            nodes,
            anchors,
            projections,
            &brokk_bifrost_core::cancellation::CancellationToken::default(),
        )
    }

    /// Every structural invariant of an arena, for lowering and hydration
    /// alike: parent before child, anchor references inside the arena, stop
    /// an ancestor of head, and each projection's actions present and selected
    /// in the anchor segment's entry order.
    fn checked(
        nodes: Vec<CleanupChainNode>,
        anchors: Vec<CleanupAnchor>,
        projections: Vec<Box<[CleanupActionCursor]>>,
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> Result<Self, CleanupChainsError> {
        if cancellation.is_cancelled() {
            return Err(CleanupChainsError::Cancelled);
        }
        let mut validation_steps = 0;
        let mut region_prefix = Vec::with_capacity(nodes.len());
        for (index, node) in nodes.iter().enumerate() {
            validation_steps += 1;
            if cancellation.is_cancelled() {
                return Err(CleanupChainsError::Cancelled);
            }
            let parent_count = match node.parent {
                None => 0,
                Some(parent) if parent.index() < index => region_prefix[parent.index()],
                Some(_) => return Err(CleanupChainsError::ParentAfterChild { node: index }),
            };
            region_prefix.push(parent_count + usize::from(node.region.is_some()));
        }
        for (projection, members) in projections.iter().enumerate() {
            validation_steps += 1 + members.len();
            if let Some(member) = members.iter().position(|cursor| {
                nodes
                    .get(cursor.node.index())
                    .is_none_or(|node| cursor.ordinal() >= node.actions.len())
            }) {
                return Err(CleanupChainsError::MissingProjectionAction { projection, member });
            }
        }
        for (index, anchor) in anchors.iter().enumerate() {
            validation_steps += 1;
            if anchor
                .projection
                .is_some_and(|projection| projection.index() >= projections.len())
            {
                return Err(CleanupChainsError::MissingProjection { anchor: index });
            }
        }
        let membership = CleanupMembership::new(&nodes, cancellation, &mut validation_steps)?;
        let mut result = Self {
            construction_steps: validation_steps,
            nodes: nodes.into_boxed_slice(),
            anchors: anchors.into_boxed_slice(),
            projections: projections.into_boxed_slice(),
            region_prefix: region_prefix.into_boxed_slice(),
            membership,
        };
        for (anchor, entry) in result.anchors().iter().enumerate() {
            validation_steps += 1;
            result
                .validate_segment(entry.segment)
                .map_err(|error| match error {
                    CleanupChainsError::InvalidSegmentNode => {
                        CleanupChainsError::MissingSegmentNode { anchor }
                    }
                    CleanupChainsError::InvalidSegmentAncestry => {
                        CleanupChainsError::StopNotAncestor { anchor }
                    }
                    _ => unreachable!("segment validation returns segment errors"),
                })?;
        }
        // Validate each shared projection once. Ordering is independent of
        // the segment: inner regions precede outer regions, while chunks in
        // one region and actions in one chunk retain their insertion order.
        // An invalid unused projection remains accepted, as before; an anchor
        // that references it reports ProjectionOutsideSegment below.
        #[derive(Clone, Copy)]
        enum ProjectionOrder {
            Empty,
            Bounds {
                shallowest: CleanupChainNodeId,
                deepest: CleanupChainNodeId,
            },
            Invalid,
        }
        let mut projection_orders = Vec::with_capacity(result.projections.len());
        for members in result.projections() {
            validation_steps += 1;
            let mut order = ProjectionOrder::Empty;
            let mut previous = None;
            for selected in members {
                validation_steps += 1;
                if cancellation.is_cancelled() {
                    return Err(CleanupChainsError::Cancelled);
                }
                let node = selected.node;
                let position = (
                    std::cmp::Reverse(result.region_prefix[node.index()]),
                    node.index(),
                    selected.ordinal(),
                );
                if previous.is_some_and(|prior| prior >= position) {
                    order = ProjectionOrder::Invalid;
                    break;
                }
                previous = Some(position);
                order = match order {
                    ProjectionOrder::Empty => ProjectionOrder::Bounds {
                        shallowest: node,
                        deepest: node,
                    },
                    ProjectionOrder::Bounds {
                        shallowest,
                        deepest,
                    } => {
                        if !result.is_ancestor(Some(node), Some(deepest))
                            && !result.is_ancestor(Some(deepest), Some(node))
                        {
                            order = ProjectionOrder::Invalid;
                            break;
                        }
                        ProjectionOrder::Bounds {
                            shallowest: if node.index() < shallowest.index() {
                                node
                            } else {
                                shallowest
                            },
                            deepest: if node.index() > deepest.index() {
                                node
                            } else {
                                deepest
                            },
                        }
                    }
                    ProjectionOrder::Invalid => {
                        unreachable!("invalid projections stop at their first invalid member")
                    }
                };
            }
            projection_orders.push(order);
        }
        for (index, anchor) in result.anchors().iter().enumerate() {
            validation_steps += 1;
            if cancellation.is_cancelled() {
                return Err(CleanupChainsError::Cancelled);
            }
            let Some(projection) = anchor.projection else {
                continue;
            };
            let in_segment = match projection_orders[projection.index()] {
                ProjectionOrder::Empty => true,
                ProjectionOrder::Invalid => false,
                ProjectionOrder::Bounds {
                    shallowest,
                    deepest,
                } => {
                    result.is_ancestor(Some(deepest), anchor.segment.head)
                        && !result.is_ancestor(Some(shallowest), anchor.segment.stop)
                }
            };
            if !in_segment {
                return Err(CleanupChainsError::ProjectionOutsideSegment { anchor: index });
            }
        }
        result.construction_steps = validation_steps;
        Ok(result)
    }
    pub fn route_entries(
        &self,
        segment: CleanupSegment,
        projection: Option<CleanupProjectionId>,
    ) -> CleanupRouteEntries<'_> {
        CleanupRouteEntries {
            entries: self.entries(segment),
            selected: projection.map(|id| self.projection(id)),
            position: 0,
        }
    }
    pub fn projections(&self) -> &[Box<[CleanupActionCursor]>] {
        &self.projections
    }
    pub fn projection(&self, id: CleanupProjectionId) -> &[CleanupActionCursor] {
        &self.projections[id.index()]
    }
    pub fn anchor_actions(
        &self,
        anchor: &CleanupAnchor,
    ) -> impl Iterator<Item = &CleanupActionEntry> {
        let segment = anchor.segment;
        let projection = anchor.projection;
        projection
            .is_none()
            .then_some(segment)
            .into_iter()
            .flat_map(move |segment| self.actions(segment))
            .chain(projection.into_iter().flat_map(move |id| {
                self.projection(id)
                    .iter()
                    .map(move |cursor| self.action(*cursor))
            }))
    }
    pub fn nodes(&self) -> &[CleanupChainNode] {
        &self.nodes
    }
    pub fn anchors(&self) -> &[CleanupAnchor] {
        &self.anchors
    }
    pub fn node(&self, id: CleanupChainNodeId) -> &CleanupChainNode {
        &self.nodes[id.index()]
    }
    pub fn action_cursor(&self, node: CleanupChainNodeId, ordinal: usize) -> CleanupActionCursor {
        assert!(
            ordinal < self.node(node).actions.len(),
            "cleanup action ordinal exists"
        );
        CleanupActionCursor {
            node,
            ordinal: u32::try_from(ordinal).expect("cleanup ordinal fits u32"),
        }
    }
    pub fn action(&self, cursor: CleanupActionCursor) -> &CleanupActionEntry {
        &self.node(cursor.node).actions[cursor.ordinal()]
    }
    /// The empty sentinel is an ancestor of every node.
    pub fn is_ancestor(
        &self,
        ancestor: Option<CleanupChainNodeId>,
        descendant: Option<CleanupChainNodeId>,
    ) -> bool {
        self.membership.is_ancestor(ancestor, descendant)
    }
    pub fn assert_segment(&self, segment: CleanupSegment) {
        assert!(
            self.is_ancestor(segment.stop, segment.head),
            "cleanup stop must be an ancestor of head"
        );
    }
    pub fn region_count(&self, segment: CleanupSegment) -> usize {
        let count =
            |id: Option<CleanupChainNodeId>| id.map_or(0, |id| self.region_prefix[id.index()]);
        count(segment.head) - count(segment.stop)
    }
    pub fn segment_nodes(&self, segment: CleanupSegment) -> CleanupNodes<'_> {
        CleanupNodes {
            chains: self,
            cursor: segment.head,
            stop: segment.stop,
        }
    }
    pub fn regions(&self, segment: CleanupSegment) -> impl Iterator<Item = CleanupRegionId> + '_ {
        self.segment_nodes(segment).filter_map(|node| node.region)
    }
    /// Logical registration order within each scope, followed by its boundary.
    pub fn entries(&self, segment: CleanupSegment) -> CleanupEntries<'_> {
        CleanupEntries {
            nodes: &self.nodes,
            cursor: segment.head,
            stop: segment.stop,
            chunks: Vec::new(),
            current: None,
            current_id: None,
            action: 0,
            owner: 0,
            region: None,
        }
    }
    pub fn actions(&self, segment: CleanupSegment) -> impl Iterator<Item = &CleanupActionEntry> {
        self.entries(segment).filter_map(|entry| match entry {
            CleanupEntryRef::Action(action) => Some(action),
            _ => None,
        })
    }
    pub fn owners(&self, segment: CleanupSegment) -> impl Iterator<Item = &CleanupOwnerEntry> {
        self.entries(segment).filter_map(|entry| match entry {
            CleanupEntryRef::Owner(owner) => Some(owner),
            _ => None,
        })
    }
    pub fn stored_entries(&self) -> usize {
        self.nodes.len()
            + self.projections.len()
            + self
                .projections
                .iter()
                .map(|projection| projection.len())
                .sum::<usize>()
            + self.anchors.len()
            + self
                .nodes
                .iter()
                .map(|node| node.actions.len() + node.owners.len())
                .sum::<usize>()
    }
    /// Fixed allocations; nested place/target payloads are charged by the central work census.
    pub fn index_retained_bytes(&self) -> usize {
        self.membership.owner_introductions.len()
            * std::mem::size_of::<(ValueId, CleanupChainNodeId)>()
            + self.region_prefix.len() * std::mem::size_of::<usize>()
            + self.membership.ancestor_intervals.len() * std::mem::size_of::<(usize, usize)>()
            + self.membership.owner_path_counts.len() * std::mem::size_of::<usize>()
    }
}

pub struct CleanupNodes<'a> {
    chains: &'a CleanupChains,
    cursor: Option<CleanupChainNodeId>,
    stop: Option<CleanupChainNodeId>,
}
impl<'a> Iterator for CleanupNodes<'a> {
    type Item = &'a CleanupChainNode;
    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor == self.stop {
            return None;
        }
        let node = self
            .chains
            .node(self.cursor.expect("valid cleanup segment"));
        self.cursor = node.parent;
        Some(node)
    }
}

/// Borrowed logical entries; no action or owner payload is copied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupEntryRef<'a> {
    Action(&'a CleanupActionEntry),
    Owner(&'a CleanupOwnerEntry),
    Region(CleanupRegionId),
}

/// Scratch stores only chunk references for the current lexical scope.
/// A region-bearing node is the oldest chunk and terminates that scope.
pub struct CleanupEntries<'a> {
    nodes: &'a [CleanupChainNode],
    cursor: Option<CleanupChainNodeId>,
    stop: Option<CleanupChainNodeId>,
    chunks: Vec<(CleanupChainNodeId, &'a CleanupChainNode)>,
    current: Option<&'a CleanupChainNode>,
    current_id: Option<CleanupChainNodeId>,
    action: usize,
    owner: usize,
    region: Option<CleanupRegionId>,
}
impl<'a> Iterator for CleanupEntries<'a> {
    type Item = CleanupEntryRef<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(node) = self.current {
                if let Some(entry) = node.actions.get(self.action) {
                    self.action += 1;
                    return Some(CleanupEntryRef::Action(entry));
                }
                if let Some(entry) = node.owners.get(self.owner) {
                    self.owner += 1;
                    return Some(CleanupEntryRef::Owner(entry));
                }
                self.current = None;
            }
            if let Some((id, node)) = self.chunks.pop() {
                self.current = Some(node);
                self.current_id = Some(id);
                self.action = 0;
                self.owner = 0;
                continue;
            }
            if let Some(region) = self.region.take() {
                return Some(CleanupEntryRef::Region(region));
            }
            if self.cursor == self.stop {
                return None;
            }
            while self.cursor != self.stop {
                let id = self.cursor.expect("valid cleanup segment");
                let node = &self.nodes[id.index()];
                self.cursor = node.parent;
                self.chunks.push((id, node));
                if let Some(region) = node.region {
                    self.region = Some(region);
                    break;
                }
            }
        }
    }
}

impl<'a> CleanupEntries<'a> {
    pub fn next_action(&mut self) -> Option<(CleanupActionCursor, &'a CleanupActionEntry)> {
        while let Some(entry) = self.next() {
            if let CleanupEntryRef::Action(action) = entry {
                return Some((
                    CleanupActionCursor {
                        node: self.current_id.expect("action has a chunk"),
                        ordinal: u32::try_from(self.action - 1).expect("action ordinal fits u32"),
                    },
                    action,
                ));
            }
        }
        None
    }
}

/// Borrowed route operations, with stable cursors and lexical region context.
#[derive(Debug, Clone, Copy)]
pub enum CleanupRouteEntryRef<'a> {
    Action {
        cursor: CleanupActionCursor,
        region: Option<CleanupRegionId>,
        entry: &'a CleanupActionEntry,
    },
    Owner(&'a CleanupOwnerEntry),
    Region {
        cursor: CleanupChainNodeId,
        region: CleanupRegionId,
    },
}
impl<'a> CleanupEntries<'a> {
    fn next_route_entry(&mut self) -> Option<CleanupRouteEntryRef<'a>> {
        match self.next()? {
            CleanupEntryRef::Action(entry) => Some(CleanupRouteEntryRef::Action {
                cursor: CleanupActionCursor {
                    node: self.current_id.expect("action has a chunk"),
                    ordinal: u32::try_from(self.action - 1).expect("action ordinal fits u32"),
                },
                region: self.region,
                entry,
            }),
            CleanupEntryRef::Owner(owner) => Some(CleanupRouteEntryRef::Owner(owner)),
            CleanupEntryRef::Region(region) => Some(CleanupRouteEntryRef::Region {
                cursor: self.current_id.expect("region has a chunk"),
                region,
            }),
        }
    }
}
/// Selection filters one shared registration-order iterator, preserving boundaries.
pub struct CleanupRouteEntries<'a> {
    entries: CleanupEntries<'a>,
    selected: Option<&'a [CleanupActionCursor]>,
    position: usize,
}
impl<'a> Iterator for CleanupRouteEntries<'a> {
    type Item = CleanupRouteEntryRef<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let Some(entry) = self.entries.next_route_entry() else {
                debug_assert!(
                    self.selected
                        .is_none_or(|selected| self.position == selected.len()),
                    "projection must be in segment order"
                );
                return None;
            };
            if let (CleanupRouteEntryRef::Action { cursor, .. }, Some(selected)) =
                (entry, self.selected)
            {
                if selected.get(self.position) != Some(&cursor) {
                    continue;
                }
                self.position += 1;
            }
            if matches!(entry, CleanupRouteEntryRef::Owner(_)) {
                continue;
            }
            return Some(entry);
        }
    }
}

// Read-only exact membership queries; no route-by-owner postings are retained.
impl CleanupChains {
    pub fn validate_segment(&self, segment: CleanupSegment) -> Result<(), CleanupChainsError> {
        if [segment.head, segment.stop]
            .into_iter()
            .flatten()
            .any(|node| node.index() >= self.nodes.len())
        {
            return Err(CleanupChainsError::InvalidSegmentNode);
        }
        if !self.is_ancestor(segment.stop, segment.head) {
            return Err(CleanupChainsError::InvalidSegmentAncestry);
        }
        Ok(())
    }

    pub fn member_owners(&self, segment: CleanupSegment) -> impl Iterator<Item = ValueId> + '_ {
        self.membership
            .owner_introductions
            .iter()
            .filter(move |(_, node)| {
                self.is_ancestor(Some(*node), segment.head)
                    && !self.is_ancestor(Some(*node), segment.stop)
            })
            .map(|(owner, _)| *owner)
            .scan(None, |previous, owner| {
                let fresh = *previous != Some(owner);
                *previous = Some(owner);
                Some(fresh.then_some(owner))
            })
            .flatten()
    }

    pub fn contains_owner(&self, segment: CleanupSegment, owner: ValueId) -> bool {
        self.membership.contains_owner(segment, owner)
    }

    /// Whether the segment names any owner, without scanning the procedure's owners.
    pub fn has_member_owners(&self, segment: CleanupSegment) -> bool {
        self.membership.has_owners(segment)
    }
}
