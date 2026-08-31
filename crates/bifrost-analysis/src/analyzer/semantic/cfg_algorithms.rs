//! Stack-safe, request-bounded algorithms over immutable dense control-flow graphs.

use std::collections::VecDeque;

use crate::analyzer::semantic::{
    CancellationToken, ControlEdgeId, ProcedureSemantics, ProgramPointId,
};
use crate::analyzer::work_budget::{BudgetLedger, WorkBudgetExceeded, define_work_dimensions};

/// Immutable directed graph with dense node identities and canonical adjacency.
///
/// Successor and predecessor iteration must be canonical and every returned edge
/// must have the same endpoints as `edge_endpoints`. Implementations are views:
/// algorithms never require a copied or normalized graph.
pub trait DenseBidirectionalGraph {
    type Node: Copy + Eq + Ord + std::fmt::Debug;
    type Edge: Copy + Eq + Ord + std::fmt::Debug;

    fn node_count(&self) -> usize;
    fn node_at(&self, index: usize) -> Option<Self::Node>;
    fn node_index(&self, node: Self::Node) -> Option<usize>;
    fn successors(
        &self,
        node: Self::Node,
    ) -> impl DoubleEndedIterator<Item = (Self::Edge, Self::Node)> + ExactSizeIterator + '_;
    fn predecessors(
        &self,
        node: Self::Node,
    ) -> impl DoubleEndedIterator<Item = (Self::Edge, Self::Node)> + ExactSizeIterator + '_;
    fn edge_endpoints(&self, edge: Self::Edge) -> Option<(Self::Node, Self::Node)>;
}

impl DenseBidirectionalGraph for ProcedureSemantics {
    type Node = ProgramPointId;
    type Edge = ControlEdgeId;

    fn node_count(&self) -> usize {
        self.points().len()
    }

    fn node_at(&self, index: usize) -> Option<Self::Node> {
        (index < self.points().len())
            .then(|| ProgramPointId::try_from_index(index).expect("validated point index fits u32"))
    }

    fn node_index(&self, node: Self::Node) -> Option<usize> {
        (node.index() < self.points().len()).then_some(node.index())
    }

    fn successors(
        &self,
        node: Self::Node,
    ) -> impl DoubleEndedIterator<Item = (Self::Edge, Self::Node)> + ExactSizeIterator + '_ {
        self.successor_edges_bidirectional(node)
            .map(|(edge_id, edge)| (edge_id, edge.target_point))
    }

    fn predecessors(
        &self,
        node: Self::Node,
    ) -> impl DoubleEndedIterator<Item = (Self::Edge, Self::Node)> + ExactSizeIterator + '_ {
        self.predecessor_edges_bidirectional(node)
            .map(|(edge_id, edge)| (edge_id, edge.source_point))
    }

    fn edge_endpoints(&self, edge: Self::Edge) -> Option<(Self::Node, Self::Node)> {
        self.control_edge(edge)
            .map(|edge| (edge.source_point, edge.target_point))
    }
}

define_work_dimensions! {
    /// Independently bounded kinds of CFG work.
    #[repr(u8)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum CfgAlgorithmLimit;
    /// Work completed by one or more algorithms sharing a request-local budget.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct CfgAlgorithmWork;
    all: [2];
    NodeVisits => node_visits = usize::MAX,
    EdgeVisits => edge_visits = usize::MAX,
}

/// Exact failed node- or edge-visit charge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CfgAlgorithmBudgetExceeded {
    pub limit_kind: CfgAlgorithmLimit,
    pub limit: usize,
    pub attempted: usize,
    pub work: CfgAlgorithmWork,
}

/// Request-local two-dimensional CFG work budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgAlgorithmBudget {
    ledger: BudgetLedger<CfgAlgorithmWork>,
}

impl CfgAlgorithmBudget {
    pub const fn new(limits: CfgAlgorithmWork) -> Self {
        Self {
            ledger: BudgetLedger::new(limits, CfgAlgorithmWork::uniform(0)),
        }
    }

    pub const fn uniform(limit: usize) -> Self {
        Self::new(CfgAlgorithmWork {
            node_visits: limit,
            edge_visits: limit,
        })
    }

    pub const fn limits(&self) -> CfgAlgorithmWork {
        self.ledger.limits()
    }

    pub const fn used(&self) -> CfgAlgorithmWork {
        self.ledger.used()
    }

    fn charge(&mut self, work: CfgAlgorithmWork) -> Result<(), CfgAlgorithmBudgetExceeded> {
        self.ledger
            .charge(work)
            .map_err(|exceeded| budget_exceeded(exceeded, self.ledger.used()))
    }
}

impl Default for CfgAlgorithmBudget {
    fn default() -> Self {
        Self::new(CfgAlgorithmWork::default_limits())
    }
}

fn budget_exceeded(
    exceeded: WorkBudgetExceeded<CfgAlgorithmLimit>,
    work: CfgAlgorithmWork,
) -> CfgAlgorithmBudgetExceeded {
    CfgAlgorithmBudgetExceeded {
        limit_kind: exceeded.dimension(),
        limit: exceeded.limit(),
        attempted: exceeded.attempted(),
        work,
    }
}

/// Complete failure of a bounded algorithm. No variant contains a partial result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CfgAlgorithmError<Node> {
    InvalidNode(Node),
    Cancelled { work: CfgAlgorithmWork },
    ExceededBudget(CfgAlgorithmBudgetExceeded),
}

/// Borrowed controls shared by all CFG algorithms.
#[derive(Debug)]
pub struct CfgAlgorithmRequest<'request> {
    pub budget: &'request mut CfgAlgorithmBudget,
    pub cancellation: &'request CancellationToken,
}

impl<'request> CfgAlgorithmRequest<'request> {
    pub const fn new(
        budget: &'request mut CfgAlgorithmBudget,
        cancellation: &'request CancellationToken,
    ) -> Self {
        Self {
            budget,
            cancellation,
        }
    }

    fn checkpoint<Node>(&mut self) -> Result<(), CfgAlgorithmError<Node>> {
        if self.cancellation.is_cancelled() {
            Err(CfgAlgorithmError::Cancelled {
                work: self.budget.used(),
            })
        } else {
            Ok(())
        }
    }

    pub(crate) fn visit_node<Node>(&mut self) -> Result<(), CfgAlgorithmError<Node>> {
        self.checkpoint()?;
        self.budget
            .charge(CfgAlgorithmWork {
                node_visits: 1,
                edge_visits: 0,
            })
            .map_err(CfgAlgorithmError::ExceededBudget)
    }

    /// Charge one unit for considering one candidate node pair.
    ///
    /// A pairwise relation over a dense graph is quadratic in the node count,
    /// and a caller that enumerates such a relation is doing graph work under
    /// the same ledger the algorithms here charge against. Exposing the charge
    /// keeps that work inside one budget instead of letting a consumer invent
    /// a second, unrelated bound (issue #2443).
    pub fn visit_pair<Node>(&mut self) -> Result<(), CfgAlgorithmError<Node>> {
        self.visit_node()
    }

    pub(crate) fn visit_edge<Node>(&mut self) -> Result<(), CfgAlgorithmError<Node>> {
        self.checkpoint()?;
        self.budget
            .charge(CfgAlgorithmWork {
                node_visits: 0,
                edge_visits: 1,
            })
            .map_err(CfgAlgorithmError::ExceededBudget)
    }
}

/// Complete reachability membership with dense-order iteration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reachability<Node> {
    membership: Box<[bool]>,
    work: CfgAlgorithmWork,
    node: std::marker::PhantomData<Node>,
}

impl<Node: Copy> Reachability<Node> {
    pub fn contains<G>(&self, graph: &G, node: Node) -> bool
    where
        G: DenseBidirectionalGraph<Node = Node>,
    {
        graph
            .node_index(node)
            .and_then(|index| self.membership.get(index))
            .copied()
            .unwrap_or(false)
    }

    pub fn iter<'graph, G>(&'graph self, graph: &'graph G) -> impl Iterator<Item = Node> + 'graph
    where
        G: DenseBidirectionalGraph<Node = Node> + 'graph,
    {
        self.membership
            .iter()
            .enumerate()
            .filter(|(_, reachable)| **reachable)
            .map(|(index, _)| required_node(graph, index))
    }

    pub fn membership(&self) -> &[bool] {
        &self.membership
    }

    pub const fn work(&self) -> CfgAlgorithmWork {
        self.work
    }
}

#[derive(Debug, Clone, Copy)]
enum Direction {
    Forward,
    Reverse,
}

pub fn forward_reachability<G>(
    graph: &G,
    start: G::Node,
    request: &mut CfgAlgorithmRequest<'_>,
) -> Result<Reachability<G::Node>, CfgAlgorithmError<G::Node>>
where
    G: DenseBidirectionalGraph,
{
    reachability(graph, start, Direction::Forward, request)
}

pub fn reverse_reachability<G>(
    graph: &G,
    start: G::Node,
    request: &mut CfgAlgorithmRequest<'_>,
) -> Result<Reachability<G::Node>, CfgAlgorithmError<G::Node>>
where
    G: DenseBidirectionalGraph,
{
    reachability(graph, start, Direction::Reverse, request)
}

fn reachability<G>(
    graph: &G,
    start: G::Node,
    direction: Direction,
    request: &mut CfgAlgorithmRequest<'_>,
) -> Result<Reachability<G::Node>, CfgAlgorithmError<G::Node>>
where
    G: DenseBidirectionalGraph,
{
    request.checkpoint()?;
    let started = request.budget.used();
    let start_index = graph
        .node_index(start)
        .ok_or(CfgAlgorithmError::InvalidNode(start))?;
    let mut membership = vec![false; graph.node_count()];
    membership[start_index] = true;
    request.visit_node()?;
    let mut stack = vec![start];

    while let Some(node) = stack.pop() {
        request.checkpoint()?;
        match direction {
            Direction::Forward => discover_adjacent(
                graph,
                graph.successors(node).rev(),
                &mut membership,
                &mut stack,
                request,
            )?,
            Direction::Reverse => discover_adjacent(
                graph,
                graph.predecessors(node),
                &mut membership,
                &mut stack,
                request,
            )?,
        }
    }

    Ok(Reachability {
        membership: membership.into_boxed_slice(),
        work: request.budget.used().saturating_sub(started),
        node: std::marker::PhantomData,
    })
}

fn discover_adjacent<G>(
    graph: &G,
    adjacent: impl Iterator<Item = (G::Edge, G::Node)>,
    membership: &mut [bool],
    stack: &mut Vec<G::Node>,
    request: &mut CfgAlgorithmRequest<'_>,
) -> Result<(), CfgAlgorithmError<G::Node>>
where
    G: DenseBidirectionalGraph,
{
    for (_, adjacent_node) in adjacent {
        request.visit_edge()?;
        let index = graph
            .node_index(adjacent_node)
            .ok_or(CfgAlgorithmError::InvalidNode(adjacent_node))?;
        if !membership[index] {
            membership[index] = true;
            request.visit_node()?;
            stack.push(adjacent_node);
        }
    }
    Ok(())
}

/// Complete deterministic iterative DFS forest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepthFirstOrder<Node, Edge> {
    pub preorder: Box<[Node]>,
    pub postorder: Box<[Node]>,
    pub reverse_postorder: Box<[Node]>,
    pub back_edges: Box<[Edge]>,
    pub work: CfgAlgorithmWork,
}

type AlgorithmResult<T, Node> = Result<T, CfgAlgorithmError<Node>>;
type ComponentsWithOrder<Node, Edge> = (
    StronglyConnectedComponents<Node>,
    DepthFirstOrder<Node, Edge>,
);
type ShortestPathResult<Node, Edge> = AlgorithmResult<Option<ShortestPath<Node, Edge>>, Node>;

enum DfsAction<Node, Edge> {
    Enter(Node),
    Examine(Edge, Node),
    Finish(Node),
}

pub fn depth_first_order<G>(
    graph: &G,
    request: &mut CfgAlgorithmRequest<'_>,
) -> AlgorithmResult<DepthFirstOrder<G::Node, G::Edge>, G::Node>
where
    G: DenseBidirectionalGraph,
{
    request.checkpoint()?;
    let started = request.budget.used();
    let mut colors = vec![0_u8; graph.node_count()];
    let mut preorder = Vec::with_capacity(graph.node_count());
    let mut postorder = Vec::with_capacity(graph.node_count());
    let mut back_edges = Vec::new();
    let mut actions = Vec::new();

    for root_index in 0..graph.node_count() {
        if colors[root_index] != 0 {
            continue;
        }
        actions.push(DfsAction::Enter(required_node(graph, root_index)));
        while let Some(action) = actions.pop() {
            request.checkpoint()?;
            match action {
                DfsAction::Enter(node) => {
                    let index = required_index(graph, node)?;
                    if colors[index] != 0 {
                        continue;
                    }
                    request.visit_node()?;
                    colors[index] = 1;
                    preorder.push(node);
                    actions.push(DfsAction::Finish(node));
                    for (edge, target) in graph.successors(node).rev() {
                        request.visit_edge()?;
                        actions.push(DfsAction::Examine(edge, target));
                    }
                }
                DfsAction::Examine(edge, target) => {
                    let target_index = required_index(graph, target)?;
                    match colors[target_index] {
                        0 => actions.push(DfsAction::Enter(target)),
                        1 => back_edges.push(edge),
                        _ => {}
                    }
                }
                DfsAction::Finish(node) => {
                    let index = required_index(graph, node)?;
                    colors[index] = 2;
                    postorder.push(node);
                }
            }
        }
    }

    let reverse_postorder = postorder.iter().rev().copied().collect();
    Ok(DepthFirstOrder {
        preorder: preorder.into_boxed_slice(),
        postorder: postorder.into_boxed_slice(),
        reverse_postorder,
        back_edges: back_edges.into_boxed_slice(),
        work: request.budget.used().saturating_sub(started),
    })
}

/// Canonically ordered strongly connected components and dense membership.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StronglyConnectedComponents<Node> {
    pub components: Box<[Box<[Node]>]>,
    component_by_node: Box<[usize]>,
    pub work: CfgAlgorithmWork,
}

impl<Node: Copy> StronglyConnectedComponents<Node> {
    pub fn component_of<G>(&self, graph: &G, node: Node) -> Option<usize>
    where
        G: DenseBidirectionalGraph<Node = Node>,
    {
        graph
            .node_index(node)
            .and_then(|index| self.component_by_node.get(index))
            .copied()
    }
}

pub fn strongly_connected_components<G>(
    graph: &G,
    request: &mut CfgAlgorithmRequest<'_>,
) -> Result<StronglyConnectedComponents<G::Node>, CfgAlgorithmError<G::Node>>
where
    G: DenseBidirectionalGraph,
{
    strongly_connected_components_with_order(graph, request).map(|(components, _)| components)
}

fn strongly_connected_components_with_order<G>(
    graph: &G,
    request: &mut CfgAlgorithmRequest<'_>,
) -> AlgorithmResult<ComponentsWithOrder<G::Node, G::Edge>, G::Node>
where
    G: DenseBidirectionalGraph,
{
    request.checkpoint()?;
    let started = request.budget.used();
    let order = depth_first_order(graph, request)?;
    let mut assigned = vec![false; graph.node_count()];
    let mut raw_component_by_node = vec![usize::MAX; graph.node_count()];
    let mut raw_component_count = 0usize;

    for seed in order.reverse_postorder.iter().copied() {
        let seed_index = required_index(graph, seed)?;
        if assigned[seed_index] {
            continue;
        }
        let raw_component = raw_component_count;
        raw_component_count += 1;
        assigned[seed_index] = true;
        raw_component_by_node[seed_index] = raw_component;
        let mut stack = vec![seed];
        while let Some(node) = stack.pop() {
            request.visit_node()?;
            for (_, predecessor) in graph.predecessors(node).rev() {
                request.visit_edge()?;
                let predecessor_index = required_index(graph, predecessor)?;
                if !assigned[predecessor_index] {
                    assigned[predecessor_index] = true;
                    raw_component_by_node[predecessor_index] = raw_component;
                    stack.push(predecessor);
                }
            }
        }
    }

    let mut members_by_raw = (0..raw_component_count)
        .map(|_| Vec::<G::Node>::new())
        .collect::<Vec<_>>();
    let mut raw_order = Vec::with_capacity(raw_component_count);
    let mut raw_seen = vec![false; raw_component_count];
    for (index, &raw_component) in raw_component_by_node.iter().enumerate() {
        request.checkpoint()?;
        debug_assert_ne!(raw_component, usize::MAX);
        if !raw_seen[raw_component] {
            raw_seen[raw_component] = true;
            raw_order.push(raw_component);
        }
        members_by_raw[raw_component].push(required_node(graph, index));
    }

    let mut canonical_by_raw = vec![usize::MAX; raw_component_count];
    for (canonical, &raw_component) in raw_order.iter().enumerate() {
        request.checkpoint()?;
        canonical_by_raw[raw_component] = canonical;
    }
    let mut component_by_node = Vec::with_capacity(graph.node_count());
    for raw_component in raw_component_by_node {
        request.checkpoint()?;
        component_by_node.push(canonical_by_raw[raw_component]);
    }
    let mut components = Vec::with_capacity(raw_component_count);
    for raw_component in raw_order {
        request.checkpoint()?;
        components.push(std::mem::take(&mut members_by_raw[raw_component]).into_boxed_slice());
    }

    Ok((
        StronglyConnectedComponents {
            components: components.into_boxed_slice(),
            component_by_node: component_by_node.into_boxed_slice(),
            work: request.budget.used().saturating_sub(started),
        },
        order,
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopEntryStructure {
    None,
    Single,
    Multiple,
}

/// One cyclic SCC described without an unsupported dominance claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopRegion<Node, Edge> {
    pub members: Box<[Node]>,
    pub entries: Box<[Node]>,
    pub entry_structure: LoopEntryStructure,
    pub back_edges: Box<[Edge]>,
    pub has_self_loop: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopRegions<Node, Edge> {
    pub regions: Box<[LoopRegion<Node, Edge>]>,
    pub work: CfgAlgorithmWork,
}

pub fn loop_regions<G>(
    graph: &G,
    request: &mut CfgAlgorithmRequest<'_>,
) -> AlgorithmResult<LoopRegions<G::Node, G::Edge>, G::Node>
where
    G: DenseBidirectionalGraph,
{
    request.checkpoint()?;
    let started = request.budget.used();
    let (components, dfs) = strongly_connected_components_with_order(graph, request)?;
    let mut self_loops = vec![false; components.components.len()];
    let mut entry_membership = vec![false; graph.node_count()];
    let mut back_edges = vec![Vec::<G::Edge>::new(); components.components.len()];

    for edge in dfs.back_edges {
        request.checkpoint()?;
        let (source, target) = graph
            .edge_endpoints(edge)
            .expect("DFS returned an edge belonging to the graph");
        let source_index = required_index(graph, source)?;
        let target_index = required_index(graph, target)?;
        let component = components.component_by_node[source_index];
        if component == components.component_by_node[target_index] {
            back_edges[component].push(edge);
        }
    }

    for source_index in 0..graph.node_count() {
        request.visit_node()?;
        let source = required_node(graph, source_index);
        let source_component = components.component_by_node[source_index];
        for (_, target) in graph.successors(source) {
            request.visit_edge()?;
            let target_index = required_index(graph, target)?;
            let target_component = components.component_by_node[target_index];
            if source == target {
                self_loops[source_component] = true;
            }
            if source_component != target_component {
                entry_membership[target_index] = true;
            }
        }
    }

    let mut regions = Vec::new();
    for (component, members) in components.components.iter().enumerate() {
        request.checkpoint()?;
        if members.len() == 1 && !self_loops[component] {
            continue;
        }
        let mut canonical_members = Vec::with_capacity(members.len());
        let mut canonical_entries = Vec::new();
        for &member in members {
            request.checkpoint()?;
            canonical_members.push(member);
            let member_index = required_index(graph, member)?;
            if entry_membership[member_index] {
                canonical_entries.push(member);
            }
        }
        let entry_structure = match canonical_entries.len() {
            0 => LoopEntryStructure::None,
            1 => LoopEntryStructure::Single,
            _ => LoopEntryStructure::Multiple,
        };
        let internal_back_edges = std::mem::take(&mut back_edges[component]);
        request.checkpoint()?;
        regions.push(LoopRegion {
            members: canonical_members.into_boxed_slice(),
            entries: canonical_entries.into_boxed_slice(),
            entry_structure,
            back_edges: internal_back_edges.into_boxed_slice(),
            has_self_loop: self_loops[component],
        });
    }

    request.checkpoint()?;
    Ok(LoopRegions {
        regions: regions.into_boxed_slice(),
        work: request.budget.used().saturating_sub(started),
    })
}

/// One deterministic shortest path, including the exact selected rich edges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShortestPath<Node, Edge> {
    pub nodes: Box<[Node]>,
    pub edges: Box<[Edge]>,
    pub work: CfgAlgorithmWork,
}

pub fn shortest_path<G>(
    graph: &G,
    start: G::Node,
    goal: G::Node,
    request: &mut CfgAlgorithmRequest<'_>,
) -> ShortestPathResult<G::Node, G::Edge>
where
    G: DenseBidirectionalGraph,
{
    request.checkpoint()?;
    let started = request.budget.used();
    let start_index = required_index(graph, start)?;
    let goal_index = required_index(graph, goal)?;
    request.visit_node()?;
    if start_index == goal_index {
        return Ok(Some(ShortestPath {
            nodes: vec![start].into_boxed_slice(),
            edges: Box::default(),
            work: request.budget.used().saturating_sub(started),
        }));
    }

    let mut discovered = vec![false; graph.node_count()];
    let mut parent = vec![None::<(G::Node, G::Edge)>; graph.node_count()];
    let mut queue = VecDeque::new();
    discovered[start_index] = true;
    queue.push_back(start);

    while let Some(node) = queue.pop_front() {
        request.checkpoint()?;
        for (edge, target) in graph.successors(node) {
            request.visit_edge()?;
            let target_index = required_index(graph, target)?;
            if discovered[target_index] {
                continue;
            }
            discovered[target_index] = true;
            parent[target_index] = Some((node, edge));
            request.visit_node()?;
            if target_index == goal_index {
                return Ok(Some(reconstruct_path(
                    graph, start, goal, &parent, started, request,
                )?));
            }
            queue.push_back(target);
        }
    }
    Ok(None)
}

fn reconstruct_path<G>(
    graph: &G,
    start: G::Node,
    goal: G::Node,
    parent: &[Option<(G::Node, G::Edge)>],
    started: CfgAlgorithmWork,
    request: &mut CfgAlgorithmRequest<'_>,
) -> AlgorithmResult<ShortestPath<G::Node, G::Edge>, G::Node>
where
    G: DenseBidirectionalGraph,
{
    let mut nodes = vec![goal];
    let mut edges = Vec::new();
    let mut cursor = goal;
    while cursor != start {
        let index = required_index(graph, cursor)?;
        let (previous, edge) = parent[index].expect("discovered path node has a parent");
        request.visit_edge()?;
        request.visit_node()?;
        edges.push(edge);
        nodes.push(previous);
        cursor = previous;
    }
    nodes.reverse();
    edges.reverse();
    Ok(ShortestPath {
        nodes: nodes.into_boxed_slice(),
        edges: edges.into_boxed_slice(),
        work: request.budget.used().saturating_sub(started),
    })
}

/// Complete immediate-dominator relation for one entry, dense by node index.
///
/// Unreachable nodes carry no dominator: they dominate nothing and nothing
/// dominates them. The entry stores itself internally so the chain walk has a
/// fixed point, and reports `None` externally because no node dominates it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dominators<Node> {
    immediate: Box<[Option<usize>]>,
    work: CfgAlgorithmWork,
    node: std::marker::PhantomData<Node>,
}

impl<Node: Copy> Dominators<Node> {
    pub fn immediate_dominator<G>(&self, graph: &G, node: Node) -> Option<Node>
    where
        G: DenseBidirectionalGraph<Node = Node>,
    {
        let index = graph.node_index(node)?;
        let parent = self.immediate.get(index).copied().flatten()?;
        (parent != index).then(|| required_node(graph, parent))
    }

    /// Reflexive dominance: `a` dominates itself, and dominates `b` when every
    /// entry-to-`b` path passes through `a`. The idom chain is walked
    /// iteratively and strictly ascends, so the walk always terminates.
    pub fn dominates<G>(&self, graph: &G, a: Node, b: Node) -> bool
    where
        G: DenseBidirectionalGraph<Node = Node>,
    {
        let (Some(a_index), Some(b_index)) = (graph.node_index(a), graph.node_index(b)) else {
            return false;
        };
        if self.immediate.get(a_index).copied().flatten().is_none() {
            return false;
        }
        let mut cursor = b_index;
        loop {
            let Some(parent) = self.immediate.get(cursor).copied().flatten() else {
                return false;
            };
            if cursor == a_index {
                return true;
            }
            if parent == cursor {
                return false;
            }
            cursor = parent;
        }
    }

    pub const fn work(&self) -> CfgAlgorithmWork {
        self.work
    }
}

/// Cooper-Harvey-Kennedy iterative dominance over the nodes reachable from `entry`.
pub fn dominators<G>(
    graph: &G,
    entry: G::Node,
    request: &mut CfgAlgorithmRequest<'_>,
) -> AlgorithmResult<Dominators<G::Node>, G::Node>
where
    G: DenseBidirectionalGraph,
{
    request.checkpoint()?;
    let started = request.budget.used();
    let entry_index = required_index(graph, entry)?;
    let order = reverse_postorder_from(graph, entry, request)?;
    debug_assert_eq!(
        order.first().copied(),
        Some(entry),
        "reverse postorder from the entry must start at the entry"
    );
    let mut rpo_position = vec![usize::MAX; graph.node_count()];
    for (position, node) in order.iter().copied().enumerate() {
        request.checkpoint()?;
        rpo_position[required_index(graph, node)?] = position;
    }

    let mut immediate = vec![None::<usize>; graph.node_count()];
    immediate[entry_index] = Some(entry_index);
    let mut changed = true;
    while changed {
        changed = false;
        for node in order.iter().copied().skip(1) {
            let index = required_index(graph, node)?;
            request.visit_node()?;
            let mut candidate = None::<usize>;
            for (_, predecessor) in graph.predecessors(node) {
                request.visit_edge()?;
                let predecessor_index = required_index(graph, predecessor)?;
                if immediate[predecessor_index].is_none() {
                    continue;
                }
                candidate = Some(match candidate {
                    None => predecessor_index,
                    Some(current) => intersect_dominators(
                        &immediate,
                        &rpo_position,
                        current,
                        predecessor_index,
                        request,
                    )?,
                });
            }
            let candidate = candidate.expect(
                "reverse postorder reaches a node only after its depth-first tree predecessor",
            );
            if immediate[index] != Some(candidate) {
                immediate[index] = Some(candidate);
                changed = true;
            }
        }
    }

    Ok(Dominators {
        immediate: immediate.into_boxed_slice(),
        work: request.budget.used().saturating_sub(started),
        node: std::marker::PhantomData,
    })
}

/// Canonical live regions which are reachable from the procedure entry but
/// have no structural path to either real exit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonExitingRegion<Node> {
    pub members: Box<[Node]>,
}

/// Complete postdominator relation for the analyzable part of one procedure.
///
/// The synthetic common exit is stored as index `graph.node_count()` and is
/// never returned by the public queries. Live non-exiting points have no
/// postdominator parent and are reported separately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Postdominators<Node> {
    immediate: Box<[Option<usize>]>,
    synthetic_exit: usize,
    pub non_exiting_regions: Box<[NonExitingRegion<Node>]>,
    pub unreachable_points: usize,
    pub work: CfgAlgorithmWork,
}

impl<Node: Copy> Postdominators<Node> {
    pub fn immediate_postdominator<G>(&self, graph: &G, node: Node) -> Option<Node>
    where
        G: DenseBidirectionalGraph<Node = Node>,
    {
        let parent = self
            .immediate
            .get(graph.node_index(node)?)
            .copied()
            .flatten()?;
        (parent != self.synthetic_exit).then(|| required_node(graph, parent))
    }

    pub fn postdominates<G>(&self, graph: &G, a: Node, b: Node) -> bool
    where
        G: DenseBidirectionalGraph<Node = Node>,
    {
        let (Some(a), Some(mut cursor)) = (graph.node_index(a), graph.node_index(b)) else {
            return false;
        };
        loop {
            if cursor == a {
                return true;
            }
            let Some(parent) = self.immediate.get(cursor).copied().flatten() else {
                return false;
            };
            if parent == cursor || parent == self.synthetic_exit {
                return false;
            }
            cursor = parent;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ControlDependenceRow<Edge, Node> {
    pub controlling_edge: Edge,
    pub governed: Node,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlDependenceResult<Edge, Node> {
    pub rows: Box<[ControlDependenceRow<Edge, Node>]>,
    pub non_exiting_regions: Box<[NonExitingRegion<Node>]>,
    pub unreachable_points: usize,
    pub work: CfgAlgorithmWork,
}

/// Narrow cross-crate projection used by the extension runtime. The extension
/// contract maps these procedure-local identities to stable source identities;
/// it never exposes them to callers.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcedureControlDependence {
    pub rows: Box<[(ControlEdgeId, ProgramPointId)]>,
    pub non_exiting_regions: Box<[Box<[ProgramPointId]>]>,
    pub unreachable_points: usize,
    pub node_visits: usize,
    pub edge_visits: usize,
}

/// Why a control-dependence derivation produced no result.
///
/// `ExceededBudget` is separated from the rest because a caller-supplied work
/// limit is not a failure: it is an answer about the caller's own limit, and a
/// host that conflates the two reports an execution error where it should
/// report a truncated result (issue #2412).
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcedureControlDependenceStop {
    /// `max_work` was exhausted. No partial result exists.
    ExceededBudget {
        limit: usize,
        attempted: usize,
    },
    Cancelled,
    Failed(Box<str>),
}

#[doc(hidden)]
pub fn derive_procedure_control_dependence(
    procedure: &ProcedureSemantics,
    max_work: usize,
    cancellation: &CancellationToken,
) -> Result<ProcedureControlDependence, ProcedureControlDependenceStop> {
    let mut budget = CfgAlgorithmBudget::uniform(max_work);
    let mut request = CfgAlgorithmRequest::new(&mut budget, cancellation);
    let result = control_dependence(
        procedure,
        procedure.entry_point(),
        procedure.normal_exit_point(),
        procedure.exceptional_exit_point(),
        &mut request,
    )
    .map_err(|error| match error {
        CfgAlgorithmError::ExceededBudget(exceeded) => {
            ProcedureControlDependenceStop::ExceededBudget {
                limit: exceeded.limit,
                attempted: exceeded.attempted,
            }
        }
        CfgAlgorithmError::Cancelled { .. } => ProcedureControlDependenceStop::Cancelled,
        CfgAlgorithmError::InvalidNode(node) => ProcedureControlDependenceStop::Failed(
            format!("invalid node {node:?}").into_boxed_str(),
        ),
    })?;
    Ok(ProcedureControlDependence {
        rows: result
            .rows
            .iter()
            .map(|row| (row.controlling_edge, row.governed))
            .collect(),
        non_exiting_regions: result
            .non_exiting_regions
            .iter()
            .map(|region| region.members.clone())
            .collect(),
        unreachable_points: result.unreachable_points,
        node_visits: result.work.node_visits,
        edge_visits: result.work.edge_visits,
    })
}

pub fn postdominators<G>(
    graph: &G,
    entry: G::Node,
    normal_exit: G::Node,
    exceptional_exit: G::Node,
    request: &mut CfgAlgorithmRequest<'_>,
) -> AlgorithmResult<Postdominators<G::Node>, G::Node>
where
    G: DenseBidirectionalGraph,
{
    request.checkpoint()?;
    let started = request.budget.used();
    required_index(graph, entry)?;
    required_index(graph, normal_exit)?;
    required_index(graph, exceptional_exit)?;
    let live = forward_reachability(graph, entry, request)?;
    let normal_reaching = reverse_reachability(graph, normal_exit, request)?;
    let exceptional_reaching = reverse_reachability(graph, exceptional_exit, request)?;
    let analyzable = live
        .membership()
        .iter()
        .zip(normal_reaching.membership())
        .zip(exceptional_reaching.membership())
        .map(|((&live, &normal), &exceptional)| live && (normal || exceptional))
        .collect::<Vec<_>>();

    let components = strongly_connected_components(graph, request)?;
    let mut non_exiting_regions = Vec::new();
    for members in &components.components {
        request.checkpoint()?;
        let retained = members
            .iter()
            .copied()
            .filter(|node| {
                let index = graph
                    .node_index(*node)
                    .expect("SCC member belongs to graph");
                live.membership()[index] && !analyzable[index]
            })
            .collect::<Vec<_>>();
        if !retained.is_empty() {
            for _ in &retained {
                request.visit_node()?;
            }
            non_exiting_regions.push(NonExitingRegion {
                members: retained.into_boxed_slice(),
            });
        }
    }

    let synthetic = graph.node_count();
    let mut order = reverse_postorder_postdom(
        graph,
        synthetic,
        normal_exit,
        exceptional_exit,
        &analyzable,
        request,
    )?;
    debug_assert_eq!(order.first().copied(), Some(synthetic));
    let mut position = vec![usize::MAX; graph.node_count() + 1];
    for (offset, index) in order.iter().copied().enumerate() {
        request.checkpoint()?;
        position[index] = offset;
    }
    let mut immediate = vec![None; graph.node_count() + 1];
    immediate[synthetic] = Some(synthetic);
    let mut changed = true;
    while changed {
        changed = false;
        for index in order.iter().copied().skip(1) {
            request.visit_node()?;
            let node = required_node(graph, index);
            let mut predecessors = graph.successors(node).map(|(_, target)| target);
            let mut candidate = None;
            for successor in predecessors.by_ref() {
                request.visit_edge()?;
                let successor = required_index(graph, successor)?;
                if !analyzable[successor] || immediate[successor].is_none() {
                    continue;
                }
                candidate = Some(match candidate {
                    None => successor,
                    Some(current) => {
                        intersect_dominators(&immediate, &position, current, successor, request)?
                    }
                });
            }
            if node == normal_exit || node == exceptional_exit {
                request.visit_edge()?;
                candidate = Some(match candidate {
                    None => synthetic,
                    Some(current) => {
                        intersect_dominators(&immediate, &position, current, synthetic, request)?
                    }
                });
            }
            let candidate = candidate.expect("analyzable node reaches a real exit");
            if immediate[index] != Some(candidate) {
                immediate[index] = Some(candidate);
                changed = true;
            }
        }
    }
    order.clear();
    Ok(Postdominators {
        immediate: immediate.into_boxed_slice(),
        synthetic_exit: synthetic,
        non_exiting_regions: non_exiting_regions.into_boxed_slice(),
        unreachable_points: live.membership().iter().filter(|live| !**live).count(),
        work: request.budget.used().saturating_sub(started),
    })
}

fn reverse_postorder_postdom<G>(
    graph: &G,
    synthetic: usize,
    normal_exit: G::Node,
    exceptional_exit: G::Node,
    analyzable: &[bool],
    request: &mut CfgAlgorithmRequest<'_>,
) -> AlgorithmResult<Vec<usize>, G::Node>
where
    G: DenseBidirectionalGraph,
{
    let mut colors = vec![0_u8; graph.node_count() + 1];
    let mut postorder = Vec::new();
    let mut actions = vec![(synthetic, false)];
    while let Some((index, finish)) = actions.pop() {
        request.checkpoint()?;
        if finish {
            colors[index] = 2;
            postorder.push(index);
            continue;
        }
        if colors[index] != 0 {
            continue;
        }
        request.visit_node()?;
        colors[index] = 1;
        actions.push((index, true));
        if index == synthetic {
            for exit in [exceptional_exit, normal_exit] {
                request.visit_edge()?;
                let exit = required_index(graph, exit)?;
                if analyzable[exit] && colors[exit] == 0 {
                    actions.push((exit, false));
                }
            }
        } else {
            let node = required_node(graph, index);
            for (_, predecessor) in graph.predecessors(node).rev() {
                request.visit_edge()?;
                let predecessor = required_index(graph, predecessor)?;
                if analyzable[predecessor] && colors[predecessor] == 0 {
                    actions.push((predecessor, false));
                }
            }
        }
    }
    postorder.reverse();
    Ok(postorder)
}

pub fn control_dependence<G>(
    graph: &G,
    entry: G::Node,
    normal_exit: G::Node,
    exceptional_exit: G::Node,
    request: &mut CfgAlgorithmRequest<'_>,
) -> AlgorithmResult<ControlDependenceResult<G::Edge, G::Node>, G::Node>
where
    G: DenseBidirectionalGraph,
{
    let started = request.budget.used();
    let postdom = postdominators(graph, entry, normal_exit, exceptional_exit, request)?;
    let mut rows = Vec::new();
    for index in 0..graph.node_count() {
        request.checkpoint()?;
        let source = required_node(graph, index);
        if postdom.immediate[index].is_none() {
            continue;
        }
        let stop = postdom.immediate[index].expect("analyzable node has parent");
        for (edge, target) in graph.successors(source) {
            request.visit_edge()?;
            let mut runner = required_index(graph, target)?;
            if postdom.immediate[runner].is_none() || postdom.postdominates(graph, target, source) {
                continue;
            }
            while runner != stop {
                request.visit_node()?;
                if runner == postdom.synthetic_exit {
                    return Err(CfgAlgorithmError::InvalidNode(source));
                }
                rows.push(ControlDependenceRow {
                    controlling_edge: edge,
                    governed: required_node(graph, runner),
                });
                runner = postdom.immediate[runner]
                    .expect("analyzable postdominator chain reaches expected stop");
            }
        }
    }
    rows.sort_unstable();
    rows.dedup();
    Ok(ControlDependenceResult {
        rows: rows.into_boxed_slice(),
        non_exiting_regions: postdom.non_exiting_regions,
        unreachable_points: postdom.unreachable_points,
        work: request.budget.used().saturating_sub(started),
    })
}

fn intersect_dominators<Node>(
    immediate: &[Option<usize>],
    rpo_position: &[usize],
    mut first: usize,
    mut second: usize,
    request: &mut CfgAlgorithmRequest<'_>,
) -> Result<usize, CfgAlgorithmError<Node>> {
    while first != second {
        while rpo_position[first] > rpo_position[second] {
            request.visit_node::<Node>()?;
            first = immediate[first].expect("a processed node has an immediate dominator");
        }
        while rpo_position[second] > rpo_position[first] {
            request.visit_node::<Node>()?;
            second = immediate[second].expect("a processed node has an immediate dominator");
        }
    }
    Ok(first)
}

/// Deterministic reverse postorder over exactly the nodes reachable from `entry`.
fn reverse_postorder_from<G>(
    graph: &G,
    entry: G::Node,
    request: &mut CfgAlgorithmRequest<'_>,
) -> AlgorithmResult<Vec<G::Node>, G::Node>
where
    G: DenseBidirectionalGraph,
{
    required_index(graph, entry)?;
    let mut colors = vec![0_u8; graph.node_count()];
    let mut postorder = Vec::new();
    let mut actions = vec![DfsAction::Enter(entry)];

    while let Some(action) = actions.pop() {
        request.checkpoint()?;
        match action {
            DfsAction::Enter(node) => {
                let index = required_index(graph, node)?;
                if colors[index] != 0 {
                    continue;
                }
                request.visit_node()?;
                colors[index] = 1;
                actions.push(DfsAction::Finish(node));
                for (edge, target) in graph.successors(node).rev() {
                    request.visit_edge()?;
                    actions.push(DfsAction::Examine(edge, target));
                }
            }
            DfsAction::Examine(_, target) => {
                let target_index = required_index(graph, target)?;
                if colors[target_index] == 0 {
                    actions.push(DfsAction::Enter(target));
                }
            }
            DfsAction::Finish(node) => {
                let index = required_index(graph, node)?;
                colors[index] = 2;
                postorder.push(node);
            }
        }
    }

    postorder.reverse();
    Ok(postorder)
}

/// Definition identities per dense bitset word.
const DEFINITIONS_PER_WORD: usize = u64::BITS as usize;

/// Dense per-node generated and killed definition sets.
///
/// Definition identities are dense `usize` values minted by the caller. The
/// node count must match the graph the facts are solved over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenKillFacts {
    node_count: usize,
    definition_count: usize,
    words_per_node: usize,
    generated: Box<[u64]>,
    killed: Box<[u64]>,
}

impl GenKillFacts {
    pub fn new(node_count: usize, definition_count: usize) -> Self {
        let words_per_node = definition_count.div_ceil(DEFINITIONS_PER_WORD);
        let words = node_count
            .checked_mul(words_per_node)
            .expect("dense gen/kill words fit in memory");
        Self {
            node_count,
            definition_count,
            words_per_node,
            generated: vec![0; words].into_boxed_slice(),
            killed: vec![0; words].into_boxed_slice(),
        }
    }

    pub fn record_generated(&mut self, node_index: usize, definition: usize) {
        let (word, bit) = self.locate(node_index, definition);
        self.generated[word] |= bit;
    }

    pub fn record_killed(&mut self, node_index: usize, definition: usize) {
        let (word, bit) = self.locate(node_index, definition);
        self.killed[word] |= bit;
    }

    fn locate(&self, node_index: usize, definition: usize) -> (usize, u64) {
        assert!(
            node_index < self.node_count,
            "node index {node_index} outside {} nodes",
            self.node_count
        );
        assert!(
            definition < self.definition_count,
            "definition {definition} outside {} definitions",
            self.definition_count
        );
        (
            node_index * self.words_per_node + definition / DEFINITIONS_PER_WORD,
            1_u64 << (definition % DEFINITIONS_PER_WORD),
        )
    }
}

/// Complete may-reaching definition sets at every node's entry.
///
/// Only the IN sets are retained: a read at a program point consults the
/// definitions that reach that point, and the OUT set is the caller's own
/// transfer of IN through the node's gen/kill facts. Nodes unreachable from
/// the entry carry the empty set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReachingSets {
    node_count: usize,
    definition_count: usize,
    words_per_node: usize,
    entry_sets: Box<[u64]>,
    work: CfgAlgorithmWork,
}

impl ReachingSets {
    pub fn reaches_in(&self, node_index: usize, definition: usize) -> bool {
        assert!(
            node_index < self.node_count,
            "node index {node_index} outside {} nodes",
            self.node_count
        );
        assert!(
            definition < self.definition_count,
            "definition {definition} outside {} definitions",
            self.definition_count
        );
        let word = node_index * self.words_per_node + definition / DEFINITIONS_PER_WORD;
        self.entry_sets[word] & (1_u64 << (definition % DEFINITIONS_PER_WORD)) != 0
    }

    /// Ascending definition identities reaching the node's entry.
    pub fn reaching_in(&self, node_index: usize) -> impl Iterator<Item = usize> + '_ {
        assert!(
            node_index < self.node_count,
            "node index {node_index} outside {} nodes",
            self.node_count
        );
        let start = node_index * self.words_per_node;
        self.entry_sets[start..start + self.words_per_node]
            .iter()
            .copied()
            .enumerate()
            .flat_map(|(word, bits)| {
                (0..DEFINITIONS_PER_WORD)
                    .filter(move |bit| bits & (1_u64 << bit) != 0)
                    .map(move |bit| word * DEFINITIONS_PER_WORD + bit)
            })
    }

    pub const fn work(&self) -> CfgAlgorithmWork {
        self.work
    }
}

/// Classic forward may gen/kill fixed point seeded in reverse postorder.
///
/// The entry's IN set is the empty boundary set even when the entry has
/// predecessors, so a definition never reaches the procedure's own start.
pub fn reaching_definitions<G>(
    graph: &G,
    entry: G::Node,
    facts: &GenKillFacts,
    request: &mut CfgAlgorithmRequest<'_>,
) -> AlgorithmResult<ReachingSets, G::Node>
where
    G: DenseBidirectionalGraph,
{
    request.checkpoint()?;
    let started = request.budget.used();
    assert_eq!(
        facts.node_count,
        graph.node_count(),
        "gen/kill facts must cover exactly the graph's nodes"
    );
    let entry_index = required_index(graph, entry)?;
    let stride = facts.words_per_node;
    let order = reverse_postorder_from(graph, entry, request)?;

    let mut in_sets = vec![0_u64; graph.node_count() * stride];
    let mut out_sets = vec![0_u64; graph.node_count() * stride];
    let mut queued = vec![false; graph.node_count()];
    let mut worklist = VecDeque::with_capacity(order.len());
    for node in order {
        request.checkpoint()?;
        queued[required_index(graph, node)?] = true;
        worklist.push_back(node);
    }
    let mut incoming = vec![0_u64; stride];
    let mut transferred = vec![0_u64; stride];

    while let Some(node) = worklist.pop_front() {
        let index = required_index(graph, node)?;
        request.visit_node()?;
        queued[index] = false;
        let row = index * stride;

        incoming.fill(0);
        if index != entry_index {
            for (_, predecessor) in graph.predecessors(node) {
                request.visit_edge()?;
                let predecessor_row = required_index(graph, predecessor)? * stride;
                for word in 0..stride {
                    incoming[word] |= out_sets[predecessor_row + word];
                }
            }
        }
        in_sets[row..row + stride].copy_from_slice(&incoming);

        let mut changed = false;
        for word in 0..stride {
            let value = (incoming[word] & !facts.killed[row + word]) | facts.generated[row + word];
            transferred[word] = value;
            changed |= value != out_sets[row + word];
        }
        if !changed {
            continue;
        }
        out_sets[row..row + stride].copy_from_slice(&transferred);
        for (_, successor) in graph.successors(node) {
            request.visit_edge()?;
            let successor_index = required_index(graph, successor)?;
            if !queued[successor_index] {
                queued[successor_index] = true;
                worklist.push_back(successor);
            }
        }
    }

    Ok(ReachingSets {
        node_count: facts.node_count,
        definition_count: facts.definition_count,
        words_per_node: stride,
        entry_sets: in_sets.into_boxed_slice(),
        work: request.budget.used().saturating_sub(started),
    })
}

fn required_node<G>(graph: &G, index: usize) -> G::Node
where
    G: DenseBidirectionalGraph,
{
    graph
        .node_at(index)
        .expect("dense graph must map every in-range index to a node")
}

fn required_index<G>(graph: &G, node: G::Node) -> Result<usize, CfgAlgorithmError<G::Node>>
where
    G: DenseBidirectionalGraph,
{
    graph
        .node_index(node)
        .filter(|index| *index < graph.node_count())
        .ok_or(CfgAlgorithmError::InvalidNode(node))
}

#[cfg(test)]
mod test_support {
    use super::DenseBidirectionalGraph;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub struct SyntheticEdgeId(pub usize);

    #[derive(Debug, Clone)]
    struct SyntheticEdge {
        source: usize,
        target: usize,
        label: u8,
    }

    #[derive(Debug)]
    pub struct SyntheticGraph {
        nodes: usize,
        edges: Box<[SyntheticEdge]>,
        outgoing: Box<[Box<[SyntheticEdgeId]>]>,
        incoming: Box<[Box<[SyntheticEdgeId]>]>,
    }

    impl SyntheticGraph {
        pub fn new(nodes: usize, edges: &[(usize, usize, u8)]) -> Self {
            Self::from_edges(nodes, edges.iter().copied())
        }

        pub fn from_edges(
            nodes: usize,
            edges: impl IntoIterator<Item = (usize, usize, u8)>,
        ) -> Self {
            let mut edges = edges
                .into_iter()
                .map(|(source, target, label)| SyntheticEdge {
                    source,
                    target,
                    label,
                })
                .collect::<Vec<_>>();
            edges.sort_unstable_by_key(|edge| (edge.source, edge.target, edge.label));
            let mut outgoing = vec![Vec::new(); nodes];
            let mut incoming = vec![Vec::new(); nodes];
            for (index, edge) in edges.iter().enumerate() {
                assert!(edge.source < nodes && edge.target < nodes);
                let id = SyntheticEdgeId(index);
                outgoing[edge.source].push(id);
                incoming[edge.target].push(id);
            }
            Self {
                nodes,
                edges: edges.into_boxed_slice(),
                outgoing: outgoing.into_iter().map(Vec::into_boxed_slice).collect(),
                incoming: incoming.into_iter().map(Vec::into_boxed_slice).collect(),
            }
        }

        pub fn edge_count(&self) -> usize {
            self.edges.len()
        }

        pub fn edge_label(&self, edge: SyntheticEdgeId) -> Option<u8> {
            self.edges.get(edge.0).map(|edge| edge.label)
        }
    }

    impl DenseBidirectionalGraph for SyntheticGraph {
        type Node = usize;
        type Edge = SyntheticEdgeId;

        fn node_count(&self) -> usize {
            self.nodes
        }

        fn node_at(&self, index: usize) -> Option<Self::Node> {
            (index < self.nodes).then_some(index)
        }

        fn node_index(&self, node: Self::Node) -> Option<usize> {
            (node < self.nodes).then_some(node)
        }

        fn successors(
            &self,
            node: Self::Node,
        ) -> impl DoubleEndedIterator<Item = (Self::Edge, Self::Node)> + ExactSizeIterator + '_
        {
            self.outgoing[node]
                .iter()
                .copied()
                .map(|id| (id, self.edges[id.0].target))
        }

        fn predecessors(
            &self,
            node: Self::Node,
        ) -> impl DoubleEndedIterator<Item = (Self::Edge, Self::Node)> + ExactSizeIterator + '_
        {
            self.incoming[node]
                .iter()
                .copied()
                .map(|id| (id, self.edges[id.0].source))
        }

        fn edge_endpoints(&self, edge: Self::Edge) -> Option<(Self::Node, Self::Node)> {
            self.edges
                .get(edge.0)
                .map(|edge| (edge.source, edge.target))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::SyntheticGraph as TestGraph;
    use super::*;

    fn request<'request>(
        budget: &'request mut CfgAlgorithmBudget,
        cancellation: &'request CancellationToken,
    ) -> CfgAlgorithmRequest<'request> {
        CfgAlgorithmRequest::new(budget, cancellation)
    }

    #[test]
    fn reachability_is_dense_ordered_and_preserves_parallel_edge_work() {
        let graph = TestGraph::new(6, &[(2, 3, 4), (0, 2, 3), (0, 1, 9), (0, 1, 2), (1, 3, 1)]);
        let cancellation = CancellationToken::default();
        let mut budget = CfgAlgorithmBudget::uniform(100);
        let forward = forward_reachability(&graph, 0, &mut request(&mut budget, &cancellation))
            .expect("forward reachability");
        assert_eq!(forward.iter(&graph).collect::<Vec<_>>(), vec![0, 1, 2, 3]);
        assert!(forward.contains(&graph, 2));
        assert!(!forward.contains(&graph, 5));
        assert_eq!(
            forward.work(),
            CfgAlgorithmWork {
                node_visits: 4,
                edge_visits: 5
            }
        );

        let mut budget = CfgAlgorithmBudget::uniform(100);
        let reverse = reverse_reachability(&graph, 3, &mut request(&mut budget, &cancellation))
            .expect("reverse reachability");
        assert_eq!(reverse.iter(&graph).collect::<Vec<_>>(), vec![0, 1, 2, 3]);
    }

    #[test]
    fn dfs_rpo_and_back_edges_are_deterministic_for_permuted_edges() {
        let first = TestGraph::new(6, &[(3, 1, 0), (0, 2, 0), (2, 3, 0), (0, 1, 0), (1, 3, 0)]);
        let second = TestGraph::new(6, &[(0, 1, 0), (1, 3, 0), (0, 2, 0), (3, 1, 0), (2, 3, 0)]);
        let cancellation = CancellationToken::default();
        let run = |graph: &TestGraph| {
            let mut budget = CfgAlgorithmBudget::uniform(100);
            depth_first_order(graph, &mut request(&mut budget, &cancellation)).unwrap()
        };
        let first_order = run(&first);
        let second_order = run(&second);
        assert_eq!(first_order, second_order);
        assert_eq!(&*first_order.preorder, &[0, 1, 3, 2, 4, 5]);
        assert_eq!(&*first_order.reverse_postorder, &[5, 4, 0, 2, 1, 3]);
        assert_eq!(first_order.back_edges.len(), 1);
        assert_eq!(
            first.edge_endpoints(first_order.back_edges[0]),
            Some((3, 1))
        );
    }

    #[test]
    fn kosaraju_canonicalizes_nested_and_disconnected_components() {
        let graph = TestGraph::new(
            9,
            &[
                (0, 1, 0),
                (1, 2, 0),
                (2, 0, 0),
                (2, 3, 0),
                (3, 4, 0),
                (4, 3, 0),
                (6, 6, 0),
                (7, 8, 0),
            ],
        );
        let cancellation = CancellationToken::default();
        let mut budget = CfgAlgorithmBudget::uniform(1_000);
        let components =
            strongly_connected_components(&graph, &mut request(&mut budget, &cancellation))
                .unwrap();
        let members = components
            .components
            .iter()
            .map(|members| members.to_vec())
            .collect::<Vec<_>>();
        assert_eq!(
            members,
            vec![
                vec![0, 1, 2],
                vec![3, 4],
                vec![5],
                vec![6],
                vec![7],
                vec![8]
            ]
        );
        assert_eq!(components.component_of(&graph, 4), Some(1));
        assert_eq!(components.component_of(&graph, 99), None);
    }

    #[test]
    fn loop_regions_preserve_self_loops_and_irreducible_entries() {
        let graph = TestGraph::new(
            7,
            &[
                (0, 2, 0),
                (1, 3, 0),
                (2, 3, 0),
                (3, 4, 0),
                (4, 2, 0),
                (5, 5, 0),
            ],
        );
        let cancellation = CancellationToken::default();
        let mut budget = CfgAlgorithmBudget::uniform(1_000);
        let loops = loop_regions(&graph, &mut request(&mut budget, &cancellation)).unwrap();
        assert_eq!(loops.regions.len(), 2);
        assert_eq!(&*loops.regions[0].members, &[2, 3, 4]);
        assert_eq!(&*loops.regions[0].entries, &[2, 3]);
        assert_eq!(
            loops.regions[0].entry_structure,
            LoopEntryStructure::Multiple
        );
        assert!(!loops.regions[0].has_self_loop);
        assert!(!loops.regions[0].back_edges.is_empty());
        assert_eq!(&*loops.regions[1].members, &[5]);
        assert!(loops.regions[1].entries.is_empty());
        assert!(loops.regions[1].has_self_loop);
        assert_eq!(loops.regions[1].entry_structure, LoopEntryStructure::None);
    }

    #[test]
    fn loop_region_back_edges_are_partitioned_linearly_across_many_cycles() {
        let cycle_count = 1_000;
        let edges = (0..cycle_count)
            .flat_map(|cycle| {
                let first = cycle * 2;
                [(first, first + 1, 0), (first + 1, first, 0)]
            })
            .collect::<Vec<_>>();
        let graph = TestGraph::new(cycle_count * 2, &edges);
        let cancellation = CancellationToken::default();
        let mut budget = CfgAlgorithmBudget::uniform(edges.len() * 8);
        let loops = loop_regions(&graph, &mut request(&mut budget, &cancellation)).unwrap();

        assert_eq!(loops.regions.len(), cycle_count);
        assert!(
            loops
                .regions
                .iter()
                .all(|region| region.back_edges.len() == 1)
        );
        assert_eq!(
            loops.work,
            CfgAlgorithmWork {
                node_visits: graph.node_count() * 3,
                edge_visits: graph.edge_count() * 3,
            }
        );
    }

    #[test]
    fn shortest_path_uses_canonical_rich_edge_tie_breaking() {
        let graph = TestGraph::new(5, &[(0, 2, 0), (2, 4, 0), (0, 1, 9), (0, 1, 1), (1, 4, 0)]);
        let cancellation = CancellationToken::default();
        let mut budget = CfgAlgorithmBudget::uniform(100);
        let path = shortest_path(&graph, 0, 4, &mut request(&mut budget, &cancellation))
            .unwrap()
            .unwrap();
        assert_eq!(&*path.nodes, &[0, 1, 4]);
        assert_eq!(graph.edge_label(path.edges[0]), Some(1));

        let mut budget = CfgAlgorithmBudget::uniform(100);
        let zero = shortest_path(&graph, 3, 3, &mut request(&mut budget, &cancellation))
            .unwrap()
            .unwrap();
        assert_eq!(&*zero.nodes, &[3]);
        assert!(zero.edges.is_empty());

        let mut budget = CfgAlgorithmBudget::uniform(100);
        assert!(
            shortest_path(&graph, 4, 0, &mut request(&mut budget, &cancellation))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn shortest_path_cancellation_during_reconstruction_returns_no_path() {
        let node_count = 100;
        let edges = (0..node_count - 1)
            .map(|source| (source, source + 1, 0))
            .collect::<Vec<_>>();
        let graph = TestGraph::new(node_count, &edges);
        let cancellation = CancellationToken::cancel_after_checks_for_test(300);
        let mut budget = CfgAlgorithmBudget::uniform(1_000);

        assert!(matches!(
            shortest_path(
                &graph,
                0,
                node_count - 1,
                &mut request(&mut budget, &cancellation)
            ),
            Err(CfgAlgorithmError::Cancelled { .. })
        ));
    }

    #[test]
    fn shortest_path_reconstruction_is_charged_to_the_visit_budget() {
        let graph = TestGraph::new(4, &[(0, 1, 0), (1, 2, 0), (2, 3, 0)]);
        let cancellation = CancellationToken::default();
        let mut budget = CfgAlgorithmBudget::new(CfgAlgorithmWork {
            node_visits: 4,
            edge_visits: 3,
        });

        assert!(matches!(
            shortest_path(&graph, 0, 3, &mut request(&mut budget, &cancellation)),
            Err(CfgAlgorithmError::ExceededBudget(
                CfgAlgorithmBudgetExceeded {
                    limit_kind: CfgAlgorithmLimit::EdgeVisits,
                    attempted: 4,
                    ..
                }
            ))
        ));
    }

    #[test]
    fn scc_and_loop_emission_observe_cancellation_after_graph_visits() {
        let node_count = 32;
        let edges = (0..node_count)
            .map(|source| (source, (source + 1) % node_count, 0))
            .collect::<Vec<_>>();
        let graph = TestGraph::new(node_count, &edges);

        let cancellation = CancellationToken::default();
        let mut budget = CfgAlgorithmBudget::uniform(1_000);
        let scc_work =
            strongly_connected_components(&graph, &mut request(&mut budget, &cancellation))
                .unwrap()
                .work;
        let mut cancelled_during_scc_emission = false;
        for checks in 1..1_000 {
            let cancellation = CancellationToken::cancel_after_checks_for_test(checks);
            let mut budget = CfgAlgorithmBudget::uniform(1_000);
            if matches!(
                strongly_connected_components(
                    &graph,
                    &mut request(&mut budget, &cancellation)
                ),
                Err(CfgAlgorithmError::Cancelled { work }) if work == scc_work
            ) {
                cancelled_during_scc_emission = true;
                break;
            }
        }
        assert!(cancelled_during_scc_emission);

        let cancellation = CancellationToken::default();
        let mut budget = CfgAlgorithmBudget::uniform(1_000);
        let loop_work = loop_regions(&graph, &mut request(&mut budget, &cancellation))
            .unwrap()
            .work;
        let mut cancelled_during_loop_emission = false;
        for checks in 1..2_000 {
            let cancellation = CancellationToken::cancel_after_checks_for_test(checks);
            let mut budget = CfgAlgorithmBudget::uniform(1_000);
            if matches!(
                loop_regions(&graph, &mut request(&mut budget, &cancellation)),
                Err(CfgAlgorithmError::Cancelled { work }) if work == loop_work
            ) {
                cancelled_during_loop_emission = true;
                break;
            }
        }
        assert!(cancelled_during_loop_emission);
    }

    #[test]
    fn invalid_nodes_budget_exhaustion_and_cancellation_are_typed() {
        let graph = TestGraph::new(3, &[(0, 1, 0), (1, 2, 0)]);
        let cancellation = CancellationToken::default();
        let mut budget = CfgAlgorithmBudget::uniform(10);
        assert_eq!(
            forward_reachability(&graph, 9, &mut request(&mut budget, &cancellation)),
            Err(CfgAlgorithmError::InvalidNode(9))
        );

        let mut budget = CfgAlgorithmBudget::new(CfgAlgorithmWork {
            node_visits: 1,
            edge_visits: 10,
        });
        let error =
            forward_reachability(&graph, 0, &mut request(&mut budget, &cancellation)).unwrap_err();
        assert!(matches!(
            error,
            CfgAlgorithmError::ExceededBudget(CfgAlgorithmBudgetExceeded {
                limit_kind: CfgAlgorithmLimit::NodeVisits,
                ..
            })
        ));

        let mut budget = CfgAlgorithmBudget::new(CfgAlgorithmWork {
            node_visits: 10,
            edge_visits: 0,
        });
        let error =
            forward_reachability(&graph, 0, &mut request(&mut budget, &cancellation)).unwrap_err();
        assert!(matches!(
            error,
            CfgAlgorithmError::ExceededBudget(CfgAlgorithmBudgetExceeded {
                limit_kind: CfgAlgorithmLimit::EdgeVisits,
                ..
            })
        ));

        let cancelled = CancellationToken::default();
        cancelled.cancel();
        let mut budget = CfgAlgorithmBudget::uniform(10);
        assert!(matches!(
            forward_reachability(&graph, 0, &mut request(&mut budget, &cancelled)),
            Err(CfgAlgorithmError::Cancelled {
                work: CfgAlgorithmWork {
                    node_visits: 0,
                    edge_visits: 0
                }
            })
        ));

        let mid_traversal = CancellationToken::cancel_after_checks_for_test(5);
        let mut budget = CfgAlgorithmBudget::uniform(10);
        assert!(matches!(
            forward_reachability(&graph, 0, &mut request(&mut budget, &mid_traversal)),
            Err(CfgAlgorithmError::Cancelled { .. })
        ));
    }

    #[test]
    fn dominance_on_a_diamond_separates_branches_from_the_join() {
        let graph = TestGraph::new(5, &[(0, 1, 0), (0, 2, 0), (1, 3, 0), (2, 3, 0)]);
        let cancellation = CancellationToken::default();
        let mut budget = CfgAlgorithmBudget::uniform(100);
        let dominance = dominators(&graph, 0, &mut request(&mut budget, &cancellation)).unwrap();

        assert_eq!(dominance.immediate_dominator(&graph, 0), None);
        assert_eq!(dominance.immediate_dominator(&graph, 1), Some(0));
        assert_eq!(dominance.immediate_dominator(&graph, 2), Some(0));
        assert_eq!(dominance.immediate_dominator(&graph, 3), Some(0));
        for node in 0..4 {
            assert!(dominance.dominates(&graph, 0, node));
            assert!(dominance.dominates(&graph, node, node));
        }
        assert!(!dominance.dominates(&graph, 1, 3));
        assert!(!dominance.dominates(&graph, 2, 3));
        assert!(!dominance.dominates(&graph, 3, 1));

        assert_eq!(dominance.immediate_dominator(&graph, 4), None);
        assert!(!dominance.dominates(&graph, 4, 4));
        assert!(!dominance.dominates(&graph, 0, 4));
        assert!(!dominance.dominates(&graph, 4, 3));
        assert_eq!(dominance.immediate_dominator(&graph, 9), None);
        assert!(!dominance.dominates(&graph, 9, 0));
        assert!(dominance.work().node_visits > 0);
    }

    #[test]
    fn dominance_on_a_loop_puts_the_header_over_the_body() {
        let graph = TestGraph::new(4, &[(0, 1, 0), (1, 2, 0), (1, 3, 0), (2, 1, 0)]);
        let cancellation = CancellationToken::default();
        let mut budget = CfgAlgorithmBudget::uniform(1_000);
        let dominance = dominators(&graph, 0, &mut request(&mut budget, &cancellation)).unwrap();

        assert_eq!(dominance.immediate_dominator(&graph, 1), Some(0));
        assert_eq!(dominance.immediate_dominator(&graph, 2), Some(1));
        assert_eq!(dominance.immediate_dominator(&graph, 3), Some(1));
        assert!(dominance.dominates(&graph, 1, 2));
        assert!(dominance.dominates(&graph, 1, 3));
        assert!(!dominance.dominates(&graph, 2, 3));
    }

    #[test]
    fn dominance_reports_invalid_entries_and_typed_budget_exhaustion() {
        let graph = TestGraph::new(4, &[(0, 1, 0), (1, 2, 0), (2, 3, 0)]);
        let cancellation = CancellationToken::default();
        let mut budget = CfgAlgorithmBudget::uniform(100);
        assert_eq!(
            dominators(&graph, 9, &mut request(&mut budget, &cancellation)),
            Err(CfgAlgorithmError::InvalidNode(9))
        );

        let mut budget = CfgAlgorithmBudget::new(CfgAlgorithmWork {
            node_visits: 2,
            edge_visits: 100,
        });
        assert!(matches!(
            dominators(&graph, 0, &mut request(&mut budget, &cancellation)),
            Err(CfgAlgorithmError::ExceededBudget(
                CfgAlgorithmBudgetExceeded {
                    limit_kind: CfgAlgorithmLimit::NodeVisits,
                    limit: 2,
                    ..
                }
            ))
        ));

        let cancelled = CancellationToken::default();
        cancelled.cancel();
        let mut budget = CfgAlgorithmBudget::uniform(100);
        assert!(matches!(
            dominators(&graph, 0, &mut request(&mut budget, &cancelled)),
            Err(CfgAlgorithmError::Cancelled { .. })
        ));
    }

    #[test]
    fn reaching_definitions_carry_a_straight_line_definition_until_a_kill() {
        let graph = TestGraph::new(4, &[(0, 1, 0), (1, 2, 0), (2, 3, 0)]);
        let mut facts = GenKillFacts::new(4, 2);
        for definition in 0..2 {
            facts.record_killed(0, definition);
            facts.record_killed(2, definition);
        }
        facts.record_generated(0, 0);
        facts.record_generated(2, 1);

        let cancellation = CancellationToken::default();
        let mut budget = CfgAlgorithmBudget::uniform(1_000);
        let reaching =
            reaching_definitions(&graph, 0, &facts, &mut request(&mut budget, &cancellation))
                .unwrap();

        assert_eq!(
            reaching.reaching_in(0).collect::<Vec<usize>>(),
            Vec::<usize>::new()
        );
        assert_eq!(reaching.reaching_in(1).collect::<Vec<_>>(), vec![0]);
        assert!(reaching.reaches_in(2, 0));
        assert_eq!(reaching.reaching_in(3).collect::<Vec<_>>(), vec![1]);
        assert!(!reaching.reaches_in(3, 0));
        assert!(reaching.work().node_visits > 0);
    }

    #[test]
    fn reaching_definitions_join_both_arms_of_a_diamond() {
        let graph = TestGraph::new(5, &[(0, 1, 0), (0, 2, 0), (1, 3, 0), (2, 3, 0)]);
        let mut facts = GenKillFacts::new(5, 3);
        for node in [0, 1, 2] {
            for definition in 0..3 {
                facts.record_killed(node, definition);
            }
            facts.record_generated(node, node);
        }

        let cancellation = CancellationToken::default();
        let mut budget = CfgAlgorithmBudget::uniform(1_000);
        let reaching =
            reaching_definitions(&graph, 0, &facts, &mut request(&mut budget, &cancellation))
                .unwrap();

        assert_eq!(reaching.reaching_in(1).collect::<Vec<_>>(), vec![0]);
        assert_eq!(reaching.reaching_in(2).collect::<Vec<_>>(), vec![0]);
        assert_eq!(reaching.reaching_in(3).collect::<Vec<_>>(), vec![1, 2]);
        assert!(!reaching.reaches_in(3, 0));
        assert_eq!(
            reaching.reaching_in(4).collect::<Vec<usize>>(),
            Vec::<usize>::new()
        );
    }

    #[test]
    fn reaching_definitions_propagate_a_loop_body_definition_back_to_the_header() {
        let graph = TestGraph::new(4, &[(0, 1, 0), (1, 2, 0), (1, 3, 0), (2, 1, 0)]);
        let mut facts = GenKillFacts::new(4, 2);
        for node in [0, 2] {
            for definition in 0..2 {
                facts.record_killed(node, definition);
            }
        }
        facts.record_generated(0, 0);
        facts.record_generated(2, 1);

        let cancellation = CancellationToken::default();
        let mut budget = CfgAlgorithmBudget::uniform(1_000);
        let reaching =
            reaching_definitions(&graph, 0, &facts, &mut request(&mut budget, &cancellation))
                .unwrap();

        assert_eq!(reaching.reaching_in(1).collect::<Vec<_>>(), vec![0, 1]);
        assert_eq!(reaching.reaching_in(2).collect::<Vec<_>>(), vec![0, 1]);
        assert_eq!(reaching.reaching_in(3).collect::<Vec<_>>(), vec![0, 1]);
    }

    #[test]
    fn reaching_definitions_report_typed_budget_exhaustion_and_cancellation() {
        let graph = TestGraph::new(4, &[(0, 1, 0), (1, 2, 0), (2, 3, 0)]);
        let facts = GenKillFacts::new(4, 1);
        let cancellation = CancellationToken::default();

        let mut budget = CfgAlgorithmBudget::new(CfgAlgorithmWork {
            node_visits: 3,
            edge_visits: 100,
        });
        assert!(matches!(
            reaching_definitions(&graph, 0, &facts, &mut request(&mut budget, &cancellation)),
            Err(CfgAlgorithmError::ExceededBudget(
                CfgAlgorithmBudgetExceeded {
                    limit_kind: CfgAlgorithmLimit::NodeVisits,
                    limit: 3,
                    ..
                }
            ))
        ));

        let mut budget = CfgAlgorithmBudget::new(CfgAlgorithmWork {
            node_visits: 100,
            edge_visits: 2,
        });
        assert!(matches!(
            reaching_definitions(&graph, 0, &facts, &mut request(&mut budget, &cancellation)),
            Err(CfgAlgorithmError::ExceededBudget(
                CfgAlgorithmBudgetExceeded {
                    limit_kind: CfgAlgorithmLimit::EdgeVisits,
                    ..
                }
            ))
        ));

        let mid_traversal = CancellationToken::cancel_after_checks_for_test(3);
        let mut budget = CfgAlgorithmBudget::uniform(1_000);
        assert!(matches!(
            reaching_definitions(&graph, 0, &facts, &mut request(&mut budget, &mid_traversal)),
            Err(CfgAlgorithmError::Cancelled { .. })
        ));
    }

    #[test]
    fn dominance_and_reaching_definitions_are_deterministic_across_runs() {
        let graph = TestGraph::new(
            7,
            &[
                (0, 1, 0),
                (0, 2, 0),
                (1, 3, 0),
                (2, 3, 0),
                (3, 4, 0),
                (4, 3, 0),
                (4, 5, 0),
            ],
        );
        let mut facts = GenKillFacts::new(7, 4);
        for (node, definition) in [(0_usize, 0_usize), (1, 1), (2, 2), (4, 3)] {
            for killed in 0..4 {
                facts.record_killed(node, killed);
            }
            facts.record_generated(node, definition);
        }
        let cancellation = CancellationToken::default();

        let run = || {
            let mut budget = CfgAlgorithmBudget::uniform(10_000);
            let mut request = CfgAlgorithmRequest::new(&mut budget, &cancellation);
            let dominance = dominators(&graph, 0, &mut request).unwrap();
            let reaching = reaching_definitions(&graph, 0, &facts, &mut request).unwrap();
            (dominance, reaching)
        };
        assert_eq!(run(), run());

        let (dominance, reaching) = run();
        assert_eq!(dominance.immediate_dominator(&graph, 3), Some(0));
        assert_eq!(dominance.immediate_dominator(&graph, 5), Some(4));
        assert!(dominance.dominates(&graph, 3, 5));
        assert_eq!(reaching.reaching_in(3).collect::<Vec<_>>(), vec![1, 2, 3]);
        assert_eq!(
            reaching.reaching_in(6).collect::<Vec<usize>>(),
            Vec::<usize>::new()
        );
    }

    #[test]
    fn hundred_thousand_node_chain_is_stack_safe() {
        let node_count = 100_000;
        let edges = (0..node_count - 1)
            .map(|source| (source, source + 1, 0))
            .collect::<Vec<_>>();
        let graph = TestGraph::new(node_count, &edges);
        let cancellation = CancellationToken::default();

        let mut budget = CfgAlgorithmBudget::uniform(node_count * 4);
        let order = depth_first_order(&graph, &mut request(&mut budget, &cancellation)).unwrap();
        assert_eq!(order.preorder.len(), node_count);
        assert_eq!(order.reverse_postorder.len(), node_count);

        let mut budget = CfgAlgorithmBudget::uniform(node_count * 4);
        let components =
            strongly_connected_components(&graph, &mut request(&mut budget, &cancellation))
                .unwrap();
        assert_eq!(components.components.len(), node_count);
    }

    #[test]
    fn postdominators_and_control_dependence_cover_diamond_and_two_exits() {
        // 0 branches to 1/2, joins at 3, then selects normal 4 or exceptional 5.
        let graph = TestGraph::new(
            6,
            &[
                (0, 1, 1),
                (0, 2, 2),
                (1, 3, 0),
                (2, 3, 0),
                (3, 4, 3),
                (3, 5, 4),
            ],
        );
        let cancellation = CancellationToken::default();
        let mut budget = CfgAlgorithmBudget::uniform(10_000);
        let postdom =
            postdominators(&graph, 0, 4, 5, &mut request(&mut budget, &cancellation)).unwrap();
        assert_eq!(postdom.immediate_postdominator(&graph, 0), Some(3));
        assert_eq!(postdom.immediate_postdominator(&graph, 1), Some(3));
        assert_eq!(postdom.immediate_postdominator(&graph, 3), None);
        assert!(postdom.postdominates(&graph, 3, 0));
        assert!(!postdom.postdominates(&graph, 1, 0));

        let mut budget = CfgAlgorithmBudget::uniform(10_000);
        let result =
            control_dependence(&graph, 0, 4, 5, &mut request(&mut budget, &cancellation)).unwrap();
        let rows = result
            .rows
            .iter()
            .map(|row| {
                (
                    graph.edge_label(row.controlling_edge).unwrap(),
                    row.governed,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(rows, vec![(1, 1), (2, 2), (3, 4), (4, 5)]);
        assert!(result.non_exiting_regions.is_empty());
        assert_eq!(result.unreachable_points, 0);
    }

    #[test]
    fn postdominators_report_unreachable_and_live_non_exiting_regions() {
        // 0->1->4 exits; 0->2->3->2 is a live non-exiting SCC; 5 is unreachable.
        let graph = TestGraph::new(6, &[(0, 1, 0), (1, 4, 0), (0, 2, 1), (2, 3, 0), (3, 2, 0)]);
        let cancellation = CancellationToken::default();
        let mut budget = CfgAlgorithmBudget::uniform(10_000);
        let postdom =
            postdominators(&graph, 0, 4, 4, &mut request(&mut budget, &cancellation)).unwrap();
        assert_eq!(postdom.unreachable_points, 1);
        assert_eq!(postdom.non_exiting_regions.len(), 1);
        assert_eq!(&*postdom.non_exiting_regions[0].members, &[2, 3]);
        assert_eq!(postdom.immediate_postdominator(&graph, 2), None);
    }

    #[test]
    fn hundred_thousand_node_postdominator_chain_is_stack_safe() {
        let node_count = 100_000;
        let graph = TestGraph::from_edges(
            node_count,
            (0..node_count - 1).map(|source| (source, source + 1, 0)),
        );
        let cancellation = CancellationToken::default();
        let mut budget = CfgAlgorithmBudget::uniform(node_count * 30);
        let postdom = postdominators(
            &graph,
            0,
            node_count - 1,
            node_count - 1,
            &mut request(&mut budget, &cancellation),
        )
        .unwrap();
        assert_eq!(postdom.immediate_postdominator(&graph, 0), Some(1));
        assert!(postdom.postdominates(&graph, node_count - 1, 0));
    }

    fn oracle_paths(graph: &TestGraph, start: usize, exits: [usize; 2]) -> Vec<Vec<usize>> {
        let mut paths = Vec::new();
        let mut stack = vec![(start, vec![start])];
        while let Some((node, path)) = stack.pop() {
            if exits.contains(&node) {
                paths.push(path);
                continue;
            }
            for (_, successor) in graph.successors(node).rev() {
                if !path.contains(&successor) {
                    let mut next = path.clone();
                    next.push(successor);
                    stack.push((successor, next));
                }
            }
        }
        paths
    }

    fn oracle_postdominators(
        graph: &TestGraph,
        exits: [usize; 2],
    ) -> Vec<std::collections::BTreeSet<usize>> {
        (0..graph.node_count())
            .map(|node| {
                let paths = oracle_paths(graph, node, exits);
                let Some(first) = paths.first() else {
                    return std::collections::BTreeSet::new();
                };
                let mut common = first
                    .iter()
                    .copied()
                    .collect::<std::collections::BTreeSet<_>>();
                for path in paths.iter().skip(1) {
                    let members = path
                        .iter()
                        .copied()
                        .collect::<std::collections::BTreeSet<_>>();
                    common.retain(|node| members.contains(node));
                }
                common
            })
            .collect()
    }

    #[test]
    fn exhaustive_four_node_oracle_agrees_with_production() {
        // Enumerate every simple directed topology without self edges. Entry is
        // 0 and the distinct real exits are 2 and 3. Retain exactly graphs in
        // which every entry-live node has a finite path to either exit.
        let candidates = (0..4)
            .flat_map(|source| {
                (0..4)
                    .filter(move |target| *target != source)
                    .map(move |target| (source, target))
            })
            .collect::<Vec<_>>();
        let mut retained = 0;
        for mask in 0_u16..(1_u16 << candidates.len()) {
            let edges = candidates
                .iter()
                .enumerate()
                .filter(|(bit, _)| mask & (1 << bit) != 0)
                .map(|(_, &(source, target))| (source, target, 0))
                .collect::<Vec<_>>();
            let graph = TestGraph::new(4, &edges);
            let oracle = oracle_postdominators(&graph, [2, 3]);
            let live = {
                let cancellation = CancellationToken::default();
                let mut budget = CfgAlgorithmBudget::uniform(10_000);
                forward_reachability(&graph, 0, &mut request(&mut budget, &cancellation)).unwrap()
            };
            if live.iter(&graph).any(|node| oracle[node].is_empty()) {
                continue;
            }
            retained += 1;
            let cancellation = CancellationToken::default();
            let mut budget = CfgAlgorithmBudget::uniform(100_000);
            let production =
                postdominators(&graph, 0, 2, 3, &mut request(&mut budget, &cancellation)).unwrap();
            for node in live.iter(&graph) {
                for candidate in live.iter(&graph) {
                    assert_eq!(
                        production.postdominates(&graph, candidate, node),
                        oracle[node].contains(&candidate),
                        "mask={mask:#x} candidate={candidate} node={node}"
                    );
                }
            }
            let mut expected_rows = std::collections::BTreeSet::new();
            for source in live.iter(&graph) {
                for (edge, target) in graph.successors(source) {
                    for governed in live.iter(&graph) {
                        if oracle[target].contains(&governed)
                            && (governed == source || !oracle[source].contains(&governed))
                        {
                            expected_rows.insert((edge, governed));
                        }
                    }
                }
            }
            let expected_rows = expected_rows.into_iter().collect::<Vec<_>>();
            let mut budget = CfgAlgorithmBudget::uniform(100_000);
            let control =
                control_dependence(&graph, 0, 2, 3, &mut request(&mut budget, &cancellation))
                    .unwrap();
            let actual_rows = control
                .rows
                .iter()
                .map(|row| (row.controlling_edge, row.governed))
                .collect::<Vec<_>>();
            assert_eq!(actual_rows, expected_rows, "control rows mask={mask:#x}");
        }
        assert!(retained > 500, "retained {retained} exhaustive graphs");
    }
}
