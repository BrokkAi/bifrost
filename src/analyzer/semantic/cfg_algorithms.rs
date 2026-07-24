//! Stack-safe, request-bounded algorithms over immutable dense control-flow graphs.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "issue #819 intentionally provides crate-internal on-demand algorithms before every derivation has a production consumer"
    )
)]

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
pub(crate) trait DenseBidirectionalGraph {
    type Node: Copy + Eq + Ord + std::fmt::Debug;
    type Edge: Copy + Eq + Ord + std::fmt::Debug;

    fn node_count(&self) -> usize;
    fn node_at(&self, index: usize) -> Option<Self::Node>;
    fn node_index(&self, node: Self::Node) -> Option<usize>;
    fn edge_index(&self, edge: Self::Edge) -> Option<usize>;
    fn successors(
        &self,
        node: Self::Node,
    ) -> impl ExactSizeIterator<Item = (Self::Edge, Self::Node)> + '_;
    fn successors_reversed(
        &self,
        node: Self::Node,
    ) -> impl ExactSizeIterator<Item = (Self::Edge, Self::Node)> + '_;
    fn predecessors(
        &self,
        node: Self::Node,
    ) -> impl ExactSizeIterator<Item = (Self::Edge, Self::Node)> + '_;
    fn predecessors_reversed(
        &self,
        node: Self::Node,
    ) -> impl ExactSizeIterator<Item = (Self::Edge, Self::Node)> + '_;
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

    fn edge_index(&self, edge: Self::Edge) -> Option<usize> {
        (edge.index() < self.control_edges().len()).then_some(edge.index())
    }

    fn successors(
        &self,
        node: Self::Node,
    ) -> impl ExactSizeIterator<Item = (Self::Edge, Self::Node)> + '_ {
        self.successor_edges(node)
            .map(|(edge_id, edge)| (edge_id, edge.target_point))
    }

    fn successors_reversed(
        &self,
        node: Self::Node,
    ) -> impl ExactSizeIterator<Item = (Self::Edge, Self::Node)> + '_ {
        self.successor_edges_reversed(node)
            .map(|(edge_id, edge)| (edge_id, edge.target_point))
    }

    fn predecessors(
        &self,
        node: Self::Node,
    ) -> impl ExactSizeIterator<Item = (Self::Edge, Self::Node)> + '_ {
        self.predecessor_edges(node)
            .map(|(edge_id, edge)| (edge_id, edge.source_point))
    }

    fn predecessors_reversed(
        &self,
        node: Self::Node,
    ) -> impl ExactSizeIterator<Item = (Self::Edge, Self::Node)> + '_ {
        self.predecessor_edges_reversed(node)
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
    pub(crate) enum CfgAlgorithmLimit;
    /// Work completed by one or more algorithms sharing a request-local budget.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
    pub(crate) struct CfgAlgorithmWork;
    all: [2];
    NodeVisits => node_visits = usize::MAX,
    EdgeVisits => edge_visits = usize::MAX,
}

/// Exact failed node- or edge-visit charge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CfgAlgorithmBudgetExceeded {
    pub(crate) limit_kind: CfgAlgorithmLimit,
    pub(crate) limit: usize,
    pub(crate) attempted: usize,
    pub(crate) work: CfgAlgorithmWork,
}

/// Request-local two-dimensional CFG work budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CfgAlgorithmBudget {
    ledger: BudgetLedger<CfgAlgorithmWork>,
}

impl CfgAlgorithmBudget {
    pub(crate) const fn new(limits: CfgAlgorithmWork) -> Self {
        Self {
            ledger: BudgetLedger::new(limits, CfgAlgorithmWork::uniform(0)),
        }
    }

    pub(crate) const fn uniform(limit: usize) -> Self {
        Self::new(CfgAlgorithmWork {
            node_visits: limit,
            edge_visits: limit,
        })
    }

    pub(crate) const fn limits(&self) -> CfgAlgorithmWork {
        self.ledger.limits()
    }

    pub(crate) const fn used(&self) -> CfgAlgorithmWork {
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
pub(crate) enum CfgAlgorithmError<Node> {
    InvalidNode(Node),
    Cancelled { work: CfgAlgorithmWork },
    ExceededBudget(CfgAlgorithmBudgetExceeded),
}

/// Borrowed controls shared by all CFG algorithms.
#[derive(Debug)]
pub(crate) struct CfgAlgorithmRequest<'request> {
    pub(crate) budget: &'request mut CfgAlgorithmBudget,
    pub(crate) cancellation: &'request CancellationToken,
}

impl<'request> CfgAlgorithmRequest<'request> {
    pub(crate) const fn new(
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

    fn visit_node<Node>(&mut self) -> Result<(), CfgAlgorithmError<Node>> {
        self.checkpoint()?;
        self.budget
            .charge(CfgAlgorithmWork {
                node_visits: 1,
                edge_visits: 0,
            })
            .map_err(CfgAlgorithmError::ExceededBudget)
    }

    fn visit_edge<Node>(&mut self) -> Result<(), CfgAlgorithmError<Node>> {
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
pub(crate) struct Reachability<Node> {
    membership: Box<[bool]>,
    work: CfgAlgorithmWork,
    node: std::marker::PhantomData<Node>,
}

impl<Node: Copy> Reachability<Node> {
    pub(crate) fn contains<G>(&self, graph: &G, node: Node) -> bool
    where
        G: DenseBidirectionalGraph<Node = Node>,
    {
        graph
            .node_index(node)
            .and_then(|index| self.membership.get(index))
            .copied()
            .unwrap_or(false)
    }

    pub(crate) fn iter<'graph, G>(
        &'graph self,
        graph: &'graph G,
    ) -> impl Iterator<Item = Node> + 'graph
    where
        G: DenseBidirectionalGraph<Node = Node> + 'graph,
    {
        self.membership
            .iter()
            .enumerate()
            .filter_map(|(index, reachable)| reachable.then(|| required_node(graph, index)))
    }

    pub(crate) fn membership(&self) -> &[bool] {
        &self.membership
    }

    pub(crate) const fn work(&self) -> CfgAlgorithmWork {
        self.work
    }
}

#[derive(Debug, Clone, Copy)]
enum Direction {
    Forward,
    Reverse,
}

pub(crate) fn forward_reachability<G>(
    graph: &G,
    start: G::Node,
    request: &mut CfgAlgorithmRequest<'_>,
) -> Result<Reachability<G::Node>, CfgAlgorithmError<G::Node>>
where
    G: DenseBidirectionalGraph,
{
    reachability(graph, start, Direction::Forward, request)
}

pub(crate) fn reverse_reachability<G>(
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
                graph.successors_reversed(node),
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
pub(crate) struct DepthFirstOrder<Node, Edge> {
    pub(crate) preorder: Box<[Node]>,
    pub(crate) postorder: Box<[Node]>,
    pub(crate) reverse_postorder: Box<[Node]>,
    pub(crate) back_edges: Box<[Edge]>,
    pub(crate) work: CfgAlgorithmWork,
}

enum DfsAction<Node, Edge> {
    Enter(Node),
    Examine(Edge, Node),
    Finish(Node),
}

pub(crate) fn depth_first_order<G>(
    graph: &G,
    request: &mut CfgAlgorithmRequest<'_>,
) -> Result<DepthFirstOrder<G::Node, G::Edge>, CfgAlgorithmError<G::Node>>
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
                    for (edge, target) in graph.successors_reversed(node) {
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
pub(crate) struct StronglyConnectedComponents<Node> {
    pub(crate) components: Box<[Box<[Node]>]>,
    component_by_node: Box<[usize]>,
    pub(crate) work: CfgAlgorithmWork,
}

impl<Node: Copy> StronglyConnectedComponents<Node> {
    pub(crate) fn component_of<G>(&self, graph: &G, node: Node) -> Option<usize>
    where
        G: DenseBidirectionalGraph<Node = Node>,
    {
        graph
            .node_index(node)
            .and_then(|index| self.component_by_node.get(index))
            .copied()
    }
}

pub(crate) fn strongly_connected_components<G>(
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
) -> Result<
    (
        StronglyConnectedComponents<G::Node>,
        DepthFirstOrder<G::Node, G::Edge>,
    ),
    CfgAlgorithmError<G::Node>,
>
where
    G: DenseBidirectionalGraph,
{
    request.checkpoint()?;
    let started = request.budget.used();
    let order = depth_first_order(graph, request)?;
    let mut assigned = vec![false; graph.node_count()];
    let mut unsorted_components = Vec::<Vec<G::Node>>::new();

    for seed in order.reverse_postorder.iter().copied() {
        let seed_index = required_index(graph, seed)?;
        if assigned[seed_index] {
            continue;
        }
        assigned[seed_index] = true;
        let mut stack = vec![seed];
        let mut members = Vec::new();
        while let Some(node) = stack.pop() {
            request.visit_node()?;
            members.push(node);
            for (_, predecessor) in graph.predecessors_reversed(node) {
                request.visit_edge()?;
                let predecessor_index = required_index(graph, predecessor)?;
                if !assigned[predecessor_index] {
                    assigned[predecessor_index] = true;
                    stack.push(predecessor);
                }
            }
        }
        members.sort_unstable_by_key(|node| {
            graph
                .node_index(*node)
                .expect("component members came from the graph")
        });
        unsorted_components.push(members);
    }

    unsorted_components.sort_unstable_by_key(|members| {
        graph
            .node_index(members[0])
            .expect("component members came from the graph")
    });
    let mut component_by_node = vec![usize::MAX; graph.node_count()];
    let components = unsorted_components
        .into_iter()
        .enumerate()
        .map(|(component, members)| {
            for &node in &members {
                component_by_node[graph
                    .node_index(node)
                    .expect("component members came from the graph")] = component;
            }
            members.into_boxed_slice()
        })
        .collect::<Vec<_>>()
        .into_boxed_slice();

    Ok((
        StronglyConnectedComponents {
            components,
            component_by_node: component_by_node.into_boxed_slice(),
            work: request.budget.used().saturating_sub(started),
        },
        order,
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LoopEntryStructure {
    NoEntry,
    SingleEntry,
    MultiEntry,
}

/// One cyclic SCC described without an unsupported dominance claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LoopRegion<Node, Edge> {
    pub(crate) members: Box<[Node]>,
    pub(crate) entries: Box<[Node]>,
    pub(crate) entry_structure: LoopEntryStructure,
    pub(crate) back_edges: Box<[Edge]>,
    pub(crate) has_self_loop: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LoopRegions<Node, Edge> {
    pub(crate) regions: Box<[LoopRegion<Node, Edge>]>,
    pub(crate) work: CfgAlgorithmWork,
}

pub(crate) fn loop_regions<G>(
    graph: &G,
    request: &mut CfgAlgorithmRequest<'_>,
) -> Result<LoopRegions<G::Node, G::Edge>, CfgAlgorithmError<G::Node>>
where
    G: DenseBidirectionalGraph,
{
    request.checkpoint()?;
    let started = request.budget.used();
    let (components, dfs) = strongly_connected_components_with_order(graph, request)?;
    let mut self_loops = vec![false; components.components.len()];
    let mut entries = vec![Vec::<G::Node>::new(); components.components.len()];
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
                entries[target_component].push(target);
            }
        }
    }

    let mut regions = Vec::new();
    for (component, members) in components.components.iter().enumerate() {
        if members.len() == 1 && !self_loops[component] {
            continue;
        }
        entries[component].sort_unstable_by_key(|node| {
            graph
                .node_index(*node)
                .expect("region entries came from the graph")
        });
        entries[component].dedup();
        let mut internal_back_edges = std::mem::take(&mut back_edges[component]);
        internal_back_edges.sort_unstable();
        let entry_structure = match entries[component].len() {
            0 => LoopEntryStructure::NoEntry,
            1 => LoopEntryStructure::SingleEntry,
            _ => LoopEntryStructure::MultiEntry,
        };
        regions.push(LoopRegion {
            members: members.clone(),
            entries: entries[component].clone().into_boxed_slice(),
            entry_structure,
            back_edges: internal_back_edges.into_boxed_slice(),
            has_self_loop: self_loops[component],
        });
    }

    Ok(LoopRegions {
        regions: regions.into_boxed_slice(),
        work: request.budget.used().saturating_sub(started),
    })
}

/// One deterministic shortest path, including the exact selected rich edges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ShortestPath<Node, Edge> {
    pub(crate) nodes: Box<[Node]>,
    pub(crate) edges: Box<[Edge]>,
    pub(crate) work: CfgAlgorithmWork,
}

pub(crate) fn shortest_path<G>(
    graph: &G,
    start: G::Node,
    goal: G::Node,
    request: &mut CfgAlgorithmRequest<'_>,
) -> Result<Option<ShortestPath<G::Node, G::Edge>>, CfgAlgorithmError<G::Node>>
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
) -> Result<ShortestPath<G::Node, G::Edge>, CfgAlgorithmError<G::Node>>
where
    G: DenseBidirectionalGraph,
{
    let mut nodes = vec![goal];
    let mut edges = Vec::new();
    let mut cursor = goal;
    while cursor != start {
        request.checkpoint()?;
        let index = required_index(graph, cursor)?;
        let (previous, edge) = parent[index].expect("discovered path node has a parent");
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
mod benchmark;

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    struct TestEdgeId(usize);

    #[derive(Debug, Clone)]
    struct TestEdge {
        source: usize,
        target: usize,
        label: u8,
    }

    #[derive(Debug)]
    struct TestGraph {
        nodes: usize,
        edges: Vec<TestEdge>,
        outgoing: Vec<Vec<TestEdgeId>>,
        incoming: Vec<Vec<TestEdgeId>>,
    }

    impl TestGraph {
        fn new(nodes: usize, edges: &[(usize, usize, u8)]) -> Self {
            let mut edges = edges
                .iter()
                .map(|&(source, target, label)| TestEdge {
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
                let id = TestEdgeId(index);
                outgoing[edge.source].push(id);
                incoming[edge.target].push(id);
            }
            Self {
                nodes,
                edges,
                outgoing,
                incoming,
            }
        }
    }

    impl DenseBidirectionalGraph for TestGraph {
        type Node = usize;
        type Edge = TestEdgeId;

        fn node_count(&self) -> usize {
            self.nodes
        }

        fn node_at(&self, index: usize) -> Option<Self::Node> {
            (index < self.nodes).then_some(index)
        }

        fn node_index(&self, node: Self::Node) -> Option<usize> {
            (node < self.nodes).then_some(node)
        }

        fn edge_index(&self, edge: Self::Edge) -> Option<usize> {
            (edge.0 < self.edges.len()).then_some(edge.0)
        }

        fn successors(
            &self,
            node: Self::Node,
        ) -> impl ExactSizeIterator<Item = (Self::Edge, Self::Node)> + '_ {
            self.outgoing[node]
                .iter()
                .copied()
                .map(|id| (id, self.edges[id.0].target))
        }

        fn successors_reversed(
            &self,
            node: Self::Node,
        ) -> impl ExactSizeIterator<Item = (Self::Edge, Self::Node)> + '_ {
            self.outgoing[node]
                .iter()
                .rev()
                .copied()
                .map(|id| (id, self.edges[id.0].target))
        }

        fn predecessors(
            &self,
            node: Self::Node,
        ) -> impl ExactSizeIterator<Item = (Self::Edge, Self::Node)> + '_ {
            self.incoming[node]
                .iter()
                .copied()
                .map(|id| (id, self.edges[id.0].source))
        }

        fn predecessors_reversed(
            &self,
            node: Self::Node,
        ) -> impl ExactSizeIterator<Item = (Self::Edge, Self::Node)> + '_ {
            self.incoming[node]
                .iter()
                .rev()
                .copied()
                .map(|id| (id, self.edges[id.0].source))
        }

        fn edge_endpoints(&self, edge: Self::Edge) -> Option<(Self::Node, Self::Node)> {
            self.edges
                .get(edge.0)
                .map(|edge| (edge.source, edge.target))
        }
    }

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
            LoopEntryStructure::MultiEntry
        );
        assert!(!loops.regions[0].has_self_loop);
        assert!(!loops.regions[0].back_edges.is_empty());
        assert_eq!(&*loops.regions[1].members, &[5]);
        assert!(loops.regions[1].entries.is_empty());
        assert!(loops.regions[1].has_self_loop);
        assert_eq!(
            loops.regions[1].entry_structure,
            LoopEntryStructure::NoEntry
        );
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
                node_visits: graph.nodes * 3,
                edge_visits: graph.edges.len() * 3,
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
        assert_eq!(graph.edges[path.edges[0].0].label, 1);

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
}
