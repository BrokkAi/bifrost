//! Client contracts for bounded distributive data-flow problems.

use std::fmt;
use std::hash::Hash;

use crate::analyzer::semantic::{IcfgEdge, IcfgEdgeId, IcfgNodeId, IcfgNodeKey, IcfgSnapshot};

/// A run-local dense identifier for one client fact.
///
/// Fact IDs are assigned deterministically by the solver and are meaningful
/// only within the result of that solver run.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FactId(u32);

impl FactId {
    pub(crate) const fn new(raw: u32) -> Self {
        Self(raw)
    }

    pub const fn get(self) -> u32 {
        self.0
    }

    pub(crate) const fn index(self) -> usize {
        self.0 as usize
    }

    pub(crate) fn try_from_index(index: usize) -> Option<Self> {
        u32::try_from(index).ok().map(Self)
    }
}

impl fmt::Display for FactId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// One context-specific input fact for a bounded ICFG solve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DataflowSeed<F> {
    pub node: IcfgNodeId,
    pub fact: F,
}

impl<F> DataflowSeed<F> {
    pub const fn new(node: IcfgNodeId, fact: F) -> Self {
        Self { node, fact }
    }
}

/// Borrowed topology for one transfer-function evaluation.
///
/// The source and target keys expose the already context-expanded ICFG nodes;
/// clients must not construct or maintain a second call stack.
#[derive(Debug, Clone, Copy)]
pub struct DataflowEdge<'graph> {
    edge_id: IcfgEdgeId,
    edge: &'graph IcfgEdge,
    source: &'graph IcfgNodeKey,
    target: &'graph IcfgNodeKey,
}

impl<'graph> DataflowEdge<'graph> {
    /// Resolve one edge and both endpoint keys from the same snapshot.
    ///
    /// Returning a descriptor only after all three rows resolve prevents
    /// callers from pairing an edge with nodes from a different snapshot.
    pub fn from_snapshot(snapshot: &'graph IcfgSnapshot, edge_id: IcfgEdgeId) -> Option<Self> {
        let edge = snapshot.edge(edge_id)?;
        let source = snapshot.node(edge.source)?;
        let target = snapshot.node(edge.target)?;
        Some(Self::new(edge_id, edge, source, target))
    }

    pub(crate) const fn new(
        edge_id: IcfgEdgeId,
        edge: &'graph IcfgEdge,
        source: &'graph IcfgNodeKey,
        target: &'graph IcfgNodeKey,
    ) -> Self {
        Self {
            edge_id,
            edge,
            source,
            target,
        }
    }

    pub const fn edge_id(self) -> IcfgEdgeId {
        self.edge_id
    }

    pub const fn edge(self) -> &'graph IcfgEdge {
        self.edge
    }

    pub const fn source(self) -> &'graph IcfgNodeKey {
        self.source
    }

    pub const fn target(self) -> &'graph IcfgNodeKey {
        self.target
    }
}

/// A finite, union-distributive may-data-flow problem.
///
/// Each callback maps one input fact independently to zero or more output
/// facts. Because clients cannot inspect or replace the whole reached set,
/// these unary relations lift pointwise to union-distributive propagation.
/// Non-distributive analyses require a separately named solver contract.
///
/// For a given edge descriptor and fact, callbacks must produce a finite,
/// repeatable relation independent of invocation order. The kernel may
/// evaluate the same pair again when a stronger path-quality profile reaches
/// it. Cooperative cancellation is the only supported callback side effect.
pub trait DistributiveDataflowProblem {
    type Fact: Copy + Eq + Hash + Ord;

    /// The distinguished fact injected at every seed node and preserved by
    /// the kernel across every edge.
    ///
    /// Transfer callbacks still receive this fact and may generate additional
    /// facts from it. They do not need to return the zero fact themselves.
    fn zero_fact(&self) -> Self::Fact;

    /// Append every explicit, context-specific seed for this run.
    ///
    /// Seed production, like transfer evaluation, must be finite, repeatable,
    /// and cooperatively returning; the kernel validates and charges the
    /// canonicalized rows only after this callback returns.
    fn seeds(&self, out: &mut Vec<DataflowSeed<Self::Fact>>);

    /// Transfer over an ordinary intraprocedural edge.
    ///
    /// This includes branch, loop, cleanup, and async-normal edges. Cleanup
    /// remains visible through the original `IcfgEdgeKind`.
    fn normal_flow(&self, edge: DataflowEdge<'_>, fact: Self::Fact, out: &mut Vec<Self::Fact>);

    /// Transfer from a call site to a materialized callee entry.
    fn call_flow(&self, edge: DataflowEdge<'_>, fact: Self::Fact, out: &mut Vec<Self::Fact>);

    /// Transfer from a callee exit to its matched caller continuation.
    ///
    /// The original edge distinguishes normal from exceptional return.
    fn return_flow(&self, edge: DataflowEdge<'_>, fact: Self::Fact, out: &mut Vec<Self::Fact>);

    /// Transfer along an ICFG-provided call-to-continuation edge.
    ///
    /// In the current bounded ICFG these edges model explicit boundary arms,
    /// such as deferred invocation; they are not an implicit bypass edge for
    /// every materialized call.
    fn call_to_return_flow(
        &self,
        edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut Vec<Self::Fact>,
    );

    /// Transfer over local exceptional or async-exceptional control flow.
    fn exceptional_flow(&self, edge: DataflowEdge<'_>, fact: Self::Fact, out: &mut Vec<Self::Fact>);
}
