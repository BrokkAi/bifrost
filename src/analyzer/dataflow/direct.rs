//! A one-fact client that follows every available ICFG edge directly.

use crate::analyzer::semantic::IcfgNodeId;

use super::{DataflowEdge, DataflowSeed, DistributiveDataflowProblem};

/// The sole fact in [`DirectFlowProblem`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DirectFact;

/// A direct reachability client with no protocol or typestate assumptions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectFlowProblem {
    seed_nodes: Box<[IcfgNodeId]>,
}

impl DirectFlowProblem {
    /// Construct a direct-flow problem from explicit snapshot-local seed nodes.
    ///
    /// Nodes are sorted and deduplicated so the client emits canonical seeds;
    /// the solver still validates every node against its input snapshot.
    pub fn new(seed_nodes: impl IntoIterator<Item = IcfgNodeId>) -> Self {
        let mut seed_nodes = seed_nodes.into_iter().collect::<Vec<_>>();
        seed_nodes.sort_unstable();
        seed_nodes.dedup();
        Self {
            seed_nodes: seed_nodes.into_boxed_slice(),
        }
    }

    pub fn seed_nodes(&self) -> &[IcfgNodeId] {
        &self.seed_nodes
    }

    fn preserve(fact: DirectFact, out: &mut Vec<DirectFact>) {
        out.push(fact);
    }
}

impl DistributiveDataflowProblem for DirectFlowProblem {
    type Fact = DirectFact;

    fn zero_fact(&self) -> Self::Fact {
        DirectFact
    }

    fn seeds(&self, out: &mut Vec<DataflowSeed<Self::Fact>>) {
        out.extend(
            self.seed_nodes
                .iter()
                .copied()
                .map(|node| DataflowSeed::new(node, DirectFact)),
        );
    }

    fn normal_flow(&self, _edge: DataflowEdge<'_>, fact: Self::Fact, out: &mut Vec<Self::Fact>) {
        Self::preserve(fact, out);
    }

    fn call_flow(&self, _edge: DataflowEdge<'_>, fact: Self::Fact, out: &mut Vec<Self::Fact>) {
        Self::preserve(fact, out);
    }

    fn return_flow(&self, _edge: DataflowEdge<'_>, fact: Self::Fact, out: &mut Vec<Self::Fact>) {
        Self::preserve(fact, out);
    }

    fn call_to_return_flow(
        &self,
        _edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut Vec<Self::Fact>,
    ) {
        Self::preserve(fact, out);
    }

    fn exceptional_flow(
        &self,
        _edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut Vec<Self::Fact>,
    ) {
        Self::preserve(fact, out);
    }
}
