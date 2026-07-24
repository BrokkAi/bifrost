//! A one-fact client that follows every available ICFG edge directly.

use crate::analyzer::semantic::IcfgNodeId;

use super::{
    BoundedSnapshotDataflowProblem, DataflowEdge, DataflowOutput, DataflowSeed,
    DistributiveDataflowProblem,
};

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
    /// The kernel validates and canonicalizes the emitted seeds.
    pub fn new(seed_nodes: impl IntoIterator<Item = IcfgNodeId>) -> Self {
        Self {
            seed_nodes: seed_nodes.into_iter().collect(),
        }
    }
}

impl DistributiveDataflowProblem for DirectFlowProblem {
    type Fact = DirectFact;

    fn zero_fact(&self) -> Self::Fact {
        DirectFact
    }

    // `DirectFact` is the distinguished zero fact, which the kernel preserves.
    fn normal_flow(
        &self,
        _edge: DataflowEdge<'_>,
        _fact: Self::Fact,
        _out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
    }

    fn call_flow(
        &self,
        _edge: DataflowEdge<'_>,
        _fact: Self::Fact,
        _out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
    }

    fn return_flow(
        &self,
        _edge: DataflowEdge<'_>,
        _fact: Self::Fact,
        _out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
    }

    fn call_to_return_flow(
        &self,
        _edge: DataflowEdge<'_>,
        _fact: Self::Fact,
        _out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
    }

    fn exceptional_flow(
        &self,
        _edge: DataflowEdge<'_>,
        _fact: Self::Fact,
        _out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
    }
}

impl BoundedSnapshotDataflowProblem for DirectFlowProblem {
    fn seeds(&self, out: &mut dyn DataflowOutput<DataflowSeed<Self::Fact>>) {
        for node in self.seed_nodes.iter().copied() {
            if !out.emit(DataflowSeed::new(node, DirectFact)) {
                break;
            }
        }
    }
}
