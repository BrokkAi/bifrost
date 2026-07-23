//! Deliberately simple reference semantics for bounded data-flow tests.
//!
//! This runner favors an obviously independent fixed-point over efficiency:
//! every round scans every published ICFG edge against a frozen copy of the
//! currently reached facts. It intentionally has no worklist, fact interner,
//! budgets, cancellation, summaries, or witness storage.

#![allow(dead_code)]

use std::collections::BTreeSet;
use std::fmt;

use brokk_bifrost::analyzer::dataflow::{DataflowEdge, DataflowSeed, DistributiveDataflowProblem};
use brokk_bifrost::analyzer::semantic::{
    ControlEdgeKind, IcfgEdgeId, IcfgEdgeKind, IcfgNodeId, IcfgSnapshot,
};

/// Canonical reached facts produced by the repeated-scan implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceDataflowResult<F> {
    reached: BTreeSet<(IcfgNodeId, F)>,
}

impl<F: Copy + Ord> ReferenceDataflowResult<F> {
    pub fn reached(&self) -> &BTreeSet<(IcfgNodeId, F)> {
        &self.reached
    }

    pub fn contains(&self, node: IcfgNodeId, fact: &F) -> bool {
        self.reached.contains(&(node, *fact))
    }

    pub fn reached_nodes(&self) -> BTreeSet<IcfgNodeId> {
        self.reached.iter().map(|(node, _)| *node).collect()
    }
}

/// A malformed seed or graph row encountered by the reference runner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceDataflowError {
    InvalidSeed(IcfgNodeId),
    InvalidEdge(IcfgEdgeId),
}

impl fmt::Display for ReferenceDataflowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSeed(node) => write!(formatter, "invalid data-flow seed node {node:?}"),
            Self::InvalidEdge(edge) => write!(formatter, "invalid ICFG edge row {edge:?}"),
        }
    }
}

impl std::error::Error for ReferenceDataflowError {}

/// Compute a may fixed point by repeatedly scanning every ICFG edge.
pub fn reference_solve<P>(
    snapshot: &IcfgSnapshot,
    problem: &P,
) -> Result<ReferenceDataflowResult<P::Fact>, ReferenceDataflowError>
where
    P: DistributiveDataflowProblem,
{
    let mut seeds = Vec::<DataflowSeed<P::Fact>>::new();
    problem.seeds(&mut seeds);
    seeds.sort_unstable();
    seeds.dedup();

    let mut reached = BTreeSet::new();
    let zero = problem.zero_fact();
    for seed in seeds {
        if snapshot.node(seed.node).is_none() {
            return Err(ReferenceDataflowError::InvalidSeed(seed.node));
        }
        reached.insert((seed.node, zero));
        reached.insert((seed.node, seed.fact));
    }

    loop {
        let before_round = reached.clone();
        let mut additions = BTreeSet::new();

        for source in snapshot.node_ids() {
            let source_facts = before_round
                .iter()
                .filter_map(|(node, fact)| (*node == source).then_some(*fact));
            let source_facts = source_facts.collect::<Vec<_>>();

            for (edge_id, edge) in snapshot.successor_edges(source) {
                let descriptor = DataflowEdge::from_snapshot(snapshot, edge_id)
                    .ok_or(ReferenceDataflowError::InvalidEdge(edge_id))?;

                for fact in source_facts.iter().copied() {
                    let mut outputs = Vec::new();
                    apply_transfer(problem, descriptor, edge.kind, fact, &mut outputs);
                    if fact == zero {
                        outputs.push(zero);
                    }
                    outputs.sort_unstable();
                    outputs.dedup();
                    additions.extend(
                        outputs
                            .into_iter()
                            .map(|output| (descriptor.edge().target, output)),
                    );
                }
            }
        }

        reached.extend(additions);
        if reached == before_round {
            return Ok(ReferenceDataflowResult { reached });
        }
    }
}

fn apply_transfer<P: DistributiveDataflowProblem>(
    problem: &P,
    edge: DataflowEdge<'_>,
    kind: IcfgEdgeKind,
    fact: P::Fact,
    out: &mut Vec<P::Fact>,
) {
    match kind {
        IcfgEdgeKind::Intraprocedural(
            ControlEdgeKind::Exceptional | ControlEdgeKind::AsyncExceptional,
        ) => problem.exceptional_flow(edge, fact, out),
        IcfgEdgeKind::Intraprocedural(_) => problem.normal_flow(edge, fact, out),
        IcfgEdgeKind::Call => problem.call_flow(edge, fact, out),
        IcfgEdgeKind::NormalReturn | IcfgEdgeKind::ExceptionalReturn => {
            problem.return_flow(edge, fact, out);
        }
        IcfgEdgeKind::CallToNormalContinuation | IcfgEdgeKind::CallToExceptionalContinuation => {
            problem.call_to_return_flow(edge, fact, out);
        }
    }
}
