//! Deterministic data-flow results and coverage.

use crate::analyzer::semantic::{IcfgBoundary, IcfgEdgeId, IcfgNodeId};

use super::{FactId, IcfgInputStatus, PathQualityFrontier, SolverBudgetExceeded, SolverWork};

/// Global input and reachable-edge coverage observed by a solve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataflowCoverage {
    input_status: IcfgInputStatus,
    unproven_edges: Box<[IcfgEdgeId]>,
    partial_edges: Box<[IcfgEdgeId]>,
    boundaries: Box<[IcfgBoundary]>,
}

impl DataflowCoverage {
    pub(crate) fn from_parts(
        input_status: IcfgInputStatus,
        mut unproven_edges: Vec<IcfgEdgeId>,
        mut partial_edges: Vec<IcfgEdgeId>,
        boundaries: Vec<IcfgBoundary>,
    ) -> Self {
        unproven_edges.sort_unstable();
        unproven_edges.dedup();
        partial_edges.sort_unstable();
        partial_edges.dedup();
        Self {
            input_status,
            unproven_edges: unproven_edges.into_boxed_slice(),
            partial_edges: partial_edges.into_boxed_slice(),
            boundaries: boundaries.into_boxed_slice(),
        }
    }

    pub const fn input_status(&self) -> IcfgInputStatus {
        self.input_status
    }

    pub fn unproven_edges(&self) -> &[IcfgEdgeId] {
        &self.unproven_edges
    }

    pub fn partial_edges(&self) -> &[IcfgEdgeId] {
        &self.partial_edges
    }

    pub fn boundaries(&self) -> &[IcfgBoundary] {
        &self.boundaries
    }

    pub fn is_complete(&self) -> bool {
        self.input_status.is_complete()
            && self.unproven_edges.is_empty()
            && self.partial_edges.is_empty()
            && self.boundaries.is_empty()
    }
}

/// Why propagation stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SolverTermination {
    FixedPoint,
    Cancelled,
    ExceededBudget(SolverBudgetExceeded),
}

impl SolverTermination {
    pub const fn is_fixed_point(self) -> bool {
        matches!(self, Self::FixedPoint)
    }

    pub const fn budget_exceeded(self) -> Option<SolverBudgetExceeded> {
        match self {
            Self::ExceededBudget(exceeded) => Some(exceeded),
            _ => None,
        }
    }
}

/// One deterministically ordered reached `(node, fact)` state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReachedFact {
    node: IcfgNodeId,
    fact: FactId,
    path_qualities: PathQualityFrontier,
}

impl ReachedFact {
    pub(crate) const fn new(
        node: IcfgNodeId,
        fact: FactId,
        path_qualities: PathQualityFrontier,
    ) -> Self {
        Self {
            node,
            fact,
            path_qualities,
        }
    }

    pub const fn node(self) -> IcfgNodeId {
        self.node
    }

    pub const fn fact(self) -> FactId {
        self.fact
    }

    pub const fn path_qualities(self) -> PathQualityFrontier {
        self.path_qualities
    }
}

/// Deterministic typed result of one bounded solve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataflowResult<Fact> {
    facts: Box<[Fact]>,
    reached: Box<[ReachedFact]>,
    coverage: DataflowCoverage,
    termination: SolverTermination,
    work: SolverWork,
}

impl<Fact> DataflowResult<Fact> {
    pub(crate) fn from_parts(
        facts: Vec<Fact>,
        reached: Vec<ReachedFact>,
        coverage: DataflowCoverage,
        termination: SolverTermination,
        work: SolverWork,
    ) -> Self {
        Self {
            facts: facts.into_boxed_slice(),
            reached: reached.into_boxed_slice(),
            coverage,
            termination,
            work,
        }
    }

    pub fn facts(&self) -> &[Fact] {
        &self.facts
    }

    pub fn fact(&self, id: FactId) -> Option<&Fact> {
        self.facts.get(id.index())
    }

    pub fn reached(&self) -> &[ReachedFact] {
        &self.reached
    }

    pub const fn coverage(&self) -> &DataflowCoverage {
        &self.coverage
    }

    pub const fn termination(&self) -> SolverTermination {
        self.termination
    }

    pub const fn work(&self) -> SolverWork {
        self.work
    }

    pub fn is_complete(&self) -> bool {
        self.termination.is_fixed_point() && self.coverage.is_complete()
    }

    pub fn reached_at(&self, node: IcfgNodeId) -> impl Iterator<Item = &ReachedFact> {
        self.reached
            .iter()
            .filter(move |reached| reached.node == node)
    }
}
