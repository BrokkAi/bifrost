use std::{error::Error, fmt};

use crate::analyzer::semantic::{
    CancellationToken, EvidenceCompleteness, IcfgBoundary, IcfgEdge, IcfgEdgeId, IcfgEdgeKind,
    IcfgNodeId, IcfgSnapshot, ProofStatus, SemanticBudgetExceeded, SemanticCapability,
    SemanticOutcome,
};

use super::problem::FactId;

/// Quality retained from the semantic outcome that produced an ICFG snapshot.
///
/// The snapshot itself does not retain this envelope, so callers must keep it
/// beside the graph to prevent a partial input from becoming a complete
/// data-flow result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IcfgInputStatus {
    Complete,
    Ambiguous,
    Unknown,
    Unsupported { capability: SemanticCapability },
    Unproven,
    ExceededBudget { exceeded: SemanticBudgetExceeded },
    Cancelled,
}

impl IcfgInputStatus {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Ambiguous => "ambiguous",
            Self::Unknown => "unknown",
            Self::Unsupported { .. } => "unsupported",
            Self::Unproven => "unproven",
            Self::ExceededBudget { .. } => "exceeded_budget",
            Self::Cancelled => "cancelled",
        }
    }

    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }

    pub const fn unsupported_capability(self) -> Option<SemanticCapability> {
        match self {
            Self::Unsupported { capability } => Some(capability),
            _ => None,
        }
    }

    pub const fn budget_exceeded(self) -> Option<SemanticBudgetExceeded> {
        match self {
            Self::ExceededBudget { exceeded } => Some(exceeded),
            _ => None,
        }
    }
}

/// One traversable ICFG snapshot paired with its construction status.
#[derive(Debug, Clone, Copy)]
pub struct IcfgSolveInput<'graph> {
    snapshot: &'graph IcfgSnapshot,
    status: IcfgInputStatus,
}

impl<'graph> IcfgSolveInput<'graph> {
    pub const fn new(snapshot: &'graph IcfgSnapshot, status: IcfgInputStatus) -> Self {
        Self { snapshot, status }
    }

    pub fn from_outcome(
        outcome: &'graph SemanticOutcome<IcfgSnapshot>,
    ) -> Result<Self, DataflowError> {
        Self::try_from(outcome)
    }

    pub const fn snapshot(self) -> &'graph IcfgSnapshot {
        self.snapshot
    }

    pub const fn status(self) -> IcfgInputStatus {
        self.status
    }
}

impl<'graph> TryFrom<&'graph SemanticOutcome<IcfgSnapshot>> for IcfgSolveInput<'graph> {
    type Error = DataflowError;

    fn try_from(outcome: &'graph SemanticOutcome<IcfgSnapshot>) -> Result<Self, Self::Error> {
        let (status, snapshot) = match outcome {
            SemanticOutcome::Complete { value, .. } => (IcfgInputStatus::Complete, Some(value)),
            SemanticOutcome::Ambiguous { candidates, .. } => {
                (IcfgInputStatus::Ambiguous, Some(candidates))
            }
            SemanticOutcome::Unknown { partial, .. } => {
                (IcfgInputStatus::Unknown, partial.as_ref())
            }
            SemanticOutcome::Unsupported {
                capability,
                partial,
                ..
            } => (
                IcfgInputStatus::Unsupported {
                    capability: *capability,
                },
                partial.as_ref(),
            ),
            SemanticOutcome::Unproven { partial, .. } => (IcfgInputStatus::Unproven, Some(partial)),
            SemanticOutcome::ExceededBudget {
                partial, exceeded, ..
            } => (
                IcfgInputStatus::ExceededBudget {
                    exceeded: *exceeded,
                },
                partial.as_ref(),
            ),
            SemanticOutcome::Cancelled { partial, .. } => {
                (IcfgInputStatus::Cancelled, partial.as_ref())
            }
        };
        let snapshot = snapshot.ok_or(DataflowError::MissingIcfgSnapshot { status })?;
        Ok(Self::new(snapshot, status))
    }
}

/// Work performed or limits applied by one bounded data-flow solve.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SolverWork {
    pub interned_facts: usize,
    pub reached_states: usize,
    pub flow_evaluations: usize,
    pub propagated_outputs: usize,
}

impl SolverWork {
    pub const fn uniform(value: usize) -> Self {
        Self {
            interned_facts: value,
            reached_states: value,
            flow_evaluations: value,
            propagated_outputs: value,
        }
    }

    pub const fn get(self, dimension: SolverBudgetDimension) -> usize {
        match dimension {
            SolverBudgetDimension::InternedFacts => self.interned_facts,
            SolverBudgetDimension::ReachedStates => self.reached_states,
            SolverBudgetDimension::FlowEvaluations => self.flow_evaluations,
            SolverBudgetDimension::PropagatedOutputs => self.propagated_outputs,
        }
    }

    pub fn checked_add(self, other: Self) -> Option<Self> {
        Some(Self {
            interned_facts: self.interned_facts.checked_add(other.interned_facts)?,
            reached_states: self.reached_states.checked_add(other.reached_states)?,
            flow_evaluations: self.flow_evaluations.checked_add(other.flow_evaluations)?,
            propagated_outputs: self
                .propagated_outputs
                .checked_add(other.propagated_outputs)?,
        })
    }

    pub const fn saturating_sub(self, other: Self) -> Self {
        Self {
            interned_facts: self.interned_facts.saturating_sub(other.interned_facts),
            reached_states: self.reached_states.saturating_sub(other.reached_states),
            flow_evaluations: self.flow_evaluations.saturating_sub(other.flow_evaluations),
            propagated_outputs: self
                .propagated_outputs
                .saturating_sub(other.propagated_outputs),
        }
    }
}

/// One independently limited source of solver growth.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SolverBudgetDimension {
    InternedFacts,
    ReachedStates,
    FlowEvaluations,
    PropagatedOutputs,
}

impl SolverBudgetDimension {
    pub const ALL: [Self; 4] = [
        Self::InternedFacts,
        Self::ReachedStates,
        Self::FlowEvaluations,
        Self::PropagatedOutputs,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::InternedFacts => "interned_facts",
            Self::ReachedStates => "reached_states",
            Self::FlowEvaluations => "flow_evaluations",
            Self::PropagatedOutputs => "propagated_outputs",
        }
    }
}

/// Exact failed solver-budget charge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SolverBudgetExceeded {
    dimension: SolverBudgetDimension,
    limit: usize,
    attempted: usize,
}

impl SolverBudgetExceeded {
    pub const fn dimension(self) -> SolverBudgetDimension {
        self.dimension
    }

    pub const fn limit(self) -> usize {
        self.limit
    }

    pub const fn attempted(self) -> usize {
        self.attempted
    }
}

impl fmt::Display for SolverBudgetExceeded {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "solver budget {} exceeded: attempted {}, limit {}",
            self.dimension.label(),
            self.attempted,
            self.limit
        )
    }
}

impl Error for SolverBudgetExceeded {}

/// Four-dimensional request-local work budget.
///
/// These limits bound work admitted and retained by the kernel. They are not
/// a preemption boundary inside client callbacks: problem implementations must
/// honor the finite, repeatable transfer contract and return cooperatively.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolverBudget {
    limits: SolverWork,
    used: SolverWork,
}

impl SolverBudget {
    pub const fn new(limits: SolverWork) -> Self {
        Self {
            limits,
            used: SolverWork {
                interned_facts: 0,
                reached_states: 0,
                flow_evaluations: 0,
                propagated_outputs: 0,
            },
        }
    }

    pub const fn uniform(limit: usize) -> Self {
        Self::new(SolverWork::uniform(limit))
    }

    pub const fn limits(&self) -> SolverWork {
        self.limits
    }

    pub const fn used(&self) -> SolverWork {
        self.used
    }

    pub const fn remaining(&self) -> SolverWork {
        self.limits.saturating_sub(self.used)
    }

    /// Check one atomic charge without mutating this budget.
    pub fn check(&self, work: SolverWork) -> Result<(), SolverBudgetExceeded> {
        for dimension in SolverBudgetDimension::ALL {
            let limit = self.limits.get(dimension);
            let Some(attempted) = self.used.get(dimension).checked_add(work.get(dimension)) else {
                return Err(SolverBudgetExceeded {
                    dimension,
                    limit,
                    attempted: usize::MAX,
                });
            };
            if attempted > limit {
                return Err(SolverBudgetExceeded {
                    dimension,
                    limit,
                    attempted,
                });
            }
        }
        Ok(())
    }

    /// Atomically charge work; a failed charge leaves the budget unchanged.
    pub fn charge(&mut self, work: SolverWork) -> Result<(), SolverBudgetExceeded> {
        self.check(work)?;
        self.used = self
            .used
            .checked_add(work)
            .expect("validated solver budget charge cannot overflow");
        Ok(())
    }

    /// Clone and charge this budget, returning a staged value for later commit.
    pub(crate) fn staged_charge(&self, work: SolverWork) -> Result<Self, SolverBudgetExceeded> {
        let mut staged = self.clone();
        staged.charge(work)?;
        Ok(staged)
    }
}

impl Default for SolverBudget {
    fn default() -> Self {
        Self::new(SolverWork {
            interned_facts: 100_000,
            reached_states: 1_000_000,
            flow_evaluations: 4_000_000,
            propagated_outputs: 4_000_000,
        })
    }
}

/// Borrowed controls for one data-flow solve.
#[derive(Debug)]
pub struct DataflowRequest<'request> {
    pub budget: &'request mut SolverBudget,
    pub cancellation: &'request CancellationToken,
}

impl<'request> DataflowRequest<'request> {
    pub const fn new(
        budget: &'request mut SolverBudget,
        cancellation: &'request CancellationToken,
    ) -> Self {
        Self {
            budget,
            cancellation,
        }
    }
}

/// Proof and completeness retained from one concrete reached path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PathQuality {
    proven: bool,
    complete: bool,
}

impl PathQuality {
    pub const PROVEN_COMPLETE: Self = Self::new(true, true);
    pub const PROVEN_PARTIAL: Self = Self::new(true, false);
    pub const UNPROVEN_COMPLETE: Self = Self::new(false, true);
    pub const UNPROVEN_PARTIAL: Self = Self::new(false, false);
    pub const ALL: [Self; 4] = [
        Self::PROVEN_COMPLETE,
        Self::PROVEN_PARTIAL,
        Self::UNPROVEN_COMPLETE,
        Self::UNPROVEN_PARTIAL,
    ];

    pub const fn new(proven: bool, complete: bool) -> Self {
        Self { proven, complete }
    }

    pub const fn is_proven(self) -> bool {
        self.proven
    }

    pub const fn is_complete(self) -> bool {
        self.complete
    }

    pub fn through_edge(self, edge: &IcfgEdge) -> Self {
        Self {
            proven: self.proven && matches!(&edge.proof, ProofStatus::Proven),
            complete: self.complete && matches!(&edge.completeness, EvidenceCompleteness::Complete),
        }
    }

    /// Whether this path is at least as strong on both quality axes.
    pub const fn dominates(self, other: Self) -> bool {
        (!other.proven || self.proven) && (!other.complete || self.complete)
    }

    pub const fn strictly_dominates(self, other: Self) -> bool {
        (self.proven != other.proven || self.complete != other.complete) && self.dominates(other)
    }
}

impl Default for PathQuality {
    fn default() -> Self {
        Self::UNPROVEN_PARTIAL
    }
}

/// The component-wise nondominated concrete path qualities for one state.
///
/// `PROVEN_PARTIAL` and `UNPROVEN_COMPLETE` are incomparable and therefore
/// may coexist. Keeping both is necessary because edge conjunction can make
/// either one the stronger continuation later; combining their axes would
/// invent a path quality that no concrete path established.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PathQualityFrontier {
    bits: u8,
}

impl PathQualityFrontier {
    pub const fn singleton(quality: PathQuality) -> Self {
        Self {
            bits: quality_bit(quality),
        }
    }

    pub const fn is_empty(self) -> bool {
        self.bits == 0
    }

    pub const fn contains(self, quality: PathQuality) -> bool {
        self.bits & quality_bit(quality) != 0
    }

    pub const fn has_proven_path(self) -> bool {
        self.contains(PathQuality::PROVEN_COMPLETE) || self.contains(PathQuality::PROVEN_PARTIAL)
    }

    pub const fn has_complete_path(self) -> bool {
        self.contains(PathQuality::PROVEN_COMPLETE) || self.contains(PathQuality::UNPROVEN_COMPLETE)
    }

    pub const fn has_proven_complete_path(self) -> bool {
        self.contains(PathQuality::PROVEN_COMPLETE)
    }

    /// Insert one concrete path quality and discard only qualities it
    /// component-wise dominates. Returns whether the frontier changed.
    pub fn insert(&mut self, candidate: PathQuality) -> bool {
        if self.iter().any(|existing| existing.dominates(candidate)) {
            return false;
        }

        let before = self.bits;
        for existing in PathQuality::ALL {
            if candidate.strictly_dominates(existing) {
                self.bits &= !quality_bit(existing);
            }
        }
        self.bits |= quality_bit(candidate);
        self.bits != before
    }

    pub fn iter(self) -> impl Iterator<Item = PathQuality> {
        PathQuality::ALL
            .into_iter()
            .filter(move |quality| self.contains(*quality))
    }
}

const fn quality_bit(quality: PathQuality) -> u8 {
    let index = (quality.proven as u8) * 2 + quality.complete as u8;
    1 << index
}

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

/// Stable malformed-input errors; cancellation and budgets are normal results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataflowError {
    MissingIcfgSnapshot {
        status: IcfgInputStatus,
    },
    InvalidSeedNode {
        node: IcfgNodeId,
        node_count: usize,
    },
    InvalidIcfgEdge {
        edge: IcfgEdgeId,
    },
    MissingInterproceduralOrigin {
        edge: IcfgEdgeId,
        kind: IcfgEdgeKind,
    },
    FactIdOverflow {
        index: usize,
    },
}

impl fmt::Display for DataflowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::MissingIcfgSnapshot { status } => write!(
                formatter,
                "ICFG outcome {} does not contain a traversable snapshot",
                status.label()
            ),
            Self::InvalidSeedNode { node, node_count } => write!(
                formatter,
                "data-flow seed node {node} is outside the {node_count}-node ICFG"
            ),
            Self::InvalidIcfgEdge { edge } => {
                write!(
                    formatter,
                    "ICFG edge {edge} has an invalid source or target"
                )
            }
            Self::MissingInterproceduralOrigin { edge, kind } => write!(
                formatter,
                "ICFG edge {edge} ({}) has no originating call site",
                kind.label()
            ),
            Self::FactIdOverflow { index } => {
                write!(formatter, "data-flow fact index {index} exceeds u32")
            }
        }
    }
}

impl Error for DataflowError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_budget_charge_is_atomic_and_identifies_dimension() {
        let mut budget = SolverBudget::new(SolverWork {
            interned_facts: 2,
            reached_states: 10,
            flow_evaluations: 10,
            propagated_outputs: 10,
        });
        budget
            .charge(SolverWork {
                interned_facts: 2,
                ..SolverWork::default()
            })
            .unwrap();
        let before = budget.used();

        let exceeded = budget
            .charge(SolverWork {
                interned_facts: 1,
                ..SolverWork::default()
            })
            .unwrap_err();

        assert_eq!(exceeded.dimension(), SolverBudgetDimension::InternedFacts);
        assert_eq!(exceeded.limit(), 2);
        assert_eq!(exceeded.attempted(), 3);
        assert_eq!(budget.used(), before);
    }

    #[test]
    fn staged_charge_does_not_mutate_source_budget() {
        let budget = SolverBudget::uniform(4);

        let staged = budget
            .staged_charge(SolverWork {
                reached_states: 3,
                ..SolverWork::default()
            })
            .unwrap();

        assert_eq!(budget.used(), SolverWork::default());
        assert_eq!(staged.used().reached_states, 3);
        assert_eq!(staged.used().saturating_sub(budget.used()), staged.used());
    }

    #[test]
    fn path_quality_frontier_preserves_incomparable_paths() {
        let mut frontier = PathQualityFrontier::default();

        assert!(frontier.insert(PathQuality::PROVEN_PARTIAL));
        assert!(frontier.insert(PathQuality::UNPROVEN_COMPLETE));
        assert_eq!(
            frontier.iter().collect::<Vec<_>>(),
            vec![PathQuality::PROVEN_PARTIAL, PathQuality::UNPROVEN_COMPLETE]
        );
        assert!(frontier.has_proven_path());
        assert!(frontier.has_complete_path());
        assert!(!frontier.has_proven_complete_path());
    }

    #[test]
    fn proven_complete_path_dominates_the_entire_frontier() {
        let mut frontier = PathQualityFrontier::default();
        frontier.insert(PathQuality::PROVEN_PARTIAL);
        frontier.insert(PathQuality::UNPROVEN_COMPLETE);

        assert!(frontier.insert(PathQuality::PROVEN_COMPLETE));
        assert_eq!(
            frontier.iter().collect::<Vec<_>>(),
            vec![PathQuality::PROVEN_COMPLETE]
        );
    }

    #[test]
    fn incomparable_paths_are_reduced_only_after_edge_conjunction() {
        let mut frontier = PathQualityFrontier::default();
        frontier.insert(PathQuality::PROVEN_PARTIAL);
        frontier.insert(PathQuality::UNPROVEN_COMPLETE);
        let edge = IcfgEdge {
            source: IcfgNodeId::new(0),
            target: IcfgNodeId::new(1),
            kind: IcfgEdgeKind::Intraprocedural(crate::analyzer::semantic::ControlEdgeKind::Normal),
            origin: None,
            proof: ProofStatus::Unproven("test suffix".into()),
            completeness: EvidenceCompleteness::Complete,
        };

        let mut after_edge = PathQualityFrontier::default();
        for quality in frontier.iter() {
            after_edge.insert(quality.through_edge(&edge));
        }

        assert_eq!(
            after_edge.iter().collect::<Vec<_>>(),
            vec![PathQuality::UNPROVEN_COMPLETE]
        );
    }
}
