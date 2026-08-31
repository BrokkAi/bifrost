//! Root-scoped backward interprocedural snapshot tabulation.
//!
//! The reusable forward-summary backend is deliberately not reused here. A backward
//! query starts with demanded observations, so its entry relation and call
//! index have different invariants. This first implementation materializes a
//! bounded root snapshot through the provider, builds an incoming-call index
//! from that forward discovery, and runs the explicit predecessor relation
//! over the resulting context-expanded graph. The snapshot is query-local and
//! never enters the reusable-summary repository.

use std::collections::HashMap;

use crate::analyzer::semantic::{
    CancellationToken, IcfgEdgeId, IcfgEdgeKind, IcfgNodeId, IcfgProvider, IcfgSnapshot,
    IcfgSnapshotLimits, ProcedureHandle, ProgramPointHandle, SemanticBudget, SemanticProviderError,
    SemanticRequest, SemanticWork,
};

use super::{
    BackwardDistributiveDataflowProblem, DataflowError, DataflowOutput, DataflowRequest,
    DataflowResult, DataflowSeed, IcfgInputStatus, IcfgSolveInput, SolverBudgetExceeded,
    SolverTermination, SolverWork, solve_backward_on_snapshot,
};
use crate::hash::HashSet;

/// One semantic point and fact demanded by a backward query.
///
/// A point may occur in more than one bounded call context. The solver seeds
/// every matching context, because a point handle alone intentionally carries
/// no call-stack identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BackwardSnapshotDemand<Fact> {
    point: ProgramPointHandle,
    fact: Fact,
}

impl<Fact> BackwardSnapshotDemand<Fact> {
    pub const fn new(point: ProgramPointHandle, fact: Fact) -> Self {
        Self { point, fact }
    }

    pub const fn point(&self) -> &ProgramPointHandle {
        &self.point
    }

    pub const fn fact(&self) -> &Fact {
        &self.fact
    }
}

/// A predecessor problem with semantic point demands rather than dense
/// snapshot node IDs.
pub trait BackwardSnapshotProblem: BackwardDistributiveDataflowProblem {
    fn demands(&self, out: &mut dyn DataflowOutput<BackwardSnapshotDemand<Self::Fact>>);
}

/// Root-scoped incoming call index.
///
/// The only source of edges in this index is the provider's snapshot for one
/// solve root. It therefore cannot accidentally admit a caller from another
/// root closure. Edges retain their original IDs and orientation for clients
/// that need to inspect the call/return pairing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackwardCallIndex {
    by_callee: HashMap<ProcedureHandle, Box<[IcfgEdgeId]>>,
}

impl BackwardCallIndex {
    fn from_snapshot(snapshot: &IcfgSnapshot) -> Self {
        let mut by_callee: HashMap<ProcedureHandle, Vec<IcfgEdgeId>> = HashMap::new();
        for (index, edge) in snapshot.edges().iter().enumerate() {
            if !matches!(edge.kind, IcfgEdgeKind::Call) {
                continue;
            }
            let Some(callee) = snapshot
                .node(edge.target)
                .map(|node| node.point().procedure())
            else {
                continue;
            };
            let edge_id = IcfgEdgeId::new(
                u32::try_from(index).expect("validated snapshot edge IDs fit in u32"),
            );
            by_callee.entry(callee.clone()).or_default().push(edge_id);
        }
        let by_callee = by_callee
            .into_iter()
            .map(|(callee, mut edges)| {
                edges.sort_unstable();
                edges.dedup();
                (callee, edges.into_boxed_slice())
            })
            .collect();
        Self { by_callee }
    }

    /// Call edges in this root's bounded closure whose target is in `callee`.
    pub fn incoming_call_edges(&self, callee: &ProcedureHandle) -> &[IcfgEdgeId] {
        self.by_callee.get(callee).map_or(&[], Box::as_ref)
    }

    pub fn procedure_count(&self) -> usize {
        self.by_callee.len()
    }

    pub fn call_count(&self) -> usize {
        self.by_callee.values().map(|edges| edges.len()).sum()
    }
}

/// Typed errors for malformed backward snapshot inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackwardSnapshotDataflowError {
    MissingIcfgSnapshot { status: IcfgInputStatus },
    InvalidDemandPoint { point: ProgramPointHandle },
    Dataflow(DataflowError),
    SemanticProvider(SemanticProviderError),
}

impl std::fmt::Display for BackwardSnapshotDataflowError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingIcfgSnapshot { status } => {
                write!(
                    formatter,
                    "backward solve has no ICFG snapshot ({status:?})"
                )
            }
            Self::InvalidDemandPoint { point } => {
                write!(
                    formatter,
                    "backward demand point is outside the root snapshot: {point:?}"
                )
            }
            Self::Dataflow(error) => error.fmt(formatter),
            Self::SemanticProvider(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for BackwardSnapshotDataflowError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Dataflow(error) => Some(error),
            Self::SemanticProvider(error) => Some(error),
            Self::MissingIcfgSnapshot { .. } | Self::InvalidDemandPoint { .. } => None,
        }
    }
}

impl From<DataflowError> for BackwardSnapshotDataflowError {
    fn from(error: DataflowError) -> Self {
        Self::Dataflow(error)
    }
}

impl From<SemanticProviderError> for BackwardSnapshotDataflowError {
    fn from(error: SemanticProviderError) -> Self {
        Self::SemanticProvider(error)
    }
}

/// Result of one non-reusable backward interprocedural solve.
#[derive(Debug, Clone)]
pub struct BackwardSnapshotDataflowResult<Fact> {
    snapshot: IcfgSnapshot,
    reverse_calls: BackwardCallIndex,
    result: DataflowResult<Fact>,
    semantic_work: SemanticWork,
}

impl<Fact> BackwardSnapshotDataflowResult<Fact> {
    fn new(
        snapshot: IcfgSnapshot,
        result: DataflowResult<Fact>,
        semantic_work: SemanticWork,
    ) -> Self {
        let reverse_calls = BackwardCallIndex::from_snapshot(&snapshot);
        Self {
            snapshot,
            reverse_calls,
            result,
            semantic_work,
        }
    }

    pub const fn snapshot(&self) -> &IcfgSnapshot {
        &self.snapshot
    }

    pub const fn reverse_call_index(&self) -> &BackwardCallIndex {
        &self.reverse_calls
    }

    pub fn facts(&self) -> &[Fact] {
        self.result.facts()
    }

    pub fn fact(&self, id: super::FactId) -> Option<&Fact> {
        self.result.fact(id)
    }

    pub fn reached(&self) -> &[super::ReachedFact] {
        self.result.reached()
    }

    pub const fn coverage(&self) -> &super::DataflowCoverage {
        self.result.coverage()
    }

    pub const fn termination(&self) -> SolverTermination {
        self.result.termination()
    }

    pub const fn work(&self) -> SolverWork {
        self.result.work()
    }

    pub const fn semantic_work(&self) -> SemanticWork {
        self.semantic_work
    }

    pub fn is_complete(&self) -> bool {
        self.result.is_complete()
    }

    pub fn reached_at(
        &self,
        point: &ProgramPointHandle,
    ) -> impl Iterator<Item = &super::ReachedFact> {
        self.result.reached().iter().filter(move |reached| {
            self.snapshot
                .node(reached.node())
                .is_some_and(|node| node.point() == point)
        })
    }
}

struct DemandSeeds<'request, Fact> {
    snapshot: &'request IcfgSnapshot,
    values: HashSet<DataflowSeed<Fact>>,
    budget: &'request super::SolverBudget,
    cancellation: &'request CancellationToken,
    invalid_point: Option<ProgramPointHandle>,
    exceeded: Option<SolverBudgetExceeded>,
}

impl<'request, Fact> DemandSeeds<'request, Fact>
where
    Fact: Copy + Eq + std::hash::Hash,
{
    fn new(
        snapshot: &'request IcfgSnapshot,
        budget: &'request super::SolverBudget,
        cancellation: &'request CancellationToken,
    ) -> Self {
        Self {
            snapshot,
            values: HashSet::default(),
            budget,
            cancellation,
            invalid_point: None,
            exceeded: None,
        }
    }

    fn seed(&mut self, demand: BackwardSnapshotDemand<Fact>) -> bool {
        if self
            .snapshot
            .nodes()
            .iter()
            .all(|node| node.point() != demand.point())
        {
            self.invalid_point = Some(demand.point().clone());
            return true;
        }
        for (index, node) in self.snapshot.nodes().iter().enumerate() {
            if node.point() != demand.point() {
                continue;
            }
            let node = IcfgNodeId::new(
                u32::try_from(index).expect("validated snapshot node IDs fit in u32"),
            );
            let value = DataflowSeed::new(node, demand.fact);
            if self.values.contains(&value) {
                continue;
            }
            let callback_rows = self.values.len().saturating_add(1);
            if let Err(exceeded) = self.budget.check(SolverWork {
                callback_rows,
                ..SolverWork::default()
            }) {
                self.exceeded = Some(exceeded);
                return false;
            }
            self.values.insert(value);
        }
        true
    }
}

impl<Fact> DataflowOutput<BackwardSnapshotDemand<Fact>> for DemandSeeds<'_, Fact>
where
    Fact: Copy + Eq + std::hash::Hash,
{
    fn should_continue(&self) -> bool {
        !self.cancellation.is_cancelled() && self.invalid_point.is_none() && self.exceeded.is_none()
    }

    fn emit(&mut self, demand: BackwardSnapshotDemand<Fact>) -> bool {
        if !self.should_continue() {
            return false;
        }
        self.seed(demand)
    }
}

struct SnapshotBackwardProblem<'problem, P: BackwardSnapshotProblem> {
    problem: &'problem P,
    seeds: Box<[DataflowSeed<P::Fact>]>,
}

impl<P> BackwardDistributiveDataflowProblem for SnapshotBackwardProblem<'_, P>
where
    P: BackwardSnapshotProblem,
{
    type Fact = P::Fact;

    fn zero_fact(&self) -> Self::Fact {
        self.problem.zero_fact()
    }

    fn resolved_call_to_return(&self) -> bool {
        self.problem.resolved_call_to_return()
    }

    fn normal_predecessor_flow(
        &self,
        edge: super::DataflowEdge<'_, Self::Fact>,
        output_fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.problem.normal_predecessor_flow(edge, output_fact, out);
    }

    fn call_predecessor_flow(
        &self,
        edge: super::DataflowEdge<'_, Self::Fact>,
        output_fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.problem.call_predecessor_flow(edge, output_fact, out);
    }

    fn return_predecessor_flow(
        &self,
        edge: super::DataflowEdge<'_, Self::Fact>,
        output_fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.problem.return_predecessor_flow(edge, output_fact, out);
    }

    fn call_to_return_predecessor_flow(
        &self,
        edge: super::DataflowEdge<'_, Self::Fact>,
        output_fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.problem
            .call_to_return_predecessor_flow(edge, output_fact, out);
    }

    fn exceptional_predecessor_flow(
        &self,
        edge: super::DataflowEdge<'_, Self::Fact>,
        output_fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.problem
            .exceptional_predecessor_flow(edge, output_fact, out);
    }
}

impl<P> super::BoundedSnapshotBackwardDataflowProblem for SnapshotBackwardProblem<'_, P>
where
    P: BackwardSnapshotProblem,
{
    fn backward_seeds(&self, out: &mut dyn DataflowOutput<DataflowSeed<Self::Fact>>) {
        for &seed in &self.seeds {
            if !out.emit(seed) {
                break;
            }
        }
    }
}

/// Solve one finite predecessor relation from semantic point demands.
///
/// The caller supplies an already materialized snapshot input and the semantic
/// work charged while producing it. This is the shared-snapshot entry point:
/// callers can estimate forward and backward work against the same immutable
/// graph, then run this demand adapter without asking the provider to rebuild
/// the graph or charging semantic work a second time.
pub fn solve_backward_demands_on_snapshot<P>(
    input: IcfgSolveInput<'_>,
    problem: &P,
    semantic_work: SemanticWork,
    request: &mut DataflowRequest<'_>,
) -> Result<BackwardSnapshotDataflowResult<P::Fact>, BackwardSnapshotDataflowError>
where
    P: BackwardSnapshotProblem,
{
    let snapshot = input.snapshot();
    let status = input.status();
    let mut demands = DemandSeeds::new(snapshot, request.budget, request.cancellation);
    problem.demands(&mut demands);
    if request.cancellation.is_cancelled() {
        let result = solve_backward_on_snapshot(
            input,
            &SnapshotBackwardProblem {
                problem,
                seeds: Box::new([]),
            },
            request,
        )?;
        return Ok(BackwardSnapshotDataflowResult::new(
            snapshot.clone(),
            result,
            semantic_work,
        ));
    }
    if let Some(point) = demands.invalid_point {
        return Err(BackwardSnapshotDataflowError::InvalidDemandPoint { point });
    }
    if let Some(exceeded) = demands.exceeded {
        let result = DataflowResult::from_parts(
            vec![problem.zero_fact()],
            Vec::new(),
            super::DataflowCoverage::from_parts(status, Vec::new(), Vec::new(), Vec::new()),
            SolverTermination::ExceededBudget(exceeded),
            SolverWork::default(),
        );
        return Ok(BackwardSnapshotDataflowResult::new(
            snapshot.clone(),
            result,
            semantic_work,
        ));
    }
    let seeds = demands
        .values
        .into_iter()
        .collect::<Vec<_>>()
        .into_boxed_slice();
    let problem = SnapshotBackwardProblem { problem, seeds };
    let result = solve_backward_on_snapshot(input, &problem, request)?;
    Ok(BackwardSnapshotDataflowResult::new(
        snapshot.clone(),
        result,
        semantic_work,
    ))
}

/// Solve one finite predecessor relation from semantic point demands.
///
/// The provider snapshot is the forward-discovered root closure. Its incoming
/// call index is retained in the result for demand-directed clients and makes
/// the root scope explicit. No reusable summary is consulted or published.
pub fn solve_backward_with_snapshot<P, Provider>(
    root: &ProcedureHandle,
    limits: IcfgSnapshotLimits,
    provider: &Provider,
    problem: &P,
    semantic_budget: &mut SemanticBudget,
    request: &mut DataflowRequest<'_>,
) -> Result<BackwardSnapshotDataflowResult<P::Fact>, BackwardSnapshotDataflowError>
where
    P: BackwardSnapshotProblem,
    Provider: IcfgProvider + ?Sized,
{
    let mut semantic_request = SemanticRequest::new(semantic_budget, request.cancellation);
    let outcome = provider.snapshot(root, limits, &mut semantic_request)?;
    let status = IcfgInputStatus::from_outcome(&outcome);
    let semantic_work = outcome.work();
    outcome
        .available_value()
        .ok_or(BackwardSnapshotDataflowError::MissingIcfgSnapshot { status })?;
    let input = IcfgSolveInput::try_from(&outcome).expect("the retained snapshot is available");
    solve_backward_demands_on_snapshot(input, problem, semantic_work, request)
}
