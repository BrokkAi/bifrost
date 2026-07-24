//! Deterministic worklist tabulation over one bounded ICFG snapshot.

use std::collections::VecDeque;

use crate::analyzer::semantic::{
    EvidenceCompleteness, IcfgEdgeId, IcfgNodeId, IcfgSnapshot, ProofStatus,
};
use crate::hash::{HashMap, HashSet};

use super::transfer::{TransferEvaluation, TransferScratch, evaluate_transfer};
use super::{
    BoundedSnapshotDataflowProblem, DataflowCoverage, DataflowEdge, DataflowError, DataflowOutput,
    DataflowRequest, DataflowResult, DataflowSeed, DistributiveDataflowProblem, FactId,
    IcfgSolveInput, PathQuality, PathQualityFrontier, ReachedFact, SolverBudget,
    SolverBudgetExceeded, SolverTermination, SolverWork,
};

const ZERO_FACT_ID: FactId = FactId::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct ExplodedState {
    node: IcfgNodeId,
    fact: FactId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct QueuedState {
    state: ExplodedState,
    quality: PathQuality,
}

struct BoundedSeedOutputs<'graph, 'request, Fact> {
    snapshot: &'graph IcfgSnapshot,
    values: HashSet<DataflowSeed<Fact>>,
    budget: &'request SolverBudget,
    cancellation: &'request crate::analyzer::semantic::CancellationToken,
    invalid_node: Option<IcfgNodeId>,
    exceeded: Option<SolverBudgetExceeded>,
}

impl<'graph, 'request, Fact> BoundedSeedOutputs<'graph, 'request, Fact>
where
    Fact: Copy + Eq + std::hash::Hash,
{
    fn new(
        snapshot: &'graph IcfgSnapshot,
        budget: &'request SolverBudget,
        cancellation: &'request crate::analyzer::semantic::CancellationToken,
    ) -> Self {
        Self {
            snapshot,
            values: HashSet::default(),
            budget,
            cancellation,
            invalid_node: None,
            exceeded: None,
        }
    }

    const fn invalid_node(&self) -> Option<IcfgNodeId> {
        self.invalid_node
    }

    const fn exceeded(&self) -> Option<SolverBudgetExceeded> {
        self.exceeded
    }

    fn into_values(self) -> HashSet<DataflowSeed<Fact>> {
        self.values
    }
}

impl<Fact> DataflowOutput<DataflowSeed<Fact>> for BoundedSeedOutputs<'_, '_, Fact>
where
    Fact: Copy + Eq + std::hash::Hash,
{
    fn emit(&mut self, seed: DataflowSeed<Fact>) -> bool {
        if self.cancellation.is_cancelled() {
            return false;
        }
        if self.snapshot.node(seed.node).is_none() {
            self.invalid_node = Some(
                self.invalid_node
                    .map_or(seed.node, |current| current.min(seed.node)),
            );
            return true;
        }
        if self.invalid_node.is_some() {
            return true;
        }
        if self.exceeded.is_some() {
            return false;
        }
        if self.values.contains(&seed) {
            return true;
        }

        let callback_rows = self.values.len().saturating_add(1);
        if let Err(exceeded) = self.budget.check(SolverWork {
            callback_rows,
            ..SolverWork::uniform(0)
        }) {
            self.exceeded = Some(exceeded);
            return false;
        }

        self.values.insert(seed);
        true
    }
}

struct TabulationState<'graph, Fact> {
    snapshot: &'graph IcfgSnapshot,
    facts: Vec<Fact>,
    fact_ids: HashMap<Fact, FactId>,
    reached: HashMap<ExplodedState, PathQualityFrontier>,
    worklist: VecDeque<QueuedState>,
    unproven_edges: HashSet<IcfgEdgeId>,
    partial_edges: HashSet<IcfgEdgeId>,
    transfer_scratch: TransferScratch<Fact>,
}

impl<'graph, Fact> TabulationState<'graph, Fact>
where
    Fact: Copy + Eq + std::hash::Hash + Ord,
{
    fn new(snapshot: &'graph IcfgSnapshot) -> Self {
        Self {
            snapshot,
            facts: Vec::new(),
            fact_ids: HashMap::default(),
            reached: HashMap::default(),
            worklist: VecDeque::new(),
            unproven_edges: HashSet::default(),
            partial_edges: HashSet::default(),
            transfer_scratch: TransferScratch::new(),
        }
    }

    fn initialize<P>(
        &mut self,
        problem: &P,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Option<SolverTermination>, DataflowError>
    where
        P: BoundedSnapshotDataflowProblem<Fact = Fact>,
    {
        if request.cancellation.is_cancelled() {
            return Ok(Some(SolverTermination::Cancelled));
        }

        let zero_fact = problem.zero_fact();
        let (invalid_node, sink_exceeded, emitted_seeds) = {
            let mut seed_outputs =
                BoundedSeedOutputs::new(self.snapshot, request.budget, request.cancellation);
            problem.seeds(&mut seed_outputs);
            let invalid_node = seed_outputs.invalid_node();
            let exceeded = seed_outputs.exceeded();
            (invalid_node, exceeded, seed_outputs.into_values())
        };

        if request.cancellation.is_cancelled() {
            return Ok(Some(SolverTermination::Cancelled));
        }
        if let Some(node) = invalid_node {
            return Err(DataflowError::InvalidSeedNode {
                node,
                node_count: self.snapshot.node_count(),
            });
        }
        if let Some(exceeded) = sink_exceeded {
            return Ok(Some(SolverTermination::ExceededBudget(exceeded)));
        }
        let mut seeds = emitted_seeds.into_iter().collect::<Vec<_>>();
        seeds.sort_unstable();
        let seed_rows = seeds.len();

        let mut staged_facts = vec![zero_fact];
        let mut staged_fact_ids = HashMap::default();
        staged_fact_ids.insert(zero_fact, ZERO_FACT_ID);
        let mut staged_states = Vec::with_capacity(seeds.len());

        for seed in seeds {
            let fact = match staged_fact_ids.get(&seed.fact).copied() {
                Some(fact) => fact,
                None => {
                    let index = staged_facts.len();
                    let fact = FactId::try_from_index(index)
                        .map_err(|_| DataflowError::FactIdOverflow { index })?;
                    staged_facts.push(seed.fact);
                    staged_fact_ids.insert(seed.fact, fact);
                    fact
                }
            };
            staged_states.push(ExplodedState {
                node: seed.node,
                fact,
            });
            staged_states.push(ExplodedState {
                node: seed.node,
                fact: ZERO_FACT_ID,
            });
        }
        staged_states.sort_unstable();
        staged_states.dedup();

        let charge = SolverWork {
            interned_facts: staged_facts.len(),
            reached_states: staged_states.len(),
            callback_rows: seed_rows,
            ..SolverWork::default()
        };
        let staged_budget = match request.budget.staged_charge(charge) {
            Ok(staged) => staged,
            Err(exceeded) => {
                return Ok(Some(SolverTermination::ExceededBudget(exceeded)));
            }
        };
        if request.cancellation.is_cancelled() {
            return Ok(Some(SolverTermination::Cancelled));
        }

        *request.budget = staged_budget;
        self.facts = staged_facts;
        self.fact_ids = staged_fact_ids;
        for state in staged_states {
            let quality = PathQuality::PROVEN_COMPLETE;
            let replaced = self
                .reached
                .insert(state, PathQualityFrontier::singleton(quality));
            debug_assert!(replaced.is_none(), "canonical seeds are unique");
            self.worklist.push_back(QueuedState { state, quality });
        }
        Ok(None)
    }

    fn propagate<P>(
        &mut self,
        problem: &P,
        request: &mut DataflowRequest<'_>,
    ) -> Result<SolverTermination, DataflowError>
    where
        P: DistributiveDataflowProblem<Fact = Fact>,
    {
        while let Some(queued) = self.worklist.pop_front() {
            if request.cancellation.is_cancelled() {
                return Ok(SolverTermination::Cancelled);
            }

            let path_qualities = *self
                .reached
                .get(&queued.state)
                .expect("queued states remain in the reached table");
            if !path_qualities.contains(queued.quality) {
                continue;
            }
            let fact = self.facts[queued.state.fact.index()];

            for (edge_id, edge) in self.snapshot.successor_edges(queued.state.node) {
                self.observe_edge(edge_id, edge);
                if request.cancellation.is_cancelled() {
                    return Ok(SolverTermination::Cancelled);
                }

                let descriptor = DataflowEdge::from_snapshot(self.snapshot, edge_id)
                    .expect("validated ICFG edge remains in its immutable snapshot");
                let canonical_outputs = match evaluate_transfer(
                    problem,
                    descriptor,
                    fact,
                    self.facts[ZERO_FACT_ID.index()],
                    queued.state.fact == ZERO_FACT_ID,
                    &mut self.transfer_scratch,
                    request,
                ) {
                    TransferEvaluation::Outputs(outputs) => outputs,
                    TransferEvaluation::Terminated(termination) => return Ok(termination),
                };
                let output_quality = queued.quality.through_edge(edge);
                if let Some(termination) =
                    self.publish_outputs(edge.target, output_quality, &canonical_outputs, request)?
                {
                    return Ok(termination);
                }
            }
        }
        Ok(SolverTermination::FixedPoint)
    }

    fn observe_edge(&mut self, edge_id: IcfgEdgeId, edge: &crate::analyzer::semantic::IcfgEdge) {
        if !matches!(&edge.proof, ProofStatus::Proven) {
            self.unproven_edges.insert(edge_id);
        }
        if !matches!(&edge.completeness, EvidenceCompleteness::Complete) {
            self.partial_edges.insert(edge_id);
        }
    }

    fn publish_outputs(
        &mut self,
        target: IcfgNodeId,
        quality: PathQuality,
        outputs: &[Fact],
        request: &mut DataflowRequest<'_>,
    ) -> Result<Option<SolverTermination>, DataflowError> {
        let propagated_outputs = outputs.len();
        let mut staged_facts = Vec::new();
        let mut staged_states = Vec::with_capacity(propagated_outputs);
        let mut new_reached_states = 0;

        for &output in outputs {
            let fact = match self.fact_ids.get(&output).copied() {
                Some(fact) => fact,
                None => {
                    let index = self.facts.len() + staged_facts.len();
                    let fact = FactId::try_from_index(index)
                        .map_err(|_| DataflowError::FactIdOverflow { index })?;
                    staged_facts.push((output, fact));
                    fact
                }
            };
            let state = ExplodedState { node: target, fact };
            let existing = self.reached.get(&state).copied();
            let mut prospective = existing.unwrap_or_default();
            if prospective.insert(quality) {
                if existing.is_none() {
                    new_reached_states += 1;
                }
                staged_states.push((state, prospective));
            }
        }

        let charge = SolverWork {
            interned_facts: staged_facts.len(),
            reached_states: new_reached_states,
            callback_rows: propagated_outputs,
            propagated_outputs,
            ..SolverWork::default()
        };
        let staged_budget = match request.budget.staged_charge(charge) {
            Ok(staged) => staged,
            Err(exceeded) => {
                return Ok(Some(SolverTermination::ExceededBudget(exceeded)));
            }
        };
        if request.cancellation.is_cancelled() {
            return Ok(Some(SolverTermination::Cancelled));
        }

        *request.budget = staged_budget;
        for (fact, fact_id) in staged_facts {
            let expected = FactId::try_from_index(self.facts.len())
                .expect("prevalidated fact index remains representable");
            debug_assert_eq!(fact_id, expected);
            let replaced = self.fact_ids.insert(fact, fact_id);
            debug_assert!(replaced.is_none(), "staged facts are unique");
            self.facts.push(fact);
        }

        for (state, path_qualities) in staged_states {
            self.reached.insert(state, path_qualities);
            self.worklist.push_back(QueuedState { state, quality });
        }
        Ok(None)
    }

    fn finish(
        self,
        input_status: super::IcfgInputStatus,
        termination: SolverTermination,
        work: SolverWork,
    ) -> DataflowResult<Fact> {
        let reached_nodes = self
            .reached
            .keys()
            .map(|state| state.node)
            .collect::<HashSet<_>>();
        let boundaries = self
            .snapshot
            .boundaries()
            .iter()
            .filter(|boundary| reached_nodes.contains(&boundary.at))
            .cloned()
            .collect::<Vec<_>>();

        let coverage = DataflowCoverage::from_parts(
            input_status,
            self.unproven_edges.into_iter().collect(),
            self.partial_edges.into_iter().collect(),
            boundaries,
        );
        let mut reached = self
            .reached
            .into_iter()
            .map(|(state, path_qualities)| ReachedFact::new(state.node, state.fact, path_qualities))
            .collect::<Vec<_>>();
        reached.sort_unstable_by_key(|row| (row.node(), row.fact()));

        DataflowResult::from_parts(self.facts, reached, coverage, termination, work)
    }
}

/// Solve one finite distributive may-data-flow problem over a bounded ICFG.
pub fn solve<P>(
    input: IcfgSolveInput<'_>,
    problem: &P,
    request: &mut DataflowRequest<'_>,
) -> Result<DataflowResult<P::Fact>, DataflowError>
where
    P: BoundedSnapshotDataflowProblem,
{
    let initial_work = request.budget.used();
    let mut state = TabulationState::new(input.snapshot());

    let termination = if let Some(termination) = state.initialize(problem, request)? {
        termination
    } else {
        state.propagate(problem, request)?
    };
    let work = request.budget.used().saturating_sub(initial_work);
    Ok(state.finish(input.status(), termination, work))
}
