//! Deterministic worklist tabulation over one bounded ICFG snapshot.

use std::collections::VecDeque;

use crate::analyzer::semantic::{
    ControlEdgeKind, EvidenceCompleteness, IcfgEdgeId, IcfgEdgeKind, IcfgNodeId, IcfgSnapshot,
    ProofStatus,
};
use crate::hash::{HashMap, HashSet};

use super::{
    DataflowCoverage, DataflowEdge, DataflowError, DataflowRequest, DataflowResult, DataflowSeed,
    DistributiveDataflowProblem, FactId, IcfgSolveInput, PathQuality, PathQualityFrontier,
    ReachedFact, SolverTermination, SolverWork,
};

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

struct TabulationState<'graph, Fact> {
    snapshot: &'graph IcfgSnapshot,
    facts: Vec<Fact>,
    fact_ids: HashMap<Fact, FactId>,
    reached: HashMap<ExplodedState, PathQualityFrontier>,
    worklist: VecDeque<QueuedState>,
    unproven_edges: HashSet<IcfgEdgeId>,
    partial_edges: HashSet<IcfgEdgeId>,
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
        }
    }

    fn validate_snapshot(
        &self,
        request: &DataflowRequest<'_>,
    ) -> Result<Option<SolverTermination>, DataflowError> {
        for (index, edge) in self.snapshot.edges().iter().enumerate() {
            if request.cancellation.is_cancelled() {
                return Ok(Some(SolverTermination::Cancelled));
            }

            let edge_id =
                IcfgEdgeId::new(u32::try_from(index).expect("published ICFG edge IDs fit in u32"));
            if DataflowEdge::from_snapshot(self.snapshot, edge_id).is_none() {
                return Err(DataflowError::InvalidIcfgEdge { edge: edge_id });
            }
            if !matches!(edge.kind, IcfgEdgeKind::Intraprocedural(_)) && edge.origin.is_none() {
                return Err(DataflowError::MissingInterproceduralOrigin {
                    edge: edge_id,
                    kind: edge.kind,
                });
            }
        }
        Ok(None)
    }

    fn initialize<P>(
        &mut self,
        problem: &P,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Option<SolverTermination>, DataflowError>
    where
        P: DistributiveDataflowProblem<Fact = Fact>,
    {
        if request.cancellation.is_cancelled() {
            return Ok(Some(SolverTermination::Cancelled));
        }

        let zero_fact = problem.zero_fact();
        let mut seeds = Vec::<DataflowSeed<Fact>>::new();
        problem.seeds(&mut seeds);

        if request.cancellation.is_cancelled() {
            return Ok(Some(SolverTermination::Cancelled));
        }

        seeds.sort_unstable();
        seeds.dedup();
        for seed in &seeds {
            if self.snapshot.node(seed.node).is_none() {
                return Err(DataflowError::InvalidSeedNode {
                    node: seed.node,
                    node_count: self.snapshot.node_count(),
                });
            }
        }

        let mut staged_facts = vec![zero_fact];
        let mut staged_fact_ids = HashMap::default();
        staged_fact_ids.insert(zero_fact, FactId::new(0));
        let mut staged_states = Vec::with_capacity(seeds.len());

        for seed in seeds {
            let fact = match staged_fact_ids.get(&seed.fact).copied() {
                Some(fact) => fact,
                None => {
                    let index = staged_facts.len();
                    let fact = FactId::try_from_index(index)
                        .ok_or(DataflowError::FactIdOverflow { index })?;
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
                fact: FactId::new(0),
            });
        }
        staged_states.sort_unstable();
        staged_states.dedup();

        let charge = SolverWork {
            interned_facts: staged_facts.len(),
            reached_states: staged_states.len(),
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

            let Some(&path_qualities) = self.reached.get(&queued.state) else {
                continue;
            };
            if !path_qualities.contains(queued.quality) {
                continue;
            }
            let fact = self.facts[queued.state.fact.index()];

            for (edge_id, edge) in self.snapshot.successor_edges(queued.state.node) {
                self.observe_edge(edge_id, edge);
                if request.cancellation.is_cancelled() {
                    return Ok(SolverTermination::Cancelled);
                }

                let staged_budget = match request.budget.staged_charge(SolverWork {
                    flow_evaluations: 1,
                    ..SolverWork::default()
                }) {
                    Ok(staged) => staged,
                    Err(exceeded) => {
                        return Ok(SolverTermination::ExceededBudget(exceeded));
                    }
                };
                if request.cancellation.is_cancelled() {
                    return Ok(SolverTermination::Cancelled);
                }
                *request.budget = staged_budget;

                let descriptor = DataflowEdge::from_snapshot(self.snapshot, edge_id)
                    .expect("validated ICFG edge remains in its immutable snapshot");
                let mut outputs = Vec::new();
                apply_transfer(problem, descriptor, fact, &mut outputs);
                if queued.state.fact == FactId::new(0) {
                    outputs.push(self.facts[FactId::new(0).index()]);
                }

                // A callback may cooperatively cancel through a shared token.
                // Its outputs must not become visible after that checkpoint.
                if request.cancellation.is_cancelled() {
                    return Ok(SolverTermination::Cancelled);
                }

                outputs.sort_unstable();
                outputs.dedup();
                let output_quality = queued.quality.through_edge(edge);
                if let Some(termination) =
                    self.publish_outputs(edge.target, output_quality, outputs, request)?
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
        outputs: Vec<Fact>,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Option<SolverTermination>, DataflowError> {
        let propagated_outputs = outputs.len();
        let mut staged_facts = Vec::new();
        let mut staged_states = Vec::with_capacity(propagated_outputs);
        let mut new_reached_states = 0;

        for output in outputs {
            let fact = match self.fact_ids.get(&output).copied() {
                Some(fact) => fact,
                None => {
                    let index = self.facts.len() + staged_facts.len();
                    let fact = match FactId::try_from_index(index) {
                        Some(fact) => fact,
                        None => return Err(DataflowError::FactIdOverflow { index }),
                    };
                    staged_facts.push((output, fact));
                    fact
                }
            };
            let state = ExplodedState { node: target, fact };
            let existing = self.reached.get(&state).copied();
            let mut prospective = existing.unwrap_or_default();
            let changed = prospective.insert(quality);
            if existing.is_none() {
                new_reached_states += 1;
            }
            staged_states.push((state, prospective, changed));
        }

        let charge = SolverWork {
            interned_facts: staged_facts.len(),
            reached_states: new_reached_states,
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

        for (state, path_qualities, changed) in staged_states {
            if changed {
                self.reached.insert(state, path_qualities);
                self.worklist.push_back(QueuedState { state, quality });
            }
        }
        Ok(None)
    }

    fn finish(
        self,
        input_status: super::IcfgInputStatus,
        termination: SolverTermination,
        initial_work: SolverWork,
        final_work: SolverWork,
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

        DataflowResult::from_parts(
            self.facts,
            reached,
            coverage,
            termination,
            final_work.saturating_sub(initial_work),
        )
    }
}

/// Solve one finite distributive may-data-flow problem over a bounded ICFG.
pub fn solve<P>(
    input: IcfgSolveInput<'_>,
    problem: &P,
    request: &mut DataflowRequest<'_>,
) -> Result<DataflowResult<P::Fact>, DataflowError>
where
    P: DistributiveDataflowProblem,
{
    let initial_work = request.budget.used();
    let mut state = TabulationState::new(input.snapshot());

    if request.cancellation.is_cancelled() {
        return Ok(state.finish(
            input.status(),
            SolverTermination::Cancelled,
            initial_work,
            request.budget.used(),
        ));
    }
    if let Some(termination) = state.validate_snapshot(request)? {
        return Ok(state.finish(
            input.status(),
            termination,
            initial_work,
            request.budget.used(),
        ));
    }
    if let Some(termination) = state.initialize(problem, request)? {
        return Ok(state.finish(
            input.status(),
            termination,
            initial_work,
            request.budget.used(),
        ));
    }

    let termination = state.propagate(problem, request)?;
    Ok(state.finish(
        input.status(),
        termination,
        initial_work,
        request.budget.used(),
    ))
}

fn apply_transfer<P>(problem: &P, edge: DataflowEdge<'_>, fact: P::Fact, out: &mut Vec<P::Fact>)
where
    P: DistributiveDataflowProblem,
{
    match edge.edge().kind {
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
