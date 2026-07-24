//! Shared bounded evaluation of one distributive transfer relation.

use crate::hash::HashSet;

use super::{
    DataflowEdge, DataflowOutput, DataflowRequest, DistributiveDataflowProblem,
    SolverBudgetExceeded, SolverTermination, SolverWork,
};

pub(crate) enum TransferEvaluation<Fact> {
    Outputs(Vec<Fact>),
    Terminated(SolverTermination),
}

pub(crate) struct TransferScratch<Fact> {
    emitted_outputs: HashSet<Fact>,
}

impl<Fact> TransferScratch<Fact> {
    pub(crate) fn new() -> Self {
        Self {
            emitted_outputs: HashSet::default(),
        }
    }
}

struct BoundedFactOutputs<'request, Fact> {
    values: &'request mut HashSet<Fact>,
    budget: &'request super::SolverBudget,
    cancellation: &'request crate::analyzer::semantic::CancellationToken,
    exceeded: Option<SolverBudgetExceeded>,
}

impl<'request, Fact> BoundedFactOutputs<'request, Fact>
where
    Fact: Copy + Eq + std::hash::Hash,
{
    fn new(
        values: &'request mut HashSet<Fact>,
        budget: &'request super::SolverBudget,
        cancellation: &'request crate::analyzer::semantic::CancellationToken,
    ) -> Self {
        Self {
            values,
            budget,
            cancellation,
            exceeded: None,
        }
    }

    const fn exceeded(&self) -> Option<SolverBudgetExceeded> {
        self.exceeded
    }
}

impl<Fact> DataflowOutput<Fact> for BoundedFactOutputs<'_, Fact>
where
    Fact: Copy + Eq + std::hash::Hash,
{
    fn emit(&mut self, value: Fact) -> bool {
        if self.cancellation.is_cancelled() || self.exceeded.is_some() {
            return false;
        }
        if self.values.contains(&value) {
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

        self.values.insert(value);
        true
    }
}

pub(crate) fn evaluate_transfer<P>(
    problem: &P,
    edge: DataflowEdge<'_>,
    fact: P::Fact,
    zero_fact: P::Fact,
    preserve_zero: bool,
    scratch: &mut TransferScratch<P::Fact>,
    request: &mut DataflowRequest<'_>,
) -> TransferEvaluation<P::Fact>
where
    P: DistributiveDataflowProblem,
{
    if request.cancellation.is_cancelled() {
        return TransferEvaluation::Terminated(SolverTermination::Cancelled);
    }
    let staged_budget = match request.budget.staged_charge(SolverWork {
        flow_evaluations: 1,
        ..SolverWork::default()
    }) {
        Ok(staged) => staged,
        Err(exceeded) => {
            return TransferEvaluation::Terminated(SolverTermination::ExceededBudget(exceeded));
        }
    };
    if request.cancellation.is_cancelled() {
        return TransferEvaluation::Terminated(SolverTermination::Cancelled);
    }
    *request.budget = staged_budget;

    scratch.emitted_outputs.clear();
    let sink_exceeded = {
        let mut outputs = BoundedFactOutputs::new(
            &mut scratch.emitted_outputs,
            request.budget,
            request.cancellation,
        );
        apply_transfer(problem, edge, fact, &mut outputs);
        if preserve_zero {
            let _ = outputs.emit(zero_fact);
        }
        outputs.exceeded()
    };

    // A callback may cooperatively cancel through a shared token. Its
    // retained relation must not become visible after that checkpoint.
    if request.cancellation.is_cancelled() {
        return TransferEvaluation::Terminated(SolverTermination::Cancelled);
    }
    if let Some(exceeded) = sink_exceeded {
        return TransferEvaluation::Terminated(SolverTermination::ExceededBudget(exceeded));
    }

    let mut outputs = scratch.emitted_outputs.iter().copied().collect::<Vec<_>>();
    outputs.sort_unstable();
    TransferEvaluation::Outputs(outputs)
}

fn apply_transfer<P>(
    problem: &P,
    edge: DataflowEdge<'_>,
    fact: P::Fact,
    out: &mut dyn DataflowOutput<P::Fact>,
) where
    P: DistributiveDataflowProblem,
{
    use crate::analyzer::semantic::{ControlEdgeKind, IcfgEdgeKind};

    match edge.kind() {
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
