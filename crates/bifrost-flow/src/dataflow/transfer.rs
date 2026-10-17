//! Shared bounded evaluation of one distributive transfer relation.

use crate::hash::HashSet;

use super::{
    BackwardDistributiveDataflowProblem, DataflowEdge, DataflowOutput, DataflowRequest,
    DistributiveDataflowProblem, SolverBudgetExceeded, SolverTermination, SolverWork,
};

pub(crate) enum TransferEvaluation<Fact> {
    Outputs(Vec<Fact>),
    Terminated(SolverTermination),
}

pub(crate) struct TransferScratch<Fact> {
    emitted_outputs: HashSet<Fact>,
}

fn evaluate_transfer_with<Fact>(
    zero_fact: Fact,
    preserve_zero: bool,
    scratch: &mut TransferScratch<Fact>,
    request: &mut DataflowRequest<'_>,
    apply: impl FnOnce(&mut dyn DataflowOutput<Fact>),
) -> TransferEvaluation<Fact>
where
    Fact: Copy + Eq + std::hash::Hash + Ord,
{
    if let Some(termination) = request.reserve(SolverWork {
        flow_evaluations: 1,
        ..SolverWork::default()
    }) {
        return TransferEvaluation::Terminated(termination);
    }

    scratch.emitted_outputs.clear();
    let sink_exceeded = {
        let mut outputs = BoundedFactOutputs::new(
            &mut scratch.emitted_outputs,
            request.budget,
            request.cancellation,
        );
        apply(&mut outputs);
        if preserve_zero {
            let _ = outputs.emit(zero_fact);
        }
        outputs.exceeded()
    };

    // A callback may cancel cooperatively; do not retain its partial relation.
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
    fn should_continue(&self) -> bool {
        super::should_continue(self.cancellation, false, self.exceeded.is_some())
    }

    fn emit(&mut self, value: Fact) -> bool {
        if !self.should_continue() {
            return false;
        }
        if let Err(exceeded) = super::emit_bounded_callback_output(self.values, value, self.budget)
        {
            self.exceeded = Some(exceeded);
            return false;
        }
        true
    }
}

pub(crate) fn evaluate_transfer<P>(
    problem: &P,
    edge: DataflowEdge<'_, P::Fact>,
    fact: P::Fact,
    zero_fact: P::Fact,
    preserve_zero: bool,
    scratch: &mut TransferScratch<P::Fact>,
    request: &mut DataflowRequest<'_>,
) -> TransferEvaluation<P::Fact>
where
    P: DistributiveDataflowProblem,
{
    evaluate_transfer_with(zero_fact, preserve_zero, scratch, request, |outputs| {
        apply_transfer(problem, edge, fact, outputs)
    })
}

pub(crate) fn evaluate_backward_transfer<P>(
    problem: &P,
    edge: DataflowEdge<'_, P::Fact>,
    output_fact: P::Fact,
    zero_fact: P::Fact,
    preserve_zero: bool,
    scratch: &mut TransferScratch<P::Fact>,
    request: &mut DataflowRequest<'_>,
) -> TransferEvaluation<P::Fact>
where
    P: BackwardDistributiveDataflowProblem,
{
    evaluate_transfer_with(zero_fact, preserve_zero, scratch, request, |outputs| {
        apply_backward_transfer(problem, edge, output_fact, outputs)
    })
}

fn apply_transfer<P>(
    problem: &P,
    edge: DataflowEdge<'_, P::Fact>,
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

fn apply_backward_transfer<P>(
    problem: &P,
    edge: DataflowEdge<'_, P::Fact>,
    output_fact: P::Fact,
    out: &mut dyn DataflowOutput<P::Fact>,
) where
    P: BackwardDistributiveDataflowProblem,
{
    use crate::analyzer::semantic::{ControlEdgeKind, IcfgEdgeKind};

    match edge.kind() {
        IcfgEdgeKind::Intraprocedural(
            ControlEdgeKind::Exceptional | ControlEdgeKind::AsyncExceptional,
        ) => problem.exceptional_predecessor_flow(edge, output_fact, out),
        IcfgEdgeKind::Intraprocedural(_) => problem.normal_predecessor_flow(edge, output_fact, out),
        IcfgEdgeKind::Call => problem.call_predecessor_flow(edge, output_fact, out),
        IcfgEdgeKind::NormalReturn | IcfgEdgeKind::ExceptionalReturn => {
            problem.return_predecessor_flow(edge, output_fact, out);
        }
        IcfgEdgeKind::CallToNormalContinuation | IcfgEdgeKind::CallToExceptionalContinuation => {
            problem.call_to_return_predecessor_flow(edge, output_fact, out);
        }
    }
}
