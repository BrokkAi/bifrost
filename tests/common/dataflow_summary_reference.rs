//! Deliberately simple reference semantics for provider-backed summary tests.
//!
//! This runner favors an obviously independent fixed point over efficiency:
//! every round rescans every reached relative path, every incoming call, and
//! every end summary. It has no worklist, dense fact interner, summary indexes,
//! solver budgets, path-quality frontier, cache metrics, or witness storage.
//! Recursive and mutually recursive calls converge because procedure entries
//! are keyed by `(procedure, entry point, entry fact)`, never by a call string.

#![allow(dead_code)]

use std::collections::HashSet;
use std::fmt;

use brokk_bifrost::analyzer::dataflow::{
    DataflowEdge, DataflowOutput, DistributiveDataflowProblem,
};
use brokk_bifrost::analyzer::semantic::{
    CallTransfer, ControlContinuation, ControlEdgeKind, IcfgEdgeKind, IcfgExitProfile,
    IcfgProvider, MatchedReturnProjection, ProcedureHandle, ProcedureIcfgEdge, ProgramPointHandle,
    ProgramPointId, ProofStatus, SemanticBudget, SemanticEffect, SemanticProviderError,
    SemanticRequest,
};

/// Canonical, context-free rows from the repeated-scan reference.
#[derive(Debug, Clone)]
pub struct ReferenceSummaryProjection<F> {
    reached: HashSet<(ProgramPointHandle, F)>,
}

impl<F> ReferenceSummaryProjection<F>
where
    F: Copy + Eq + std::hash::Hash,
{
    pub fn reached(&self) -> &HashSet<(ProgramPointHandle, F)> {
        &self.reached
    }
}

/// A malformed semantic row or operational provider failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReferenceSummaryError {
    MissingPoint(&'static str),
    SemanticProvider(SemanticProviderError),
}

impl fmt::Display for ReferenceSummaryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingPoint(detail) => write!(formatter, "missing semantic point: {detail}"),
            Self::SemanticProvider(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ReferenceSummaryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::MissingPoint(_) => None,
            Self::SemanticProvider(error) => Some(error),
        }
    }
}

impl From<SemanticProviderError> for ReferenceSummaryError {
    fn from(error: SemanticProviderError) -> Self {
        Self::SemanticProvider(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Entry<F> {
    procedure: ProcedureHandle,
    point: ProgramPointId,
    fact: F,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Path<F> {
    entry: Entry<F>,
    point: ProgramPointId,
    fact: F,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EndSummary<F> {
    entry: Entry<F>,
    exit: IcfgExitProfile,
    fact: F,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Incoming<F> {
    callee: Entry<F>,
    caller: Entry<F>,
    call_point: ProgramPointId,
    call_fact: F,
    transfer: CallTransfer,
}

struct VecOutput<'output, Value>(&'output mut Vec<Value>);

impl<Value> DataflowOutput<Value> for VecOutput<'_, Value> {
    fn emit(&mut self, value: Value) -> bool {
        self.0.push(value);
        true
    }
}

/// Compute a context-free may fixed point by repeated provider-backed scans.
///
/// The reference consumes materialized call transfers and matched exit
/// projections. Dispatch boundaries with call-to-return models are outside
/// this small differential oracle and have dedicated behavior tests.
pub fn reference_summary_projection<P, Provider>(
    root: &ProcedureHandle,
    entry_facts: &[P::Fact],
    provider: &Provider,
    problem: &P,
    semantic_budget: &mut SemanticBudget,
) -> Result<ReferenceSummaryProjection<P::Fact>, ReferenceSummaryError>
where
    P: DistributiveDataflowProblem,
    Provider: IcfgProvider + ?Sized,
{
    let root_entry = root
        .point_handle(root.semantics().entry_point())
        .ok_or(ReferenceSummaryError::MissingPoint("root entry"))?;
    let zero = problem.zero_fact();
    let mut seeds = entry_facts.to_vec();
    seeds.push(zero);
    seeds.sort_unstable();
    seeds.dedup();

    let mut reached = HashSet::new();
    for fact in seeds {
        let entry = Entry {
            procedure: root.clone(),
            point: root_entry.id(),
            fact,
        };
        reached.insert(Path {
            entry,
            point: root_entry.id(),
            fact,
        });
    }
    let mut incoming = HashSet::<Incoming<P::Fact>>::new();
    let mut summaries = Vec::<EndSummary<P::Fact>>::new();
    let cancellation = brokk_bifrost::analyzer::semantic::CancellationToken::default();

    loop {
        let before_reached = reached.len();
        let before_incoming = incoming.len();
        let before_summaries = summaries.len();
        let frozen_paths = reached.iter().cloned().collect::<Vec<_>>();
        let frozen_incoming = incoming.iter().cloned().collect::<Vec<_>>();
        let frozen_summaries = summaries.clone();

        for path in frozen_paths {
            let point = path.entry.procedure.point_handle(path.point).ok_or(
                ReferenceSummaryError::MissingPoint("reached procedure-local point"),
            )?;

            if is_exit(&point) {
                let entry = path
                    .entry
                    .procedure
                    .point_handle(path.entry.point)
                    .ok_or(ReferenceSummaryError::MissingPoint("summary entry"))?;
                let outcome = provider.exit_profile(
                    &entry,
                    &point,
                    &mut SemanticRequest::new(semantic_budget, &cancellation),
                )?;
                if let Some(exit) = outcome.available_value() {
                    push_unique(
                        &mut summaries,
                        EndSummary {
                            entry: path.entry.clone(),
                            exit: exit.clone(),
                            fact: path.fact,
                        },
                    );
                }
                continue;
            }

            if let Some(call) = invoked_call_at(&point) {
                let semantic_call = point
                    .procedure()
                    .semantics()
                    .call_site(call)
                    .ok_or(ReferenceSummaryError::MissingPoint("invoked call row"))?
                    .clone();
                let outcome = provider.call_transfers(
                    point.procedure(),
                    call,
                    &mut SemanticRequest::new(semantic_budget, &cancellation),
                )?;
                if let Some(transfers) = outcome.available_value() {
                    for transfer in transfers.transfers.iter() {
                        let edge = ProcedureIcfgEdge {
                            source: point.clone(),
                            target: transfer.callee_entry.clone(),
                            kind: IcfgEdgeKind::Call,
                            origin: Some(transfer.origin.clone()),
                            proof: transfer.proof.clone(),
                            completeness: transfer.completeness.clone(),
                        };
                        for output in transfer_outputs(problem, descriptor(&edge), path.fact, zero)
                        {
                            let callee = Entry {
                                procedure: transfer.callee.clone(),
                                point: transfer.callee_entry.id(),
                                fact: output,
                            };
                            reached.insert(Path {
                                entry: callee.clone(),
                                point: transfer.callee_entry.id(),
                                fact: output,
                            });
                            incoming.insert(Incoming {
                                callee,
                                caller: path.entry.clone(),
                                call_point: path.point,
                                call_fact: path.fact,
                                transfer: transfer.clone(),
                            });
                        }
                    }
                }

                propagate_local_edges(
                    &mut reached,
                    problem,
                    &point,
                    &path,
                    Some(&semantic_call),
                    zero,
                )?;
            } else {
                propagate_local_edges(&mut reached, problem, &point, &path, None, zero)?;
            }
        }

        for waiting in frozen_incoming {
            for summary in &frozen_summaries {
                if waiting.callee != summary.entry {
                    continue;
                }
                match summary.exit.project_matched_return(&waiting.transfer)? {
                    MatchedReturnProjection::Absent | MatchedReturnProjection::Boundary(_) => {}
                    MatchedReturnProjection::Edge(edge) => {
                        for output in
                            transfer_outputs(problem, descriptor(&edge), summary.fact, zero)
                        {
                            reached.insert(Path {
                                entry: waiting.caller.clone(),
                                point: edge.target.id(),
                                fact: output,
                            });
                        }
                    }
                }
            }
        }

        if reached.len() == before_reached
            && incoming.len() == before_incoming
            && summaries.len() == before_summaries
        {
            let reached = reached
                .into_iter()
                .map(|path| {
                    let point = path
                        .entry
                        .procedure
                        .point_handle(path.point)
                        .expect("published reference point remains valid");
                    (point, path.fact)
                })
                .collect();
            return Ok(ReferenceSummaryProjection { reached });
        }
    }
}

fn propagate_local_edges<P>(
    reached: &mut HashSet<Path<P::Fact>>,
    problem: &P,
    point: &ProgramPointHandle,
    path: &Path<P::Fact>,
    call: Option<&brokk_bifrost::analyzer::semantic::SemanticCallSite>,
    zero: P::Fact,
) -> Result<(), ReferenceSummaryError>
where
    P: DistributiveDataflowProblem,
{
    for (_, edge) in point.procedure().semantics().successor_edges(point.id()) {
        if call.is_some_and(|call| is_call_scaffolding(edge, call)) {
            continue;
        }
        let target = point
            .procedure()
            .point_handle(edge.target_point)
            .ok_or(ReferenceSummaryError::MissingPoint("local edge target"))?;
        let owned = ProcedureIcfgEdge {
            source: point.clone(),
            target,
            kind: IcfgEdgeKind::Intraprocedural(edge.kind),
            origin: None,
            proof: ProofStatus::Proven,
            completeness: brokk_bifrost::analyzer::semantic::EvidenceCompleteness::Complete,
        };
        for output in transfer_outputs(problem, descriptor(&owned), path.fact, zero) {
            reached.insert(Path {
                entry: path.entry.clone(),
                point: owned.target.id(),
                fact: output,
            });
        }
    }
    Ok(())
}

fn transfer_outputs<P>(
    problem: &P,
    edge: DataflowEdge<'_>,
    fact: P::Fact,
    zero: P::Fact,
) -> Vec<P::Fact>
where
    P: DistributiveDataflowProblem,
{
    let mut outputs = Vec::new();
    apply_transfer(
        problem,
        edge,
        edge.kind(),
        fact,
        &mut VecOutput(&mut outputs),
    );
    if fact == zero {
        outputs.push(zero);
    }
    outputs.sort_unstable();
    outputs.dedup();
    outputs
}

fn apply_transfer<P>(
    problem: &P,
    edge: DataflowEdge<'_>,
    kind: IcfgEdgeKind,
    fact: P::Fact,
    out: &mut dyn DataflowOutput<P::Fact>,
) where
    P: DistributiveDataflowProblem,
{
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

fn descriptor(edge: &ProcedureIcfgEdge) -> DataflowEdge<'_> {
    DataflowEdge::new(
        edge.kind,
        edge.origin.as_ref(),
        &edge.source,
        &edge.target,
        &edge.proof,
        &edge.completeness,
    )
}

fn invoked_call_at(
    point: &ProgramPointHandle,
) -> Option<brokk_bifrost::analyzer::semantic::CallSiteId> {
    point
        .procedure()
        .semantics()
        .point(point.id())?
        .events
        .iter()
        .find_map(|event| match event.effect {
            SemanticEffect::Invoke { call_site } => Some(call_site),
            _ => None,
        })
}

fn is_call_scaffolding(
    edge: &brokk_bifrost::analyzer::semantic::ControlEdge,
    call: &brokk_bifrost::analyzer::semantic::SemanticCallSite,
) -> bool {
    matches!(
        (edge.kind, call.normal_continuation),
        (ControlEdgeKind::Normal, ControlContinuation::Target(target))
            if edge.target_point == target
    ) || matches!(
        (edge.kind, call.exceptional_continuation),
        (ControlEdgeKind::Exceptional, ControlContinuation::Target(target))
            if edge.target_point == target
    )
}

fn is_exit(point: &ProgramPointHandle) -> bool {
    let semantics = point.procedure().semantics();
    point.id() == semantics.normal_exit_point() || point.id() == semantics.exceptional_exit_point()
}

fn push_unique<T: PartialEq>(rows: &mut Vec<T>, row: T) {
    if !rows.contains(&row) {
        rows.push(row);
    }
}
