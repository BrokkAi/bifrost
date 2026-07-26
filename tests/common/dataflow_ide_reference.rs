//! Deliberately simple repeated-scan IDE semantics for differential tests.
//!
//! This oracle has no dense IDs, worklist, caches, budgets, quality frontier,
//! or production jump tables. It repeatedly scans owned relative paths,
//! incoming calls, and end summaries until no function changes.

#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::hash::Hash;

use brokk_bifrost::analyzer::dataflow::{
    DataflowEdge, DataflowOutput, IdeDataflowProblem, IdeDataflowSeed, IdeTransition,
};
use brokk_bifrost::analyzer::semantic::{
    CallTransfer, ControlContinuation, ControlEdgeKind, IcfgEdgeKind, IcfgExitProfile,
    IcfgProvider, MatchedReturnProjection, ProcedureHandle, ProcedureIcfgEdge, ProgramPointHandle,
    ProgramPointId, ProofStatus, SemanticBudget, SemanticEffect, SemanticProviderError,
    SemanticRequest,
};

#[derive(Debug, Clone)]
pub struct ReferenceIdeResult<Fact, Value> {
    point_values: HashMap<(ProgramPointHandle, Fact), Value>,
}

impl<Fact, Value> ReferenceIdeResult<Fact, Value>
where
    Fact: Copy + Eq + Hash,
{
    pub fn point_values(&self) -> &HashMap<(ProgramPointHandle, Fact), Value> {
        &self.point_values
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReferenceIdeError {
    MissingPoint(&'static str),
    MissingSeed,
    SemanticProvider(SemanticProviderError),
}

impl fmt::Display for ReferenceIdeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingPoint(detail) => write!(formatter, "missing semantic point: {detail}"),
            Self::MissingSeed => formatter.write_str("root IDE entry has no seed value"),
            Self::SemanticProvider(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ReferenceIdeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SemanticProvider(error) => Some(error),
            Self::MissingPoint(_) | Self::MissingSeed => None,
        }
    }
}

impl From<SemanticProviderError> for ReferenceIdeError {
    fn from(error: SemanticProviderError) -> Self {
        Self::SemanticProvider(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Entry<Fact> {
    procedure: ProcedureHandle,
    point: ProgramPointId,
    fact: Fact,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Path<Fact> {
    entry: Entry<Fact>,
    point: ProgramPointId,
    fact: Fact,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EndSummary<Fact, EdgeFunction> {
    entry: Entry<Fact>,
    exit: IcfgExitProfile,
    fact: Fact,
    function: EdgeFunction,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Incoming<Fact, EdgeFunction> {
    callee: Entry<Fact>,
    caller_path: Path<Fact>,
    transfer: CallTransfer,
    call_function: EdgeFunction,
}

struct VecOutput<'output, Value>(&'output mut Vec<Value>);

impl<Value> DataflowOutput<Value> for VecOutput<'_, Value> {
    fn emit(&mut self, value: Value) -> bool {
        self.0.push(value);
        true
    }
}

pub fn reference_ide_projection<Problem, Provider>(
    root: &ProcedureHandle,
    seeds: &[IdeDataflowSeed<Problem::Fact, Problem::Value>],
    provider: &Provider,
    problem: &Problem,
    semantic_budget: &mut SemanticBudget,
) -> Result<ReferenceIdeResult<Problem::Fact, Problem::Value>, ReferenceIdeError>
where
    Problem: IdeDataflowProblem,
    Provider: IcfgProvider + ?Sized,
{
    let root_entry = root
        .point_handle(root.semantics().entry_point())
        .ok_or(ReferenceIdeError::MissingPoint("root entry"))?;
    let zero = problem.zero_fact();
    let mut seed_values = HashMap::new();
    seed_values.insert(zero, problem.zero_value());
    for seed in seeds {
        let fact = *seed.fact();
        let value = seed.value().clone();
        match seed_values.get(&fact) {
            Some(existing) if existing != &value => {
                seed_values.insert(fact, meet_values(problem, existing, &value));
            }
            None => {
                seed_values.insert(fact, value);
            }
            Some(_) => {}
        }
    }

    let identity = problem.identity_edge_function();
    let mut jumps = HashMap::<Path<Problem::Fact>, Problem::EdgeFunction>::new();
    for fact in seed_values.keys().copied() {
        let entry = Entry {
            procedure: root.clone(),
            point: root_entry.id(),
            fact,
        };
        jumps.insert(
            Path {
                entry,
                point: root_entry.id(),
                fact,
            },
            identity.clone(),
        );
    }
    let mut incoming = HashSet::<Incoming<Problem::Fact, Problem::EdgeFunction>>::new();
    let mut summaries = Vec::<EndSummary<Problem::Fact, Problem::EdgeFunction>>::new();
    let cancellation = brokk_bifrost::analyzer::semantic::CancellationToken::default();

    loop {
        let frozen_jumps = jumps.clone();
        let frozen_incoming = incoming.iter().cloned().collect::<Vec<_>>();
        let frozen_summaries = summaries.clone();
        let mut changed = false;

        for (path, jump) in &frozen_jumps {
            let point = path.entry.procedure.point_handle(path.point).ok_or(
                ReferenceIdeError::MissingPoint("reached procedure-local point"),
            )?;
            if is_exit(&point) {
                let entry = path
                    .entry
                    .procedure
                    .point_handle(path.entry.point)
                    .ok_or(ReferenceIdeError::MissingPoint("summary entry"))?;
                let outcome = provider.exit_profile(
                    &entry,
                    &point,
                    &mut SemanticRequest::new(semantic_budget, &cancellation),
                )?;
                if let Some(exit) = outcome.available_value() {
                    changed |= publish_summary(
                        &mut summaries,
                        EndSummary {
                            entry: path.entry.clone(),
                            exit: exit.clone(),
                            fact: path.fact,
                            function: jump.clone(),
                        },
                        problem,
                    );
                }
                continue;
            }

            if let Some(call) = invoked_call_at(&point) {
                let semantic_call = point
                    .procedure()
                    .semantics()
                    .call_site(call)
                    .ok_or(ReferenceIdeError::MissingPoint("invoked call row"))?
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
                            boundary: None,
                        };
                        for transition in transition_outputs(problem, &edge, path.fact) {
                            let callee = Entry {
                                procedure: transfer.callee.clone(),
                                point: transfer.callee_entry.id(),
                                fact: transition.fact,
                            };
                            changed |= publish_jump(
                                &mut jumps,
                                Path {
                                    entry: callee.clone(),
                                    point: transfer.callee_entry.id(),
                                    fact: transition.fact,
                                },
                                identity.clone(),
                                problem,
                            );
                            changed |= incoming.insert(Incoming {
                                callee,
                                caller_path: path.clone(),
                                transfer: transfer.clone(),
                                call_function: transition.function,
                            });
                        }
                    }
                }
                changed |= propagate_local_edges(
                    &mut jumps,
                    problem,
                    &point,
                    path,
                    jump,
                    Some(&semantic_call),
                )?;
            } else {
                changed |= propagate_local_edges(&mut jumps, problem, &point, path, jump, None)?;
            }
        }

        for waiting in frozen_incoming {
            let Some(caller_jump) = frozen_jumps.get(&waiting.caller_path) else {
                continue;
            };
            for summary in &frozen_summaries {
                if waiting.callee != summary.entry {
                    continue;
                }
                match summary.exit.project_matched_return(&waiting.transfer)? {
                    MatchedReturnProjection::Absent | MatchedReturnProjection::Boundary(_) => {}
                    MatchedReturnProjection::Edge(edge) => {
                        for transition in transition_outputs(problem, &edge, summary.fact) {
                            let call = compose(problem, caller_jump, &waiting.call_function);
                            let callee = compose(problem, &call, &summary.function);
                            let candidate = compose(problem, &callee, &transition.function);
                            changed |= publish_jump(
                                &mut jumps,
                                Path {
                                    entry: waiting.caller_path.entry.clone(),
                                    point: edge.target.id(),
                                    fact: transition.fact,
                                },
                                candidate,
                                problem,
                            );
                        }
                    }
                }
            }
        }

        if !changed {
            break;
        }
    }

    let mut point_values = HashMap::new();
    for (path, function) in jumps {
        if path.entry.procedure != *root || path.entry.point != root_entry.id() {
            continue;
        }
        let seed = seed_values
            .get(&path.entry.fact)
            .ok_or(ReferenceIdeError::MissingSeed)?;
        let value = problem.apply_edge_function(&function, seed);
        let point = path
            .entry
            .procedure
            .point_handle(path.point)
            .ok_or(ReferenceIdeError::MissingPoint("published root point"))?;
        let key = (point, path.fact);
        match point_values.get(&key) {
            Some(existing) if existing != &value => {
                point_values.insert(key, meet_values(problem, existing, &value));
            }
            None => {
                point_values.insert(key, value);
            }
            Some(_) => {}
        }
    }
    Ok(ReferenceIdeResult { point_values })
}

#[allow(clippy::too_many_arguments)]
fn propagate_local_edges<Problem>(
    jumps: &mut HashMap<Path<Problem::Fact>, Problem::EdgeFunction>,
    problem: &Problem,
    point: &ProgramPointHandle,
    path: &Path<Problem::Fact>,
    jump: &Problem::EdgeFunction,
    call: Option<&brokk_bifrost::analyzer::semantic::SemanticCallSite>,
) -> Result<bool, ReferenceIdeError>
where
    Problem: IdeDataflowProblem,
{
    let mut changed = false;
    for (_, edge) in point.procedure().semantics().successor_edges(point.id()) {
        if call.is_some_and(|call| is_call_scaffolding(edge, call)) {
            continue;
        }
        let target = point
            .procedure()
            .point_handle(edge.target_point)
            .ok_or(ReferenceIdeError::MissingPoint("local edge target"))?;
        let owned = ProcedureIcfgEdge {
            source: point.clone(),
            target,
            kind: IcfgEdgeKind::Intraprocedural(edge.kind),
            origin: None,
            proof: ProofStatus::Proven,
            completeness: brokk_bifrost::analyzer::semantic::EvidenceCompleteness::Complete,
            boundary: None,
        };
        for transition in transition_outputs(problem, &owned, path.fact) {
            changed |= publish_jump(
                jumps,
                Path {
                    entry: path.entry.clone(),
                    point: owned.target.id(),
                    fact: transition.fact,
                },
                compose(problem, jump, &transition.function),
                problem,
            );
        }
    }
    Ok(changed)
}

struct OwnedTransition<Fact, EdgeFunction> {
    fact: Fact,
    function: EdgeFunction,
}

fn transition_outputs<Problem>(
    problem: &Problem,
    edge: &ProcedureIcfgEdge,
    fact: Problem::Fact,
) -> Vec<OwnedTransition<Problem::Fact, Problem::EdgeFunction>>
where
    Problem: IdeDataflowProblem,
{
    let mut emitted = Vec::new();
    apply_transfer(
        problem,
        descriptor(edge),
        edge.kind,
        fact,
        &mut VecOutput(&mut emitted),
    );
    if fact == problem.zero_fact() {
        emitted.push(IdeTransition::new(fact, problem.identity_edge_function()));
    }
    let mut outputs = HashMap::new();
    for transition in emitted {
        let (output, function) = transition.into_parts();
        match outputs.get(&output) {
            Some(existing) if existing != &function => {
                outputs.insert(output, meet_functions(problem, existing, &function));
            }
            None => {
                outputs.insert(output, function);
            }
            Some(_) => {}
        }
    }
    outputs
        .into_iter()
        .map(|(fact, function)| OwnedTransition { fact, function })
        .collect()
}

fn apply_transfer<Problem>(
    problem: &Problem,
    edge: DataflowEdge<'_>,
    kind: IcfgEdgeKind,
    fact: Problem::Fact,
    out: &mut dyn DataflowOutput<IdeTransition<Problem::Fact, Problem::EdgeFunction>>,
) where
    Problem: IdeDataflowProblem,
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

fn publish_jump<Problem>(
    jumps: &mut HashMap<Path<Problem::Fact>, Problem::EdgeFunction>,
    path: Path<Problem::Fact>,
    candidate: Problem::EdgeFunction,
    problem: &Problem,
) -> bool
where
    Problem: IdeDataflowProblem,
{
    let next = match jumps.get(&path) {
        Some(existing) if existing != &candidate => meet_functions(problem, existing, &candidate),
        Some(_) => return false,
        None => candidate,
    };
    if jumps.get(&path) == Some(&next) {
        return false;
    }
    jumps.insert(path, next);
    true
}

fn publish_summary<Problem>(
    summaries: &mut Vec<EndSummary<Problem::Fact, Problem::EdgeFunction>>,
    candidate: EndSummary<Problem::Fact, Problem::EdgeFunction>,
    problem: &Problem,
) -> bool
where
    Problem: IdeDataflowProblem,
{
    if let Some(existing) = summaries.iter_mut().find(|existing| {
        existing.entry == candidate.entry
            && existing.exit == candidate.exit
            && existing.fact == candidate.fact
    }) {
        let next = meet_functions(problem, &existing.function, &candidate.function);
        if next == existing.function {
            return false;
        }
        existing.function = next;
        return true;
    }
    summaries.push(candidate);
    true
}

fn compose<Problem>(
    problem: &Problem,
    first: &Problem::EdgeFunction,
    second: &Problem::EdgeFunction,
) -> Problem::EdgeFunction
where
    Problem: IdeDataflowProblem,
{
    problem.compose_edge_functions(first, second)
}

fn meet_functions<Problem>(
    problem: &Problem,
    left: &Problem::EdgeFunction,
    right: &Problem::EdgeFunction,
) -> Problem::EdgeFunction
where
    Problem: IdeDataflowProblem,
{
    if left <= right {
        problem.meet_edge_functions(left, right)
    } else {
        problem.meet_edge_functions(right, left)
    }
}

fn meet_values<Problem>(
    problem: &Problem,
    left: &Problem::Value,
    right: &Problem::Value,
) -> Problem::Value
where
    Problem: IdeDataflowProblem,
{
    if left <= right {
        problem.meet_values(left, right)
    } else {
        problem.meet_values(right, left)
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
