//! Client contracts for bounded IDE edge-function propagation.

use std::{cell::RefCell, collections::VecDeque, hash::Hash};

use crate::analyzer::semantic::{
    CallTransfer, IcfgEdgeKind, MatchedReturnProjection, ProcedureHandle, ProcedureIcfgEdge,
    SemanticBudget, SemanticWork,
};
use crate::hash::{HashMap, HashSet};

use super::{
    DataflowEdge, DataflowOutput, DataflowRequest, DistributiveDataflowProblem, FactId,
    IdeDataflowError, IdeEdgeFunctionId, IdeMetrics, IdePointValue, IdeSummaryDataflowResult,
    IdeValueId, PathQualityFrontier, SolverTermination, SolverWork, SummaryDataflowError,
    SummaryDataflowResult, SummaryEntry, SummarySolveInput, WitnessRetentionLimits,
    solve_with_summaries,
};

/// One fact transition coupled to its client-supplied edge function.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdeTransition<Fact, EdgeFunction> {
    fact: Fact,
    edge_function: EdgeFunction,
}

impl<Fact, EdgeFunction> IdeTransition<Fact, EdgeFunction> {
    pub const fn new(fact: Fact, edge_function: EdgeFunction) -> Self {
        Self {
            fact,
            edge_function,
        }
    }

    pub const fn fact(&self) -> &Fact {
        &self.fact
    }

    pub const fn edge_function(&self) -> &EdgeFunction {
        &self.edge_function
    }

    pub fn into_parts(self) -> (Fact, EdgeFunction) {
        (self.fact, self.edge_function)
    }
}

/// One explicit root fact and the value supplied at that fact.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdeDataflowSeed<Fact, Value> {
    fact: Fact,
    value: Value,
}

impl<Fact, Value> IdeDataflowSeed<Fact, Value> {
    pub const fn new(fact: Fact, value: Value) -> Self {
        Self { fact, value }
    }

    pub const fn fact(&self) -> &Fact {
        &self.fact
    }

    pub const fn value(&self) -> &Value {
        &self.value
    }

    pub fn into_parts(self) -> (Fact, Value) {
        (self.fact, self.value)
    }
}

/// A finite or explicitly bounded IDE problem over one language-neutral ICFG.
///
/// Value and edge-function meet must be associative, commutative, and
/// idempotent. Composition must be associative and use
/// [`IdeDataflowProblem::identity_edge_function`] as both identities.
/// `compose_edge_functions(first, second)` is deliberately defined in path
/// order: applying its result must equal applying `first` and then `second`.
/// Pointwise edge-function meet must agree with meeting the corresponding
/// applied values.
///
/// For one request, the closure of functions reachable through callbacks,
/// composition, and meet must be finite or stabilize before the request's
/// explicit operation budgets are exhausted. Callbacks must emit finite,
/// repeatable relations independent of evaluation order. Cooperative
/// cancellation is their only supported side effect.
pub trait IdeDataflowProblem {
    type Fact: Copy + Eq + Hash + Ord;
    type Value: Clone + Eq + Hash + Ord;
    type EdgeFunction: Clone + Eq + Hash + Ord;

    /// The distinguished fact preserved by the kernel on every edge.
    fn zero_fact(&self) -> Self::Fact;

    /// The implicit value supplied at the distinguished zero fact.
    fn zero_value(&self) -> Self::Value;

    /// The function that returns every input value unchanged.
    fn identity_edge_function(&self) -> Self::EdgeFunction;

    /// Meet two values at an identical root `(point, fact)` state.
    fn meet_values(&self, left: &Self::Value, right: &Self::Value) -> Self::Value;

    /// Compose two functions in path order: first `first`, then `second`.
    fn compose_edge_functions(
        &self,
        first: &Self::EdgeFunction,
        second: &Self::EdgeFunction,
    ) -> Self::EdgeFunction;

    /// Apply one canonical edge or jump function to one client value.
    fn apply_edge_function(
        &self,
        function: &Self::EdgeFunction,
        value: &Self::Value,
    ) -> Self::Value;

    /// Pointwise meet two functions reaching the same relative state.
    fn meet_edge_functions(
        &self,
        left: &Self::EdgeFunction,
        right: &Self::EdgeFunction,
    ) -> Self::EdgeFunction;

    fn normal_flow(
        &self,
        edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<IdeTransition<Self::Fact, Self::EdgeFunction>>,
    );

    fn call_flow(
        &self,
        edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<IdeTransition<Self::Fact, Self::EdgeFunction>>,
    );

    fn return_flow(
        &self,
        edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<IdeTransition<Self::Fact, Self::EdgeFunction>>,
    );

    fn call_to_return_flow(
        &self,
        edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<IdeTransition<Self::Fact, Self::EdgeFunction>>,
    );

    fn exceptional_flow(
        &self,
        edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<IdeTransition<Self::Fact, Self::EdgeFunction>>,
    );
}

/// One root procedure, explicit fact/value seeds, and optional witness policy.
///
/// The solver always adds `problem.zero_fact()` with `problem.zero_value()`.
/// Duplicate explicit fact seeds, including an explicit zero fact, are met
/// before propagation.
#[derive(Debug, Clone, Copy)]
pub struct IdeSummarySolveInput<'input, Fact, Value> {
    root: &'input ProcedureHandle,
    seeds: &'input [IdeDataflowSeed<Fact, Value>],
    witness_retention: WitnessRetentionLimits,
}

impl<'input, Fact, Value> IdeSummarySolveInput<'input, Fact, Value> {
    pub const fn new(
        root: &'input ProcedureHandle,
        seeds: &'input [IdeDataflowSeed<Fact, Value>],
    ) -> Self {
        Self {
            root,
            seeds,
            witness_retention: WitnessRetentionLimits::disabled(),
        }
    }

    pub const fn root(&self) -> &'input ProcedureHandle {
        self.root
    }

    pub const fn seeds(&self) -> &'input [IdeDataflowSeed<Fact, Value>] {
        self.seeds
    }

    pub const fn with_witness_retention(
        mut self,
        witness_retention: WitnessRetentionLimits,
    ) -> Self {
        self.witness_retention = witness_retention;
        self
    }

    pub const fn witness_retention(&self) -> WitnessRetentionLimits {
        self.witness_retention
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TransferKey<Fact> {
    edge: ProcedureIcfgEdge,
    input: Fact,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TraceOutput<Fact, EdgeFunction> {
    fact: Fact,
    function: EdgeFunction,
}

struct CollectedTransitions<Fact, EdgeFunction> {
    outputs: Vec<TraceOutput<Fact, EdgeFunction>>,
    capture_meets: usize,
}

#[derive(Debug, Clone)]
struct TraceRecord<Fact, EdgeFunction> {
    key: TransferKey<Fact>,
    outputs: Vec<TraceOutput<Fact, EdgeFunction>>,
}

#[derive(Debug)]
struct IdeTrace<Fact, EdgeFunction> {
    records: Vec<TraceRecord<Fact, EdgeFunction>>,
    ids: HashMap<TransferKey<Fact>, usize>,
    retained_relations: usize,
    relation_limit: usize,
    capture_operation_limit: usize,
    attempted_work: Option<SolverWork>,
    capture_meets: usize,
}

impl<Fact, EdgeFunction> IdeTrace<Fact, EdgeFunction>
where
    Fact: Copy + Eq + Hash,
    EdgeFunction: Clone,
{
    fn new(relation_limit: usize, capture_operation_limit: usize) -> Self {
        Self {
            records: Vec::new(),
            ids: HashMap::default(),
            retained_relations: 0,
            relation_limit,
            capture_operation_limit,
            attempted_work: None,
            capture_meets: 0,
        }
    }

    fn get(&self, key: &TransferKey<Fact>) -> Option<&[TraceOutput<Fact, EdgeFunction>]> {
        let id = self.ids.get(key).copied()?;
        Some(&self.records[id].outputs)
    }

    fn remaining_relations(&self) -> usize {
        self.relation_limit.saturating_sub(self.retained_relations)
    }

    fn remaining_capture_operations(&self) -> usize {
        self.capture_operation_limit
            .saturating_sub(self.capture_meets)
    }

    fn mark_relation_exhausted(&mut self, staged_relations: usize, staged_meets: usize) {
        self.attempted_work = Some(SolverWork {
            ide_relations: self
                .retained_relations
                .saturating_add(staged_relations)
                .saturating_add(1),
            edge_function_operations: self.capture_meets.saturating_add(staged_meets),
            ..SolverWork::default()
        });
    }

    fn mark_capture_operations_exhausted(
        &mut self,
        staged_relations: usize,
        attempted_meets: usize,
    ) {
        self.attempted_work = Some(SolverWork {
            ide_relations: self.retained_relations.saturating_add(staged_relations),
            edge_function_operations: self.capture_meets.saturating_add(attempted_meets),
            ..SolverWork::default()
        });
    }

    fn insert(
        &mut self,
        key: TransferKey<Fact>,
        outputs: Vec<TraceOutput<Fact, EdgeFunction>>,
        capture_meets: usize,
    ) {
        debug_assert!(!self.ids.contains_key(&key));
        debug_assert!(self.retained_relations.saturating_add(outputs.len()) <= self.relation_limit);
        let id = self.records.len();
        self.retained_relations = self.retained_relations.saturating_add(outputs.len());
        self.capture_meets = self.capture_meets.saturating_add(capture_meets);
        self.records.push(TraceRecord {
            key: key.clone(),
            outputs,
        });
        self.ids.insert(key, id);
    }
}

struct IdeTransitionCollector<'output, Problem>
where
    Problem: IdeDataflowProblem,
{
    problem: &'output Problem,
    fact_output: &'output mut dyn DataflowOutput<Problem::Fact>,
    transitions: HashMap<Problem::Fact, Problem::EdgeFunction>,
    max_outputs: usize,
    max_meets: usize,
    capture_meets: usize,
    stopped: bool,
    relation_overflowed: bool,
    operation_overflowed: bool,
}

impl<'output, Problem> IdeTransitionCollector<'output, Problem>
where
    Problem: IdeDataflowProblem,
{
    fn new(
        problem: &'output Problem,
        fact_output: &'output mut dyn DataflowOutput<Problem::Fact>,
        max_outputs: usize,
        max_meets: usize,
    ) -> Self {
        Self {
            problem,
            fact_output,
            transitions: HashMap::default(),
            max_outputs,
            max_meets,
            capture_meets: 0,
            stopped: false,
            relation_overflowed: false,
            operation_overflowed: false,
        }
    }

    fn into_outputs(mut self) -> CollectedTransitions<Problem::Fact, Problem::EdgeFunction> {
        let mut outputs = self
            .transitions
            .drain()
            .map(|(fact, function)| TraceOutput { fact, function })
            .collect::<Vec<_>>();
        outputs.sort_unstable_by(|left, right| {
            left.fact
                .cmp(&right.fact)
                .then_with(|| left.function.cmp(&right.function))
        });
        CollectedTransitions {
            outputs,
            capture_meets: self.capture_meets,
        }
    }
}

impl<Problem> DataflowOutput<IdeTransition<Problem::Fact, Problem::EdgeFunction>>
    for IdeTransitionCollector<'_, Problem>
where
    Problem: IdeDataflowProblem,
{
    fn should_continue(&self) -> bool {
        !self.stopped
            && !self.relation_overflowed
            && !self.operation_overflowed
            && self.fact_output.should_continue()
    }

    fn emit(&mut self, transition: IdeTransition<Problem::Fact, Problem::EdgeFunction>) -> bool {
        if !self.should_continue() {
            self.stopped = true;
            return false;
        }
        let (fact, function) = transition.into_parts();
        if let Some(existing) = self.transitions.get(&fact) {
            if existing == &function {
                return true;
            }
            if self.capture_meets >= self.max_meets {
                self.operation_overflowed = true;
                return false;
            }
            let merged = if existing <= &function {
                self.problem.meet_edge_functions(existing, &function)
            } else {
                self.problem.meet_edge_functions(&function, existing)
            };
            self.capture_meets = self.capture_meets.saturating_add(1);
            self.transitions.insert(fact, merged);
            return true;
        }
        if self.transitions.len() >= self.max_outputs {
            self.relation_overflowed = true;
            return false;
        }
        if !self.fact_output.emit(fact) {
            self.stopped = true;
            return false;
        }
        self.transitions.insert(fact, function);
        true
    }
}

struct IdeFactAdapter<'problem, Problem>
where
    Problem: IdeDataflowProblem,
{
    problem: &'problem Problem,
    trace: RefCell<IdeTrace<Problem::Fact, Problem::EdgeFunction>>,
}

impl<'problem, Problem> IdeFactAdapter<'problem, Problem>
where
    Problem: IdeDataflowProblem,
{
    fn new(
        problem: &'problem Problem,
        relation_limit: usize,
        capture_operation_limit: usize,
    ) -> Self {
        Self {
            problem,
            trace: RefCell::new(IdeTrace::new(relation_limit, capture_operation_limit)),
        }
    }

    fn project(
        &self,
        edge: DataflowEdge<'_>,
        fact: Problem::Fact,
        out: &mut dyn DataflowOutput<Problem::Fact>,
        callback: impl FnOnce(
            &Problem,
            DataflowEdge<'_>,
            Problem::Fact,
            &mut dyn DataflowOutput<IdeTransition<Problem::Fact, Problem::EdgeFunction>>,
        ),
    ) {
        let key = TransferKey {
            edge: owned_edge(edge),
            input: fact,
        };
        if let Some(cached) = self.trace.borrow().get(&key).map(<[_]>::to_vec) {
            for output in cached {
                if !out.emit(output.fact) {
                    break;
                }
            }
            return;
        }

        let remaining = self.trace.borrow().remaining_relations();
        let remaining_operations = self.trace.borrow().remaining_capture_operations();
        let mut collector =
            IdeTransitionCollector::new(self.problem, out, remaining, remaining_operations);
        callback(self.problem, edge, fact, &mut collector);
        if fact == self.problem.zero_fact() && collector.should_continue() {
            let _ = collector.emit(IdeTransition::new(
                fact,
                self.problem.identity_edge_function(),
            ));
        }
        if collector.relation_overflowed {
            let staged = collector.transitions.len();
            self.trace
                .borrow_mut()
                .mark_relation_exhausted(staged, collector.capture_meets);
            return;
        }
        if collector.operation_overflowed {
            let staged = collector.transitions.len();
            self.trace.borrow_mut().mark_capture_operations_exhausted(
                staged,
                collector.capture_meets.saturating_add(1),
            );
            return;
        }
        if collector.stopped || !collector.fact_output.should_continue() {
            return;
        }
        let collected = collector.into_outputs();
        self.trace
            .borrow_mut()
            .insert(key, collected.outputs, collected.capture_meets);
    }

    fn into_trace(self) -> IdeTrace<Problem::Fact, Problem::EdgeFunction> {
        self.trace.into_inner()
    }
}

impl<Problem> DistributiveDataflowProblem for IdeFactAdapter<'_, Problem>
where
    Problem: IdeDataflowProblem,
{
    type Fact = Problem::Fact;

    fn zero_fact(&self) -> Self::Fact {
        self.problem.zero_fact()
    }

    fn normal_flow(
        &self,
        edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.project(edge, fact, out, Problem::normal_flow);
    }

    fn call_flow(
        &self,
        edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.project(edge, fact, out, Problem::call_flow);
    }

    fn return_flow(
        &self,
        edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.project(edge, fact, out, Problem::return_flow);
    }

    fn call_to_return_flow(
        &self,
        edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.project(edge, fact, out, Problem::call_to_return_flow);
    }

    fn exceptional_flow(
        &self,
        edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.project(edge, fact, out, Problem::exceptional_flow);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RawDirectRelation<EdgeFunction> {
    source: usize,
    target: usize,
    function: EdgeFunction,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RawSummaryRelation<EdgeFunction> {
    caller: usize,
    callee_exit: usize,
    target: usize,
    end_summary: usize,
    call_function: EdgeFunction,
    return_function: EdgeFunction,
}

struct RawIdeGraph<EdgeFunction> {
    row_count: usize,
    direct: Vec<RawDirectRelation<EdgeFunction>>,
    summaries: Vec<RawSummaryRelation<EdgeFunction>>,
    entry_rows: Vec<usize>,
    end_summary_exit_rows: Vec<usize>,
    reused_summary_functions: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct DirectRelation {
    target: usize,
    function: IdeEdgeFunctionId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct SummaryRelation {
    caller: usize,
    callee_exit: usize,
    target: usize,
    call_function: IdeEdgeFunctionId,
    return_function: IdeEdgeFunctionId,
}

struct IdeGraph {
    direct_by_source: Vec<Vec<DirectRelation>>,
    summaries: Vec<SummaryRelation>,
    summaries_by_dependency: Vec<Vec<usize>>,
    entry_rows: Vec<usize>,
    end_summary_exit_rows: Vec<usize>,
}

struct FunctionArena<EdgeFunction> {
    functions: Vec<EdgeFunction>,
    ids: HashMap<EdgeFunction, IdeEdgeFunctionId>,
    identity: IdeEdgeFunctionId,
    composition_cache: HashMap<(IdeEdgeFunctionId, IdeEdgeFunctionId), IdeEdgeFunctionId>,
    meet_cache: HashMap<(IdeEdgeFunctionId, IdeEdgeFunctionId), IdeEdgeFunctionId>,
}

impl<EdgeFunction> FunctionArena<EdgeFunction>
where
    EdgeFunction: Clone + Eq + Hash + Ord,
{
    fn new<Problem>(
        problem: &Problem,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Self, IdeRunFailure>
    where
        Problem: IdeDataflowProblem<EdgeFunction = EdgeFunction>,
    {
        reserve_ide_work(
            SolverWork {
                edge_functions: 1,
                ..SolverWork::default()
            },
            request,
        )?;
        let identity_function = problem.identity_edge_function();
        let identity = IdeEdgeFunctionId::try_from_index(0)
            .map_err(|_| IdeDataflowError::EdgeFunctionIdOverflow { index: 0 })?;
        let mut ids = HashMap::default();
        ids.insert(identity_function.clone(), identity);
        Ok(Self {
            functions: vec![identity_function],
            ids,
            identity,
            composition_cache: HashMap::default(),
            meet_cache: HashMap::default(),
        })
    }

    fn intern(
        &mut self,
        function: EdgeFunction,
        request: &mut DataflowRequest<'_>,
    ) -> Result<IdeEdgeFunctionId, IdeRunFailure> {
        if let Some(id) = self.ids.get(&function).copied() {
            return Ok(id);
        }
        let index = self.functions.len();
        let id = IdeEdgeFunctionId::try_from_index(index)
            .map_err(|_| IdeDataflowError::EdgeFunctionIdOverflow { index })?;
        reserve_ide_work(
            SolverWork {
                edge_functions: 1,
                ..SolverWork::default()
            },
            request,
        )?;
        self.functions.push(function.clone());
        self.ids.insert(function, id);
        Ok(id)
    }

    fn compose<Problem>(
        &mut self,
        first: IdeEdgeFunctionId,
        second: IdeEdgeFunctionId,
        problem: &Problem,
        request: &mut DataflowRequest<'_>,
        metrics: &mut IdeMetrics,
    ) -> Result<IdeEdgeFunctionId, IdeRunFailure>
    where
        Problem: IdeDataflowProblem<EdgeFunction = EdgeFunction>,
    {
        if first == self.identity {
            return Ok(second);
        }
        if second == self.identity {
            return Ok(first);
        }
        if let Some(result) = self.composition_cache.get(&(first, second)).copied() {
            metrics.composition_cache_hits = metrics.composition_cache_hits.saturating_add(1);
            return Ok(result);
        }
        reserve_ide_work(
            SolverWork {
                edge_function_operations: 1,
                ..SolverWork::default()
            },
            request,
        )?;
        let function = problem.compose_edge_functions(
            &self.functions[first.index()],
            &self.functions[second.index()],
        );
        if request.cancellation.is_cancelled() {
            return Err(IdeRunFailure::Terminated(SolverTermination::Cancelled));
        }
        let result = self.intern(function, request)?;
        self.composition_cache.insert((first, second), result);
        metrics.composition_cache_misses = metrics.composition_cache_misses.saturating_add(1);
        Ok(result)
    }

    fn meet<Problem>(
        &mut self,
        left: IdeEdgeFunctionId,
        right: IdeEdgeFunctionId,
        problem: &Problem,
        request: &mut DataflowRequest<'_>,
        metrics: &mut IdeMetrics,
    ) -> Result<IdeEdgeFunctionId, IdeRunFailure>
    where
        Problem: IdeDataflowProblem<EdgeFunction = EdgeFunction>,
    {
        if left == right {
            return Ok(left);
        }
        let (first, second) = if self.functions[left.index()] <= self.functions[right.index()] {
            (left, right)
        } else {
            (right, left)
        };
        if let Some(result) = self.meet_cache.get(&(first, second)).copied() {
            metrics.meet_cache_hits = metrics.meet_cache_hits.saturating_add(1);
            return Ok(result);
        }
        reserve_ide_work(
            SolverWork {
                edge_function_operations: 1,
                ..SolverWork::default()
            },
            request,
        )?;
        let function = problem.meet_edge_functions(
            &self.functions[first.index()],
            &self.functions[second.index()],
        );
        if request.cancellation.is_cancelled() {
            return Err(IdeRunFailure::Terminated(SolverTermination::Cancelled));
        }
        let result = self.intern(function, request)?;
        self.meet_cache.insert((first, second), result);
        metrics.meet_cache_misses = metrics.meet_cache_misses.saturating_add(1);
        Ok(result)
    }

    fn into_sorted_parts(
        self,
        reached: &mut [Option<IdeEdgeFunctionId>],
        summaries: &mut [Option<IdeEdgeFunctionId>],
    ) -> Result<Vec<EdgeFunction>, IdeDataflowError> {
        let mut sorted = self.functions.clone();
        sorted.sort_unstable();
        sorted.dedup();
        let ids = sorted
            .iter()
            .cloned()
            .enumerate()
            .map(|(index, function)| {
                IdeEdgeFunctionId::try_from_index(index)
                    .map(|id| (function, id))
                    .map_err(|_| IdeDataflowError::EdgeFunctionIdOverflow { index })
            })
            .collect::<Result<HashMap<_, _>, _>>()?;
        let remap = self
            .functions
            .iter()
            .map(|function| {
                ids.get(function)
                    .copied()
                    .ok_or(IdeDataflowError::Invariant(
                        "sorted edge-function table omitted an interned function",
                    ))
            })
            .collect::<Result<Vec<_>, _>>()?;
        for id in reached.iter_mut().chain(summaries.iter_mut()).flatten() {
            *id = remap[id.index()];
        }
        Ok(sorted)
    }
}

#[derive(Debug)]
enum IdeRunFailure {
    Terminated(SolverTermination),
    Fatal(IdeDataflowError),
}

impl From<IdeDataflowError> for IdeRunFailure {
    fn from(error: IdeDataflowError) -> Self {
        Self::Fatal(error)
    }
}

impl From<SummaryDataflowError> for IdeRunFailure {
    fn from(error: SummaryDataflowError) -> Self {
        Self::Fatal(error.into())
    }
}

struct CompleteIdePhase<Value, EdgeFunction> {
    functions: Vec<EdgeFunction>,
    values: Vec<Value>,
    reached_functions: Vec<Option<IdeEdgeFunctionId>>,
    summary_functions: Vec<Option<IdeEdgeFunctionId>>,
    point_values: Vec<IdePointValue>,
    metrics: IdeMetrics,
}

type IdeSolveOutcome<Problem> = Result<
    IdeSummaryDataflowResult<
        <Problem as IdeDataflowProblem>::Fact,
        <Problem as IdeDataflowProblem>::Value,
        <Problem as IdeDataflowProblem>::EdgeFunction,
    >,
    IdeDataflowError,
>;

struct CanonicalSeeds<Fact, Value> {
    facts: Vec<Fact>,
    values: HashMap<Fact, Value>,
    value_operations: usize,
    attempted_value_operations: Option<usize>,
}

/// Solve one finite IDE problem through the existing summary-driven fact
/// topology and a separate jump-function fixed point.
pub fn solve_ide_with_summaries<Problem, Provider>(
    input: IdeSummarySolveInput<'_, Problem::Fact, Problem::Value>,
    provider: &Provider,
    problem: &Problem,
    semantic_budget: &mut SemanticBudget,
    request: &mut DataflowRequest<'_>,
) -> IdeSolveOutcome<Problem>
where
    Problem: IdeDataflowProblem,
    Provider: crate::analyzer::semantic::IcfgProvider + ?Sized,
{
    let initial_work = request.budget.used();
    let initial_semantic_work = semantic_budget.used();
    let remaining = request.budget.remaining();
    let canonical_seeds = canonical_seed_values(&input, problem, remaining.value_operations);
    let adapter = IdeFactAdapter::new(
        problem,
        remaining.ide_relations,
        remaining.edge_function_operations,
    );
    let fact_result = solve_with_summaries(
        SummarySolveInput::new(input.root(), &canonical_seeds.facts)
            .with_witness_retention(input.witness_retention()),
        provider,
        &adapter,
        semantic_budget,
        request,
    )?;
    let trace = adapter.into_trace();

    if !fact_result.termination().is_fixed_point() {
        return Ok(empty_ide_result(
            fact_result,
            initial_work,
            initial_semantic_work,
            semantic_budget,
            request,
            None,
        ));
    }
    if trace.attempted_work.is_some() || canonical_seeds.attempted_value_operations.is_some() {
        let mut attempted = trace.attempted_work.unwrap_or(SolverWork {
            ide_relations: trace.retained_relations,
            edge_function_operations: trace.capture_meets,
            ..SolverWork::default()
        });
        attempted.value_operations = canonical_seeds
            .attempted_value_operations
            .unwrap_or(canonical_seeds.value_operations);
        let termination = request
            .reserve(attempted)
            .expect("an IDE capture beyond its remaining work limit must stop");
        return Ok(empty_ide_result(
            fact_result,
            initial_work,
            initial_semantic_work,
            semantic_budget,
            request,
            Some(termination),
        ));
    }
    if let Some(termination) = request.reserve(SolverWork {
        ide_relations: trace.retained_relations,
        edge_function_operations: trace.capture_meets,
        value_operations: canonical_seeds.value_operations,
        ..SolverWork::default()
    }) {
        return Ok(empty_ide_result(
            fact_result,
            initial_work,
            initial_semantic_work,
            semantic_budget,
            request,
            Some(termination),
        ));
    }

    let phase = match run_ide_phase(
        input.root(),
        &canonical_seeds.values,
        problem,
        &fact_result,
        &trace,
        request,
    ) {
        Ok(phase) => phase,
        Err(IdeRunFailure::Fatal(error)) => return Err(error),
        Err(IdeRunFailure::Terminated(termination)) => {
            return Ok(empty_ide_result(
                fact_result,
                initial_work,
                initial_semantic_work,
                semantic_budget,
                request,
                Some(termination),
            ));
        }
    };
    let work = request.budget.used().saturating_sub(initial_work);
    let semantic_work = semantic_budget.used().saturating_sub(initial_semantic_work);
    Ok(IdeSummaryDataflowResult::from_parts(
        fact_result,
        phase.functions,
        phase.values,
        phase.reached_functions,
        phase.summary_functions,
        phase.point_values,
        SolverTermination::FixedPoint,
        work,
        semantic_work,
        phase.metrics,
    ))
}

fn canonical_seed_values<Problem>(
    input: &IdeSummarySolveInput<'_, Problem::Fact, Problem::Value>,
    problem: &Problem,
    operation_limit: usize,
) -> CanonicalSeeds<Problem::Fact, Problem::Value>
where
    Problem: IdeDataflowProblem,
{
    let zero = problem.zero_fact();
    let mut rows = input.seeds().to_vec();
    rows.sort_unstable_by(|left, right| {
        left.fact()
            .cmp(right.fact())
            .then_with(|| left.value().cmp(right.value()))
    });
    let mut values = HashMap::default();
    values.insert(zero, problem.zero_value());
    let mut operations = 0usize;
    let mut attempted_operations = None;
    for seed in rows {
        let (fact, value) = seed.into_parts();
        if let Some(existing) = values.get(&fact) {
            if existing == &value {
                continue;
            }
            if operations >= operation_limit {
                attempted_operations = Some(operations.saturating_add(1));
                continue;
            }
            let merged = if existing <= &value {
                problem.meet_values(existing, &value)
            } else {
                problem.meet_values(&value, existing)
            };
            operations = operations.saturating_add(1);
            values.insert(fact, merged);
        } else {
            values.insert(fact, value);
        }
    }
    let mut facts = values.keys().copied().collect::<Vec<_>>();
    facts.sort_unstable();
    CanonicalSeeds {
        facts,
        values,
        value_operations: operations,
        attempted_value_operations: attempted_operations,
    }
}

fn run_ide_phase<Problem>(
    root: &ProcedureHandle,
    seed_values: &HashMap<Problem::Fact, Problem::Value>,
    problem: &Problem,
    fact_result: &SummaryDataflowResult<Problem::Fact>,
    trace: &IdeTrace<Problem::Fact, Problem::EdgeFunction>,
    request: &mut DataflowRequest<'_>,
) -> Result<CompleteIdePhase<Problem::Value, Problem::EdgeFunction>, IdeRunFailure>
where
    Problem: IdeDataflowProblem,
{
    let raw_graph = build_raw_graph(fact_result, trace, request)?;
    let relation_count = raw_graph
        .direct
        .len()
        .saturating_add(raw_graph.summaries.len());
    reserve_ide_work(
        SolverWork {
            ide_relations: relation_count,
            ..SolverWork::default()
        },
        request,
    )?;

    let mut metrics = IdeMetrics {
        captured_relations: trace.retained_relations,
        direct_relations: raw_graph.direct.len(),
        summary_relations: raw_graph.summaries.len(),
        reused_summary_functions: raw_graph.reused_summary_functions,
        ..IdeMetrics::default()
    };
    let (graph, mut functions) = intern_graph(raw_graph, problem, request)?;
    let mut jumps = vec![None; fact_result.reached().len()];
    let mut worklist = VecDeque::new();
    let mut queued = vec![false; jumps.len()];
    for entry in graph.entry_rows.iter().copied() {
        jumps[entry] = Some(functions.identity);
        enqueue(entry, &mut worklist, &mut queued);
        metrics.jump_updates = metrics.jump_updates.saturating_add(1);
    }

    while let Some(source) = worklist.pop_front() {
        queued[source] = false;
        if request.cancellation.is_cancelled() {
            return Err(IdeRunFailure::Terminated(SolverTermination::Cancelled));
        }
        let source_jump = jumps[source].ok_or(IdeDataflowError::Invariant(
            "queued IDE state has no jump function",
        ))?;
        for relation in graph.direct_by_source[source].iter().copied() {
            let candidate = functions.compose(
                source_jump,
                relation.function,
                problem,
                request,
                &mut metrics,
            )?;
            publish_jump(
                relation.target,
                candidate,
                &mut jumps,
                &mut functions,
                problem,
                request,
                &mut metrics,
                &mut worklist,
                &mut queued,
            )?;
        }
        for relation_id in graph.summaries_by_dependency[source].iter().copied() {
            let relation = graph.summaries[relation_id];
            let (Some(caller), Some(callee)) =
                (jumps[relation.caller], jumps[relation.callee_exit])
            else {
                continue;
            };
            metrics.summary_function_applications =
                metrics.summary_function_applications.saturating_add(1);
            let call = functions.compose(
                caller,
                relation.call_function,
                problem,
                request,
                &mut metrics,
            )?;
            let summary = functions.compose(call, callee, problem, request, &mut metrics)?;
            let candidate = functions.compose(
                summary,
                relation.return_function,
                problem,
                request,
                &mut metrics,
            )?;
            publish_jump(
                relation.target,
                candidate,
                &mut jumps,
                &mut functions,
                problem,
                request,
                &mut metrics,
                &mut worklist,
                &mut queued,
            )?;
        }
    }
    if jumps.iter().any(Option::is_none) {
        return Err(
            IdeDataflowError::Invariant("fixed-point fact row has no IDE jump function").into(),
        );
    }

    let mut summary_functions = graph
        .end_summary_exit_rows
        .iter()
        .map(|index| jumps[*index])
        .collect::<Vec<_>>();
    let (values, point_values) = materialize_root_values(
        root,
        seed_values,
        problem,
        fact_result,
        &jumps,
        &functions.functions,
        request,
    )?;
    let sorted_functions = functions.into_sorted_parts(&mut jumps, &mut summary_functions)?;
    Ok(CompleteIdePhase {
        functions: sorted_functions,
        values,
        reached_functions: jumps,
        summary_functions,
        point_values,
        metrics,
    })
}

#[allow(clippy::too_many_arguments)]
fn publish_jump<Problem>(
    target: usize,
    candidate: IdeEdgeFunctionId,
    jumps: &mut [Option<IdeEdgeFunctionId>],
    functions: &mut FunctionArena<Problem::EdgeFunction>,
    problem: &Problem,
    request: &mut DataflowRequest<'_>,
    metrics: &mut IdeMetrics,
    worklist: &mut VecDeque<usize>,
    queued: &mut [bool],
) -> Result<(), IdeRunFailure>
where
    Problem: IdeDataflowProblem,
{
    let next = match jumps[target] {
        Some(existing) => functions.meet(existing, candidate, problem, request, metrics)?,
        None => candidate,
    };
    if jumps[target] == Some(next) {
        return Ok(());
    }
    jumps[target] = Some(next);
    metrics.jump_updates = metrics.jump_updates.saturating_add(1);
    enqueue(target, worklist, queued);
    Ok(())
}

fn enqueue(row: usize, worklist: &mut VecDeque<usize>, queued: &mut [bool]) {
    if !queued[row] {
        queued[row] = true;
        worklist.push_back(row);
    }
}

fn intern_graph<Problem>(
    raw: RawIdeGraph<Problem::EdgeFunction>,
    problem: &Problem,
    request: &mut DataflowRequest<'_>,
) -> Result<(IdeGraph, FunctionArena<Problem::EdgeFunction>), IdeRunFailure>
where
    Problem: IdeDataflowProblem,
{
    let mut functions = FunctionArena::new(problem, request)?;
    let mut direct_by_source = vec![Vec::new(); raw.row_count];
    for relation in raw.direct {
        let function = functions.intern(relation.function, request)?;
        direct_by_source[relation.source].push(DirectRelation {
            target: relation.target,
            function,
        });
    }
    let mut summaries = Vec::with_capacity(raw.summaries.len());
    for relation in raw.summaries {
        summaries.push(SummaryRelation {
            caller: relation.caller,
            callee_exit: relation.callee_exit,
            target: relation.target,
            call_function: functions.intern(relation.call_function, request)?,
            return_function: functions.intern(relation.return_function, request)?,
        });
    }
    let row_count = direct_by_source.len();
    let mut summaries_by_dependency = vec![Vec::new(); row_count];
    for (id, relation) in summaries.iter().copied().enumerate() {
        summaries_by_dependency[relation.caller].push(id);
        if relation.callee_exit != relation.caller {
            summaries_by_dependency[relation.callee_exit].push(id);
        }
    }
    Ok((
        IdeGraph {
            direct_by_source,
            summaries,
            summaries_by_dependency,
            entry_rows: raw.entry_rows,
            end_summary_exit_rows: raw.end_summary_exit_rows,
        },
        functions,
    ))
}

fn build_raw_graph<Fact, EdgeFunction>(
    result: &SummaryDataflowResult<Fact>,
    trace: &IdeTrace<Fact, EdgeFunction>,
    request: &DataflowRequest<'_>,
) -> Result<RawIdeGraph<EdgeFunction>, IdeRunFailure>
where
    Fact: Copy + Eq + Hash + Ord,
    EdgeFunction: Clone + Eq + Hash + Ord,
{
    let mut fact_ids = HashMap::default();
    for (index, fact) in result.facts().iter().copied().enumerate() {
        let id = FactId::try_from_index(index)
            .map_err(|_| SummaryDataflowError::FactIdOverflow { index })?;
        fact_ids.insert(fact, id);
    }
    let mut by_point_fact = HashMap::<_, Vec<usize>>::default();
    let mut by_state = HashMap::default();
    let mut entry_rows = Vec::new();
    for (index, reached) in result.reached().iter().enumerate() {
        let fact = result
            .fact(reached.fact())
            .copied()
            .ok_or(IdeDataflowError::Invariant(
                "reached IDE fact ID is absent from its result",
            ))?;
        by_point_fact
            .entry((reached.point().clone(), fact))
            .or_default()
            .push(index);
        by_state.insert(
            (reached.entry().clone(), reached.point().clone(), fact),
            index,
        );
        if reached.point() == reached.entry().entry_point()
            && reached.fact() == reached.entry().entry_fact()
        {
            entry_rows.push(index);
        }
    }
    let mut summaries_by_entry = HashMap::<SummaryEntry, Vec<usize>>::default();
    let mut end_summary_exit_rows = Vec::with_capacity(result.end_summaries().len());
    for (index, summary) in result.end_summaries().iter().enumerate() {
        summaries_by_entry
            .entry(summary.entry().clone())
            .or_default()
            .push(index);
        let fact = result
            .fact(summary.exit_fact())
            .copied()
            .ok_or(IdeDataflowError::Invariant(
                "end-summary IDE fact ID is absent from its result",
            ))?;
        let row = by_state
            .get(&(summary.entry().clone(), summary.exit_point().clone(), fact))
            .copied()
            .ok_or(IdeDataflowError::Invariant(
                "end summary has no reached exit row",
            ))?;
        end_summary_exit_rows.push(row);
    }

    let mut direct = HashSet::default();
    let mut summaries = HashSet::default();
    let mut summary_uses = HashMap::<usize, usize>::default();
    for record in &trace.records {
        if request.cancellation.is_cancelled() {
            return Err(IdeRunFailure::Terminated(SolverTermination::Cancelled));
        }
        let sources = by_point_fact
            .get(&(record.key.edge.source.clone(), record.key.input))
            .cloned()
            .unwrap_or_default();
        match record.key.edge.kind {
            IcfgEdgeKind::Call => {
                let transfer = call_transfer_for_edge(&record.key.edge)?;
                for source in sources {
                    let caller_entry = result.reached()[source].entry().clone();
                    for output in &record.outputs {
                        let output_id = fact_ids.get(&output.fact).copied().ok_or(
                            IdeDataflowError::Invariant(
                                "captured call output fact was not interned",
                            ),
                        )?;
                        let callee_entry = SummaryEntry::new(
                            transfer.callee.clone(),
                            transfer.callee_entry.clone(),
                            output_id,
                        );
                        for end_summary in summaries_by_entry
                            .get(&callee_entry)
                            .into_iter()
                            .flatten()
                            .copied()
                        {
                            let summary = &result.end_summaries()[end_summary];
                            let exit_fact = result.fact(summary.exit_fact()).copied().ok_or(
                                IdeDataflowError::Invariant(
                                    "captured summary exit fact was not interned",
                                ),
                            )?;
                            let projection = summary
                                .exit()
                                .project_matched_return(&transfer)
                                .map_err(SummaryDataflowError::from)?;
                            let MatchedReturnProjection::Edge(return_edge) = projection else {
                                continue;
                            };
                            let return_key = TransferKey {
                                edge: return_edge,
                                input: exit_fact,
                            };
                            let Some(return_outputs) = trace.get(&return_key) else {
                                continue;
                            };
                            for returned in return_outputs {
                                let Some(target) = by_state
                                    .get(&(
                                        caller_entry.clone(),
                                        return_key.edge.target.clone(),
                                        returned.fact,
                                    ))
                                    .copied()
                                else {
                                    continue;
                                };
                                let relation = RawSummaryRelation {
                                    caller: source,
                                    callee_exit: end_summary_exit_rows[end_summary],
                                    target,
                                    end_summary,
                                    call_function: output.function.clone(),
                                    return_function: returned.function.clone(),
                                };
                                if !summaries.contains(&relation) {
                                    ensure_relation_capacity(
                                        direct.len().saturating_add(summaries.len()),
                                        request,
                                    )?;
                                    summaries.insert(relation);
                                    *summary_uses.entry(end_summary).or_default() += 1;
                                }
                            }
                        }
                    }
                }
            }
            IcfgEdgeKind::NormalReturn | IcfgEdgeKind::ExceptionalReturn => {}
            _ => {
                for source in sources {
                    let entry = result.reached()[source].entry().clone();
                    for output in &record.outputs {
                        let Some(target) = by_state
                            .get(&(entry.clone(), record.key.edge.target.clone(), output.fact))
                            .copied()
                        else {
                            continue;
                        };
                        let relation = RawDirectRelation {
                            source,
                            target,
                            function: output.function.clone(),
                        };
                        if !direct.contains(&relation) {
                            ensure_relation_capacity(
                                direct.len().saturating_add(summaries.len()),
                                request,
                            )?;
                            direct.insert(relation);
                        }
                    }
                }
            }
        }
    }
    let mut direct = direct.into_iter().collect::<Vec<_>>();
    direct.sort_unstable_by(|left, right| {
        (left.source, left.target)
            .cmp(&(right.source, right.target))
            .then_with(|| left.function.cmp(&right.function))
    });
    let mut summaries = summaries.into_iter().collect::<Vec<_>>();
    summaries.sort_unstable_by(|left, right| {
        (left.caller, left.callee_exit, left.target, left.end_summary)
            .cmp(&(
                right.caller,
                right.callee_exit,
                right.target,
                right.end_summary,
            ))
            .then_with(|| left.call_function.cmp(&right.call_function))
            .then_with(|| left.return_function.cmp(&right.return_function))
    });
    let reused_summary_functions = summary_uses
        .values()
        .map(|uses| uses.saturating_sub(1))
        .sum();
    Ok(RawIdeGraph {
        row_count: result.reached().len(),
        direct,
        summaries,
        entry_rows,
        end_summary_exit_rows,
        reused_summary_functions,
    })
}

fn ensure_relation_capacity(
    retained: usize,
    request: &DataflowRequest<'_>,
) -> Result<(), IdeRunFailure> {
    request
        .budget
        .check(SolverWork {
            ide_relations: retained.saturating_add(1),
            ..SolverWork::default()
        })
        .map_err(|exceeded| IdeRunFailure::Terminated(SolverTermination::ExceededBudget(exceeded)))
}

fn call_transfer_for_edge(edge: &ProcedureIcfgEdge) -> Result<CallTransfer, IdeDataflowError> {
    let origin = edge.origin.clone().ok_or(IdeDataflowError::Invariant(
        "captured call edge has no origin",
    ))?;
    let call = origin
        .procedure()
        .semantics()
        .call_site(origin.id())
        .ok_or(IdeDataflowError::Invariant(
            "captured call edge origin is stale",
        ))?;
    let normal_continuation = call.normal_continuation;
    let exceptional_continuation = call.exceptional_continuation;
    Ok(CallTransfer {
        origin,
        callee: edge.target.procedure().clone(),
        callee_entry: edge.target.clone(),
        normal_continuation,
        exceptional_continuation,
        proof: edge.proof.clone(),
        completeness: edge.completeness.clone(),
    })
}

#[derive(Debug)]
struct PendingPointValue<Value> {
    point: crate::analyzer::semantic::ProgramPointHandle,
    fact: FactId,
    value: Value,
    qualities: PathQualityFrontier,
}

fn materialize_root_values<Problem>(
    root: &ProcedureHandle,
    seed_values: &HashMap<Problem::Fact, Problem::Value>,
    problem: &Problem,
    result: &SummaryDataflowResult<Problem::Fact>,
    jumps: &[Option<IdeEdgeFunctionId>],
    functions: &[Problem::EdgeFunction],
    request: &mut DataflowRequest<'_>,
) -> Result<(Vec<Problem::Value>, Vec<IdePointValue>), IdeRunFailure>
where
    Problem: IdeDataflowProblem,
{
    let root_entry =
        root.point_handle(root.semantics().entry_point())
            .ok_or(IdeDataflowError::Invariant(
                "IDE root procedure has no entry point",
            ))?;
    let mut pending = Vec::<PendingPointValue<Problem::Value>>::new();
    let mut pending_ids = HashMap::default();
    for (index, reached) in result.reached().iter().enumerate() {
        if reached.entry().procedure() != root || reached.entry().entry_point() != &root_entry {
            continue;
        }
        let entry_fact = result.fact(reached.entry().entry_fact()).copied().ok_or(
            IdeDataflowError::Invariant("root IDE entry fact is absent from its result"),
        )?;
        let seed = seed_values
            .get(&entry_fact)
            .ok_or(IdeDataflowError::MissingRootSeedValue {
                fact: reached.entry().entry_fact(),
            })?;
        let function = jumps[index].ok_or(IdeDataflowError::Invariant(
            "root IDE row has no jump function",
        ))?;
        reserve_ide_work(
            SolverWork {
                value_operations: 1,
                ..SolverWork::default()
            },
            request,
        )?;
        let value = problem.apply_edge_function(&functions[function.index()], seed);
        if request.cancellation.is_cancelled() {
            return Err(IdeRunFailure::Terminated(SolverTermination::Cancelled));
        }
        let key = (reached.point().clone(), reached.fact());
        if let Some(existing_id) = pending_ids.get(&key).copied() {
            let existing: &mut PendingPointValue<Problem::Value> = &mut pending[existing_id];
            if existing.value != value {
                reserve_ide_work(
                    SolverWork {
                        value_operations: 1,
                        ..SolverWork::default()
                    },
                    request,
                )?;
                existing.value = if existing.value <= value {
                    problem.meet_values(&existing.value, &value)
                } else {
                    problem.meet_values(&value, &existing.value)
                };
                if request.cancellation.is_cancelled() {
                    return Err(IdeRunFailure::Terminated(SolverTermination::Cancelled));
                }
            }
            for quality in reached.path_qualities().iter() {
                existing.qualities.insert(quality);
            }
        } else {
            let id = pending.len();
            pending.push(PendingPointValue {
                point: reached.point().clone(),
                fact: reached.fact(),
                value,
                qualities: reached.path_qualities(),
            });
            pending_ids.insert(key, id);
        }
    }

    let mut values = pending
        .iter()
        .map(|row| row.value.clone())
        .collect::<Vec<_>>();
    values.sort_unstable();
    values.dedup();
    for index in 0..values.len() {
        IdeValueId::try_from_index(index)
            .map_err(|_| IdeDataflowError::ValueIdOverflow { index })?;
    }
    reserve_ide_work(
        SolverWork {
            ide_values: values.len(),
            ..SolverWork::default()
        },
        request,
    )?;
    let value_ids = values
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, value)| {
            let id = IdeValueId::try_from_index(index)
                .expect("IDE value indices were validated before publication");
            (value, id)
        })
        .collect::<HashMap<_, _>>();
    let point_values = pending
        .into_iter()
        .map(|row| {
            let value = value_ids[&row.value];
            IdePointValue::new(row.point, row.fact, value, row.qualities)
        })
        .collect();
    Ok((values, point_values))
}

fn empty_ide_result<Fact, Value, EdgeFunction>(
    fact_result: SummaryDataflowResult<Fact>,
    initial_work: SolverWork,
    initial_semantic_work: SemanticWork,
    semantic_budget: &SemanticBudget,
    request: &DataflowRequest<'_>,
    termination: Option<SolverTermination>,
) -> IdeSummaryDataflowResult<Fact, Value, EdgeFunction> {
    let reached_len = fact_result.reached().len();
    let summary_len = fact_result.end_summaries().len();
    let termination = termination.unwrap_or_else(|| fact_result.termination());
    IdeSummaryDataflowResult::from_parts(
        fact_result,
        Vec::new(),
        Vec::new(),
        vec![None; reached_len],
        vec![None; summary_len],
        Vec::new(),
        termination,
        request.budget.used().saturating_sub(initial_work),
        semantic_budget.used().saturating_sub(initial_semantic_work),
        IdeMetrics::default(),
    )
}

fn reserve_ide_work(
    work: SolverWork,
    request: &mut DataflowRequest<'_>,
) -> Result<(), IdeRunFailure> {
    match request.reserve(work) {
        Some(termination) => Err(IdeRunFailure::Terminated(termination)),
        None => Ok(()),
    }
}

fn owned_edge(edge: DataflowEdge<'_>) -> ProcedureIcfgEdge {
    ProcedureIcfgEdge {
        source: edge.source().clone(),
        target: edge.target().clone(),
        kind: edge.kind(),
        origin: edge.origin().cloned(),
        proof: edge.proof().clone(),
        completeness: edge.completeness().clone(),
        boundary: edge.boundary().cloned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transition_and_seed_preserve_owned_components() {
        let transition = IdeTransition::new(7_u8, [1_u8, 2]);
        assert_eq!(transition.fact(), &7);
        assert_eq!(transition.edge_function(), &[1, 2]);
        assert_eq!(transition.into_parts(), (7, [1, 2]));

        let seed = IdeDataflowSeed::new(3_u8, "qualified".to_owned());
        assert_eq!(seed.fact(), &3);
        assert_eq!(seed.value(), "qualified");
        assert_eq!(seed.into_parts(), (3, "qualified".to_owned()));
    }
}
