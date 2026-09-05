//! Client contracts for bounded IDE edge-function propagation.

use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet, VecDeque},
    hash::Hash,
};

use crate::analyzer::semantic::{
    CallSiteHandle, CallTransfer, IcfgEdgeKind, MatchedReturnProjection, ProcedureHandle,
    ProcedureIcfgEdge, SemanticBudget, SemanticWork,
};
use crate::hash::{HashMap, HashSet};

use super::{
    DataflowEdge, DataflowOutput, DataflowRequest, DistributiveDataflowProblem, FactId,
    IdeDataflowError, IdeEdgeFunctionId, IdeEntryTransfer, IdeMetrics, IdePointValue,
    IdeSummaryDataflowResult, IdeValueId, PathQuality, PathQualityFrontier, ReusableEndSummary,
    ReusableProcedureSummary, ReusableReachedFact, ReusableSummaryProvider, SolverTermination,
    SolverWork, SummaryCallCycle, SummaryCalledProcedures, SummaryDataflowError,
    SummaryDataflowResult, SummaryEntry, SummarySolveInput, WitnessRetentionLimits,
    solve_with_reusable_end_summaries,
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

/// One reusable entry-to-exit fact relation and its relative IDE jump function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReusableIdeEndSummary<Fact, EdgeFunction> {
    pub exit_kind: crate::analyzer::semantic::ReturnTransferKind,
    pub exit_fact: Fact,
    pub qualities: Box<[PathQuality]>,
    pub edge_function: EdgeFunction,
}

/// One reusable internal observation and its relative IDE jump function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReusableIdeReachedFact<Fact, EdgeFunction> {
    pub point: crate::analyzer::semantic::ProgramPointHandle,
    pub fact: Fact,
    pub qualities: Box<[PathQuality]>,
    pub edge_function: EdgeFunction,
}

/// Complete reusable IDE relation for one exact procedure entry fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReusableIdeProcedureSummary<Fact, EdgeFunction> {
    pub exits: Box<[ReusableIdeEndSummary<Fact, EdgeFunction>]>,
    pub reached: Box<[ReusableIdeReachedFact<Fact, EdgeFunction>]>,
    /// How the summarized procedure's call cycle relates to the solve root.
    /// See [`SummaryCallCycle`]: the fact solver refuses a summary that shares
    /// a call cycle with the root, so the callee body is solved instead
    /// (#2285).
    pub call_cycle: SummaryCallCycle,
    /// Whether the summary's validity contract covers every analyzed procedure
    /// the summarized body calls. See [`SummaryCalledProcedures`]: the fact
    /// solver refuses a summary that cannot state this, so the callee body is
    /// solved instead and the run's completeness verdict stays the fresh one
    /// (#2296).
    pub called_procedures: SummaryCalledProcedures,
}

/// Optional context-independent cross-query IDE summary oracle.
///
/// The relation and every edge function must be relative to the exact
/// procedure and entry fact supplied here. As with the fact-only provider,
/// query-local tabulation deduplicates that identity and cannot accept a
/// call-site-sensitive answer.
///
/// `root` is the procedure this solve is rooted at. A provider must report
/// [`SummaryCallCycle::IncludesRoot`] whenever the summarized procedure and
/// `root` sit in one call cycle, and whenever it cannot tell (#2285), and
/// [`SummaryCalledProcedures::MayEscapeContract`] whenever the summary's
/// validity contract does not cover what the summarized body calls, and
/// whenever it cannot tell (#2296).
pub trait ReusableIdeSummaryProvider<Fact, EdgeFunction> {
    fn summary_for(
        &mut self,
        procedure: &ProcedureHandle,
        root: &ProcedureHandle,
        entry_fact: Fact,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Option<ReusableIdeProcedureSummary<Fact, EdgeFunction>>, SolverTermination>;
}

struct NoReusableIdeSummaries;

impl<Fact, EdgeFunction> ReusableIdeSummaryProvider<Fact, EdgeFunction> for NoReusableIdeSummaries {
    fn summary_for(
        &mut self,
        _procedure: &ProcedureHandle,
        _root: &ProcedureHandle,
        _entry_fact: Fact,
        _request: &mut DataflowRequest<'_>,
    ) -> Result<Option<ReusableIdeProcedureSummary<Fact, EdgeFunction>>, SolverTermination> {
        Ok(None)
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

    /// See [`super::DistributiveDataflowProblem::resolved_call_to_return`].
    fn resolved_call_to_return(&self) -> bool {
        false
    }

    /// See [`super::DistributiveDataflowProblem::call_replaced_by_model`].
    fn call_replaced_by_model(&self, _call: &CallSiteHandle) -> bool {
        false
    }

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

    /// Whether `fact` records a monitored observation on the current path.
    /// See [`DistributiveDataflowProblem::is_flow_observation`].
    fn is_flow_observation(&self, _fact: &Self::Fact) -> bool {
        false
    }

    fn normal_flow(
        &self,
        edge: DataflowEdge<'_, Self::Fact>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<IdeTransition<Self::Fact, Self::EdgeFunction>>,
    );

    fn call_flow(
        &self,
        edge: DataflowEdge<'_, Self::Fact>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<IdeTransition<Self::Fact, Self::EdgeFunction>>,
    );

    fn return_flow(
        &self,
        edge: DataflowEdge<'_, Self::Fact>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<IdeTransition<Self::Fact, Self::EdgeFunction>>,
    );

    fn call_to_return_flow(
        &self,
        edge: DataflowEdge<'_, Self::Fact>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<IdeTransition<Self::Fact, Self::EdgeFunction>>,
    );

    fn exceptional_flow(
        &self,
        edge: DataflowEdge<'_, Self::Fact>,
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
    call_transfer: Option<CallTransfer>,
    entry: Fact,
    input: Fact,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TraceOutput<Fact, EdgeFunction> {
    fact: Fact,
    function: EdgeFunction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct InternedTraceOutput<Fact> {
    fact: Fact,
    function: usize,
}

struct CollectedTransitions<Fact, EdgeFunction> {
    outputs: Vec<TraceOutput<Fact, EdgeFunction>>,
    capture_meets: usize,
}

#[derive(Debug, Clone)]
struct TraceRecord<Fact> {
    key: TransferKey<Fact>,
    outputs: Vec<InternedTraceOutput<Fact>>,
}

#[derive(Debug)]
struct IdeTrace<Fact, EdgeFunction> {
    records: Vec<TraceRecord<Fact>>,
    ids: HashMap<TransferKey<Fact>, usize>,
    functions: Vec<EdgeFunction>,
    function_ids: HashMap<EdgeFunction, usize>,
    retained_relations: usize,
    relation_limit: usize,
    capture_operation_limit: usize,
    function_limit: usize,
    attempted_work: Option<SolverWork>,
    capture_meets: usize,
}

impl<Fact, EdgeFunction> IdeTrace<Fact, EdgeFunction>
where
    Fact: Copy + Eq + Hash,
    EdgeFunction: Clone + Eq + Hash,
{
    fn new(relation_limit: usize, capture_operation_limit: usize, function_limit: usize) -> Self {
        Self {
            records: Vec::new(),
            ids: HashMap::default(),
            functions: Vec::new(),
            function_ids: HashMap::default(),
            retained_relations: 0,
            relation_limit,
            capture_operation_limit,
            function_limit,
            attempted_work: None,
            capture_meets: 0,
        }
    }

    fn get(&self, key: &TransferKey<Fact>) -> Option<&[InternedTraceOutput<Fact>]> {
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

    fn mark_functions_exhausted(
        &mut self,
        staged_relations: usize,
        staged_meets: usize,
        attempted_functions: usize,
    ) {
        self.attempted_work = Some(SolverWork {
            ide_relations: self.retained_relations.saturating_add(staged_relations),
            edge_function_operations: self.capture_meets.saturating_add(staged_meets),
            edge_functions: attempted_functions,
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
        debug_assert!(outputs.iter().all(|output| {
            self.function_ids.contains_key(&output.function)
                || self.functions.len() < self.function_limit
        }));
        let outputs: Vec<InternedTraceOutput<Fact>> = outputs
            .into_iter()
            .map(|output| {
                let function = if let Some(id) = self.function_ids.get(&output.function).copied() {
                    id
                } else {
                    let id = self.functions.len();
                    self.functions.push(output.function.clone());
                    self.function_ids.insert(output.function, id);
                    id
                };
                InternedTraceOutput {
                    fact: output.fact,
                    function,
                }
            })
            .collect();
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

struct IdeTransitionCollector<'output, 'trace, Problem>
where
    Problem: IdeDataflowProblem,
{
    problem: &'output Problem,
    fact_output: &'output mut dyn DataflowOutput<Problem::Fact>,
    transitions: HashMap<Problem::Fact, Problem::EdgeFunction>,
    known_functions: &'trace HashMap<Problem::EdgeFunction, usize>,
    staged_functions: HashSet<Problem::EdgeFunction>,
    max_new_functions: usize,
    max_outputs: usize,
    max_meets: usize,
    capture_meets: usize,
    stopped: bool,
    relation_overflowed: bool,
    operation_overflowed: bool,
    function_overflowed: bool,
}

impl<'output, 'trace, Problem> IdeTransitionCollector<'output, 'trace, Problem>
where
    Problem: IdeDataflowProblem,
{
    fn new(
        problem: &'output Problem,
        fact_output: &'output mut dyn DataflowOutput<Problem::Fact>,
        known_functions: &'trace HashMap<Problem::EdgeFunction, usize>,
        max_outputs: usize,
        max_meets: usize,
        max_new_functions: usize,
    ) -> Self {
        Self {
            problem,
            fact_output,
            transitions: HashMap::default(),
            known_functions,
            staged_functions: HashSet::default(),
            max_new_functions,
            max_outputs,
            max_meets,
            capture_meets: 0,
            stopped: false,
            relation_overflowed: false,
            operation_overflowed: false,
            function_overflowed: false,
        }
    }

    fn retain_function(&mut self, function: &Problem::EdgeFunction) -> bool {
        if self.known_functions.contains_key(function) || self.staged_functions.contains(function) {
            return true;
        }
        if self.staged_functions.len() >= self.max_new_functions {
            self.function_overflowed = true;
            return false;
        }
        self.staged_functions.insert(function.clone());
        true
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
    for IdeTransitionCollector<'_, '_, Problem>
where
    Problem: IdeDataflowProblem,
{
    fn should_continue(&self) -> bool {
        !self.stopped && self.fact_output.should_continue()
    }

    fn emit(&mut self, transition: IdeTransition<Problem::Fact, Problem::EdgeFunction>) -> bool {
        if !self.should_continue() {
            self.stopped = true;
            return false;
        }
        let (fact, function) = transition.into_parts();
        if self.relation_overflowed || self.operation_overflowed || self.function_overflowed {
            return self.fact_output.emit(fact);
        }
        if !self.retain_function(&function) {
            return self.fact_output.emit(fact);
        }
        if let Some(existing) = self.transitions.get(&fact) {
            if existing == &function {
                return true;
            }
            if self.capture_meets >= self.max_meets {
                self.operation_overflowed = true;
                return self.fact_output.should_continue();
            }
            let merged = if existing <= &function {
                self.problem.meet_edge_functions(existing, &function)
            } else {
                self.problem.meet_edge_functions(&function, existing)
            };
            self.capture_meets = self.capture_meets.saturating_add(1);
            if !self.retain_function(&merged) {
                return self.fact_output.should_continue();
            }
            self.transitions.insert(fact, merged);
            return true;
        }
        if self.transitions.len() >= self.max_outputs {
            self.relation_overflowed = true;
            return self.fact_output.emit(fact);
        }
        if !self.fact_output.emit(fact) {
            self.stopped = true;
            return false;
        }
        self.transitions.insert(fact, function);
        true
    }
}

struct IdeFactOnlyCollector<'output, Fact> {
    fact_output: &'output mut dyn DataflowOutput<Fact>,
}

impl<Fact, EdgeFunction> DataflowOutput<IdeTransition<Fact, EdgeFunction>>
    for IdeFactOnlyCollector<'_, Fact>
{
    fn should_continue(&self) -> bool {
        self.fact_output.should_continue()
    }

    fn emit(&mut self, transition: IdeTransition<Fact, EdgeFunction>) -> bool {
        let (fact, _) = transition.into_parts();
        self.fact_output.emit(fact)
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
        function_limit: usize,
    ) -> Self {
        Self {
            problem,
            trace: RefCell::new(IdeTrace::new(
                relation_limit,
                capture_operation_limit,
                function_limit,
            )),
        }
    }

    fn project(
        &self,
        edge: DataflowEdge<'_, Problem::Fact>,
        fact: Problem::Fact,
        out: &mut dyn DataflowOutput<Problem::Fact>,
        callback: impl FnOnce(
            &Problem,
            DataflowEdge<'_, Problem::Fact>,
            Problem::Fact,
            &mut dyn DataflowOutput<IdeTransition<Problem::Fact, Problem::EdgeFunction>>,
        ),
    ) {
        let key = TransferKey {
            edge: owned_edge(edge),
            call_transfer: edge.call_transfer().cloned(),
            entry: edge
                .summary_entry_fact()
                .copied()
                .expect("summary-backed IDE edges retain their exact entry fact"),
            input: fact,
        };
        let trace = self.trace.borrow();
        if let Some(cached) = trace.get(&key) {
            for output in cached {
                if !out.emit(output.fact) {
                    break;
                }
            }
            return;
        }
        if trace.attempted_work.is_some() {
            drop(trace);
            let mut collector = IdeFactOnlyCollector { fact_output: out };
            callback(self.problem, edge, fact, &mut collector);
            if fact == self.problem.zero_fact() && collector.fact_output.should_continue() {
                let _ = collector.fact_output.emit(fact);
            }
            return;
        }

        let remaining = trace.remaining_relations();
        let remaining_operations = trace.remaining_capture_operations();
        let max_new_functions = trace.function_limit.saturating_sub(trace.functions.len());
        let mut collector = IdeTransitionCollector::new(
            self.problem,
            out,
            &trace.function_ids,
            remaining,
            remaining_operations,
            max_new_functions,
        );
        callback(self.problem, edge, fact, &mut collector);
        if fact == self.problem.zero_fact() && collector.should_continue() {
            let _ = collector.emit(IdeTransition::new(
                fact,
                self.problem.identity_edge_function(),
            ));
        }
        if collector.relation_overflowed {
            let staged = collector.transitions.len();
            let staged_meets = collector.capture_meets;
            drop(collector);
            drop(trace);
            self.trace
                .borrow_mut()
                .mark_relation_exhausted(staged, staged_meets);
            return;
        }
        if collector.operation_overflowed {
            let staged = collector.transitions.len();
            let attempted_meets = collector.capture_meets.saturating_add(1);
            drop(collector);
            drop(trace);
            self.trace
                .borrow_mut()
                .mark_capture_operations_exhausted(staged, attempted_meets);
            return;
        }
        if collector.function_overflowed {
            let staged = collector.transitions.len();
            let attempted_functions = trace
                .functions
                .len()
                .saturating_add(collector.staged_functions.len())
                .saturating_add(1);
            let staged_meets = collector.capture_meets;
            drop(collector);
            drop(trace);
            self.trace.borrow_mut().mark_functions_exhausted(
                staged,
                staged_meets,
                attempted_functions,
            );
            return;
        }
        if collector.stopped || !collector.fact_output.should_continue() {
            return;
        }
        let collected = collector.into_outputs();
        drop(trace);
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

    fn resolved_call_to_return(&self) -> bool {
        self.problem.resolved_call_to_return()
    }

    fn call_replaced_by_model(&self, call: &CallSiteHandle) -> bool {
        self.problem.call_replaced_by_model(call)
    }

    fn is_flow_observation(&self, fact: &Self::Fact) -> bool {
        self.problem.is_flow_observation(fact)
    }

    fn normal_flow(
        &self,
        edge: DataflowEdge<'_, Self::Fact>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.project(edge, fact, out, Problem::normal_flow);
    }

    fn call_flow(
        &self,
        edge: DataflowEdge<'_, Self::Fact>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.project(edge, fact, out, Problem::call_flow);
    }

    fn return_flow(
        &self,
        edge: DataflowEdge<'_, Self::Fact>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.project(edge, fact, out, Problem::return_flow);
    }

    fn call_to_return_flow(
        &self,
        edge: DataflowEdge<'_, Self::Fact>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.project(edge, fact, out, Problem::call_to_return_flow);
    }

    fn exceptional_flow(
        &self,
        edge: DataflowEdge<'_, Self::Fact>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.project(edge, fact, out, Problem::exceptional_flow);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RawDirectRelation {
    source: usize,
    target: usize,
    function: IdeEdgeFunctionId,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RawSummaryRelation {
    caller: usize,
    callee_exit: usize,
    target: usize,
    end_summary: usize,
    call_function: IdeEdgeFunctionId,
    return_function: IdeEdgeFunctionId,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RawEntryValueRelation {
    caller: usize,
    target_entry: usize,
    function: IdeEdgeFunctionId,
    edge_quality: PathQuality,
}

struct RawIdeGraph {
    row_count: usize,
    direct: Vec<RawDirectRelation>,
    summaries: Vec<RawSummaryRelation>,
    entry_values: Vec<RawEntryValueRelation>,
    entry_rows: Vec<usize>,
    row_entries: Vec<usize>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct EntryValueRelation {
    caller: usize,
    target_entry: usize,
    function: IdeEdgeFunctionId,
    edge_quality: PathQuality,
}

struct IdeGraph {
    direct_by_source: Vec<Vec<DirectRelation>>,
    summaries: Vec<SummaryRelation>,
    summaries_by_dependency: Vec<Vec<usize>>,
    entry_values_by_entry: Vec<Vec<EntryValueRelation>>,
    entry_rows: Vec<usize>,
    row_entries: Vec<usize>,
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

    fn intern_ref(
        &mut self,
        function: &EdgeFunction,
        request: &mut DataflowRequest<'_>,
    ) -> Result<IdeEdgeFunctionId, IdeRunFailure> {
        if let Some(id) = self.ids.get(function).copied() {
            return Ok(id);
        }
        self.intern(function.clone(), request)
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
        entry_transfers: &mut [IdeEntryTransfer],
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
        for transfer in entry_transfers {
            transfer.remap_edge_function(remap[transfer.edge_function_id().index()]);
        }
        Ok(sorted)
    }
}

struct ValueArena<Value> {
    values: Vec<Value>,
    ids: HashMap<Value, IdeValueId>,
}

impl<Value> ValueArena<Value>
where
    Value: Clone + Eq + Hash + Ord,
{
    fn new() -> Self {
        Self {
            values: Vec::new(),
            ids: HashMap::default(),
        }
    }

    fn intern(
        &mut self,
        value: Value,
        request: &mut DataflowRequest<'_>,
    ) -> Result<IdeValueId, IdeRunFailure> {
        if let Some(id) = self.ids.get(&value).copied() {
            return Ok(id);
        }
        let index = self.values.len();
        let id = IdeValueId::try_from_index(index)
            .map_err(|_| IdeDataflowError::ValueIdOverflow { index })?;
        reserve_ide_work(
            SolverWork {
                ide_values: 1,
                ..SolverWork::default()
            },
            request,
        )?;
        self.values.push(value.clone());
        self.ids.insert(value, id);
        Ok(id)
    }

    fn intern_ref(
        &mut self,
        value: &Value,
        request: &mut DataflowRequest<'_>,
    ) -> Result<IdeValueId, IdeRunFailure> {
        if let Some(id) = self.ids.get(value).copied() {
            return Ok(id);
        }
        self.intern(value.clone(), request)
    }

    fn get(&self, id: IdeValueId) -> &Value {
        &self.values[id.index()]
    }

    fn into_sorted_parts(
        self,
        pending: &mut [PendingPointValue],
    ) -> Result<Vec<Value>, IdeDataflowError> {
        let mut sorted = self.values.clone();
        sorted.sort_unstable();
        sorted.dedup();
        let ids = sorted
            .iter()
            .cloned()
            .enumerate()
            .map(|(index, value)| {
                IdeValueId::try_from_index(index)
                    .map(|id| (value, id))
                    .map_err(|_| IdeDataflowError::ValueIdOverflow { index })
            })
            .collect::<Result<HashMap<_, _>, _>>()?;
        let remap = self
            .values
            .iter()
            .map(|value| {
                ids.get(value).copied().ok_or(IdeDataflowError::Invariant(
                    "sorted IDE value table omitted an interned value",
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;
        for row in pending {
            row.value = remap[row.value.index()];
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
    entry_transfers: Vec<IdeEntryTransfer>,
    point_values: Vec<IdePointValue>,
}

struct CapturedReusableIdeSummary<Fact, EdgeFunction> {
    procedure: ProcedureHandle,
    entry_fact: Fact,
    summary: ReusableIdeProcedureSummary<Fact, EdgeFunction>,
}

struct IdeReusableProviderAdapter<'provider, Provider, Fact, EdgeFunction> {
    provider: &'provider mut Provider,
    captured: Vec<CapturedReusableIdeSummary<Fact, EdgeFunction>>,
}

impl<'provider, Provider, Fact, EdgeFunction>
    IdeReusableProviderAdapter<'provider, Provider, Fact, EdgeFunction>
{
    fn new(provider: &'provider mut Provider) -> Self {
        Self {
            provider,
            captured: Vec::new(),
        }
    }

    fn into_captured(self) -> Vec<CapturedReusableIdeSummary<Fact, EdgeFunction>> {
        self.captured
    }
}

impl<Provider, Fact, EdgeFunction> ReusableSummaryProvider<Fact>
    for IdeReusableProviderAdapter<'_, Provider, Fact, EdgeFunction>
where
    Provider: ReusableIdeSummaryProvider<Fact, EdgeFunction>,
    Fact: Copy + Eq,
    EdgeFunction: Clone,
{
    fn summary_for(
        &mut self,
        procedure: &ProcedureHandle,
        root: &ProcedureHandle,
        entry_fact: Fact,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Option<ReusableProcedureSummary<Fact>>, SolverTermination> {
        let Some(mut summary) = self
            .provider
            .summary_for(procedure, root, entry_fact, request)?
        else {
            return Ok(None);
        };
        // #2291. The IDE half of the reusable-row rule: every reusable reached
        // row must name the callee's own procedure. Binding a summary skips the
        // callee's body, and with the body the calls that body makes, so a
        // non-leaf callee's transitive callees are never entered through this
        // bind and the value phase has no state there to give a value to. The
        // replayed projection is a subset of a fresh solve's, values agree
        // wherever both produce a state, and every missing state sits strictly
        // below the summarized callee.
        // `deterministic_ide_family_reuse_matches_fresh_and_reference` in
        // `tests/suite_semantic/dataflow_ide.rs` pins those claims on the
        // `non_leaf_reuse` family of the #1563 gate. The full contract, and why
        // no production consumer turns the omission into a user-visible
        // verdict, is written out at the matching site in
        // `Tabulator::apply_reusable_callee_summaries` in `summary.rs`.
        if summary.exits.iter().any(|row| row.qualities.is_empty())
            || summary
                .reached
                .iter()
                .any(|row| row.qualities.is_empty() || row.point.procedure() != procedure)
        {
            return Ok(None);
        }
        let mut reached = summary.reached.into_vec();
        for exit in &summary.exits {
            let exit_point = match exit.exit_kind {
                crate::analyzer::semantic::ReturnTransferKind::Normal => {
                    procedure.semantics().normal_exit_point()
                }
                crate::analyzer::semantic::ReturnTransferKind::Exceptional => {
                    procedure.semantics().exceptional_exit_point()
                }
            };
            let Some(exit_point) = procedure.point_handle(exit_point) else {
                return Ok(None);
            };
            if !reached
                .iter()
                .any(|row| row.point == exit_point && row.fact == exit.exit_fact)
            {
                reached.push(ReusableIdeReachedFact {
                    point: exit_point,
                    fact: exit.exit_fact,
                    qualities: exit.qualities.clone(),
                    edge_function: exit.edge_function.clone(),
                });
            }
        }
        summary.reached = reached.into_boxed_slice();
        let relation_count = summary.exits.len().saturating_add(summary.reached.len());
        if let Some(termination) = request.reserve(SolverWork {
            ide_relations: relation_count,
            ..SolverWork::default()
        }) {
            return Err(termination);
        }
        let fact_summary = ReusableProcedureSummary {
            call_cycle: summary.call_cycle,
            called_procedures: summary.called_procedures,
            exits: summary
                .exits
                .iter()
                .map(|row| ReusableEndSummary {
                    exit_kind: row.exit_kind,
                    exit_fact: row.exit_fact,
                    qualities: row.qualities.clone(),
                })
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            reached: summary
                .reached
                .iter()
                .map(|row| ReusableReachedFact {
                    point: row.point.clone(),
                    fact: row.fact,
                    qualities: row.qualities.clone(),
                })
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        };
        // #2285. The fact solver refuses a summary that shares a call cycle
        // with the solve root and solves the body instead. Retaining the IDE
        // rows of a refused summary would be worse than useless: the value
        // phase would graft the summarized jump functions onto states the fresh
        // solve computed, which is exactly the reuse the fact solver just
        // declined. Hand the judgment through so one place decides, and retain
        // nothing when it refuses.
        // #2296 rides on the same judgment for the same reason: a summary the
        // fact solver refuses because its contract does not cover what the body
        // calls must not leave its jump functions behind either.
        if fact_summary.call_cycle == SummaryCallCycle::ExcludesRoot
            && fact_summary.called_procedures == SummaryCalledProcedures::CoveredByContract
        {
            self.captured.push(CapturedReusableIdeSummary {
                procedure: procedure.clone(),
                entry_fact,
                summary,
            });
        }
        Ok(Some(fact_summary))
    }
}

type IdeSolveOutcome<Problem> = Result<
    IdeSummaryDataflowResult<
        <Problem as IdeDataflowProblem>::Fact,
        <Problem as IdeDataflowProblem>::Value,
        <Problem as IdeDataflowProblem>::EdgeFunction,
    >,
    IdeDataflowError,
>;

struct BoundedSeedFacts<Fact> {
    facts: Vec<Fact>,
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
    let mut reusable = NoReusableIdeSummaries;
    solve_ide_with_reusable_summaries(
        input,
        provider,
        problem,
        &mut reusable,
        semantic_budget,
        request,
    )
}

/// Solve one finite IDE problem with an optional cross-query summary oracle.
pub fn solve_ide_with_reusable_summaries<Problem, Provider, Reusable>(
    input: IdeSummarySolveInput<'_, Problem::Fact, Problem::Value>,
    provider: &Provider,
    problem: &Problem,
    reusable: &mut Reusable,
    semantic_budget: &mut SemanticBudget,
    request: &mut DataflowRequest<'_>,
) -> IdeSolveOutcome<Problem>
where
    Problem: IdeDataflowProblem,
    Provider: crate::analyzer::semantic::IcfgProvider + ?Sized,
    Reusable: ReusableIdeSummaryProvider<Problem::Fact, Problem::EdgeFunction>,
{
    let initial_work = request.budget.used();
    let initial_semantic_work = semantic_budget.used();
    let seed_facts = bounded_seed_facts::<Problem>(&input, problem.zero_fact(), request);
    let remaining = request.budget.remaining();
    let adapter = IdeFactAdapter::new(
        problem,
        remaining.ide_relations,
        remaining.edge_function_operations,
        remaining.edge_functions,
    );
    let mut reusable_adapter = IdeReusableProviderAdapter::new(reusable);
    let fact_result = solve_with_reusable_end_summaries(
        SummarySolveInput::new(input.root(), &seed_facts.facts)
            .with_witness_retention(input.witness_retention()),
        provider,
        &adapter,
        &mut reusable_adapter,
        semantic_budget,
        request,
    )?;
    let reusable_summaries = reusable_adapter.into_captured();
    let trace = adapter.into_trace();
    let mut metrics = IdeMetrics {
        captured_relations: trace.retained_relations,
        ..IdeMetrics::default()
    };

    if !fact_result.termination().is_fixed_point() {
        return Ok(empty_ide_result(
            fact_result,
            initial_work,
            initial_semantic_work,
            semantic_budget,
            request,
            None,
            metrics,
        ));
    }
    if let Some(attempted) = trace.attempted_work {
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
            metrics,
        ));
    }
    if let Some(termination) = request.reserve(SolverWork {
        ide_relations: trace.retained_relations,
        edge_function_operations: trace.capture_meets,
        ..SolverWork::default()
    }) {
        return Ok(empty_ide_result(
            fact_result,
            initial_work,
            initial_semantic_work,
            semantic_budget,
            request,
            Some(termination),
            metrics,
        ));
    }
    let seed_values = match canonical_seed_values(&input, problem, request) {
        Ok(values) => values,
        Err(termination) => {
            return Ok(empty_ide_result(
                fact_result,
                initial_work,
                initial_semantic_work,
                semantic_budget,
                request,
                Some(termination),
                metrics,
            ));
        }
    };

    let phase = match run_ide_phase(
        input.root(),
        &seed_values,
        problem,
        &fact_result,
        &trace,
        &reusable_summaries,
        request,
        &mut metrics,
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
                metrics,
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
        phase.entry_transfers,
        phase.point_values,
        SolverTermination::FixedPoint,
        work,
        semantic_work,
        metrics,
    ))
}

fn bounded_seed_facts<Problem>(
    input: &IdeSummarySolveInput<'_, Problem::Fact, Problem::Value>,
    zero_fact: Problem::Fact,
    request: &DataflowRequest<'_>,
) -> BoundedSeedFacts<Problem::Fact>
where
    Problem: IdeDataflowProblem,
{
    let mut facts = Vec::new();
    let mut unique_facts = HashSet::default();
    unique_facts.insert(zero_fact);
    let mut callback_rows = 0usize;
    for seed in input.seeds() {
        if request.cancellation.is_cancelled() {
            break;
        }
        callback_rows = callback_rows.saturating_add(1);
        let fact = *seed.fact();
        let prospective_facts = unique_facts
            .len()
            .saturating_add(usize::from(!unique_facts.contains(&fact)));
        if request
            .budget
            .check(SolverWork {
                interned_facts: prospective_facts,
                reached_states: prospective_facts,
                callback_rows,
                ..SolverWork::default()
            })
            .is_err()
        {
            // Retain the triggering row so summary initialization reports the
            // same typed limit without materializing any semantic provider.
            facts.push(fact);
            break;
        }
        unique_facts.insert(fact);
        facts.push(fact);
    }
    BoundedSeedFacts { facts }
}

fn canonical_seed_values<Problem>(
    input: &IdeSummarySolveInput<'_, Problem::Fact, Problem::Value>,
    problem: &Problem,
    request: &mut DataflowRequest<'_>,
) -> Result<HashMap<Problem::Fact, Problem::Value>, SolverTermination>
where
    Problem: IdeDataflowProblem,
{
    let mut grouped = BTreeMap::<Problem::Fact, BTreeSet<&Problem::Value>>::new();
    for seed in input.seeds() {
        if request.cancellation.is_cancelled() {
            return Err(SolverTermination::Cancelled);
        }
        grouped
            .entry(*seed.fact())
            .or_default()
            .insert(seed.value());
    }

    let mut values = HashMap::default();
    values.insert(problem.zero_fact(), problem.zero_value());
    for (fact, candidates) in grouped {
        for value in candidates {
            if request.cancellation.is_cancelled() {
                return Err(SolverTermination::Cancelled);
            }
            if let Some(existing) = values.get(&fact) {
                if existing == value {
                    continue;
                }
                if let Some(termination) = request.reserve(SolverWork {
                    value_operations: 1,
                    ..SolverWork::default()
                }) {
                    return Err(termination);
                }
                let merged = if existing <= value {
                    problem.meet_values(existing, value)
                } else {
                    problem.meet_values(value, existing)
                };
                if request.cancellation.is_cancelled() {
                    return Err(SolverTermination::Cancelled);
                }
                values.insert(fact, merged);
            } else {
                values.insert(fact, value.clone());
            }
        }
    }
    Ok(values)
}

#[allow(clippy::too_many_arguments)]
fn run_ide_phase<Problem>(
    root: &ProcedureHandle,
    seed_values: &HashMap<Problem::Fact, Problem::Value>,
    problem: &Problem,
    fact_result: &SummaryDataflowResult<Problem::Fact>,
    trace: &IdeTrace<Problem::Fact, Problem::EdgeFunction>,
    reusable_summaries: &[CapturedReusableIdeSummary<Problem::Fact, Problem::EdgeFunction>],
    request: &mut DataflowRequest<'_>,
    metrics: &mut IdeMetrics,
) -> Result<CompleteIdePhase<Problem::Value, Problem::EdgeFunction>, IdeRunFailure>
where
    Problem: IdeDataflowProblem,
{
    let mut functions = FunctionArena::new(problem, request)?;
    let raw_graph = build_raw_graph(
        fact_result,
        trace,
        reusable_summaries,
        &mut functions,
        &|fact| problem.is_flow_observation(fact),
        request,
    )?;
    let relation_count = raw_graph
        .direct
        .len()
        .saturating_add(raw_graph.summaries.len())
        .saturating_add(raw_graph.entry_values.len());
    reserve_ide_work(
        SolverWork {
            ide_relations: relation_count,
            ..SolverWork::default()
        },
        request,
    )?;

    metrics.direct_relations = raw_graph.direct.len();
    metrics.summary_relations = raw_graph.summaries.len();
    metrics.entry_value_relations = raw_graph.entry_values.len();
    metrics.reused_summary_functions = raw_graph.reused_summary_functions;
    let graph = build_graph(raw_graph, request)?;
    let scheduling_storage = fact_result
        .reached()
        .len()
        .saturating_mul(2)
        .saturating_add(fact_result.end_summaries().len());
    reserve_ide_work(
        SolverWork {
            ide_propagations: scheduling_storage,
            ..SolverWork::default()
        },
        request,
    )?;
    let mut jumps = vec![None; fact_result.reached().len()];
    let mut worklist = VecDeque::new();
    let mut queued = vec![false; jumps.len()];
    for entry in graph.entry_rows.iter().copied() {
        jumps[entry] = Some(functions.identity);
        enqueue(entry, &mut worklist, &mut queued, request)?;
        metrics.jump_updates = metrics.jump_updates.saturating_add(1);
    }

    while let Some(source) = worklist.pop_front() {
        reserve_ide_propagation(request)?;
        queued[source] = false;
        if request.cancellation.is_cancelled() {
            return Err(IdeRunFailure::Terminated(SolverTermination::Cancelled));
        }
        let source_jump = jumps[source].ok_or(IdeDataflowError::Invariant(
            "queued IDE state has no jump function",
        ))?;
        for relation in graph.direct_by_source[source].iter().copied() {
            reserve_ide_propagation(request)?;
            let candidate =
                functions.compose(source_jump, relation.function, problem, request, metrics)?;
            publish_jump(
                relation.target,
                candidate,
                &mut jumps,
                &mut functions,
                problem,
                request,
                metrics,
                &mut worklist,
                &mut queued,
            )?;
        }
        for relation_id in graph.summaries_by_dependency[source].iter().copied() {
            reserve_ide_propagation(request)?;
            let relation = graph.summaries[relation_id];
            let (Some(caller), Some(callee)) =
                (jumps[relation.caller], jumps[relation.callee_exit])
            else {
                continue;
            };
            metrics.summary_function_applications =
                metrics.summary_function_applications.saturating_add(1);
            let call =
                functions.compose(caller, relation.call_function, problem, request, metrics)?;
            let summary = functions.compose(call, callee, problem, request, metrics)?;
            let candidate =
                functions.compose(summary, relation.return_function, problem, request, metrics)?;
            publish_jump(
                relation.target,
                candidate,
                &mut jumps,
                &mut functions,
                problem,
                request,
                metrics,
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
    let mut entry_transfers = Vec::new();
    for (source_entry_row, relations) in graph.entry_values_by_entry.iter().enumerate() {
        for relation in relations.iter().copied() {
            let function = functions.compose(
                jumps[relation.caller].ok_or(IdeDataflowError::Invariant(
                    "IDE call source has no jump function",
                ))?,
                relation.function,
                problem,
                request,
                metrics,
            )?;
            let path_qualities = fact_result.reached()[relation.caller]
                .path_qualities()
                .conjoin(PathQualityFrontier::singleton(relation.edge_quality));
            entry_transfers.push(IdeEntryTransfer::new(
                fact_result.reached()[source_entry_row].entry().clone(),
                fact_result.reached()[relation.target_entry].entry().clone(),
                path_qualities,
                function,
            ));
        }
    }
    let (values, point_values) = materialize_values(
        root,
        seed_values,
        problem,
        fact_result,
        &graph,
        &jumps,
        &functions.functions,
        request,
    )?;
    let sorted_functions =
        functions.into_sorted_parts(&mut jumps, &mut summary_functions, &mut entry_transfers)?;
    Ok(CompleteIdePhase {
        functions: sorted_functions,
        values,
        reached_functions: jumps,
        summary_functions,
        entry_transfers,
        point_values,
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
    enqueue(target, worklist, queued, request)?;
    Ok(())
}

fn enqueue(
    row: usize,
    worklist: &mut VecDeque<usize>,
    queued: &mut [bool],
    request: &mut DataflowRequest<'_>,
) -> Result<(), IdeRunFailure> {
    if !queued[row] {
        reserve_ide_propagation(request)?;
        queued[row] = true;
        worklist.push_back(row);
    }
    Ok(())
}

fn build_graph(
    raw: RawIdeGraph,
    request: &mut DataflowRequest<'_>,
) -> Result<IdeGraph, IdeRunFailure> {
    let expansion_work = raw
        .row_count
        .saturating_mul(3)
        .saturating_add(raw.direct.len())
        .saturating_add(raw.summaries.len().saturating_mul(3))
        .saturating_add(raw.entry_values.len());
    reserve_ide_work(
        SolverWork {
            ide_propagations: expansion_work,
            ..SolverWork::default()
        },
        request,
    )?;
    let mut direct_by_source = vec![Vec::new(); raw.row_count];
    for relation in raw.direct {
        direct_by_source[relation.source].push(DirectRelation {
            target: relation.target,
            function: relation.function,
        });
    }
    let mut summaries = Vec::with_capacity(raw.summaries.len());
    for relation in raw.summaries {
        summaries.push(SummaryRelation {
            caller: relation.caller,
            callee_exit: relation.callee_exit,
            target: relation.target,
            call_function: relation.call_function,
            return_function: relation.return_function,
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
    let mut entry_values_by_entry = vec![Vec::new(); row_count];
    for relation in raw.entry_values {
        let caller_entry = raw.row_entries[relation.caller];
        entry_values_by_entry[caller_entry].push(EntryValueRelation {
            caller: relation.caller,
            target_entry: relation.target_entry,
            function: relation.function,
            edge_quality: relation.edge_quality,
        });
    }
    Ok(IdeGraph {
        direct_by_source,
        summaries,
        summaries_by_dependency,
        entry_values_by_entry,
        entry_rows: raw.entry_rows,
        row_entries: raw.row_entries,
        end_summary_exit_rows: raw.end_summary_exit_rows,
    })
}

fn build_raw_graph<Fact, EdgeFunction>(
    result: &SummaryDataflowResult<Fact>,
    trace: &IdeTrace<Fact, EdgeFunction>,
    reusable_summaries: &[CapturedReusableIdeSummary<Fact, EdgeFunction>],
    functions: &mut FunctionArena<EdgeFunction>,
    is_flow_observation: &dyn Fn(&Fact) -> bool,
    request: &mut DataflowRequest<'_>,
) -> Result<RawIdeGraph, IdeRunFailure>
where
    Fact: Copy + Eq + Hash + Ord,
    EdgeFunction: Clone + Eq + Hash + Ord,
{
    let indexing_work = result
        .facts()
        .len()
        .saturating_add(result.reached().len().saturating_mul(3))
        .saturating_add(result.end_summaries().len().saturating_mul(2));
    reserve_ide_work(
        SolverWork {
            ide_propagations: indexing_work,
            ..SolverWork::default()
        },
        request,
    )?;
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
        let entry_fact = result.fact(reached.entry().entry_fact()).copied().ok_or(
            IdeDataflowError::Invariant("reached IDE entry fact ID is absent from its result"),
        )?;
        by_point_fact
            .entry((reached.point().clone(), fact, entry_fact))
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
    let row_entries = result
        .reached()
        .iter()
        .map(|reached| {
            let entry_fact = result.fact(reached.entry().entry_fact()).copied().ok_or(
                IdeDataflowError::Invariant("IDE entry fact ID is absent from its result"),
            )?;
            by_state
                .get(&(
                    reached.entry().clone(),
                    reached.entry().entry_point().clone(),
                    entry_fact,
                ))
                .copied()
                .ok_or(IdeDataflowError::Invariant(
                    "IDE reached row has no relative entry row",
                ))
        })
        .collect::<Result<Vec<_>, IdeDataflowError>>()?;
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
    let mut entry_values = HashSet::default();
    let mut summary_uses = HashMap::<usize, usize>::default();
    for record in &trace.records {
        reserve_ide_propagation(request)?;
        let sources = by_point_fact
            .get(&(
                record.key.edge.source.clone(),
                record.key.input,
                record.key.entry,
            ))
            .map(Vec::as_slice)
            .unwrap_or_default();
        match record.key.edge.kind {
            IcfgEdgeKind::Call => {
                let transfer =
                    record
                        .key
                        .call_transfer
                        .as_ref()
                        .ok_or(IdeDataflowError::Invariant(
                            "captured call edge has no exact transfer",
                        ))?;
                for source in sources.iter().copied() {
                    reserve_ide_propagation(request)?;
                    let caller_entry = result.reached()[source].entry().clone();
                    for output in &record.outputs {
                        reserve_ide_propagation(request)?;
                        let call_function =
                            functions.intern_ref(&trace.functions[output.function], request)?;
                        let output_id = fact_ids.get(&output.fact).copied().ok_or(
                            IdeDataflowError::Invariant(
                                "captured call output fact was not interned",
                            ),
                        )?;
                        if is_flow_observation(&output.fact) {
                            // The summary solver keeps a call-edge observation
                            // in the calling context at the call point
                            // (#1917), so its value relation is a direct one.
                            let target = by_state
                                .get(&(
                                    caller_entry.clone(),
                                    record.key.edge.source.clone(),
                                    output.fact,
                                ))
                                .copied()
                                .ok_or(IdeDataflowError::Invariant(
                                    "captured call observation has no caller row",
                                ))?;
                            let relation = RawDirectRelation {
                                source,
                                target,
                                function: call_function,
                            };
                            if !direct.contains(&relation) {
                                ensure_relation_capacity(
                                    direct
                                        .len()
                                        .saturating_add(summaries.len())
                                        .saturating_add(entry_values.len()),
                                    request,
                                )?;
                                direct.insert(relation);
                            }
                            continue;
                        }
                        let callee_entry = SummaryEntry::new(
                            transfer.callee.clone(),
                            transfer.callee_entry.clone(),
                            output_id,
                        );
                        let target_entry = by_state
                            .get(&(
                                callee_entry.clone(),
                                transfer.callee_entry.clone(),
                                output.fact,
                            ))
                            .copied()
                            .ok_or(IdeDataflowError::Invariant(
                                "captured call output has no callee entry row",
                            ))?;
                        let entry_value = RawEntryValueRelation {
                            caller: source,
                            target_entry,
                            function: call_function,
                            edge_quality: PathQuality::PROVEN_COMPLETE.through_evidence(
                                &record.key.edge.proof,
                                &record.key.edge.completeness,
                            ),
                        };
                        if !entry_values.contains(&entry_value) {
                            ensure_relation_capacity(
                                direct
                                    .len()
                                    .saturating_add(summaries.len())
                                    .saturating_add(entry_values.len()),
                                request,
                            )?;
                            entry_values.insert(entry_value);
                        }
                        for end_summary in summaries_by_entry
                            .get(&callee_entry)
                            .into_iter()
                            .flatten()
                            .copied()
                        {
                            reserve_ide_propagation(request)?;
                            let summary = &result.end_summaries()[end_summary];
                            let exit_fact = result.fact(summary.exit_fact()).copied().ok_or(
                                IdeDataflowError::Invariant(
                                    "captured summary exit fact was not interned",
                                ),
                            )?;
                            let entry_fact = result
                                .fact(summary.entry().entry_fact())
                                .copied()
                                .ok_or(IdeDataflowError::Invariant(
                                    "captured summary entry fact was not interned",
                                ))?;
                            let projection = summary
                                .exit()
                                .project_matched_return(transfer)
                                .map_err(SummaryDataflowError::from)?;
                            let MatchedReturnProjection::Edge {
                                edge: return_edge, ..
                            } = projection
                            else {
                                continue;
                            };
                            let return_key = TransferKey {
                                edge: return_edge,
                                call_transfer: None,
                                entry: entry_fact,
                                input: exit_fact,
                            };
                            let Some(return_outputs) = trace.get(&return_key) else {
                                continue;
                            };
                            for returned in return_outputs {
                                reserve_ide_propagation(request)?;
                                let return_function = functions
                                    .intern_ref(&trace.functions[returned.function], request)?;
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
                                    call_function,
                                    return_function,
                                };
                                if !summaries.contains(&relation) {
                                    ensure_relation_capacity(
                                        direct
                                            .len()
                                            .saturating_add(summaries.len())
                                            .saturating_add(entry_values.len()),
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
                for source in sources.iter().copied() {
                    reserve_ide_propagation(request)?;
                    let entry = result.reached()[source].entry().clone();
                    for output in &record.outputs {
                        reserve_ide_propagation(request)?;
                        let function =
                            functions.intern_ref(&trace.functions[output.function], request)?;
                        let Some(target) = by_state
                            .get(&(entry.clone(), record.key.edge.target.clone(), output.fact))
                            .copied()
                        else {
                            continue;
                        };
                        let relation = RawDirectRelation {
                            source,
                            target,
                            function,
                        };
                        if !direct.contains(&relation) {
                            ensure_relation_capacity(
                                direct
                                    .len()
                                    .saturating_add(summaries.len())
                                    .saturating_add(entry_values.len()),
                                request,
                            )?;
                            direct.insert(relation);
                        }
                    }
                }
            }
        }
    }
    for cached in reusable_summaries {
        reserve_ide_propagation(request)?;
        let entry_point = cached
            .procedure
            .point_handle(cached.procedure.semantics().entry_point())
            .ok_or(IdeDataflowError::Invariant(
                "reusable IDE procedure entry point is stale",
            ))?;
        let entry_fact_id =
            fact_ids
                .get(&cached.entry_fact)
                .copied()
                .ok_or(IdeDataflowError::Invariant(
                    "reusable IDE entry fact was not interned",
                ))?;
        let entry = SummaryEntry::new(cached.procedure.clone(), entry_point.clone(), entry_fact_id);
        let source = by_state
            .get(&(entry.clone(), entry_point, cached.entry_fact))
            .copied()
            .ok_or(IdeDataflowError::Invariant(
                "reusable IDE summary has no entry row",
            ))?;
        for row in &cached.summary.reached {
            reserve_ide_propagation(request)?;
            let target = by_state
                .get(&(entry.clone(), row.point.clone(), row.fact))
                .copied()
                .ok_or(IdeDataflowError::Invariant(
                    "reusable IDE observation has no reached row",
                ))?;
            let function = functions.intern_ref(&row.edge_function, request)?;
            let relation = RawDirectRelation {
                source,
                target,
                function,
            };
            if !direct.contains(&relation) {
                ensure_relation_capacity(
                    direct
                        .len()
                        .saturating_add(summaries.len())
                        .saturating_add(entry_values.len()),
                    request,
                )?;
                direct.insert(relation);
            }
        }
        for row in &cached.summary.exits {
            reserve_ide_propagation(request)?;
            let exit_point = match row.exit_kind {
                crate::analyzer::semantic::ReturnTransferKind::Normal => {
                    cached.procedure.semantics().normal_exit_point()
                }
                crate::analyzer::semantic::ReturnTransferKind::Exceptional => {
                    cached.procedure.semantics().exceptional_exit_point()
                }
            };
            let exit_point =
                cached
                    .procedure
                    .point_handle(exit_point)
                    .ok_or(IdeDataflowError::Invariant(
                        "reusable IDE procedure exit point is stale",
                    ))?;
            let target = by_state
                .get(&(entry.clone(), exit_point, row.exit_fact))
                .copied()
                .ok_or(IdeDataflowError::Invariant(
                    "reusable IDE exit has no reached row",
                ))?;
            let function = functions.intern_ref(&row.edge_function, request)?;
            let relation = RawDirectRelation {
                source,
                target,
                function,
            };
            if !direct.contains(&relation) {
                ensure_relation_capacity(
                    direct
                        .len()
                        .saturating_add(summaries.len())
                        .saturating_add(entry_values.len()),
                    request,
                )?;
                direct.insert(relation);
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
    let mut entry_values = entry_values.into_iter().collect::<Vec<_>>();
    entry_values.sort_unstable_by(|left, right| {
        (left.caller, left.target_entry)
            .cmp(&(right.caller, right.target_entry))
            .then_with(|| left.function.cmp(&right.function))
            .then_with(|| {
                (
                    left.edge_quality.is_proven(),
                    left.edge_quality.is_complete(),
                )
                    .cmp(&(
                        right.edge_quality.is_proven(),
                        right.edge_quality.is_complete(),
                    ))
            })
    });
    let reused_summary_functions = summary_uses
        .values()
        .map(|uses| uses.saturating_sub(1))
        .sum();
    Ok(RawIdeGraph {
        row_count: result.reached().len(),
        direct,
        summaries,
        entry_values,
        entry_rows,
        row_entries,
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

#[derive(Debug)]
struct PendingPointValue {
    entry: SummaryEntry,
    point: crate::analyzer::semantic::ProgramPointHandle,
    fact: FactId,
    value: IdeValueId,
    qualities: PathQualityFrontier,
}

#[allow(clippy::too_many_arguments)]
fn materialize_values<Problem>(
    root: &ProcedureHandle,
    seed_values: &HashMap<Problem::Fact, Problem::Value>,
    problem: &Problem,
    result: &SummaryDataflowResult<Problem::Fact>,
    graph: &IdeGraph,
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
    reserve_ide_work(
        SolverWork {
            ide_propagations: result.reached().len().saturating_mul(4),
            ..SolverWork::default()
        },
        request,
    )?;
    let mut values = ValueArena::new();
    let mut entry_values = vec![None; result.reached().len()];
    let mut entry_qualities = vec![PathQualityFrontier::default(); result.reached().len()];
    let mut entry_worklist = VecDeque::new();
    let mut entry_queued = vec![false; result.reached().len()];
    for entry in graph.entry_rows.iter().copied() {
        reserve_ide_propagation(request)?;
        let reached = &result.reached()[entry];
        if reached.entry().procedure() != root || reached.entry().entry_point() != &root_entry {
            continue;
        }
        let entry_fact = result.fact(reached.entry().entry_fact()).copied().ok_or(
            IdeDataflowError::Invariant("root IDE entry fact is absent from its result"),
        )?;
        let Some(seed) = seed_values.get(&entry_fact) else {
            continue;
        };
        entry_values[entry] = Some(values.intern_ref(seed, request)?);
        entry_qualities[entry] = reached.path_qualities();
        enqueue(entry, &mut entry_worklist, &mut entry_queued, request)?;
    }

    while let Some(entry) = entry_worklist.pop_front() {
        reserve_ide_propagation(request)?;
        entry_queued[entry] = false;
        if request.cancellation.is_cancelled() {
            return Err(IdeRunFailure::Terminated(SolverTermination::Cancelled));
        }
        let entry_value = entry_values[entry].ok_or(IdeDataflowError::Invariant(
            "queued IDE entry has no concrete value",
        ))?;
        for relation in graph.entry_values_by_entry[entry].iter().copied() {
            reserve_ide_propagation(request)?;
            reserve_ide_work(
                SolverWork {
                    value_operations: 1,
                    ..SolverWork::default()
                },
                request,
            )?;
            let caller_value = problem.apply_edge_function(
                &functions[jumps[relation.caller]
                    .ok_or(IdeDataflowError::Invariant(
                        "IDE call source has no jump function",
                    ))?
                    .index()],
                values.get(entry_value),
            );
            if request.cancellation.is_cancelled() {
                return Err(IdeRunFailure::Terminated(SolverTermination::Cancelled));
            }
            reserve_ide_work(
                SolverWork {
                    value_operations: 1,
                    ..SolverWork::default()
                },
                request,
            )?;
            let candidate =
                problem.apply_edge_function(&functions[relation.function.index()], &caller_value);
            if request.cancellation.is_cancelled() {
                return Err(IdeRunFailure::Terminated(SolverTermination::Cancelled));
            }
            let candidate = values.intern(candidate, request)?;
            let next_value = match entry_values[relation.target_entry] {
                Some(existing) if existing != candidate => {
                    reserve_ide_work(
                        SolverWork {
                            value_operations: 1,
                            ..SolverWork::default()
                        },
                        request,
                    )?;
                    let existing_value = values.get(existing);
                    let candidate_value = values.get(candidate);
                    let met = if existing_value <= candidate_value {
                        problem.meet_values(existing_value, candidate_value)
                    } else {
                        problem.meet_values(candidate_value, existing_value)
                    };
                    if request.cancellation.is_cancelled() {
                        return Err(IdeRunFailure::Terminated(SolverTermination::Cancelled));
                    }
                    values.intern(met, request)?
                }
                Some(existing) => existing,
                None => candidate,
            };

            let prefix_qualities =
                entry_qualities[entry].conjoin(result.reached()[relation.caller].path_qualities());
            let candidate_qualities =
                prefix_qualities.conjoin(PathQualityFrontier::singleton(relation.edge_quality));
            let mut next_qualities = entry_qualities[relation.target_entry];
            let mut quality_changed = false;
            for quality in candidate_qualities.iter() {
                quality_changed |= next_qualities.insert(quality);
            }

            let value_changed = entry_values[relation.target_entry] != Some(next_value);
            if !value_changed && !quality_changed {
                continue;
            }
            entry_values[relation.target_entry] = Some(next_value);
            entry_qualities[relation.target_entry] = next_qualities;
            enqueue(
                relation.target_entry,
                &mut entry_worklist,
                &mut entry_queued,
                request,
            )?;
        }
    }

    let mut pending = Vec::<PendingPointValue>::with_capacity(result.reached().len());
    for (index, reached) in result.reached().iter().enumerate() {
        let seed = entry_values[graph.row_entries[index]].ok_or(IdeDataflowError::Invariant(
            "reachable IDE entry has no concrete value",
        ))?;
        let function =
            jumps[index].ok_or(IdeDataflowError::Invariant("IDE row has no jump function"))?;
        reserve_ide_work(
            SolverWork {
                value_operations: 1,
                ..SolverWork::default()
            },
            request,
        )?;
        let value = problem.apply_edge_function(&functions[function.index()], values.get(seed));
        if request.cancellation.is_cancelled() {
            return Err(IdeRunFailure::Terminated(SolverTermination::Cancelled));
        }
        let value = values.intern(value, request)?;
        pending.push(PendingPointValue {
            entry: reached.entry().clone(),
            point: reached.point().clone(),
            fact: reached.fact(),
            value,
            qualities: entry_qualities[graph.row_entries[index]].conjoin(reached.path_qualities()),
        });
    }

    let values = values.into_sorted_parts(&mut pending)?;
    let point_values = pending
        .into_iter()
        .map(|row| IdePointValue::new(row.entry, row.point, row.fact, row.value, row.qualities))
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
    metrics: IdeMetrics,
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
        Vec::new(),
        termination,
        request.budget.used().saturating_sub(initial_work),
        semantic_budget.used().saturating_sub(initial_semantic_work),
        metrics,
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

fn reserve_ide_propagation(request: &mut DataflowRequest<'_>) -> Result<(), IdeRunFailure> {
    reserve_ide_work(
        SolverWork {
            ide_propagations: 1,
            ..SolverWork::default()
        },
        request,
    )
}

fn owned_edge<Fact>(edge: DataflowEdge<'_, Fact>) -> ProcedureIcfgEdge {
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
