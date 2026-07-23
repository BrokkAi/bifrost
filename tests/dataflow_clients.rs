mod common;
#[path = "common/dataflow_fixtures.rs"]
mod dataflow_fixtures;

use std::cell::Cell;
use std::collections::BTreeSet;

use brokk_bifrost::analyzer::dataflow::{
    DataflowEdge, DataflowError, DataflowOutput, DataflowRequest, DataflowResult, DataflowSeed,
    DirectFact, DirectFlowProblem, DistributiveDataflowProblem, IcfgInputStatus, IcfgSolveInput,
    SolverBudget, SolverBudgetDimension, SolverTermination, SolverWork, solve,
};
use brokk_bifrost::analyzer::semantic::{
    CancellationToken, IcfgLimitKind, IcfgNodeId, IcfgSnapshot, IcfgSnapshotLimits, SemanticBudget,
    SemanticCapability, SemanticOutcome, SemanticWork,
};
use brokk_bifrost::{AnalyzerConfig, Language};

use common::{
    InlineTestProject,
    dataflow_reference::reference_solve,
    semantic_graph::{
        CallContextSelector, ExpectedIcfgBoundary, ExpectedIcfgBoundaryKind, IcfgGraph,
        PointSelector, reachable_icfg_nodes,
    },
};
use dataflow_fixtures::{rust_choose_icfg, rust_deferred_call_icfg};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum GeneratingFact {
    Seed,
    Generated,
}

struct GeneratingProblem {
    seed: IcfgNodeId,
}

impl GeneratingProblem {
    fn transfer(fact: GeneratingFact, out: &mut dyn DataflowOutput<GeneratingFact>) {
        match fact {
            GeneratingFact::Seed | GeneratingFact::Generated => {
                let _ = out.emit(GeneratingFact::Generated);
            }
        }
    }
}

impl DistributiveDataflowProblem for GeneratingProblem {
    type Fact = GeneratingFact;

    fn zero_fact(&self) -> Self::Fact {
        GeneratingFact::Seed
    }

    fn seeds(&self, out: &mut dyn DataflowOutput<DataflowSeed<Self::Fact>>) {
        let _ = out.emit(DataflowSeed::new(self.seed, GeneratingFact::Seed));
    }

    fn normal_flow(
        &self,
        _edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        Self::transfer(fact, out);
    }

    fn call_flow(
        &self,
        _edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        Self::transfer(fact, out);
    }

    fn return_flow(
        &self,
        _edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        Self::transfer(fact, out);
    }

    fn call_to_return_flow(
        &self,
        _edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        Self::transfer(fact, out);
    }

    fn exceptional_flow(
        &self,
        _edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        Self::transfer(fact, out);
    }
}

struct CancelOnTransferProblem {
    seed: IcfgNodeId,
    cancellation: CancellationToken,
}

impl CancelOnTransferProblem {
    fn transfer(&self, out: &mut dyn DataflowOutput<GeneratingFact>) {
        self.cancellation.cancel();
        let _ = out.emit(GeneratingFact::Generated);
    }
}

impl DistributiveDataflowProblem for CancelOnTransferProblem {
    type Fact = GeneratingFact;

    fn zero_fact(&self) -> Self::Fact {
        GeneratingFact::Seed
    }

    fn seeds(&self, out: &mut dyn DataflowOutput<DataflowSeed<Self::Fact>>) {
        let _ = out.emit(DataflowSeed::new(self.seed, GeneratingFact::Seed));
    }

    fn normal_flow(
        &self,
        _edge: DataflowEdge<'_>,
        _fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.transfer(out);
    }

    fn call_flow(
        &self,
        _edge: DataflowEdge<'_>,
        _fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.transfer(out);
    }

    fn return_flow(
        &self,
        _edge: DataflowEdge<'_>,
        _fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.transfer(out);
    }

    fn call_to_return_flow(
        &self,
        _edge: DataflowEdge<'_>,
        _fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.transfer(out);
    }

    fn exceptional_flow(
        &self,
        _edge: DataflowEdge<'_>,
        _fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.transfer(out);
    }
}

struct SeedBurstProblem {
    seed: IcfgNodeId,
    attempts: Cell<usize>,
}

impl DistributiveDataflowProblem for SeedBurstProblem {
    type Fact = u32;

    fn zero_fact(&self) -> Self::Fact {
        0
    }

    fn seeds(&self, out: &mut dyn DataflowOutput<DataflowSeed<Self::Fact>>) {
        for fact in 1..=10 {
            self.attempts.set(self.attempts.get() + 1);
            let _ = out.emit(DataflowSeed::new(self.seed, fact));
        }
    }

    fn normal_flow(
        &self,
        _edge: DataflowEdge<'_>,
        _fact: Self::Fact,
        _out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
    }

    fn call_flow(
        &self,
        _edge: DataflowEdge<'_>,
        _fact: Self::Fact,
        _out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
    }

    fn return_flow(
        &self,
        _edge: DataflowEdge<'_>,
        _fact: Self::Fact,
        _out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
    }

    fn call_to_return_flow(
        &self,
        _edge: DataflowEdge<'_>,
        _fact: Self::Fact,
        _out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
    }

    fn exceptional_flow(
        &self,
        _edge: DataflowEdge<'_>,
        _fact: Self::Fact,
        _out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
    }
}

struct TransferBurstProblem {
    seed: IcfgNodeId,
    attempts: Cell<usize>,
    cancel_on_stop: Option<CancellationToken>,
}

impl TransferBurstProblem {
    fn transfer(&self, out: &mut dyn DataflowOutput<u32>) {
        for fact in 1..=10 {
            self.attempts.set(self.attempts.get() + 1);
            if !out.emit(fact)
                && let Some(cancellation) = &self.cancel_on_stop
            {
                cancellation.cancel();
            }
        }
    }
}

impl DistributiveDataflowProblem for TransferBurstProblem {
    type Fact = u32;

    fn zero_fact(&self) -> Self::Fact {
        0
    }

    fn seeds(&self, out: &mut dyn DataflowOutput<DataflowSeed<Self::Fact>>) {
        let _ = out.emit(DataflowSeed::new(self.seed, 0));
    }

    fn normal_flow(
        &self,
        _edge: DataflowEdge<'_>,
        _fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.transfer(out);
    }

    fn call_flow(
        &self,
        _edge: DataflowEdge<'_>,
        _fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.transfer(out);
    }

    fn return_flow(
        &self,
        _edge: DataflowEdge<'_>,
        _fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.transfer(out);
    }

    fn call_to_return_flow(
        &self,
        _edge: DataflowEdge<'_>,
        _fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.transfer(out);
    }

    fn exceptional_flow(
        &self,
        _edge: DataflowEdge<'_>,
        _fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.transfer(out);
    }
}

fn solve_direct(input: IcfgSolveInput<'_>, seed: IcfgNodeId) -> DataflowResult<DirectFact> {
    let problem = DirectFlowProblem::new([seed]);
    let cancellation = CancellationToken::default();
    let mut budget = SolverBudget::default();
    solve(
        input,
        &problem,
        &mut DataflowRequest::new(&mut budget, &cancellation),
    )
    .expect("valid direct-flow fixture")
}

fn result_nodes<Fact>(result: &DataflowResult<Fact>) -> BTreeSet<IcfgNodeId> {
    result
        .reached()
        .iter()
        .map(|reached| reached.node())
        .collect()
}

fn has_fact<Fact: PartialEq>(result: &DataflowResult<Fact>, fact: Fact) -> bool {
    result.facts().contains(&fact)
}

fn reached_nodes_for_fact<Fact: PartialEq>(
    result: &DataflowResult<Fact>,
    expected: &Fact,
) -> BTreeSet<IcfgNodeId> {
    result
        .reached()
        .iter()
        .filter_map(|reached| {
            (result.fact(reached.fact()) == Some(expected)).then_some(reached.node())
        })
        .collect()
}

fn budget_with_limit(dimension: SolverBudgetDimension, limit: usize) -> SolverBudget {
    let mut limits = SolverWork::uniform(10_000);
    match dimension {
        SolverBudgetDimension::InternedFacts => limits.interned_facts = limit,
        SolverBudgetDimension::ReachedStates => limits.reached_states = limit,
        SolverBudgetDimension::FlowEvaluations => limits.flow_evaluations = limit,
        SolverBudgetDimension::PropagatedOutputs => limits.propagated_outputs = limit,
    }
    SolverBudget::new(limits)
}

#[test]
fn direct_client_equals_bounded_graph_reachability_and_reference_semantics() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/direct.ts",
            r#"
                function leaf(value: number): number {
                    return value;
                }

                function caller(): number {
                    const first = leaf(1);
                    const second = leaf(2);
                    return first + second;
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = IcfgGraph::materialize(
        &project,
        &analyzer,
        "src/direct.ts",
        PointSelector::new("function caller")
            .procedure("caller")
            .effect("entry"),
    );
    graph.bind_node(
        "root",
        "src/direct.ts",
        PointSelector::new("function caller")
            .procedure("caller")
            .effect("entry"),
        CallContextSelector::root(),
    );

    let root = graph.node("root");
    let problem = DirectFlowProblem::new([root]);
    let result = solve_direct(graph.solve_input(), root);
    let reference =
        reference_solve(graph.snapshot(), &problem).expect("reference direct-flow fixture");

    assert_eq!(
        result_nodes(&result),
        reachable_icfg_nodes(graph.snapshot(), [root])
    );
    assert_eq!(result_nodes(&result), reference.reached_nodes());
    assert_eq!(result.facts(), &[DirectFact]);
}

#[test]
fn direct_client_keeps_recursive_depth_frontiers_incomplete() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/recursive.ts",
            r#"
                function recurse(n: number): number {
                    if (n <= 0) return 0;
                    return recurse(n - 1);
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let limits = IcfgSnapshotLimits::new(2, 10_000, 20_000).unwrap();
    let mut graph = IcfgGraph::materialize_with_limits(
        &project,
        &analyzer,
        "src/recursive.ts",
        PointSelector::new("function recurse")
            .procedure("recurse")
            .effect("entry"),
        limits,
    );
    graph
        .bind_call(
            "recursive_call",
            "src/recursive.ts",
            PointSelector::new("recurse(n - 1)")
                .procedure("recurse")
                .effect("invoke"),
        )
        .bind_node(
            "root",
            "src/recursive.ts",
            PointSelector::new("function recurse")
                .procedure("recurse")
                .effect("entry"),
            CallContextSelector::root(),
        )
        .bind_node(
            "frontier",
            "src/recursive.ts",
            PointSelector::new("recurse(n - 1)")
                .procedure("recurse")
                .effect("invoke"),
            ["recursive_call", "recursive_call"],
        );
    graph.assert_boundary(
        "frontier",
        ExpectedIcfgBoundary::new(ExpectedIcfgBoundaryKind::Limit(IcfgLimitKind::CallDepth))
            .originating_call("recursive_call"),
    );

    let result = solve_direct(graph.solve_input(), graph.node("root"));
    assert_eq!(result.coverage().input_status(), IcfgInputStatus::Unknown);
    assert_eq!(result.termination(), SolverTermination::FixedPoint);
    assert!(result_nodes(&result).contains(&graph.node("frontier")));
    assert!(
        result
            .coverage()
            .boundaries()
            .iter()
            .any(|boundary| boundary.at == graph.node("frontier"))
    );
    assert!(!result.is_complete());
}

#[test]
fn icfg_input_conversion_preserves_budget_exhaustion_and_rejects_missing_snapshots() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("lib.rs", "pub fn root() {}\n")
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = IcfgGraph::materialize(
        &project,
        &analyzer,
        "lib.rs",
        PointSelector::new("pub fn root")
            .procedure("root")
            .effect("entry"),
    );
    graph.bind_node(
        "root",
        "lib.rs",
        PointSelector::new("pub fn root")
            .procedure("root")
            .effect("entry"),
        CallContextSelector::root(),
    );

    let missing = SemanticOutcome::<IcfgSnapshot>::Unknown {
        partial: None,
        work: SemanticWork::default(),
    };
    assert_eq!(
        IcfgSolveInput::from_outcome(&missing).expect_err("missing partial snapshot must fail"),
        DataflowError::MissingIcfgSnapshot {
            status: IcfgInputStatus::Unknown,
        }
    );

    let mut semantic_budget =
        SemanticBudget::new(SemanticWork::uniform(1)).expect("positive semantic limits");
    let exceeded = semantic_budget
        .charge(SemanticWork {
            source_bytes: 2,
            ..SemanticWork::default()
        })
        .expect_err("charge must exceed the one-byte source limit");
    assert_eq!(exceeded.limit(), 1);
    assert_eq!(exceeded.attempted(), 2);
    let status = IcfgInputStatus::ExceededBudget { exceeded };

    let missing_exceeded = SemanticOutcome::<IcfgSnapshot>::ExceededBudget {
        partial: None,
        exceeded,
        work: SemanticWork::default(),
    };
    assert_eq!(
        IcfgSolveInput::from_outcome(&missing_exceeded)
            .expect_err("budget outcome without a partial snapshot must fail"),
        DataflowError::MissingIcfgSnapshot { status }
    );

    let retained = SemanticOutcome::ExceededBudget {
        partial: Some(graph.snapshot().clone()),
        exceeded,
        work: SemanticWork::default(),
    };
    let input =
        IcfgSolveInput::from_outcome(&retained).expect("partial budget outcome is traversable");
    assert_eq!(input.status(), status);
    let result = solve_direct(input, graph.node("root"));
    assert_eq!(result.coverage().input_status(), status);
    assert_eq!(result.termination(), SolverTermination::FixedPoint);
    assert!(!result.is_complete());
}

#[test]
fn completeness_keeps_input_edge_and_boundary_uncertainty_separate() {
    let complete_graph = rust_choose_icfg();
    let root = complete_graph.node("root");
    let complete_result = solve_direct(complete_graph.solve_input(), root);
    assert!(complete_result.is_complete(), "{complete_result:#?}");

    for status in [
        IcfgInputStatus::Ambiguous,
        IcfgInputStatus::Unknown,
        IcfgInputStatus::Unsupported {
            capability: SemanticCapability::ExceptionalControlFlow,
        },
        IcfgInputStatus::Unproven,
        IcfgInputStatus::Cancelled,
    ] {
        let result = solve_direct(IcfgSolveInput::new(complete_graph.snapshot(), status), root);
        assert_eq!(result.coverage().input_status(), status);
        assert_eq!(result.termination(), SolverTermination::FixedPoint);
        assert!(!result.is_complete(), "{status:?} input became complete");
    }

    let partial_project = InlineTestProject::with_language(Language::Rust)
        .file(
            "drop.rs",
            r#"
                struct Guard;
                impl Drop for Guard {
                    fn drop(&mut self) {}
                }

                fn target() {
                    let guard = Guard;
                    let _ = guard;
                }

                pub fn caller() {
                    target();
                }
            "#,
        )
        .build();
    let partial_analyzer = partial_project.workspace_analyzer(AnalyzerConfig::default());
    let mut partial_graph = IcfgGraph::materialize(
        &partial_project,
        &partial_analyzer,
        "drop.rs",
        PointSelector::new("pub fn caller")
            .procedure("caller")
            .effect("entry"),
    );
    partial_graph.bind_node(
        "root",
        "drop.rs",
        PointSelector::new("pub fn caller")
            .procedure("caller")
            .effect("entry"),
        CallContextSelector::root(),
    );
    let partial_result = solve_direct(
        IcfgSolveInput::new(partial_graph.snapshot(), IcfgInputStatus::Complete),
        partial_graph.node("root"),
    );
    assert!(
        !partial_result.coverage().partial_edges().is_empty()
            || !partial_result.coverage().unproven_edges().is_empty(),
        "{partial_result:#?}"
    );
    assert!(!partial_result.is_complete());

    let boundary_graph = rust_deferred_call_icfg();
    let boundary_result = solve_direct(boundary_graph.solve_input(), boundary_graph.node("root"));
    assert_eq!(
        boundary_result.coverage().input_status(),
        IcfgInputStatus::Complete
    );
    assert!(!boundary_result.coverage().boundaries().is_empty());
    assert!(!boundary_result.is_complete());
}

#[test]
fn cancellation_before_and_during_transfer_publishes_no_cancelled_output() {
    let graph = rust_choose_icfg();
    let root = graph.node("root");

    let cancelled = CancellationToken::default();
    cancelled.cancel();
    let mut before_budget = SolverBudget::default();
    let before = solve(
        graph.solve_input(),
        &GeneratingProblem { seed: root },
        &mut DataflowRequest::new(&mut before_budget, &cancelled),
    )
    .expect("cancellation is a normal partial result");
    assert_eq!(before.termination(), SolverTermination::Cancelled);
    assert!(before.facts().is_empty());
    assert!(before.reached().is_empty());
    assert_eq!(before.work(), SolverWork::default());

    let during_token = CancellationToken::default();
    let problem = CancelOnTransferProblem {
        seed: root,
        cancellation: during_token.clone(),
    };
    let mut during_budget = SolverBudget::default();
    let during = solve(
        graph.solve_input(),
        &problem,
        &mut DataflowRequest::new(&mut during_budget, &during_token),
    )
    .expect("cancellation is a normal partial result");
    assert_eq!(during.termination(), SolverTermination::Cancelled);
    assert!(!has_fact(&during, GeneratingFact::Generated));
    assert_eq!(result_nodes(&during), BTreeSet::from([root]));
}

#[test]
fn each_budget_dimension_stops_atomically_before_output_publication() {
    let graph = rust_choose_icfg();
    let root = graph.node("root");
    let problem = GeneratingProblem { seed: root };

    let cancellation = CancellationToken::default();
    let mut complete_budget = SolverBudget::default();
    let complete = solve(
        graph.solve_input(),
        &problem,
        &mut DataflowRequest::new(&mut complete_budget, &cancellation),
    )
    .expect("generating problem is valid");
    assert_eq!(complete.termination(), SolverTermination::FixedPoint);
    assert_eq!(
        reached_nodes_for_fact(&complete, &GeneratingFact::Seed),
        reachable_icfg_nodes(graph.snapshot(), [root]),
        "the distinguished zero fact must survive callbacks that omit it"
    );

    for (dimension, limit, attempted) in [
        (SolverBudgetDimension::InternedFacts, 1, 2),
        (SolverBudgetDimension::ReachedStates, 1, 2),
        (SolverBudgetDimension::FlowEvaluations, 0, 1),
        (SolverBudgetDimension::PropagatedOutputs, 0, 1),
    ] {
        let cancellation = CancellationToken::default();
        let mut budget = budget_with_limit(dimension, limit);
        let result = solve(
            graph.solve_input(),
            &problem,
            &mut DataflowRequest::new(&mut budget, &cancellation),
        )
        .expect("budget exhaustion is a normal partial result");
        let exceeded = result
            .termination()
            .budget_exceeded()
            .expect("targeted budget must stop the solve");

        assert_eq!(exceeded.dimension(), dimension);
        assert_eq!(exceeded.limit(), limit);
        assert_eq!(exceeded.attempted(), attempted);
        assert!(
            !has_fact(&result, GeneratingFact::Generated),
            "{dimension:?} published a staged output: {result:#?}"
        );
        assert_eq!(result_nodes(&result), BTreeSet::from([root]));
        assert_eq!(budget.used(), result.work());
    }
}

#[test]
fn callback_sinks_bound_seed_and_transfer_buffers_before_publication() {
    let graph = rust_choose_icfg();
    let root = graph.node("root");

    let seed_problem = SeedBurstProblem {
        seed: root,
        attempts: Cell::new(0),
    };
    let cancellation = CancellationToken::default();
    let mut seed_budget = budget_with_limit(SolverBudgetDimension::InternedFacts, 1);
    let seed_result = solve(
        graph.solve_input(),
        &seed_problem,
        &mut DataflowRequest::new(&mut seed_budget, &cancellation),
    )
    .expect("seed output exhaustion is a normal result");
    let seed_exceeded = seed_result
        .termination()
        .budget_exceeded()
        .expect("seed sink must stop");
    assert_eq!(
        (
            seed_exceeded.dimension(),
            seed_exceeded.limit(),
            seed_exceeded.attempted(),
        ),
        (SolverBudgetDimension::InternedFacts, 1, 2)
    );
    assert_eq!(seed_problem.attempts.get(), 10);
    assert!(seed_result.facts().is_empty());
    assert!(seed_result.reached().is_empty());
    assert_eq!(seed_budget.used(), SolverWork::default());

    let transfer_problem = TransferBurstProblem {
        seed: root,
        attempts: Cell::new(0),
        cancel_on_stop: None,
    };
    let mut transfer_budget = budget_with_limit(SolverBudgetDimension::PropagatedOutputs, 3);
    let transfer_result = solve(
        graph.solve_input(),
        &transfer_problem,
        &mut DataflowRequest::new(&mut transfer_budget, &cancellation),
    )
    .expect("transfer output exhaustion is a normal result");
    let transfer_exceeded = transfer_result
        .termination()
        .budget_exceeded()
        .expect("transfer sink must stop");
    assert_eq!(
        (
            transfer_exceeded.dimension(),
            transfer_exceeded.limit(),
            transfer_exceeded.attempted(),
        ),
        (SolverBudgetDimension::PropagatedOutputs, 3, 4)
    );
    assert_eq!(transfer_problem.attempts.get(), 10);
    assert_eq!(transfer_result.facts(), &[0]);
    assert_eq!(result_nodes(&transfer_result), BTreeSet::from([root]));
    assert_eq!(transfer_result.work().propagated_outputs, 0);

    let cross_dimension_problem = TransferBurstProblem {
        seed: root,
        attempts: Cell::new(0),
        cancel_on_stop: None,
    };
    let mut cross_dimension_budget = budget_with_limit(SolverBudgetDimension::InternedFacts, 1);
    let cross_dimension_result = solve(
        graph.solve_input(),
        &cross_dimension_problem,
        &mut DataflowRequest::new(&mut cross_dimension_budget, &cancellation),
    )
    .expect("cross-dimension output exhaustion is a normal result");
    let cross_dimension_exceeded = cross_dimension_result
        .termination()
        .budget_exceeded()
        .expect("the tighter fact limit must stop the transfer sink");
    assert_eq!(
        (
            cross_dimension_exceeded.dimension(),
            cross_dimension_exceeded.limit(),
            cross_dimension_exceeded.attempted(),
        ),
        (SolverBudgetDimension::InternedFacts, 1, 2)
    );
    assert_eq!(cross_dimension_problem.attempts.get(), 10);
    assert_eq!(cross_dimension_result.facts(), &[0]);
    assert_eq!(
        result_nodes(&cross_dimension_result),
        BTreeSet::from([root])
    );
}

#[test]
fn cancellation_after_sink_exhaustion_takes_precedence() {
    let graph = rust_choose_icfg();
    let cancellation = CancellationToken::default();
    let problem = TransferBurstProblem {
        seed: graph.node("root"),
        attempts: Cell::new(0),
        cancel_on_stop: Some(cancellation.clone()),
    };
    let mut budget = budget_with_limit(SolverBudgetDimension::PropagatedOutputs, 3);
    let result = solve(
        graph.solve_input(),
        &problem,
        &mut DataflowRequest::new(&mut budget, &cancellation),
    )
    .expect("cancellation is a normal partial result");

    assert_eq!(problem.attempts.get(), 10);
    assert_eq!(result.termination(), SolverTermination::Cancelled);
    assert_eq!(result.work().propagated_outputs, 0);
}
