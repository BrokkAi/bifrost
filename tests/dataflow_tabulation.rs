mod common;
#[path = "common/dataflow_fixtures.rs"]
mod dataflow_fixtures;

use std::collections::BTreeSet;

use brokk_bifrost::analyzer::dataflow::{
    DataflowEdge, DataflowError, DataflowOutput, DataflowRequest, DataflowResult, DataflowSeed,
    DirectFlowProblem, DistributiveDataflowProblem, IcfgSolveInput, SolverBudget, solve,
};
use brokk_bifrost::analyzer::semantic::{
    CancellationToken, ControlEdgeKind, IcfgEdgeKind, IcfgNodeId, IcfgSnapshot,
};
use brokk_bifrost::{AnalyzerConfig, Language};

use common::{
    InlineTestProject,
    dataflow_reference::reference_solve,
    semantic_graph::{CallContextSelector, IcfgGraph, PointSelector},
};
use dataflow_fixtures::{rust_choose_icfg, rust_deferred_call_icfg};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum MarkerFact {
    Zero,
    Seed,
    Normal,
    Call,
    NormalReturn,
    ExceptionalReturn,
    CallToNormalReturn,
    CallToExceptionalReturn,
    Exceptional,
    CleanupNormal,
    CleanupExceptional,
}

struct MarkerProblem {
    seed: IcfgNodeId,
}

impl MarkerProblem {
    fn emit(fact: MarkerFact, marker: MarkerFact, out: &mut dyn DataflowOutput<MarkerFact>) {
        if out.emit(fact) {
            let _ = out.emit(marker);
        }
    }
}

impl DistributiveDataflowProblem for MarkerProblem {
    type Fact = MarkerFact;

    fn zero_fact(&self) -> Self::Fact {
        MarkerFact::Zero
    }

    fn seeds(&self, out: &mut dyn DataflowOutput<DataflowSeed<Self::Fact>>) {
        let _ = out.emit(DataflowSeed::new(self.seed, MarkerFact::Seed));
    }

    fn normal_flow(
        &self,
        edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        let marker = match edge.edge().kind {
            IcfgEdgeKind::Intraprocedural(ControlEdgeKind::Cleanup) => MarkerFact::CleanupNormal,
            _ => MarkerFact::Normal,
        };
        Self::emit(fact, marker, out);
    }

    fn call_flow(
        &self,
        _edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        Self::emit(fact, MarkerFact::Call, out);
    }

    fn return_flow(
        &self,
        edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        let marker = match edge.edge().kind {
            IcfgEdgeKind::NormalReturn => MarkerFact::NormalReturn,
            IcfgEdgeKind::ExceptionalReturn => MarkerFact::ExceptionalReturn,
            kind => panic!("return callback received {kind:?}"),
        };
        Self::emit(fact, marker, out);
    }

    fn call_to_return_flow(
        &self,
        edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        let marker = match edge.edge().kind {
            IcfgEdgeKind::CallToNormalContinuation => MarkerFact::CallToNormalReturn,
            IcfgEdgeKind::CallToExceptionalContinuation => MarkerFact::CallToExceptionalReturn,
            kind => panic!("call-to-return callback received {kind:?}"),
        };
        Self::emit(fact, marker, out);
    }

    fn exceptional_flow(
        &self,
        edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        let marker = match edge.edge().kind {
            IcfgEdgeKind::Intraprocedural(ControlEdgeKind::Cleanup) => {
                MarkerFact::CleanupExceptional
            }
            _ => MarkerFact::Exceptional,
        };
        Self::emit(fact, marker, out);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum KillFact {
    Zero,
    Live,
}

struct KillProblem {
    seed: IcfgNodeId,
}

impl DistributiveDataflowProblem for KillProblem {
    type Fact = KillFact;

    fn zero_fact(&self) -> Self::Fact {
        KillFact::Zero
    }

    fn seeds(&self, out: &mut dyn DataflowOutput<DataflowSeed<Self::Fact>>) {
        let _ = out.emit(DataflowSeed::new(self.seed, KillFact::Live));
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum PermutedFact {
    Zero,
    Seed,
    Alpha,
    Beta,
}

struct PermutedProblem {
    seeds: Vec<DataflowSeed<PermutedFact>>,
    reverse_outputs: bool,
}

impl PermutedProblem {
    fn transfer(&self, fact: PermutedFact, out: &mut dyn DataflowOutput<PermutedFact>) {
        let mut outputs = vec![fact, PermutedFact::Alpha, PermutedFact::Beta];
        if self.reverse_outputs {
            outputs.reverse();
        }
        for output in outputs {
            if !out.emit(output) {
                break;
            }
        }
    }
}

impl DistributiveDataflowProblem for PermutedProblem {
    type Fact = PermutedFact;

    fn zero_fact(&self) -> Self::Fact {
        PermutedFact::Zero
    }

    fn seeds(&self, out: &mut dyn DataflowOutput<DataflowSeed<Self::Fact>>) {
        for seed in self.seeds.iter().copied() {
            if !out.emit(seed) {
                break;
            }
        }
    }

    fn normal_flow(
        &self,
        _edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.transfer(fact, out);
    }

    fn call_flow(
        &self,
        _edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.transfer(fact, out);
    }

    fn return_flow(
        &self,
        _edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.transfer(fact, out);
    }

    fn call_to_return_flow(
        &self,
        _edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.transfer(fact, out);
    }

    fn exceptional_flow(
        &self,
        _edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.transfer(fact, out);
    }
}

fn solve_default<P>(input: IcfgSolveInput<'_>, problem: &P) -> DataflowResult<P::Fact>
where
    P: DistributiveDataflowProblem,
{
    let cancellation = CancellationToken::default();
    let mut budget = SolverBudget::default();
    solve(
        input,
        problem,
        &mut DataflowRequest::new(&mut budget, &cancellation),
    )
    .expect("valid data-flow fixture")
}

fn reached_facts<F>(result: &DataflowResult<F>) -> BTreeSet<(IcfgNodeId, F)>
where
    F: Copy + Ord,
{
    result
        .reached()
        .iter()
        .map(|reached| {
            let fact = *result
                .fact(reached.fact())
                .expect("reached fact ID must resolve in the result");
            (reached.node(), fact)
        })
        .collect()
}

fn assert_matches_reference<P>(graph: &IcfgGraph, problem: &P) -> DataflowResult<P::Fact>
where
    P: DistributiveDataflowProblem,
    P::Fact: std::fmt::Debug,
{
    let optimized = solve_default(graph.solve_input(), problem);
    let reference =
        reference_solve(graph.snapshot(), problem).expect("reference fixture must be valid");
    assert_eq!(reached_facts(&optimized), *reference.reached());
    optimized
}

fn contains_fact<F: PartialEq>(result: &DataflowResult<F>, expected: F) -> bool {
    result.facts().contains(&expected)
}

fn edge_is(snapshot: &IcfgSnapshot, expected: IcfgEdgeKind) -> bool {
    snapshot.edges().iter().any(|edge| edge.kind == expected)
}

#[test]
fn worklist_matches_reference_across_call_return_and_exceptional_edges() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/families.ts",
            r#"
                function leaf(value: number): number {
                    return value;
                }

                function fail(error: Error): never {
                    throw error;
                }

                function caller(error: Error): number {
                    const first = leaf(1);
                    const second = leaf(2);
                    try {
                        fail(error);
                        return first + second;
                    } catch {
                        return -1;
                    }
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = IcfgGraph::materialize(
        &project,
        &analyzer,
        "src/families.ts",
        PointSelector::new("function caller")
            .procedure("caller")
            .effect("entry"),
    );
    graph.bind_node(
        "root",
        "src/families.ts",
        PointSelector::new("function caller")
            .procedure("caller")
            .effect("entry"),
        CallContextSelector::root(),
    );

    let snapshot = graph.snapshot();
    assert!(edge_is(snapshot, IcfgEdgeKind::Call));
    assert!(edge_is(snapshot, IcfgEdgeKind::NormalReturn));
    assert!(edge_is(snapshot, IcfgEdgeKind::ExceptionalReturn));
    assert!(edge_is(
        snapshot,
        IcfgEdgeKind::Intraprocedural(ControlEdgeKind::Exceptional)
    ));

    let result = assert_matches_reference(
        &graph,
        &MarkerProblem {
            seed: graph.node("root"),
        },
    );
    for marker in [
        MarkerFact::Normal,
        MarkerFact::Call,
        MarkerFact::NormalReturn,
        MarkerFact::ExceptionalReturn,
        MarkerFact::Exceptional,
    ] {
        assert!(
            contains_fact(&result, marker),
            "callback marker {marker:?} was not reached"
        );
    }
}

#[test]
fn worklist_matches_reference_for_deferred_call_to_return_edges() {
    let graph = rust_deferred_call_icfg();

    assert!(edge_is(
        graph.snapshot(),
        IcfgEdgeKind::CallToNormalContinuation
    ));
    assert!(edge_is(
        graph.snapshot(),
        IcfgEdgeKind::CallToExceptionalContinuation
    ));

    let result = assert_matches_reference(
        &graph,
        &MarkerProblem {
            seed: graph.node("root"),
        },
    );
    assert!(contains_fact(&result, MarkerFact::CallToNormalReturn));
    assert!(contains_fact(&result, MarkerFact::CallToExceptionalReturn));
}

#[test]
fn cleanup_edges_use_normal_flow_and_loops_reach_a_reference_fixed_point() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/cleanup.ts",
            r#"
                function cleanup(flag: boolean, count: number): number {
                    while (count > 0) {
                        count -= 1;
                    }
                    try {
                        if (flag) return count;
                    } finally {
                        flag = false;
                    }
                    return count + 1;
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = IcfgGraph::materialize(
        &project,
        &analyzer,
        "src/cleanup.ts",
        PointSelector::new("function cleanup")
            .procedure("cleanup")
            .effect("entry"),
    );
    graph.bind_node(
        "root",
        "src/cleanup.ts",
        PointSelector::new("function cleanup")
            .procedure("cleanup")
            .effect("entry"),
        CallContextSelector::root(),
    );

    assert!(edge_is(
        graph.snapshot(),
        IcfgEdgeKind::Intraprocedural(ControlEdgeKind::LoopBack)
    ));
    assert!(edge_is(
        graph.snapshot(),
        IcfgEdgeKind::Intraprocedural(ControlEdgeKind::Cleanup)
    ));

    let result = assert_matches_reference(
        &graph,
        &MarkerProblem {
            seed: graph.node("root"),
        },
    );
    assert!(contains_fact(&result, MarkerFact::CleanupNormal));
    assert!(!contains_fact(&result, MarkerFact::CleanupExceptional));
}

#[test]
fn seed_and_transfer_output_permutations_have_identical_results() {
    let graph = rust_choose_icfg();

    let root = graph.node("root");
    let second = graph
        .snapshot()
        .node_ids()
        .find(|node| *node != root)
        .expect("branching fixture must contain another node");
    let forward = PermutedProblem {
        seeds: vec![
            DataflowSeed::new(root, PermutedFact::Seed),
            DataflowSeed::new(second, PermutedFact::Alpha),
        ],
        reverse_outputs: false,
    };
    let reverse = PermutedProblem {
        seeds: forward.seeds.iter().copied().rev().collect(),
        reverse_outputs: true,
    };

    let forward_result = solve_default(graph.solve_input(), &forward);
    let reverse_result = solve_default(graph.solve_input(), &reverse);
    assert_eq!(forward_result, reverse_result);
    assert_eq!(
        reached_facts(&forward_result),
        *reference_solve(graph.snapshot(), &forward)
            .expect("reference solve")
            .reached()
    );
}

#[test]
fn nonzero_facts_can_be_killed_while_zero_remains_on_every_path() {
    let graph = rust_choose_icfg();

    let root = graph.node("root");
    let result = assert_matches_reference(&graph, &KillProblem { seed: root });
    let reached = reached_facts(&result);
    let zero_nodes = reached
        .iter()
        .filter_map(|(node, fact)| (*fact == KillFact::Zero).then_some(*node))
        .collect::<BTreeSet<_>>();
    let live_nodes = reached
        .iter()
        .filter_map(|(node, fact)| (*fact == KillFact::Live).then_some(*node))
        .collect::<BTreeSet<_>>();

    assert_eq!(
        zero_nodes.len(),
        graph.snapshot().node_count(),
        "the distinguished zero fact must be preserved by the kernel"
    );
    assert_eq!(
        live_nodes,
        BTreeSet::from([root]),
        "a seeded nonzero fact omitted by transfer callbacks must be killed"
    );
}

#[test]
fn invalid_seed_nodes_are_rejected_before_propagation() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("lib.rs", "pub fn root() {}\n")
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = IcfgGraph::materialize(
        &project,
        &analyzer,
        "lib.rs",
        PointSelector::new("pub fn root")
            .procedure("root")
            .effect("entry"),
    );
    let invalid =
        IcfgNodeId::new(u32::try_from(graph.snapshot().node_count()).expect("small fixture") + 1);
    let problem = DirectFlowProblem::new([invalid]);
    let cancellation = CancellationToken::default();
    let mut budget = SolverBudget::default();
    let error = solve(
        graph.solve_input(),
        &problem,
        &mut DataflowRequest::new(&mut budget, &cancellation),
    )
    .expect_err("invalid seed must be rejected");

    assert!(matches!(
        error,
        DataflowError::InvalidSeedNode { node, .. } if node == invalid
    ));
}
