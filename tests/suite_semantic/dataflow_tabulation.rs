use std::cmp::Ordering;
use std::collections::BTreeSet;

use brokk_bifrost::analyzer::dataflow::{
    BoundedSnapshotDataflowProblem, DataflowEdge, DataflowError, DataflowOutput, DataflowRequest,
    DataflowResult, DataflowSeed, DirectFlowProblem, DistributiveDataflowProblem, IcfgSolveInput,
    SolverBudget, SolverBudgetDimension, SolverWork, solve,
};
use brokk_bifrost::analyzer::semantic::{
    CancellationToken, ControlEdgeKind, IcfgEdgeKind, IcfgNodeId, IcfgSnapshot,
};
use brokk_bifrost::{AnalyzerConfig, Language};

use crate::common::{
    InlineTestProject,
    dataflow_reference::reference_solve,
    dataflow_regression::{RegressionIcfg, RegressionMutation, RegressionScenario},
    semantic_graph::{CallContextSelector, IcfgGraph, PointSelector},
};
use crate::dataflow_fixtures::{rust_choose_icfg, rust_deferred_call_icfg};

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

    fn normal_flow(
        &self,
        edge: DataflowEdge<'_, Self::Fact>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        let marker = match edge.kind() {
            IcfgEdgeKind::Intraprocedural(ControlEdgeKind::Cleanup) => MarkerFact::CleanupNormal,
            _ => MarkerFact::Normal,
        };
        Self::emit(fact, marker, out);
    }

    fn call_flow(
        &self,
        _edge: DataflowEdge<'_, Self::Fact>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        Self::emit(fact, MarkerFact::Call, out);
    }

    fn return_flow(
        &self,
        edge: DataflowEdge<'_, Self::Fact>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        let marker = match edge.kind() {
            IcfgEdgeKind::NormalReturn => MarkerFact::NormalReturn,
            IcfgEdgeKind::ExceptionalReturn => MarkerFact::ExceptionalReturn,
            kind => panic!("return callback received {kind:?}"),
        };
        Self::emit(fact, marker, out);
    }

    fn call_to_return_flow(
        &self,
        edge: DataflowEdge<'_, Self::Fact>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        let marker = match edge.kind() {
            IcfgEdgeKind::CallToNormalContinuation => MarkerFact::CallToNormalReturn,
            IcfgEdgeKind::CallToExceptionalContinuation => MarkerFact::CallToExceptionalReturn,
            kind => panic!("call-to-return callback received {kind:?}"),
        };
        Self::emit(fact, marker, out);
    }

    fn exceptional_flow(
        &self,
        edge: DataflowEdge<'_, Self::Fact>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        let marker = match edge.kind() {
            IcfgEdgeKind::Intraprocedural(ControlEdgeKind::Cleanup) => {
                MarkerFact::CleanupExceptional
            }
            _ => MarkerFact::Exceptional,
        };
        Self::emit(fact, marker, out);
    }
}

impl BoundedSnapshotDataflowProblem for MarkerProblem {
    fn seeds(&self, out: &mut dyn DataflowOutput<DataflowSeed<Self::Fact>>) {
        let _ = out.emit(DataflowSeed::new(self.seed, MarkerFact::Seed));
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

    fn normal_flow(
        &self,
        _edge: DataflowEdge<'_, Self::Fact>,
        _fact: Self::Fact,
        _out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
    }

    fn call_flow(
        &self,
        _edge: DataflowEdge<'_, Self::Fact>,
        _fact: Self::Fact,
        _out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
    }

    fn return_flow(
        &self,
        _edge: DataflowEdge<'_, Self::Fact>,
        _fact: Self::Fact,
        _out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
    }

    fn call_to_return_flow(
        &self,
        _edge: DataflowEdge<'_, Self::Fact>,
        _fact: Self::Fact,
        _out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
    }

    fn exceptional_flow(
        &self,
        _edge: DataflowEdge<'_, Self::Fact>,
        _fact: Self::Fact,
        _out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
    }
}

impl BoundedSnapshotDataflowProblem for KillProblem {
    fn seeds(&self, out: &mut dyn DataflowOutput<DataflowSeed<Self::Fact>>) {
        let _ = out.emit(DataflowSeed::new(self.seed, KillFact::Live));
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

    fn normal_flow(
        &self,
        _edge: DataflowEdge<'_, Self::Fact>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.transfer(fact, out);
    }

    fn call_flow(
        &self,
        _edge: DataflowEdge<'_, Self::Fact>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.transfer(fact, out);
    }

    fn return_flow(
        &self,
        _edge: DataflowEdge<'_, Self::Fact>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.transfer(fact, out);
    }

    fn call_to_return_flow(
        &self,
        _edge: DataflowEdge<'_, Self::Fact>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.transfer(fact, out);
    }

    fn exceptional_flow(
        &self,
        _edge: DataflowEdge<'_, Self::Fact>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.transfer(fact, out);
    }
}

impl BoundedSnapshotDataflowProblem for PermutedProblem {
    fn seeds(&self, out: &mut dyn DataflowOutput<DataflowSeed<Self::Fact>>) {
        for seed in self.seeds.iter().copied() {
            if !out.emit(seed) {
                break;
            }
        }
    }
}

fn solve_default<P>(input: IcfgSolveInput<'_>, problem: &P) -> DataflowResult<P::Fact>
where
    P: BoundedSnapshotDataflowProblem,
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
    P: BoundedSnapshotDataflowProblem,
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
fn constrained_output_permutations_report_the_same_budget_dimension() {
    let graph = rust_choose_icfg();
    let root = graph.node("root");
    let forward = PermutedProblem {
        seeds: vec![DataflowSeed::new(root, PermutedFact::Zero)],
        reverse_outputs: false,
    };
    let reverse = PermutedProblem {
        seeds: forward.seeds.clone(),
        reverse_outputs: true,
    };
    // Zero is already interned while Alpha and Beta are new. A streaming
    // multidimensional preflight would therefore report different dimensions
    // depending on which end of this relation arrives first.
    let limits = SolverWork {
        interned_facts: 2,
        propagated_outputs: 1,
        ..SolverWork::uniform(usize::MAX)
    };

    let solve_constrained = |problem: &PermutedProblem| {
        let cancellation = CancellationToken::default();
        let mut budget = SolverBudget::new(limits);
        solve(
            graph.solve_input(),
            problem,
            &mut DataflowRequest::new(&mut budget, &cancellation),
        )
        .expect("budget exhaustion is a normal partial result")
    };
    let forward_result = solve_constrained(&forward);
    let reverse_result = solve_constrained(&reverse);

    assert_eq!(forward_result, reverse_result);
    let exceeded = forward_result
        .termination()
        .budget_exceeded()
        .expect("the canonical relation must exceed the remaining fact slot");
    assert_eq!(
        (exceeded.dimension(), exceeded.limit(), exceeded.attempted(),),
        (SolverBudgetDimension::InternedFacts, 2, 3)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum FamilyFactLabel {
    Zero,
    Alpha,
    Beta,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FamilyFact {
    label: FamilyFactLabel,
    rank: u8,
}

impl Ord for FamilyFact {
    fn cmp(&self, other: &Self) -> Ordering {
        self.rank
            .cmp(&other.rank)
            .then_with(|| self.label.cmp(&other.label))
    }
}

impl PartialOrd for FamilyFact {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

struct FamilyProblem {
    seeds: Vec<DataflowSeed<FamilyFact>>,
    facts: [FamilyFact; 3],
    reverse_outputs: bool,
}

impl FamilyProblem {
    fn transfer(&self, fact: FamilyFact, out: &mut dyn DataflowOutput<FamilyFact>) {
        let mut outputs = vec![fact, self.facts[1], self.facts[2]];
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

impl DistributiveDataflowProblem for FamilyProblem {
    type Fact = FamilyFact;

    fn zero_fact(&self) -> Self::Fact {
        self.facts[0]
    }

    fn normal_flow(
        &self,
        _edge: DataflowEdge<'_, Self::Fact>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.transfer(fact, out);
    }

    fn call_flow(
        &self,
        _edge: DataflowEdge<'_, Self::Fact>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.transfer(fact, out);
    }

    fn return_flow(
        &self,
        _edge: DataflowEdge<'_, Self::Fact>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.transfer(fact, out);
    }

    fn call_to_return_flow(
        &self,
        _edge: DataflowEdge<'_, Self::Fact>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.transfer(fact, out);
    }

    fn exceptional_flow(
        &self,
        _edge: DataflowEdge<'_, Self::Fact>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.transfer(fact, out);
    }
}

impl BoundedSnapshotDataflowProblem for FamilyProblem {
    fn seeds(&self, out: &mut dyn DataflowOutput<DataflowSeed<Self::Fact>>) {
        for seed in self.seeds.iter().copied() {
            if !out.emit(seed) {
                break;
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct FamilyVariant {
    name: &'static str,
    reverse_edges: bool,
    reverse_seeds: bool,
    reverse_facts: bool,
    reverse_outputs: bool,
}

const FAMILY_VARIANTS: [FamilyVariant; 5] = [
    FamilyVariant {
        name: "baseline",
        reverse_edges: false,
        reverse_seeds: false,
        reverse_facts: false,
        reverse_outputs: false,
    },
    FamilyVariant {
        name: "seed_order",
        reverse_edges: false,
        reverse_seeds: true,
        reverse_facts: false,
        reverse_outputs: false,
    },
    FamilyVariant {
        name: "edge_order",
        reverse_edges: true,
        reverse_seeds: false,
        reverse_facts: false,
        reverse_outputs: false,
    },
    FamilyVariant {
        name: "fact_interning_order",
        reverse_edges: false,
        reverse_seeds: false,
        reverse_facts: true,
        reverse_outputs: false,
    },
    FamilyVariant {
        name: "worklist_discovery_order",
        reverse_edges: true,
        reverse_seeds: true,
        reverse_facts: true,
        reverse_outputs: true,
    },
];

fn family_problem(graph: &RegressionIcfg, variant: FamilyVariant) -> FamilyProblem {
    let facts = if variant.reverse_facts {
        [
            FamilyFact {
                label: FamilyFactLabel::Zero,
                rank: 2,
            },
            FamilyFact {
                label: FamilyFactLabel::Alpha,
                rank: 1,
            },
            FamilyFact {
                label: FamilyFactLabel::Beta,
                rank: 0,
            },
        ]
    } else {
        [
            FamilyFact {
                label: FamilyFactLabel::Zero,
                rank: 0,
            },
            FamilyFact {
                label: FamilyFactLabel::Alpha,
                rank: 1,
            },
            FamilyFact {
                label: FamilyFactLabel::Beta,
                rank: 2,
            },
        ]
    };
    let mut seeds = vec![
        DataflowSeed::new(graph.root_entry_node(), facts[1]),
        DataflowSeed::new(graph.alternate_seed_node(), facts[2]),
    ];
    if variant.reverse_seeds {
        seeds.reverse();
    }
    FamilyProblem {
        seeds,
        facts,
        reverse_outputs: variant.reverse_outputs,
    }
}

fn family_projection(
    graph: &RegressionIcfg,
    result: &DataflowResult<FamilyFact>,
) -> BTreeSet<(String, FamilyFactLabel)> {
    result
        .reached()
        .iter()
        .map(|row| {
            let fact = result.fact(row.fact()).expect("family fact resolves");
            (graph.node_label(row.node()).to_owned(), fact.label)
        })
        .collect()
}

#[test]
fn deterministic_language_neutral_family_matches_reference_and_metamorphic_variants() {
    for scenario in RegressionScenario::ALL {
        let mut expected = None;
        for variant in FAMILY_VARIANTS {
            let graph = RegressionIcfg::new(
                scenario,
                RegressionMutation {
                    reverse_edges: variant.reverse_edges,
                    reverse_provider_rows: false,
                },
            );
            let problem = family_problem(&graph, variant);
            let outcome = graph.snapshot_outcome();
            let input = IcfgSolveInput::from_outcome(&outcome).expect("complete family snapshot");
            let first = solve_default(input, &problem);
            let second = solve_default(input, &problem);
            assert_eq!(first, second, "{} / {}", scenario.name(), variant.name);
            assert!(
                first.is_complete(),
                "{} / {}",
                scenario.name(),
                variant.name
            );

            let production = family_projection(&graph, &first);
            let reference = reference_solve(graph.snapshot(), &problem)
                .expect("family reference solve")
                .reached()
                .iter()
                .map(|(node, fact)| (graph.node_label(*node).to_owned(), fact.label))
                .collect::<BTreeSet<_>>();
            assert_eq!(
                production,
                reference,
                "{} / {}",
                scenario.name(),
                variant.name
            );
            if let Some(expected) = &expected {
                assert_eq!(
                    &production,
                    expected,
                    "{} / {}",
                    scenario.name(),
                    variant.name
                );
            } else {
                expected = Some(production);
            }
        }
    }
}

#[test]
fn deterministic_family_low_budget_is_typed_incomplete_evidence() {
    let graph = RegressionIcfg::new(
        RegressionScenario::DiamondJoin,
        RegressionMutation::default(),
    );
    let problem = family_problem(&graph, FAMILY_VARIANTS[0]);
    let outcome = graph.snapshot_outcome();
    let input = IcfgSolveInput::from_outcome(&outcome).expect("complete family snapshot");
    let complete = solve_default(input, &problem);
    assert!(complete.is_complete());

    let mut limits = SolverWork::uniform(usize::MAX);
    limits.propagated_outputs = complete.work().propagated_outputs.saturating_sub(1);
    let cancellation = CancellationToken::default();
    let mut budget = SolverBudget::new(limits);
    let partial = solve(
        input,
        &problem,
        &mut DataflowRequest::new(&mut budget, &cancellation),
    )
    .expect("budget exhaustion is a typed result");
    let exceeded = partial
        .termination()
        .budget_exceeded()
        .expect("exact low budget terminates incompletely");
    assert_eq!(
        exceeded.dimension(),
        SolverBudgetDimension::PropagatedOutputs
    );
    assert!(!partial.is_complete());
    assert!(
        family_projection(&graph, &partial).is_subset(&family_projection(&graph, &complete)),
        "partial reachability is evidence, never a clean negative"
    );
}
