mod common;

use std::{cell::Cell, collections::HashMap, rc::Rc};

use brokk_bifrost::analyzer::dataflow::{
    DataflowEdge, DataflowOutput, DataflowRequest, IdeDataflowProblem, IdeDataflowSeed,
    IdeSummaryDataflowResult, IdeSummarySolveInput, IdeTransition, SolverBudget,
    SolverBudgetDimension, SolverTermination, SolverWork, WitnessRetentionLimits,
    solve_ide_with_summaries,
};
use brokk_bifrost::analyzer::semantic::{
    CancellationToken, ControlEdgeKind, IcfgEdgeKind, SemanticBudget,
};
use brokk_bifrost::{AnalyzerConfig, Language};

use common::{
    InlineTestProject,
    dataflow_ide_reference::reference_ide_projection,
    semantic_graph::{PointSelector, resolve_procedure_handle},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum QualifierFact {
    Zero,
    Tracked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
enum Qualifier {
    Bottom,
    Clean,
    Dirty,
    Top,
}

impl Qualifier {
    const ALL: [Self; 4] = [Self::Bottom, Self::Clean, Self::Dirty, Self::Top];

    const fn index(self) -> usize {
        self as usize
    }
}

/// A complete finite lookup table makes every algebra operation closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct QualifierFunction([Qualifier; 4]);

impl QualifierFunction {
    const IDENTITY: Self = Self(Qualifier::ALL);
    const PROMOTE: Self = Self([
        Qualifier::Bottom,
        Qualifier::Dirty,
        Qualifier::Top,
        Qualifier::Top,
    ]);

    const fn constant(value: Qualifier) -> Self {
        Self([value; 4])
    }

    fn apply(self, value: Qualifier) -> Qualifier {
        self.0[value.index()]
    }
}

#[derive(Default)]
struct QualifierProblem {
    cancel_on_composition: Option<CancellationToken>,
    duplicate_normal_outputs: bool,
    edge_function_meets: Option<Rc<Cell<usize>>>,
}

impl QualifierProblem {
    fn preserve(
        fact: QualifierFact,
        function: QualifierFunction,
        out: &mut dyn DataflowOutput<IdeTransition<QualifierFact, QualifierFunction>>,
    ) {
        if fact == QualifierFact::Tracked {
            let _ = out.emit(IdeTransition::new(fact, function));
        }
    }
}

impl IdeDataflowProblem for QualifierProblem {
    type Fact = QualifierFact;
    type Value = Qualifier;
    type EdgeFunction = QualifierFunction;

    fn zero_fact(&self) -> Self::Fact {
        QualifierFact::Zero
    }

    fn zero_value(&self) -> Self::Value {
        Qualifier::Bottom
    }

    fn identity_edge_function(&self) -> Self::EdgeFunction {
        QualifierFunction::IDENTITY
    }

    fn meet_values(&self, left: &Self::Value, right: &Self::Value) -> Self::Value {
        (*left).max(*right)
    }

    fn compose_edge_functions(
        &self,
        first: &Self::EdgeFunction,
        second: &Self::EdgeFunction,
    ) -> Self::EdgeFunction {
        if let Some(cancellation) = &self.cancel_on_composition {
            cancellation.cancel();
        }
        QualifierFunction(first.0.map(|value| second.apply(value)))
    }

    fn apply_edge_function(
        &self,
        function: &Self::EdgeFunction,
        value: &Self::Value,
    ) -> Self::Value {
        function.apply(*value)
    }

    fn meet_edge_functions(
        &self,
        left: &Self::EdgeFunction,
        right: &Self::EdgeFunction,
    ) -> Self::EdgeFunction {
        if let Some(meets) = &self.edge_function_meets {
            meets.set(meets.get().saturating_add(1));
        }
        QualifierFunction(std::array::from_fn(|index| {
            left.0[index].max(right.0[index])
        }))
    }

    fn normal_flow(
        &self,
        edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<IdeTransition<Self::Fact, Self::EdgeFunction>>,
    ) {
        let function = match edge.kind() {
            IcfgEdgeKind::Intraprocedural(ControlEdgeKind::ConditionalTrue) => {
                QualifierFunction::constant(Qualifier::Clean)
            }
            IcfgEdgeKind::Intraprocedural(ControlEdgeKind::ConditionalFalse) => {
                QualifierFunction::constant(Qualifier::Dirty)
            }
            _ => QualifierFunction::IDENTITY,
        };
        Self::preserve(fact, function, out);
        if self.duplicate_normal_outputs {
            Self::preserve(fact, QualifierFunction::constant(Qualifier::Top), out);
        }
    }

    fn call_flow(
        &self,
        _edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<IdeTransition<Self::Fact, Self::EdgeFunction>>,
    ) {
        Self::preserve(fact, QualifierFunction::constant(Qualifier::Dirty), out);
    }

    fn return_flow(
        &self,
        edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<IdeTransition<Self::Fact, Self::EdgeFunction>>,
    ) {
        let function = match edge.kind() {
            IcfgEdgeKind::NormalReturn => QualifierFunction::PROMOTE,
            IcfgEdgeKind::ExceptionalReturn => QualifierFunction::constant(Qualifier::Clean),
            kind => panic!("return callback received {kind:?}"),
        };
        Self::preserve(fact, function, out);
    }

    fn call_to_return_flow(
        &self,
        _edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<IdeTransition<Self::Fact, Self::EdgeFunction>>,
    ) {
        Self::preserve(fact, QualifierFunction::constant(Qualifier::Dirty), out);
    }

    fn exceptional_flow(
        &self,
        _edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<IdeTransition<Self::Fact, Self::EdgeFunction>>,
    ) {
        Self::preserve(fact, QualifierFunction::constant(Qualifier::Top), out);
    }
}

type QualifierResult = IdeSummaryDataflowResult<QualifierFact, Qualifier, QualifierFunction>;

fn value_at(
    result: &QualifierResult,
    point: &brokk_bifrost::analyzer::semantic::ProgramPointHandle,
    fact: QualifierFact,
) -> Qualifier {
    let row = result
        .point_values()
        .iter()
        .find(|row| {
            row.point() == point && result.fact_result().fact(row.fact()).copied() == Some(fact)
        })
        .expect("requested root IDE point value exists");
    *result
        .value(row.value())
        .expect("point-value ID resolves in its result")
}

fn point_value_projection(
    result: &QualifierResult,
) -> HashMap<
    (
        brokk_bifrost::analyzer::semantic::ProgramPointHandle,
        QualifierFact,
    ),
    Qualifier,
> {
    result
        .point_values()
        .iter()
        .map(|row| {
            let fact = result
                .fact_result()
                .fact(row.fact())
                .copied()
                .expect("point-value fact ID resolves");
            let value = result
                .value(row.value())
                .copied()
                .expect("point-value value ID resolves");
            ((row.point().clone(), fact), value)
        })
        .collect()
}

fn ide_dimension_work(work: SolverWork, dimension: SolverBudgetDimension) -> usize {
    match dimension {
        SolverBudgetDimension::IdeRelations => work.ide_relations,
        SolverBudgetDimension::EdgeFunctions => work.edge_functions,
        SolverBudgetDimension::EdgeFunctionOperations => work.edge_function_operations,
        SolverBudgetDimension::IdeValues => work.ide_values,
        SolverBudgetDimension::ValueOperations => work.value_operations,
        _ => panic!("{dimension:?} is not IDE-specific"),
    }
}

fn set_ide_dimension_limit(work: &mut SolverWork, dimension: SolverBudgetDimension, limit: usize) {
    match dimension {
        SolverBudgetDimension::IdeRelations => work.ide_relations = limit,
        SolverBudgetDimension::EdgeFunctions => work.edge_functions = limit,
        SolverBudgetDimension::EdgeFunctionOperations => work.edge_function_operations = limit,
        SolverBudgetDimension::IdeValues => work.ide_values = limit,
        SolverBudgetDimension::ValueOperations => work.value_operations = limit,
        _ => panic!("{dimension:?} is not IDE-specific"),
    }
}

fn solve(
    root: &brokk_bifrost::analyzer::semantic::ProcedureHandle,
    provider: &impl brokk_bifrost::analyzer::semantic::IcfgProvider,
) -> QualifierResult {
    let cancellation = CancellationToken::default();
    let mut solver_budget = SolverBudget::default();
    solve_with_controls(root, provider, &mut solver_budget, &cancellation)
}

fn solve_with_controls(
    root: &brokk_bifrost::analyzer::semantic::ProcedureHandle,
    provider: &impl brokk_bifrost::analyzer::semantic::IcfgProvider,
    solver_budget: &mut SolverBudget,
    cancellation: &CancellationToken,
) -> QualifierResult {
    let mut semantic_budget = SemanticBudget::default();
    let seeds = [IdeDataflowSeed::new(
        QualifierFact::Tracked,
        Qualifier::Clean,
    )];
    solve_ide_with_summaries(
        IdeSummarySolveInput::new(root, &seeds),
        provider,
        &QualifierProblem::default(),
        &mut semantic_budget,
        &mut DataflowRequest::new(solver_budget, cancellation),
    )
    .expect("valid IDE fixture")
}

#[test]
fn intraprocedural_identity_preserves_the_root_seed_value() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
                pub fn root(value: i32) -> i32 {
                    let incremented = value + 1;
                    incremented
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let root = resolve_procedure_handle(
        &project,
        &analyzer,
        "lib.rs",
        PointSelector::new("pub fn root")
            .procedure("root")
            .effect("entry"),
    );
    let exit = root
        .point_handle(root.semantics().normal_exit_point())
        .expect("root normal exit");

    let result = solve(&root, &analyzer.icfg_provider());

    assert_eq!(result.termination(), SolverTermination::FixedPoint);
    assert_eq!(
        value_at(&result, &exit, QualifierFact::Tracked),
        Qualifier::Clean
    );
    assert_eq!(
        result.reached_jump_functions().count(),
        result.fact_result().reached().len(),
    );
    assert!(result.metrics().direct_relations > 0);
}

#[test]
fn branch_functions_meet_at_the_join_independently_of_path_order() {
    fn run(true_first: bool) -> Qualifier {
        let branches = if true_first {
            "if flag { value = 1; } else { value = 2; }"
        } else {
            "if !flag { value = 2; } else { value = 1; }"
        };
        let project = InlineTestProject::with_language(Language::Rust)
            .file(
                "lib.rs",
                format!(
                    r#"
                        pub fn root(flag: bool) -> i32 {{
                            let value;
                            {branches}
                            value
                        }}
                    "#,
                ),
            )
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let root = resolve_procedure_handle(
            &project,
            &analyzer,
            "lib.rs",
            PointSelector::new("pub fn root")
                .procedure("root")
                .effect("entry"),
        );
        let exit = root
            .point_handle(root.semantics().normal_exit_point())
            .expect("root normal exit");
        let result = solve(&root, &analyzer.icfg_provider());
        assert!(result.metrics().meet_cache_misses > 0);
        value_at(&result, &exit, QualifierFact::Tracked)
    }

    assert_eq!(run(true), Qualifier::Dirty);
    assert_eq!(run(false), Qualifier::Dirty);
}

#[test]
fn each_ide_budget_dimension_returns_a_typed_atomic_partial_result() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
                pub fn root(flag: bool) -> i32 {
                    if flag { 1 } else { 2 }
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let root = resolve_procedure_handle(
        &project,
        &analyzer,
        "lib.rs",
        PointSelector::new("pub fn root")
            .procedure("root")
            .effect("entry"),
    );
    let provider = analyzer.icfg_provider();
    let baseline = solve(&root, &provider);
    let dimensions = [
        SolverBudgetDimension::IdeRelations,
        SolverBudgetDimension::EdgeFunctions,
        SolverBudgetDimension::EdgeFunctionOperations,
        SolverBudgetDimension::IdeValues,
        SolverBudgetDimension::ValueOperations,
    ];

    for dimension in dimensions {
        let baseline_used = ide_dimension_work(baseline.work(), dimension);
        assert!(baseline_used > 0, "fixture must exercise {dimension:?}");
        let mut limits = SolverBudget::default().limits();
        set_ide_dimension_limit(&mut limits, dimension, baseline_used - 1);
        let cancellation = CancellationToken::default();
        let result = solve_with_controls(
            &root,
            &provider,
            &mut SolverBudget::new(limits),
            &cancellation,
        );
        let exceeded = result
            .termination()
            .budget_exceeded()
            .unwrap_or_else(|| panic!("{dimension:?} should stop the IDE solve"));
        assert_eq!(exceeded.dimension(), dimension);
        assert!(result.edge_functions().is_empty());
        assert!(result.values().is_empty());
        assert!(result.point_values().is_empty());
        assert_eq!(
            result.fact_result().termination(),
            SolverTermination::FixedPoint,
            "the completed fact topology remains available",
        );
    }
}

#[test]
fn capture_meet_budget_stops_before_running_client_algebra() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("lib.rs", "pub fn root(value: i32) -> i32 { value + 1 }\n")
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let root = resolve_procedure_handle(
        &project,
        &analyzer,
        "lib.rs",
        PointSelector::new("pub fn root")
            .procedure("root")
            .effect("entry"),
    );
    let cancellation = CancellationToken::default();
    let meets = Rc::new(Cell::new(0));
    let problem = QualifierProblem {
        duplicate_normal_outputs: true,
        edge_function_meets: Some(Rc::clone(&meets)),
        ..QualifierProblem::default()
    };
    let seeds = [IdeDataflowSeed::new(
        QualifierFact::Tracked,
        Qualifier::Clean,
    )];
    let mut limits = SolverBudget::default().limits();
    limits.edge_function_operations = 0;
    let mut solver_budget = SolverBudget::new(limits);
    let mut semantic_budget = SemanticBudget::default();
    let result = solve_ide_with_summaries(
        IdeSummarySolveInput::new(&root, &seeds),
        &analyzer.icfg_provider(),
        &problem,
        &mut semantic_budget,
        &mut DataflowRequest::new(&mut solver_budget, &cancellation),
    )
    .expect("capture exhaustion is a typed partial result");

    assert_eq!(meets.get(), 0);
    assert_eq!(
        result.fact_result().termination(),
        SolverTermination::FixedPoint
    );
    assert_eq!(
        result
            .termination()
            .budget_exceeded()
            .expect("capture meet exceeds its operation budget")
            .dimension(),
        SolverBudgetDimension::EdgeFunctionOperations,
    );
    assert!(result.point_values().is_empty());
}

#[test]
fn seed_order_and_witness_retention_do_not_change_functions_or_values() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("lib.rs", "pub fn root(value: i32) -> i32 { value + 1 }\n")
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let root = resolve_procedure_handle(
        &project,
        &analyzer,
        "lib.rs",
        PointSelector::new("pub fn root")
            .procedure("root")
            .effect("entry"),
    );
    let exit = root
        .point_handle(root.semantics().normal_exit_point())
        .expect("root normal exit");
    let provider = analyzer.icfg_provider();
    let solve_seeds = |seeds: &[IdeDataflowSeed<QualifierFact, Qualifier>], witness_retention| {
        let cancellation = CancellationToken::default();
        let mut solver_budget = SolverBudget::default();
        let mut semantic_budget = SemanticBudget::default();
        solve_ide_with_summaries(
            IdeSummarySolveInput::new(&root, seeds).with_witness_retention(witness_retention),
            &provider,
            &QualifierProblem::default(),
            &mut semantic_budget,
            &mut DataflowRequest::new(&mut solver_budget, &cancellation),
        )
        .expect("valid duplicate-seed IDE fixture")
    };
    let clean_then_dirty = [
        IdeDataflowSeed::new(QualifierFact::Tracked, Qualifier::Clean),
        IdeDataflowSeed::new(QualifierFact::Tracked, Qualifier::Dirty),
    ];
    let dirty_then_clean = [
        IdeDataflowSeed::new(QualifierFact::Tracked, Qualifier::Dirty),
        IdeDataflowSeed::new(QualifierFact::Tracked, Qualifier::Clean),
    ];

    let without_witnesses = solve_seeds(&clean_then_dirty, WitnessRetentionLimits::disabled());
    let with_witnesses = solve_seeds(
        &dirty_then_clean,
        WitnessRetentionLimits::new(2).expect("positive witness limit"),
    );

    assert_eq!(
        value_at(&without_witnesses, &exit, QualifierFact::Tracked),
        Qualifier::Dirty,
    );
    assert_eq!(
        point_value_projection(&without_witnesses),
        point_value_projection(&with_witnesses),
    );
    assert_eq!(
        without_witnesses.edge_functions(),
        with_witnesses.edge_functions(),
    );
    assert_eq!(
        without_witnesses.fact_result().reached(),
        with_witnesses.fact_result().reached(),
    );
    assert_eq!(
        without_witnesses.fact_result().end_summaries(),
        with_witnesses.fact_result().end_summaries(),
    );
    assert_eq!(without_witnesses.coverage(), with_witnesses.coverage());
}

#[test]
fn helper_summary_composes_call_body_and_exact_return_in_path_order() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
                fn helper(value: i32) -> i32 {
                    value + 1
                }

                pub fn root() -> i32 {
                    helper(1)
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let root = resolve_procedure_handle(
        &project,
        &analyzer,
        "lib.rs",
        PointSelector::new("pub fn root")
            .procedure("root")
            .effect("entry"),
    );
    let call = root
        .semantics()
        .call_sites()
        .first()
        .expect("root has one helper call");
    let continuation = root
        .point_handle(
            call.normal_continuation
                .target()
                .expect("helper call has a normal continuation"),
        )
        .expect("helper continuation remains valid");

    let result = solve(&root, &analyzer.icfg_provider());

    assert_eq!(result.termination(), SolverTermination::FixedPoint);
    assert_eq!(
        value_at(&result, &continuation, QualifierFact::Tracked),
        Qualifier::Top
    );
    assert!(result.metrics().summary_relations > 0);
    assert!(result.metrics().summary_function_applications > 0);
    assert_eq!(
        result.end_summary_jump_functions().count(),
        result.fact_result().end_summaries().len(),
    );
}

#[test]
fn cancellation_during_edge_function_algebra_discards_the_ide_overlay() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
                fn helper(value: i32) -> i32 { value + 1 }
                pub fn root() -> i32 { helper(1) }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let root = resolve_procedure_handle(
        &project,
        &analyzer,
        "lib.rs",
        PointSelector::new("pub fn root")
            .procedure("root")
            .effect("entry"),
    );
    let cancellation = CancellationToken::default();
    let problem = QualifierProblem {
        cancel_on_composition: Some(cancellation.clone()),
        ..QualifierProblem::default()
    };
    let seeds = [IdeDataflowSeed::new(
        QualifierFact::Tracked,
        Qualifier::Clean,
    )];
    let mut solver_budget = SolverBudget::default();
    let mut semantic_budget = SemanticBudget::default();
    let result = solve_ide_with_summaries(
        IdeSummarySolveInput::new(&root, &seeds),
        &analyzer.icfg_provider(),
        &problem,
        &mut semantic_budget,
        &mut DataflowRequest::new(&mut solver_budget, &cancellation),
    )
    .expect("algebra cancellation is a typed partial result");

    assert_eq!(
        result.fact_result().termination(),
        SolverTermination::FixedPoint
    );
    assert_eq!(result.termination(), SolverTermination::Cancelled);
    assert!(result.edge_functions().is_empty());
    assert!(result.values().is_empty());
    assert!(result.point_values().is_empty());
}

#[test]
fn exceptional_return_uses_its_exact_continuation_and_function_family() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/returns.ts",
            r#"
                function fail(error: Error): never {
                    throw error;
                }

                export function root(error: Error): number {
                    try {
                        fail(error);
                        return 1;
                    } catch {
                        return 2;
                    }
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let root = resolve_procedure_handle(
        &project,
        &analyzer,
        "src/returns.ts",
        PointSelector::new("function root")
            .procedure("root")
            .effect("entry"),
    );
    let call = root
        .semantics()
        .call_sites()
        .first()
        .expect("root has one failing call");
    let continuation = root
        .point_handle(
            call.exceptional_continuation
                .target()
                .expect("failing call has an exceptional continuation"),
        )
        .expect("exceptional continuation remains valid");

    let result = solve(&root, &analyzer.icfg_provider());

    assert_eq!(result.termination(), SolverTermination::FixedPoint);
    assert_eq!(
        value_at(&result, &continuation, QualifierFact::Tracked),
        Qualifier::Clean,
    );
    assert!(result.metrics().summary_relations > 0);
}

#[test]
fn deferred_invocation_composes_only_the_call_to_return_function() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "leaf.rs",
            r#"
                pub async fn async_leaf() -> i32 {
                    7
                }
            "#,
        )
        .file(
            "lib.rs",
            r#"
                mod leaf;
                use crate::leaf::async_leaf;

                pub fn make_future() {
                    let _pending = async_leaf();
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let root = resolve_procedure_handle(
        &project,
        &analyzer,
        "lib.rs",
        PointSelector::new("pub fn make_future")
            .procedure("make_future")
            .effect("entry"),
    );
    let call = root
        .semantics()
        .call_sites()
        .first()
        .expect("deferred fixture has one call");
    let continuation = root
        .point_handle(
            call.normal_continuation
                .target()
                .expect("deferred call has a normal continuation"),
        )
        .expect("deferred continuation remains valid");

    let result = solve(&root, &analyzer.icfg_provider());

    assert_eq!(result.termination(), SolverTermination::FixedPoint);
    assert_eq!(
        value_at(&result, &continuation, QualifierFact::Tracked),
        Qualifier::Dirty,
    );
    assert_eq!(result.metrics().summary_relations, 0);
}

#[test]
fn recursive_function_improvements_match_the_repeated_scan_reference() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/recursive.ts",
            r#"
                function recurse(n: number): number {
                    if (n <= 0) return 0;
                    return recurse(n - 1);
                }

                export function root(): number {
                    return recurse(2);
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let root = resolve_procedure_handle(
        &project,
        &analyzer,
        "src/recursive.ts",
        PointSelector::new("function root")
            .procedure("root")
            .effect("entry"),
    );
    let provider = analyzer.icfg_provider();
    let result = solve(&root, &provider);
    let seeds = [IdeDataflowSeed::new(
        QualifierFact::Tracked,
        Qualifier::Clean,
    )];
    let mut reference_budget =
        SemanticBudget::uniform(100_000_000).expect("positive reference budget");
    let reference = reference_ide_projection(
        &root,
        &seeds,
        &provider,
        &QualifierProblem::default(),
        &mut reference_budget,
    )
    .expect("recursive IDE reference reaches a fixed point");

    assert_eq!(result.termination(), SolverTermination::FixedPoint);
    assert_eq!(point_value_projection(&result), *reference.point_values());
    assert!(result.metrics().meet_cache_misses > 0);
    assert!(result.metrics().summary_function_applications > 1);
}

#[test]
fn two_callers_reuse_one_relative_summary_function() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/Shared.java",
            r#"
                class Shared {
                    static int leaf() { return 1; }

                    static int root() {
                        int first = leaf();
                        int second = leaf();
                        return first + second;
                    }
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let root = resolve_procedure_handle(
        &project,
        &analyzer,
        "src/Shared.java",
        PointSelector::new("static int root")
            .procedure("root")
            .effect("entry"),
    );
    let calls = root.semantics().call_sites();
    assert_eq!(calls.len(), 2);
    let first_continuation = root
        .point_handle(
            calls[0]
                .normal_continuation
                .target()
                .expect("first call has a continuation"),
        )
        .expect("first continuation remains valid");
    let second_continuation = root
        .point_handle(
            calls[1]
                .normal_continuation
                .target()
                .expect("second call has a continuation"),
        )
        .expect("second continuation remains valid");
    let provider = analyzer.icfg_provider();

    let result = solve(&root, &provider);

    assert_eq!(
        value_at(&result, &first_continuation, QualifierFact::Tracked),
        Qualifier::Top,
    );
    assert_eq!(
        value_at(&result, &second_continuation, QualifierFact::Tracked),
        Qualifier::Top,
    );
    assert!(result.metrics().reused_summary_functions > 0);
    assert!(result.metrics().summary_relations >= 2);
}

#[test]
fn mutual_recursion_matches_the_repeated_scan_reference() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/mutual.ts",
            r#"
                function even(n: number): boolean {
                    if (n <= 0) return true;
                    return odd(n - 1);
                }

                function odd(n: number): boolean {
                    if (n <= 0) return false;
                    return even(n - 1);
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let root = resolve_procedure_handle(
        &project,
        &analyzer,
        "src/mutual.ts",
        PointSelector::new("function even")
            .procedure("even")
            .effect("entry"),
    );
    let provider = analyzer.icfg_provider();
    let result = solve(&root, &provider);
    let seeds = [IdeDataflowSeed::new(
        QualifierFact::Tracked,
        Qualifier::Clean,
    )];
    let mut reference_budget =
        SemanticBudget::uniform(100_000_000).expect("positive reference budget");
    let reference = reference_ide_projection(
        &root,
        &seeds,
        &provider,
        &QualifierProblem::default(),
        &mut reference_budget,
    )
    .expect("mutual-recursion IDE reference reaches a fixed point");

    assert_eq!(point_value_projection(&result), *reference.point_values());
    assert!(result.metrics().summary_function_applications >= 2);
}
