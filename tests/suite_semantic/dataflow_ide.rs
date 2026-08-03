use std::{cell::Cell, collections::HashMap, rc::Rc};

use brokk_bifrost::analyzer::dataflow::{
    DataflowEdge, DataflowOutput, DataflowRequest, IdeDataflowProblem, IdeDataflowSeed,
    IdeSummaryDataflowResult, IdeSummarySolveInput, IdeTransition, PathQuality,
    ReusableIdeEndSummary, ReusableIdeProcedureSummary, ReusableIdeReachedFact,
    ReusableIdeSummaryProvider, SolverBudget, SolverBudgetDimension, SolverTermination, SolverWork,
    WitnessRetentionLimits, solve_ide_with_reusable_summaries, solve_ide_with_summaries,
};
use brokk_bifrost::analyzer::semantic::{
    CallSiteHandle, CallSiteId, CallTransferSet, CancellationToken, ControlEdgeKind,
    DispatchOracle, DispatchResult, EvidenceCompleteness, IcfgEdgeKind, IcfgExitProfile,
    IcfgProvider, IcfgSnapshot, IcfgSnapshotLimits, ProcedureHandle, ProgramPointId, ProofStatus,
    ReturnTransferKind, SemanticBudget, SemanticOutcome, SemanticProviderError, SemanticRequest,
    WorkspaceIcfgProvider,
};
use brokk_bifrost::{AnalyzerConfig, Language};

use crate::common::{
    InlineTestProject,
    dataflow_ide_reference::reference_ide_projection,
    dataflow_regression::{RegressionIcfg, RegressionMutation, RegressionScenario},
    semantic_graph::{PointSelector, resolve_procedure_handle},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum QualifierFact {
    Zero,
    Tracked,
    Alternate,
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
    reverse_duplicate_normal_outputs: bool,
    value_meets: Option<Rc<Cell<usize>>>,
    edge_function_meets: Option<Rc<Cell<usize>>>,
    remap_recursive_call_fact: bool,
}

impl QualifierProblem {
    fn preserve(
        fact: QualifierFact,
        function: QualifierFunction,
        out: &mut dyn DataflowOutput<IdeTransition<QualifierFact, QualifierFunction>>,
    ) {
        if fact != QualifierFact::Zero {
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
        if let Some(meets) = &self.value_meets {
            meets.set(meets.get().saturating_add(1));
        }
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
        edge: DataflowEdge<'_, Self::Fact>,
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
        if self.duplicate_normal_outputs && self.reverse_duplicate_normal_outputs {
            Self::preserve(fact, QualifierFunction::constant(Qualifier::Top), out);
        }
        Self::preserve(fact, function, out);
        if self.duplicate_normal_outputs && !self.reverse_duplicate_normal_outputs {
            Self::preserve(fact, QualifierFunction::constant(Qualifier::Top), out);
        }
    }

    fn call_flow(
        &self,
        _edge: DataflowEdge<'_, Self::Fact>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<IdeTransition<Self::Fact, Self::EdgeFunction>>,
    ) {
        let output_fact = if self.remap_recursive_call_fact && fact == QualifierFact::Tracked {
            QualifierFact::Alternate
        } else {
            fact
        };
        Self::preserve(
            output_fact,
            QualifierFunction::constant(Qualifier::Dirty),
            out,
        );
    }

    fn return_flow(
        &self,
        edge: DataflowEdge<'_, Self::Fact>,
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
        _edge: DataflowEdge<'_, Self::Fact>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<IdeTransition<Self::Fact, Self::EdgeFunction>>,
    ) {
        Self::preserve(fact, QualifierFunction::constant(Qualifier::Dirty), out);
    }

    fn exceptional_flow(
        &self,
        _edge: DataflowEdge<'_, Self::Fact>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<IdeTransition<Self::Fact, Self::EdgeFunction>>,
    ) {
        Self::preserve(fact, QualifierFunction::constant(Qualifier::Top), out);
    }
}

type QualifierResult = IdeSummaryDataflowResult<QualifierFact, Qualifier, QualifierFunction>;

struct FixedReusableIdeProvider {
    callee: ProcedureHandle,
    summaries:
        HashMap<QualifierFact, ReusableIdeProcedureSummary<QualifierFact, QualifierFunction>>,
    calls: Cell<usize>,
}

impl ReusableIdeSummaryProvider<QualifierFact, QualifierFunction> for FixedReusableIdeProvider {
    fn summary_for(
        &mut self,
        procedure: &ProcedureHandle,
        entry_fact: QualifierFact,
        request: &mut DataflowRequest<'_>,
    ) -> Result<
        Option<ReusableIdeProcedureSummary<QualifierFact, QualifierFunction>>,
        SolverTermination,
    > {
        if procedure != &self.callee {
            return Ok(None);
        }
        let Some(summary) = self.summaries.get(&entry_fact) else {
            return Ok(None);
        };
        self.calls.set(self.calls.get().saturating_add(1));
        let rows = summary.exits.len().saturating_add(summary.reached.len());
        if let Some(termination) = request.reserve(SolverWork {
            callback_rows: rows,
            propagated_outputs: rows,
            ..SolverWork::default()
        }) {
            return Err(termination);
        }
        Ok(Some(summary.clone()))
    }
}

fn reusable_ide_summaries_for(
    result: &QualifierResult,
    procedure: &ProcedureHandle,
) -> HashMap<QualifierFact, ReusableIdeProcedureSummary<QualifierFact, QualifierFunction>> {
    let mut exits = HashMap::<
        QualifierFact,
        Vec<ReusableIdeEndSummary<QualifierFact, QualifierFunction>>,
    >::new();
    for (summary, function) in result.end_summary_jump_functions() {
        if summary.entry().procedure() != procedure {
            continue;
        }
        let entry_fact = *result
            .fact_result()
            .fact(summary.entry().entry_fact())
            .expect("reusable entry fact resolves");
        let exit_fact = *result
            .fact_result()
            .fact(summary.exit_fact())
            .expect("reusable exit fact resolves");
        exits
            .entry(entry_fact)
            .or_default()
            .push(ReusableIdeEndSummary {
                exit_kind: summary.exit_kind(),
                exit_fact,
                qualities: summary
                    .path_qualities()
                    .iter()
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
                edge_function: *function,
            });
    }
    let mut reached = HashMap::<
        QualifierFact,
        Vec<ReusableIdeReachedFact<QualifierFact, QualifierFunction>>,
    >::new();
    for (row, function) in result.reached_jump_functions() {
        if row.entry().procedure() != procedure {
            continue;
        }
        let entry_fact = *result
            .fact_result()
            .fact(row.entry().entry_fact())
            .expect("reusable reached entry fact resolves");
        let fact = *result
            .fact_result()
            .fact(row.fact())
            .expect("reusable reached fact resolves");
        reached
            .entry(entry_fact)
            .or_default()
            .push(ReusableIdeReachedFact {
                point: row.point().clone(),
                fact,
                qualities: row
                    .path_qualities()
                    .iter()
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
                edge_function: *function,
            });
    }
    exits
        .into_iter()
        .map(|(entry, exits)| {
            let reached = reached.remove(&entry).unwrap_or_default();
            (
                entry,
                ReusableIdeProcedureSummary {
                    exits: exits.into_boxed_slice(),
                    reached: reached.into_boxed_slice(),
                },
            )
        })
        .collect()
}

#[derive(Clone, Copy)]
struct ReversingProvider<'workspace> {
    inner: WorkspaceIcfgProvider<'workspace>,
    reverse: bool,
    degrade_calls: bool,
}

impl DispatchOracle for ReversingProvider<'_> {
    fn resolve_call(
        &self,
        call: &CallSiteHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<DispatchResult>, SemanticProviderError> {
        self.inner.resolve_call(call, request)
    }
}

impl IcfgProvider for ReversingProvider<'_> {
    fn call_transfers(
        &self,
        caller: &ProcedureHandle,
        call: CallSiteId,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<CallTransferSet>, SemanticProviderError> {
        self.inner
            .call_transfers(caller, call, request)
            .map(|outcome| {
                outcome.map(|mut transfers| {
                    if self.degrade_calls {
                        for transfer in &mut transfers.transfers {
                            transfer.proof = ProofStatus::Unproven("test call evidence".into());
                            transfer.completeness =
                                EvidenceCompleteness::Partial("test call coverage".into());
                        }
                    }
                    if self.reverse {
                        let mut rows = transfers.transfers.into_vec();
                        rows.reverse();
                        transfers.transfers = rows.into_boxed_slice();
                        let mut boundaries = transfers.boundaries.into_vec();
                        boundaries.reverse();
                        transfers.boundaries = boundaries.into_boxed_slice();
                    }
                    transfers
                })
            })
    }

    fn snapshot(
        &self,
        root: &ProcedureHandle,
        limits: IcfgSnapshotLimits,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<IcfgSnapshot>, SemanticProviderError> {
        self.inner.snapshot(root, limits, request)
    }

    fn exit_profile(
        &self,
        callee_entry: &brokk_bifrost::analyzer::semantic::ProgramPointHandle,
        callee_exit: &brokk_bifrost::analyzer::semantic::ProgramPointHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<IcfgExitProfile>, SemanticProviderError> {
        self.inner.exit_profile(callee_entry, callee_exit, request)
    }
}

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
        ProcedureHandle,
        ProgramPointId,
        QualifierFact,
        brokk_bifrost::analyzer::semantic::ProgramPointHandle,
        QualifierFact,
    ),
    Qualifier,
> {
    result
        .point_values()
        .iter()
        .map(|row| {
            let entry_fact = result
                .fact_result()
                .fact(row.entry().entry_fact())
                .copied()
                .expect("point-value entry fact ID resolves");
            let fact = result
                .fact_result()
                .fact(row.fact())
                .copied()
                .expect("point-value fact ID resolves");
            let value = result
                .value(row.value())
                .copied()
                .expect("point-value value ID resolves");
            (
                (
                    row.entry().procedure().clone(),
                    row.entry().entry_point().id(),
                    entry_fact,
                    row.point().clone(),
                    fact,
                ),
                value,
            )
        })
        .collect()
}

fn reached_function_projection(
    result: &QualifierResult,
) -> HashMap<
    (
        ProcedureHandle,
        ProgramPointId,
        QualifierFact,
        brokk_bifrost::analyzer::semantic::ProgramPointHandle,
        QualifierFact,
    ),
    QualifierFunction,
> {
    result
        .reached_jump_functions()
        .map(|(reached, function)| {
            let entry_fact = *result
                .fact_result()
                .fact(reached.entry().entry_fact())
                .expect("reached entry fact resolves");
            let fact = *result
                .fact_result()
                .fact(reached.fact())
                .expect("reached fact resolves");
            (
                (
                    reached.entry().procedure().clone(),
                    reached.entry().entry_point().id(),
                    entry_fact,
                    reached.point().clone(),
                    fact,
                ),
                *function,
            )
        })
        .collect()
}

fn summary_function_projection(
    result: &QualifierResult,
) -> HashMap<
    (
        ProcedureHandle,
        ProgramPointId,
        QualifierFact,
        brokk_bifrost::analyzer::semantic::ProgramPointHandle,
        ReturnTransferKind,
        QualifierFact,
    ),
    QualifierFunction,
> {
    result
        .end_summary_jump_functions()
        .map(|(summary, function)| {
            let entry_fact = *result
                .fact_result()
                .fact(summary.entry().entry_fact())
                .expect("summary entry fact resolves");
            let exit_fact = *result
                .fact_result()
                .fact(summary.exit_fact())
                .expect("summary exit fact resolves");
            (
                (
                    summary.entry().procedure().clone(),
                    summary.entry().entry_point().id(),
                    entry_fact,
                    summary.exit_point().clone(),
                    summary.exit_kind(),
                    exit_fact,
                ),
                *function,
            )
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
        SolverBudgetDimension::IdePropagations => work.ide_propagations,
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
        SolverBudgetDimension::IdePropagations => work.ide_propagations = limit,
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
    let seeds = [IdeDataflowSeed::new(
        QualifierFact::Tracked,
        Qualifier::Clean,
    )];
    solve_problem_with_controls(
        root,
        provider,
        &QualifierProblem::default(),
        &seeds,
        solver_budget,
        cancellation,
    )
}

fn solve_problem_with_controls(
    root: &brokk_bifrost::analyzer::semantic::ProcedureHandle,
    provider: &impl brokk_bifrost::analyzer::semantic::IcfgProvider,
    problem: &QualifierProblem,
    seeds: &[IdeDataflowSeed<QualifierFact, Qualifier>],
    solver_budget: &mut SolverBudget,
    cancellation: &CancellationToken,
) -> QualifierResult {
    let mut semantic_budget = SemanticBudget::default();
    solve_ide_with_summaries(
        IdeSummarySolveInput::new(root, seeds),
        provider,
        problem,
        &mut semantic_budget,
        &mut DataflowRequest::new(solver_budget, cancellation),
    )
    .expect("valid IDE fixture")
}

fn assert_matches_reference(
    root: &ProcedureHandle,
    provider: &impl IcfgProvider,
    result: &QualifierResult,
) {
    let seeds = [IdeDataflowSeed::new(
        QualifierFact::Tracked,
        Qualifier::Clean,
    )];
    let mut reference_budget =
        SemanticBudget::uniform(100_000_000).expect("positive reference budget");
    let reference = reference_ide_projection(
        root,
        &seeds,
        provider,
        &QualifierProblem::default(),
        &mut reference_budget,
    )
    .expect("IDE reference reaches a fixed point");
    assert_eq!(point_value_projection(result), *reference.point_values());
    assert_eq!(
        reached_function_projection(result),
        *reference.reached_functions()
    );
    assert_eq!(
        summary_function_projection(result),
        *reference.summary_functions()
    );
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
fn provider_and_callback_permutations_produce_the_same_ide_result() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/Permutation.java",
            r#"
                class Permutation {
                    static int left(String value) { return 1; }
                    static int left(Object value) { return 2; }
                    static int root() { return left("x"); }
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let root = resolve_procedure_handle(
        &project,
        &analyzer,
        "src/Permutation.java",
        PointSelector::new("static int root")
            .procedure("root")
            .effect("entry"),
    );
    let forward_provider = ReversingProvider {
        inner: analyzer.icfg_provider(),
        reverse: false,
        degrade_calls: false,
    };
    let reverse_provider = ReversingProvider {
        inner: analyzer.icfg_provider(),
        reverse: true,
        degrade_calls: false,
    };
    let semantic_call = root
        .semantics()
        .call_sites()
        .first()
        .expect("permutation fixture retains one call");
    let cancellation = CancellationToken::default();
    let mut semantic_budget = SemanticBudget::default();
    let provider_outcome = forward_provider
        .call_transfers(
            &root,
            semantic_call.id,
            &mut SemanticRequest::new(&mut semantic_budget, &cancellation),
        )
        .expect("permutation fixture transfers");
    assert!(
        provider_outcome
            .available_value()
            .expect("permutation fixture retains transfer payload")
            .transfers
            .len()
            > 1,
        "the reversal must exercise a genuinely multi-target provider relation",
    );

    let seeds = [IdeDataflowSeed::new(
        QualifierFact::Tracked,
        Qualifier::Clean,
    )];
    let forward_problem = QualifierProblem {
        duplicate_normal_outputs: true,
        reverse_duplicate_normal_outputs: false,
        ..QualifierProblem::default()
    };
    let reverse_problem = QualifierProblem {
        duplicate_normal_outputs: true,
        reverse_duplicate_normal_outputs: true,
        ..QualifierProblem::default()
    };
    let mut forward_budget = SolverBudget::default();
    let forward = solve_problem_with_controls(
        &root,
        &forward_provider,
        &forward_problem,
        &seeds,
        &mut forward_budget,
        &cancellation,
    );
    let mut reverse_budget = SolverBudget::default();
    let reverse = solve_problem_with_controls(
        &root,
        &reverse_provider,
        &reverse_problem,
        &seeds,
        &mut reverse_budget,
        &cancellation,
    );

    assert_eq!(forward, reverse);
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
        SolverBudgetDimension::IdePropagations,
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
        assert_eq!(
            result.fact_result().reached(),
            baseline.fact_result().reached(),
            "IDE exhaustion must not truncate the completed fact topology",
        );
        assert_eq!(
            result.fact_result().end_summaries(),
            baseline.fact_result().end_summaries(),
            "IDE exhaustion must not truncate fact summaries",
        );
    }
}

#[test]
fn ide_propagation_budget_bounds_multi_entry_graph_expansion() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("lib.rs", "pub fn root() {}\n")
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
    let seeds = [
        IdeDataflowSeed::new(QualifierFact::Tracked, Qualifier::Clean),
        IdeDataflowSeed::new(QualifierFact::Alternate, Qualifier::Dirty),
    ];
    let mut limits = SolverBudget::default().limits();
    limits.ide_propagations = 0;
    let cancellation = CancellationToken::default();
    let result = solve_problem_with_controls(
        &root,
        &analyzer.icfg_provider(),
        &QualifierProblem::default(),
        &seeds,
        &mut SolverBudget::new(limits),
        &cancellation,
    );

    assert_eq!(
        result.fact_result().termination(),
        SolverTermination::FixedPoint
    );
    assert_eq!(
        result
            .termination()
            .budget_exceeded()
            .expect("entry graph indexing exceeds the zero propagation budget")
            .dimension(),
        SolverBudgetDimension::IdePropagations,
    );
    assert!(result.point_values().is_empty());
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
fn capture_exhaustion_switches_later_callbacks_to_fact_only_projection() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            "pub fn root(value: i32) -> i32 { let next = value + 1; next + 1 }\n",
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
    let meets = Rc::new(Cell::new(0));
    let problem = QualifierProblem {
        duplicate_normal_outputs: true,
        edge_function_meets: Some(Rc::clone(&meets)),
        ..QualifierProblem::default()
    };
    let seeds = [
        IdeDataflowSeed::new(QualifierFact::Tracked, Qualifier::Clean),
        IdeDataflowSeed::new(QualifierFact::Alternate, Qualifier::Clean),
    ];
    let mut limits = SolverBudget::default().limits();
    limits.edge_function_operations = 1;
    let result = solve_problem_with_controls(
        &root,
        &analyzer.icfg_provider(),
        &problem,
        &seeds,
        &mut SolverBudget::new(limits),
        &cancellation,
    );

    assert_eq!(
        meets.get(),
        1,
        "later callbacks must not rerun capture meets"
    );
    assert_eq!(
        result.fact_result().termination(),
        SolverTermination::FixedPoint
    );
    assert_eq!(
        result
            .termination()
            .budget_exceeded()
            .expect("the second capture meet exceeds the global limit")
            .dimension(),
        SolverBudgetDimension::EdgeFunctionOperations,
    );
}

#[test]
fn seed_fact_and_value_limits_stop_before_unbounded_value_algebra() {
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
    let provider = analyzer.icfg_provider();

    let distinct_seeds = [
        IdeDataflowSeed::new(QualifierFact::Tracked, Qualifier::Clean),
        IdeDataflowSeed::new(QualifierFact::Alternate, Qualifier::Dirty),
    ];
    let mut fact_limits = SolverBudget::default().limits();
    fact_limits.interned_facts = 2;
    let cancellation = CancellationToken::default();
    let fact_limited = solve_problem_with_controls(
        &root,
        &provider,
        &QualifierProblem::default(),
        &distinct_seeds,
        &mut SolverBudget::new(fact_limits),
        &cancellation,
    );
    let fact_exceeded = fact_limited
        .termination()
        .budget_exceeded()
        .expect("the second explicit fact exceeds the seed fact cap");
    assert_eq!(
        fact_exceeded.dimension(),
        SolverBudgetDimension::InternedFacts
    );
    assert_eq!(
        fact_limited.fact_result().termination(),
        fact_limited.termination()
    );
    assert!(fact_limited.point_values().is_empty());

    let value_meets = Rc::new(Cell::new(0));
    let value_problem = QualifierProblem {
        value_meets: Some(Rc::clone(&value_meets)),
        ..QualifierProblem::default()
    };
    let duplicate_seeds = [
        IdeDataflowSeed::new(QualifierFact::Tracked, Qualifier::Clean),
        IdeDataflowSeed::new(QualifierFact::Tracked, Qualifier::Dirty),
    ];
    let mut value_limits = SolverBudget::default().limits();
    value_limits.value_operations = 0;
    let value_limited = solve_problem_with_controls(
        &root,
        &provider,
        &value_problem,
        &duplicate_seeds,
        &mut SolverBudget::new(value_limits),
        &cancellation,
    );
    assert_eq!(value_meets.get(), 0);
    assert_eq!(
        value_limited.fact_result().termination(),
        SolverTermination::FixedPoint
    );
    assert_eq!(
        value_limited
            .termination()
            .budget_exceeded()
            .expect("the duplicate seed requires one value meet")
            .dimension(),
        SolverBudgetDimension::ValueOperations,
    );
    assert!(value_limited.point_values().is_empty());

    let cancelled_value_meets = Rc::new(Cell::new(0));
    let cancelled_problem = QualifierProblem {
        value_meets: Some(Rc::clone(&cancelled_value_meets)),
        ..QualifierProblem::default()
    };
    let cancelled = CancellationToken::default();
    cancelled.cancel();
    let mut cancelled_budget = SolverBudget::uniform(0);
    let cancelled_result = solve_problem_with_controls(
        &root,
        &provider,
        &cancelled_problem,
        &duplicate_seeds,
        &mut cancelled_budget,
        &cancelled,
    );
    assert_eq!(cancelled_value_meets.get(), 0);
    assert_eq!(cancelled_result.termination(), SolverTermination::Cancelled);
    assert_eq!(
        cancelled_result.fact_result().termination(),
        SolverTermination::Cancelled
    );
}

#[test]
fn duplicate_seed_meets_have_a_canonical_budget_cost() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("lib.rs", "pub fn root() {}\n")
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
    let grouped_duplicates = [
        IdeDataflowSeed::new(QualifierFact::Tracked, Qualifier::Clean),
        IdeDataflowSeed::new(QualifierFact::Tracked, Qualifier::Clean),
        IdeDataflowSeed::new(QualifierFact::Tracked, Qualifier::Dirty),
    ];
    let interleaved_duplicates = [
        IdeDataflowSeed::new(QualifierFact::Tracked, Qualifier::Clean),
        IdeDataflowSeed::new(QualifierFact::Tracked, Qualifier::Dirty),
        IdeDataflowSeed::new(QualifierFact::Tracked, Qualifier::Clean),
    ];
    let run = |seeds: &[IdeDataflowSeed<QualifierFact, Qualifier>]| {
        let value_meets = Rc::new(Cell::new(0));
        let problem = QualifierProblem {
            value_meets: Some(Rc::clone(&value_meets)),
            ..QualifierProblem::default()
        };
        let mut limits = SolverBudget::default().limits();
        limits.value_operations = 1;
        let cancellation = CancellationToken::default();
        let result = solve_problem_with_controls(
            &root,
            &provider,
            &problem,
            seeds,
            &mut SolverBudget::new(limits),
            &cancellation,
        );
        (result, value_meets.get())
    };

    let grouped = run(&grouped_duplicates);
    let interleaved = run(&interleaved_duplicates);
    assert_eq!(grouped.1, 1);
    assert_eq!(interleaved.1, 1);
    assert_eq!(grouped.0, interleaved.0);
    assert_eq!(grouped.0.work().value_operations, 1);
    assert_eq!(
        grouped
            .0
            .termination()
            .budget_exceeded()
            .expect("materialization exceeds the exact one-meet seed budget")
            .dimension(),
        SolverBudgetDimension::ValueOperations,
    );
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
    let callee_entry_value = result
        .point_values()
        .iter()
        .find(|row| {
            row.entry().procedure() != &root
                && row.point() == row.entry().entry_point()
                && result.fact_result().fact(row.fact()).copied() == Some(QualifierFact::Tracked)
        })
        .and_then(|row| result.value(row.value()))
        .copied()
        .expect("the helper entry exposes its propagated IDE value");
    assert_eq!(callee_entry_value, Qualifier::Dirty);
    assert!(result.metrics().summary_relations > 0);
    assert!(result.metrics().entry_value_relations > 0);
    let entry_transfers = result.entry_transfers().collect::<Vec<_>>();
    assert_eq!(
        entry_transfers.len(),
        result.metrics().entry_value_relations,
        "every retained call-entry relation exposes its relative edge function"
    );
    assert!(entry_transfers.iter().all(|(transfer, _)| {
        transfer.source().procedure() == &root && transfer.target().procedure() != &root
    }));
    assert!(result.metrics().summary_function_applications > 0);
    assert_eq!(
        result.end_summary_jump_functions().count(),
        result.fact_result().end_summaries().len(),
    );
    assert_matches_reference(&root, &analyzer.icfg_provider(), &result);
}

#[test]
fn callee_values_include_the_incoming_call_quality() {
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
    let provider = ReversingProvider {
        inner: analyzer.icfg_provider(),
        reverse: false,
        degrade_calls: true,
    };

    let result = solve(&root, &provider);

    let callee_entry = result
        .point_values()
        .iter()
        .find(|row| {
            row.entry().procedure() != &root
                && row.point() == row.entry().entry_point()
                && result.fact_result().fact(row.fact()).copied() == Some(QualifierFact::Tracked)
        })
        .expect("the helper entry has a concrete value and quality");
    assert!(
        callee_entry
            .path_qualities()
            .contains(PathQuality::UNPROVEN_PARTIAL)
    );
    assert!(!callee_entry.path_qualities().has_proven_path());
    assert!(!callee_entry.path_qualities().has_complete_path());
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
fn exceptional_return_meets_exact_and_boundary_continuations() {
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
        Qualifier::Dirty,
    );
    assert_matches_reference(&root, &analyzer.icfg_provider(), &result);
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
    assert_eq!(
        reached_function_projection(&result),
        *reference.reached_functions()
    );
    assert_eq!(
        summary_function_projection(&result),
        *reference.summary_functions()
    );
    assert!(result.metrics().meet_cache_misses > 0);
    assert!(result.metrics().summary_function_applications > 1);
}

#[test]
fn recursive_call_can_create_a_distinct_root_entry_fact() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/recursive.ts",
            r#"
                export function root(n: number): number {
                    if (n <= 0) return 0;
                    return root(n - 1);
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
    let problem = QualifierProblem {
        remap_recursive_call_fact: true,
        ..QualifierProblem::default()
    };
    let seeds = [IdeDataflowSeed::new(
        QualifierFact::Tracked,
        Qualifier::Clean,
    )];
    let cancellation = CancellationToken::default();
    let mut budget = SolverBudget::default();
    let result = solve_problem_with_controls(
        &root,
        &analyzer.icfg_provider(),
        &problem,
        &seeds,
        &mut budget,
        &cancellation,
    );

    assert_eq!(result.termination(), SolverTermination::FixedPoint);
    let recursive_entry_value = result
        .point_values()
        .iter()
        .find(|row| {
            let entry_fact = result.fact_result().fact(row.entry().entry_fact()).copied();
            let fact = result.fact_result().fact(row.fact()).copied();
            row.entry().procedure() == &root
                && row.point() == row.entry().entry_point()
                && entry_fact == Some(QualifierFact::Alternate)
                && fact == Some(QualifierFact::Alternate)
        })
        .and_then(|row| result.value(row.value()))
        .copied()
        .expect("the recursive call populates the remapped root entry");
    assert_eq!(recursive_entry_value, Qualifier::Dirty);

    let mut reference_budget =
        SemanticBudget::uniform(100_000_000).expect("positive reference budget");
    let reference = reference_ide_projection(
        &root,
        &seeds,
        &analyzer.icfg_provider(),
        &problem,
        &mut reference_budget,
    )
    .expect("remapped recursive reference reaches a fixed point");
    assert_eq!(point_value_projection(&result), *reference.point_values());
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
    assert_matches_reference(&root, &provider, &result);
}

#[test]
fn cross_query_reusable_summary_restores_relative_jump_functions() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/Shared.java",
            r#"
                class Shared {
                    static int leaf(int value) {
                        if (value > 0) return value;
                        return -value;
                    }

                    static int root(int value) {
                        return leaf(value);
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
    let leaf = resolve_procedure_handle(
        &project,
        &analyzer,
        "src/Shared.java",
        PointSelector::new("static int leaf")
            .procedure("leaf")
            .effect("entry"),
    );
    let provider = analyzer.icfg_provider();
    let seeds = [IdeDataflowSeed::new(
        QualifierFact::Tracked,
        Qualifier::Clean,
    )];
    let cancellation = CancellationToken::default();
    let mut leaf_budget = SolverBudget::default();
    let mut leaf_semantic_budget = SemanticBudget::default();
    let leaf_result = solve_ide_with_summaries(
        IdeSummarySolveInput::new(&leaf, &seeds),
        &provider,
        &QualifierProblem::default(),
        &mut leaf_semantic_budget,
        &mut DataflowRequest::new(&mut leaf_budget, &cancellation),
    )
    .expect("leaf summary solve succeeds");
    let summaries = reusable_ide_summaries_for(&leaf_result, &leaf);
    assert!(summaries.contains_key(&QualifierFact::Tracked));

    let mut uncached_budget = SolverBudget::default();
    let uncached = solve_problem_with_controls(
        &root,
        &provider,
        &QualifierProblem::default(),
        &seeds,
        &mut uncached_budget,
        &cancellation,
    );
    let mut reusable = FixedReusableIdeProvider {
        callee: leaf,
        summaries,
        calls: Cell::new(0),
    };
    let mut cached_budget = SolverBudget::default();
    let mut cached_semantic_budget = SemanticBudget::default();
    let cached = solve_ide_with_reusable_summaries(
        IdeSummarySolveInput::new(&root, &seeds),
        &provider,
        &QualifierProblem::default(),
        &mut reusable,
        &mut cached_semantic_budget,
        &mut DataflowRequest::new(&mut cached_budget, &cancellation),
    )
    .expect("cached IDE solve succeeds");

    assert!(reusable.calls.get() > 0);
    assert!(cached.fact_result().metrics().reusable_summary_hits > 0);
    assert_eq!(cached.termination(), SolverTermination::FixedPoint);
    assert_eq!(
        point_value_projection(&cached),
        point_value_projection(&uncached)
    );
    assert_eq!(
        reached_function_projection(&cached),
        reached_function_projection(&uncached)
    );
    assert_eq!(
        summary_function_projection(&cached),
        summary_function_projection(&uncached)
    );
    assert_matches_reference(&root, &provider, &uncached);
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
    assert_eq!(
        reached_function_projection(&result),
        *reference.reached_functions()
    );
    assert_eq!(
        summary_function_projection(&result),
        *reference.summary_functions()
    );
    assert!(result.metrics().summary_function_applications >= 2);
}

#[derive(Debug, Clone, Copy)]
struct FamilyVariant {
    name: &'static str,
    reverse_edges: bool,
    reverse_provider_rows: bool,
    reverse_seeds: bool,
    reverse_outputs: bool,
}

const FAMILY_VARIANTS: [FamilyVariant; 4] = [
    FamilyVariant {
        name: "baseline",
        reverse_edges: false,
        reverse_provider_rows: false,
        reverse_seeds: false,
        reverse_outputs: false,
    },
    FamilyVariant {
        name: "seed_order",
        reverse_edges: false,
        reverse_provider_rows: false,
        reverse_seeds: true,
        reverse_outputs: false,
    },
    FamilyVariant {
        name: "edge_order",
        reverse_edges: true,
        reverse_provider_rows: true,
        reverse_seeds: false,
        reverse_outputs: false,
    },
    FamilyVariant {
        name: "worklist_discovery_order",
        reverse_edges: true,
        reverse_provider_rows: true,
        reverse_seeds: true,
        reverse_outputs: true,
    },
];

type NormalizedState = (String, QualifierFact, String, QualifierFact);
type NormalizedSummary = (
    String,
    QualifierFact,
    String,
    ReturnTransferKind,
    QualifierFact,
);

fn normalized_state(
    graph: &RegressionIcfg,
    procedure: &ProcedureHandle,
    entry: ProgramPointId,
    entry_fact: QualifierFact,
    point: &brokk_bifrost::analyzer::semantic::ProgramPointHandle,
    fact: QualifierFact,
) -> NormalizedState {
    let entry = procedure
        .point_handle(entry)
        .expect("family entry point resolves");
    (
        graph.point_label(&entry).to_owned(),
        entry_fact,
        graph.point_label(point).to_owned(),
        fact,
    )
}

fn normalized_point_values(
    graph: &RegressionIcfg,
    values: &HashMap<
        (
            ProcedureHandle,
            ProgramPointId,
            QualifierFact,
            brokk_bifrost::analyzer::semantic::ProgramPointHandle,
            QualifierFact,
        ),
        Qualifier,
    >,
) -> HashMap<NormalizedState, Qualifier> {
    values
        .iter()
        .map(|((procedure, entry, entry_fact, point, fact), value)| {
            (
                normalized_state(graph, procedure, *entry, *entry_fact, point, *fact),
                *value,
            )
        })
        .collect()
}

fn normalized_reached_functions(
    graph: &RegressionIcfg,
    functions: &HashMap<
        (
            ProcedureHandle,
            ProgramPointId,
            QualifierFact,
            brokk_bifrost::analyzer::semantic::ProgramPointHandle,
            QualifierFact,
        ),
        QualifierFunction,
    >,
) -> HashMap<NormalizedState, QualifierFunction> {
    functions
        .iter()
        .map(|((procedure, entry, entry_fact, point, fact), function)| {
            (
                normalized_state(graph, procedure, *entry, *entry_fact, point, *fact),
                *function,
            )
        })
        .collect()
}

fn normalized_summary_functions(
    graph: &RegressionIcfg,
    functions: &HashMap<
        (
            ProcedureHandle,
            ProgramPointId,
            QualifierFact,
            brokk_bifrost::analyzer::semantic::ProgramPointHandle,
            ReturnTransferKind,
            QualifierFact,
        ),
        QualifierFunction,
    >,
) -> HashMap<NormalizedSummary, QualifierFunction> {
    functions
        .iter()
        .map(
            |((procedure, entry, entry_fact, exit, kind, exit_fact), function)| {
                let entry = procedure
                    .point_handle(*entry)
                    .expect("family summary entry resolves");
                (
                    (
                        graph.point_label(&entry).to_owned(),
                        *entry_fact,
                        graph.point_label(exit).to_owned(),
                        *kind,
                        *exit_fact,
                    ),
                    *function,
                )
            },
        )
        .collect()
}

fn family_projections(
    graph: &RegressionIcfg,
    result: &QualifierResult,
) -> (
    HashMap<NormalizedState, Qualifier>,
    HashMap<NormalizedState, QualifierFunction>,
    HashMap<NormalizedSummary, QualifierFunction>,
) {
    (
        normalized_point_values(graph, &point_value_projection(result)),
        normalized_reached_functions(graph, &reached_function_projection(result)),
        normalized_summary_functions(graph, &summary_function_projection(result)),
    )
}

#[test]
fn deterministic_ide_family_matches_reference_witness_and_order_variants() {
    for scenario in RegressionScenario::ALL {
        let mut expected = None;
        for variant in FAMILY_VARIANTS {
            let graph = RegressionIcfg::new(
                scenario,
                RegressionMutation {
                    reverse_edges: variant.reverse_edges,
                    reverse_provider_rows: variant.reverse_provider_rows,
                },
            );
            let root = graph.root();
            let mut seeds = vec![
                IdeDataflowSeed::new(QualifierFact::Tracked, Qualifier::Clean),
                IdeDataflowSeed::new(QualifierFact::Alternate, Qualifier::Dirty),
            ];
            if variant.reverse_seeds {
                seeds.reverse();
            }
            let problem = QualifierProblem {
                duplicate_normal_outputs: true,
                reverse_duplicate_normal_outputs: variant.reverse_outputs,
                ..QualifierProblem::default()
            };
            let cancellation = CancellationToken::default();
            let mut solver_budget = SolverBudget::default();
            let first = solve_problem_with_controls(
                &root,
                &graph,
                &problem,
                &seeds,
                &mut solver_budget,
                &cancellation,
            );
            let mut solver_budget = SolverBudget::default();
            let second = solve_problem_with_controls(
                &root,
                &graph,
                &problem,
                &seeds,
                &mut solver_budget,
                &cancellation,
            );
            assert_eq!(first, second, "{} / {}", scenario.name(), variant.name);
            assert!(
                first.is_complete(),
                "{} / {}",
                scenario.name(),
                variant.name
            );

            let mut semantic_budget = SemanticBudget::default();
            let mut solver_budget = SolverBudget::default();
            let witnessed = solve_ide_with_summaries(
                IdeSummarySolveInput::new(&root, &seeds).with_witness_retention(
                    WitnessRetentionLimits::new(2).expect("positive witness limit"),
                ),
                &graph,
                &problem,
                &mut semantic_budget,
                &mut DataflowRequest::new(&mut solver_budget, &cancellation),
            )
            .expect("valid witnessed IDE family solve");
            let production = family_projections(&graph, &first);
            assert_eq!(
                production,
                family_projections(&graph, &witnessed),
                "witness retention changed IDE semantics for {} / {}",
                scenario.name(),
                variant.name,
            );

            let mut reference_budget =
                SemanticBudget::uniform(100_000_000).expect("positive reference budget");
            let reference =
                reference_ide_projection(&root, &seeds, &graph, &problem, &mut reference_budget)
                    .expect("family IDE reference reaches a fixed point");
            let reference = (
                normalized_point_values(&graph, reference.point_values()),
                normalized_reached_functions(&graph, reference.reached_functions()),
                normalized_summary_functions(&graph, reference.summary_functions()),
            );
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
fn deterministic_ide_family_low_budget_is_typed_incomplete_evidence() {
    let graph = RegressionIcfg::new(
        RegressionScenario::DiamondJoin,
        RegressionMutation::default(),
    );
    let root = graph.root();
    let seeds = [
        IdeDataflowSeed::new(QualifierFact::Tracked, Qualifier::Clean),
        IdeDataflowSeed::new(QualifierFact::Alternate, Qualifier::Dirty),
    ];
    let problem = QualifierProblem::default();
    let cancellation = CancellationToken::default();
    let mut solver_budget = SolverBudget::default();
    let complete = solve_problem_with_controls(
        &root,
        &graph,
        &problem,
        &seeds,
        &mut solver_budget,
        &cancellation,
    );
    assert!(complete.is_complete());

    let mut limits = SolverWork::uniform(usize::MAX);
    limits.ide_propagations = complete.work().ide_propagations.saturating_sub(1);
    let mut solver_budget = SolverBudget::new(limits);
    let partial = solve_problem_with_controls(
        &root,
        &graph,
        &problem,
        &seeds,
        &mut solver_budget,
        &cancellation,
    );
    let exceeded = partial
        .termination()
        .budget_exceeded()
        .expect("exact low IDE budget terminates incompletely");
    assert_eq!(exceeded.dimension(), SolverBudgetDimension::IdePropagations);
    assert!(!partial.is_complete());
    let complete_values = family_projections(&graph, &complete).0;
    let partial_values = family_projections(&graph, &partial).0;
    assert!(
        partial_values
            .keys()
            .all(|key| complete_values.contains_key(key)),
        "partial IDE values are evidence, never a clean negative"
    );
}
