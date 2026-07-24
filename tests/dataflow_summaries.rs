mod common;

use std::collections::HashSet;

use brokk_bifrost::analyzer::dataflow::{
    DataflowEdge, DataflowOutput, DataflowRequest, DirectFact, DirectFlowProblem,
    DistributiveDataflowProblem, SolverBudget, SolverBudgetDimension, SolverTermination,
    SummaryBoundaryKind, SummaryDataflowError, SummaryDataflowResult, SummarySemanticStatus,
    SummarySolveInput, solve_with_summaries,
};
use brokk_bifrost::analyzer::semantic::{
    CallSiteId, CallTransferSet, CancellationToken, ControlContinuation, DispatchOracle,
    DispatchResult, IcfgBoundaryKind, IcfgExitProfile, IcfgLimitKind, IcfgProvider, IcfgSnapshot,
    IcfgSnapshotLimits, ProcedureHandle, ReturnTransferKind, SemanticBudget, SemanticOutcome,
    SemanticProviderError, SemanticRequest, WorkspaceIcfgProvider,
};
use brokk_bifrost::{AnalyzerConfig, Language};

use common::{
    InlineTestProject,
    dataflow_summary_reference::reference_summary_projection,
    semantic_graph::{PointSelector, resolve_procedure_handle},
};

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
}

struct MarkerProblem;

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
        _edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        Self::emit(fact, MarkerFact::Normal, out);
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
        let marker = match edge.kind() {
            brokk_bifrost::analyzer::semantic::IcfgEdgeKind::NormalReturn => {
                MarkerFact::NormalReturn
            }
            brokk_bifrost::analyzer::semantic::IcfgEdgeKind::ExceptionalReturn => {
                MarkerFact::ExceptionalReturn
            }
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
        let marker = match edge.kind() {
            brokk_bifrost::analyzer::semantic::IcfgEdgeKind::CallToNormalContinuation => {
                MarkerFact::CallToNormalReturn
            }
            brokk_bifrost::analyzer::semantic::IcfgEdgeKind::CallToExceptionalContinuation => {
                MarkerFact::CallToExceptionalReturn
            }
            kind => panic!("call-to-return callback received {kind:?}"),
        };
        Self::emit(fact, marker, out);
    }

    fn exceptional_flow(
        &self,
        _edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        Self::emit(fact, MarkerFact::Exceptional, out);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum CallIdentityFact {
    Zero,
    Root,
    First,
    Second,
}

struct CallIdentityProblem {
    first: CallSiteId,
    second: CallSiteId,
}

impl CallIdentityProblem {
    fn preserve(fact: CallIdentityFact, out: &mut dyn DataflowOutput<CallIdentityFact>) {
        let _ = out.emit(fact);
    }
}

impl DistributiveDataflowProblem for CallIdentityProblem {
    type Fact = CallIdentityFact;

    fn zero_fact(&self) -> Self::Fact {
        CallIdentityFact::Zero
    }

    fn normal_flow(
        &self,
        _edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        Self::preserve(fact, out);
    }

    fn call_flow(
        &self,
        edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        if fact == CallIdentityFact::Zero {
            return;
        }
        let call = edge.origin().expect("call edge has an origin").id();
        let output = if call == self.first {
            CallIdentityFact::First
        } else if call == self.second {
            CallIdentityFact::Second
        } else {
            panic!("unexpected call site {call}");
        };
        let _ = out.emit(output);
    }

    fn return_flow(
        &self,
        _edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        Self::preserve(fact, out);
    }

    fn call_to_return_flow(
        &self,
        _edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        Self::preserve(fact, out);
    }

    fn exceptional_flow(
        &self,
        _edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        Self::preserve(fact, out);
    }
}

struct CancelOnFlowProblem {
    cancellation: CancellationToken,
}

impl DistributiveDataflowProblem for CancelOnFlowProblem {
    type Fact = DirectFact;

    fn zero_fact(&self) -> Self::Fact {
        DirectFact
    }

    fn normal_flow(
        &self,
        _edge: DataflowEdge<'_>,
        _fact: Self::Fact,
        _out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.cancellation.cancel();
    }

    fn call_flow(
        &self,
        _edge: DataflowEdge<'_>,
        _fact: Self::Fact,
        _out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.cancellation.cancel();
    }

    fn return_flow(
        &self,
        _edge: DataflowEdge<'_>,
        _fact: Self::Fact,
        _out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.cancellation.cancel();
    }

    fn call_to_return_flow(
        &self,
        _edge: DataflowEdge<'_>,
        _fact: Self::Fact,
        _out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.cancellation.cancel();
    }

    fn exceptional_flow(
        &self,
        _edge: DataflowEdge<'_>,
        _fact: Self::Fact,
        _out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.cancellation.cancel();
    }
}

struct CancelOnReturnProblem {
    cancellation: CancellationToken,
}

impl DistributiveDataflowProblem for CancelOnReturnProblem {
    type Fact = DirectFact;

    fn zero_fact(&self) -> Self::Fact {
        DirectFact
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
        self.cancellation.cancel();
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
    reverse: bool,
}

impl PermutedProblem {
    fn transfer(&self, fact: PermutedFact, out: &mut dyn DataflowOutput<PermutedFact>) {
        let mut outputs = [fact, PermutedFact::Alpha, PermutedFact::Beta];
        if self.reverse {
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

#[derive(Clone, Copy)]
struct TransformingProvider<'workspace> {
    inner: WorkspaceIcfgProvider<'workspace>,
    reverse: bool,
    weaken_calls: bool,
    corruption: Option<CallTransferCorruption>,
}

#[derive(Debug, Clone, Copy)]
enum CallTransferCorruption {
    CalleeEntry,
    Origin,
    NormalContinuation,
    ExceptionalContinuation,
}

impl<'workspace> TransformingProvider<'workspace> {
    const fn new(inner: WorkspaceIcfgProvider<'workspace>) -> Self {
        Self {
            inner,
            reverse: false,
            weaken_calls: false,
            corruption: None,
        }
    }

    const fn reversing(mut self) -> Self {
        self.reverse = true;
        self
    }

    const fn weakening_calls(mut self) -> Self {
        self.weaken_calls = true;
        self
    }

    const fn corrupting(mut self, corruption: CallTransferCorruption) -> Self {
        self.corruption = Some(corruption);
        self
    }
}

impl DispatchOracle for TransformingProvider<'_> {
    fn resolve_call(
        &self,
        call: &brokk_bifrost::analyzer::semantic::CallSiteHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<DispatchResult>, SemanticProviderError> {
        self.inner.resolve_call(call, request)
    }
}

impl IcfgProvider for TransformingProvider<'_> {
    fn call_transfers(
        &self,
        caller: &ProcedureHandle,
        call: CallSiteId,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<CallTransferSet>, SemanticProviderError> {
        let mut outcome = self.inner.call_transfers(caller, call, request)?;
        if self.reverse {
            outcome = outcome.map(|mut transfers| {
                let mut rows = transfers.transfers.into_vec();
                rows.reverse();
                transfers.transfers = rows.into_boxed_slice();
                let mut boundaries = transfers.boundaries.into_vec();
                boundaries.reverse();
                transfers.boundaries = boundaries.into_boxed_slice();
                transfers
            });
        }
        if let Some(corruption) = self.corruption {
            outcome = outcome.map(|mut transfers| {
                let transfer = transfers
                    .transfers
                    .first_mut()
                    .expect("corruption fixture retains a call transfer");
                match corruption {
                    CallTransferCorruption::CalleeEntry => {
                        transfer.callee = caller.clone();
                    }
                    CallTransferCorruption::Origin => {
                        transfer.origin = caller
                            .semantics()
                            .call_sites()
                            .iter()
                            .find(|candidate| candidate.id != call)
                            .and_then(|candidate| caller.call_site_handle(candidate.id))
                            .expect("origin-corruption fixture retains another call");
                    }
                    CallTransferCorruption::NormalContinuation => {
                        transfer.normal_continuation =
                            different_continuation(transfer.normal_continuation);
                    }
                    CallTransferCorruption::ExceptionalContinuation => {
                        transfer.exceptional_continuation =
                            different_continuation(transfer.exceptional_continuation);
                    }
                }
                transfers
            });
        }
        if self.weaken_calls {
            let work = outcome.work();
            if let Some(partial) = outcome.available_value().cloned() {
                return Ok(SemanticOutcome::Unproven { partial, work });
            }
        }
        Ok(outcome)
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

fn different_continuation(continuation: ControlContinuation) -> ControlContinuation {
    if continuation == ControlContinuation::Unknown {
        ControlContinuation::Absent
    } else {
        ControlContinuation::Unknown
    }
}

fn solve_default<P, Provider>(
    root: &ProcedureHandle,
    entry_facts: &[P::Fact],
    provider: &Provider,
    problem: &P,
) -> SummaryDataflowResult<P::Fact>
where
    P: DistributiveDataflowProblem,
    Provider: IcfgProvider + ?Sized,
{
    let cancellation = CancellationToken::default();
    let mut solver_budget = SolverBudget::default();
    let mut semantic_budget = SemanticBudget::default();
    solve_with_summaries(
        SummarySolveInput::new(root, entry_facts),
        provider,
        problem,
        &mut semantic_budget,
        &mut DataflowRequest::new(&mut solver_budget, &cancellation),
    )
    .expect("valid summary fixture")
}

fn reached_projection<F>(
    result: &SummaryDataflowResult<F>,
) -> HashSet<(brokk_bifrost::analyzer::semantic::ProgramPointHandle, F)>
where
    F: Copy + Eq + std::hash::Hash,
{
    result
        .reached()
        .iter()
        .map(|reached| {
            let fact = *result
                .fact(reached.fact())
                .expect("reached fact ID resolves");
            (reached.point().clone(), fact)
        })
        .collect()
}

fn facts_at<F>(
    result: &SummaryDataflowResult<F>,
    point: &brokk_bifrost::analyzer::semantic::ProgramPointHandle,
) -> HashSet<F>
where
    F: Copy + Eq + std::hash::Hash,
{
    result
        .reached_at(point)
        .map(|reached| {
            *result
                .fact(reached.fact())
                .expect("reached fact ID resolves")
        })
        .collect()
}

fn direct_problem() -> DirectFlowProblem {
    DirectFlowProblem::new(std::iter::empty())
}

#[test]
fn direct_recursion_converges_without_inheriting_snapshot_call_depth() {
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
    let root = resolve_procedure_handle(
        &project,
        &analyzer,
        "src/recursive.ts",
        PointSelector::new("function recurse")
            .procedure("recurse")
            .effect("entry"),
    );
    let provider = analyzer.icfg_provider();

    let snapshot_cancellation = CancellationToken::default();
    let mut snapshot_budget = SemanticBudget::default();
    let snapshot_outcome = provider
        .snapshot(
            &root,
            IcfgSnapshotLimits::new(2, 10_000, 20_000).unwrap(),
            &mut SemanticRequest::new(&mut snapshot_budget, &snapshot_cancellation),
        )
        .expect("recursive bounded snapshot");
    assert!(!snapshot_outcome.is_complete());
    assert!(
        snapshot_outcome
            .available_value()
            .expect("recursive snapshot retains its frontier")
            .boundaries()
            .iter()
            .any(|boundary| matches!(
                boundary.kind,
                IcfgBoundaryKind::Limit(IcfgLimitKind::CallDepth)
            )),
        "the bounded snapshot should stop at its configured call depth",
    );

    let problem = direct_problem();
    let result = solve_default(&root, &[], &provider, &problem);
    assert_eq!(result.termination(), SolverTermination::FixedPoint);
    assert!(
        result
            .coverage()
            .boundaries()
            .iter()
            .all(|boundary| !matches!(
                boundary.kind(),
                SummaryBoundaryKind::Limit(IcfgLimitKind::CallDepth)
            )),
        "summary convergence must not publish a synthetic call-depth frontier",
    );
    assert!(result.metrics().summary_applications > 0);
    assert!(result.metrics().reused_entry_contexts > 0);
    assert!(
        result.end_summaries().iter().any(|summary| {
            summary.entry().procedure() == &root
                && summary.exit_kind() == ReturnTransferKind::Normal
        }),
        "the recursive root should acquire a reusable normal end summary",
    );

    let mut reference_budget =
        SemanticBudget::uniform(100_000_000).expect("positive reference budget");
    let reference =
        reference_summary_projection(&root, &[], &provider, &problem, &mut reference_budget)
            .expect("recursive reference fixed point");
    assert_eq!(reached_projection(&result), *reference.reached());
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
    let problem = direct_problem();
    let result = solve_default(&root, &[], &provider, &problem);

    assert_eq!(result.termination(), SolverTermination::FixedPoint);
    let summarized_procedures = result
        .end_summaries()
        .iter()
        .map(|summary| summary.entry().procedure().clone())
        .collect::<HashSet<_>>();
    assert_eq!(
        summarized_procedures.len(),
        2,
        "even and odd should each contribute one relative summary context",
    );
    assert!(result.metrics().summary_applications >= 2);

    let mut reference_budget =
        SemanticBudget::uniform(100_000_000).expect("positive reference budget");
    let reference =
        reference_summary_projection(&root, &[], &provider, &problem, &mut reference_budget)
            .expect("mutual-recursion reference fixed point");
    assert_eq!(reached_projection(&result), *reference.reached());
}

#[test]
fn shared_callee_reuses_entries_without_crossing_return_sites() {
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
    assert_eq!(calls.len(), 2, "fixture should contain exactly two calls");
    let first_continuation = root
        .point_handle(
            calls[0]
                .normal_continuation
                .target()
                .expect("first call has a normal continuation"),
        )
        .expect("first continuation remains valid");
    let second_continuation = root
        .point_handle(
            calls[1]
                .normal_continuation
                .target()
                .expect("second call has a normal continuation"),
        )
        .expect("second continuation remains valid");
    let problem = CallIdentityProblem {
        first: calls[0].id,
        second: calls[1].id,
    };
    let result = solve_default(
        &root,
        &[CallIdentityFact::Root],
        &analyzer.icfg_provider(),
        &problem,
    );

    assert_eq!(result.termination(), SolverTermination::FixedPoint);
    assert!(
        result.metrics().reused_entry_contexts > 0,
        "the second zero-fact call should reuse the leaf entry context",
    );
    assert!(result.metrics().summary_applications >= 2);

    let first_facts = facts_at(&result, &first_continuation);
    assert!(first_facts.contains(&CallIdentityFact::First));
    assert!(!first_facts.contains(&CallIdentityFact::Second));
    let second_facts = facts_at(&result, &second_continuation);
    assert!(second_facts.contains(&CallIdentityFact::Second));
    assert!(
        !second_facts.contains(&CallIdentityFact::First),
        "the first invocation's summary must not replay to the second continuation",
    );
}

#[test]
fn normal_and_exceptional_returns_match_the_repeated_scan_reference() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/returns.ts",
            r#"
                function leaf(value: number): number {
                    return value;
                }

                function fail(error: Error): never {
                    throw error;
                }

                function caller(error: Error): number {
                    const value = leaf(1);
                    try {
                        fail(error);
                        return value;
                    } catch {
                        return -1;
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
        PointSelector::new("function caller")
            .procedure("caller")
            .effect("entry"),
    );
    let provider = analyzer.icfg_provider();
    let result = solve_default(&root, &[MarkerFact::Seed], &provider, &MarkerProblem);

    assert_eq!(result.termination(), SolverTermination::FixedPoint);
    assert!(result.facts().contains(&MarkerFact::NormalReturn));
    assert!(result.facts().contains(&MarkerFact::ExceptionalReturn));
    assert!(
        result
            .end_summaries()
            .iter()
            .any(|summary| summary.exit_kind() == ReturnTransferKind::Normal),
    );
    assert!(
        result
            .end_summaries()
            .iter()
            .any(|summary| summary.exit_kind() == ReturnTransferKind::Exceptional),
    );

    let mut reference_budget =
        SemanticBudget::uniform(100_000_000).expect("positive reference budget");
    let reference = reference_summary_projection(
        &root,
        &[MarkerFact::Seed],
        &provider,
        &MarkerProblem,
        &mut reference_budget,
    )
    .expect("return-family reference fixed point");
    assert_eq!(reached_projection(&result), *reference.reached());
}

#[test]
fn deferred_invocation_uses_explicit_call_to_return_flow() {
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
    let result = solve_default(
        &root,
        &[MarkerFact::Seed],
        &analyzer.icfg_provider(),
        &MarkerProblem,
    );

    assert_eq!(result.termination(), SolverTermination::FixedPoint);
    assert!(result.facts().contains(&MarkerFact::CallToNormalReturn));
    assert!(
        !result.facts().contains(&MarkerFact::Call),
        "scheduling a deferred body must not invoke ordinary call-flow",
    );
    let deferred_boundary = result
        .coverage()
        .boundaries()
        .iter()
        .find(|boundary| {
            matches!(
                boundary.kind(),
                SummaryBoundaryKind::Dispatch(
                    brokk_bifrost::analyzer::semantic::DispatchBoundaryKind::Deferred { .. }
                )
            )
        })
        .expect("deferred dispatch boundary remains visible");
    assert!(deferred_boundary.proof().is_some());
    assert!(deferred_boundary.completeness().is_some());
    assert!(
        !deferred_boundary.provenance().is_empty(),
        "summary coverage must retain structured dispatch provenance",
    );
    assert!(result.coverage().partial_edges().iter().any(|edge| {
        matches!(
            edge.kind(),
            brokk_bifrost::analyzer::semantic::IcfgEdgeKind::CallToNormalContinuation
        ) && matches!(
            edge.completeness(),
            brokk_bifrost::analyzer::semantic::EvidenceCompleteness::Partial(_)
        )
    }));
}

#[test]
fn partial_provider_payload_remains_reachable_but_incomplete() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/Partial.java",
            r#"
                class Partial {
                    static int leaf() { return 1; }
                    static int root() { return leaf(); }
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let root = resolve_procedure_handle(
        &project,
        &analyzer,
        "src/Partial.java",
        PointSelector::new("static int root")
            .procedure("root")
            .effect("entry"),
    );
    let provider = TransformingProvider::new(analyzer.icfg_provider()).weakening_calls();
    let result = solve_default(&root, &[], &provider, &direct_problem());

    assert_eq!(result.termination(), SolverTermination::FixedPoint);
    assert!(!result.is_complete());
    assert_eq!(
        result.coverage().semantic_status(),
        SummarySemanticStatus::Unproven,
    );
    assert!(result.end_summaries().len() >= 2);
    assert!(result.coverage().boundaries().iter().any(|boundary| {
        matches!(
            boundary.kind(),
            SummaryBoundaryKind::Semantic(SummarySemanticStatus::Unproven)
        )
    }));
}

#[test]
fn cooperative_callback_cancellation_discards_unpublished_outputs() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("lib.rs", "pub fn root() -> i32 { 1 }\n")
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
    let problem = CancelOnFlowProblem {
        cancellation: cancellation.clone(),
    };
    let mut solver_budget = SolverBudget::default();
    let mut semantic_budget = SemanticBudget::default();
    let result = solve_with_summaries(
        SummarySolveInput::new(&root, &[]),
        &analyzer.icfg_provider(),
        &problem,
        &mut semantic_budget,
        &mut DataflowRequest::new(&mut solver_budget, &cancellation),
    )
    .expect("valid cancellation fixture");

    assert_eq!(result.termination(), SolverTermination::Cancelled);
    assert_eq!(result.work().flow_evaluations, 1);
    assert_eq!(
        result.reached().len(),
        1,
        "the callback's cancelled relation must not become visible",
    );
    assert!(result.end_summaries().is_empty());
}

#[test]
fn return_flow_cancellation_does_not_publish_application_metrics() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/CancelReturn.java",
            r#"
                class CancelReturn {
                    static int leaf() { return 1; }
                    static int root() { return leaf(); }
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let root = resolve_procedure_handle(
        &project,
        &analyzer,
        "src/CancelReturn.java",
        PointSelector::new("static int root")
            .procedure("root")
            .effect("entry"),
    );
    let cancellation = CancellationToken::default();
    let problem = CancelOnReturnProblem {
        cancellation: cancellation.clone(),
    };
    let mut solver_budget = SolverBudget::default();
    let mut semantic_budget = SemanticBudget::default();
    let result = solve_with_summaries(
        SummarySolveInput::new(&root, &[]),
        &analyzer.icfg_provider(),
        &problem,
        &mut semantic_budget,
        &mut DataflowRequest::new(&mut solver_budget, &cancellation),
    )
    .expect("valid return-cancellation fixture");

    assert_eq!(result.termination(), SolverTermination::Cancelled);
    assert_eq!(
        result.work().summary_applications,
        1,
        "the attempted application should consume its explicit work budget",
    );
    assert_eq!(
        result.metrics().summary_applications,
        0,
        "a cancelled return relation must not count as an applied summary",
    );
}

#[test]
fn malformed_call_transfer_contracts_fail_as_provider_errors() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/Malformed.java",
            r#"
                class Malformed {
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
        "src/Malformed.java",
        PointSelector::new("static int root")
            .procedure("root")
            .effect("entry"),
    );

    for (corruption, expected) in [
        (
            CallTransferCorruption::CalleeEntry,
            "entry belongs to a different callee",
        ),
        (
            CallTransferCorruption::Origin,
            "origin does not match the requested call",
        ),
        (
            CallTransferCorruption::NormalContinuation,
            "mismatched normal continuation",
        ),
        (
            CallTransferCorruption::ExceptionalContinuation,
            "mismatched exceptional continuation",
        ),
    ] {
        let provider = TransformingProvider::new(analyzer.icfg_provider()).corrupting(corruption);
        let cancellation = CancellationToken::default();
        let mut solver_budget = SolverBudget::default();
        let mut semantic_budget = SemanticBudget::default();
        let error = solve_with_summaries(
            SummarySolveInput::new(&root, &[]),
            &provider,
            &direct_problem(),
            &mut semantic_budget,
            &mut DataflowRequest::new(&mut solver_budget, &cancellation),
        )
        .expect_err("malformed provider transfer must fail closed");

        assert!(
            matches!(error, SummaryDataflowError::SemanticProvider(_)),
            "unexpected error for {corruption:?}: {error:?}",
        );
        assert!(
            error.to_string().contains(expected),
            "unexpected error for {corruption:?}: {error}",
        );
    }
}

#[test]
fn summary_specific_budget_dimensions_stop_at_exact_publication_boundaries() {
    let leaf_project = InlineTestProject::with_language(Language::Rust)
        .file("lib.rs", "pub fn root() -> i32 { 1 }\n")
        .build();
    let leaf_analyzer = leaf_project.workspace_analyzer(AnalyzerConfig::default());
    let leaf_root = resolve_procedure_handle(
        &leaf_project,
        &leaf_analyzer,
        "lib.rs",
        PointSelector::new("pub fn root")
            .procedure("root")
            .effect("entry"),
    );
    assert_budget_dimension(
        &leaf_root,
        &leaf_analyzer.icfg_provider(),
        SolverBudgetDimension::ProviderMaterializations,
    );
    assert_budget_dimension(
        &leaf_root,
        &leaf_analyzer.icfg_provider(),
        SolverBudgetDimension::EndSummaries,
    );

    let call_project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/Budget.java",
            r#"
                class Budget {
                    static int leaf() { return 1; }
                    static int root() { return leaf(); }
                }
            "#,
        )
        .build();
    let call_analyzer = call_project.workspace_analyzer(AnalyzerConfig::default());
    let call_root = resolve_procedure_handle(
        &call_project,
        &call_analyzer,
        "src/Budget.java",
        PointSelector::new("static int root")
            .procedure("root")
            .effect("entry"),
    );
    assert_budget_dimension(
        &call_root,
        &call_analyzer.icfg_provider(),
        SolverBudgetDimension::IncomingCalls,
    );
    assert_budget_dimension(
        &call_root,
        &call_analyzer.icfg_provider(),
        SolverBudgetDimension::SummaryApplications,
    );
    assert_budget_dimension(
        &call_root,
        &TransformingProvider::new(call_analyzer.icfg_provider()).weakening_calls(),
        SolverBudgetDimension::CoverageRows,
    );
}

fn assert_budget_dimension<Provider>(
    root: &ProcedureHandle,
    provider: &Provider,
    dimension: SolverBudgetDimension,
) where
    Provider: IcfgProvider + ?Sized,
{
    let mut limits = SolverBudget::default().limits();
    match dimension {
        SolverBudgetDimension::EndSummaries => limits.end_summaries = 0,
        SolverBudgetDimension::IncomingCalls => limits.incoming_calls = 0,
        SolverBudgetDimension::ProviderMaterializations => limits.provider_materializations = 0,
        SolverBudgetDimension::SummaryApplications => limits.summary_applications = 0,
        SolverBudgetDimension::CoverageRows => limits.coverage_rows = 0,
        other => panic!("not a summary-specific dimension: {other:?}"),
    }
    let mut solver_budget = SolverBudget::new(limits);
    let cancellation = CancellationToken::default();
    let mut semantic_budget = SemanticBudget::default();
    let result = solve_with_summaries(
        SummarySolveInput::new(root, &[]),
        provider,
        &direct_problem(),
        &mut semantic_budget,
        &mut DataflowRequest::new(&mut solver_budget, &cancellation),
    )
    .expect("valid budget fixture");
    let exceeded = result
        .termination()
        .budget_exceeded()
        .expect("summary-specific budget should terminate the solve");
    assert_eq!(exceeded.dimension(), dimension);
    assert_eq!(exceeded.limit(), 0);
    assert_eq!(exceeded.attempted(), 1);
}

#[test]
fn provider_and_callback_permutations_produce_the_same_result() {
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
    let forward_provider = TransformingProvider::new(analyzer.icfg_provider());
    let reverse_provider = forward_provider.reversing();
    let semantic_call = root
        .semantics()
        .call_sites()
        .first()
        .expect("permutation fixture retains one call");
    let cancellation = CancellationToken::default();
    let mut provider_budget = SemanticBudget::default();
    let provider_outcome = forward_provider
        .call_transfers(
            &root,
            semantic_call.id,
            &mut SemanticRequest::new(&mut provider_budget, &cancellation),
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
    let forward = solve_default(
        &root,
        &[PermutedFact::Seed],
        &forward_provider,
        &PermutedProblem { reverse: false },
    );
    let reverse = solve_default(
        &root,
        &[PermutedFact::Seed],
        &reverse_provider,
        &PermutedProblem { reverse: true },
    );

    assert_eq!(forward.facts(), reverse.facts());
    assert_eq!(forward.reached(), reverse.reached());
    assert_eq!(forward.end_summaries(), reverse.end_summaries());
    assert_eq!(forward.coverage(), reverse.coverage());
    assert_eq!(forward.termination(), reverse.termination());
    assert_eq!(forward.work(), reverse.work());
    assert_eq!(forward.metrics(), reverse.metrics());
}
