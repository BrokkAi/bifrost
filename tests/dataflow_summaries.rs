mod common;

use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
};

use brokk_bifrost::analyzer::dataflow::{
    DataflowEdge, DataflowOutput, DataflowRequest, DirectFlowProblem, DistributiveDataflowProblem,
    SolverBudget, SolverBudgetDimension, SolverTermination, SummaryBoundaryKind,
    SummaryDataflowError, SummaryDataflowResult, SummarySemanticStatus, SummarySolveInput,
    solve_with_summaries,
};
use brokk_bifrost::analyzer::semantic::{
    CallBoundary, CallSiteHandle, CallSiteId, CallTransferSet, CancellationToken,
    ControlContinuation, DispatchBoundaryKind, DispatchOracle, DispatchResult, IcfgBoundaryKind,
    IcfgExitProfile, IcfgLimitKind, IcfgProvider, IcfgSnapshot, IcfgSnapshotLimits, OracleLimits,
    OracleRelationArena, OracleRelationId, ProcedureHandle, ReturnTransferKind, SemanticBudget,
    SemanticBudgetDimension, SemanticOutcome, SemanticProviderError, SemanticRequest, SemanticWork,
    WorkspaceIcfgProvider,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum CancellationFact {
    Zero,
    Seed,
    Staged,
}

struct CancelOnFlowProblem {
    cancellation: CancellationToken,
}

impl CancelOnFlowProblem {
    fn emit_then_cancel(&self, out: &mut dyn DataflowOutput<CancellationFact>) {
        let _ = out.emit(CancellationFact::Staged);
        self.cancellation.cancel();
    }
}

impl DistributiveDataflowProblem for CancelOnFlowProblem {
    type Fact = CancellationFact;

    fn zero_fact(&self) -> Self::Fact {
        CancellationFact::Zero
    }

    fn normal_flow(
        &self,
        _edge: DataflowEdge<'_>,
        _fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.emit_then_cancel(out);
    }

    fn call_flow(
        &self,
        _edge: DataflowEdge<'_>,
        _fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.emit_then_cancel(out);
    }

    fn return_flow(
        &self,
        _edge: DataflowEdge<'_>,
        _fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.emit_then_cancel(out);
    }

    fn call_to_return_flow(
        &self,
        _edge: DataflowEdge<'_>,
        _fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.emit_then_cancel(out);
    }

    fn exceptional_flow(
        &self,
        _edge: DataflowEdge<'_>,
        _fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.emit_then_cancel(out);
    }
}

struct CancelOnReturnProblem {
    cancellation: CancellationToken,
}

impl DistributiveDataflowProblem for CancelOnReturnProblem {
    type Fact = CancellationFact;

    fn zero_fact(&self) -> Self::Fact {
        CancellationFact::Zero
    }

    fn normal_flow(
        &self,
        _edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        let _ = out.emit(fact);
    }

    fn call_flow(
        &self,
        _edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        let _ = out.emit(fact);
    }

    fn return_flow(
        &self,
        _edge: DataflowEdge<'_>,
        _fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        let _ = out.emit(CancellationFact::Staged);
        self.cancellation.cancel();
    }

    fn call_to_return_flow(
        &self,
        _edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        let _ = out.emit(fact);
    }

    fn exceptional_flow(
        &self,
        _edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        let _ = out.emit(fact);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum ReplayWaveFact {
    Zero,
    Wave0,
    Wave1,
    Wave2,
}

struct ReplayWaveProblem;

impl ReplayWaveProblem {
    fn preserve(fact: ReplayWaveFact, out: &mut dyn DataflowOutput<ReplayWaveFact>) {
        let _ = out.emit(fact);
    }
}

impl DistributiveDataflowProblem for ReplayWaveProblem {
    type Fact = ReplayWaveFact;

    fn zero_fact(&self) -> Self::Fact {
        ReplayWaveFact::Zero
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
        _edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        Self::preserve(fact, out);
    }

    fn return_flow(
        &self,
        _edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        let next = match fact {
            ReplayWaveFact::Zero => ReplayWaveFact::Zero,
            ReplayWaveFact::Wave0 => ReplayWaveFact::Wave1,
            ReplayWaveFact::Wave1 | ReplayWaveFact::Wave2 => ReplayWaveFact::Wave2,
        };
        let _ = out.emit(next);
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
    BoundaryEmptyProvenance,
    BoundaryWrongSubject,
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
                match corruption {
                    CallTransferCorruption::CalleeEntry => {
                        let transfer = transfers
                            .transfers
                            .first_mut()
                            .expect("corruption fixture retains a call transfer");
                        transfer.callee = caller.clone();
                    }
                    CallTransferCorruption::Origin => {
                        let transfer = transfers
                            .transfers
                            .first_mut()
                            .expect("corruption fixture retains a call transfer");
                        transfer.origin = caller
                            .semantics()
                            .call_sites()
                            .iter()
                            .find(|candidate| candidate.id != call)
                            .and_then(|candidate| caller.call_site_handle(candidate.id))
                            .expect("origin-corruption fixture retains another call");
                    }
                    CallTransferCorruption::NormalContinuation => {
                        let transfer = transfers
                            .transfers
                            .first_mut()
                            .expect("corruption fixture retains a call transfer");
                        transfer.normal_continuation =
                            different_continuation(transfer.normal_continuation);
                    }
                    CallTransferCorruption::ExceptionalContinuation => {
                        let transfer = transfers
                            .transfers
                            .first_mut()
                            .expect("corruption fixture retains a call transfer");
                        transfer.exceptional_continuation =
                            different_continuation(transfer.exceptional_continuation);
                    }
                    CallTransferCorruption::BoundaryEmptyProvenance => {
                        transfers
                            .boundaries
                            .first_mut()
                            .expect("corruption fixture retains a call boundary")
                            .dispatch
                            .provenance = Box::new([]);
                    }
                    CallTransferCorruption::BoundaryWrongSubject => {
                        transfers
                            .boundaries
                            .first_mut()
                            .expect("corruption fixture retains a call boundary")
                            .dispatch
                            .kind = DispatchBoundaryKind::Unresolved;
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

#[derive(Clone)]
struct ReplayingExitProvider<'workspace> {
    inner: WorkspaceIcfgProvider<'workspace>,
    intercepted_entry: brokk_bifrost::analyzer::semantic::ProgramPointHandle,
    intercepted_exit: brokk_bifrost::analyzer::semantic::ProgramPointHandle,
    replay: SemanticOutcome<IcfgExitProfile>,
}

impl DispatchOracle for ReplayingExitProvider<'_> {
    fn resolve_call(
        &self,
        call: &CallSiteHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<DispatchResult>, SemanticProviderError> {
        self.inner.resolve_call(call, request)
    }
}

impl IcfgProvider for ReplayingExitProvider<'_> {
    fn call_transfers(
        &self,
        caller: &ProcedureHandle,
        call: CallSiteId,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<CallTransferSet>, SemanticProviderError> {
        self.inner.call_transfers(caller, call, request)
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
        if callee_entry == &self.intercepted_entry && callee_exit == &self.intercepted_exit {
            Ok(self.replay.clone())
        } else {
            self.inner.exit_profile(callee_entry, callee_exit, request)
        }
    }
}

#[derive(Clone)]
struct BoundaryOrderProvider<'workspace> {
    inner: WorkspaceIcfgProvider<'workspace>,
    boundaries: Box<[CallBoundary]>,
}

impl DispatchOracle for BoundaryOrderProvider<'_> {
    fn resolve_call(
        &self,
        call: &CallSiteHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<DispatchResult>, SemanticProviderError> {
        self.inner.resolve_call(call, request)
    }
}

impl IcfgProvider for BoundaryOrderProvider<'_> {
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
                    transfers.boundaries = self.boundaries.clone();
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

#[derive(Debug, Default)]
struct ProviderCounts {
    call_transfers: HashMap<(ProcedureHandle, CallSiteId), usize>,
    exit_profiles: HashMap<
        (
            brokk_bifrost::analyzer::semantic::ProgramPointHandle,
            brokk_bifrost::analyzer::semantic::ProgramPointHandle,
        ),
        usize,
    >,
}

struct CountingProvider<'workspace> {
    inner: WorkspaceIcfgProvider<'workspace>,
    counts: RefCell<ProviderCounts>,
}

impl<'workspace> CountingProvider<'workspace> {
    fn new(inner: WorkspaceIcfgProvider<'workspace>) -> Self {
        Self {
            inner,
            counts: RefCell::new(ProviderCounts::default()),
        }
    }

    fn call_count(&self, caller: &ProcedureHandle, call: CallSiteId) -> usize {
        self.counts
            .borrow()
            .call_transfers
            .get(&(caller.clone(), call))
            .copied()
            .unwrap_or_default()
    }

    fn exit_count(
        &self,
        entry: &brokk_bifrost::analyzer::semantic::ProgramPointHandle,
        exit: &brokk_bifrost::analyzer::semantic::ProgramPointHandle,
    ) -> usize {
        self.counts
            .borrow()
            .exit_profiles
            .get(&(entry.clone(), exit.clone()))
            .copied()
            .unwrap_or_default()
    }
}

impl DispatchOracle for CountingProvider<'_> {
    fn resolve_call(
        &self,
        call: &CallSiteHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<DispatchResult>, SemanticProviderError> {
        self.inner.resolve_call(call, request)
    }
}

impl IcfgProvider for CountingProvider<'_> {
    fn call_transfers(
        &self,
        caller: &ProcedureHandle,
        call: CallSiteId,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<CallTransferSet>, SemanticProviderError> {
        *self
            .counts
            .borrow_mut()
            .call_transfers
            .entry((caller.clone(), call))
            .or_default() += 1;
        self.inner.call_transfers(caller, call, request)
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
        *self
            .counts
            .borrow_mut()
            .exit_profiles
            .entry((callee_entry.clone(), callee_exit.clone()))
            .or_default() += 1;
        self.inner.exit_profile(callee_entry, callee_exit, request)
    }
}

#[derive(Clone, Copy)]
struct ExceededCallBudgetProvider<'workspace> {
    inner: WorkspaceIcfgProvider<'workspace>,
    retain_payload: bool,
}

impl DispatchOracle for ExceededCallBudgetProvider<'_> {
    fn resolve_call(
        &self,
        call: &CallSiteHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<DispatchResult>, SemanticProviderError> {
        self.inner.resolve_call(call, request)
    }
}

impl IcfgProvider for ExceededCallBudgetProvider<'_> {
    fn call_transfers(
        &self,
        caller: &ProcedureHandle,
        call: CallSiteId,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<CallTransferSet>, SemanticProviderError> {
        let partial = if self.retain_payload {
            let mut payload_budget = SemanticBudget::default();
            self.inner
                .call_transfers(
                    caller,
                    call,
                    &mut SemanticRequest::new(&mut payload_budget, request.cancellation),
                )?
                .available_value()
                .cloned()
        } else {
            None
        };

        let completed = SemanticWork {
            nested_entries: 1,
            ..SemanticWork::default()
        };
        request
            .budget
            .charge(completed)
            .expect("semantic-budget fixture has room for completed work");
        let attempted = SemanticWork {
            program_points: request
                .budget
                .remaining()
                .program_points
                .checked_add(1)
                .expect("default semantic budget remains finite"),
            ..SemanticWork::default()
        };
        let exceeded = request
            .budget
            .charge(attempted)
            .expect_err("fixture deliberately exceeds program-point work");
        Ok(SemanticOutcome::ExceededBudget {
            partial,
            exceeded,
            work: completed,
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
fn recursive_summary_deltas_replay_until_a_multi_fact_fixed_point() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/replay.ts",
            r#"
                function recurse(n: number): number {
                    if (n <= 0) return 0;
                    return recurse(n - 1);
                }

                function root(): number {
                    return recurse(2);
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let root = resolve_procedure_handle(
        &project,
        &analyzer,
        "src/replay.ts",
        PointSelector::new("function root")
            .procedure("root")
            .effect("entry"),
    );
    let call = root
        .semantics()
        .call_sites()
        .first()
        .expect("root has one recursive-callee call");
    let continuation = root
        .point_handle(
            call.normal_continuation
                .target()
                .expect("root call has a normal continuation"),
        )
        .expect("root continuation remains valid");
    let provider = analyzer.icfg_provider();
    let result = solve_default(
        &root,
        &[ReplayWaveFact::Wave0],
        &provider,
        &ReplayWaveProblem,
    );

    assert_eq!(result.termination(), SolverTermination::FixedPoint);
    assert!(
        facts_at(&result, &continuation).contains(&ReplayWaveFact::Wave2),
        "Wave2 requires two recursive end-summary delta replays",
    );
    assert!(
        result.metrics().summary_applications >= 3,
        "the recursive incoming row must consume successive Wave0, Wave1, and Wave2 summaries",
    );

    let mut reference_budget =
        SemanticBudget::uniform(100_000_000).expect("positive reference budget");
    let reference = reference_summary_projection(
        &root,
        &[ReplayWaveFact::Wave0],
        &provider,
        &ReplayWaveProblem,
        &mut reference_budget,
    )
    .expect("multi-wave recursive reference fixed point");
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
    let leaf = resolve_procedure_handle(
        &project,
        &analyzer,
        "src/Shared.java",
        PointSelector::new("static int leaf")
            .procedure("leaf")
            .effect("entry"),
    );
    let leaf_entry = leaf
        .point_handle(leaf.semantics().entry_point())
        .expect("leaf entry");
    let leaf_normal_exit = leaf
        .point_handle(leaf.semantics().normal_exit_point())
        .expect("leaf normal exit");
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
    let provider = CountingProvider::new(analyzer.icfg_provider());
    let result = solve_default(&root, &[CallIdentityFact::Root], &provider, &problem);

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
    assert_eq!(
        provider.exit_count(&leaf_entry, &leaf_normal_exit),
        1,
        "the exact leaf entry/normal-exit profile must be provider-materialized once",
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
    let provider = CountingProvider::new(analyzer.icfg_provider());
    let result = solve_default(&root, &[MarkerFact::Seed], &provider, &MarkerProblem);

    assert_eq!(result.termination(), SolverTermination::FixedPoint);
    assert_eq!(
        provider.call_count(&root, call.id),
        1,
        "zero and explicit facts must share one provider materialization",
    );
    assert!(
        result.metrics().provider_cache_hits > 0,
        "the explicit seed should consume the cached call-to-return projection",
    );
    assert!(
        facts_at(&result, &continuation).contains(&MarkerFact::Seed),
        "the explicit seed must reach the deferred continuation through the cache hit",
    );
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
fn semantic_budget_outcomes_preserve_payload_work_and_coverage() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/SemanticBudget.java",
            r#"
                class SemanticBudgetFixture {
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
        "src/SemanticBudget.java",
        PointSelector::new("static int root")
            .procedure("root")
            .effect("entry"),
    );
    let leaf = resolve_procedure_handle(
        &project,
        &analyzer,
        "src/SemanticBudget.java",
        PointSelector::new("static int leaf")
            .procedure("leaf")
            .effect("entry"),
    );

    for retain_payload in [false, true] {
        let provider = ExceededCallBudgetProvider {
            inner: analyzer.icfg_provider(),
            retain_payload,
        };
        let cancellation = CancellationToken::default();
        let mut solver_budget = SolverBudget::default();
        let mut semantic_budget = SemanticBudget::default();
        let result = solve_with_summaries(
            SummarySolveInput::new(&root, &[]),
            &provider,
            &direct_problem(),
            &mut semantic_budget,
            &mut DataflowRequest::new(&mut solver_budget, &cancellation),
        )
        .expect("semantic-budget outcome is a typed solver result");

        assert_eq!(
            result.termination(),
            SolverTermination::FixedPoint,
            "semantic exhaustion must not be mislabeled as solver-budget exhaustion",
        );
        let SummarySemanticStatus::ExceededBudget { exceeded } =
            result.coverage().semantic_status()
        else {
            panic!(
                "semantic exhaustion must remain visible in coverage: {:?}",
                result.coverage()
            );
        };
        assert_eq!(exceeded.dimension(), SemanticBudgetDimension::ProgramPoints,);
        assert_eq!(result.semantic_work(), semantic_budget.used());
        assert!(
            result.semantic_work().nested_entries >= 1,
            "completed provider work must survive the exceeded envelope",
        );
        assert!(!result.is_complete());

        let reached_leaf = result
            .reached()
            .iter()
            .any(|reached| reached.entry().procedure() == &leaf);
        assert_eq!(
            reached_leaf, retain_payload,
            "only a retained partial payload may publish the callee entry",
        );
    }
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
    let entry = root
        .point_handle(root.semantics().entry_point())
        .expect("root entry");
    let first_target = root
        .semantics()
        .successor_edges(entry.id())
        .next()
        .and_then(|(_, edge)| root.point_handle(edge.target_point))
        .expect("root entry has one normal successor");
    let mut solver_budget = SolverBudget::default();
    let mut semantic_budget = SemanticBudget::default();
    let result = solve_with_summaries(
        SummarySolveInput::new(&root, &[CancellationFact::Seed]),
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
        2,
        "the callback's cancelled relation must not become visible",
    );
    assert!(
        !result.facts().contains(&CancellationFact::Staged),
        "the fact staged before cancellation must not be interned",
    );
    assert!(
        !facts_at(&result, &first_target).contains(&CancellationFact::Staged),
        "the exact transfer target must not publish the staged fact",
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
    let continuation = root
        .semantics()
        .call_sites()
        .first()
        .and_then(|call| call.normal_continuation.target())
        .and_then(|point| root.point_handle(point))
        .expect("root call has a normal continuation");
    let mut solver_budget = SolverBudget::default();
    let mut semantic_budget = SemanticBudget::default();
    let result = solve_with_summaries(
        SummarySolveInput::new(&root, &[CancellationFact::Seed]),
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
    assert!(
        !result.facts().contains(&CancellationFact::Staged),
        "the return fact staged before cancellation must not be interned",
    );
    assert!(
        !facts_at(&result, &continuation).contains(&CancellationFact::Staged),
        "the exact matched-return continuation must not publish the staged fact",
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
fn malformed_call_boundary_provenance_fails_as_a_provider_error() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("leaf.rs", "pub async fn async_leaf() -> i32 { 7 }\n")
        .file(
            "lib.rs",
            "mod leaf;\nuse crate::leaf::async_leaf;\npub fn root() { let _pending = async_leaf(); }\n",
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

    for corruption in [
        CallTransferCorruption::BoundaryEmptyProvenance,
        CallTransferCorruption::BoundaryWrongSubject,
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
        .expect_err("malformed dispatch provenance must fail closed");

        assert!(
            matches!(error, SummaryDataflowError::SemanticProvider(_)),
            "unexpected error for {corruption:?}: {error:?}",
        );
        assert!(
            error.to_string().contains("invalid dispatch provenance"),
            "unexpected error for {corruption:?}: {error}",
        );
    }
}

#[test]
fn replayed_exit_profiles_must_match_the_exact_requested_entry_and_exit() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/Replay.java",
            r#"
                class Replay {
                    static int leaf() { return 1; }
                    static int foreign() { return 2; }
                    static int root() { return leaf(); }
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let root = resolve_procedure_handle(
        &project,
        &analyzer,
        "src/Replay.java",
        PointSelector::new("static int root")
            .procedure("root")
            .effect("entry"),
    );
    let leaf = resolve_procedure_handle(
        &project,
        &analyzer,
        "src/Replay.java",
        PointSelector::new("static int leaf")
            .procedure("leaf")
            .effect("entry"),
    );
    let foreign = resolve_procedure_handle(
        &project,
        &analyzer,
        "src/Replay.java",
        PointSelector::new("static int foreign")
            .procedure("foreign")
            .effect("entry"),
    );
    let leaf_entry = leaf
        .point_handle(leaf.semantics().entry_point())
        .expect("leaf entry");
    let leaf_normal = leaf
        .point_handle(leaf.semantics().normal_exit_point())
        .expect("leaf normal exit");
    let leaf_exceptional = leaf
        .point_handle(leaf.semantics().exceptional_exit_point())
        .expect("leaf exceptional exit");
    let foreign_entry = foreign
        .point_handle(foreign.semantics().entry_point())
        .expect("foreign entry");
    let foreign_exit = foreign
        .point_handle(foreign.semantics().normal_exit_point())
        .expect("foreign normal exit");
    let inner = analyzer.icfg_provider();
    let cancellation = CancellationToken::default();
    let materialize = |entry, exit| {
        let mut budget = SemanticBudget::default();
        inner
            .exit_profile(
                entry,
                exit,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("valid replay profile")
    };
    let cases = [
        (
            "wrong entry",
            materialize(&leaf_normal, &leaf_normal),
            "entry does not match",
        ),
        (
            "wrong exit",
            materialize(&leaf_entry, &leaf_exceptional),
            "exit does not match",
        ),
        (
            "foreign procedure",
            materialize(&foreign_entry, &foreign_exit),
            "entry does not match",
        ),
    ];

    for (label, replay, expected) in cases {
        let provider = ReplayingExitProvider {
            inner,
            intercepted_entry: leaf_entry.clone(),
            intercepted_exit: leaf_normal.clone(),
            replay,
        };
        let mut solver_budget = SolverBudget::default();
        let mut semantic_budget = SemanticBudget::default();
        let error = solve_with_summaries(
            SummarySolveInput::new(&root, &[]),
            &provider,
            &direct_problem(),
            &mut semantic_budget,
            &mut DataflowRequest::new(&mut solver_budget, &cancellation),
        )
        .expect_err("replayed exit profile must fail closed");

        assert!(
            matches!(error, SummaryDataflowError::SemanticProvider(_)),
            "unexpected {label} error: {error:?}",
        );
        assert!(
            error.to_string().contains(expected),
            "unexpected {label} error: {error}",
        );
    }
}

#[test]
fn duplicate_root_inputs_are_bounded_before_seed_scratch_can_grow() {
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
    let mut limits = SolverBudget::default().limits();
    limits.callback_rows = 1;
    let mut solver_budget = SolverBudget::new(limits);
    let mut semantic_budget = SemanticBudget::default();
    let cancellation = CancellationToken::default();
    let result = solve_with_summaries(
        SummarySolveInput::new(&root, &[MarkerFact::Seed, MarkerFact::Seed]),
        &analyzer.icfg_provider(),
        &MarkerProblem,
        &mut semantic_budget,
        &mut DataflowRequest::new(&mut solver_budget, &cancellation),
    )
    .expect("valid bounded root input");

    let exceeded = result
        .termination()
        .budget_exceeded()
        .expect("the second supplied input row must be bounded");
    assert_eq!(exceeded.dimension(), SolverBudgetDimension::CallbackRows);
    assert_eq!(exceeded.limit(), 1);
    assert_eq!(exceeded.attempted(), 2);
    assert!(
        result.facts().is_empty(),
        "failed root admission must remain atomic",
    );
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

    match dimension {
        SolverBudgetDimension::ProviderMaterializations => {
            assert_eq!(result.metrics().provider_materializations, 0);
            assert!(result.end_summaries().is_empty());
            assert!(result.coverage().boundaries().is_empty());
        }
        SolverBudgetDimension::EndSummaries => {
            assert!(
                result.end_summaries().is_empty(),
                "a rejected end-summary publication must leave no prefix",
            );
        }
        SolverBudgetDimension::IncomingCalls => {
            assert!(
                result
                    .reached()
                    .iter()
                    .all(|reached| reached.entry().procedure() == root),
                "a rejected incoming relation must not publish its callee entry",
            );
        }
        SolverBudgetDimension::SummaryApplications => {
            let continuation = root
                .semantics()
                .call_sites()
                .first()
                .and_then(|call| call.normal_continuation.target())
                .and_then(|point| root.point_handle(point))
                .expect("summary-application fixture has a normal continuation");
            assert!(
                result.reached_at(&continuation).next().is_none(),
                "a rejected matched return must not publish its continuation",
            );
        }
        SolverBudgetDimension::CoverageRows => {
            assert!(result.coverage().boundaries().is_empty());
            assert!(result.coverage().unproven_edges().is_empty());
            assert!(result.coverage().partial_edges().is_empty());
        }
        other => panic!("not a summary-specific dimension: {other:?}"),
    }
}

#[test]
fn multi_output_incoming_budget_rejects_the_entire_staged_prefix() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/AtomicIncoming.java",
            r#"
                class AtomicIncoming {
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
        "src/AtomicIncoming.java",
        PointSelector::new("static int root")
            .procedure("root")
            .effect("entry"),
    );
    let mut limits = SolverBudget::default().limits();
    limits.incoming_calls = 1;
    let mut solver_budget = SolverBudget::new(limits);
    let mut semantic_budget = SemanticBudget::default();
    let cancellation = CancellationToken::default();
    let result = solve_with_summaries(
        SummarySolveInput::new(&root, &[PermutedFact::Seed]),
        &analyzer.icfg_provider(),
        &PermutedProblem { reverse: false },
        &mut semantic_budget,
        &mut DataflowRequest::new(&mut solver_budget, &cancellation),
    )
    .expect("valid atomic incoming-budget fixture");

    let exceeded = result
        .termination()
        .budget_exceeded()
        .expect("the second distinct staged incoming row exceeds the limit");
    assert_eq!(exceeded.dimension(), SolverBudgetDimension::IncomingCalls);
    assert_eq!(exceeded.limit(), 1);
    assert_eq!(exceeded.attempted(), 2);
    assert!(
        result
            .reached()
            .iter()
            .all(|reached| reached.entry().procedure() == &root),
        "none of the non-empty staged incoming prefix may publish",
    );
    assert_eq!(
        result.work().incoming_calls,
        0,
        "the one-row staged prefix must not consume retained incoming work",
    );
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

#[test]
fn boundary_provenance_order_is_deterministic_at_an_exact_coverage_limit() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("leaf.rs", "pub async fn async_leaf() -> i32 { 7 }\n")
        .file(
            "lib.rs",
            "mod leaf;\nuse crate::leaf::async_leaf;\npub fn root() { let _pending = async_leaf(); }\n",
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
        .expect("boundary fixture retains one call");
    let inner = analyzer.icfg_provider();
    let cancellation = CancellationToken::default();
    let mut materialization_budget = SemanticBudget::default();
    let outcome = inner
        .call_transfers(
            &root,
            call.id,
            &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
        )
        .expect("deferred call transfer");
    assert!(
        matches!(outcome, SemanticOutcome::Complete { .. }),
        "the coverage limit must first encounter dispatch boundaries",
    );
    let original = outcome
        .available_value()
        .and_then(|transfers| transfers.boundaries.first())
        .cloned()
        .expect("deferred boundary");
    let original_relation = original
        .dispatch
        .provenance
        .first()
        .expect("deferred boundary provenance");
    let duplicate_arena = OracleRelationArena::new(
        original_relation.owner().clone(),
        vec![original_relation.record().clone()],
        OracleLimits::default(),
    )
    .expect("parallel valid provenance arena");
    let mut duplicate = original.clone();
    duplicate.dispatch.provenance = vec![
        duplicate_arena
            .handle(OracleRelationId::new(0))
            .expect("parallel provenance handle"),
    ]
    .into_boxed_slice();
    assert_ne!(original, duplicate);

    let forward_provider = BoundaryOrderProvider {
        inner,
        boundaries: vec![original.clone(), duplicate.clone()].into_boxed_slice(),
    };
    let reverse_provider = BoundaryOrderProvider {
        inner,
        boundaries: vec![duplicate, original].into_boxed_slice(),
    };
    let solve = |provider: &BoundaryOrderProvider<'_>| {
        let mut limits = SolverBudget::default().limits();
        limits.coverage_rows = 1;
        let mut solver_budget = SolverBudget::new(limits);
        let mut semantic_budget = SemanticBudget::default();
        solve_with_summaries(
            SummarySolveInput::new(&root, &[]),
            provider,
            &direct_problem(),
            &mut semantic_budget,
            &mut DataflowRequest::new(&mut solver_budget, &cancellation),
        )
        .expect("valid boundary permutation")
    };
    let forward = solve(&forward_provider);
    let reverse = solve(&reverse_provider);

    assert_eq!(forward.termination(), reverse.termination());
    assert_eq!(forward.work(), reverse.work());
    assert_eq!(forward.coverage(), reverse.coverage());
    assert_eq!(forward.coverage().boundaries().len(), 1);
    let exceeded = forward
        .termination()
        .budget_exceeded()
        .expect("the second distinct provenance row exceeds the exact limit");
    assert_eq!(exceeded.dimension(), SolverBudgetDimension::CoverageRows);
    assert_eq!(exceeded.limit(), 1);
    assert_eq!(exceeded.attempted(), 2);
}
