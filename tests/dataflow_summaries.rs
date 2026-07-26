mod common;

use std::{
    cell::{Cell, RefCell},
    collections::{HashMap, HashSet},
};

use brokk_bifrost::analyzer::dataflow::{
    DataflowEdge, DataflowOutput, DataflowRequest, DirectFact, DirectFlowProblem,
    DistributiveDataflowProblem, PathQuality, ReusableEndSummary, ReusableProcedureSummary,
    ReusableReachedFact, ReusableSummaryProvider, SolverBudget, SolverBudgetDimension,
    SolverTermination, SolverWork, SummaryBoundaryKind, SummaryDataflowError,
    SummaryDataflowResult, SummaryReachedFact, SummarySemanticStatus, SummarySolveInput,
    SummaryWitness, SummaryWitnessError, SummaryWitnessStepKind, WitnessReconstructionLimits,
    WitnessRetentionLimits, solve_with_reusable_end_summaries, solve_with_summaries,
};
use brokk_bifrost::analyzer::semantic::{
    CallBoundary, CallSiteHandle, CallSiteId, CallTransferSet, CancellationToken,
    ControlContinuation, DispatchBoundaryKind, DispatchOracle, DispatchResult,
    EvidenceCompleteness, IcfgBoundaryKind, IcfgEdgeKind, IcfgExitProfile, IcfgLimitKind,
    IcfgProvider, IcfgSnapshot, IcfgSnapshotLimits, OracleLimits, OracleRelationArena,
    OracleRelationId, ProcedureHandle, ProgramPointHandle, ProofStatus, ReturnTransferKind,
    SemanticBudget, SemanticBudgetDimension, SemanticOutcome, SemanticProviderError,
    SemanticRequest, SemanticWork, WorkspaceIcfgProvider,
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

struct FixedDirectSummaryProvider {
    callee: ProcedureHandle,
    observation: ProgramPointHandle,
    exit_kinds: Box<[ReturnTransferKind]>,
    cancellation: Option<CancellationToken>,
    calls: Cell<usize>,
}

impl ReusableSummaryProvider<DirectFact> for FixedDirectSummaryProvider {
    fn summary_for(
        &mut self,
        procedure: &ProcedureHandle,
        _entry_fact: DirectFact,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Option<ReusableProcedureSummary<DirectFact>>, SolverTermination> {
        if procedure != &self.callee {
            return Ok(None);
        }
        self.calls.set(self.calls.get().saturating_add(1));
        if let Some(cancellation) = &self.cancellation {
            cancellation.cancel();
        }
        if request.cancellation.is_cancelled() {
            return Err(SolverTermination::Cancelled);
        }
        let rows = self.exit_kinds.len().saturating_add(1);
        if let Some(termination) = request.reserve(SolverWork {
            callback_rows: rows,
            propagated_outputs: rows,
            ..SolverWork::default()
        }) {
            return Err(termination);
        }
        Ok(Some(ReusableProcedureSummary {
            exits: self
                .exit_kinds
                .iter()
                .copied()
                .map(|exit_kind| ReusableEndSummary {
                    exit_kind,
                    exit_fact: DirectFact,
                    qualities: vec![PathQuality::PROVEN_COMPLETE].into_boxed_slice(),
                })
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            reached: vec![ReusableReachedFact {
                point: self.observation.clone(),
                fact: DirectFact,
                qualities: vec![PathQuality::PROVEN_COMPLETE].into_boxed_slice(),
            }]
            .into_boxed_slice(),
        }))
    }
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
    incomparable_calls: bool,
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
            incomparable_calls: false,
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

    const fn with_incomparable_call_evidence(mut self) -> Self {
        self.incomparable_calls = true;
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
        if self.incomparable_calls {
            outcome = outcome.map(|mut transfers| {
                assert!(
                    transfers.transfers.len() >= 2,
                    "incomparable fixture needs two call targets",
                );
                transfers.transfers[0].proof = ProofStatus::Proven;
                transfers.transfers[0].completeness =
                    EvidenceCompleteness::Partial("test partial target".into());
                transfers.transfers[1].proof = ProofStatus::Unproven("test unproven target".into());
                transfers.transfers[1].completeness = EvidenceCompleteness::Complete;
                transfers
            });
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

fn solve_with_witnesses<P, Provider>(
    root: &ProcedureHandle,
    entry_facts: &[P::Fact],
    provider: &Provider,
    problem: &P,
) -> SummaryDataflowResult<P::Fact>
where
    P: DistributiveDataflowProblem,
    Provider: IcfgProvider + ?Sized,
{
    solve_with_witness_limit(
        root,
        entry_facts,
        provider,
        problem,
        WitnessRetentionLimits::new(2).unwrap(),
    )
}

fn solve_with_witness_limit<P, Provider>(
    root: &ProcedureHandle,
    entry_facts: &[P::Fact],
    provider: &Provider,
    problem: &P,
    witness_retention: WitnessRetentionLimits,
) -> SummaryDataflowResult<P::Fact>
where
    P: DistributiveDataflowProblem,
    Provider: IcfgProvider + ?Sized,
{
    let cancellation = CancellationToken::default();
    let mut solver_budget = SolverBudget::default();
    let mut semantic_budget = SemanticBudget::default();
    solve_with_summaries(
        SummarySolveInput::new(root, entry_facts).with_witness_retention(witness_retention),
        provider,
        problem,
        &mut semantic_budget,
        &mut DataflowRequest::new(&mut solver_budget, &cancellation),
    )
    .expect("valid summary witness fixture")
}

fn reached_fact<'result, F>(
    result: &'result SummaryDataflowResult<F>,
    point: &'result ProgramPointHandle,
    fact: F,
) -> &'result SummaryReachedFact
where
    F: Copy + Eq,
{
    result
        .reached_at(point)
        .find(|reached| result.fact(reached.fact()).copied() == Some(fact))
        .expect("requested fact reaches the selected point")
}

fn assert_all_retained_witnesses_reconstruct<F>(result: &SummaryDataflowResult<F>) {
    for reached in result.reached() {
        for quality in reached.path_qualities().iter() {
            let witness = result
                .witness_for_reached(reached, quality, WitnessReconstructionLimits::default())
                .expect("every active reached quality has valid evidence");
            assert_eq!(witness.quality(), quality);
            if !witness.truncated() {
                assert_eq!(fold_witness_quality(&witness), quality);
            }
        }
    }
    for summary in result.end_summaries() {
        for quality in summary.path_qualities().iter() {
            let witness = result
                .witness_for_end_summary(summary, quality, WitnessReconstructionLimits::default())
                .expect("every active end-summary quality has valid evidence");
            assert_eq!(witness.quality(), quality);
            if !witness.truncated() {
                assert_eq!(fold_witness_quality(&witness), quality);
            }
        }
    }
}

fn fold_witness_quality(witness: &SummaryWitness) -> PathQuality {
    let proven = witness
        .steps()
        .iter()
        .all(|step| matches!(step.proof(), ProofStatus::Proven));
    let complete = witness
        .steps()
        .iter()
        .all(|step| matches!(step.completeness(), EvidenceCompleteness::Complete));
    match (proven, complete) {
        (true, true) => PathQuality::PROVEN_COMPLETE,
        (true, false) => PathQuality::PROVEN_PARTIAL,
        (false, true) => PathQuality::UNPROVEN_COMPLETE,
        (false, false) => PathQuality::UNPROVEN_PARTIAL,
    }
}

fn complete_snapshot<Provider>(root: &ProcedureHandle, provider: &Provider) -> IcfgSnapshot
where
    Provider: IcfgProvider + ?Sized,
{
    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    let outcome = provider
        .snapshot(
            root,
            IcfgSnapshotLimits::default(),
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("valid witness-validation snapshot");
    outcome
        .available_value()
        .cloned()
        .expect("complete snapshot retains its graph")
}

fn assert_witness_matches_snapshot(witness: &SummaryWitness, snapshot: &IcfgSnapshot) {
    for step in witness.steps() {
        match step.kind() {
            SummaryWitnessStepKind::Seed => assert!(
                snapshot
                    .nodes()
                    .iter()
                    .any(|node| node.point() == step.source()),
                "witness seed must be a real snapshot program point",
            ),
            SummaryWitnessStepKind::Edge(kind) => {
                let target = step.target().expect("edge witness has a target");
                assert!(
                    snapshot.edges().iter().any(|edge| {
                        edge.kind == kind
                            && edge.origin.as_ref() == step.origin()
                            && &edge.proof == step.proof()
                            && &edge.completeness == step.completeness()
                            && snapshot
                                .node(edge.source)
                                .is_some_and(|node| node.point() == step.source())
                            && snapshot
                                .node(edge.target)
                                .is_some_and(|node| node.point() == target)
                    }),
                    "witness edge must match an independently materialized semantic ICFG edge: {step:?}",
                );
            }
            SummaryWitnessStepKind::EndSummaryGap(_) => {
                assert!(step.target().is_none());
                assert!(step.origin().is_none());
                assert!(matches!(step.proof(), ProofStatus::Unproven(_)));
                assert!(matches!(
                    step.completeness(),
                    EvidenceCompleteness::Partial(_)
                ));
                assert!(
                    snapshot
                        .nodes()
                        .iter()
                        .any(|node| node.point() == step.source()),
                    "end-summary gap must be attached to a real exit point",
                );
            }
        }
    }
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
fn intraprocedural_witness_is_opt_in_source_backed_and_bounded() {
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
    let provider = analyzer.icfg_provider();

    let without_witnesses = solve_default(&root, &[MarkerFact::Seed], &provider, &MarkerProblem);
    let reached = reached_fact(&without_witnesses, &exit, MarkerFact::Seed);
    assert_eq!(
        without_witnesses
            .witness_for_reached(
                reached,
                PathQuality::PROVEN_COMPLETE,
                WitnessReconstructionLimits::default(),
            )
            .unwrap_err(),
        SummaryWitnessError::RetentionDisabled,
    );

    let result = solve_with_witnesses(&root, &[MarkerFact::Seed], &provider, &MarkerProblem);
    let reached = reached_fact(&result, &exit, MarkerFact::Seed);
    let witness = result
        .witness_for_reached(
            reached,
            PathQuality::PROVEN_COMPLETE,
            WitnessReconstructionLimits::default(),
        )
        .expect("intraprocedural witness");
    assert_eq!(witness.quality(), PathQuality::PROVEN_COMPLETE);
    assert!(!witness.truncated());
    assert_eq!(witness.omitted_steps_lower_bound(), 0);
    assert!(witness.work().evidence_expansions() >= witness.steps().len());
    assert_eq!(
        witness.steps().first().map(|step| step.kind()),
        Some(SummaryWitnessStepKind::Seed),
    );
    assert_eq!(
        witness.steps().last().and_then(|step| step.target()),
        Some(&exit),
    );
    assert!(witness.steps().iter().skip(1).all(|step| matches!(
        step.kind(),
        SummaryWitnessStepKind::Edge(IcfgEdgeKind::Intraprocedural(_))
    )));
    assert_witness_matches_snapshot(&witness, &complete_snapshot(&root, &provider));
    let end_summary = result
        .end_summaries()
        .iter()
        .find(|summary| {
            summary.entry().procedure() == &root
                && summary.exit_kind() == ReturnTransferKind::Normal
                && result.fact(summary.exit_fact()) == Some(&MarkerFact::Seed)
        })
        .expect("root seed has a normal end summary");
    let end_witness = result
        .witness_for_end_summary(
            end_summary,
            end_summary
                .path_qualities()
                .iter()
                .next()
                .expect("end summary retains one quality"),
            WitnessReconstructionLimits::default(),
        )
        .expect("end-summary witness");
    let last_end_step = end_witness.steps().last().expect("non-empty end witness");
    match last_end_step.kind() {
        SummaryWitnessStepKind::EndSummaryGap(ReturnTransferKind::Normal) => {
            assert_eq!(last_end_step.source(), &exit);
            assert_eq!(last_end_step.target(), None);
        }
        SummaryWitnessStepKind::Edge(_) => assert_eq!(last_end_step.target(), Some(&exit)),
        other => panic!("unexpected terminal end-summary witness step: {other:?}"),
    }
    assert_eq!(fold_witness_quality(&end_witness), end_witness.quality());
    let shallow_end_witness_bytes = std::mem::size_of_val(&end_witness)
        + end_witness
            .steps()
            .iter()
            .map(std::mem::size_of_val)
            .sum::<usize>();
    if matches!(
        last_end_step.kind(),
        SummaryWitnessStepKind::EndSummaryGap(_)
    ) {
        assert!(
            end_witness.retained_bytes() > shallow_end_witness_bytes,
            "owned gap reasons must be included in retained-byte accounting",
        );
    }

    let cloned_reached = reached.clone();
    result
        .witness_for_reached(
            &cloned_reached,
            PathQuality::PROVEN_COMPLETE,
            WitnessReconstructionLimits::default(),
        )
        .expect("a cloned row retains this result's witness ownership");
    let other_result = solve_with_witnesses(&root, &[MarkerFact::Seed], &provider, &MarkerProblem);
    assert_eq!(
        other_result
            .witness_for_reached(
                reached,
                PathQuality::PROVEN_COMPLETE,
                WitnessReconstructionLimits::default(),
            )
            .unwrap_err(),
        SummaryWitnessError::TargetNotInResult,
    );

    let truncated = result
        .witness_for_reached(
            reached,
            PathQuality::PROVEN_COMPLETE,
            WitnessReconstructionLimits::new(1, 64).unwrap(),
        )
        .expect("bounded witness prefix");
    assert!(truncated.truncated());
    assert_eq!(truncated.steps().len(), 1);
    assert!(truncated.omitted_steps_lower_bound() > 0);
    let expansion_limited = result
        .witness_for_reached(
            reached,
            PathQuality::PROVEN_COMPLETE,
            WitnessReconstructionLimits::new(64, 1).unwrap(),
        )
        .expect("expansion-bounded witness prefix");
    assert!(expansion_limited.truncated());
    assert_eq!(expansion_limited.work().evidence_expansions(), 1);
    assert!(expansion_limited.omitted_steps_lower_bound() > 0);
}

#[test]
fn best_effort_witness_exhaustion_does_not_change_semantic_results() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
                pub fn root(value: i32) -> i32 {
                    value + 1
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
    let solve = |entry_facts: &[MarkerFact],
                 retention: WitnessRetentionLimits,
                 witness_relations: usize| {
        let cancellation = CancellationToken::default();
        let mut limits = SolverBudget::default().limits();
        limits.witness_relations = witness_relations;
        let mut solver_budget = SolverBudget::new(limits);
        let mut semantic_budget = SemanticBudget::default();
        solve_with_summaries(
            SummarySolveInput::new(&root, entry_facts).with_witness_retention(retention),
            &provider,
            &MarkerProblem,
            &mut semantic_budget,
            &mut DataflowRequest::new(&mut solver_budget, &cancellation),
        )
        .expect("valid best-effort witness fixture")
    };

    let baseline = solve(&[MarkerFact::Seed], WitnessRetentionLimits::disabled(), 0);
    let request_exhausted = solve(
        &[MarkerFact::Seed],
        WitnessRetentionLimits::best_effort(1, 64, 64 * 1024 * 1024).unwrap(),
        0,
    );
    let local_exhausted = solve(
        &[MarkerFact::Seed],
        WitnessRetentionLimits::best_effort(1, 1, 64 * 1024 * 1024).unwrap(),
        64,
    );
    let byte_exhausted = solve(
        &[MarkerFact::Seed],
        WitnessRetentionLimits::best_effort(1, 64, 1).unwrap(),
        64,
    );
    for candidate in [&request_exhausted, &local_exhausted, &byte_exhausted] {
        assert_eq!(candidate.facts(), baseline.facts());
        assert_eq!(candidate.reached(), baseline.reached());
        assert_eq!(candidate.end_summaries(), baseline.end_summaries());
        assert_eq!(candidate.coverage(), baseline.coverage());
        assert_eq!(candidate.termination(), baseline.termination());
        assert_eq!(candidate.work(), baseline.work());
        assert_eq!(candidate.semantic_work(), baseline.semantic_work());
        assert_eq!(candidate.metrics(), baseline.metrics());
        assert!(candidate.witness_retention_truncated());

        let reached = candidate
            .reached()
            .iter()
            .find(|reached| candidate.fact(reached.fact()) == Some(&MarkerFact::Seed))
            .expect("seed remains semantically reachable");
        let quality = reached
            .path_qualities()
            .iter()
            .next()
            .expect("reached row retains one quality");
        let marker = candidate
            .witness_for_reached(reached, quality, WitnessReconstructionLimits::default())
            .expect("best-effort exhaustion is explicit");
        assert!(marker.steps().is_empty());
        assert!(marker.truncated());
        assert!(marker.alternatives_truncated());
        assert!(marker.retention_truncated());
        assert_eq!(marker.omitted_steps_lower_bound(), 1);
    }

    let late_baseline = solve(&[], WitnessRetentionLimits::disabled(), 0);
    let late_exhausted = solve(
        &[],
        WitnessRetentionLimits::best_effort(1, 1, 64 * 1024 * 1024).unwrap(),
        64,
    );
    let late_request_exhausted = solve(
        &[],
        WitnessRetentionLimits::best_effort(1, 64, 64 * 1024 * 1024).unwrap(),
        1,
    );
    for candidate in [&late_exhausted, &late_request_exhausted] {
        assert_eq!(candidate.facts(), late_baseline.facts());
        assert_eq!(candidate.reached(), late_baseline.reached());
        assert_eq!(candidate.end_summaries(), late_baseline.end_summaries());
        assert_eq!(candidate.coverage(), late_baseline.coverage());
        assert_eq!(candidate.termination(), late_baseline.termination());
        let mut candidate_work = candidate.work();
        let mut late_baseline_work = late_baseline.work();
        candidate_work.witness_relations = 0;
        late_baseline_work.witness_relations = 0;
        assert_eq!(candidate_work, late_baseline_work);
        assert!(candidate.witness_retention_truncated());
    }
}

#[test]
fn witness_alternative_retention_reports_its_strict_cap() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
                pub fn root(flag: bool) -> i32 {
                    let value;
                    if flag {
                        value = 1;
                    } else {
                        value = 2;
                    }
                    value
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
    let provider = analyzer.icfg_provider();
    let result = solve_with_witness_limit(
        &root,
        &[MarkerFact::Seed],
        &provider,
        &MarkerProblem,
        WitnessRetentionLimits::new(1).unwrap(),
    );
    let witness = result
        .witness_for_reached(
            reached_fact(&result, &exit, MarkerFact::Seed),
            PathQuality::PROVEN_COMPLETE,
            WitnessReconstructionLimits::default(),
        )
        .expect("one retained branch witness");
    assert!(
        witness.alternatives_truncated(),
        "the second branch must be reported rather than retained beyond the cap",
    );
}

#[test]
fn witness_budget_stop_preserves_a_reconstructable_published_prefix() {
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
    let mut limits = SolverBudget::default().limits();
    limits.witness_relations = 2;
    let mut solver_budget = SolverBudget::new(limits);
    let mut semantic_budget = SemanticBudget::default();
    let result = solve_with_summaries(
        SummarySolveInput::new(&root, &[MarkerFact::Seed])
            .with_witness_retention(WitnessRetentionLimits::new(2).unwrap()),
        &analyzer.icfg_provider(),
        &MarkerProblem,
        &mut semantic_budget,
        &mut DataflowRequest::new(&mut solver_budget, &cancellation),
    )
    .expect("witness budget is a typed partial result");

    let exceeded = result
        .termination()
        .budget_exceeded()
        .expect("the first propagated witness relation exceeds the exact cap");
    assert_eq!(
        exceeded.dimension(),
        SolverBudgetDimension::WitnessRelations
    );
    assert_eq!(result.work().witness_relations, 2);
    assert_eq!(
        result.reached().len(),
        2,
        "both atomically admitted root seeds remain visible",
    );
    assert_all_retained_witnesses_reconstruct(&result);
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
    let result = solve_with_witnesses(&root, &[], &provider, &problem);
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
    assert_all_retained_witnesses_reconstruct(&result);

    let best_effort = solve_with_witness_limit(
        &root,
        &[],
        &provider,
        &problem,
        WitnessRetentionLimits::best_effort(1, 65_536, 64 * 1024 * 1024).unwrap(),
    );
    let entry = root
        .point_handle(root.semantics().entry_point())
        .expect("recursive root entry");
    let entry_witness = best_effort
        .witness_for_reached(
            reached_fact(&best_effort, &entry, DirectFact),
            PathQuality::PROVEN_COMPLETE,
            WitnessReconstructionLimits::default(),
        )
        .expect("recursive root seed witness");
    assert!(
        !entry_witness.alternatives_truncated(),
        "replaying the identical recursive entry seed is a duplicate, not an omitted alternative",
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
    let result = solve_with_witnesses(
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
    let wave_two_witness = result
        .witness_for_reached(
            reached_fact(&result, &continuation, ReplayWaveFact::Wave2),
            reached_fact(&result, &continuation, ReplayWaveFact::Wave2)
                .path_qualities()
                .iter()
                .next()
                .expect("Wave2 retains one concrete quality"),
            WitnessReconstructionLimits::default(),
        )
        .expect("multi-wave summary replay witness");
    assert!(wave_two_witness.steps().iter().any(|step| {
        step.kind() == SummaryWitnessStepKind::Edge(IcfgEdgeKind::NormalReturn)
            && step.target() == Some(&continuation)
    }));

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
    let result = solve_with_witnesses(&root, &[], &provider, &problem);

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
    assert_all_retained_witnesses_reconstruct(&result);

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
    let result = solve_with_witnesses(&root, &[CallIdentityFact::Root], &provider, &problem);

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

    let first_reached = reached_fact(&result, &first_continuation, CallIdentityFact::First);
    let second_reached = reached_fact(&result, &second_continuation, CallIdentityFact::Second);
    let first_witness = result
        .witness_for_reached(
            first_reached,
            PathQuality::PROVEN_COMPLETE,
            WitnessReconstructionLimits::default(),
        )
        .expect("first continuation witness");
    let second_witness = result
        .witness_for_reached(
            second_reached,
            PathQuality::PROVEN_COMPLETE,
            WitnessReconstructionLimits::default(),
        )
        .expect("second continuation witness");
    let first_origin = root
        .call_site_handle(calls[0].id)
        .expect("first call remains scoped");
    let second_origin = root
        .call_site_handle(calls[1].id)
        .expect("second call remains scoped");
    let first_return = first_witness
        .steps()
        .iter()
        .rev()
        .find(|step| step.kind() == SummaryWitnessStepKind::Edge(IcfgEdgeKind::NormalReturn))
        .expect("first witness contains a matched normal return");
    assert_eq!(first_return.origin(), Some(&first_origin));
    assert_eq!(first_return.target(), Some(&first_continuation));
    let second_return = second_witness
        .steps()
        .iter()
        .rev()
        .find(|step| step.kind() == SummaryWitnessStepKind::Edge(IcfgEdgeKind::NormalReturn))
        .expect("second witness contains a matched normal return");
    assert_eq!(second_return.origin(), Some(&second_origin));
    assert_eq!(second_return.target(), Some(&second_continuation));
    assert!(
        first_witness
            .steps()
            .iter()
            .all(|step| step.origin() != Some(&second_origin)),
        "the first summary application must not cross-return through the second call",
    );
    let snapshot = complete_snapshot(&root, &provider);
    assert_witness_matches_snapshot(&first_witness, &snapshot);
    assert_witness_matches_snapshot(&second_witness, &snapshot);
}

#[test]
fn reusable_callee_rows_restore_query_state_and_observe_cancellation() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/Reusable.java",
            r#"
                class Reusable {
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
        "src/Reusable.java",
        PointSelector::new("static int root")
            .procedure("root")
            .effect("entry"),
    );
    let leaf = resolve_procedure_handle(
        &project,
        &analyzer,
        "src/Reusable.java",
        PointSelector::new("static int leaf")
            .procedure("leaf")
            .effect("entry"),
    );
    let observation = leaf
        .point_handle(leaf.semantics().normal_exit_point())
        .expect("leaf normal exit");
    let cancellation = CancellationToken::default();
    let mut reusable = FixedDirectSummaryProvider {
        callee: leaf.clone(),
        observation: observation.clone(),
        exit_kinds: vec![ReturnTransferKind::Normal].into_boxed_slice(),
        cancellation: None,
        calls: Cell::new(0),
    };
    let mut solver_budget = SolverBudget::default();
    let mut semantic_budget = SemanticBudget::default();
    let result = solve_with_reusable_end_summaries(
        SummarySolveInput::new(&root, &[]),
        &analyzer.icfg_provider(),
        &direct_problem(),
        &mut reusable,
        &mut semantic_budget,
        &mut DataflowRequest::new(&mut solver_budget, &cancellation),
    )
    .expect("valid reusable direct-flow solve");

    assert_eq!(result.termination(), SolverTermination::FixedPoint);
    assert!(reusable.calls.get() > 0);
    assert!(result.metrics().reusable_summary_hits > 0);
    assert!(result.metrics().reusable_observations > 0);
    assert!(result.reached_at(&observation).next().is_some());

    let mut strict_witnesses = FixedDirectSummaryProvider {
        callee: leaf.clone(),
        observation: observation.clone(),
        exit_kinds: vec![ReturnTransferKind::Normal].into_boxed_slice(),
        cancellation: None,
        calls: Cell::new(0),
    };
    let mut solver_budget = SolverBudget::default();
    let mut semantic_budget = SemanticBudget::default();
    let strict_result = solve_with_reusable_end_summaries(
        SummarySolveInput::new(&root, &[])
            .with_witness_retention(WitnessRetentionLimits::new(2).unwrap()),
        &analyzer.icfg_provider(),
        &direct_problem(),
        &mut strict_witnesses,
        &mut semantic_budget,
        &mut DataflowRequest::new(&mut solver_budget, &cancellation),
    )
    .expect("strict witnesses safely fall back to source-backed tabulation");
    assert_eq!(strict_witnesses.calls.get(), 0);
    assert_eq!(strict_result.metrics().reusable_summary_hits, 0);
    assert!(!strict_result.witness_retention_truncated());
    assert_all_retained_witnesses_reconstruct(&strict_result);

    let mut limits = SolverBudget::default().limits();
    limits.callback_rows = result.work().callback_rows.saturating_sub(1);
    let mut bounded = FixedDirectSummaryProvider {
        callee: leaf.clone(),
        observation: observation.clone(),
        exit_kinds: vec![ReturnTransferKind::Normal].into_boxed_slice(),
        cancellation: None,
        calls: Cell::new(0),
    };
    let mut solver_budget = SolverBudget::new(limits);
    let mut semantic_budget = SemanticBudget::default();
    let bounded_result = solve_with_reusable_end_summaries(
        SummarySolveInput::new(&root, &[]),
        &analyzer.icfg_provider(),
        &direct_problem(),
        &mut bounded,
        &mut semantic_budget,
        &mut DataflowRequest::new(&mut solver_budget, &cancellation),
    )
    .expect("budget exhaustion produces a typed partial result");
    assert!(bounded.calls.get() > 0);
    assert!(bounded_result.termination().budget_exceeded().is_some());
    assert!(!bounded_result.is_complete());

    let cancellation = CancellationToken::default();
    let mut cancelling = FixedDirectSummaryProvider {
        callee: leaf,
        observation,
        exit_kinds: vec![ReturnTransferKind::Normal].into_boxed_slice(),
        cancellation: Some(cancellation.clone()),
        calls: Cell::new(0),
    };
    let mut solver_budget = SolverBudget::default();
    let mut semantic_budget = SemanticBudget::default();
    let cancelled = solve_with_reusable_end_summaries(
        SummarySolveInput::new(&root, &[]),
        &analyzer.icfg_provider(),
        &direct_problem(),
        &mut cancelling,
        &mut semantic_budget,
        &mut DataflowRequest::new(&mut solver_budget, &cancellation),
    )
    .expect("cancellation produces a typed partial result");

    assert!(cancelling.calls.get() > 0);
    assert_eq!(cancelled.termination(), SolverTermination::Cancelled);
    assert_eq!(cancelled.metrics().reusable_summary_hits, 0);
    assert_eq!(cancelled.metrics().reusable_observations, 0);
}

#[test]
fn reusable_callee_rows_preserve_normal_and_exceptional_returns() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/ReusableReturns.java",
            r#"
                class ReusableReturns {
                    static int leaf(boolean fail) {
                        if (fail) throw new IllegalStateException();
                        return 1;
                    }

                    static int root(boolean fail) {
                        try {
                            return leaf(fail);
                        } catch (IllegalStateException ignored) {
                            return -1;
                        }
                    }
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let root = resolve_procedure_handle(
        &project,
        &analyzer,
        "src/ReusableReturns.java",
        PointSelector::new("static int root")
            .procedure("root")
            .effect("entry"),
    );
    let leaf = resolve_procedure_handle(
        &project,
        &analyzer,
        "src/ReusableReturns.java",
        PointSelector::new("static int leaf")
            .procedure("leaf")
            .effect("entry"),
    );
    let observation = leaf
        .point_handle(leaf.semantics().entry_point())
        .expect("leaf entry");
    let mut reusable = FixedDirectSummaryProvider {
        callee: leaf,
        observation,
        exit_kinds: vec![ReturnTransferKind::Normal, ReturnTransferKind::Exceptional]
            .into_boxed_slice(),
        cancellation: None,
        calls: Cell::new(0),
    };
    let cancellation = CancellationToken::default();
    let mut solver_budget = SolverBudget::default();
    let mut semantic_budget = SemanticBudget::default();
    let result = solve_with_reusable_end_summaries(
        SummarySolveInput::new(&root, &[]),
        &analyzer.icfg_provider(),
        &direct_problem(),
        &mut reusable,
        &mut semantic_budget,
        &mut DataflowRequest::new(&mut solver_budget, &cancellation),
    )
    .expect("dual-exit reusable solve");

    assert_eq!(result.termination(), SolverTermination::FixedPoint);
    assert!(result.metrics().reusable_summary_hits > 0);
    let call = root
        .semantics()
        .call_sites()
        .first()
        .expect("root calls leaf");
    let normal = root
        .point_handle(call.normal_continuation.target().unwrap())
        .unwrap();
    let exceptional = root
        .point_handle(call.exceptional_continuation.target().unwrap())
        .unwrap();
    assert!(result.reached_at(&normal).next().is_some());
    assert!(result.reached_at(&exceptional).next().is_some());
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
    let result = solve_with_witnesses(&root, &[MarkerFact::Seed], &provider, &MarkerProblem);

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

    let calls = root.semantics().call_sites();
    assert_eq!(calls.len(), 2, "fixture has leaf and fail calls");
    let normal_continuation = root
        .point_handle(
            calls[0]
                .normal_continuation
                .target()
                .expect("leaf call has a normal continuation"),
        )
        .expect("leaf continuation remains valid");
    let exceptional_continuation = root
        .point_handle(
            calls[1]
                .exceptional_continuation
                .target()
                .expect("fail call has an exceptional continuation"),
        )
        .expect("fail continuation remains valid");
    let normal_witness = result
        .witness_for_reached(
            reached_fact(&result, &normal_continuation, MarkerFact::NormalReturn),
            PathQuality::PROVEN_COMPLETE,
            WitnessReconstructionLimits::default(),
        )
        .expect("normal-return witness");
    assert!(normal_witness.steps().iter().any(|step| {
        step.kind() == SummaryWitnessStepKind::Edge(IcfgEdgeKind::NormalReturn)
            && step.target() == Some(&normal_continuation)
    }));
    let exceptional_witness = result
        .witness_for_reached(
            reached_fact(
                &result,
                &exceptional_continuation,
                MarkerFact::ExceptionalReturn,
            ),
            PathQuality::PROVEN_COMPLETE,
            WitnessReconstructionLimits::default(),
        )
        .expect("exceptional-return witness");
    assert!(exceptional_witness.steps().iter().any(|step| {
        step.kind() == SummaryWitnessStepKind::Edge(IcfgEdgeKind::ExceptionalReturn)
            && step.target() == Some(&exceptional_continuation)
    }));
    let snapshot = complete_snapshot(&root, &provider);
    assert_witness_matches_snapshot(&normal_witness, &snapshot);
    assert_witness_matches_snapshot(&exceptional_witness, &snapshot);
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
    let result = solve_with_witnesses(&root, &[MarkerFact::Seed], &provider, &MarkerProblem);

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
    let witness = result
        .witness_for_reached(
            reached_fact(&result, &continuation, MarkerFact::CallToNormalReturn),
            PathQuality::PROVEN_PARTIAL,
            WitnessReconstructionLimits::default(),
        )
        .expect("explicit call-to-return witness");
    assert!(witness.steps().iter().any(|step| {
        step.kind() == SummaryWitnessStepKind::Edge(IcfgEdgeKind::CallToNormalContinuation)
            && step.target() == Some(&continuation)
    }));
    assert!(witness.steps().iter().all(|step| {
        !matches!(
            step.kind(),
            SummaryWitnessStepKind::Edge(
                IcfgEdgeKind::Call | IcfgEdgeKind::NormalReturn | IcfgEdgeKind::ExceptionalReturn
            )
        )
    }));
    assert_witness_matches_snapshot(&witness, &complete_snapshot(&root, &provider));
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
        SummarySolveInput::new(&root, &[CancellationFact::Seed])
            .with_witness_retention(WitnessRetentionLimits::new(2).unwrap()),
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
    assert_all_retained_witnesses_reconstruct(&result);
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
        SummarySolveInput::new(&root, &[CancellationFact::Seed])
            .with_witness_retention(WitnessRetentionLimits::new(2).unwrap()),
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
    assert_all_retained_witnesses_reconstruct(&result);
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
    assert_budget_dimension(
        &leaf_root,
        &leaf_analyzer.icfg_provider(),
        SolverBudgetDimension::WitnessRelations,
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
        SolverBudgetDimension::WitnessRelations => limits.witness_relations = 0,
        other => panic!("not a summary-specific dimension: {other:?}"),
    }
    let mut solver_budget = SolverBudget::new(limits);
    let cancellation = CancellationToken::default();
    let mut semantic_budget = SemanticBudget::default();
    let input = if dimension == SolverBudgetDimension::WitnessRelations {
        SummarySolveInput::new(root, &[])
            .with_witness_retention(WitnessRetentionLimits::new(1).unwrap())
    } else {
        SummarySolveInput::new(root, &[])
    };
    let result = solve_with_summaries(
        input,
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
        SolverBudgetDimension::WitnessRelations => {
            assert!(
                result.facts().is_empty(),
                "a rejected seed witness must not publish its reached row",
            );
            assert_eq!(result.work().witness_relations, 0);
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
fn incomparable_path_qualities_reconstruct_separate_concrete_witnesses() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/Incomparable.java",
            r#"
                class Incomparable {
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
        "src/Incomparable.java",
        PointSelector::new("static int root")
            .procedure("root")
            .effect("entry"),
    );
    let call = root
        .semantics()
        .call_sites()
        .first()
        .expect("fixture retains one overloaded call");
    let continuation = root
        .point_handle(
            call.normal_continuation
                .target()
                .expect("overloaded call has a normal continuation"),
        )
        .expect("continuation remains valid");
    let provider =
        TransformingProvider::new(analyzer.icfg_provider()).with_incomparable_call_evidence();
    let result = solve_with_witnesses(&root, &[], &provider, &direct_problem());
    let reached = result
        .reached_at(&continuation)
        .next()
        .expect("both call targets reach the same continuation");

    assert!(
        reached
            .path_qualities()
            .contains(PathQuality::PROVEN_PARTIAL)
    );
    assert!(
        reached
            .path_qualities()
            .contains(PathQuality::UNPROVEN_COMPLETE)
    );
    assert!(!reached.path_qualities().has_proven_complete_path());
    for quality in [PathQuality::PROVEN_PARTIAL, PathQuality::UNPROVEN_COMPLETE] {
        let witness = result
            .witness_for_reached(reached, quality, WitnessReconstructionLimits::default())
            .expect("quality-specific witness");
        assert_eq!(witness.quality(), quality);
        assert_eq!(
            witness
                .steps()
                .iter()
                .all(|step| matches!(step.proof(), ProofStatus::Proven)),
            quality.is_proven(),
        );
        assert_eq!(
            witness
                .steps()
                .iter()
                .all(|step| matches!(step.completeness(), EvidenceCompleteness::Complete)),
            quality.is_complete(),
        );
    }
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
    let forward = solve_with_witnesses(
        &root,
        &[PermutedFact::Seed, PermutedFact::Alpha, PermutedFact::Beta],
        &forward_provider,
        &PermutedProblem { reverse: false },
    );
    let reverse = solve_with_witnesses(
        &root,
        &[PermutedFact::Beta, PermutedFact::Alpha, PermutedFact::Seed],
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
    for (forward_reached, reverse_reached) in forward.reached().iter().zip(reverse.reached()) {
        for quality in forward_reached.path_qualities().iter() {
            assert_eq!(
                forward
                    .witness_for_reached(
                        forward_reached,
                        quality,
                        WitnessReconstructionLimits::default(),
                    )
                    .expect("forward witness"),
                reverse
                    .witness_for_reached(
                        reverse_reached,
                        quality,
                        WitnessReconstructionLimits::default(),
                    )
                    .expect("reverse witness"),
            );
        }
    }
    for (forward_summary, reverse_summary) in
        forward.end_summaries().iter().zip(reverse.end_summaries())
    {
        for quality in forward_summary.path_qualities().iter() {
            assert_eq!(
                forward
                    .witness_for_end_summary(
                        forward_summary,
                        quality,
                        WitnessReconstructionLimits::default(),
                    )
                    .expect("forward end-summary witness"),
                reverse
                    .witness_for_end_summary(
                        reverse_summary,
                        quality,
                        WitnessReconstructionLimits::default(),
                    )
                    .expect("reverse end-summary witness"),
            );
        }
    }
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
