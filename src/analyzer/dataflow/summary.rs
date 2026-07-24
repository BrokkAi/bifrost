//! Demand-driven in-memory summary tabulation.

use std::cmp::Ordering;
use std::collections::VecDeque;

use crate::analyzer::semantic::{
    CallBoundary, CallSiteHandle, CallTransfer, CallTransferSet, ControlContinuation,
    EvidenceCompleteness, IcfgEdgeKind, IcfgExitProfile, IcfgProvider, MatchedReturnProjection,
    ProcedureHandle, ProcedureIcfgBoundary, ProcedureIcfgEdge, ProgramPointHandle, ProgramPointId,
    ProofStatus, SemanticBudget, SemanticOutcome, SemanticProviderError, SemanticRequest,
    SemanticWork,
};
use crate::hash::{HashMap, HashSet};

use super::transfer::{TransferEvaluation, evaluate_transfer};
use super::{
    DataflowEdge, DataflowRequest, DistributiveDataflowProblem, FactId, PathQuality,
    PathQualityFrontier, SolverTermination, SolverWork, SummaryBoundary, SummaryBoundaryKind,
    SummaryCoverage, SummaryDataflowError, SummaryDataflowResult, SummaryEdge, SummaryEntry,
    SummaryMetrics, SummaryReachedFact, SummarySemanticStatus, TabulationEndSummary,
};

const ZERO_FACT_ID: FactId = FactId::new(0);

/// One root procedure and its explicit entry facts for a summary solve.
///
/// The root's declared entry point is implicit. The distinguished zero fact is
/// always added as its own relative entry relation.
#[derive(Debug, Clone, Copy)]
pub struct SummarySolveInput<'input, Fact> {
    root: &'input ProcedureHandle,
    entry_facts: &'input [Fact],
}

impl<'input, Fact> SummarySolveInput<'input, Fact> {
    pub const fn new(root: &'input ProcedureHandle, entry_facts: &'input [Fact]) -> Self {
        Self { root, entry_facts }
    }

    pub const fn root(self) -> &'input ProcedureHandle {
        self.root
    }

    pub const fn entry_facts(self) -> &'input [Fact] {
        self.entry_facts
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct EntryKey {
    procedure: usize,
    entry_point: ProgramPointId,
    entry_fact: FactId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct PathEdgeKey {
    entry: EntryKey,
    point: ProgramPointId,
    fact: FactId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct QueuedPath {
    key: PathEdgeKey,
    quality: PathQuality,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct EndSummaryKey {
    entry: EntryKey,
    exit_point: ProgramPointId,
    exit_fact: FactId,
}

#[derive(Debug, Clone)]
struct EndSummaryRow {
    key: EndSummaryKey,
    exit: IcfgExitProfile,
    qualities: PathQualityFrontier,
    applications: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct IncomingKey {
    callee: EntryKey,
    caller: EntryKey,
    call_point: ProgramPointId,
    call_fact: FactId,
    transfer_index: usize,
}

#[derive(Debug, Clone)]
struct IncomingCall {
    key: IncomingKey,
    transfer: CallTransfer,
    qualities: PathQualityFrontier,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct AppliedReturn {
    incoming: usize,
    summary: usize,
    incoming_quality: PathQuality,
    summary_quality: PathQuality,
}

struct StagedFacts<Fact> {
    new_facts: Vec<(Fact, FactId)>,
    ids: Vec<FactId>,
}

struct SummaryState<Fact> {
    zero_fact: Fact,
    facts: Vec<Fact>,
    fact_ids: HashMap<Fact, FactId>,
    procedures: Vec<ProcedureHandle>,
    procedure_ids: HashMap<ProcedureHandle, usize>,
    reached: HashMap<PathEdgeKey, PathQualityFrontier>,
    worklist: VecDeque<QueuedPath>,
    summaries: Vec<EndSummaryRow>,
    summary_ids: HashMap<EndSummaryKey, usize>,
    summaries_by_entry: HashMap<EntryKey, Vec<usize>>,
    incoming: Vec<IncomingCall>,
    incoming_ids: HashMap<IncomingKey, usize>,
    incoming_by_entry: HashMap<EntryKey, Vec<usize>>,
    applied_returns: HashSet<AppliedReturn>,
    call_cache: HashMap<CallSiteHandle, SemanticOutcome<CallTransferSet>>,
    exit_cache: HashMap<(ProcedureHandle, ProgramPointId), SemanticOutcome<IcfgExitProfile>>,
    unproven_edges: HashSet<SummaryEdge>,
    partial_edges: HashSet<SummaryEdge>,
    boundaries: Vec<SummaryBoundary>,
    metrics: SummaryMetrics,
}

impl<Fact> SummaryState<Fact>
where
    Fact: Copy + Eq + std::hash::Hash + Ord,
{
    fn new(zero_fact: Fact) -> Self {
        Self {
            zero_fact,
            facts: Vec::new(),
            fact_ids: HashMap::default(),
            procedures: Vec::new(),
            procedure_ids: HashMap::default(),
            reached: HashMap::default(),
            worklist: VecDeque::new(),
            summaries: Vec::new(),
            summary_ids: HashMap::default(),
            summaries_by_entry: HashMap::default(),
            incoming: Vec::new(),
            incoming_ids: HashMap::default(),
            incoming_by_entry: HashMap::default(),
            applied_returns: HashSet::default(),
            call_cache: HashMap::default(),
            exit_cache: HashMap::default(),
            unproven_edges: HashSet::default(),
            partial_edges: HashSet::default(),
            boundaries: Vec::new(),
            metrics: SummaryMetrics::default(),
        }
    }

    fn initialize(
        &mut self,
        input: SummarySolveInput<'_, Fact>,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Option<SolverTermination>, SummaryDataflowError> {
        if request.cancellation.is_cancelled() {
            return Ok(Some(SolverTermination::Cancelled));
        }

        let root = self.intern_procedure(input.root().clone());
        let entry_point = input
            .root()
            .point_handle(input.root().semantics().entry_point())
            .ok_or_else(|| {
                SemanticProviderError::internal("summary root procedure has no entry point")
            })?;

        let mut explicit = input.entry_facts().to_vec();
        explicit.sort_unstable();
        explicit.dedup();
        let callback_rows = explicit.len();
        let mut seeds = explicit;
        seeds.push(self.zero_fact);
        seeds.sort_unstable();
        seeds.dedup();

        let mut staged_facts = Vec::with_capacity(seeds.len());
        let mut staged_fact_ids = HashMap::default();
        staged_facts.push(self.zero_fact);
        staged_fact_ids.insert(self.zero_fact, ZERO_FACT_ID);
        for seed in seeds {
            if staged_fact_ids.contains_key(&seed) {
                continue;
            }
            let index = staged_facts.len();
            let id = FactId::try_from_index(index)
                .map_err(|_| SummaryDataflowError::FactIdOverflow { index })?;
            staged_facts.push(seed);
            staged_fact_ids.insert(seed, id);
        }

        let mut staged_states = staged_facts
            .iter()
            .enumerate()
            .map(|(index, _)| {
                let fact = FactId::try_from_index(index)
                    .expect("prevalidated root fact index remains representable");
                PathEdgeKey {
                    entry: EntryKey {
                        procedure: root,
                        entry_point: entry_point.id(),
                        entry_fact: fact,
                    },
                    point: entry_point.id(),
                    fact,
                }
            })
            .collect::<Vec<_>>();
        staged_states.sort_unstable();
        staged_states.dedup();

        let staged_budget = match request.budget.staged_charge(SolverWork {
            interned_facts: staged_facts.len(),
            reached_states: staged_states.len(),
            callback_rows,
            ..SolverWork::default()
        }) {
            Ok(staged) => staged,
            Err(exceeded) => {
                return Ok(Some(SolverTermination::ExceededBudget(exceeded)));
            }
        };
        if request.cancellation.is_cancelled() {
            return Ok(Some(SolverTermination::Cancelled));
        }

        *request.budget = staged_budget;
        self.facts = staged_facts;
        self.fact_ids = staged_fact_ids;
        for key in staged_states {
            let quality = PathQuality::PROVEN_COMPLETE;
            self.reached
                .insert(key, PathQualityFrontier::singleton(quality));
            self.worklist.push_back(QueuedPath { key, quality });
        }
        Ok(None)
    }

    fn intern_procedure(&mut self, procedure: ProcedureHandle) -> usize {
        if let Some(index) = self.procedure_ids.get(&procedure).copied() {
            return index;
        }
        let index = self.procedures.len();
        self.procedures.push(procedure.clone());
        self.procedure_ids.insert(procedure, index);
        index
    }

    fn stage_facts(&self, outputs: &[Fact]) -> Result<StagedFacts<Fact>, SummaryDataflowError> {
        let mut new_facts = Vec::new();
        let mut ids = Vec::with_capacity(outputs.len());
        for &output in outputs {
            if let Some(id) = self.fact_ids.get(&output).copied() {
                ids.push(id);
                continue;
            }
            let index = self.facts.len().saturating_add(new_facts.len());
            let id = FactId::try_from_index(index)
                .map_err(|_| SummaryDataflowError::FactIdOverflow { index })?;
            new_facts.push((output, id));
            ids.push(id);
        }
        Ok(StagedFacts { new_facts, ids })
    }

    fn commit_facts(&mut self, staged: Vec<(Fact, FactId)>) {
        for (fact, id) in staged {
            let expected = FactId::try_from_index(self.facts.len())
                .expect("prevalidated fact index remains representable");
            debug_assert_eq!(id, expected);
            let replaced = self.fact_ids.insert(fact, id);
            debug_assert!(replaced.is_none(), "staged facts are unique");
            self.facts.push(fact);
        }
    }

    fn publish_path_outputs(
        &mut self,
        entry: EntryKey,
        target: ProgramPointId,
        quality: PathQuality,
        outputs: &[Fact],
        request: &mut DataflowRequest<'_>,
    ) -> Result<Option<SolverTermination>, SummaryDataflowError> {
        let staged = self.stage_facts(outputs)?;
        let mut staged_states = Vec::new();
        let mut new_reached_states = 0;

        for &fact in &staged.ids {
            let key = PathEdgeKey {
                entry,
                point: target,
                fact,
            };
            let existing = self.reached.get(&key).copied();
            let mut prospective = existing.unwrap_or_default();
            if prospective.insert(quality) {
                if existing.is_none() {
                    new_reached_states += 1;
                }
                staged_states.push((key, prospective));
            }
        }

        let staged_budget = match request.budget.staged_charge(SolverWork {
            interned_facts: staged.new_facts.len(),
            reached_states: new_reached_states,
            callback_rows: outputs.len(),
            propagated_outputs: outputs.len(),
            ..SolverWork::default()
        }) {
            Ok(staged_budget) => staged_budget,
            Err(exceeded) => {
                return Ok(Some(SolverTermination::ExceededBudget(exceeded)));
            }
        };
        if request.cancellation.is_cancelled() {
            return Ok(Some(SolverTermination::Cancelled));
        }

        *request.budget = staged_budget;
        self.commit_facts(staged.new_facts);
        for (key, frontier) in staged_states {
            self.reached.insert(key, frontier);
            self.worklist.push_back(QueuedPath { key, quality });
        }
        Ok(None)
    }

    fn observe_edge(&mut self, edge: &ProcedureIcfgEdge) {
        let row = SummaryEdge::from_procedure_edge(edge);
        if !matches!(edge.proof, ProofStatus::Proven) {
            self.unproven_edges.insert(row.clone());
        }
        if !matches!(edge.completeness, EvidenceCompleteness::Complete) {
            self.partial_edges.insert(row);
        }
    }

    fn observe_boundary(&mut self, boundary: ProcedureIcfgBoundary) {
        self.boundaries
            .push(SummaryBoundary::from_procedure_boundary(boundary));
    }

    fn observe_semantic_outcome<T>(
        &mut self,
        at: &ProgramPointHandle,
        origin: Option<CallSiteHandle>,
        outcome: &SemanticOutcome<T>,
    ) {
        let status = SummarySemanticStatus::from_outcome(outcome);
        if !status.is_complete() {
            self.boundaries.push(SummaryBoundary::new(
                at.clone(),
                origin,
                SummaryBoundaryKind::Semantic(status),
            ));
        }
    }

    fn reserve_provider_materialization(
        &mut self,
        request: &mut DataflowRequest<'_>,
    ) -> Option<SolverTermination> {
        if request.cancellation.is_cancelled() {
            return Some(SolverTermination::Cancelled);
        }
        let staged = match request.budget.staged_charge(SolverWork {
            provider_materializations: 1,
            ..SolverWork::default()
        }) {
            Ok(staged) => staged,
            Err(exceeded) => return Some(SolverTermination::ExceededBudget(exceeded)),
        };
        if request.cancellation.is_cancelled() {
            return Some(SolverTermination::Cancelled);
        }
        *request.budget = staged;
        self.metrics.provider_materializations =
            self.metrics.provider_materializations.saturating_add(1);
        None
    }

    fn cached_call_transfers<Provider>(
        &mut self,
        provider: &Provider,
        point: &ProgramPointHandle,
        call: crate::analyzer::semantic::CallSiteId,
        semantic_budget: &mut SemanticBudget,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Result<SemanticOutcome<CallTransferSet>, SolverTermination>, SummaryDataflowError>
    where
        Provider: IcfgProvider + ?Sized,
    {
        let origin = point
            .procedure()
            .call_site_handle(call)
            .ok_or_else(|| SemanticProviderError::internal("failed to scope summary call"))?;
        if let Some(cached) = self.call_cache.get(&origin).cloned() {
            self.metrics.provider_cache_hits = self.metrics.provider_cache_hits.saturating_add(1);
            return Ok(Ok(cached));
        }
        if let Some(termination) = self.reserve_provider_materialization(request) {
            return Ok(Err(termination));
        }
        let mut semantic_request = SemanticRequest::new(semantic_budget, request.cancellation);
        let outcome = provider
            .call_transfers(point.procedure(), call, &mut semantic_request)?
            .map(canonicalize_call_transfer_set);
        self.call_cache.insert(origin, outcome.clone());
        Ok(Ok(outcome))
    }

    fn cached_exit_profile<Provider>(
        &mut self,
        provider: &Provider,
        point: &ProgramPointHandle,
        semantic_budget: &mut SemanticBudget,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Result<SemanticOutcome<IcfgExitProfile>, SolverTermination>, SummaryDataflowError>
    where
        Provider: IcfgProvider + ?Sized,
    {
        let cache_key = (point.procedure().clone(), point.id());
        if let Some(cached) = self.exit_cache.get(&cache_key).cloned() {
            self.metrics.provider_cache_hits = self.metrics.provider_cache_hits.saturating_add(1);
            return Ok(Ok(cached));
        }
        if let Some(termination) = self.reserve_provider_materialization(request) {
            return Ok(Err(termination));
        }
        let mut semantic_request = SemanticRequest::new(semantic_budget, request.cancellation);
        let outcome = provider.exit_profile(point, &mut semantic_request)?;
        self.exit_cache.insert(cache_key, outcome.clone());
        Ok(Ok(outcome))
    }

    fn propagate<P, Provider>(
        &mut self,
        provider: &Provider,
        problem: &P,
        semantic_budget: &mut SemanticBudget,
        request: &mut DataflowRequest<'_>,
    ) -> Result<SolverTermination, SummaryDataflowError>
    where
        P: DistributiveDataflowProblem<Fact = Fact>,
        Provider: IcfgProvider + ?Sized,
    {
        while let Some(queued) = self.worklist.pop_front() {
            if request.cancellation.is_cancelled() {
                return Ok(SolverTermination::Cancelled);
            }
            let frontier = *self
                .reached
                .get(&queued.key)
                .expect("queued summary paths remain in the reached table");
            if !frontier.contains(queued.quality) {
                continue;
            }

            let procedure = self.procedures[queued.key.entry.procedure].clone();
            let point = procedure.point_handle(queued.key.point).ok_or_else(|| {
                SemanticProviderError::internal("summary worklist point is stale")
            })?;
            let fact = self.facts[queued.key.fact.index()];

            if is_procedure_exit(&point) {
                if let Some(termination) =
                    self.process_exit(provider, &point, queued, problem, semantic_budget, request)?
                {
                    return Ok(termination);
                }
                continue;
            }

            if let Some(call) = crate::analyzer::semantic::icfg::invoked_call_at(&point)? {
                if let Some(termination) = self.process_call(
                    provider,
                    problem,
                    &point,
                    call,
                    queued,
                    fact,
                    semantic_budget,
                    request,
                )? {
                    return Ok(termination);
                }
            } else if let Some(termination) =
                self.process_local_edges(problem, &point, queued, None, request)?
            {
                return Ok(termination);
            }
        }
        Ok(SolverTermination::FixedPoint)
    }

    fn process_exit<P, Provider>(
        &mut self,
        provider: &Provider,
        point: &ProgramPointHandle,
        queued: QueuedPath,
        problem: &P,
        semantic_budget: &mut SemanticBudget,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Option<SolverTermination>, SummaryDataflowError>
    where
        P: DistributiveDataflowProblem<Fact = Fact>,
        Provider: IcfgProvider + ?Sized,
    {
        let outcome = match self.cached_exit_profile(provider, point, semantic_budget, request)? {
            Ok(outcome) => outcome,
            Err(termination) => return Ok(Some(termination)),
        };
        self.observe_semantic_outcome(point, None, &outcome);
        if matches!(outcome, SemanticOutcome::Cancelled { .. })
            || request.cancellation.is_cancelled()
        {
            return Ok(Some(SolverTermination::Cancelled));
        }
        let Some(exit) = outcome.available_value().cloned() else {
            return Ok(None);
        };
        let quality = if exit.has_return_affecting_gaps() {
            queued.quality.conjoin(PathQuality::UNPROVEN_PARTIAL)
        } else {
            queued.quality
        };
        self.publish_end_summary(queued.key, exit, quality, problem, request)
    }

    #[allow(clippy::too_many_arguments)]
    fn process_call<P, Provider>(
        &mut self,
        provider: &Provider,
        problem: &P,
        point: &ProgramPointHandle,
        call: crate::analyzer::semantic::CallSiteId,
        queued: QueuedPath,
        fact: Fact,
        semantic_budget: &mut SemanticBudget,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Option<SolverTermination>, SummaryDataflowError>
    where
        P: DistributiveDataflowProblem<Fact = Fact>,
        Provider: IcfgProvider + ?Sized,
    {
        let semantic_call = point
            .procedure()
            .semantics()
            .call_site(call)
            .ok_or_else(|| SemanticProviderError::internal("summary invoke event has no call row"))?
            .clone();
        let origin = point
            .procedure()
            .call_site_handle(call)
            .ok_or_else(|| SemanticProviderError::internal("failed to scope summary invoke"))?;
        let outcome =
            match self.cached_call_transfers(provider, point, call, semantic_budget, request)? {
                Ok(outcome) => outcome,
                Err(termination) => return Ok(Some(termination)),
            };
        self.observe_semantic_outcome(point, Some(origin.clone()), &outcome);
        if matches!(outcome, SemanticOutcome::Cancelled { .. })
            || request.cancellation.is_cancelled()
        {
            return Ok(Some(SolverTermination::Cancelled));
        }

        if let Some(transfers) = outcome.available_value().cloned() {
            for boundary in &transfers.boundaries {
                self.boundaries.push(SummaryBoundary::new(
                    point.clone(),
                    Some(boundary.origin.clone()),
                    SummaryBoundaryKind::Dispatch(boundary.dispatch.kind.clone()),
                ));
                let projection = crate::analyzer::semantic::icfg::project_call_boundary(
                    point.procedure(),
                    &semantic_call,
                    boundary,
                )?;
                for boundary in projection.boundaries {
                    self.observe_boundary(boundary);
                }
                for edge in projection.edges {
                    if let Some(termination) = self.propagate_owned_edge(
                        problem,
                        queued.key.entry,
                        queued.key.fact,
                        queued.quality,
                        edge,
                        request,
                    )? {
                        return Ok(Some(termination));
                    }
                }
            }

            for (transfer_index, transfer) in transfers.transfers.iter().enumerate() {
                let edge = ProcedureIcfgEdge {
                    source: point.clone(),
                    target: transfer.callee_entry.clone(),
                    kind: IcfgEdgeKind::Call,
                    origin: Some(origin.clone()),
                    proof: transfer.proof.clone(),
                    completeness: transfer.completeness.clone(),
                };
                self.observe_edge(&edge);
                let incoming_quality = queued
                    .quality
                    .through_evidence(&edge.proof, &edge.completeness);
                let descriptor = descriptor(&edge);
                let outputs = match evaluate_transfer(
                    problem,
                    descriptor,
                    fact,
                    self.zero_fact,
                    queued.key.fact == ZERO_FACT_ID,
                    request,
                ) {
                    TransferEvaluation::Outputs(outputs) => outputs,
                    TransferEvaluation::Terminated(termination) => {
                        return Ok(Some(termination));
                    }
                };
                if let Some(termination) = self.publish_call_outputs(
                    queued.key,
                    transfer_index,
                    transfer.clone(),
                    incoming_quality,
                    &outputs,
                    problem,
                    request,
                )? {
                    return Ok(Some(termination));
                }
            }
        }

        self.process_local_edges(problem, point, queued, Some(&semantic_call), request)
    }

    fn process_local_edges<P>(
        &mut self,
        problem: &P,
        point: &ProgramPointHandle,
        queued: QueuedPath,
        call: Option<&crate::analyzer::semantic::SemanticCallSite>,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Option<SolverTermination>, SummaryDataflowError>
    where
        P: DistributiveDataflowProblem<Fact = Fact>,
    {
        let edges = point
            .procedure()
            .semantics()
            .successor_edges(point.id())
            .map(|(_, edge)| edge.clone())
            .collect::<Vec<_>>();
        for edge in edges {
            if call.is_some_and(|call| {
                crate::analyzer::semantic::icfg::is_call_scaffolding(&edge, call)
            }) {
                continue;
            }
            let target = point
                .procedure()
                .point_handle(edge.target_point)
                .ok_or_else(|| {
                    SemanticProviderError::internal("summary local edge target is stale")
                })?;
            let owned = ProcedureIcfgEdge {
                source: point.clone(),
                target,
                kind: IcfgEdgeKind::Intraprocedural(edge.kind),
                origin: None,
                proof: ProofStatus::Proven,
                completeness: EvidenceCompleteness::Complete,
            };
            if let Some(termination) = self.propagate_owned_edge(
                problem,
                queued.key.entry,
                queued.key.fact,
                queued.quality,
                owned,
                request,
            )? {
                return Ok(Some(termination));
            }
        }
        Ok(None)
    }

    fn propagate_owned_edge<P>(
        &mut self,
        problem: &P,
        entry: EntryKey,
        fact_id: FactId,
        input_quality: PathQuality,
        edge: ProcedureIcfgEdge,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Option<SolverTermination>, SummaryDataflowError>
    where
        P: DistributiveDataflowProblem<Fact = Fact>,
    {
        self.observe_edge(&edge);
        let output_quality = input_quality.through_evidence(&edge.proof, &edge.completeness);
        let target = edge.target.id();
        let flow = descriptor(&edge);
        let outputs = match evaluate_transfer(
            problem,
            flow,
            self.facts[fact_id.index()],
            self.zero_fact,
            fact_id == ZERO_FACT_ID,
            request,
        ) {
            TransferEvaluation::Outputs(outputs) => outputs,
            TransferEvaluation::Terminated(termination) => {
                return Ok(Some(termination));
            }
        };
        self.publish_path_outputs(entry, target, output_quality, &outputs, request)
    }

    #[allow(clippy::too_many_arguments)]
    fn publish_call_outputs<P>(
        &mut self,
        caller_path: PathEdgeKey,
        transfer_index: usize,
        transfer: CallTransfer,
        quality: PathQuality,
        outputs: &[Fact],
        problem: &P,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Option<SolverTermination>, SummaryDataflowError>
    where
        P: DistributiveDataflowProblem<Fact = Fact>,
    {
        let callee_procedure = self.intern_procedure(transfer.callee.clone());
        let staged = self.stage_facts(outputs)?;
        let mut staged_paths = Vec::new();
        let mut staged_incoming = Vec::new();
        let mut new_reached_states = 0;
        let mut new_incoming_calls = 0;

        for &fact in &staged.ids {
            let callee = EntryKey {
                procedure: callee_procedure,
                entry_point: transfer.callee_entry.id(),
                entry_fact: fact,
            };
            let path = PathEdgeKey {
                entry: callee,
                point: transfer.callee_entry.id(),
                fact,
            };
            let existing_path = self.reached.get(&path).copied();
            let mut path_frontier = existing_path.unwrap_or_default();
            let path_changed = path_frontier.insert(PathQuality::PROVEN_COMPLETE);
            if path_changed {
                if existing_path.is_none() {
                    new_reached_states += 1;
                }
                staged_paths.push((path, path_frontier));
            }

            let incoming_key = IncomingKey {
                callee,
                caller: caller_path.entry,
                call_point: caller_path.point,
                call_fact: caller_path.fact,
                transfer_index,
            };
            let existing_incoming = self.incoming_ids.get(&incoming_key).copied();
            let existing_frontier = existing_incoming.map(|id| self.incoming[id].qualities);
            let mut incoming_frontier = existing_frontier.unwrap_or_default();
            let incoming_changed = incoming_frontier.insert(quality);
            if existing_incoming.is_none() {
                new_incoming_calls += 1;
            }
            staged_incoming.push((
                incoming_key,
                existing_incoming,
                incoming_frontier,
                incoming_changed,
                transfer.clone(),
                existing_path.is_some(),
            ));
        }

        let staged_budget = match request.budget.staged_charge(SolverWork {
            interned_facts: staged.new_facts.len(),
            reached_states: new_reached_states,
            callback_rows: outputs.len(),
            propagated_outputs: outputs.len(),
            incoming_calls: new_incoming_calls,
            ..SolverWork::default()
        }) {
            Ok(staged_budget) => staged_budget,
            Err(exceeded) => {
                return Ok(Some(SolverTermination::ExceededBudget(exceeded)));
            }
        };
        if request.cancellation.is_cancelled() {
            return Ok(Some(SolverTermination::Cancelled));
        }

        *request.budget = staged_budget;
        self.commit_facts(staged.new_facts);
        for (key, frontier) in staged_paths {
            self.reached.insert(key, frontier);
            self.worklist.push_back(QueuedPath {
                key,
                quality: PathQuality::PROVEN_COMPLETE,
            });
        }

        let mut activated = Vec::new();
        for (key, existing, frontier, changed, incoming_transfer, reused_entry) in staged_incoming {
            let id = if let Some(id) = existing {
                self.incoming[id].qualities = frontier;
                id
            } else {
                let id = self.incoming.len();
                self.incoming.push(IncomingCall {
                    key,
                    transfer: incoming_transfer,
                    qualities: frontier,
                });
                self.incoming_ids.insert(key, id);
                self.incoming_by_entry
                    .entry(key.callee)
                    .or_default()
                    .push(id);
                if reused_entry {
                    self.metrics.reused_entry_contexts =
                        self.metrics.reused_entry_contexts.saturating_add(1);
                }
                id
            };
            if changed {
                activated.push((id, quality));
            }
        }

        for (incoming, active_quality) in activated {
            if let Some(termination) =
                self.replay_existing_summaries(incoming, active_quality, problem, request)?
            {
                return Ok(Some(termination));
            }
        }
        Ok(None)
    }

    fn publish_end_summary<P>(
        &mut self,
        path: PathEdgeKey,
        exit: IcfgExitProfile,
        quality: PathQuality,
        problem: &P,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Option<SolverTermination>, SummaryDataflowError>
    where
        P: DistributiveDataflowProblem<Fact = Fact>,
    {
        let key = EndSummaryKey {
            entry: path.entry,
            exit_point: exit.callee_exit().id(),
            exit_fact: path.fact,
        };
        let (summary_id, changed) = if let Some(id) = self.summary_ids.get(&key).copied() {
            let changed = self.summaries[id].qualities.insert(quality);
            (id, changed)
        } else {
            let staged_budget = match request.budget.staged_charge(SolverWork {
                end_summaries: 1,
                ..SolverWork::default()
            }) {
                Ok(staged) => staged,
                Err(exceeded) => {
                    return Ok(Some(SolverTermination::ExceededBudget(exceeded)));
                }
            };
            if request.cancellation.is_cancelled() {
                return Ok(Some(SolverTermination::Cancelled));
            }
            *request.budget = staged_budget;
            let id = self.summaries.len();
            self.summaries.push(EndSummaryRow {
                key,
                exit,
                qualities: PathQualityFrontier::singleton(quality),
                applications: 0,
            });
            self.summary_ids.insert(key, id);
            self.summaries_by_entry
                .entry(key.entry)
                .or_default()
                .push(id);
            (id, true)
        };
        if !changed {
            return Ok(None);
        }

        let incoming = self
            .incoming_by_entry
            .get(&key.entry)
            .cloned()
            .unwrap_or_default();
        for incoming_id in incoming {
            let qualities = self.incoming[incoming_id]
                .qualities
                .iter()
                .collect::<Vec<_>>();
            for incoming_quality in qualities {
                if let Some(termination) = self.apply_summary(
                    incoming_id,
                    summary_id,
                    incoming_quality,
                    quality,
                    problem,
                    request,
                )? {
                    return Ok(Some(termination));
                }
            }
        }
        Ok(None)
    }

    fn replay_existing_summaries<P>(
        &mut self,
        incoming: usize,
        incoming_quality: PathQuality,
        problem: &P,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Option<SolverTermination>, SummaryDataflowError>
    where
        P: DistributiveDataflowProblem<Fact = Fact>,
    {
        let entry = self.incoming[incoming].key.callee;
        let summaries = self
            .summaries_by_entry
            .get(&entry)
            .cloned()
            .unwrap_or_default();
        if summaries.is_empty() {
            self.metrics.summary_misses = self.metrics.summary_misses.saturating_add(1);
            return Ok(None);
        }
        self.metrics.summary_hits = self.metrics.summary_hits.saturating_add(1);
        for summary in summaries {
            let qualities = self.summaries[summary].qualities.iter().collect::<Vec<_>>();
            for summary_quality in qualities {
                if let Some(termination) = self.apply_summary(
                    incoming,
                    summary,
                    incoming_quality,
                    summary_quality,
                    problem,
                    request,
                )? {
                    return Ok(Some(termination));
                }
            }
        }
        Ok(None)
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_summary<P>(
        &mut self,
        incoming_id: usize,
        summary_id: usize,
        incoming_quality: PathQuality,
        summary_quality: PathQuality,
        problem: &P,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Option<SolverTermination>, SummaryDataflowError>
    where
        P: DistributiveDataflowProblem<Fact = Fact>,
    {
        let application = AppliedReturn {
            incoming: incoming_id,
            summary: summary_id,
            incoming_quality,
            summary_quality,
        };
        if !self.applied_returns.insert(application) {
            return Ok(None);
        }
        self.metrics.summary_applications = self.metrics.summary_applications.saturating_add(1);
        self.summaries[summary_id].applications =
            self.summaries[summary_id].applications.saturating_add(1);

        let incoming = self.incoming[incoming_id].clone();
        let summary = self.summaries[summary_id].clone();
        debug_assert_eq!(incoming.key.callee, summary.key.entry);
        let projection = summary.exit.project_matched_return(&incoming.transfer)?;
        match projection {
            MatchedReturnProjection::Absent => Ok(None),
            MatchedReturnProjection::Boundary(boundary) => {
                self.observe_boundary(boundary);
                Ok(None)
            }
            MatchedReturnProjection::Edge(edge) => {
                self.observe_edge(&edge);
                let quality = incoming_quality
                    .conjoin(summary_quality)
                    .through_evidence(&edge.proof, &edge.completeness);
                let target = edge.target.id();
                let flow = descriptor(&edge);
                let outputs = match evaluate_transfer(
                    problem,
                    flow,
                    self.facts[summary.key.exit_fact.index()],
                    self.zero_fact,
                    summary.key.exit_fact == ZERO_FACT_ID,
                    request,
                ) {
                    TransferEvaluation::Outputs(outputs) => outputs,
                    TransferEvaluation::Terminated(termination) => {
                        return Ok(Some(termination));
                    }
                };
                self.publish_path_outputs(incoming.key.caller, target, quality, &outputs, request)
            }
        }
    }

    fn finish(
        self,
        termination: SolverTermination,
        work: SolverWork,
        semantic_work: SemanticWork,
    ) -> SummaryDataflowResult<Fact> {
        let mut reached_rows = self.reached.into_iter().collect::<Vec<_>>();
        reached_rows.sort_unstable_by_key(|(key, _)| *key);
        let reached = reached_rows
            .into_iter()
            .map(|(key, qualities)| {
                let procedure = self.procedures[key.entry.procedure].clone();
                let entry_point = procedure
                    .point_handle(key.entry.entry_point)
                    .expect("published summary entry point remains valid");
                let point = procedure
                    .point_handle(key.point)
                    .expect("published summary path point remains valid");
                SummaryReachedFact::new(
                    SummaryEntry::new(procedure, entry_point, key.entry.entry_fact),
                    point,
                    key.fact,
                    qualities,
                )
            })
            .collect();

        let mut summary_rows = self.summaries;
        summary_rows.sort_unstable_by_key(|row| row.key);
        let end_summaries = summary_rows
            .into_iter()
            .map(|row| {
                let procedure = self.procedures[row.key.entry.procedure].clone();
                let entry_point = procedure
                    .point_handle(row.key.entry.entry_point)
                    .expect("published summary entry point remains valid");
                TabulationEndSummary::new(
                    SummaryEntry::new(procedure, entry_point, row.key.entry.entry_fact),
                    row.exit,
                    row.key.exit_fact,
                    row.qualities,
                )
            })
            .collect();
        let coverage = SummaryCoverage::from_parts(
            self.unproven_edges.into_iter().collect(),
            self.partial_edges.into_iter().collect(),
            self.boundaries,
        );
        SummaryDataflowResult::from_parts(
            self.facts,
            reached,
            end_summaries,
            coverage,
            termination,
            work,
            semantic_work,
            self.metrics,
        )
    }
}

/// Solve one finite distributive problem with query-local procedure summaries.
pub fn solve_with_summaries<P, Provider>(
    input: SummarySolveInput<'_, P::Fact>,
    provider: &Provider,
    problem: &P,
    semantic_budget: &mut SemanticBudget,
    request: &mut DataflowRequest<'_>,
) -> Result<SummaryDataflowResult<P::Fact>, SummaryDataflowError>
where
    P: DistributiveDataflowProblem,
    Provider: IcfgProvider + ?Sized,
{
    let initial_work = request.budget.used();
    let initial_semantic_work = semantic_budget.used();
    let mut state = SummaryState::new(problem.zero_fact());
    let termination = if let Some(termination) = state.initialize(input, request)? {
        termination
    } else {
        state.propagate(provider, problem, semantic_budget, request)?
    };
    let work = request.budget.used().saturating_sub(initial_work);
    let semantic_work = semantic_budget.used().saturating_sub(initial_semantic_work);
    Ok(state.finish(termination, work, semantic_work))
}

fn canonicalize_call_transfer_set(mut set: CallTransferSet) -> CallTransferSet {
    let mut transfers = set.transfers.into_vec();
    transfers.sort_by(compare_call_transfers);
    transfers.dedup();
    let mut boundaries = set.boundaries.into_vec();
    boundaries.sort_by(compare_call_boundaries);
    boundaries.dedup();
    set.transfers = transfers.into_boxed_slice();
    set.boundaries = boundaries.into_boxed_slice();
    set
}

fn descriptor(edge: &ProcedureIcfgEdge) -> DataflowEdge<'_> {
    DataflowEdge::new(
        edge.kind,
        edge.origin.as_ref(),
        &edge.source,
        &edge.target,
        &edge.proof,
        &edge.completeness,
    )
}

fn is_procedure_exit(point: &ProgramPointHandle) -> bool {
    let semantics = point.procedure().semantics();
    point.id() == semantics.normal_exit_point() || point.id() == semantics.exceptional_exit_point()
}

fn compare_call_transfers(left: &CallTransfer, right: &CallTransfer) -> Ordering {
    compare_call_sites(&left.origin, &right.origin)
        .then_with(|| compare_procedures(&left.callee, &right.callee))
        .then_with(|| left.callee_entry.id().cmp(&right.callee_entry.id()))
        .then_with(|| compare_continuations(left.normal_continuation, right.normal_continuation))
        .then_with(|| {
            compare_continuations(
                left.exceptional_continuation,
                right.exceptional_continuation,
            )
        })
        .then_with(|| compare_proof(&left.proof, &right.proof))
        .then_with(|| compare_completeness(&left.completeness, &right.completeness))
}

fn compare_call_boundaries(left: &CallBoundary, right: &CallBoundary) -> Ordering {
    compare_call_sites(&left.origin, &right.origin)
        .then_with(|| compare_dispatch_boundary_kind(&left.dispatch.kind, &right.dispatch.kind))
        .then_with(|| compare_call_to_return_model(left.model, right.model))
        .then_with(|| compare_proof(&left.dispatch.proof, &right.dispatch.proof))
        .then_with(|| {
            compare_completeness(&left.dispatch.completeness, &right.dispatch.completeness)
        })
}

fn compare_procedures(left: &ProcedureHandle, right: &ProcedureHandle) -> Ordering {
    left.artifact()
        .key()
        .cmp(right.artifact().key())
        .then_with(|| left.semantics().locator().cmp(right.semantics().locator()))
        .then_with(|| left.id().cmp(&right.id()))
}

fn compare_call_sites(left: &CallSiteHandle, right: &CallSiteHandle) -> Ordering {
    compare_procedures(left.procedure(), right.procedure()).then_with(|| left.id().cmp(&right.id()))
}

fn compare_continuations(left: ControlContinuation, right: ControlContinuation) -> Ordering {
    let key = |continuation| match continuation {
        ControlContinuation::Target(point) => (0, point.get()),
        ControlContinuation::Absent => (1, 0),
        ControlContinuation::Unknown => (2, 0),
        ControlContinuation::Unsupported => (3, 0),
        ControlContinuation::Unproven => (4, 0),
        ControlContinuation::ExceededBudget => (5, 0),
    };
    key(left).cmp(&key(right))
}

fn compare_proof(left: &ProofStatus, right: &ProofStatus) -> Ordering {
    match (left, right) {
        (ProofStatus::Proven, ProofStatus::Proven) => Ordering::Equal,
        (ProofStatus::Proven, ProofStatus::Unproven(_)) => Ordering::Less,
        (ProofStatus::Unproven(_), ProofStatus::Proven) => Ordering::Greater,
        (ProofStatus::Unproven(left), ProofStatus::Unproven(right)) => left.cmp(right),
    }
}

fn compare_completeness(left: &EvidenceCompleteness, right: &EvidenceCompleteness) -> Ordering {
    match (left, right) {
        (EvidenceCompleteness::Complete, EvidenceCompleteness::Complete) => Ordering::Equal,
        (EvidenceCompleteness::Complete, EvidenceCompleteness::Partial(_)) => Ordering::Less,
        (EvidenceCompleteness::Partial(_), EvidenceCompleteness::Complete) => Ordering::Greater,
        (EvidenceCompleteness::Partial(left), EvidenceCompleteness::Partial(right)) => {
            left.cmp(right)
        }
    }
}

fn compare_call_to_return_model(
    left: Option<crate::analyzer::semantic::CallToReturnModel>,
    right: Option<crate::analyzer::semantic::CallToReturnModel>,
) -> Ordering {
    let rank = |model| match model {
        None => 0,
        Some(crate::analyzer::semantic::CallToReturnModel::Normal) => 1,
        Some(crate::analyzer::semantic::CallToReturnModel::Exceptional) => 2,
        Some(crate::analyzer::semantic::CallToReturnModel::NormalAndExceptional) => 3,
    };
    rank(left).cmp(&rank(right))
}

fn compare_dispatch_boundary_kind(
    left: &crate::analyzer::semantic::DispatchBoundaryKind,
    right: &crate::analyzer::semantic::DispatchBoundaryKind,
) -> Ordering {
    use crate::analyzer::semantic::DispatchBoundaryKind;

    let rank = |kind: &DispatchBoundaryKind| match kind {
        DispatchBoundaryKind::External(_) => 0,
        DispatchBoundaryKind::Unmaterialized(_) => 1,
        DispatchBoundaryKind::Deferred { .. } => 2,
        DispatchBoundaryKind::Unresolved => 3,
        DispatchBoundaryKind::Truncated => 4,
    };
    rank(left)
        .cmp(&rank(right))
        .then_with(|| match (left, right) {
            (DispatchBoundaryKind::External(left), DispatchBoundaryKind::External(right)) => {
                left.cmp(right)
            }
            (
                DispatchBoundaryKind::Unmaterialized(left),
                DispatchBoundaryKind::Unmaterialized(right),
            ) => left.cmp(right),
            (
                DispatchBoundaryKind::Deferred {
                    target: left_target,
                    kind: left_kind,
                },
                DispatchBoundaryKind::Deferred {
                    target: right_target,
                    kind: right_kind,
                },
            ) => left_target
                .cmp(right_target)
                .then_with(|| deferred_kind_rank(*left_kind).cmp(&deferred_kind_rank(*right_kind))),
            _ => Ordering::Equal,
        })
}

fn deferred_kind_rank(kind: crate::analyzer::semantic::DeferredInvocationKind) -> u8 {
    use crate::analyzer::semantic::DeferredInvocationKind;
    match kind {
        DeferredInvocationKind::Async => 0,
        DeferredInvocationKind::Generator => 1,
        DeferredInvocationKind::AsyncGenerator => 2,
        DeferredInvocationKind::LanguageDefined => 3,
    }
}
