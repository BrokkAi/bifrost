//! Request-owned refinement of the first forward IDE solve. Symbolic discovery
//! never calls a classifier. Local alternatives are reconstructed from the plan
//! and may emit only an output recorded for the exact original transfer key.

use crate::analyzer::store::cache_budget::RetainedHeap;
use std::cell::{Cell, RefCell};
use std::sync::Arc;

use crate::analyzer::semantic::partial_flow::observation_value;
use crate::analyzer::semantic::{
    BarrierObservation, IcfgEdgeKind, IcfgProvider, LenientValueTypeBarriers, ObservationPhase,
    OracleLimits, ProcedureHandle, ProgramPointHandle, SemanticBudget, StrictValueTypeBarriers,
    ValueFlowEndpoint, ValueTypeBarrierDecision, ValueTypeBarrierFilter, ValueTypePredicate,
};
use crate::dataflow::{
    DataflowEdge, DataflowOutput, DataflowRequest, FactId, IdeDataflowProblem,
    IdeSummarySolveInput, IdeTransition, NoReusableSummaries, PathQuality, PathQualityFrontier,
    RecordedIdeRelations, SolverTermination, SolverWork, SummaryWitness, SummaryWitnessStep,
    SummaryWitnessStepKind, TransferKey, WitnessReconstructionWork, WitnessRetentionLimits,
    solve_ide_with_recorded_relations,
};
use crate::hash::{HashMap, HashSet};
use crate::value_flow::{
    ValueFlowCarrier, ValueFlowCarrierId, ValueFlowObservationPhase, ValueFlowSinkId,
    ValueFlowSourceId,
};

use super::attributed::AttributedTaintFunction;
use super::client::{TaintFlowProblem, TaintObservationHook};
use super::compose::{
    ValueTypeBarrierCheck, ValueTypeBarrierFindingNotes, ValueTypeBarrierPairEvidence,
};
use super::{
    TaintAnalysisPlan, TaintAttributionBudget, TaintClassSet, TaintEdgeFunction, TaintFact,
    TaintFinding, TaintFindingCollectionLimits, TaintFindingError, TaintFindingReport,
    TaintOriginFindingEvidence, TaintOriginStatus, TaintSolveError, TaintSummaryResult,
    TaintWitnessTruncationCause, collect_taint_findings_with_attribution_budget,
    collect_taint_findings_with_model_receipts,
};

/// Classifier failures propagate outside discovery's infallible callbacks.
#[derive(Debug)]
pub enum IcfgTaintError {
    Solve(TaintSolveError),
    Findings(TaintFindingError),
    Provider(Box<str>),
    Terminated(SolverTermination),
    RetentionBudget { limit: usize, attempted: usize },
}

impl std::fmt::Display for IcfgTaintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Solve(e) => e.fmt(f),
            Self::Findings(e) => e.fmt(f),
            Self::Provider(e) => f.write_str(e),
            Self::Terminated(e) => write!(f, "ICFG taint evaluation stopped: {e:?}"),
            Self::RetentionBudget { limit, attempted } => write!(
                f,
                "ICFG taint evaluation retained-byte budget exceeded: attempted {attempted}, limit {limit}"
            ),
        }
    }
}
impl std::error::Error for IcfgTaintError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Solve(error) => Some(error),
            Self::Findings(error) => Some(error),
            _ => None,
        }
    }
}

/// The first solve, its immutable relations, and its existing bounded candidates.
/// This value cannot publish into a reusable summary repository.
pub struct IcfgTaintSession<'receipts> {
    predicates: Box<[(Box<str>, ValueTypePredicate)]>,
    model_receipts: Option<&'receipts crate::model_attribution::TaintModelReceiptInputs>,
    meeting_values: HashMap<(ValueFlowSinkId, bool), Vec<usize>>,
    baseline: TaintFindingReport,
    collection_limits: TaintFindingCollectionLimits,
    max_refinement_bytes: usize,
    max_origins: usize,
    output_owned_bytes: Cell<usize>,
    fixed_owned_bytes: usize,
    witness_limits: crate::dataflow::WitnessReconstructionLimits,
    recorded: Option<RecordedIdeRelations<TaintFact, AttributedTaintFunction>>,
}

// Borrowed additions to the session's existing live-owner census. Nested
// scratch scopes restore their caller's census on success, stop, and unwind.
struct ScratchBytes<'a> {
    live: &'a Cell<usize>,
    previous: usize,
}

impl Drop for ScratchBytes<'_> {
    fn drop(&mut self) {
        self.live.set(self.previous);
    }
}

impl<'receipts> IcfgTaintSession<'receipts> {
    fn baseline_stop(&self) -> Option<IcfgTaintIncomplete> {
        let termination = self.baseline.result().termination();
        if !termination.is_fixed_point() {
            return Some(IcfgTaintIncomplete::Terminated(termination));
        }
        if self.baseline.omitted_findings_lower_bound() != 0 {
            return Some(IcfgTaintIncomplete::FindingLimit {
                limit: self.collection_limits.max_findings,
            });
        }
        for finding in self.baseline.findings() {
            if finding.origins().origin_truncated() {
                return Some(IcfgTaintIncomplete::OriginLimit {
                    limit: self.max_origins,
                });
            }
            if let Some(cause) = finding.origins().witness_truncation_cause() {
                return Some(IcfgTaintIncomplete::WitnessLimit(cause));
            }
        }
        // Semantic gaps remain part of the discovery result. They do not mean
        // that attribution failed to enumerate this captured fixed-point graph.
        None
    }

    fn scratch_bytes(&self, bytes: usize) -> ScratchBytes<'_> {
        let previous = self.output_owned_bytes.get();
        self.output_owned_bytes.set(previous.saturating_add(bytes));
        ScratchBytes {
            live: &self.output_owned_bytes,
            previous,
        }
    }

    fn remaining_bytes(&self, extra: usize) -> Result<usize, IcfgTaintError> {
        let live = self
            .fixed_owned_bytes
            .saturating_add(self.output_owned_bytes.get())
            .saturating_add(extra);
        if live > self.max_refinement_bytes {
            return Err(IcfgTaintError::RetentionBudget {
                limit: self.max_refinement_bytes,
                attempted: live,
            });
        }
        Ok(self.max_refinement_bytes - live)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn discover<Provider: IcfgProvider + ?Sized>(
        root: &ProcedureHandle,
        provider: &Provider,
        plan: &TaintAnalysisPlan,
        retention: WitnessRetentionLimits,
        semantic: &mut SemanticBudget,
        request: &mut DataflowRequest<'_>,
        max_origins: usize,
        witnesses: crate::dataflow::WitnessReconstructionLimits,
        collection: TaintFindingCollectionLimits,
        attribution: &mut super::TaintAttributionBudget,
    ) -> Result<Self, IcfgTaintError> {
        Self::discover_inner(
            root,
            provider,
            plan,
            None,
            retention,
            semantic,
            request,
            max_origins,
            witnesses,
            collection,
            attribution,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn discover_with_model_receipts<Provider: IcfgProvider + ?Sized>(
        root: &ProcedureHandle,
        provider: &Provider,
        plan: &TaintAnalysisPlan,
        receipts: &'receipts crate::model_attribution::TaintModelReceiptInputs,
        retention: WitnessRetentionLimits,
        semantic: &mut SemanticBudget,
        request: &mut DataflowRequest<'_>,
        max_origins: usize,
        witnesses: crate::dataflow::WitnessReconstructionLimits,
        collection: TaintFindingCollectionLimits,
        attribution: &mut super::TaintAttributionBudget,
    ) -> Result<Self, IcfgTaintError> {
        Self::discover_inner(
            root,
            provider,
            plan,
            Some(receipts),
            retention,
            semantic,
            request,
            max_origins,
            witnesses,
            collection,
            attribution,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn discover_inner<Provider: IcfgProvider + ?Sized>(
        root: &ProcedureHandle,
        provider: &Provider,
        plan: &TaintAnalysisPlan,
        receipts: Option<&'receipts crate::model_attribution::TaintModelReceiptInputs>,
        retention: WitnessRetentionLimits,
        semantic: &mut SemanticBudget,
        request: &mut DataflowRequest<'_>,
        max_origins: usize,
        witnesses: crate::dataflow::WitnessReconstructionLimits,
        collection: TaintFindingCollectionLimits,
        attribution: &mut super::TaintAttributionBudget,
    ) -> Result<Self, IcfgTaintError> {
        if root != plan.value_flow().root() {
            return Err(IcfgTaintError::Solve(TaintSolveError::RootMismatch));
        }
        let input = IdeSummarySolveInput::new(root, &[]).with_witness_retention(retention);
        let mut problem = TaintFlowProblem::new(plan).with_cancellation(request.cancellation);
        if let Some(receipts) = receipts {
            problem = problem.with_model_receipts(receipts);
        }
        let (result, recorded) = solve_ide_with_recorded_relations(
            input,
            provider,
            &problem,
            &mut NoReusableSummaries,
            plan.value_flow()
                .has_contextual_bindings()
                .then(OracleLimits::default),
            semantic,
            request,
        )
        .map_err(|e| IcfgTaintError::Solve(TaintSolveError::from(e)))?;
        let result = TaintSummaryResult::from_result(plan, result);
        let baseline = if let Some(receipts) = receipts {
            collect_taint_findings_with_model_receipts(
                plan,
                result,
                max_origins,
                witnesses,
                collection,
                attribution,
                receipts,
            )
        } else {
            collect_taint_findings_with_attribution_budget(
                plan,
                result,
                max_origins,
                witnesses,
                collection,
                attribution,
            )
        }
        .map_err(IcfgTaintError::Findings)?;
        let predicates: Box<[(Box<str>, ValueTypePredicate)]> = plan.value_type_barriers().into();
        let mut fixed_owned_bytes = std::mem::size_of::<Self>()
            .saturating_add(baseline.retained_bytes())
            .saturating_add(recorded.as_ref().map_or(0, |recorded| {
                recorded.owned_bytes(AttributedTaintFunction::retained_heap_bytes)
            }))
            .saturating_add(std::mem::size_of_val(&*predicates))
            .saturating_add(predicates.iter().map(|(name, _)| name.len()).sum::<usize>());
        let max_refinement_bytes = retention
            .best_effort_max_retained_bytes()
            .unwrap_or(collection.max_retained_witness_bytes);
        // Index the complete captured meeting domain, independently of display
        // collection caps. Original sink receipts are borrowed from their caller.
        let mut meeting_values = HashMap::<(ValueFlowSinkId, bool), Vec<usize>>::default();
        let mut indexed_bytes = 0usize;
        if fixed_owned_bytes <= max_refinement_bytes {
            for (index, value) in baseline.result().point_values().iter().enumerate() {
                let fact = baseline
                    .result()
                    .fact_result()
                    .fact(value.fact())
                    .ok_or(IcfgTaintError::Findings(TaintFindingError::InvalidResult))?;
                let Some(sink) = fact.sink() else {
                    continue;
                };
                let rows = meeting_values
                    .entry((sink, fact.is_uncertain()))
                    .or_default();
                let before = rows.capacity();
                rows.push(index);
                indexed_bytes = indexed_bytes.saturating_add(
                    (rows.capacity() - before).saturating_mul(std::mem::size_of::<usize>()),
                );
                let mut heap = RetainedHeap::default();
                heap.map(&meeting_values);
                if fixed_owned_bytes
                    .saturating_add(heap.total())
                    .saturating_add(indexed_bytes)
                    > max_refinement_bytes
                {
                    break;
                }
            }
        }
        let mut index_heap = RetainedHeap::default();
        index_heap.map(&meeting_values);
        fixed_owned_bytes = fixed_owned_bytes
            .saturating_add(index_heap.total())
            .saturating_add(indexed_bytes);
        Ok(Self {
            predicates,
            model_receipts: receipts,
            meeting_values,
            baseline,
            recorded,
            collection_limits: collection,
            max_origins,
            output_owned_bytes: Cell::new(0),
            fixed_owned_bytes,
            max_refinement_bytes,
            witness_limits: witnesses,
        })
    }
}

/// Why the captured batch could not establish complete source coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcfgTaintIncomplete {
    Terminated(SolverTermination),
    RetentionBudget { limit: usize, attempted: usize },
    OriginLimit { limit: usize },
    FindingLimit { limit: usize },
    WitnessLimit(TaintWitnessTruncationCause),
    CoverageUnavailable,
}

/// Per-pair evidence goes through the same public grouping and strict-witness
/// selection as composition. The baseline completion reasons are never reset.
pub struct IcfgTaintOutcome {
    pub report: TaintFindingReport,
    pub barrier_pairs: Vec<ValueTypeBarrierPairEvidence>,
    pub barrier_notes: Vec<ValueTypeBarrierFindingNotes>,
    pub source_coverage: Option<IcfgTaintIncomplete>,
}

#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
struct PathChecks {
    ids: Vec<usize>,
    omitted: bool,
}
impl PathChecks {
    fn insert(&mut self, id: usize) {
        if self.ids.contains(&id) {
            return;
        }
        if self.ids.len() < 64 {
            self.ids.push(id);
        } else {
            self.omitted = true;
        }
    }
    fn extend(&mut self, other: &Self) {
        for &id in &other.ids {
            self.insert(id);
        }
        self.omitted |= other.omitted;
    }
}

fn concrete_value(carrier: &ValueFlowCarrier) -> Option<crate::analyzer::semantic::ValueId> {
    match carrier {
        ValueFlowCarrier::Value(value) => Some(value.id()),
        ValueFlowCarrier::Port(port) => observation_value(&ValueFlowEndpoint::Port(port.clone())),
        // A location's owner type says nothing about the stored value.
        ValueFlowCarrier::Location(_) => None,
    }
}

#[derive(Clone)]
struct Alternative {
    fact: TaintFact,
    function: AttributedTaintFunction,
    checks: PathChecks,
}

fn alternatives_owned_bytes(alternatives: &Vec<Alternative>) -> usize {
    let mut heap = RetainedHeap::default();
    heap.vec(alternatives);
    for alternative in alternatives {
        heap.add(alternative.function.retained_heap_bytes());
        heap.vec(&alternative.checks.ids);
    }
    heap.total()
}

struct TransferAttempt {
    alternatives: Vec<Alternative>,
    pending: Option<(BarrierObservation, ValueTypePredicate)>,
    work: SolverWork,
}

struct DiscardTransitions;
impl DataflowOutput<IdeTransition<TaintFact, AttributedTaintFunction>> for DiscardTransitions {
    fn emit(&mut self, _row: IdeTransition<TaintFact, AttributedTaintFunction>) -> bool {
        true
    }
}

struct CollectTransitions(Vec<(TaintFact, AttributedTaintFunction)>);
impl DataflowOutput<IdeTransition<TaintFact, AttributedTaintFunction>> for CollectTransitions {
    fn emit(&mut self, row: IdeTransition<TaintFact, AttributedTaintFunction>) -> bool {
        self.0.push(row.into_parts());
        true
    }
}

fn descriptor(key: &TransferKey<TaintFact>) -> DataflowEdge<'_, TaintFact> {
    let edge = &key.edge;
    let mut out = DataflowEdge::new(
        edge.kind,
        edge.origin.as_ref(),
        &edge.source,
        &edge.target,
        &edge.proof,
        &edge.completeness,
    )
    .with_caller_conversion(key.caller_conversion_may_run_user_code)
    .with_summary_entry_fact(key.entry);
    if let Some(boundary) = &edge.boundary {
        out = out.with_boundary(boundary);
    }
    if let Some(transfer) = &key.call_transfer {
        out = out.with_call_transfer(transfer);
    }
    if let Some(context) = &key.caller_context {
        out = out.with_call_context(context);
    }
    out
}

fn reconstruct_into<Hook: TaintObservationHook>(
    problem: &TaintFlowProblem<'_, Hook>,
    key: &TransferKey<TaintFact>,
    out: &mut dyn DataflowOutput<IdeTransition<TaintFact, AttributedTaintFunction>>,
) {
    let edge = descriptor(key);
    match key.edge.kind {
        IcfgEdgeKind::Call => IdeDataflowProblem::call_flow(problem, edge, key.input, out),
        IcfgEdgeKind::NormalReturn | IcfgEdgeKind::ExceptionalReturn => {
            IdeDataflowProblem::return_flow(problem, edge, key.input, out)
        }
        IcfgEdgeKind::CallToNormalContinuation | IcfgEdgeKind::CallToExceptionalContinuation => {
            problem.call_to_return_flow(edge, key.input, out)
        }
        _ => problem.normal_flow(edge, key.input, out),
    }
    // IDE's distinguished zero is preserved independently of client transfers.
    if key.input.is_zero() && out.should_continue() {
        // This is the final output, so no later callback needs its continuation.
        let _ = out.emit(IdeTransition::new(
            TaintFact::zero(),
            problem.identity_edge_function(),
        ));
    }
}

fn reconstruct<Hook: TaintObservationHook>(
    problem: &TaintFlowProblem<'_, Hook>,
    key: &TransferKey<TaintFact>,
) -> Vec<(TaintFact, AttributedTaintFunction)> {
    let mut out = CollectTransitions(Vec::new());
    reconstruct_into(problem, key, &mut out);
    out.0
}

struct ObservationHook<'a> {
    plan: &'a TaintAnalysisPlan,
    source: ValueFlowSourceId,
    source_classes: &'a TaintClassSet,
    input: &'a TaintClassSet,
    predicates: &'a [(Box<str>, ValueTypePredicate)],
    decisions: &'a HashMap<(BarrierObservation, ValueTypePredicate), usize>,
    checks: &'a [ValueTypeBarrierCheck],
    filter: &'a dyn ValueTypeBarrierFilter,
    pending: RefCell<Option<(BarrierObservation, ValueTypePredicate)>>,
    emitted: RefCell<Vec<Alternative>>,
    work: Cell<usize>,
}

impl TaintObservationHook for &ObservationHook<'_> {
    type Evidence = PathChecks;
    fn source(&self, source: ValueFlowSourceId) -> bool {
        source == self.source
    }
    fn source_classes<'a>(
        &'a self,
        _source: ValueFlowSourceId,
        _classes: &'a TaintClassSet,
    ) -> &'a TaintClassSet {
        self.source_classes
    }
    fn phase(
        &self,
        point: &ProgramPointHandle,
        phase: ValueFlowObservationPhase,
        carrier: ValueFlowCarrierId,
        function: &TaintEdgeFunction,
        evidence: &mut Self::Evidence,
    ) -> bool {
        let observed = self
            .plan
            .value_flow()
            .source_bindings_at(point, phase)
            .any(|(_, bound)| bound == carrier)
            || self
                .plan
                .value_flow()
                .sink_bindings_at(point, phase)
                .any(|(_, bound)| bound == carrier)
            || !self
                .plan
                .transfer_function(point, phase, carrier)
                .0
                .is_identity();
        !observed || self.permits(point, phase, carrier, function, evidence)
    }
    fn call_input(
        &self,
        point: &ProgramPointHandle,
        call: &crate::analyzer::semantic::CallSiteHandle,
        carrier: ValueFlowCarrierId,
        function: &TaintEdgeFunction,
        evidence: &mut Self::Evidence,
    ) -> bool {
        !self.plan.value_flow().is_call_input(call, carrier)
            || self.model_input(point, call, carrier, function, evidence)
    }
    fn model_input(
        &self,
        point: &ProgramPointHandle,
        call: &crate::analyzer::semantic::CallSiteHandle,
        carrier: ValueFlowCarrierId,
        function: &TaintEdgeFunction,
        evidence: &mut Self::Evidence,
    ) -> bool {
        let site = call
            .procedure()
            .semantics()
            .call_site(call.id())
            .expect("a boundary retains its call site");
        let output = match self.plan.value_flow().carrier(carrier) {
            Some(ValueFlowCarrier::Value(value)) if value.procedure() == call.procedure() => {
                site.normal_result_values().any(|id| id == value.id())
                    || site.thrown == Some(value.id())
            }
            _ => false,
        };
        self.permits(
            point,
            if output {
                ValueFlowObservationPhase::AfterEffects
            } else {
                ValueFlowObservationPhase::BeforeEffects
            },
            carrier,
            function,
            evidence,
        )
    }
    fn permits(
        &self,
        point: &ProgramPointHandle,
        phase: ValueFlowObservationPhase,
        carrier: ValueFlowCarrierId,
        function: &TaintEdgeFunction,
        evidence: &mut Self::Evidence,
    ) -> bool {
        self.work.set(self.work.get().saturating_add(1));
        if function.apply(self.input).is_empty() {
            return true;
        }
        let carrier = self
            .plan
            .value_flow()
            .carrier(carrier)
            .expect("a live carrier belongs to its plan");
        let Some(value) = concrete_value(carrier) else {
            return true;
        };
        let owner = carrier
            .procedure()
            .expect("a value or port has an owning procedure");
        let point = if point.procedure() == owner {
            point.clone()
        } else {
            owner
                .point_handle(owner.semantics().entry_point())
                .expect("a procedure retains its entry")
        };
        let phase = match phase {
            ValueFlowObservationPhase::BeforeEffects => ObservationPhase::BeforeEffects,
            ValueFlowObservationPhase::AfterEffects => ObservationPhase::AfterEffects,
        };
        let observation = BarrierObservation::new(point, value, phase);
        for (_, predicate) in self.predicates {
            let Some(&id) = self.decisions.get(&(observation.clone(), *predicate)) else {
                if self.pending.borrow().is_none() {
                    self.pending.replace(Some((observation, *predicate)));
                }
                return false;
            };
            let decision = self.checks[id].decision;
            if !self.filter.permits(decision) {
                return false;
            }
            if matches!(decision, ValueTypeBarrierDecision::Undecided(_))
                && !evidence.ids.contains(&id)
            {
                evidence.insert(id);
            }
        }
        true
    }
    fn emitted(&self, fact: TaintFact, function: &TaintEdgeFunction, checks: &Self::Evidence) {
        self.emitted.borrow_mut().push(Alternative {
            fact,
            function: AttributedTaintFunction::exact(function.clone()),
            checks: checks.clone(),
        });
    }
}

fn reserve(request: &mut DataflowRequest<'_>, work: SolverWork) -> Result<(), IcfgTaintError> {
    if request.cancellation.is_cancelled() {
        return Err(IcfgTaintError::Terminated(SolverTermination::Cancelled));
    }
    if let Some(termination) = request.reserve(work) {
        return Err(IcfgTaintError::Terminated(termination));
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct Direct {
    source: usize,
    target: usize,
    record: usize,
}
#[derive(Clone, Copy)]
struct Matched {
    caller: usize,
    exit: usize,
    target: usize,
    call: usize,
    returned: usize,
}
struct FrozenSupports {
    direct_by_source: Vec<Vec<usize>>,
    entries_by_source: Vec<Vec<usize>>,
    matched_by_caller: Vec<Vec<usize>>,
    matched_by_exit: Vec<Vec<usize>>,
    direct: Vec<Direct>,
    entries: Vec<Direct>,
    matched: Vec<Matched>,
    chop: Vec<bool>,
    retained_bytes: usize,
}

impl FrozenSupports {
    fn new(
        session: &IcfgTaintSession<'_>,
        recorded: &RecordedIdeRelations<TaintFact, AttributedTaintFunction>,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Self, IcfgTaintError> {
        let result = session.baseline.result();
        let facts = result.fact_result();
        let rows = facts.reached();
        let trace = recorded.trace();
        let graph = recorded.graph();
        let fact = |row: usize| {
            *facts
                .fact(rows[row].fact())
                .expect("recorded row has a fact")
        };
        let entry = |row: usize| {
            *facts
                .fact(rows[row].entry().entry_fact())
                .expect("recorded row has an entry fact")
        };
        let limit = session.remaining_bytes(0)?;
        let mut retained_bytes = rows
            .len()
            .saturating_mul(1 + 4 * std::mem::size_of::<Vec<usize>>());
        let mut retain = |extra: usize| -> Result<(), IcfgTaintError> {
            retained_bytes = retained_bytes.saturating_add(extra);
            if retained_bytes > limit {
                return Err(IcfgTaintError::RetentionBudget {
                    limit: session.max_refinement_bytes,
                    attempted: session
                        .fixed_owned_bytes
                        .saturating_add(session.output_owned_bytes.get())
                        .saturating_add(retained_bytes),
                });
            }
            Ok(())
        };
        retain(0)?;
        let mut index: HashMap<_, Vec<usize>> = HashMap::default();
        for (id, record) in trace.records.iter().enumerate() {
            retain(
                std::mem::size_of::<(ProgramPointHandle, TaintFact, TaintFact)>()
                    + std::mem::size_of::<Vec<usize>>()
                    + std::mem::size_of::<usize>(),
            )?;
            index
                .entry((
                    record.key.edge.source.clone(),
                    record.key.input,
                    record.key.entry,
                ))
                .or_default()
                .push(id);
        }
        let records = |row: usize| {
            index
                .get(&(rows[row].point().clone(), fact(row), entry(row)))
                .map(Vec::as_slice)
                .unwrap_or_default()
        };
        let output_matches = |record: usize, target: usize, function| {
            trace.records[record].outputs.iter().any(|output| {
                output.fact == fact(target)
                    && &trace.functions[output.function] == recorded.edge_function(function)
            })
        };
        let caller_matches = |record: usize, row: usize| {
            trace.records[record]
                .key
                .caller_context
                .as_ref()
                .is_none_or(|context| context == rows[row].entry().call_context())
        };
        let mut direct = Vec::new();
        let mut entries = Vec::new();
        let mut matched = Vec::new();
        for relation in graph.direct_relations() {
            for &record in records(relation.source) {
                let key = &trace.records[record].key;
                let target = if key.edge.kind == IcfgEdgeKind::Call
                    && fact(relation.target).sink().is_some()
                {
                    &key.edge.source
                } else {
                    &key.edge.target
                };
                if target == rows[relation.target].point()
                    && caller_matches(record, relation.source)
                    && output_matches(record, relation.target, relation.function)
                {
                    retain(std::mem::size_of::<Direct>() + std::mem::size_of::<usize>())?;
                    direct.push(Direct {
                        source: relation.source,
                        target: relation.target,
                        record,
                    });
                }
            }
        }
        for relation in graph.call_relations() {
            for &record in records(relation.caller) {
                let key = &trace.records[record].key;
                if key.edge.kind == IcfgEdgeKind::Call
                    && &key.edge.target == rows[relation.target_entry].point()
                    && caller_matches(record, relation.caller)
                    && output_matches(record, relation.target_entry, relation.function)
                {
                    retain(std::mem::size_of::<Direct>() + std::mem::size_of::<usize>())?;
                    entries.push(Direct {
                        source: relation.caller,
                        target: relation.target_entry,
                        record,
                    });
                }
            }
        }
        for relation in &graph.summaries {
            let callee_entry = graph.row_entries[relation.callee_exit];
            for call in entries
                .iter()
                .filter(|call| call.source == relation.caller && call.target == callee_entry)
            {
                if !output_matches(call.record, callee_entry, relation.call_function) {
                    continue;
                }
                for &returned in records(relation.callee_exit) {
                    let call_key = &trace.records[call.record].key;
                    let return_key = &trace.records[returned].key;
                    if matches!(
                        return_key.edge.kind,
                        IcfgEdgeKind::NormalReturn | IcfgEdgeKind::ExceptionalReturn
                    ) && return_key.edge.origin == call_key.edge.origin
                        && return_key.caller_context == call_key.caller_context
                        && &return_key.edge.target == rows[relation.target].point()
                        && output_matches(returned, relation.target, relation.return_function)
                    {
                        retain(std::mem::size_of::<Matched>() + 2 * std::mem::size_of::<usize>())?;
                        matched.push(Matched {
                            caller: relation.caller,
                            exit: relation.callee_exit,
                            target: relation.target,
                            call: call.record,
                            returned,
                        });
                    }
                }
            }
        }
        reserve(
            request,
            SolverWork {
                ide_relations: direct
                    .len()
                    .saturating_add(entries.len())
                    .saturating_add(matched.len()),
                ide_propagations: rows.len(),
                ..SolverWork::default()
            },
        )?;
        let mut construction_heap = RetainedHeap::default();
        construction_heap.map(&index);
        for records in index.values() {
            construction_heap.vec(records);
        }
        construction_heap.vec(&direct);
        construction_heap.vec(&entries);
        construction_heap.vec(&matched);
        session.remaining_bytes(construction_heap.total())?;
        drop(index);
        let mut chop = vec![false; rows.len()];
        for (row, reached) in rows.iter().enumerate() {
            if fact(row).sink().is_some() {
                chop[row] = true;
            }
            debug_assert_eq!(reached, &rows[row]);
        }
        loop {
            let mut changed = false;
            reserve(
                request,
                SolverWork {
                    ide_propagations: direct
                        .len()
                        .saturating_add(entries.len())
                        .saturating_add(matched.len())
                        .saturating_add(rows.len()),
                    ..SolverWork::default()
                },
            )?;
            for relation in direct.iter().chain(&entries) {
                if chop[relation.target] && !chop[relation.source] {
                    chop[relation.source] = true;
                    changed = true;
                }
            }
            for relation in &matched {
                if chop[relation.target] {
                    for row in [relation.caller, relation.exit] {
                        if !chop[row] {
                            chop[row] = true;
                            changed = true;
                        }
                    }
                }
            }
            for row in 0..rows.len() {
                if chop[row] && !chop[graph.row_entries[row]] {
                    chop[graph.row_entries[row]] = true;
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        direct.retain(|relation| chop[relation.target]);
        entries.retain(|relation| chop[relation.target]);
        matched.retain(|relation| chop[relation.target]);
        let mut direct_by_source = vec![Vec::new(); rows.len()];
        let mut entries_by_source = vec![Vec::new(); rows.len()];
        let mut matched_by_caller = vec![Vec::new(); rows.len()];
        let mut matched_by_exit = vec![Vec::new(); rows.len()];
        for (id, relation) in direct.iter().enumerate() {
            direct_by_source[relation.source].push(id);
        }
        for (id, relation) in entries.iter().enumerate() {
            entries_by_source[relation.source].push(id);
        }
        for (id, relation) in matched.iter().enumerate() {
            matched_by_caller[relation.caller].push(id);
            matched_by_exit[relation.exit].push(id);
        }
        let mut supports = Self {
            direct_by_source,
            entries_by_source,
            matched_by_caller,
            matched_by_exit,
            direct,
            entries,
            matched,
            chop,
            retained_bytes,
        };
        let mut heap = RetainedHeap::default();
        heap.add(std::mem::size_of::<Self>());
        for rows in [
            &supports.direct_by_source,
            &supports.entries_by_source,
            &supports.matched_by_caller,
            &supports.matched_by_exit,
        ] {
            heap.vec(rows);
            for row in rows {
                heap.vec(row);
            }
        }
        heap.vec(&supports.direct);
        heap.vec(&supports.entries);
        heap.vec(&supports.matched);
        heap.vec(&supports.chop);
        supports.retained_bytes = heap.total();
        session.remaining_bytes(supports.retained_bytes)?;
        Ok(supports)
    }
}

struct Classification {
    check_name_bytes: usize,
    decisions: HashMap<(BarrierObservation, ValueTypePredicate), usize>,
    checks: Vec<ValueTypeBarrierCheck>,
    // Stable note identities, not classification answers. Budget failures are
    // sampled again through the native context on the next transfer, whose
    // allowance may differ. Only that context owns budget-keyed failure memos.
    budget_note_ids: HashMap<(BarrierObservation, ValueTypePredicate), usize>,
    verified: HashSet<usize>,
}

impl Classification {
    fn owned_bytes(&self) -> usize {
        let mut heap = RetainedHeap::default();
        heap.add(std::mem::size_of::<Self>());
        heap.map(&self.decisions);
        heap.vec(&self.checks);
        heap.map(&self.budget_note_ids);
        heap.hash_set(&self.verified);
        heap.add(self.check_name_bytes);
        heap.total()
    }

    #[allow(clippy::too_many_arguments)]
    fn transfer(
        &mut self,
        recorded: &RecordedIdeRelations<TaintFact, AttributedTaintFunction>,
        record: usize,
        plan: &TaintAnalysisPlan,
        source: ValueFlowSourceId,
        source_classes: &TaintClassSet,
        input: &TaintClassSet,
        predicates: &[(Box<str>, ValueTypePredicate)],
        filter: &dyn ValueTypeBarrierFilter,
        request: &mut DataflowRequest<'_>,
    ) -> TransferAttempt {
        let trace = recorded.trace();
        let row = &trace.records[record];
        if cfg!(debug_assertions) && self.verified.insert(record) {
            let mut reconstructed: HashMap<_, AttributedTaintFunction> = HashMap::default();
            for (fact, function) in reconstruct(
                &TaintFlowProblem::new(plan).with_cancellation(request.cancellation),
                &row.key,
            ) {
                reconstructed
                    .entry(fact)
                    .and_modify(|old| *old = old.meet(&function))
                    .or_insert(function);
            }
            debug_assert_eq!(
                reconstructed.len(),
                row.outputs.len(),
                "unfiltered replay output membership drifted"
            );
            for output in &row.outputs {
                // Replay reconstructs the class relation without receipt inputs;
                // the refined finding inherits receipt evidence from baseline.
                debug_assert_eq!(
                    reconstructed
                        .get(&output.fact)
                        .map(|function| &function.base),
                    Some(&trace.functions[output.function].base),
                    "unfiltered local alternatives must meet to the frozen output function"
                );
            }
        }
        let hook = ObservationHook {
            plan,
            source,
            source_classes,
            input,
            predicates,
            decisions: &self.decisions,
            checks: &self.checks,
            filter,
            pending: RefCell::new(None),
            emitted: RefCell::new(Vec::new()),
            work: Cell::new(0),
        };
        let problem = TaintFlowProblem::with_observations(plan, &hook)
            .with_cancellation(request.cancellation);
        reconstruct_into(&problem, &row.key, &mut DiscardTransitions);
        let work = SolverWork {
            flow_evaluations: 1,
            edge_function_operations: hook.work.get(),
            callback_rows: hook.emitted.borrow().len(),
            ..SolverWork::default()
        };
        TransferAttempt {
            alternatives: hook.emitted.into_inner(),
            pending: hook.pending.into_inner(),
            work,
        }
    }
}

impl Classification {
    #[allow(clippy::too_many_arguments)]
    fn evaluate(
        &mut self,
        session: &IcfgTaintSession<'_>,
        replay_owned_bytes: usize,
        recorded: &RecordedIdeRelations<TaintFact, AttributedTaintFunction>,
        record: usize,
        plan: &TaintAnalysisPlan,
        source: ValueFlowSourceId,
        classes: &TaintClassSet,
        input: &TaintClassSet,
        predicates: &[(Box<str>, ValueTypePredicate)],
        filter: &dyn ValueTypeBarrierFilter,
        request: &mut DataflowRequest<'_>,
        classify: &mut impl FnMut(
            &BarrierObservation,
            ValueTypePredicate,
        ) -> Result<ValueTypeBarrierDecision, Box<str>>,
    ) -> Result<Vec<Alternative>, IcfgTaintError> {
        let mut budget_keys = Vec::new();
        loop {
            let TransferAttempt {
                mut alternatives,
                pending,
                work,
            } = self.transfer(
                recorded, record, plan, source, classes, input, predicates, filter, request,
            );
            // Keep every callback owner live through both checks, even when work
            // or retention refuses this attempt. Work/cancellation keeps priority.
            let work_result = reserve(request, work);
            let mut scratch = RetainedHeap::default();
            scratch.vec(&budget_keys);
            scratch.add(alternatives_owned_bytes(&alternatives));
            let retention_result = session.remaining_bytes(
                replay_owned_bytes
                    .saturating_add(self.owned_bytes())
                    .saturating_add(scratch.total()),
            );
            work_result?;
            retention_result?;
            let transferred = if let Some(pending) = pending {
                // A classifier retry must not retain this unused output packet.
                drop(alternatives);
                Err(pending)
            } else {
                let row = &recorded.trace().records[record];
                if row.key.input.is_zero() {
                    alternatives.push(Alternative {
                        fact: TaintFact::zero(),
                        function: AttributedTaintFunction::exact(plan.identity().clone()),
                        checks: PathChecks::default(),
                    });
                }
                // No reconstructed output may add a fact to the first discovery.
                alternatives.retain(|alternative| {
                    row.outputs
                        .iter()
                        .any(|output| output.fact == alternative.fact)
                });
                // Raw callback owners were admitted above. Zero can grow the
                // vector, so reprice the final retained capacity after filtering.
                let mut scratch = RetainedHeap::default();
                scratch.vec(&budget_keys);
                scratch.add(alternatives_owned_bytes(&alternatives));
                session.remaining_bytes(
                    replay_owned_bytes
                        .saturating_add(self.owned_bytes())
                        .saturating_add(scratch.total()),
                )?;
                Ok(alternatives)
            };
            match transferred {
                Ok(alternatives) => {
                    // A reconstructed transfer may suspend to obtain an answer
                    // outside its callbacks. Keep budget failures only until
                    // that one transfer finishes; reusing them across another
                    // transfer or pass would bypass the native budget key.
                    for key in budget_keys {
                        self.decisions.remove(&key);
                    }
                    return Ok(alternatives);
                }
                Err((observation, predicate)) => {
                    let decision =
                        classify(&observation, predicate).map_err(IcfgTaintError::Provider)?;
                    if matches!(
                        decision,
                        ValueTypeBarrierDecision::Undecided(
                            crate::analyzer::semantic::ValueTypeBarrierReason::Cancelled
                        )
                    ) {
                        return Err(IcfgTaintError::Terminated(SolverTermination::Cancelled));
                    }
                    let key = (observation.clone(), predicate);
                    let budget_failure = matches!(
                        decision,
                        ValueTypeBarrierDecision::Undecided(
                            crate::analyzer::semantic::ValueTypeBarrierReason::BudgetExceeded
                        )
                    );
                    let existing_note = budget_failure
                        .then(|| self.budget_note_ids.get(&key).copied())
                        .flatten();
                    let id = if let Some(id) = existing_note {
                        id
                    } else {
                        let id = self.checks.len();
                        let name = &predicates
                            .iter()
                            .find(|(_, p)| *p == predicate)
                            .expect("a pending predicate belongs to the request")
                            .0;
                        self.check_name_bytes = self.check_name_bytes.saturating_add(name.len());
                        self.checks.push(ValueTypeBarrierCheck {
                            id: name.clone(),
                            observation,
                            predicate,
                            decision,
                        });
                        if budget_failure {
                            self.budget_note_ids.insert(key.clone(), id);
                        }
                        id
                    };
                    if budget_failure {
                        budget_keys.push(key.clone());
                    }
                    self.decisions.insert(key, id);
                    let mut scratch = RetainedHeap::default();
                    scratch.vec(&budget_keys);
                    session.remaining_bytes(
                        replay_owned_bytes
                            .saturating_add(self.owned_bytes())
                            .saturating_add(scratch.total()),
                    )?;
                }
            }
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct AppliedTransfer {
    record: usize,
    fact: TaintFact,
    checks: PathChecks,
}
impl AppliedTransfer {
    fn new(record: usize, alternative: &Alternative) -> Self {
        Self {
            record,
            fact: alternative.fact,
            checks: alternative.checks.clone(),
        }
    }
    fn retained_bytes(&self) -> usize {
        self.checks
            .ids
            .capacity()
            .saturating_mul(std::mem::size_of::<usize>())
    }
}

#[derive(Clone, PartialEq, Eq)]
enum Derivation {
    Entry,
    Direct {
        predecessor: usize,
        step: AppliedTransfer,
    },
    Matched {
        caller: usize,
        callee: usize,
        call: AppliedTransfer,
        returned: AppliedTransfer,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct StateKey {
    row: usize,
    entry: usize,
    classes: usize,
    quality: PathQuality,
}
struct State {
    key: StateKey,
    derivation: Derivation,
    alternatives_truncated: bool,
}
struct Entry {
    row: usize,
    classes: usize,
    prefixes: [Option<usize>; 4],
}
struct IncomingPrefix {
    caller: usize,
    entry: usize,
    step: AppliedTransfer,
}
struct Prefix {
    parent: Option<usize>,
    incoming: Option<usize>,
    seed: Option<usize>,
    quality: PathQuality,
    alternatives_truncated: bool,
}
#[derive(Clone)]
struct WaitingReturn {
    caller: usize,
    entry: usize,
    call: AppliedTransfer,
}

/// Values remain distinct while observations filter local alternatives. Meeting
/// payloads before filtering could revive labels from a removed support, or
/// lose a path that generates a fresh label after an empty contribution.
/// This is request-local proof state over the first solve's unchanged facts.
struct Replay {
    nested_owned_bytes: usize,
    states: Vec<State>,
    state_ids: HashMap<StateKey, usize>,
    by_row: Vec<Vec<usize>>,
    entries: Vec<Entry>,
    entry_ids: HashMap<(usize, usize), usize>,
    values: Vec<TaintClassSet>,
    value_ids: HashMap<TaintClassSet, usize>,
    incoming: Vec<IncomingPrefix>,
    incoming_ids: HashSet<(usize, usize, usize)>,
    waiting: Vec<Vec<WaitingReturn>>,
    waiting_ids: HashSet<(usize, usize, usize)>,
    prefixes: Vec<Prefix>,
    queue: std::collections::VecDeque<usize>,
    query_limit: usize,
    max_retained_bytes: usize,
}

// Borrow the existing query controls for one witness walk without resetting spend.
struct WitnessCollection<'a, 'request> {
    limits: &'a mut TaintFindingCollectionLimits,
    request: &'a mut DataflowRequest<'request>,
    attribution: &'a mut TaintAttributionBudget,
}

impl Replay {
    fn owned_bytes(&self) -> usize {
        let mut heap = RetainedHeap::default();
        heap.add(std::mem::size_of::<Self>());
        heap.vec(&self.states);
        heap.map(&self.state_ids);
        heap.vec(&self.by_row);
        heap.vec(&self.entries);
        heap.map(&self.entry_ids);
        heap.vec(&self.values);
        heap.map(&self.value_ids);
        heap.vec(&self.incoming);
        heap.hash_set(&self.incoming_ids);
        heap.vec(&self.waiting);
        heap.hash_set(&self.waiting_ids);
        heap.vec(&self.prefixes);
        heap.add(
            self.queue
                .capacity()
                .saturating_mul(std::mem::size_of::<usize>()),
        );
        heap.add(self.nested_owned_bytes);
        heap.total()
    }

    fn reserve_bytes(&mut self, extra: usize) -> Result<(), IcfgTaintError> {
        let attempted = self.owned_bytes().saturating_add(extra);
        if attempted > self.max_retained_bytes {
            return Err(IcfgTaintError::RetentionBudget {
                limit: self.query_limit,
                attempted: self
                    .query_limit
                    .saturating_sub(self.max_retained_bytes)
                    .saturating_add(attempted),
            });
        }
        Ok(())
    }

    fn value(
        &mut self,
        classes: TaintClassSet,
        request: &mut DataflowRequest<'_>,
    ) -> Result<usize, IcfgTaintError> {
        if let Some(&id) = self.value_ids.get(&classes) {
            return Ok(id);
        }
        self.reserve_bytes(
            std::mem::size_of::<TaintClassSet>()
                .saturating_mul(2)
                .saturating_add(classes.retained_heap_bytes().saturating_mul(2)),
        )?;
        reserve(
            request,
            SolverWork {
                ide_values: 1,
                ..SolverWork::default()
            },
        )?;
        let id = self.values.len();
        self.nested_owned_bytes = self
            .nested_owned_bytes
            .saturating_add(classes.retained_heap_bytes().saturating_mul(2));
        self.value_ids.insert(classes.clone(), id);
        self.values.push(classes);
        self.reserve_bytes(0)?;
        Ok(id)
    }

    fn publish(
        &mut self,
        row: usize,
        entry: usize,
        classes: TaintClassSet,
        quality: PathQuality,
        derivation: Derivation,
        request: &mut DataflowRequest<'_>,
    ) -> Result<usize, IcfgTaintError> {
        let classes = self.value(classes, request)?;
        let key = StateKey {
            row,
            entry,
            classes,
            quality,
        };
        if let Some(&id) = self.state_ids.get(&key) {
            // Reachability needs only one derivation per state. A displayed
            // witness must still disclose other derivations omitted here.
            self.states[id].alternatives_truncated |= self.states[id].derivation != derivation;
            return Ok(id);
        }
        let evidence = match &derivation {
            Derivation::Entry => {
                debug_assert_eq!(self.entries[entry].row, row);
                debug_assert_eq!(self.entries[entry].classes, key.classes);
                0
            }
            Derivation::Direct { step, .. } => step.retained_bytes(),
            Derivation::Matched { call, returned, .. } => call
                .retained_bytes()
                .saturating_add(returned.retained_bytes()),
        };
        self.reserve_bytes(
            std::mem::size_of::<State>()
                .saturating_add(std::mem::size_of::<StateKey>())
                .saturating_add(evidence),
        )?;
        reserve(
            request,
            SolverWork {
                reached_states: 1,
                ide_relations: 1,
                witness_relations: 1,
                ide_propagations: 1,
                ..SolverWork::default()
            },
        )?;
        let id = self.states.len();
        self.state_ids.insert(key, id);
        let old_capacity = self.by_row[row].capacity();
        self.by_row[row].push(id);
        self.nested_owned_bytes = self
            .nested_owned_bytes
            .saturating_add(evidence)
            .saturating_add(
                self.by_row[row]
                    .capacity()
                    .saturating_sub(old_capacity)
                    .saturating_mul(std::mem::size_of::<usize>()),
            );
        self.states.push(State {
            key,
            derivation,
            alternatives_truncated: false,
        });
        self.queue.push_back(id);
        self.reserve_bytes(0)?;
        Ok(id)
    }

    fn entry(
        &mut self,
        row: usize,
        classes: TaintClassSet,
        request: &mut DataflowRequest<'_>,
    ) -> Result<usize, IcfgTaintError> {
        let value = self.value(classes, request)?;
        if let Some(&id) = self.entry_ids.get(&(row, value)) {
            return Ok(id);
        }
        self.reserve_bytes(
            std::mem::size_of::<Entry>().saturating_add(std::mem::size_of::<(usize, usize)>()),
        )?;
        reserve(
            request,
            SolverWork {
                ide_relations: 1,
                ..SolverWork::default()
            },
        )?;
        let id = self.entries.len();
        self.entry_ids.insert((row, value), id);
        self.entries.push(Entry {
            row,
            classes: value,
            prefixes: [None; 4],
        });
        self.publish(
            row,
            id,
            self.values[value].clone(),
            PathQuality::PROVEN_COMPLETE,
            Derivation::Entry,
            request,
        )?;
        Ok(id)
    }

    fn incoming(
        &mut self,
        caller: usize,
        entry: usize,
        step: AppliedTransfer,
        request: &mut DataflowRequest<'_>,
    ) -> Result<(), IcfgTaintError> {
        if !self.incoming_ids.insert((caller, entry, step.record)) {
            return Ok(());
        }
        self.reserve_bytes(
            std::mem::size_of::<IncomingPrefix>().saturating_add(step.retained_bytes()),
        )?;
        reserve(
            request,
            SolverWork {
                incoming_calls: 1,
                witness_relations: 1,
                ..SolverWork::default()
            },
        )?;
        self.nested_owned_bytes = self
            .nested_owned_bytes
            .saturating_add(step.retained_bytes());
        self.incoming.push(IncomingPrefix {
            caller,
            entry,
            step,
        });
        self.reserve_bytes(0)?;
        Ok(())
    }

    fn prefix_qualities(
        &mut self,
        recorded: &RecordedIdeRelations<TaintFact, AttributedTaintFunction>,
        request: &mut DataflowRequest<'_>,
    ) -> Result<(), IcfgTaintError> {
        self.reserve_bytes(
            self.entries
                .len()
                .saturating_mul(std::mem::size_of::<Vec<usize>>())
                .saturating_add(
                    self.incoming
                        .len()
                        .saturating_mul(std::mem::size_of::<usize>()),
                ),
        )?;
        let mut by_entry = vec![Vec::new(); self.entries.len()];
        for (id, incoming) in self.incoming.iter().enumerate() {
            by_entry[self.states[incoming.caller].key.entry].push(id);
        }
        let mut queue = std::collections::VecDeque::new();
        for (id, entry) in self.entries.iter().enumerate() {
            for quality in PathQuality::ALL {
                if entry.prefixes[quality.ordinal()].is_some() {
                    queue.push_back((id, quality));
                }
            }
        }
        let mut prefix_heap = RetainedHeap::default();
        prefix_heap.vec(&by_entry);
        for row in &by_entry {
            prefix_heap.vec(row);
        }
        let prefix_bytes = prefix_heap.total();
        while let Some((entry, quality)) = queue.pop_front() {
            let mut transient = RetainedHeap::default();
            transient.add(prefix_bytes);
            transient.add(
                queue
                    .capacity()
                    .saturating_mul(std::mem::size_of::<(usize, PathQuality)>()),
            );
            self.reserve_bytes(transient.total())?;
            reserve(
                request,
                SolverWork {
                    ide_propagations: 1 + by_entry[entry].len(),
                    ..SolverWork::default()
                },
            )?;
            let parent = self.entries[entry].prefixes[quality.ordinal()]
                .expect("a queued prefix has a proof");
            for &incoming in &by_entry[entry] {
                let row = &self.incoming[incoming];
                let edge = &recorded.trace().records[row.step.record].key.edge;
                let quality = quality
                    .conjoin(self.states[row.caller].key.quality)
                    .through_evidence(&edge.proof, &edge.completeness);
                if let Some(id) = self.entries[row.entry].prefixes[quality.ordinal()] {
                    let prefix = &mut self.prefixes[id];
                    prefix.alternatives_truncated |=
                        prefix.parent != Some(parent) || prefix.incoming != Some(incoming);
                    continue;
                }
                let target = row.entry;
                self.reserve_bytes(std::mem::size_of::<Prefix>())?;
                reserve(
                    request,
                    SolverWork {
                        witness_relations: 1,
                        ..SolverWork::default()
                    },
                )?;
                let id = self.prefixes.len();
                self.prefixes.push(Prefix {
                    parent: Some(parent),
                    incoming: Some(incoming),
                    seed: None,
                    quality,
                    alternatives_truncated: false,
                });
                self.entries[target].prefixes[quality.ordinal()] = Some(id);
                queue.push_back((target, quality));
            }
        }
        Ok(())
    }

    fn witness(
        &self,
        state: usize,
        prefix: usize,
        session: &IcfgTaintSession<'_>,
        recorded: &RecordedIdeRelations<TaintFact, AttributedTaintFunction>,
        collection: WitnessCollection<'_, '_>,
        other_owned_bytes: usize,
    ) -> Result<Option<(Arc<SummaryWitness>, PathChecks)>, IcfgTaintError> {
        let WitnessCollection {
            limits,
            request,
            attribution,
        } = collection;
        enum Frame<'a> {
            State(usize),
            Prefix(usize),
            Edge(&'a AppliedTransfer),
        }
        let Some(grant) = attribution.witness_grant(session.witness_limits) else {
            attribution.charge_witness_walk(0, 0, true);
            return Ok(None);
        };
        let facts = session.baseline.result().fact_result();
        let mut stack = vec![Frame::State(state), Frame::Prefix(prefix)];
        let mut steps = Vec::new();
        let mut checks = PathChecks::default();
        let mut alternatives_truncated = false;
        let mut expansions = 0;
        let check_live = |stack: &Vec<Frame<'_>>,
                          steps: &Vec<SummaryWitnessStep>,
                          checks: &PathChecks,
                          extra: usize|
         -> Result<(), IcfgTaintError> {
            let live = self
                .owned_bytes()
                .saturating_add(other_owned_bytes)
                .saturating_add(
                    stack
                        .capacity()
                        .saturating_mul(std::mem::size_of::<Frame<'_>>()),
                )
                .saturating_add(
                    steps
                        .capacity()
                        .saturating_mul(std::mem::size_of::<SummaryWitnessStep>()),
                )
                .saturating_add(
                    steps
                        .iter()
                        .map(SummaryWitnessStep::retained_owned_bytes)
                        .sum::<usize>(),
                )
                .saturating_add(
                    checks
                        .ids
                        .capacity()
                        .saturating_mul(std::mem::size_of::<usize>()),
                );
            let live = live.saturating_add(extra);
            if live > self.max_retained_bytes {
                return Err(IcfgTaintError::RetentionBudget {
                    limit: self.query_limit,
                    attempted: self
                        .query_limit
                        .saturating_sub(self.max_retained_bytes)
                        .saturating_add(live),
                });
            }
            Ok(())
        };
        let walked = (|| -> Result<bool, IcfgTaintError> {
            while let Some(frame) = stack.pop() {
                reserve(
                    request,
                    SolverWork {
                        ide_propagations: 1,
                        ..SolverWork::default()
                    },
                )?;
                if expansions == limits.max_witness_expansions.min(grant.max_expansions())
                    || steps.len() == limits.max_witness_steps.min(grant.max_steps())
                {
                    return Ok(false);
                }
                check_live(&stack, &steps, &checks, 0)?;
                expansions += 1;
                match frame {
                    Frame::Prefix(id) => {
                        let prefix = &self.prefixes[id];
                        alternatives_truncated |= prefix.alternatives_truncated;
                        if let Some(row) = prefix.seed {
                            let seed = &facts.reached()[row];
                            check_live(
                                &stack,
                                &steps,
                                &checks,
                                std::mem::size_of::<SummaryWitnessStep>(),
                            )?;
                            // Only the root prefix owns a seed. Relative callee
                            // entries are connected by their actual call edge.
                            steps.push(SummaryWitnessStep::new(
                                SummaryWitnessStepKind::Seed,
                                seed.point().clone(),
                                None,
                                None,
                                None,
                                crate::analyzer::semantic::ProofStatus::Proven,
                                crate::analyzer::semantic::EvidenceCompleteness::Complete,
                                seed.fact(),
                                seed.fact(),
                            ));
                        }
                        if let Some(incoming) = prefix.incoming {
                            let incoming = &self.incoming[incoming];
                            stack.push(Frame::Edge(&incoming.step));
                            stack.push(Frame::State(incoming.caller));
                        }
                        if let Some(parent) = prefix.parent {
                            stack.push(Frame::Prefix(parent));
                        }
                    }
                    Frame::State(id) => {
                        alternatives_truncated |= self.states[id].alternatives_truncated;
                        match &self.states[id].derivation {
                            Derivation::Entry => {}
                            Derivation::Direct { predecessor, step } => {
                                stack.push(Frame::Edge(step));
                                stack.push(Frame::State(*predecessor));
                            }
                            Derivation::Matched {
                                caller,
                                callee,
                                call,
                                returned,
                            } => {
                                stack.push(Frame::Edge(returned));
                                stack.push(Frame::State(*callee));
                                stack.push(Frame::Edge(call));
                                stack.push(Frame::State(*caller));
                            }
                        }
                    }
                    Frame::Edge(step) => {
                        checks.extend(&step.checks);
                        let key = &recorded.trace().records[step.record].key;
                        let edge =
                            if key.edge.kind == IcfgEdgeKind::Call && step.fact.sink().is_some() {
                                // The frozen kernel publishes call observations at
                                // the caller point, not inside the callee (#1954).
                                // Use its actual observation edge and transfer
                                // evidence for either observation phase.
                                let transfer = key
                                    .call_transfer
                                    .as_ref()
                                    .expect("a captured call has its transfer");
                                crate::dataflow::call_observation_edge(
                                    &key.edge.source,
                                    &transfer.origin,
                                    &transfer.proof,
                                    &transfer.completeness,
                                )
                            } else {
                                key.edge.clone()
                            };
                        let input = facts
                            .facts()
                            .iter()
                            .position(|fact| *fact == key.input)
                            .expect("a captured input is interned");
                        let output = facts
                            .facts()
                            .iter()
                            .position(|fact| *fact == step.fact)
                            .expect("a captured output is interned");
                        steps.push(SummaryWitnessStep::new(
                            SummaryWitnessStepKind::Edge(edge.kind),
                            edge.source,
                            Some(edge.target),
                            edge.origin,
                            edge.boundary,
                            edge.proof,
                            edge.completeness,
                            FactId::try_from_index(input).expect("interned fact IDs fit"),
                            FactId::try_from_index(output).expect("interned fact IDs fit"),
                        ));
                    }
                }
                check_live(&stack, &steps, &checks, 0)?;
            }
            // The last Edge has already appended owned evidence even though no
            // next loop iteration exists. Admit the Arc owner before publishing.
            check_live(
                &stack,
                &steps,
                &checks,
                std::mem::size_of::<SummaryWitness>() + 2 * std::mem::size_of::<usize>(),
            )?;
            Ok(true)
        })();
        attribution.charge_witness_walk(steps.len(), expansions, matches!(walked, Ok(false)));
        limits.max_witness_expansions = limits.max_witness_expansions.saturating_sub(expansions);
        if !walked? {
            return Ok(None);
        }
        let retained = std::mem::size_of::<SummaryWitness>()
            .saturating_add(std::mem::size_of_val(steps.as_slice()))
            .saturating_add(
                steps
                    .iter()
                    .map(SummaryWitnessStep::retained_owned_bytes)
                    .sum::<usize>(),
            );
        if limits.max_witnesses == 0 || retained > limits.max_retained_witness_bytes {
            return Ok(None);
        }
        limits.max_witnesses -= 1;
        limits.max_witness_steps -= steps.len();
        limits.max_retained_witness_bytes -= retained;
        let count = steps.len();
        let meeting = facts
            .fact(facts.reached()[self.states[state].key.row].fact())
            .expect("a replay state retains its captured fact");
        let quality = self.states[state]
            .key
            .quality
            .conjoin(self.prefixes[prefix].quality)
            .conjoin(if meeting.is_uncertain() {
                PathQuality::UNPROVEN_PARTIAL
            } else {
                PathQuality::PROVEN_COMPLETE
            });
        Ok(Some((
            Arc::new(SummaryWitness::from_parts(
                steps,
                quality,
                None,
                0,
                alternatives_truncated,
                retained,
                WitnessReconstructionWork::new(expansions, count),
            )),
            checks,
        )))
    }
}

impl Classification {
    fn admit_replay(
        &self,
        replay: &mut Replay,
        session: &IcfgTaintSession<'_>,
        supports: &FrozenSupports,
    ) -> Result<(), IcfgTaintError> {
        replay.max_retained_bytes =
            session.remaining_bytes(supports.retained_bytes.saturating_add(self.owned_bytes()))?;
        replay.reserve_bytes(0)
    }

    #[allow(clippy::too_many_arguments)]
    fn solve(
        &mut self,
        session: &IcfgTaintSession<'_>,
        recorded: &RecordedIdeRelations<TaintFact, AttributedTaintFunction>,
        supports: &FrozenSupports,
        plan: &TaintAnalysisPlan,
        source: ValueFlowSourceId,
        classes: &TaintClassSet,
        predicates: &[(Box<str>, ValueTypePredicate)],
        filter: &dyn ValueTypeBarrierFilter,
        request: &mut DataflowRequest<'_>,
        classify: &mut impl FnMut(
            &BarrierObservation,
            ValueTypePredicate,
        ) -> Result<ValueTypeBarrierDecision, Box<str>>,
    ) -> Result<Replay, IcfgTaintError> {
        let facts = session.baseline.result().fact_result();
        let rows = facts.reached();
        let graph = recorded.graph();
        let max_retained_bytes =
            session.remaining_bytes(supports.retained_bytes.saturating_add(self.owned_bytes()))?;
        let initial_bytes = rows
            .len()
            .saturating_mul(std::mem::size_of::<Vec<usize>>())
            .saturating_add(
                supports
                    .matched
                    .len()
                    .saturating_mul(std::mem::size_of::<Vec<WaitingReturn>>()),
            );
        if initial_bytes > max_retained_bytes {
            return Err(IcfgTaintError::RetentionBudget {
                limit: session.max_refinement_bytes,
                attempted: session
                    .max_refinement_bytes
                    .saturating_sub(max_retained_bytes)
                    .saturating_add(initial_bytes),
            });
        }
        reserve(
            request,
            SolverWork {
                ide_propagations: rows.len() + supports.matched.len(),
                ..SolverWork::default()
            },
        )?;
        let mut replay = Replay {
            nested_owned_bytes: 0,
            states: Vec::new(),
            state_ids: HashMap::default(),
            by_row: vec![Vec::new(); rows.len()],
            entries: Vec::new(),
            entry_ids: HashMap::default(),
            values: Vec::new(),
            value_ids: HashMap::default(),
            incoming: Vec::new(),
            incoming_ids: HashSet::default(),
            waiting: vec![Vec::new(); supports.matched.len()],
            waiting_ids: HashSet::default(),
            prefixes: Vec::new(),
            queue: std::collections::VecDeque::new(),
            query_limit: session.max_refinement_bytes,
            max_retained_bytes,
        };
        for &entry in &graph.entry_rows {
            if supports.chop[entry]
                && rows[entry].entry().procedure() == plan.value_flow().root()
                && rows[entry].entry().call_context()
                    == &crate::analyzer::semantic::OracleCallContext::empty()
                && facts
                    .fact(rows[entry].fact())
                    .is_some_and(|fact| fact.is_zero())
            {
                let entry = replay.entry(entry, plan.universe().empty_set(), request)?;
                replay.reserve_bytes(std::mem::size_of::<Prefix>())?;
                let prefix = replay.prefixes.len();
                replay.prefixes.push(Prefix {
                    parent: None,
                    incoming: None,
                    seed: Some(replay.entries[entry].row),
                    quality: PathQuality::PROVEN_COMPLETE,
                    alternatives_truncated: false,
                });
                replay.entries[entry].prefixes[PathQuality::PROVEN_COMPLETE.ordinal()] =
                    Some(prefix);
            }
        }
        while let Some(state) = replay.queue.pop_front() {
            replay.max_retained_bytes = session
                .remaining_bytes(supports.retained_bytes.saturating_add(self.owned_bytes()))?;
            replay.reserve_bytes(0)?;
            reserve(
                request,
                SolverWork {
                    ide_propagations: 1,
                    ..SolverWork::default()
                },
            )?;
            let key = replay.states[state].key;
            let input = replay.values[key.classes].clone();
            let _input_bytes = session.scratch_bytes(input.retained_heap_bytes());
            self.admit_replay(&mut replay, session, supports)?;
            for &id in &supports.direct_by_source[key.row] {
                let relation = supports.direct[id];
                let target = *facts
                    .fact(rows[relation.target].fact())
                    .expect("a frozen target has a fact");
                let alternatives = self.evaluate(
                    session,
                    supports.retained_bytes.saturating_add(replay.owned_bytes()),
                    recorded,
                    relation.record,
                    plan,
                    source,
                    classes,
                    &input,
                    predicates,
                    filter,
                    request,
                    classify,
                )?;
                let edge = &recorded.trace().records[relation.record].key.edge;
                let _alternative_bytes =
                    session.scratch_bytes(alternatives_owned_bytes(&alternatives));
                self.admit_replay(&mut replay, session, supports)?;
                for alternative in alternatives.iter().filter(|a| a.fact == target) {
                    reserve(
                        request,
                        SolverWork {
                            value_operations: 1,
                            ..SolverWork::default()
                        },
                    )?;
                    let output = alternative.function.base.apply(&input);
                    replay.publish(
                        relation.target,
                        key.entry,
                        output,
                        key.quality
                            .through_evidence(&edge.proof, &edge.completeness),
                        Derivation::Direct {
                            predecessor: state,
                            step: AppliedTransfer::new(relation.record, alternative),
                        },
                        request,
                    )?;
                }
            }
            for &id in &supports.entries_by_source[key.row] {
                let relation = supports.entries[id];
                let target = *facts
                    .fact(rows[relation.target].fact())
                    .expect("a frozen entry has a fact");
                let alternatives = self.evaluate(
                    session,
                    supports.retained_bytes.saturating_add(replay.owned_bytes()),
                    recorded,
                    relation.record,
                    plan,
                    source,
                    classes,
                    &input,
                    predicates,
                    filter,
                    request,
                    classify,
                )?;
                let _alternative_bytes =
                    session.scratch_bytes(alternatives_owned_bytes(&alternatives));
                self.admit_replay(&mut replay, session, supports)?;
                for alternative in alternatives.iter().filter(|a| a.fact == target) {
                    reserve(
                        request,
                        SolverWork {
                            value_operations: 1,
                            ..SolverWork::default()
                        },
                    )?;
                    let entry = replay.entry(
                        relation.target,
                        alternative.function.base.apply(&input),
                        request,
                    )?;
                    replay.incoming(
                        state,
                        entry,
                        AppliedTransfer::new(relation.record, alternative),
                        request,
                    )?;
                }
            }
            for &id in &supports.matched_by_caller[key.row] {
                let relation = supports.matched[id];
                let entry_row = graph.row_entries[relation.exit];
                let target = *facts
                    .fact(rows[entry_row].fact())
                    .expect("a frozen callee entry has a fact");
                let alternatives = self.evaluate(
                    session,
                    supports.retained_bytes.saturating_add(replay.owned_bytes()),
                    recorded,
                    relation.call,
                    plan,
                    source,
                    classes,
                    &input,
                    predicates,
                    filter,
                    request,
                    classify,
                )?;
                let _alternative_bytes =
                    session.scratch_bytes(alternatives_owned_bytes(&alternatives));
                self.admit_replay(&mut replay, session, supports)?;
                for alternative in alternatives.iter().filter(|a| a.fact == target) {
                    reserve(
                        request,
                        SolverWork {
                            value_operations: 1,
                            ..SolverWork::default()
                        },
                    )?;
                    let entry = replay.entry(
                        entry_row,
                        alternative.function.base.apply(&input),
                        request,
                    )?;
                    if replay.waiting_ids.insert((id, state, entry)) {
                        let call = AppliedTransfer::new(relation.call, alternative);
                        replay.reserve_bytes(
                            std::mem::size_of::<WaitingReturn>()
                                .saturating_add(call.retained_bytes()),
                        )?;
                        reserve(
                            request,
                            SolverWork {
                                summary_applications: 1,
                                witness_relations: 1,
                                ..SolverWork::default()
                            },
                        )?;
                        let waiting = WaitingReturn {
                            caller: state,
                            entry,
                            call,
                        };
                        let _waiting_bytes = session.scratch_bytes(waiting.call.retained_bytes());
                        self.admit_replay(&mut replay, session, supports)?;
                        let old_capacity = replay.waiting[id].capacity();
                        replay.waiting[id].push(waiting.clone());
                        replay.nested_owned_bytes = replay
                            .nested_owned_bytes
                            .saturating_add(waiting.call.retained_bytes())
                            .saturating_add(
                                replay.waiting[id]
                                    .capacity()
                                    .saturating_sub(old_capacity)
                                    .saturating_mul(std::mem::size_of::<WaitingReturn>()),
                            );
                        replay.reserve_bytes(0)?;
                        for index in 0..replay.by_row[relation.exit].len() {
                            let exit = replay.by_row[relation.exit][index];
                            if replay.states[exit].key.entry == entry {
                                self.apply_return(
                                    &mut replay,
                                    recorded,
                                    relation,
                                    exit,
                                    &waiting,
                                    session,
                                    supports,
                                    plan,
                                    source,
                                    classes,
                                    predicates,
                                    filter,
                                    request,
                                    classify,
                                )?;
                            }
                        }
                    }
                }
            }
            for &id in &supports.matched_by_exit[key.row] {
                for index in 0..replay.waiting[id].len() {
                    let waiting = replay.waiting[id][index].clone();
                    let _waiting_bytes = session.scratch_bytes(waiting.call.retained_bytes());
                    self.admit_replay(&mut replay, session, supports)?;
                    if waiting.entry == key.entry {
                        self.apply_return(
                            &mut replay,
                            recorded,
                            supports.matched[id],
                            state,
                            &waiting,
                            session,
                            supports,
                            plan,
                            source,
                            classes,
                            predicates,
                            filter,
                            request,
                            classify,
                        )?;
                    }
                }
            }
        }
        replay.max_retained_bytes =
            session.remaining_bytes(supports.retained_bytes.saturating_add(self.owned_bytes()))?;
        replay.prefix_qualities(recorded, request)?;
        replay.reserve_bytes(0)?;
        Ok(replay)
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_return(
        &mut self,
        replay: &mut Replay,
        recorded: &RecordedIdeRelations<TaintFact, AttributedTaintFunction>,
        relation: Matched,
        exit: usize,
        waiting: &WaitingReturn,
        session: &IcfgTaintSession<'_>,
        supports: &FrozenSupports,
        plan: &TaintAnalysisPlan,
        source: ValueFlowSourceId,
        classes: &TaintClassSet,
        predicates: &[(Box<str>, ValueTypePredicate)],
        filter: &dyn ValueTypeBarrierFilter,
        request: &mut DataflowRequest<'_>,
        classify: &mut impl FnMut(
            &BarrierObservation,
            ValueTypePredicate,
        ) -> Result<ValueTypeBarrierDecision, Box<str>>,
    ) -> Result<(), IcfgTaintError> {
        let input = replay.values[replay.states[exit].key.classes].clone();
        let _input_bytes = session.scratch_bytes(input.retained_heap_bytes());
        self.admit_replay(replay, session, supports)?;
        let target = *session
            .baseline
            .result()
            .fact_result()
            .fact(session.baseline.result().fact_result().reached()[relation.target].fact())
            .expect("a frozen return target has a fact");
        let alternatives = self.evaluate(
            session,
            supports.retained_bytes.saturating_add(replay.owned_bytes()),
            recorded,
            relation.returned,
            plan,
            source,
            classes,
            &input,
            predicates,
            filter,
            request,
            classify,
        )?;
        let caller = &replay.states[waiting.caller].key;
        let entry = caller.entry;
        let call_edge = &recorded.trace().records[relation.call].key.edge;
        let return_edge = &recorded.trace().records[relation.returned].key.edge;
        let quality = caller
            .quality
            .through_evidence(&call_edge.proof, &call_edge.completeness)
            .conjoin(replay.states[exit].key.quality)
            .through_evidence(&return_edge.proof, &return_edge.completeness);
        let _alternative_bytes = session.scratch_bytes(alternatives_owned_bytes(&alternatives));
        self.admit_replay(replay, session, supports)?;
        for alternative in alternatives.iter().filter(|a| a.fact == target) {
            reserve(
                request,
                SolverWork {
                    value_operations: 1,
                    summary_applications: 1,
                    ..SolverWork::default()
                },
            )?;
            replay.publish(
                relation.target,
                entry,
                alternative.function.base.apply(&input),
                quality,
                Derivation::Matched {
                    caller: waiting.caller,
                    callee: exit,
                    call: waiting.call.clone(),
                    returned: AppliedTransfer::new(relation.returned, alternative),
                },
                request,
            )?;
        }
        Ok(())
    }
}

#[derive(Clone)]
struct PairPass {
    sink: ValueFlowSinkId,
    meeting: TaintFact,
    classes: TaintClassSet,
    contributed: TaintClassSet,
    qualities: PathQualityFrontier,
    witnesses: Vec<Arc<SummaryWitness>>,
    checks: PathChecks,
    certain: bool,
    unavailable: bool,
    closures: Vec<crate::value_flow::AuthoredArmClosure>,
}

fn passes_owned_bytes(passes: &Vec<PairPass>) -> usize {
    let mut heap = RetainedHeap::default();
    retain_passes(passes, &mut heap);
    heap.total()
}

fn retain_passes(passes: &Vec<PairPass>, heap: &mut RetainedHeap) {
    heap.vec(passes);
    for pass in passes {
        heap.add(
            pass.classes
                .retained_heap_bytes()
                .saturating_add(pass.contributed.retained_heap_bytes()),
        );
        heap.vec(&pass.checks.ids);
        heap.vec(&pass.witnesses);
        heap.vec(&pass.closures);
        for closure in &pass.closures {
            heap.add(closure.retained_heap_bytes());
        }
        for witness in &pass.witnesses {
            heap.arc(witness, |witness, heap| {
                heap.add(
                    witness
                        .retained_bytes()
                        .saturating_sub(std::mem::size_of::<SummaryWitness>()),
                )
            });
        }
    }
}

impl IcfgTaintSession<'_> {
    #[allow(clippy::too_many_arguments)]
    fn pair_passes(
        &self,
        replay: &Replay,
        classification_checks: &[ValueTypeBarrierCheck],
        plan: &TaintAnalysisPlan,
        recorded: &RecordedIdeRelations<TaintFact, AttributedTaintFunction>,
        source: &super::TaintSourceBinding,
        source_class: &TaintClassSet,
        limits: &mut TaintFindingCollectionLimits,
        request: &mut DataflowRequest<'_>,
        attribution: &mut TaintAttributionBudget,
    ) -> Result<(Vec<PairPass>, Option<IcfgTaintIncomplete>), IcfgTaintError> {
        let facts = self.baseline.result().fact_result();
        let mut passes: Vec<PairPass> = Vec::new();
        // Keep a representative for each pair, payload and concrete quality.
        // Discovery and replay retain every support; duplicate meeting states
        // must not consume the witness budget and downgrade later pairs.
        let mut represented: HashMap<_, (usize, usize)> = HashMap::default();
        let mut unavailable = HashSet::default();
        let mut source_coverage = None;
        'states: for (state_id, state) in replay.states.iter().enumerate() {
            let fact = *facts
                .fact(facts.reached()[state.key.row].fact())
                .expect("a frozen state has a fact");
            let Some(sink) = fact.sink() else {
                continue;
            };
            let live = replay.values[state.key.classes].intersection(
                plan.sink(sink)
                    .expect("a frozen meeting has a bound sink")
                    .accepted(),
            );
            if live.is_empty() {
                continue;
            }
            let mut candidates = Vec::new();
            let mut frontier = PathQualityFrontier::default();
            for prefix in replay.entries[state.key.entry]
                .prefixes
                .iter()
                .flatten()
                .copied()
            {
                let quality = replay.prefixes[prefix].quality.conjoin(state.key.quality);
                let quality = if fact.is_uncertain() {
                    quality.conjoin(PathQuality::UNPROVEN_PARTIAL)
                } else {
                    quality
                };
                frontier.insert(quality);
                candidates.push((quality, prefix));
            }
            for quality in frontier.iter() {
                if let Some(&(pair, witness)) =
                    represented.get(&(sink, fact.is_uncertain(), state.key.classes, quality))
                {
                    // This state was visited once. Its distinct meeting/entry
                    // is not reconstructed after selecting a representative.
                    Arc::get_mut(&mut passes[pair].witnesses[witness])
                        .expect("pair construction owns its witness")
                        .mark_alternatives_truncated();
                    continue;
                }
                let prefix = candidates
                    .iter()
                    .find(|(candidate, _)| *candidate == quality)
                    .expect("a retained quality has a concrete prefix")
                    .1;
                let mut transient = RetainedHeap::default();
                transient.map(&represented);
                transient.hash_set(&unavailable);
                transient.vec(&candidates);
                transient.add(passes_owned_bytes(&passes));
                transient.add(live.retained_heap_bytes());
                let transient_bytes = transient.total();
                let available = replay
                    .max_retained_bytes
                    .saturating_sub(replay.owned_bytes());
                if transient_bytes > available {
                    source_coverage = Some(IcfgTaintIncomplete::RetentionBudget {
                        limit: self.max_refinement_bytes,
                        attempted: replay
                            .query_limit
                            .saturating_sub(replay.max_retained_bytes)
                            .saturating_add(replay.owned_bytes())
                            .saturating_add(transient_bytes),
                    });
                    break 'states;
                }
                let witness = match replay.witness(
                    state_id,
                    prefix,
                    self,
                    recorded,
                    WitnessCollection {
                        limits: &mut *limits,
                        request: &mut *request,
                        attribution: &mut *attribution,
                    },
                    transient_bytes,
                ) {
                    Ok(witness) => witness,
                    Err(error) => {
                        source_coverage = Some(recoverable_stop(error)?);
                        break 'states;
                    }
                };
                let position = passes
                    .iter()
                    .position(|pass| {
                        pass.sink == sink && pass.meeting.is_uncertain() == fact.is_uncertain()
                    })
                    .unwrap_or_else(|| {
                        passes.push(PairPass {
                            sink,
                            meeting: fact,
                            classes: plan.universe().empty_set(),
                            contributed: plan.universe().empty_set(),
                            qualities: PathQualityFrontier::default(),
                            witnesses: Vec::new(),
                            checks: PathChecks::default(),
                            certain: false,
                            unavailable: false,
                            closures: Vec::new(),
                        });
                        passes.len() - 1
                    });
                let pass = &mut passes[position];
                pass.classes.union_with(&live);
                pass.contributed.union_with(source_class);
                if let Some((mut witness, mut checks)) = witness {
                    if candidates
                        .iter()
                        .filter(|(candidate, _)| *candidate == quality)
                        .nth(1)
                        .is_some()
                    {
                        Arc::get_mut(&mut witness)
                            .expect("new witness has one owner")
                            .mark_alternatives_truncated();
                    }
                    represented.insert(
                        (sink, fact.is_uncertain(), state.key.classes, quality),
                        (position, pass.witnesses.len()),
                    );
                    pass.qualities.insert(quality);
                    let source_spec = plan
                        .value_flow()
                        .source(source.source())
                        .expect("a selected source has a specification");
                    for closure in plan
                        .value_flow()
                        .witness_arm_closures(&witness, source_spec.point())
                    {
                        if !pass.closures.contains(&closure) {
                            pass.closures.push(closure);
                        }
                    }
                    let sink_spec = plan
                        .value_flow()
                        .sink(sink)
                        .expect("a frozen sink has a specification");
                    if let Some(closures) = plan.value_flow().certain_witness_closures(
                        facts,
                        &witness,
                        source_spec,
                        sink_spec,
                    ) {
                        // Closure validation discharges native/authored path
                        // and dispatch obligations, not an uncertain source or
                        // meeting fact. Keep its dependencies in either case.
                        pass.certain |= !fact.is_uncertain();
                        for closure in closures {
                            if !pass.closures.contains(&closure) {
                                pass.closures.push(closure);
                            }
                        }
                    }
                    // Like composition, render checks on value-producing witness
                    // steps. A terminal sink adds no step. Its observation still
                    // filters both passes, but an identical failure already
                    // represented by the value's producer needs no phase-only note.
                    let redundant = checks
                        .ids
                        .iter()
                        .copied()
                        .filter(|&id| {
                            let check = &classification_checks[id];
                            check.observation.point() == sink_spec.point()
                                && check.observation.phase() == ObservationPhase::BeforeEffects
                                && concrete_value(sink_spec.carrier())
                                    == Some(check.observation.value())
                                && !(source_spec.point() == sink_spec.point()
                                    && source_spec.phase()
                                        == ValueFlowObservationPhase::BeforeEffects
                                    && concrete_value(source_spec.carrier())
                                        == Some(check.observation.value()))
                                && checks.ids.iter().any(|&other| {
                                    let other = &classification_checks[other];
                                    other.observation.point().procedure()
                                        == check.observation.point().procedure()
                                        && other.observation.value() == check.observation.value()
                                        && other.observation.phase()
                                            == ObservationPhase::AfterEffects
                                        && other.predicate == check.predicate
                                        && other.decision == check.decision
                                })
                        })
                        .collect::<Vec<_>>();
                    checks.ids.retain(|id| !redundant.contains(id));
                    pass.checks.extend(&checks);
                    drop(redundant);
                    drop(checks);
                    pass.witnesses.push(witness);
                    // Include the final pair growth while Replay is still live.
                    let mut retained = RetainedHeap::default();
                    retained.map(&represented);
                    retained.hash_set(&unavailable);
                    retained.vec(&candidates);
                    retained.add(live.retained_heap_bytes());
                    retain_passes(&passes, &mut retained);
                    let live = replay.owned_bytes().saturating_add(retained.total());
                    if live > replay.max_retained_bytes {
                        source_coverage = Some(IcfgTaintIncomplete::RetentionBudget {
                            limit: replay.query_limit,
                            attempted: replay
                                .query_limit
                                .saturating_sub(replay.max_retained_bytes)
                                .saturating_add(live),
                        });
                        break 'states;
                    }
                } else {
                    unavailable.insert((sink, fact.is_uncertain(), state.key.classes, quality));
                    source_coverage = Some(IcfgTaintIncomplete::WitnessLimit(
                        TaintWitnessTruncationCause::CollectionBudget,
                    ));
                    break 'states;
                }
            }
        }
        for (sink, uncertain, payload, quality) in unavailable {
            if represented
                .iter()
                .any(|(&(seen_sink, seen_uncertain, seen_payload, proof), _)| {
                    seen_sink == sink
                        && seen_uncertain == uncertain
                        && seen_payload == payload
                        && proof.dominates(quality)
                })
            {
                continue;
            }
            let pass = passes
                .iter_mut()
                .find(|pass| pass.sink == sink && pass.meeting.is_uncertain() == uncertain)
                .expect("a candidate has a pair envelope");
            pass.unavailable = true;
            pass.qualities.insert(PathQuality::UNPROVEN_PARTIAL);
        }
        if source_coverage.is_none() && passes.iter().any(|pass| pass.unavailable) {
            source_coverage = Some(IcfgTaintIncomplete::WitnessLimit(
                TaintWitnessTruncationCause::CollectionBudget,
            ));
        }
        // Even an unavailable final witness can grow the last pair/quality.
        // Check it while the complete Replay owner is still present.
        let mut retained = RetainedHeap::default();
        retained.map(&represented);
        retain_passes(&passes, &mut retained);
        let live = replay.owned_bytes().saturating_add(retained.total());
        if live > replay.max_retained_bytes {
            source_coverage = Some(IcfgTaintIncomplete::RetentionBudget {
                limit: replay.query_limit,
                attempted: replay
                    .query_limit
                    .saturating_sub(replay.max_retained_bytes)
                    .saturating_add(live),
            });
        }
        Ok((passes, source_coverage))
    }

    fn report_pair(
        &self,
        plan: &TaintAnalysisPlan,
        source: &super::TaintSourceBinding,
        pass: &PairPass,
    ) -> Result<TaintFindingReport, IcfgTaintError> {
        let origins = TaintOriginStatus::composed(
            vec![TaintOriginFindingEvidence::composed(
                source.origin().clone(),
                pass.contributed.clone(),
                pass.classes.clone(),
                pass.witnesses.clone(),
                pass.certain,
                pass.closures.clone(),
                None,
            )],
            pass.unavailable,
        );
        let fixed = self
            .baseline
            .result()
            .result()
            .termination()
            .is_fixed_point();
        let coverage = self.baseline.result().fact_result().coverage();
        let proven = !pass.meeting.is_uncertain()
            && fixed
            && (self.baseline.is_complete()
                || (coverage.unproven_edges().is_empty() && coverage.partial_edges().is_empty()))
            && pass.qualities.has_proven_path();
        let mut finding = TaintFinding::composed(
            plan,
            pass.sink,
            pass.classes.clone(),
            pass.qualities,
            proven || (fixed && pass.certain),
            (self.baseline.is_complete() && pass.qualities.has_complete_path())
                || (fixed && pass.certain),
            origins,
        )
        .map_err(IcfgTaintError::Findings)?
        .with_meeting_fact(pass.meeting);
        // Replay tracks classes and path quality, but not per-class model
        // receipts. A strict pair can discard an approximate alternative;
        // retaining its baseline sink receipt is conservative and prevents
        // the refinement from silently clearing a recorded dependency. A
        // multi-class baseline finding may mark another class in this pair.
        let result = self.baseline.result();
        if let Some(indices) = self
            .meeting_values
            .get(&(pass.sink, pass.meeting.is_uncertain()))
        {
            for &index in indices {
                let meeting = &result.point_values()[index];
                let classes = result
                    .value(meeting.value())
                    .ok_or(IcfgTaintError::Findings(TaintFindingError::InvalidResult))?
                    .intersection(&pass.classes);
                if !classes.is_empty() {
                    let receipt = result
                        .model_receipt(meeting.value(), &classes)
                        .ok_or(IcfgTaintError::Findings(TaintFindingError::InvalidResult))?;
                    finding.merge_model_receipt(&receipt);
                }
            }
        }
        if let Some(receipt) = self
            .model_receipts
            .and_then(|inputs| inputs.sinks.get(&pass.sink))
        {
            finding.merge_model_receipt(receipt);
        }
        let authored = (self.baseline.is_proven_by_authored_summaries()
            && !pass.closures.is_empty())
        .then(|| pass.closures.clone());
        let result =
            self.baseline
                .result()
                .refined_pair_result(plan, self.baseline.is_complete(), authored);
        Ok(self
            .baseline
            .refined_pair(result, vec![finding], pass.unavailable))
    }

    /// Attribute every bound source on this session's frozen relations.
    pub fn attribute_sources(
        self,
        plan: &TaintAnalysisPlan,
        request: &mut DataflowRequest<'_>,
        attribution: &mut TaintAttributionBudget,
    ) -> Result<IcfgTaintOutcome, IcfgTaintError> {
        assert!(
            self.predicates.is_empty(),
            "ordinary attribution has no barrier predicates"
        );
        self.refine(plan, request, attribution, |_, _| {
            unreachable!("no predicate can request classification")
        })
    }

    /// Both passes use this session's first bounded graph and one classifier
    /// context supplied by the host. Neither pass can discover a new edge.
    pub fn refine(
        self,
        plan: &TaintAnalysisPlan,
        request: &mut DataflowRequest<'_>,
        attribution: &mut TaintAttributionBudget,
        mut classify: impl FnMut(
            &BarrierObservation,
            ValueTypePredicate,
        ) -> Result<ValueTypeBarrierDecision, Box<str>>,
    ) -> Result<IcfgTaintOutcome, IcfgTaintError> {
        if !self.baseline.belongs_to(plan) || plan.value_type_barriers() != &*self.predicates {
            return Err(IcfgTaintError::Findings(TaintFindingError::PlanMismatch));
        }
        if self.recorded.is_none() {
            let termination = self.baseline.result().termination();
            let cause = if termination.is_fixed_point() {
                IcfgTaintIncomplete::CoverageUnavailable
            } else {
                IcfgTaintIncomplete::Terminated(termination)
            };
            return Ok(IcfgTaintOutcome {
                report: self.baseline.with_open_source_coverage(),
                barrier_pairs: Vec::new(),
                barrier_notes: Vec::new(),
                source_coverage: Some(cause),
            });
        }
        if let Err(error) = self.remaining_bytes(0) {
            let cause = recoverable_stop(error)?;
            return Ok(IcfgTaintOutcome {
                report: self.baseline.with_open_source_coverage(),
                barrier_pairs: Vec::new(),
                barrier_notes: Vec::new(),
                source_coverage: Some(cause),
            });
        }
        if !self
            .baseline
            .result()
            .fact_result()
            .reached()
            .iter()
            .any(|row| {
                self.baseline
                    .result()
                    .fact_result()
                    .fact(row.fact())
                    .is_some_and(|fact| fact.sink().is_some())
            })
        {
            let source_coverage = self.baseline_stop();
            let report = if source_coverage.is_some() {
                self.baseline.with_open_source_coverage()
            } else {
                self.baseline
            };
            return Ok(IcfgTaintOutcome {
                source_coverage,
                report,
                barrier_pairs: Vec::new(),
                barrier_notes: Vec::new(),
            });
        }
        let predicates = &*self.predicates;
        let recorded = self
            .recorded
            .as_ref()
            .expect("candidate solve retained its relations");
        let supports = match FrozenSupports::new(&self, recorded, request) {
            Ok(supports) => supports,
            Err(error) => {
                let cause = recoverable_stop(error)?;
                return Ok(IcfgTaintOutcome {
                    report: self.baseline.with_open_source_coverage(),
                    barrier_pairs: Vec::new(),
                    barrier_notes: Vec::new(),
                    source_coverage: Some(cause),
                });
            }
        };
        let mut classification = Classification {
            check_name_bytes: 0,
            decisions: HashMap::default(),
            checks: Vec::new(),
            budget_note_ids: HashMap::default(),
            verified: HashSet::default(),
        };
        let mut barrier_pairs = Vec::new();
        let mut barrier_notes = Vec::new();
        let fallback_slots = if predicates.is_empty() {
            self.baseline.findings().len()
        } else {
            0
        };
        if let Err(error) = self.remaining_bytes(
            supports
                .retained_bytes
                .saturating_add(classification.owned_bytes())
                .saturating_add(fallback_slots.saturating_mul(std::mem::size_of::<TaintFinding>())),
        ) {
            return Ok(IcfgTaintOutcome {
                report: self.baseline.with_open_source_coverage(),
                barrier_pairs: Vec::new(),
                barrier_notes: Vec::new(),
                source_coverage: Some(recoverable_stop(error)?),
            });
        }
        let mut findings = Vec::with_capacity(fallback_slots);
        let mut finding_slots = 0usize;
        let mut limits = self.collection_limits;
        limits.max_witnesses = limits
            .max_witnesses
            .saturating_sub(self.baseline.retained_witnesses());
        limits.max_witness_steps = limits
            .max_witness_steps
            .saturating_sub(self.baseline.retained_witness_steps());
        limits.max_witness_expansions = limits
            .max_witness_expansions
            .saturating_sub(self.baseline.witness_expansions());
        limits.max_retained_witness_bytes = limits
            .max_retained_witness_bytes
            .saturating_sub(self.baseline.retained_witness_bytes());
        let attribution_start = attribution.work();
        let mut source_coverage = self.baseline_stop();
        let mut origins_by_sink: HashMap<ValueFlowSinkId, HashSet<super::SourceEventKey>> =
            HashMap::default();
        let processing = (|| -> Result<(), IcfgTaintError> {
            for source in plan.sources() {
                // Replay one class at a time, but publish one source/sink/meeting
                // aggregate. A later class replaces only this source's admitted
                // packet; an interrupted replacement leaves its prior prefix.
                let source_start = (findings.len(), barrier_pairs.len(), barrier_notes.len());
                let mut lenient_passes: Vec<PairPass> = Vec::new();
                let mut strict_accumulated: Vec<PairPass> = Vec::new();
                for class in source.classes().iter_dense() {
                    let mut source_class = plan.universe().empty_set();
                    source_class.insert_dense(class);
                    self.output_owned_bytes.set(output_owned_bytes(
                        self.baseline.result(),
                        &findings,
                        &barrier_pairs,
                        &barrier_notes,
                        &origins_by_sink,
                        &source_class,
                        &lenient_passes,
                        &strict_accumulated,
                        &[],
                    ));
                    self.remaining_bytes(
                        supports
                            .retained_bytes
                            .saturating_add(classification.owned_bytes()),
                    )?;
                    // A source whose only labels die before every candidate sink
                    // performs no native classification, even in a mixed batch.
                    let unfiltered = classification.solve(
                        &self,
                        recorded,
                        &supports,
                        plan,
                        source.source(),
                        &source_class,
                        &[],
                        &LenientValueTypeBarriers,
                        request,
                        &mut classify,
                    )?;
                    let has_candidate = unfiltered.states.iter().any(|state| {
                        let facts = self.baseline.result().fact_result();
                        let fact = *facts
                            .fact(facts.reached()[state.key.row].fact())
                            .expect("a frozen state has a fact");
                        fact.sink().is_some_and(|sink| {
                            !unfiltered.values[state.key.classes]
                                .intersection(
                                    plan.sink(sink).expect("a meeting names a sink").accepted(),
                                )
                                .is_empty()
                        })
                    });
                    if !has_candidate {
                        drop(unfiltered);
                        continue;
                    }
                    let replay = if predicates.is_empty() {
                        unfiltered
                    } else {
                        drop(unfiltered);
                        classification.solve(
                            &self,
                            recorded,
                            &supports,
                            plan,
                            source.source(),
                            &source_class,
                            predicates,
                            &LenientValueTypeBarriers,
                            request,
                            &mut classify,
                        )?
                    };
                    let (passes, stopped) = self.pair_passes(
                        &replay,
                        &classification.checks,
                        plan,
                        recorded,
                        source,
                        &source_class,
                        &mut limits,
                        request,
                        attribution,
                    )?;
                    drop(replay);
                    if let Some(stopped) = stopped {
                        source_coverage = Some(stopped);
                    }
                    let output_before_passes = self.output_owned_bytes.get();
                    self.output_owned_bytes
                        .set(output_before_passes.saturating_add(passes_owned_bytes(&passes)));
                    let strict_required = passes.iter().any(|pass| {
                        !pass.checks.ids.is_empty() || pass.checks.omitted || pass.unavailable
                    });
                    let strict_passes = if predicates.is_empty() {
                        Vec::new()
                    } else if !strict_required {
                        // These concrete paths encounter no check on which the
                        // strict evaluator could differ from the lenient one.
                        passes.clone()
                    } else if source_coverage.is_some() {
                        // A required evaluation that did not run proves nothing.
                        // Keep the lenient paths and their barrier notes below.
                        Vec::new()
                    } else {
                        match classification.solve(
                            &self,
                            recorded,
                            &supports,
                            plan,
                            source.source(),
                            &source_class,
                            predicates,
                            &StrictValueTypeBarriers,
                            request,
                            &mut classify,
                        ) {
                            Ok(replay) => {
                                let (strict, stopped) = self.pair_passes(
                                    &replay,
                                    &classification.checks,
                                    plan,
                                    recorded,
                                    source,
                                    &source_class,
                                    &mut limits,
                                    request,
                                    attribution,
                                )?;
                                if let Some(stopped) = stopped {
                                    source_coverage = Some(stopped);
                                }
                                // Only the prefix actually evaluated is strict evidence.
                                strict
                            }
                            Err(error) => {
                                source_coverage = Some(recoverable_stop(error)?);
                                Vec::new()
                            }
                        }
                    };
                    self.output_owned_bytes.set(output_before_passes);
                    merge_passes(&mut lenient_passes, passes);
                    merge_passes(&mut strict_accumulated, strict_passes);
                    self.output_owned_bytes.set(output_owned_bytes(
                        self.baseline.result(),
                        &findings,
                        &barrier_pairs,
                        &barrier_notes,
                        &origins_by_sink,
                        &source_class,
                        &lenient_passes,
                        &strict_accumulated,
                        &[],
                    ));
                    self.remaining_bytes(
                        supports
                            .retained_bytes
                            .saturating_add(classification.owned_bytes()),
                    )?;
                    for pass in &lenient_passes {
                        // Admit spare header slots before publishing a new pair, so
                        // a later stop can move baseline evidence without cloning it.
                        let wanted = findings
                            .len()
                            .saturating_add(fallback_slots)
                            .saturating_add(1);
                        let growth = wanted
                            .saturating_sub(findings.capacity())
                            .saturating_mul(std::mem::size_of::<TaintFinding>());
                        self.remaining_bytes(
                            supports
                                .retained_bytes
                                .saturating_add(classification.owned_bytes())
                                .saturating_add(growth),
                        )?;
                        findings.reserve_exact(fallback_slots.saturating_add(1));
                        self.output_owned_bytes.set(output_owned_bytes(
                            self.baseline.result(),
                            &findings,
                            &barrier_pairs,
                            &barrier_notes,
                            &origins_by_sink,
                            &source_class,
                            &lenient_passes,
                            &strict_accumulated,
                            &[],
                        ));
                        self.remaining_bytes(
                            supports
                                .retained_bytes
                                .saturating_add(classification.owned_bytes()),
                        )?;
                        let origins = origins_by_sink.entry(pass.sink).or_default();
                        if !origins.contains(source.origin()) && origins.len() == self.max_origins {
                            source_coverage = Some(IcfgTaintIncomplete::OriginLimit {
                                limit: self.max_origins,
                            });
                            return Ok(());
                        }
                        origins.insert(source.origin().clone());
                        let mut lenient = self.report_pair(plan, source, pass)?;
                        self.output_owned_bytes.set(output_owned_bytes(
                            self.baseline.result(),
                            &findings,
                            &barrier_pairs,
                            &barrier_notes,
                            &origins_by_sink,
                            &source_class,
                            &lenient_passes,
                            &strict_accumulated,
                            &[&lenient],
                        ));
                        self.remaining_bytes(
                            supports
                                .retained_bytes
                                .saturating_add(classification.owned_bytes()),
                        )?;
                        // Origins of one finding share its collection slot. Source
                        // qualification must not turn that slot into a per-origin cap.
                        let new_key = lenient
                            .findings()
                            .first()
                            .expect("a qualified pair has a finding")
                            .key();
                        let is_new_key = !findings.iter().any(|finding| finding.key() == new_key);
                        if is_new_key && finding_slots == self.collection_limits.max_findings {
                            source_coverage = Some(IcfgTaintIncomplete::FindingLimit {
                                limit: self.collection_limits.max_findings,
                            });
                            return Ok(());
                        }
                        let strict_pass = strict_accumulated.iter().find(|candidate| {
                            candidate.sink == pass.sink
                                && candidate.meeting.is_uncertain() == pass.meeting.is_uncertain()
                        });
                        let strict = strict_pass
                            .map(|pass| self.report_pair(plan, source, pass))
                            .transpose()?;
                        let pending = [&lenient, strict.as_ref().unwrap_or(&lenient)];
                        let pending = if strict.is_some() {
                            &pending[..]
                        } else {
                            &pending[..1]
                        };
                        self.output_owned_bytes.set(output_owned_bytes(
                            self.baseline.result(),
                            &findings,
                            &barrier_pairs,
                            &barrier_notes,
                            &origins_by_sink,
                            &source_class,
                            &lenient_passes,
                            &strict_accumulated,
                            pending,
                        ));
                        self.remaining_bytes(
                            supports
                                .retained_bytes
                                .saturating_add(classification.owned_bytes()),
                        )?;
                        let mut note = None;
                        // A strict alpha path does not discharge an unknown beta
                        // check in the same aggregate.
                        if !predicates.is_empty()
                            && pass.classes.iter_dense().any(|class| {
                                !strict_pass
                                    .is_some_and(|strict| strict.classes.contains_dense(class))
                            })
                        {
                            let mut checks = Vec::new();
                            let mut omitted = u64::from(pass.checks.omitted || pass.unavailable);
                            for &id in &pass.checks.ids {
                                let check = &classification.checks[id];
                                // Include all authored IDs that share a predicate, while
                                // reusing the native decision for that value and predicate.
                                for (name, predicate) in
                                    predicates.iter().filter(|(_, p)| *p == check.predicate)
                                {
                                    let mut check = check.clone();
                                    check.id = name.clone();
                                    check.predicate = *predicate;
                                    // Public projection applies the shared 16-KiB
                                    // byte bound after exact locations are rendered.
                                    if checks.len() < 64 {
                                        checks.push(check);
                                    } else {
                                        omitted += 1;
                                    }
                                }
                            }
                            if !checks.is_empty() || omitted != 0 {
                                note = Some(ValueTypeBarrierFindingNotes {
                                    source: source.origin().clone(),
                                    sink: plan
                                        .value_flow()
                                        .sink(pass.sink)
                                        .expect("a pair names a sink")
                                        .key()
                                        .clone(),
                                    checks,
                                    omitted_lower_bound: omitted,
                                });
                            }
                        }
                        let publication = if predicates.is_empty() {
                            let findings = lenient.take_findings();
                            drop(lenient);
                            drop(strict);
                            FindingPublication {
                                findings,
                                pair: None,
                                note,
                            }
                        } else {
                            FindingPublication {
                                findings: lenient.findings().into(),
                                pair: Some(ValueTypeBarrierPairEvidence { lenient, strict }),
                                note,
                            }
                        };
                        publish_findings(
                            &mut findings,
                            &mut barrier_pairs,
                            &mut barrier_notes,
                            source_start,
                            publication,
                            |findings, pairs, notes| {
                                self.output_owned_bytes.set(output_owned_bytes(
                                    self.baseline.result(),
                                    findings,
                                    pairs,
                                    notes,
                                    &origins_by_sink,
                                    &source_class,
                                    &lenient_passes,
                                    &strict_accumulated,
                                    &[],
                                ));
                                self.remaining_bytes(
                                    supports
                                        .retained_bytes
                                        .saturating_add(classification.owned_bytes()),
                                )
                                .map(|_| ())
                            },
                        )?;
                        finding_slots += usize::from(is_new_key);
                        if pass.unavailable && source_coverage.is_none() {
                            source_coverage = Some(IcfgTaintIncomplete::WitnessLimit(
                                TaintWitnessTruncationCause::CollectionBudget,
                            ));
                        }
                    }
                    self.output_owned_bytes.set(output_owned_bytes(
                        self.baseline.result(),
                        &findings,
                        &barrier_pairs,
                        &barrier_notes,
                        &origins_by_sink,
                        &source_class,
                        &lenient_passes,
                        &strict_accumulated,
                        &[],
                    ));
                    self.remaining_bytes(
                        supports
                            .retained_bytes
                            .saturating_add(classification.owned_bytes()),
                    )?;
                    if source_coverage.is_some() {
                        return Ok(());
                    }
                }
            }
            Ok(())
        })();
        if let Err(error) = processing {
            source_coverage = Some(recoverable_stop(error)?);
        }
        let incomplete = source_coverage.is_some()
            || findings
                .iter()
                .any(|finding| finding.origins().witness_unavailable());
        let added_work = attribution.work().since(attribution_start);
        drop(classification);
        drop(supports);
        drop(self.recorded);
        drop(self.meeting_values);
        let retain_baseline = source_coverage.is_some() && self.predicates.is_empty();
        let mut baseline = self.baseline;
        if retain_baseline {
            // All replay, support and classifier owners have ended. Spare header
            // slots were admitted above; transfer existing evidence without a clone.
            let original = baseline.take_findings();
            for finding in Vec::from(original) {
                if !finding.origins().evidence().is_empty() && !findings.contains(&finding) {
                    assert!(
                        findings.len() < findings.capacity(),
                        "baseline transfer uses reserved slots"
                    );
                    findings.push(finding);
                }
            }
        }
        let mut report = baseline.into_refined_findings(findings, incomplete);
        report.add_attribution_work(added_work);
        Ok(IcfgTaintOutcome {
            report,
            barrier_pairs,
            barrier_notes,
            source_coverage,
        })
    }
}

struct FindingPublication {
    findings: Box<[TaintFinding]>,
    pair: Option<ValueTypeBarrierPairEvidence>,
    note: Option<ValueTypeBarrierFindingNotes>,
}

fn publish_findings(
    findings: &mut Vec<TaintFinding>,
    pairs: &mut Vec<ValueTypeBarrierPairEvidence>,
    notes: &mut Vec<ValueTypeBarrierFindingNotes>,
    source_start: (usize, usize, usize),
    mut publication: FindingPublication,
    admit: impl FnOnce(
        &Vec<TaintFinding>,
        &Vec<ValueTypeBarrierPairEvidence>,
        &Vec<ValueTypeBarrierFindingNotes>,
    ) -> Result<(), IcfgTaintError>,
) -> Result<(), IcfgTaintError> {
    assert_eq!(
        publication.findings.len(),
        1,
        "one qualified meeting packet"
    );
    let key = publication.findings[0].key();
    let finding_index = findings[source_start.0..]
        .iter()
        .position(|finding| finding.key() == key)
        .map(|index| index + source_start.0);
    let pair_index = publication.pair.as_ref().and_then(|_| {
        pairs[source_start.1..]
            .iter()
            .position(|pair| pair.lenient.findings()[0].key() == key)
            .map(|index| index + source_start.1)
    });
    let note_index = publication.note.as_ref().and_then(|note| {
        notes[source_start.2..]
            .iter()
            .position(|old| old.source == note.source && old.sink == note.sink)
            .map(|index| index + source_start.2)
    });
    if let Some(index) = note_index {
        let old = &notes[index];
        let note = publication.note.as_mut().expect("replacement has notes");
        let mut omitted = 0;
        for check in &old.checks {
            if !note.checks.contains(check) {
                if note.checks.len() < 64 {
                    note.checks.push(check.clone());
                } else {
                    omitted += 1;
                }
            }
        }
        // The old and new omitted sets can overlap; summing them would invent
        // a lower bound. Retain the strongest independently established bound.
        note.omitted_lower_bound = note
            .omitted_lower_bound
            .max(old.omitted_lower_bound)
            .max(omitted);
    }
    let previous = (findings.len(), pairs.len(), notes.len());
    findings.extend(Vec::from(publication.findings));
    pairs.extend(publication.pair);
    notes.extend(publication.note);
    if let Err(error) = admit(findings, pairs, notes) {
        findings.truncate(previous.0);
        pairs.truncate(previous.1);
        notes.truncate(previous.2);
        // Pair/note growth was not admitted. Discard its spare headers too.
        // Finding headers were admitted before staging, including fallback slots.
        *pairs = std::mem::take(pairs).into_boxed_slice().into_vec();
        *notes = std::mem::take(notes).into_boxed_slice().into_vec();
        return Err(error);
    }
    // Admission counted BOTH the previous packet and its complete replacement,
    // including shared witness owners. Only now may the old values be dropped.
    if let Some(index) = finding_index {
        let replacement = findings.pop().expect("staged finding");
        findings[index] = replacement;
    }
    if let Some(index) = pair_index {
        let replacement = pairs.pop().expect("staged pair");
        pairs[index] = replacement;
    }
    if let Some(index) = note_index {
        let replacement = notes.pop().expect("staged note");
        notes[index] = replacement;
    }
    Ok(())
}

fn merge_passes(target: &mut Vec<PairPass>, incoming: Vec<PairPass>) {
    for mut pass in incoming {
        if let Some(existing) = target.iter_mut().find(|candidate| {
            candidate.sink == pass.sink
                && candidate.meeting.is_uncertain() == pass.meeting.is_uncertain()
        }) {
            existing.classes.union_with(&pass.classes);
            existing.contributed.union_with(&pass.contributed);
            for quality in pass.qualities.iter() {
                existing.qualities.insert(quality);
            }
            existing.witnesses.append(&mut pass.witnesses);
            existing.checks.extend(&pass.checks);
            for closure in pass.closures {
                if !existing.closures.contains(&closure) {
                    existing.closures.push(closure);
                }
            }
            existing.certain |= pass.certain;
            existing.unavailable |= pass.unavailable;
        } else {
            target.push(pass);
        }
    }
}

fn recoverable_stop(error: IcfgTaintError) -> Result<IcfgTaintIncomplete, IcfgTaintError> {
    match error {
        IcfgTaintError::Terminated(termination) => Ok(IcfgTaintIncomplete::Terminated(termination)),
        IcfgTaintError::RetentionBudget { limit, attempted } => {
            Ok(IcfgTaintIncomplete::RetentionBudget { limit, attempted })
        }
        error => Err(error),
    }
}

/// Borrowed census of the live output owners; this creates no budget or authority.
#[allow(clippy::too_many_arguments)]
fn output_owned_bytes(
    baseline: &TaintSummaryResult,
    findings: &Vec<TaintFinding>,
    pairs: &Vec<ValueTypeBarrierPairEvidence>,
    notes: &Vec<ValueTypeBarrierFindingNotes>,
    origins: &HashMap<ValueFlowSinkId, HashSet<super::SourceEventKey>>,
    source_class: &TaintClassSet,
    lenient: &Vec<PairPass>,
    strict: &Vec<PairPass>,
    pending: &[&TaintFindingReport],
) -> usize {
    let mut heap = RetainedHeap::default();
    // The session fixed census already charges this owner. Seed its identity
    // here so pair reports share the charge while the baseline remains live.
    baseline.fact_result().retained_facts_heap(&mut heap);
    let shared_facts = heap.bytes();
    heap.add(source_class.retained_heap_bytes());
    retain_passes(lenient, &mut heap);
    retain_passes(strict, &mut heap);
    heap.vec(findings);
    for finding in findings {
        finding.retained_heap(&mut heap);
    }
    for report in pending {
        report.retained_heap(&mut heap);
    }
    heap.vec(pairs);
    for pair in pairs {
        pair.lenient.retained_heap(&mut heap);
        if let Some(strict) = &pair.strict {
            strict.retained_heap(&mut heap);
        }
    }
    heap.vec(notes);
    for note in notes {
        heap.add(
            note.source
                .value_flow_key()
                .retained_bytes()
                .saturating_add(note.sink.retained_bytes()),
        );
        heap.vec(&note.checks);
        for check in &note.checks {
            heap.add(check.id.len());
        }
    }
    heap.map(origins);
    for sources in origins.values() {
        heap.hash_set(sources);
        for source in sources {
            heap.add(source.value_flow_key().retained_bytes());
        }
    }
    heap.total().saturating_sub(shared_facts)
}

#[cfg(test)]
mod receipt_projection_tests {
    use super::*;

    fn source_with_two_call_sinks() -> (
        crate::inline_project::BuiltInlineTestProject,
        crate::analyzer::WorkspaceAnalyzer,
        TaintAnalysisPlan,
        SemanticBudget,
        crate::analyzer::semantic::CancellationToken,
    ) {
        use crate::analyzer::semantic::{CancellationToken, ProcedurePortHandle, SemanticRequest};
        use crate::analyzer::{AnalyzerConfig, Language};
        use crate::dataflow::UnmodeledCallBehavior;
        use crate::inline_project::InlineTestProject;
        use crate::taint::{
            SourceClassId, SourceEventKey, TaintSinkBinding, TaintSourceBinding, TaintUniverse,
        };
        use crate::value_flow::{
            ClosureLimits, ValueFlowPlan, ValueFlowSinkSpec, ValueFlowSourceSpec, discover_closure,
        };
        let project = InlineTestProject::with_language(Language::Rust)
            .file(
                "lib.rs",
                "fn sink(_: u8) {} pub fn root(source: u8) { sink(source); sink(source); }",
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut semantic = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &project.file("lib.rs"),
                &mut SemanticRequest::new(&mut semantic, &cancellation),
            )
            .unwrap()
            .available_value()
            .cloned()
            .unwrap();
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("root")
            })
            .unwrap();
        let root = artifact.procedure_handle(procedure.id()).unwrap();
        let closure = discover_closure(
            &workspace,
            &root,
            ClosureLimits { max_procedures: 32 },
            &mut semantic,
            &cancellation,
        )
        .unwrap();
        assert!(!closure.truncated);
        assert_eq!(root.semantics().call_sites().len(), 2);
        let entry = root.point_handle(root.semantics().entry_point()).unwrap();
        let source = ValueFlowSourceSpec::at_point(
            &entry,
            0,
            ValueFlowCarrier::Port(ProcedurePortHandle::parameter(root.clone(), 0).unwrap()),
        )
        .unwrap();
        let sinks = root
            .semantics()
            .call_sites()
            .iter()
            .map(|call| {
                assert_eq!(call.arguments.len(), 1);
                ValueFlowSinkSpec::at_point(
                    &root.point_handle(call.point).unwrap(),
                    0,
                    ValueFlowCarrier::for_value(
                        root.value_handle(call.arguments[0].value).unwrap(),
                    ),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let flow = ValueFlowPlan::with_call_behavior(
            root.clone(),
            closure.snapshots,
            closure.bindings,
            vec![source],
            sinks,
            UnmodeledCallBehavior::default(),
        )
        .unwrap();
        let universe = TaintUniverse::new(vec![SourceClassId::new("remote").unwrap()]).unwrap();
        let classes = universe.class_set(universe.classes()).unwrap();
        let sources = flow
            .sources()
            .map(|(id, spec)| {
                TaintSourceBinding::new(
                    id,
                    classes.clone(),
                    SourceEventKey::new(spec.key().clone()),
                )
            })
            .collect();
        let sinks = flow
            .sinks()
            .map(|(id, _)| TaintSinkBinding::new(id, classes.clone()))
            .collect();
        let plan = TaintAnalysisPlan::new(flow, universe, sources, sinks, vec![], vec![]).unwrap();
        assert_eq!(plan.sources().len(), 1);
        assert_eq!(plan.sinks().len(), 2);
        (project, workspace, plan, semantic, cancellation)
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9925: pending callback alternatives escaped retained-byte admission"
    )]
    fn pending_callback_alternatives_require_admission_before_classification() {
        use crate::analyzer::Language;
        use crate::analyzer::semantic::{
            SemanticRequest, evaluate_value_type_barrier, open_value_type_barrier_context,
        };
        use crate::dataflow::{SolverBudget, WitnessReconstructionLimits};

        let (_project, workspace, plan, mut semantic, cancellation) = source_with_two_call_sinks();
        // The authored fixture uses u8, so the native Boolean classifier can
        // truthfully retain its route. No model or guessed proof is installed.
        let plan = plan.with_value_type_barriers(vec![(
            "test.boolean".into(),
            ValueTypePredicate::IntrinsicBool,
        )]);
        let mut solver = SolverBudget::default();
        let mut attribution = TaintAttributionBudget::new(1_000_000, 1_000_000);
        let mut session = IcfgTaintSession::discover(
            plan.value_flow().root(),
            &workspace.icfg_provider(),
            &plan,
            WitnessRetentionLimits::new(64).unwrap(),
            &mut semantic,
            &mut DataflowRequest::new(&mut solver, &cancellation),
            16,
            WitnessReconstructionLimits::new(100_000, 100_000).unwrap(),
            TaintFindingCollectionLimits::new(128, 128, 100_000, 100_000, 10_000_000).unwrap(),
            &mut attribution,
        )
        .unwrap();
        let context =
            open_value_type_barrier_context(Language::Rust, workspace.analyzer(), &cancellation)
                .unwrap()
                .expect("Rust native barrier context");
        let mut classify_native = |observation: &BarrierObservation, predicate| {
            evaluate_value_type_barrier(
                Language::Rust,
                workspace.analyzer(),
                observation,
                predicate,
                &mut SemanticRequest::new(&mut semantic, &cancellation)
                    .with_value_type_barrier_context(context.as_ref()),
            )
            .map_err(|error| error.to_string().into_boxed_str())
        };
        let recorded = session.recorded.as_ref().expect("real captured solve");
        let source = &plan.sources()[0];
        let clone_classification = |known: &Classification| Classification {
            check_name_bytes: known.check_name_bytes,
            decisions: known.decisions.clone(),
            checks: known.checks.clone(),
            budget_note_ids: known.budget_note_ids.clone(),
            verified: known.verified.clone(),
        };
        let mut selected = None;
        for (record, row) in recorded.trace().records.iter().enumerate() {
            if row.key.edge.kind != IcfgEdgeKind::Call
                || row.key.input.carrier().is_none()
                || !row
                    .outputs
                    .iter()
                    .any(|output| output.fact.sink().is_some())
            {
                continue;
            }
            let Some(value) = session
                .baseline
                .result()
                .point_values()
                .iter()
                .find(|value| {
                    value.point() == &row.key.edge.source
                        && session.baseline.result().fact_result().fact(value.fact())
                            == Some(&row.key.input)
                })
            else {
                continue;
            };
            let input = session
                .baseline
                .result()
                .value(value.value())
                .unwrap()
                .clone();
            if input.is_empty() {
                continue;
            }
            let mut known = Classification {
                check_name_bytes: 0,
                decisions: HashMap::default(),
                checks: Vec::new(),
                budget_note_ids: HashMap::default(),
                verified: HashSet::default(),
            };
            // Populate the real observation cache through the production path.
            let complete = known
                .evaluate(
                    &session,
                    0,
                    recorded,
                    record,
                    &plan,
                    source.source(),
                    source.classes(),
                    &input,
                    plan.value_type_barriers(),
                    &LenientValueTypeBarriers,
                    &mut DataflowRequest::new(&mut solver, &cancellation),
                    &mut classify_native,
                )
                .unwrap();
            if complete.is_empty() {
                continue;
            }
            drop(complete);
            for key in known.decisions.keys().cloned().collect::<Vec<_>>() {
                // Leave one REAL callee observation unanswered while preserving
                // its previously observed caller decisions, as a partial cache.
                if key.0.point().procedure() == plan.value_flow().root() {
                    continue;
                }
                let mut partial = clone_classification(&known);
                partial.decisions.remove(&key);
                let attempt = partial.transfer(
                    recorded,
                    record,
                    &plan,
                    source.source(),
                    source.classes(),
                    &input,
                    plan.value_type_barriers(),
                    &LenientValueTypeBarriers,
                    &mut DataflowRequest::new(&mut solver, &cancellation),
                );
                if attempt.pending.is_some() && !attempt.alternatives.is_empty() {
                    selected = Some((record, input.clone(), partial, attempt));
                    break;
                }
            }
            if selected.is_some() {
                break;
            }
        }
        let (record, input, mut classification, attempt) = selected
            .expect("real call emits a caller meeting while its callee observation is pending");
        assert!(attempt.pending.is_some());
        assert!(!attempt.alternatives.is_empty());
        let packet_bytes = alternatives_owned_bytes(&attempt.alternatives);
        assert!(packet_bytes > 0);
        let ample_limit = session.max_refinement_bytes;
        let base_bytes = session
            .fixed_owned_bytes
            .saturating_add(session.output_owned_bytes.get())
            .saturating_add(classification.owned_bytes());
        let refused_limit = base_bytes.saturating_add(packet_bytes).saturating_sub(1);
        assert!(
            base_bytes <= refused_limit && refused_limit < ample_limit,
            "fixture has a fitting baseline and an independently owned packet"
        );
        drop(attempt);
        session.max_refinement_bytes = refused_limit;
        let mut refused_calls = 0;
        let mut refused_solver = SolverBudget::default();
        let error = classification
            .evaluate(
                &session,
                0,
                session.recorded.as_ref().unwrap(),
                record,
                &plan,
                source.source(),
                source.classes(),
                &input,
                plan.value_type_barriers(),
                &LenientValueTypeBarriers,
                &mut DataflowRequest::new(&mut refused_solver, &cancellation),
                &mut |_, _| {
                    refused_calls += 1;
                    panic!("unfunded callback owner reached classifier")
                },
            )
            .err()
            .expect("unfunded packet must be refused");
        assert!(
            matches!(error, IcfgTaintError::RetentionBudget { .. }),
            "{error:?}"
        );
        assert_eq!(refused_calls, 0);
        assert!(
            refused_solver.used().flow_evaluations > 0,
            "performed transfer work survives retention refusal"
        );

        // SAME pending observation and captured transfer, with only the grant restored.
        session.max_refinement_bytes = ample_limit;
        let mut control_calls = 0;
        let mut control_solver = SolverBudget::default();
        let control = classification
            .evaluate(
                &session,
                0,
                session.recorded.as_ref().unwrap(),
                record,
                &plan,
                source.source(),
                source.classes(),
                &input,
                plan.value_type_barriers(),
                &LenientValueTypeBarriers,
                &mut DataflowRequest::new(&mut control_solver, &cancellation),
                &mut |observation, predicate| {
                    control_calls += 1;
                    classify_native(observation, predicate)
                },
            )
            .unwrap();
        assert!(
            control_calls > 0,
            "ample grant actually reaches the native classifier"
        );
        assert!(!control.is_empty(), "the real captured route continues");
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9925: qualified pairs lost model receipts when the baseline display cap omitted their sink"
    )]
    fn clipped_baseline_sink_retains_its_model_receipt_in_qualified_pair() {
        use crate::dataflow::{SolverBudget, WitnessReconstructionLimits};
        use crate::model_attribution::{
            ModelContributor, ModelContributorRole, ModelReceipt, SUMMARY_RECEIPT_CAP,
            TaintModelReceiptInputs, model_receipt_from_full,
        };

        let (_project, workspace, plan, mut semantic, cancellation) = source_with_two_call_sinks();
        let root = plan.value_flow().root().clone();
        let mut receipts = TaintModelReceiptInputs::default();
        for sink in plan.sinks() {
            let receipt = model_receipt_from_full(
                vec![ModelContributor {
                    role: ModelContributorRole::Sink,
                    pack_digest: "a".repeat(64),
                    record_id: format!("sink-{}", sink.sink().index()),
                    built_from: "0.4.23".into(),
                    resolved: "0.4.25".into(),
                    direction: "older_artifact".into(),
                    mismatch_kinds: vec!["version_nearby".into()],
                    selection_rule_id: "cargo-compatible-nearest".into(),
                    selection_rule_version: 1,
                }],
                SUMMARY_RECEIPT_CAP,
            );
            assert_ne!(receipt, ModelReceipt::default());
            assert!(receipts.sinks.insert(sink.sink(), receipt).is_none());
        }
        assert_ne!(
            receipts.sinks[&plan.sinks()[0].sink()],
            receipts.sinks[&plan.sinks()[1].sink()]
        );
        let collection =
            TaintFindingCollectionLimits::new(1, 32, 100_000, 100_000, 10_000_000).unwrap();
        let witnesses = WitnessReconstructionLimits::new(100_000, 100_000).unwrap();
        let provider = workspace.icfg_provider();
        let mut solver = SolverBudget::default();
        let mut request = DataflowRequest::new(&mut solver, &cancellation);
        // One attribution ledger for discovery AND the later qualified pass.
        let mut attribution = TaintAttributionBudget::new(1_000_000, 1_000_000);
        let session = IcfgTaintSession::discover_with_model_receipts(
            &root,
            &provider,
            &plan,
            &receipts,
            WitnessRetentionLimits::new(64).unwrap(),
            &mut semantic,
            &mut request,
            16,
            witnesses,
            collection,
            &mut attribution,
        )
        .unwrap();
        assert_eq!(session.baseline.findings().len(), 1);
        let omitted = session.baseline.omitted_findings_lower_bound();
        assert!(omitted > 0);
        assert!(!session.baseline.is_complete());
        // Choose from ACTUAL baseline output, not dense IDs or enumeration order.
        let displayed = session.baseline.findings()[0].sink();
        let clipped = plan
            .sinks()
            .iter()
            .map(|sink| sink.sink())
            .find(|sink| *sink != displayed)
            .unwrap();
        assert!(
            !session
                .baseline
                .findings()
                .iter()
                .any(|finding| finding.sink() == clipped)
        );
        let expected = &receipts.sinks[&clipped];
        let recorded = session
            .recorded
            .as_ref()
            .expect("real first solve retained relations");
        let supports = FrozenSupports::new(&session, recorded, &mut request).unwrap();
        let mut classification = Classification {
            check_name_bytes: 0,
            decisions: HashMap::default(),
            checks: Vec::new(),
            budget_note_ids: HashMap::default(),
            verified: HashSet::default(),
        };
        let source = &plan.sources()[0];
        let replay = classification
            .solve(
                &session,
                recorded,
                &supports,
                &plan,
                source.source(),
                source.classes(),
                &[],
                &LenientValueTypeBarriers,
                &mut request,
                &mut |_, _| -> Result<ValueTypeBarrierDecision, Box<str>> {
                    panic!("an unfiltered replay has no barrier classifier")
                },
            )
            .unwrap();
        // Keep the ORIGINAL cap-one collection limits. This private boundary
        // enumerates qualified supports; it does not select public display rows.
        let mut pair_limits = session.collection_limits;
        assert_eq!(pair_limits.max_findings, 1);
        let (passes, stopped) = session
            .pair_passes(
                &replay,
                &classification.checks,
                &plan,
                recorded,
                source,
                source.classes(),
                &mut pair_limits,
                &mut request,
                &mut attribution,
            )
            .unwrap();
        assert!(
            stopped.is_none(),
            "adequate shared witness allowance: {stopped:?}"
        );
        let pass = passes
            .iter()
            .find(|pass| pass.sink == clipped)
            .expect("the clipped sink has a real source-qualified frozen meeting");
        assert!(!pass.witnesses.is_empty());
        assert!(
            pass.witnesses
                .iter()
                .all(|witness| !witness.steps().is_empty())
        );
        let pair = session.report_pair(&plan, source, pass).unwrap();
        assert_eq!(pair.findings().len(), 1);
        let finding = &pair.findings()[0];
        assert_eq!(finding.sink(), clipped);
        assert_eq!(
            finding.origins().origins(),
            std::slice::from_ref(source.origin())
        );
        assert!(!finding.origins().evidence().is_empty());
        for evidence in finding.origins().evidence() {
            assert_eq!(evidence.origin(), source.origin());
            assert!(!evidence.witnesses().is_empty());
            assert!(evidence.witnesses().iter().all(|witness| {
                !witness.steps().is_empty() && witness.steps()[0].source().procedure() == &root
            }));
        }
        // Old baseline.findings().find(sink) cannot supply this clipped receipt.
        // Compare the full exact metadata, not just an approximation marker.
        assert_ne!(finding.model_receipt(), &ModelReceipt::default());
        assert_eq!(finding.model_receipt(), expected);
        assert!(finding.model_receipt().approximate_contributed);
        assert_eq!(finding.model_receipt().contributors, expected.contributors);
        assert!(!pair.is_complete());
        assert_eq!(pair.omitted_findings_lower_bound(), omitted);
        assert_eq!(session.collection_limits.max_findings, 1);

        // A last publication can exceed the live allowance even after replay
        // succeeds. Refuse that packet, not the previously admitted positive.
        let mut published = session.baseline.findings().to_vec();
        published.reserve_exact(pair.findings().len());
        let earlier = published.clone();
        let mut pairs = Vec::new();
        let mut notes = Vec::new();
        let owned = |findings: &Vec<TaintFinding>,
                     pairs: &Vec<ValueTypeBarrierPairEvidence>,
                     notes: &Vec<ValueTypeBarrierFindingNotes>| {
            let mut heap = RetainedHeap::default();
            heap.vec(findings);
            for finding in findings {
                finding.retained_heap(&mut heap);
            }
            heap.vec(pairs);
            for pair in pairs {
                pair.lenient.retained_heap(&mut heap);
                if let Some(strict) = &pair.strict {
                    strict.retained_heap(&mut heap);
                }
            }
            heap.vec(notes);
            heap.total()
        };
        let admitted = owned(&published, &pairs, &notes);
        let replacement_pair = pair.clone();
        let refused = publish_findings(
            &mut published,
            &mut pairs,
            &mut notes,
            (0, 0, 0),
            FindingPublication {
                findings: pair.findings().into(),
                pair: Some(ValueTypeBarrierPairEvidence {
                    lenient: pair,
                    strict: None,
                }),
                note: None,
            },
            |findings, pairs, notes| {
                let attempted = owned(findings, pairs, notes);
                assert!(
                    attempted > admitted,
                    "the actual new packet owns additional memory"
                );
                Err(IcfgTaintError::RetentionBudget {
                    limit: admitted,
                    attempted,
                })
            },
        );
        assert!(matches!(recoverable_stop(refused.unwrap_err()).unwrap(),
            IcfgTaintIncomplete::RetentionBudget { limit, attempted }
                if limit == admitted && attempted > admitted));
        assert_eq!(published, earlier);
        assert!(pairs.is_empty() && notes.is_empty());
        assert!(owned(&published, &pairs, &notes) <= admitted);

        // A class update stages the same semantic key while its previous
        // finding AND pair remain owned. A refused update must restore both.
        let mut published = replacement_pair.findings().to_vec();
        let earlier = published.clone();
        let mut pairs = vec![ValueTypeBarrierPairEvidence {
            lenient: replacement_pair.clone(),
            strict: None,
        }];
        let admitted = owned(&published, &pairs, &notes);
        let refused = publish_findings(
            &mut published,
            &mut pairs,
            &mut notes,
            (0, 0, 0),
            FindingPublication {
                findings: replacement_pair.findings().into(),
                pair: Some(ValueTypeBarrierPairEvidence {
                    lenient: replacement_pair.clone(),
                    strict: None,
                }),
                note: None,
            },
            |findings, pairs, notes| {
                let attempted = owned(findings, pairs, notes);
                assert!(attempted > admitted, "old and staged packets both count");
                Err(IcfgTaintError::RetentionBudget {
                    limit: admitted,
                    attempted,
                })
            },
        );
        assert!(matches!(
            refused,
            Err(IcfgTaintError::RetentionBudget { .. })
        ));
        assert_eq!(published, earlier);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].lenient, replacement_pair);
        assert!(pairs[0].strict.is_none() && notes.is_empty());

        publish_findings(
            &mut published,
            &mut pairs,
            &mut notes,
            (0, 0, 0),
            FindingPublication {
                findings: replacement_pair.findings().into(),
                pair: Some(ValueTypeBarrierPairEvidence {
                    lenient: replacement_pair.clone(),
                    strict: None,
                }),
                note: None,
            },
            |_, _, _| Ok(()),
        )
        .unwrap();
        assert_eq!(published, earlier);
        assert_eq!(pairs.len(), 1, "replacement cannot append a class fragment");
        assert_eq!(pairs[0].lenient, replacement_pair);
    }
}
