//! Request-owned refinement of the first forward IDE solve. Symbolic discovery
//! never calls a classifier. Local alternatives are reconstructed from the plan
//! and may emit only an output recorded for the exact original transfer key.

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

use super::client::{TaintFlowProblem, TaintObservationHook};
use super::compose::{
    ValueTypeBarrierCheck, ValueTypeBarrierFindingNotes, ValueTypeBarrierPairEvidence,
};
use super::{
    TaintAnalysisPlan, TaintClassSet, TaintEdgeFunction, TaintFact, TaintFinding,
    TaintFindingCollectionLimits, TaintFindingError, TaintFindingReport,
    TaintOriginFindingEvidence, TaintOriginStatus, TaintSolveError, TaintSummaryResult,
    collect_taint_findings_with_limits,
};

/// Classifier failures propagate outside discovery's infallible callbacks.
#[derive(Debug)]
pub enum IcfgBarrierError {
    Solve(TaintSolveError),
    Findings(TaintFindingError),
    Provider(Box<str>),
    Terminated(SolverTermination),
    RetentionBudget { limit: usize, attempted: usize },
}

impl std::fmt::Display for IcfgBarrierError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Solve(e) => e.fmt(f),
            Self::Findings(e) => e.fmt(f),
            Self::Provider(e) => f.write_str(e),
            Self::Terminated(e) => write!(f, "ICFG barrier refinement stopped: {e:?}"),
            Self::RetentionBudget { limit, attempted } => write!(
                f,
                "ICFG barrier refinement retained-byte budget exceeded: attempted {attempted}, limit {limit}"
            ),
        }
    }
}
impl std::error::Error for IcfgBarrierError {
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
pub struct IcfgBarrierSession {
    predicates: Box<[(Box<str>, ValueTypePredicate)]>,
    baseline: TaintFindingReport,
    collection_limits: TaintFindingCollectionLimits,
    max_refinement_bytes: usize,
    witness_limits: crate::dataflow::WitnessReconstructionLimits,
    recorded: Option<RecordedIdeRelations<TaintFact, TaintEdgeFunction>>,
}

impl IcfgBarrierSession {
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
    ) -> Result<Self, IcfgBarrierError> {
        if root != plan.value_flow().root() {
            return Err(IcfgBarrierError::Solve(TaintSolveError::RootMismatch));
        }
        let input = IdeSummarySolveInput::new(root, &[]).with_witness_retention(retention);
        let (result, recorded) = solve_ide_with_recorded_relations(
            input,
            provider,
            &TaintFlowProblem::new(plan),
            &mut NoReusableSummaries,
            plan.value_flow()
                .has_contextual_bindings()
                .then(OracleLimits::default),
            semantic,
            request,
        )
        .map_err(|e| IcfgBarrierError::Solve(TaintSolveError::from(e)))?;
        let result = TaintSummaryResult::from_result(plan, result);
        let baseline =
            collect_taint_findings_with_limits(plan, result, max_origins, witnesses, collection)
                .map_err(IcfgBarrierError::Findings)?;
        Ok(Self {
            predicates: plan.value_type_barriers().into(),
            baseline,
            recorded,
            collection_limits: collection,
            max_refinement_bytes: retention
                .best_effort_max_retained_bytes()
                .unwrap_or(collection.max_retained_witness_bytes),
            witness_limits: witnesses,
        })
    }
}

/// Per-pair evidence goes through the same public grouping and strict-witness
/// selection as composition. The baseline completion reasons are never reset.
pub struct IcfgBarrierOutcome {
    pub report: TaintFindingReport,
    pub barrier_pairs: Vec<ValueTypeBarrierPairEvidence>,
    pub barrier_notes: Vec<ValueTypeBarrierFindingNotes>,
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
    function: TaintEdgeFunction,
    checks: PathChecks,
}

struct CollectTransitions(Vec<(TaintFact, TaintEdgeFunction)>);
impl DataflowOutput<IdeTransition<TaintFact, TaintEdgeFunction>> for CollectTransitions {
    fn emit(&mut self, row: IdeTransition<TaintFact, TaintEdgeFunction>) -> bool {
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

fn reconstruct<Hook: TaintObservationHook>(
    problem: &TaintFlowProblem<'_, Hook>,
    key: &TransferKey<TaintFact>,
) -> Vec<(TaintFact, TaintEdgeFunction)> {
    let edge = descriptor(key);
    let mut out = CollectTransitions(Vec::new());
    match key.edge.kind {
        IcfgEdgeKind::Call => IdeDataflowProblem::call_flow(problem, edge, key.input, &mut out),
        IcfgEdgeKind::NormalReturn | IcfgEdgeKind::ExceptionalReturn => {
            IdeDataflowProblem::return_flow(problem, edge, key.input, &mut out)
        }
        IcfgEdgeKind::CallToNormalContinuation | IcfgEdgeKind::CallToExceptionalContinuation => {
            problem.call_to_return_flow(edge, key.input, &mut out)
        }
        _ => problem.normal_flow(edge, key.input, &mut out),
    }
    // IDE's distinguished zero is preserved independently of client transfers.
    if key.input.is_zero() {
        out.0
            .push((TaintFact::zero(), problem.identity_edge_function()));
    }
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
            function: function.clone(),
            checks: checks.clone(),
        });
    }
}

fn reserve(request: &mut DataflowRequest<'_>, work: SolverWork) -> Result<(), IcfgBarrierError> {
    if request.cancellation.is_cancelled() {
        return Err(IcfgBarrierError::Terminated(SolverTermination::Cancelled));
    }
    if let Some(termination) = request.reserve(work) {
        return Err(IcfgBarrierError::Terminated(termination));
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
        session: &IcfgBarrierSession,
        recorded: &RecordedIdeRelations<TaintFact, TaintEdgeFunction>,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Self, IcfgBarrierError> {
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
        let limit = session
            .max_refinement_bytes
            .saturating_sub(session.baseline.retained_witness_bytes());
        let mut retained_bytes = rows
            .len()
            .saturating_mul(1 + 4 * std::mem::size_of::<Vec<usize>>());
        let mut retain = |extra: usize| -> Result<(), IcfgBarrierError> {
            retained_bytes = retained_bytes.saturating_add(extra);
            if retained_bytes > limit {
                return Err(IcfgBarrierError::RetentionBudget {
                    limit,
                    attempted: retained_bytes,
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
        let mut chop = vec![false; rows.len()];
        for (row, reached) in rows.iter().enumerate() {
            if fact(row).sink().is_some_and(|sink| {
                session
                    .baseline
                    .findings()
                    .iter()
                    .any(|finding| finding.sink() == sink)
            }) {
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
        Ok(Self {
            direct_by_source,
            entries_by_source,
            matched_by_caller,
            matched_by_exit,
            direct,
            entries,
            matched,
            chop,
            retained_bytes,
        })
    }
}

struct Classification {
    decisions: HashMap<(BarrierObservation, ValueTypePredicate), usize>,
    checks: Vec<ValueTypeBarrierCheck>,
    // Stable note identities, not classification answers. Budget failures are
    // sampled again through the native context on the next transfer, whose
    // allowance may differ. Only that context owns budget-keyed failure memos.
    budget_note_ids: HashMap<(BarrierObservation, ValueTypePredicate), usize>,
    verified: HashSet<usize>,
}

impl Classification {
    #[allow(clippy::too_many_arguments)]
    fn transfer(
        &mut self,
        recorded: &RecordedIdeRelations<TaintFact, TaintEdgeFunction>,
        record: usize,
        plan: &TaintAnalysisPlan,
        source: ValueFlowSourceId,
        source_classes: &TaintClassSet,
        input: &TaintClassSet,
        predicates: &[(Box<str>, ValueTypePredicate)],
        filter: &dyn ValueTypeBarrierFilter,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Result<Vec<Alternative>, (BarrierObservation, ValueTypePredicate)>, IcfgBarrierError>
    {
        let trace = recorded.trace();
        let row = &trace.records[record];
        if cfg!(debug_assertions) && self.verified.insert(record) {
            let mut reconstructed: HashMap<_, TaintEdgeFunction> = HashMap::default();
            for (fact, function) in reconstruct(&TaintFlowProblem::new(plan), &row.key) {
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
                debug_assert_eq!(
                    reconstructed.get(&output.fact),
                    Some(&trace.functions[output.function]),
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
        let problem = TaintFlowProblem::with_observations(plan, &hook);
        reconstruct(&problem, &row.key);
        reserve(
            request,
            SolverWork {
                flow_evaluations: 1,
                edge_function_operations: hook.work.get(),
                callback_rows: hook.emitted.borrow().len(),
                ..SolverWork::default()
            },
        )?;
        if let Some(pending) = hook.pending.into_inner() {
            return Ok(Err(pending));
        }
        let mut alternatives = hook.emitted.into_inner();
        if row.key.input.is_zero() {
            alternatives.push(Alternative {
                fact: TaintFact::zero(),
                function: plan.identity().clone(),
                checks: PathChecks::default(),
            });
        }
        // No reconstructed output may add a fact to the first discovery.
        alternatives.retain(|alternative| {
            row.outputs
                .iter()
                .any(|output| output.fact == alternative.fact)
        });
        Ok(Ok(alternatives))
    }
}

impl Classification {
    #[allow(clippy::too_many_arguments)]
    fn evaluate(
        &mut self,
        recorded: &RecordedIdeRelations<TaintFact, TaintEdgeFunction>,
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
    ) -> Result<Vec<Alternative>, IcfgBarrierError> {
        let mut budget_keys = Vec::new();
        loop {
            match self.transfer(
                recorded, record, plan, source, classes, input, predicates, filter, request,
            )? {
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
                        classify(&observation, predicate).map_err(IcfgBarrierError::Provider)?;
                    if matches!(
                        decision,
                        ValueTypeBarrierDecision::Undecided(
                            crate::analyzer::semantic::ValueTypeBarrierReason::Cancelled
                        )
                    ) {
                        return Err(IcfgBarrierError::Terminated(SolverTermination::Cancelled));
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
                }
            }
        }
    }
}

#[derive(Clone)]
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

#[derive(Clone)]
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
    quality: PathQuality,
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
    retained_bytes: usize,
    max_retained_bytes: usize,
}

impl Replay {
    fn reserve_bytes(&mut self, extra: usize) -> Result<(), IcfgBarrierError> {
        let attempted = self.retained_bytes.saturating_add(extra);
        if attempted > self.max_retained_bytes {
            return Err(IcfgBarrierError::RetentionBudget {
                limit: self.max_retained_bytes,
                attempted,
            });
        }
        self.retained_bytes = attempted;
        Ok(())
    }

    fn value(
        &mut self,
        classes: TaintClassSet,
        request: &mut DataflowRequest<'_>,
    ) -> Result<usize, IcfgBarrierError> {
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
        self.value_ids.insert(classes.clone(), id);
        self.values.push(classes);
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
    ) -> Result<usize, IcfgBarrierError> {
        let classes = self.value(classes, request)?;
        let key = StateKey {
            row,
            entry,
            classes,
            quality,
        };
        if let Some(&id) = self.state_ids.get(&key) {
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
        self.by_row[row].push(id);
        self.states.push(State { key, derivation });
        self.queue.push_back(id);
        Ok(id)
    }

    fn entry(
        &mut self,
        row: usize,
        classes: TaintClassSet,
        request: &mut DataflowRequest<'_>,
    ) -> Result<usize, IcfgBarrierError> {
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
    ) -> Result<(), IcfgBarrierError> {
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
        self.incoming.push(IncomingPrefix {
            caller,
            entry,
            step,
        });
        Ok(())
    }

    fn prefix_qualities(
        &mut self,
        recorded: &RecordedIdeRelations<TaintFact, TaintEdgeFunction>,
        request: &mut DataflowRequest<'_>,
    ) -> Result<(), IcfgBarrierError> {
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
        while let Some((entry, quality)) = queue.pop_front() {
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
                if self.entries[row.entry].prefixes[quality.ordinal()].is_some() {
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
                    quality,
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
        session: &IcfgBarrierSession,
        recorded: &RecordedIdeRelations<TaintFact, TaintEdgeFunction>,
        limits: &mut TaintFindingCollectionLimits,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Option<(Arc<SummaryWitness>, PathChecks)>, IcfgBarrierError> {
        enum Frame {
            State(usize),
            Prefix(usize),
            Edge(AppliedTransfer),
        }
        let facts = session.baseline.result().fact_result();
        let mut stack = vec![Frame::State(state), Frame::Prefix(prefix)];
        let mut steps = Vec::new();
        let mut checks = PathChecks::default();
        let mut expansions = 0;
        while let Some(frame) = stack.pop() {
            reserve(
                request,
                SolverWork {
                    ide_propagations: 1,
                    ..SolverWork::default()
                },
            )?;
            if expansions
                == limits
                    .max_witness_expansions
                    .min(session.witness_limits.max_expansions())
                || steps.len()
                    == limits
                        .max_witness_steps
                        .min(session.witness_limits.max_steps())
            {
                return Ok(None);
            }
            expansions += 1;
            match frame {
                Frame::Prefix(id) => {
                    let prefix = &self.prefixes[id];
                    if let Some(incoming) = prefix.incoming {
                        let incoming = &self.incoming[incoming];
                        stack.push(Frame::Edge(incoming.step.clone()));
                        stack.push(Frame::State(incoming.caller));
                    }
                    if let Some(parent) = prefix.parent {
                        stack.push(Frame::Prefix(parent));
                    }
                }
                Frame::State(id) => match &self.states[id].derivation {
                    Derivation::Entry => {}
                    Derivation::Direct { predecessor, step } => {
                        stack.push(Frame::Edge(step.clone()));
                        stack.push(Frame::State(*predecessor));
                    }
                    Derivation::Matched {
                        caller,
                        callee,
                        call,
                        returned,
                    } => {
                        stack.push(Frame::Edge(returned.clone()));
                        stack.push(Frame::State(*callee));
                        stack.push(Frame::Edge(call.clone()));
                        stack.push(Frame::State(*caller));
                    }
                },
                Frame::Edge(step) => {
                    checks.extend(&step.checks);
                    let key = &recorded.trace().records[step.record].key;
                    let edge = &key.edge;
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
                        edge.source.clone(),
                        Some(edge.target.clone()),
                        edge.origin.clone(),
                        edge.boundary.clone(),
                        edge.proof.clone(),
                        edge.completeness.clone(),
                        FactId::try_from_index(input).expect("interned fact IDs fit"),
                        FactId::try_from_index(output).expect("interned fact IDs fit"),
                    ));
                }
            }
        }
        let retained = std::mem::size_of::<SummaryWitness>()
            .saturating_add(std::mem::size_of_val(steps.as_slice()));
        if limits.max_witnesses == 0 || retained > limits.max_retained_witness_bytes {
            return Ok(None);
        }
        limits.max_witnesses -= 1;
        limits.max_witness_steps -= steps.len();
        limits.max_witness_expansions -= expansions;
        limits.max_retained_witness_bytes -= retained;
        let count = steps.len();
        let quality = self.states[state]
            .key
            .quality
            .conjoin(self.prefixes[prefix].quality);
        Ok(Some((
            Arc::new(SummaryWitness::from_parts(
                steps,
                quality,
                None,
                0,
                false,
                retained,
                WitnessReconstructionWork::new(expansions, count),
            )),
            checks,
        )))
    }
}

impl Classification {
    #[allow(clippy::too_many_arguments)]
    fn solve(
        &mut self,
        session: &IcfgBarrierSession,
        recorded: &RecordedIdeRelations<TaintFact, TaintEdgeFunction>,
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
    ) -> Result<Replay, IcfgBarrierError> {
        let facts = session.baseline.result().fact_result();
        let rows = facts.reached();
        let graph = recorded.graph();
        let max_retained_bytes = session
            .max_refinement_bytes
            .saturating_sub(session.baseline.retained_witness_bytes())
            .saturating_sub(supports.retained_bytes);
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
            return Err(IcfgBarrierError::RetentionBudget {
                limit: max_retained_bytes,
                attempted: initial_bytes,
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
            retained_bytes: initial_bytes,
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
                    quality: PathQuality::PROVEN_COMPLETE,
                });
                replay.entries[entry].prefixes[PathQuality::PROVEN_COMPLETE.ordinal()] =
                    Some(prefix);
            }
        }
        while let Some(state) = replay.queue.pop_front() {
            reserve(
                request,
                SolverWork {
                    ide_propagations: 1,
                    ..SolverWork::default()
                },
            )?;
            let key = replay.states[state].key;
            let input = replay.values[key.classes].clone();
            for &id in &supports.direct_by_source[key.row] {
                let relation = supports.direct[id];
                let target = *facts
                    .fact(rows[relation.target].fact())
                    .expect("a frozen target has a fact");
                let alternatives = self.evaluate(
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
                for alternative in alternatives.into_iter().filter(|a| a.fact == target) {
                    reserve(
                        request,
                        SolverWork {
                            value_operations: 1,
                            ..SolverWork::default()
                        },
                    )?;
                    let output = alternative.function.apply(&input);
                    replay.publish(
                        relation.target,
                        key.entry,
                        output,
                        key.quality
                            .through_evidence(&edge.proof, &edge.completeness),
                        Derivation::Direct {
                            predecessor: state,
                            step: AppliedTransfer::new(relation.record, &alternative),
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
                for alternative in alternatives.into_iter().filter(|a| a.fact == target) {
                    reserve(
                        request,
                        SolverWork {
                            value_operations: 1,
                            ..SolverWork::default()
                        },
                    )?;
                    let entry = replay.entry(
                        relation.target,
                        alternative.function.apply(&input),
                        request,
                    )?;
                    replay.incoming(
                        state,
                        entry,
                        AppliedTransfer::new(relation.record, &alternative),
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
                for alternative in alternatives.into_iter().filter(|a| a.fact == target) {
                    reserve(
                        request,
                        SolverWork {
                            value_operations: 1,
                            ..SolverWork::default()
                        },
                    )?;
                    let entry =
                        replay.entry(entry_row, alternative.function.apply(&input), request)?;
                    if replay.waiting_ids.insert((id, state, entry)) {
                        let call = AppliedTransfer::new(relation.call, &alternative);
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
                        replay.waiting[id].push(waiting.clone());
                        for exit in replay.by_row[relation.exit].clone() {
                            if replay.states[exit].key.entry == entry {
                                self.apply_return(
                                    &mut replay,
                                    recorded,
                                    relation,
                                    exit,
                                    &waiting,
                                    session,
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
                for waiting in replay.waiting[id].clone() {
                    if waiting.entry == key.entry {
                        self.apply_return(
                            &mut replay,
                            recorded,
                            supports.matched[id],
                            state,
                            &waiting,
                            session,
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
        replay.prefix_qualities(recorded, request)?;
        Ok(replay)
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_return(
        &mut self,
        replay: &mut Replay,
        recorded: &RecordedIdeRelations<TaintFact, TaintEdgeFunction>,
        relation: Matched,
        exit: usize,
        waiting: &WaitingReturn,
        session: &IcfgBarrierSession,
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
    ) -> Result<(), IcfgBarrierError> {
        let input = replay.values[replay.states[exit].key.classes].clone();
        let target = *session
            .baseline
            .result()
            .fact_result()
            .fact(session.baseline.result().fact_result().reached()[relation.target].fact())
            .expect("a frozen return target has a fact");
        let alternatives = self.evaluate(
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
        for alternative in alternatives.into_iter().filter(|a| a.fact == target) {
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
                alternative.function.apply(&input),
                quality,
                Derivation::Matched {
                    caller: waiting.caller,
                    callee: exit,
                    call: waiting.call.clone(),
                    returned: AppliedTransfer::new(relation.returned, &alternative),
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
    classes: TaintClassSet,
    contributed: TaintClassSet,
    qualities: PathQualityFrontier,
    witnesses: Vec<Arc<SummaryWitness>>,
    checks: PathChecks,
    certain: bool,
    unavailable: bool,
    closures: Vec<crate::value_flow::AuthoredArmClosure>,
}

impl IcfgBarrierSession {
    #[allow(clippy::too_many_arguments)]
    fn pair_passes(
        &self,
        replay: &Replay,
        classification_checks: &[ValueTypeBarrierCheck],
        plan: &TaintAnalysisPlan,
        recorded: &RecordedIdeRelations<TaintFact, TaintEdgeFunction>,
        source: &super::TaintSourceBinding,
        source_class: &TaintClassSet,
        limits: &mut TaintFindingCollectionLimits,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Vec<PairPass>, IcfgBarrierError> {
        let facts = self.baseline.result().fact_result();
        let mut passes: Vec<PairPass> = Vec::new();
        // Keep a representative for each pair, payload and concrete quality.
        // Discovery and replay retain every support; duplicate meeting states
        // must not consume the witness budget and downgrade later pairs.
        let mut represented = HashSet::default();
        let mut unavailable = HashSet::default();
        for (state_id, state) in replay.states.iter().enumerate() {
            let fact = *facts
                .fact(facts.reached()[state.key.row].fact())
                .expect("a frozen state has a fact");
            let Some(sink) = fact.sink() else {
                continue;
            };
            if !self
                .baseline
                .findings()
                .iter()
                .any(|finding| finding.sink() == sink)
            {
                continue;
            }
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
                if represented.contains(&(sink, state.key.classes, quality)) {
                    continue;
                }
                let prefix = candidates
                    .iter()
                    .find(|(candidate, _)| *candidate == quality)
                    .expect("a retained quality has a concrete prefix")
                    .1;
                let witness = replay.witness(state_id, prefix, self, recorded, limits, request)?;
                let position = passes
                    .iter()
                    .position(|pass| pass.sink == sink)
                    .unwrap_or_else(|| {
                        passes.push(PairPass {
                            sink,
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
                    represented.insert((sink, state.key.classes, quality));
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
                        pass.certain = true;
                        for closure in closures {
                            if !pass.closures.contains(&closure) {
                                pass.closures.push(closure);
                            }
                        }
                    }
                    pass.certain |= quality == PathQuality::PROVEN_COMPLETE;
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
                    Arc::make_mut(&mut witness).clear_carrier_facts();
                    pass.witnesses.push(witness);
                } else {
                    unavailable.insert((sink, state.key.classes, quality));
                }
            }
        }
        for (sink, payload, quality) in unavailable {
            if represented.iter().any(|&(seen_sink, seen_payload, proof)| {
                seen_sink == sink && seen_payload == payload && proof.dominates(quality)
            }) {
                continue;
            }
            let pass = passes
                .iter_mut()
                .find(|pass| pass.sink == sink)
                .expect("a candidate has a pair envelope");
            pass.unavailable = true;
            pass.qualities.insert(PathQuality::UNPROVEN_PARTIAL);
        }
        Ok(passes)
    }

    fn report_pair(
        &self,
        plan: &TaintAnalysisPlan,
        source: &super::TaintSourceBinding,
        pass: &PairPass,
    ) -> Result<TaintFindingReport, IcfgBarrierError> {
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
        let finding = TaintFinding::composed(
            plan,
            pass.sink,
            pass.classes.clone(),
            pass.qualities,
            fixed && pass.qualities.has_proven_path(),
            (self.baseline.is_complete() && pass.qualities.has_complete_path())
                || (fixed && pass.certain),
            origins,
        )
        .map_err(IcfgBarrierError::Findings)?;
        let authored = (self.baseline.is_proven_by_authored_summaries()
            && !pass.closures.is_empty())
        .then(|| pass.closures.clone());
        let result = TaintSummaryResult::composed(
            plan,
            vec![TaintFact::zero()],
            self.baseline.result().termination(),
            self.baseline.is_complete(),
            authored,
        );
        Ok(self
            .baseline
            .refined_pair(result, vec![finding], pass.unavailable))
    }

    /// Both passes use this session's first bounded graph and one classifier
    /// context supplied by the host. Neither pass can discover a new edge.
    pub fn refine(
        self,
        plan: &TaintAnalysisPlan,
        request: &mut DataflowRequest<'_>,
        mut classify: impl FnMut(
            &BarrierObservation,
            ValueTypePredicate,
        ) -> Result<ValueTypeBarrierDecision, Box<str>>,
    ) -> Result<IcfgBarrierOutcome, IcfgBarrierError> {
        if !self.baseline.belongs_to(plan) || plan.value_type_barriers() != &*self.predicates {
            return Err(IcfgBarrierError::Findings(TaintFindingError::PlanMismatch));
        }
        if self.baseline.findings().is_empty()
            || self.predicates.is_empty()
            || self.recorded.is_none()
        {
            return Ok(IcfgBarrierOutcome {
                report: self.baseline,
                barrier_pairs: Vec::new(),
                barrier_notes: Vec::new(),
            });
        }
        let predicates = &*self.predicates;
        let recorded = self
            .recorded
            .as_ref()
            .expect("candidate solve retained its relations");
        let supports = FrozenSupports::new(&self, recorded, request)?;
        let mut classification = Classification {
            decisions: HashMap::default(),
            checks: Vec::new(),
            budget_note_ids: HashMap::default(),
            verified: HashSet::default(),
        };
        let mut barrier_pairs = Vec::new();
        let mut barrier_notes = Vec::new();
        let mut findings = Vec::new();
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
        for source in plan.sources() {
            let mut lenient: Vec<PairPass> = Vec::new();
            let mut strict: Vec<PairPass> = Vec::new();
            for class in source.classes().iter_dense() {
                let mut source_class = plan.universe().empty_set();
                source_class.insert_dense(class);
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
                drop(unfiltered);
                if !has_candidate {
                    continue;
                }
                let replay = classification.solve(
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
                )?;
                let passes = self.pair_passes(
                    &replay,
                    &classification.checks,
                    plan,
                    recorded,
                    source,
                    &source_class,
                    &mut limits,
                    request,
                )?;
                drop(replay);
                let strict_passes = if passes.iter().any(|pass| {
                    !pass.checks.ids.is_empty() || pass.checks.omitted || pass.unavailable
                }) {
                    let replay = classification.solve(
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
                    )?;
                    self.pair_passes(
                        &replay,
                        &classification.checks,
                        plan,
                        recorded,
                        source,
                        &source_class,
                        &mut limits,
                        request,
                    )?
                } else {
                    passes.clone()
                };
                merge_passes(&mut lenient, passes);
                merge_passes(&mut strict, strict_passes);
            }
            for pass in &lenient {
                let lenient = self.report_pair(plan, source, pass)?;
                let strict = strict
                    .iter()
                    .find(|candidate| candidate.sink == pass.sink)
                    .map(|pass| self.report_pair(plan, source, pass))
                    .transpose()?;
                if strict.is_none() {
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
                        barrier_notes.push(ValueTypeBarrierFindingNotes {
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
                findings.extend(lenient.findings().iter().cloned());
                barrier_pairs.push(ValueTypeBarrierPairEvidence { lenient, strict });
            }
        }
        let incomplete = findings
            .iter()
            .any(|finding| finding.origins().witness_unavailable());
        let report = self.baseline.into_refined_findings(findings, incomplete);
        Ok(IcfgBarrierOutcome {
            report,
            barrier_pairs,
            barrier_notes,
        })
    }
}

fn merge_passes(target: &mut Vec<PairPass>, incoming: Vec<PairPass>) {
    for mut pass in incoming {
        if let Some(existing) = target
            .iter_mut()
            .find(|candidate| candidate.sink == pass.sink)
        {
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
