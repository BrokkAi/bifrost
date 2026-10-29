use std::{collections::HashSet, error::Error, fmt};

use crate::analyzer::semantic::{
    AccessPathRoot, CaptureMode, CaptureSource, EvidenceCompleteness, IcfgEdgeId, IcfgEdgeKind,
    IcfgNodeId, IcfgProvider, IcfgSnapshot, OracleCallContext, OracleLimits, ProcedureHandle,
    ProcedurePortHandle, ProofStatus, SemanticBudget, ValueFlowRelationKind,
};
use crate::dataflow::{
    BoundedSnapshotDataflowProblem, DataflowEdge, DataflowOutput, DataflowRequest, DataflowSeed,
    DistributiveDataflowProblem, ReusableSummaryProvider, SolverBudgetExceeded, SolverWork,
    SummaryDataflowError, SummarySolveInput, WitnessRetentionLimits,
    solve_with_reusable_end_summaries, solve_with_reusable_root_and_end_summaries,
    solve_with_summaries,
};

use super::plan::CallFlowRuleKind;
use super::{
    ValueFlowCarrier, ValueFlowCarrierId, ValueFlowPlan, ValueFlowSinkId, ValueFlowSourceId,
    ValueFlowSummaryResult,
};
use crate::hash::HashMap;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ValueFlowUncertainty(u8);

impl ValueFlowUncertainty {
    const SEMANTIC: u8 = 1 << 0;

    pub(crate) const fn empty() -> Self {
        Self(0)
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub const fn is_uncertain(self) -> bool {
        !self.is_empty()
    }

    pub(crate) const fn with_semantic(self) -> Self {
        Self(self.0 | Self::SEMANTIC)
    }

    pub(crate) const fn with_complete(self, complete: bool) -> Self {
        if complete { self } else { self.with_semantic() }
    }

    pub(crate) const fn from_semantic_uncertainty(uncertain: bool) -> Self {
        if uncertain {
            Self::empty().with_semantic()
        } else {
            Self::empty()
        }
    }

    pub(crate) const fn with_quality(
        self,
        proof: &ProofStatus,
        completeness: &EvidenceCompleteness,
    ) -> Self {
        if matches!(proof, ProofStatus::Proven)
            && matches!(completeness, EvidenceCompleteness::Complete)
        {
            self
        } else {
            self.with_semantic()
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum ValueFlowFactKind {
    Zero,
    Carrier {
        source: ValueFlowSourceId,
        carrier: ValueFlowCarrierId,
        uncertainty: ValueFlowUncertainty,
    },
    Meeting {
        source: ValueFlowSourceId,
        sink: ValueFlowSinkId,
        uncertainty: ValueFlowUncertainty,
    },
}

/// Finite source-sensitive fact used by the policy-free value-flow client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ValueFlowFact(ValueFlowFactKind);

impl ValueFlowFact {
    const ZERO: Self = Self(ValueFlowFactKind::Zero);

    pub(crate) const fn zero() -> Self {
        Self::ZERO
    }

    pub(crate) const fn carrier_fact(
        source: ValueFlowSourceId,
        carrier: ValueFlowCarrierId,
        uncertainty: ValueFlowUncertainty,
    ) -> Self {
        Self(ValueFlowFactKind::Carrier {
            source,
            carrier,
            uncertainty,
        })
    }

    pub(crate) const fn meeting_fact(
        source: ValueFlowSourceId,
        sink: ValueFlowSinkId,
        uncertainty: ValueFlowUncertainty,
    ) -> Self {
        Self(ValueFlowFactKind::Meeting {
            source,
            sink,
            uncertainty,
        })
    }

    pub const fn source(self) -> Option<ValueFlowSourceId> {
        match self.0 {
            ValueFlowFactKind::Carrier { source, .. }
            | ValueFlowFactKind::Meeting { source, .. } => Some(source),
            ValueFlowFactKind::Zero => None,
        }
    }

    pub const fn carrier(self) -> Option<ValueFlowCarrierId> {
        match self.0 {
            ValueFlowFactKind::Carrier { carrier, .. } => Some(carrier),
            ValueFlowFactKind::Zero | ValueFlowFactKind::Meeting { .. } => None,
        }
    }

    pub const fn sink(self) -> Option<ValueFlowSinkId> {
        match self.0 {
            ValueFlowFactKind::Meeting { sink, .. } => Some(sink),
            ValueFlowFactKind::Zero | ValueFlowFactKind::Carrier { .. } => None,
        }
    }

    pub const fn uncertainty(self) -> ValueFlowUncertainty {
        match self.0 {
            ValueFlowFactKind::Carrier { uncertainty, .. }
            | ValueFlowFactKind::Meeting { uncertainty, .. } => uncertainty,
            ValueFlowFactKind::Zero => ValueFlowUncertainty(0),
        }
    }

    pub(crate) const fn is_terminal_meeting(self) -> bool {
        matches!(self.0, ValueFlowFactKind::Meeting { .. })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct ActiveFlow {
    source: ValueFlowSourceId,
    carrier: ValueFlowCarrierId,
    uncertainty: ValueFlowUncertainty,
}

impl ActiveFlow {
    const fn fact(self) -> ValueFlowFact {
        ValueFlowFact(ValueFlowFactKind::Carrier {
            source: self.source,
            carrier: self.carrier,
            uncertainty: self.uncertainty,
        })
    }

    const fn with_transfer_quality(
        mut self,
        proof: &ProofStatus,
        completeness: &EvidenceCompleteness,
    ) -> Self {
        self.uncertainty = self.uncertainty.with_quality(proof, completeness);
        self
    }

    const fn with_transfer_completeness(mut self, complete: bool) -> Self {
        if !complete {
            self.uncertainty = self.uncertainty.with_semantic();
        }
        self
    }
}

/// Fact-only direct/indirect value-flow client over one immutable plan.
pub struct ValueFlowProblem<'plan> {
    plan: &'plan ValueFlowPlan,
    snapshot: Option<SnapshotValueFlow>,
    summary_captures: Option<SummaryCaptureAssociations>,
}

impl<'plan> ValueFlowProblem<'plan> {
    pub const fn new(plan: &'plan ValueFlowPlan) -> Self {
        Self {
            plan,
            snapshot: None,
            summary_captures: None,
        }
    }

    /// Prepare query-local contextual capture transfers for one frozen ICFG.
    /// Summary-only construction stays context independent; this constructor
    /// binds exact edge identities and root seeds for the bounded runner.
    fn for_snapshot(
        plan: &'plan ValueFlowPlan,
        snapshot: &IcfgSnapshot,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Self, ValueFlowSolveError> {
        let capture_edges = argument_capture_edges(plan, snapshot, request)?;
        let mut seeds = Vec::new();
        for id in snapshot.node_ids() {
            charge_capture_projection(request)?;
            let node = snapshot.node(id).expect("snapshot node ID");
            if node.point().procedure() == plan.root()
                && node.point().id() == plan.root().semantics().entry_point()
                && node.call_context().is_empty()
            {
                seeds.push(id);
            }
        }
        if seeds.is_empty() {
            return Err(ValueFlowSolveError::RootMismatch);
        }
        Ok(Self {
            plan,
            summary_captures: None,
            snapshot: Some(SnapshotValueFlow {
                capture_edges,
                seeds,
            }),
        })
    }

    fn active_before_point(
        &self,
        point: &crate::analyzer::semantic::ProgramPointHandle,
        fact: ValueFlowFact,
    ) -> Vec<ActiveFlow> {
        let mut active = Vec::new();
        let is_zero = matches!(fact.0, ValueFlowFactKind::Zero);
        if let ValueFlowFactKind::Carrier {
            source,
            carrier,
            uncertainty,
        } = fact.0
        {
            active.push(ActiveFlow {
                source,
                carrier,
                uncertainty,
            });
        }
        let generated = self.source_flows_at(
            point,
            super::ValueFlowObservationPhase::BeforeEffects,
            is_zero,
            &active,
        );
        active.extend(generated);
        active.sort_unstable();
        active.dedup();
        active
    }

    fn source_flows_at(
        &self,
        point: &crate::analyzer::semantic::ProgramPointHandle,
        phase: super::ValueFlowObservationPhase,
        is_zero: bool,
        active: &[ActiveFlow],
    ) -> Vec<ActiveFlow> {
        let mut generated = Vec::new();
        for source in self.plan.sources_at(point, phase) {
            match source
                .activation_triggers
                .map(|list| self.plan.source_list(list))
            {
                None if is_zero => generated.push(ActiveFlow {
                    source: source.id,
                    carrier: source.carrier,
                    uncertainty: quality_uncertainty(
                        source.spec.proof(),
                        source.spec.completeness(),
                    ),
                }),
                Some(triggers) if !is_zero => generated.extend(conditional_source_flows(
                    source.id,
                    source.carrier,
                    triggers,
                    active.iter().copied(),
                    source.spec.proof(),
                    source.spec.completeness(),
                )),
                None | Some(_) => {}
            }
        }
        generated
    }

    fn apply_point(
        &self,
        point: &crate::analyzer::semantic::ProgramPointHandle,
        fact: ValueFlowFact,
        meetings: &mut Vec<ValueFlowFact>,
    ) -> Vec<ActiveFlow> {
        if fact.is_terminal_meeting() {
            return Vec::new();
        }
        let active = self.active_before_point(point, fact);
        self.append_meetings(
            point,
            super::ValueFlowObservationPhase::BeforeEffects,
            &active,
            meetings,
        );
        let mut active = active.into_iter().collect::<HashSet<_>>();
        for rule in self.plan.local_rule_views(point) {
            apply_local_rule(&mut active, rule);
        }
        let mut active = active.into_iter().collect::<Vec<_>>();
        let generated = self.source_flows_at(
            point,
            super::ValueFlowObservationPhase::AfterEffects,
            matches!(fact.0, ValueFlowFactKind::Zero),
            &active,
        );
        // Evaluate every conditional source against the incoming active set.
        // Extending only after this loop prevents a source generated here from
        // recursively activating another source at the same point.
        active.extend(generated);
        active.sort_unstable();
        active.dedup();
        self.append_meetings(
            point,
            super::ValueFlowObservationPhase::AfterEffects,
            &active,
            meetings,
        );
        active
    }

    fn append_meetings(
        &self,
        point: &crate::analyzer::semantic::ProgramPointHandle,
        phase: super::ValueFlowObservationPhase,
        active: &[ActiveFlow],
        meetings: &mut Vec<ValueFlowFact>,
    ) {
        for sink in self.plan.sinks_at(point, phase) {
            for flow in active.iter().filter(|flow| flow.carrier == sink.carrier) {
                let uncertainty = if matches!(sink.spec.proof(), ProofStatus::Proven)
                    && matches!(sink.spec.completeness(), EvidenceCompleteness::Complete)
                {
                    flow.uncertainty
                } else {
                    flow.uncertainty.with_semantic()
                };
                meetings.push(ValueFlowFact(ValueFlowFactKind::Meeting {
                    source: flow.source,
                    sink: sink.id,
                    uncertainty,
                }));
            }
        }
    }

    fn emit_all(
        &self,
        active: Vec<ActiveFlow>,
        mut meetings: Vec<ValueFlowFact>,
        out: &mut dyn DataflowOutput<ValueFlowFact>,
    ) {
        meetings.extend(active.into_iter().map(ActiveFlow::fact));
        meetings.sort_unstable();
        meetings.dedup();
        for fact in meetings {
            if !out.emit(fact) {
                break;
            }
        }
    }

    fn call_transfer(
        &self,
        edge: DataflowEdge<'_, ValueFlowFact>,
        fact: ValueFlowFact,
        out: &mut dyn DataflowOutput<ValueFlowFact>,
    ) {
        let mut meetings = Vec::new();
        let active = self.apply_point(edge.source(), fact, &mut meetings);
        let Some(call) = edge.origin() else {
            self.emit_all(Vec::new(), meetings, out);
            return;
        };
        let callee = edge.target().procedure();
        let mut mapped = Vec::new();
        let capture_rows = self
            .snapshot
            .as_ref()
            .and_then(|snapshot| {
                edge.snapshot_edge()
                    .and_then(|id| snapshot.capture_edges.get(&id))
            })
            .or_else(|| {
                let context = edge.call_context()?;
                if context.was_truncated() {
                    return None;
                }
                self.summary_captures
                    .as_ref()?
                    .get(&(call.clone(), edge.kind()))?
                    .get(callee)?
                    .get(context)
            });
        for flow in active {
            if let Some(rows) = capture_rows {
                for (source, target) in rows {
                    if flow.carrier == *source {
                        mapped.push(ActiveFlow {
                            carrier: *target,
                            uncertainty: flow.uncertainty.with_semantic(),
                            ..flow
                        });
                    }
                }
            }
            if self.plan.is_callee_port(flow.carrier, callee)
                && !self
                    .plan
                    .call_rules_to_target_in_context(
                        call,
                        callee,
                        CallFlowRuleKind::Call,
                        flow.carrier,
                        edge.call_context(),
                    )
                    .any(|rule| self.plan.is_default_argument_carrier(rule.source, callee))
            {
                mapped.push(flow);
            }
            for rule in self.plan.call_rules_in_context(
                call,
                callee,
                CallFlowRuleKind::Call,
                edge.call_context(),
            ) {
                if flow.carrier == rule.source {
                    mapped.push(ActiveFlow {
                        carrier: rule.target,
                        ..flow.with_transfer_quality(&rule.proof, &rule.completeness)
                    });
                }
            }
        }
        if matches!(fact.0, ValueFlowFactKind::Zero) {
            // A default value belongs to the callee, was saved at definition
            // time, and is exposed as a source at its entry. It is consequently
            // absent from the caller's active facts. Select that entry source
            // only for the call rule that explicitly binds the default.
            for rule in self
                .plan
                .call_rules_in_context(call, callee, CallFlowRuleKind::Call, edge.call_context())
                .filter(|rule| self.plan.is_default_argument_carrier(rule.source, callee))
            {
                for phase in [
                    super::ValueFlowObservationPhase::BeforeEffects,
                    super::ValueFlowObservationPhase::AfterEffects,
                ] {
                    for source in self.plan.sources_at(edge.target(), phase).filter(|source| {
                        source.carrier == rule.source && source.activation_triggers.is_none()
                    }) {
                        let uncertainty =
                            quality_uncertainty(source.spec.proof(), source.spec.completeness());
                        mapped.push(
                            ActiveFlow {
                                source: source.id,
                                carrier: rule.target,
                                uncertainty,
                            }
                            .with_transfer_quality(&rule.proof, &rule.completeness),
                        );
                    }
                }
            }
        }
        self.emit_all(mapped, meetings, out);
    }

    fn return_transfer(
        &self,
        edge: DataflowEdge<'_, ValueFlowFact>,
        fact: ValueFlowFact,
        out: &mut dyn DataflowOutput<ValueFlowFact>,
    ) {
        let mut meetings = Vec::new();
        let active = self.apply_point(edge.source(), fact, &mut meetings);
        let Some(call) = edge.origin() else {
            self.emit_all(Vec::new(), meetings, out);
            return;
        };
        let kind = match edge.kind() {
            IcfgEdgeKind::NormalReturn => CallFlowRuleKind::NormalReturn,
            IcfgEdgeKind::ExceptionalReturn => CallFlowRuleKind::ExceptionalReturn,
            _ => {
                self.emit_all(Vec::new(), meetings, out);
                return;
            }
        };
        let callee = edge.source().procedure();
        let mut mapped = Vec::new();
        let capture_rows = self
            .snapshot
            .as_ref()
            .and_then(|snapshot| {
                edge.snapshot_edge()
                    .and_then(|id| snapshot.capture_edges.get(&id))
            })
            .or_else(|| {
                let context = edge.call_context()?;
                if context.was_truncated() {
                    return None;
                }
                self.summary_captures
                    .as_ref()?
                    .get(&(call.clone(), edge.kind()))?
                    .get(callee)?
                    .get(context)
            });
        for flow in active {
            if let Some(rows) = capture_rows {
                for (source, target) in rows {
                    if flow.carrier == *source {
                        mapped.push(ActiveFlow {
                            carrier: *target,
                            uncertainty: flow.uncertainty.with_semantic(),
                            ..flow
                        });
                    }
                }
            }
            for rule in self.plan.call_rules_from_source_in_context(
                call,
                callee,
                kind,
                flow.carrier,
                edge.call_context(),
            ) {
                mapped.push(ActiveFlow {
                    carrier: rule.target,
                    ..flow.with_transfer_quality(&rule.proof, &rule.completeness)
                });
            }
        }
        self.emit_all(mapped, meetings, out);
    }

    fn boundary_transfer(
        &self,
        edge: DataflowEdge<'_, ValueFlowFact>,
        fact: ValueFlowFact,
        out: &mut dyn DataflowOutput<ValueFlowFact>,
    ) {
        let mut meetings = Vec::new();
        let active = self.apply_point(edge.source(), fact, &mut meetings);
        let Some(call) = edge.origin() else {
            self.emit_all(active, meetings, out);
            return;
        };
        meetings.sort_unstable();
        meetings.dedup();
        for meeting in meetings {
            if !out.emit(meeting) {
                return;
            }
        }
        for flow in active {
            let mut emitting = true;
            let application = self.plan.visit_boundary_transfers(
                call,
                edge.boundary(),
                edge.kind(),
                flow.carrier,
                |transfer| {
                    let transferred = ActiveFlow {
                        carrier: transfer.target,
                        uncertainty: if transfer.proven_complete {
                            flow.uncertainty
                        } else {
                            flow.uncertainty.with_semantic()
                        },
                        ..flow
                    };
                    emitting = out.emit(transferred.fact());
                    emitting
                },
            );
            if !emitting {
                return;
            }
            let preserved = if application.abstained {
                ActiveFlow {
                    uncertainty: flow.uncertainty.with_semantic(),
                    ..flow
                }
            } else {
                flow
            };
            if !out.emit(preserved.fact()) {
                return;
            }
        }
    }
}

fn conditional_source_flows(
    source: ValueFlowSourceId,
    carrier: ValueFlowCarrierId,
    triggers: &[ValueFlowSourceId],
    active: impl IntoIterator<Item = ActiveFlow>,
    proof: &ProofStatus,
    completeness: &EvidenceCompleteness,
) -> Vec<ActiveFlow> {
    active
        .into_iter()
        .filter(|flow| flow.carrier == carrier && triggers.binary_search(&flow.source).is_ok())
        .map(|flow| ActiveFlow {
            source,
            carrier,
            uncertainty: flow.uncertainty.with_quality(proof, completeness),
        })
        .collect()
}

fn apply_local_rule(active: &mut HashSet<ActiveFlow>, rule: super::plan::LocalRuleView) {
    if kills_target(&rule) {
        active.retain(|flow| flow.carrier != rule.target);
    }
    let generated = active
        .iter()
        .copied()
        .filter(|flow| flow.carrier == rule.source)
        .map(|flow| ActiveFlow {
            carrier: rule.target,
            ..flow.with_transfer_completeness(rule.complete)
        })
        .collect::<Vec<_>>();
    if invalidates_source(&rule) {
        active.retain(|flow| flow.carrier != rule.source);
    }
    active.extend(generated);
}

/// Query-local bounded forward value-flow evidence. Plan discovery and ICFG
/// coverage remain separate and both are required for a complete result.
#[derive(Debug, Clone)]
pub struct ValueFlowSnapshotResult {
    raw: crate::dataflow::DataflowResult<ValueFlowFact>,
    discovery_complete: bool,
    work: SolverWork,
}

impl ValueFlowSnapshotResult {
    pub const fn work(&self) -> SolverWork {
        self.work
    }

    pub const fn raw(&self) -> &crate::dataflow::DataflowResult<ValueFlowFact> {
        &self.raw
    }
    pub fn is_complete(&self) -> bool {
        self.discovery_complete && self.raw.is_complete()
    }
}

/// Solve forward over the supplied bounded snapshot. Construction and solving
/// stay together so dense contextual edge IDs cannot escape into another input.
pub fn solve_value_flow_on_snapshot(
    plan: &ValueFlowPlan,
    input: crate::dataflow::IcfgSolveInput<'_>,
    request: &mut DataflowRequest<'_>,
) -> Result<ValueFlowSnapshotResult, ValueFlowSolveError> {
    if plan.has_contextual_bindings() {
        return Err(ValueFlowSolveError::CallContextRequired);
    }
    let initial_work = request.budget.used();
    let problem = ValueFlowProblem::for_snapshot(plan, input.snapshot(), request)?;
    let raw = crate::dataflow::solve_on_snapshot(input, &problem, request)?;
    Ok(ValueFlowSnapshotResult {
        raw,
        discovery_complete: plan.discovery_complete(),
        work: request.budget.used().saturating_sub(initial_work),
    })
}

type CaptureCarrierPairs = Vec<(ValueFlowCarrierId, ValueFlowCarrierId)>;
type SummaryCaptureAssociations =
    HashMap<(crate::analyzer::semantic::CallSiteHandle, IcfgEdgeKind), SummaryCaptureTargets>;
type SummaryCaptureTargets =
    HashMap<ProcedureHandle, HashMap<OracleCallContext, CaptureCarrierPairs>>;

struct SnapshotValueFlow {
    capture_edges: HashMap<IcfgEdgeId, Vec<(ValueFlowCarrierId, ValueFlowCarrierId)>>,
    seeds: Vec<IcfgNodeId>,
}

impl BoundedSnapshotDataflowProblem for ValueFlowProblem<'_> {
    fn seeds(&self, out: &mut dyn DataflowOutput<DataflowSeed<Self::Fact>>) {
        if let Some(snapshot) = &self.snapshot {
            for node in &snapshot.seeds {
                if !out.emit(DataflowSeed::new(*node, ValueFlowFact::ZERO)) {
                    break;
                }
            }
        }
    }
}

pub(crate) enum CaptureProjectionError {
    Cancelled,
    ExceededBudget(SolverBudgetExceeded),
}

/// Preserve already represented member storage beneath an exact capture cell.
/// Member identity uses the shared call-location selector respelling. Typed
/// constant indexes can cross procedures; incomplete or absent paths cannot.
fn capture_carrier_transports(
    plan: &ValueFlowPlan,
    source: ValueFlowCarrierId,
    target: ValueFlowCarrierId,
    request: &mut DataflowRequest<'_>,
) -> Result<Vec<(ValueFlowCarrierId, ValueFlowCarrierId)>, CaptureProjectionError> {
    let mut rows = vec![(source, target)];
    let (Some(ValueFlowCarrier::Location(cell)), Some(ValueFlowCarrier::Port(port))) =
        (plan.carrier(source), plan.carrier(target))
    else {
        return Ok(rows);
    };
    let AccessPathRoot::LexicalCell(owner) = cell.path().root() else {
        return Ok(rows);
    };
    if !cell.path().selectors().is_empty() || !cell.path().is_exact() {
        return Ok(rows);
    }
    for carrier in plan.carriers() {
        charge_capture_projection(request)?;
        let ValueFlowCarrier::Location(location) = carrier else {
            continue;
        };
        if !location.path().is_exact()
            || !matches!(location.path().root(), AccessPathRoot::CaptureSlot(slot) if slot == port)
        {
            continue;
        }
        let target = plan
            .carrier_id(carrier)
            .expect("an enumerated carrier is retained");
        for candidate in plan.carriers() {
            charge_capture_projection(request)?;
            let ValueFlowCarrier::Location(projected) = candidate else {
                continue;
            };
            request
                .budget
                .charge(SolverWork {
                    callback_rows: location.path().selectors().len(),
                    ..SolverWork::default()
                })
                .map_err(CaptureProjectionError::ExceededBudget)?;
            if !super::plan::is_capture_location_projection(
                cell,
                projected,
                location,
                owner.procedure(),
            ) {
                continue;
            }
            let source = plan
                .carrier_id(candidate)
                .expect("an enumerated carrier is retained");
            let mut proven = true;
            for (procedure, carrier) in [(owner.procedure(), source), (port.procedure(), target)] {
                let mut retained = false;
                for point in procedure.semantics().points() {
                    charge_capture_projection(request)?;
                    let point = procedure
                        .point_handle(point.id)
                        .expect("retained capture point");
                    for rule in plan.local_rules_at(&point) {
                        charge_capture_projection(request)?;
                        retained |= (rule.source == carrier || rule.target == carrier)
                            && rule.proof == ProofStatus::Proven
                            && rule.completeness == EvidenceCompleteness::Complete;
                    }
                }
                proven &= retained;
            }
            if !proven {
                continue;
            }
            rows.push((source, target));
        }
    }
    Ok(rows)
}

pub(crate) fn argument_capture_edges(
    plan: &ValueFlowPlan,
    snapshot: &IcfgSnapshot,
    request: &mut DataflowRequest<'_>,
) -> Result<
    HashMap<IcfgEdgeId, Vec<(ValueFlowCarrierId, ValueFlowCarrierId)>>,
    CaptureProjectionError,
> {
    let mut capture_edges: HashMap<IcfgEdgeId, Vec<(ValueFlowCarrierId, ValueFlowCarrierId)>> =
        HashMap::default();
    // These indexes live only for this bounded solve. Edge IDs retain the
    // full frozen context, so two callers of one Invoke cannot share rows.
    if request.cancellation.is_cancelled() {
        // The snapshot solver publishes the existing typed Cancelled result.
        return Ok(capture_edges);
    }
    let mut entries = HashMap::default();
    for (index, edge) in snapshot.edges().iter().enumerate() {
        charge_capture_projection(request)?;
        if edge.kind != IcfgEdgeKind::Call {
            continue;
        }
        let target = snapshot.node(edge.target).expect("snapshot edge target");
        request
            .budget
            .charge(SolverWork {
                callback_rows: target.call_context().len(),
                ..SolverWork::default()
            })
            .map_err(CaptureProjectionError::ExceededBudget)?;
        let key = (
            target.point().procedure().clone(),
            target.call_context().to_vec(),
        );
        let id = IcfgEdgeId::new(u32::try_from(index).expect("snapshot edge ID"));
        entries
            .entry(key)
            .and_modify(|entry| *entry = None)
            .or_insert(Some(id));
    }
    for (index, edge) in snapshot.edges().iter().enumerate() {
        charge_capture_projection(request)?;
        if edge.kind != IcfgEdgeKind::Call {
            continue;
        }
        let node = snapshot.node(edge.target).expect("snapshot edge target");
        let Some(proof) = node.argument_callable() else {
            continue;
        };
        let context = node.call_context();
        // This consumer handles a direct actual/formal callback call. A
        // relay or truncated suffix is a different contract, not a guess.
        // Factory environments require an exact producer-return projection;
        // their storage is never substituted with a direct caller cell.
        if context.len() < 2
            || context[context.len() - 2] != *proof.entering_call()
            || edge.origin.as_ref() != context.last()
            || edge.origin.as_ref().map(|call| call.procedure()) != Some(proof.callee())
            || node.point().procedure() != proof.closure()
            || (proof.producer().is_none()
                && proof.creation().procedure() != proof.entering_call().procedure())
            || proof.caller_context().was_truncated()
            || context[..context.len() - 2] != *proof.caller_context().calls()
        {
            continue;
        }
        request
            .budget
            .charge(SolverWork {
                callback_rows: context.len(),
                ..SolverWork::default()
            })
            .map_err(CaptureProjectionError::ExceededBudget)?;
        let key = (
            proof.callee().clone(),
            context[..context.len() - 1].to_vec(),
        );
        let Some(Some(entering)) = entries.get(&key) else {
            continue;
        };
        if snapshot
            .edge(*entering)
            .expect("indexed entering edge")
            .origin
            .as_ref()
            != Some(proof.entering_call())
        {
            continue;
        }
        if let Some(producer) = proof.producer() {
            // Preserve an exact factory environment only on its matched normal
            // return, then the proven actual/formal entry and callback entry.
            // This carries the live capture port, not its initializer value.
            let mut producer_context = proof.caller_context().calls().to_vec();
            request
                .budget
                .charge(SolverWork {
                    callback_rows: producer_context.len().saturating_mul(2).saturating_add(2),
                    ..SolverWork::default()
                })
                .map_err(CaptureProjectionError::ExceededBudget)?;
            producer_context.push(producer.producer().clone());
            let producer_key = (producer.producer_callee().clone(), producer_context.clone());
            let Some(Some(producer_entry)) = entries.get(&producer_key) else {
                continue;
            };
            if snapshot
                .edge(*producer_entry)
                .expect("producer entry")
                .origin
                .as_ref()
                != Some(producer.producer())
            {
                continue;
            }
            let mut returns = Vec::new();
            for (return_index, returned) in snapshot.edges().iter().enumerate() {
                charge_capture_projection(request)?;
                if returned.kind != IcfgEdgeKind::NormalReturn
                    || returned.origin.as_ref() != Some(producer.producer())
                {
                    continue;
                }
                let source = snapshot
                    .node(returned.source)
                    .expect("factory return source");
                let target = snapshot
                    .node(returned.target)
                    .expect("factory return target");
                if source.point().procedure() == producer.producer_callee()
                    && source.call_context() == producer_context
                    && target.point().procedure() == producer.producer().procedure()
                    && target.call_context() == proof.caller_context().calls()
                {
                    returns.push(IcfgEdgeId::new(
                        u32::try_from(return_index).expect("return edge ID"),
                    ));
                }
            }
            if returns.is_empty() {
                continue;
            }
            for binding in proof.capture_bindings() {
                charge_capture_projection(request)?;
                if !matches!(
                    binding.mode,
                    CaptureMode::MutableCell | CaptureMode::SharedCell
                ) || !matches!(binding.captured, CaptureSource::Location(_))
                {
                    continue;
                }
                let port =
                    ProcedurePortHandle::capture(proof.closure().clone(), binding.destination)
                        .expect("factory capture slot");
                let Some(destination) = plan.carrier_id(&ValueFlowCarrier::Port(port)) else {
                    continue;
                };
                let point = proof
                    .creation()
                    .procedure()
                    .point_handle(binding.point)
                    .expect("factory capture point");
                for rule in plan.local_rules_at(&point) {
                    charge_capture_projection(request)?;
                    if rule.kind != ValueFlowRelationKind::Capture
                        || rule.target != destination
                        || rule.proof != ProofStatus::Proven
                        || rule.completeness != EvidenceCompleteness::Complete
                        || !matches!(
                            plan.carrier(rule.source),
                            Some(ValueFlowCarrier::Location(_))
                        )
                    {
                        continue;
                    }
                    for (source, destination) in
                        capture_carrier_transports(plan, rule.source, destination, request)?
                    {
                        for returned in &returns {
                            charge_capture_projection(request)?;
                            capture_edges
                                .entry(*returned)
                                .or_default()
                                .push((source, destination));
                        }
                        let callback =
                            IcfgEdgeId::new(u32::try_from(index).expect("callback edge ID"));
                        request
                            .budget
                            .charge(SolverWork {
                                callback_rows: 2,
                                ..SolverWork::default()
                            })
                            .map_err(CaptureProjectionError::ExceededBudget)?;
                        capture_edges
                            .entry(*entering)
                            .or_default()
                            .push((destination, destination));
                        capture_edges
                            .entry(callback)
                            .or_default()
                            .push((destination, destination));
                    }
                }
            }
            continue;
        }
        for binding in proof.capture_bindings() {
            charge_capture_projection(request)?;
            if !matches!(
                binding.mode,
                CaptureMode::MutableCell | CaptureMode::SharedCell
            ) || !matches!(binding.captured, CaptureSource::Location(_))
            {
                continue;
            }
            let port = ProcedurePortHandle::capture(proof.closure().clone(), binding.destination)
                .expect("proven capture slot");
            let Some(destination) = plan.carrier_id(&ValueFlowCarrier::Port(port)) else {
                continue;
            };
            let point = proof
                .creation()
                .procedure()
                .point_handle(binding.point)
                .expect("proven capture point");
            for rule in plan.local_rules_at(&point) {
                charge_capture_projection(request)?;
                if rule.kind != ValueFlowRelationKind::Capture
                    || rule.target != destination
                    || !matches!(rule.proof, crate::analyzer::semantic::ProofStatus::Proven)
                    || !matches!(
                        rule.completeness,
                        crate::analyzer::semantic::EvidenceCompleteness::Complete
                    )
                    || !matches!(
                        plan.carrier(rule.source),
                        Some(ValueFlowCarrier::Location(_))
                    )
                {
                    continue;
                }
                for (source, destination) in
                    capture_carrier_transports(plan, rule.source, destination, request)?
                {
                    request
                        .budget
                        .charge(SolverWork {
                            callback_rows: 2,
                            ..SolverWork::default()
                        })
                        .map_err(CaptureProjectionError::ExceededBudget)?;
                    let callback = IcfgEdgeId::new(u32::try_from(index).expect("snapshot edge ID"));
                    capture_edges
                        .entry(callback)
                        .or_default()
                        .push((source, destination));
                    capture_edges
                        .entry(*entering)
                        .or_default()
                        .push((source, source));
                }
            }
        }
    }
    for rows in capture_edges.values_mut() {
        rows.sort_unstable();
        rows.dedup();
    }
    Ok(capture_edges)
}
pub(crate) fn charge_capture_projection(
    request: &mut DataflowRequest<'_>,
) -> Result<(), CaptureProjectionError> {
    if request.cancellation.is_cancelled() {
        return Err(CaptureProjectionError::Cancelled);
    }
    request
        .budget
        .charge(SolverWork {
            callback_rows: 1,
            ..SolverWork::default()
        })
        .map_err(CaptureProjectionError::ExceededBudget)
}

impl DistributiveDataflowProblem for ValueFlowProblem<'_> {
    type Fact = ValueFlowFact;

    fn zero_fact(&self) -> Self::Fact {
        ValueFlowFact::ZERO
    }

    fn resolved_call_to_return(&self) -> bool {
        true
    }

    fn call_replaced_by_model(&self, call: &crate::analyzer::semantic::CallSiteHandle) -> bool {
        self.plan.curated_model_for_call(call).is_some()
    }

    fn call_replaced_by_proven_model(
        &self,
        call: &crate::analyzer::semantic::CallSiteHandle,
    ) -> bool {
        self.plan.curated_model_is_proven_complete(call)
    }

    fn normal_flow(
        &self,
        edge: DataflowEdge<'_, Self::Fact>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.flow(edge, fact, out);
    }

    fn call_flow(
        &self,
        edge: DataflowEdge<'_, Self::Fact>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.call_transfer(edge, fact, out);
    }

    fn return_flow(
        &self,
        edge: DataflowEdge<'_, Self::Fact>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.return_transfer(edge, fact, out);
    }

    fn call_to_return_flow(
        &self,
        edge: DataflowEdge<'_, Self::Fact>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.boundary_transfer(edge, fact, out);
    }

    fn exceptional_flow(
        &self,
        edge: DataflowEdge<'_, Self::Fact>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.flow(edge, fact, out);
    }
}

impl ValueFlowProblem<'_> {
    fn flow(
        &self,
        edge: DataflowEdge<'_, ValueFlowFact>,
        fact: ValueFlowFact,
        out: &mut dyn DataflowOutput<ValueFlowFact>,
    ) {
        let mut meetings = Vec::new();
        let mut active = self.apply_point(edge.source(), fact, &mut meetings);
        if let crate::analyzer::semantic::IcfgEdgeKind::Intraprocedural(kind) = edge.kind() {
            let kills = self
                .plan
                .edge_kills(edge.source(), edge.target().id(), kind);
            active.retain(|flow| {
                !kills.iter().any(|kill| {
                    // A label narrowing cannot remove the whole provenance fact.
                    kill.labels.is_none()
                        && kill.carrier == flow.carrier
                        && self
                            .plan
                            .source_list(kill.sources)
                            .binary_search(&flow.source)
                            .is_ok()
                })
            });
        }
        self.emit_all(active, meetings, out);
    }
}

pub fn solve_value_flow_with_summaries<Provider>(
    root: &ProcedureHandle,
    provider: &Provider,
    plan: &ValueFlowPlan,
    semantic_budget: &mut SemanticBudget,
    request: &mut DataflowRequest<'_>,
) -> Result<ValueFlowSummaryResult, ValueFlowSolveError>
where
    Provider: IcfgProvider + ?Sized,
{
    solve_value_flow_with_witnesses(
        root,
        provider,
        plan,
        WitnessRetentionLimits::disabled(),
        semantic_budget,
        request,
    )
}

pub fn solve_value_flow_with_witnesses<Provider>(
    root: &ProcedureHandle,
    provider: &Provider,
    plan: &ValueFlowPlan,
    witness_retention: WitnessRetentionLimits,
    semantic_budget: &mut SemanticBudget,
    request: &mut DataflowRequest<'_>,
) -> Result<ValueFlowSummaryResult, ValueFlowSolveError>
where
    Provider: IcfgProvider + ?Sized,
{
    if root != plan.root() {
        return Err(ValueFlowSolveError::RootMismatch);
    }
    if plan.has_contextual_bindings() {
        return Err(ValueFlowSolveError::CallContextRequired);
    }
    let problem = ValueFlowProblem::new(plan);
    let result = solve_with_summaries(
        SummarySolveInput::new(root, &[]).with_witness_retention(witness_retention),
        provider,
        &problem,
        semantic_budget,
        request,
    )?;
    ValueFlowSummaryResult::from_result(plan, result)
}

/// Execute query-local summaries with capture associations from this exact
/// frozen input. Snapshot edge IDs are discarded before summary evaluation.
pub fn solve_value_flow_summaries_on_snapshot<Provider>(
    provider: &Provider,
    plan: &ValueFlowPlan,
    input: crate::dataflow::IcfgSolveInput<'_>,
    limits: OracleLimits,
    witness_retention: WitnessRetentionLimits,
    semantic_budget: &mut SemanticBudget,
    request: &mut DataflowRequest<'_>,
) -> Result<ValueFlowSummaryResult, ValueFlowSolveError>
where
    Provider: IcfgProvider + ?Sized,
{
    let initial_work = request.budget.used();
    let snapshot = input.snapshot();
    let mut problem = ValueFlowProblem::for_snapshot(plan, snapshot, request)?;
    let projected = problem
        .snapshot
        .take()
        .expect("validated snapshot projection")
        .capture_edges;
    let mut captures = SummaryCaptureAssociations::default();
    for (id, rows) in projected {
        charge_capture_projection(request)?;
        let edge = snapshot.edge(id).expect("projected snapshot edge");
        let source = snapshot.node(edge.source).expect("projected source");
        let target = snapshot.node(edge.target).expect("projected target");
        let caller = if edge.kind == IcfgEdgeKind::NormalReturn {
            target
        } else {
            source
        };
        let callee = if edge.kind == IcfgEdgeKind::NormalReturn {
            source
        } else {
            target
        };
        let context = OracleCallContext::bounded(caller.call_context().to_vec(), limits);
        if context.was_truncated() || callee.call_context().len() > limits.call_context_depth() {
            continue;
        }
        request
            .budget
            .charge(SolverWork {
                callback_rows: context.calls().len() + rows.len(),
                ..SolverWork::default()
            })
            .map_err(CaptureProjectionError::ExceededBudget)?;
        captures
            .entry((
                edge.origin.clone().expect("projected call origin"),
                edge.kind,
            ))
            .or_default()
            .entry(callee.point().procedure().clone())
            .or_default()
            .entry(context)
            .or_default()
            .extend(rows);
    }
    for targets in captures.values_mut() {
        for contexts in targets.values_mut() {
            for rows in contexts.values_mut() {
                rows.sort_unstable();
                rows.dedup();
            }
        }
    }
    problem.summary_captures = Some(captures);
    let replay = crate::dataflow::SnapshotReplayProvider::new(provider, input);
    let mut result = solve_with_summaries(
        SummarySolveInput::new(plan.root(), &[])
            .with_call_context(limits)
            .with_witness_retention(witness_retention),
        &replay,
        &problem,
        semantic_budget,
        request,
    )?;
    result.set_query_work(request.budget.used().saturating_sub(initial_work));
    ValueFlowSummaryResult::from_result(plan, result)
}

pub(crate) fn solve_value_flow_with_reusable_summaries<Provider, Reusable>(
    root: &ProcedureHandle,
    provider: &Provider,
    reusable: &mut Reusable,
    plan: &ValueFlowPlan,
    witness_retention: WitnessRetentionLimits,
    semantic_budget: &mut SemanticBudget,
    request: &mut DataflowRequest<'_>,
) -> Result<ValueFlowSummaryResult, ValueFlowSolveError>
where
    Provider: IcfgProvider + ?Sized,
    Reusable: ReusableSummaryProvider<ValueFlowFact> + ?Sized,
{
    if root != plan.root() {
        return Err(ValueFlowSolveError::RootMismatch);
    }
    if plan.has_contextual_bindings() {
        return Err(ValueFlowSolveError::CallContextRequired);
    }
    let problem = ValueFlowProblem::new(plan);
    let result = solve_with_reusable_root_and_end_summaries(
        SummarySolveInput::new(root, &[]).with_witness_retention(witness_retention),
        provider,
        &problem,
        reusable,
        semantic_budget,
        request,
    )?;
    ValueFlowSummaryResult::from_result(plan, result)
}

/// Solve one procedure already present in `plan` from one exact entry fact.
///
/// This is the maintenance counterpart to the ordinary root solve. It reuses
/// the immutable plan and its validated call bindings, but roots tabulation at
/// a demanded procedure entry so an incremental summary coordinator can
/// refresh that relation without solving an unrelated caller. The summary
/// kernel always includes its distinguished zero entry; a nonzero
/// `entry_fact` is the only additional entry relation. Witness retention is
/// deliberately disabled because persisted class-set summaries retain the
/// normalized relation rather than witness fragments.
pub(crate) fn solve_value_flow_entry_with_reusable_summaries<Provider, Reusable>(
    procedure: &ProcedureHandle,
    entry_fact: ValueFlowFact,
    provider: &Provider,
    reusable: &mut Reusable,
    plan: &ValueFlowPlan,
    semantic_budget: &mut SemanticBudget,
    request: &mut DataflowRequest<'_>,
) -> Result<ValueFlowSummaryResult, ValueFlowSolveError>
where
    Provider: IcfgProvider + ?Sized,
    Reusable: ReusableSummaryProvider<ValueFlowFact> + ?Sized,
{
    if procedure != plan.root() && !plan.has_snapshot(procedure) {
        return Err(ValueFlowSolveError::RootMismatch);
    }
    if plan.has_contextual_bindings() {
        return Err(ValueFlowSolveError::CallContextRequired);
    }
    let problem = ValueFlowProblem::new(plan);
    let explicit_entry = (entry_fact != ValueFlowFact::zero()).then_some(entry_fact);
    let result = solve_with_reusable_end_summaries(
        SummarySolveInput::new(procedure, explicit_entry.as_slice()),
        provider,
        &problem,
        reusable,
        semantic_budget,
        request,
    )?;
    ValueFlowSummaryResult::from_result(plan, result)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueFlowSolveError {
    RootMismatch,
    CallContextRequired,
    CaptureProjectionCancelled,
    CaptureProjectionBudgetExceeded(SolverBudgetExceeded),
    InvalidResult,
    Summary(SummaryDataflowError),
    Snapshot(crate::dataflow::DataflowError),
}

impl ValueFlowSolveError {
    pub(crate) const fn mandatory_summary_cut_miss(&self) -> Option<&ProcedureHandle> {
        match self {
            Self::Summary(SummaryDataflowError::MandatorySummaryCutMiss { procedure }) => {
                Some(procedure)
            }
            Self::RootMismatch
            | Self::CallContextRequired
            | Self::InvalidResult
            | Self::Summary(_)
            | Self::Snapshot(_)
            | Self::CaptureProjectionCancelled
            | Self::CaptureProjectionBudgetExceeded(_) => None,
        }
    }
}

impl fmt::Display for ValueFlowSolveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CaptureProjectionCancelled => {
                formatter.write_str("callback capture projection cancelled")
            }
            Self::CaptureProjectionBudgetExceeded(error) => error.fmt(formatter),
            Self::CallContextRequired => {
                formatter.write_str("contextual call bindings require contextual summary execution")
            }
            Self::RootMismatch => formatter.write_str("value-flow root does not match the plan"),
            Self::InvalidResult => {
                formatter.write_str("value-flow result contains an invalid fact")
            }
            Self::Summary(error) => error.fmt(formatter),
            Self::Snapshot(error) => error.fmt(formatter),
        }
    }
}

impl Error for ValueFlowSolveError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Summary(error) => Some(error),
            Self::Snapshot(error) => Some(error),
            Self::CaptureProjectionBudgetExceeded(error) => Some(error),
            Self::RootMismatch
            | Self::CallContextRequired
            | Self::CaptureProjectionCancelled
            | Self::InvalidResult => None,
        }
    }
}

impl From<SummaryDataflowError> for ValueFlowSolveError {
    fn from(error: SummaryDataflowError) -> Self {
        Self::Summary(error)
    }
}

/// Whether a point-local rule replaces, rather than joins, the facts at its
/// target carrier. The rule is defined once in
/// `brokk_bifrost_analysis::analyzer::semantic::partial_flow::rules`.
pub(crate) fn kills_target(rule: &super::plan::LocalRuleView) -> bool {
    brokk_bifrost_analysis::analyzer::semantic::partial_flow::rules::kills_target(
        rule.kind,
        rule.source != rule.target,
        rule.strong_update,
        rule.direct_cell_overwrite,
    )
}

/// Whether a by-value relation consumes the value held by its source. The rule
/// is defined once in
/// `brokk_bifrost_analysis::analyzer::semantic::partial_flow::rules`.
pub(crate) fn invalidates_source(rule: &super::plan::LocalRuleView) -> bool {
    brokk_bifrost_analysis::analyzer::semantic::partial_flow::rules::invalidates_source(
        rule.transfer,
    )
}

pub(super) fn quality_uncertainty(
    proof: &ProofStatus,
    completeness: &EvidenceCompleteness,
) -> ValueFlowUncertainty {
    if matches!(proof, ProofStatus::Proven)
        && matches!(completeness, EvidenceCompleteness::Complete)
    {
        ValueFlowUncertainty(0)
    } else {
        ValueFlowUncertainty(0).with_semantic()
    }
}

impl From<CaptureProjectionError> for ValueFlowSolveError {
    fn from(error: CaptureProjectionError) -> Self {
        match error {
            CaptureProjectionError::Cancelled => Self::CaptureProjectionCancelled,
            CaptureProjectionError::ExceededBudget(error) => {
                Self::CaptureProjectionBudgetExceeded(error)
            }
        }
    }
}

impl From<crate::dataflow::DataflowError> for ValueFlowSolveError {
    fn from(error: crate::dataflow::DataflowError) -> Self {
        Self::Snapshot(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic::{
        CancellationToken, EvidenceCompleteness, MoveInvalidation, SemanticRequest,
        SemanticValueKind, TransferKind, TransferOperation, ValueTransfer,
    };
    use crate::analyzer::{AnalyzerConfig, Language};
    use crate::inline_project::InlineTestProject;
    use crate::value_flow::{
        ValueFlowCarrier, ValueFlowEventKey, ValueFlowEventKind, ValueFlowObservationPhase,
        ValueFlowSourceSpec,
    };
    use brokk_bifrost_test_macros::hardwon;

    fn carrier(index: usize) -> ValueFlowCarrierId {
        ValueFlowCarrierId::try_from_index(index).expect("carrier id")
    }

    fn active_at(index: usize) -> ActiveFlow {
        ActiveFlow {
            source: ValueFlowSourceId::try_from_index(0).expect("source id"),
            carrier: carrier(index),
            uncertainty: ValueFlowUncertainty::empty(),
        }
    }

    fn transfer_rule(kind: TransferKind) -> super::super::plan::LocalRuleView {
        super::super::plan::LocalRuleView {
            event_index: 0,
            source: carrier(0),
            target: carrier(1),
            kind: ValueFlowRelationKind::Assignment,
            transfer: Some(ValueTransfer {
                kind,
                operation: TransferOperation::None,
            }),
            complete: true,
            policy_local: false,
            strong_update: false,
            direct_cell_overwrite: false,
        }
    }

    #[test]
    fn copy_preserves_source_while_move_invalidates_it_after_generation() {
        let mut copied = HashSet::from([active_at(0)]);
        apply_local_rule(&mut copied, transfer_rule(TransferKind::Copy));
        assert_eq!(
            copied
                .iter()
                .map(|flow| flow.carrier.get())
                .collect::<std::collections::BTreeSet<_>>(),
            std::collections::BTreeSet::from([0, 1])
        );

        let mut moved = HashSet::from([active_at(0)]);
        apply_local_rule(
            &mut moved,
            transfer_rule(TransferKind::Move {
                invalidation: MoveInvalidation::Invalidated,
            }),
        );
        assert_eq!(
            moved
                .iter()
                .map(|flow| flow.carrier.get())
                .collect::<std::collections::BTreeSet<_>>(),
            std::collections::BTreeSet::from([1])
        );

        let mut later_use = transfer_rule(TransferKind::Copy);
        later_use.target = carrier(2);
        apply_local_rule(&mut moved, later_use);
        assert_eq!(
            moved
                .iter()
                .map(|flow| flow.carrier.get())
                .collect::<std::collections::BTreeSet<_>>(),
            std::collections::BTreeSet::from([1]),
            "a later read of the invalidated source must not regenerate flow"
        );

        let mut unknown_move = HashSet::from([active_at(0)]);
        apply_local_rule(
            &mut unknown_move,
            transfer_rule(TransferKind::Move {
                invalidation: MoveInvalidation::Unknown,
            }),
        );
        assert_eq!(
            unknown_move
                .iter()
                .map(|flow| flow.carrier.get())
                .collect::<std::collections::BTreeSet<_>>(),
            std::collections::BTreeSet::from([0, 1]),
            "an unknown invalidation cannot prove the source value was killed"
        );
    }

    #[test]
    #[hardwon(
        "#3131: A conditional unknown source activates only when its exact trigger source reaches the same carrier and keeps that source's uncertainty."
    )]
    fn conditional_source_requires_matching_source_on_same_carrier() {
        let matching = ActiveFlow {
            source: ValueFlowSourceId::try_from_index(1).expect("source id"),
            carrier: carrier(0),
            uncertainty: ValueFlowUncertainty::empty().with_semantic(),
        };
        let unrelated_source = ActiveFlow {
            source: ValueFlowSourceId::try_from_index(2).expect("source id"),
            ..matching
        };
        let unrelated_carrier = ActiveFlow {
            carrier: carrier(3),
            ..matching
        };
        let active = [matching, unrelated_source, unrelated_carrier];
        let generated = conditional_source_flows(
            ValueFlowSourceId::try_from_index(4).expect("source id"),
            carrier(0),
            &[ValueFlowSourceId::try_from_index(1).expect("source id")],
            active,
            &ProofStatus::Proven,
            &EvidenceCompleteness::Complete,
        );
        assert_eq!(generated.len(), 1);
        assert_eq!(generated[0].source.get(), 4);
        assert_eq!(generated[0].carrier.get(), 0);
        assert_eq!(generated[0].uncertainty, matching.uncertainty);
    }

    #[test]
    fn conditional_sources_are_forward_only_and_never_zero_seeded() {
        let project = InlineTestProject::with_language(Language::Go)
            .file(
                "flow.go",
                "package fixture\nfunc run(value string) string { return value }\n",
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut budget = crate::analyzer::semantic::SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &project.file("flow.go"),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("fixture semantics materialize")
            .available_value()
            .cloned()
            .expect("fixture semantics remain available");
        let root = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("run")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("fixture declares run");
        // The conditional sources ride a carrier other than the parameter's
        // port. A formal's only carrier is its port, so this is a value that is
        // not a formal.
        let local = root
            .semantics()
            .values()
            .iter()
            .find(|value| {
                !matches!(
                    value.kind,
                    SemanticValueKind::Parameter { .. } | SemanticValueKind::Receiver { .. }
                )
            })
            .expect("fixture has a value that is not a formal")
            .id;
        let value_carrier = ValueFlowCarrier::for_value(
            root.value_handle(local).expect("local value remains live"),
        );
        let other_carrier = ValueFlowCarrier::Port(
            crate::analyzer::semantic::ProcedurePortHandle::parameter(root.clone(), 0)
                .expect("parameter port remains live"),
        );
        let entry = root
            .point_handle(root.semantics().entry_point())
            .expect("entry point remains live");
        let exit = root
            .point_handle(root.semantics().normal_exit_point())
            .expect("normal exit remains live");
        let trigger_key = ValueFlowEventKey::at_point(&entry, 0, ValueFlowEventKind::Source)
            .expect("trigger key");
        let unrelated_key = ValueFlowEventKey::at_point(&entry, 1, ValueFlowEventKind::Source)
            .expect("unrelated key");
        let before_key = ValueFlowEventKey::at_point(&exit, 2, ValueFlowEventKind::Source)
            .expect("before-effects key");
        let after_key = ValueFlowEventKey::at_point(&exit, 3, ValueFlowEventKind::Source)
            .expect("after-effects key");
        let trigger = ValueFlowSourceSpec::new(
            trigger_key.clone(),
            entry.clone(),
            ValueFlowObservationPhase::BeforeEffects,
            value_carrier.clone(),
            ProofStatus::Proven,
            EvidenceCompleteness::Complete,
        );
        let unrelated = ValueFlowSourceSpec::new(
            unrelated_key.clone(),
            entry,
            ValueFlowObservationPhase::BeforeEffects,
            other_carrier,
            ProofStatus::Proven,
            EvidenceCompleteness::Complete,
        );
        let mut sources = super::super::ValueFlowSources::from(vec![unrelated, trigger]);
        let trigger_id = sources.id_for_key(&trigger_key).expect("seeded trigger");
        let triggers = sources.intern_list(vec![trigger_id]);
        let before = ValueFlowSourceSpec::new(
            before_key,
            exit.clone(),
            ValueFlowObservationPhase::BeforeEffects,
            value_carrier.clone(),
            ProofStatus::Proven,
            EvidenceCompleteness::Complete,
        )
        .when_sources_reach(triggers);
        let after = ValueFlowSourceSpec::new(
            after_key,
            exit.clone(),
            ValueFlowObservationPhase::AfterEffects,
            value_carrier,
            ProofStatus::Proven,
            EvidenceCompleteness::Complete,
        )
        .when_sources_reach(triggers);
        sources.push(before);
        sources.push(after);
        let plan = ValueFlowPlan::try_new(root, Vec::new(), Vec::new(), sources, Vec::new())
            .expect("conditional source plan");
        let problem = ValueFlowProblem::new(&plan);
        let before_id = plan
            .sources()
            .find(|(_, spec)| {
                spec.phase() == ValueFlowObservationPhase::BeforeEffects
                    && spec.activation_triggers().is_some()
            })
            .map(|(id, _)| id)
            .expect("before conditional source");
        let after_id = plan
            .sources()
            .find(|(_, spec)| {
                spec.phase() == ValueFlowObservationPhase::AfterEffects
                    && spec.activation_triggers().is_some()
            })
            .map(|(id, _)| id)
            .expect("after conditional source");
        let trigger_id = plan
            .source_id_for_key(&trigger_key)
            .expect("trigger source");
        let unrelated_id = plan
            .source_id_for_key(&unrelated_key)
            .expect("unrelated source");
        let value_carrier_id = plan
            .carrier_id_for_key(
                &ValueFlowCarrier::for_value(
                    plan.root()
                        .value_handle(local)
                        .expect("local value remains live"),
                )
                .stable_key()
                .expect("value carrier key"),
            )
            .expect("value carrier id");
        let unrelated_carrier_id = plan
            .carrier_id_for_key(
                &ValueFlowCarrier::Port(
                    crate::analyzer::semantic::ProcedurePortHandle::parameter(
                        plan.root().clone(),
                        0,
                    )
                    .expect("parameter port remains live"),
                )
                .stable_key()
                .expect("port carrier key"),
            )
            .expect("port carrier id");
        assert!(
            plan.has_edge_kills(),
            "conditional plans require forward solving"
        );
        let zero = problem.apply_point(&exit, ValueFlowFact::ZERO, &mut Vec::new());
        assert!(
            zero.iter()
                .all(|flow| flow.source != before_id && flow.source != after_id)
        );
        let unmatched = problem.apply_point(
            &plan
                .root()
                .point_handle(plan.root().semantics().normal_exit_point())
                .expect("normal exit remains live"),
            ValueFlowFact::carrier_fact(
                unrelated_id,
                unrelated_carrier_id,
                ValueFlowUncertainty::empty(),
            ),
            &mut Vec::new(),
        );
        assert!(
            unmatched
                .iter()
                .all(|flow| flow.source != before_id && flow.source != after_id)
        );
        let mut meetings = Vec::new();
        let matched = problem.apply_point(
            &plan
                .root()
                .point_handle(plan.root().semantics().normal_exit_point())
                .expect("normal exit remains live"),
            ValueFlowFact::carrier_fact(
                trigger_id,
                value_carrier_id,
                ValueFlowUncertainty::empty(),
            ),
            &mut meetings,
        );
        assert!(matched.iter().any(|flow| flow.source == before_id));
        assert!(matched.iter().any(|flow| flow.source == after_id));
    }
}
