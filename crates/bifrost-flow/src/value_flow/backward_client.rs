//! Demand-directed value-flow analysis over the bounded backward ICFG runner.
//!
//! The backward client is deliberately a separate transfer relation. Reversing
//! the graph and reusing the forward callback would make strong updates and
//! call/return bindings unsound: those operations need explicit preimages.

use std::{error::Error, fmt};

use crate::analyzer::semantic::{
    EvidenceCompleteness, IcfgEdgeKind, IcfgProvider, IcfgSnapshotLimits, ProcedureHandle,
    ProgramPointHandle, ProofStatus, SemanticBudget, ValueFlowRelationKind,
};
use crate::dataflow::{
    BackwardDistributiveDataflowProblem, BackwardSnapshotDataflowError,
    BackwardSnapshotDataflowResult, BackwardSnapshotDemand, BackwardSnapshotProblem, DataflowEdge,
    DataflowOutput, DataflowRequest, IcfgSolveInput, PathQualityFrontier, SolverTermination,
};

use super::plan::{CallFlowRuleKind as PlanCallFlowRuleKind, LocalRuleView};
use super::{
    ValueFlowCarrierId, ValueFlowPlan, ValueFlowSinkId, ValueFlowSourceId, ValueFlowUncertainty,
};

/// The phase at which a backward demand is currently located.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BackwardValueFlowPhase {
    BeforeEffects,
    AfterEffects,
}

impl From<super::ValueFlowObservationPhase> for BackwardValueFlowPhase {
    fn from(phase: super::ValueFlowObservationPhase) -> Self {
        match phase {
            super::ValueFlowObservationPhase::BeforeEffects => Self::BeforeEffects,
            super::ValueFlowObservationPhase::AfterEffects => Self::AfterEffects,
        }
    }
}

/// A backward value-flow fact retains the sink being explained while its
/// carrier is moved toward possible sources. Meeting facts are terminal
/// observations and are never treated as carrier demands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BackwardValueFlowFact {
    Zero,
    Demand {
        sink: ValueFlowSinkId,
        carrier: ValueFlowCarrierId,
        phase: BackwardValueFlowPhase,
        uncertainty: ValueFlowUncertainty,
    },
    Meeting {
        source: ValueFlowSourceId,
        sink: ValueFlowSinkId,
        uncertainty: ValueFlowUncertainty,
    },
}

impl BackwardValueFlowFact {
    pub const fn source(self) -> Option<ValueFlowSourceId> {
        match self {
            Self::Meeting { source, .. } => Some(source),
            Self::Zero | Self::Demand { .. } => None,
        }
    }

    pub const fn sink(self) -> Option<ValueFlowSinkId> {
        match self {
            Self::Demand { sink, .. } | Self::Meeting { sink, .. } => Some(sink),
            Self::Zero => None,
        }
    }

    pub const fn carrier(self) -> Option<ValueFlowCarrierId> {
        match self {
            Self::Demand { carrier, .. } => Some(carrier),
            Self::Zero | Self::Meeting { .. } => None,
        }
    }

    pub const fn phase(self) -> Option<BackwardValueFlowPhase> {
        match self {
            Self::Demand { phase, .. } => Some(phase),
            Self::Zero | Self::Meeting { .. } => None,
        }
    }

    pub const fn uncertainty(self) -> ValueFlowUncertainty {
        match self {
            Self::Demand { uncertainty, .. } | Self::Meeting { uncertainty, .. } => uncertainty,
            Self::Zero => ValueFlowUncertainty::empty(),
        }
    }
}

/// One backward value-flow meeting. Unlike forward summary meetings it has no
/// summary-entry identity: the bounded snapshot result owns the context-local
/// reached row instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackwardValueFlowMeeting {
    source: ValueFlowSourceId,
    sink: ValueFlowSinkId,
    point: ProgramPointHandle,
    path_qualities: PathQualityFrontier,
    uncertainty: ValueFlowUncertainty,
}

impl BackwardValueFlowMeeting {
    pub const fn source(&self) -> ValueFlowSourceId {
        self.source
    }

    pub const fn sink(&self) -> ValueFlowSinkId {
        self.sink
    }

    pub const fn point(&self) -> &ProgramPointHandle {
        &self.point
    }

    pub const fn path_qualities(&self) -> PathQualityFrontier {
        self.path_qualities
    }

    pub const fn is_uncertain(&self) -> bool {
        !self.uncertainty.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackwardValueFlowSinkOutcome<'result> {
    Reached(Box<[&'result BackwardValueFlowMeeting]>),
    NotReached,
    Inconclusive,
}

/// Result of one explicit backward value-flow solve.
#[derive(Debug, Clone)]
pub struct BackwardValueFlowResult {
    result: BackwardSnapshotDataflowResult<BackwardValueFlowFact>,
    meetings: Box<[BackwardValueFlowMeeting]>,
}

impl BackwardValueFlowResult {
    fn from_result(
        plan: &ValueFlowPlan,
        result: BackwardSnapshotDataflowResult<BackwardValueFlowFact>,
    ) -> Result<Self, BackwardValueFlowSolveError> {
        let mut meetings = Vec::new();
        for reached in result.reached() {
            let Some(fact) = result.fact(reached.fact()).copied() else {
                return Err(BackwardValueFlowSolveError::InvalidResult);
            };
            let BackwardValueFlowFact::Meeting {
                source,
                sink,
                uncertainty,
            } = fact
            else {
                continue;
            };
            if plan.source(source).is_none() || plan.sink(sink).is_none() {
                return Err(BackwardValueFlowSolveError::InvalidResult);
            }
            let point = result
                .snapshot()
                .node(reached.node())
                .ok_or(BackwardValueFlowSolveError::InvalidResult)?
                .point()
                .clone();
            meetings.push(BackwardValueFlowMeeting {
                source,
                sink,
                point,
                path_qualities: reached.path_qualities(),
                uncertainty,
            });
        }
        meetings.sort_by(|left, right| {
            (left.sink, left.source, left.point.durable_key()).cmp(&(
                right.sink,
                right.source,
                right.point.durable_key(),
            ))
        });
        meetings.dedup();
        Ok(Self {
            result,
            meetings: meetings.into_boxed_slice(),
        })
    }

    pub const fn result(&self) -> &BackwardSnapshotDataflowResult<BackwardValueFlowFact> {
        &self.result
    }

    pub fn meetings(&self) -> &[BackwardValueFlowMeeting] {
        &self.meetings
    }

    pub fn sink_outcome(&self, sink: ValueFlowSinkId) -> BackwardValueFlowSinkOutcome<'_> {
        let meetings = self
            .meetings
            .iter()
            .filter(|meeting| meeting.sink == sink)
            .collect::<Vec<_>>();
        if !meetings.is_empty() {
            BackwardValueFlowSinkOutcome::Reached(meetings.into_boxed_slice())
        } else if self.is_complete() {
            BackwardValueFlowSinkOutcome::NotReached
        } else {
            BackwardValueFlowSinkOutcome::Inconclusive
        }
    }

    pub fn is_complete(&self) -> bool {
        self.result.is_complete()
    }

    pub const fn termination(&self) -> SolverTermination {
        self.result.termination()
    }
}

struct BackwardValueFlowProblem<'plan> {
    plan: &'plan ValueFlowPlan,
}

impl<'plan> BackwardValueFlowProblem<'plan> {
    const fn new(plan: &'plan ValueFlowPlan) -> Self {
        Self { plan }
    }

    fn append_source_meetings(
        &self,
        point: &ProgramPointHandle,
        phase: BackwardValueFlowPhase,
        demand: Demand,
        out: &mut dyn DataflowOutput<BackwardValueFlowFact>,
    ) -> bool {
        for meeting in self.source_meetings(point, phase, demand) {
            if !out.emit(meeting) {
                return false;
            }
        }
        true
    }

    fn source_meetings(
        &self,
        point: &ProgramPointHandle,
        phase: BackwardValueFlowPhase,
        demand: Demand,
    ) -> Vec<BackwardValueFlowFact> {
        let mut meetings = Vec::new();
        let phase = phase.into_observation();
        for source in self.plan.sources_at(point, phase) {
            if source.carrier != demand.carrier {
                continue;
            }
            let uncertainty = demand
                .uncertainty
                .with_quality(source.spec.proof(), source.spec.completeness());
            meetings.push(BackwardValueFlowFact::Meeting {
                source: source.id,
                sink: demand.sink,
                uncertainty,
            });
        }
        meetings
    }

    fn inverse_local(&self, point: &ProgramPointHandle, demand: Demand, out: &mut Vec<Demand>) {
        let rules = self
            .plan
            .local_rule_views_reverse_at(point)
            .collect::<Vec<_>>();
        inverse_local_demands(demand, &rules, out);
    }

    fn inverse_call(
        &self,
        edge: DataflowEdge<'_, BackwardValueFlowFact>,
        demand: Demand,
        out: &mut Vec<Demand>,
    ) {
        let Some(call) = edge.origin() else {
            return;
        };
        let callee = edge.target().procedure();
        if self.plan.is_callee_port(demand.carrier, callee) {
            out.push(demand);
        }
        for rule in
            self.plan
                .call_rules_to_target(call, callee, PlanCallFlowRuleKind::Call, demand.carrier)
        {
            out.push(Demand {
                carrier: rule.source,
                uncertainty: demand
                    .uncertainty
                    .with_quality(&rule.proof, &rule.completeness),
                ..demand
            });
        }
    }

    fn inverse_return(
        &self,
        edge: DataflowEdge<'_, BackwardValueFlowFact>,
        demand: Demand,
        out: &mut Vec<Demand>,
    ) {
        let Some(call) = edge.origin() else {
            return;
        };
        let kind = match edge.kind() {
            IcfgEdgeKind::NormalReturn => PlanCallFlowRuleKind::NormalReturn,
            IcfgEdgeKind::ExceptionalReturn => PlanCallFlowRuleKind::ExceptionalReturn,
            _ => return,
        };
        let callee = edge.source().procedure();
        for rule in self
            .plan
            .call_rules_to_target(call, callee, kind, demand.carrier)
        {
            out.push(Demand {
                carrier: rule.source,
                uncertainty: demand
                    .uncertainty
                    .with_quality(&rule.proof, &rule.completeness),
                ..demand
            });
        }
    }

    fn inverse_boundary(
        &self,
        edge: DataflowEdge<'_, BackwardValueFlowFact>,
        demand: Demand,
        out: &mut Vec<Demand>,
    ) {
        let Some(call) = edge.origin() else {
            out.push(demand);
            return;
        };
        // Boundary transfers are structured semantic relations. Enumerating
        // the bounded carrier universe is intentionally conservative but does
        // not fall back to source text or a reversed CFG edge.
        for (index, _) in self.plan.carriers().iter().enumerate() {
            let Some(input) = ValueFlowCarrierId::try_from_index(index).ok() else {
                continue;
            };
            let mut matched = false;
            let application = self.plan.visit_boundary_transfers(
                call,
                edge.boundary(),
                edge.kind(),
                input,
                |transfer| {
                    if transfer.target == demand.carrier {
                        matched = true;
                    }
                    true
                },
            );
            if matched {
                out.push(Demand {
                    carrier: input,
                    uncertainty: if application.modeled {
                        demand.uncertainty
                    } else {
                        demand.uncertainty.with_semantic()
                    },
                    ..demand
                });
            }
            // The caller-side continuation always preserves the incoming
            // carrier unless RequireModel abstains, in which case that
            // preserved fact is retained but marked uncertain.
            if input == demand.carrier {
                out.push(Demand {
                    uncertainty: if application.abstained {
                        demand.uncertainty.with_semantic()
                    } else {
                        demand.uncertainty
                    },
                    ..demand
                });
            }
        }
    }

    fn inverse_edge(
        &self,
        edge: DataflowEdge<'_, BackwardValueFlowFact>,
        demand: Demand,
        out: &mut Vec<Demand>,
    ) {
        match edge.kind() {
            IcfgEdgeKind::Intraprocedural(_) => out.push(demand),
            IcfgEdgeKind::Call => self.inverse_call(edge, demand, out),
            IcfgEdgeKind::NormalReturn | IcfgEdgeKind::ExceptionalReturn => {
                self.inverse_return(edge, demand, out)
            }
            IcfgEdgeKind::CallToNormalContinuation
            | IcfgEdgeKind::CallToExceptionalContinuation => {
                self.inverse_boundary(edge, demand, out)
            }
        }
    }

    fn predecessor_flow(
        &self,
        edge: DataflowEdge<'_, BackwardValueFlowFact>,
        output_fact: BackwardValueFlowFact,
        out: &mut dyn DataflowOutput<BackwardValueFlowFact>,
    ) {
        let BackwardValueFlowFact::Demand {
            sink,
            carrier,
            phase,
            uncertainty,
        } = output_fact
        else {
            return;
        };
        let mut target_demands = Vec::new();
        let target = Demand {
            sink,
            carrier,
            phase,
            uncertainty,
        };
        // A queued demand is the state at the target point. For an after-
        // effects observation, first undo the target point before crossing
        // its incoming edge. This also lets a source and sink share a point.
        if phase == BackwardValueFlowPhase::AfterEffects {
            if !self.append_source_meetings(edge.target(), phase, target, out) {
                return;
            }
            self.inverse_local(edge.target(), target, &mut target_demands);
            for demand in &mut target_demands {
                demand.phase = BackwardValueFlowPhase::BeforeEffects;
                if !self.append_source_meetings(
                    edge.target(),
                    BackwardValueFlowPhase::BeforeEffects,
                    *demand,
                    out,
                ) {
                    return;
                }
            }
        } else {
            if !self.append_source_meetings(edge.target(), phase, target, out) {
                return;
            }
            target_demands.push(target);
        }

        for target_demand in target_demands {
            let mut after_source = Vec::new();
            self.inverse_edge(
                edge,
                Demand {
                    phase: BackwardValueFlowPhase::AfterEffects,
                    ..target_demand
                },
                &mut after_source,
            );
            for demand in after_source {
                if !self.append_source_meetings(edge.source(), demand.phase, demand, out) {
                    return;
                }
                let mut before_source = Vec::new();
                self.inverse_local(edge.source(), demand, &mut before_source);
                for demand in before_source {
                    if !self.append_source_meetings(
                        edge.source(),
                        BackwardValueFlowPhase::BeforeEffects,
                        demand,
                        out,
                    ) {
                        return;
                    }
                    if !out.emit(BackwardValueFlowFact::Demand {
                        sink: demand.sink,
                        carrier: demand.carrier,
                        phase: BackwardValueFlowPhase::BeforeEffects,
                        uncertainty: demand.uncertainty,
                    }) {
                        return;
                    }
                }
            }
        }
    }
}

/// Compute the preimage of one demand through all local rules at a point.
/// `rules` must be in reverse event order. Keeping this relation independent
/// from the plan makes its chained-carrier behavior directly testable.
fn inverse_local_demands(demand: Demand, rules: &[LocalRuleView], out: &mut Vec<Demand>) {
    let mut current = vec![demand];
    for rule in rules {
        let mut next = Vec::with_capacity(current.len().saturating_add(1));
        for candidate in current.drain(..) {
            if candidate.carrier != rule.target {
                next.push(candidate);
                continue;
            }
            next.push(Demand {
                carrier: rule.source,
                uncertainty: candidate.uncertainty.with_complete(rule.complete),
                ..candidate
            });
            // A strong update removes the previous value at the target. A
            // weak update retains that old value as another possible preimage.
            if is_weak_update(rule) {
                next.push(candidate);
            }
        }
        current = next;
    }
    current.sort_unstable();
    current.dedup();
    out.extend(current);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Demand {
    sink: ValueFlowSinkId,
    carrier: ValueFlowCarrierId,
    phase: BackwardValueFlowPhase,
    uncertainty: ValueFlowUncertainty,
}

impl BackwardValueFlowPhase {
    const fn into_observation(self) -> super::ValueFlowObservationPhase {
        match self {
            Self::BeforeEffects => super::ValueFlowObservationPhase::BeforeEffects,
            Self::AfterEffects => super::ValueFlowObservationPhase::AfterEffects,
        }
    }
}

impl BackwardDistributiveDataflowProblem for BackwardValueFlowProblem<'_> {
    type Fact = BackwardValueFlowFact;

    fn zero_fact(&self) -> Self::Fact {
        BackwardValueFlowFact::Zero
    }

    /// The forward client takes the caller-side continuation of a resolved
    /// call, so the preimage relation must take it too, or a carrier the
    /// callee neither receives nor returns has no backward path past the call
    /// and the two directions disagree on every pair that spans one (#2782).
    fn resolved_call_to_return(&self) -> bool {
        true
    }

    fn normal_predecessor_flow(
        &self,
        edge: DataflowEdge<'_, Self::Fact>,
        output_fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.predecessor_flow(edge, output_fact, out);
    }

    fn call_predecessor_flow(
        &self,
        edge: DataflowEdge<'_, Self::Fact>,
        output_fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.predecessor_flow(edge, output_fact, out);
    }

    fn return_predecessor_flow(
        &self,
        edge: DataflowEdge<'_, Self::Fact>,
        output_fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.predecessor_flow(edge, output_fact, out);
    }

    fn call_to_return_predecessor_flow(
        &self,
        edge: DataflowEdge<'_, Self::Fact>,
        output_fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.predecessor_flow(edge, output_fact, out);
    }

    fn exceptional_predecessor_flow(
        &self,
        edge: DataflowEdge<'_, Self::Fact>,
        output_fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.predecessor_flow(edge, output_fact, out);
    }
}

impl BackwardSnapshotProblem for BackwardValueFlowProblem<'_> {
    fn demands(&self, out: &mut dyn DataflowOutput<BackwardSnapshotDemand<Self::Fact>>) {
        for (sink, spec) in self.plan.sinks() {
            let demand = Demand {
                sink,
                carrier: self
                    .plan
                    .carrier_id(spec.carrier())
                    .expect("plan sink carrier is bound"),
                phase: spec.phase().into(),
                uncertainty: quality_uncertainty(spec.proof(), spec.completeness()),
            };
            for meeting in self.source_meetings(spec.point(), demand.phase, demand) {
                if !out.emit(BackwardSnapshotDemand::new(spec.point().clone(), meeting)) {
                    return;
                }
            }
            let mut initial = Vec::new();
            if demand.phase == BackwardValueFlowPhase::AfterEffects {
                self.inverse_local(spec.point(), demand, &mut initial);
            } else {
                initial.push(demand);
            }
            for demand in initial {
                let demand = Demand {
                    phase: BackwardValueFlowPhase::BeforeEffects,
                    ..demand
                };
                for meeting in self.source_meetings(
                    spec.point(),
                    BackwardValueFlowPhase::BeforeEffects,
                    demand,
                ) {
                    if !out.emit(BackwardSnapshotDemand::new(spec.point().clone(), meeting)) {
                        return;
                    }
                }
                if !out.emit(BackwardSnapshotDemand::new(
                    spec.point().clone(),
                    BackwardValueFlowFact::Demand {
                        sink: demand.sink,
                        carrier: demand.carrier,
                        phase: demand.phase,
                        uncertainty: demand.uncertainty,
                    },
                )) {
                    return;
                }
            }
        }
    }
}

fn is_weak_update(rule: &LocalRuleView) -> bool {
    match rule.kind {
        ValueFlowRelationKind::Assignment => rule.source == rule.target,
        ValueFlowRelationKind::MemoryStore => !rule.strong_update,
        _ => true,
    }
}

fn quality_uncertainty(
    proof: &ProofStatus,
    completeness: &EvidenceCompleteness,
) -> ValueFlowUncertainty {
    if matches!(proof, ProofStatus::Proven)
        && matches!(completeness, EvidenceCompleteness::Complete)
    {
        ValueFlowUncertainty::default()
    } else {
        ValueFlowUncertainty::default().with_semantic()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn demand(carrier: usize) -> Demand {
        Demand {
            sink: ValueFlowSinkId::try_from_index(0).expect("sink id"),
            carrier: ValueFlowCarrierId::try_from_index(carrier).expect("carrier id"),
            phase: BackwardValueFlowPhase::BeforeEffects,
            uncertainty: ValueFlowUncertainty::empty(),
        }
    }

    fn rule(
        source: usize,
        target: usize,
        kind: ValueFlowRelationKind,
        strong_update: bool,
    ) -> LocalRuleView {
        LocalRuleView {
            source: ValueFlowCarrierId::try_from_index(source).expect("source id"),
            target: ValueFlowCarrierId::try_from_index(target).expect("target id"),
            kind,
            transfer: None,
            complete: true,
            strong_update,
        }
    }

    #[test]
    fn backward_chained_rules_reach_the_original_carrier() {
        let rules = [
            rule(1, 2, ValueFlowRelationKind::Assignment, false),
            rule(0, 1, ValueFlowRelationKind::Assignment, false),
        ];
        let mut preimages = Vec::new();
        inverse_local_demands(demand(2), &rules, &mut preimages);
        assert_eq!(
            preimages
                .iter()
                .map(|demand| demand.carrier.get())
                .collect::<Vec<_>>(),
            [0]
        );
    }

    #[test]
    fn backward_strong_and_weak_updates_keep_exact_preimages() {
        let rules = [
            rule(1, 2, ValueFlowRelationKind::MemoryStore, false),
            rule(0, 2, ValueFlowRelationKind::MemoryStore, true),
        ];
        let mut preimages = Vec::new();
        inverse_local_demands(demand(2), &rules, &mut preimages);
        assert_eq!(
            preimages
                .iter()
                .map(|demand| demand.carrier.get())
                .collect::<Vec<_>>(),
            [0, 1]
        );
    }
}

pub fn solve_value_flow_backward_with_snapshot<Provider>(
    root: &ProcedureHandle,
    provider: &Provider,
    plan: &ValueFlowPlan,
    limits: IcfgSnapshotLimits,
    semantic_budget: &mut SemanticBudget,
    request: &mut DataflowRequest<'_>,
) -> Result<BackwardValueFlowResult, BackwardValueFlowSolveError>
where
    Provider: IcfgProvider + ?Sized,
{
    if root != plan.root() {
        return Err(BackwardValueFlowSolveError::RootMismatch);
    }
    if plan.has_edge_kills() {
        return Err(BackwardValueFlowSolveError::EdgeKillsUnsupported);
    }
    let problem = BackwardValueFlowProblem::new(plan);
    let result = crate::dataflow::solve_backward_with_snapshot(
        root,
        limits,
        provider,
        &problem,
        semantic_budget,
        request,
    )?;
    BackwardValueFlowResult::from_result(plan, result)
}

pub(crate) fn solve_value_flow_backward_on_input(
    plan: &ValueFlowPlan,
    input: IcfgSolveInput<'_>,
    semantic_work: crate::analyzer::semantic::SemanticWork,
    request: &mut DataflowRequest<'_>,
) -> Result<BackwardValueFlowResult, BackwardValueFlowSolveError> {
    if plan.has_edge_kills() {
        return Err(BackwardValueFlowSolveError::EdgeKillsUnsupported);
    }
    let problem = BackwardValueFlowProblem::new(plan);
    let result = crate::dataflow::solve_backward_demands_on_snapshot(
        input,
        &problem,
        semantic_work,
        request,
    )?;
    BackwardValueFlowResult::from_result(plan, result)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackwardValueFlowSolveError {
    RootMismatch,
    EdgeKillsUnsupported,
    InvalidResult,
    Snapshot(BackwardSnapshotDataflowError),
}

impl fmt::Display for BackwardValueFlowSolveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RootMismatch => formatter.write_str("value-flow root does not match the plan"),
            Self::EdgeKillsUnsupported => formatter
                .write_str("backward value flow does not support source-selective edge kills"),
            Self::InvalidResult => formatter.write_str("backward value-flow result is invalid"),
            Self::Snapshot(error) => error.fmt(formatter),
        }
    }
}

impl Error for BackwardValueFlowSolveError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Snapshot(error) => Some(error),
            Self::RootMismatch | Self::EdgeKillsUnsupported | Self::InvalidResult => None,
        }
    }
}

impl From<BackwardSnapshotDataflowError> for BackwardValueFlowSolveError {
    fn from(error: BackwardSnapshotDataflowError) -> Self {
        Self::Snapshot(error)
    }
}
