//! Demand-directed value-flow analysis over the bounded backward ICFG runner.
//!
//! The backward client is deliberately a separate transfer relation. Reversing
//! the graph and reusing the forward callback would make strong updates and
//! call/return bindings unsound: those operations need explicit preimages.

use std::{error::Error, fmt};

use crate::analyzer::semantic::{
    IcfgEdgeId, IcfgEdgeKind, IcfgProvider, IcfgSnapshot, IcfgSnapshotLimits, ProcedureHandle,
    ProgramPointHandle, SemanticBudget, SemanticRequest, ValueFlowRelationKind,
};
use crate::dataflow::{
    BackwardDistributiveDataflowProblem, BackwardSnapshotDataflowError,
    BackwardSnapshotDataflowResult, BackwardSnapshotDemand, BackwardSnapshotProblem, DataflowEdge,
    DataflowOutput, DataflowRequest, IcfgInputStatus, IcfgSolveInput, PathQualityFrontier,
    SolverBudgetExceeded, SolverTermination, SolverWork,
};

use super::client::quality_uncertainty;
use super::plan::{CallFlowRuleKind as PlanCallFlowRuleKind, LocalRuleView};
use super::{
    ValueFlowCarrierId, ValueFlowPlan, ValueFlowSinkId, ValueFlowSourceId, ValueFlowUncertainty,
};
use crate::hash::HashMap;

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
        self.uncertainty.is_uncertain()
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
    work: SolverWork,
    discovery_complete: bool,
}

impl BackwardValueFlowResult {
    fn from_result(
        plan: &ValueFlowPlan,
        result: BackwardSnapshotDataflowResult<BackwardValueFlowFact>,
        work: SolverWork,
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
            work,
            discovery_complete: plan.discovery_complete(),
        })
    }

    pub const fn result(&self) -> &BackwardSnapshotDataflowResult<BackwardValueFlowFact> {
        &self.result
    }

    /// Combined capture projection and propagation work for this solve.
    pub const fn work(&self) -> SolverWork {
        self.work
    }

    pub fn meetings(&self) -> &[BackwardValueFlowMeeting] {
        &self.meetings
    }

    pub fn is_complete(&self) -> bool {
        self.discovery_complete && self.result.is_complete()
    }

    pub const fn termination(&self) -> SolverTermination {
        self.result.termination()
    }
}

struct BackwardValueFlowProblem<'plan> {
    plan: &'plan ValueFlowPlan,
    capture_edges: HashMap<IcfgEdgeId, Vec<(ValueFlowCarrierId, ValueFlowCarrierId)>>,
}

impl<'plan> BackwardValueFlowProblem<'plan> {
    fn for_snapshot(
        plan: &'plan ValueFlowPlan,
        snapshot: &IcfgSnapshot,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Self, BackwardValueFlowSolveError> {
        Ok(Self {
            plan,
            capture_edges: super::client::argument_capture_edges(plan, snapshot, request)?,
        })
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
        for source in self
            .plan
            .sources_at(point, phase)
            .filter(|source| source.activation_triggers.is_none())
        {
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
        meetings: &mut Vec<BackwardValueFlowFact>,
    ) {
        let Some(call) = edge.origin() else {
            return;
        };
        let callee = edge.target().procedure();
        let capture_rules = edge
            .snapshot_edge()
            .and_then(|id| self.capture_edges.get(&id));
        let contextual_target = capture_rules
            .is_some_and(|rows| rows.iter().any(|(_, target)| *target == demand.carrier));
        if let Some(rows) = capture_rules {
            for (source, target) in rows {
                if *target == demand.carrier {
                    // Keep the capture boundary incomplete. This is live-cell
                    // transport, not a proof that all mutation/escape is known.
                    out.push(Demand {
                        carrier: *source,
                        uncertainty: demand.uncertainty.with_semantic(),
                        ..demand
                    });
                }
            }
        }
        let default_target = self
            .plan
            .call_rules_to_target(call, callee, PlanCallFlowRuleKind::Call, demand.carrier)
            .any(|rule| self.plan.is_default_argument_carrier(rule.source, callee));
        if self.plan.is_callee_port(demand.carrier, callee) && !default_target && !contextual_target
        {
            out.push(demand);
        }
        for rule in
            self.plan
                .call_rules_to_target(call, callee, PlanCallFlowRuleKind::Call, demand.carrier)
        {
            if self.plan.is_default_argument_carrier(rule.source, callee) {
                // The default value is owned by the callee, was saved at
                // definition time, and is exposed as a source at this entry.
                // There is no caller carrier to demand; terminate at the
                // exact entry source instead of carrying the saved value
                // backwards across the call boundary.
                for phase in [
                    super::ValueFlowObservationPhase::BeforeEffects,
                    super::ValueFlowObservationPhase::AfterEffects,
                ] {
                    for source in self.plan.sources_at(edge.target(), phase).filter(|source| {
                        source.carrier == rule.source && source.activation_triggers.is_none()
                    }) {
                        let uncertainty = demand
                            .uncertainty
                            .with_quality(&rule.proof, &rule.completeness)
                            .with_quality(source.spec.proof(), source.spec.completeness());
                        meetings.push(BackwardValueFlowFact::Meeting {
                            source: source.id,
                            sink: demand.sink,
                            uncertainty,
                        });
                    }
                }
                continue;
            }
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
        if let Some(rows) = edge
            .snapshot_edge()
            .and_then(|id| self.capture_edges.get(&id))
        {
            for (source, target) in rows {
                if demand.carrier == *target {
                    out.push(Demand {
                        carrier: *source,
                        uncertainty: demand.uncertainty.with_semantic(),
                        ..demand
                    });
                }
            }
        }
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
            let application = self.plan.visit_boundary_transfers(
                call,
                edge.boundary(),
                edge.kind(),
                edge.caller_conversion_may_run_user_code(),
                input,
                |transfer| {
                    if transfer.target == demand.carrier {
                        out.push(Demand {
                            carrier: input,
                            uncertainty: if transfer.proven_complete {
                                demand.uncertainty
                            } else {
                                demand.uncertainty.with_semantic()
                            },
                            ..demand
                        });
                    }
                    true
                },
            );
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
        meetings: &mut Vec<BackwardValueFlowFact>,
    ) {
        match edge.kind() {
            IcfgEdgeKind::Intraprocedural(_) => out.push(demand),
            IcfgEdgeKind::Call => self.inverse_call(edge, demand, out, meetings),
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
            let mut terminal_meetings = Vec::new();
            self.inverse_edge(
                edge,
                Demand {
                    phase: BackwardValueFlowPhase::AfterEffects,
                    ..target_demand
                },
                &mut after_source,
                &mut terminal_meetings,
            );
            for meeting in terminal_meetings {
                if !out.emit(meeting) {
                    return;
                }
            }
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
            if super::client::invalidates_source(rule)
                && candidate.carrier == rule.source
                && candidate.carrier != rule.target
            {
                continue;
            }
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
    // Same-event alternatives into one target are simultaneous, so none of
    // them removes what another one demands. For a kind this walk treats as a
    // kill (an assignment, parameter or receiver between distinct carriers, a
    // strong store), the killing alternative is first in application order,
    // hence last in this reverse walk, and drops the target only after every
    // alternative has contributed its source. Every other kind, NormalReturn
    // included, is weak here and never drops demand: the backward preimage
    // can then be a superset of the forward answer, never a subset.
    if rule.joins_same_event_alternative {
        return true;
    }
    match rule.kind {
        ValueFlowRelationKind::Assignment
        | ValueFlowRelationKind::Parameter
        | ValueFlowRelationKind::Receiver => rule.source == rule.target,
        ValueFlowRelationKind::MemoryStore => !(rule.strong_update || rule.direct_cell_overwrite),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_analysis::analyzer::semantic::partial_flow::rules::{
        joins_same_event_alternatives, same_event_rule,
    };
    use brokk_bifrost_test_macros::hardwon;
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
            event_index: 0,
            source: ValueFlowCarrierId::try_from_index(source).expect("source id"),
            target: ValueFlowCarrierId::try_from_index(target).expect("target id"),
            kind,
            transfer: None,
            complete: true,
            policy_local: false,
            strong_update,
            direct_cell_overwrite: false,
            joins_same_event_alternative: false,
        }
    }

    fn invalidating_move_rule(source: usize, target: usize) -> LocalRuleView {
        LocalRuleView {
            transfer: Some(crate::analyzer::semantic::ValueTransfer {
                kind: crate::analyzer::semantic::TransferKind::Move {
                    invalidation: crate::analyzer::semantic::MoveInvalidation::Invalidated,
                },
                operation: crate::analyzer::semantic::TransferOperation::None,
            }),
            ..rule(source, target, ValueFlowRelationKind::Assignment, false)
        }
    }

    /// Apply `rules` (forward event order) to a set of carrier facts the way the
    /// forward client does: a killing rule drops the target's prior fact, and a
    /// rule whose source was live before the rule adds the target.
    fn forward_facts(rules: &[LocalRuleView], start: &[u32]) -> Vec<u32> {
        let mut facts = start.to_vec();
        for rule in rules {
            let had_source = facts.contains(&rule.source.get());
            if super::super::client::kills_target(rule) {
                facts.retain(|fact| *fact != rule.target.get());
            }
            if had_source && !facts.contains(&rule.target.get()) {
                facts.push(rule.target.get());
            }
        }
        facts.sort_unstable();
        facts
    }

    /// Flag a forward-ordered event the way the plan does: the shared helper
    /// decides each target's group from its kinds.
    fn mark_joins(rules: &mut [LocalRuleView]) {
        let event = rules
            .iter()
            .map(|rule| {
                same_event_rule(
                    rule.kind,
                    rule.source,
                    rule.target,
                    rule.strong_update,
                    rule.direct_cell_overwrite,
                )
            })
            .collect::<Vec<_>>();
        for (rule, joins) in rules.iter_mut().zip(joins_same_event_alternatives(&event)) {
            rule.joins_same_event_alternative = joins;
        }
    }

    /// Demand through `forward` (application order), the way the reverse walk
    /// takes it.
    fn backward_preimage(forward: &[LocalRuleView], from: usize) -> Vec<u32> {
        let reverse = forward.iter().rev().copied().collect::<Vec<_>>();
        let mut preimages = Vec::new();
        inverse_local_demands(demand(from), &reverse, &mut preimages);
        preimages
            .iter()
            .map(|demand| demand.carrier.get())
            .collect()
    }

    /// A container collapse at the assignment's event and target adds members
    /// to the assigned value; it does not preserve the old target. The
    /// assignment still kills, forward and backward, wherever the supplement
    /// sits in the event (the plan sorts it last).
    #[hardwon("#10539: a container-collapse supplement cancelled the assignment's kill")]
    #[test]
    fn collapse_supplement_does_not_cancel_the_assignment_kill() {
        // Y(1) is assigned to X(2); the collapse brings member M(0) into X.
        let mut forward = [
            rule(1, 2, ValueFlowRelationKind::Assignment, false),
            rule(0, 2, ValueFlowRelationKind::ContainerCollapse, false),
        ];
        mark_joins(&mut forward);
        // The old fact on X is gone, and both Y and M reach X.
        assert!(!forward_facts(&forward, &[2]).contains(&2));
        assert!(forward_facts(&forward, &[1]).contains(&2));
        assert!(forward_facts(&forward, &[0]).contains(&2));
        // Backward agrees: X's preimage is Y and M, and not X itself.
        assert_eq!(backward_preimage(&forward, 2), [0, 1]);
        // The assignment keeps its kill; the collapse joins.
        assert!(!forward[0].joins_same_event_alternative);
        assert!(forward[1].joins_same_event_alternative);
    }

    /// A lone rule that reads its own target joins: the new value includes the
    /// old one, so the target keeps its facts forward and backward.
    #[test]
    fn lone_self_sourced_strong_store_keeps_the_target_facts() {
        let mut forward = [rule(2, 2, ValueFlowRelationKind::MemoryStore, true)];
        mark_joins(&mut forward);
        assert!(forward[0].joins_same_event_alternative);
        assert_eq!(forward_facts(&forward, &[2]), [2]);
        assert_eq!(backward_preimage(&forward, 2), [2]);
    }

    #[hardwon("#10539: same-event strong alternatives into one target killed each other backward")]
    #[test]
    fn backward_demand_reaches_every_same_event_alternative() {
        // One event writes X(2) from Y(1) and from Z(0). The killer is first in
        // application order; the other alternative joins.
        let killer = rule(1, 2, ValueFlowRelationKind::Assignment, false);
        let joining = LocalRuleView {
            joins_same_event_alternative: true,
            ..rule(0, 2, ValueFlowRelationKind::Assignment, false)
        };
        let forward = [killer, joining];
        let reverse = [joining, killer];
        let mut preimages = Vec::new();
        inverse_local_demands(demand(2), &reverse, &mut preimages);
        let backward = preimages
            .iter()
            .map(|demand| demand.carrier.get())
            .collect::<Vec<_>>();
        assert_eq!(backward, [0, 1]);
        // Forward agrees: exactly the carriers in the preimage reach X, and the
        // prior fact on X does not survive the group's single kill.
        for start in 0..3u32 {
            assert_eq!(
                forward_facts(&forward, &[start]).contains(&2),
                backward.contains(&start),
                "start {start}"
            );
        }
    }

    /// The group is decided as a whole: with a weak alternative nothing kills,
    /// so the prior fact survives forward and the demand survives backward.
    #[test]
    fn backward_mixed_group_keeps_the_prior_demand_in_both_orders() {
        for weak_first in [false, true] {
            let weak = LocalRuleView {
                joins_same_event_alternative: true,
                ..rule(0, 2, ValueFlowRelationKind::MemoryStore, false)
            };
            let strong = LocalRuleView {
                joins_same_event_alternative: true,
                ..rule(1, 2, ValueFlowRelationKind::Assignment, false)
            };
            let forward = if weak_first {
                [weak, strong]
            } else {
                [strong, weak]
            };
            let reverse = [forward[1], forward[0]];
            let mut preimages = Vec::new();
            inverse_local_demands(demand(2), &reverse, &mut preimages);
            let backward = preimages
                .iter()
                .map(|demand| demand.carrier.get())
                .collect::<Vec<_>>();
            assert_eq!(backward, [0, 1, 2], "weak_first {weak_first}");
            for start in 0..3u32 {
                assert_eq!(
                    forward_facts(&forward, &[start]).contains(&2),
                    backward.contains(&start),
                    "weak_first {weak_first} start {start}"
                );
            }
        }
    }

    #[test]
    fn backward_move_maps_target_to_source_but_kills_later_source_demand() {
        let rules = [invalidating_move_rule(0, 1)];
        let mut target_preimages = Vec::new();
        inverse_local_demands(demand(1), &rules, &mut target_preimages);
        assert_eq!(
            target_preimages
                .iter()
                .map(|demand| demand.carrier.get())
                .collect::<Vec<_>>(),
            [0]
        );

        let mut source_preimages = Vec::new();
        inverse_local_demands(demand(0), &rules, &mut source_preimages);
        assert!(source_preimages.is_empty());
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
    validate_backward_plan(plan)?;
    let outcome = provider
        .snapshot(
            root,
            limits,
            &mut SemanticRequest::new(semantic_budget, request.cancellation),
        )
        .map_err(BackwardSnapshotDataflowError::from)?;
    let status = IcfgInputStatus::from_outcome(&outcome);
    let input = IcfgSolveInput::from_outcome(&outcome)
        .map_err(|_| BackwardSnapshotDataflowError::MissingIcfgSnapshot { status })?;
    solve_value_flow_backward_on_input(plan, input, outcome.work(), request)
}

pub(crate) fn solve_value_flow_backward_on_input(
    plan: &ValueFlowPlan,
    input: IcfgSolveInput<'_>,
    semantic_work: crate::analyzer::semantic::SemanticWork,
    request: &mut DataflowRequest<'_>,
) -> Result<BackwardValueFlowResult, BackwardValueFlowSolveError> {
    validate_backward_plan(plan)?;
    let initial_work = request.budget.used();
    let problem = BackwardValueFlowProblem::for_snapshot(plan, input.snapshot(), request)?;
    let result = crate::dataflow::solve_backward_demands_on_snapshot(
        input,
        &problem,
        semantic_work,
        request,
    )?;
    BackwardValueFlowResult::from_result(
        plan,
        result,
        request.budget.used().saturating_sub(initial_work),
    )
}

fn validate_backward_plan(plan: &ValueFlowPlan) -> Result<(), BackwardValueFlowSolveError> {
    if plan.has_contextual_bindings() {
        return Err(BackwardValueFlowSolveError::CallContextRequired);
    }
    if plan.has_edge_kills() {
        return Err(BackwardValueFlowSolveError::EdgeKillsUnsupported);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackwardValueFlowSolveError {
    RootMismatch,
    CallContextRequired,
    CaptureProjectionCancelled,
    CaptureProjectionBudgetExceeded(SolverBudgetExceeded),
    EdgeKillsUnsupported,
    InvalidResult,
    Snapshot(BackwardSnapshotDataflowError),
}

impl fmt::Display for BackwardValueFlowSolveError {
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
            Self::CaptureProjectionBudgetExceeded(error) => Some(error),
            Self::RootMismatch
            | Self::CallContextRequired
            | Self::CaptureProjectionCancelled
            | Self::EdgeKillsUnsupported
            | Self::InvalidResult => None,
        }
    }
}

impl From<BackwardSnapshotDataflowError> for BackwardValueFlowSolveError {
    fn from(error: BackwardSnapshotDataflowError) -> Self {
        Self::Snapshot(error)
    }
}

impl From<super::client::CaptureProjectionError> for BackwardValueFlowSolveError {
    fn from(error: super::client::CaptureProjectionError) -> Self {
        match error {
            super::client::CaptureProjectionError::Cancelled => Self::CaptureProjectionCancelled,
            super::client::CaptureProjectionError::ExceededBudget(error) => {
                Self::CaptureProjectionBudgetExceeded(error)
            }
        }
    }
}
