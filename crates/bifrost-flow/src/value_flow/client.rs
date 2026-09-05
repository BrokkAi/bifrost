use std::{collections::HashSet, error::Error, fmt};

use crate::analyzer::semantic::{
    EvidenceCompleteness, IcfgEdgeKind, IcfgProvider, ProcedureHandle, ProofStatus, SemanticBudget,
    ValueFlowRelationKind,
};
use crate::dataflow::{
    DataflowEdge, DataflowOutput, DataflowRequest, DistributiveDataflowProblem,
    ReusableSummaryProvider, SummaryDataflowError, SummarySolveInput, WitnessRetentionLimits,
    solve_with_reusable_end_summaries, solve_with_summaries,
};

use super::plan::CallFlowRuleKind;
use super::{
    ValueFlowCarrierId, ValueFlowPlan, ValueFlowSinkId, ValueFlowSourceId, ValueFlowSummaryResult,
};

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

    pub(crate) fn with_quality(
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
        if !matches!(proof, ProofStatus::Proven)
            || !matches!(completeness, EvidenceCompleteness::Complete)
        {
            self.uncertainty = self.uncertainty.with_semantic();
        }
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
}

impl<'plan> ValueFlowProblem<'plan> {
    pub const fn new(plan: &'plan ValueFlowPlan) -> Self {
        Self { plan }
    }

    fn active_before_point(
        &self,
        point: &crate::analyzer::semantic::ProgramPointHandle,
        fact: ValueFlowFact,
    ) -> Vec<ActiveFlow> {
        let mut active = Vec::new();
        if matches!(fact.0, ValueFlowFactKind::Zero) {
            for source in self
                .plan
                .sources_at(point, super::ValueFlowObservationPhase::BeforeEffects)
            {
                let uncertainty =
                    quality_uncertainty(source.spec.proof(), source.spec.completeness());
                active.push(ActiveFlow {
                    source: source.id,
                    carrier: source.carrier,
                    uncertainty,
                });
            }
        } else if let ValueFlowFactKind::Carrier {
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
        active.sort_unstable();
        active.dedup();
        active
    }

    fn apply_point(
        &self,
        point: &crate::analyzer::semantic::ProgramPointHandle,
        fact: ValueFlowFact,
        meetings: &mut Vec<ValueFlowFact>,
    ) -> Vec<ActiveFlow> {
        if matches!(fact.0, ValueFlowFactKind::Meeting { .. }) {
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
            let (source, target, complete) = (rule.source, rule.target, rule.complete);
            if kills_target(&rule) {
                active.retain(|flow| flow.carrier != target);
            }
            let generated = active
                .iter()
                .copied()
                .filter(|flow| flow.carrier == source)
                .map(|flow| ActiveFlow {
                    carrier: target,
                    ..flow.with_transfer_completeness(complete)
                })
                .collect::<Vec<_>>();
            active.extend(generated);
        }
        if matches!(fact.0, ValueFlowFactKind::Zero) {
            for source in self
                .plan
                .sources_at(point, super::ValueFlowObservationPhase::AfterEffects)
            {
                active.insert(ActiveFlow {
                    source: source.id,
                    carrier: source.carrier,
                    uncertainty: quality_uncertainty(
                        source.spec.proof(),
                        source.spec.completeness(),
                    ),
                });
            }
        }
        let mut active = active.into_iter().collect::<Vec<_>>();
        active.sort_unstable();
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
        let Some(transfer) = edge.call_transfer() else {
            self.emit_all(Vec::new(), meetings, out);
            return;
        };
        let mut mapped = Vec::new();
        for flow in active {
            if self.plan.is_callee_port(flow.carrier, &transfer.callee) {
                mapped.push(flow);
            }
            for rule in
                self.plan
                    .call_rules(&transfer.origin, &transfer.callee, CallFlowRuleKind::Call)
            {
                if flow.carrier == rule.source {
                    mapped.push(ActiveFlow {
                        carrier: rule.target,
                        ..flow.with_transfer_quality(&rule.proof, &rule.completeness)
                    });
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
        for flow in active {
            for rule in self.plan.call_rules(call, callee, kind) {
                if flow.carrier == rule.source {
                    mapped.push(ActiveFlow {
                        carrier: rule.target,
                        ..flow.with_transfer_quality(&rule.proof, &rule.completeness)
                    });
                }
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

    fn normal_flow(
        &self,
        edge: DataflowEdge<'_, Self::Fact>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        let mut meetings = Vec::new();
        let mut active = self.apply_point(edge.source(), fact, &mut meetings);
        if let crate::analyzer::semantic::IcfgEdgeKind::Intraprocedural(kind) = edge.kind() {
            let kills = self
                .plan
                .edge_kills(edge.source(), edge.target().id(), kind);
            active.retain(|flow| {
                !kills.iter().any(|kill| {
                    kill.carrier == flow.carrier && kill.sources.binary_search(&flow.source).is_ok()
                })
            });
        }
        self.emit_all(active, meetings, out);
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
        let mut meetings = Vec::new();
        let active = self.apply_point(edge.source(), fact, &mut meetings);
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
    let problem = ValueFlowProblem::new(plan);
    let result = solve_with_reusable_end_summaries(
        SummarySolveInput::new(root, &[]).with_witness_retention(witness_retention),
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
    InvalidResult,
    Summary(SummaryDataflowError),
}

impl fmt::Display for ValueFlowSolveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RootMismatch => formatter.write_str("value-flow root does not match the plan"),
            Self::InvalidResult => {
                formatter.write_str("value-flow result contains an invalid fact")
            }
            Self::Summary(error) => error.fmt(formatter),
        }
    }
}

impl Error for ValueFlowSolveError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Summary(error) => Some(error),
            Self::RootMismatch | Self::InvalidResult => None,
        }
    }
}

impl From<SummaryDataflowError> for ValueFlowSolveError {
    fn from(error: SummaryDataflowError) -> Self {
        Self::Summary(error)
    }
}

/// Whether a point-local rule replaces, rather than joins, the facts at its
/// target carrier.
///
/// A local assignment has always killed its target: the target names one
/// procedure-local slot and the assignment is the only writer that can reach
/// it. A `MemoryStore` joins by default, because a store through one name can
/// land on a location another name also reaches, and killing it would launder
/// an unanalyzed write into a clean answer.
///
/// #2444 adds the one case where a store does not join. The heap oracle issues
/// a `StrongUpdateCertificate` only when the store's location is exact, the
/// object it belongs to is a proven singleton, no other location can be
/// updated by the store, and the object does not escape. Under that proof the
/// store definitely overwrote what this carrier held, so keeping the old fact
/// would be a false positive rather than caution.
///
/// Aliasing is not laundered away by this. A second name the access-path
/// resolver proved is the same origin resolves to the same carrier, so the
/// kill is correct for it too; a name the resolver could not prove leaves more
/// than one candidate object, which is a weak update and no kill at all.
pub(crate) fn kills_target(rule: &super::plan::LocalRuleView) -> bool {
    match rule.kind {
        ValueFlowRelationKind::Assignment => rule.source != rule.target,
        ValueFlowRelationKind::MemoryStore => rule.strong_update,
        _ => false,
    }
}

fn quality_uncertainty(
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
