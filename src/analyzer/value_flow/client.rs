use std::{error::Error, fmt};

use crate::analyzer::dataflow::{
    DataflowEdge, DataflowOutput, DataflowRequest, DistributiveDataflowProblem,
    SummaryDataflowError, SummaryExitKind, SummarySolveInput, SummaryTransfer,
    UnmodeledCallBehavior, WitnessRetentionLimits, solve_with_summaries,
};
use crate::analyzer::semantic::{
    EvidenceCompleteness, IcfgEdgeKind, IcfgProvider, ProcedureHandle, ProofStatus, SemanticBudget,
};

use super::plan::CallFlowRuleKind;
use super::{
    ValueFlowCarrierId, ValueFlowPlan, ValueFlowSinkId, ValueFlowSourceId, ValueFlowSummaryResult,
};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ValueFlowUncertainty(u8);

impl ValueFlowUncertainty {
    const SEMANTIC: u8 = 1 << 0;

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    const fn with_semantic(self) -> Self {
        Self(self.0 | Self::SEMANTIC)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
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

    fn with_summary_quality(
        mut self,
        evidence: &crate::analyzer::dataflow::SummaryEvidence,
    ) -> Self {
        if !evidence.alternatives().iter().any(|alternative| {
            alternative.quality().is_proven() && alternative.quality().is_complete()
        }) {
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
        let mut active = self.active_before_point(point, fact);
        self.append_meetings(
            point,
            super::ValueFlowObservationPhase::BeforeEffects,
            &active,
            meetings,
        );
        for rule in self.plan.local_rules_at(point) {
            let generated = active
                .iter()
                .copied()
                .filter(|flow| flow.carrier == rule.source)
                .map(|flow| ActiveFlow {
                    carrier: rule.target,
                    ..flow.with_transfer_quality(&rule.proof, &rule.completeness)
                })
                .collect::<Vec<_>>();
            active.extend(generated);
            active.sort_unstable();
            active.dedup();
        }
        if matches!(fact.0, ValueFlowFactKind::Zero) {
            for source in self
                .plan
                .sources_at(point, super::ValueFlowObservationPhase::AfterEffects)
            {
                active.push(ActiveFlow {
                    source: source.id,
                    carrier: source.carrier,
                    uncertainty: quality_uncertainty(
                        source.spec.proof(),
                        source.spec.completeness(),
                    ),
                });
            }
            active.sort_unstable();
            active.dedup();
        }
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
        if let Some(summary) = edge
            .boundary()
            .and_then(|boundary| self.plan.external_summary_for_boundary(boundary))
            && self.apply_modeled_transfers(
                edge,
                call,
                summary.transfers(),
                &active,
                &meetings,
                out,
            )
        {
            return;
        }
        if let Some(model) = self.plan.curated_model_for_call(call)
            && self.apply_modeled_transfers(edge, call, model.transfers(), &active, &meetings, out)
        {
            return;
        }
        let mut propagated = match self.plan.unmodeled_call_behavior() {
            UnmodeledCallBehavior::Paranoid | UnmodeledCallBehavior::Optimistic => active.clone(),
            UnmodeledCallBehavior::RequireModel => active
                .iter()
                .copied()
                .map(|flow| {
                    if self.plan.is_call_input(call, flow.carrier) {
                        ActiveFlow {
                            uncertainty: flow.uncertainty.with_semantic(),
                            ..flow
                        }
                    } else {
                        flow
                    }
                })
                .collect(),
        };
        if self.plan.unmodeled_call_behavior() == UnmodeledCallBehavior::Paranoid {
            let outputs = self
                .plan
                .fallback_outputs(call, edge.kind())
                .collect::<Vec<_>>();
            for flow in active {
                if self.plan.is_call_input(call, flow.carrier) {
                    for output in &outputs {
                        propagated.push(ActiveFlow {
                            carrier: *output,
                            uncertainty: flow.uncertainty.with_semantic(),
                            ..flow
                        });
                    }
                }
            }
        }
        self.emit_all(propagated, meetings, out);
    }

    fn apply_modeled_transfers(
        &self,
        edge: DataflowEdge<'_, ValueFlowFact>,
        call: &crate::analyzer::semantic::CallSiteHandle,
        model: &[SummaryTransfer],
        active: &[ActiveFlow],
        meetings: &[ValueFlowFact],
        out: &mut dyn DataflowOutput<ValueFlowFact>,
    ) -> bool {
        let exit = match edge.kind() {
            IcfgEdgeKind::CallToNormalContinuation => SummaryExitKind::Normal,
            IcfgEdgeKind::CallToExceptionalContinuation => SummaryExitKind::Exceptional,
            _ => return false,
        };
        let transfers = model
            .iter()
            .filter(|transfer| transfer.exit().kind() == exit)
            .map(|transfer| {
                Some((
                    self.plan.summary_port_carrier(call, transfer.input())?,
                    self.plan
                        .summary_port_carrier(call, transfer.exit().port())?,
                    transfer.evidence(),
                ))
            })
            .collect::<Option<Vec<_>>>();
        let Some(transfers) = transfers else {
            // The exact summary is not applicable until every referenced heap
            // or capture port can be bound to a live structured carrier.
            return false;
        };

        let mut propagated = active.to_vec();
        for flow in active {
            for (input, output, evidence) in &transfers {
                if flow.carrier == *input {
                    propagated.push(ActiveFlow {
                        carrier: *output,
                        ..flow.with_summary_quality(evidence)
                    });
                }
            }
        }
        self.emit_all(propagated, meetings.to_vec(), out);
        true
    }
}

impl DistributiveDataflowProblem for ValueFlowProblem<'_> {
    type Fact = ValueFlowFact;

    fn zero_fact(&self) -> Self::Fact {
        ValueFlowFact::ZERO
    }

    fn normal_flow(
        &self,
        edge: DataflowEdge<'_, Self::Fact>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        let mut meetings = Vec::new();
        let active = self.apply_point(edge.source(), fact, &mut meetings);
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
