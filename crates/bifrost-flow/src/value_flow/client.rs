use std::{collections::HashSet, error::Error, fmt};

use crate::analyzer::semantic::{
    EvidenceCompleteness, IcfgEdgeKind, IcfgProvider, ProcedureHandle, ProofStatus, SemanticBudget,
    ValueFlowRelationKind,
};
use crate::dataflow::{
    DataflowEdge, DataflowOutput, DataflowRequest, DistributiveDataflowProblem,
    ReusableSummaryProvider, SummaryDataflowError, SummarySolveInput, WitnessRetentionLimits,
    solve_with_reusable_end_summaries, solve_with_reusable_root_and_end_summaries,
    solve_with_summaries,
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
        let mut generated = Vec::new();
        for source in self
            .plan
            .sources_at(point, super::ValueFlowObservationPhase::BeforeEffects)
        {
            match source.activation_triggers.as_deref() {
                None if is_zero => {
                    generated.push(ActiveFlow {
                        source: source.id,
                        carrier: source.carrier,
                        uncertainty: quality_uncertainty(
                            source.spec.proof(),
                            source.spec.completeness(),
                        ),
                    });
                }
                Some(triggers) if !is_zero => {
                    generated.extend(conditional_source_flows(
                        source.id,
                        source.carrier,
                        triggers,
                        active.iter().copied(),
                        source.spec.proof(),
                        source.spec.completeness(),
                    ));
                }
                None | Some(_) => {}
            }
        }
        active.extend(generated);
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
        let mut generated = Vec::new();
        for source in self
            .plan
            .sources_at(point, super::ValueFlowObservationPhase::AfterEffects)
        {
            match source.activation_triggers.as_deref() {
                None if matches!(fact.0, ValueFlowFactKind::Zero) => {
                    generated.push(ActiveFlow {
                        source: source.id,
                        carrier: source.carrier,
                        uncertainty: quality_uncertainty(
                            source.spec.proof(),
                            source.spec.completeness(),
                        ),
                    });
                }
                Some(triggers) if !matches!(fact.0, ValueFlowFactKind::Zero) => {
                    generated.extend(conditional_source_flows(
                        source.id,
                        source.carrier,
                        triggers,
                        active.iter().copied(),
                        source.spec.proof(),
                        source.spec.completeness(),
                    ));
                }
                None | Some(_) => {}
            }
        }
        // Evaluate every conditional source against the incoming active set.
        // Extending only after this loop prevents a source generated here from
        // recursively activating another source at the same point.
        active.extend(generated);
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
            if self.plan.is_callee_port(flow.carrier, &transfer.callee)
                && !self
                    .plan
                    .call_rules_to_target(
                        &transfer.origin,
                        &transfer.callee,
                        CallFlowRuleKind::Call,
                        flow.carrier,
                    )
                    .any(|rule| {
                        self.plan
                            .is_default_argument_carrier(rule.source, &transfer.callee)
                    })
            {
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
        if matches!(fact.0, ValueFlowFactKind::Zero) {
            // A default value belongs to the callee, was saved at definition
            // time, and is exposed as a source at its entry. It is consequently
            // absent from the caller's active facts. Select that entry source
            // only for the call rule that explicitly binds the default.
            for rule in self
                .plan
                .call_rules(&transfer.origin, &transfer.callee, CallFlowRuleKind::Call)
                .filter(|rule| {
                    self.plan
                        .is_default_argument_carrier(rule.source, &transfer.callee)
                })
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
    InvalidResult,
    Summary(SummaryDataflowError),
}

impl ValueFlowSolveError {
    pub(crate) const fn mandatory_summary_cut_miss(&self) -> Option<&ProcedureHandle> {
        match self {
            Self::Summary(SummaryDataflowError::MandatorySummaryCutMiss { procedure }) => {
                Some(procedure)
            }
            Self::RootMismatch | Self::InvalidResult | Self::Summary(_) => None,
        }
    }
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
    // Parameter and receiver relations are copies between a boundary port and
    // a value carrier, so a distinct endpoint replaces the target carrier.
    match rule.kind {
        ValueFlowRelationKind::Assignment
        | ValueFlowRelationKind::Parameter
        | ValueFlowRelationKind::Receiver => rule.source != rule.target,
        ValueFlowRelationKind::MemoryStore => rule.strong_update,
        _ => false,
    }
}

/// Whether a by-value relation consumes the value held by its source.
///
/// Generate the destination fact before applying this kill: the target keeps
/// the moved value while later observations of the source binding do not.
pub(crate) fn invalidates_source(rule: &super::plan::LocalRuleView) -> bool {
    matches!(
        rule.transfer,
        Some(crate::analyzer::semantic::ValueTransfer {
            kind: crate::analyzer::semantic::TransferKind::Move {
                invalidation: crate::analyzer::semantic::MoveInvalidation::Invalidated,
            },
            ..
        })
    )
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
        let parameter = root
            .semantics()
            .values()
            .iter()
            .find(|value| matches!(value.kind, SemanticValueKind::Parameter { ordinal: 0, .. }))
            .expect("fixture has one parameter")
            .id;
        let value_carrier = ValueFlowCarrier::Value(
            root.value_handle(parameter)
                .expect("parameter value remains live"),
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
        let before = ValueFlowSourceSpec::new(
            before_key,
            exit.clone(),
            ValueFlowObservationPhase::BeforeEffects,
            value_carrier.clone(),
            ProofStatus::Proven,
            EvidenceCompleteness::Complete,
        )
        .when_sources_reach(vec![trigger_key.clone()]);
        let after = ValueFlowSourceSpec::new(
            after_key,
            exit.clone(),
            ValueFlowObservationPhase::AfterEffects,
            value_carrier,
            ProofStatus::Proven,
            EvidenceCompleteness::Complete,
        )
        .when_sources_reach(vec![trigger_key.clone()]);
        let plan = ValueFlowPlan::try_new(
            root,
            Vec::new(),
            Vec::new(),
            vec![trigger, unrelated, before, after],
            Vec::new(),
        )
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
                &ValueFlowCarrier::Value(
                    plan.root()
                        .value_handle(parameter)
                        .expect("parameter value remains live"),
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
