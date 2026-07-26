use std::{error::Error, fmt, sync::Arc};

use crate::analyzer::dataflow::{
    DataflowEdge, DataflowOutput, DataflowRequest, IdeDataflowError, IdeDataflowProblem,
    IdeSummaryDataflowResult, IdeSummarySolveInput, IdeTransition, SummaryWitnessStep,
    SummaryWitnessStepKind, WitnessRetentionLimits, solve_ide_with_summaries,
};
use crate::analyzer::semantic::{
    EvidenceCompleteness, IcfgEdgeKind, IcfgProvider, ProcedureHandle, ProofStatus, SemanticBudget,
};
use crate::analyzer::value_flow::{
    ValueFlowCarrier, ValueFlowCarrierId, ValueFlowObservationPhase, ValueFlowSinkId,
};

use super::model::TaintClassId;
use super::{SourceClassId, TaintAnalysisPlan, TaintClassSet, TaintUniverse};

/// Canonical sparse affine union function `G ∪ ⋃ R(class)`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaintEdgeFunction {
    generated: TaintClassSet,
    default_identity: bool,
    overrides: Box<[(TaintClassId, TaintClassSet)]>,
}

impl TaintEdgeFunction {
    pub fn identity(universe: &TaintUniverse) -> Self {
        Self {
            generated: universe.empty_set(),
            default_identity: true,
            overrides: Box::new([]),
        }
    }

    pub fn generate(classes: &TaintClassSet) -> Self {
        Self {
            generated: classes.clone(),
            default_identity: true,
            overrides: Box::new([]),
        }
    }

    pub fn kill(classes: &TaintClassSet) -> Self {
        let empty = classes.empty_like();
        let overrides = classes
            .iter_dense()
            .map(|class| (class, empty.clone()))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            generated: empty,
            default_identity: true,
            overrides,
        }
    }

    pub fn transform(
        universe: &TaintUniverse,
        mappings: impl IntoIterator<Item = (SourceClassId, TaintClassSet)>,
        preserve_unmapped: bool,
    ) -> Result<Self, TaintSolveError> {
        let mut overrides = Vec::new();
        for (source, targets) in mappings {
            universe
                .validate_set(&targets)
                .map_err(|_| TaintSolveError::UniverseMismatch)?;
            let source = universe
                .class_id(&source)
                .ok_or(TaintSolveError::UniverseMismatch)?;
            overrides.push((source, targets));
        }
        overrides.sort_by_key(|(source, _)| *source);
        if overrides.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(TaintSolveError::DuplicateTransformSource);
        }
        overrides.retain(|(source, targets)| {
            *targets != default_output(&universe.empty_set(), preserve_unmapped, *source)
        });
        Ok(Self {
            generated: universe.empty_set(),
            default_identity: preserve_unmapped,
            overrides: overrides.into_boxed_slice(),
        })
    }

    pub const fn class_count(&self) -> usize {
        self.generated.class_count()
    }

    pub const fn universe(&self) -> super::TaintUniverseHash {
        self.generated.universe()
    }

    pub fn apply(&self, value: &TaintClassSet) -> TaintClassSet {
        self.assert_value_compatible(value);
        let mut output = self.generated.clone();
        output.union_with(&self.apply_relation(value));
        output
    }

    pub fn meet(&self, other: &Self) -> Self {
        self.assert_compatible(other);
        if self == other {
            return self.clone();
        }
        if self.default_identity == other.default_identity && self.overrides == other.overrides {
            return Self {
                generated: self.generated.union(&other.generated),
                default_identity: self.default_identity,
                overrides: self.overrides.clone(),
            };
        }
        let default_identity = self.default_identity || other.default_identity;
        self.combine_outputs(
            other,
            default_identity,
            |left, right| left.union(&right),
            self.generated.union(&other.generated),
        )
    }

    /// Compose in path order: apply `self`, then `second`.
    pub fn compose(&self, second: &Self) -> Self {
        self.assert_compatible(second);
        if self.is_identity() {
            return second.clone();
        }
        if second.is_identity() {
            return self.clone();
        }
        if self.relation_is_identity() {
            let mut result = second.clone();
            result.generated = second.apply(&self.generated);
            return result;
        }
        if second.relation_is_identity() {
            let mut result = self.clone();
            result.generated.union_with(&second.generated);
            return result;
        }
        let default_identity = self.default_identity && second.default_identity;
        let mut overrides = Vec::new();
        for index in 0..self.class_count() {
            let class =
                TaintClassId::try_from_index(index).expect("taint universe size was validated");
            let output = second.apply_relation(&self.output_for(class));
            if output != default_output(&self.generated, default_identity, class) {
                overrides.push((class, output));
            }
        }
        Self {
            generated: second.apply(&self.generated),
            default_identity,
            overrides: overrides.into_boxed_slice(),
        }
    }

    fn apply_relation(&self, value: &TaintClassSet) -> TaintClassSet {
        self.assert_value_compatible(value);
        let mut output = if self.default_identity {
            value.clone()
        } else {
            self.generated.empty_like()
        };
        if self.default_identity {
            for (source, _) in &self.overrides {
                if value.contains_dense(*source) {
                    output.remove_dense(*source);
                }
            }
        }
        for (source, targets) in &self.overrides {
            if !value.contains_dense(*source) {
                continue;
            }
            output.union_with(targets);
        }
        output
    }

    fn output_for(&self, class: TaintClassId) -> TaintClassSet {
        self.overrides
            .binary_search_by_key(&class, |(source, _)| *source)
            .ok()
            .map_or_else(
                || default_output(&self.generated, self.default_identity, class),
                |index| {
                    self.overrides
                        .get(index)
                        .expect("binary search returned a live override")
                        .1
                        .clone()
                },
            )
    }

    fn combine_outputs(
        &self,
        other: &Self,
        default_identity: bool,
        combine: impl Fn(TaintClassSet, TaintClassSet) -> TaintClassSet,
        generated: TaintClassSet,
    ) -> Self {
        let mut overrides = Vec::new();
        for index in 0..self.class_count() {
            let class =
                TaintClassId::try_from_index(index).expect("taint universe size was validated");
            let output = combine(self.output_for(class), other.output_for(class));
            if output != default_output(&self.generated, default_identity, class) {
                overrides.push((class, output));
            }
        }
        Self {
            generated,
            default_identity,
            overrides: overrides.into_boxed_slice(),
        }
    }

    fn is_identity(&self) -> bool {
        self.generated.is_empty() && self.relation_is_identity()
    }

    fn relation_is_identity(&self) -> bool {
        self.default_identity && self.overrides.is_empty()
    }

    fn assert_value_compatible(&self, value: &TaintClassSet) {
        assert_eq!(
            (self.generated.universe(), self.class_count()),
            (value.universe(), value.class_count()),
            "taint edge function and value require one universe"
        );
    }

    fn assert_compatible(&self, other: &Self) {
        assert_eq!(
            (self.generated.universe(), self.class_count()),
            (other.generated.universe(), other.class_count()),
            "taint edge functions require one universe"
        );
    }
}

fn default_output(
    prototype: &TaintClassSet,
    default_identity: bool,
    class: TaintClassId,
) -> TaintClassSet {
    let mut output = prototype.empty_like();
    if default_identity {
        output.insert_dense(class);
    }
    output
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum TaintFactKind {
    Zero,
    Carrier {
        carrier: ValueFlowCarrierId,
        uncertain: bool,
    },
    Meeting {
        sink: ValueFlowSinkId,
        uncertain: bool,
    },
}

/// Source-set-neutral fact topology; concrete classes live only in IDE values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaintFact(TaintFactKind);

impl TaintFact {
    const ZERO: Self = Self(TaintFactKind::Zero);

    pub const fn carrier(self) -> Option<ValueFlowCarrierId> {
        match self.0 {
            TaintFactKind::Carrier { carrier, .. } => Some(carrier),
            TaintFactKind::Zero | TaintFactKind::Meeting { .. } => None,
        }
    }

    pub const fn sink(self) -> Option<ValueFlowSinkId> {
        match self.0 {
            TaintFactKind::Meeting { sink, .. } => Some(sink),
            TaintFactKind::Zero | TaintFactKind::Carrier { .. } => None,
        }
    }

    pub const fn is_uncertain(self) -> bool {
        match self.0 {
            TaintFactKind::Carrier { uncertain, .. } | TaintFactKind::Meeting { uncertain, .. } => {
                uncertain
            }
            TaintFactKind::Zero => false,
        }
    }

    pub(crate) const fn is_zero(self) -> bool {
        matches!(self.0, TaintFactKind::Zero)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ActiveTaint {
    carrier: ValueFlowCarrierId,
    uncertain: bool,
    function: TaintEdgeFunction,
}

impl ActiveTaint {
    fn fact(&self) -> TaintFact {
        TaintFact(TaintFactKind::Carrier {
            carrier: self.carrier,
            uncertain: self.uncertain,
        })
    }

    fn through_semantics(mut self, complete: bool) -> Self {
        self.uncertain |= !complete;
        self
    }
}

pub struct TaintFlowProblem<'plan> {
    plan: &'plan TaintAnalysisPlan,
}

impl<'plan> TaintFlowProblem<'plan> {
    pub const fn new(plan: &'plan TaintAnalysisPlan) -> Self {
        Self { plan }
    }

    fn initial_active(
        &self,
        point: &crate::analyzer::semantic::ProgramPointHandle,
        fact: TaintFact,
    ) -> Vec<ActiveTaint> {
        match fact.0 {
            TaintFactKind::Zero => self
                .plan
                .value_flow()
                .source_bindings_at(point, ValueFlowObservationPhase::BeforeEffects)
                .filter_map(|(source, carrier)| {
                    let binding = self.plan.source(source)?;
                    let spec = self.plan.value_flow().source(source)?;
                    Some(ActiveTaint {
                        carrier,
                        uncertain: !matches!(spec.proof(), ProofStatus::Proven)
                            || !matches!(spec.completeness(), EvidenceCompleteness::Complete),
                        function: TaintEdgeFunction::generate(binding.classes()),
                    })
                })
                .collect(),
            TaintFactKind::Carrier { carrier, uncertain } => vec![ActiveTaint {
                carrier,
                uncertain,
                function: self.plan.identity().clone(),
            }],
            TaintFactKind::Meeting { .. } => Vec::new(),
        }
    }

    fn apply_phase(
        &self,
        point: &crate::analyzer::semantic::ProgramPointHandle,
        phase: ValueFlowObservationPhase,
        active: &mut [ActiveTaint],
    ) {
        for flow in active {
            let (transfer, complete) = self.plan.transfer_function(point, phase, flow.carrier);
            flow.function = flow.function.compose(transfer);
            flow.uncertain |= !complete;
        }
    }

    fn apply_local_rules(
        &self,
        point: &crate::analyzer::semantic::ProgramPointHandle,
        active: &mut Vec<ActiveTaint>,
    ) {
        for (source, target, complete) in self.plan.value_flow().local_rule_views(point) {
            let generated = active
                .iter()
                .filter(|flow| flow.carrier == source)
                .cloned()
                .map(|flow| ActiveTaint {
                    carrier: target,
                    ..flow.through_semantics(complete)
                })
                .collect::<Vec<_>>();
            active.extend(generated);
        }
    }

    fn append_sources_after(
        &self,
        point: &crate::analyzer::semantic::ProgramPointHandle,
        fact: TaintFact,
        active: &mut Vec<ActiveTaint>,
    ) {
        if !matches!(fact.0, TaintFactKind::Zero) {
            return;
        }
        for (source, carrier) in self
            .plan
            .value_flow()
            .source_bindings_at(point, ValueFlowObservationPhase::AfterEffects)
        {
            let Some(binding) = self.plan.source(source) else {
                continue;
            };
            let Some(spec) = self.plan.value_flow().source(source) else {
                continue;
            };
            active.push(ActiveTaint {
                carrier,
                uncertain: !matches!(spec.proof(), ProofStatus::Proven)
                    || !matches!(spec.completeness(), EvidenceCompleteness::Complete),
                function: TaintEdgeFunction::generate(binding.classes()),
            });
        }
    }

    fn append_meetings(
        &self,
        point: &crate::analyzer::semantic::ProgramPointHandle,
        phase: ValueFlowObservationPhase,
        active: &[ActiveTaint],
        output: &mut Vec<(TaintFact, TaintEdgeFunction)>,
    ) {
        for (sink, carrier) in self.plan.value_flow().sink_bindings_at(point, phase) {
            if self.plan.sink(sink).is_none() {
                continue;
            }
            for flow in active.iter().filter(|flow| flow.carrier == carrier) {
                let spec = self
                    .plan
                    .value_flow()
                    .sink(sink)
                    .expect("bound sink remains live");
                output.push((
                    TaintFact(TaintFactKind::Meeting {
                        sink,
                        uncertain: flow.uncertain
                            || !matches!(spec.proof(), ProofStatus::Proven)
                            || !matches!(spec.completeness(), EvidenceCompleteness::Complete),
                    }),
                    flow.function.clone(),
                ));
            }
        }
    }

    fn apply_point(
        &self,
        point: &crate::analyzer::semantic::ProgramPointHandle,
        fact: TaintFact,
        output: &mut Vec<(TaintFact, TaintEdgeFunction)>,
    ) -> Vec<ActiveTaint> {
        let mut active = self.initial_active(point, fact);
        self.apply_phase(point, ValueFlowObservationPhase::BeforeEffects, &mut active);
        self.append_meetings(
            point,
            ValueFlowObservationPhase::BeforeEffects,
            &active,
            output,
        );
        self.apply_local_rules(point, &mut active);
        self.append_sources_after(point, fact, &mut active);
        self.apply_phase(point, ValueFlowObservationPhase::AfterEffects, &mut active);
        self.append_meetings(
            point,
            ValueFlowObservationPhase::AfterEffects,
            &active,
            output,
        );
        active.sort_unstable();
        active.dedup();
        active
    }

    pub(crate) fn source_contribution(
        &self,
        source_id: crate::analyzer::value_flow::ValueFlowSourceId,
        output_fact: TaintFact,
        step: &SummaryWitnessStep,
    ) -> TaintClassSet {
        let Some(binding) = self.plan.source(source_id) else {
            return self.plan.universe().empty_set();
        };
        let Some(spec) = self.plan.value_flow().source(source_id) else {
            return self.plan.universe().empty_set();
        };
        if spec.point() != step.source() {
            return self.plan.universe().empty_set();
        }
        let carrier = self
            .plan
            .value_flow()
            .source_bindings_at(spec.point(), spec.phase())
            .find_map(|(candidate, carrier)| (candidate == source_id).then_some(carrier));
        let Some(carrier) = carrier else {
            return self.plan.universe().empty_set();
        };
        let make_source = || ActiveTaint {
            carrier,
            uncertain: !matches!(spec.proof(), ProofStatus::Proven)
                || !matches!(spec.completeness(), EvidenceCompleteness::Complete),
            function: TaintEdgeFunction::generate(binding.classes()),
        };
        let mut output = Vec::new();
        let mut active = if spec.phase() == ValueFlowObservationPhase::BeforeEffects {
            vec![make_source()]
        } else {
            Vec::new()
        };
        self.apply_phase(
            spec.point(),
            ValueFlowObservationPhase::BeforeEffects,
            &mut active,
        );
        self.append_meetings(
            spec.point(),
            ValueFlowObservationPhase::BeforeEffects,
            &active,
            &mut output,
        );
        self.apply_local_rules(spec.point(), &mut active);
        if spec.phase() == ValueFlowObservationPhase::AfterEffects {
            active.push(make_source());
        }
        self.apply_phase(
            spec.point(),
            ValueFlowObservationPhase::AfterEffects,
            &mut active,
        );
        self.append_meetings(
            spec.point(),
            ValueFlowObservationPhase::AfterEffects,
            &active,
            &mut output,
        );

        let active = match step.kind() {
            SummaryWitnessStepKind::Edge(IcfgEdgeKind::Call) => {
                let (Some(call), Some(target)) = (step.origin(), step.target()) else {
                    return self.plan.universe().empty_set();
                };
                let callee = target.procedure();
                active
                    .into_iter()
                    .flat_map(|flow| {
                        let preserved = self
                            .plan
                            .value_flow()
                            .is_callee_port(flow.carrier, callee)
                            .then_some(flow.clone());
                        preserved.into_iter().chain(
                            self.plan
                                .value_flow()
                                .call_targets(call, callee, flow.carrier)
                                .map(move |(target, complete)| ActiveTaint {
                                    carrier: target,
                                    ..flow.clone().through_semantics(complete)
                                }),
                        )
                    })
                    .collect()
            }
            SummaryWitnessStepKind::Edge(IcfgEdgeKind::NormalReturn)
            | SummaryWitnessStepKind::Edge(IcfgEdgeKind::ExceptionalReturn) => {
                let Some(call) = step.origin() else {
                    return self.plan.universe().empty_set();
                };
                active
                    .into_iter()
                    .flat_map(|flow| {
                        let targets = match step.kind() {
                            SummaryWitnessStepKind::Edge(IcfgEdgeKind::NormalReturn) => self
                                .plan
                                .value_flow()
                                .normal_return_targets(
                                    call,
                                    step.source().procedure(),
                                    flow.carrier,
                                )
                                .collect::<Vec<_>>(),
                            _ => self
                                .plan
                                .value_flow()
                                .exceptional_return_targets(
                                    call,
                                    step.source().procedure(),
                                    flow.carrier,
                                )
                                .collect::<Vec<_>>(),
                        };
                        targets
                            .into_iter()
                            .map(move |(target, complete)| ActiveTaint {
                                carrier: target,
                                ..flow.clone().through_semantics(complete)
                            })
                    })
                    .collect()
            }
            SummaryWitnessStepKind::Edge(IcfgEdgeKind::CallToNormalContinuation)
            | SummaryWitnessStepKind::Edge(IcfgEdgeKind::CallToExceptionalContinuation) => {
                let Some(call) = step.origin() else {
                    return self.plan.universe().empty_set();
                };
                let row = call
                    .procedure()
                    .semantics()
                    .call_site(call.id())
                    .expect("witness call handles are validated");
                let result = match step.kind() {
                    SummaryWitnessStepKind::Edge(IcfgEdgeKind::CallToNormalContinuation) => {
                        row.result
                    }
                    _ => row.thrown,
                }
                .and_then(|value| call.procedure().value_handle(value))
                .and_then(|value| {
                    self.plan
                        .value_flow()
                        .carrier_id(&ValueFlowCarrier::Value(value))
                });
                let mut propagated = active.clone();
                if let Some(result) = result {
                    propagated.extend(active.into_iter().filter_map(|flow| {
                        self.plan
                            .value_flow()
                            .is_call_input(call, flow.carrier)
                            .then_some(ActiveTaint {
                                carrier: result,
                                uncertain: true,
                                ..flow
                            })
                    }));
                }
                propagated
            }
            SummaryWitnessStepKind::Edge(_)
            | SummaryWitnessStepKind::Seed
            | SummaryWitnessStepKind::EndSummaryGap(_) => active,
        };
        output.extend(active.into_iter().map(|flow| (flow.fact(), flow.function)));
        let mut contribution = self.plan.universe().empty_set();
        for (fact, function) in output {
            if fact == output_fact {
                contribution.union_with(&function.apply(&self.plan.universe().empty_set()));
            }
        }
        contribution
    }

    fn emit(
        &self,
        active: Vec<ActiveTaint>,
        mut output: Vec<(TaintFact, TaintEdgeFunction)>,
        out: &mut dyn DataflowOutput<IdeTransition<TaintFact, TaintEdgeFunction>>,
    ) {
        output.extend(active.into_iter().map(|flow| (flow.fact(), flow.function)));
        output.sort_unstable();
        output.dedup();
        for (fact, function) in output {
            if !out.emit(IdeTransition::new(fact, function)) {
                break;
            }
        }
    }

    fn call_flow(
        &self,
        edge: DataflowEdge<'_>,
        fact: TaintFact,
        out: &mut dyn DataflowOutput<IdeTransition<TaintFact, TaintEdgeFunction>>,
    ) {
        let mut output = Vec::new();
        let active = self.apply_point(edge.source(), fact, &mut output);
        let Some(transfer) = edge.call_transfer() else {
            self.emit(Vec::new(), output, out);
            return;
        };
        let mapped = active
            .into_iter()
            .flat_map(|flow| {
                let preserved = self
                    .plan
                    .value_flow()
                    .is_callee_port(flow.carrier, &transfer.callee)
                    .then_some(flow.clone());
                preserved.into_iter().chain(
                    self.plan
                        .value_flow()
                        .call_targets(&transfer.origin, &transfer.callee, flow.carrier)
                        .map(move |(target, complete)| ActiveTaint {
                            carrier: target,
                            ..flow.clone().through_semantics(complete)
                        }),
                )
            })
            .collect();
        self.emit(mapped, output, out);
    }

    fn return_flow(
        &self,
        edge: DataflowEdge<'_>,
        fact: TaintFact,
        out: &mut dyn DataflowOutput<IdeTransition<TaintFact, TaintEdgeFunction>>,
    ) {
        let mut output = Vec::new();
        let active = self.apply_point(edge.source(), fact, &mut output);
        let Some(call) = edge.origin() else {
            self.emit(Vec::new(), output, out);
            return;
        };
        let callee = edge.source().procedure();
        let mapped = active
            .into_iter()
            .flat_map(|flow| {
                let targets = match edge.kind() {
                    IcfgEdgeKind::NormalReturn => self
                        .plan
                        .value_flow()
                        .normal_return_targets(call, callee, flow.carrier)
                        .collect::<Vec<_>>(),
                    IcfgEdgeKind::ExceptionalReturn => self
                        .plan
                        .value_flow()
                        .exceptional_return_targets(call, callee, flow.carrier)
                        .collect::<Vec<_>>(),
                    _ => Vec::new(),
                };
                targets
                    .into_iter()
                    .map(move |(target, complete)| ActiveTaint {
                        carrier: target,
                        ..flow.clone().through_semantics(complete)
                    })
            })
            .collect();
        self.emit(mapped, output, out);
    }

    fn boundary_flow(
        &self,
        edge: DataflowEdge<'_>,
        fact: TaintFact,
        out: &mut dyn DataflowOutput<IdeTransition<TaintFact, TaintEdgeFunction>>,
    ) {
        let mut output = Vec::new();
        let active = self.apply_point(edge.source(), fact, &mut output);
        let Some(call) = edge.origin() else {
            self.emit(active, output, out);
            return;
        };
        let row = call
            .procedure()
            .semantics()
            .call_site(call.id())
            .expect("call handles are validated");
        let result = match edge.kind() {
            IcfgEdgeKind::CallToNormalContinuation => row.result,
            IcfgEdgeKind::CallToExceptionalContinuation => row.thrown,
            _ => None,
        }
        .and_then(|value| call.procedure().value_handle(value))
        .and_then(|value| {
            self.plan
                .value_flow()
                .carrier_id(&ValueFlowCarrier::Value(value))
        });
        let mut propagated = active.clone();
        if let Some(result) = result {
            propagated.extend(active.into_iter().filter_map(|flow| {
                self.plan
                    .value_flow()
                    .is_call_input(call, flow.carrier)
                    .then_some(ActiveTaint {
                        carrier: result,
                        uncertain: true,
                        ..flow
                    })
            }));
        }
        self.emit(propagated, output, out);
    }
}

impl IdeDataflowProblem for TaintFlowProblem<'_> {
    type Fact = TaintFact;
    type Value = TaintClassSet;
    type EdgeFunction = TaintEdgeFunction;

    fn zero_fact(&self) -> Self::Fact {
        TaintFact::ZERO
    }

    fn zero_value(&self) -> Self::Value {
        self.plan.universe().empty_set()
    }

    fn identity_edge_function(&self) -> Self::EdgeFunction {
        self.plan.identity().clone()
    }

    fn meet_values(&self, left: &Self::Value, right: &Self::Value) -> Self::Value {
        left.union(right)
    }

    fn compose_edge_functions(
        &self,
        first: &Self::EdgeFunction,
        second: &Self::EdgeFunction,
    ) -> Self::EdgeFunction {
        first.compose(second)
    }

    fn apply_edge_function(
        &self,
        function: &Self::EdgeFunction,
        value: &Self::Value,
    ) -> Self::Value {
        function.apply(value)
    }

    fn meet_edge_functions(
        &self,
        left: &Self::EdgeFunction,
        right: &Self::EdgeFunction,
    ) -> Self::EdgeFunction {
        left.meet(right)
    }

    fn normal_flow(
        &self,
        edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<IdeTransition<Self::Fact, Self::EdgeFunction>>,
    ) {
        let mut output = Vec::new();
        let active = self.apply_point(edge.source(), fact, &mut output);
        self.emit(active, output, out);
    }

    fn call_flow(
        &self,
        edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<IdeTransition<Self::Fact, Self::EdgeFunction>>,
    ) {
        self.call_flow(edge, fact, out);
    }

    fn return_flow(
        &self,
        edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<IdeTransition<Self::Fact, Self::EdgeFunction>>,
    ) {
        self.return_flow(edge, fact, out);
    }

    fn call_to_return_flow(
        &self,
        edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<IdeTransition<Self::Fact, Self::EdgeFunction>>,
    ) {
        self.boundary_flow(edge, fact, out);
    }

    fn exceptional_flow(
        &self,
        edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<IdeTransition<Self::Fact, Self::EdgeFunction>>,
    ) {
        let mut output = Vec::new();
        let active = self.apply_point(edge.source(), fact, &mut output);
        self.emit(active, output, out);
    }
}

type RawTaintSummaryResult = IdeSummaryDataflowResult<TaintFact, TaintClassSet, TaintEdgeFunction>;

/// One IDE result branded to the exact taint plan that defined its dense domains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintSummaryResult {
    result: RawTaintSummaryResult,
    owner: Arc<()>,
    discovery_complete: bool,
}

impl TaintSummaryResult {
    fn from_result(plan: &TaintAnalysisPlan, result: RawTaintSummaryResult) -> Self {
        let discovery_complete = plan
            .value_flow()
            .execution_discovery_complete(result.fact_result())
            && plan.discovery_complete();
        Self {
            result,
            owner: Arc::clone(plan.owner()),
            discovery_complete,
        }
    }

    pub const fn result(&self) -> &RawTaintSummaryResult {
        &self.result
    }

    pub const fn fact_result(
        &self,
    ) -> &crate::analyzer::dataflow::SummaryDataflowResult<TaintFact> {
        self.result.fact_result()
    }

    pub fn point_values(&self) -> &[crate::analyzer::dataflow::IdePointValue] {
        self.result.point_values()
    }

    pub fn value(&self, id: crate::analyzer::dataflow::IdeValueId) -> Option<&TaintClassSet> {
        self.result.value(id)
    }

    pub const fn coverage(&self) -> &crate::analyzer::dataflow::SummaryCoverage {
        self.result.coverage()
    }

    pub const fn termination(&self) -> crate::analyzer::dataflow::SolverTermination {
        self.result.termination()
    }

    pub fn is_complete(&self) -> bool {
        self.discovery_complete && self.result.is_complete()
    }

    pub(crate) fn owner(&self) -> &Arc<()> {
        &self.owner
    }
}

pub fn solve_taint_batch_with_summaries<Provider>(
    root: &ProcedureHandle,
    provider: &Provider,
    plan: &TaintAnalysisPlan,
    semantic_budget: &mut SemanticBudget,
    request: &mut DataflowRequest<'_>,
) -> Result<TaintSummaryResult, TaintSolveError>
where
    Provider: IcfgProvider + ?Sized,
{
    solve_taint_batch_with_witnesses(
        root,
        provider,
        plan,
        WitnessRetentionLimits::disabled(),
        semantic_budget,
        request,
    )
}

pub fn solve_taint_batch_with_witnesses<Provider>(
    root: &ProcedureHandle,
    provider: &Provider,
    plan: &TaintAnalysisPlan,
    witness_retention: WitnessRetentionLimits,
    semantic_budget: &mut SemanticBudget,
    request: &mut DataflowRequest<'_>,
) -> Result<TaintSummaryResult, TaintSolveError>
where
    Provider: IcfgProvider + ?Sized,
{
    if root != plan.value_flow().root() {
        return Err(TaintSolveError::RootMismatch);
    }
    let result = solve_ide_with_summaries(
        IdeSummarySolveInput::new(root, &[]).with_witness_retention(witness_retention),
        provider,
        &TaintFlowProblem::new(plan),
        semantic_budget,
        request,
    )?;
    Ok(TaintSummaryResult::from_result(plan, result))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaintSolveError {
    RootMismatch,
    UniverseMismatch,
    DuplicateTransformSource,
    Ide(IdeDataflowError),
}

impl fmt::Display for TaintSolveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RootMismatch => {
                formatter.write_str("taint root does not match the analysis plan")
            }
            Self::UniverseMismatch => {
                formatter.write_str("taint transfer uses a different universe")
            }
            Self::DuplicateTransformSource => {
                formatter.write_str("taint transform repeats one source class")
            }
            Self::Ide(error) => error.fmt(formatter),
        }
    }
}

impl Error for TaintSolveError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Ide(error) => Some(error),
            Self::RootMismatch | Self::UniverseMismatch | Self::DuplicateTransformSource => None,
        }
    }
}

impl From<IdeDataflowError> for TaintSolveError {
    fn from(error: IdeDataflowError) -> Self {
        Self::Ide(error)
    }
}
