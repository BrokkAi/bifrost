use std::{error::Error, fmt, sync::Arc};

use crate::analyzer::semantic::{
    EvidenceCompleteness, IcfgEdgeKind, IcfgProvider, IcfgSnapshot, IcfgSnapshotLimits,
    OracleCallContext, OracleLimits, ProcedureHandle, ProofStatus, SemanticBudget, SemanticWork,
};
use crate::dataflow::{
    BackwardDistributiveDataflowProblem, BackwardSnapshotDataflowError, BackwardSnapshotDemand,
    BackwardSnapshotProblem, DataflowDirectionCapabilities, DataflowDirectionPlan,
    DataflowDirectionPlanningError, DataflowDirectionRequirements, DataflowEdge, DataflowOutput,
    DataflowRequest, IcfgSolveInput, IdeDataflowError, IdeDataflowProblem,
    IdeSummaryDataflowResult, IdeSummarySolveInput, IdeTransition, ReusableIdeSummaryProvider,
    SnapshotReplayProvider, SolverTermination, SolverWork, SummaryWitnessStep,
    SummaryWitnessStepKind, WitnessRetentionLimits, plan_snapshot_dataflow_direction,
    snapshot_node_ids_for_points, solve_backward_with_snapshot, solve_ide_with_reusable_summaries,
    solve_ide_with_reusable_summaries_with_call_context, solve_ide_with_summaries,
    solve_ide_with_summaries_with_call_context,
};
use crate::value_flow::{
    AuthoredArmClosure, ValueFlowCarrierId, ValueFlowObservationPhase, ValueFlowSinkId,
    ValueFlowSourceId,
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

    pub(crate) const fn generated(&self) -> &TaintClassSet {
        &self.generated
    }

    pub(crate) const fn default_identity(&self) -> bool {
        self.default_identity
    }

    pub(crate) fn overrides(&self) -> &[(TaintClassId, TaintClassSet)] {
        &self.overrides
    }

    pub(crate) fn retained_heap_bytes(&self) -> usize {
        self.generated
            .retained_heap_bytes()
            .saturating_add(std::mem::size_of_val(&*self.overrides))
            .saturating_add(
                self.overrides
                    .iter()
                    .map(|(_, targets)| targets.retained_heap_bytes())
                    .fold(0usize, usize::saturating_add),
            )
    }

    pub(crate) fn from_canonical_parts(
        universe: &TaintUniverse,
        generated: TaintClassSet,
        default_identity: bool,
        overrides: Vec<(TaintClassId, TaintClassSet)>,
    ) -> Result<Self, TaintSolveError> {
        universe
            .validate_set(&generated)
            .map_err(|_| TaintSolveError::UniverseMismatch)?;
        let mut previous = None;
        for (source, targets) in &overrides {
            universe
                .validate_set(targets)
                .map_err(|_| TaintSolveError::UniverseMismatch)?;
            if previous.is_some_and(|previous| previous >= *source) {
                return Err(TaintSolveError::DuplicateTransformSource);
            }
            previous = Some(*source);
        }
        Ok(Self {
            generated,
            default_identity,
            overrides: overrides.into_boxed_slice(),
        })
    }

    pub fn apply(&self, value: &TaintClassSet) -> TaintClassSet {
        self.assert_value_compatible(value);
        let mut output = self.generated.clone();
        output.union_with(&self.apply_relation(value));
        output
    }

    /// Return the finite preimage of one output class.
    ///
    /// The taint domain is small enough to enumerate exactly. This is
    /// deliberately not implemented by swapping the sparse relation: a
    /// generated class is reachable from every input class, and a kill has no
    /// predecessor for the killed output. Keeping the enumeration here makes
    /// those cases explicit for the backward client.
    pub(crate) fn preimage_class(&self, output: TaintClassId) -> TaintClassSet {
        let mut input = self.generated.empty_like();
        let generated = self.generated.contains_dense(output);
        for index in 0..self.class_count() {
            let class =
                TaintClassId::try_from_index(index).expect("taint universe size was validated");
            if generated || self.output_for(class).contains_dense(output) {
                input.insert_dense(class);
            }
        }
        input
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

    pub(super) fn is_identity(&self) -> bool {
        self.generated.is_empty() && self.relation_is_identity()
    }

    fn relation_is_identity(&self) -> bool {
        self.default_identity && self.overrides.is_empty()
    }

    fn assert_value_compatible(&self, value: &TaintClassSet) {
        super::model::assert_class_sets_compatible(
            &self.generated,
            value,
            "taint edge function and value require one universe",
        );
    }

    fn assert_compatible(&self, other: &Self) {
        super::model::assert_class_sets_compatible(
            &self.generated,
            &other.generated,
            "taint edge functions require one universe",
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
        entry: Option<TaintMeetingEntryFact>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum TaintMeetingEntryFact {
    Zero,
    Carrier {
        carrier: ValueFlowCarrierId,
        uncertain: bool,
    },
}

impl TaintMeetingEntryFact {
    fn from_fact(fact: TaintFact) -> Option<Self> {
        match fact.0 {
            TaintFactKind::Zero => Some(Self::Zero),
            TaintFactKind::Carrier { carrier, uncertain } => {
                Some(Self::Carrier { carrier, uncertain })
            }
            TaintFactKind::Meeting { .. } => None,
        }
    }

    const fn fact(self) -> TaintFact {
        match self {
            Self::Zero => TaintFact::zero(),
            Self::Carrier { carrier, uncertain } => TaintFact::for_carrier(carrier, uncertain),
        }
    }
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

    pub(crate) const fn zero() -> Self {
        Self::ZERO
    }

    pub(crate) const fn for_carrier(carrier: ValueFlowCarrierId, uncertain: bool) -> Self {
        Self(TaintFactKind::Carrier { carrier, uncertain })
    }

    pub(crate) const fn for_sink(sink: ValueFlowSinkId, uncertain: bool) -> Self {
        Self(TaintFactKind::Meeting {
            sink,
            uncertain,
            entry: None,
        })
    }

    pub(crate) fn for_sink_with_entry(
        sink: ValueFlowSinkId,
        uncertain: bool,
        entry: TaintFact,
    ) -> Option<Self> {
        Some(Self(TaintFactKind::Meeting {
            sink,
            uncertain,
            entry: Some(TaintMeetingEntryFact::from_fact(entry)?),
        }))
    }

    pub(crate) const fn meeting_entry_fact(self) -> Option<TaintFact> {
        match self.0 {
            TaintFactKind::Meeting {
                entry: Some(entry), ..
            } => Some(entry.fact()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ActiveTaint<Evidence = ()> {
    evidence: Evidence,
    carrier: ValueFlowCarrierId,
    uncertain: bool,
    function: TaintEdgeFunction,
}

impl<Evidence> ActiveTaint<Evidence> {
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

/// Transfer observations are independent of the taint fact lattice. Discovery
/// uses the empty implementation; request-local refinement supplies the hook.
pub(crate) trait TaintObservationHook {
    type Evidence: Clone + Default + Eq + Ord;
    fn permits(
        &self,
        _point: &crate::analyzer::semantic::ProgramPointHandle,
        _phase: ValueFlowObservationPhase,
        _carrier: ValueFlowCarrierId,
        _function: &TaintEdgeFunction,
        _evidence: &mut Self::Evidence,
    ) -> bool {
        true
    }
    fn phase(
        &self,
        _point: &crate::analyzer::semantic::ProgramPointHandle,
        _phase: ValueFlowObservationPhase,
        _carrier: ValueFlowCarrierId,
        _function: &TaintEdgeFunction,
        _evidence: &mut Self::Evidence,
    ) -> bool {
        true
    }
    fn call_input(
        &self,
        _point: &crate::analyzer::semantic::ProgramPointHandle,
        _call: &crate::analyzer::semantic::CallSiteHandle,
        _carrier: ValueFlowCarrierId,
        _function: &TaintEdgeFunction,
        _evidence: &mut Self::Evidence,
    ) -> bool {
        true
    }
    fn model_input(
        &self,
        _point: &crate::analyzer::semantic::ProgramPointHandle,
        _call: &crate::analyzer::semantic::CallSiteHandle,
        _carrier: ValueFlowCarrierId,
        _function: &TaintEdgeFunction,
        _evidence: &mut Self::Evidence,
    ) -> bool {
        true
    }
    fn emitted(&self, _fact: TaintFact, _function: &TaintEdgeFunction, _evidence: &Self::Evidence) {
    }
    fn source_classes<'a>(
        &'a self,
        _source: ValueFlowSourceId,
        classes: &'a TaintClassSet,
    ) -> &'a TaintClassSet {
        classes
    }
    fn source(&self, _source: ValueFlowSourceId) -> bool {
        true
    }
}

pub struct NoTaintObservations;
impl TaintObservationHook for NoTaintObservations {
    type Evidence = ();
}

pub struct TaintFlowProblem<'plan, Hook = NoTaintObservations> {
    plan: &'plan TaintAnalysisPlan,
    observations: Hook,
}

impl<'plan> TaintFlowProblem<'plan> {
    pub const fn new(plan: &'plan TaintAnalysisPlan) -> Self {
        Self {
            plan,
            observations: NoTaintObservations,
        }
    }
}

#[allow(private_bounds)]
impl<'plan, Hook: TaintObservationHook> TaintFlowProblem<'plan, Hook> {
    pub(crate) fn with_observations(plan: &'plan TaintAnalysisPlan, observations: Hook) -> Self {
        Self { plan, observations }
    }

    fn observe(
        &self,
        point: &crate::analyzer::semantic::ProgramPointHandle,
        phase: ValueFlowObservationPhase,
        active: &mut Vec<ActiveTaint<Hook::Evidence>>,
    ) {
        active.retain_mut(|flow| {
            self.observations.permits(
                point,
                phase,
                flow.carrier,
                &flow.function,
                &mut flow.evidence,
            )
        });
    }

    /// Compose a modeled transfer's label function with the labels a pack-shipped
    /// sanitize effect removes on that transfer (#1923). This reuses the single
    /// label-removal primitive, `TaintEdgeFunction::kill`, that a policy-local
    /// sanitizer also composes. A removed label absent from the run universe
    /// cannot appear in any fact, so it is skipped rather than treated as an
    /// error.
    fn sanitized_transfer_function(
        &self,
        base: &TaintEdgeFunction,
        removed_labels: &[Box<str>],
    ) -> TaintEdgeFunction {
        if removed_labels.is_empty() {
            return base.clone();
        }
        let universe = self.plan.universe();
        let mut removed = universe.empty_set();
        for label in removed_labels {
            if let Ok(class) = SourceClassId::new(label.as_ref())
                && let Some(id) = universe.class_id(&class)
            {
                removed.insert_dense(id);
            }
        }
        base.compose(&TaintEdgeFunction::kill(&removed))
    }

    fn apply_sanitizers<'a>(
        &self,
        base: &TaintEdgeFunction,
        sanitizers: impl Iterator<Item = &'a super::TaintSanitizerBinding>,
    ) -> (TaintEdgeFunction, bool) {
        let mut function = base.clone();
        let mut complete = true;
        for sanitizer in sanitizers {
            if sanitizer.is_proven() {
                function = function.compose(&TaintEdgeFunction::kill(sanitizer.removed()));
            }
            if !sanitizer.is_resolved() {
                complete = false;
            }
        }
        (function, complete)
    }

    fn active_sources_at(
        &self,
        point: &crate::analyzer::semantic::ProgramPointHandle,
        phase: ValueFlowObservationPhase,
    ) -> Vec<ActiveTaint<Hook::Evidence>> {
        self.plan
            .value_flow()
            .source_bindings_at(point, phase)
            .filter_map(|(source, carrier)| {
                if !self.observations.source(source) {
                    return None;
                }
                let binding = self.plan.source(source)?;
                let spec = self.plan.value_flow().source(source)?;
                Some(ActiveTaint {
                    evidence: Default::default(),
                    carrier,
                    uncertain: !matches!(spec.proof(), ProofStatus::Proven)
                        || !matches!(spec.completeness(), EvidenceCompleteness::Complete),
                    function: TaintEdgeFunction::generate(
                        self.observations.source_classes(source, binding.classes()),
                    ),
                })
            })
            .collect()
    }

    fn ordinary_edge_flow(
        &self,
        edge: DataflowEdge<'_, TaintFact>,
        fact: TaintFact,
        out: &mut dyn DataflowOutput<IdeTransition<TaintFact, TaintEdgeFunction>>,
    ) {
        let mut output = Vec::new();
        let active = self.apply_point(
            edge.source(),
            fact,
            edge.summary_entry_fact().copied(),
            &mut output,
        );
        let mut active = active;
        self.apply_edge_kills(&edge, &mut active);
        self.emit(active, output, out);
    }

    /// Apply policy-local sanitizer effects while an input carrier crosses a
    /// call boundary. Keeping this out of the point transfer is important:
    /// the call-to-return edge still carries the caller's original value when
    /// the sanitizer result is unused. Unresolved bindings are deliberately
    /// retained as incomplete instead of removing any labels.
    fn sanitizer_input_transfer(
        &self,
        point: &crate::analyzer::semantic::ProgramPointHandle,
        carrier: ValueFlowCarrierId,
        base: &TaintEdgeFunction,
    ) -> (TaintEdgeFunction, bool) {
        self.apply_sanitizers(
            base,
            self.plan
                .sanitizers()
                .iter()
                .filter(|sanitizer| sanitizer.point() == point && sanitizer.carrier() == carrier),
        )
    }

    /// Apply a policy-local sanitizer only to its declared output transfer at
    /// an unmodeled call boundary. The preserved caller-side flow is emitted
    /// separately and remains untouched.
    fn sanitizer_boundary_transfer(
        &self,
        point: &crate::analyzer::semantic::ProgramPointHandle,
        input: ValueFlowCarrierId,
        output: ValueFlowCarrierId,
        base: &TaintEdgeFunction,
    ) -> (TaintEdgeFunction, bool) {
        self.apply_sanitizers(
            base,
            self.plan.sanitizers().iter().filter(|sanitizer| {
                sanitizer.point() == point
                    && sanitizer.carrier() == input
                    && sanitizer.output() == output
            }),
        )
    }

    fn initial_active(
        &self,
        point: &crate::analyzer::semantic::ProgramPointHandle,
        fact: TaintFact,
    ) -> Vec<ActiveTaint<Hook::Evidence>> {
        match fact.0 {
            TaintFactKind::Zero => {
                self.active_sources_at(point, ValueFlowObservationPhase::BeforeEffects)
            }
            TaintFactKind::Carrier { carrier, uncertain } => vec![ActiveTaint {
                evidence: Default::default(),
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
        active: &mut Vec<ActiveTaint<Hook::Evidence>>,
    ) {
        for flow in active.iter_mut() {
            let (transfer, complete) = self.plan.transfer_function(point, phase, flow.carrier);
            flow.function = flow.function.compose(transfer);
            flow.uncertain |= !complete;
        }
        active.retain_mut(|flow| {
            self.observations.phase(
                point,
                phase,
                flow.carrier,
                &flow.function,
                &mut flow.evidence,
            )
        });
    }

    fn apply_local_rules(
        &self,
        point: &crate::analyzer::semantic::ProgramPointHandle,
        active: &mut Vec<ActiveTaint<Hook::Evidence>>,
    ) {
        for rule in self.plan.value_flow().local_rule_views(point) {
            assert!(self.apply_local_rule(point, rule, active, usize::MAX));
        }
    }

    fn apply_local_rule(
        &self,
        point: &crate::analyzer::semantic::ProgramPointHandle,
        rule: crate::value_flow::LocalRuleView,
        active: &mut Vec<ActiveTaint<Hook::Evidence>>,
        max_generated: usize,
    ) -> bool {
        if crate::value_flow::rule_kills_target(&rule) {
            active.retain(|flow| flow.carrier != rule.target);
        }
        active.retain_mut(|flow| {
            flow.carrier != rule.source
                || self.observations.permits(
                    point,
                    ValueFlowObservationPhase::BeforeEffects,
                    flow.carrier,
                    &flow.function,
                    &mut flow.evidence,
                )
        });
        let local_transform = rule.policy_local.then(|| {
            self.plan
                .local_transform_function(point, rule.source, rule.target)
                .unwrap_or_else(|| self.plan.identity())
        });
        let mut generated = active
            .iter()
            .filter(|flow| flow.carrier == rule.source)
            .take(max_generated.saturating_add(1))
            .cloned()
            .map(|flow| {
                let mut flow = flow.through_semantics(rule.complete);
                if let Some(function) = local_transform {
                    flow.function = flow.function.compose(function);
                }
                ActiveTaint {
                    carrier: rule.target,
                    ..flow
                }
            })
            .collect::<Vec<_>>();
        if crate::value_flow::rule_invalidates_source(&rule) {
            active.retain(|flow| flow.carrier != rule.source);
        }
        self.observe(
            point,
            ValueFlowObservationPhase::AfterEffects,
            &mut generated,
        );
        if generated.len() > max_generated {
            return false;
        }
        active.extend(generated);
        true
    }

    fn append_sources_after(
        &self,
        point: &crate::analyzer::semantic::ProgramPointHandle,
        fact: TaintFact,
        active: &mut Vec<ActiveTaint<Hook::Evidence>>,
    ) {
        if !matches!(fact.0, TaintFactKind::Zero) {
            return;
        }
        active.extend(self.active_sources_at(point, ValueFlowObservationPhase::AfterEffects));
    }

    /// Apply source-selective value-flow kills after the guard point and before
    /// the selected intraprocedural edge. The taint domain carries source
    /// labels rather than value-flow source IDs, so the killed source IDs are
    /// projected to their declared class sets and composed as one edge-local
    /// kill function.
    fn apply_edge_kills(
        &self,
        edge: &DataflowEdge<'_, TaintFact>,
        active: &mut [ActiveTaint<Hook::Evidence>],
    ) {
        let IcfgEdgeKind::Intraprocedural(kind) = edge.kind() else {
            return;
        };
        let kills = self
            .plan
            .value_flow()
            .edge_kills(edge.source(), edge.target().id(), kind);
        if kills.is_empty() {
            return;
        }
        for flow in active {
            let mut killed = self.plan.universe().empty_set();
            for kill in kills.iter().filter(|kill| kill.carrier == flow.carrier) {
                for key in &kill.sources {
                    let Some(source) = self.plan.source(*key) else {
                        continue;
                    };
                    killed.union_with(source.classes());
                }
            }
            if !killed.is_empty() {
                flow.function = flow.function.compose(&TaintEdgeFunction::kill(&killed));
            }
        }
    }

    fn append_meetings(
        &self,
        point: &crate::analyzer::semantic::ProgramPointHandle,
        phase: ValueFlowObservationPhase,
        active: &[ActiveTaint<Hook::Evidence>],
        entry: Option<TaintFact>,
        output: &mut Vec<(TaintFact, TaintEdgeFunction, Hook::Evidence)>,
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
                let uncertain = flow.uncertain
                    || !matches!(spec.proof(), ProofStatus::Proven)
                    || !matches!(spec.completeness(), EvidenceCompleteness::Complete);
                let meeting = entry
                    .and_then(|entry| TaintFact::for_sink_with_entry(sink, uncertain, entry))
                    .unwrap_or_else(|| TaintFact::for_sink(sink, uncertain));
                output.push((meeting, flow.function.clone(), flow.evidence.clone()));
            }
        }
    }

    fn apply_point(
        &self,
        point: &crate::analyzer::semantic::ProgramPointHandle,
        fact: TaintFact,
        entry: Option<TaintFact>,
        output: &mut Vec<(TaintFact, TaintEdgeFunction, Hook::Evidence)>,
    ) -> Vec<ActiveTaint<Hook::Evidence>> {
        let active = self.initial_active(point, fact);
        let mut after = Vec::new();
        self.append_sources_after(point, fact, &mut after);
        self.apply_point_from_active(point, entry, active, after, output)
    }

    fn apply_point_from_active(
        &self,
        point: &crate::analyzer::semantic::ProgramPointHandle,
        entry: Option<TaintFact>,
        mut active: Vec<ActiveTaint<Hook::Evidence>>,
        after: Vec<ActiveTaint<Hook::Evidence>>,
        output: &mut Vec<(TaintFact, TaintEdgeFunction, Hook::Evidence)>,
    ) -> Vec<ActiveTaint<Hook::Evidence>> {
        self.apply_phase(point, ValueFlowObservationPhase::BeforeEffects, &mut active);
        self.append_meetings(
            point,
            ValueFlowObservationPhase::BeforeEffects,
            &active,
            entry,
            output,
        );
        self.apply_local_rules(point, &mut active);
        active.extend(after);
        self.apply_phase(point, ValueFlowObservationPhase::AfterEffects, &mut active);
        self.append_meetings(
            point,
            ValueFlowObservationPhase::AfterEffects,
            &active,
            entry,
            output,
        );
        active.sort_unstable();
        active.dedup();
        active
    }

    pub(crate) fn observer_candidates(
        &self,
        point: &crate::analyzer::semantic::ProgramPointHandle,
        fact: TaintFact,
        phase: ValueFlowObservationPhase,
        max_candidates: usize,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Option<Vec<(TaintFact, TaintEdgeFunction)>>, SolverTermination> {
        if request.cancellation.is_cancelled() {
            return Err(SolverTermination::Cancelled);
        }
        let mut active = match fact.0 {
            TaintFactKind::Zero => {
                let mut active = Vec::new();
                for (source, carrier) in self
                    .plan
                    .value_flow()
                    .source_bindings_at(point, ValueFlowObservationPhase::BeforeEffects)
                {
                    if request.cancellation.is_cancelled() {
                        return Err(SolverTermination::Cancelled);
                    }
                    if let Some(termination) = request.reserve(SolverWork {
                        callback_rows: 1,
                        ..SolverWork::default()
                    }) {
                        return Err(termination);
                    }
                    if !self.observations.source(source) {
                        continue;
                    }
                    let Some(binding) = self.plan.source(source) else {
                        continue;
                    };
                    let Some(spec) = self.plan.value_flow().source(source) else {
                        continue;
                    };
                    if active.len() == max_candidates {
                        return Ok(None);
                    }
                    active.push(ActiveTaint {
                        evidence: Default::default(),
                        carrier,
                        uncertain: !matches!(spec.proof(), ProofStatus::Proven)
                            || !matches!(spec.completeness(), EvidenceCompleteness::Complete),
                        function: TaintEdgeFunction::generate(
                            self.observations.source_classes(source, binding.classes()),
                        ),
                    });
                }
                active
            }
            TaintFactKind::Carrier { carrier, uncertain } => vec![ActiveTaint {
                evidence: Default::default(),
                carrier,
                uncertain,
                function: self.plan.identity().clone(),
            }],
            TaintFactKind::Meeting { .. } => Vec::new(),
        };
        if let Some(termination) = request.reserve(SolverWork {
            edge_function_operations: active.len(),
            ..SolverWork::default()
        }) {
            return Err(termination);
        }
        self.apply_phase(point, ValueFlowObservationPhase::BeforeEffects, &mut active);
        if phase == ValueFlowObservationPhase::AfterEffects {
            for rule in self.plan.value_flow().local_rule_views(point) {
                if request.cancellation.is_cancelled() {
                    return Err(SolverTermination::Cancelled);
                }
                if let Some(termination) = request.reserve(SolverWork {
                    ide_propagations: active.len(),
                    ..SolverWork::default()
                }) {
                    return Err(termination);
                }
                let invalidated = active
                    .iter()
                    .filter(|flow| {
                        (crate::value_flow::rule_kills_target(&rule) && flow.carrier == rule.target)
                            || (crate::value_flow::rule_invalidates_source(&rule)
                                && flow.carrier == rule.source)
                    })
                    .count();
                let remaining =
                    max_candidates.saturating_sub(active.len().saturating_sub(invalidated));
                if !self.apply_local_rule(point, rule, &mut active, remaining) {
                    return Ok(None);
                }
            }
            if matches!(fact.0, TaintFactKind::Zero) {
                let remaining = max_candidates.saturating_sub(active.len());
                let generated = self
                    .plan
                    .value_flow()
                    .source_bindings_at(point, ValueFlowObservationPhase::AfterEffects)
                    .filter_map(|(source, carrier)| {
                        if !self.observations.source(source) {
                            return None;
                        }
                        let binding = self.plan.source(source)?;
                        let spec = self.plan.value_flow().source(source)?;
                        Some(ActiveTaint {
                            evidence: Default::default(),
                            carrier,
                            uncertain: !matches!(spec.proof(), ProofStatus::Proven)
                                || !matches!(spec.completeness(), EvidenceCompleteness::Complete),
                            function: TaintEdgeFunction::generate(
                                self.observations.source_classes(source, binding.classes()),
                            ),
                        })
                    })
                    .take(remaining.saturating_add(1))
                    .collect::<Vec<_>>();
                if let Some(termination) = request.reserve(SolverWork {
                    callback_rows: generated.len(),
                    ..SolverWork::default()
                }) {
                    return Err(termination);
                }
                if generated.len() > remaining {
                    return Ok(None);
                }
                active.extend(generated);
            }
            if let Some(termination) = request.reserve(SolverWork {
                edge_function_operations: active.len(),
                ..SolverWork::default()
            }) {
                return Err(termination);
            }
            self.apply_phase(point, ValueFlowObservationPhase::AfterEffects, &mut active);
        }
        if request.cancellation.is_cancelled() {
            return Err(SolverTermination::Cancelled);
        }
        if let Some(termination) = request.reserve(SolverWork {
            ide_propagations: active.len(),
            ..SolverWork::default()
        }) {
            return Err(termination);
        }
        active.sort_unstable();
        active.dedup();
        Ok((active.len() <= max_candidates).then(|| {
            active
                .into_iter()
                .map(|flow| (flow.fact(), flow.function))
                .collect()
        }))
    }

    pub(crate) fn source_contribution(
        &self,
        source_id: crate::value_flow::ValueFlowSourceId,
        output_fact: TaintFact,
        context: &OracleCallContext,
        step: &SummaryWitnessStep,
    ) -> TaintClassSet {
        if !self.observations.source(source_id) {
            return self.plan.universe().empty_set();
        }
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
            evidence: Default::default(),
            carrier,
            uncertain: !matches!(spec.proof(), ProofStatus::Proven)
                || !matches!(spec.completeness(), EvidenceCompleteness::Complete),
            function: TaintEdgeFunction::generate(
                self.observations
                    .source_classes(source_id, binding.classes()),
            ),
        };
        let before = if spec.phase() == ValueFlowObservationPhase::BeforeEffects {
            vec![make_source()]
        } else {
            Vec::new()
        };
        let after = if spec.phase() == ValueFlowObservationPhase::AfterEffects {
            vec![make_source()]
        } else {
            Vec::new()
        };
        self.replay_witness_step(output_fact, step, context, before, after)
            .into_iter()
            .fold(self.plan.universe().empty_set(), |mut classes, function| {
                classes.union_with(&function.apply(&self.plan.universe().empty_set()));
                classes
            })
    }

    /// Map demanded output classes back through one exact retained witness
    /// step. Origin reconstruction uses this instead of assuming that class
    /// names are unchanged between a source and a sink.
    pub(crate) fn witness_step_preimages(
        &self,
        input_fact: TaintFact,
        output_fact: TaintFact,
        context: &OracleCallContext,
        step: &SummaryWitnessStep,
        demanded: &[(TaintClassId, TaintClassSet)],
    ) -> Vec<TaintClassSet> {
        let active = match input_fact.0 {
            TaintFactKind::Carrier { carrier, uncertain } => vec![ActiveTaint {
                evidence: Default::default(),
                carrier,
                uncertain,
                function: self.plan.identity().clone(),
            }],
            TaintFactKind::Zero | TaintFactKind::Meeting { .. } => Vec::new(),
        };
        let functions = self.replay_witness_step(output_fact, step, context, active, Vec::new());
        demanded
            .iter()
            .map(|(_, classes)| {
                let mut preimage = self.plan.universe().empty_set();
                for function in &functions {
                    for class in classes.iter_dense() {
                        preimage.union_with(&function.preimage_class(class));
                    }
                }
                preimage
            })
            .collect()
    }

    /// Replay one retained summary witness step from an explicitly selected
    /// set of active inputs. `after` supports a source whose authored phase is
    /// after effects without admitting every other source at the point.
    fn replay_witness_step(
        &self,
        output_fact: TaintFact,
        step: &SummaryWitnessStep,
        context: &OracleCallContext,
        mut active: Vec<ActiveTaint<Hook::Evidence>>,
        after: Vec<ActiveTaint<Hook::Evidence>>,
    ) -> Vec<TaintEdgeFunction> {
        let mut output = Vec::new();
        active = self.apply_point_from_active(
            step.source(),
            output_fact.meeting_entry_fact(),
            active,
            after,
            &mut output,
        );
        active = match step.kind() {
            SummaryWitnessStepKind::Edge(IcfgEdgeKind::Call) => {
                match (step.origin(), step.target()) {
                    (Some(call), Some(target)) => {
                        self.map_call(step.source(), target, call, Some(context), active)
                    }
                    _ => Vec::new(),
                }
            }
            SummaryWitnessStepKind::Edge(
                kind @ (IcfgEdgeKind::NormalReturn | IcfgEdgeKind::ExceptionalReturn),
            ) => match (step.origin(), step.target()) {
                (Some(call), Some(_target)) => {
                    self.map_return(step.source(), call, kind, Some(context), active)
                }
                _ => Vec::new(),
            },
            SummaryWitnessStepKind::Edge(
                kind @ (IcfgEdgeKind::CallToNormalContinuation
                | IcfgEdgeKind::CallToExceptionalContinuation),
            ) => self.map_boundary(step.source(), step.origin(), step.boundary(), kind, active),
            SummaryWitnessStepKind::Edge(IcfgEdgeKind::Intraprocedural(kind)) => {
                if let Some(target) = step.target() {
                    let kills = self
                        .plan
                        .value_flow()
                        .edge_kills(step.source(), target.id(), kind);
                    for flow in &mut active {
                        let mut killed = self.plan.universe().empty_set();
                        for kill in kills.iter().filter(|kill| kill.carrier == flow.carrier) {
                            for source in &kill.sources {
                                if let Some(source) = self.plan.source(*source) {
                                    killed.union_with(source.classes());
                                }
                            }
                        }
                        flow.function = flow.function.compose(&TaintEdgeFunction::kill(&killed));
                    }
                }
                active
            }
            _ => active,
        };
        output.extend(
            active
                .into_iter()
                .map(|flow| (flow.fact(), flow.function, flow.evidence)),
        );
        output
            .into_iter()
            .filter_map(|(fact, function, evidence)| {
                self.observations.emitted(fact, &function, &evidence);
                (fact == output_fact).then_some(function)
            })
            .collect()
    }

    fn emit(
        &self,
        active: Vec<ActiveTaint<Hook::Evidence>>,
        mut output: Vec<(TaintFact, TaintEdgeFunction, Hook::Evidence)>,
        out: &mut dyn DataflowOutput<IdeTransition<TaintFact, TaintEdgeFunction>>,
    ) {
        output.extend(
            active
                .into_iter()
                .map(|flow| (flow.fact(), flow.function, flow.evidence)),
        );
        output.sort_unstable();
        output.dedup();
        for (fact, function, evidence) in output {
            self.observations.emitted(fact, &function, &evidence);
            if !out.emit(IdeTransition::new(fact, function)) {
                break;
            }
        }
    }

    fn call_flow(
        &self,
        edge: DataflowEdge<'_, TaintFact>,
        fact: TaintFact,
        out: &mut dyn DataflowOutput<IdeTransition<TaintFact, TaintEdgeFunction>>,
    ) {
        let mut output = Vec::new();
        let active = self.apply_point(
            edge.source(),
            fact,
            edge.summary_entry_fact().copied(),
            &mut output,
        );
        let Some(transfer) = edge.call_transfer() else {
            self.emit(Vec::new(), output, out);
            return;
        };
        let mapped = self.map_call(
            edge.source(),
            edge.target(),
            &transfer.origin,
            edge.call_context(),
            active,
        );
        self.emit(mapped, output, out);
    }

    fn map_call(
        &self,
        point: &crate::analyzer::semantic::ProgramPointHandle,
        target: &crate::analyzer::semantic::ProgramPointHandle,
        call: &crate::analyzer::semantic::CallSiteHandle,
        context: Option<&OracleCallContext>,
        active: Vec<ActiveTaint<Hook::Evidence>>,
    ) -> Vec<ActiveTaint<Hook::Evidence>> {
        let mut mapped = active
            .into_iter()
            .flat_map(|mut flow| {
                let mut targets = self
                    .plan
                    .value_flow()
                    .call_targets_in_context(call, target.procedure(), flow.carrier, context)
                    .peekable();
                let preserves_port = self
                    .plan
                    .value_flow()
                    .is_callee_port(flow.carrier, target.procedure());
                let observed = preserves_port || targets.peek().is_some();
                let permitted = !observed
                    || self.observations.permits(
                        point,
                        ValueFlowObservationPhase::BeforeEffects,
                        flow.carrier,
                        &flow.function,
                        &mut flow.evidence,
                    );
                let (mapped_function, mapped_complete) =
                    self.sanitizer_input_transfer(point, flow.carrier, &flow.function);
                let mapped_flow = ActiveTaint {
                    function: mapped_function,
                    ..flow.clone().through_semantics(mapped_complete)
                };
                let preserved = (permitted && preserves_port).then_some(flow.clone());
                preserved
                    .into_iter()
                    .chain(
                        targets
                            .filter(move |_| permitted)
                            .map(move |(target, complete)| ActiveTaint {
                                carrier: target,
                                ..mapped_flow.clone().through_semantics(complete)
                            }),
                    )
            })
            .collect();
        self.observe(
            target,
            ValueFlowObservationPhase::BeforeEffects,
            &mut mapped,
        );
        mapped
    }

    fn return_flow(
        &self,
        edge: DataflowEdge<'_, TaintFact>,
        fact: TaintFact,
        out: &mut dyn DataflowOutput<IdeTransition<TaintFact, TaintEdgeFunction>>,
    ) {
        let mut output = Vec::new();
        let active = self.apply_point(
            edge.source(),
            fact,
            edge.summary_entry_fact().copied(),
            &mut output,
        );
        let Some(call) = edge.origin() else {
            self.emit(Vec::new(), output, out);
            return;
        };
        let mapped = self.map_return(
            edge.source(),
            call,
            edge.kind(),
            edge.call_context(),
            active,
        );
        self.emit(mapped, output, out);
    }

    fn map_return(
        &self,
        point: &crate::analyzer::semantic::ProgramPointHandle,
        call: &crate::analyzer::semantic::CallSiteHandle,
        kind: IcfgEdgeKind,
        context: Option<&OracleCallContext>,
        active: Vec<ActiveTaint<Hook::Evidence>>,
    ) -> Vec<ActiveTaint<Hook::Evidence>> {
        let callee = point.procedure();
        let mut mapped = active
            .into_iter()
            .flat_map(|mut flow| {
                let mut targets = match kind {
                    IcfgEdgeKind::NormalReturn => self
                        .plan
                        .value_flow()
                        .normal_return_targets_in_context(call, callee, flow.carrier, context)
                        .collect::<Vec<_>>(),
                    IcfgEdgeKind::ExceptionalReturn => self
                        .plan
                        .value_flow()
                        .exceptional_return_targets_in_context(call, callee, flow.carrier, context)
                        .collect::<Vec<_>>(),
                    _ => Vec::new(),
                };
                if !targets.is_empty()
                    && !self.observations.permits(
                        point,
                        ValueFlowObservationPhase::BeforeEffects,
                        flow.carrier,
                        &flow.function,
                        &mut flow.evidence,
                    )
                {
                    targets.clear();
                }
                targets
                    .into_iter()
                    .map(move |(target, complete)| ActiveTaint {
                        carrier: target,
                        ..flow.clone().through_semantics(complete)
                    })
            })
            .collect();
        let site = call
            .procedure()
            .semantics()
            .call_site(call.id())
            .expect("a return names a live caller site");
        let call_point = call
            .procedure()
            .point_handle(site.point)
            .expect("a call retains its point");
        self.observe(
            &call_point,
            ValueFlowObservationPhase::AfterEffects,
            &mut mapped,
        );
        mapped
    }

    fn boundary_flow(
        &self,
        edge: DataflowEdge<'_, TaintFact>,
        fact: TaintFact,
        out: &mut dyn DataflowOutput<IdeTransition<TaintFact, TaintEdgeFunction>>,
    ) {
        let mut output = Vec::new();
        let active = self.apply_point(
            edge.source(),
            fact,
            edge.summary_entry_fact().copied(),
            &mut output,
        );
        if edge.origin().is_none() {
            self.emit(active, output, out);
            return;
        }
        output.sort_unstable();
        output.dedup();
        for (fact, function, evidence) in output {
            self.observations.emitted(fact, &function, &evidence);
            if !out.emit(IdeTransition::new(fact, function)) {
                return;
            }
        }
        self.visit_boundary(
            edge.source(),
            edge.origin(),
            edge.boundary(),
            edge.kind(),
            active,
            |flow| {
                self.observations
                    .emitted(flow.fact(), &flow.function, &flow.evidence);
                out.emit(IdeTransition::new(flow.fact(), flow.function))
            },
        );
    }

    fn map_boundary(
        &self,
        point: &crate::analyzer::semantic::ProgramPointHandle,
        call: Option<&crate::analyzer::semantic::CallSiteHandle>,
        boundary: Option<&crate::analyzer::semantic::DispatchBoundaryKind>,
        kind: IcfgEdgeKind,
        active: Vec<ActiveTaint<Hook::Evidence>>,
    ) -> Vec<ActiveTaint<Hook::Evidence>> {
        let mut mapped = Vec::new();
        self.visit_boundary(point, call, boundary, kind, active, |flow| {
            mapped.push(flow);
            true
        });
        mapped
    }

    fn visit_boundary(
        &self,
        point: &crate::analyzer::semantic::ProgramPointHandle,
        call: Option<&crate::analyzer::semantic::CallSiteHandle>,
        boundary: Option<&crate::analyzer::semantic::DispatchBoundaryKind>,
        kind: IcfgEdgeKind,
        mut active: Vec<ActiveTaint<Hook::Evidence>>,
        mut emit: impl FnMut(ActiveTaint<Hook::Evidence>) -> bool,
    ) {
        let Some(call) = call else {
            for flow in active {
                if !emit(flow) {
                    return;
                }
            }
            return;
        };
        active.retain_mut(|flow| {
            self.observations.call_input(
                point,
                call,
                flow.carrier,
                &flow.function,
                &mut flow.evidence,
            )
        });
        for mut flow in active {
            let mut input_rejected = false;
            let mut emitting = true;
            let application = self.plan.value_flow().visit_boundary_transfers(
                call,
                boundary,
                kind,
                flow.carrier,
                |transfer| {
                    if input_rejected
                        || !self.observations.model_input(
                            point,
                            call,
                            flow.carrier,
                            &flow.function,
                            &mut flow.evidence,
                        )
                    {
                        input_rejected = true;
                        return true;
                    }
                    let (function, complete) = self.sanitizer_boundary_transfer(
                        point,
                        flow.carrier,
                        transfer.target,
                        &flow.function,
                    );
                    let mut transferred = ActiveTaint {
                        evidence: flow.evidence.clone(),
                        carrier: transfer.target,
                        uncertain: flow.uncertain
                            || !(transfer.proven_complete || transfer.authored_complete)
                            || !complete,
                        function: self
                            .sanitized_transfer_function(&function, &transfer.removed_labels),
                    };
                    if self.observations.permits(
                        point,
                        ValueFlowObservationPhase::AfterEffects,
                        transferred.carrier,
                        &transferred.function,
                        &mut transferred.evidence,
                    ) {
                        emitting = emit(transferred);
                    }
                    emitting
                },
            );
            if !emitting {
                return;
            }
            if !input_rejected
                && !emit(ActiveTaint {
                    uncertain: flow.uncertain || application.abstained,
                    ..flow
                })
            {
                return;
            }
        }
    }
}

#[allow(private_bounds)]
impl<Hook: TaintObservationHook> IdeDataflowProblem for TaintFlowProblem<'_, Hook> {
    type Fact = TaintFact;
    type Value = TaintClassSet;
    type EdgeFunction = TaintEdgeFunction;

    fn zero_fact(&self) -> Self::Fact {
        TaintFact::ZERO
    }

    fn resolved_call_to_return(&self) -> bool {
        true
    }

    fn call_replaced_by_model(&self, call: &crate::analyzer::semantic::CallSiteHandle) -> bool {
        self.plan
            .value_flow()
            .curated_model_for_call(call)
            .is_some()
    }

    fn call_replaced_by_proven_model(
        &self,
        call: &crate::analyzer::semantic::CallSiteHandle,
    ) -> bool {
        self.plan
            .value_flow()
            .curated_model_is_proven_complete(call)
    }

    fn zero_value(&self) -> Self::Value {
        self.plan.universe().empty_set()
    }

    fn identity_edge_function(&self) -> Self::EdgeFunction {
        self.plan.identity().clone()
    }

    fn is_flow_observation(&self, fact: &Self::Fact) -> bool {
        // A sink-meeting fact records that tainted data reached a bound sink
        // on the current path. It is a terminal observation of the calling
        // context, never a value entering a callee (#1917).
        fact.sink().is_some()
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
        edge: DataflowEdge<'_, Self::Fact>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<IdeTransition<Self::Fact, Self::EdgeFunction>>,
    ) {
        self.ordinary_edge_flow(edge, fact, out);
    }

    fn call_flow(
        &self,
        edge: DataflowEdge<'_, Self::Fact>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<IdeTransition<Self::Fact, Self::EdgeFunction>>,
    ) {
        self.call_flow(edge, fact, out);
    }

    fn return_flow(
        &self,
        edge: DataflowEdge<'_, Self::Fact>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<IdeTransition<Self::Fact, Self::EdgeFunction>>,
    ) {
        self.return_flow(edge, fact, out);
    }

    fn call_to_return_flow(
        &self,
        edge: DataflowEdge<'_, Self::Fact>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<IdeTransition<Self::Fact, Self::EdgeFunction>>,
    ) {
        self.boundary_flow(edge, fact, out);
    }

    fn exceptional_flow(
        &self,
        edge: DataflowEdge<'_, Self::Fact>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<IdeTransition<Self::Fact, Self::EdgeFunction>>,
    ) {
        self.ordinary_edge_flow(edge, fact, out);
    }
}

/// One finite backward taint demand.
///
/// Backward tabulation carries the dense class in the fact topology rather
/// than in an IDE value. That makes every preimage explicit and keeps the
/// kernel's backward contract (which is a finite fact relation) honest. A
/// separate `Hit` variant records a source that can satisfy a demand; hits do
/// not continue past their source point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaintBackwardFact(TaintBackwardFactKind);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum TaintBackwardFactKind {
    Zero,
    Demand {
        carrier: ValueFlowCarrierId,
        sink: ValueFlowSinkId,
        class_index: u16,
        phase: TaintBackwardPhase,
        uncertain: bool,
    },
    Hit {
        source: ValueFlowSourceId,
        sink: ValueFlowSinkId,
        class_index: u16,
        uncertain: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum TaintBackwardPhase {
    BeforeEffects,
    AfterEffects,
    PointEntry,
}

impl From<ValueFlowObservationPhase> for TaintBackwardPhase {
    fn from(phase: ValueFlowObservationPhase) -> Self {
        match phase {
            ValueFlowObservationPhase::BeforeEffects => Self::BeforeEffects,
            ValueFlowObservationPhase::AfterEffects => Self::AfterEffects,
        }
    }
}

impl TaintBackwardFact {
    const ZERO: Self = Self(TaintBackwardFactKind::Zero);

    pub const fn zero() -> Self {
        Self::ZERO
    }

    const fn demand(
        carrier: ValueFlowCarrierId,
        sink: ValueFlowSinkId,
        class_index: u16,
        phase: TaintBackwardPhase,
        uncertain: bool,
    ) -> Self {
        Self(TaintBackwardFactKind::Demand {
            carrier,
            sink,
            class_index,
            phase,
            uncertain,
        })
    }

    const fn hit(
        source: ValueFlowSourceId,
        sink: ValueFlowSinkId,
        class_index: u16,
        uncertain: bool,
    ) -> Self {
        Self(TaintBackwardFactKind::Hit {
            source,
            sink,
            class_index,
            uncertain,
        })
    }

    pub const fn carrier(self) -> Option<ValueFlowCarrierId> {
        match self.0 {
            TaintBackwardFactKind::Demand { carrier, .. } => Some(carrier),
            TaintBackwardFactKind::Zero | TaintBackwardFactKind::Hit { .. } => None,
        }
    }

    pub const fn source(self) -> Option<ValueFlowSourceId> {
        match self.0 {
            TaintBackwardFactKind::Hit { source, .. } => Some(source),
            TaintBackwardFactKind::Zero | TaintBackwardFactKind::Demand { .. } => None,
        }
    }

    pub const fn sink(self) -> Option<ValueFlowSinkId> {
        match self.0 {
            TaintBackwardFactKind::Demand { sink, .. }
            | TaintBackwardFactKind::Hit { sink, .. } => Some(sink),
            TaintBackwardFactKind::Zero => None,
        }
    }

    pub const fn class_index(self) -> Option<u16> {
        match self.0 {
            TaintBackwardFactKind::Demand { class_index, .. }
            | TaintBackwardFactKind::Hit { class_index, .. } => Some(class_index),
            TaintBackwardFactKind::Zero => None,
        }
    }

    pub const fn is_uncertain(self) -> bool {
        match self.0 {
            TaintBackwardFactKind::Demand { uncertain, .. }
            | TaintBackwardFactKind::Hit { uncertain, .. } => uncertain,
            TaintBackwardFactKind::Zero => false,
        }
    }

    const fn is_demand(self) -> bool {
        matches!(self.0, TaintBackwardFactKind::Demand { .. })
    }

    const fn is_zero(self) -> bool {
        matches!(self.0, TaintBackwardFactKind::Zero)
    }

    const fn demand_parts(
        self,
    ) -> Option<(
        ValueFlowCarrierId,
        ValueFlowSinkId,
        u16,
        TaintBackwardPhase,
        bool,
    )> {
        match self.0 {
            TaintBackwardFactKind::Demand {
                carrier,
                sink,
                class_index,
                phase,
                uncertain,
            } => Some((carrier, sink, class_index, phase, uncertain)),
            TaintBackwardFactKind::Zero | TaintBackwardFactKind::Hit { .. } => None,
        }
    }
}

/// A source/sink/class witness discovered by the backward solve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaintBackwardHit {
    source: ValueFlowSourceId,
    sink: ValueFlowSinkId,
    class_index: u16,
    uncertain: bool,
}

impl TaintBackwardHit {
    pub const fn source(self) -> ValueFlowSourceId {
        self.source
    }

    pub const fn sink(self) -> ValueFlowSinkId {
        self.sink
    }

    pub const fn class_index(self) -> u16 {
        self.class_index
    }

    pub const fn is_uncertain(self) -> bool {
        self.uncertain
    }
}

/// Explicit backward taint problem over a root-scoped bounded ICFG.
pub struct TaintBackwardFlowProblem<'plan> {
    plan: &'plan TaintAnalysisPlan,
    demands: Box<[BackwardSnapshotDemand<TaintBackwardFact>]>,
}

impl<'plan> TaintBackwardFlowProblem<'plan> {
    pub fn new(plan: &'plan TaintAnalysisPlan) -> Self {
        let mut demands = Vec::new();
        for (sink, spec) in plan.value_flow().sinks() {
            let Some(binding) = plan.sink(sink) else {
                continue;
            };
            let Some((_, carrier)) = plan
                .value_flow()
                .sink_bindings_at(spec.point(), spec.phase())
                .find(|(candidate, _)| *candidate == sink)
            else {
                continue;
            };
            let uncertain = !matches!(spec.proof(), ProofStatus::Proven)
                || !matches!(spec.completeness(), EvidenceCompleteness::Complete);
            for class in binding.accepted().iter_dense() {
                let class_index = u16::try_from(class.index()).expect("taint universe fits in u16");
                demands.push(BackwardSnapshotDemand::new(
                    spec.point().clone(),
                    TaintBackwardFact::demand(
                        carrier,
                        sink,
                        class_index,
                        spec.phase().into(),
                        uncertain,
                    ),
                ));
            }
        }
        demands.sort_unstable_by(|left, right| {
            left.point()
                .procedure()
                .semantics()
                .locator()
                .cmp(right.point().procedure().semantics().locator())
                .then_with(|| left.point().id().cmp(&right.point().id()))
                .then_with(|| left.fact().cmp(right.fact()))
        });
        demands.dedup();
        Self {
            plan,
            demands: demands.into_boxed_slice(),
        }
    }

    fn class_id(&self, index: u16) -> Option<TaintClassId> {
        TaintClassId::try_from_index(usize::from(index)).ok()
    }

    fn edge_uncertain(edge: DataflowEdge<'_, TaintBackwardFact>) -> bool {
        !matches!(edge.proof(), ProofStatus::Proven)
            || !matches!(edge.completeness(), EvidenceCompleteness::Complete)
    }

    fn demand_with(
        demand: TaintBackwardFact,
        carrier: ValueFlowCarrierId,
        class_index: u16,
        uncertain: bool,
    ) -> TaintBackwardFact {
        let (_, sink, _, phase, original_uncertain) = demand
            .demand_parts()
            .expect("backward carrier mapping only handles demand facts");
        TaintBackwardFact::demand(
            carrier,
            sink,
            class_index,
            phase,
            original_uncertain || uncertain,
        )
    }

    fn demand_at_phase(demand: TaintBackwardFact, phase: TaintBackwardPhase) -> TaintBackwardFact {
        let (carrier, sink, class_index, _, uncertain) = demand
            .demand_parts()
            .expect("only demand facts carry a point phase");
        TaintBackwardFact::demand(carrier, sink, class_index, phase, uncertain)
    }

    fn inverse_phase(
        &self,
        point: &crate::analyzer::semantic::ProgramPointHandle,
        phase: ValueFlowObservationPhase,
        facts: Vec<TaintBackwardFact>,
    ) -> Vec<TaintBackwardFact> {
        let mut output = Vec::new();
        for fact in facts {
            let Some((carrier, _, class_index, _, _)) = fact.demand_parts() else {
                continue;
            };
            let Some(class) = self.class_id(class_index) else {
                continue;
            };
            let (function, complete) = self.plan.transfer_function(point, phase, carrier);
            for predecessor in function.preimage_class(class).iter_dense() {
                let predecessor_index =
                    u16::try_from(predecessor.index()).expect("taint universe fits in u16");
                output.push(Self::demand_with(
                    fact,
                    carrier,
                    predecessor_index,
                    !complete,
                ));
            }
        }
        output.sort_unstable();
        output.dedup();
        output
    }

    fn append_source_hits(
        &self,
        point: &crate::analyzer::semantic::ProgramPointHandle,
        phase: ValueFlowObservationPhase,
        facts: &[TaintBackwardFact],
        output: &mut Vec<TaintBackwardFact>,
    ) {
        for fact in facts {
            let Some((carrier, sink, class_index, _, uncertain)) = fact.demand_parts() else {
                continue;
            };
            let Some(class) = self.class_id(class_index) else {
                continue;
            };
            for (source, source_carrier) in self.plan.value_flow().source_bindings_at(point, phase)
            {
                let Some(binding) = self.plan.source(source) else {
                    continue;
                };
                let Some(spec) = self.plan.value_flow().source(source) else {
                    continue;
                };
                if source_carrier != carrier || !binding.classes().contains_dense(class) {
                    continue;
                }
                output.push(TaintBackwardFact::hit(
                    source,
                    sink,
                    class_index,
                    uncertain
                        || !matches!(spec.proof(), ProofStatus::Proven)
                        || !matches!(spec.completeness(), EvidenceCompleteness::Complete),
                ));
            }
        }
    }

    fn inverse_local_rules(
        &self,
        point: &crate::analyzer::semantic::ProgramPointHandle,
        mut facts: Vec<TaintBackwardFact>,
    ) -> Vec<TaintBackwardFact> {
        // The point reverse index retains every local rule in reverse event
        // order. A target-only lookup misses chained rules whose source
        // becomes the next demanded carrier.
        let reverse_views = self
            .plan
            .value_flow()
            .local_rule_views_reverse_at(point)
            .collect::<Vec<_>>();
        for view in reverse_views {
            let mut next = Vec::with_capacity(facts.len().saturating_add(1));
            for fact in facts {
                let Some((carrier, _, class_index, _, uncertain)) = fact.demand_parts() else {
                    next.push(fact);
                    continue;
                };
                if crate::value_flow::rule_invalidates_source(&view)
                    && carrier == view.source
                    && carrier != view.target
                {
                    continue;
                }
                if carrier != view.target {
                    next.push(fact);
                    continue;
                }
                if !crate::value_flow::rule_kills_target(&view) {
                    next.push(fact);
                }
                let predecessors = if view.policy_local {
                    self.plan
                        .local_transform_function(point, view.source, view.target)
                        .unwrap_or_else(|| self.plan.identity())
                        .preimage_class(
                            self.class_id(class_index)
                                .expect("a demand class belongs to the plan universe"),
                        )
                } else {
                    let mut identity = self.plan.universe().empty_set();
                    identity.insert_dense(
                        self.class_id(class_index)
                            .expect("a demand class belongs to the plan universe"),
                    );
                    identity
                };
                for predecessor in predecessors.iter_dense() {
                    next.push(Self::demand_with(
                        fact,
                        view.source,
                        u16::try_from(predecessor.index()).expect("taint universe fits in u16"),
                        uncertain || !view.complete,
                    ));
                }
            }
            next.sort_unstable();
            next.dedup();
            facts = next;
        }
        facts
    }

    fn inverse_point(
        &self,
        point: &crate::analyzer::semantic::ProgramPointHandle,
        fact: TaintBackwardFact,
        out: &mut Vec<TaintBackwardFact>,
    ) {
        let Some((_, _, _, phase, _)) = fact.demand_parts() else {
            return;
        };
        let mut facts = match phase {
            TaintBackwardPhase::AfterEffects => {
                let mut facts =
                    self.inverse_phase(point, ValueFlowObservationPhase::AfterEffects, vec![fact]);
                self.append_source_hits(
                    point,
                    ValueFlowObservationPhase::AfterEffects,
                    &facts,
                    out,
                );
                facts = self.inverse_local_rules(point, facts);
                self.inverse_phase(point, ValueFlowObservationPhase::BeforeEffects, facts)
            }
            TaintBackwardPhase::BeforeEffects => {
                self.inverse_phase(point, ValueFlowObservationPhase::BeforeEffects, vec![fact])
            }
            TaintBackwardPhase::PointEntry => vec![fact],
        };
        if !matches!(phase, TaintBackwardPhase::PointEntry) {
            self.append_source_hits(point, ValueFlowObservationPhase::BeforeEffects, &facts, out);
        }
        out.extend(
            facts
                .drain(..)
                .map(|fact| Self::demand_at_phase(fact, TaintBackwardPhase::PointEntry)),
        );
    }

    fn inverse_boundary_classes(&self, labels: &[Box<str>], class_index: u16) -> Vec<u16> {
        let mut removed = self.plan.universe().empty_set();
        for label in labels {
            if let Ok(class) = SourceClassId::new(label.as_ref())
                && let Some(id) = self.plan.universe().class_id(&class)
            {
                removed.insert_dense(id);
            }
        }
        let Some(class) = self.class_id(class_index) else {
            return Vec::new();
        };
        let function = TaintEdgeFunction::kill(&removed);
        function
            .preimage_class(class)
            .iter_dense()
            .map(|id| u16::try_from(id.index()).expect("taint universe fits in u16"))
            .collect()
    }

    /// Compute the backward preimage of a class after a policy-local
    /// input-to-output sanitizer transfer. The policy transfer is kept
    /// separate from the semantic boundary labels so unresolved policy
    /// bindings can conservatively preserve the demand while marking it
    /// uncertain.
    fn inverse_policy_sanitizer_classes(
        &self,
        point: &crate::analyzer::semantic::ProgramPointHandle,
        input: ValueFlowCarrierId,
        output: ValueFlowCarrierId,
        class_index: u16,
    ) -> Vec<(u16, bool)> {
        let Some(class) = self.class_id(class_index) else {
            return Vec::new();
        };
        let mut classes = vec![(class, false)];
        for sanitizer in self.plan.sanitizers().iter().filter(|sanitizer| {
            sanitizer.point() == point
                && sanitizer.carrier() == input
                && sanitizer.output() == output
                && sanitizer.carrier() != sanitizer.output()
        }) {
            if sanitizer.is_proven() {
                let mut predecessors = Vec::new();
                let function = TaintEdgeFunction::kill(sanitizer.removed());
                for (class, uncertain) in classes {
                    predecessors.extend(
                        function
                            .preimage_class(class)
                            .iter_dense()
                            .map(|predecessor| (predecessor, uncertain)),
                    );
                }
                classes = predecessors;
            }
            if !sanitizer.is_resolved() {
                for (_, uncertain) in &mut classes {
                    *uncertain = true;
                }
            }
        }
        classes
            .into_iter()
            .map(|(class, uncertain)| {
                (
                    u16::try_from(class.index()).expect("taint universe fits in u16"),
                    uncertain,
                )
            })
            .collect()
    }

    fn inverse_edge_carriers(
        &self,
        edge: DataflowEdge<'_, TaintBackwardFact>,
        demand: TaintBackwardFact,
    ) -> Vec<(ValueFlowCarrierId, u16, bool)> {
        let Some((output_carrier, _, class_index, _, uncertain)) = demand.demand_parts() else {
            return Vec::new();
        };
        let edge_uncertain = Self::edge_uncertain(edge);
        match edge.kind() {
            IcfgEdgeKind::Intraprocedural(_) => {
                vec![(output_carrier, class_index, uncertain || edge_uncertain)]
            }
            IcfgEdgeKind::Call => {
                let Some(call) = edge.origin() else {
                    return Vec::new();
                };
                let callee = edge.target().procedure();
                let mut output = Vec::new();
                if self
                    .plan
                    .value_flow()
                    .is_callee_port(output_carrier, callee)
                {
                    output.push((output_carrier, class_index, uncertain || edge_uncertain));
                }
                for index in 0..self.plan.value_flow().carriers().len() {
                    let source = ValueFlowCarrierId::try_from_index(index)
                        .expect("carrier count fits dense ID capacity");
                    for (target, complete) in self.plan.value_flow().call_targets_in_context(
                        call,
                        callee,
                        source,
                        edge.call_context(),
                    ) {
                        if target == output_carrier {
                            for (predecessor_class, sanitizer_uncertain) in self
                                .inverse_policy_sanitizer_classes(
                                    edge.source(),
                                    source,
                                    target,
                                    class_index,
                                )
                            {
                                output.push((
                                    source,
                                    predecessor_class,
                                    uncertain || edge_uncertain || !complete || sanitizer_uncertain,
                                ));
                            }
                        }
                    }
                }
                output
            }
            IcfgEdgeKind::NormalReturn | IcfgEdgeKind::ExceptionalReturn => {
                let Some(call) = edge.origin() else {
                    return Vec::new();
                };
                let callee = edge.source().procedure();
                let mut output = Vec::new();
                // Return targets are indexed by the forward source. Enumerate
                // the finite carrier universe to compute their exact inverse.
                for index in 0..self.plan.value_flow().carriers().len() {
                    let source = ValueFlowCarrierId::try_from_index(index)
                        .expect("carrier count fits dense ID capacity");
                    let targets = match edge.kind() {
                        IcfgEdgeKind::NormalReturn => self
                            .plan
                            .value_flow()
                            .normal_return_targets_in_context(
                                call,
                                callee,
                                source,
                                edge.call_context(),
                            )
                            .collect::<Vec<_>>(),
                        IcfgEdgeKind::ExceptionalReturn => self
                            .plan
                            .value_flow()
                            .exceptional_return_targets_in_context(
                                call,
                                callee,
                                source,
                                edge.call_context(),
                            )
                            .collect::<Vec<_>>(),
                        _ => unreachable!(),
                    };
                    for (target, complete) in targets {
                        if target == output_carrier {
                            output.push((
                                source,
                                class_index,
                                uncertain || edge_uncertain || !complete,
                            ));
                        }
                    }
                }
                output
            }
            IcfgEdgeKind::CallToNormalContinuation
            | IcfgEdgeKind::CallToExceptionalContinuation => {
                let Some(call) = edge.origin() else {
                    return Vec::new();
                };
                let mut output = Vec::new();
                for index in 0..self.plan.value_flow().carriers().len() {
                    let source = ValueFlowCarrierId::try_from_index(index)
                        .expect("carrier count fits dense ID capacity");
                    if source == output_carrier {
                        output.push((source, class_index, uncertain || edge_uncertain));
                    }
                    let mut transfers = Vec::new();
                    let application = self.plan.value_flow().visit_boundary_transfers(
                        call,
                        edge.boundary(),
                        edge.kind(),
                        source,
                        |transfer| {
                            transfers.push(transfer);
                            true
                        },
                    );
                    for transfer in transfers {
                        if transfer.target != output_carrier {
                            continue;
                        }
                        for (policy_class, sanitizer_uncertain) in self
                            .inverse_policy_sanitizer_classes(
                                edge.source(),
                                source,
                                transfer.target,
                                class_index,
                            )
                        {
                            for predecessor_class in self
                                .inverse_boundary_classes(&transfer.removed_labels, policy_class)
                            {
                                output.push((
                                    source,
                                    predecessor_class,
                                    uncertain
                                        || edge_uncertain
                                        || !(transfer.proven_complete
                                            || transfer.authored_complete)
                                        || sanitizer_uncertain,
                                ));
                            }
                        }
                    }
                    if source == output_carrier && application.abstained {
                        output.push((source, class_index, true));
                    }
                }
                output
            }
        }
    }

    fn emit_predecessors(
        &self,
        edge: DataflowEdge<'_, TaintBackwardFact>,
        output_fact: TaintBackwardFact,
        out: &mut dyn DataflowOutput<TaintBackwardFact>,
    ) {
        if output_fact.is_zero() || !output_fact.is_demand() {
            return;
        }
        let mut target_demands = Vec::new();
        self.inverse_point(edge.target(), output_fact, &mut target_demands);
        let mut predecessors = Vec::new();
        for target_demand in target_demands {
            if !target_demand.is_demand() {
                predecessors.push(target_demand);
                continue;
            }
            for (carrier, class_index, uncertain) in self.inverse_edge_carriers(edge, target_demand)
            {
                let demand = Self::demand_at_phase(
                    Self::demand_with(target_demand, carrier, class_index, uncertain),
                    TaintBackwardPhase::AfterEffects,
                );
                self.inverse_point(edge.source(), demand, &mut predecessors);
            }
        }
        predecessors.sort_unstable();
        predecessors.dedup();
        for predecessor in predecessors {
            if !out.emit(predecessor) {
                break;
            }
        }
    }
}

impl BackwardSnapshotProblem for TaintBackwardFlowProblem<'_> {
    fn demands(&self, out: &mut dyn DataflowOutput<BackwardSnapshotDemand<Self::Fact>>) {
        for demand in &self.demands {
            let mut initial = Vec::new();
            self.inverse_point(demand.point(), *demand.fact(), &mut initial);
            initial.sort_unstable();
            initial.dedup();
            for fact in initial {
                if !out.emit(BackwardSnapshotDemand::new(demand.point().clone(), fact)) {
                    return;
                }
            }
        }
    }
}

impl BackwardDistributiveDataflowProblem for TaintBackwardFlowProblem<'_> {
    type Fact = TaintBackwardFact;

    fn zero_fact(&self) -> Self::Fact {
        TaintBackwardFact::zero()
    }

    /// The forward taint client takes the caller-side continuation of a
    /// resolved call, so the preimage relation must take it too, or a class
    /// the callee neither receives nor returns has no backward path past the
    /// call (#2782).
    fn resolved_call_to_return(&self) -> bool {
        true
    }

    fn normal_predecessor_flow(
        &self,
        edge: DataflowEdge<'_, Self::Fact>,
        output_fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.emit_predecessors(edge, output_fact, out);
    }

    fn call_predecessor_flow(
        &self,
        edge: DataflowEdge<'_, Self::Fact>,
        output_fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.emit_predecessors(edge, output_fact, out);
    }

    fn return_predecessor_flow(
        &self,
        edge: DataflowEdge<'_, Self::Fact>,
        output_fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.emit_predecessors(edge, output_fact, out);
    }

    fn call_to_return_predecessor_flow(
        &self,
        edge: DataflowEdge<'_, Self::Fact>,
        output_fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.emit_predecessors(edge, output_fact, out);
    }

    fn exceptional_predecessor_flow(
        &self,
        edge: DataflowEdge<'_, Self::Fact>,
        output_fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.emit_predecessors(edge, output_fact, out);
    }
}

/// One root-scoped backward taint result.
#[derive(Debug, Clone)]
pub struct TaintBackwardResult {
    result: crate::dataflow::BackwardSnapshotDataflowResult<TaintBackwardFact>,
    hits: Box<[TaintBackwardHit]>,
}

impl TaintBackwardResult {
    pub(crate) fn from_result(
        result: crate::dataflow::BackwardSnapshotDataflowResult<TaintBackwardFact>,
    ) -> Self {
        let mut hits = Vec::new();
        for reached in result.reached() {
            let Some(fact) = result.fact(reached.fact()) else {
                continue;
            };
            let TaintBackwardFactKind::Hit {
                source,
                sink,
                class_index,
                uncertain,
            } = fact.0
            else {
                continue;
            };
            hits.push(TaintBackwardHit {
                source,
                sink,
                class_index,
                uncertain,
            });
        }
        hits.sort_unstable();
        hits.dedup();
        Self {
            result,
            hits: hits.into_boxed_slice(),
        }
    }

    pub fn hits(&self) -> &[TaintBackwardHit] {
        &self.hits
    }

    pub const fn termination(&self) -> SolverTermination {
        self.result.termination()
    }

    pub const fn work(&self) -> SolverWork {
        self.result.work()
    }

    pub const fn semantic_work(&self) -> SemanticWork {
        self.result.semantic_work()
    }

    pub const fn coverage(&self) -> &crate::dataflow::DataflowCoverage {
        self.result.coverage()
    }

    pub fn is_complete(&self) -> bool {
        self.result.is_complete()
    }

    pub const fn snapshot(&self) -> &crate::analyzer::semantic::IcfgSnapshot {
        self.result.snapshot()
    }

    pub const fn reverse_call_index(&self) -> &crate::dataflow::BackwardCallIndex {
        self.result.reverse_call_index()
    }
}

/// Plan one taint query against an already materialized bounded snapshot.
///
/// Source and sink bindings are projected onto every matching context-specific
/// snapshot node. Their logical binding counts remain separate from those
/// dense node IDs, so multiple bindings at one point are still visible to the
/// planner. Directional transfer fan-out comes from the validated taint plan;
/// callers cannot replace the engine-owned cost proxy with a guess.
///
/// This function only selects a direction; it does not run either solver. In
/// particular, the adapter requires complete reverse semantics before selecting
/// a backward result. With the engine's current capabilities, plus taint's
/// finite preimage relation, the bounded reverse route is supported while
/// summary and witness routes remain forward-only.
/// Capabilities are owned by this adapter rather than caller-supplied, so an
/// external caller cannot claim that an unsupported reverse model is complete.
/// An explicit unsupported request remains a typed planning error instead of
/// being silently downgraded. The adapter always adds the bounded-snapshot and
/// complete-reverse-semantics gates; caller requirements can additionally ask
/// for reusable summaries or normalized witnesses.
pub fn plan_taint_batch_direction(
    plan: &TaintAnalysisPlan,
    snapshot: &IcfgSnapshot,
    request: &DataflowRequest<'_>,
    requirements: DataflowDirectionRequirements,
) -> Result<DataflowDirectionPlan, DataflowDirectionPlanningError> {
    let forward_points = plan
        .sources()
        .iter()
        .map(|binding| {
            plan.value_flow()
                .source(binding.source())
                .expect("validated taint source retains its value-flow source")
                .point()
        })
        .collect::<Vec<_>>();
    let backward_points = plan
        .sinks()
        .iter()
        .map(|binding| {
            plan.value_flow()
                .sink(binding.sink())
                .expect("validated taint sink retains its value-flow sink")
                .point()
        })
        .collect::<Vec<_>>();
    let forward_seed_nodes = snapshot_node_ids_for_points(snapshot, &forward_points);
    let backward_demand_nodes = snapshot_node_ids_for_points(snapshot, &backward_points);
    let (forward_transfer_fanout, backward_transfer_fanout) =
        plan.directional_transfer_fanout_estimates();
    plan_snapshot_dataflow_direction(
        request,
        snapshot,
        &forward_seed_nodes,
        &backward_demand_nodes,
        forward_transfer_fanout,
        backward_transfer_fanout,
        plan.sources().len(),
        plan.sinks().len(),
        taint_query_capabilities(plan),
        requirements,
    )
}

fn taint_query_capabilities(plan: &TaintAnalysisPlan) -> DataflowDirectionCapabilities {
    let mut capabilities = DataflowDirectionCapabilities::current();
    // TaintBackwardFlowProblem computes finite preimages for point transfers,
    // local rules, call/return mappings, and call-to-return boundaries. It
    // retains uncertainty for incomplete evidence, so the bounded reverse
    // relation is implemented even when an individual result is not proven.
    capabilities.backward_reverse_semantics_complete = plan.value_type_barriers().is_empty();
    capabilities
}

/// Solve taint from bound sinks toward their possible source events.
pub fn solve_taint_batch_backward<Provider>(
    root: &ProcedureHandle,
    provider: &Provider,
    plan: &TaintAnalysisPlan,
    semantic_budget: &mut SemanticBudget,
    request: &mut DataflowRequest<'_>,
) -> Result<TaintBackwardResult, TaintSolveError>
where
    Provider: IcfgProvider + ?Sized,
{
    if !plan.value_type_barriers().is_empty() {
        return Err(TaintSolveError::UnsupportedValueTypeBarriers {
            operation: "backward taint",
        });
    }
    if root != plan.value_flow().root() {
        return Err(TaintSolveError::RootMismatch);
    }
    let problem = TaintBackwardFlowProblem::new(plan);
    let result = solve_backward_with_snapshot(
        root,
        IcfgSnapshotLimits::default(),
        provider,
        &problem,
        semantic_budget,
        request,
    )
    .map_err(TaintSolveError::Backward)?;
    Ok(TaintBackwardResult::from_result(result))
}

pub(crate) fn solve_taint_batch_backward_on_input(
    root: &ProcedureHandle,
    plan: &TaintAnalysisPlan,
    input: IcfgSolveInput<'_>,
    snapshot_work: SemanticWork,
    request: &mut DataflowRequest<'_>,
) -> Result<TaintBackwardResult, TaintSolveError> {
    if !plan.value_type_barriers().is_empty() {
        return Err(TaintSolveError::UnsupportedValueTypeBarriers {
            operation: "backward taint",
        });
    }
    if root != plan.value_flow().root() {
        return Err(TaintSolveError::RootMismatch);
    }
    let problem = TaintBackwardFlowProblem::new(plan);
    let result = crate::dataflow::solve_backward_demands_on_snapshot(
        input,
        &problem,
        snapshot_work,
        request,
    )
    .map_err(TaintSolveError::Backward)?;
    Ok(TaintBackwardResult::from_result(result))
}

type RawTaintSummaryResult = IdeSummaryDataflowResult<TaintFact, TaintClassSet, TaintEdgeFunction>;

/// One IDE result branded to the exact taint plan that defined its dense domains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintSummaryResult {
    result: RawTaintSummaryResult,
    owner: Arc<()>,
    discovery_complete: bool,
    proven_by_authored_summaries: bool,
    authored_arm_closures: Box<[AuthoredArmClosure]>,
}

impl TaintSummaryResult {
    pub(crate) fn from_result(plan: &TaintAnalysisPlan, result: RawTaintSummaryResult) -> Self {
        let value_flow = plan.value_flow();
        let facts = result.fact_result();
        // The taint layer adds exactly one discovery input of its own: whether
        // every sanitizer resolved. Value-flow discovery is asked once, by
        // `execution_result_complete` over the solved result, in the #1952
        // sense that a snapshot left open only by call-target refinement is
        // closed when this result fully models its residual calls. Conjoining
        // the plan-time value-flow flag here asked it a second time and more
        // strictly, which withheld both tiers from every run a boundary model
        // exists to close (#2342).
        // Store bindings share the sanitizer contract: a persistence end whose
        // carrier resolution stayed partial may still flow (the join is the
        // sound direction) but must keep the run from a complete verdict.
        let sanitizers_resolved = plan.sanitizers_resolved() && plan.stores_resolved();
        let derived_complete = value_flow.execution_result_complete(facts);
        let discovery_complete = derived_complete && sanitizers_resolved;
        // The run is proven only by authored models when every open boundary is
        // closed by an authored-complete external summary (#1916): the plan is
        // structurally complete, derived proof alone does not close the run, and
        // accepting authored-complete summaries does. Deriving the run in full
        // stays the strictly stronger `Complete`, never this tier.
        let proven_by_authored_summaries = sanitizers_resolved
            && !derived_complete
            && value_flow.execution_result_complete_accepting_authored_summaries(facts);
        // Record what proved a residual-arm closure only when such a closure
        // decided the run (#2342). A derived-complete run closed nothing this
        // way, and a run that stayed inconclusive concluded nothing to explain.
        let authored_arm_closures = if proven_by_authored_summaries {
            value_flow.authored_arm_closures(facts).into_boxed_slice()
        } else {
            Box::default()
        };
        Self {
            result,
            owner: Arc::clone(plan.owner()),
            discovery_complete,
            proven_by_authored_summaries,
            authored_arm_closures,
        }
    }

    /// The result of a composition, which solves no IDE problem: it holds
    /// only `facts` (the facts its witnesses name), no reached states and no
    /// coverage rows. `complete` is the composition's own verdict, derived
    /// without authored summaries. `authored` is `Some` with the closures
    /// that decided the run when the composition is otherwise complete but
    /// rests on authored external summaries (#1916); `complete` is then
    /// false.
    pub(crate) fn composed(
        plan: &TaintAnalysisPlan,
        facts: Vec<TaintFact>,
        termination: crate::dataflow::SolverTermination,
        complete: bool,
        authored: Option<Vec<AuthoredArmClosure>>,
    ) -> Self {
        assert!(
            !(complete && authored.is_some()),
            "a composition proven by authored summaries is not derived-complete"
        );
        use crate::dataflow::{
            IdeMetrics, IdeSummaryDataflowResult, SummaryCoverage, SummaryDataflowResult,
            SummaryMetrics, WitnessArena, WitnessRetentionLimits,
        };
        let fact_result = SummaryDataflowResult::from_parts(
            facts,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            SummaryCoverage::from_parts(Vec::new(), Vec::new(), Vec::new()),
            termination,
            SolverWork::default(),
            SemanticWork::default(),
            SummaryMetrics::default(),
            WitnessArena::new(WitnessRetentionLimits::disabled()).into_store(),
            false,
        );
        let result = IdeSummaryDataflowResult::from_parts(
            fact_result,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            termination,
            SolverWork::default(),
            SemanticWork::default(),
            IdeMetrics::default(),
        );
        Self {
            result,
            owner: Arc::clone(plan.owner()),
            discovery_complete: complete && termination.is_fixed_point(),
            proven_by_authored_summaries: authored.is_some() && termination.is_fixed_point(),
            authored_arm_closures: authored
                .filter(|_| termination.is_fixed_point())
                .unwrap_or_default()
                .into_boxed_slice(),
        }
    }

    pub(crate) fn without_observed_values(mut self) -> Self {
        self.result = self.result.without_values();
        self
    }

    pub const fn result(&self) -> &RawTaintSummaryResult {
        &self.result
    }

    pub const fn fact_result(&self) -> &crate::dataflow::SummaryDataflowResult<TaintFact> {
        self.result.fact_result()
    }

    pub fn point_values(&self) -> &[crate::dataflow::IdePointValue] {
        self.result.point_values()
    }

    pub fn value(&self, id: crate::dataflow::IdeValueId) -> Option<&TaintClassSet> {
        self.result.value(id)
    }

    pub const fn coverage(&self) -> &crate::dataflow::SummaryCoverage {
        self.result.coverage()
    }

    pub const fn termination(&self) -> crate::dataflow::SolverTermination {
        self.result.termination()
    }

    pub const fn work(&self) -> SolverWork {
        self.result.work()
    }

    pub const fn semantic_work(&self) -> SemanticWork {
        self.result.semantic_work()
    }

    pub fn is_complete(&self) -> bool {
        self.discovery_complete
    }

    /// Whether the run terminates precisely, but its precision rests on
    /// authored-complete external procedure summaries rather than on derived
    /// proof (#1916). Mutually exclusive with `is_complete`.
    pub fn is_proven_by_authored_summaries(&self) -> bool {
        self.proven_by_authored_summaries
    }

    /// The authored external summaries that closed a residual dispatch arm in
    /// this run (#2342), so a rendered finding can state what proved the
    /// closure. Empty unless `is_proven_by_authored_summaries` holds.
    pub fn authored_arm_closures(&self) -> &[AuthoredArmClosure] {
        &self.authored_arm_closures
    }

    pub(crate) fn owner(&self) -> &Arc<()> {
        &self.owner
    }

    pub(crate) fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>().saturating_add(self.result.retained_bytes_with(
            TaintClassSet::retained_heap_bytes,
            TaintEdgeFunction::retained_heap_bytes,
        ))
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
    solve_taint_batch_with_witnesses_from_provider(
        root,
        provider,
        plan,
        witness_retention,
        semantic_budget,
        request,
    )
}

pub(crate) fn solve_taint_batch_with_witnesses_on_input<Provider>(
    root: &ProcedureHandle,
    provider: &Provider,
    plan: &TaintAnalysisPlan,
    input: IcfgSolveInput<'_>,
    witness_retention: WitnessRetentionLimits,
    semantic_budget: &mut SemanticBudget,
    request: &mut DataflowRequest<'_>,
) -> Result<TaintSummaryResult, TaintSolveError>
where
    Provider: IcfgProvider + ?Sized,
{
    let replay = SnapshotReplayProvider::new(provider, input);
    solve_taint_batch_with_witnesses_from_provider(
        root,
        &replay,
        plan,
        witness_retention,
        semantic_budget,
        request,
    )
}

fn solve_taint_batch_with_witnesses_from_provider<Provider>(
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
    if !plan.value_type_barriers().is_empty() {
        return Err(TaintSolveError::UnsupportedValueTypeBarriers {
            operation: "unrefined forward taint",
        });
    }
    if root != plan.value_flow().root() {
        return Err(TaintSolveError::RootMismatch);
    }
    let input = IdeSummarySolveInput::new(root, &[]).with_witness_retention(witness_retention);
    let problem = TaintFlowProblem::new(plan);
    let result = if plan.value_flow().has_contextual_bindings() {
        solve_ide_with_summaries_with_call_context(
            input,
            provider,
            &problem,
            OracleLimits::default(),
            semantic_budget,
            request,
        )?
    } else {
        solve_ide_with_summaries(input, provider, &problem, semantic_budget, request)?
    };
    Ok(TaintSummaryResult::from_result(plan, result))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn solve_taint_with_reusable_provider<Provider, Reusable>(
    root: &ProcedureHandle,
    provider: &Provider,
    reusable: &mut Reusable,
    plan: &TaintAnalysisPlan,
    witness_retention: WitnessRetentionLimits,
    semantic_budget: &mut SemanticBudget,
    request: &mut DataflowRequest<'_>,
) -> Result<TaintSummaryResult, TaintSolveError>
where
    Provider: IcfgProvider + ?Sized,
    Reusable: ReusableIdeSummaryProvider<TaintFact, TaintEdgeFunction>,
{
    if !plan.value_type_barriers().is_empty() {
        return Err(TaintSolveError::UnsupportedValueTypeBarriers {
            operation: "reusable taint summaries",
        });
    }
    if root != plan.value_flow().root() {
        return Err(TaintSolveError::RootMismatch);
    }
    let input = IdeSummarySolveInput::new(root, &[]).with_witness_retention(witness_retention);
    let problem = TaintFlowProblem::new(plan);
    let result = if plan.value_flow().has_contextual_bindings() {
        solve_ide_with_reusable_summaries_with_call_context(
            input,
            provider,
            &problem,
            reusable,
            OracleLimits::default(),
            semantic_budget,
            request,
        )?
    } else {
        solve_ide_with_reusable_summaries(
            input,
            provider,
            &problem,
            reusable,
            semantic_budget,
            request,
        )?
    };
    Ok(TaintSummaryResult::from_result(plan, result))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaintSolveError {
    RootMismatch,
    UniverseMismatch,
    DuplicateTransformSource,
    UnsupportedValueTypeBarriers { operation: &'static str },
    Ide(IdeDataflowError),
    Backward(BackwardSnapshotDataflowError),
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
            Self::UnsupportedValueTypeBarriers { operation } => write!(
                formatter,
                "value-type barriers are unsupported for {operation}; use request-local forward ICFG refinement"
            ),
            Self::Ide(error) => error.fmt(formatter),
            Self::Backward(error) => error.fmt(formatter),
        }
    }
}

impl Error for TaintSolveError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Ide(error) => Some(error),
            Self::Backward(error) => Some(error),
            Self::RootMismatch
            | Self::UniverseMismatch
            | Self::DuplicateTransformSource
            | Self::UnsupportedValueTypeBarriers { .. } => None,
        }
    }
}

impl From<IdeDataflowError> for TaintSolveError {
    fn from(error: IdeDataflowError) -> Self {
        Self::Ide(error)
    }
}

impl From<BackwardSnapshotDataflowError> for TaintSolveError {
    fn from(error: BackwardSnapshotDataflowError) -> Self {
        Self::Backward(error)
    }
}
