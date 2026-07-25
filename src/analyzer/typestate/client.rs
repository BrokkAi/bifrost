use std::fmt;

use crate::analyzer::dataflow::{DataflowEdge, DataflowOutput, DistributiveDataflowProblem};
use crate::analyzer::semantic::{EvidenceCompleteness, IcfgEdgeKind, ProofStatus};

use super::{
    BoundTypestateEvent, BoundTypestateTerminal, CompiledProtocol, ProtocolEventId,
    ProtocolEventOccurrence, ProtocolObservationPhase, ProtocolStateId,
    ProtocolTerminalObservationSpec, ProtocolUncertaintyCause, ProtocolUncertaintyResolution,
    ProtocolUnmatchedEventBehavior, TypestateBindingPlan, TypestateBindingQuality,
    TypestateEventBindingId, TypestateSubjectId, TypestateTerminalBindingId,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum TypestateUncertainty {
    AmbiguousDispatch = 0,
    UnknownCall = 1,
    ExternalCall = 2,
    Escape = 3,
    IncompleteAnalysis = 4,
    UnmatchedEvent = 5,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TypestateUncertaintySet(u8);

impl TypestateUncertaintySet {
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub const fn contains(self, uncertainty: TypestateUncertainty) -> bool {
        self.0 & (1 << uncertainty as u8) != 0
    }

    const fn with(self, uncertainty: TypestateUncertainty) -> Self {
        Self(self.0 | (1 << uncertainty as u8))
    }

    pub(super) const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TypestateFact {
    Zero,
    State {
        subject: TypestateSubjectId,
        state: ProtocolStateId,
        uncertainty: TypestateUncertaintySet,
        abstained: bool,
    },
    Violation {
        subject: TypestateSubjectId,
        violation: TypestateViolation,
        uncertainty: TypestateUncertaintySet,
        abstained: bool,
    },
    Terminal {
        subject: TypestateSubjectId,
        terminal_binding: TypestateTerminalBindingId,
        state: ProtocolStateId,
        uncertainty: TypestateUncertaintySet,
        abstained: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TypestateViolation {
    event_binding: TypestateEventBindingId,
    from: ProtocolStateId,
    to: ProtocolStateId,
}

impl TypestateViolation {
    pub const fn event_binding(self) -> TypestateEventBindingId {
        self.event_binding
    }

    pub const fn from(self) -> ProtocolStateId {
        self.from
    }

    pub const fn to(self) -> ProtocolStateId {
        self.to
    }
}

impl TypestateFact {
    pub const fn state(subject: TypestateSubjectId, state: ProtocolStateId) -> Self {
        Self::State {
            subject,
            state,
            uncertainty: TypestateUncertaintySet(0),
            abstained: false,
        }
    }

    pub const fn subject(self) -> Option<TypestateSubjectId> {
        match self {
            Self::Zero => None,
            Self::State { subject, .. }
            | Self::Violation { subject, .. }
            | Self::Terminal { subject, .. } => Some(subject),
        }
    }

    pub const fn protocol_state(self) -> Option<ProtocolStateId> {
        match self {
            Self::Zero => None,
            Self::State { state, .. } => Some(state),
            Self::Violation { violation, .. } => Some(violation.to),
            Self::Terminal { state, .. } => Some(state),
        }
    }

    pub const fn uncertainty(self) -> TypestateUncertaintySet {
        match self {
            Self::Zero => TypestateUncertaintySet(0),
            Self::State { uncertainty, .. }
            | Self::Violation { uncertainty, .. }
            | Self::Terminal { uncertainty, .. } => uncertainty,
        }
    }

    pub const fn abstained(self) -> bool {
        matches!(
            self,
            Self::State {
                abstained: true,
                ..
            } | Self::Violation {
                abstained: true,
                ..
            } | Self::Terminal {
                abstained: true,
                ..
            }
        )
    }

    pub const fn violation(self) -> Option<TypestateViolation> {
        match self {
            Self::Violation { violation, .. } => Some(violation),
            Self::Zero | Self::State { .. } | Self::Terminal { .. } => None,
        }
    }

    pub const fn terminal_observation(
        self,
    ) -> Option<(TypestateTerminalBindingId, ProtocolStateId)> {
        match self {
            Self::Terminal {
                terminal_binding,
                state,
                ..
            } => Some((terminal_binding, state)),
            Self::Zero | Self::State { .. } | Self::Violation { .. } => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypestateFlowProblemError {
    ProtocolMismatch,
}

impl fmt::Display for TypestateFlowProblemError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProtocolMismatch => {
                formatter.write_str("typestate binding plan was compiled for a different protocol")
            }
        }
    }
}

impl std::error::Error for TypestateFlowProblemError {}

/// Reusable finite-state transfer relation over one pre-resolved binding plan.
///
/// All semantic and oracle work happens before construction. Transfer
/// callbacks perform only bounded plan lookups and finite protocol-state
/// transitions.
#[derive(Debug)]
pub struct TypestateFlowProblem<'plan> {
    protocol: &'plan CompiledProtocol,
    bindings: &'plan TypestateBindingPlan,
}

impl<'plan> TypestateFlowProblem<'plan> {
    pub fn try_new(
        protocol: &'plan CompiledProtocol,
        bindings: &'plan TypestateBindingPlan,
    ) -> Result<Self, TypestateFlowProblemError> {
        if bindings.protocol_hash() != protocol.hash() {
            return Err(TypestateFlowProblemError::ProtocolMismatch);
        }
        Ok(Self { protocol, bindings })
    }

    pub const fn protocol(&self) -> &CompiledProtocol {
        self.protocol
    }

    pub const fn bindings(&self) -> &TypestateBindingPlan {
        self.bindings
    }

    fn transfer(
        &self,
        edge: DataflowEdge<'_>,
        fact: TypestateFact,
        family: TransferFamily,
        out: &mut dyn DataflowOutput<TypestateFact>,
    ) {
        match fact {
            TypestateFact::Zero => {
                for seed in self
                    .bindings
                    .initial_seeds_at_program_point_all_contexts(edge.source())
                {
                    let fact = TypestateFact::state(seed.subject(), seed.state());
                    let facts = self.apply_seed_quality(fact, seed.quality());
                    if !self.transfer_facts(edge, family, facts, out) {
                        return;
                    }
                }
            }
            fact @ TypestateFact::State { .. } => {
                let _ = self.transfer_facts(edge, family, vec![fact], out);
            }
            TypestateFact::Violation { .. } | TypestateFact::Terminal { .. } => {}
        }
    }

    fn transfer_facts(
        &self,
        edge: DataflowEdge<'_>,
        family: TransferFamily,
        mut facts: Vec<TypestateFact>,
        out: &mut dyn DataflowOutput<TypestateFact>,
    ) -> bool {
        let subject = facts.first().and_then(|fact| fact.subject());
        let mut eligible_events = Vec::new();
        for binding in self
            .bindings
            .event_bindings_at_program_point_all_contexts(edge.source())
        {
            if point_occurrence(self.protocol, binding.event()) {
                if subject == Some(binding.subject()) {
                    eligible_events.push(binding.event());
                }
                facts = self.apply_binding(facts, binding);
            }
        }
        for binding in self
            .bindings
            .terminal_bindings_at_program_point_all_contexts(edge.source())
        {
            if terminal_point_occurrence(self.protocol, binding) {
                append_terminal_observations(&mut facts, binding);
            }
        }

        if let Some(call) = edge.origin() {
            for stage in family.stages(edge.kind()) {
                for binding in self.bindings.event_bindings_at_call_site_all_contexts(call) {
                    if call_occurrence(self.protocol, binding.event(), *stage) {
                        if subject == Some(binding.subject()) {
                            eligible_events.push(binding.event());
                        }
                        facts = self.apply_binding(facts, binding);
                    }
                }
                for binding in self
                    .bindings
                    .terminal_bindings_at_call_site_all_contexts(call)
                {
                    if terminal_call_occurrence(self.protocol, binding, *stage) {
                        append_terminal_observations(&mut facts, binding);
                    }
                }
            }
        } else {
            for stage in family.originless_call_stages() {
                for binding in self
                    .bindings
                    .event_bindings_at_call_program_point_all_contexts(edge.source())
                {
                    if call_occurrence(self.protocol, binding.event(), *stage) {
                        if subject == Some(binding.subject()) {
                            eligible_events.push(binding.event());
                        }
                        facts = self.apply_binding(facts, binding);
                    }
                }
                for binding in self
                    .bindings
                    .terminal_bindings_at_call_program_point_all_contexts(edge.source())
                {
                    if terminal_call_occurrence(self.protocol, binding, *stage) {
                        append_terminal_observations(&mut facts, binding);
                    }
                }
            }
        }
        eligible_events.sort_unstable();
        eligible_events.dedup();

        if !matches!(edge.proof(), ProofStatus::Proven)
            || !matches!(edge.completeness(), EvidenceCompleteness::Complete)
        {
            facts = facts
                .into_iter()
                .flat_map(|fact| {
                    self.apply_uncertainty(
                        fact,
                        ProtocolUncertaintyCause::IncompleteAnalysis,
                        &eligible_events,
                    )
                })
                .collect();
            canonicalize_facts(&mut facts);
        }

        for fact in facts {
            if !out.emit(fact) {
                return false;
            }
        }
        true
    }

    fn apply_seed_quality(
        &self,
        fact: TypestateFact,
        quality: &TypestateBindingQuality,
    ) -> Vec<TypestateFact> {
        if quality.is_definitive() {
            vec![fact]
        } else {
            self.apply_uncertainty(fact, ProtocolUncertaintyCause::IncompleteAnalysis, &[])
        }
    }

    fn apply_binding(
        &self,
        facts: Vec<TypestateFact>,
        binding: &BoundTypestateEvent,
    ) -> Vec<TypestateFact> {
        let mut next = Vec::new();
        for fact in facts {
            if !matches!(fact, TypestateFact::State { .. }) {
                next.push(fact);
                continue;
            }
            if fact.subject() != Some(binding.subject()) || fact.abstained() {
                next.push(fact);
                continue;
            }
            let quality = binding.quality();
            if quality.is_definitive() {
                if matches!(
                    self.protocol
                        .event(binding.event())
                        .expect("binding-plan events retain valid protocol IDs")
                        .observation()
                        .occurrence,
                    ProtocolEventOccurrence::Escape
                ) {
                    next.extend(self.apply_uncertainty(
                        fact,
                        ProtocolUncertaintyCause::Escape,
                        &[binding.event()],
                    ));
                } else {
                    next.extend(self.apply_event(fact, binding));
                }
                continue;
            }

            let retained_multiple = quality.multiplicity().retained() > 1;
            let call_site = binding.site().call_site_handle().is_some();
            let mut uncertain = vec![fact];
            if retained_multiple && call_site {
                uncertain = uncertain
                    .into_iter()
                    .flat_map(|fact| {
                        self.apply_uncertainty(
                            fact,
                            ProtocolUncertaintyCause::AmbiguousDispatch,
                            &[binding.event()],
                        )
                    })
                    .collect();
            }
            if !quality.is_proven() || !quality.is_complete() || (retained_multiple && !call_site) {
                uncertain = uncertain
                    .into_iter()
                    .flat_map(|fact| {
                        self.apply_uncertainty(
                            fact,
                            ProtocolUncertaintyCause::IncompleteAnalysis,
                            &[binding.event()],
                        )
                    })
                    .collect();
            }
            next.extend(uncertain);
        }
        canonicalize_facts(&mut next);
        next
    }

    fn apply_event(
        &self,
        fact: TypestateFact,
        binding: &BoundTypestateEvent,
    ) -> Vec<TypestateFact> {
        let TypestateFact::State {
            subject,
            state,
            uncertainty,
            abstained,
        } = fact
        else {
            return Vec::new();
        };
        let cardinality = self
            .bindings
            .subject(subject)
            .expect("binding-plan facts retain valid subject IDs")
            .cardinality();
        if let Some(transition) = self
            .protocol
            .transition_for(state, binding.event(), cardinality)
        {
            let target = TypestateFact::State {
                subject,
                state: transition.to(),
                uncertainty,
                abstained,
            };
            if self.protocol.is_error(transition.to()) {
                return vec![
                    target,
                    TypestateFact::Violation {
                        subject,
                        violation: TypestateViolation {
                            event_binding: binding.id(),
                            from: state,
                            to: transition.to(),
                        },
                        uncertainty,
                        abstained,
                    },
                ];
            }
            return vec![target];
        }
        match self.protocol.semantics().unmatched_event {
            ProtocolUnmatchedEventBehavior::PreserveState => vec![fact],
            ProtocolUnmatchedEventBehavior::MarkInconclusive => {
                vec![TypestateFact::State {
                    subject,
                    state,
                    uncertainty: uncertainty.with(TypestateUncertainty::UnmatchedEvent),
                    abstained,
                }]
            }
        }
    }

    fn apply_uncertainty(
        &self,
        fact: TypestateFact,
        cause: ProtocolUncertaintyCause,
        eligible_events: &[ProtocolEventId],
    ) -> Vec<TypestateFact> {
        let uncertainty_kind = uncertainty_kind(cause);
        match fact {
            TypestateFact::Violation {
                subject,
                violation,
                uncertainty,
                abstained,
            } => {
                return vec![TypestateFact::Violation {
                    subject,
                    violation,
                    uncertainty: uncertainty.with(uncertainty_kind),
                    abstained,
                }];
            }
            TypestateFact::Terminal {
                subject,
                terminal_binding,
                state,
                uncertainty,
                abstained,
            } => {
                return vec![TypestateFact::Terminal {
                    subject,
                    terminal_binding,
                    state,
                    uncertainty: uncertainty.with(uncertainty_kind),
                    abstained,
                }];
            }
            TypestateFact::Zero | TypestateFact::State { .. } => {}
        }
        let TypestateFact::State {
            subject,
            state,
            uncertainty,
            abstained,
        } = fact
        else {
            return Vec::new();
        };
        let cardinality = self
            .bindings
            .subject(subject)
            .expect("binding-plan facts retain valid subject IDs")
            .cardinality();
        let Some(resolution) =
            self.protocol
                .resolve_uncertainty(cause, state, cardinality, eligible_events)
        else {
            return vec![TypestateFact::State {
                subject,
                state,
                uncertainty: uncertainty.with(TypestateUncertainty::IncompleteAnalysis),
                abstained: true,
            }];
        };
        let uncertainty = uncertainty.with(uncertainty_kind);
        match resolution {
            ProtocolUncertaintyResolution::StateSet(states) => states
                .iter()
                .map(|state| TypestateFact::State {
                    subject,
                    state: *state,
                    uncertainty,
                    abstained,
                })
                .collect(),
            ProtocolUncertaintyResolution::PreserveUncertainty { state } => {
                vec![TypestateFact::State {
                    subject,
                    state,
                    uncertainty,
                    abstained,
                }]
            }
            ProtocolUncertaintyResolution::Abstain => vec![TypestateFact::State {
                subject,
                state,
                uncertainty,
                abstained: true,
            }],
        }
    }
}

impl DistributiveDataflowProblem for TypestateFlowProblem<'_> {
    type Fact = TypestateFact;

    fn zero_fact(&self) -> Self::Fact {
        TypestateFact::Zero
    }

    fn normal_flow(
        &self,
        edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.transfer(edge, fact, TransferFamily::Normal, out);
    }

    fn call_flow(
        &self,
        edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.transfer(edge, fact, TransferFamily::Call, out);
    }

    fn return_flow(
        &self,
        edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.transfer(edge, fact, TransferFamily::Return, out);
    }

    fn call_to_return_flow(
        &self,
        edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.transfer(edge, fact, TransferFamily::CallToReturn, out);
    }

    fn exceptional_flow(
        &self,
        edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.transfer(edge, fact, TransferFamily::Exceptional, out);
    }
}

#[derive(Debug, Clone, Copy)]
enum TransferFamily {
    Normal,
    Call,
    Return,
    CallToReturn,
    Exceptional,
}

impl TransferFamily {
    fn stages(self, edge_kind: IcfgEdgeKind) -> &'static [CallStage] {
        match self {
            Self::Call => &[CallStage::BeforeCall, CallStage::ActualToFormal],
            Self::Return if edge_kind == IcfgEdgeKind::NormalReturn => {
                &[CallStage::ReturnFlow, CallStage::AfterNormalReturn]
            }
            Self::Return if edge_kind == IcfgEdgeKind::ExceptionalReturn => {
                &[CallStage::ReturnFlow, CallStage::AfterExceptionalReturn]
            }
            Self::CallToReturn if edge_kind == IcfgEdgeKind::CallToNormalContinuation => {
                &[CallStage::BeforeCall, CallStage::AfterNormalReturn]
            }
            Self::CallToReturn if edge_kind == IcfgEdgeKind::CallToExceptionalContinuation => {
                &[CallStage::BeforeCall, CallStage::AfterExceptionalReturn]
            }
            Self::Normal | Self::Return | Self::CallToReturn | Self::Exceptional => &[],
        }
    }

    fn originless_call_stages(self) -> &'static [CallStage] {
        match self {
            Self::Normal => &[CallStage::BeforeCall, CallStage::AfterNormalReturn],
            Self::Exceptional => &[CallStage::BeforeCall, CallStage::AfterExceptionalReturn],
            Self::Call | Self::Return | Self::CallToReturn => &[],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CallStage {
    BeforeCall,
    AfterNormalReturn,
    AfterExceptionalReturn,
    ActualToFormal,
    ReturnFlow,
}

fn point_occurrence(protocol: &CompiledProtocol, event: ProtocolEventId) -> bool {
    matches!(
        protocol
            .event(event)
            .expect("binding-plan events retain valid protocol IDs")
            .observation()
            .occurrence,
        ProtocolEventOccurrence::Allocation
            | ProtocolEventOccurrence::Endpoint {
                phase: ProtocolObservationPhase::AtMatch
            }
            | ProtocolEventOccurrence::FieldRead
            | ProtocolEventOccurrence::FieldWrite
            | ProtocolEventOccurrence::Escape
            | ProtocolEventOccurrence::ProcedureExit { .. }
    )
}

fn call_occurrence(protocol: &CompiledProtocol, event: ProtocolEventId, stage: CallStage) -> bool {
    let occurrence = &protocol
        .event(event)
        .expect("binding-plan events retain valid protocol IDs")
        .observation()
        .occurrence;
    matches!(
        (occurrence, stage),
        (
            ProtocolEventOccurrence::Endpoint {
                phase: ProtocolObservationPhase::BeforeCall
            },
            CallStage::BeforeCall
        ) | (
            ProtocolEventOccurrence::Endpoint {
                phase: ProtocolObservationPhase::AfterNormalReturn
            },
            CallStage::AfterNormalReturn
        ) | (
            ProtocolEventOccurrence::Endpoint {
                phase: ProtocolObservationPhase::AfterExceptionalReturn
            },
            CallStage::AfterExceptionalReturn
        ) | (
            ProtocolEventOccurrence::ActualToFormal,
            CallStage::ActualToFormal
        ) | (ProtocolEventOccurrence::ReturnFlow, CallStage::ReturnFlow)
    )
}

fn terminal_point_occurrence(
    protocol: &CompiledProtocol,
    binding: &BoundTypestateTerminal,
) -> bool {
    let terminal = protocol
        .terminal_expectation(binding.expectation())
        .expect("binding-plan expectations retain valid protocol IDs");
    matches!(
        terminal.on(),
        ProtocolTerminalObservationSpec::Event { observation }
            if matches!(
                observation.occurrence,
                ProtocolEventOccurrence::Allocation
                    | ProtocolEventOccurrence::Endpoint {
                        phase: ProtocolObservationPhase::AtMatch
                    }
                    | ProtocolEventOccurrence::FieldRead
                    | ProtocolEventOccurrence::FieldWrite
                    | ProtocolEventOccurrence::Escape
                    | ProtocolEventOccurrence::ProcedureExit { .. }
            )
    )
}

fn terminal_call_occurrence(
    protocol: &CompiledProtocol,
    binding: &BoundTypestateTerminal,
    stage: CallStage,
) -> bool {
    let terminal = protocol
        .terminal_expectation(binding.expectation())
        .expect("binding-plan expectations retain valid protocol IDs");
    match terminal.on() {
        ProtocolTerminalObservationSpec::AnalysisRootExit { .. } => false,
        ProtocolTerminalObservationSpec::Event { observation } => matches!(
            (&observation.occurrence, stage),
            (
                ProtocolEventOccurrence::Endpoint {
                    phase: ProtocolObservationPhase::BeforeCall
                },
                CallStage::BeforeCall
            ) | (
                ProtocolEventOccurrence::Endpoint {
                    phase: ProtocolObservationPhase::AfterNormalReturn
                },
                CallStage::AfterNormalReturn
            ) | (
                ProtocolEventOccurrence::Endpoint {
                    phase: ProtocolObservationPhase::AfterExceptionalReturn
                },
                CallStage::AfterExceptionalReturn
            ) | (
                ProtocolEventOccurrence::ActualToFormal,
                CallStage::ActualToFormal
            ) | (ProtocolEventOccurrence::ReturnFlow, CallStage::ReturnFlow)
        ),
    }
}

fn append_terminal_observations(facts: &mut Vec<TypestateFact>, binding: &BoundTypestateTerminal) {
    let observations = facts
        .iter()
        .filter_map(|fact| match *fact {
            TypestateFact::State {
                subject,
                state,
                uncertainty,
                abstained,
            } if subject == binding.subject() => Some(TypestateFact::Terminal {
                subject,
                terminal_binding: binding.id(),
                state,
                uncertainty,
                abstained,
            }),
            TypestateFact::Zero
            | TypestateFact::State { .. }
            | TypestateFact::Violation { .. }
            | TypestateFact::Terminal { .. } => None,
        })
        .collect::<Vec<_>>();
    facts.extend(observations);
    canonicalize_facts(facts);
}

fn canonicalize_facts(facts: &mut Vec<TypestateFact>) {
    facts.sort_unstable();
    facts.dedup();
}

const fn uncertainty_kind(cause: ProtocolUncertaintyCause) -> TypestateUncertainty {
    match cause {
        ProtocolUncertaintyCause::AmbiguousDispatch => TypestateUncertainty::AmbiguousDispatch,
        ProtocolUncertaintyCause::UnknownCall => TypestateUncertainty::UnknownCall,
        ProtocolUncertaintyCause::ExternalCall => TypestateUncertainty::ExternalCall,
        ProtocolUncertaintyCause::Escape => TypestateUncertainty::Escape,
        ProtocolUncertaintyCause::IncompleteAnalysis => TypestateUncertainty::IncompleteAnalysis,
    }
}
