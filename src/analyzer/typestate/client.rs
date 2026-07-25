use std::fmt;

use crate::analyzer::dataflow::{DataflowEdge, DataflowOutput, DistributiveDataflowProblem};
use crate::analyzer::semantic::{EvidenceCompleteness, IcfgEdgeKind, ProofStatus};

use super::{
    BoundTypestateEvent, CompiledProtocol, ProtocolEventId, ProtocolEventOccurrence,
    ProtocolObservationPhase, ProtocolStateId, ProtocolUncertaintyCause,
    ProtocolUncertaintyResolution, ProtocolUnmatchedEventBehavior, TypestateBindingPlan,
    TypestateBindingQuality, TypestateSubjectId,
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
            Self::State { subject, .. } => Some(subject),
        }
    }

    pub const fn protocol_state(self) -> Option<ProtocolStateId> {
        match self {
            Self::Zero => None,
            Self::State { state, .. } => Some(state),
        }
    }

    pub const fn uncertainty(self) -> TypestateUncertaintySet {
        match self {
            Self::Zero => TypestateUncertaintySet(0),
            Self::State { uncertainty, .. } => uncertainty,
        }
    }

    pub const fn abstained(self) -> bool {
        matches!(
            self,
            Self::State {
                abstained: true,
                ..
            }
        )
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
                    next.extend(self.apply_event(fact, binding.event()));
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

    fn apply_event(&self, fact: TypestateFact, event: ProtocolEventId) -> Vec<TypestateFact> {
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
        if let Some(transition) = self.protocol.transition_for(state, event, cardinality) {
            return vec![TypestateFact::State {
                subject,
                state: transition.to(),
                uncertainty,
                abstained,
            }];
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
        let uncertainty = uncertainty.with(uncertainty_kind(cause));
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
