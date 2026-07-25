use std::collections::BTreeSet;
use std::fmt;

use crate::analyzer::dataflow::{
    DataflowEdge, DataflowOutput, DataflowRequest, DistributiveDataflowProblem,
    SummaryDataflowError, SummaryDataflowResult, SummarySolveInput, solve_with_summaries,
};
use crate::analyzer::semantic::{
    EvidenceCompleteness, IcfgEdgeKind, IcfgProvider, ProcedureHandle, ProofStatus, SemanticBudget,
};

use super::{
    BoundTypestateEvent, BoundTypestateTerminal, CompiledProtocol, ProtocolEventId,
    ProtocolEventOccurrence, ProtocolObservationPhase, ProtocolStateId,
    ProtocolTerminalObservationSpec, ProtocolUncertaintyCause, ProtocolUncertaintyResolution,
    ProtocolUnmatchedEventBehavior, TypestateBindingPlan, TypestateBindingPlanHash,
    TypestateBindingQuality, TypestateEventBindingId, TypestateProtocolHash, TypestateSubjectId,
    TypestateTerminalBindingId,
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

pub const MAX_TYPESTATE_CALLBACK_FACTS: usize = 8_192;
pub const MAX_TYPESTATE_CALLBACK_EXPANSIONS: usize = 65_536;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TypestateUncertaintySet(u8);

impl TypestateUncertaintySet {
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub const fn contains(self, uncertainty: TypestateUncertainty) -> bool {
        self.0 & (1 << uncertainty as u8) != 0
    }

    pub(super) const fn with(self, uncertainty: TypestateUncertainty) -> Self {
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
        plan: TypestateBindingPlanHash,
        subject: TypestateSubjectId,
        state: ProtocolStateId,
        uncertainty: TypestateUncertaintySet,
        abstained: bool,
    },
    Violation {
        plan: TypestateBindingPlanHash,
        subject: TypestateSubjectId,
        violation: TypestateViolation,
        uncertainty: TypestateUncertaintySet,
        abstained: bool,
    },
    NonViolation {
        plan: TypestateBindingPlanHash,
        subject: TypestateSubjectId,
        event_binding: TypestateEventBindingId,
        uncertainty: TypestateUncertaintySet,
        abstained: bool,
    },
    Terminal {
        plan: TypestateBindingPlanHash,
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
    const fn state(
        plan: TypestateBindingPlanHash,
        subject: TypestateSubjectId,
        state: ProtocolStateId,
    ) -> Self {
        Self::State {
            plan,
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
            | Self::NonViolation { subject, .. }
            | Self::Terminal { subject, .. } => Some(subject),
        }
    }

    pub const fn binding_plan_hash(self) -> Option<TypestateBindingPlanHash> {
        match self {
            Self::Zero => None,
            Self::State { plan, .. }
            | Self::Violation { plan, .. }
            | Self::NonViolation { plan, .. }
            | Self::Terminal { plan, .. } => Some(plan),
        }
    }

    pub const fn protocol_state(self) -> Option<ProtocolStateId> {
        match self {
            Self::Zero => None,
            Self::State { state, .. } => Some(state),
            Self::Violation { violation, .. } => Some(violation.to),
            Self::NonViolation { .. } => None,
            Self::Terminal { state, .. } => Some(state),
        }
    }

    pub const fn uncertainty(self) -> TypestateUncertaintySet {
        match self {
            Self::Zero => TypestateUncertaintySet(0),
            Self::State { uncertainty, .. }
            | Self::Violation { uncertainty, .. }
            | Self::NonViolation { uncertainty, .. }
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
            } | Self::NonViolation {
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
            Self::Zero | Self::State { .. } | Self::NonViolation { .. } | Self::Terminal { .. } => {
                None
            }
        }
    }

    pub const fn non_violation_binding(self) -> Option<TypestateEventBindingId> {
        match self {
            Self::NonViolation { event_binding, .. } => Some(event_binding),
            Self::Zero | Self::State { .. } | Self::Violation { .. } | Self::Terminal { .. } => {
                None
            }
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
            Self::Zero
            | Self::State { .. }
            | Self::Violation { .. }
            | Self::NonViolation { .. } => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypestateFlowProblemError {
    ProtocolMismatch,
    ContextSensitiveBindingsUnsupported,
    AnalysisRootMismatch,
    BindingPlanMismatch,
    InvalidEntryFact,
    InvalidFactIdentity,
    InvalidFindingLimits,
    FindingBudgetExceeded,
    FindingCancelled,
}

impl fmt::Display for TypestateFlowProblemError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProtocolMismatch => {
                formatter.write_str("typestate binding plan was compiled for a different protocol")
            }
            Self::ContextSensitiveBindingsUnsupported => formatter.write_str(
                "the summary typestate client currently accepts only root-context bindings",
            ),
            Self::AnalysisRootMismatch => formatter.write_str(
                "an analysis-root terminal binding belongs to a different root procedure",
            ),
            Self::BindingPlanMismatch => {
                formatter.write_str("typestate result was produced by a different binding plan")
            }
            Self::InvalidEntryFact => formatter
                .write_str("typestate entry facts must be plan-branded state facts with valid IDs"),
            Self::InvalidFactIdentity => {
                formatter.write_str("typestate fact carries an ID from a different binding plan")
            }
            Self::InvalidFindingLimits => {
                formatter.write_str("typestate finding limits are zero or exceed hard limits")
            }
            Self::FindingBudgetExceeded => {
                formatter.write_str("typestate finding post-processing budget was exceeded")
            }
            Self::FindingCancelled => {
                formatter.write_str("typestate finding post-processing was cancelled")
            }
        }
    }
}

impl std::error::Error for TypestateFlowProblemError {}

#[derive(Debug)]
pub enum TypestateSolveError {
    Contract(TypestateFlowProblemError),
    Dataflow(SummaryDataflowError),
}

impl fmt::Display for TypestateSolveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(error) => error.fmt(formatter),
            Self::Dataflow(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for TypestateSolveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Contract(error) => Some(error),
            Self::Dataflow(error) => Some(error),
        }
    }
}

impl From<TypestateFlowProblemError> for TypestateSolveError {
    fn from(error: TypestateFlowProblemError) -> Self {
        Self::Contract(error)
    }
}

impl From<SummaryDataflowError> for TypestateSolveError {
    fn from(error: SummaryDataflowError) -> Self {
        Self::Dataflow(error)
    }
}

/// A summary result branded with the exact protocol and binding plan that
/// produced its run-local IDs.
#[derive(Debug)]
pub struct TypestateSummaryResult {
    protocol_hash: TypestateProtocolHash,
    binding_plan_hash: TypestateBindingPlanHash,
    bindings_complete: bool,
    execution_complete: bool,
    result: SummaryDataflowResult<TypestateFact>,
}

impl TypestateSummaryResult {
    pub const fn protocol_hash(&self) -> TypestateProtocolHash {
        self.protocol_hash
    }

    pub const fn binding_plan_hash(&self) -> TypestateBindingPlanHash {
        self.binding_plan_hash
    }

    pub const fn bindings_complete(&self) -> bool {
        self.bindings_complete
    }

    pub const fn result(&self) -> &SummaryDataflowResult<TypestateFact> {
        &self.result
    }

    pub fn is_complete(&self) -> bool {
        self.bindings_complete && self.execution_complete && self.result.is_complete()
    }
}

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
        if bindings
            .initial_seeds()
            .iter()
            .any(|binding| !is_root_context(binding.site()))
            || bindings
                .event_bindings()
                .iter()
                .any(|binding| !is_root_context(binding.site()))
            || bindings
                .terminal_bindings()
                .iter()
                .any(|binding| !is_root_context(binding.site()))
        {
            return Err(TypestateFlowProblemError::ContextSensitiveBindingsUnsupported);
        }
        Ok(Self { protocol, bindings })
    }

    pub const fn protocol(&self) -> &CompiledProtocol {
        self.protocol
    }

    pub const fn bindings(&self) -> &TypestateBindingPlan {
        self.bindings
    }

    pub fn state_fact(
        &self,
        subject: TypestateSubjectId,
        state: ProtocolStateId,
    ) -> Result<TypestateFact, TypestateFlowProblemError> {
        if self.bindings.subject(subject).is_none() || self.protocol.state_key(state).is_none() {
            return Err(TypestateFlowProblemError::InvalidFactIdentity);
        }
        Ok(TypestateFact::state(self.bindings.hash(), subject, state))
    }

    fn validate_entry_facts(
        &self,
        facts: &[TypestateFact],
    ) -> Result<(), TypestateFlowProblemError> {
        for fact in facts {
            let TypestateFact::State {
                plan,
                subject,
                state,
                ..
            } = *fact
            else {
                return Err(TypestateFlowProblemError::InvalidEntryFact);
            };
            if plan != self.bindings.hash()
                || self.bindings.subject(subject).is_none()
                || self.protocol.state_key(state).is_none()
            {
                return Err(TypestateFlowProblemError::InvalidEntryFact);
            }
        }
        Ok(())
    }

    fn validate_analysis_root(
        &self,
        root: &ProcedureHandle,
    ) -> Result<(), TypestateFlowProblemError> {
        for binding in self.bindings.terminal_bindings() {
            let Some(terminal) = self.protocol.terminal_expectation(binding.expectation()) else {
                return Err(TypestateFlowProblemError::InvalidFactIdentity);
            };
            if matches!(
                terminal.on(),
                ProtocolTerminalObservationSpec::AnalysisRootExit { .. }
            ) && binding
                .site()
                .program_point_handle()
                .is_none_or(|point| point.procedure() != root)
            {
                return Err(TypestateFlowProblemError::AnalysisRootMismatch);
            }
        }
        Ok(())
    }

    fn bindings_complete(&self) -> bool {
        self.bindings
            .subjects()
            .iter()
            .all(|binding| binding.quality().is_definitive())
            && self
                .bindings
                .initial_seeds()
                .iter()
                .all(|binding| binding.quality().is_definitive())
            && self
                .bindings
                .event_bindings()
                .iter()
                .all(|binding| binding.quality().is_definitive())
            && self
                .bindings
                .terminal_bindings()
                .iter()
                .all(|binding| binding.quality().is_definitive())
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
                    let fact =
                        TypestateFact::state(self.bindings.hash(), seed.subject(), seed.state());
                    let facts = self.apply_seed_quality(fact, seed.subject(), seed.quality());
                    if !self.transfer_facts(edge, family, facts, out) {
                        return;
                    }
                }
            }
            fact @ TypestateFact::State { .. } => {
                if fact.binding_plan_hash() != Some(self.bindings.hash()) {
                    return;
                }
                let _ = self.transfer_facts(edge, family, vec![fact], out);
            }
            TypestateFact::Violation { .. }
            | TypestateFact::NonViolation { .. }
            | TypestateFact::Terminal { .. } => {}
        }
    }

    fn transfer_facts(
        &self,
        edge: DataflowEdge<'_>,
        family: TransferFamily,
        facts: Vec<TypestateFact>,
        out: &mut dyn DataflowOutput<TypestateFact>,
    ) -> bool {
        let mut facts = TransferFactSet::new(facts);
        let subject = facts.subject();
        let mut eligible_events = Vec::new();
        for binding in self
            .bindings
            .event_bindings_at_program_point_all_contexts(edge.source())
        {
            if point_occurrence(self.protocol, binding.event()) {
                if subject == Some(binding.subject()) {
                    eligible_events.push(EligibleEvent::from_binding(binding));
                }
                if !self.apply_binding(&mut facts, binding) {
                    return facts.emit(out);
                }
            }
        }
        for binding in self
            .bindings
            .terminal_bindings_at_program_point_all_contexts(edge.source())
        {
            if terminal_point_occurrence(self.protocol, binding)
                && !self.append_terminal_observations(&mut facts, binding)
            {
                return facts.emit(out);
            }
        }

        if let Some(call) = edge.origin() {
            for stage in family.stages(edge.kind()) {
                for binding in self.bindings.event_bindings_at_call_site_all_contexts(call) {
                    if call_occurrence(self.protocol, binding.event(), *stage) {
                        if subject == Some(binding.subject()) {
                            eligible_events.push(EligibleEvent::from_binding(binding));
                        }
                        if edge.boundary().is_none() && !self.apply_binding(&mut facts, binding) {
                            return facts.emit(out);
                        }
                    }
                }
                for binding in self
                    .bindings
                    .terminal_bindings_at_call_site_all_contexts(call)
                {
                    if terminal_call_occurrence(self.protocol, binding, *stage)
                        && !self.append_terminal_observations(&mut facts, binding)
                    {
                        return facts.emit(out);
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
                            eligible_events.push(EligibleEvent::from_binding(binding));
                        }
                        if edge.boundary().is_none() && !self.apply_binding(&mut facts, binding) {
                            return facts.emit(out);
                        }
                    }
                }
                for binding in self
                    .bindings
                    .terminal_bindings_at_call_program_point_all_contexts(edge.source())
                {
                    if terminal_call_occurrence(self.protocol, binding, *stage)
                        && !self.append_terminal_observations(&mut facts, binding)
                    {
                        return facts.emit(out);
                    }
                }
            }
        }
        eligible_events.sort_unstable();
        eligible_events.dedup();

        if let Some(boundary) = edge.boundary() {
            let cause = match boundary {
                crate::analyzer::semantic::DispatchBoundaryKind::External(_)
                | crate::analyzer::semantic::DispatchBoundaryKind::Unmaterialized(_)
                | crate::analyzer::semantic::DispatchBoundaryKind::Deferred { .. } => {
                    ProtocolUncertaintyCause::ExternalCall
                }
                crate::analyzer::semantic::DispatchBoundaryKind::Unresolved
                | crate::analyzer::semantic::DispatchBoundaryKind::Truncated => {
                    ProtocolUncertaintyCause::UnknownCall
                }
            };
            if !facts.map(|fact| self.apply_uncertainty(fact, cause, &eligible_events)) {
                return facts.emit(out);
            }
        } else if (!matches!(edge.proof(), ProofStatus::Proven)
            || !matches!(edge.completeness(), EvidenceCompleteness::Complete))
            && !facts.map(|fact| {
                self.apply_uncertainty(
                    fact,
                    ProtocolUncertaintyCause::IncompleteAnalysis,
                    &eligible_events,
                )
            })
        {
            return facts.emit(out);
        }

        // A return or call-to-return edge can both apply a call-stage event and
        // enter the procedure exit. Exit observations must see the post-return
        // state, including any uncertainty introduced by the edge boundary.
        for binding in self
            .bindings
            .event_bindings_at_program_point_all_contexts(edge.target())
        {
            if exit_point_occurrence(self.protocol, binding.event(), edge.target()) {
                if subject == Some(binding.subject()) {
                    eligible_events.push(EligibleEvent::from_binding(binding));
                }
                if !self.apply_binding(&mut facts, binding) {
                    return facts.emit(out);
                }
            }
        }
        for binding in self
            .bindings
            .terminal_bindings_at_program_point_all_contexts(edge.target())
        {
            if terminal_exit_point_occurrence(self.protocol, binding, edge.target())
                && !self.append_terminal_observations(&mut facts, binding)
            {
                return facts.emit(out);
            }
        }

        facts.emit(out)
    }

    fn apply_seed_quality(
        &self,
        fact: TypestateFact,
        subject: TypestateSubjectId,
        quality: &TypestateBindingQuality,
    ) -> Vec<TypestateFact> {
        if self.effective_quality_is_definitive(subject, quality) {
            vec![fact]
        } else {
            self.apply_uncertainty(fact, ProtocolUncertaintyCause::IncompleteAnalysis, &[])
        }
    }

    fn apply_binding(&self, facts: &mut TransferFactSet, binding: &BoundTypestateEvent) -> bool {
        let quality = binding.quality();
        if self.effective_quality_is_definitive(binding.subject(), quality) {
            if matches!(
                self.protocol
                    .event(binding.event())
                    .expect("binding-plan events retain valid protocol IDs")
                    .observation()
                    .occurrence,
                ProtocolEventOccurrence::Escape
            ) {
                return facts.map(|fact| {
                    if !matches!(fact, TypestateFact::State { .. })
                        || fact.subject() != Some(binding.subject())
                        || fact.abstained()
                    {
                        vec![fact]
                    } else {
                        self.apply_uncertainty(
                            fact,
                            ProtocolUncertaintyCause::Escape,
                            &[EligibleEvent::from_binding(binding)],
                        )
                    }
                });
            }
            return facts.map(|fact| {
                if !matches!(fact, TypestateFact::State { .. })
                    || fact.subject() != Some(binding.subject())
                    || fact.abstained()
                {
                    vec![fact]
                } else {
                    self.apply_event(fact, binding)
                }
            });
        }

        let retained_multiple = quality.multiplicity().retained() > 1;
        let call_site = binding.site().call_site_handle().is_some();
        if retained_multiple
            && call_site
            && !facts.map(|fact| {
                if !matches!(fact, TypestateFact::State { .. })
                    || fact.subject() != Some(binding.subject())
                    || fact.abstained()
                {
                    vec![fact]
                } else {
                    self.apply_uncertainty(
                        fact,
                        ProtocolUncertaintyCause::AmbiguousDispatch,
                        &[EligibleEvent::from_binding(binding)],
                    )
                }
            })
        {
            return false;
        }
        if (!quality.is_proven() || !quality.is_complete() || (retained_multiple && !call_site))
            && !facts.map(|fact| {
                if !matches!(fact, TypestateFact::State { .. })
                    || fact.subject() != Some(binding.subject())
                    || fact.abstained()
                {
                    vec![fact]
                } else {
                    self.apply_uncertainty(
                        fact,
                        ProtocolUncertaintyCause::IncompleteAnalysis,
                        &[EligibleEvent::from_binding(binding)],
                    )
                }
            })
        {
            return false;
        }
        true
    }

    fn effective_quality_is_definitive(
        &self,
        subject: TypestateSubjectId,
        row: &TypestateBindingQuality,
    ) -> bool {
        row.is_definitive()
            && self
                .bindings
                .subject(subject)
                .is_some_and(|subject| subject.quality().is_definitive())
    }

    fn append_terminal_observations(
        &self,
        facts: &mut TransferFactSet,
        binding: &BoundTypestateTerminal,
    ) -> bool {
        let definitive = self.effective_quality_is_definitive(binding.subject(), binding.quality());
        let observations = facts
            .facts()
            .iter()
            .filter_map(|fact| match *fact {
                TypestateFact::State {
                    plan,
                    subject,
                    state,
                    uncertainty,
                    abstained,
                } if subject == binding.subject() => {
                    Some((plan, subject, state, uncertainty, abstained))
                }
                TypestateFact::Zero
                | TypestateFact::State { .. }
                | TypestateFact::Violation { .. }
                | TypestateFact::NonViolation { .. }
                | TypestateFact::Terminal { .. } => None,
            })
            .flat_map(|(plan, subject, state, uncertainty, abstained)| {
                let state_fact = TypestateFact::State {
                    plan,
                    subject,
                    state,
                    uncertainty,
                    abstained,
                };
                if definitive {
                    vec![state_fact]
                } else {
                    self.apply_uncertainty(
                        state_fact,
                        ProtocolUncertaintyCause::IncompleteAnalysis,
                        &[],
                    )
                }
            })
            .filter_map(|fact| match fact {
                TypestateFact::State {
                    plan,
                    subject,
                    state,
                    uncertainty,
                    abstained,
                } => Some(TypestateFact::Terminal {
                    plan,
                    subject,
                    terminal_binding: binding.id(),
                    state,
                    uncertainty,
                    abstained,
                }),
                TypestateFact::Zero
                | TypestateFact::Violation { .. }
                | TypestateFact::NonViolation { .. }
                | TypestateFact::Terminal { .. } => None,
            })
            .collect::<Vec<_>>();
        facts.extend(observations)
    }

    fn apply_event(
        &self,
        fact: TypestateFact,
        binding: &BoundTypestateEvent,
    ) -> Vec<TypestateFact> {
        let TypestateFact::State {
            plan,
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
                plan,
                subject,
                state: transition.to(),
                uncertainty,
                abstained,
            };
            if self.protocol.is_error(transition.to()) {
                return vec![
                    target,
                    TypestateFact::Violation {
                        plan,
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
            return vec![
                target,
                TypestateFact::NonViolation {
                    plan,
                    subject,
                    event_binding: binding.id(),
                    uncertainty,
                    abstained,
                },
            ];
        }
        let non_violation = |uncertainty| TypestateFact::NonViolation {
            plan,
            subject,
            event_binding: binding.id(),
            uncertainty,
            abstained,
        };
        match self.protocol.semantics().unmatched_event {
            ProtocolUnmatchedEventBehavior::PreserveState => {
                vec![fact, non_violation(uncertainty)]
            }
            ProtocolUnmatchedEventBehavior::MarkInconclusive => {
                let uncertainty = uncertainty.with(TypestateUncertainty::UnmatchedEvent);
                vec![
                    TypestateFact::State {
                        plan,
                        subject,
                        state,
                        uncertainty,
                        abstained,
                    },
                    non_violation(uncertainty),
                ]
            }
        }
    }

    fn apply_uncertainty(
        &self,
        fact: TypestateFact,
        cause: ProtocolUncertaintyCause,
        eligible_events: &[EligibleEvent],
    ) -> Vec<TypestateFact> {
        let uncertainty_kind = uncertainty_kind(cause);
        match fact {
            TypestateFact::Violation {
                plan,
                subject,
                violation,
                uncertainty,
                abstained,
            } => {
                return vec![TypestateFact::Violation {
                    plan,
                    subject,
                    violation,
                    uncertainty: uncertainty.with(uncertainty_kind),
                    abstained,
                }];
            }
            TypestateFact::NonViolation {
                plan,
                subject,
                event_binding,
                uncertainty,
                abstained,
            } => {
                return vec![TypestateFact::NonViolation {
                    plan,
                    subject,
                    event_binding,
                    uncertainty: uncertainty.with(uncertainty_kind),
                    abstained,
                }];
            }
            TypestateFact::Terminal {
                plan,
                subject,
                terminal_binding,
                state,
                uncertainty,
                abstained,
            } => {
                return vec![TypestateFact::Terminal {
                    plan,
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
            plan,
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
        let Some(resolution) = self.protocol.resolve_uncertainty_events(
            cause,
            state,
            cardinality,
            eligible_events.iter().map(|eligible| eligible.event),
        ) else {
            return vec![TypestateFact::State {
                plan,
                subject,
                state,
                uncertainty: uncertainty.with(TypestateUncertainty::IncompleteAnalysis),
                abstained: true,
            }];
        };
        let uncertainty = uncertainty.with(uncertainty_kind);
        match resolution {
            ProtocolUncertaintyResolution::StateSet(states) => {
                let mut facts = states
                    .states()
                    .iter()
                    .map(|state| TypestateFact::State {
                        plan,
                        subject,
                        state: *state,
                        uncertainty,
                        abstained,
                    })
                    .collect::<Vec<_>>();
                for witness in states.error_witnesses() {
                    for binding in eligible_events
                        .iter()
                        .filter(|eligible| eligible.event == witness.event())
                    {
                        facts.push(TypestateFact::Violation {
                            plan,
                            subject,
                            violation: TypestateViolation {
                                event_binding: binding.binding,
                                from: witness.from(),
                                to: witness.to(),
                            },
                            uncertainty,
                            abstained,
                        });
                    }
                }
                facts
            }
            ProtocolUncertaintyResolution::PreserveUncertainty { state } => {
                vec![TypestateFact::State {
                    plan,
                    subject,
                    state,
                    uncertainty,
                    abstained,
                }]
            }
            ProtocolUncertaintyResolution::Abstain => vec![TypestateFact::State {
                plan,
                subject,
                state,
                uncertainty,
                abstained: true,
            }],
        }
    }
}

/// Solve a pre-resolved typestate plan while retaining its durable identity.
pub fn solve_typestate_with_summaries<Provider>(
    root: &ProcedureHandle,
    entry_facts: &[TypestateFact],
    provider: &Provider,
    protocol: &CompiledProtocol,
    bindings: &TypestateBindingPlan,
    semantic_budget: &mut SemanticBudget,
    request: &mut DataflowRequest<'_>,
) -> Result<TypestateSummaryResult, TypestateSolveError>
where
    Provider: IcfgProvider + ?Sized,
{
    let problem = TypestateFlowProblem::try_new(protocol, bindings)?;
    problem.validate_analysis_root(root)?;
    problem.validate_entry_facts(entry_facts)?;
    let result = solve_with_summaries(
        SummarySolveInput::new(root, entry_facts),
        provider,
        &problem,
        semantic_budget,
        request,
    )?;
    let execution_complete = result
        .facts()
        .iter()
        .all(|fact| fact.uncertainty().is_empty() && !fact.abstained());
    Ok(TypestateSummaryResult {
        protocol_hash: protocol.hash(),
        binding_plan_hash: bindings.hash(),
        bindings_complete: problem.bindings_complete(),
        execution_complete,
        result,
    })
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct EligibleEvent {
    event: ProtocolEventId,
    binding: TypestateEventBindingId,
}

impl EligibleEvent {
    const fn from_binding(binding: &BoundTypestateEvent) -> Self {
        Self {
            event: binding.event(),
            binding: binding.id(),
        }
    }
}

#[derive(Debug)]
struct TransferFactSet {
    facts: BTreeSet<TypestateFact>,
    fallback: Option<TypestateFact>,
    expansions: usize,
    overflowed: bool,
}

impl TransferFactSet {
    fn new(facts: Vec<TypestateFact>) -> Self {
        let fallback = facts
            .iter()
            .copied()
            .find(|fact| matches!(fact, TypestateFact::State { .. }));
        let mut set = Self {
            facts: BTreeSet::new(),
            fallback,
            expansions: 0,
            overflowed: false,
        };
        if !set.extend(facts) {
            set.collapse();
        }
        set
    }

    fn subject(&self) -> Option<TypestateSubjectId> {
        self.fallback.and_then(TypestateFact::subject)
    }

    fn facts(&self) -> &BTreeSet<TypestateFact> {
        &self.facts
    }

    fn map(&mut self, mut mapper: impl FnMut(TypestateFact) -> Vec<TypestateFact>) -> bool {
        if self.overflowed {
            return false;
        }
        let current = std::mem::take(&mut self.facts);
        for fact in current {
            for output in mapper(fact) {
                if !self.insert(output) {
                    self.collapse();
                    return false;
                }
            }
        }
        true
    }

    fn extend(&mut self, facts: impl IntoIterator<Item = TypestateFact>) -> bool {
        for fact in facts {
            if !self.insert(fact) {
                self.collapse();
                return false;
            }
        }
        true
    }

    fn insert(&mut self, fact: TypestateFact) -> bool {
        self.expansions = self.expansions.saturating_add(1);
        if self.expansions > MAX_TYPESTATE_CALLBACK_EXPANSIONS {
            return false;
        }
        if !self.facts.contains(&fact) && self.facts.len() >= MAX_TYPESTATE_CALLBACK_FACTS {
            return false;
        }
        self.facts.insert(fact);
        true
    }

    fn collapse(&mut self) {
        self.overflowed = true;
        self.facts.clear();
        if let Some(TypestateFact::State {
            plan,
            subject,
            state,
            uncertainty,
            ..
        }) = self.fallback
        {
            self.facts.insert(TypestateFact::State {
                plan,
                subject,
                state,
                uncertainty: uncertainty.with(TypestateUncertainty::IncompleteAnalysis),
                abstained: true,
            });
        }
    }

    fn emit(self, out: &mut dyn DataflowOutput<TypestateFact>) -> bool {
        for fact in self.facts {
            if !out.emit(fact) {
                return false;
            }
        }
        true
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
    )
}

fn exit_point_occurrence(
    protocol: &CompiledProtocol,
    event: ProtocolEventId,
    point: &crate::analyzer::semantic::ProgramPointHandle,
) -> bool {
    let Some(event) = protocol.event(event) else {
        return false;
    };
    matches!(
        event.observation().occurrence,
        ProtocolEventOccurrence::ProcedureExit { kind }
            if point_has_exit_kind(point, kind)
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
            )
    )
}

fn terminal_exit_point_occurrence(
    protocol: &CompiledProtocol,
    binding: &BoundTypestateTerminal,
    point: &crate::analyzer::semantic::ProgramPointHandle,
) -> bool {
    let Some(terminal) = protocol.terminal_expectation(binding.expectation()) else {
        return false;
    };
    matches!(
        terminal.on(),
        ProtocolTerminalObservationSpec::Event { observation }
            if matches!(
                observation.occurrence,
                ProtocolEventOccurrence::ProcedureExit { kind }
                    if point_has_exit_kind(point, kind)
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

fn point_has_exit_kind(
    point: &crate::analyzer::semantic::ProgramPointHandle,
    kind: super::ProtocolProcedureExitKind,
) -> bool {
    let semantics = point.procedure().semantics();
    match kind {
        super::ProtocolProcedureExitKind::Normal => point.id() == semantics.normal_exit_point(),
        super::ProtocolProcedureExitKind::Exceptional => {
            point.id() == semantics.exceptional_exit_point()
        }
    }
}

fn is_root_context(site: &super::TypestateObservationSite) -> bool {
    site.context().runtime().calls().is_empty() && !site.context().was_truncated()
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
