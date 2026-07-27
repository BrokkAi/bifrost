use std::collections::BTreeSet;
use std::fmt;

use crate::analyzer::dataflow::{
    DataflowEdge, DataflowOutput, DataflowRequest, DistributiveDataflowProblem,
    ReusableProcedureSummary, ReusableSummaryProvider, SolverTermination, SummaryDataflowError,
    SummaryDataflowResult, SummarySolveInput, SummaryWitnessError, WitnessRetentionLimits,
    solve_with_reusable_end_summaries,
};
use crate::analyzer::semantic::{
    EvidenceCompleteness, IcfgEdgeKind, IcfgProvider, ProcedureHandle, ProofStatus, SemanticBudget,
};

use super::{
    BoundTypestateEvent, BoundTypestateTerminal, CompiledProtocol, ProtocolEventId,
    ProtocolEventOccurrence, ProtocolObservationPhase, ProtocolStateId, ProtocolStateKey,
    ProtocolTerminalObservationSpec, ProtocolUncertaintyCause, ProtocolUncertaintyResolution,
    ProtocolUnmatchedEventBehavior, TypestateBindingPlan, TypestateBindingPlanHash,
    TypestateBindingQuality, TypestateEventBindingId, TypestateProtocolHash, TypestateSubjectId,
    TypestateSubjectKey, TypestateTerminalBindingId,
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
const MAX_TYPESTATE_RETAINED_WITNESS_RELATIONS: usize = 65_536;
const MAX_TYPESTATE_RETAINED_WITNESS_BYTES: usize = 64 * 1024 * 1024;

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
pub struct TypestateFact(TypestateFactKind);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum TypestateFactKind {
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
    pub const fn zero() -> Self {
        Self(TypestateFactKind::Zero)
    }

    const fn state(
        plan: TypestateBindingPlanHash,
        subject: TypestateSubjectId,
        state: ProtocolStateId,
    ) -> Self {
        Self::summary_state(plan, subject, state, TypestateUncertaintySet(0), false)
    }

    pub(super) const fn summary_state(
        plan: TypestateBindingPlanHash,
        subject: TypestateSubjectId,
        state: ProtocolStateId,
        uncertainty: TypestateUncertaintySet,
        abstained: bool,
    ) -> Self {
        Self(TypestateFactKind::State {
            plan,
            subject,
            state,
            uncertainty,
            abstained,
        })
    }

    pub(super) const fn summary_violation(
        plan: TypestateBindingPlanHash,
        subject: TypestateSubjectId,
        event_binding: TypestateEventBindingId,
        from: ProtocolStateId,
        to: ProtocolStateId,
        uncertainty: TypestateUncertaintySet,
        abstained: bool,
    ) -> Self {
        Self(TypestateFactKind::Violation {
            plan,
            subject,
            violation: TypestateViolation {
                event_binding,
                from,
                to,
            },
            uncertainty,
            abstained,
        })
    }

    pub(super) const fn summary_non_violation(
        plan: TypestateBindingPlanHash,
        subject: TypestateSubjectId,
        event_binding: TypestateEventBindingId,
        uncertainty: TypestateUncertaintySet,
        abstained: bool,
    ) -> Self {
        Self(TypestateFactKind::NonViolation {
            plan,
            subject,
            event_binding,
            uncertainty,
            abstained,
        })
    }

    pub(super) const fn summary_terminal(
        plan: TypestateBindingPlanHash,
        subject: TypestateSubjectId,
        terminal_binding: TypestateTerminalBindingId,
        state: ProtocolStateId,
        uncertainty: TypestateUncertaintySet,
        abstained: bool,
    ) -> Self {
        Self(TypestateFactKind::Terminal {
            plan,
            subject,
            terminal_binding,
            state,
            uncertainty,
            abstained,
        })
    }

    pub const fn subject(self) -> Option<TypestateSubjectId> {
        match self.0 {
            TypestateFactKind::Zero => None,
            TypestateFactKind::State { subject, .. }
            | TypestateFactKind::Violation { subject, .. }
            | TypestateFactKind::NonViolation { subject, .. }
            | TypestateFactKind::Terminal { subject, .. } => Some(subject),
        }
    }

    pub const fn binding_plan_hash(self) -> Option<TypestateBindingPlanHash> {
        match self.0 {
            TypestateFactKind::Zero => None,
            TypestateFactKind::State { plan, .. }
            | TypestateFactKind::Violation { plan, .. }
            | TypestateFactKind::NonViolation { plan, .. }
            | TypestateFactKind::Terminal { plan, .. } => Some(plan),
        }
    }

    pub const fn protocol_state(self) -> Option<ProtocolStateId> {
        match self.0 {
            TypestateFactKind::Zero => None,
            TypestateFactKind::State { state, .. } => Some(state),
            TypestateFactKind::Violation { violation, .. } => Some(violation.to),
            TypestateFactKind::NonViolation { .. } => None,
            TypestateFactKind::Terminal { state, .. } => Some(state),
        }
    }

    pub(super) const fn state_observation(
        self,
    ) -> Option<(
        TypestateSubjectId,
        ProtocolStateId,
        TypestateUncertaintySet,
        bool,
    )> {
        match self.0 {
            TypestateFactKind::State {
                subject,
                state,
                uncertainty,
                abstained,
                ..
            } => Some((subject, state, uncertainty, abstained)),
            TypestateFactKind::Zero
            | TypestateFactKind::Violation { .. }
            | TypestateFactKind::NonViolation { .. }
            | TypestateFactKind::Terminal { .. } => None,
        }
    }

    pub const fn uncertainty(self) -> TypestateUncertaintySet {
        match self.0 {
            TypestateFactKind::Zero => TypestateUncertaintySet(0),
            TypestateFactKind::State { uncertainty, .. }
            | TypestateFactKind::Violation { uncertainty, .. }
            | TypestateFactKind::NonViolation { uncertainty, .. }
            | TypestateFactKind::Terminal { uncertainty, .. } => uncertainty,
        }
    }

    pub const fn abstained(self) -> bool {
        matches!(
            self.0,
            TypestateFactKind::State {
                abstained: true,
                ..
            } | TypestateFactKind::Violation {
                abstained: true,
                ..
            } | TypestateFactKind::NonViolation {
                abstained: true,
                ..
            } | TypestateFactKind::Terminal {
                abstained: true,
                ..
            }
        )
    }

    pub const fn violation(self) -> Option<TypestateViolation> {
        match self.0 {
            TypestateFactKind::Violation { violation, .. } => Some(violation),
            TypestateFactKind::Zero
            | TypestateFactKind::State { .. }
            | TypestateFactKind::NonViolation { .. }
            | TypestateFactKind::Terminal { .. } => None,
        }
    }

    pub(super) const fn non_violation_binding(self) -> Option<TypestateEventBindingId> {
        match self.0 {
            TypestateFactKind::NonViolation { event_binding, .. } => Some(event_binding),
            TypestateFactKind::Zero
            | TypestateFactKind::State { .. }
            | TypestateFactKind::Violation { .. }
            | TypestateFactKind::Terminal { .. } => None,
        }
    }

    pub const fn terminal_observation(
        self,
    ) -> Option<(TypestateTerminalBindingId, ProtocolStateId)> {
        match self.0 {
            TypestateFactKind::Terminal {
                terminal_binding,
                state,
                ..
            } => Some((terminal_binding, state)),
            TypestateFactKind::Zero
            | TypestateFactKind::State { .. }
            | TypestateFactKind::Violation { .. }
            | TypestateFactKind::NonViolation { .. } => None,
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
    WitnessReconstruction(SummaryWitnessError),
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
            Self::WitnessReconstruction(error) => {
                write!(
                    formatter,
                    "typestate witness reconstruction failed: {error}"
                )
            }
        }
    }
}

impl std::error::Error for TypestateFlowProblemError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::WitnessReconstruction(error) => Some(error),
            Self::ProtocolMismatch
            | Self::ContextSensitiveBindingsUnsupported
            | Self::AnalysisRootMismatch
            | Self::BindingPlanMismatch
            | Self::InvalidEntryFact
            | Self::InvalidFactIdentity
            | Self::InvalidFindingLimits
            | Self::FindingBudgetExceeded
            | Self::FindingCancelled => None,
        }
    }
}

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
    bindings_summary_complete: bool,
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

    /// Whether binding discovery covered every candidate needed for reuse.
    ///
    /// Unlike [`Self::bindings_complete`], this permits exhaustive modeled
    /// ambiguity because multiplicity and proof remain in the summary facts.
    pub const fn bindings_summary_complete(&self) -> bool {
        self.bindings_summary_complete
    }

    pub const fn result(&self) -> &SummaryDataflowResult<TypestateFact> {
        &self.result
    }

    pub fn is_complete(&self) -> bool {
        self.bindings_complete && self.execution_complete && self.result.is_complete()
    }

    /// Whether this solve is safe to project into a reusable protocol artifact.
    ///
    /// Modeled ambiguity, unknown/external calls, escape, and unmatched events
    /// remain sound summary effects. Cancellation, bounded truncation,
    /// incomplete bindings, abstention, and explicit incomplete-analysis facts
    /// do not.
    pub fn is_summary_publication_complete(&self) -> bool {
        self.bindings_summary_complete
            && self.result.is_complete()
            && self.result.facts().iter().all(|fact| {
                !fact.abstained()
                    && !fact
                        .uncertainty()
                        .contains(TypestateUncertainty::IncompleteAnalysis)
            })
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
        subject: &TypestateSubjectKey,
        state: &ProtocolStateKey,
    ) -> Result<TypestateFact, TypestateFlowProblemError> {
        let subject = self
            .bindings
            .subject_id(subject)
            .ok_or(TypestateFlowProblemError::InvalidFactIdentity)?;
        let state = self
            .protocol
            .state_id(state)
            .ok_or(TypestateFlowProblemError::InvalidFactIdentity)?;
        Ok(TypestateFact::state(self.bindings.hash(), subject, state))
    }

    fn validate_entry_facts(
        &self,
        facts: &[TypestateFact],
    ) -> Result<(), TypestateFlowProblemError> {
        for fact in facts {
            let TypestateFactKind::State {
                plan,
                subject,
                state,
                ..
            } = fact.0
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

    fn bindings_summary_complete(&self) -> bool {
        self.bindings
            .subjects()
            .iter()
            .all(|binding| binding.quality().is_complete())
            && self
                .bindings
                .initial_seeds()
                .iter()
                .all(|binding| binding.quality().is_complete())
            && self
                .bindings
                .event_bindings()
                .iter()
                .all(|binding| binding.quality().is_complete())
            && self
                .bindings
                .terminal_bindings()
                .iter()
                .all(|binding| binding.quality().is_complete())
    }

    fn transfer(
        &self,
        edge: DataflowEdge<'_, TypestateFact>,
        fact: TypestateFact,
        family: TransferFamily,
        out: &mut dyn DataflowOutput<TypestateFact>,
    ) {
        match fact.0 {
            TypestateFactKind::Zero => {
                for seed in self
                    .bindings
                    .initial_seeds_at_program_point_all_contexts(edge.source())
                {
                    if !out.should_continue() {
                        return;
                    }
                    let fact =
                        TypestateFact::state(self.bindings.hash(), seed.subject(), seed.state());
                    let facts = self.apply_seed_quality(fact, seed.subject(), seed.quality());
                    if !self.transfer_facts(edge, family, facts, out) {
                        return;
                    }
                }
            }
            TypestateFactKind::State { .. } => {
                if fact.binding_plan_hash() != Some(self.bindings.hash()) {
                    return;
                }
                let _ = self.transfer_facts(edge, family, vec![fact], out);
            }
            TypestateFactKind::Violation { .. }
            | TypestateFactKind::NonViolation { .. }
            | TypestateFactKind::Terminal { .. } => {}
        }
    }

    fn transfer_facts(
        &self,
        edge: DataflowEdge<'_, TypestateFact>,
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
            if !out.should_continue() {
                return false;
            }
            if point_occurrence(self.protocol, binding.event()) {
                if subject == Some(binding.subject()) {
                    eligible_events.push(EligibleEvent::from_binding(binding));
                }
                if !self.apply_binding(&mut facts, binding, out) {
                    return facts.emit(out);
                }
            }
        }
        for binding in self
            .bindings
            .terminal_bindings_at_program_point_all_contexts(edge.source())
        {
            if !out.should_continue() {
                return false;
            }
            if terminal_point_occurrence(self.protocol, binding)
                && !self.append_terminal_observations(&mut facts, binding, out)
            {
                return facts.emit(out);
            }
        }

        if let Some(call) = edge.origin() {
            for stage in family.stages(edge.kind()) {
                for binding in self.bindings.event_bindings_at_call_site_all_contexts(call) {
                    if !out.should_continue() {
                        return false;
                    }
                    if call_occurrence(self.protocol, binding.event(), *stage) {
                        if subject == Some(binding.subject()) {
                            eligible_events.push(EligibleEvent::from_binding(binding));
                        }
                        if edge.boundary().is_none()
                            && !self.apply_binding(&mut facts, binding, out)
                        {
                            return facts.emit(out);
                        }
                    }
                }
                for binding in self
                    .bindings
                    .terminal_bindings_at_call_site_all_contexts(call)
                {
                    if !out.should_continue() {
                        return false;
                    }
                    if terminal_call_occurrence(self.protocol, binding, *stage)
                        && !self.append_terminal_observations(&mut facts, binding, out)
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
                    if !out.should_continue() {
                        return false;
                    }
                    if call_occurrence(self.protocol, binding.event(), *stage) {
                        if subject == Some(binding.subject()) {
                            eligible_events.push(EligibleEvent::from_binding(binding));
                        }
                        if edge.boundary().is_none()
                            && !self.apply_binding(&mut facts, binding, out)
                        {
                            return facts.emit(out);
                        }
                    }
                }
                for binding in self
                    .bindings
                    .terminal_bindings_at_call_program_point_all_contexts(edge.source())
                {
                    if !out.should_continue() {
                        return false;
                    }
                    if terminal_call_occurrence(self.protocol, binding, *stage)
                        && !self.append_terminal_observations(&mut facts, binding, out)
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
            if !facts.map_stream(out, |fact, emit| {
                self.emit_uncertainty(fact, cause, &eligible_events, emit)
            }) {
                return facts.emit(out);
            }
        } else if (!matches!(edge.proof(), ProofStatus::Proven)
            || !matches!(edge.completeness(), EvidenceCompleteness::Complete))
            && !facts.map_stream(out, |fact, emit| {
                self.emit_uncertainty(
                    fact,
                    ProtocolUncertaintyCause::IncompleteAnalysis,
                    &eligible_events,
                    emit,
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
            if !out.should_continue() {
                return false;
            }
            if exit_point_occurrence(self.protocol, binding.event(), edge.target()) {
                if subject == Some(binding.subject()) {
                    eligible_events.push(EligibleEvent::from_binding(binding));
                }
                if !self.apply_binding(&mut facts, binding, out) {
                    return facts.emit(out);
                }
            }
        }
        for binding in self
            .bindings
            .terminal_bindings_at_program_point_all_contexts(edge.target())
        {
            if !out.should_continue() {
                return false;
            }
            if terminal_exit_point_occurrence(self.protocol, binding, edge.target())
                && !self.append_terminal_observations(&mut facts, binding, out)
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

    fn apply_binding(
        &self,
        facts: &mut TransferFactSet,
        binding: &BoundTypestateEvent,
        out: &dyn DataflowOutput<TypestateFact>,
    ) -> bool {
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
                return facts.map_stream(out, |fact, emit| {
                    if !matches!(fact.0, TypestateFactKind::State { .. })
                        || fact.subject() != Some(binding.subject())
                        || fact.abstained()
                    {
                        emit(fact)
                    } else {
                        self.emit_uncertainty(
                            fact,
                            ProtocolUncertaintyCause::Escape,
                            &[EligibleEvent::from_binding(binding)],
                            emit,
                        )
                    }
                });
            }
            return facts.map(out, |fact| {
                if !matches!(fact.0, TypestateFactKind::State { .. })
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
            && !facts.map_stream(out, |fact, emit| {
                if !matches!(fact.0, TypestateFactKind::State { .. })
                    || fact.subject() != Some(binding.subject())
                    || fact.abstained()
                {
                    emit(fact)
                } else {
                    self.emit_uncertainty(
                        fact,
                        ProtocolUncertaintyCause::AmbiguousDispatch,
                        &[EligibleEvent::from_binding(binding)],
                        emit,
                    )
                }
            })
        {
            return false;
        }
        if (!quality.is_proven() || !quality.is_complete() || (retained_multiple && !call_site))
            && !facts.map_stream(out, |fact, emit| {
                if !matches!(fact.0, TypestateFactKind::State { .. })
                    || fact.subject() != Some(binding.subject())
                    || fact.abstained()
                {
                    emit(fact)
                } else {
                    self.emit_uncertainty(
                        fact,
                        ProtocolUncertaintyCause::IncompleteAnalysis,
                        &[EligibleEvent::from_binding(binding)],
                        emit,
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
        out: &dyn DataflowOutput<TypestateFact>,
    ) -> bool {
        if !out.should_continue() {
            return false;
        }
        let definitive = self.effective_quality_is_definitive(binding.subject(), binding.quality());
        let observations = facts
            .facts()
            .iter()
            .filter_map(|fact| match fact.0 {
                TypestateFactKind::State {
                    plan,
                    subject,
                    state,
                    uncertainty,
                    abstained,
                } if subject == binding.subject() => {
                    Some((plan, subject, state, uncertainty, abstained))
                }
                TypestateFactKind::Zero
                | TypestateFactKind::State { .. }
                | TypestateFactKind::Violation { .. }
                | TypestateFactKind::NonViolation { .. }
                | TypestateFactKind::Terminal { .. } => None,
            })
            .flat_map(|(plan, subject, state, uncertainty, abstained)| {
                let state_fact = TypestateFact(TypestateFactKind::State {
                    plan,
                    subject,
                    state,
                    uncertainty,
                    abstained,
                });
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
            .filter_map(|fact| match fact.0 {
                TypestateFactKind::State {
                    plan,
                    subject,
                    state,
                    uncertainty,
                    abstained,
                } => Some(TypestateFact(TypestateFactKind::Terminal {
                    plan,
                    subject,
                    terminal_binding: binding.id(),
                    state,
                    uncertainty,
                    abstained,
                })),
                TypestateFactKind::Zero
                | TypestateFactKind::Violation { .. }
                | TypestateFactKind::NonViolation { .. }
                | TypestateFactKind::Terminal { .. } => None,
            })
            .collect::<Vec<_>>();
        facts.extend_with_output(observations, out)
    }

    fn apply_event(
        &self,
        fact: TypestateFact,
        binding: &BoundTypestateEvent,
    ) -> Vec<TypestateFact> {
        let TypestateFactKind::State {
            plan,
            subject,
            state,
            uncertainty,
            abstained,
        } = fact.0
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
            let target = TypestateFact(TypestateFactKind::State {
                plan,
                subject,
                state: transition.to(),
                uncertainty,
                abstained,
            });
            if self.protocol.is_error(transition.to()) {
                return vec![
                    target,
                    TypestateFact(TypestateFactKind::Violation {
                        plan,
                        subject,
                        violation: TypestateViolation {
                            event_binding: binding.id(),
                            from: state,
                            to: transition.to(),
                        },
                        uncertainty,
                        abstained,
                    }),
                ];
            }
            return vec![
                target,
                TypestateFact(TypestateFactKind::NonViolation {
                    plan,
                    subject,
                    event_binding: binding.id(),
                    uncertainty,
                    abstained,
                }),
            ];
        }
        let non_violation = |uncertainty| {
            TypestateFact(TypestateFactKind::NonViolation {
                plan,
                subject,
                event_binding: binding.id(),
                uncertainty,
                abstained,
            })
        };
        match self.protocol.semantics().unmatched_event {
            ProtocolUnmatchedEventBehavior::PreserveState => {
                vec![fact, non_violation(uncertainty)]
            }
            ProtocolUnmatchedEventBehavior::MarkInconclusive => {
                let uncertainty = uncertainty.with(TypestateUncertainty::UnmatchedEvent);
                vec![
                    TypestateFact(TypestateFactKind::State {
                        plan,
                        subject,
                        state,
                        uncertainty,
                        abstained,
                    }),
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
        let mut facts = Vec::new();
        let emitted_all = self.emit_uncertainty(fact, cause, eligible_events, &mut |fact| {
            facts.push(fact);
            true
        });
        debug_assert!(emitted_all, "Vec-backed uncertainty sink cannot stop");
        facts
    }

    fn emit_uncertainty(
        &self,
        fact: TypestateFact,
        cause: ProtocolUncertaintyCause,
        eligible_events: &[EligibleEvent],
        emit: &mut dyn FnMut(TypestateFact) -> bool,
    ) -> bool {
        let uncertainty_kind = uncertainty_kind(cause);
        match fact.0 {
            TypestateFactKind::Violation {
                plan,
                subject,
                violation,
                uncertainty,
                abstained,
            } => {
                return emit(TypestateFact(TypestateFactKind::Violation {
                    plan,
                    subject,
                    violation,
                    uncertainty: uncertainty.with(uncertainty_kind),
                    abstained,
                }));
            }
            TypestateFactKind::NonViolation {
                plan,
                subject,
                event_binding,
                uncertainty,
                abstained,
            } => {
                return emit(TypestateFact(TypestateFactKind::NonViolation {
                    plan,
                    subject,
                    event_binding,
                    uncertainty: uncertainty.with(uncertainty_kind),
                    abstained,
                }));
            }
            TypestateFactKind::Terminal {
                plan,
                subject,
                terminal_binding,
                state,
                uncertainty,
                abstained,
            } => {
                return emit(TypestateFact(TypestateFactKind::Terminal {
                    plan,
                    subject,
                    terminal_binding,
                    state,
                    uncertainty: uncertainty.with(uncertainty_kind),
                    abstained,
                }));
            }
            TypestateFactKind::Zero | TypestateFactKind::State { .. } => {}
        }
        let TypestateFactKind::State {
            plan,
            subject,
            state,
            uncertainty,
            abstained,
        } = fact.0
        else {
            return true;
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
            return emit(TypestateFact(TypestateFactKind::State {
                plan,
                subject,
                state,
                uncertainty: uncertainty.with(TypestateUncertainty::IncompleteAnalysis),
                abstained: true,
            }));
        };
        let uncertainty = uncertainty.with(uncertainty_kind);
        match resolution {
            ProtocolUncertaintyResolution::StateSet(states) => {
                for state in states.states() {
                    if !emit(TypestateFact(TypestateFactKind::State {
                        plan,
                        subject,
                        state: *state,
                        uncertainty,
                        abstained,
                    })) {
                        return false;
                    }
                }
                for witness in states.error_witnesses() {
                    for binding in eligible_events
                        .iter()
                        .filter(|eligible| eligible.event == witness.event())
                    {
                        if !emit(TypestateFact(TypestateFactKind::Violation {
                            plan,
                            subject,
                            violation: TypestateViolation {
                                event_binding: binding.binding,
                                from: witness.from(),
                                to: witness.to(),
                            },
                            uncertainty,
                            abstained,
                        })) {
                            return false;
                        }
                    }
                }
                true
            }
            ProtocolUncertaintyResolution::PreserveUncertainty { state } => {
                emit(TypestateFact(TypestateFactKind::State {
                    plan,
                    subject,
                    state,
                    uncertainty,
                    abstained,
                }))
            }
            ProtocolUncertaintyResolution::Abstain => {
                emit(TypestateFact(TypestateFactKind::State {
                    plan,
                    subject,
                    state,
                    uncertainty,
                    abstained: true,
                }))
            }
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
    let mut reusable = NoReusableTypestateSummaries;
    solve_typestate_with_reusable_provider(
        root,
        entry_facts,
        provider,
        &mut reusable,
        protocol,
        bindings,
        semantic_budget,
        request,
    )
}

struct NoReusableTypestateSummaries;

impl ReusableSummaryProvider<TypestateFact> for NoReusableTypestateSummaries {
    fn summary_for(
        &mut self,
        _procedure: &ProcedureHandle,
        _entry_fact: TypestateFact,
        _request: &mut DataflowRequest<'_>,
    ) -> Result<Option<ReusableProcedureSummary<TypestateFact>>, SolverTermination> {
        Ok(None)
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn solve_typestate_with_reusable_provider<Provider, Reusable>(
    root: &ProcedureHandle,
    entry_facts: &[TypestateFact],
    provider: &Provider,
    reusable: &mut Reusable,
    protocol: &CompiledProtocol,
    bindings: &TypestateBindingPlan,
    semantic_budget: &mut SemanticBudget,
    request: &mut DataflowRequest<'_>,
) -> Result<TypestateSummaryResult, TypestateSolveError>
where
    Provider: IcfgProvider + ?Sized,
    Reusable: ReusableSummaryProvider<TypestateFact> + ?Sized,
{
    let problem = TypestateFlowProblem::try_new(protocol, bindings)?;
    problem.validate_analysis_root(root)?;
    problem.validate_entry_facts(entry_facts)?;
    let witness_retention = WitnessRetentionLimits::best_effort(
        1,
        MAX_TYPESTATE_RETAINED_WITNESS_RELATIONS,
        MAX_TYPESTATE_RETAINED_WITNESS_BYTES,
    )
    .expect("typestate best-effort witness limits are valid");
    let result = solve_with_reusable_end_summaries(
        SummarySolveInput::new(root, entry_facts).with_witness_retention(witness_retention),
        provider,
        &problem,
        reusable,
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
        bindings_summary_complete: problem.bindings_summary_complete(),
        execution_complete,
        result,
    })
}

impl DistributiveDataflowProblem for TypestateFlowProblem<'_> {
    type Fact = TypestateFact;

    fn zero_fact(&self) -> Self::Fact {
        TypestateFact::zero()
    }

    fn normal_flow(
        &self,
        edge: DataflowEdge<'_, Self::Fact>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.transfer(edge, fact, TransferFamily::Normal, out);
    }

    fn call_flow(
        &self,
        edge: DataflowEdge<'_, Self::Fact>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.transfer(edge, fact, TransferFamily::Call, out);
    }

    fn return_flow(
        &self,
        edge: DataflowEdge<'_, Self::Fact>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.transfer(edge, fact, TransferFamily::Return, out);
    }

    fn call_to_return_flow(
        &self,
        edge: DataflowEdge<'_, Self::Fact>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        self.transfer(edge, fact, TransferFamily::CallToReturn, out);
    }

    fn exceptional_flow(
        &self,
        edge: DataflowEdge<'_, Self::Fact>,
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
            .find(|fact| matches!(fact.0, TypestateFactKind::State { .. }));
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

    fn map(
        &mut self,
        out: &dyn DataflowOutput<TypestateFact>,
        mut mapper: impl FnMut(TypestateFact) -> Vec<TypestateFact>,
    ) -> bool {
        self.map_stream(out, |fact, emit| {
            for output in mapper(fact) {
                if !emit(output) {
                    return false;
                }
            }
            true
        })
    }

    fn map_stream(
        &mut self,
        out: &dyn DataflowOutput<TypestateFact>,
        mut mapper: impl FnMut(TypestateFact, &mut dyn FnMut(TypestateFact) -> bool) -> bool,
    ) -> bool {
        if self.overflowed {
            return false;
        }
        let current = std::mem::take(&mut self.facts);
        let mut next = BTreeSet::new();
        let mut expansions = self.expansions;
        let mut outputs = 0usize;
        let mut overflowed = false;
        for fact in current {
            if !out.should_continue() {
                self.facts = next;
                return false;
            }
            let mut emit = |output| {
                outputs = outputs.saturating_add(1);
                if outputs.is_multiple_of(256) && !out.should_continue() {
                    return false;
                }
                if output != fact {
                    expansions = expansions.saturating_add(1);
                    if expansions > MAX_TYPESTATE_CALLBACK_EXPANSIONS {
                        overflowed = true;
                        return false;
                    }
                }
                if !next.contains(&output) && next.len() >= MAX_TYPESTATE_CALLBACK_FACTS {
                    overflowed = true;
                    return false;
                }
                next.insert(output);
                true
            };
            if !mapper(fact, &mut emit) {
                self.expansions = expansions;
                self.facts = next;
                if overflowed {
                    self.collapse();
                }
                return false;
            }
        }
        self.expansions = expansions;
        self.facts = next;
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

    fn extend_with_output(
        &mut self,
        facts: impl IntoIterator<Item = TypestateFact>,
        out: &dyn DataflowOutput<TypestateFact>,
    ) -> bool {
        for fact in facts {
            if self.expansions.is_multiple_of(256) && !out.should_continue() {
                return false;
            }
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
        if let Some(TypestateFact(TypestateFactKind::State {
            plan,
            subject,
            state,
            uncertainty,
            ..
        })) = self.fallback
        {
            self.facts.insert(TypestateFact(TypestateFactKind::State {
                plan,
                subject,
                state,
                uncertainty: uncertainty.with(TypestateUncertainty::IncompleteAnalysis),
                abstained: true,
            }));
        }
    }

    fn emit(self, out: &mut dyn DataflowOutput<TypestateFact>) -> bool {
        if !out.should_continue() {
            return false;
        }
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

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    struct PollingOutput {
        polls: Cell<usize>,
    }

    impl DataflowOutput<TypestateFact> for PollingOutput {
        fn should_continue(&self) -> bool {
            let polls = self.polls.get().saturating_add(1);
            self.polls.set(polls);
            polls <= 2
        }

        fn emit(&mut self, _value: TypestateFact) -> bool {
            true
        }
    }

    #[test]
    fn streamed_mapper_stops_generation_during_expansion() {
        let mut facts = TransferFactSet::new(vec![TypestateFact::zero()]);
        let output = PollingOutput {
            polls: Cell::new(0),
        };
        let generated = Cell::new(0usize);

        let completed = facts.map_stream(&output, |_fact, emit| {
            for _ in 0..1_000_000 {
                generated.set(generated.get().saturating_add(1));
                if !emit(TypestateFact::zero()) {
                    return false;
                }
            }
            true
        });

        assert!(!completed);
        assert_eq!(generated.get(), 512);
    }
}
