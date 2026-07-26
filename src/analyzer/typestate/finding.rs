use std::hash::Hash;

use crate::analyzer::dataflow::{
    PathQuality, PathQualityFrontier, SummaryWitness,
    SummaryWitnessStep as SummaryDataflowWitnessStep, SummaryWitnessStepKind,
    WitnessReconstructionLimits, WitnessReconstructionWork,
};
use crate::analyzer::semantic::{
    CallSiteHandle, CancellationToken, EvidenceCompleteness, ProgramPointHandle, ProofStatus,
    SemanticLocator,
};
use crate::hash::{HashMap, HashSet};

use super::{
    CompiledProtocol, ProtocolAnalysisMode, ProtocolEventId, ProtocolExpectationId,
    ProtocolStateId, ProtocolTerminalObservationSpec, TypestateBindingPlan,
    TypestateEventBindingId, TypestateFact, TypestateFlowProblemError, TypestateSubjectId,
    TypestateSummaryResult, TypestateTerminalBindingId, TypestateUncertaintySet,
};

pub const MAX_TYPESTATE_FINDINGS: usize = 4_096;
pub const MAX_TYPESTATE_FINDING_CANDIDATES: usize = 8_192;
pub const MAX_TYPESTATE_FINDING_REACHED_ROWS: usize = 1_000_000;
pub const MAX_TYPESTATE_FINDING_WITNESS_EXPANSIONS: usize = 1_000_000;
pub const MAX_TYPESTATE_FINDING_WITNESS_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_TYPESTATE_WITNESSES_PER_FINDING: usize = 16;
pub const MAX_TYPESTATE_WITNESS_STEPS: usize = 64;
pub const MAX_TYPESTATE_WITNESS_EXPANSIONS: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypestateFindingLimits {
    max_reached_rows: usize,
    max_candidates: usize,
    witness_reconstruction: WitnessReconstructionLimits,
    max_witness_expansions: usize,
    max_witness_bytes: usize,
}

impl TypestateFindingLimits {
    pub fn new(
        max_reached_rows: usize,
        max_candidates: usize,
    ) -> Result<Self, TypestateFlowProblemError> {
        Self::with_witness_limits(
            max_reached_rows,
            max_candidates,
            WitnessReconstructionLimits::new(
                MAX_TYPESTATE_WITNESS_STEPS,
                MAX_TYPESTATE_WITNESS_EXPANSIONS,
            )
            .expect("typestate witness limits are positive"),
            MAX_TYPESTATE_FINDING_WITNESS_EXPANSIONS,
            MAX_TYPESTATE_FINDING_WITNESS_BYTES,
        )
    }

    pub fn with_witness_limits(
        max_reached_rows: usize,
        max_candidates: usize,
        witness_reconstruction: WitnessReconstructionLimits,
        max_witness_expansions: usize,
        max_witness_bytes: usize,
    ) -> Result<Self, TypestateFlowProblemError> {
        if max_reached_rows == 0
            || max_reached_rows > MAX_TYPESTATE_FINDING_REACHED_ROWS
            || max_candidates == 0
            || max_candidates > MAX_TYPESTATE_FINDING_CANDIDATES
            || witness_reconstruction.max_steps() > MAX_TYPESTATE_WITNESS_STEPS
            || witness_reconstruction.max_expansions() > MAX_TYPESTATE_WITNESS_EXPANSIONS
            || max_witness_expansions == 0
            || max_witness_expansions > MAX_TYPESTATE_FINDING_WITNESS_EXPANSIONS
            || max_witness_bytes == 0
            || max_witness_bytes > MAX_TYPESTATE_FINDING_WITNESS_BYTES
        {
            return Err(TypestateFlowProblemError::InvalidFindingLimits);
        }
        Ok(Self {
            max_reached_rows,
            max_candidates,
            witness_reconstruction,
            max_witness_expansions,
            max_witness_bytes,
        })
    }
}

impl Default for TypestateFindingLimits {
    fn default() -> Self {
        Self {
            max_reached_rows: MAX_TYPESTATE_FINDING_REACHED_ROWS,
            max_candidates: MAX_TYPESTATE_FINDING_CANDIDATES,
            witness_reconstruction: WitnessReconstructionLimits::new(
                MAX_TYPESTATE_WITNESS_STEPS,
                MAX_TYPESTATE_WITNESS_EXPANSIONS,
            )
            .expect("typestate witness limits are positive"),
            max_witness_expansions: MAX_TYPESTATE_FINDING_WITNESS_EXPANSIONS,
            max_witness_bytes: MAX_TYPESTATE_FINDING_WITNESS_BYTES,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TypestateFindingCertainty {
    May,
    Must,
    Inconclusive,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TypestateFindingKind {
    ErrorTransition {
        event: ProtocolEventId,
        from: ProtocolStateId,
        to: ProtocolStateId,
    },
    TerminalExpectation {
        expectation: ProtocolExpectationId,
        actual_states: Box<[ProtocolStateId]>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TypestateFindingEvidence {
    path_proven: bool,
    path_complete: bool,
    analysis_complete: bool,
    uncertainty: TypestateUncertaintySet,
    abstained: bool,
}

impl TypestateFindingEvidence {
    pub const fn path_proven(self) -> bool {
        self.path_proven
    }

    pub const fn path_complete(self) -> bool {
        self.path_complete
    }

    pub const fn analysis_complete(self) -> bool {
        self.analysis_complete
    }

    pub const fn uncertainty(self) -> TypestateUncertaintySet {
        self.uncertainty
    }

    pub const fn abstained(self) -> bool {
        self.abstained
    }

    fn merge(&mut self, other: Self) {
        self.path_proven |= other.path_proven;
        self.path_complete |= other.path_complete;
        self.analysis_complete &= other.analysis_complete;
        self.uncertainty = self.uncertainty.union(other.uncertainty);
        self.abstained |= other.abstained;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypestateFinding {
    subject: TypestateSubjectId,
    site: SemanticLocator,
    kind: TypestateFindingKind,
    certainty: TypestateFindingCertainty,
    evidence: TypestateFindingEvidence,
    witnesses: Box<[TypestateFindingWitness]>,
    omitted_witnesses: usize,
}

impl TypestateFinding {
    pub const fn subject(&self) -> TypestateSubjectId {
        self.subject
    }

    pub const fn site(&self) -> &SemanticLocator {
        &self.site
    }

    pub const fn kind(&self) -> &TypestateFindingKind {
        &self.kind
    }

    pub const fn certainty(&self) -> TypestateFindingCertainty {
        self.certainty
    }

    pub const fn evidence(&self) -> TypestateFindingEvidence {
        self.evidence
    }

    pub fn witnesses(&self) -> &[TypestateFindingWitness] {
        &self.witnesses
    }

    pub const fn omitted_witnesses(&self) -> usize {
        self.omitted_witnesses
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypestateFindingWitness {
    observed_state: Option<ProtocolStateId>,
    witness: TypestateWitness,
}

impl TypestateFindingWitness {
    pub const fn observed_state(&self) -> Option<ProtocolStateId> {
        self.observed_state
    }

    pub const fn witness(&self) -> &TypestateWitness {
        &self.witness
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypestateWitnessStep<'a> {
    step: &'a SummaryDataflowWitnessStep,
}

impl TypestateWitnessStep<'_> {
    pub const fn kind(&self) -> SummaryWitnessStepKind {
        self.step.kind()
    }

    pub const fn source(&self) -> &ProgramPointHandle {
        self.step.source()
    }

    pub const fn target(&self) -> Option<&ProgramPointHandle> {
        self.step.target()
    }

    pub const fn origin(&self) -> Option<&CallSiteHandle> {
        self.step.origin()
    }

    pub const fn proof(&self) -> &ProofStatus {
        self.step.proof()
    }

    pub const fn completeness(&self) -> &EvidenceCompleteness {
        self.step.completeness()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypestateWitness {
    summary: SummaryWitness,
    uncertainty: TypestateUncertaintySet,
    abstained: bool,
}

impl TypestateWitness {
    fn from_summary(
        witness: SummaryWitness,
        uncertainty: TypestateUncertaintySet,
        abstained: bool,
    ) -> Self {
        Self {
            summary: witness,
            uncertainty,
            abstained,
        }
    }

    pub fn steps(&self) -> impl ExactSizeIterator<Item = TypestateWitnessStep<'_>> + '_ {
        self.summary
            .steps()
            .iter()
            .map(|step| TypestateWitnessStep { step })
    }

    pub fn step_count(&self) -> usize {
        self.summary.steps().len()
    }

    pub const fn quality(&self) -> PathQuality {
        self.summary.quality()
    }

    pub const fn truncated(&self) -> bool {
        self.summary.truncated()
    }

    pub const fn omitted_steps_lower_bound(&self) -> usize {
        self.summary.omitted_steps_lower_bound()
    }

    pub const fn alternatives_truncated(&self) -> bool {
        self.summary.alternatives_truncated()
    }

    pub const fn retention_truncated(&self) -> bool {
        self.summary.retention_truncated()
    }

    pub const fn retained_bytes(&self) -> usize {
        self.summary.retained_bytes()
    }

    pub const fn work(&self) -> WitnessReconstructionWork {
        self.summary.work()
    }

    pub const fn uncertainty(&self) -> TypestateUncertaintySet {
        self.uncertainty
    }

    pub const fn abstained(&self) -> bool {
        self.abstained
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypestateFindingReport {
    findings: Box<[TypestateFinding]>,
    omitted: usize,
    analysis_complete: bool,
}

impl TypestateFindingReport {
    pub fn findings(&self) -> &[TypestateFinding] {
        &self.findings
    }

    pub const fn omitted(&self) -> usize {
        self.omitted
    }

    pub const fn analysis_complete(&self) -> bool {
        self.analysis_complete
    }
}

pub fn collect_summary_findings(
    protocol: &CompiledProtocol,
    bindings: &TypestateBindingPlan,
    typestate_result: &TypestateSummaryResult,
) -> Result<TypestateFindingReport, TypestateFlowProblemError> {
    collect_summary_findings_with_limits(
        protocol,
        bindings,
        typestate_result,
        TypestateFindingLimits::default(),
        &CancellationToken::default(),
    )
}

pub fn collect_summary_findings_with_limits(
    protocol: &CompiledProtocol,
    bindings: &TypestateBindingPlan,
    typestate_result: &TypestateSummaryResult,
    limits: TypestateFindingLimits,
    cancellation: &CancellationToken,
) -> Result<TypestateFindingReport, TypestateFlowProblemError> {
    if bindings.protocol_hash() != protocol.hash() {
        return Err(TypestateFlowProblemError::ProtocolMismatch);
    }
    if typestate_result.protocol_hash() != protocol.hash()
        || typestate_result.binding_plan_hash() != bindings.hash()
    {
        return Err(TypestateFlowProblemError::BindingPlanMismatch);
    }

    let result = typestate_result.result();
    if result.reached().len() > limits.max_reached_rows {
        return Err(TypestateFlowProblemError::FindingBudgetExceeded);
    }
    let analysis_complete = typestate_result.is_complete();
    let mut violations = HashMap::<ViolationKey, ViolationAggregate>::default();
    let mut non_violations = HashSet::<EventOutcomeKey>::default();
    let mut violation_outcome_counts = HashMap::<EventOutcomeKey, usize>::default();
    let mut violation_witnesses = HashMap::<ViolationKey, FindingWitnessTargets>::default();
    let mut terminal_witnesses = HashMap::<TerminalWitnessKey, FindingWitnessTargets>::default();
    let mut state_witnesses = HashMap::<StateWitnessKey, FindingWitnessTargets>::default();
    let mut event_terminals: Vec<Option<ObservationAggregate>> =
        vec![None; bindings.terminal_bindings().len()];
    let mut needed_states = HashSet::<StateKey>::default();
    let mut retained_candidates = 0usize;
    for binding in bindings.terminal_bindings() {
        let terminal = protocol
            .terminal_expectation(binding.expectation())
            .ok_or(TypestateFlowProblemError::InvalidFactIdentity)?;
        if matches!(
            terminal.on(),
            ProtocolTerminalObservationSpec::AnalysisRootExit { .. }
        ) {
            let point = binding
                .site()
                .program_point_handle()
                .ok_or(TypestateFlowProblemError::InvalidFactIdentity)?;
            needed_states.insert(StateKey {
                point: point.clone(),
                subject: binding.subject(),
            });
        }
    }

    for (index, reached) in result.reached().iter().enumerate() {
        check_cancellation(cancellation, index)?;
        let fact = *result
            .fact(reached.fact())
            .ok_or(TypestateFlowProblemError::InvalidFactIdentity)?;
        if let Some(violation) = fact.violation() {
            let subject = fact
                .subject()
                .ok_or(TypestateFlowProblemError::InvalidFactIdentity)?;
            if bindings.event_binding(violation.event_binding()).is_none() {
                return Err(TypestateFlowProblemError::InvalidFactIdentity);
            }
            let key = ViolationKey {
                point: reached.point().clone(),
                subject,
                binding: violation.event_binding(),
                from: violation.from(),
                to: violation.to(),
            };
            retain_preferred_witness_target(
                &mut violation_witnesses,
                key.clone(),
                FindingWitnessTarget::new(
                    index,
                    reached.path_qualities(),
                    fact.uncertainty(),
                    fact.abstained(),
                )?,
            );
            if let Some(aggregate) = violations.get_mut(&key) {
                aggregate.merge(
                    reached.path_qualities(),
                    fact.uncertainty(),
                    fact.abstained(),
                );
            } else {
                charge_candidate(&mut retained_candidates, limits.max_candidates)?;
                let event_key = EventOutcomeKey {
                    point: key.point.clone(),
                    subject,
                    binding: violation.event_binding(),
                };
                violation_outcome_counts
                    .entry(event_key)
                    .and_modify(|count| *count = count.saturating_add(1))
                    .or_insert(1);
                violations.insert(
                    key,
                    ViolationAggregate::new(
                        reached.path_qualities(),
                        fact.uncertainty(),
                        fact.abstained(),
                    ),
                );
                needed_states.insert(StateKey {
                    point: reached.point().clone(),
                    subject,
                });
            }
        }
        if let Some(binding) = fact.non_violation_binding() {
            let subject = fact
                .subject()
                .ok_or(TypestateFlowProblemError::InvalidFactIdentity)?;
            if bindings.event_binding(binding).is_none() {
                return Err(TypestateFlowProblemError::InvalidFactIdentity);
            }
            let key = EventOutcomeKey {
                point: reached.point().clone(),
                subject,
                binding,
            };
            if !non_violations.contains(&key) {
                charge_candidate(&mut retained_candidates, limits.max_candidates)?;
                non_violations.insert(key);
            }
        }
        if let Some((terminal_binding, state)) = fact.terminal_observation() {
            retain_preferred_witness_target(
                &mut terminal_witnesses,
                TerminalWitnessKey {
                    binding: terminal_binding,
                    state,
                },
                FindingWitnessTarget::new(
                    index,
                    reached.path_qualities(),
                    fact.uncertainty(),
                    fact.abstained(),
                )?,
            );
            let aggregate = event_terminals
                .get_mut(terminal_binding.index())
                .ok_or(TypestateFlowProblemError::InvalidFactIdentity)?;
            let is_new = aggregate
                .as_ref()
                .is_none_or(|aggregate| !aggregate.contains(state));
            if is_new {
                charge_candidate(&mut retained_candidates, limits.max_candidates)?;
            }
            let aggregate = aggregate.get_or_insert_with(ObservationAggregate::default);
            aggregate.insert(
                state,
                reached.path_qualities(),
                fact.uncertainty(),
                fact.abstained(),
            );
        }
    }

    let mut reached_states = HashMap::<StateKey, ObservationAggregate>::default();
    for (index, reached) in result.reached().iter().enumerate() {
        check_cancellation(cancellation, index)?;
        let fact = *result
            .fact(reached.fact())
            .ok_or(TypestateFlowProblemError::InvalidFactIdentity)?;
        let Some((subject, state, uncertainty, abstained)) = fact.state_observation() else {
            continue;
        };
        let key = StateKey {
            point: reached.point().clone(),
            subject,
        };
        if needed_states.contains(&key) {
            retain_preferred_witness_target(
                &mut state_witnesses,
                StateWitnessKey {
                    point: reached.point().clone(),
                    subject,
                    state,
                },
                FindingWitnessTarget::new(index, reached.path_qualities(), uncertainty, abstained)?,
            );
            let is_new = reached_states
                .get(&key)
                .is_none_or(|aggregate| !aggregate.contains(state));
            if is_new {
                charge_candidate(&mut retained_candidates, limits.max_candidates)?;
            }
            reached_states.entry(key).or_default().insert(
                state,
                reached.path_qualities(),
                uncertainty,
                abstained,
            );
        }
    }

    let mut findings = Vec::with_capacity(
        violations
            .len()
            .saturating_add(bindings.terminal_bindings().len()),
    );
    for (index, (key, aggregate)) in violations.into_iter().enumerate() {
        check_cancellation(cancellation, index)?;
        let binding = bindings
            .event_binding(key.binding)
            .ok_or(TypestateFlowProblemError::InvalidFactIdentity)?;
        let event_key = EventOutcomeKey {
            point: key.point.clone(),
            subject: key.subject,
            binding: key.binding,
        };
        let has_competing_outcome = non_violations.contains(&event_key)
            || violation_outcome_counts.get(&event_key).copied() != Some(1);
        let certainty = error_transition_certainty(
            protocol.semantics().analysis_mode,
            analysis_complete,
            &aggregate,
            has_competing_outcome,
        );
        let witness_target = violation_witnesses
            .get(&key)
            .copied()
            .and_then(FindingWitnessTargets::preferred)
            .ok_or(TypestateFlowProblemError::InvalidFactIdentity)?;
        findings.push(PendingTypestateFinding {
            subject: key.subject,
            site: binding.site().identity().clone(),
            kind: TypestateFindingKind::ErrorTransition {
                event: binding.event(),
                from: key.from,
                to: key.to,
            },
            certainty,
            evidence: finding_evidence(
                aggregate.paths,
                analysis_complete,
                aggregate.uncertainty,
                aggregate.abstained,
            ),
            witness_targets: vec![PendingFindingWitness {
                observed_state: None,
                target: witness_target,
            }],
            omitted_witnesses: 0,
        });
    }

    for (index, binding) in bindings.terminal_bindings().iter().enumerate() {
        check_cancellation(cancellation, index)?;
        let terminal = protocol
            .terminal_expectation(binding.expectation())
            .ok_or(TypestateFlowProblemError::InvalidFactIdentity)?;
        let (observations, root_point) = match terminal.on() {
            ProtocolTerminalObservationSpec::AnalysisRootExit { .. } => {
                let point = binding
                    .site()
                    .program_point_handle()
                    .ok_or(TypestateFlowProblemError::InvalidFactIdentity)?;
                (
                    reached_states.get(&StateKey {
                        point: point.clone(),
                        subject: binding.subject(),
                    }),
                    Some(point.clone()),
                )
            }
            ProtocolTerminalObservationSpec::Event { .. } => (
                event_terminals
                    .get(binding.id().index())
                    .and_then(Option::as_ref),
                None,
            ),
        };
        let Some(observations) = observations else {
            continue;
        };

        let mut actual_states = observations.states.keys().copied().collect::<Vec<_>>();
        actual_states.sort_unstable();
        let failing = actual_states
            .iter()
            .filter(|state| terminal.expected_states().binary_search(state).is_err())
            .count();
        let binding_definitive = binding.quality().is_definitive()
            && bindings
                .subject(binding.subject())
                .is_some_and(|subject| subject.quality().is_definitive());
        let uncertain = !binding_definitive
            || observations
                .states
                .values()
                .any(|observation| !observation.uncertainty.is_empty() || observation.abstained);
        let failing_proven = observations.states.iter().any(|(state, observation)| {
            terminal.expected_states().binary_search(state).is_err()
                && observation.has_definite_proven_path
                && binding_definitive
        });
        let all_paths_definitive = binding_definitive
            && observations.states.values().all(|observation| {
                observation.has_definite_proven_complete_path
                    && observation.uncertainty.is_empty()
                    && !observation.abstained
            });
        let certainty = match protocol.semantics().analysis_mode {
            ProtocolAnalysisMode::May if failing_proven => Some(TypestateFindingCertainty::May),
            ProtocolAnalysisMode::May if failing > 0 || uncertain || !analysis_complete => {
                Some(TypestateFindingCertainty::Inconclusive)
            }
            ProtocolAnalysisMode::May => None,
            ProtocolAnalysisMode::Must
                if failing == actual_states.len() && analysis_complete && all_paths_definitive =>
            {
                Some(TypestateFindingCertainty::Must)
            }
            ProtocolAnalysisMode::Must if failing > 0 || uncertain || !analysis_complete => {
                Some(TypestateFindingCertainty::Inconclusive)
            }
            ProtocolAnalysisMode::Must => None,
        };
        let Some(certainty) = certainty else {
            continue;
        };
        let path_proven = observations
            .states
            .values()
            .any(|observation| observation.paths.has_proven_path());
        let path_complete = observations
            .states
            .values()
            .any(|observation| observation.paths.has_complete_path());
        let uncertainty = observations.states.values().fold(
            TypestateUncertaintySet::default(),
            |uncertainty, observation| uncertainty.union(observation.uncertainty),
        );
        let targets_for_state = |state: ProtocolStateId| match root_point.as_ref() {
            Some(point) => state_witnesses
                .get(&StateWitnessKey {
                    point: (*point).clone(),
                    subject: binding.subject(),
                    state,
                })
                .copied(),
            None => terminal_witnesses
                .get(&TerminalWitnessKey {
                    binding: binding.id(),
                    state,
                })
                .copied(),
        };
        let mut omitted_witnesses = 0usize;
        let mut witness_targets =
            Vec::with_capacity(actual_states.len().min(MAX_TYPESTATE_WITNESSES_PER_FINDING));
        match certainty {
            TypestateFindingCertainty::May => {
                let mut preferred = None;
                for (state_index, state) in actual_states.iter().copied().enumerate() {
                    check_cancellation(cancellation, state_index)?;
                    if terminal.expected_states().binary_search(&state).is_ok() {
                        continue;
                    }
                    let Some(target) =
                        targets_for_state(state).and_then(FindingWitnessTargets::may_witness)
                    else {
                        continue;
                    };
                    let candidate = PendingFindingWitness {
                        observed_state: Some(state),
                        target,
                    };
                    if preferred
                        .as_ref()
                        .is_none_or(|retained: &PendingFindingWitness| {
                            candidate.target.preference() > retained.target.preference()
                        })
                    {
                        preferred = Some(candidate);
                    }
                }
                witness_targets.extend(preferred);
            }
            TypestateFindingCertainty::Must => {
                for (state_index, state) in actual_states.iter().copied().enumerate() {
                    check_cancellation(cancellation, state_index)?;
                    let Some(target) =
                        targets_for_state(state).and_then(|targets| targets.definitive)
                    else {
                        continue;
                    };
                    if witness_targets.len() < MAX_TYPESTATE_WITNESSES_PER_FINDING {
                        witness_targets.push(PendingFindingWitness {
                            observed_state: Some(state),
                            target,
                        });
                    } else {
                        omitted_witnesses = omitted_witnesses.saturating_add(1);
                    }
                }
            }
            TypestateFindingCertainty::Inconclusive => {
                for (state_index, state) in actual_states.iter().copied().enumerate() {
                    check_cancellation(cancellation, state_index)?;
                    if failing != 0 && terminal.expected_states().binary_search(&state).is_ok() {
                        continue;
                    }
                    let Some(targets) = targets_for_state(state) else {
                        continue;
                    };
                    let Some(observation) = observations.states.get(&state) else {
                        continue;
                    };
                    let target = if failing == 0 {
                        targets
                            .uncertainty_witness()
                            .or_else(|| targets.preferred())
                    } else if !observation.uncertainty.is_empty() || observation.abstained {
                        targets
                            .uncertainty_witness()
                            .or_else(|| targets.preferred())
                    } else {
                        targets.preferred()
                    };
                    let Some(target) = target else {
                        continue;
                    };
                    if witness_targets.len() < MAX_TYPESTATE_WITNESSES_PER_FINDING {
                        witness_targets.push(PendingFindingWitness {
                            observed_state: Some(state),
                            target,
                        });
                    } else {
                        omitted_witnesses = omitted_witnesses.saturating_add(1);
                    }
                }
            }
        }
        if witness_targets.is_empty() && certainty != TypestateFindingCertainty::Inconclusive {
            return Err(TypestateFlowProblemError::InvalidFactIdentity);
        }
        findings.push(PendingTypestateFinding {
            subject: binding.subject(),
            site: binding.site().identity().clone(),
            kind: TypestateFindingKind::TerminalExpectation {
                expectation: binding.expectation(),
                actual_states: actual_states.into_boxed_slice(),
            },
            certainty,
            evidence: TypestateFindingEvidence {
                path_proven,
                path_complete,
                analysis_complete,
                uncertainty,
                abstained: !binding_definitive
                    || observations
                        .states
                        .values()
                        .any(|observation| observation.abstained),
            },
            witness_targets,
            omitted_witnesses,
        });
    }

    check_cancelled(cancellation)?;
    findings.sort_by(compare_pending_findings);
    check_cancelled(cancellation)?;
    findings = merge_pending_findings(findings, cancellation)?;
    let omitted = findings.len().saturating_sub(MAX_TYPESTATE_FINDINGS);
    findings.truncate(MAX_TYPESTATE_FINDINGS);
    let findings = materialize_findings(findings, result, limits, cancellation)?;
    Ok(TypestateFindingReport {
        findings: findings.into_boxed_slice(),
        omitted,
        analysis_complete,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct StateKey {
    point: ProgramPointHandle,
    subject: TypestateSubjectId,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ViolationKey {
    point: ProgramPointHandle,
    subject: TypestateSubjectId,
    binding: TypestateEventBindingId,
    from: ProtocolStateId,
    to: ProtocolStateId,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct EventOutcomeKey {
    point: ProgramPointHandle,
    subject: TypestateSubjectId,
    binding: TypestateEventBindingId,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TerminalWitnessKey {
    binding: TypestateTerminalBindingId,
    state: ProtocolStateId,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct StateWitnessKey {
    point: ProgramPointHandle,
    subject: TypestateSubjectId,
    state: ProtocolStateId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FindingWitnessTarget {
    reached_index: usize,
    quality: PathQuality,
    uncertainty: TypestateUncertaintySet,
    abstained: bool,
}

impl FindingWitnessTarget {
    fn new(
        reached_index: usize,
        paths: PathQualityFrontier,
        uncertainty: TypestateUncertaintySet,
        abstained: bool,
    ) -> Result<Self, TypestateFlowProblemError> {
        let quality = paths
            .iter()
            .max_by_key(|quality| (quality.is_proven(), quality.is_complete()))
            .ok_or(TypestateFlowProblemError::InvalidFactIdentity)?;
        Ok(Self {
            reached_index,
            quality,
            uncertainty,
            abstained,
        })
    }

    const fn is_definitive(self) -> bool {
        self.quality.is_proven()
            && self.quality.is_complete()
            && self.uncertainty.is_empty()
            && !self.abstained
    }

    const fn supports_may(self) -> bool {
        self.quality.is_proven() && self.uncertainty.is_empty() && !self.abstained
    }

    const fn preference(self) -> (bool, bool, std::cmp::Reverse<usize>) {
        (
            self.quality.is_proven(),
            self.quality.is_complete(),
            std::cmp::Reverse(self.reached_index),
        )
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct FindingWitnessTargets {
    definitive: Option<FindingWitnessTarget>,
    may: Option<FindingWitnessTarget>,
    uncertain: Option<FindingWitnessTarget>,
}

impl FindingWitnessTargets {
    fn insert(&mut self, candidate: FindingWitnessTarget) {
        let retained = if candidate.is_definitive() {
            &mut self.definitive
        } else {
            &mut self.uncertain
        };
        if retained.is_none_or(|retained| candidate.preference() > retained.preference()) {
            *retained = Some(candidate);
        }
        if candidate.supports_may()
            && self
                .may
                .is_none_or(|retained| candidate.preference() > retained.preference())
        {
            self.may = Some(candidate);
        }
    }

    const fn preferred(self) -> Option<FindingWitnessTarget> {
        match self.definitive {
            Some(target) => Some(target),
            None => match self.may {
                Some(target) => Some(target),
                None => self.uncertain,
            },
        }
    }

    const fn may_witness(self) -> Option<FindingWitnessTarget> {
        self.may
    }

    const fn uncertainty_witness(self) -> Option<FindingWitnessTarget> {
        self.uncertain
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingFindingWitness {
    observed_state: Option<ProtocolStateId>,
    target: FindingWitnessTarget,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingTypestateFinding {
    subject: TypestateSubjectId,
    site: SemanticLocator,
    kind: TypestateFindingKind,
    certainty: TypestateFindingCertainty,
    evidence: TypestateFindingEvidence,
    witness_targets: Vec<PendingFindingWitness>,
    omitted_witnesses: usize,
}

fn retain_preferred_witness_target<Key>(
    targets: &mut HashMap<Key, FindingWitnessTargets>,
    key: Key,
    candidate: FindingWitnessTarget,
) where
    Key: Eq + Hash,
{
    targets.entry(key).or_default().insert(candidate);
}

#[derive(Debug, Clone, Copy)]
struct PathEvidenceAggregate {
    paths: PathQualityFrontier,
    uncertainty: TypestateUncertaintySet,
    abstained: bool,
    has_definite_proven_path: bool,
    has_definite_proven_complete_path: bool,
}

impl PathEvidenceAggregate {
    fn new(
        paths: PathQualityFrontier,
        uncertainty: TypestateUncertaintySet,
        abstained: bool,
    ) -> Self {
        let definitive = uncertainty.is_empty() && !abstained;
        Self {
            paths,
            uncertainty,
            abstained,
            has_definite_proven_path: definitive && paths.has_proven_path(),
            has_definite_proven_complete_path: definitive && paths.has_proven_complete_path(),
        }
    }

    fn merge(
        &mut self,
        paths: PathQualityFrontier,
        uncertainty: TypestateUncertaintySet,
        abstained: bool,
    ) {
        let definitive = uncertainty.is_empty() && !abstained;
        self.has_definite_proven_path |= definitive && paths.has_proven_path();
        self.has_definite_proven_complete_path |= definitive && paths.has_proven_complete_path();
        merge_paths(&mut self.paths, paths);
        self.uncertainty = self.uncertainty.union(uncertainty);
        self.abstained |= abstained;
    }
}

type ViolationAggregate = PathEvidenceAggregate;

fn error_transition_certainty(
    mode: ProtocolAnalysisMode,
    analysis_complete: bool,
    aggregate: &ViolationAggregate,
    has_competing_outcome: bool,
) -> TypestateFindingCertainty {
    match mode {
        ProtocolAnalysisMode::May if aggregate.has_definite_proven_path => {
            TypestateFindingCertainty::May
        }
        ProtocolAnalysisMode::Must
            if analysis_complete
                && aggregate.has_definite_proven_complete_path
                && !has_competing_outcome =>
        {
            TypestateFindingCertainty::Must
        }
        ProtocolAnalysisMode::May | ProtocolAnalysisMode::Must => {
            TypestateFindingCertainty::Inconclusive
        }
    }
}

#[derive(Debug, Default, Clone)]
struct ObservationAggregate {
    states: HashMap<ProtocolStateId, ObservationEvidence>,
}

impl ObservationAggregate {
    fn contains(&self, state: ProtocolStateId) -> bool {
        self.states.contains_key(&state)
    }

    fn insert(
        &mut self,
        state: ProtocolStateId,
        paths: PathQualityFrontier,
        uncertainty: TypestateUncertaintySet,
        abstained: bool,
    ) {
        self.states
            .entry(state)
            .and_modify(|observation| observation.merge(paths, uncertainty, abstained))
            .or_insert_with(|| ObservationEvidence::new(paths, uncertainty, abstained));
    }
}

type ObservationEvidence = PathEvidenceAggregate;

fn merge_paths(target: &mut PathQualityFrontier, incoming: PathQualityFrontier) {
    for quality in incoming.iter() {
        target.insert(quality);
    }
}

fn check_cancellation(
    cancellation: &CancellationToken,
    index: usize,
) -> Result<(), TypestateFlowProblemError> {
    if index.is_multiple_of(256) && cancellation.is_cancelled() {
        Err(TypestateFlowProblemError::FindingCancelled)
    } else {
        Ok(())
    }
}

fn check_cancelled(cancellation: &CancellationToken) -> Result<(), TypestateFlowProblemError> {
    if cancellation.is_cancelled() {
        Err(TypestateFlowProblemError::FindingCancelled)
    } else {
        Ok(())
    }
}

fn charge_candidate(retained: &mut usize, maximum: usize) -> Result<(), TypestateFlowProblemError> {
    if *retained >= maximum {
        return Err(TypestateFlowProblemError::FindingBudgetExceeded);
    }
    *retained += 1;
    Ok(())
}

fn finding_evidence(
    paths: PathQualityFrontier,
    analysis_complete: bool,
    uncertainty: TypestateUncertaintySet,
    abstained: bool,
) -> TypestateFindingEvidence {
    TypestateFindingEvidence {
        path_proven: paths.has_proven_path(),
        path_complete: paths.has_complete_path(),
        analysis_complete,
        uncertainty,
        abstained,
    }
}

fn compare_pending_findings(
    left: &PendingTypestateFinding,
    right: &PendingTypestateFinding,
) -> std::cmp::Ordering {
    left.site
        .cmp(&right.site)
        .then_with(|| left.subject.cmp(&right.subject))
        .then_with(|| left.kind.cmp(&right.kind))
}

fn merge_pending_findings(
    findings: Vec<PendingTypestateFinding>,
    cancellation: &CancellationToken,
) -> Result<Vec<PendingTypestateFinding>, TypestateFlowProblemError> {
    let mut merged: Vec<PendingTypestateFinding> = Vec::with_capacity(findings.len());
    for (index, finding) in findings.into_iter().enumerate() {
        check_cancellation(cancellation, index)?;
        if let Some(previous) = merged.last_mut()
            && previous.site == finding.site
            && previous.subject == finding.subject
            && previous.kind == finding.kind
        {
            previous.evidence.merge(finding.evidence);
            previous.certainty = merge_finding_certainty(previous.certainty, finding.certainty);
            previous.omitted_witnesses = previous
                .omitted_witnesses
                .saturating_add(finding.omitted_witnesses);
            for candidate in finding.witness_targets {
                if let Some(retained) = previous
                    .witness_targets
                    .iter_mut()
                    .find(|retained| retained.observed_state == candidate.observed_state)
                {
                    if should_replace_merged_witness(
                        retained.target,
                        candidate.target,
                        previous.certainty,
                    ) {
                        *retained = candidate;
                    }
                } else if previous.witness_targets.len() < MAX_TYPESTATE_WITNESSES_PER_FINDING {
                    previous.witness_targets.push(candidate);
                } else {
                    previous.omitted_witnesses = previous.omitted_witnesses.saturating_add(1);
                }
            }
            previous
                .witness_targets
                .sort_by_key(|witness| witness.observed_state);
        } else {
            merged.push(finding);
        }
    }
    Ok(merged)
}

fn should_replace_merged_witness(
    retained: FindingWitnessTarget,
    candidate: FindingWitnessTarget,
    certainty: TypestateFindingCertainty,
) -> bool {
    let (retained_supports_certainty, candidate_supports_certainty) = match certainty {
        TypestateFindingCertainty::May => (retained.supports_may(), candidate.supports_may()),
        TypestateFindingCertainty::Must => (retained.is_definitive(), candidate.is_definitive()),
        TypestateFindingCertainty::Inconclusive => {
            (!retained.is_definitive(), !candidate.is_definitive())
        }
    };
    if retained_supports_certainty != candidate_supports_certainty {
        return candidate_supports_certainty;
    }
    candidate.preference() > retained.preference()
}

const fn merge_finding_certainty(
    retained: TypestateFindingCertainty,
    candidate: TypestateFindingCertainty,
) -> TypestateFindingCertainty {
    match (retained, candidate) {
        (TypestateFindingCertainty::May, _) | (_, TypestateFindingCertainty::May) => {
            TypestateFindingCertainty::May
        }
        (TypestateFindingCertainty::Must, TypestateFindingCertainty::Must) => {
            TypestateFindingCertainty::Must
        }
        _ => TypestateFindingCertainty::Inconclusive,
    }
}

fn materialize_findings(
    findings: Vec<PendingTypestateFinding>,
    result: &crate::analyzer::dataflow::SummaryDataflowResult<TypestateFact>,
    limits: TypestateFindingLimits,
    cancellation: &CancellationToken,
) -> Result<Vec<TypestateFinding>, TypestateFlowProblemError> {
    let mut retained_expansions = 0usize;
    let mut retained_bytes = 0usize;
    let mut materialized = Vec::with_capacity(findings.len());
    for (finding_index, finding) in findings.into_iter().enumerate() {
        check_cancellation(cancellation, finding_index)?;
        let mut witnesses = Vec::with_capacity(finding.witness_targets.len());
        for (witness_index, pending) in finding.witness_targets.into_iter().enumerate() {
            check_cancellation(cancellation, witness_index)?;
            let remaining_expansions = limits
                .max_witness_expansions
                .saturating_sub(retained_expansions);
            if remaining_expansions == 0 {
                return Err(TypestateFlowProblemError::FindingBudgetExceeded);
            }
            let reconstruction_limits = WitnessReconstructionLimits::new(
                limits.witness_reconstruction.max_steps(),
                limits
                    .witness_reconstruction
                    .max_expansions()
                    .min(remaining_expansions),
            )
            .expect("validated typestate witness limits are positive");
            let summary = result
                .witness_for_reached_index(
                    pending.target.reached_index,
                    pending.target.quality,
                    reconstruction_limits,
                )
                .map_err(TypestateFlowProblemError::WitnessReconstruction)?;
            let next_expansions = retained_expansions
                .checked_add(summary.work().evidence_expansions())
                .filter(|total| *total <= limits.max_witness_expansions)
                .ok_or(TypestateFlowProblemError::FindingBudgetExceeded)?;
            let next_bytes = retained_bytes
                .checked_add(summary.retained_bytes())
                .filter(|total| *total <= limits.max_witness_bytes)
                .ok_or(TypestateFlowProblemError::FindingBudgetExceeded)?;
            check_cancelled(cancellation)?;
            retained_expansions = next_expansions;
            retained_bytes = next_bytes;
            witnesses.push(TypestateFindingWitness {
                observed_state: pending.observed_state,
                witness: TypestateWitness::from_summary(
                    summary,
                    pending.target.uncertainty,
                    pending.target.abstained,
                ),
            });
        }
        materialized.push(TypestateFinding {
            subject: finding.subject,
            site: finding.site,
            kind: finding.kind,
            certainty: finding.certainty,
            evidence: finding.evidence,
            witnesses: witnesses.into_boxed_slice(),
            omitted_witnesses: finding.omitted_witnesses,
        });
    }
    Ok(materialized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::dataflow::{PathQuality, PathQualityFrontier};
    use crate::analyzer::typestate::TypestateUncertainty;

    #[test]
    fn clean_may_evidence_survives_an_uncertain_parallel_path() {
        let paths = PathQualityFrontier::singleton(PathQuality::PROVEN_COMPLETE);
        let mut aggregate =
            ViolationAggregate::new(paths, TypestateUncertaintySet::default(), false);
        aggregate.merge(
            paths,
            TypestateUncertaintySet::default().with(TypestateUncertainty::IncompleteAnalysis),
            false,
        );

        assert_eq!(
            error_transition_certainty(ProtocolAnalysisMode::May, false, &aggregate, false),
            TypestateFindingCertainty::May
        );
        assert!(!aggregate.uncertainty.is_empty());
    }

    #[test]
    fn must_evidence_requires_complete_paths_and_one_exact_outcome() {
        let paths = PathQualityFrontier::singleton(PathQuality::PROVEN_COMPLETE);
        let aggregate = ViolationAggregate::new(paths, TypestateUncertaintySet::default(), false);

        assert_eq!(
            error_transition_certainty(ProtocolAnalysisMode::Must, true, &aggregate, false),
            TypestateFindingCertainty::Must
        );
        assert_eq!(
            error_transition_certainty(ProtocolAnalysisMode::Must, true, &aggregate, true),
            TypestateFindingCertainty::Inconclusive
        );
        assert_eq!(
            error_transition_certainty(ProtocolAnalysisMode::Must, false, &aggregate, false),
            TypestateFindingCertainty::Inconclusive
        );
    }

    #[test]
    fn witness_target_is_definitive_only_for_a_proven_complete_path() {
        for quality in [
            PathQuality::PROVEN_PARTIAL,
            PathQuality::UNPROVEN_COMPLETE,
            PathQuality::UNPROVEN_PARTIAL,
        ] {
            assert!(
                !FindingWitnessTarget {
                    reached_index: 0,
                    quality,
                    uncertainty: TypestateUncertaintySet::default(),
                    abstained: false,
                }
                .is_definitive()
            );
        }
        assert!(
            FindingWitnessTarget {
                reached_index: 0,
                quality: PathQuality::PROVEN_COMPLETE,
                uncertainty: TypestateUncertaintySet::default(),
                abstained: false,
            }
            .is_definitive()
        );
    }

    #[test]
    fn proven_partial_terminal_evidence_retains_a_may_witness() {
        let clean_partial = FindingWitnessTarget {
            reached_index: 0,
            quality: PathQuality::PROVEN_PARTIAL,
            uncertainty: TypestateUncertaintySet::default(),
            abstained: false,
        };
        let uncertain_complete = FindingWitnessTarget {
            reached_index: 1,
            quality: PathQuality::PROVEN_COMPLETE,
            uncertainty: TypestateUncertaintySet::default()
                .with(TypestateUncertainty::IncompleteAnalysis),
            abstained: false,
        };
        let mut targets = FindingWitnessTargets::default();
        targets.insert(clean_partial);
        targets.insert(uncertain_complete);

        assert!(!clean_partial.is_definitive());
        assert!(clean_partial.supports_may());
        assert_eq!(targets.uncertainty_witness(), Some(uncertain_complete));
        assert_eq!(targets.may_witness(), Some(clean_partial));
        assert_eq!(targets.preferred(), Some(clean_partial));
    }

    #[test]
    fn duplicate_may_and_inconclusive_findings_merge_as_may() {
        assert_eq!(
            merge_finding_certainty(
                TypestateFindingCertainty::May,
                TypestateFindingCertainty::Inconclusive
            ),
            TypestateFindingCertainty::May
        );
        assert_eq!(
            merge_finding_certainty(
                TypestateFindingCertainty::Inconclusive,
                TypestateFindingCertainty::May
            ),
            TypestateFindingCertainty::May
        );
        assert_eq!(
            merge_finding_certainty(
                TypestateFindingCertainty::Must,
                TypestateFindingCertainty::Inconclusive
            ),
            TypestateFindingCertainty::Inconclusive
        );
    }

    #[test]
    fn may_merge_prefers_clean_proven_evidence_even_when_partial() {
        let uncertain = FindingWitnessTarget {
            reached_index: 0,
            quality: PathQuality::PROVEN_COMPLETE,
            uncertainty: TypestateUncertaintySet::default()
                .with(TypestateUncertainty::IncompleteAnalysis),
            abstained: false,
        };
        let clean_partial = FindingWitnessTarget {
            reached_index: 1,
            quality: PathQuality::PROVEN_PARTIAL,
            uncertainty: TypestateUncertaintySet::default(),
            abstained: false,
        };

        assert!(should_replace_merged_witness(
            uncertain,
            clean_partial,
            TypestateFindingCertainty::May
        ));
        assert!(!should_replace_merged_witness(
            clean_partial,
            uncertain,
            TypestateFindingCertainty::May
        ));
    }

    #[test]
    fn inconclusive_merge_prefers_the_witness_that_explains_uncertainty() {
        let clean = FindingWitnessTarget {
            reached_index: 0,
            quality: PathQuality::PROVEN_COMPLETE,
            uncertainty: TypestateUncertaintySet::default(),
            abstained: false,
        };
        let uncertain = FindingWitnessTarget {
            reached_index: 1,
            quality: PathQuality::UNPROVEN_PARTIAL,
            uncertainty: TypestateUncertaintySet::default(),
            abstained: false,
        };

        assert!(should_replace_merged_witness(
            clean,
            uncertain,
            TypestateFindingCertainty::Inconclusive
        ));
        assert!(!should_replace_merged_witness(
            uncertain,
            clean,
            TypestateFindingCertainty::Inconclusive
        ));
    }
}
