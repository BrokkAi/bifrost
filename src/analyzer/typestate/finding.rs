use crate::analyzer::dataflow::PathQualityFrontier;
use crate::analyzer::semantic::{CancellationToken, ProgramPointHandle, SemanticLocator};
use crate::hash::{HashMap, HashSet};

use super::{
    CompiledProtocol, ProtocolAnalysisMode, ProtocolEventId, ProtocolExpectationId,
    ProtocolStateId, ProtocolTerminalObservationSpec, TypestateBindingPlan,
    TypestateEventBindingId, TypestateFlowProblemError, TypestateSubjectId, TypestateSummaryResult,
    TypestateUncertaintySet,
};

pub const MAX_TYPESTATE_FINDINGS: usize = 4_096;
pub const MAX_TYPESTATE_FINDING_CANDIDATES: usize = 8_192;
pub const MAX_TYPESTATE_FINDING_REACHED_ROWS: usize = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypestateFindingLimits {
    max_reached_rows: usize,
    max_candidates: usize,
}

impl TypestateFindingLimits {
    pub fn new(
        max_reached_rows: usize,
        max_candidates: usize,
    ) -> Result<Self, TypestateFlowProblemError> {
        if max_reached_rows == 0
            || max_reached_rows > MAX_TYPESTATE_FINDING_REACHED_ROWS
            || max_candidates == 0
            || max_candidates > MAX_TYPESTATE_FINDING_CANDIDATES
        {
            return Err(TypestateFlowProblemError::InvalidFindingLimits);
        }
        Ok(Self {
            max_reached_rows,
            max_candidates,
        })
    }
}

impl Default for TypestateFindingLimits {
    fn default() -> Self {
        Self {
            max_reached_rows: MAX_TYPESTATE_FINDING_REACHED_ROWS,
            max_candidates: MAX_TYPESTATE_FINDING_CANDIDATES,
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
            if let Some(aggregate) = violations.get_mut(&key) {
                aggregate.merge(
                    reached.path_qualities(),
                    fact.uncertainty(),
                    fact.abstained(),
                );
            } else {
                charge_candidate(&mut retained_candidates, limits.max_candidates)?;
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
        let has_non_violation = non_violations.contains(&EventOutcomeKey {
            point: key.point.clone(),
            subject: key.subject,
            binding: key.binding,
        });
        let certainty = error_transition_certainty(
            protocol.semantics().analysis_mode,
            analysis_complete,
            &aggregate,
            has_non_violation,
        );
        findings.push(TypestateFinding {
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
        });
    }

    for (index, binding) in bindings.terminal_bindings().iter().enumerate() {
        check_cancellation(cancellation, index)?;
        let terminal = protocol
            .terminal_expectation(binding.expectation())
            .ok_or(TypestateFlowProblemError::InvalidFactIdentity)?;
        let observations = match terminal.on() {
            ProtocolTerminalObservationSpec::AnalysisRootExit { .. } => {
                let point = binding
                    .site()
                    .program_point_handle()
                    .ok_or(TypestateFlowProblemError::InvalidFactIdentity)?;
                reached_states.get(&StateKey {
                    point: point.clone(),
                    subject: binding.subject(),
                })
            }
            ProtocolTerminalObservationSpec::Event { .. } => event_terminals
                .get(binding.id().index())
                .and_then(Option::as_ref),
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
        findings.push(TypestateFinding {
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
        });
    }

    check_cancelled(cancellation)?;
    findings.sort_by(compare_findings);
    check_cancelled(cancellation)?;
    findings = merge_findings(findings, cancellation)?;
    let omitted = findings.len().saturating_sub(MAX_TYPESTATE_FINDINGS);
    findings.truncate(MAX_TYPESTATE_FINDINGS);
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

#[derive(Debug, Clone)]
struct ViolationAggregate {
    paths: PathQualityFrontier,
    uncertainty: TypestateUncertaintySet,
    abstained: bool,
    has_definite_proven_path: bool,
    has_definite_proven_complete_path: bool,
}

impl ViolationAggregate {
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

fn error_transition_certainty(
    mode: ProtocolAnalysisMode,
    analysis_complete: bool,
    aggregate: &ViolationAggregate,
    has_non_violation: bool,
) -> TypestateFindingCertainty {
    match mode {
        ProtocolAnalysisMode::May if aggregate.has_definite_proven_path => {
            TypestateFindingCertainty::May
        }
        ProtocolAnalysisMode::Must
            if analysis_complete
                && aggregate.has_definite_proven_complete_path
                && !has_non_violation =>
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
            .and_modify(|observation| {
                let definitive = uncertainty.is_empty() && !abstained;
                observation.has_definite_proven_path |= definitive && paths.has_proven_path();
                observation.has_definite_proven_complete_path |=
                    definitive && paths.has_proven_complete_path();
                merge_paths(&mut observation.paths, paths);
                observation.uncertainty = observation.uncertainty.union(uncertainty);
                observation.abstained |= abstained;
            })
            .or_insert(ObservationEvidence {
                paths,
                uncertainty,
                abstained,
                has_definite_proven_path: uncertainty.is_empty()
                    && !abstained
                    && paths.has_proven_path(),
                has_definite_proven_complete_path: uncertainty.is_empty()
                    && !abstained
                    && paths.has_proven_complete_path(),
            });
    }
}

#[derive(Debug, Clone, Copy)]
struct ObservationEvidence {
    paths: PathQualityFrontier,
    uncertainty: TypestateUncertaintySet,
    abstained: bool,
    has_definite_proven_path: bool,
    has_definite_proven_complete_path: bool,
}

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

fn compare_findings(left: &TypestateFinding, right: &TypestateFinding) -> std::cmp::Ordering {
    left.site
        .cmp(&right.site)
        .then_with(|| left.subject.cmp(&right.subject))
        .then_with(|| left.kind.cmp(&right.kind))
}

fn merge_findings(
    findings: Vec<TypestateFinding>,
    cancellation: &CancellationToken,
) -> Result<Vec<TypestateFinding>, TypestateFlowProblemError> {
    let mut merged: Vec<TypestateFinding> = Vec::with_capacity(findings.len());
    for (index, finding) in findings.into_iter().enumerate() {
        check_cancellation(cancellation, index)?;
        if let Some(previous) = merged.last_mut()
            && previous.site == finding.site
            && previous.subject == finding.subject
            && previous.kind == finding.kind
        {
            previous.evidence.merge(finding.evidence);
            if previous.certainty != finding.certainty {
                previous.certainty = TypestateFindingCertainty::Inconclusive;
            }
        } else {
            merged.push(finding);
        }
    }
    Ok(merged)
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
    fn must_evidence_requires_complete_paths_and_no_safe_outcome() {
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
}
