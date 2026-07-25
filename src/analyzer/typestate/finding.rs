use crate::analyzer::dataflow::{PathQualityFrontier, SummaryDataflowResult};
use crate::analyzer::semantic::SemanticLocator;

use super::{
    CompiledProtocol, ProtocolAnalysisMode, ProtocolEventId, ProtocolExpectationId,
    ProtocolStateId, ProtocolTerminalObservationSpec, TypestateBindingPlan, TypestateFact,
    TypestateFlowProblemError, TypestateSubjectId, TypestateUncertaintySet,
};

pub const MAX_TYPESTATE_FINDINGS: usize = 4_096;

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
    result: &SummaryDataflowResult<TypestateFact>,
) -> Result<TypestateFindingReport, TypestateFlowProblemError> {
    if bindings.protocol_hash() != protocol.hash() {
        return Err(TypestateFlowProblemError::ProtocolMismatch);
    }

    let analysis_complete = result.is_complete();
    let mut findings = Vec::new();
    for reached in result.reached() {
        let fact = *result
            .fact(reached.fact())
            .expect("reached typestate fact IDs resolve");
        let Some(violation) = fact.violation() else {
            continue;
        };
        let subject = fact
            .subject()
            .expect("violation facts always retain subjects");
        let binding = bindings
            .event_binding(violation.event_binding())
            .expect("violation facts retain valid binding IDs");
        let certainty = match protocol.semantics().analysis_mode {
            ProtocolAnalysisMode::May => TypestateFindingCertainty::May,
            ProtocolAnalysisMode::Must
                if must_error_at(protocol, result, reached.point(), subject) =>
            {
                TypestateFindingCertainty::Must
            }
            ProtocolAnalysisMode::Must => TypestateFindingCertainty::Inconclusive,
        };
        findings.push(TypestateFinding {
            subject,
            site: binding.site().identity().clone(),
            kind: TypestateFindingKind::ErrorTransition {
                event: binding.event(),
                from: violation.from(),
                to: violation.to(),
            },
            certainty,
            evidence: finding_evidence(
                reached.path_qualities(),
                analysis_complete,
                fact.uncertainty(),
                fact.abstained(),
            ),
        });
    }

    for binding in bindings.terminal_bindings() {
        let terminal = protocol
            .terminal_expectation(binding.expectation())
            .expect("terminal bindings retain valid expectation IDs");
        let observations = match terminal.on() {
            ProtocolTerminalObservationSpec::AnalysisRootExit { .. } => {
                let Some(point) = binding.site().program_point_handle() else {
                    continue;
                };
                result
                    .reached_at(point)
                    .filter_map(|reached| {
                        state_observation(
                            result,
                            reached.fact(),
                            reached.path_qualities(),
                            binding.subject(),
                        )
                    })
                    .collect::<Vec<_>>()
            }
            ProtocolTerminalObservationSpec::Event { .. } => result
                .reached()
                .iter()
                .filter_map(|reached| {
                    let fact = *result.fact(reached.fact())?;
                    let (terminal_binding, state) = fact.terminal_observation()?;
                    (terminal_binding == binding.id()).then_some(StateObservation {
                        state,
                        uncertainty: fact.uncertainty(),
                        abstained: fact.abstained(),
                        path_qualities: reached.path_qualities(),
                    })
                })
                .collect::<Vec<_>>(),
        };
        if observations.is_empty() {
            continue;
        }

        let mut actual_states = observations
            .iter()
            .map(|observation| observation.state)
            .collect::<Vec<_>>();
        actual_states.sort_unstable();
        actual_states.dedup();
        let failing = actual_states
            .iter()
            .filter(|state| terminal.expected_states().binary_search(state).is_err())
            .count();
        let uncertain = observations
            .iter()
            .any(|observation| !observation.uncertainty.is_empty() || observation.abstained);
        let all_paths_definitive = observations.iter().all(|observation| {
            observation.path_qualities.has_proven_complete_path()
                && observation.uncertainty.is_empty()
                && !observation.abstained
        });
        let certainty = match protocol.semantics().analysis_mode {
            ProtocolAnalysisMode::May if failing > 0 => Some(TypestateFindingCertainty::May),
            ProtocolAnalysisMode::May if uncertain || !analysis_complete => {
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
            .iter()
            .any(|observation| observation.path_qualities.has_proven_path());
        let path_complete = observations
            .iter()
            .any(|observation| observation.path_qualities.has_complete_path());
        let uncertainty = observations.iter().fold(
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
                abstained: observations.iter().any(|observation| observation.abstained),
            },
        });
    }

    findings.sort_by(compare_findings);
    findings = merge_findings(findings);
    let omitted = findings.len().saturating_sub(MAX_TYPESTATE_FINDINGS);
    findings.truncate(MAX_TYPESTATE_FINDINGS);
    Ok(TypestateFindingReport {
        findings: findings.into_boxed_slice(),
        omitted,
        analysis_complete,
    })
}

#[derive(Debug, Clone, Copy)]
struct StateObservation {
    state: ProtocolStateId,
    uncertainty: TypestateUncertaintySet,
    abstained: bool,
    path_qualities: PathQualityFrontier,
}

fn state_observation(
    result: &SummaryDataflowResult<TypestateFact>,
    fact_id: crate::analyzer::dataflow::FactId,
    path_qualities: PathQualityFrontier,
    subject: TypestateSubjectId,
) -> Option<StateObservation> {
    let fact = *result.fact(fact_id)?;
    match fact {
        TypestateFact::State {
            subject: fact_subject,
            state,
            uncertainty,
            abstained,
        } if fact_subject == subject => Some(StateObservation {
            state,
            uncertainty,
            abstained,
            path_qualities,
        }),
        TypestateFact::Zero
        | TypestateFact::State { .. }
        | TypestateFact::Violation { .. }
        | TypestateFact::Terminal { .. } => None,
    }
}

fn must_error_at(
    protocol: &CompiledProtocol,
    result: &SummaryDataflowResult<TypestateFact>,
    point: &crate::analyzer::semantic::ProgramPointHandle,
    subject: TypestateSubjectId,
) -> bool {
    if !result.is_complete() {
        return false;
    }
    let observations = result
        .reached_at(point)
        .filter_map(|reached| {
            state_observation(result, reached.fact(), reached.path_qualities(), subject)
        })
        .collect::<Vec<_>>();
    !observations.is_empty()
        && observations.iter().all(|observation| {
            protocol.is_error(observation.state)
                && observation.uncertainty.is_empty()
                && !observation.abstained
                && observation.path_qualities.has_proven_complete_path()
        })
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

fn merge_findings(findings: Vec<TypestateFinding>) -> Vec<TypestateFinding> {
    let mut merged: Vec<TypestateFinding> = Vec::with_capacity(findings.len());
    for finding in findings {
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
    merged
}
