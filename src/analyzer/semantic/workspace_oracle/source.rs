//! Bounded source-range projection for point-sensitive heap queries.

use std::sync::Arc;

use crate::analyzer::{ProjectFile, Range};
use crate::hash::HashMap;

use super::{WorkspaceSemanticOracle, common::Interruption, common::WorkStager};
use crate::analyzer::semantic::{
    AbstractObject, CandidateCoverage, HeapOracle, ObservationPhase, OracleCallContext,
    OracleCandidate, PointsToResult, SemanticArtifact, SemanticBudgetExceeded, SemanticCapability,
    SemanticOutcome, SemanticProviderError, SemanticRequest, SemanticWork, SourceSpan,
    ValueAtPoint, ValueHandle,
};

impl WorkspaceSemanticOracle<'_> {
    /// Resolve every retained point-sensitive value observation for the
    /// narrowest semantic source mapping that contains `range`.
    ///
    /// A single source value can occur at several path-specialized program
    /// points (for example, a duplicated cleanup path). Keeping each
    /// [`PointsToResult`] separate preserves its exact query identity and
    /// provenance. The number of retained observations is bounded by the
    /// oracle's source-observation limit; reaching that bound is reported
    /// through truncated coverage and an unproven outcome.
    pub fn pointees_at_source(
        &self,
        file: &ProjectFile,
        range: Range,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<SourcePointsToResult>, SemanticProviderError> {
        if request.cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: SemanticWork::default(),
            });
        }
        let materialized = self
            .workspace
            .materialize_program_semantics(file, request)?;
        let mut quality = SourcePointsToQuality::from_outcome(&materialized);
        let mut work = materialized.work();
        let Some(artifact) = materialized.available_value().cloned() else {
            return Ok(source_points_to_without_value(materialized));
        };

        let mut staged = WorkStager::new(request);
        let projection = source_value_observations(
            &artifact,
            range,
            self.limits.source_observations(),
            &mut staged,
            request.cancellation,
        );
        work = work.conservative_add(staged.work);
        let (observations, observations_truncated) = match projection {
            Ok(_) if request.cancellation.is_cancelled() => {
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work,
                });
            }
            Ok(projection) => projection,
            Err(Interruption::Budget(exceeded)) => {
                return Ok(SemanticOutcome::ExceededBudget {
                    partial: None,
                    exceeded,
                    work,
                });
            }
            Err(Interruption::Cancelled) => {
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work,
                });
            }
        };
        *request.budget = staged.budget;
        if observations.is_empty() {
            return Ok(SemanticOutcome::Unknown {
                partial: None,
                work,
            });
        }
        if observations_truncated {
            quality.absorb(SourcePointsToQuality::Unproven);
        }

        let mut points_to = Vec::with_capacity(observations.len());
        let mut all_results_exhaustive = true;
        let mut any_result_truncated = false;
        let observation_count = observations.len();
        for (index, observation) in observations.into_iter().enumerate() {
            let outcome = self.pointees(&observation, request)?;
            work = work.conservative_add(outcome.work());
            quality.absorb(SourcePointsToQuality::from_outcome(&outcome));
            if let Some(result) = outcome.available_value() {
                all_results_exhaustive &= result.objects().coverage().is_exhaustive();
                any_result_truncated |= result.objects().coverage().is_truncated();
                points_to.push(result.clone());
            } else {
                all_results_exhaustive = false;
            }
            if matches!(
                outcome,
                SemanticOutcome::Cancelled { .. } | SemanticOutcome::ExceededBudget { .. }
            ) {
                all_results_exhaustive &= index + 1 == observation_count;
                break;
            }
        }

        let coverage = if observations_truncated || any_result_truncated {
            CandidateCoverage::Truncated
        } else if all_results_exhaustive
            && !matches!(
                quality,
                SourcePointsToQuality::Unknown
                    | SourcePointsToQuality::Unsupported(_)
                    | SourcePointsToQuality::ExceededBudget(_)
                    | SourcePointsToQuality::Cancelled
            )
        {
            CandidateCoverage::Exhaustive
        } else {
            CandidateCoverage::Open
        };
        if coverage == CandidateCoverage::Open {
            quality.absorb(SourcePointsToQuality::Unknown);
        } else if coverage == CandidateCoverage::Truncated {
            quality.absorb(SourcePointsToQuality::Unproven);
        }
        let result = (!points_to.is_empty()).then(|| SourcePointsToResult {
            observations: points_to.into_boxed_slice(),
            coverage,
        });
        Ok(quality.publish(result, work))
    }
}

/// Point-sensitive points-to answers associated with one source range.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SourcePointsToResult {
    observations: Box<[PointsToResult]>,
    coverage: CandidateCoverage,
}

impl SourcePointsToResult {
    /// Exact value/point observations retained for the source range.
    pub fn observations(&self) -> &[PointsToResult] {
        &self.observations
    }

    /// Coverage across both source observations and their object sets.
    pub const fn coverage(&self) -> CandidateCoverage {
        self.coverage
    }

    pub fn object_candidates(&self) -> impl Iterator<Item = &OracleCandidate<AbstractObject>> {
        self.observations
            .iter()
            .flat_map(|result| result.objects().candidates())
    }

    pub fn is_empty(&self) -> bool {
        self.observations
            .iter()
            .all(|result| result.objects().candidates().is_empty())
    }
}

#[derive(Debug, Clone, Copy)]
enum SourcePointsToQuality {
    Complete,
    Ambiguous,
    Unproven,
    Unknown,
    Unsupported(SemanticCapability),
    ExceededBudget(SemanticBudgetExceeded),
    Cancelled,
}

impl SourcePointsToQuality {
    fn from_outcome<T>(outcome: &SemanticOutcome<T>) -> Self {
        match outcome {
            SemanticOutcome::Complete { .. } => Self::Complete,
            SemanticOutcome::Ambiguous { .. } => Self::Ambiguous,
            SemanticOutcome::Unknown { .. } => Self::Unknown,
            SemanticOutcome::Unsupported { capability, .. } => Self::Unsupported(*capability),
            SemanticOutcome::Unproven { .. } => Self::Unproven,
            SemanticOutcome::ExceededBudget { exceeded, .. } => Self::ExceededBudget(*exceeded),
            SemanticOutcome::Cancelled { .. } => Self::Cancelled,
        }
    }

    const fn priority(self) -> u8 {
        match self {
            Self::Complete => 0,
            Self::Ambiguous => 1,
            Self::Unproven => 2,
            Self::Unknown => 3,
            Self::Unsupported(_) => 4,
            Self::ExceededBudget(_) => 5,
            Self::Cancelled => 6,
        }
    }

    fn absorb(&mut self, other: Self) {
        if other.priority() > self.priority() {
            *self = other;
        }
    }

    fn publish(
        self,
        result: Option<SourcePointsToResult>,
        work: SemanticWork,
    ) -> SemanticOutcome<SourcePointsToResult> {
        match self {
            Self::Complete => result.map_or(
                SemanticOutcome::Unknown {
                    partial: None,
                    work,
                },
                |value| SemanticOutcome::Complete { value, work },
            ),
            Self::Ambiguous => result.map_or(
                SemanticOutcome::Unknown {
                    partial: None,
                    work,
                },
                |candidates| SemanticOutcome::Ambiguous { candidates, work },
            ),
            Self::Unproven => result.map_or(
                SemanticOutcome::Unknown {
                    partial: None,
                    work,
                },
                |partial| SemanticOutcome::Unproven { partial, work },
            ),
            Self::Unknown => SemanticOutcome::Unknown {
                partial: result,
                work,
            },
            Self::Unsupported(capability) => SemanticOutcome::Unsupported {
                capability,
                partial: result,
                work,
            },
            Self::ExceededBudget(exceeded) => SemanticOutcome::ExceededBudget {
                partial: result,
                exceeded,
                work,
            },
            Self::Cancelled => SemanticOutcome::Cancelled {
                partial: result,
                work,
            },
        }
    }
}

fn source_points_to_without_value(
    outcome: SemanticOutcome<Arc<SemanticArtifact>>,
) -> SemanticOutcome<SourcePointsToResult> {
    match outcome {
        SemanticOutcome::Unknown { work, .. } => SemanticOutcome::Unknown {
            partial: None,
            work,
        },
        SemanticOutcome::Unsupported {
            capability, work, ..
        } => SemanticOutcome::Unsupported {
            capability,
            partial: None,
            work,
        },
        SemanticOutcome::ExceededBudget { exceeded, work, .. } => SemanticOutcome::ExceededBudget {
            partial: None,
            exceeded,
            work,
        },
        SemanticOutcome::Cancelled { work, .. } => SemanticOutcome::Cancelled {
            partial: None,
            work,
        },
        SemanticOutcome::Complete { .. }
        | SemanticOutcome::Ambiguous { .. }
        | SemanticOutcome::Unproven { .. } => {
            unreachable!("available semantic outcomes always retain their value")
        }
    }
}

fn source_value_observations(
    artifact: &Arc<SemanticArtifact>,
    range: Range,
    limit: usize,
    staged: &mut WorkStager,
    cancellation: &crate::cancellation::CancellationToken,
) -> Result<(Vec<ValueAtPoint>, bool), Interruption> {
    let candidate_groups = source_value_candidates(artifact, range, staged, cancellation)?;
    let mut observations = Vec::new();
    for group in candidate_groups {
        if cancellation.is_cancelled() {
            return Err(Interruption::Cancelled);
        }
        if project_procedure_observations(
            &group.procedure,
            &group.candidates,
            range,
            limit,
            &mut observations,
            staged,
            cancellation,
        )? {
            return Ok((observations, true));
        }
    }
    Ok((observations, false))
}

#[derive(Debug)]
struct SourceValueCandidate {
    value: ValueHandle,
    span: SourceSpan,
}

#[derive(Debug)]
struct ProcedureSourceCandidates {
    procedure: crate::analyzer::semantic::ProcedureHandle,
    candidates: Vec<SourceValueCandidate>,
}

fn source_value_candidates(
    artifact: &Arc<SemanticArtifact>,
    range: Range,
    staged: &mut WorkStager,
    cancellation: &crate::cancellation::CancellationToken,
) -> Result<Vec<ProcedureSourceCandidates>, Interruption> {
    let mut best_value_width = None;
    let mut groups = Vec::new();
    for procedure in artifact.procedures() {
        if cancellation.is_cancelled() {
            return Err(Interruption::Cancelled);
        }
        staged.charge(SemanticWork {
            procedures: 1,
            ..SemanticWork::default()
        })?;
        let Some(procedure_handle) = artifact.procedure_handle(procedure.id()) else {
            continue;
        };
        let mut candidates = Vec::new();
        for value in procedure.values() {
            if cancellation.is_cancelled() {
                return Err(Interruption::Cancelled);
            }
            staged.charge(SemanticWork {
                values: 1,
                source_mappings: 1,
                ..SemanticWork::default()
            })?;
            let Some(mapping) = procedure.source_mapping(value.source) else {
                continue;
            };
            let span = mapping.locator.anchor().span();
            if !span_contains_range(span, range) {
                continue;
            }
            let width = (span.end_byte() - span.start_byte()) as usize;
            if best_value_width.is_some_and(|best| width > best) {
                continue;
            }
            if best_value_width.is_none_or(|best| width < best) {
                best_value_width = Some(width);
                groups.clear();
                candidates.clear();
            }
            let Some(value_handle) = procedure_handle.value_handle(value.id) else {
                continue;
            };
            staged.charge(SemanticWork {
                nested_entries: 1,
                ..SemanticWork::default()
            })?;
            candidates.push(SourceValueCandidate {
                value: value_handle,
                span,
            });
        }
        if !candidates.is_empty() {
            groups.push(ProcedureSourceCandidates {
                procedure: procedure_handle,
                candidates,
            });
        }
    }
    Ok(groups)
}

#[derive(Debug, Default)]
struct CandidateSpan {
    indexes: Vec<usize>,
    has_exact_point: bool,
}

#[allow(clippy::too_many_arguments)]
fn project_procedure_observations(
    procedure: &crate::analyzer::semantic::ProcedureHandle,
    candidates: &[SourceValueCandidate],
    range: Range,
    limit: usize,
    observations: &mut Vec<ValueAtPoint>,
    staged: &mut WorkStager,
    cancellation: &crate::cancellation::CancellationToken,
) -> Result<bool, Interruption> {
    let mut candidates_by_span = HashMap::<SourceSpan, CandidateSpan>::default();
    for (index, candidate) in candidates.iter().enumerate() {
        if cancellation.is_cancelled() {
            return Err(Interruption::Cancelled);
        }
        staged.charge(SemanticWork {
            nested_entries: 1,
            ..SemanticWork::default()
        })?;
        candidates_by_span
            .entry(candidate.span)
            .or_default()
            .indexes
            .push(index);
    }

    staged.charge(SemanticWork {
        procedures: 1,
        ..SemanticWork::default()
    })?;
    let mut fallback_width = None;
    for point in procedure.semantics().points() {
        if cancellation.is_cancelled() {
            return Err(Interruption::Cancelled);
        }
        staged.charge(SemanticWork {
            program_points: 1,
            source_mappings: 1,
            ..SemanticWork::default()
        })?;
        let Some(mapping) = procedure.semantics().source_mapping(point.source) else {
            continue;
        };
        let span = mapping.locator.anchor().span();
        if let Some(candidate_span) = candidates_by_span.get_mut(&span) {
            candidate_span.has_exact_point = true;
        }
        if !span_contains_range(span, range) {
            continue;
        }
        let width = (span.end_byte() - span.start_byte()) as usize;
        if fallback_width.is_none_or(|best| width < best) {
            fallback_width = Some(width);
        }
    }

    let mut fallback_candidates = Vec::new();
    for (index, candidate) in candidates.iter().enumerate() {
        if cancellation.is_cancelled() {
            return Err(Interruption::Cancelled);
        }
        staged.charge(SemanticWork {
            nested_entries: 1,
            ..SemanticWork::default()
        })?;
        if !candidates_by_span
            .get(&candidate.span)
            .is_some_and(|span| span.has_exact_point)
        {
            fallback_candidates.push(index);
        }
    }

    staged.charge(SemanticWork {
        procedures: 1,
        ..SemanticWork::default()
    })?;
    for point in procedure.semantics().points() {
        if cancellation.is_cancelled() {
            return Err(Interruption::Cancelled);
        }
        staged.charge(SemanticWork {
            program_points: 1,
            source_mappings: 1,
            ..SemanticWork::default()
        })?;
        let Some(mapping) = procedure.semantics().source_mapping(point.source) else {
            continue;
        };
        let span = mapping.locator.anchor().span();
        let Some(point_handle) = procedure.point_handle(point.id) else {
            continue;
        };
        if let Some(exact) = candidates_by_span
            .get(&span)
            .filter(|candidate_span| candidate_span.has_exact_point)
            && append_observations(
                &exact.indexes,
                candidates,
                procedure,
                &point_handle,
                limit,
                observations,
                staged,
                cancellation,
            )?
        {
            return Ok(true);
        }
        let span_width = (span.end_byte() - span.start_byte()) as usize;
        if span_contains_range(span, range)
            && fallback_width == Some(span_width)
            && append_observations(
                &fallback_candidates,
                candidates,
                procedure,
                &point_handle,
                limit,
                observations,
                staged,
                cancellation,
            )?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

#[allow(clippy::too_many_arguments)]
fn append_observations(
    candidate_indexes: &[usize],
    candidates: &[SourceValueCandidate],
    procedure: &crate::analyzer::semantic::ProcedureHandle,
    point: &crate::analyzer::semantic::ProgramPointHandle,
    limit: usize,
    observations: &mut Vec<ValueAtPoint>,
    staged: &mut WorkStager,
    cancellation: &crate::cancellation::CancellationToken,
) -> Result<bool, Interruption> {
    for index in candidate_indexes {
        if cancellation.is_cancelled() {
            return Err(Interruption::Cancelled);
        }
        staged.charge(SemanticWork {
            nested_entries: 1,
            ..SemanticWork::default()
        })?;
        if procedure
            .semantics()
            .call_phase_points(candidates[*index].value.id())
            .is_some_and(|points| !points.contains(&point.id()))
        {
            continue;
        }
        let Ok(observation) = ValueAtPoint::new(
            candidates[*index].value.clone(),
            point.clone(),
            ObservationPhase::AfterEffects,
            OracleCallContext::empty(),
        ) else {
            continue;
        };
        if observations.len() == limit {
            return Ok(true);
        }
        observations.push(observation);
    }
    Ok(false)
}

fn span_contains_range(span: SourceSpan, range: Range) -> bool {
    (span.start_byte() as usize) <= range.start_byte && (span.end_byte() as usize) >= range.end_byte
}
