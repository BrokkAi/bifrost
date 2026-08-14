//! Bounded source-range projection for point-sensitive heap and dispatch
//! queries.
//!
//! Both entry points share the same bridge: materialize the file's semantic
//! artifact, select the narrowest retained source mapping that contains the
//! requested range, and delegate to the handle-keyed oracle. Neither entry
//! point re-implements the answer it projects.

use std::sync::Arc;

use crate::analyzer::{ProjectFile, Range};
use crate::hash::HashMap;

use super::{
    WorkspaceSemanticOracle, common::Interruption, common::WorkStager,
    heap::points_to_capability_surface_is_incomplete,
};
use crate::analyzer::semantic::{
    AbstractObject, CallSiteHandle, CandidateCoverage, DispatchCandidate, DispatchOracle,
    DispatchResult, HeapOracle, ObservationPhase, OracleCallContext, OracleCandidate,
    PointsToResult, SemanticArtifact, SemanticBudgetExceeded, SemanticCapability, SemanticOutcome,
    SemanticProviderError, SemanticRequest, SemanticWork, SourceSpan, ValueAtPoint, ValueHandle,
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
        let mut quality = SourceOutcomeQuality::from_outcome(&materialized);
        let mut work = materialized.work();
        let Some(artifact) = materialized.available_value().cloned() else {
            return Ok(source_outcome_without_value(materialized));
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
            quality.absorb(SourceOutcomeQuality::Unproven);
        }

        let mut points_to = Vec::with_capacity(observations.len());
        let mut all_results_exhaustive = true;
        let mut any_result_truncated = false;
        let observation_count = observations.len();
        for (index, observation) in observations.into_iter().enumerate() {
            let outcome = self.pointees(&observation, request)?;
            work = work.conservative_add(outcome.work());
            quality.absorb(SourceOutcomeQuality::from_outcome(&outcome));
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
                SourceOutcomeQuality::Unknown
                    | SourceOutcomeQuality::Unsupported(_)
                    | SourceOutcomeQuality::ExceededBudget(_)
                    | SourceOutcomeQuality::Cancelled
            )
        {
            CandidateCoverage::Exhaustive
        } else {
            CandidateCoverage::Open
        };
        if coverage == CandidateCoverage::Open {
            quality.absorb(SourceOutcomeQuality::Unknown);
        } else if coverage == CandidateCoverage::Truncated {
            quality.absorb(SourceOutcomeQuality::Unproven);
        }
        let result = (!points_to.is_empty()).then(|| SourcePointsToResult {
            observations: points_to.into_boxed_slice(),
            coverage,
        });
        Ok(quality.publish(result, work))
    }

    /// Resolve dispatch for every semantic call site whose narrowest source
    /// mapping contains `range`.
    ///
    /// This is a bridging seam only: it locates the exact `CallSiteHandle`s at
    /// a source position and delegates each one to the handle-keyed dispatch
    /// oracle. Per-candidate proof, completeness, provenance, typed boundaries,
    /// and each call site's own [`CandidateCoverage`] are retained exactly as
    /// [`DispatchOracle::resolve_call`] reports them.
    ///
    /// One source range can address several call sites when a procedure is
    /// path-specialized or when equally narrow mappings coincide, so each
    /// answer stays separate under its own call-site identity. The number of
    /// retained call sites is bounded by the oracle's source-observation
    /// limit; reaching that bound is reported through truncated coverage and
    /// an unproven outcome.
    ///
    /// No call site at the position is [`SemanticOutcome::Unknown`], never an
    /// empty proven set: absence of a mapping is absence of evidence.
    pub fn dispatch_at_source(
        &self,
        file: &ProjectFile,
        range: Range,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<SourceDispatchResult>, SemanticProviderError> {
        if request.cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: SemanticWork::default(),
            });
        }
        let materialized = self
            .workspace
            .materialize_program_semantics(file, request)?;
        let mut quality = SourceOutcomeQuality::from_outcome(&materialized);
        let mut work = materialized.work();
        let Some(artifact) = materialized.available_value().cloned() else {
            return Ok(source_outcome_without_value(materialized));
        };

        let mut staged = WorkStager::new(request);
        let projection = source_call_sites(
            &artifact,
            range,
            self.limits.source_observations(),
            &mut staged,
            request.cancellation,
        );
        work = work.conservative_add(staged.work);
        let (calls, calls_truncated) = match projection {
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
        if calls.is_empty() {
            // An unsupported or otherwise degraded materialization keeps its
            // own quality; an otherwise healthy artifact with no call site at
            // this position is unknown, not an exhaustive empty answer.
            quality.absorb(SourceOutcomeQuality::Unknown);
            return Ok(quality.publish(None, work));
        }
        if calls_truncated {
            quality.absorb(SourceOutcomeQuality::Unproven);
        }

        let mut observations = Vec::with_capacity(calls.len());
        let mut all_results_exhaustive = true;
        let mut any_result_truncated = false;
        let call_count = calls.len();
        for (index, call) in calls.into_iter().enumerate() {
            let outcome = self.resolve_call(&call, request)?;
            work = work.conservative_add(outcome.work());
            quality.absorb(SourceOutcomeQuality::from_outcome(&outcome));
            if let Some(result) = outcome.available_value() {
                all_results_exhaustive &= result.coverage().is_exhaustive();
                any_result_truncated |= result.coverage().is_truncated();
                observations.push(SourceDispatchObservation {
                    call,
                    dispatch: result.clone(),
                });
            } else {
                all_results_exhaustive = false;
            }
            if matches!(
                outcome,
                SemanticOutcome::Cancelled { .. } | SemanticOutcome::ExceededBudget { .. }
            ) {
                all_results_exhaustive &= index + 1 == call_count;
                break;
            }
        }

        let coverage = if calls_truncated || any_result_truncated {
            CandidateCoverage::Truncated
        } else if all_results_exhaustive
            && !matches!(
                quality,
                SourceOutcomeQuality::Unknown
                    | SourceOutcomeQuality::Unsupported(_)
                    | SourceOutcomeQuality::ExceededBudget(_)
                    | SourceOutcomeQuality::Cancelled
            )
        {
            CandidateCoverage::Exhaustive
        } else {
            CandidateCoverage::Open
        };
        // Unlike the points-to seam, the aggregate coverage is not fed back
        // into the quality. Each delegated `resolve_call` already classified
        // its own open or truncated coverage (an unresolved boundary makes it
        // at least unproven), so re-absorbing would report a source position
        // as less certain than the exact call-site query it forwards to. Only
        // omission this seam caused itself is added, above.
        let result = (!observations.is_empty()).then(|| SourceDispatchResult {
            observations: observations.into_boxed_slice(),
            coverage,
        });
        Ok(quality.publish(result, work))
    }
}

/// One call site addressed by a source range together with its exact dispatch
/// answer. The call-site handle is retained so consumers key rows on semantic
/// identity rather than on the source range that located it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceDispatchObservation {
    call: CallSiteHandle,
    dispatch: DispatchResult,
}

impl SourceDispatchObservation {
    pub const fn call(&self) -> &CallSiteHandle {
        &self.call
    }

    pub const fn dispatch(&self) -> &DispatchResult {
        &self.dispatch
    }
}

/// Dispatch answers associated with one source range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceDispatchResult {
    observations: Box<[SourceDispatchObservation]>,
    coverage: CandidateCoverage,
}

impl SourceDispatchResult {
    /// Exact call-site dispatch answers retained for the source range.
    pub fn observations(&self) -> &[SourceDispatchObservation] {
        &self.observations
    }

    /// Coverage across both the located call sites and their target sets.
    /// This is `Exhaustive` only when every retained call site was itself
    /// exhaustive and no call site was omitted.
    pub const fn coverage(&self) -> CandidateCoverage {
        self.coverage
    }

    /// Every retained target across the located call sites. Each candidate
    /// keeps the proof, completeness, and provenance the dispatch oracle
    /// attached to it.
    pub fn target_candidates(&self) -> impl Iterator<Item = &DispatchCandidate> {
        self.observations
            .iter()
            .flat_map(|observation| observation.dispatch.candidates())
    }

    pub fn is_empty(&self) -> bool {
        self.observations
            .iter()
            .all(|observation| observation.dispatch.candidates().is_empty())
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

    /// Whether every retained observation is locally proven even though the
    /// adapter's whole-language points-to capability surface keeps coverage
    /// open. Consumers with an independent, syntax-scoped closure proof can
    /// use this distinction without treating arbitrary open evidence as exact.
    pub(crate) fn globally_incomplete_with_proven_candidates(&self) -> bool {
        self.coverage == CandidateCoverage::Open
            && !self.observations.is_empty()
            && self.observations.iter().all(|result| {
                let query = result.query();
                let candidates = result.objects().candidates();
                result.objects().coverage() == CandidateCoverage::Open
                    && points_to_capability_surface_is_incomplete(query.point().procedure())
                    && !query.context().was_truncated()
                    && !candidates.is_empty()
                    && candidates.iter().all(OracleCandidate::is_proven_complete)
            })
    }
}

#[derive(Debug, Clone, Copy)]
enum SourceOutcomeQuality {
    Complete,
    Ambiguous,
    Unproven,
    Unknown,
    Unsupported(SemanticCapability),
    ExceededBudget(SemanticBudgetExceeded),
    Cancelled,
}

impl SourceOutcomeQuality {
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

    /// Publish the merged quality over an optional projected answer. A quality
    /// that asserts an available answer but has none degrades to `Unknown`,
    /// never to an empty proven set.
    fn publish<T>(self, result: Option<T>, work: SemanticWork) -> SemanticOutcome<T> {
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

/// Re-type an unavailable materialization outcome for the projected answer.
/// Only the artifact's own honest failure state survives; no projection is
/// invented for a file whose semantics never materialized.
fn source_outcome_without_value<T>(
    outcome: SemanticOutcome<Arc<SemanticArtifact>>,
) -> SemanticOutcome<T> {
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

/// Locate the call sites whose source mapping is the narrowest one containing
/// `range`, across every procedure in the artifact.
///
/// Narrowest-span selection matches [`source_value_candidates`]: a nested call
/// such as `outer(inner())` must address `inner` when the range is inside it,
/// never the enclosing call. Returns the retained handles and whether the
/// oracle's source-observation limit omitted an equally narrow call site.
fn source_call_sites(
    artifact: &Arc<SemanticArtifact>,
    range: Range,
    limit: usize,
    staged: &mut WorkStager,
    cancellation: &crate::cancellation::CancellationToken,
) -> Result<(Vec<CallSiteHandle>, bool), Interruption> {
    let mut best_width = None;
    let mut calls = Vec::new();
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
        for call in procedure.call_sites() {
            if cancellation.is_cancelled() {
                return Err(Interruption::Cancelled);
            }
            staged.charge(SemanticWork {
                call_sites: 1,
                source_mappings: 1,
                ..SemanticWork::default()
            })?;
            let Some(mapping) = procedure.source_mapping(call.source) else {
                continue;
            };
            let span = mapping.locator.anchor().span();
            if !span_contains_range(span, range) {
                continue;
            }
            let width = (span.end_byte() - span.start_byte()) as usize;
            if best_width.is_some_and(|best| width > best) {
                continue;
            }
            if best_width.is_none_or(|best| width < best) {
                best_width = Some(width);
                calls.clear();
            }
            let Some(call_handle) = procedure_handle.call_site_handle(call.id) else {
                continue;
            };
            staged.charge(SemanticWork {
                nested_entries: 1,
                ..SemanticWork::default()
            })?;
            calls.push(call_handle);
        }
    }
    let truncated = calls.len() > limit;
    calls.truncate(limit);
    Ok((calls, truncated))
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
            .is_some_and(|points| points.binary_search(&point.id()).is_err())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic::SemanticBudget;
    use crate::analyzer::{Language, ProjectFile};
    use crate::cancellation::CancellationToken;
    use crate::test_support::AnalyzerFixture;

    const CALL_SOURCE: &str = "function target() {}\nexport function caller() { target(); }\n";

    /// The durable, arena-independent shape of one dispatch answer. Relation
    /// provenance handles are query-local (they compare by arena identity), so
    /// two runs of the same query are compared through the observable target,
    /// quality, boundary, and coverage vocabulary instead.
    #[derive(Debug, PartialEq, Eq)]
    struct DispatchShape {
        targets: Vec<(String, String, String)>,
        boundaries: Vec<String>,
        coverage: CandidateCoverage,
    }

    fn dispatch_shape(result: &DispatchResult) -> DispatchShape {
        DispatchShape {
            targets: result
                .candidates()
                .iter()
                .map(|candidate| {
                    (
                        format!("{:?}", candidate.target().semantics().locator()),
                        format!("{:?}", candidate.proof()),
                        format!("{:?}", candidate.completeness()),
                    )
                })
                .collect(),
            boundaries: result
                .boundaries()
                .iter()
                .map(|boundary| format!("{:?}", boundary.kind))
                .collect(),
            coverage: result.coverage(),
        }
    }

    fn outcome_label<T>(outcome: &SemanticOutcome<T>) -> &'static str {
        match outcome {
            SemanticOutcome::Complete { .. } => "complete",
            SemanticOutcome::Ambiguous { .. } => "ambiguous",
            SemanticOutcome::Unproven { .. } => "unproven",
            SemanticOutcome::Unknown { .. } => "unknown",
            SemanticOutcome::Unsupported { .. } => "unsupported",
            SemanticOutcome::ExceededBudget { .. } => "exceeded_budget",
            SemanticOutcome::Cancelled { .. } => "cancelled",
        }
    }

    fn typescript_fixture(files: &[(&str, &str)]) -> AnalyzerFixture {
        AnalyzerFixture::new_for_language(Language::TypeScript, files)
    }

    fn artifact_for(
        fixture: &AnalyzerFixture,
        file: &ProjectFile,
    ) -> Arc<crate::analyzer::semantic::SemanticArtifact> {
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        fixture
            .analyzer
            .materialize_program_semantics(
                file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("TypeScript semantic materialization")
            .available_value()
            .cloned()
            .expect("TypeScript semantic artifact")
    }

    /// The only call site in `CALL_SOURCE`, with the exact source range its
    /// semantic mapping anchors.
    fn only_call_site(
        artifact: &Arc<crate::analyzer::semantic::SemanticArtifact>,
    ) -> (CallSiteHandle, Range) {
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| !procedure.call_sites().is_empty())
            .expect("caller procedure");
        let call = &procedure.call_sites()[0];
        let span = procedure
            .source_mapping(call.source)
            .expect("call source mapping")
            .locator
            .anchor()
            .span();
        let handle = artifact
            .procedure_handle(procedure.id())
            .and_then(|procedure| procedure.call_site_handle(call.id))
            .expect("scoped call handle");
        (
            handle,
            Range {
                start_byte: span.start_byte() as usize,
                end_byte: span.end_byte() as usize,
                start_line: span.start().line() as usize,
                end_line: span.end().line() as usize,
            },
        )
    }

    /// #1477 Milestone 4: the source-position seam must publish exactly the
    /// answer the `CallSiteHandle` path publishes, not an approximation of it.
    #[test]
    fn dispatch_at_source_agrees_with_the_call_site_handle_path() {
        let fixture = typescript_fixture(&[("call.ts", CALL_SOURCE)]);
        let file = ProjectFile::new(fixture.project_root(), "call.ts");
        let artifact = artifact_for(&fixture, &file);
        let (call, range) = only_call_site(&artifact);
        let oracle = fixture.analyzer.semantic_oracle_provider();
        let cancellation = CancellationToken::default();

        let mut handle_budget = SemanticBudget::default();
        let by_handle = oracle
            .resolve_call(
                &call,
                &mut SemanticRequest::new(&mut handle_budget, &cancellation),
            )
            .expect("handle dispatch");
        let by_handle_result = by_handle
            .available_value()
            .expect("handle dispatch retains a result");

        let mut source_budget = SemanticBudget::default();
        let by_source = oracle
            .dispatch_at_source(
                &file,
                range,
                &mut SemanticRequest::new(&mut source_budget, &cancellation),
            )
            .expect("source dispatch");
        assert_eq!(
            outcome_label(&by_source),
            outcome_label(&by_handle),
            "source and handle dispatch must classify the same call identically: \
             {by_source:?} vs {by_handle:?}"
        );
        let by_source_result = by_source
            .available_value()
            .expect("source dispatch retains a result");
        assert_eq!(
            by_source_result.observations().len(),
            1,
            "one call site occupies this range: {by_source_result:?}"
        );
        let observation = &by_source_result.observations()[0];
        assert_eq!(
            observation.call().id(),
            call.id(),
            "the seam must address the same semantic call site"
        );
        assert_eq!(
            dispatch_shape(observation.dispatch()),
            dispatch_shape(by_handle_result),
            "the seam must not alter targets, quality, boundaries, or coverage"
        );
        assert_eq!(by_source_result.coverage(), by_handle_result.coverage());
        assert_eq!(
            by_source_result.target_candidates().count(),
            by_handle_result.candidates().len()
        );
    }

    /// A position that no call site covers is unknown. It must never publish
    /// an empty target set that a policy could read as a proven zero.
    #[test]
    fn dispatch_at_source_without_a_call_site_is_unknown() {
        let fixture = typescript_fixture(&[("call.ts", CALL_SOURCE)]);
        let file = ProjectFile::new(fixture.project_root(), "call.ts");
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        // The `function` keyword of the callee declaration: inside the file,
        // outside every call expression.
        let outcome = fixture
            .analyzer
            .semantic_oracle_provider()
            .dispatch_at_source(
                &file,
                Range {
                    start_byte: 0,
                    end_byte: "function".len(),
                    start_line: 0,
                    end_line: 0,
                },
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("source dispatch");
        let SemanticOutcome::Unknown { partial, .. } = &outcome else {
            panic!("a position with no call site must be Unknown: {outcome:?}");
        };
        assert!(
            partial.is_none(),
            "no call site means no dispatch answer at all: {partial:?}"
        );
    }

    /// A file the workspace cannot materialize keeps the materialization's own
    /// unsupported capability rather than reporting an empty dispatch set.
    #[test]
    fn dispatch_at_source_in_an_unsupported_file_is_unsupported() {
        let fixture =
            typescript_fixture(&[("call.ts", CALL_SOURCE), ("notes.txt", "plain prose\n")]);
        let file = ProjectFile::new(fixture.project_root(), "notes.txt");
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let outcome = fixture
            .analyzer
            .semantic_oracle_provider()
            .dispatch_at_source(
                &file,
                Range {
                    start_byte: 0,
                    end_byte: 5,
                    start_line: 0,
                    end_line: 0,
                },
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("source dispatch");
        let SemanticOutcome::Unsupported {
            capability,
            partial,
            ..
        } = &outcome
        else {
            panic!("an unsupported file must report Unsupported: {outcome:?}");
        };
        assert_eq!(*capability, SemanticCapability::Procedures);
        assert!(partial.is_none(), "{partial:?}");
    }

    /// Cancellation before any work is a cancelled outcome, not an empty one.
    #[test]
    fn dispatch_at_source_reports_cancellation() {
        let fixture = typescript_fixture(&[("call.ts", CALL_SOURCE)]);
        let file = ProjectFile::new(fixture.project_root(), "call.ts");
        let artifact = artifact_for(&fixture, &file);
        let (_, range) = only_call_site(&artifact);
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        let mut budget = SemanticBudget::default();
        let outcome = fixture
            .analyzer
            .semantic_oracle_provider()
            .dispatch_at_source(
                &file,
                range,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("source dispatch");
        assert!(
            matches!(outcome, SemanticOutcome::Cancelled { .. }),
            "{outcome:?}"
        );
    }
}
