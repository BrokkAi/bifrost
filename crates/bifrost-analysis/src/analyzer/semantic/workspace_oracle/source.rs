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
    dispatch::PreparedWorkspaceDispatchSession, heap::points_to_capability_surface_is_incomplete,
};
use crate::analyzer::semantic::{
    AbstractObject, CallSiteHandle, CandidateCoverage, DispatchBoundary, DispatchBoundaryKind,
    DispatchCandidate, DispatchResult, EvidenceCompleteness, HeapOracle, LengthDelimitedDigest,
    ObservationPhase, OracleCallContext, OracleCandidate, PointsToResult, ProofStatus,
    SemanticArtifact, SemanticBudgetExceeded, SemanticBudgetScopeIdentity, SemanticCapability,
    SemanticLocator, SemanticOutcome, SemanticProviderError, SemanticRequest, SemanticWork,
    SourceSpan, StableDigest, ValueAtPoint, ValueHandle,
};

/// A lazy file-window dispatch session over one immutable semantic artifact.
///
/// Source ranges need not be known up front. Each range is projected only when
/// requested, and each resulting call is dispatched serially. The first real
/// call initializes the exact-source parse session; skipped rows perform no
/// low-level work and cannot desynchronize later rows. That first demand also
/// freezes the caller source for the rest of this query-scoped file window;
/// later demands deliberately reuse it even if a live editor overlay changes.
/// Reuse is valid only inside one logical [`crate::analyzer::semantic::SemanticBudget`]
/// scope, so a fresh independent request cannot inherit work paid elsewhere.
#[doc(hidden)]
pub struct PreparedSourceDispatchSession<'a> {
    oracle: WorkspaceSemanticOracle<'a>,
    materialized: SemanticOutcome<Arc<SemanticArtifact>>,
    pending_materialization_work: SemanticWork,
    budget_scope: Option<SemanticBudgetScopeIdentity>,
    calls: Option<PreparedWorkspaceDispatchSession<'a>>,
}

impl PreparedSourceDispatchSession<'_> {
    /// Conservative physical footprint retained only for this prepared file
    /// window. The artifact itself is accounted by its lease owner.
    #[doc(hidden)]
    pub fn retained_bytes(&self) -> usize {
        self.calls
            .as_ref()
            .map_or(0, PreparedWorkspaceDispatchSession::retained_bytes)
    }

    #[doc(hidden)]
    pub fn resolve_at_source(
        &mut self,
        range: Range,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<SourceDispatchResult>, SemanticProviderError> {
        if !request.cancellation.is_cancelled() {
            match &self.budget_scope {
                Some(scope) if !request.budget.shares_scope_with(scope) => {
                    return Err(SemanticProviderError::invalid_identity(
                        "prepared source dispatch cannot cross semantic budget scopes",
                    ));
                }
                Some(_) => {}
                None => self.budget_scope = Some(request.budget.scope_identity()),
            }
        }
        let mut quality = SourceOutcomeQuality::from_outcome(&self.materialized);
        // Materialization happened once before this file session opened. Its
        // outcome quality applies to every projection, but its physical work
        // is reported only by the first projection that consumes the session.
        let mut work = std::mem::take(&mut self.pending_materialization_work);
        let Some(artifact) = self.materialized.available_value().cloned() else {
            return Ok(quality.publish(None, work));
        };

        let mut staged = WorkStager::new(request);
        let projection = source_call_sites(
            &artifact,
            range,
            self.oracle.limits.source_observations(),
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
            let outcome = self
                .calls
                .as_mut()
                .expect("an available artifact owns a dispatch session")
                .resolve_call(&call, request)?;
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

        let coverage = projected_source_coverage(
            quality,
            calls_truncated || any_result_truncated,
            all_results_exhaustive,
        );
        // Aggregate coverage does not feed back into quality. Each delegated
        // call already classified its own open or truncated answer; only
        // source-observation omission introduced by this seam is absorbed
        // above.
        let result = (!observations.is_empty()).then(|| SourceDispatchResult {
            observations: observations.into_boxed_slice(),
            coverage,
        });
        Ok(quality.publish(result, work))
    }
}

impl<'a> WorkspaceSemanticOracle<'a> {
    /// Open a source dispatch session without reading or parsing source.
    #[doc(hidden)]
    pub fn prepare_source_dispatch_session_in_artifact(
        &self,
        materialized: SemanticOutcome<Arc<SemanticArtifact>>,
    ) -> PreparedSourceDispatchSession<'a> {
        let pending_materialization_work = materialized.work();
        let calls = materialized
            .available_value()
            .cloned()
            .map(|artifact| self.prepare_call_dispatch_session(artifact));
        PreparedSourceDispatchSession {
            oracle: self.clone(),
            materialized,
            pending_materialization_work,
            budget_scope: None,
            calls,
        }
    }

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
    /// [`crate::analyzer::semantic::DispatchOracle::resolve_call`] reports
    /// them.
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
        self.dispatch_at_source_in_artifact(materialized, range, request)
    }

    /// Resolve source dispatch from an artifact materialization the caller
    /// already charged to `request`.
    ///
    /// The complete materialization outcome is accepted, rather than only its
    /// artifact, so an ambiguous, unproven, unknown, unsupported, budgeted, or
    /// cancelled partial retains exactly the quality it would have had through
    /// [`Self::dispatch_at_source`]. Source-observation limits and every
    /// call-site dispatch budget remain active; this entry point only avoids
    /// paying for the same artifact a second time when a query context already
    /// owns its exact materialization.
    pub fn dispatch_at_source_in_artifact(
        &self,
        materialized: SemanticOutcome<Arc<SemanticArtifact>>,
        range: Range,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<SourceDispatchResult>, SemanticProviderError> {
        // Only retained when a ledger will read it: the artifact is needed to
        // name the question, and an Arc bump on every dispatch is a cost this
        // milestone must not add to runs that record nothing.
        let artifact = self
            .workspace
            .analyzer()
            .read_ledger_attached()
            .then(|| materialized.available_value().map(Arc::clone))
            .flatten();
        let question = artifact
            .as_ref()
            .map(|artifact| dispatch_question(artifact, range));
        let outcome = self
            .prepare_source_dispatch_session_in_artifact(materialized)
            .resolve_at_source(range, request)?;
        // Dispatch is the channel a result contract or a task slice composes
        // callee bodies through, so the answer -- which targets, and whether
        // the set was exhaustive -- is itself an input the reader depended on.
        if let Some(question) = question {
            self.workspace
                .analyzer()
                .record_read(crate::analyzer::read_ledger::ReadKey::lookup(
                    crate::analyzer::read_ledger::LookupKind::Dispatch,
                    question,
                    dispatch_answer_digest(outcome.available_value()),
                ));
        }
        Ok(outcome)
    }
}

/// Domain for the digest of one dispatch answer.
const DISPATCH_ANSWER_DOMAIN: &[u8] = b"bifrost-read-ledger:dispatch-answer:v1";

/// The coverage a source-range dispatch answer publishes.
///
/// `truncated` is set when the located call set, or any located call's own
/// answer, was cut short; `exhaustive` when every located call answered
/// exhaustively. A quality that asserts no answer -- unknown, unsupported,
/// budgeted, cancelled -- cannot publish an exhaustive range answer even when
/// every call it did retain was itself exhaustive.
///
/// Shared with [`one_call_dispatch_answer_digest`], which is the same rule for
/// a range that located exactly one call site.
const fn projected_source_coverage(
    quality: SourceOutcomeQuality,
    truncated: bool,
    exhaustive: bool,
) -> CandidateCoverage {
    if truncated {
        CandidateCoverage::Truncated
    } else if exhaustive
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
    }
}

/// The answer digest the exact handle-keyed dispatch funnel records for
/// `call`.
///
/// Procedure-local replay resolves the structured relative-range address back
/// to exactly one [`CallSiteHandle`] and calls [`DispatchOracle::resolve_call`]
/// directly. Its answer therefore uses the procedure-dispatch domain and
/// stable target lineages, not the artifact-wide source projection's identity
/// terms.
///
/// The materialization quality is `Complete` by construction here: the caller
/// holds a `CallSiteHandle` into an artifact that materialized.
#[doc(hidden)]
pub fn one_call_dispatch_answer_digest(
    call: &CallSiteHandle,
    outcome: &SemanticOutcome<DispatchResult>,
) -> crate::analyzer::semantic::ids::StableDigest {
    let quality = SourceOutcomeQuality::from_outcome(outcome);
    let Some(dispatch) = outcome.available_value() else {
        return procedure_dispatch_answer_digest(quality, None);
    };
    let coverage = projected_source_coverage(
        quality,
        dispatch.coverage().is_truncated(),
        dispatch.coverage().is_exhaustive(),
    );
    procedure_dispatch_answer_digest(
        quality,
        Some(&SourceDispatchResult {
            observations: Box::new([SourceDispatchObservation {
                call: call.clone(),
                dispatch: dispatch.clone(),
            }]),
            coverage,
        }),
    )
}

/// The replayable question "dispatch at this range of this artifact".
///
/// The file is named by its workspace-relative path and the artifact by its
/// public fingerprint, never by the mount-bearing `SemanticArtifactKey`, so
/// the same question over the same content at two roots is the same question.
pub(crate) fn dispatch_question(
    artifact: &SemanticArtifact,
    range: Range,
) -> crate::analyzer::read_ledger::LookupQuestion {
    crate::analyzer::read_ledger::LookupQuestion::call_site(
        artifact.key().path().as_str(),
        artifact.key().public_fingerprint(),
        range,
    )
}

/// The replayable question for one handle-keyed procedure-local dispatch.
///
/// Unlike [`dispatch_question`], this address excludes the artifact source
/// revision and measures the call range from the owning procedure's start.
/// That is the exact scope a procedure summary needs: another declaration in
/// the same file may move both absolute ranges without changing this call.
pub(crate) fn procedure_dispatch_question(
    call: &CallSiteHandle,
    range: Range,
) -> Option<crate::analyzer::read_ledger::LookupQuestion> {
    let procedure = call.procedure();
    let procedure_start = procedure.semantics().locator().anchor().span().start_byte() as usize;
    let start_byte = range.start_byte.checked_sub(procedure_start)?;
    let end_byte = range.end_byte.checked_sub(procedure_start)?;
    Some(
        crate::analyzer::read_ledger::LookupQuestion::procedure_call_site(
            procedure.artifact().key().path().as_str(),
            procedure
                .artifact()
                .key()
                .procedure_lineage_fingerprint(procedure.semantics().locator().declaration()),
            crate::analyzer::read_ledger::ProcedureCallSiteLocator {
                start_byte,
                end_byte,
            },
        ),
    )
}

/// The canonical digest of a dispatch answer: its targets by public artifact
/// fingerprint and procedure id, plus its coverage.
///
/// A target is never named by its `SemanticArtifactKey` or its
/// `SemanticLocator`: both fold the workspace mount, so the same answer at two
/// roots would digest differently and no base unit could ever verify.
pub(crate) fn dispatch_answer_digest(
    result: Option<&SourceDispatchResult>,
) -> crate::analyzer::semantic::ids::StableDigest {
    let mut hasher = crate::analyzer::canonical_hash::CanonicalHasher::new(DISPATCH_ANSWER_DOMAIN);
    let Some(result) = result else {
        hasher.value(b"unavailable");
        return crate::analyzer::semantic::ids::StableDigest::from_array(hasher.finish());
    };
    hasher.field("coverage", result.coverage().label().as_bytes());
    let mut targets = result
        .target_candidates()
        .map(|candidate| {
            let target = candidate.target();
            (
                *target.artifact().key().public_fingerprint().as_bytes(),
                target.id().index(),
            )
        })
        .collect::<Vec<_>>();
    targets.sort();
    targets.dedup();
    for (artifact, procedure) in targets {
        hasher.value(&artifact);
        hasher.value(&(procedure as u64).to_be_bytes());
    }
    crate::analyzer::semantic::ids::StableDigest::from_array(hasher.finish())
}

/// Canonical answer for a procedure-local dispatch question.
///
/// This is the complete stable projection that can affect direct-call binding
/// or planning. Query-local provenance is deliberately absent: it certifies
/// the answer inside one oracle request but cannot be replayed across arenas.
/// Stable target lineages exclude whole-artifact source revisions; consumers
/// that enter those bodies record their semantic artifacts or summary
/// dependencies separately.
fn procedure_dispatch_answer_digest(
    quality: SourceOutcomeQuality,
    result: Option<&SourceDispatchResult>,
) -> crate::analyzer::semantic::ids::StableDigest {
    let mut digest =
        LengthDelimitedDigest::new(b"bifrost-read-ledger:procedure-dispatch-answer:v2");
    push_source_outcome_quality(&mut digest, quality);
    let Some(result) = result else {
        digest.push(b"unavailable");
        return digest.finish();
    };
    digest.push(b"available");
    digest.push(result.coverage().label().as_bytes());
    assert_eq!(
        result.observations().len(),
        1,
        "a procedure dispatch answer belongs to exactly one procedure-local call question"
    );
    digest.push(
        &u64::try_from(result.observations().len())
            .expect("one procedure dispatch observation fits in u64")
            .to_le_bytes(),
    );
    digest.push(
        procedure_dispatch_observation_digest(result.observations()[0].dispatch()).as_bytes(),
    );
    digest.finish()
}

fn procedure_dispatch_observation_digest(dispatch: &DispatchResult) -> StableDigest {
    let mut candidates = dispatch
        .candidates()
        .iter()
        .map(procedure_dispatch_candidate_digest)
        .collect::<Vec<_>>();
    let mut boundaries = dispatch
        .boundaries()
        .iter()
        .map(procedure_dispatch_boundary_digest)
        .collect::<Vec<_>>();
    procedure_dispatch_components_digest(
        dispatch.coverage(),
        dispatch.complete_receiver_hint_refinable(),
        &mut candidates,
        &mut boundaries,
    )
}

fn procedure_dispatch_components_digest(
    coverage: CandidateCoverage,
    complete_receiver_hint_refinable: bool,
    candidates: &mut [StableDigest],
    boundaries: &mut [StableDigest],
) -> StableDigest {
    let mut digest =
        LengthDelimitedDigest::new(b"bifrost-read-ledger:procedure-dispatch-observation:v2");
    digest.push(coverage.label().as_bytes());
    digest.push(&[u8::from(complete_receiver_hint_refinable)]);

    candidates.sort_unstable();
    digest.push(
        &u64::try_from(candidates.len())
            .expect("procedure dispatch candidate count fits in u64")
            .to_le_bytes(),
    );
    for candidate in candidates {
        digest.push(candidate.as_bytes());
    }

    boundaries.sort_unstable();
    digest.push(
        &u64::try_from(boundaries.len())
            .expect("procedure dispatch boundary count fits in u64")
            .to_le_bytes(),
    );
    for boundary in boundaries {
        digest.push(boundary.as_bytes());
    }
    digest.finish()
}

fn procedure_dispatch_candidate_digest(candidate: &DispatchCandidate) -> StableDigest {
    let mut digest =
        LengthDelimitedDigest::new(b"bifrost-read-ledger:procedure-dispatch-candidate:v2");
    let target = candidate.target();
    digest.push(
        target
            .artifact()
            .key()
            .procedure_lineage_fingerprint(target.semantics().locator().declaration())
            .as_bytes(),
    );
    push_proof(&mut digest, candidate.proof());
    push_completeness(&mut digest, candidate.completeness());
    let mut excluded = candidate
        .excluded_targets()
        .iter()
        .map(|target| {
            target
                .artifact()
                .key()
                .procedure_lineage_fingerprint(target.semantics().locator().declaration())
        })
        .collect::<Vec<_>>();
    excluded.sort_unstable();
    digest.push(
        &u64::try_from(excluded.len())
            .expect("excluded dispatch target count fits in u64")
            .to_le_bytes(),
    );
    for target in excluded {
        digest.push(target.as_bytes());
    }
    digest.finish()
}

fn procedure_dispatch_boundary_digest(boundary: &DispatchBoundary) -> StableDigest {
    let mut digest =
        LengthDelimitedDigest::new(b"bifrost-read-ledger:procedure-dispatch-boundary:v2");
    digest.push(boundary.kind.label().as_bytes());
    match &boundary.kind {
        DispatchBoundaryKind::External(target) => {
            push_optional_locator(&mut digest, target.as_ref());
        }
        DispatchBoundaryKind::Unmaterialized(target) => {
            push_locator(&mut digest, target);
        }
        DispatchBoundaryKind::Deferred { target, kind } => {
            push_locator(&mut digest, target);
            digest.push(kind.label().as_bytes());
        }
        DispatchBoundaryKind::Unresolved | DispatchBoundaryKind::Truncated => {}
    }

    match boundary.external_callee_identity() {
        Some(identity) => {
            digest.push(b"external-callee-identity");
            digest.push(identity.language().config_label().as_bytes());
            digest.push(identity.owner_fqn().as_bytes());
            digest.push(identity.member().as_bytes());
        }
        None => digest.push(b"no-external-callee-identity"),
    }

    match boundary.exact_external_target() {
        Some(target) => {
            digest.push(b"exact-external-target");
            digest.push(target.artifact().public_fingerprint().as_bytes());
            push_locator(&mut digest, target.procedure());
            digest.push(target.symbol().as_bytes());
            digest.push(&[u8::from(target.has_receiver())]);
            let contract = target.formal_contract();
            digest.push(contract.label().as_bytes());
            digest.push(
                &u64::try_from(contract.parameters().len())
                    .expect("exact external formal count fits in u64")
                    .to_le_bytes(),
            );
            for parameter in contract.parameters() {
                digest.push(parameter.label().as_bytes());
                push_optional_bytes(&mut digest, parameter.declared_type().map(str::as_bytes));
                digest.push(&[u8::from(parameter.optional())]);
                digest.push(&[u8::from(parameter.repeated())]);
            }
            match contract.arity() {
                Some(arity) => {
                    digest.push(b"arity");
                    digest.push(
                        &u64::try_from(arity.required())
                            .expect("required callable arity fits in u64")
                            .to_le_bytes(),
                    );
                    digest.push(
                        &u64::try_from(arity.total())
                            .expect("total callable arity fits in u64")
                            .to_le_bytes(),
                    );
                    digest.push(&[u8::from(arity.is_repeated())]);
                }
                None => digest.push(b"no-arity"),
            }
        }
        None => digest.push(b"no-exact-external-target"),
    }

    match boundary.unmaterialized_external_target() {
        Some(target) => {
            digest.push(b"unmaterialized-external-target");
            push_locator(&mut digest, target.locator());
            digest.push(target.owner_fqn().as_bytes());
            digest.push(target.member().as_bytes());
            digest.push(&target.arity().to_le_bytes());
            digest.push(&[u8::from(target.has_receiver())]);
            digest.push(&[u8::from(target.has_resolver_owned_call_shape())]);
            push_optional_bytes(
                &mut digest,
                target.normalized_static_owner().map(str::as_bytes),
            );
        }
        None => digest.push(b"no-unmaterialized-external-target"),
    }
    push_proof(&mut digest, &boundary.proof);
    push_completeness(&mut digest, &boundary.completeness);
    digest.finish()
}

fn push_source_outcome_quality(digest: &mut LengthDelimitedDigest, quality: SourceOutcomeQuality) {
    match quality {
        SourceOutcomeQuality::Complete => digest.push(b"complete"),
        SourceOutcomeQuality::Ambiguous => digest.push(b"ambiguous"),
        SourceOutcomeQuality::Unproven => digest.push(b"unproven"),
        SourceOutcomeQuality::Unknown => digest.push(b"unknown"),
        SourceOutcomeQuality::Unsupported(capability) => {
            digest.push(b"unsupported");
            digest.push(capability.label().as_bytes());
        }
        SourceOutcomeQuality::ExceededBudget(exceeded) => {
            digest.push(b"exceeded-budget");
            digest.push(exceeded.dimension().label().as_bytes());
            digest.push(
                &u64::try_from(exceeded.limit())
                    .expect("semantic budget limit fits in u64")
                    .to_le_bytes(),
            );
            digest.push(
                &u64::try_from(exceeded.attempted())
                    .expect("semantic budget attempt fits in u64")
                    .to_le_bytes(),
            );
        }
        SourceOutcomeQuality::Cancelled => digest.push(b"cancelled"),
    }
}

fn push_proof(digest: &mut LengthDelimitedDigest, proof: &ProofStatus) {
    digest.push(proof.label().as_bytes());
    if let ProofStatus::Unproven(reason) = proof {
        digest.push(reason.as_bytes());
    }
}

fn push_completeness(digest: &mut LengthDelimitedDigest, completeness: &EvidenceCompleteness) {
    digest.push(completeness.label().as_bytes());
    if let EvidenceCompleteness::Partial(reason) = completeness {
        digest.push(reason.as_bytes());
    }
}

fn push_optional_locator(digest: &mut LengthDelimitedDigest, locator: Option<&SemanticLocator>) {
    match locator {
        Some(locator) => {
            digest.push(b"locator");
            push_locator(digest, locator);
        }
        None => digest.push(b"no-locator"),
    }
}

fn push_locator(digest: &mut LengthDelimitedDigest, locator: &SemanticLocator) {
    locator.push_anchor_free_procedure_declaration_identity(digest);
}

fn push_optional_bytes(digest: &mut LengthDelimitedDigest, value: Option<&[u8]>) {
    match value {
        Some(value) => {
            digest.push(b"some");
            digest.push(value);
        }
        None => digest.push(b"none"),
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
    use crate::analyzer::semantic::{DispatchOracle, SemanticBudget, SemanticBudgetDimension};
    use crate::analyzer::{Language, ProjectFile};
    use crate::cancellation::CancellationToken;
    use crate::test_support::AnalyzerFixture;

    const CALL_SOURCE: &str = "function target() {}\nexport function caller() { target(); }\n";
    const BATCH_CALL_SOURCE: &str = "import { open } from \"third-party\";\nexport function caller() { open(\"a\"); open(\"b\"); }\n";
    const DISTINCT_CALL_SOURCE: &str = "function first() {}\nfunction second() {}\nexport function caller() { first(); second(); }\n";

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

    fn all_call_sites(
        artifact: &Arc<crate::analyzer::semantic::SemanticArtifact>,
    ) -> Vec<(CallSiteHandle, Range)> {
        artifact
            .procedures()
            .iter()
            .flat_map(|procedure| {
                procedure.call_sites().iter().map(|call| {
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
                })
            })
            .collect()
    }

    fn complete_materialization(
        artifact: &Arc<crate::analyzer::semantic::SemanticArtifact>,
    ) -> SemanticOutcome<Arc<crate::analyzer::semantic::SemanticArtifact>> {
        complete_materialization_with_work(artifact, SemanticWork::default())
    }

    fn complete_materialization_with_work(
        artifact: &Arc<crate::analyzer::semantic::SemanticArtifact>,
        work: SemanticWork,
    ) -> SemanticOutcome<Arc<crate::analyzer::semantic::SemanticArtifact>> {
        SemanticOutcome::Complete {
            value: Arc::clone(artifact),
            work,
        }
    }

    #[test]
    fn prepared_source_dispatch_session_shares_one_parse_and_matches_serial_results() {
        let fixture = typescript_fixture(&[("batch.ts", BATCH_CALL_SOURCE)]);
        let file = ProjectFile::new(fixture.project_root(), "batch.ts");
        let artifact = artifact_for(&fixture, &file);
        let calls = all_call_sites(&artifact);
        assert_eq!(calls.len(), 2, "the fixture has two external calls");
        let oracle = fixture.analyzer.semantic_oracle_provider();
        let cancellation = CancellationToken::default();
        let mut session_budget = SemanticBudget::default();
        let mut session_request = SemanticRequest::new(&mut session_budget, &cancellation);
        let mut session =
            oracle.prepare_source_dispatch_session_in_artifact(complete_materialization(&artifact));

        let mut session_outcomes = Vec::new();
        for (call, range) in &calls {
            let outcome = session
                .resolve_at_source(*range, &mut session_request)
                .expect("prepared source dispatch");
            let result = outcome
                .available_value()
                .expect("external call retains a dispatch result");
            assert_eq!(result.observations().len(), 1);
            assert_eq!(result.observations()[0].call(), call);
            session_outcomes.push(outcome);
        }
        assert_eq!(
            session_outcomes[0].work().source_bytes,
            BATCH_CALL_SOURCE.len()
        );
        assert_eq!(session_outcomes[1].work().source_bytes, 0);
        assert_eq!(
            session_request.budget.used().source_bytes,
            BATCH_CALL_SOURCE.len()
        );

        for ((_, range), session_outcome) in calls.iter().zip(&session_outcomes) {
            let mut serial_budget = SemanticBudget::default();
            let serial = oracle
                .dispatch_at_source_in_artifact(
                    complete_materialization(&artifact),
                    *range,
                    &mut SemanticRequest::new(&mut serial_budget, &cancellation),
                )
                .expect("serial source dispatch");
            assert_eq!(outcome_label(session_outcome), outcome_label(&serial));
            let session_result = session_outcome
                .available_value()
                .expect("session dispatch result");
            let serial_result = serial.available_value().expect("serial dispatch result");
            assert_eq!(session_result.coverage(), serial_result.coverage());
            assert_eq!(session_result.observations().len(), 1);
            assert_eq!(serial_result.observations().len(), 1);
            assert_eq!(
                dispatch_shape(session_result.observations()[0].dispatch()),
                dispatch_shape(serial_result.observations()[0].dispatch())
            );
        }
    }

    #[test]
    fn prepared_source_dispatch_session_uses_one_source_budget_for_two_calls() {
        let fixture = typescript_fixture(&[("batch.ts", BATCH_CALL_SOURCE)]);
        let file = ProjectFile::new(fixture.project_root(), "batch.ts");
        let artifact = artifact_for(&fixture, &file);
        let calls = all_call_sites(&artifact);
        assert_eq!(calls.len(), 2, "the fixture has two external calls");
        let oracle = fixture.analyzer.semantic_oracle_provider();
        let cancellation = CancellationToken::default();
        let mut limits = SemanticBudget::default().limits();
        limits.source_bytes = BATCH_CALL_SOURCE.len();

        let mut session_budget = SemanticBudget::new(limits).expect("positive source budget");
        let mut session_request = SemanticRequest::new(&mut session_budget, &cancellation);
        let mut session =
            oracle.prepare_source_dispatch_session_in_artifact(complete_materialization(&artifact));
        for (_, range) in &calls {
            let outcome = session
                .resolve_at_source(*range, &mut session_request)
                .expect("prepared source dispatch");
            assert!(
                outcome.available_value().is_some(),
                "the shared parse keeps both calls inside one source budget: {outcome:?}"
            );
        }
        assert_eq!(
            session_request.budget.used().source_bytes,
            BATCH_CALL_SOURCE.len()
        );

        let mut serial_budget = SemanticBudget::new(limits).expect("positive source budget");
        let first = oracle
            .dispatch_at_source_in_artifact(
                complete_materialization(&artifact),
                calls[0].1,
                &mut SemanticRequest::new(&mut serial_budget, &cancellation),
            )
            .expect("first serial source dispatch");
        assert!(first.available_value().is_some(), "{first:?}");
        let second = oracle
            .dispatch_at_source_in_artifact(
                complete_materialization(&artifact),
                calls[1].1,
                &mut SemanticRequest::new(&mut serial_budget, &cancellation),
            )
            .expect("second serial source dispatch");
        assert!(
            matches!(second, SemanticOutcome::ExceededBudget { .. }),
            "a second independent parse exceeds the one-source budget: {second:?}"
        );
    }

    #[test]
    fn prepared_source_dispatch_drops_a_parse_whose_source_charge_rolled_back() {
        let fixture = typescript_fixture(&[("batch.ts", BATCH_CALL_SOURCE)]);
        let file = ProjectFile::new(fixture.project_root(), "batch.ts");
        let artifact = artifact_for(&fixture, &file);
        let calls = all_call_sites(&artifact);
        assert_eq!(calls.len(), 2, "the fixture has two external calls");
        let oracle = fixture.analyzer.semantic_oracle_provider();
        let cancellation = CancellationToken::default();
        let mut first_budget = SemanticBudget::default();
        let nested_limit = first_budget.limits().nested_entries;
        first_budget
            .charge(SemanticWork {
                nested_entries: nested_limit - 1,
                ..SemanticWork::default()
            })
            .expect("the first source projection retains one nested entry of headroom");
        let mut session =
            oracle.prepare_source_dispatch_session_in_artifact(complete_materialization(&artifact));

        let first = session
            .resolve_at_source(
                calls[0].1,
                &mut SemanticRequest::new(&mut first_budget, &cancellation),
            )
            .expect("post-parse budget refusal remains a typed source outcome");
        let SemanticOutcome::ExceededBudget { exceeded, work, .. } = first else {
            panic!("the low-level nested entry must exceed the remaining budget: {first:?}");
        };
        assert_eq!(exceeded.dimension(), SemanticBudgetDimension::NestedEntries);
        assert_eq!(work.source_bytes, BATCH_CALL_SOURCE.len());
        assert_eq!(first_budget.used().source_bytes, 0);
        assert_eq!(
            session.retained_bytes(),
            0,
            "rolled-back source work cannot leave reusable parsed syntax"
        );

        let first_scope = first_budget.scope_snapshot();
        let mut retry_budget =
            SemanticBudget::new_child(SemanticBudget::default().limits(), &first_scope);
        let second = session
            .resolve_at_source(
                calls[1].1,
                &mut SemanticRequest::new(&mut retry_budget, &cancellation),
            )
            .expect("a same-scope retry reparses after the unpaid syntax was dropped");
        assert!(second.available_value().is_some(), "{second:?}");
        assert_eq!(second.work().source_bytes, BATCH_CALL_SOURCE.len());
        assert_eq!(retry_budget.used().source_bytes, BATCH_CALL_SOURCE.len());
        assert!(session.retained_bytes() > 0);
    }

    #[test]
    fn prepared_source_dispatch_session_reports_materialization_work_once() {
        let fixture = typescript_fixture(&[("batch.ts", BATCH_CALL_SOURCE)]);
        let file = ProjectFile::new(fixture.project_root(), "batch.ts");
        let artifact = artifact_for(&fixture, &file);
        let calls = all_call_sites(&artifact);
        assert_eq!(calls.len(), 2, "the fixture has two external calls");
        let oracle = fixture.analyzer.semantic_oracle_provider();
        let cancellation = CancellationToken::default();
        let mut baseline_budget = SemanticBudget::default();
        let mut baseline_request = SemanticRequest::new(&mut baseline_budget, &cancellation);
        let mut baseline_session =
            oracle.prepare_source_dispatch_session_in_artifact(complete_materialization(&artifact));
        let baseline_first = baseline_session
            .resolve_at_source(calls[0].1, &mut baseline_request)
            .expect("baseline first source dispatch");
        let baseline_second = baseline_session
            .resolve_at_source(calls[1].1, &mut baseline_request)
            .expect("baseline second source dispatch");

        let materialization_work = SemanticWork {
            owned_text_bytes: 37,
            ..SemanticWork::default()
        };
        let mut budget = SemanticBudget::default();
        let mut request = SemanticRequest::new(&mut budget, &cancellation);
        let mut session = oracle.prepare_source_dispatch_session_in_artifact(
            complete_materialization_with_work(&artifact, materialization_work),
        );

        let first = session
            .resolve_at_source(calls[0].1, &mut request)
            .expect("first source dispatch");
        let second = session
            .resolve_at_source(calls[1].1, &mut request)
            .expect("second source dispatch");

        assert_eq!(
            first.work(),
            baseline_first.work().conservative_add(materialization_work)
        );
        assert_eq!(second.work(), baseline_second.work());
    }

    #[test]
    fn prepared_source_dispatch_session_rejects_an_unrelated_budget_scope() {
        let fixture = typescript_fixture(&[("batch.ts", BATCH_CALL_SOURCE)]);
        let file = ProjectFile::new(fixture.project_root(), "batch.ts");
        let artifact = artifact_for(&fixture, &file);
        let calls = all_call_sites(&artifact);
        assert_eq!(calls.len(), 2, "the fixture has two external calls");
        let oracle = fixture.analyzer.semantic_oracle_provider();
        let cancellation = CancellationToken::default();
        let mut session =
            oracle.prepare_source_dispatch_session_in_artifact(complete_materialization(&artifact));

        let mut first_budget = SemanticBudget::default();
        session
            .resolve_at_source(
                calls[0].1,
                &mut SemanticRequest::new(&mut first_budget, &cancellation),
            )
            .expect("first logical budget scope binds the prepared session");

        let first_scope = first_budget.scope_snapshot();
        let mut same_scope_child =
            SemanticBudget::new_child(SemanticBudget::default().limits(), &first_scope);
        let same_scope = session
            .resolve_at_source(
                calls[1].1,
                &mut SemanticRequest::new(&mut same_scope_child, &cancellation),
            )
            .expect("a child ledger in the same logical scope can reuse the session");
        assert!(same_scope.available_value().is_some(), "{same_scope:?}");
        assert_eq!(same_scope.work().source_bytes, 0);

        let mut unrelated_budget = SemanticBudget::default();
        let error = session
            .resolve_at_source(
                calls[0].1,
                &mut SemanticRequest::new(&mut unrelated_budget, &cancellation),
            )
            .expect_err("fresh budget scope cannot inherit a retained parse charge");
        assert!(
            error.to_string().contains("semantic budget scopes"),
            "{error}"
        );
        assert_eq!(unrelated_budget.used(), SemanticWork::default());
    }

    #[test]
    fn source_dispatch_session_preserves_reverse_order_for_distinct_targets() {
        let fixture = typescript_fixture(&[("ordered.ts", DISTINCT_CALL_SOURCE)]);
        let file = ProjectFile::new(fixture.project_root(), "ordered.ts");
        let artifact = artifact_for(&fixture, &file);
        let mut calls = all_call_sites(&artifact);
        calls.sort_by_key(|(_, range)| (range.start_byte, range.end_byte));
        assert_eq!(calls.len(), 2, "the fixture has two distinct local calls");
        let oracle = fixture.analyzer.semantic_oracle_provider();
        let cancellation = CancellationToken::default();
        let mut serial_outcomes = Vec::new();
        let mut serial_shapes = Vec::new();
        for (_, range) in &calls {
            let mut serial_budget = SemanticBudget::default();
            let serial = oracle
                .dispatch_at_source_in_artifact(
                    complete_materialization(&artifact),
                    *range,
                    &mut SemanticRequest::new(&mut serial_budget, &cancellation),
                )
                .expect("serial source dispatch baseline");
            let result = serial.available_value().expect("serial target is resolved");
            assert_eq!(result.observations().len(), 1);
            serial_shapes.push(dispatch_shape(result.observations()[0].dispatch()));
            serial_outcomes.push(outcome_label(&serial));
        }
        assert_ne!(
            serial_shapes[0], serial_shapes[1],
            "the regression requires distinguishable target answers"
        );

        let mut budget = SemanticBudget::default();
        let mut request = SemanticRequest::new(&mut budget, &cancellation);
        let mut session =
            oracle.prepare_source_dispatch_session_in_artifact(complete_materialization(&artifact));
        assert_eq!(session.retained_bytes(), 0);

        let second = session
            .resolve_at_source(calls[1].1, &mut request)
            .expect("second row can be the first row actually requested");
        let second_result = second.available_value().expect("second dispatch result");
        assert_eq!(second_result.observations()[0].call(), &calls[1].0);
        assert_eq!(outcome_label(&second), serial_outcomes[1]);
        assert_eq!(
            dispatch_shape(second_result.observations()[0].dispatch()),
            serial_shapes[1]
        );
        assert_eq!(second.work().source_bytes, DISTINCT_CALL_SOURCE.len());

        let first = session
            .resolve_at_source(calls[0].1, &mut request)
            .expect("an earlier skipped row does not desynchronize the session");
        let first_result = first.available_value().expect("first dispatch result");
        assert_eq!(first_result.observations()[0].call(), &calls[0].0);
        assert_eq!(outcome_label(&first), serial_outcomes[0]);
        assert_eq!(
            dispatch_shape(first_result.observations()[0].dispatch()),
            serial_shapes[0]
        );
        assert_eq!(first.work().source_bytes, 0);
    }

    #[test]
    fn source_dispatch_session_defers_parse_until_a_range_contains_a_call() {
        let fixture = typescript_fixture(&[("batch.ts", BATCH_CALL_SOURCE)]);
        let file = ProjectFile::new(fixture.project_root(), "batch.ts");
        let artifact = artifact_for(&fixture, &file);
        let calls = all_call_sites(&artifact);
        assert_eq!(calls.len(), 2, "the fixture has two external calls");
        let oracle = fixture.analyzer.semantic_oracle_provider();
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let mut request = SemanticRequest::new(&mut budget, &cancellation);
        let mut session =
            oracle.prepare_source_dispatch_session_in_artifact(complete_materialization(&artifact));

        let no_call = session
            .resolve_at_source(
                Range {
                    start_byte: 0,
                    end_byte: "import".len(),
                    start_line: 0,
                    end_line: 0,
                },
                &mut request,
            )
            .expect("a non-call range remains a typed source answer");
        assert!(matches!(&no_call, SemanticOutcome::Unknown { .. }));
        assert_eq!(no_call.work().source_bytes, 0);
        assert_eq!(session.retained_bytes(), 0);

        let first_call = session
            .resolve_at_source(calls[0].1, &mut request)
            .expect("the first real call initializes exact dispatch");
        assert_eq!(first_call.work().source_bytes, BATCH_CALL_SOURCE.len());
        assert_eq!(
            session.retained_bytes(),
            crate::analyzer::tree_sitter_analyzer::prepared_syntax_retained_bytes(
                BATCH_CALL_SOURCE.len()
            )
            .saturating_add(file.retained_bytes())
        );
    }

    #[test]
    fn source_dispatch_session_cancellation_does_not_reclassify_prior_calls() {
        let fixture = typescript_fixture(&[("batch.ts", BATCH_CALL_SOURCE)]);
        let file = ProjectFile::new(fixture.project_root(), "batch.ts");
        let artifact = artifact_for(&fixture, &file);
        let calls = all_call_sites(&artifact);
        assert_eq!(calls.len(), 2, "the fixture has two external calls");
        let oracle = fixture.analyzer.semantic_oracle_provider();
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let mut request = SemanticRequest::new(&mut budget, &cancellation);
        let mut session =
            oracle.prepare_source_dispatch_session_in_artifact(complete_materialization(&artifact));

        let first = session
            .resolve_at_source(calls[0].1, &mut request)
            .expect("first requested dispatch");
        assert!(!matches!(first, SemanticOutcome::Cancelled { .. }));
        assert_eq!(first.work().source_bytes, BATCH_CALL_SOURCE.len());

        cancellation.cancel();
        let second = session
            .resolve_at_source(calls[1].1, &mut request)
            .expect("second requested dispatch");
        let SemanticOutcome::Cancelled { work, .. } = second else {
            panic!("only the call requested after cancellation is cancelled: {second:?}");
        };
        assert_eq!(work.source_bytes, 0);
        assert_eq!(work.call_sites, 0);
        assert_eq!(work.nested_entries, 0);
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

    #[test]
    fn procedure_dispatch_v2_is_order_independent_and_rotates_coverage_and_refinement() {
        let candidate_a = StableDigest::sha256(b"candidate-a");
        let candidate_b = StableDigest::sha256(b"candidate-b");
        let boundary_a = StableDigest::sha256(b"boundary-a");
        let boundary_b = StableDigest::sha256(b"boundary-b");
        let baseline = procedure_dispatch_components_digest(
            CandidateCoverage::Open,
            false,
            &mut [candidate_a, candidate_b],
            &mut [boundary_a, boundary_b],
        );
        assert_eq!(
            baseline,
            procedure_dispatch_components_digest(
                CandidateCoverage::Open,
                false,
                &mut [candidate_b, candidate_a],
                &mut [boundary_b, boundary_a],
            ),
            "candidate and boundary iteration order is not answer semantics"
        );
        assert_ne!(
            baseline,
            procedure_dispatch_components_digest(
                CandidateCoverage::Truncated,
                false,
                &mut [candidate_a, candidate_b],
                &mut [boundary_a, boundary_b],
            ),
            "coverage is a binding-relevant axis"
        );
        assert_ne!(
            baseline,
            procedure_dispatch_components_digest(
                CandidateCoverage::Open,
                true,
                &mut [candidate_a, candidate_b],
                &mut [boundary_a, boundary_b],
            ),
            "the typed feedback-refinement exception is a planning-relevant axis"
        );
    }

    #[test]
    fn procedure_dispatch_v2_rotates_candidate_and_boundary_evidence_axes() {
        let fixture =
            typescript_fixture(&[("call.ts", CALL_SOURCE), ("external.ts", BATCH_CALL_SOURCE)]);
        let call_file = ProjectFile::new(fixture.project_root(), "call.ts");
        let call_artifact = artifact_for(&fixture, &call_file);
        let (call, _) = only_call_site(&call_artifact);
        let oracle = fixture.analyzer.semantic_oracle_provider();
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let outcome = oracle
            .resolve_call(&call, &mut SemanticRequest::new(&mut budget, &cancellation))
            .expect("workspace call dispatch");
        let dispatch = outcome
            .available_value()
            .expect("workspace call retains dispatch");
        let candidate = dispatch
            .candidates()
            .first()
            .expect("workspace call has one target");
        let candidate_digest = procedure_dispatch_candidate_digest(candidate);

        let mut changed_proof = candidate.clone();
        changed_proof.proof = ProofStatus::Unproven("changed proof".into());
        assert_ne!(
            candidate_digest,
            procedure_dispatch_candidate_digest(&changed_proof)
        );
        let mut changed_completeness = candidate.clone();
        changed_completeness.completeness =
            EvidenceCompleteness::Partial("changed completeness".into());
        assert_ne!(
            candidate_digest,
            procedure_dispatch_candidate_digest(&changed_completeness)
        );
        let excluded = call_artifact
            .procedures()
            .iter()
            .find(|procedure| procedure.id() != candidate.target().id())
            .and_then(|procedure| call_artifact.procedure_handle(procedure.id()))
            .expect("the caller is a distinct exclusion identity");
        let mut changed_exclusions = candidate.clone();
        changed_exclusions.excluded_targets = Box::new([excluded]);
        assert_ne!(
            candidate_digest,
            procedure_dispatch_candidate_digest(&changed_exclusions)
        );

        let external_file = ProjectFile::new(fixture.project_root(), "external.ts");
        let external_artifact = artifact_for(&fixture, &external_file);
        let (external_call, _) = all_call_sites(&external_artifact)
            .into_iter()
            .next()
            .expect("external fixture call");
        let mut external_budget = SemanticBudget::default();
        let external = oracle
            .resolve_call(
                &external_call,
                &mut SemanticRequest::new(&mut external_budget, &cancellation),
            )
            .expect("external call dispatch");
        let boundary = external
            .available_value()
            .and_then(|dispatch| dispatch.boundaries().first())
            .expect("external call retains a boundary");
        let boundary_digest = procedure_dispatch_boundary_digest(boundary);
        let mut changed_boundary = boundary.clone();
        changed_boundary.kind = DispatchBoundaryKind::Unresolved;
        assert_ne!(
            boundary_digest,
            procedure_dispatch_boundary_digest(&changed_boundary),
            "same empty target set and coverage with a different boundary must rotate"
        );
        let mut changed_boundary_proof = boundary.clone();
        changed_boundary_proof.proof = ProofStatus::Unproven("changed boundary proof".into());
        assert_ne!(
            boundary_digest,
            procedure_dispatch_boundary_digest(&changed_boundary_proof)
        );
        let mut changed_boundary_completeness = boundary.clone();
        changed_boundary_completeness.completeness =
            EvidenceCompleteness::Partial("changed boundary completeness".into());
        assert_ne!(
            boundary_digest,
            procedure_dispatch_boundary_digest(&changed_boundary_completeness)
        );
    }

    #[test]
    fn procedure_dispatch_v2_rotates_quality_and_cannot_equal_a_v1_answer() {
        let fixture = typescript_fixture(&[("call.ts", CALL_SOURCE)]);
        let file = ProjectFile::new(fixture.project_root(), "call.ts");
        let artifact = artifact_for(&fixture, &file);
        let (call, _) = only_call_site(&artifact);
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let outcome = fixture
            .analyzer
            .semantic_oracle_provider()
            .resolve_call(&call, &mut SemanticRequest::new(&mut budget, &cancellation))
            .expect("workspace dispatch");
        let result = SourceDispatchResult {
            observations: Box::new([SourceDispatchObservation {
                call,
                dispatch: outcome
                    .available_value()
                    .expect("workspace call retains dispatch")
                    .clone(),
            }]),
            coverage: CandidateCoverage::Exhaustive,
        };
        let complete =
            procedure_dispatch_answer_digest(SourceOutcomeQuality::Complete, Some(&result));
        assert_ne!(
            complete,
            procedure_dispatch_answer_digest(SourceOutcomeQuality::Ambiguous, Some(&result)),
            "outcome quality changes direct-call binding status"
        );

        let mut legacy = crate::analyzer::canonical_hash::CanonicalHasher::new(
            b"bifrost-read-ledger:procedure-dispatch-answer:v1",
        );
        legacy.field("coverage", result.coverage().label().as_bytes());
        let mut targets = result
            .target_candidates()
            .map(|candidate| {
                let target = candidate.target();
                target
                    .artifact()
                    .key()
                    .procedure_lineage_fingerprint(target.semantics().locator().declaration())
            })
            .collect::<Vec<_>>();
        targets.sort_unstable();
        targets.dedup();
        for target in targets {
            legacy.value(target.as_bytes());
        }
        assert_ne!(
            complete,
            StableDigest::from_array(legacy.finish()),
            "the v2 domain must invalidate every persisted v1 read answer"
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
