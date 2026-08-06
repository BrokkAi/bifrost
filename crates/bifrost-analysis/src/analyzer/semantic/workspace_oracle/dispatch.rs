//! Exact, location-first workspace dispatch and candidate materialization.
//!
//! Control-flow stitching consumes the workspace-oracle facade; it does not
//! reach into the usage-graph dispatch resolver directly.

use std::cmp::Ordering;
use std::sync::Arc;

use sha2::{Digest, Sha256};

use super::WorkspaceSemanticOracle;
use crate::analyzer::semantic::{
    CallSiteHandle, CancellationToken, CandidateCoverage, ContentIdentity, DeclarationLocator,
    DeclarationSegment, DeclarationSegmentKind, DispatchBoundary, DispatchBoundaryKind,
    DispatchCandidate, DispatchExtensibility, DispatchOracle, DispatchResult, EvidenceCompleteness,
    EvidenceHandle, ExactExternalProcedureTarget, OracleLimits, OracleRelationArena,
    OracleRelationId, OracleRelationOwner, OracleRelationRecord, OracleRelationSubject,
    ProcedureHandle, ProcedureKind, ProcedureSemantics, ProofStatus, SemanticArtifact,
    SemanticBudgetExceeded, SemanticCallSite, SemanticCapability, SemanticGap, SemanticGapImpact,
    SemanticGapKind, SemanticGapSubject, SemanticLocator, SemanticOutcome, SemanticProviderError,
    SemanticRequest, SemanticRole, SemanticWork, SourceAnchor, SourcePosition, SourceSpan,
    StableDigest, WorkspaceMountId, WorkspaceRelativePath,
};
use crate::analyzer::structural::resolution::BoundaryStatus;
use crate::analyzer::usages::get_definition::DefinitionLookupStatus;
use crate::analyzer::usages::{
    CallDispatchBoundaryKind, CallDispatchTarget, CallRelationLimits, CallRelationService,
    ExactCallLocation, UsageProof, call_dispatch_equivalence_source,
};
use crate::analyzer::{
    CodeUnit, CodeUnitType, IAnalyzer, LanguageDialect, ProjectFile, Range, WorkspaceAnalyzer,
};
use crate::hash::HashMap;

/// Source-scoped callable identity used only while resolving dispatch. The
/// location-first resolver may return both a C/C++ declaration and a related
/// body, but the oracle never manufactures equivalents from a workspace-global
/// FQN: external linkage does not identify one link unit.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(in crate::analyzer::semantic) struct CallableDefinitionIdentity {
    kind: CodeUnitType,
    fq_name: String,
    signature: Option<String>,
    source_scope: Option<ProjectFile>,
}

impl CallableDefinitionIdentity {
    fn of(analyzer: &dyn IAnalyzer, definition: &CodeUnit) -> Self {
        Self::with_source_scope(
            definition,
            call_dispatch_equivalence_source(analyzer, definition),
        )
    }

    pub(in crate::analyzer::semantic) fn with_source_scope(
        definition: &CodeUnit,
        source_scope: Option<ProjectFile>,
    ) -> Self {
        Self {
            kind: definition.kind(),
            fq_name: definition.fq_name(),
            signature: definition.signature().map(str::to_owned),
            source_scope,
        }
    }
}

#[derive(Debug)]
struct DispatchTargetGroup {
    representative: CodeUnit,
    proof: UsageProof,
}

fn dispatch_target_groups(
    analyzer: &dyn IAnalyzer,
    targets: Vec<CallDispatchTarget>,
) -> Vec<DispatchTargetGroup> {
    let mut groups = Vec::<DispatchTargetGroup>::new();
    let mut index = HashMap::<CallableDefinitionIdentity, usize>::default();
    for target in targets {
        let identity = CallableDefinitionIdentity::of(analyzer, &target.definition);
        if let Some(group) = index
            .get(&identity)
            .and_then(|group| groups.get_mut(*group))
        {
            if target.definition < group.representative {
                group.representative = target.definition;
            }
            if target.proof == UsageProof::Proven {
                group.proof = UsageProof::Proven;
            }
            continue;
        }
        index.insert(identity, groups.len());
        groups.push(DispatchTargetGroup {
            representative: target.definition,
            proof: target.proof,
        });
    }
    groups
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DispatchQuality {
    Complete,
    Ambiguous,
    Unproven,
    Unknown,
    Unsupported(SemanticCapability),
    Truncated,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MaterializationInterruption {
    Budget,
    Cancelled,
}

fn materialization_interruption(
    quality: DispatchQuality,
    budget_exceeded: bool,
    cancellation: &crate::cancellation::CancellationToken,
) -> Option<MaterializationInterruption> {
    if quality == DispatchQuality::Cancelled || cancellation.is_cancelled() {
        Some(MaterializationInterruption::Cancelled)
    } else if budget_exceeded {
        Some(MaterializationInterruption::Budget)
    } else {
        None
    }
}

impl DispatchOracle for WorkspaceSemanticOracle<'_> {
    fn resolve_call(
        &self,
        call: &CallSiteHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<DispatchResult>, SemanticProviderError> {
        if request.cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: SemanticWork::default(),
            });
        }

        let max_source_bytes = request.budget.remaining().source_bytes;
        let Some((file, exact_source)) =
            exact_source_for_procedure(self.workspace, call.procedure(), max_source_bytes)?
        else {
            let work = SemanticWork {
                source_bytes: max_source_bytes.saturating_add(1),
                ..SemanticWork::default()
            };
            let exceeded = request.budget.check(work).map_or_else(
                |exceeded| exceeded,
                |_| unreachable!("bounded source omission must exceed the remaining budget"),
            );
            return Ok(SemanticOutcome::ExceededBudget {
                partial: None,
                exceeded,
                work,
            });
        };
        let semantic_call = call
            .procedure()
            .semantics()
            .call_site(call.id())
            .ok_or_else(|| SemanticProviderError::internal("semantic call-site handle is stale"))?;
        let call_dispatch_gap =
            scoped_call_dispatch_gap(call.procedure().semantics(), semantic_call);
        let procedure_call_gap = scoped_procedure_dispatch_gap(call.procedure());
        let mapping = call
            .procedure()
            .semantics()
            .source_mapping(semantic_call.source)
            .ok_or_else(|| {
                SemanticProviderError::internal("semantic call site has no source mapping")
            })?;
        let span = mapping.locator.anchor().span();
        let location = ExactCallLocation {
            file,
            call_span: Range {
                start_byte: span.start_byte() as usize,
                end_byte: span.end_byte() as usize,
                start_line: span.start().line() as usize,
                end_line: span.end().line() as usize,
            },
        };

        let max_dispatch_targets = self.limits.dispatch_targets();
        // `dispatch_targets` bounds the final unique ProcedureHandle projection,
        // not raw resolver declarations. Raw exploration instead consumes the
        // request's generic nested-entry budget; any omission at this layer is
        // therefore a semantic-budget partial, not an oracle-target cap.
        let max_exploration_candidates = request.budget.remaining().nested_entries.max(1);
        let mut staged_budget = request.budget.clone();
        let lookup = CallRelationService::dispatch_at_bounded(
            self.workspace.analyzer(),
            &location,
            Arc::clone(&exact_source),
            CallRelationLimits {
                max_files: 1,
                max_source_bytes,
                max_candidates: max_exploration_candidates,
            },
            Some(request.cancellation),
        );
        debug_assert!(lookup.work.scanned_files <= 1);
        debug_assert!(
            lookup.status.is_none() || !lookup.targets.is_empty() || !lookup.boundaries.is_empty(),
            "every completed dispatch status must retain a target or typed boundary"
        );
        let dispatch_work = low_level_dispatch_work(
            lookup.work.scanned_files,
            lookup.work.scanned_source_bytes,
            lookup.work.examined_candidates,
        );
        if lookup.cancelled || request.cancellation.is_cancelled() {
            return cancelled_lookup_outcome(
                self.workspace,
                call,
                self.limits,
                CancelledLookupArtifacts {
                    resolved_targets: &lookup.targets,
                    low_level_boundaries: &lookup.boundaries,
                    call_dispatch_gap,
                    procedure_call_gap,
                    observed_work: dispatch_work,
                },
                request,
            );
        }
        if let Err(exceeded) = staged_budget.charge(dispatch_work) {
            return Ok(SemanticOutcome::ExceededBudget {
                partial: None,
                exceeded,
                work: dispatch_work,
            });
        }
        let mut reported_work = dispatch_work;
        if lookup.budget_exhausted {
            let attempted = SemanticWork {
                source_bytes: exact_source.len().max(1),
                call_sites: 1,
                ..SemanticWork::default()
            };
            if let Err(exceeded) = request.budget.check(attempted) {
                return Ok(SemanticOutcome::ExceededBudget {
                    partial: None,
                    exceeded,
                    work: attempted,
                });
            }
        }

        let mut candidates = Vec::new();
        let mut boundaries = lookup
            .boundaries
            .iter()
            .map(low_level_boundary)
            .collect::<Vec<_>>();
        let mut target_groups =
            dispatch_target_groups(self.workspace.analyzer(), lookup.targets).into_iter();
        let mut candidate_indexes = HashMap::<ProcedureHandle, usize>::default();
        let mut final_candidates_truncated = false;
        let mut cancelled_targets_truncated = false;
        let mut materialization_quality = DispatchQuality::Complete;
        let exploration_exceeded = lookup.truncated.then(|| {
            request
                .budget
                .check(SemanticWork {
                    nested_entries: request.budget.remaining().nested_entries.saturating_add(1),
                    ..SemanticWork::default()
                })
                .expect_err("exploration truncation must exceed the nested-entry budget")
        });
        let mut materialization_exceeded = None;
        let mut materialized_files: HashMap<ProjectFile, SemanticOutcome<Arc<SemanticArtifact>>> =
            HashMap::default();
        let mut staged_request = request.staged(&mut staged_budget);

        while let Some(group) = target_groups.next() {
            if request.cancellation.is_cancelled() {
                cancelled_targets_truncated |= append_cancelled_target_boundaries(
                    self.workspace.analyzer(),
                    &candidates,
                    &mut boundaries,
                    std::iter::once(group).chain(target_groups.by_ref()),
                    self.limits,
                    call_dispatch_gap,
                    procedure_call_gap,
                )?;
                materialization_quality = DispatchQuality::Cancelled;
                break;
            }
            if !staged_request.charge_execution_traversal(1) {
                append_execution_budget_target_boundaries(
                    self.workspace.analyzer(),
                    &candidates,
                    &mut boundaries,
                    std::iter::once(group).chain(target_groups.by_ref()),
                    self.limits,
                    call_dispatch_gap,
                    procedure_call_gap,
                )?;
                materialization_quality = DispatchQuality::Truncated;
                break;
            }
            // Exact dispatch already performed the structured, language-aware
            // declaration/body expansion. Do not repeat it by global FQN here:
            // that would cross C/C++ link units and bypass dispatch work bounds.
            let mut matched_any = false;
            let mut matched_quality = match group.proof {
                UsageProof::Proven => DispatchQuality::Complete,
                UsageProof::Unproven => DispatchQuality::Unproven,
            };
            let mut failure_quality = DispatchQuality::Complete;
            let definition = group.representative.clone();
            let outcome = if let Some(outcome) = materialized_files.get(definition.source()) {
                outcome.clone()
            } else {
                let outcome = self
                    .workspace
                    .materialize_program_semantics(definition.source(), &mut staged_request)?;
                reported_work = reported_work.conservative_add(outcome.work());
                materialized_files.insert(definition.source().clone(), outcome.clone());
                outcome
            };
            let exact_external_artifact =
                outcome.available_value().map(|value| value.key().clone());
            match outcome {
                SemanticOutcome::Complete { value, .. } => {
                    let (has_match, truncated) = retain_artifact_candidates(
                        self.workspace.analyzer(),
                        &definition,
                        &value,
                        &mut candidates,
                        &mut candidate_indexes,
                        proof_from_usage(group.proof),
                        completeness_from_usage(group.proof),
                        max_dispatch_targets,
                    );
                    matched_any |= has_match;
                    final_candidates_truncated |= truncated;
                }
                SemanticOutcome::Ambiguous {
                    candidates: value, ..
                }
                | SemanticOutcome::Unproven { partial: value, .. } => {
                    let (has_match, truncated) = retain_artifact_candidates(
                        self.workspace.analyzer(),
                        &definition,
                        &value,
                        &mut candidates,
                        &mut candidate_indexes,
                        ProofStatus::Unproven(
                            "target semantic materialization is not authoritative".into(),
                        ),
                        EvidenceCompleteness::Partial(
                            "target semantic materialization is incomplete".into(),
                        ),
                        max_dispatch_targets,
                    );
                    matched_any |= has_match;
                    final_candidates_truncated |= truncated;
                    if has_match {
                        matched_quality =
                            merge_dispatch_quality(matched_quality, DispatchQuality::Unproven);
                    } else {
                        failure_quality =
                            merge_dispatch_quality(failure_quality, DispatchQuality::Unproven);
                    }
                }
                SemanticOutcome::Unknown { partial, .. } => {
                    let has_match = partial.as_ref().is_some_and(|value| {
                        let (has_match, truncated) = retain_artifact_candidates(
                            self.workspace.analyzer(),
                            &definition,
                            value,
                            &mut candidates,
                            &mut candidate_indexes,
                            ProofStatus::Unproven(
                                "target semantic materialization is unknown".into(),
                            ),
                            EvidenceCompleteness::Partial(
                                "target semantic materialization retained only an unknown partial"
                                    .into(),
                            ),
                            max_dispatch_targets,
                        );
                        final_candidates_truncated |= truncated;
                        has_match
                    });
                    matched_any |= has_match;
                    let quality = DispatchQuality::Unknown;
                    if has_match {
                        matched_quality = merge_dispatch_quality(matched_quality, quality);
                    } else {
                        failure_quality = merge_dispatch_quality(failure_quality, quality);
                    }
                }
                SemanticOutcome::Unsupported {
                    capability,
                    partial,
                    ..
                } => {
                    let has_match = partial.as_ref().is_some_and(|value| {
                        let (has_match, truncated) = retain_artifact_candidates(
                            self.workspace.analyzer(),
                            &definition,
                            value,
                            &mut candidates,
                            &mut candidate_indexes,
                            ProofStatus::Unproven(
                                format!(
                                    "target semantic materialization does not completely support {}",
                                    capability.label()
                                )
                                .into(),
                            ),
                            EvidenceCompleteness::Partial(
                                "target semantic materialization retained an unsupported partial"
                                    .into(),
                            ),
                            max_dispatch_targets,
                        );
                        final_candidates_truncated |= truncated;
                        has_match
                    });
                    matched_any |= has_match;
                    let quality = DispatchQuality::Unsupported(capability);
                    if has_match {
                        matched_quality = merge_dispatch_quality(matched_quality, quality);
                    } else {
                        failure_quality = merge_dispatch_quality(failure_quality, quality);
                    }
                }
                SemanticOutcome::ExceededBudget {
                    partial, exceeded, ..
                } => {
                    if let Some(value) = partial {
                        let (has_match, truncated) = retain_artifact_candidates(
                            self.workspace.analyzer(),
                            &definition,
                            &value,
                            &mut candidates,
                            &mut candidate_indexes,
                            ProofStatus::Unproven(
                                "target semantic materialization exceeded its budget".into(),
                            ),
                            EvidenceCompleteness::Partial(
                                "target semantic materialization retained a budget-limited partial"
                                    .into(),
                            ),
                            max_dispatch_targets,
                        );
                        matched_any |= has_match;
                        final_candidates_truncated |= truncated;
                    }
                    boundaries.push(truncated_dispatch_boundary());
                    materialization_exceeded = Some(exceeded);
                    materialization_quality = DispatchQuality::Truncated;
                }
                SemanticOutcome::Cancelled { partial, .. } => {
                    if let Some(value) = partial {
                        let (has_match, truncated) = retain_artifact_candidates(
                            self.workspace.analyzer(),
                            &definition,
                            &value,
                            &mut candidates,
                            &mut candidate_indexes,
                            ProofStatus::Unproven(
                                "target semantic materialization was cancelled".into(),
                            ),
                            EvidenceCompleteness::Partial(
                                "target semantic materialization retained a cancelled partial"
                                    .into(),
                            ),
                            max_dispatch_targets,
                        );
                        matched_any |= has_match;
                        final_candidates_truncated |= truncated;
                    }
                    materialization_quality = DispatchQuality::Cancelled;
                }
            }

            let interruption = materialization_interruption(
                materialization_quality,
                materialization_exceeded.is_some(),
                request.cancellation,
            );
            if matched_any {
                materialization_quality =
                    merge_dispatch_quality(materialization_quality, matched_quality);
            } else if interruption.is_none() {
                let target =
                    locator_for_definition(self.workspace.analyzer(), &group.representative)?;
                boundaries.push(DispatchBoundary {
                    kind: DispatchBoundaryKind::Unmaterialized(target.clone()),
                    exact_external_target: exact_external_artifact.as_ref().and_then(|artifact| {
                        exact_external_procedure_target(
                            self.workspace.analyzer(),
                            &group.representative,
                            artifact,
                            target.clone(),
                            semantic_call.receiver.is_some(),
                        )
                    }),
                    proof: proof_from_usage(group.proof),
                    completeness: EvidenceCompleteness::Partial(
                        "equivalent callable declarations have no published workspace body".into(),
                    ),
                    provenance: Box::new([]),
                });
                let missing_quality = if failure_quality == DispatchQuality::Complete {
                    DispatchQuality::Unproven
                } else {
                    failure_quality
                };
                materialization_quality =
                    merge_dispatch_quality(materialization_quality, missing_quality);
            }

            if let Some(interruption) = interruption {
                if interruption == MaterializationInterruption::Cancelled {
                    let current = (!matched_any).then_some(group);
                    cancelled_targets_truncated |= append_cancelled_target_boundaries(
                        self.workspace.analyzer(),
                        &candidates,
                        &mut boundaries,
                        current.into_iter().chain(target_groups.by_ref()),
                        self.limits,
                        call_dispatch_gap,
                        procedure_call_gap,
                    )?;
                    materialization_quality = DispatchQuality::Cancelled;
                }
                break;
            }
        }

        if final_candidates_truncated {
            if !boundaries
                .iter()
                .any(|boundary| boundary.kind == DispatchBoundaryKind::Truncated)
            {
                boundaries.push(truncated_dispatch_boundary());
            }
            materialization_quality =
                merge_dispatch_quality(materialization_quality, DispatchQuality::Truncated);
        }

        let call_dispatch_gap =
            call_dispatch_gap.filter(|gap| !closed_dispatch_discharges_gap(&candidates, gap));
        let gap_exceeded = call_dispatch_gap
            .and_then(|gap| gap.budget)
            .or_else(|| procedure_call_gap.and_then(|gap| gap.budget));
        if let Some(gap) = call_dispatch_gap {
            materialization_quality = merge_dispatch_quality(
                materialization_quality,
                apply_dynamic_dispatch_gap(gap, &mut boundaries),
            );
        }
        if let Some(gap) = procedure_call_gap {
            materialization_quality = merge_dispatch_quality(
                materialization_quality,
                apply_procedure_call_gap(gap, &mut boundaries),
            );
        }

        candidates.sort_by(|left, right| {
            left.target
                .semantics()
                .locator()
                .cmp(right.target.semantics().locator())
        });
        boundaries.sort_by(compare_dispatch_boundaries);
        boundaries.dedup();
        if boundaries
            .iter()
            .any(|boundary| boundary.kind == DispatchBoundaryKind::Unresolved)
        {
            // A typed unresolved arm is itself unproven, even when the
            // low-level location lookup reported `Resolved`. That status can
            // describe a lexical callable value (for example a function-typed
            // parameter) without publishing any callable body.
            materialization_quality =
                merge_dispatch_quality(materialization_quality, DispatchQuality::Unproven);
        }
        if lookup.truncated {
            if !boundaries
                .iter()
                .any(|boundary| boundary.kind == DispatchBoundaryKind::Truncated)
            {
                boundaries.push(truncated_dispatch_boundary());
            }
            materialization_quality =
                merge_dispatch_quality(materialization_quality, DispatchQuality::Truncated);
        }
        let provenance_truncated = bound_dispatch_projection(
            &mut candidates,
            &mut boundaries,
            self.limits,
            call_dispatch_gap,
            procedure_call_gap,
        );
        if provenance_truncated {
            materialization_quality =
                merge_dispatch_quality(materialization_quality, DispatchQuality::Truncated);
        }
        attach_dispatch_provenance(
            call,
            &mut candidates,
            &mut boundaries,
            call_dispatch_gap,
            procedure_call_gap,
            self.limits,
        )?;
        let cancelled = materialization_quality == DispatchQuality::Cancelled
            || request.cancellation.is_cancelled();
        let dispatch_truncated = cancelled_targets_truncated
            || provenance_truncated
            || boundaries
                .iter()
                .any(|boundary| boundary.kind == DispatchBoundaryKind::Truncated);
        let coverage = if dispatch_truncated {
            CandidateCoverage::Truncated
        } else if cancelled {
            CandidateCoverage::Open
        } else {
            dispatch_coverage(lookup.status, &boundaries)
        };
        let result = DispatchResult::new(call, candidates, boundaries, coverage, self.limits)
            .map_err(|error| {
                SemanticProviderError::internal(format!(
                    "workspace dispatch produced invalid relation provenance: {error}"
                ))
            })?;
        let retained_work = dispatch_result_work(&result);
        let total_work = sum_semantic_work(reported_work, retained_work);
        if let Err(exceeded) = staged_budget.charge(retained_work) {
            if cancelled {
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work: total_work,
                });
            }
            return Ok(SemanticOutcome::ExceededBudget {
                partial: None,
                exceeded,
                work: total_work,
            });
        }
        reported_work = total_work;
        *request.budget = staged_budget;

        let interruption = materialization_exceeded
            .or(exploration_exceeded)
            .or(gap_exceeded);
        let result =
            match finish_dispatch_interruption(result, cancelled, interruption, reported_work) {
                Ok(result) => result,
                Err(outcome) => return Ok(*outcome),
            };
        let status_quality = match lookup.status {
            Some(DefinitionLookupStatus::Resolved) => DispatchQuality::Complete,
            Some(DefinitionLookupStatus::Ambiguous) => DispatchQuality::Ambiguous,
            Some(DefinitionLookupStatus::UnsupportedLanguage) => {
                DispatchQuality::Unsupported(SemanticCapability::Calls)
            }
            Some(
                DefinitionLookupStatus::NoDefinition
                | DefinitionLookupStatus::InvalidLocation
                | DefinitionLookupStatus::NotFound,
            )
            | None => DispatchQuality::Unknown,
            // A boundary outcome is complete only when the refined evidence
            // (#1474) actually names the external target. A declared-but-
            // unindexed dependency leaves the answer partial, and an unknown
            // external root means the resolver never saw the target at all.
            Some(DefinitionLookupStatus::UnresolvableImportBoundary) => match lookup.boundary {
                Some(BoundaryStatus::WorkspaceLocal | BoundaryStatus::ExternalIndexed) => {
                    DispatchQuality::Complete
                }
                Some(BoundaryStatus::ExternalDeclaredUnindexed) => DispatchQuality::Unproven,
                Some(BoundaryStatus::ExternalUnknown) | None => DispatchQuality::Unknown,
            },
        };
        let quality = if status_quality == DispatchQuality::Ambiguous
            && matches!(
                materialization_quality,
                DispatchQuality::Complete | DispatchQuality::Ambiguous | DispatchQuality::Unproven
            ) {
            // Ambiguous lookup remains the precise dispatch classification
            // when its retained candidates are merely unproven or partial.
            // Candidate evidence must not collapse the set-level ambiguity
            // into generic Unproven.
            DispatchQuality::Ambiguous
        } else {
            merge_dispatch_quality(status_quality, materialization_quality)
        };
        dispatch_outcome(result, quality, reported_work)
    }
}

fn closed_dispatch_discharges_gap(candidates: &[DispatchCandidate], gap: &SemanticGap) -> bool {
    gap.capability == SemanticCapability::DynamicDispatch
        && !candidates.is_empty()
        && candidates.iter().all(|candidate| {
            candidate
                .target()
                .semantics()
                .properties()
                .dispatch_extensibility
                == DispatchExtensibility::Closed
        })
}

fn finish_dispatch_interruption(
    result: DispatchResult,
    cancelled: bool,
    exceeded: Option<SemanticBudgetExceeded>,
    work: SemanticWork,
) -> Result<DispatchResult, Box<SemanticOutcome<DispatchResult>>> {
    if cancelled {
        return Err(Box::new(SemanticOutcome::Cancelled {
            partial: Some(result),
            work,
        }));
    }
    if let Some(exceeded) = exceeded {
        return Err(Box::new(SemanticOutcome::ExceededBudget {
            partial: Some(result),
            exceeded,
            work,
        }));
    }
    Ok(result)
}

fn merge_dispatch_quality(current: DispatchQuality, incoming: DispatchQuality) -> DispatchQuality {
    use DispatchQuality::*;
    match (current, incoming) {
        (Cancelled, _) | (_, Cancelled) => Cancelled,
        (Truncated, _) | (_, Truncated) => Truncated,
        (Unsupported(capability), _) => Unsupported(capability),
        (_, Unsupported(capability)) => Unsupported(capability),
        (Unknown, _) | (_, Unknown) => Unknown,
        (Unproven, _) | (_, Unproven) => Unproven,
        (Ambiguous, _) | (_, Ambiguous) => Ambiguous,
        (Complete, Complete) => Complete,
    }
}

fn low_level_dispatch_work(
    scanned_files: usize,
    scanned_source_bytes: usize,
    examined_candidates: usize,
) -> SemanticWork {
    let inspected_call = scanned_files > 0 || examined_candidates > 0;
    SemanticWork {
        source_bytes: scanned_source_bytes,
        call_sites: usize::from(inspected_call),
        // Resolver rows are transient. Final retained candidates and
        // boundaries are charged exactly once after materialization.
        nested_entries: examined_candidates,
        ..SemanticWork::default()
    }
}

/// Keep the final projected answer within the finite provenance arena. The
/// result-level `Truncated` coverage records any omitted arms, so no synthetic
/// uncharged boundary is needed merely to report the cap.
fn bound_dispatch_projection(
    candidates: &mut Vec<DispatchCandidate>,
    boundaries: &mut Vec<DispatchBoundary>,
    limits: OracleLimits,
    call_dispatch_gap: Option<&SemanticGap>,
    procedure_call_gap: Option<&SemanticGap>,
) -> bool {
    let original_candidates = candidates.len();
    let original_boundaries = boundaries.len();
    let retained_candidates = candidates
        .len()
        .min(limits.dispatch_targets())
        .min(limits.provenance_records())
        .min(limits.evidence_handles());
    candidates.truncate(retained_candidates);

    let mut remaining_records = limits
        .provenance_records()
        .saturating_sub(retained_candidates);
    let mut remaining_evidence = limits
        .evidence_handles()
        .saturating_sub(retained_candidates);
    let mut retained_boundaries = 0;
    for boundary in boundaries.iter() {
        let evidence =
            dispatch_boundary_evidence_count(boundary, call_dispatch_gap, procedure_call_gap);
        if remaining_records == 0 || evidence > remaining_evidence {
            break;
        }
        remaining_records -= 1;
        remaining_evidence -= evidence;
        retained_boundaries += 1;
    }
    boundaries.truncate(retained_boundaries);

    candidates.len() != original_candidates || boundaries.len() != original_boundaries
}

fn dispatch_boundary_evidence_count(
    boundary: &DispatchBoundary,
    call_dispatch_gap: Option<&SemanticGap>,
    procedure_call_gap: Option<&SemanticGap>,
) -> usize {
    let expected_exceeded = match &boundary.kind {
        DispatchBoundaryKind::Unresolved => Some(false),
        DispatchBoundaryKind::Truncated => Some(true),
        DispatchBoundaryKind::External(_)
        | DispatchBoundaryKind::Unmaterialized(_)
        | DispatchBoundaryKind::Deferred { .. } => None,
    };
    let mut evidence = Vec::with_capacity(2);
    for gap in [call_dispatch_gap, procedure_call_gap]
        .into_iter()
        .flatten()
    {
        if expected_exceeded
            .is_some_and(|exceeded| (gap.kind == SemanticGapKind::ExceededBudget) == exceeded)
            && !evidence.contains(&gap.evidence)
        {
            evidence.push(gap.evidence);
        }
    }
    evidence.len().max(1)
}

fn attach_dispatch_provenance(
    call: &CallSiteHandle,
    candidates: &mut [DispatchCandidate],
    boundaries: &mut [DispatchBoundary],
    call_dispatch_gap: Option<&SemanticGap>,
    procedure_call_gap: Option<&SemanticGap>,
    limits: OracleLimits,
) -> Result<(), SemanticProviderError> {
    let call_row = call
        .procedure()
        .semantics()
        .call_site(call.id())
        .ok_or_else(|| SemanticProviderError::internal("semantic call-site handle is stale"))?;
    let call_evidence = call
        .procedure()
        .evidence_handle(call_row.evidence)
        .ok_or_else(|| SemanticProviderError::internal("semantic call site has no evidence row"))?;
    let target_evidence = call
        .procedure()
        .evidence_handle(call_row.target_evidence)
        .ok_or_else(|| {
            SemanticProviderError::internal("semantic call site has no target evidence row")
        })?;
    let mut gap_evidence = Vec::new();
    for gap in [call_dispatch_gap, procedure_call_gap]
        .into_iter()
        .flatten()
    {
        let evidence = call
            .procedure()
            .evidence_handle(gap.evidence)
            .ok_or_else(|| {
                SemanticProviderError::internal("semantic dispatch gap has no evidence row")
            })?;
        if !gap_evidence
            .iter()
            .any(|(kind, retained): &(SemanticGapKind, EvidenceHandle)| {
                *kind == gap.kind && retained == &evidence
            })
        {
            gap_evidence.push((gap.kind, evidence));
        }
    }
    let mut records = Vec::with_capacity(candidates.len().saturating_add(boundaries.len()));
    records.extend(
        candidates
            .iter()
            .map(|candidate| {
                OracleRelationRecord::dispatch_candidate(
                    candidate.target().clone(),
                    [target_evidence.clone()],
                    limits,
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                SemanticProviderError::internal(format!(
                    "could not create bounded dispatch provenance: {error}"
                ))
            })?,
    );
    records.extend(
        boundaries
            .iter()
            .map(|boundary| {
                let evidence = if boundary.target_locator().is_some() {
                    vec![target_evidence.clone()]
                } else {
                    let expected_gap_kind = match &boundary.kind {
                        DispatchBoundaryKind::Unresolved => Some(false),
                        DispatchBoundaryKind::Truncated => Some(true),
                        DispatchBoundaryKind::External(None) => None,
                        DispatchBoundaryKind::External(Some(_))
                        | DispatchBoundaryKind::Unmaterialized(_)
                        | DispatchBoundaryKind::Deferred { .. } => {
                            unreachable!("named dispatch boundaries handled above")
                        }
                    };
                    let mut evidence = Vec::new();
                    for (_, retained) in gap_evidence.iter().filter(|(kind, _)| {
                        expected_gap_kind.is_some_and(|exceeded| {
                            (*kind == SemanticGapKind::ExceededBudget) == exceeded
                        })
                    }) {
                        if !evidence.contains(retained) {
                            evidence.push(retained.clone());
                        }
                    }
                    if evidence.is_empty() {
                        evidence.push(call_evidence.clone());
                    }
                    evidence
                };
                OracleRelationRecord::dispatch_boundary(boundary.kind.clone(), evidence, limits)
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                SemanticProviderError::internal(format!(
                    "could not create bounded dispatch provenance: {error}"
                ))
            })?,
    );
    let arena =
        OracleRelationArena::new(OracleRelationOwner::Dispatch(call.clone()), records, limits)
            .map_err(|error| {
                SemanticProviderError::internal(format!(
                    "could not create bounded dispatch provenance: {error}"
                ))
            })?;
    for (index, candidate) in candidates.iter_mut().enumerate() {
        let id = u32::try_from(index)
            .map(OracleRelationId::new)
            .map_err(|_| {
                SemanticProviderError::internal(
                    "dispatch provenance exceeds dense relation ID space",
                )
            })?;
        let relation = arena
            .handle(id)
            .expect("dispatch candidate record was inserted into the relation arena");
        candidate.provenance = vec![relation].into_boxed_slice();
    }
    let offset = candidates.len();
    for (index, boundary) in boundaries.iter_mut().enumerate() {
        let id = u32::try_from(offset.saturating_add(index))
            .map(OracleRelationId::new)
            .map_err(|_| {
                SemanticProviderError::internal(
                    "dispatch provenance exceeds dense relation ID space",
                )
            })?;
        let relation = arena
            .handle(id)
            .expect("dispatch boundary record was inserted into the relation arena");
        boundary.provenance = vec![relation].into_boxed_slice();
    }
    Ok(())
}

struct CancelledLookupArtifacts<'a> {
    resolved_targets: &'a [CallDispatchTarget],
    low_level_boundaries: &'a [CallDispatchBoundaryKind],
    call_dispatch_gap: Option<&'a SemanticGap>,
    procedure_call_gap: Option<&'a SemanticGap>,
    observed_work: SemanticWork,
}

fn cancelled_lookup_outcome(
    workspace: &WorkspaceAnalyzer,
    call: &CallSiteHandle,
    limits: OracleLimits,
    artifacts: CancelledLookupArtifacts<'_>,
    request: &mut SemanticRequest<'_>,
) -> Result<SemanticOutcome<DispatchResult>, SemanticProviderError> {
    let CancelledLookupArtifacts {
        resolved_targets,
        low_level_boundaries,
        call_dispatch_gap,
        procedure_call_gap,
        observed_work,
    } = artifacts;
    if observed_work == SemanticWork::default()
        && resolved_targets.is_empty()
        && low_level_boundaries.is_empty()
    {
        return Ok(SemanticOutcome::Cancelled {
            partial: None,
            work: SemanticWork::default(),
        });
    }

    let mut boundaries = low_level_boundaries
        .iter()
        .map(low_level_boundary)
        .collect::<Vec<_>>();
    let resolved_target_groups =
        dispatch_target_groups(workspace.analyzer(), resolved_targets.to_vec());
    let resolved_target_limit = limits
        .dispatch_targets()
        .min(limits.provenance_records())
        .min(limits.evidence_handles());
    let resolved_targets_truncated = resolved_target_groups.len() > resolved_target_limit;
    boundaries.extend(
        resolved_target_groups
            .iter()
            .take(resolved_target_limit)
            .map(|target| cancelled_target_boundary(workspace.analyzer(), target))
            .collect::<Result<Vec<_>, _>>()?,
    );
    boundaries.sort_by(compare_dispatch_boundaries);
    boundaries.dedup();
    let mut candidates = Vec::new();
    let truncated = bound_dispatch_projection(
        &mut candidates,
        &mut boundaries,
        limits,
        call_dispatch_gap,
        procedure_call_gap,
    );
    attach_dispatch_provenance(
        call,
        &mut candidates,
        &mut boundaries,
        call_dispatch_gap,
        procedure_call_gap,
        limits,
    )?;
    let retained_truncation = resolved_targets_truncated
        || truncated
        || boundaries
            .iter()
            .any(|boundary| boundary.kind == DispatchBoundaryKind::Truncated);
    let result = DispatchResult::new(
        call,
        candidates,
        boundaries,
        // Cancellation alone leaves coverage open. An independent finite cap
        // still records known omission as truncated while the outer outcome
        // preserves the operation-level cancellation state.
        if retained_truncation {
            CandidateCoverage::Truncated
        } else {
            CandidateCoverage::Open
        },
        limits,
    )
    .map_err(|error| {
        SemanticProviderError::internal(format!(
            "cancelled dispatch produced invalid relation provenance: {error}"
        ))
    })?;
    let retained_work = dispatch_result_work(&result);
    let total_work = sum_semantic_work(observed_work, retained_work);
    let mut staged_budget = request.budget.clone();
    if staged_budget.charge(total_work).is_err() {
        return Ok(SemanticOutcome::Cancelled {
            partial: None,
            work: total_work,
        });
    }
    *request.budget = staged_budget;
    Ok(SemanticOutcome::Cancelled {
        partial: Some(result),
        work: total_work,
    })
}

fn cancelled_target_boundary(
    analyzer: &dyn IAnalyzer,
    target: &DispatchTargetGroup,
) -> Result<DispatchBoundary, SemanticProviderError> {
    unmaterialized_target_boundary(
        analyzer,
        target,
        "resolved target was not materialized because dispatch was cancelled",
    )
}

fn unmaterialized_target_boundary(
    analyzer: &dyn IAnalyzer,
    target: &DispatchTargetGroup,
    reason: &'static str,
) -> Result<DispatchBoundary, SemanticProviderError> {
    Ok(DispatchBoundary {
        kind: DispatchBoundaryKind::Unmaterialized(locator_for_definition(
            analyzer,
            &target.representative,
        )?),
        exact_external_target: None,
        proof: proof_from_usage(target.proof),
        completeness: EvidenceCompleteness::Partial(reason.into()),
        provenance: Box::new([]),
    })
}

fn append_cancelled_target_boundaries(
    analyzer: &dyn IAnalyzer,
    candidates: &[DispatchCandidate],
    boundaries: &mut Vec<DispatchBoundary>,
    groups: impl IntoIterator<Item = DispatchTargetGroup>,
    limits: OracleLimits,
    call_dispatch_gap: Option<&SemanticGap>,
    procedure_call_gap: Option<&SemanticGap>,
) -> Result<bool, SemanticProviderError> {
    append_unmaterialized_target_boundaries(
        analyzer,
        candidates,
        boundaries,
        groups,
        limits,
        call_dispatch_gap,
        procedure_call_gap,
        "resolved target was not materialized because dispatch was cancelled",
    )
}

#[allow(clippy::too_many_arguments)]
fn append_execution_budget_target_boundaries(
    analyzer: &dyn IAnalyzer,
    candidates: &[DispatchCandidate],
    boundaries: &mut Vec<DispatchBoundary>,
    groups: impl IntoIterator<Item = DispatchTargetGroup>,
    limits: OracleLimits,
    call_dispatch_gap: Option<&SemanticGap>,
    procedure_call_gap: Option<&SemanticGap>,
) -> Result<bool, SemanticProviderError> {
    append_unmaterialized_target_boundaries(
        analyzer,
        candidates,
        boundaries,
        groups,
        limits,
        call_dispatch_gap,
        procedure_call_gap,
        "resolved target was not materialized because the request execution budget was exhausted",
    )
}

#[allow(clippy::too_many_arguments)]
fn append_unmaterialized_target_boundaries(
    analyzer: &dyn IAnalyzer,
    candidates: &[DispatchCandidate],
    boundaries: &mut Vec<DispatchBoundary>,
    groups: impl IntoIterator<Item = DispatchTargetGroup>,
    limits: OracleLimits,
    call_dispatch_gap: Option<&SemanticGap>,
    procedure_call_gap: Option<&SemanticGap>,
    reason: &'static str,
) -> Result<bool, SemanticProviderError> {
    let retained_target_arms = candidates.len().saturating_add(
        boundaries
            .iter()
            .filter(|boundary| boundary.target_locator().is_some())
            .count(),
    );
    let retained_records = candidates.len().saturating_add(boundaries.len());
    let retained_evidence = candidates.len().saturating_add(
        boundaries
            .iter()
            .map(|boundary| {
                dispatch_boundary_evidence_count(boundary, call_dispatch_gap, procedure_call_gap)
            })
            .fold(0usize, usize::saturating_add),
    );
    let mut remaining_targets = limits
        .dispatch_targets()
        .saturating_sub(retained_target_arms);
    let mut remaining_records = limits.provenance_records().saturating_sub(retained_records);
    let mut remaining_evidence = limits.evidence_handles().saturating_sub(retained_evidence);
    let mut groups = groups.into_iter();

    loop {
        if remaining_targets == 0 || remaining_records == 0 || remaining_evidence == 0 {
            // Consume at most one omitted group to distinguish an exactly-full
            // projection from a truncated one without allocating the tail.
            return Ok(groups.next().is_some());
        }
        let Some(group) = groups.next() else {
            return Ok(false);
        };
        let boundary = unmaterialized_target_boundary(analyzer, &group, reason)?;
        let evidence =
            dispatch_boundary_evidence_count(&boundary, call_dispatch_gap, procedure_call_gap);
        if evidence > remaining_evidence {
            return Ok(true);
        }
        boundaries.push(boundary);
        remaining_targets -= 1;
        remaining_records -= 1;
        remaining_evidence -= evidence;
    }
}

fn dispatch_result_work(result: &DispatchResult) -> SemanticWork {
    let relation_subject_work = result
        .candidates()
        .iter()
        .flat_map(|candidate| candidate.provenance.iter())
        .chain(
            result
                .boundaries()
                .iter()
                .flat_map(|boundary| boundary.provenance.iter()),
        )
        .filter_map(|relation| match relation.record().subject() {
            Some(OracleRelationSubject::DispatchBoundary(kind)) => {
                Some(dispatch_boundary_kind_locator_work(kind))
            }
            Some(OracleRelationSubject::DispatchCandidate(_)) | None => None,
        })
        .fold(SemanticWork::default(), sum_semantic_work);
    let owned_text_bytes = result
        .candidates()
        .iter()
        .map(|candidate| {
            proof_reason_bytes(&candidate.proof)
                .saturating_add(completeness_reason_bytes(&candidate.completeness))
        })
        .chain(result.boundaries().iter().map(|boundary| {
            proof_reason_bytes(&boundary.proof)
                .saturating_add(completeness_reason_bytes(&boundary.completeness))
                .saturating_add(dispatch_boundary_locator_work(boundary).owned_text_bytes)
        }))
        .fold(0usize, usize::saturating_add)
        .saturating_add(relation_subject_work.owned_text_bytes);
    let provenance_entries = result
        .candidates()
        .iter()
        .flat_map(|candidate| candidate.provenance.iter())
        .chain(
            result
                .boundaries()
                .iter()
                .flat_map(|boundary| boundary.provenance.iter()),
        )
        .map(|relation| {
            // One payload handle, one arena record, and the record's retained
            // evidence-handle array are all distinct nested entries.
            2usize.saturating_add(relation.record().evidence().len())
        })
        .fold(0usize, usize::saturating_add);
    SemanticWork {
        nested_entries: result
            .candidates()
            .len()
            .saturating_add(result.boundaries().len())
            .saturating_add(
                result
                    .boundaries()
                    .iter()
                    .map(dispatch_boundary_locator_work)
                    .map(|work| work.nested_entries)
                    .fold(0usize, usize::saturating_add),
            )
            .saturating_add(provenance_entries)
            .saturating_add(relation_subject_work.nested_entries),
        owned_text_bytes,
        ..SemanticWork::default()
    }
}

pub(in crate::analyzer::semantic) fn semantic_locator_work(
    locator: &SemanticLocator,
) -> SemanticWork {
    SemanticWork {
        nested_entries: locator.declaration().segments().len(),
        owned_text_bytes: locator
            .declaration()
            .segments()
            .iter()
            .filter_map(DeclarationSegment::name)
            .map(str::len)
            .fold(locator.path().as_str().len(), usize::saturating_add),
        ..SemanticWork::default()
    }
}

fn dispatch_boundary_locator_work(boundary: &DispatchBoundary) -> SemanticWork {
    let mut work = dispatch_boundary_kind_locator_work(&boundary.kind);
    if let Some(target) = boundary.exact_external_target() {
        let procedure = semantic_locator_work(target.procedure());
        work.nested_entries = work
            .nested_entries
            .saturating_add(1)
            .saturating_add(procedure.nested_entries);
        work.owned_text_bytes = work
            .owned_text_bytes
            .saturating_add(target.symbol().len())
            .saturating_add(target.artifact().path().as_str().len())
            .saturating_add(target.artifact().adapter().name().len())
            .saturating_add(procedure.owned_text_bytes);
    }
    work
}

fn dispatch_boundary_kind_locator_work(kind: &DispatchBoundaryKind) -> SemanticWork {
    match kind {
        DispatchBoundaryKind::External(Some(locator))
        | DispatchBoundaryKind::Unmaterialized(locator)
        | DispatchBoundaryKind::Deferred {
            target: locator, ..
        } => semantic_locator_work(locator),
        DispatchBoundaryKind::External(None)
        | DispatchBoundaryKind::Unresolved
        | DispatchBoundaryKind::Truncated => SemanticWork::default(),
    }
}

fn proof_reason_bytes(proof: &ProofStatus) -> usize {
    match proof {
        ProofStatus::Proven => 0,
        ProofStatus::Unproven(reason) => reason.len(),
    }
}

fn completeness_reason_bytes(completeness: &EvidenceCompleteness) -> usize {
    match completeness {
        EvidenceCompleteness::Complete => 0,
        EvidenceCompleteness::Partial(reason) => reason.len(),
    }
}

fn sum_semantic_work(left: SemanticWork, right: SemanticWork) -> SemanticWork {
    left.conservative_add(right)
}

pub(crate) fn exact_source_for_procedure(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    max_source_bytes: usize,
) -> Result<Option<(ProjectFile, Arc<str>)>, SemanticProviderError> {
    let key = procedure.artifact().key();
    let project = workspace.analyzer().project();
    let root = project.root();
    if key.mount() != WorkspaceMountId::from_root(root) {
        return Err(SemanticProviderError::invalid_identity(
            "call-site artifact belongs to a different workspace mount",
        ));
    }
    let file = ProjectFile::new(root.to_path_buf(), key.path().as_path());
    let Some(provider) = workspace.program_semantics_provider_for_file(&file) else {
        return Err(SemanticProviderError::invalid_identity(
            "call-site artifact has no semantic provider in the current analyzer generation",
        ));
    };
    let Some(snapshot) = provider.current_artifact_source(&file, max_source_bytes)? else {
        return Ok(None);
    };
    if snapshot.key() != key {
        return Err(SemanticProviderError::invalid_identity(
            "call-site artifact no longer matches the current semantic analyzer generation",
        ));
    }
    let (_, source) = snapshot.into_parts();
    Ok(Some((file, source)))
}

fn low_level_boundary(boundary: &CallDispatchBoundaryKind) -> DispatchBoundary {
    match boundary {
        CallDispatchBoundaryKind::External => DispatchBoundary {
            kind: DispatchBoundaryKind::External(None),
            exact_external_target: None,
            proof: ProofStatus::Proven,
            completeness: EvidenceCompleteness::Partial(
                "external declaration body is outside the indexed workspace".into(),
            ),
            provenance: Box::new([]),
        },
        CallDispatchBoundaryKind::Unresolved(status) => DispatchBoundary {
            kind: DispatchBoundaryKind::Unresolved,
            exact_external_target: None,
            proof: ProofStatus::Unproven(
                format!("exact dispatch status is {}", status.as_str()).into(),
            ),
            completeness: EvidenceCompleteness::Partial(
                "no materialized workspace target is available".into(),
            ),
            provenance: Box::new([]),
        },
        CallDispatchBoundaryKind::UnprovenTargetIdentity => DispatchBoundary {
            kind: DispatchBoundaryKind::Unresolved,
            exact_external_target: None,
            proof: ProofStatus::Unproven(
                "C/C++ include evidence does not prove one link-unit target identity".into(),
            ),
            completeness: EvidenceCompleteness::Partial(
                "additional or alternative linked bodies may exist".into(),
            ),
            provenance: Box::new([]),
        },
        CallDispatchBoundaryKind::Truncated => truncated_dispatch_boundary(),
    }
}

fn truncated_dispatch_boundary() -> DispatchBoundary {
    DispatchBoundary {
        kind: DispatchBoundaryKind::Truncated,
        exact_external_target: None,
        proof: ProofStatus::Unproven("dispatch candidate set was truncated".into()),
        completeness: EvidenceCompleteness::Partial(
            "not every dispatch candidate was retained".into(),
        ),
        provenance: Box::new([]),
    }
}

fn dispatch_coverage(
    status: Option<DefinitionLookupStatus>,
    boundaries: &[DispatchBoundary],
) -> CandidateCoverage {
    if boundaries
        .iter()
        .any(|boundary| boundary.kind == DispatchBoundaryKind::Truncated)
    {
        CandidateCoverage::Truncated
    } else if boundaries
        .iter()
        .any(|boundary| boundary.kind == DispatchBoundaryKind::Unresolved)
    {
        CandidateCoverage::Open
    } else {
        match status {
            Some(
                DefinitionLookupStatus::Resolved
                | DefinitionLookupStatus::Ambiguous
                | DefinitionLookupStatus::UnresolvableImportBoundary,
            ) => CandidateCoverage::Exhaustive,
            Some(
                DefinitionLookupStatus::NoDefinition
                | DefinitionLookupStatus::UnsupportedLanguage
                | DefinitionLookupStatus::InvalidLocation
                | DefinitionLookupStatus::NotFound,
            )
            | None => CandidateCoverage::Open,
        }
    }
}

fn proof_from_usage(proof: UsageProof) -> ProofStatus {
    match proof {
        UsageProof::Proven => ProofStatus::Proven,
        UsageProof::Unproven => ProofStatus::Unproven("dispatch target is ambiguous".into()),
    }
}

fn completeness_from_usage(proof: UsageProof) -> EvidenceCompleteness {
    match proof {
        UsageProof::Proven => EvidenceCompleteness::Complete,
        UsageProof::Unproven => EvidenceCompleteness::Partial(
            "dispatch cannot prove one complete target identity".into(),
        ),
    }
}

fn scoped_call_dispatch_gap<'a>(
    procedure: &'a ProcedureSemantics,
    call: &SemanticCallSite,
) -> Option<&'a SemanticGap> {
    procedure
        .gaps()
        .iter()
        .filter(|gap| {
            gap.point == call.point
                && gap.impacts.contains(SemanticGapImpact::DispatchCoverage)
                && match gap.subject {
                    SemanticGapSubject::Point => true,
                    SemanticGapSubject::CallSite(call_site) => call_site == call.id,
                    _ => false,
                }
        })
        .max_by_key(|gap| dynamic_dispatch_gap_rank(gap.kind))
}

pub(in crate::analyzer::semantic) fn scoped_procedure_dispatch_gap(
    procedure: &ProcedureHandle,
) -> Option<&SemanticGap> {
    procedure
        .semantics()
        .gaps()
        .iter()
        .filter(|gap| {
            gap.subject == SemanticGapSubject::Procedure
                && gap.impacts.contains(SemanticGapImpact::DispatchCoverage)
        })
        .max_by_key(|gap| dynamic_dispatch_gap_rank(gap.kind))
}

fn dynamic_dispatch_gap_rank(kind: SemanticGapKind) -> u8 {
    match kind {
        SemanticGapKind::Unproven => 0,
        SemanticGapKind::Ambiguous => 1,
        SemanticGapKind::Unknown => 2,
        SemanticGapKind::Unsupported => 3,
        SemanticGapKind::ExceededBudget => 4,
    }
}

fn dispatch_gap_quality(gap: &SemanticGap) -> DispatchQuality {
    match gap.kind {
        SemanticGapKind::Ambiguous => DispatchQuality::Ambiguous,
        SemanticGapKind::Unsupported => DispatchQuality::Unsupported(gap.capability),
        SemanticGapKind::ExceededBudget => DispatchQuality::Truncated,
        SemanticGapKind::Unknown | SemanticGapKind::Unproven => DispatchQuality::Unproven,
    }
}

fn apply_dynamic_dispatch_gap(
    gap: &SemanticGap,
    boundaries: &mut Vec<DispatchBoundary>,
) -> DispatchQuality {
    let proof_reason = format!(
        "{} dynamic-dispatch evidence does not prove the complete target set: {}",
        gap.kind.label(),
        gap.detail
    );
    let completeness_reason = format!(
        "dynamic-dispatch target coverage is incomplete: {}",
        gap.detail
    );
    let boundary_kind = if gap.kind == SemanticGapKind::ExceededBudget {
        DispatchBoundaryKind::Truncated
    } else {
        DispatchBoundaryKind::Unresolved
    };
    if !boundaries
        .iter()
        .any(|boundary| boundary.kind == boundary_kind)
    {
        boundaries.push(DispatchBoundary {
            kind: boundary_kind,
            exact_external_target: None,
            proof: ProofStatus::Unproven(proof_reason.into()),
            completeness: EvidenceCompleteness::Partial(completeness_reason.into()),
            provenance: Box::new([]),
        });
    }
    dispatch_gap_quality(gap)
}

fn apply_procedure_call_gap(
    gap: &SemanticGap,
    boundaries: &mut Vec<DispatchBoundary>,
) -> DispatchQuality {
    let proof_reason = format!(
        "procedure-wide {} evidence does not prove this complete call target set: {}",
        gap.capability.label(),
        gap.detail
    );
    let completeness_reason = format!(
        "procedure-wide {} coverage is incomplete: {}",
        gap.capability.label(),
        gap.detail
    );
    let boundary_kind = if gap.kind == SemanticGapKind::ExceededBudget {
        DispatchBoundaryKind::Truncated
    } else {
        DispatchBoundaryKind::Unresolved
    };
    if !boundaries
        .iter()
        .any(|boundary| boundary.kind == boundary_kind)
    {
        boundaries.push(DispatchBoundary {
            kind: boundary_kind,
            exact_external_target: None,
            proof: ProofStatus::Unproven(proof_reason.into()),
            completeness: EvidenceCompleteness::Partial(completeness_reason.into()),
            provenance: Box::new([]),
        });
    }
    if gap.kind == SemanticGapKind::ExceededBudget {
        DispatchQuality::Truncated
    } else {
        DispatchQuality::Unproven
    }
}

#[allow(clippy::too_many_arguments)]
fn retain_artifact_candidates(
    analyzer: &dyn IAnalyzer,
    definition: &CodeUnit,
    artifact: &Arc<SemanticArtifact>,
    candidates: &mut Vec<DispatchCandidate>,
    indexes: &mut HashMap<ProcedureHandle, usize>,
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
    max_candidates: usize,
) -> (bool, bool) {
    let targets = procedures_for_definition(analyzer, definition, artifact);
    let matched = !targets.is_empty();
    let mut truncated = false;
    for target in targets {
        truncated |= retain_dispatch_candidate(
            candidates,
            indexes,
            DispatchCandidate::new(
                target,
                proof.clone(),
                completeness.clone(),
                std::iter::empty(),
                OracleLimits::default(),
            )
            .expect("an empty dispatch draft fits every positive provenance limit"),
            max_candidates,
        );
    }
    (matched, truncated)
}

pub(in crate::analyzer::semantic) fn retain_dispatch_candidate(
    candidates: &mut Vec<DispatchCandidate>,
    indexes: &mut HashMap<ProcedureHandle, usize>,
    candidate: DispatchCandidate,
    max_candidates: usize,
) -> bool {
    if let Some(existing) = indexes
        .get(&candidate.target)
        .and_then(|index| candidates.get_mut(*index))
    {
        if matches!(candidate.proof, ProofStatus::Proven) {
            existing.proof = ProofStatus::Proven;
        }
        if matches!(candidate.completeness, EvidenceCompleteness::Complete) {
            existing.completeness = EvidenceCompleteness::Complete;
        }
        return false;
    }
    if candidates.len() >= max_candidates {
        return true;
    }
    indexes.insert(candidate.target.clone(), candidates.len());
    candidates.push(candidate);
    false
}

fn dispatch_outcome(
    result: DispatchResult,
    quality: DispatchQuality,
    work: SemanticWork,
) -> Result<SemanticOutcome<DispatchResult>, SemanticProviderError> {
    Ok(match quality {
        DispatchQuality::Complete => SemanticOutcome::Complete {
            value: result,
            work,
        },
        DispatchQuality::Ambiguous => SemanticOutcome::Ambiguous {
            candidates: result,
            work,
        },
        DispatchQuality::Unproven | DispatchQuality::Truncated => SemanticOutcome::Unproven {
            partial: result,
            work,
        },
        DispatchQuality::Unknown => SemanticOutcome::Unknown {
            partial: Some(result),
            work,
        },
        DispatchQuality::Unsupported(capability) => SemanticOutcome::Unsupported {
            capability,
            partial: Some(result),
            work,
        },
        DispatchQuality::Cancelled => SemanticOutcome::Cancelled {
            partial: Some(result),
            work,
        },
    })
}

pub(crate) fn procedures_for_definition(
    analyzer: &dyn IAnalyzer,
    definition: &CodeUnit,
    artifact: &Arc<SemanticArtifact>,
) -> Vec<ProcedureHandle> {
    let cancellation = CancellationToken::default();
    let lookup = procedures_for_definition_with_limits(
        analyzer,
        definition,
        artifact,
        usize::MAX,
        &cancellation,
    );
    if lookup.status == ProcedureRangeLookupStatus::Complete {
        lookup.handles
    } else {
        Vec::new()
    }
}

pub(crate) fn procedures_for_definition_with_limits(
    analyzer: &dyn IAnalyzer,
    definition: &CodeUnit,
    artifact: &Arc<SemanticArtifact>,
    max_examined: usize,
    cancellation: &CancellationToken,
) -> ProcedureRangeLookup {
    let mut progress = ProcedureLookupProgress::new(max_examined, cancellation);
    if let Err(status) = progress.examine() {
        return progress.failed(status);
    }
    let Some(indexed_source) = analyzer.indexed_source(definition.source()) else {
        return ProcedureRangeLookup {
            handles: Vec::new(),
            examined: progress.examined,
            status: ProcedureRangeLookupStatus::SourceChanged,
        };
    };
    let indexed_identity = match content_identity_with_progress(&indexed_source, &mut progress) {
        Ok(identity) => identity,
        Err(status) => return progress.failed(status),
    };
    if indexed_identity != artifact.key().revision().content() {
        return ProcedureRangeLookup {
            handles: Vec::new(),
            examined: progress.examined,
            status: ProcedureRangeLookupStatus::SourceChanged,
        };
    }
    if let Err(status) = progress.examine() {
        return progress.failed(status);
    }
    let (ranges, inspected_ranges, range_lookup_incomplete) =
        analyzer.ranges_with_limit(definition, progress.remaining(), cancellation);
    for _ in 0..inspected_ranges {
        if let Err(status) = progress.examine() {
            return progress.failed(status);
        }
    }
    if range_lookup_incomplete {
        let status = if cancellation.is_cancelled() {
            ProcedureRangeLookupStatus::Cancelled
        } else {
            ProcedureRangeLookupStatus::BudgetExhausted
        };
        return progress.failed(status);
    }
    let mut exact = Vec::new();
    let mut boundary_aligned = Vec::new();
    let mut enclosing = Vec::new();
    for procedure in artifact.procedures() {
        if let Err(status) = progress.examine() {
            return progress.failed(status);
        }
        if !procedure_matches_definition(procedure, definition) {
            continue;
        }
        let span = procedure.locator().anchor().span();
        let mut exact_match = false;
        let mut boundary_aligned_match = false;
        let mut enclosing_match = false;
        for range in &ranges {
            if let Err(status) = progress.examine() {
                return progress.failed(status);
            }
            if range.start_byte == span.start_byte() as usize
                && range.end_byte == span.end_byte() as usize
            {
                exact_match = true;
                break;
            }
            boundary_aligned_match |= range.start_byte == span.start_byte() as usize
                || range.end_byte == span.end_byte() as usize;
            enclosing_match |= (range.start_byte <= span.start_byte() as usize
                && range.end_byte >= span.end_byte() as usize)
                || (span.start_byte() as usize <= range.start_byte
                    && span.end_byte() as usize >= range.end_byte);
        }
        let target = if exact_match {
            &mut exact
        } else if boundary_aligned_match {
            &mut boundary_aligned
        } else if enclosing_match {
            &mut enclosing
        } else {
            continue;
        };
        target.push(procedure);
    }
    let matches = if !exact.is_empty() {
        exact
    } else if !boundary_aligned.is_empty() {
        boundary_aligned
    } else {
        enclosing
    };
    let matches = match sort_procedures_by_locator(matches, &mut progress) {
        Ok(matches) => matches,
        Err(status) => return progress.failed(status),
    };
    let mut handles = Vec::with_capacity(matches.len());
    for procedure in matches {
        if let Err(status) = progress.examine() {
            return progress.failed(status);
        }
        if let Some(handle) = artifact.procedure_handle(procedure.id()) {
            handles.push(handle);
        }
    }
    ProcedureRangeLookup {
        handles,
        examined: progress.examined,
        status: ProcedureRangeLookupStatus::Complete,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcedureRangeLookupStatus {
    Complete,
    BudgetExhausted,
    Cancelled,
    SourceChanged,
}

pub struct ProcedureRangeLookup {
    pub handles: Vec<ProcedureHandle>,
    pub examined: usize,
    pub status: ProcedureRangeLookupStatus,
}

struct ProcedureLookupProgress<'a> {
    max_examined: usize,
    cancellation: &'a CancellationToken,
    examined: usize,
}

impl<'a> ProcedureLookupProgress<'a> {
    const fn new(max_examined: usize, cancellation: &'a CancellationToken) -> Self {
        Self {
            max_examined,
            cancellation,
            examined: 0,
        }
    }

    fn examine(&mut self) -> Result<(), ProcedureRangeLookupStatus> {
        if self.cancellation.is_cancelled() {
            return Err(ProcedureRangeLookupStatus::Cancelled);
        }
        if self.examined >= self.max_examined {
            return Err(ProcedureRangeLookupStatus::BudgetExhausted);
        }
        self.examined = self.examined.saturating_add(1);
        Ok(())
    }

    const fn remaining(&self) -> usize {
        self.max_examined.saturating_sub(self.examined)
    }

    fn failed(&self, status: ProcedureRangeLookupStatus) -> ProcedureRangeLookup {
        ProcedureRangeLookup {
            handles: Vec::new(),
            examined: self.examined,
            status,
        }
    }
}

fn content_identity_with_progress(
    source: &str,
    progress: &mut ProcedureLookupProgress<'_>,
) -> Result<ContentIdentity, ProcedureRangeLookupStatus> {
    const HASH_CHUNK_BYTES: usize = 64 * 1024;

    let mut digest = Sha256::new();
    if source.is_empty() {
        progress.examine()?;
    } else {
        for chunk in source.as_bytes().chunks(HASH_CHUNK_BYTES) {
            progress.examine()?;
            digest.update(chunk);
        }
    }
    let bytes: [u8; 32] = digest.finalize().into();
    Ok(ContentIdentity::from_digest(StableDigest::from_array(
        bytes,
    )))
}

fn sort_procedures_by_locator<'a>(
    mut source: Vec<&'a ProcedureSemantics>,
    progress: &mut ProcedureLookupProgress<'_>,
) -> Result<Vec<&'a ProcedureSemantics>, ProcedureRangeLookupStatus> {
    let len = source.len();
    let mut width = 1usize;
    let mut target = Vec::with_capacity(len);
    while width < len {
        target.clear();
        let run_width = width.saturating_mul(2);
        for start in (0..len).step_by(run_width) {
            let middle = start.saturating_add(width).min(len);
            let end = start.saturating_add(run_width).min(len);
            let mut left = start;
            let mut right = middle;
            while left < middle && right < end {
                progress.examine()?;
                if source[left].locator() <= source[right].locator() {
                    target.push(source[left]);
                    left += 1;
                } else {
                    target.push(source[right]);
                    right += 1;
                }
            }
            while left < middle {
                progress.examine()?;
                target.push(source[left]);
                left += 1;
            }
            while right < end {
                progress.examine()?;
                target.push(source[right]);
                right += 1;
            }
        }
        std::mem::swap(&mut source, &mut target);
        width = run_width;
    }
    Ok(source)
}

pub fn procedures_for_source_ranges(
    artifact: &Arc<SemanticArtifact>,
    ranges: &[Range],
    max_examined: usize,
    cancellation: &CancellationToken,
) -> ProcedureRangeLookup {
    let mut progress = ProcedureLookupProgress::new(max_examined, cancellation);
    let mut exact = Vec::new();
    let mut enclosing = Vec::new();
    for procedure in artifact.procedures() {
        if let Err(status) = progress.examine() {
            return progress.failed(status);
        }
        let span = procedure.locator().anchor().span();
        let mut exact_match = false;
        let mut enclosing_match = false;
        for range in ranges {
            if let Err(status) = progress.examine() {
                return progress.failed(status);
            }
            if range.start_byte == span.start_byte() as usize
                && range.end_byte == span.end_byte() as usize
            {
                exact_match = true;
                break;
            }
            enclosing_match |= span.start_byte() as usize <= range.start_byte
                && span.end_byte() as usize >= range.end_byte;
        }
        if exact_match {
            exact.push(procedure);
        } else if enclosing_match {
            enclosing.push(procedure);
        }
    }
    let matches = if exact.is_empty() { enclosing } else { exact };
    let matches = match sort_procedures_by_locator(matches, &mut progress) {
        Ok(matches) => matches,
        Err(status) => return progress.failed(status),
    };
    let mut handles = Vec::with_capacity(matches.len());
    for procedure in matches {
        if let Err(status) = progress.examine() {
            return progress.failed(status);
        }
        if let Some(handle) = artifact.procedure_handle(procedure.id()) {
            handles.push(handle);
        }
    }
    ProcedureRangeLookup {
        handles,
        examined: progress.examined,
        status: ProcedureRangeLookupStatus::Complete,
    }
}

fn procedure_matches_definition(procedure: &ProcedureSemantics, definition: &CodeUnit) -> bool {
    if definition.is_class() {
        return procedure.kind() == ProcedureKind::Constructor;
    }
    if !definition.is_callable() {
        return false;
    }
    let Some(name) = procedure
        .locator()
        .declaration()
        .segments()
        .last()
        .and_then(DeclarationSegment::name)
    else {
        return definition.is_anonymous();
    };
    name == definition.identifier()
        || (procedure.kind() == ProcedureKind::Constructor && name == definition.short_name())
}

fn exact_external_procedure_target(
    analyzer: &dyn IAnalyzer,
    definition: &CodeUnit,
    artifact: &crate::analyzer::semantic::SemanticArtifactKey,
    procedure: SemanticLocator,
    has_receiver: bool,
) -> Option<ExactExternalProcedureTarget> {
    let mut metadata = analyzer.signature_metadata(definition).into_iter();
    let parameter_count = u32::try_from(metadata.next()?.parameters().len()).ok()?;
    if metadata
        .any(|candidate| u32::try_from(candidate.parameters().len()).ok() != Some(parameter_count))
    {
        return None;
    }
    let symbol = format!("{}{}", definition.identifier(), definition.signature()?);
    ExactExternalProcedureTarget::new(
        artifact.clone(),
        procedure,
        symbol,
        has_receiver,
        parameter_count,
    )
}

fn locator_for_definition(
    analyzer: &dyn IAnalyzer,
    definition: &CodeUnit,
) -> Result<SemanticLocator, SemanticProviderError> {
    let source = analyzer
        .indexed_source(definition.source())
        .ok_or_else(|| {
            SemanticProviderError::source_access(format!(
                "indexed source is unavailable for resolved declaration `{}`",
                definition.fq_name()
            ))
        })?;
    let mut ranges = analyzer.ranges_of(definition);
    ranges.sort_by_key(|range| (range.start_byte, range.end_byte));
    let range = ranges.into_iter().next().unwrap_or(Range {
        start_byte: 0,
        end_byte: source.len(),
        start_line: 0,
        end_line: source.lines().count().saturating_sub(1),
    });
    let anchor = source_anchor_for_range(&source, &range)?;
    let file_name = definition
        .source()
        .rel_path()
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("source");
    let file_segment =
        DeclarationSegment::named(DeclarationSegmentKind::File, file_name, anchor, 0)
            .map_err(|error| SemanticProviderError::invalid_identity(error.to_string()))?;
    let kind = match definition.kind() {
        CodeUnitType::Class => DeclarationSegmentKind::Type,
        CodeUnitType::Function => DeclarationSegmentKind::Function,
        CodeUnitType::Field
        | CodeUnitType::Module
        | CodeUnitType::Macro
        | CodeUnitType::FileScope => DeclarationSegmentKind::AnonymousCallable,
    };
    let declaration_segment =
        DeclarationSegment::named(kind, definition.identifier(), anchor, 0)
            .map_err(|error| SemanticProviderError::invalid_identity(error.to_string()))?;
    let declaration = DeclarationLocator::new(vec![file_segment, declaration_segment])
        .map_err(|error| SemanticProviderError::invalid_identity(error.to_string()))?;
    let path = WorkspaceRelativePath::try_from_path(definition.source().rel_path())
        .map_err(|error| SemanticProviderError::invalid_identity(error.to_string()))?;
    Ok(SemanticLocator::new(
        WorkspaceMountId::from_root(definition.source().root()),
        path,
        LanguageDialect::for_path(
            crate::analyzer::common::language_for_file(definition.source()),
            definition.source().rel_path(),
        ),
        declaration,
        SemanticRole::Procedure,
        anchor,
    ))
}

fn source_anchor_for_range(
    source: &str,
    range: &Range,
) -> Result<SourceAnchor, SemanticProviderError> {
    let start = source_position(source, range.start_byte)?;
    let end = source_position(source, range.end_byte)?;
    let span = SourceSpan::new(start, end)
        .map_err(|error| SemanticProviderError::invalid_identity(error.to_string()))?;
    Ok(SourceAnchor::new(span, 0))
}

fn source_position(source: &str, offset: usize) -> Result<SourcePosition, SemanticProviderError> {
    if offset > source.len() || !source.is_char_boundary(offset) {
        return Err(SemanticProviderError::invalid_identity(
            "resolved declaration range is outside its UTF-8 source",
        ));
    }
    let bytes = source.as_bytes();
    let line_start = bytes[..offset]
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |newline| newline.saturating_add(1));
    let line = bytes[..offset]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count();
    Ok(SourcePosition::new(
        u32::try_from(offset)
            .map_err(|_| SemanticProviderError::invalid_identity("source offset exceeds u32"))?,
        u32::try_from(line)
            .map_err(|_| SemanticProviderError::invalid_identity("source line exceeds u32"))?,
        u32::try_from(offset.saturating_sub(line_start))
            .map_err(|_| SemanticProviderError::invalid_identity("source column exceeds u32"))?,
    ))
}

fn compare_dispatch_boundaries(left: &DispatchBoundary, right: &DispatchBoundary) -> Ordering {
    dispatch_boundary_rank(&left.kind)
        .cmp(&dispatch_boundary_rank(&right.kind))
        .then_with(|| match (&left.kind, &right.kind) {
            (DispatchBoundaryKind::External(left), DispatchBoundaryKind::External(right)) => {
                compare_optional_locators(left.as_ref(), right.as_ref())
            }
            (
                DispatchBoundaryKind::Unmaterialized(left),
                DispatchBoundaryKind::Unmaterialized(right),
            ) => compare_locator_fields(left, right),
            (
                DispatchBoundaryKind::Deferred {
                    target: left_target,
                    kind: left_kind,
                },
                DispatchBoundaryKind::Deferred {
                    target: right_target,
                    kind: right_kind,
                },
            ) => left_kind
                .label()
                .cmp(right_kind.label())
                .then_with(|| compare_locator_fields(left_target, right_target)),
            (DispatchBoundaryKind::Unresolved, DispatchBoundaryKind::Unresolved)
            | (DispatchBoundaryKind::Truncated, DispatchBoundaryKind::Truncated) => Ordering::Equal,
            _ => unreachable!("matching boundary ranks must identify the same variant"),
        })
}

const fn dispatch_boundary_rank(kind: &DispatchBoundaryKind) -> u8 {
    match kind {
        DispatchBoundaryKind::External(_) => 0,
        DispatchBoundaryKind::Unmaterialized(_) => 1,
        DispatchBoundaryKind::Deferred { .. } => 2,
        DispatchBoundaryKind::Unresolved => 3,
        DispatchBoundaryKind::Truncated => 4,
    }
}

fn compare_optional_locators(
    left: Option<&SemanticLocator>,
    right: Option<&SemanticLocator>,
) -> Ordering {
    match (left, right) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(left), Some(right)) => compare_locator_fields(left, right),
    }
}

fn compare_locator_fields(left: &SemanticLocator, right: &SemanticLocator) -> Ordering {
    let left_anchor = left.anchor();
    let right_anchor = right.anchor();
    let left_span = left_anchor.span();
    let right_span = right_anchor.span();
    left.path()
        .cmp(right.path())
        .then_with(|| left_span.start_byte().cmp(&right_span.start_byte()))
        .then_with(|| left_span.end_byte().cmp(&right_span.end_byte()))
        .then_with(|| left_anchor.occurrence().cmp(&right_anchor.occurrence()))
        // Source anchors ordinarily distinguish dispatch targets. Retain the
        // locator's complete stable identity as a deterministic tie-breaker.
        .then_with(|| left.cmp(right))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic::{
        OracleLimitValues, OracleRelationKind, SemanticBudget, SemanticGapId, SemanticGapImpact,
        SemanticGapImpacts,
    };
    use crate::analyzer::{Language, ProjectFile};
    use crate::cancellation::CancellationToken;
    use crate::test_support::AnalyzerFixture;

    fn semantic_call_fixture() -> (AnalyzerFixture, crate::analyzer::semantic::CallSiteHandle) {
        semantic_call_fixture_for(
            "call.ts",
            "function target() {}\nexport function caller() { target(); }\n",
        )
    }

    fn semantic_call_fixture_for(
        name: &str,
        source: &str,
    ) -> (AnalyzerFixture, crate::analyzer::semantic::CallSiteHandle) {
        let fixture = AnalyzerFixture::new_for_language(Language::TypeScript, &[(name, source)]);
        let file = ProjectFile::new(fixture.project_root(), name);
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("TypeScript semantic materialization")
            .available_value()
            .cloned()
            .expect("TypeScript semantic artifact");
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| !procedure.call_sites().is_empty())
            .expect("caller procedure");
        let call = artifact
            .procedure_handle(procedure.id())
            .and_then(|procedure| {
                procedure.call_site_handle(procedure.semantics().call_sites()[0].id)
            })
            .expect("scoped call handle");
        (fixture, call)
    }

    fn semantic_call_handle() -> crate::analyzer::semantic::CallSiteHandle {
        semantic_call_fixture().1
    }

    const EXTERNAL_CALL_SOURCE: &str = "import { work } from \"third-party\";\nexport function caller(): number { work(); return 1; }\n";

    /// A complete discovery outcome declaring exactly `modules`, mirroring the
    /// shape the npm resolver produces.
    fn discovery_declaring(
        modules: &[&str],
    ) -> crate::analyzer::semantic_model::DependencyDiscoveryOutcome {
        use crate::analyzer::semantic_model::{
            CatalogCoordinate, DependencyArtifactRole, DependencyDiscoveryOutcome,
            ExternalArtifactKind, ResolvedDependency, ResolvedDependencyArtifact,
            SemanticModelActivationEvidence,
        };
        DependencyDiscoveryOutcome::complete(
            modules
                .iter()
                .map(|module| ResolvedDependency {
                    id: format!("test:distribution:{module}"),
                    evidence: SemanticModelActivationEvidence {
                        language: "typescript".to_owned(),
                        ecosystem: "test".to_owned(),
                        package: None,
                        module: Some(CatalogCoordinate {
                            name: (*module).to_owned(),
                            version: None,
                        }),
                        toolchain: None,
                        target: None,
                        configuration: None,
                        artifact_sha256: None,
                    },
                    provenance: Vec::new(),
                    artifacts: vec![ResolvedDependencyArtifact::module_file(
                        DependencyArtifactRole::Declarations,
                        ExternalArtifactKind::TypeScriptDeclarationFile,
                        (*module).to_owned(),
                        std::path::PathBuf::from("unused-in-this-test.d.ts"),
                    )],
                })
                .collect(),
        )
    }

    fn resolve_external_call(
        fixture: &AnalyzerFixture,
        call: &crate::analyzer::semantic::CallSiteHandle,
    ) -> SemanticOutcome<DispatchResult> {
        let oracle = fixture.analyzer.semantic_oracle_provider();
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        oracle
            .resolve_call(call, &mut SemanticRequest::new(&mut budget, &cancellation))
            .expect("external dispatch should run")
    }

    /// #1599: a boundary outcome is only as complete as its refined external
    /// evidence. An import nothing declares is `external_unknown`, so dispatch
    /// must answer `Unknown` instead of claiming a closed target set.
    #[test]
    fn undeclared_external_call_dispatch_is_unknown() {
        let (fixture, call) = semantic_call_fixture_for("external.ts", EXTERNAL_CALL_SOURCE);
        let outcome = resolve_external_call(&fixture, &call);
        let SemanticOutcome::Unknown {
            partial: Some(result),
            ..
        } = outcome
        else {
            panic!("undeclared external dispatch must be Unknown: {outcome:?}");
        };
        assert!(
            result
                .boundaries()
                .iter()
                .any(|boundary| matches!(boundary.kind, DispatchBoundaryKind::External(_))),
            "{result:?}"
        );
    }

    /// #1599: the same call whose module the build declares (but nothing
    /// indexed) is `external_declared_unindexed`: the target may well be in
    /// the declared dependency, so the answer is partial, not closed.
    #[test]
    fn declared_unindexed_external_call_dispatch_is_unproven() {
        let (fixture, call) = semantic_call_fixture_for("external.ts", EXTERNAL_CALL_SOURCE);
        fixture.analyzer.retain_dependency_discovery_evidence(
            &[Language::JavaScript, Language::TypeScript],
            &discovery_declaring(&["third-party"]),
        );
        let outcome = resolve_external_call(&fixture, &call);
        assert!(
            matches!(outcome, SemanticOutcome::Unproven { .. }),
            "declared-unindexed external dispatch must be Unproven: {outcome:?}"
        );
    }

    #[test]
    fn declaration_procedure_lookup_charges_and_observes_cancellation_per_comparison() {
        let (fixture, call) = semantic_call_fixture();
        let definition = fixture
            .analyzer
            .analyzer()
            .get_definitions("target")
            .into_iter()
            .next()
            .expect("target definition");
        let artifact = call.procedure().artifact();

        let cancellation = CancellationToken::default();
        let bounded = procedures_for_definition_with_limits(
            fixture.analyzer.analyzer(),
            &definition,
            artifact,
            1,
            &cancellation,
        );
        assert_eq!(bounded.status, ProcedureRangeLookupStatus::BudgetExhausted);
        assert_eq!(bounded.examined, 1);
        assert!(bounded.handles.is_empty());

        let range_bounded = procedures_for_definition_with_limits(
            fixture.analyzer.analyzer(),
            &definition,
            artifact,
            3,
            &cancellation,
        );
        assert_eq!(
            range_bounded.status,
            ProcedureRangeLookupStatus::BudgetExhausted
        );
        assert_eq!(
            range_bounded.examined, 3,
            "stored declaration ranges must not be cloned past the remaining budget"
        );
        assert!(range_bounded.handles.is_empty());

        cancellation.cancel();
        let cancelled = procedures_for_definition_with_limits(
            fixture.analyzer.analyzer(),
            &definition,
            artifact,
            usize::MAX,
            &cancellation,
        );
        assert_eq!(cancelled.status, ProcedureRangeLookupStatus::Cancelled);
        assert_eq!(cancelled.examined, 0);
        assert!(cancelled.handles.is_empty());
    }

    #[test]
    fn declaration_procedure_lookup_excludes_nested_same_named_ruby_method() {
        let fixture = AnalyzerFixture::new_for_language(
            Language::Ruby,
            &[(
                "nested.rb",
                "def target(value)\n  def target(value)\n    value\n  end\n  value\nend\n",
            )],
        );
        let file = ProjectFile::new(fixture.project_root(), "nested.rb");
        let analyzer = fixture.analyzer.analyzer();
        let definition = analyzer
            .get_definitions("target")
            .into_iter()
            .max_by_key(|definition| {
                analyzer
                    .ranges(definition)
                    .into_iter()
                    .map(|range| range.end_byte.saturating_sub(range.start_byte))
                    .max()
                    .unwrap_or_default()
            })
            .expect("outer target definition");
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("Ruby semantic materialization")
            .available_value()
            .cloned()
            .expect("Ruby semantic artifact");
        let matching_procedures = artifact
            .procedures()
            .iter()
            .filter(|procedure| procedure_matches_definition(procedure, &definition))
            .count();
        assert_eq!(
            matching_procedures, 2,
            "fixture must contain outer and nested same-name procedures"
        );

        let lookup = procedures_for_definition_with_limits(
            analyzer,
            &definition,
            &artifact,
            usize::MAX,
            &cancellation,
        );

        assert_eq!(lookup.status, ProcedureRangeLookupStatus::Complete);
        assert_eq!(lookup.handles.len(), 1, "nested same-name procedure leaked");
        assert_eq!(
            lookup.handles[0]
                .semantics()
                .locator()
                .anchor()
                .span()
                .start_byte(),
            0,
            "the outer declaration must resolve to the outer procedure"
        );
    }

    #[test]
    fn source_range_procedure_lookup_budgets_sorting_and_materialization() {
        let (_fixture, call) = semantic_call_fixture();
        let artifact = call.procedure().artifact();
        let ranges = artifact
            .procedures()
            .iter()
            .map(|procedure| {
                let span = procedure.locator().anchor().span();
                Range {
                    start_byte: span.start_byte() as usize,
                    end_byte: span.end_byte() as usize,
                    start_line: span.start().line() as usize,
                    end_line: span.end().line() as usize,
                }
            })
            .collect::<Vec<_>>();
        assert!(ranges.len() > 1, "fixture must exercise the sorting path");

        let cancellation = CancellationToken::default();
        let complete = procedures_for_source_ranges(artifact, &ranges, usize::MAX, &cancellation);
        assert_eq!(complete.status, ProcedureRangeLookupStatus::Complete);
        assert_eq!(complete.handles.len(), artifact.procedures().len());

        let bounded = procedures_for_source_ranges(
            artifact,
            &ranges,
            complete.examined - 1,
            &CancellationToken::default(),
        );
        assert_eq!(bounded.status, ProcedureRangeLookupStatus::BudgetExhausted);
        assert_eq!(bounded.examined, complete.examined - 1);
        assert!(bounded.handles.is_empty());

        let mid_lookup_cancellation =
            CancellationToken::cancel_after_checks_for_test(complete.examined);
        let cancelled =
            procedures_for_source_ranges(artifact, &ranges, usize::MAX, &mid_lookup_cancellation);
        assert_eq!(cancelled.status, ProcedureRangeLookupStatus::Cancelled);
        assert_eq!(cancelled.examined, complete.examined - 1);
        assert!(cancelled.handles.is_empty());
    }

    fn locator_with_anchor(locator: &SemanticLocator, offset: u32) -> SemanticLocator {
        let start = SourcePosition::new(offset, 0, offset);
        let end = SourcePosition::new(offset + 1, 0, offset + 1);
        SemanticLocator::new(
            locator.mount(),
            locator.path().clone(),
            locator.language(),
            locator.declaration().clone(),
            locator.role(),
            SourceAnchor::new(
                SourceSpan::new(start, end).expect("ordered fixture span"),
                0,
            ),
        )
    }

    #[test]
    fn dispatch_boundary_order_uses_typed_variants_and_numeric_locator_fields() {
        use crate::analyzer::semantic::DeferredInvocationKind;

        let locator = semantic_call_handle()
            .procedure()
            .semantics()
            .locator()
            .clone();
        let early = locator_with_anchor(&locator, 2);
        let late = locator_with_anchor(&locator, 10);

        assert_eq!(compare_locator_fields(&early, &late), Ordering::Less);

        let boundary = |kind| DispatchBoundary {
            kind,
            exact_external_target: None,
            proof: ProofStatus::Proven,
            completeness: EvidenceCompleteness::Complete,
            provenance: Box::new([]),
        };
        let mut boundaries = vec![
            boundary(DispatchBoundaryKind::Truncated),
            boundary(DispatchBoundaryKind::Deferred {
                target: late,
                kind: DeferredInvocationKind::Generator,
            }),
            boundary(DispatchBoundaryKind::Unresolved),
            boundary(DispatchBoundaryKind::Unmaterialized(early.clone())),
            boundary(DispatchBoundaryKind::External(Some(early))),
            boundary(DispatchBoundaryKind::External(None)),
        ];
        boundaries.sort_by(compare_dispatch_boundaries);

        assert!(matches!(
            boundaries.as_slice(),
            [
                DispatchBoundary {
                    kind: DispatchBoundaryKind::External(None),
                    ..
                },
                DispatchBoundary {
                    kind: DispatchBoundaryKind::External(Some(_)),
                    ..
                },
                DispatchBoundary {
                    kind: DispatchBoundaryKind::Unmaterialized(_),
                    ..
                },
                DispatchBoundary {
                    kind: DispatchBoundaryKind::Deferred { .. },
                    ..
                },
                DispatchBoundary {
                    kind: DispatchBoundaryKind::Unresolved,
                    ..
                },
                DispatchBoundary {
                    kind: DispatchBoundaryKind::Truncated,
                    ..
                },
            ]
        ));
    }

    #[test]
    fn low_level_work_excludes_rows_owned_by_the_final_dispatch_result() {
        let work = low_level_dispatch_work(1, 128, 7);

        assert_eq!(work.source_bytes, 128);
        assert_eq!(work.call_sites, 1);
        assert_eq!(work.nested_entries, 7);
    }

    #[test]
    fn cancelled_partial_is_open_and_charges_its_retained_boundary() {
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let observed_work = SemanticWork {
            source_bytes: 64,
            call_sites: 1,
            nested_entries: 3,
            ..SemanticWork::default()
        };
        let (fixture, call) = semantic_call_fixture();
        let outcome = cancelled_lookup_outcome(
            &fixture.analyzer,
            &call,
            OracleLimits::default(),
            CancelledLookupArtifacts {
                resolved_targets: &[],
                low_level_boundaries: &[CallDispatchBoundaryKind::Unresolved(
                    DefinitionLookupStatus::NotFound,
                )],
                call_dispatch_gap: None,
                procedure_call_gap: None,
                observed_work,
            },
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("cancelled lookup outcome");

        let SemanticOutcome::Cancelled {
            partial: Some(partial),
            work,
        } = outcome
        else {
            panic!("retained cancelled lookup must publish one partial")
        };
        assert_eq!(partial.coverage(), CandidateCoverage::Open);
        assert_eq!(partial.boundaries().len(), 1);
        assert_eq!(work.nested_entries, observed_work.nested_entries + 4);
        assert_eq!(partial.boundaries()[0].provenance.len(), 1);
        assert!(work.owned_text_bytes > 0);
        assert_eq!(budget.used(), work);
    }

    #[test]
    fn cancelled_partial_preserves_an_independent_projection_cap() {
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let (fixture, call) = semantic_call_fixture();
        let outcome = cancelled_lookup_outcome(
            &fixture.analyzer,
            &call,
            OracleLimits::uniform(1).expect("positive oracle limits"),
            CancelledLookupArtifacts {
                resolved_targets: &[],
                low_level_boundaries: &[
                    CallDispatchBoundaryKind::External,
                    CallDispatchBoundaryKind::Unresolved(DefinitionLookupStatus::NotFound),
                ],
                call_dispatch_gap: None,
                procedure_call_gap: None,
                observed_work: SemanticWork::default(),
            },
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("projection-capped cancelled lookup outcome");

        let SemanticOutcome::Cancelled {
            partial: Some(partial),
            ..
        } = outcome
        else {
            panic!("projection-capped cancellation must retain its partial")
        };
        assert_eq!(partial.coverage(), CandidateCoverage::Truncated);
        assert_eq!(partial.boundaries().len(), 1);
    }

    #[test]
    fn cancelled_partial_preserves_a_retained_truncated_boundary() {
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let (fixture, call) = semantic_call_fixture();
        let outcome = cancelled_lookup_outcome(
            &fixture.analyzer,
            &call,
            OracleLimits::default(),
            CancelledLookupArtifacts {
                resolved_targets: &[],
                low_level_boundaries: &[CallDispatchBoundaryKind::Truncated],
                call_dispatch_gap: None,
                procedure_call_gap: None,
                observed_work: SemanticWork::default(),
            },
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("truncated cancelled lookup outcome");

        let SemanticOutcome::Cancelled {
            partial: Some(partial),
            ..
        } = outcome
        else {
            panic!("cancelled lookup must retain its truncated boundary")
        };
        assert_eq!(partial.coverage(), CandidateCoverage::Truncated);
        assert!(matches!(
            partial.boundaries(),
            [DispatchBoundary {
                kind: DispatchBoundaryKind::Truncated,
                ..
            }]
        ));
    }

    #[test]
    fn cancelled_partial_preserves_resolved_targets_as_typed_boundaries() {
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let (fixture, call) = semantic_call_fixture();
        let target = CallDispatchTarget {
            definition: CodeUnit::new(
                ProjectFile::new(fixture.project_root(), "call.ts"),
                CodeUnitType::Function,
                "",
                "target",
            ),
            proof: UsageProof::Proven,
        };
        let outcome = cancelled_lookup_outcome(
            &fixture.analyzer,
            &call,
            OracleLimits::default(),
            CancelledLookupArtifacts {
                resolved_targets: &[target],
                low_level_boundaries: &[],
                call_dispatch_gap: None,
                procedure_call_gap: None,
                observed_work: SemanticWork::default(),
            },
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("cancelled target projection");

        let SemanticOutcome::Cancelled {
            partial: Some(partial),
            ..
        } = outcome
        else {
            panic!("resolved cancelled target must remain in the partial")
        };
        assert_eq!(partial.coverage(), CandidateCoverage::Open);
        assert!(matches!(
            partial.boundaries(),
            [DispatchBoundary {
                kind: DispatchBoundaryKind::Unmaterialized(_),
                proof: ProofStatus::Proven,
                completeness: EvidenceCompleteness::Partial(_),
                ..
            }]
        ));
        let call_row = call
            .procedure()
            .semantics()
            .call_site(call.id())
            .expect("semantic call row");
        let boundary = &partial.boundaries()[0];
        assert_eq!(
            boundary.provenance[0].record().evidence()[0].id(),
            call_row.target_evidence
        );
        assert!(matches!(
            boundary.provenance[0].record().subject(),
            Some(crate::analyzer::semantic::OracleRelationSubject::DispatchBoundary(subject))
                if subject == &boundary.kind
        ));
    }

    #[test]
    fn cancelled_partial_caps_unique_resolved_target_identities() {
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let (fixture, call) = semantic_call_fixture();
        let source = ProjectFile::new(fixture.project_root(), "call.ts");
        let target = CallDispatchTarget {
            definition: CodeUnit::new(source.clone(), CodeUnitType::Function, "", "target"),
            proof: UsageProof::Unproven,
        };
        let proven_duplicate = CallDispatchTarget {
            definition: target.definition.clone(),
            proof: UsageProof::Proven,
        };
        let caller = CallDispatchTarget {
            definition: CodeUnit::new(source, CodeUnitType::Function, "", "caller"),
            proof: UsageProof::Proven,
        };
        let limits = OracleLimits::new(OracleLimitValues {
            dispatch_targets: 2,
            ..OracleLimitValues::uniform(4)
        })
        .expect("positive dispatch limits");
        let outcome = cancelled_lookup_outcome(
            &fixture.analyzer,
            &call,
            limits,
            CancelledLookupArtifacts {
                resolved_targets: &[target, proven_duplicate, caller],
                low_level_boundaries: &[],
                call_dispatch_gap: None,
                procedure_call_gap: None,
                observed_work: SemanticWork::default(),
            },
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("deduplicated cancelled target projection");

        let SemanticOutcome::Cancelled {
            partial: Some(partial),
            ..
        } = outcome
        else {
            panic!("cancelled target projection must retain its partial")
        };
        assert_eq!(partial.coverage(), CandidateCoverage::Open);
        assert_eq!(partial.boundaries().len(), 2);
        assert!(
            partial.boundaries().iter().all(|boundary| {
                matches!(&boundary.kind, DispatchBoundaryKind::Unmaterialized(_))
            })
        );
        assert!(
            partial
                .boundaries()
                .iter()
                .all(|boundary| { matches!(&boundary.proof, ProofStatus::Proven) })
        );
    }

    #[test]
    fn late_cancellation_precedes_budget_and_caps_remaining_target_groups() {
        let (fixture, call) = semantic_call_fixture();
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        assert_eq!(
            materialization_interruption(DispatchQuality::Truncated, true, &cancellation),
            Some(MaterializationInterruption::Cancelled),
            "token cancellation must win when materialization also exceeds its budget"
        );

        let source = ProjectFile::new(fixture.project_root(), "call.ts");
        let targets = ["target", "caller", "not_materialized"]
            .into_iter()
            .map(|name| CallDispatchTarget {
                definition: CodeUnit::new(source.clone(), CodeUnitType::Function, "", name),
                proof: UsageProof::Proven,
            })
            .collect();
        let groups = dispatch_target_groups(fixture.analyzer.analyzer(), targets);
        let limits = OracleLimits::new(OracleLimitValues {
            provenance_records: 2,
            evidence_handles: 2,
            ..OracleLimitValues::uniform(4)
        })
        .expect("positive cancellation projection limits");
        let mut candidates = Vec::new();
        let mut boundaries = Vec::new();

        let truncated = append_cancelled_target_boundaries(
            fixture.analyzer.analyzer(),
            &candidates,
            &mut boundaries,
            groups,
            limits,
            None,
            None,
        )
        .expect("late-cancelled targets project to typed boundaries");
        assert!(truncated, "the omitted target group must remain observable");
        assert_eq!(
            boundaries.len(),
            2,
            "the helper must stop at the aggregate provenance/evidence cap"
        );

        boundaries.sort_by(compare_dispatch_boundaries);
        boundaries.dedup();
        assert!(!bound_dispatch_projection(
            &mut candidates,
            &mut boundaries,
            limits,
            None,
            None,
        ));
        assert_eq!(boundaries.len(), 2);
        attach_dispatch_provenance(&call, &mut candidates, &mut boundaries, None, None, limits)
            .expect("bounded late-cancellation provenance");
        let result = DispatchResult::new(
            &call,
            candidates,
            boundaries,
            CandidateCoverage::Truncated,
            limits,
        )
        .expect("bounded late-cancellation dispatch partial");
        let target_evidence = call
            .procedure()
            .semantics()
            .call_site(call.id())
            .expect("semantic call row")
            .target_evidence;
        assert!(result.boundaries().iter().all(|boundary| {
            matches!(boundary.kind, DispatchBoundaryKind::Unmaterialized(_))
                && boundary.provenance[0].record().evidence()[0].id() == target_evidence
                && matches!(
                    boundary.provenance[0].record().subject(),
                    Some(OracleRelationSubject::DispatchBoundary(subject))
                        if subject == &boundary.kind
                )
        }));
    }

    #[test]
    fn target_cap_truncation_does_not_overwrite_cancelled_quality() {
        assert_eq!(
            merge_dispatch_quality(DispatchQuality::Cancelled, DispatchQuality::Truncated),
            DispatchQuality::Cancelled
        );
    }

    #[test]
    fn cancellation_precedes_a_retained_budget_interruption() {
        let call = semantic_call_handle();
        let mut candidates = Vec::new();
        let mut boundaries = vec![DispatchBoundary {
            kind: DispatchBoundaryKind::Unresolved,
            exact_external_target: None,
            proof: ProofStatus::Unproven("unresolved dispatch arm".into()),
            completeness: EvidenceCompleteness::Partial("open dispatch".into()),
            provenance: Box::new([]),
        }];
        attach_dispatch_provenance(
            &call,
            &mut candidates,
            &mut boundaries,
            None,
            None,
            OracleLimits::default(),
        )
        .expect("dispatch provenance projection");
        let result = DispatchResult::new(
            &call,
            candidates,
            boundaries,
            CandidateCoverage::Open,
            OracleLimits::default(),
        )
        .expect("valid retained dispatch partial");
        let exceeded = SemanticBudget::uniform(1)
            .expect("positive semantic budget")
            .check(SemanticWork {
                nested_entries: 2,
                ..SemanticWork::default()
            })
            .expect_err("work must exceed the nested-entry budget");
        let work = dispatch_result_work(&result);

        let outcome = *finish_dispatch_interruption(result, true, Some(exceeded), work)
            .expect_err("cancellation must remain the outer interruption");
        assert!(matches!(
            outcome,
            SemanticOutcome::Cancelled {
                partial: Some(partial),
                work: retained_work,
            } if partial.coverage() == CandidateCoverage::Open && retained_work == work
        ));
    }

    #[test]
    fn cancelled_projection_truncates_to_the_total_evidence_limit() {
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let (fixture, call) = semantic_call_fixture();
        let limits = OracleLimits::new(OracleLimitValues {
            provenance_records: 2,
            evidence_handles: 1,
            ..OracleLimitValues::uniform(2)
        })
        .expect("positive independent evidence limit");
        let outcome = cancelled_lookup_outcome(
            &fixture.analyzer,
            &call,
            limits,
            CancelledLookupArtifacts {
                resolved_targets: &[],
                low_level_boundaries: &[
                    CallDispatchBoundaryKind::External,
                    CallDispatchBoundaryKind::Unresolved(DefinitionLookupStatus::NotFound),
                ],
                call_dispatch_gap: None,
                procedure_call_gap: None,
                observed_work: SemanticWork::default(),
            },
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("evidence-capped cancelled lookup outcome");

        let SemanticOutcome::Cancelled {
            partial: Some(partial),
            ..
        } = outcome
        else {
            panic!("evidence-capped cancellation must retain its partial")
        };
        assert_eq!(partial.coverage(), CandidateCoverage::Truncated);
        assert_eq!(partial.boundaries().len(), 1);
    }

    #[test]
    fn dispatch_provenance_uses_target_and_gap_evidence() {
        let call = semantic_call_handle();
        let call_row = call
            .procedure()
            .semantics()
            .call_site(call.id())
            .expect("semantic call row");
        let gap_evidence = call
            .procedure()
            .semantics()
            .evidence_rows()
            .iter()
            .find(|evidence| evidence.id != call_row.evidence)
            .map(|evidence| evidence.id)
            .expect("caller has independent semantic evidence");
        let exceeded = SemanticBudget::uniform(1)
            .expect("positive semantic budget")
            .check(SemanticWork {
                nested_entries: 2,
                ..SemanticWork::default()
            })
            .expect_err("work must exceed the nested-entry budget");
        let gap = SemanticGap {
            id: SemanticGapId::new(0),
            point: call_row.point,
            subject: SemanticGapSubject::CallSite(call_row.id),
            capability: SemanticCapability::DynamicDispatch,
            impacts: SemanticGapImpacts::single(SemanticGapImpact::DispatchCoverage),
            kind: SemanticGapKind::ExceededBudget,
            budget: Some(exceeded),
            detail: "dynamic target exploration exceeded its finite budget".into(),
            source: call_row.source,
            evidence: gap_evidence,
        };
        let mut candidates = vec![
            DispatchCandidate::new(
                call.procedure().clone(),
                ProofStatus::Proven,
                EvidenceCompleteness::Complete,
                std::iter::empty(),
                OracleLimits::default(),
            )
            .expect("an empty dispatch draft fits every positive provenance limit"),
        ];
        let mut boundaries = Vec::new();
        assert_eq!(
            apply_dynamic_dispatch_gap(&gap, &mut boundaries),
            DispatchQuality::Truncated
        );
        assert!(matches!(
            boundaries.as_slice(),
            [DispatchBoundary {
                kind: DispatchBoundaryKind::Truncated,
                ..
            }]
        ));

        attach_dispatch_provenance(
            &call,
            &mut candidates,
            &mut boundaries,
            Some(&gap),
            None,
            OracleLimits::default(),
        )
        .expect("dispatch provenance projection");

        assert_eq!(
            candidates[0].provenance[0].record().kind(),
            OracleRelationKind::DispatchCandidate
        );
        assert_eq!(
            candidates[0].provenance[0].record().evidence()[0].id(),
            call_row.target_evidence
        );
        assert_eq!(
            boundaries[0].provenance[0].record().kind(),
            OracleRelationKind::DispatchBoundary
        );
        assert_eq!(
            boundaries[0].provenance[0].record().evidence()[0].id(),
            gap.evidence
        );
        assert!(matches!(
            boundaries[0].provenance[0].record().subject(),
            Some(OracleRelationSubject::DispatchBoundary(subject))
                if subject == &boundaries[0].kind
        ));
    }

    #[test]
    fn dispatch_gap_evidence_keeps_distinct_kinds_before_handle_deduplication() {
        let call = semantic_call_handle();
        let call_row = call
            .procedure()
            .semantics()
            .call_site(call.id())
            .expect("semantic call row");
        let shared_evidence = call
            .procedure()
            .semantics()
            .evidence_rows()
            .iter()
            .find(|evidence| evidence.id != call_row.evidence)
            .map(|evidence| evidence.id)
            .expect("caller has independent semantic evidence");
        let exceeded = SemanticBudget::uniform(1)
            .expect("positive semantic budget")
            .check(SemanticWork {
                nested_entries: 2,
                ..SemanticWork::default()
            })
            .expect_err("work must exceed the nested-entry budget");
        let unsupported_gap = SemanticGap {
            id: SemanticGapId::new(0),
            point: call_row.point,
            subject: SemanticGapSubject::CallSite(call_row.id),
            capability: SemanticCapability::DynamicDispatch,
            impacts: SemanticGapImpacts::single(SemanticGapImpact::DispatchCoverage),
            kind: SemanticGapKind::Unsupported,
            budget: None,
            detail: "dynamic target discovery is unsupported".into(),
            source: call_row.source,
            evidence: shared_evidence,
        };
        let exceeded_gap = SemanticGap {
            id: SemanticGapId::new(1),
            kind: SemanticGapKind::ExceededBudget,
            budget: Some(exceeded),
            detail: "dynamic target exploration exceeded its finite budget".into(),
            ..unsupported_gap.clone()
        };
        let mut candidates = Vec::new();
        let mut boundaries = vec![
            DispatchBoundary {
                kind: DispatchBoundaryKind::Unresolved,
                exact_external_target: None,
                proof: ProofStatus::Unproven("unresolved dispatch arm".into()),
                completeness: EvidenceCompleteness::Partial("open dispatch".into()),
                provenance: Box::new([]),
            },
            DispatchBoundary {
                kind: DispatchBoundaryKind::Truncated,
                exact_external_target: None,
                proof: ProofStatus::Unproven("dispatch limit reached".into()),
                completeness: EvidenceCompleteness::Partial("targets were omitted".into()),
                provenance: Box::new([]),
            },
        ];

        attach_dispatch_provenance(
            &call,
            &mut candidates,
            &mut boundaries,
            Some(&unsupported_gap),
            Some(&exceeded_gap),
            OracleLimits::default(),
        )
        .expect("dispatch gap provenance projection");

        assert!(boundaries.iter().all(|boundary| {
            boundary.provenance[0].record().evidence()
                == [call.procedure().evidence_handle(shared_evidence).unwrap()]
        }));
        assert!(boundaries.iter().all(|boundary| {
            matches!(
                boundary.provenance[0].record().subject(),
                Some(OracleRelationSubject::DispatchBoundary(subject))
                    if subject == &boundary.kind
            )
        }));
    }

    #[test]
    fn retained_boundary_work_includes_owned_locator_payload() {
        let call = semantic_call_handle();
        let locator = call.procedure().semantics().locator().clone();
        let locator_work = semantic_locator_work(&locator);
        let mut candidates = Vec::new();
        let mut boundaries = vec![DispatchBoundary {
            kind: DispatchBoundaryKind::Unmaterialized(locator),
            exact_external_target: None,
            proof: ProofStatus::Proven,
            completeness: EvidenceCompleteness::Complete,
            provenance: Box::new([]),
        }];
        attach_dispatch_provenance(
            &call,
            &mut candidates,
            &mut boundaries,
            None,
            None,
            OracleLimits::default(),
        )
        .expect("dispatch provenance projection");
        let result = DispatchResult::new(
            &call,
            candidates,
            boundaries,
            CandidateCoverage::Open,
            OracleLimits::default(),
        )
        .expect("valid unmaterialized dispatch boundary");
        let work = dispatch_result_work(&result);

        assert_eq!(
            work.owned_text_bytes,
            locator_work.owned_text_bytes.saturating_mul(2)
        );
        assert_eq!(
            work.nested_entries,
            // Boundary row plus both the boundary and relation-subject locator
            // payloads, relation handle, relation record, and one evidence.
            1 + locator_work.nested_entries.saturating_mul(2) + 3
        );
    }

    #[test]
    fn workspace_semantic_oracle_remains_copy() {
        fn assert_copy<T: Copy>() {}
        assert_copy::<WorkspaceSemanticOracle<'static>>();
    }
}
