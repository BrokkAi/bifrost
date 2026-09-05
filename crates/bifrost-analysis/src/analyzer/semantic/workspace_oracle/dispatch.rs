//! Exact, location-first workspace dispatch and candidate materialization.
//!
//! Control-flow stitching consumes the workspace-oracle facade; it does not
//! reach into the usage-graph dispatch resolver directly.

use std::cmp::Ordering;
use std::collections::VecDeque;
use std::sync::Arc;

use sha2::{Digest, Sha256};

use super::WorkspaceSemanticOracle;
use crate::analyzer::languages::{LanguageSupport, language_support};
use crate::analyzer::semantic::{
    AbstractObjectIdentity, CallSiteHandle, CallableTarget, CallableTargetResolution,
    CancellationToken, CandidateCoverage, ContentIdentity, DeclarationLocator, DeclarationSegment,
    DeclarationSegmentKind, DispatchBoundary, DispatchBoundaryKind, DispatchCandidate,
    DispatchExtensibility, DispatchOracle, DispatchResult, EvidenceCompleteness, EvidenceHandle,
    ExactExternalFormalContract, ExactExternalProcedureTarget, HeapOracle, MemberDeclaration,
    MemoryLocationKind, ObjectCardinality, ObservationPhase, OracleCallContext, OracleLimits,
    OracleRelationArena, OracleRelationId, OracleRelationOwner, OracleRelationRecord,
    OracleRelationSubject, ProcedureHandle, ProcedureKind, ProcedureSemantics, ProofStatus,
    SemanticArtifact, SemanticBudgetExceeded, SemanticCallSite, SemanticCapability, SemanticGap,
    SemanticGapImpact, SemanticGapKind, SemanticGapSubject, SemanticLanguage, SemanticLocator,
    SemanticOutcome, SemanticProviderError, SemanticRequest, SemanticRole, SemanticWork,
    SourceAnchor, SourcePosition, SourceSpan, StableDigest, UnmaterializedExternalTarget,
    ValueAtPoint, WorkspaceMountId, WorkspaceRelativePath, split_canonical_qualified_callee,
    unmaterialized_external_mount, unmaterialized_external_path,
};
use crate::analyzer::semantic_model::{
    CompiledProcedureSummary, Completeness, ProcedureSummaryMemberKey,
    SemanticModelMatchDisposition, SemanticModelSymbolKind,
};
use crate::analyzer::structural::resolution::{BoundaryStatus, MethodFamilyRelation};
use crate::analyzer::usages::get_definition::{
    CallApplicationKind, DefinitionLookupStatus, DispatchQuality, ExactExternalCallProof,
    dispatch_quality_for_status,
};
use crate::analyzer::usages::{
    CallDispatchBoundaryKind, CallDispatchLookup, CallDispatchSession, CallDispatchTarget,
    CallRelationService, CallRelationWork, UsageProof, call_dispatch_equivalence_source,
};
use crate::analyzer::{AnalyzerQueryScope, QueryScope};
use crate::analyzer::{
    CodeUnit, CodeUnitType, IAnalyzer, Language, LanguageDialect, ProjectFile, Range,
    WorkspaceAnalyzer,
};
use crate::hash::{HashMap, HashSet};

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
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
    receiver_hint: bool,
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
                group.proof = ProofStatus::Proven;
                group.completeness = EvidenceCompleteness::Complete;
            }
            continue;
        }
        index.insert(identity, groups.len());
        groups.push(DispatchTargetGroup {
            representative: target.definition,
            proof: proof_from_usage(target.proof),
            completeness: completeness_from_usage(target.proof),
            receiver_hint: false,
        });
    }
    groups
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

struct PreparedCallDispatch {
    lookup: CallDispatchLookup,
}

/// A lazy serial dispatch session bound to one exact semantic artifact.
///
/// Construction performs no source or resolver work. The first actual call
/// reads and parses its exact source snapshot; later calls from the same
/// artifact reuse that tree while definition lookup, target materialization,
/// cancellation, and budgets remain ordered per call.
pub(super) struct PreparedWorkspaceDispatchSession<'a> {
    oracle: WorkspaceSemanticOracle<'a>,
    artifact: Arc<SemanticArtifact>,
    low_level: Option<CallDispatchSession>,
    low_level_source_paid: bool,
}

impl PreparedWorkspaceDispatchSession<'_> {
    pub(crate) fn retained_bytes(&self) -> usize {
        debug_assert_eq!(
            self.low_level.is_some(),
            self.low_level_source_paid,
            "retained exact syntax must have a committed source charge"
        );
        self.low_level
            .as_ref()
            .map_or(0, CallDispatchSession::retained_bytes)
    }

    pub(super) fn resolve_call(
        &mut self,
        call: &CallSiteHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<DispatchResult>, SemanticProviderError> {
        if request.cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: SemanticWork::default(),
            });
        }
        if !Arc::ptr_eq(call.procedure().artifact(), &self.artifact) {
            return Err(SemanticProviderError::invalid_identity(
                "prepared dispatch call must belong to the exact semantic artifact allocation",
            ));
        }
        if let Some(outcome) = self.resolve_declared_indirect_local_call(call, request)? {
            return Ok(outcome);
        }
        let call_span = exact_call_range(call)?;
        debug_assert_eq!(
            self.low_level.is_some(),
            self.low_level_source_paid,
            "a returned prepared session retains only paid exact syntax"
        );
        let initialized_low_level = self.low_level.is_none();
        if self.low_level.is_none() {
            let max_source_bytes = request.budget.remaining().source_bytes;
            let Some((file, exact_source)) = exact_source_for_procedure(
                self.oracle.workspace,
                call.procedure(),
                max_source_bytes,
            )?
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
            self.low_level = Some(CallRelationService::dispatch_session(file, exact_source));
        }
        let source_bytes_before = request.budget.used().source_bytes;
        let low_level = self
            .low_level
            .as_mut()
            .expect("the first real dispatch call initializes its source session");
        let scope = AnalyzerQueryScope::with_semantic_model_overlay(
            self.oracle.workspace.analyzer(),
            self.oracle.semantic_model_overlay(),
        );
        let source_was_paid = self.low_level_source_paid;
        let mut lookup = low_level.dispatch_at_bounded(
            self.oracle.workspace.analyzer(),
            scope.token(),
            &call_span,
            request.budget.remaining().nested_entries.max(1),
            Some(request.cancellation),
        );
        let parsed_source_bytes = lookup.work.scanned_source_bytes;
        let parsed_source = lookup.work.scanned_files > 0;
        if source_was_paid {
            // An earlier adapter-proven local call opened and paid this exact
            // immutable snapshot without parsing it. A later resolver call may
            // initialize the lazy tree, but must not charge the same source a
            // second time.
            lookup.work.scanned_files = 0;
            lookup.work.scanned_source_bytes = 0;
        }
        let outcome =
            self.oracle
                .resolve_prepared_call(call, PreparedCallDispatch { lookup }, request);
        drop(scope);
        if initialized_low_level {
            let source_bytes_committed = parsed_source
                && request
                    .budget
                    .used()
                    .source_bytes
                    .checked_sub(source_bytes_before)
                    .is_some_and(|committed| committed >= parsed_source_bytes);
            self.low_level_source_paid = source_bytes_committed;
            if !source_bytes_committed {
                self.low_level = None;
            }
        }
        assert_eq!(
            self.low_level.is_some(),
            self.low_level_source_paid,
            "a prepared session cannot return with unpaid exact syntax"
        );
        outcome
    }

    /// Materialize an adapter-proven same-artifact indirect target without asking
    /// a source-level definition resolver to rediscover a lexical callable
    /// value binding it does not model. Direct callable syntax stays on the
    /// ordinary resolver route. The semantic artifact validation already
    /// proved the local procedure ID, and dispatch provenance below retains
    /// the exact call and target evidence just like that route.
    fn resolve_declared_indirect_local_call(
        &mut self,
        call: &CallSiteHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Option<SemanticOutcome<DispatchResult>>, SemanticProviderError> {
        if !matches!(self.artifact.key().language(), LanguageDialect::Standard(_)) {
            return Ok(None);
        }
        let semantic_call = call
            .procedure()
            .semantics()
            .call_site(call.id())
            .ok_or_else(|| SemanticProviderError::internal("semantic call-site handle is stale"))?;
        let CallableTargetResolution::Proven(CallableTarget::Local(target_id)) =
            &semantic_call.declared_targets
        else {
            return Ok(None);
        };
        let target = self.artifact.procedure_handle(*target_id).ok_or_else(|| {
            SemanticProviderError::internal(
                "validated local call target is absent from its semantic artifact",
            )
        })?;
        let call_span = exact_call_range(call)?;
        let target_span = target.semantics().locator().anchor().span();
        if call_span.start_byte <= target_span.start_byte() as usize
            && target_span.end_byte() as usize <= call_span.end_byte
        {
            return Ok(None);
        }
        let initialized_low_level = self.low_level.is_none();
        let source_work = if initialized_low_level {
            let max_source_bytes = request.budget.remaining().source_bytes;
            let Some((file, exact_source)) = exact_source_for_procedure(
                self.oracle.workspace,
                call.procedure(),
                max_source_bytes,
            )?
            else {
                let work = SemanticWork {
                    source_bytes: max_source_bytes.saturating_add(1),
                    ..SemanticWork::default()
                };
                let exceeded = request.budget.check(work).map_or_else(
                    |exceeded| exceeded,
                    |_| unreachable!("bounded source omission must exceed the remaining budget"),
                );
                return Ok(Some(SemanticOutcome::ExceededBudget {
                    partial: None,
                    exceeded,
                    work,
                }));
            };
            let source_work = SemanticWork {
                source_bytes: exact_source.len(),
                ..SemanticWork::default()
            };
            self.low_level = Some(CallRelationService::dispatch_session(file, exact_source));
            source_work
        } else {
            SemanticWork::default()
        };
        let mut candidates = vec![
            DispatchCandidate::new(
                target,
                ProofStatus::Proven,
                EvidenceCompleteness::Complete,
                std::iter::empty(),
                *self.oracle.limits(),
            )
            .map_err(|error| {
                SemanticProviderError::internal(format!(
                    "declared local dispatch candidate is invalid: {error}"
                ))
            })?,
        ];
        let mut boundaries = Vec::new();
        attach_dispatch_provenance(
            call,
            &mut candidates,
            &mut boundaries,
            scoped_call_dispatch_gap(call.procedure().semantics(), semantic_call),
            scoped_procedure_dispatch_gap(call.procedure()),
            *self.oracle.limits(),
        )?;
        let result = DispatchResult::new(
            call,
            candidates,
            boundaries,
            CandidateCoverage::Exhaustive,
            *self.oracle.limits(),
        )
        .map_err(|error| {
            SemanticProviderError::internal(format!(
                "declared local dispatch result is invalid: {error}"
            ))
        })?;
        let work = sum_semantic_work(source_work, dispatch_result_work(&result));
        if let Err(exceeded) = request.budget.charge(work) {
            if initialized_low_level {
                self.low_level = None;
            }
            return Ok(Some(SemanticOutcome::ExceededBudget {
                partial: None,
                exceeded,
                work,
            }));
        }
        if initialized_low_level {
            self.low_level_source_paid = true;
        }
        assert_eq!(
            self.low_level.is_some(),
            self.low_level_source_paid,
            "a prepared session cannot return with unpaid exact syntax"
        );
        Ok(Some(SemanticOutcome::Complete {
            value: result,
            work,
        }))
    }
}

pub(crate) fn exact_call_range(call: &CallSiteHandle) -> Result<Range, SemanticProviderError> {
    let semantic_call = call
        .procedure()
        .semantics()
        .call_site(call.id())
        .ok_or_else(|| SemanticProviderError::internal("semantic call-site handle is stale"))?;
    let mapping = call
        .procedure()
        .semantics()
        .source_mapping(semantic_call.source)
        .ok_or_else(|| {
            SemanticProviderError::internal("semantic call site has no source mapping")
        })?;
    let span = mapping.locator.anchor().span();
    Ok(Range {
        start_byte: span.start_byte() as usize,
        end_byte: span.end_byte() as usize,
        start_line: span.start().line() as usize,
        end_line: span.end().line() as usize,
    })
}

impl<'a> WorkspaceSemanticOracle<'a> {
    pub(super) fn prepare_call_dispatch_session(
        &self,
        artifact: Arc<SemanticArtifact>,
    ) -> PreparedWorkspaceDispatchSession<'a> {
        PreparedWorkspaceDispatchSession {
            oracle: self.clone(),
            artifact,
            low_level: None,
            low_level_source_paid: false,
        }
    }

    fn resolve_prepared_call(
        &self,
        call: &CallSiteHandle,
        prepared: PreparedCallDispatch,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<DispatchResult>, SemanticProviderError> {
        let semantic_call = call
            .procedure()
            .semantics()
            .call_site(call.id())
            .ok_or_else(|| SemanticProviderError::internal("semantic call-site handle is stale"))?;
        let call_language = call.procedure().artifact().key().language();
        let call_dispatch_gap =
            scoped_call_dispatch_gap(call.procedure().semantics(), semantic_call);
        let procedure_call_gap = scoped_procedure_dispatch_gap(call.procedure());

        let max_dispatch_targets = self.limits.dispatch_targets();
        // `dispatch_targets` bounds the final unique ProcedureHandle projection,
        // not raw resolver declarations. Raw exploration instead consumes the
        // request's generic nested-entry budget; any omission at this layer is
        // therefore a semantic-budget partial, not an oracle-target cap.
        let mut staged_budget = request.budget.clone();
        let PreparedCallDispatch { lookup } = prepared;
        debug_assert!(lookup.work.scanned_files <= 1);
        debug_assert!(
            lookup.status.is_none() || !lookup.targets.is_empty() || !lookup.boundaries.is_empty(),
            "every completed dispatch status must retain a target or typed boundary"
        );
        let dispatch_work = low_level_dispatch_work(lookup.work);
        if lookup.cancelled || request.cancellation.is_cancelled() {
            return cancelled_lookup_outcome(
                self.workspace,
                call,
                self.limits,
                CancelledLookupArtifacts {
                    resolved_targets: &lookup.targets,
                    low_level_boundaries: &lookup.boundaries,
                    exact_external_call: lookup.exact_external_call.as_ref(),
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
        debug_assert!(
            !lookup.budget_exhausted || lookup.truncated,
            "prepared dispatch never submits a zero-sized low-level budget"
        );
        let exact_go_external_call = if call_language == SemanticLanguage::Standard(Language::Go)
            && lookup.status == Some(DefinitionLookupStatus::UnresolvableImportBoundary)
            && lookup.boundary == Some(BoundaryStatus::ExternalIndexed)
        {
            lookup.exact_external_call.as_ref().filter(|proof| {
                matches!(
                    proof.call_application(),
                    CallApplicationKind::PackageFunction
                ) || (proof.call_application() == CallApplicationKind::BoundReceiver
                    && proof.dispatch_extensibility() == Some(DispatchExtensibility::Closed))
            })
        } else {
            None
        };

        let mut candidates = Vec::new();
        let mut boundaries = lookup
            .boundaries
            .iter()
            .map(|boundary| {
                low_level_boundary(
                    boundary,
                    call_language,
                    Some(semantic_call),
                    lookup.exact_external_call.as_ref(),
                )
            })
            .collect::<Vec<_>>();
        let mut target_groups = VecDeque::from(dispatch_target_groups(
            self.workspace.analyzer(),
            lookup.targets,
        ));
        let ordinary_dispatch_is_only_unresolved = target_groups.is_empty()
            && !lookup.truncated
            && boundaries
                .iter()
                .all(|boundary| boundary.kind == DispatchBoundaryKind::Unresolved)
            && (call_dispatch_gap.is_some() || !boundaries.is_empty());
        let hinted_dispatch = ordinary_dispatch_is_only_unresolved
            .then(|| self.dispatch_hints().for_call(call.procedure(), call.id()))
            .flatten();
        let mut hinted_arms_materialized = hinted_dispatch.is_some();
        let mut hinted_external_targets = HashSet::<SemanticLocator>::default();
        if let Some(hint_set) = hinted_dispatch {
            let receiver_classes = hint_set
                .hints()
                .iter()
                .map(|hint| hint.receiver_class().qualified_name())
                .collect::<Vec<_>>();
            let proof = if hint_set.singleton() {
                ProofStatus::Proven
            } else {
                ProofStatus::Unproven(
                    format!("target selected by propagated receiver classes {receiver_classes:?}")
                        .into(),
                )
            };
            let completeness = if hint_set.exhaustive() {
                EvidenceCompleteness::Complete
            } else {
                EvidenceCompleteness::Partial(
                    "propagated receiver classes do not cover every call arm".into(),
                )
            };
            let mut declarations = HashSet::default();
            for hint in hint_set.hints() {
                match hint.declaration() {
                    MemberDeclaration::Workspace(declaration) => {
                        if declarations.insert(declaration.clone()) {
                            target_groups.push_back(DispatchTargetGroup {
                                representative: declaration.clone(),
                                proof: proof.clone(),
                                completeness: completeness.clone(),
                                receiver_hint: true,
                            });
                        }
                    }
                    MemberDeclaration::External(declaration) => {
                        let Some(targets) = hinted_external_member_targets(
                            self,
                            declaration,
                            call_language,
                            semantic_call,
                        ) else {
                            hinted_arms_materialized = false;
                            continue;
                        };
                        for (target, summary_complete) in targets {
                            hinted_arms_materialized &= summary_complete;
                            hinted_external_targets.insert(target.locator().clone());
                            boundaries.push(DispatchBoundary {
                                kind: DispatchBoundaryKind::External(Some(
                                    target.locator().clone(),
                                )),
                                external_callee_identity: None,
                                exact_external_target: None,
                                unmaterialized_external_target: Some(target),
                                proof: proof.clone(),
                                completeness: if summary_complete {
                                    EvidenceCompleteness::Complete
                                } else {
                                    EvidenceCompleteness::Partial(
                                        "propagated external receiver member has no complete authored procedure summary"
                                            .into(),
                                    )
                                },
                                provenance: Box::new([]),
                            });
                        }
                    }
                }
            }
        }
        // Every declaration this call has already queued, so a class-hierarchy
        // expansion (below) can never queue the same implementor twice and two
        // interfaces that declare the same member cannot loop.
        let mut queued_declarations = target_groups
            .iter()
            .map(|group| group.representative.clone())
            .collect::<HashSet<CodeUnit>>();
        let mut candidate_indexes = HashMap::<ProcedureHandle, usize>::default();
        let mut final_candidates_truncated = false;
        let mut cancelled_targets_truncated = false;
        let mut materialization_quality = DispatchQuality::Complete;
        // #2480: whether every concrete (materialized-body) match this call
        // resolved to has a class-hierarchy-proven *empty* override set. A
        // concrete match starts this `true`; it becomes `false` the moment
        // any matched declaration's override set is unproven or non-empty.
        // Distinct from `hierarchy_expansion().concrete_overrides` (#2277),
        // which controls whether a *non-empty* proven override set widens the
        // candidate list with `Unproven` entries -- a precision question this
        // wave does not touch. Proving the set empty is not a precision
        // question: an empty, proven override set cannot select a different
        // target, so it is sound to trust regardless of that flag.
        let mut concrete_overrides_proven_absent = true;
        let mut matched_concrete_groups = false;
        let exploration_exceeded = lookup.truncated.then(|| {
            staged_budget
                .check(SemanticWork {
                    nested_entries: staged_budget.remaining().nested_entries.saturating_add(1),
                    ..SemanticWork::default()
                })
                .expect_err("exploration truncation must exceed the nested-entry budget")
        });
        let mut materialization_exceeded = None;
        let mut materialized_files: HashMap<ProjectFile, SemanticOutcome<Arc<SemanticArtifact>>> =
            HashMap::default();
        let mut staged_request = request.staged(&mut staged_budget);

        while let Some(group) = target_groups.pop_front() {
            if request.cancellation.is_cancelled() {
                cancelled_targets_truncated |= append_cancelled_target_boundaries(
                    self.workspace.analyzer(),
                    &candidates,
                    &mut boundaries,
                    std::iter::once(group).chain(target_groups.drain(..)),
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
                    std::iter::once(group).chain(target_groups.drain(..)),
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
            let mut matched_quality = match &group.proof {
                ProofStatus::Proven => DispatchQuality::Complete,
                ProofStatus::Unproven(_) => DispatchQuality::Unproven,
            };
            let mut failure_quality = DispatchQuality::Complete;
            // Whether the declaration's own file was materialized completely.
            // Only then does "no procedure matched this declaration" mean "this
            // declaration has no body", which is the condition the
            // class-hierarchy expansion below is scoped to.
            let mut complete_materialization = false;
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
                        group.proof.clone(),
                        group.completeness.clone(),
                        max_dispatch_targets,
                    );
                    matched_any |= has_match;
                    final_candidates_truncated |= truncated;
                    complete_materialization = true;
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
                // The declaration's file materialized completely and did
                // publish a body for it: this callee is a concrete method. A
                // subclass may still override it, in which case the code that
                // runs at this call site is the override rather than the body
                // just retained. Offering those overrides is the second, wider
                // class-hierarchy lever (#2277): unlike the body-less case in
                // the other arm of this branch, there is already something
                // analyzable here, so this strictly widens the candidate set
                // and is off unless a host asked for it.
                //
                // The retained concrete candidate keeps its own proof. The
                // overrides enter as `Unproven`, exactly like the implementors
                // of a body-less declaration, so the answer says "the callee
                // the types name runs, and these overrides could run instead"
                // and never claims a proven edge to an override.
                //
                // #2480: the class-hierarchy question is asked here
                // unconditionally (not just under `concrete_overrides`) so a
                // *proven-empty* answer can discharge the call's own
                // "may select an override" gap below. This mirrors
                // `virtual_dispatch_implementor_targets`'s other caller (the
                // body-less arm), which already asks unconditionally. Only
                // *acting* on a non-empty answer by widening the candidate
                // set stays behind the flag.
                if complete_materialization && !group.receiver_hint {
                    if staged_request.charge_execution_traversal(1) {
                        matched_concrete_groups = true;
                        match virtual_dispatch_implementor_targets(
                            self.workspace.analyzer(),
                            &group.representative,
                            request.cancellation,
                        ) {
                            Some(overrides) if overrides.is_empty() => {
                                // Proven: no workspace declaration overrides
                                // this member. `concrete_overrides_proven_absent`
                                // stays true.
                            }
                            Some(overrides) => {
                                concrete_overrides_proven_absent = false;
                                if self.hierarchy_expansion().concrete_overrides {
                                    for overriding in overrides {
                                        if queued_declarations.insert(overriding.clone()) {
                                            target_groups.push_back(DispatchTargetGroup {
                                                representative: overriding,
                                                proof: ProofStatus::Unproven(
                                                    "dispatch target is a possible override".into(),
                                                ),
                                                completeness: EvidenceCompleteness::Partial(
                                                    "dispatch cannot prove one complete override target identity"
                                                        .into(),
                                                ),
                                                receiver_hint: false,
                                            });
                                        }
                                    }
                                }
                            }
                            None => {
                                // The question does not apply or the member
                                // family is unproven: the override set is not
                                // established either way.
                                concrete_overrides_proven_absent = false;
                            }
                        }
                    } else {
                        // The expansion could not be charged, so the target set
                        // is knowingly short of the overrides that could run,
                        // and the empty-override proof this call would have
                        // needed to discharge its dispatch gap was not taken.
                        concrete_overrides_proven_absent = false;
                        if self.hierarchy_expansion().concrete_overrides {
                            materialization_quality = merge_dispatch_quality(
                                materialization_quality,
                                DispatchQuality::Truncated,
                            );
                        }
                    }
                }
            } else if interruption.is_none() {
                let target =
                    locator_for_definition(self.workspace.analyzer(), &group.representative)?;
                boundaries.push(DispatchBoundary {
                    kind: DispatchBoundaryKind::Unmaterialized(target.clone()),
                    external_callee_identity: None,
                    exact_external_target: exact_external_artifact.as_ref().and_then(|artifact| {
                        exact_external_procedure_target(
                            self.workspace.analyzer(),
                            &group.representative,
                            artifact,
                            target.clone(),
                            semantic_call.receiver.is_some(),
                        )
                    }),
                    unmaterialized_external_target: None,
                    proof: group.proof.clone(),
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
                // The declaration's own file was analyzed completely and still
                // published no body for it, so this callee is an interface or
                // abstract member and the code that runs is in the workspace
                // types below it (#2205). Queue those implementors as further
                // dispatch targets. They stay `Unproven`, and the boundary
                // pushed just above stays with them, so the answer says "the
                // named callee has no body, and these are the members that
                // could run" rather than claiming a resolved edge.
                if complete_materialization && !group.receiver_hint {
                    if staged_request.charge_execution_traversal(1) {
                        if let Some(implementors) = virtual_dispatch_implementor_targets(
                            self.workspace.analyzer(),
                            &group.representative,
                            request.cancellation,
                        ) {
                            for implementor in implementors {
                                if queued_declarations.insert(implementor.clone()) {
                                    target_groups.push_back(DispatchTargetGroup {
                                        representative: implementor,
                                        proof: ProofStatus::Unproven(
                                            "dispatch target is a possible implementor".into(),
                                        ),
                                        completeness: EvidenceCompleteness::Partial(
                                            "dispatch cannot prove one complete implementor target identity"
                                                .into(),
                                        ),
                                        receiver_hint: false,
                                    });
                                }
                            }
                        }
                    } else {
                        // The expansion this body-less callee needs could not be
                        // charged, so the target set is knowingly short of the
                        // members that could run. Say so instead of answering as
                        // if the hierarchy had been consulted.
                        materialization_quality = merge_dispatch_quality(
                            materialization_quality,
                            DispatchQuality::Truncated,
                        );
                    }
                }
            }

            if let Some(interruption) = interruption {
                if interruption == MaterializationInterruption::Cancelled {
                    let current = (!matched_any).then_some(group);
                    cancelled_targets_truncated |= append_cancelled_target_boundaries(
                        self.workspace.analyzer(),
                        &candidates,
                        &mut boundaries,
                        current.into_iter().chain(target_groups.drain(..)),
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

        let hint_refinement_complete = hinted_dispatch.is_some_and(|hint_set| {
            hint_set.exhaustive()
                && hinted_arms_materialized
                && materialization_exceeded.is_none()
                && !final_candidates_truncated
                && !request.cancellation.is_cancelled()
                && boundaries.iter().all(|boundary| {
                    boundary.kind == DispatchBoundaryKind::Unresolved
                        || matches!(
                            &boundary.kind,
                            DispatchBoundaryKind::External(Some(target))
                                if hinted_external_targets.contains(target)
                                    && matches!(
                                        boundary.completeness,
                                        EvidenceCompleteness::Complete
                                    )
                        )
                })
        });
        if hint_refinement_complete {
            boundaries.retain(|boundary| boundary.kind != DispatchBoundaryKind::Unresolved);
        }

        let (anonymous_receiver_refined, receiver_refinement_work) = self
            .refine_java_anonymous_receiver_dispatch(
                call,
                semantic_call,
                &mut candidates,
                &mut boundaries,
                &mut staged_request,
            )?;
        reported_work = reported_work.conservative_add(receiver_refinement_work);
        if anonymous_receiver_refined {
            materialization_quality = DispatchQuality::Complete;
        }

        let resolver_proven_external_static =
            resolver_proven_external_static_boundary(lookup.status, &candidates, &boundaries);
        let call_dispatch_gap = (!anonymous_receiver_refined && !hint_refinement_complete)
            .then_some(call_dispatch_gap)
            .flatten()
            .filter(|gap| {
                !closed_dispatch_discharges_gap(&candidates, gap)
                    && !proven_static_target_discharges_gap(
                        call.procedure(),
                        &semantic_call.declared_targets,
                        semantic_call.receiver.is_none(),
                        &candidates,
                        &boundaries,
                        lookup.status == Some(DefinitionLookupStatus::Resolved),
                        materialization_quality,
                        gap,
                    )
                    && !concrete_overrides_proven_absent_discharges_gap(
                        &candidates,
                        &boundaries,
                        gap,
                        matched_concrete_groups,
                        concrete_overrides_proven_absent,
                    )
                    && !exact_go_external_dispatch_discharges_gap(
                        exact_go_external_call,
                        &candidates,
                        &boundaries,
                        gap,
                    )
                    && !resolver_proven_external_static_dispatch_discharges_gap(
                        resolver_proven_external_static,
                        gap,
                    )
            });
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

        // #2371: the discharge rule for a call's residual dynamic-dispatch arm
        // needs the workspace half proven -- workspace implementors of the
        // resolved declaring member enumerated, possibly empty -- before a
        // contract-claiming summary can answer the external half. A call whose
        // only named target is an unmaterialized external member never queues a
        // `DispatchTargetGroup` for it (there is no workspace `CodeUnit` to
        // queue), so the ordinary CHA expansion above never runs for it and
        // "enumerated" is not satisfied by construction. Prove it here instead,
        // or else refuse: see `external_member_workspace_override_proven_absent`.
        if call_dispatch_gap.is_some()
            && !boundaries
                .iter()
                .any(|boundary| boundary.kind == DispatchBoundaryKind::Truncated)
        {
            let unenumerated = boundaries
                .iter()
                .filter_map(|boundary| match &boundary.kind {
                    DispatchBoundaryKind::External(Some(_)) => {
                        boundary.unmaterialized_external_target.as_ref()
                    }
                    _ => None,
                })
                .any(|target| {
                    !external_member_workspace_override_proven_absent(
                        self.workspace.analyzer(),
                        target,
                    )
                });
            if unenumerated {
                boundaries.push(workspace_hierarchy_unenumerated_boundary());
                materialization_quality =
                    merge_dispatch_quality(materialization_quality, DispatchQuality::Truncated);
            }
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
        } else if anonymous_receiver_refined
            || resolver_proven_external_static
            || hint_refinement_complete
        {
            CandidateCoverage::Exhaustive
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
        let status_quality = if anonymous_receiver_refined || resolver_proven_external_static {
            DispatchQuality::Complete
        } else {
            dispatch_quality_for_status(lookup.status, lookup.boundary)
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

    /// Refine a Java virtual call only when the source resolver and heap
    /// oracle independently close the callable and receiver identities.
    ///
    /// Resolver candidates own callable identity. A proven singleton
    /// allocation owns receiver identity. An anonymous implementation method
    /// is structurally contained by its object-creation source anchor, so one
    /// contained resolver candidate composes those facts without comparing a
    /// method name or rendered signature.
    fn refine_java_anonymous_receiver_dispatch(
        &self,
        call: &CallSiteHandle,
        semantic_call: &SemanticCallSite,
        candidates: &mut Vec<DispatchCandidate>,
        boundaries: &mut Vec<DispatchBoundary>,
        request: &mut SemanticRequest<'_>,
    ) -> Result<(bool, SemanticWork), SemanticProviderError> {
        if call.procedure().artifact().key().language()
            != SemanticLanguage::Standard(Language::Java)
        {
            return Ok((false, SemanticWork::default()));
        }
        let Some(receiver_id) = semantic_call.receiver else {
            return Ok((false, SemanticWork::default()));
        };
        if candidates.is_empty()
            || boundaries.is_empty()
            || boundaries
                .iter()
                .any(|boundary| !matches!(boundary.kind, DispatchBoundaryKind::Unmaterialized(_)))
            || candidates.iter().any(|candidate| {
                !candidate
                    .target()
                    .semantics()
                    .locator()
                    .declaration()
                    .segments()
                    .iter()
                    .any(|segment| {
                        segment.kind() == DeclarationSegmentKind::Type && segment.name().is_none()
                    })
            })
        {
            return Ok((false, SemanticWork::default()));
        }

        let procedure = call.procedure();
        let receiver = procedure.value_handle(receiver_id).ok_or_else(|| {
            SemanticProviderError::internal("Java dispatch receiver value is stale")
        })?;
        let point = procedure
            .point_handle(semantic_call.point)
            .ok_or_else(|| SemanticProviderError::internal("Java dispatch call point is stale"))?;
        let query = ValueAtPoint::new(
            receiver,
            point,
            ObservationPhase::BeforeEffects,
            OracleCallContext::empty(),
        )
        .map_err(|error| {
            SemanticProviderError::internal(format!(
                "could not construct Java receiver points-to query: {error}"
            ))
        })?;
        let outcome = HeapOracle::pointees(self, &query, request)?;
        let work = outcome.work();
        let SemanticOutcome::Complete {
            value: points_to, ..
        } = &outcome
        else {
            return Ok((false, work));
        };
        if points_to.objects().coverage() != CandidateCoverage::Exhaustive {
            return Ok((false, work));
        }
        let [object] = points_to.objects().candidates() else {
            return Ok((false, work));
        };
        if !object.is_proven_complete()
            || object.value().cardinality() != ObjectCardinality::Singleton
        {
            return Ok((false, work));
        }
        let AbstractObjectIdentity::Allocation(allocation) = object.value().identity() else {
            return Ok((false, work));
        };
        if allocation.procedure() != procedure {
            return Ok((false, work));
        }
        let allocation_row = procedure
            .semantics()
            .allocation(allocation.id())
            .ok_or_else(|| SemanticProviderError::internal("Java receiver allocation is stale"))?;
        let allocation_span = procedure
            .semantics()
            .source_mapping(allocation_row.source)
            .ok_or_else(|| {
                SemanticProviderError::internal("Java receiver allocation source is stale")
            })?
            .locator
            .anchor()
            .span();

        let mut retained = candidates
            .iter()
            .filter(|candidate| {
                let target = candidate.target();
                if target.artifact().key() != procedure.artifact().key() {
                    return false;
                }
                let span = target.semantics().locator().anchor().span();
                allocation_span.start_byte() <= span.start_byte()
                    && span.end_byte() <= allocation_span.end_byte()
            })
            .cloned();
        let Some(mut exact) = retained.next() else {
            return Ok((false, work));
        };
        if retained.next().is_some() {
            return Ok((false, work));
        }

        exact.excluded_targets = candidates
            .iter()
            .filter(|candidate| candidate.target() != exact.target())
            .map(|candidate| candidate.target().clone())
            .collect();
        exact.proof = ProofStatus::Proven;
        exact.completeness = EvidenceCompleteness::Complete;
        candidates.clear();
        candidates.push(exact);
        boundaries.clear();
        Ok((true, work))
    }
}

impl DispatchOracle for WorkspaceSemanticOracle<'_> {
    fn resolve_call(
        &self,
        call: &CallSiteHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<DispatchResult>, SemanticProviderError> {
        let mut session =
            self.prepare_call_dispatch_session(Arc::clone(call.procedure().artifact()));
        session.resolve_call(call, request)
    }
}

/// The workspace members that implement or override a body-less callee
/// declaration: class-hierarchy analysis for virtual dispatch (#2205).
///
/// A call written against an interface, or against an abstract method, names a
/// declaration that has no body. Dispatch resolves the call to that declaration,
/// materializes its file, finds no procedure, and stops. The value-flow snapshot
/// of the enclosing procedure is then reported unknown and require-model taint
/// abstains -- even though the code that actually runs is in the same workspace,
/// in the classes below the declared type. This function supplies those classes'
/// members so the flow can continue through one of them.
///
/// Three properties make this honest rather than a guess.
///
/// It is *scoped*. The caller only asks after the declaration's own file
/// materialized completely, so "no member family" is a fact about the hierarchy
/// rather than about how far materialization got. Two callers ask, and they are
/// scoped differently.
///
/// The first is the body-less case: the file published no procedure for the
/// declaration, which is exactly the interface-method and abstract-method case
/// (#2205). Without expansion there is no code to analyze at all, so this
/// caller always asks.
///
/// The second is the concrete case: the file did publish a body, and the
/// question is whether a subclass override could run instead (#2277). That
/// strictly widens a candidate set which already names analyzable code, so this
/// caller asks only when the workspace's
/// [`crate::analyzer::DispatchHierarchyExpansion::concrete_overrides`] is on.
///
/// A `native` method is excluded from both: its body is outside every source
/// this workspace can read, which is a boundary fact rather than a hierarchy
/// question, and the declaration records it.
///
/// It is *exact*. The edges come from the member-family capability
/// ([`crate::analyzer::usages::MemberFamilyProvider`], #1477), which derives
/// `implemented_by` and `overridden_by` by bounded inversion over the same
/// forward `implements`/`overrides` relation an analyzer proves from a
/// declaration and its owner's hierarchy. Nothing is matched by fully-qualified
/// name or by rendered signature text. An answer that is not `proven` yields no
/// targets at all, so an inheritance cycle, an unrecorded modifier, or an
/// unresolved overload set leaves the call exactly as unresolved as it was.
///
/// It is *bounded*. The family walk carries its own shared visit budget and the
/// caller's cancellation token, and the caller charges the expansion against the
/// request's traversal allowance before asking.
///
/// The result is a set of *candidates*, never proven edges. The caller queues
/// them with [`UsageProof::Unproven`] and keeps the unmaterialized boundary for
/// the declaration itself, so an implementor the analyzer cannot materialize
/// still surfaces as its own honest diagnostic beside any flow that completes
/// through a sibling implementor.
///
/// `None` means the question does not apply to this declaration or the language
/// states no member family; it is not an empty answer about the hierarchy.
///
/// Set `BIFROST_DEBUG_CHA=1` to print one line per expansion, which is how the
/// resolution was measured at corpus scale.
fn virtual_dispatch_implementor_targets(
    analyzer: &dyn IAnalyzer,
    declaration: &CodeUnit,
    cancellation: &CancellationToken,
) -> Option<Vec<CodeUnit>> {
    if !declaration.is_function() {
        return None;
    }
    let metadata = analyzer.signature_metadata(declaration);
    if metadata
        .iter()
        .any(|entry| entry.callable_modifiers_recorded() && entry.callable_is_native())
    {
        return None;
    }
    let provider = analyzer.member_family_provider()?;
    let answer = provider.member_family(declaration, Some(cancellation));
    // An unproven family answers nothing about the hierarchy, so it contributes
    // no target: the call stays exactly as unresolved as it already was.
    let targets = if answer.is_proven() {
        answer
            .edges
            .iter()
            .filter(|edge| {
                matches!(
                    edge.relation,
                    MethodFamilyRelation::ImplementedBy | MethodFamilyRelation::OverriddenBy
                )
            })
            .map(|edge| edge.target.clone())
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    if debug_cha_enabled() {
        eprintln!(
            "virtual_dispatch_implementor_targets {} proven={} outcome={:?} reason={:?} implemented_by={}",
            declaration.fq_name(),
            answer.is_proven(),
            answer.outcome,
            answer.reason,
            targets.len()
        );
    }
    Some(targets)
}

/// #2371: whether the analyzer's complete short-name index proves that no
/// workspace declaration can override `target`'s external member.
///
/// `virtual_dispatch_implementor_targets` above answers the same "workspace
/// half" question for a *workspace* declaration with no body, by expanding its
/// `CodeUnit` through class-hierarchy analysis. An unmaterialized external
/// member has no such `CodeUnit` -- it is definitionally not indexed -- so
/// that expansion never runs for it, and #2371's discharge rule cannot treat
/// "never ran" as "enumerated and proven empty".
///
/// The proof this asks instead: a workspace type overriding `target` must
/// declare a member spelled exactly like it (the same terminal identifier), so
/// no workspace declaration with that identifier means no workspace type
/// overrides it. `lookup_candidates_by_identifier` answers this from the
/// analyzer's persisted index without a source scan, but only a *complete*
/// index makes an empty answer conclusive; an analyzer that cannot answer
/// cheaply reports an empty set regardless, so the completeness flag is
/// checked first.
///
/// The proof is sound only in the refusing direction. An unrelated
/// same-named declaration -- a workspace class with its own, unconnected
/// `getParameter` method, say -- costs a discharge, exactly like an
/// incomplete index does: both fail closed rather than open. Neither
/// manufactures a false discharge, which is what keeps the workspace-double
/// fixture (#2371) from being skated past: a workspace type that actually
/// implements the external interface and declares the member is exactly a
/// declaration `lookup_candidates_by_identifier` finds.
fn external_member_workspace_override_proven_absent(
    analyzer: &dyn IAnalyzer,
    target: &UnmaterializedExternalTarget,
) -> bool {
    analyzer.has_complete_symbol_lookup_index()
        && analyzer
            .lookup_candidates_by_identifier(target.member())
            .is_empty()
}

/// #2371: the arm a call keeps when the workspace half of its residual
/// dynamic-dispatch gap is not proven enumerated. Distinct from the generic
/// [`truncated_dispatch_boundary`] reason so a corpus trace can tell the two
/// causes apart; both are `Truncated`, so both refuse discharge identically.
fn workspace_hierarchy_unenumerated_boundary() -> DispatchBoundary {
    DispatchBoundary {
        kind: DispatchBoundaryKind::Truncated,
        external_callee_identity: None,
        exact_external_target: None,
        unmaterialized_external_target: None,
        proof: ProofStatus::Unproven(
            "workspace implementors of the external member are not proven enumerated".into(),
        ),
        completeness: EvidenceCompleteness::Partial(
            "no workspace declaration shares the external member's identifier, or the identifier index is not complete, so an absent workspace override is not proven"
                .into(),
        ),
        provenance: Box::new([]),
    }
}

/// Whether `BIFROST_DEBUG_CHA` asks for the class-hierarchy dispatch trace.
/// Read once: the trace is a development aid, and re-reading the environment on
/// every call site of a corpus run would dominate the measurement it exists to
/// take.
fn debug_cha_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("BIFROST_DEBUG_CHA").is_some())
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

/// Whether a class-hierarchy-proven *empty* override set discharges a call's
/// dynamic-dispatch gap, for an overridable (non-final, non-private,
/// non-static) concrete method (#2480).
///
/// `closed_dispatch_discharges_gap` only answers the structural half: a
/// `final`/`private`/`static` member cannot be overridden, so its call sites
/// never carry a residual dispatch arm. An ordinary overridable instance
/// method called on a same-class or same-object receiver -- `doPost(...)`
/// inside `doGet`'s own body, say -- is `DispatchExtensibility::Open`
/// regardless of whether any override actually exists, so that predicate
/// never discharges it, and the call's own "may select an override" gap
/// (added unconditionally at Java-adapter lowering) stays open on every such
/// call in the corpus.
///
/// The class-hierarchy answer this call's own resolution already computed
/// (`concrete_overrides_proven_absent` in `resolve_call`, independent of the
/// `concrete_overrides` widen flag) closes exactly that residual honestly: if
/// class-hierarchy analysis *proves* the override set of every concrete match
/// is empty, no other target could have run, so the single retained candidate
/// is the whole answer. This can only discharge more, never select a
/// different target: an empty proven set contributes no candidate of its own,
/// so a wrong answer here would require `virtual_dispatch_implementor_targets`
/// itself to be unsound, which is the same proof #2205 and #2371 already rely
/// on for the body-less and external-interface cases.
///
/// `matched_concrete_groups` guards against the vacuous case where no
/// concrete match happened at all (`concrete_overrides_proven_absent` starts
/// `true` and is never touched): a call resolved only through a body-less
/// declaration, or not resolved at all, must not discharge here.
///
/// `boundaries` must be empty because a boundary arm is exactly a dispatch
/// arm the empty-override proof does not cover. A body-less root (an
/// interface or abstract member) queues its workspace implementors as
/// further target groups, and each implementor is itself a concrete match
/// with a possibly proven-empty override set -- but the open question at
/// such a call is the *implementor set* of the root, which the boundary
/// pushed for the body-less declaration records and which proving each known
/// implementor override-free does not close. The same holds for external,
/// truncated, and unenumerated-hierarchy arms. Without this condition,
/// `interface Shape { int area(); }` with two workspace implementors claimed
/// an exhaustive target set (caught by
/// `open_interface_receiver_never_upgrades_to_proven_dispatch` and
/// `a_possible_dispatch_downgrades_a_definite_declaration_to_a_possible_effect`).
fn concrete_overrides_proven_absent_discharges_gap(
    candidates: &[DispatchCandidate],
    boundaries: &[DispatchBoundary],
    gap: &SemanticGap,
    matched_concrete_groups: bool,
    concrete_overrides_proven_absent: bool,
) -> bool {
    gap.capability == SemanticCapability::DynamicDispatch
        && matches!(
            gap.kind,
            SemanticGapKind::Unknown | SemanticGapKind::Unproven
        )
        && !candidates.is_empty()
        && candidates.iter().all(|candidate| {
            matches!(candidate.proof, ProofStatus::Proven)
                && matches!(candidate.completeness, EvidenceCompleteness::Complete)
        })
        && boundaries.is_empty()
        && matched_concrete_groups
        && concrete_overrides_proven_absent
}

/// Whether exact Go resolution closes the target set of an external package
/// function or concrete method selected from an activated declaration overlay.
///
/// A package function is statically selected. Go also has no virtual method
/// override dispatch: the resolver carries a closed receiver proof only after
/// structured value typing and the declaration overlay prove one direct public
/// method on one concrete struct. Interface and otherwise unresolved receiver
/// calls carry no proof and remain open.
fn exact_go_external_dispatch_discharges_gap(
    exact_go_external_call: Option<&ExactExternalCallProof>,
    candidates: &[DispatchCandidate],
    boundaries: &[DispatchBoundary],
    gap: &SemanticGap,
) -> bool {
    let Some(proof) = exact_go_external_call else {
        return false;
    };
    let Some((expected_owner, expected_member)) =
        split_canonical_qualified_callee(proof.canonical_callee(), Language::Go)
    else {
        return false;
    };
    gap.capability == SemanticCapability::DynamicDispatch
        && matches!(
            gap.kind,
            SemanticGapKind::Unknown | SemanticGapKind::Unproven
        )
        && candidates.is_empty()
        && matches!(
            boundaries,
            [boundary]
                if matches!(boundary.kind, DispatchBoundaryKind::External(Some(_)))
                    && matches!(boundary.proof, ProofStatus::Proven)
                    && boundary
                        .unmaterialized_external_target
                        .as_ref()
                        .is_some_and(|target| {
                            target.language() == SemanticLanguage::Standard(Language::Go)
                                && target.owner_fqn() == expected_owner
                                && target.member() == expected_member
                                && target.has_receiver() == proof.has_receiver()
                                && target.arity() == proof.parameter_count()
                        })
        )
}

/// Whether structured language resolution proved one receiverless external
/// target whose call cannot participate in dynamic dispatch.
///
/// The boundary stays partial with respect to the unavailable body. This
/// answers only the target-set question; exact declaration and formal proof
/// remain the semantic-model binder's responsibility.
fn resolver_proven_external_static_boundary(
    status: Option<DefinitionLookupStatus>,
    candidates: &[DispatchCandidate],
    boundaries: &[DispatchBoundary],
) -> bool {
    matches!(
        status,
        Some(
            DefinitionLookupStatus::NoDefinition
                | DefinitionLookupStatus::UnresolvableImportBoundary
        )
    ) && candidates.is_empty()
        && matches!(
            boundaries,
            [boundary]
                if matches!(boundary.kind, DispatchBoundaryKind::External(Some(_)))
                    && matches!(boundary.proof, ProofStatus::Proven)
                    && boundary
                        .unmaterialized_external_target
                        .as_ref()
                        .is_some_and(UnmaterializedExternalTarget::resolver_proves_static_call)
        )
}

fn resolver_proven_external_static_dispatch_discharges_gap(
    resolver_proven_external_static: bool,
    gap: &SemanticGap,
) -> bool {
    gap.capability == SemanticCapability::DynamicDispatch
        && matches!(
            gap.kind,
            SemanticGapKind::Unknown | SemanticGapKind::Unproven
        )
        && resolver_proven_external_static
}

/// Whether a statically proven target set discharges an avoidable per-call
/// dynamic-dispatch gap (#1952).
///
/// Several adapters publish a blanket `Unknown` dynamic-dispatch gap on every
/// call site -- "complete target coverage requires lexical and value-flow
/// refinement" -- including calls whose target is statically known. The gap is
/// answered, and must not open the run, in exactly two proven situations:
/// the adapter itself proved `declared_targets` and dispatch retained that
/// target with proven, complete evidence; or the workspace resolver performed
/// the demanded whole-program refinement and proved a clean result (lookup
/// resolved, every retained candidate proven and complete, no boundary, no
/// truncation). `Unsupported`, `Ambiguous`, and `ExceededBudget` gaps keep
/// standing: they assert something a proven target set does not answer.
#[allow(clippy::too_many_arguments)]
fn proven_static_target_discharges_gap(
    caller: &ProcedureHandle,
    declared_targets: &CallableTargetResolution,
    receiverless: bool,
    candidates: &[DispatchCandidate],
    boundaries: &[DispatchBoundary],
    lookup_resolved: bool,
    materialization_quality: DispatchQuality,
    gap: &SemanticGap,
) -> bool {
    if gap.capability != SemanticCapability::DynamicDispatch
        || !matches!(
            gap.kind,
            SemanticGapKind::Unknown | SemanticGapKind::Unproven
        )
        || candidates.is_empty()
    {
        return false;
    }
    let proven_complete = |candidate: &DispatchCandidate| {
        matches!(candidate.proof, ProofStatus::Proven)
            && matches!(candidate.completeness, EvidenceCompleteness::Complete)
    };
    if let CallableTargetResolution::Proven(target) = declared_targets
        && candidates.iter().all(|candidate| {
            proven_complete(candidate)
                && candidate_matches_declared_target(caller, candidate, target)
        })
    {
        return true;
    }
    // The resolver-proven arm normally accepts only receiverless calls whose
    // retained candidates are free functions: a plain function call's target
    // set is exactly what the whole-program resolver proved. Go is the one
    // receiver-call exception. Its named concrete methods are selected from a
    // compile-time method set and cannot be overridden; interface calls remain
    // open because their body-less declaration or implementor search retains a
    // boundary. Thus a resolved, boundary-free Go method candidate is the same
    // exhaustive proof as a resolved free function, including promoted methods
    // whose structured method-set lookup selected one declaration.
    let go_concrete_method = matches!(
        caller.artifact().key().language(),
        LanguageDialect::Standard(crate::analyzer::Language::Go)
    ) && candidates
        .iter()
        .all(|candidate| candidate.target().semantics().kind() == ProcedureKind::Method);
    (receiverless || go_concrete_method)
        && lookup_resolved
        && boundaries.is_empty()
        && materialization_quality == DispatchQuality::Complete
        && candidates.iter().all(|candidate| {
            proven_complete(candidate)
                && (go_concrete_method || candidate_has_free_target(candidate))
        })
}

/// Whether a retained candidate's target is a *free* callable: one that no type
/// or namespace owns, so no override of it can exist to enumerate.
///
/// The obvious spelling is the procedure kind, and for adapters that lower
/// their file-scope declarations as `Function` (Python, PHP, JavaScript) it is
/// enough. Ruby lowers every `def` as `ProcedureKind::Method`, including a
/// top-level `def` that is not a member of anything, so the kind alone would
/// keep every Ruby call open forever (#2637). The declaration path answers the
/// real question the kind is standing in for: a callable whose enclosing
/// segments contain no `Type` and no `Namespace` is declared directly in the
/// file, so it has no owning class or module, so it has no override set that
/// the proven candidate list could be missing. A `def` inside a Ruby `class`
/// or `module` body carries that ancestor segment and stays open here, which
/// is exactly the case a subclass can override.
///
/// The invariant this relies on: a procedure's *own* trailing segment is never
/// `Type` or `Namespace` -- those kinds name containers, not callables -- so
/// scanning the whole path is the same test as scanning the ancestors.
fn candidate_has_free_target(candidate: &DispatchCandidate) -> bool {
    matches!(
        candidate.target().semantics().kind(),
        ProcedureKind::Function | ProcedureKind::LocalFunction
    ) || candidate
        .target()
        .semantics()
        .locator()
        .declaration()
        .segments()
        .iter()
        .all(|segment| {
            !matches!(
                segment.kind(),
                DeclarationSegmentKind::Type | DeclarationSegmentKind::Namespace
            )
        })
}

fn candidate_matches_declared_target(
    caller: &ProcedureHandle,
    candidate: &DispatchCandidate,
    target: &CallableTarget,
) -> bool {
    match target {
        CallableTarget::Local(id) => {
            candidate.target().artifact().key() == caller.artifact().key()
                && candidate.target().id() == *id
        }
        CallableTarget::Unmaterialized(locator) | CallableTarget::External(locator) => {
            let candidate_locator = candidate.target().semantics().locator();
            candidate_locator.path() == locator.path()
                && candidate_locator.declaration() == locator.declaration()
        }
    }
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

fn low_level_dispatch_work(work: CallRelationWork) -> SemanticWork {
    SemanticWork {
        source_bytes: work.scanned_source_bytes,
        call_sites: usize::from(work.examined_candidates > 0),
        // Resolver rows are transient. Final retained candidates and
        // boundaries are charged exactly once after materialization.
        nested_entries: work.examined_candidates,
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
                let evidence = if boundary.target_locator().is_some()
                    || boundary.external_callee_identity().is_some()
                {
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
    exact_external_call: Option<&'a ExactExternalCallProof>,
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
        exact_external_call,
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

    let cancelled_language = call.procedure().artifact().key().language();
    let cancelled_semantic_call = call.procedure().semantics().call_site(call.id());
    let mut boundaries = low_level_boundaries
        .iter()
        .map(|boundary| {
            low_level_boundary(
                boundary,
                cancelled_language,
                cancelled_semantic_call,
                exact_external_call,
            )
        })
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
        external_callee_identity: None,
        exact_external_target: None,
        unmaterialized_external_target: None,
        proof: target.proof.clone(),
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
        let formal = target.formal_contract();
        let formal_text_bytes =
            formal
                .parameters()
                .iter()
                .fold(formal.label().len(), |bytes, parameter| {
                    bytes
                        .saturating_add(parameter.label().len())
                        .saturating_add(parameter.declared_type().map_or(0, str::len))
                });
        work.nested_entries = work
            .nested_entries
            .saturating_add(1)
            .saturating_add(procedure.nested_entries)
            .saturating_add(formal.parameters().len());
        work.owned_text_bytes = work
            .owned_text_bytes
            .saturating_add(target.symbol().len())
            .saturating_add(target.artifact().path().as_str().len())
            .saturating_add(target.artifact().adapter().name().len())
            .saturating_add(procedure.owned_text_bytes)
            .saturating_add(formal_text_bytes);
    } else if let Some(target) = boundary.unmaterialized_external_target() {
        let locator = semantic_locator_work(target.locator());
        work.nested_entries = work
            .nested_entries
            .saturating_add(1)
            .saturating_add(locator.nested_entries);
        work.owned_text_bytes = work
            .owned_text_bytes
            .saturating_add(locator.owned_text_bytes)
            .saturating_add(target.owner_fqn().len())
            .saturating_add(target.member().len());
    }
    if let Some(identity) = boundary.external_callee_identity() {
        work.nested_entries = work.nested_entries.saturating_add(1);
        work.owned_text_bytes = work
            .owned_text_bytes
            .saturating_add(identity.owner_fqn().len())
            .saturating_add(identity.member().len());
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

/// Whether a `FieldMemory` gap is discharged because the field it occurs on
/// is provably a `static final` field on an *external* type (#2538).
///
/// A `static final` field on an external type is, by Java Language
/// Specification semantics, either a compile-time constant (a primitive or
/// `String` field initialized with a constant expression) or an immutable
/// reference (any other type); either way, reading it carries no
/// attacker-influenced value flow. Java's own field-identity resolution
/// (`memory_member_locator`,
/// `crates/bifrost-analysis/src/analyzer/java/semantic/values.rs`) has no
/// path at all for a type-qualified static access -- it only resolves
/// `instance.field` through a local variable of a same-file-declared type --
/// so lowering mints an ordinary, unresolved `FieldMemory` gap for every
/// `Type.FIELD`-shaped read, external or not, and lowering itself has no
/// access to the external declaration surface to tell the two apart: Java
/// CFG lowering is a per-file, syntax-only pass with no analyzer or
/// dependency access (see the #2538 ExecPlan's Decision Log for why the
/// proof is not attempted there instead).
///
/// This predicate runs at query time, where full analyzer access exists, and
/// mirrors exactly how [`exact_source_for_procedure`] and
/// `CallRelationService::dispatch_at_bounded` already resolve an unmaterialized
/// external *call* target above: recover the field access's own literal
/// written spelling from the gap's own recorded source span (fetch the
/// procedure's exact source text via [`exact_source_for_procedure`], slice it
/// at the span), and resolve that spelling through the language's
/// `LanguageSupport::external_compile_time_constant_member` capability (Java
/// answers via the same resolver `#1900` built for "go to definition" and
/// diagnostics, unmodified; every other language currently answers `false`).
///
/// Fails closed in every case the proof is unavailable: a non-`FieldMemory`
/// gap, a gap not on a `MemoryLocation`, a non-`Field` memory location, a
/// language whose support offers no external-constant proof, a dialect
/// projection, a source fetch that comes up empty or over budget, a
/// spelling the resolver cannot place on any external declaration, or a
/// resolved member that is not proven both `is_static()` and
/// `is_compile_time_constant()`. None of those return an error; they return
/// `Ok(false)`, leaving the gap exactly as open as it was, because a missing
/// proof for one gap must never abort the rest of the sweep it is composed
/// into.
pub(crate) fn external_constant_field_read_discharges_gap(
    gap: &SemanticGap,
    procedure: &ProcedureHandle,
    workspace: &WorkspaceAnalyzer,
    request: &mut SemanticRequest<'_>,
) -> Result<bool, SemanticProviderError> {
    if gap.capability != SemanticCapability::FieldMemory {
        return Ok(false);
    }
    let SemanticGapSubject::MemoryLocation(location_id) = gap.subject else {
        return Ok(false);
    };
    let LanguageDialect::Standard(language) = procedure.artifact().key().language() else {
        return Ok(false);
    };
    let Some(support) = language_support(language) else {
        return Ok(false);
    };
    let Some(location) = procedure.semantics().memory_location(location_id) else {
        return Ok(false);
    };
    if !matches!(location.kind, MemoryLocationKind::Field { .. }) {
        return Ok(false);
    }

    let max_source_bytes = request.budget.remaining().source_bytes;
    let Some((file, exact_source)) =
        exact_source_for_procedure(workspace, procedure, max_source_bytes)?
    else {
        // A budget-exhausted or otherwise unavailable source fetch does not
        // abort the sweep this predicate is composed into; it only leaves
        // this one gap undischarged.
        return Ok(false);
    };
    let Some(mapping) = procedure.semantics().source_mapping(gap.source) else {
        return Ok(false);
    };
    let span = mapping.locator.anchor().span();
    let (start, end) = (span.start_byte() as usize, span.end_byte() as usize);
    if start > end || end > exact_source.len() {
        return Ok(false);
    }
    let Some(spelling) = exact_source.get(start..end) else {
        return Ok(false);
    };

    Ok(support.external_compile_time_constant_member(workspace.analyzer(), &file, spelling))
}

fn low_level_boundary(
    boundary: &CallDispatchBoundaryKind,
    language: SemanticLanguage,
    semantic_call: Option<&SemanticCallSite>,
    exact_external_call: Option<&ExactExternalCallProof>,
) -> DispatchBoundary {
    match boundary {
        // #1978: when the resolver retained a fully-qualified callee text for an
        // external boundary, synthesize its canonical identity so an activated
        // authored summary can bind it even though it never materializes.
        CallDispatchBoundaryKind::External {
            callee_text,
            normalized_static_owner,
            external_callee_identity,
        } => {
            match callee_text.as_deref().zip(semantic_call).and_then(
                |(text, semantic_call)| {
                    synthetic_unmaterialized_external(
                        text,
                        language,
                        semantic_call,
                        exact_external_call,
                        normalized_static_owner.as_deref(),
                    )
                },
            ) {
                Some(target) => DispatchBoundary {
                    kind: DispatchBoundaryKind::External(Some(target.locator().clone())),
                    external_callee_identity: external_identity_for_target(
                        external_callee_identity.as_ref(),
                        &target,
                    ),
                    exact_external_target: None,
                    unmaterialized_external_target: Some(target),
                    proof: ProofStatus::Proven,
                    completeness: EvidenceCompleteness::Partial(
                        "external callee body is outside the indexed workspace; an activated summary supplies its transfers"
                            .into(),
                    ),
                    provenance: Box::new([]),
                },
                None => DispatchBoundary {
                    kind: DispatchBoundaryKind::External(None),
                    external_callee_identity: external_identity_for_language(
                        external_callee_identity.as_ref(),
                        language,
                    ),
                    exact_external_target: None,
                    unmaterialized_external_target: None,
                    proof: ProofStatus::Proven,
                    completeness: EvidenceCompleteness::Partial(
                        "external declaration body is outside the indexed workspace".into(),
                    ),
                    provenance: Box::new([]),
                },
            }
        }
        CallDispatchBoundaryKind::Unresolved(status) => unresolved_dispatch_boundary(*status),
        CallDispatchBoundaryKind::UnresolvedWithTarget {
            status,
            callee_text,
            normalized_static_owner,
        } => match semantic_call.and_then(|semantic_call| {
            synthetic_unmaterialized_external(
                callee_text,
                language,
                semantic_call,
                exact_external_call,
                normalized_static_owner.as_deref(),
            )
        }) {
            Some(target) => DispatchBoundary {
                kind: DispatchBoundaryKind::External(Some(target.locator().clone())),
                external_callee_identity: None,
                exact_external_target: None,
                unmaterialized_external_target: Some(target),
                proof: ProofStatus::Unproven(
                    format!("exact dispatch status is {}", status.as_str()).into(),
                ),
                completeness: EvidenceCompleteness::Partial(
                    "the retained canonical callee does not prove one resolved dispatch target"
                        .into(),
                ),
                provenance: Box::new([]),
            },
            None => unresolved_dispatch_boundary(*status),
        },
        CallDispatchBoundaryKind::UnprovenTargetIdentity => DispatchBoundary {
            kind: DispatchBoundaryKind::Unresolved,
            external_callee_identity: None,
            exact_external_target: None,
            unmaterialized_external_target: None,
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

fn external_identity_for_language(
    identity: Option<&crate::analyzer::semantic::ResolverOwnedExternalCalleeIdentity>,
    language: SemanticLanguage,
) -> Option<crate::analyzer::semantic::ResolverOwnedExternalCalleeIdentity> {
    let identity = identity?;
    let matches_language = identity.language() == language.language();
    debug_assert!(
        matches_language,
        "resolver-owned external identity language must match its call boundary"
    );
    matches_language.then(|| identity.clone())
}

fn external_identity_for_target(
    identity: Option<&crate::analyzer::semantic::ResolverOwnedExternalCalleeIdentity>,
    target: &UnmaterializedExternalTarget,
) -> Option<crate::analyzer::semantic::ResolverOwnedExternalCalleeIdentity> {
    let identity = identity?;
    let matches_target = identity.matches_unmaterialized_external_target(target);
    debug_assert!(
        matches_target,
        "resolver-owned external identity must match its unmaterialized target"
    );
    matches_target.then(|| identity.clone())
}

fn hinted_external_member_targets(
    oracle: &WorkspaceSemanticOracle<'_>,
    declaration: &crate::analyzer::semantic::ExternalMemberDeclaration,
    language: SemanticLanguage,
    semantic_call: &SemanticCallSite,
) -> Option<Vec<(UnmaterializedExternalTarget, bool)>> {
    let overlay = oracle.semantic_model_overlay()?;
    let arity = u32::try_from(semantic_call.arguments.len()).ok()?;
    let mut targets = Vec::new();
    for symbol_id in declaration.symbol_ids() {
        let matched = overlay.symbols_with_id(symbol_id);
        let [symbol] = matched.records.as_slice() else {
            return None;
        };
        if !matches!(
            symbol.kind,
            SemanticModelSymbolKind::Constructor
                | SemanticModelSymbolKind::Method
                | SemanticModelSymbolKind::Function
        ) || symbol.language != language.semantic_pack_label()
        {
            return None;
        }
        let owner_id = symbol.owner_id.as_deref()?;
        let owners = overlay.symbols_with_id(owner_id);
        let [owner] = owners.records.as_slice() else {
            return None;
        };
        let target = modeled_unmaterialized_external(
            &owner.qualified_name,
            &symbol.name,
            language,
            arity,
            symbol.has_receiver(),
        )?;
        let complete = hinted_external_summary_is_complete(oracle, &target);
        targets.push((target, complete));
    }
    targets.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    targets.dedup_by(|left, right| {
        if left.0 == right.0 {
            left.1 &= right.1;
            true
        } else {
            false
        }
    });
    (!targets.is_empty()).then_some(targets)
}

fn hinted_external_summary_is_complete(
    oracle: &WorkspaceSemanticOracle<'_>,
    target: &UnmaterializedExternalTarget,
) -> bool {
    let Some(active) = oracle.active_semantic_models() else {
        return false;
    };
    let matched = active.procedure_summaries_for_member(ProcedureSummaryMemberKey::new(
        target.language().semantic_pack_label(),
        target.owner_fqn(),
        target.member(),
        target.has_receiver(),
        target.arity(),
    ));
    match matched.disposition {
        SemanticModelMatchDisposition::Unique => matches!(
            matched.records.as_slice(),
            [selected] if selected.record.completeness == Completeness::Complete
        ),
        SemanticModelMatchDisposition::Conflict => {
            let Some((first, rest)) = matched.records.split_first() else {
                return false;
            };
            first.record.completeness == Completeness::Complete
                && !rest.is_empty()
                && rest.iter().all(|other| {
                    other.record.completeness == Completeness::Complete
                        && external_flow_claims_agree(other.record, first.record)
                })
        }
        SemanticModelMatchDisposition::Empty => false,
    }
}

fn external_flow_claims_agree(
    left: &CompiledProcedureSummary,
    right: &CompiledProcedureSummary,
) -> bool {
    left.covers_overrides == right.covers_overrides
        && left.normal_continuation_absent == right.normal_continuation_absent
        && left.normal_result_count == right.normal_result_count
        && left.locations == right.locations
        && left.transfers == right.transfers
        && left.effects == right.effects
}

fn unresolved_dispatch_boundary(status: DefinitionLookupStatus) -> DispatchBoundary {
    DispatchBoundary {
        kind: DispatchBoundaryKind::Unresolved,
        external_callee_identity: None,
        exact_external_target: None,
        unmaterialized_external_target: None,
        proof: ProofStatus::Unproven(
            format!("exact dispatch status is {}", status.as_str()).into(),
        ),
        completeness: EvidenceCompleteness::Partial(
            "no materialized workspace target is available".into(),
        ),
        provenance: Box::new([]),
    }
}

/// Build the canonical identity for a fully-qualified external callee that never
/// materializes to a workspace or classpath artifact (#1978).
///
/// Only fully-qualified callees are in scope: the owner must be a multi-segment
/// path present verbatim in the callee text, written with the separator the
/// language uses (`java.net.URLDecoder.decode`, `std::str::from_utf8`). The
/// owner is published dot-joined whatever the source separator was, because
/// that is the spelling authored summaries are indexed under (#2596).
///
/// Instance-method transforms whose owner needs type resolution (`s.trim()`)
/// are deliberately excluded; they need type resolution this cut does not
/// perform. An import-qualified call (`URLDecoder.decode`, `Path::new`) reaches
/// here already expanded when its language could prove the expansion from its
/// import binders, and is otherwise excluded for the same reason.
///
/// A language whose external surface is spelled with single-segment owners
/// (`JSON.parse`, `path.join`) opts out of the multi-segment requirement
/// through [`LanguageSupport::publishes_single_segment_external_owners`]
/// (#2598). The owner such a callee arrives with has already been decided by
/// the classification stage, which is the only place that holds the call site's
/// file and can tell a runtime global from a parameter of the enclosing
/// procedure. Keeping the requirement for every other language is what stops a
/// Java `URLDecoder.decode` from minting under a bare class name that import
/// resolution should have expanded.
///
/// Go is another reviewed single-segment case. Its exact resolver replaces a
/// source alias such as `files.Open` with the structured canonical import path
/// `os.Open` before classification. JS/TS direct named imports likewise arrive
/// with the module specifier and imported symbol proven by the import binder,
/// even though the source call itself is bare. Any resolver-owned exact proof
/// may carry a single-segment owner: Python's explicit import binder proves
/// `subprocess.run` without treating that spelling as a global API.
fn synthetic_unmaterialized_external(
    callee_text: &str,
    language: SemanticLanguage,
    semantic_call: &SemanticCallSite,
    exact_external_call: Option<&ExactExternalCallProof>,
    normalized_static_owner: Option<&str>,
) -> Option<UnmaterializedExternalTarget> {
    let (owner_fqn, member) = split_canonical_qualified_callee(callee_text, language.language())?;
    let canonical_go_import = language == SemanticLanguage::Standard(Language::Go);
    let resolver_owned_identity =
        exact_external_call.is_some_and(|proof| proof.canonical_callee() == callee_text);
    if !owner_fqn.contains('.')
        && !canonical_go_import
        && !resolver_owned_identity
        && !language_support(language.language())
            .is_some_and(LanguageSupport::publishes_single_segment_external_owners)
    {
        return None;
    }
    let normalized_static_owner = normalized_static_owner.map(Box::<str>::from);
    let (arity, has_receiver, resolver_owned_call_shape) = match exact_external_call {
        Some(proof) if proof.canonical_callee() == callee_text => {
            match proof.call_application() {
                CallApplicationKind::PackageFunction | CallApplicationKind::BoundReceiver => {}
                CallApplicationKind::ReceiverBindingUnknown | CallApplicationKind::Unknown => {
                    return None;
                }
            }
            (proof.parameter_count(), proof.has_receiver(), true)
        }
        Some(_) => return None,
        None if language == SemanticLanguage::Standard(Language::Go) => return None,
        None => (
            u32::try_from(semantic_call.arguments.len()).ok()?,
            crate::analyzer::semantic::normalized_external_has_receiver(
                semantic_call.receiver.is_some(),
                language,
                &owner_fqn,
                normalized_static_owner.as_deref(),
            ),
            false,
        ),
    };
    let anchor = zero_source_anchor();
    let owner_segment =
        DeclarationSegment::named(DeclarationSegmentKind::Type, owner_fqn.clone(), anchor, 0)
            .ok()?;
    // Arity and receiver shape enter the synthetic declaration, so the locator
    // distinguishes different-arity overloads of one `owner.member`. Same-arity
    // overloads that differ only by parameter type cannot be told apart for an
    // unmaterialized callee, whose parameter types are unrecoverable.
    let member_kind = if has_receiver {
        DeclarationSegmentKind::Method
    } else {
        DeclarationSegmentKind::Function
    };
    let member_segment =
        DeclarationSegment::named(member_kind, member.clone(), anchor, arity).ok()?;
    let declaration = DeclarationLocator::new(vec![owner_segment, member_segment]).ok()?;
    let locator = SemanticLocator::new(
        unmaterialized_external_mount(),
        unmaterialized_external_path(),
        language,
        declaration,
        SemanticRole::Procedure,
        anchor,
    );
    Some(if resolver_owned_call_shape {
        UnmaterializedExternalTarget::new_for_resolver_owned_call(
            owner_fqn,
            member,
            arity,
            has_receiver,
            locator,
        )
    } else {
        UnmaterializedExternalTarget::new_with_normalized_static_owner(
            owner_fqn,
            member,
            arity,
            has_receiver,
            normalized_static_owner,
            locator,
        )
    })
}

fn modeled_unmaterialized_external(
    owner_fqn: &str,
    member: &str,
    language: SemanticLanguage,
    arity: u32,
    has_receiver: bool,
) -> Option<UnmaterializedExternalTarget> {
    let anchor = zero_source_anchor();
    let owner_segment = DeclarationSegment::named(
        DeclarationSegmentKind::Type,
        owner_fqn.to_owned(),
        anchor,
        0,
    )
    .ok()?;
    let member_kind = if has_receiver {
        DeclarationSegmentKind::Method
    } else {
        DeclarationSegmentKind::Function
    };
    let member_segment =
        DeclarationSegment::named(member_kind, member.to_owned(), anchor, arity).ok()?;
    let declaration = DeclarationLocator::new(vec![owner_segment, member_segment]).ok()?;
    let locator = SemanticLocator::new(
        unmaterialized_external_mount(),
        unmaterialized_external_path(),
        language,
        declaration,
        SemanticRole::Procedure,
        anchor,
    );
    Some(
        UnmaterializedExternalTarget::new_with_normalized_static_owner(
            owner_fqn.to_owned(),
            member.to_owned(),
            arity,
            has_receiver,
            None,
            locator,
        ),
    )
}

fn zero_source_anchor() -> SourceAnchor {
    let position = SourcePosition::new(0, 0, 0);
    let span = SourceSpan::new(position, position).expect("zero-width sentinel span is ordered");
    SourceAnchor::new(span, 0)
}

fn truncated_dispatch_boundary() -> DispatchBoundary {
    DispatchBoundary {
        kind: DispatchBoundaryKind::Truncated,
        external_callee_identity: None,
        exact_external_target: None,
        unmaterialized_external_target: None,
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
    } else if boundaries.iter().any(|boundary| {
        boundary.kind == DispatchBoundaryKind::Unresolved
            || matches!(boundary.proof, ProofStatus::Unproven(_))
    }) {
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
            external_callee_identity: None,
            exact_external_target: None,
            unmaterialized_external_target: None,
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
            external_callee_identity: None,
            exact_external_target: None,
            unmaterialized_external_target: None,
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

pub fn procedures_for_definition_with_limits(
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
        self.examine_many(1)
    }

    /// Charge `count` examination steps at once.
    ///
    /// A caller that knows the cost of the whole unit it is about to inspect
    /// charges it here instead of looping over [`Self::examine`], so the
    /// budget sees one decision per unit.
    fn examine_many(&mut self, count: usize) -> Result<(), ProcedureRangeLookupStatus> {
        if self.cancellation.is_cancelled() {
            return Err(ProcedureRangeLookupStatus::Cancelled);
        }
        let examined = self.examined.saturating_add(count);
        if examined > self.max_examined {
            return Err(ProcedureRangeLookupStatus::BudgetExhausted);
        }
        self.examined = examined;
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

/// Every procedure in one file artifact, charged against the shared traversal
/// budget.
///
/// Policy call binding uses this instead of narrowing by procedure-anchor
/// containment. Narrowing loses calls in languages whose procedure anchors
/// cover only the declaration header: Ruby anchors `def name`, not the body,
/// so no procedure ever contains a body span (#1953 for taint, #1957 for
/// typestate). The call site's own source anchor, which the caller compares
/// when it selects a call, is the identity that decides the binding.
///
/// Each procedure costs `1 + call_sites().len()` because the caller inspects
/// every call site of every returned procedure.
pub fn procedures_in_artifact(
    artifact: &Arc<SemanticArtifact>,
    max_examined: usize,
    cancellation: &CancellationToken,
) -> ProcedureRangeLookup {
    let mut progress = ProcedureLookupProgress::new(max_examined, cancellation);
    let mut handles = Vec::with_capacity(artifact.procedures().len());
    for procedure in artifact.procedures() {
        if let Err(status) = progress.examine_many(1 + procedure.call_sites().len()) {
            return progress.failed(status);
        }
        handles.push(
            artifact
                .procedure_handle(procedure.id())
                .expect("validated artifact procedure has a scoped handle"),
        );
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
        // A JS/TS static member's declaration identity carries a `$static`
        // suffix (`read$static`); its semantic procedure is the class method
        // `read` with `is_static`. Both spellings assert the same fact, so
        // accept the stripped name exactly when the procedure declares static
        // (#2717).
        || (procedure.properties().is_static
            && definition
                .identifier()
                .strip_suffix("$static")
                .is_some_and(|stripped| name == stripped))
}

fn exact_external_procedure_target(
    analyzer: &dyn IAnalyzer,
    definition: &CodeUnit,
    artifact: &crate::analyzer::semantic::SemanticArtifactKey,
    procedure: SemanticLocator,
    call_has_receiver: bool,
) -> Option<ExactExternalProcedureTarget> {
    let has_receiver = if artifact.language() == SemanticLanguage::Standard(Language::Go) {
        let declaration_has_receiver = definition.owner_is_type_scope();
        if call_has_receiver != declaration_has_receiver {
            return None;
        }
        declaration_has_receiver
    } else {
        call_has_receiver
    };
    let formal_contract = agreed_external_formal_contract(analyzer.signature_metadata(definition))?;
    let symbol = format!("{}{}", definition.identifier(), definition.signature()?);
    ExactExternalProcedureTarget::new(
        artifact.clone(),
        procedure,
        symbol,
        has_receiver,
        formal_contract,
    )
}

fn agreed_external_formal_contract(
    metadata: impl IntoIterator<Item = crate::analyzer::SignatureMetadata>,
) -> Option<ExactExternalFormalContract> {
    let mut agreed = None;
    for candidate in metadata {
        let candidate = ExactExternalFormalContract::from_metadata(&candidate)?;
        match &agreed {
            None => agreed = Some(candidate),
            Some(existing) if existing == &candidate => {}
            Some(_) => return None,
        }
    }
    agreed
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
        .then_with(|| {
            left.external_callee_identity
                .cmp(&right.external_callee_identity)
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
        ClassIdentity, DispatchHint, DispatchHintCallSiteKey, DispatchHintSet, DispatchHints,
        MemberDeclaration, OracleLimitValues, OracleRelationKind,
        ResolverOwnedExternalCalleeIdentity, SemanticBudget, SemanticBudgetDimension,
        SemanticGapDischarge, SemanticGapId, SemanticGapImpact, SemanticGapImpacts, SourceSite,
        SourceSiteKind, WorkspaceIcfgProvider,
    };
    use crate::analyzer::{
        AnalyzerConfig, CallableArity, Language, OverlayProject, ParameterMetadata, Project,
        ProjectFile, SignatureMetadata, TestProject, WorkspaceAnalyzer,
    };
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
        semantic_call_fixture_for_language(Language::TypeScript, name, source)
    }

    fn semantic_call_fixture_for_language(
        language: Language,
        name: &str,
        source: &str,
    ) -> (AnalyzerFixture, crate::analyzer::semantic::CallSiteHandle) {
        let fixture = AnalyzerFixture::new_for_language(language, &[(name, source)]);
        let file = ProjectFile::new(fixture.project_root(), name);
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("semantic materialization")
            .available_value()
            .cloned()
            .expect("semantic artifact");
        let call = first_call_in_artifact(&artifact);
        (fixture, call)
    }

    fn first_call_in_artifact(
        artifact: &Arc<SemanticArtifact>,
    ) -> crate::analyzer::semantic::CallSiteHandle {
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| !procedure.call_sites().is_empty())
            .expect("caller procedure");
        artifact
            .procedure_handle(procedure.id())
            .and_then(|procedure| {
                procedure.call_site_handle(procedure.semantics().call_sites()[0].id)
            })
            .expect("scoped call handle")
    }

    fn calls_in_source_order(
        artifact: &Arc<SemanticArtifact>,
    ) -> Vec<crate::analyzer::semantic::CallSiteHandle> {
        let mut calls = artifact
            .procedures()
            .iter()
            .flat_map(|procedure| {
                let handle = artifact
                    .procedure_handle(procedure.id())
                    .expect("artifact procedure has a scoped handle");
                procedure.call_sites().iter().map(move |call| {
                    let span = procedure
                        .source_mapping(call.source)
                        .expect("semantic call has a source mapping")
                        .locator
                        .anchor()
                        .span();
                    (
                        (span.start_byte(), span.end_byte()),
                        handle
                            .call_site_handle(call.id)
                            .expect("semantic call has a scoped handle"),
                    )
                })
            })
            .collect::<Vec<_>>();
        calls.sort_by_key(|(span, _)| *span);
        calls.into_iter().map(|(_, call)| call).collect()
    }

    fn dispatch_target_shape(outcome: &SemanticOutcome<DispatchResult>) -> Vec<String> {
        outcome
            .available_value()
            .expect("dispatch retains an answer")
            .candidates()
            .iter()
            .map(|candidate| format!("{:?}", candidate.target().semantics().locator()))
            .collect()
    }

    fn semantic_call_handle() -> crate::analyzer::semantic::CallSiteHandle {
        semantic_call_fixture().1
    }

    #[test]
    fn propagated_singleton_receiver_resolves_an_unresolved_python_member_call() {
        let (fixture, call) = semantic_call_fixture_for_language(
            Language::Python,
            "hinted.py",
            "class A:\n    def foo(self):\n        return 1\n\ndef caller(x):\n    return x.foo()\n",
        );
        let analyzer = fixture.analyzer.analyzer();
        let file = ProjectFile::new(fixture.project_root(), "hinted.py");
        let declarations = analyzer.get_declarations(&file);
        let class = declarations
            .iter()
            .find(|declaration| declaration.is_class())
            .cloned()
            .expect("class A declaration");
        let member = declarations
            .into_iter()
            .find(|definition| definition.terminal_name() == "foo")
            .expect("A.foo declaration");
        let mapping = call
            .procedure()
            .semantics()
            .source_mapping(
                call.procedure()
                    .semantics()
                    .call_site(call.id())
                    .expect("live call")
                    .source,
            )
            .expect("call source mapping");
        let origin = SourceSite {
            file,
            span: mapping.locator.anchor().span(),
            kind: SourceSiteKind::DeclaredParameter,
        };
        let hints = DispatchHints::new(vec![DispatchHintSet::new(
            DispatchHintCallSiteKey::for_call(call.procedure(), call.id()),
            vec![DispatchHint::new(
                MemberDeclaration::Workspace(member),
                ClassIdentity::Workspace(class),
                origin,
            )],
            true,
            true,
        )]);
        let provider = WorkspaceIcfgProvider::with_active_semantic_model_snapshot_and_hints(
            &fixture.analyzer,
            None,
            hints,
        );
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let outcome = provider
            .resolve_call(&call, &mut SemanticRequest::new(&mut budget, &cancellation))
            .expect("hinted dispatch");
        let result = outcome.available_value().expect("hinted dispatch answer");

        assert_eq!(result.coverage(), CandidateCoverage::Exhaustive);
        assert_eq!(result.candidates().len(), 1, "{result:#?}");
        assert!(matches!(result.candidates()[0].proof, ProofStatus::Proven));
        assert_eq!(
            result.candidates()[0]
                .target()
                .semantics()
                .locator()
                .declaration()
                .segments()
                .last()
                .and_then(DeclarationSegment::name),
            Some("foo")
        );
        assert!(
            result
                .boundaries()
                .iter()
                .all(|boundary| boundary.kind != DispatchBoundaryKind::Unresolved),
            "{result:#?}"
        );
    }

    #[test]
    fn unresolved_canonical_callee_is_model_bindable_but_stays_open() {
        let (_fixture, call) = semantic_call_fixture_for_language(
            Language::Java,
            "Caller.java",
            "class Caller { void call() { com.example.Missing.run(); } }\n",
        );
        let semantic_call = call
            .procedure()
            .semantics()
            .call_site(call.id())
            .expect("fixture call belongs to its procedure");
        let named = low_level_boundary(
            &CallDispatchBoundaryKind::UnresolvedWithTarget {
                status: DefinitionLookupStatus::NotFound,
                callee_text: "com.example.Missing.run".into(),
                normalized_static_owner: Some("com.example.Missing".into()),
            },
            SemanticLanguage::Standard(Language::Java),
            Some(semantic_call),
            None,
        );

        let target = named
            .unmaterialized_external_target()
            .expect("structured callee and semantic call mint a model key");
        assert_eq!(target.owner_fqn(), "com.example.Missing");
        assert_eq!(target.member(), "run");
        assert!(!target.has_receiver());
        assert!(matches!(
            named.kind,
            DispatchBoundaryKind::External(Some(ref locator)) if locator == target.locator()
        ));
        assert!(matches!(named.proof, ProofStatus::Unproven(_)));
        assert!(matches!(
            named.completeness,
            EvidenceCompleteness::Partial(_)
        ));
        assert_eq!(
            dispatch_coverage(Some(DefinitionLookupStatus::NotFound), &[named]),
            CandidateCoverage::Open,
            "a bindable model key must not turn an unresolved lookup exhaustive"
        );

        let unnamed = low_level_boundary(
            &CallDispatchBoundaryKind::Unresolved(DefinitionLookupStatus::NotFound),
            SemanticLanguage::Standard(Language::Java),
            Some(semantic_call),
            None,
        );
        assert_eq!(unnamed.kind, DispatchBoundaryKind::Unresolved);
        assert!(unnamed.target_locator().is_none());
        assert!(unnamed.unmaterialized_external_target().is_none());
    }

    #[test]
    fn adapter_proven_local_callback_bypasses_source_rediscovery() {
        let source = "export function caller() { const callback = () => 1; callback(); }\n";
        let (fixture, call) = semantic_call_fixture_for("callback.ts", source);
        let declared_target = match &call
            .procedure()
            .semantics()
            .call_site(call.id())
            .expect("call belongs to its procedure")
            .declared_targets
        {
            CallableTargetResolution::Proven(CallableTarget::Local(target)) => *target,
            other => panic!("expected one adapter-proven local callback, got {other:?}"),
        };
        let artifact = Arc::clone(call.procedure().artifact());
        let mut session = fixture
            .analyzer
            .semantic_oracle_provider()
            .prepare_call_dispatch_session(artifact);
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let outcome = session
            .resolve_call(&call, &mut SemanticRequest::new(&mut budget, &cancellation))
            .expect("adapter-proven callback dispatch");
        let SemanticOutcome::Complete { value, .. } = outcome else {
            panic!("adapter-proven local dispatch must be complete: {outcome:?}");
        };

        assert_eq!(value.coverage(), CandidateCoverage::Exhaustive);
        assert_eq!(value.candidates().len(), 1);
        assert_eq!(value.candidates()[0].target().id(), declared_target);
        assert_eq!(value.candidates()[0].proof(), &ProofStatus::Proven);
        assert_eq!(
            value.candidates()[0].completeness(),
            &EvidenceCompleteness::Complete
        );
        assert!(!value.candidates()[0].provenance().is_empty());
        assert_eq!(budget.used().source_bytes, source.len());
        assert!(session.retained_bytes() >= source.len());
    }

    #[test]
    fn kotlin_adapter_proven_local_callback_bypasses_source_rediscovery() {
        let source = "fun caller() { val callback = { 1 }; callback() }\n";
        let (fixture, call) =
            semantic_call_fixture_for_language(Language::Kotlin, "callback.kt", source);
        let declared_target = match &call
            .procedure()
            .semantics()
            .call_site(call.id())
            .expect("call belongs to its procedure")
            .declared_targets
        {
            CallableTargetResolution::Proven(CallableTarget::Local(target)) => *target,
            other => panic!("expected one adapter-proven local callback, got {other:?}"),
        };
        let artifact = Arc::clone(call.procedure().artifact());
        let mut session = fixture
            .analyzer
            .semantic_oracle_provider()
            .prepare_call_dispatch_session(artifact);
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let outcome = session
            .resolve_call(&call, &mut SemanticRequest::new(&mut budget, &cancellation))
            .expect("adapter-proven Kotlin callback dispatch");
        let SemanticOutcome::Complete { value, .. } = outcome else {
            panic!("adapter-proven Kotlin local dispatch must be complete: {outcome:?}");
        };

        assert_eq!(value.coverage(), CandidateCoverage::Exhaustive);
        assert_eq!(value.candidates().len(), 1);
        assert_eq!(value.candidates()[0].target().id(), declared_target);
        assert_eq!(value.candidates()[0].proof(), &ProofStatus::Proven);
        assert_eq!(
            value.candidates()[0].completeness(),
            &EvidenceCompleteness::Complete
        );
        assert!(!value.candidates()[0].provenance().is_empty());
        assert_eq!(budget.used().source_bytes, source.len());
        assert!(session.retained_bytes() >= source.len());
    }

    #[test]
    fn go_adapter_proven_local_callback_bypasses_source_rediscovery() {
        let source = "package sample\nfunc caller() { callback := func() {}; callback() }\n";
        let (fixture, call) =
            semantic_call_fixture_for_language(Language::Go, "callback.go", source);
        let declared_target = match &call
            .procedure()
            .semantics()
            .call_site(call.id())
            .expect("call belongs to its procedure")
            .declared_targets
        {
            CallableTargetResolution::Proven(CallableTarget::Local(target)) => *target,
            other => panic!("expected one adapter-proven Go local callback, got {other:?}"),
        };
        let artifact = Arc::clone(call.procedure().artifact());
        let mut session = fixture
            .analyzer
            .semantic_oracle_provider()
            .prepare_call_dispatch_session(artifact);
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let outcome = session
            .resolve_call(&call, &mut SemanticRequest::new(&mut budget, &cancellation))
            .expect("adapter-proven Go callback dispatch");
        let SemanticOutcome::Complete { value, .. } = outcome else {
            panic!("adapter-proven Go local dispatch must be complete: {outcome:?}");
        };

        assert_eq!(value.coverage(), CandidateCoverage::Exhaustive);
        assert_eq!(value.candidates().len(), 1);
        assert_eq!(value.candidates()[0].target().id(), declared_target);
        assert_eq!(value.candidates()[0].proof(), &ProofStatus::Proven);
        assert_eq!(
            value.candidates()[0].completeness(),
            &EvidenceCompleteness::Complete
        );
        assert!(!value.candidates()[0].provenance().is_empty());
        assert_eq!(budget.used().source_bytes, source.len());
        assert!(session.retained_bytes() >= source.len());
    }

    #[test]
    fn cpp_adapter_proven_local_function_pointer_bypasses_source_rediscovery() {
        let source =
            "void target() {}\nvoid caller() { void (*callback)() = &target; callback(); }\n";
        let fixture = AnalyzerFixture::new_for_language(Language::Cpp, &[("callback.cpp", source)]);
        let file = ProjectFile::new(fixture.project_root(), "callback.cpp");
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("C++ semantic materialization")
            .available_value()
            .cloned()
            .expect("C++ semantic artifact");
        let proven_calls = calls_in_source_order(&artifact)
            .into_iter()
            .filter(|call| {
                matches!(
                    call.procedure()
                        .semantics()
                        .call_site(call.id())
                        .expect("call belongs to its procedure")
                        .declared_targets,
                    CallableTargetResolution::Proven(CallableTarget::Local(_))
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            proven_calls.len(),
            1,
            "the stable pointer invocation is the sole exact local call: {:#?}",
            calls_in_source_order(&artifact)
                .iter()
                .map(|call| call
                    .procedure()
                    .semantics()
                    .call_site(call.id())
                    .expect("call belongs to its procedure"))
                .collect::<Vec<_>>()
        );

        let call = &proven_calls[0];
        let declared_target = match call
            .procedure()
            .semantics()
            .call_site(call.id())
            .expect("call belongs to its procedure")
            .declared_targets
        {
            CallableTargetResolution::Proven(CallableTarget::Local(target)) => target,
            ref other => panic!("expected one C++ local target, got {other:?}"),
        };
        let mut session = fixture
            .analyzer
            .semantic_oracle_provider()
            .prepare_call_dispatch_session(Arc::clone(call.procedure().artifact()));
        let mut dispatch_budget = SemanticBudget::default();
        let outcome = session
            .resolve_call(
                call,
                &mut SemanticRequest::new(&mut dispatch_budget, &cancellation),
            )
            .expect("adapter-proven C++ pointer dispatch");
        let SemanticOutcome::Complete { value, .. } = outcome else {
            panic!("adapter-proven C++ local dispatch must be complete: {outcome:?}");
        };

        assert_eq!(value.coverage(), CandidateCoverage::Exhaustive);
        assert_eq!(value.candidates().len(), 1);
        assert_eq!(value.candidates()[0].target().id(), declared_target);
        assert_eq!(value.candidates()[0].proof(), &ProofStatus::Proven);
        assert_eq!(
            value.candidates()[0].completeness(),
            &EvidenceCompleteness::Complete
        );
    }

    #[test]
    fn unsafe_cpp_function_pointer_bindings_retain_no_initializer_target() {
        for (name, source) in [
            (
                "reassigned.cpp",
                "void first() {}\nvoid second() {}\nvoid caller() { void (*callback)() = &first; callback = &second; callback(); }\n",
            ),
            (
                "copied.cpp",
                "void target() {}\nvoid caller() { void (*callback)() = &target; auto escaped = callback; callback(); }\n",
            ),
            (
                "address_escaped.cpp",
                "void target() {}\nvoid caller() { void (*callback)() = &target; auto escaped = &callback; callback(); }\n",
            ),
            (
                "passed.cpp",
                "void target() {}\nvoid consume(void (*)()) {}\nvoid caller() { void (*callback)() = &target; consume(callback); callback(); }\n",
            ),
            (
                "nonempty_signature.cpp",
                "void target(int) {}\nvoid caller() { void (*callback)(int) = &target; callback(1); }\n",
            ),
        ] {
            let fixture = AnalyzerFixture::new_for_language(Language::Cpp, &[(name, source)]);
            let file = ProjectFile::new(fixture.project_root(), name);
            let cancellation = CancellationToken::default();
            let mut budget = SemanticBudget::default();
            let artifact = fixture
                .analyzer
                .materialize_program_semantics(
                    &file,
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .expect("C++ semantic materialization")
                .available_value()
                .cloned()
                .expect("C++ semantic artifact");

            assert!(
                calls_in_source_order(&artifact).into_iter().all(|call| {
                    !matches!(
                        call.procedure()
                            .semantics()
                            .call_site(call.id())
                            .expect("call belongs to its procedure")
                            .declared_targets,
                        CallableTargetResolution::Proven(CallableTarget::Local(_))
                    )
                }),
                "{name} must not retain an initializer target"
            );
        }
    }

    #[test]
    fn ruby_adapter_proven_local_lambda_bypasses_source_rediscovery() {
        let source = "def caller\n  local = ->(value) { value }\n  local.(1)\nend\n";
        let (fixture, call) =
            semantic_call_fixture_for_language(Language::Ruby, "callback.rb", source);
        let declared_target = match call
            .procedure()
            .semantics()
            .call_site(call.id())
            .expect("call belongs to its procedure")
            .declared_targets
        {
            CallableTargetResolution::Proven(CallableTarget::Local(target)) => target,
            ref other => panic!("expected one adapter-proven Ruby lambda, got {other:?}"),
        };
        let artifact = Arc::clone(call.procedure().artifact());
        let mut session = fixture
            .analyzer
            .semantic_oracle_provider()
            .prepare_call_dispatch_session(artifact);
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let outcome = session
            .resolve_call(&call, &mut SemanticRequest::new(&mut budget, &cancellation))
            .expect("adapter-proven Ruby lambda dispatch");
        let SemanticOutcome::Complete { value, .. } = outcome else {
            panic!("adapter-proven Ruby local dispatch must be complete: {outcome:?}");
        };

        assert_eq!(value.coverage(), CandidateCoverage::Exhaustive);
        assert_eq!(value.candidates().len(), 1);
        assert_eq!(value.candidates()[0].target().id(), declared_target);
        assert_eq!(value.candidates()[0].proof(), &ProofStatus::Proven);
        assert_eq!(
            value.candidates()[0].completeness(),
            &EvidenceCompleteness::Complete
        );
    }

    fn assert_declared_binding_shortcut_is_skipped(language: Language, name: &str, source: &str) {
        let (fixture, call) = semantic_call_fixture_for_language(language, name, source);
        assert!(matches!(
            call.procedure()
                .semantics()
                .call_site(call.id())
                .expect("call belongs to its procedure")
                .declared_targets,
            CallableTargetResolution::Proven(CallableTarget::Local(_))
        ));
        let artifact = Arc::clone(call.procedure().artifact());
        let mut session = fixture
            .analyzer
            .semantic_oracle_provider()
            .prepare_call_dispatch_session(artifact);
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let outcome = session
            .resolve_declared_indirect_local_call(
                &call,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("declared binding shortcut eligibility check");

        assert!(outcome.is_none());
        assert_eq!(budget.used(), SemanticWork::default());
        assert_eq!(session.retained_bytes(), 0);
    }

    #[test]
    fn direct_go_callable_syntax_stays_on_source_resolver_route() {
        assert_declared_binding_shortcut_is_skipped(
            Language::Go,
            "call.go",
            "package sample\nfunc caller() { defer func() {}() }\n",
        );
    }

    #[test]
    fn direct_js_ts_callable_syntax_stays_on_source_resolver_route() {
        assert_declared_binding_shortcut_is_skipped(
            Language::TypeScript,
            "call.ts",
            "export function caller() { (() => 1)(); }\n",
        );
    }

    #[test]
    fn resolver_call_after_declared_local_callback_does_not_recharge_source() {
        let source = "function target() {}\nexport function caller() { const callback = () => 1; callback(); target(); }\n";
        let fixture =
            AnalyzerFixture::new_for_language(Language::TypeScript, &[("callback.ts", source)]);
        let file = ProjectFile::new(fixture.project_root(), "callback.ts");
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("TypeScript semantic materialization")
            .available_value()
            .cloned()
            .expect("TypeScript semantic artifact");
        let calls = calls_in_source_order(&artifact);
        assert_eq!(calls.len(), 2, "fixture has callback and named calls");
        assert!(matches!(
            calls[0]
                .procedure()
                .semantics()
                .call_site(calls[0].id())
                .expect("callback call row")
                .declared_targets,
            CallableTargetResolution::Proven(CallableTarget::Local(_))
        ));

        let mut session = fixture
            .analyzer
            .semantic_oracle_provider()
            .prepare_call_dispatch_session(artifact);
        let mut budget = SemanticBudget::default();
        for call in &calls {
            let outcome = session
                .resolve_call(call, &mut SemanticRequest::new(&mut budget, &cancellation))
                .expect("prepared dispatch");
            assert!(outcome.available_value().is_some(), "{outcome:?}");
        }
        assert_eq!(budget.used().source_bytes, source.len());
    }

    #[test]
    fn prepared_dispatch_session_rejects_a_same_key_distinct_artifact_allocation() {
        let fixture = AnalyzerFixture::new_for_language(
            Language::TypeScript,
            &[(
                "call.ts",
                "function target() {}\nexport function caller() { target(); }\n",
            )],
        );
        let second_workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            Arc::new(fixture.test_project().clone()),
            AnalyzerConfig::default(),
        )
        .expect("second workspace over the same immutable project");
        let file = ProjectFile::new(fixture.project_root(), "call.ts");
        let cancellation = CancellationToken::default();
        let materialize = |workspace: &WorkspaceAnalyzer| {
            let mut budget = SemanticBudget::default();
            workspace
                .materialize_program_semantics(
                    &file,
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .expect("TypeScript semantic materialization")
                .available_value()
                .cloned()
                .expect("TypeScript semantic artifact")
        };
        let selected = materialize(&fixture.analyzer);
        let same_key_sibling = materialize(&second_workspace);
        assert_eq!(selected.key(), same_key_sibling.key());
        assert!(!Arc::ptr_eq(&selected, &same_key_sibling));
        let sibling_call = first_call_in_artifact(&same_key_sibling);
        let mut session = fixture
            .analyzer
            .semantic_oracle_provider()
            .prepare_call_dispatch_session(selected);
        let mut budget = SemanticBudget::default();
        let error = session
            .resolve_call(
                &sibling_call,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect_err("same-key handles from a distinct allocation are rejected");
        assert!(matches!(error, SemanticProviderError::InvalidIdentity(_)));

        let cancelled = CancellationToken::default();
        cancelled.cancel();
        let outcome = session
            .resolve_call(
                &sibling_call,
                &mut SemanticRequest::new(&mut budget, &cancelled),
            )
            .expect("cancellation takes precedence over identity validation");
        assert!(matches!(outcome, SemanticOutcome::Cancelled { .. }));
    }

    #[test]
    fn prepared_dispatch_freezes_source_after_first_demand_but_new_session_revalidates() {
        let source = "function first() {}\nfunction second() {}\nexport function caller() { first(); second(); }\n";
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        let file = ProjectFile::new(&root, "call.ts");
        file.write(source).expect("write TypeScript fixture");
        let base: Arc<dyn Project> = Arc::new(TestProject::new(&root, Language::TypeScript));
        let overlay = Arc::new(OverlayProject::new(base));
        assert!(overlay.set(file.abs_path(), source.to_owned()));
        let project: Arc<dyn Project> = overlay.clone();
        let workspace =
            WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
                .expect("overlay workspace");
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("initial overlay materialization")
            .available_value()
            .cloned()
            .expect("initial overlay artifact");
        let calls = calls_in_source_order(&artifact);
        assert_eq!(calls.len(), 2, "fixture has two call sites");
        let oracle = workspace.semantic_oracle_provider();

        let mut expected_budget = SemanticBudget::default();
        let expected_second = oracle
            .resolve_call(
                &calls[1],
                &mut SemanticRequest::new(&mut expected_budget, &cancellation),
            )
            .expect("second-call baseline before overlay mutation");
        let expected_second_shape = dispatch_target_shape(&expected_second);

        let mut prepared = oracle.prepare_call_dispatch_session(Arc::clone(&artifact));
        let mut prepared_budget = SemanticBudget::default();
        let first = prepared
            .resolve_call(
                &calls[0],
                &mut SemanticRequest::new(&mut prepared_budget, &cancellation),
            )
            .expect("first demand freezes the caller snapshot");
        assert!(!dispatch_target_shape(&first).is_empty());

        // The prepared contract freezes the caller source/tree, not every
        // downstream declaration snapshot. Keep the local target declarations
        // at the same coordinates while changing the caller generation, so a
        // retained session can still materialize its frozen `second` target.
        let changed_source = source.replace("first(); second();", "first(); first(); ");
        assert_eq!(changed_source.len(), source.len());
        assert_ne!(changed_source, source);
        assert!(overlay.set(file.abs_path(), changed_source));
        let retained_second = prepared
            .resolve_call(
                &calls[1],
                &mut SemanticRequest::new(&mut prepared_budget, &cancellation),
            )
            .expect("the active prepared window remains on its frozen source snapshot");
        assert_eq!(
            dispatch_target_shape(&retained_second),
            expected_second_shape
        );

        let mut fresh = oracle.prepare_call_dispatch_session(artifact);
        let mut fresh_budget = SemanticBudget::default();
        let error = fresh
            .resolve_call(
                &calls[1],
                &mut SemanticRequest::new(&mut fresh_budget, &cancellation),
            )
            .expect_err("a new session revalidates the old handle against the new overlay");
        assert!(matches!(error, SemanticProviderError::InvalidIdentity(_)));
    }

    #[test]
    fn later_lookup_truncation_exceeds_nested_entries_after_source_was_paid_once() {
        let source = "import { open } from \"third-party\";\nexport function caller() { open(\"a\"); open(\"b\"); }\n";
        let fixture =
            AnalyzerFixture::new_for_language(Language::TypeScript, &[("calls.ts", source)]);
        let file = ProjectFile::new(fixture.project_root(), "calls.ts");
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("TypeScript materialization")
            .available_value()
            .cloned()
            .expect("TypeScript artifact");
        let calls = calls_in_source_order(&artifact);
        assert_eq!(calls.len(), 2, "fixture has two external calls");
        let oracle = fixture.analyzer.semantic_oracle_provider();

        let mut calibration = oracle.prepare_call_dispatch_session(Arc::clone(&artifact));
        let mut calibration_budget = SemanticBudget::default();
        calibration
            .resolve_call(
                &calls[0],
                &mut SemanticRequest::new(&mut calibration_budget, &cancellation),
            )
            .expect("calibrate first-call nested work");
        let first_nested = calibration_budget.used().nested_entries;
        assert!(first_nested > 0);

        let mut limits = SemanticBudget::default().limits();
        limits.source_bytes = source.len();
        limits.nested_entries = first_nested.saturating_add(1);
        let mut budget = SemanticBudget::new(limits).expect("positive tight semantic limits");
        let mut prepared = oracle.prepare_call_dispatch_session(Arc::clone(&artifact));
        let first = prepared
            .resolve_call(
                &calls[0],
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("first call fits the one-source budget");
        assert!(first.available_value().is_some(), "{first:?}");
        assert_eq!(budget.used().source_bytes, source.len());
        assert_eq!(budget.remaining().nested_entries, 1);

        let truncated_lookup = || CallDispatchLookup {
            status: Some(DefinitionLookupStatus::Ambiguous),
            boundaries: vec![CallDispatchBoundaryKind::Truncated],
            truncated: true,
            budget_exhausted: true,
            work: CallRelationWork {
                examined_candidates: 1,
                ..CallRelationWork::default()
            },
            ..CallDispatchLookup::default()
        };
        let second = oracle
            .resolve_prepared_call(
                &calls[1],
                PreparedCallDispatch {
                    lookup: truncated_lookup(),
                },
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("later truncated lookup remains a typed exhaustion");
        let SemanticOutcome::ExceededBudget {
            partial: None,
            exceeded,
            work,
        } = second
        else {
            panic!("a partial that cannot be admitted must be dropped: {second:?}");
        };
        assert_eq!(exceeded.dimension(), SemanticBudgetDimension::NestedEntries);
        assert_eq!(work.source_bytes, 0);
        assert_eq!(budget.used().source_bytes, source.len());

        let mut retaining = oracle.prepare_call_dispatch_session(artifact);
        let mut retaining_budget = SemanticBudget::default();
        let first = retaining
            .resolve_call(
                &calls[0],
                &mut SemanticRequest::new(&mut retaining_budget, &cancellation),
            )
            .expect("first call fits before the retainable truncation");
        assert!(first.available_value().is_some(), "{first:?}");
        assert_eq!(retaining_budget.used().source_bytes, source.len());
        let retained = oracle
            .resolve_prepared_call(
                &calls[1],
                PreparedCallDispatch {
                    lookup: truncated_lookup(),
                },
                &mut SemanticRequest::new(&mut retaining_budget, &cancellation),
            )
            .expect("the admitted later truncation retains its typed partial");
        let SemanticOutcome::ExceededBudget {
            partial: Some(_),
            exceeded,
            work,
        } = retained
        else {
            panic!("a partial with sufficient admission budget must be retained: {retained:?}");
        };
        assert_eq!(exceeded.dimension(), SemanticBudgetDimension::NestedEntries);
        assert_eq!(work.source_bytes, 0);
        assert_eq!(retaining_budget.used().source_bytes, source.len());
    }

    #[test]
    fn canonical_go_package_function_can_be_an_unmaterialized_external_target() {
        let call = semantic_call_handle();
        let semantic_call = call
            .procedure()
            .semantics()
            .call_site(call.id())
            .expect("call belongs to its procedure");
        let proof = ExactExternalCallProof::go_package_function("os.Open", 0);
        let target = synthetic_unmaterialized_external(
            "os.Open",
            SemanticLanguage::Standard(Language::Go),
            semantic_call,
            Some(&proof),
            None,
        )
        .expect("the Go resolver-proven import path is a canonical owner");

        assert_eq!(target.owner_fqn(), "os");
        assert_eq!(target.member(), "Open");
        assert!(!target.has_receiver());
        assert_eq!(target.arity(), 0);
        let tuple_proof =
            ExactExternalCallProof::go_package_function("example.com/model.Binary", 2);
        let tuple_target = synthetic_unmaterialized_external(
            "example.com/model.Binary",
            SemanticLanguage::Standard(Language::Go),
            semantic_call,
            Some(&tuple_proof),
            None,
        )
        .expect("effective tuple-expansion arity");
        assert_eq!(
            tuple_target.arity(),
            2,
            "the semantic fixture has no written arguments; arity comes from the resolver proof"
        );
        let python_proof = ExactExternalCallProof::python_imported_call("subprocess.run", 2);
        let python_target = synthetic_unmaterialized_external(
            "subprocess.run",
            SemanticLanguage::Standard(Language::Python),
            semantic_call,
            Some(&python_proof),
            None,
        )
        .expect("the Python resolver-owned import identity admits a single-segment module");
        assert_eq!(python_target.owner_fqn(), "subprocess");
        assert_eq!(python_target.member(), "run");
        assert_eq!(python_target.arity(), 2);
        assert!(
            synthetic_unmaterialized_external(
                "subprocess.run",
                SemanticLanguage::Standard(Language::Python),
                semantic_call,
                None,
                None,
            )
            .is_none(),
            "the same Python spelling without import proof stays unsupported"
        );
        assert!(
            synthetic_unmaterialized_external(
                "URLDecoder.decode",
                SemanticLanguage::Standard(Language::Java),
                semantic_call,
                None,
                None,
            )
            .is_none(),
            "a single-segment owner without Go import evidence stays unsupported"
        );
        assert!(
            synthetic_unmaterialized_external(
                "os.Open",
                SemanticLanguage::Standard(Language::Go),
                semantic_call,
                None,
                None,
            )
            .is_none(),
            "a Go spelling without the resolver-owned shape is not an exact target"
        );
    }

    #[test]
    fn go_package_proof_overrides_a_lowered_receiver_for_declared_package_name() {
        let source = r#"package main
import "example.com/driver"
func caller() { db.Open() }
"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Go, &[("main.go", source)]);
        let file = ProjectFile::new(fixture.project_root(), "main.go");
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("Go semantic materialization")
            .available_value()
            .cloned()
            .expect("Go semantic artifact");
        let call = first_call_in_artifact(&artifact);
        let semantic_call = call
            .procedure()
            .semantics()
            .call_site(call.id())
            .expect("call belongs to its procedure");
        assert!(
            semantic_call.receiver.is_some(),
            "the syntax-only lowering treats the non-terminal package name as a receiver"
        );

        let proof = ExactExternalCallProof::go_package_function("example.com/driver.Open", 0);
        let target = synthetic_unmaterialized_external(
            "example.com/driver.Open",
            SemanticLanguage::Standard(Language::Go),
            semantic_call,
            Some(&proof),
            None,
        )
        .expect("resolver-owned package proof");

        assert_eq!(target.owner_fqn(), "example.com/driver");
        assert_eq!(target.member(), "Open");
        assert_eq!(target.arity(), 0);
        assert!(
            !target.has_receiver(),
            "staticness comes from exact package resolution, not selector lowering"
        );

        let gap = scoped_call_dispatch_gap(call.procedure().semantics(), semantic_call)
            .expect("syntax-only receiver lowering carries a dispatch gap");
        assert_eq!(gap.capability, SemanticCapability::DynamicDispatch);
        let oracle = fixture.analyzer.semantic_oracle_provider();
        let mut dispatch_budget = SemanticBudget::default();
        let resolved = oracle
            .resolve_prepared_call(
                &call,
                PreparedCallDispatch {
                    lookup: CallDispatchLookup {
                        status: Some(DefinitionLookupStatus::UnresolvableImportBoundary),
                        boundary: Some(BoundaryStatus::ExternalIndexed),
                        boundaries: vec![CallDispatchBoundaryKind::External {
                            callee_text: Some("example.com/driver.Open".into()),
                            normalized_static_owner: None,
                            external_callee_identity: None,
                        }],
                        call_application: CallApplicationKind::PackageFunction,
                        exact_external_call: Some(proof),
                        ..CallDispatchLookup::default()
                    },
                },
                &mut SemanticRequest::new(&mut dispatch_budget, &cancellation),
            )
            .expect("resolver-owned package dispatch");
        let SemanticOutcome::Complete {
            value: resolved, ..
        } = resolved
        else {
            panic!("the exact static package proof closes the syntax-only gap: {resolved:#?}");
        };
        let [boundary] = resolved.boundaries() else {
            panic!("one external package boundary: {resolved:#?}");
        };
        let target = boundary
            .unmaterialized_external_target
            .as_ref()
            .expect("external package identity");
        assert!(!target.has_receiver());
        assert_eq!(target.arity(), 0);
        assert_eq!(
            boundary.proven_external_receiver_shape(),
            Some(false),
            "the resolver-owned static call shape is exact even though the external body is absent"
        );

        let mut handcrafted = boundary.clone();
        handcrafted.unmaterialized_external_target = Some(UnmaterializedExternalTarget::new(
            target.owner_fqn(),
            target.member(),
            target.arity(),
            target.has_receiver(),
            target.locator().clone(),
        ));
        assert!(
            handcrafted.validate_for_call(&call).is_err(),
            "an ordinary Go target cannot bypass a mismatched lowered receiver merely by naming Go"
        );
        assert_eq!(
            handcrafted.proven_external_receiver_shape(),
            None,
            "a syntax-derived unmaterialized target has no independent receiver authority"
        );
        let mut unresolved = boundary.clone();
        unresolved.kind = DispatchBoundaryKind::Unresolved;
        unresolved.unmaterialized_external_target = None;
        assert_eq!(unresolved.proven_external_receiver_shape(), None);
        let mut unproven = boundary.clone();
        unproven.proof = ProofStatus::Unproven("test near miss".into());
        assert_eq!(unproven.proven_external_receiver_shape(), None);
    }

    #[test]
    fn only_closed_exact_go_receiver_dispatch_discharges_the_dynamic_gap() {
        let source = r#"package main
import "testing"
func caller(t *testing.T) { t.Fatal("stop") }
"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Go, &[("main.go", source)]);
        let file = ProjectFile::new(fixture.project_root(), "main.go");
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("Go semantic materialization")
            .available_value()
            .cloned()
            .expect("Go semantic artifact");
        let call = first_call_in_artifact(&artifact);
        let semantic_call = call
            .procedure()
            .semantics()
            .call_site(call.id())
            .expect("call belongs to its procedure");
        assert!(semantic_call.receiver.is_some(), "receiver call fixture");
        let gap = scoped_call_dispatch_gap(call.procedure().semantics(), semantic_call)
            .expect("Go receiver call carries a dynamic-dispatch gap");
        assert_eq!(gap.capability, SemanticCapability::DynamicDispatch);
        assert!(matches!(
            gap.kind,
            SemanticGapKind::Unknown | SemanticGapKind::Unproven
        ));

        let oracle = fixture.analyzer.semantic_oracle_provider();
        let lookup = |exact_external_call, dispatch_extensibility| CallDispatchLookup {
            status: Some(DefinitionLookupStatus::UnresolvableImportBoundary),
            boundary: Some(BoundaryStatus::ExternalIndexed),
            boundaries: vec![CallDispatchBoundaryKind::External {
                callee_text: Some("testing.T.Fatal".into()),
                normalized_static_owner: None,
                external_callee_identity: None,
            }],
            call_application:
                crate::analyzer::usages::get_definition::CallApplicationKind::BoundReceiver,
            dispatch_extensibility,
            exact_external_call,
            ..CallDispatchLookup::default()
        };

        let mut closed_budget = SemanticBudget::default();
        let closed = oracle
            .resolve_prepared_call(
                &call,
                PreparedCallDispatch {
                    lookup: lookup(
                        Some(ExactExternalCallProof::go_concrete_receiver(
                            "testing.T.Fatal",
                            1,
                        )),
                        Some(DispatchExtensibility::Closed),
                    ),
                },
                &mut SemanticRequest::new(&mut closed_budget, &cancellation),
            )
            .expect("closed Go receiver dispatch");
        let SemanticOutcome::Complete { value: closed, .. } = closed else {
            panic!("closed exact Go dispatch must be complete: {closed:#?}");
        };
        assert_eq!(closed.coverage(), CandidateCoverage::Exhaustive);
        assert!(closed.candidates().is_empty(), "{closed:#?}");
        let [boundary] = closed.boundaries() else {
            panic!("closed dispatch keeps one external summary arm: {closed:#?}");
        };
        assert!(matches!(
            boundary.kind,
            DispatchBoundaryKind::External(Some(_))
        ));
        assert_eq!(boundary.proof, ProofStatus::Proven);
        let target = boundary
            .unmaterialized_external_target
            .as_ref()
            .expect("external receiver identity");
        assert_eq!(target.owner_fqn(), "testing.T");
        assert_eq!(target.member(), "Fatal");
        assert_eq!(target.arity(), 1);
        assert!(target.has_receiver());
        assert_eq!(boundary.proven_external_receiver_shape(), Some(true));

        for dispatch_extensibility in [None, Some(DispatchExtensibility::Open)] {
            let mut budget = SemanticBudget::default();
            let open = oracle
                .resolve_prepared_call(
                    &call,
                    PreparedCallDispatch {
                        lookup: lookup(None, dispatch_extensibility),
                    },
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .expect("open Go receiver dispatch");
            let SemanticOutcome::Unproven { partial: open, .. } = open else {
                panic!("unproven extensibility must keep dispatch open: {open:#?}");
            };
            assert_eq!(open.coverage(), CandidateCoverage::Open);
            assert!(open.candidates().is_empty(), "{open:#?}");
            assert_eq!(
                open.boundaries()
                    .iter()
                    .filter(|boundary| matches!(boundary.kind, DispatchBoundaryKind::External(_)))
                    .count(),
                1,
                "{open:#?}"
            );
            assert!(
                open.boundaries()
                    .iter()
                    .any(|boundary| matches!(boundary.kind, DispatchBoundaryKind::Unresolved)),
                "{open:#?}"
            );
            assert!(
                open.boundaries()
                    .iter()
                    .all(|boundary| !matches!(boundary.kind, DispatchBoundaryKind::Truncated)),
                "{open:#?}"
            );
        }
    }

    fn external_signature(
        label: &str,
        parameter_label: &str,
        parameter_type: Option<&str>,
    ) -> SignatureMetadata {
        let metadata = SignatureMetadata::new(
            label,
            vec![ParameterMetadata::new(
                parameter_label,
                0,
                parameter_label.len(),
            )],
        )
        .with_callable_arity(CallableArity::exact(1));
        match parameter_type {
            Some(parameter_type) => {
                metadata.with_callable_parameter_types(vec![parameter_type.to_owned()])
            }
            None => metadata,
        }
    }

    #[test]
    fn exact_external_formal_contract_collapses_equivalent_metadata() {
        let contract = agreed_external_formal_contract([
            external_signature("execute(String)", "value", Some("String")),
            external_signature("execute(String)", "value", Some("String")),
        ])
        .expect("equivalent metadata is exact");

        assert_eq!(contract.label(), "execute(String)");
        assert_eq!(contract.parameter_count(), 1);
        assert_eq!(contract.arity(), Some(CallableArity::exact(1)));
        assert_eq!(contract.parameters()[0].label(), "value");
        assert_eq!(contract.parameters()[0].declared_type(), Some("String"));
        assert!(!contract.parameters()[0].optional());
        assert!(!contract.parameters()[0].repeated());
    }

    #[test]
    fn exact_external_formal_contract_rejects_same_arity_overloads() {
        let contract = agreed_external_formal_contract([
            external_signature("execute(String)", "value", Some("String")),
            external_signature("execute(int)", "value", Some("int")),
        ]);

        assert!(contract.is_none());
    }

    #[test]
    fn exact_external_formal_contract_rejects_missing_discriminators() {
        let contract = agreed_external_formal_contract([
            external_signature("execute(String)", "value", None),
            external_signature("execute(String)", "value", Some("String")),
        ]);

        assert!(contract.is_none());
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
                    scope: crate::analyzer::topology::DependencyScope::Unknown,
                    declared_by: None,
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

    /// A concrete base method, one subclass that overrides it, and a call
    /// written against the base type. Each member lives in its own file so a
    /// retained candidate can be named by the file it came from.
    const CONCRETE_OVERRIDE_FILES: [(&str, &str); 3] = [
        (
            "overrides/BaseHandler.java",
            "package overrides;\n\npublic class BaseHandler {\n    public String handle(String input) {\n        return \"constant\";\n    }\n}\n",
        ),
        (
            "overrides/PassthroughHandler.java",
            "package overrides;\n\npublic class PassthroughHandler extends BaseHandler {\n    @Override\n    public String handle(String input) {\n        return input;\n    }\n}\n",
        ),
        (
            "overrides/Caller.java",
            "package overrides;\n\npublic class Caller {\n    public String run(BaseHandler handler, String param) {\n        return handler.handle(param);\n    }\n}\n",
        ),
    ];

    /// Resolve the single call in `overrides/Caller.java` with an explicitly
    /// stated class-hierarchy expansion, and report the workspace-relative file
    /// each retained candidate came from together with its proof status.
    ///
    /// The expansion is passed in rather than read from the environment because
    /// both settings have to be exercised in one test binary, and the
    /// `BIFROST_CHA_CONCRETE_OVERRIDES` variable is read once per process.
    fn concrete_override_dispatch_candidates(
        expansion: crate::analyzer::DispatchHierarchyExpansion,
    ) -> Vec<(String, ProofStatus)> {
        let fixture = AnalyzerFixture::new_for_language(Language::Java, &CONCRETE_OVERRIDE_FILES);
        let file = ProjectFile::new(fixture.project_root(), "overrides/Caller.java");
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("Java semantic materialization")
            .available_value()
            .cloned()
            .expect("Java semantic artifact");
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| !procedure.call_sites().is_empty())
            .expect("the calling procedure");
        let call = artifact
            .procedure_handle(procedure.id())
            .and_then(|procedure| {
                procedure.call_site_handle(procedure.semantics().call_sites()[0].id)
            })
            .expect("scoped call handle");
        let oracle = WorkspaceSemanticOracle::with_limits_and_expansion(
            &fixture.analyzer,
            OracleLimits::default(),
            expansion,
        );
        let outcome = oracle
            .resolve_call(&call, &mut SemanticRequest::new(&mut budget, &cancellation))
            .expect("concrete override dispatch should run");
        let result = outcome
            .available_value()
            .expect("dispatch retained a result");
        let mut named = result
            .candidates()
            .iter()
            .map(|candidate| {
                (
                    candidate
                        .target()
                        .semantics()
                        .locator()
                        .path()
                        .as_str()
                        .to_owned(),
                    candidate.proof().clone(),
                )
            })
            .collect::<Vec<_>>();
        named.sort_by(|left, right| left.0.cmp(&right.0));
        named
    }

    /// #2277, off: the call resolves to the concrete base method and stops
    /// there. The override is real code that could run, and dispatch does not
    /// offer it, which is exactly the behavior the opt-in exists to change.
    #[test]
    fn a_concrete_call_retains_only_its_static_target_by_default() {
        let candidates =
            concrete_override_dispatch_candidates(crate::analyzer::DispatchHierarchyExpansion::OFF);
        assert_eq!(
            candidates
                .iter()
                .map(|(path, _)| path.as_str())
                .collect::<Vec<_>>(),
            vec!["overrides/BaseHandler.java"],
            "the default must retain the static target and nothing else: {candidates:?}"
        );
    }

    /// #2277, on: the override joins the candidate set, and it joins it as an
    /// unproven candidate while the static target keeps its own proof. This is
    /// the honesty contract stated as a fact about the retained set rather than
    /// as a consequence downstream.
    #[test]
    fn an_enabled_concrete_override_joins_the_set_as_an_unproven_candidate() {
        let candidates = concrete_override_dispatch_candidates(
            crate::analyzer::DispatchHierarchyExpansion::CONCRETE_OVERRIDES,
        );
        assert_eq!(
            candidates
                .iter()
                .map(|(path, _)| path.as_str())
                .collect::<Vec<_>>(),
            vec![
                "overrides/BaseHandler.java",
                "overrides/PassthroughHandler.java",
            ],
            "the enabled expansion must add the override: {candidates:?}"
        );
        assert_eq!(
            candidates[0].1,
            ProofStatus::Proven,
            "the statically resolved concrete target keeps its own proof: {candidates:?}"
        );
        assert!(
            matches!(candidates[1].1, ProofStatus::Unproven(_)),
            "an expanded override is a candidate, never a proven edge: {candidates:?}"
        );
    }

    /// #1599: a boundary outcome is only as complete as its refined external
    /// evidence. The direct named import proves an unmaterialized external
    /// target, but absent dependency discovery and open dispatch prevent a
    /// closed target set, so the outcome is `Unproven`.
    #[test]
    fn undeclared_external_call_dispatch_is_unproven() {
        let (fixture, call) = semantic_call_fixture_for("external.ts", EXTERNAL_CALL_SOURCE);
        let outcome = resolve_external_call(&fixture, &call);
        let SemanticOutcome::Unproven {
            partial: result, ..
        } = outcome
        else {
            panic!("undeclared external dispatch must be Unproven: {outcome:?}");
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
            external_callee_identity: None,
            exact_external_target: None,
            unmaterialized_external_target: None,
            proof: ProofStatus::Proven,
            completeness: EvidenceCompleteness::Complete,
            provenance: Box::new([]),
        };
        let identity_only = |owner| DispatchBoundary {
            kind: DispatchBoundaryKind::External(None),
            external_callee_identity: Some(ResolverOwnedExternalCalleeIdentity::new(
                Language::Go,
                owner,
                "Open",
            )),
            exact_external_target: None,
            unmaterialized_external_target: None,
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
            identity_only("z.example/package"),
            identity_only("a.example/package"),
            boundary(DispatchBoundaryKind::External(None)),
        ];
        boundaries.sort_by(compare_dispatch_boundaries);

        assert_eq!(
            boundaries[1]
                .external_callee_identity()
                .expect("first identity-only boundary")
                .owner_fqn(),
            "a.example/package"
        );
        assert_eq!(
            boundaries[2]
                .external_callee_identity()
                .expect("second identity-only boundary")
                .owner_fqn(),
            "z.example/package"
        );

        assert!(matches!(
            boundaries.as_slice(),
            [
                DispatchBoundary {
                    kind: DispatchBoundaryKind::External(None),
                    ..
                },
                DispatchBoundary {
                    kind: DispatchBoundaryKind::External(None),
                    ..
                },
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
        let work = low_level_dispatch_work(CallRelationWork {
            scanned_files: 1,
            scanned_source_bytes: 128,
            examined_candidates: 7,
        });

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
                exact_external_call: None,
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
                    CallDispatchBoundaryKind::External {
                        callee_text: None,
                        normalized_static_owner: None,
                        external_callee_identity: None,
                    },
                    CallDispatchBoundaryKind::Unresolved(DefinitionLookupStatus::NotFound),
                ],
                exact_external_call: None,
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
                exact_external_call: None,
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
                exact_external_call: None,
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
                exact_external_call: None,
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
            external_callee_identity: None,
            exact_external_target: None,
            unmaterialized_external_target: None,
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
                    CallDispatchBoundaryKind::External {
                        callee_text: None,
                        normalized_static_owner: None,
                        external_callee_identity: None,
                    },
                    CallDispatchBoundaryKind::Unresolved(DefinitionLookupStatus::NotFound),
                ],
                exact_external_call: None,
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
            discharge: SemanticGapDischarge::None,
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
            discharge: SemanticGapDischarge::None,
            detail: "dynamic target discovery is unsupported".into(),
            source: call_row.source,
            evidence: shared_evidence,
        };
        let exceeded_gap = SemanticGap {
            id: SemanticGapId::new(1),
            kind: SemanticGapKind::ExceededBudget,
            budget: Some(exceeded),
            discharge: SemanticGapDischarge::None,
            detail: "dynamic target exploration exceeded its finite budget".into(),
            ..unsupported_gap.clone()
        };
        let mut candidates = Vec::new();
        let mut boundaries = vec![
            DispatchBoundary {
                kind: DispatchBoundaryKind::Unresolved,
                external_callee_identity: None,
                exact_external_target: None,
                unmaterialized_external_target: None,
                proof: ProofStatus::Unproven("unresolved dispatch arm".into()),
                completeness: EvidenceCompleteness::Partial("open dispatch".into()),
                provenance: Box::new([]),
            },
            DispatchBoundary {
                kind: DispatchBoundaryKind::Truncated,
                external_callee_identity: None,
                exact_external_target: None,
                unmaterialized_external_target: None,
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

    fn retained_boundary_work(call: &CallSiteHandle, boundary: DispatchBoundary) -> SemanticWork {
        let mut candidates = Vec::new();
        let mut boundaries = vec![boundary];
        attach_dispatch_provenance(
            call,
            &mut candidates,
            &mut boundaries,
            None,
            None,
            OracleLimits::default(),
        )
        .expect("dispatch provenance projection");
        let result = DispatchResult::new(
            call,
            candidates,
            boundaries,
            CandidateCoverage::Open,
            OracleLimits::default(),
        )
        .expect("valid retained dispatch boundary");
        dispatch_result_work(&result)
    }

    #[test]
    fn retained_boundary_work_includes_owned_locator_payload() {
        let call = semantic_call_handle();
        let locator = call.procedure().semantics().locator().clone();
        let locator_work = semantic_locator_work(&locator);
        let work = retained_boundary_work(
            &call,
            DispatchBoundary {
                kind: DispatchBoundaryKind::Unmaterialized(locator),
                external_callee_identity: None,
                exact_external_target: None,
                unmaterialized_external_target: None,
                proof: ProofStatus::Proven,
                completeness: EvidenceCompleteness::Complete,
                provenance: Box::new([]),
            },
        );

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
    fn retained_exact_external_boundary_work_includes_formal_contract_payload() {
        let call = semantic_call_handle();
        let locator = call.procedure().semantics().locator().clone();
        let locator_work = semantic_locator_work(&locator);
        let artifact = call.procedure().artifact().key().clone();
        let metadata = SignatureMetadata::new(
            "execute(String, int)",
            vec![
                ParameterMetadata::new("value", 0, 5),
                ParameterMetadata::new("radix", 7, 12),
            ],
        )
        .with_callable_arity(CallableArity::exact(2))
        .with_callable_parameter_types(vec!["String".to_owned(), "int".to_owned()]);
        let formal = ExactExternalFormalContract::from_metadata(&metadata)
            .expect("complete formal metadata");
        let formal_entries = formal.parameters().len();
        let formal_text_bytes =
            formal
                .parameters()
                .iter()
                .fold(formal.label().len(), |bytes, parameter| {
                    bytes
                        .saturating_add(parameter.label().len())
                        .saturating_add(parameter.declared_type().map_or(0, str::len))
                });
        let symbol = "execute(java.lang.String,int)";
        let target = ExactExternalProcedureTarget::new(
            artifact.clone(),
            locator.clone(),
            symbol,
            false,
            formal,
        )
        .expect("exact external target");
        let boundary = DispatchBoundary {
            kind: DispatchBoundaryKind::Unmaterialized(locator),
            external_callee_identity: None,
            exact_external_target: Some(target),
            unmaterialized_external_target: None,
            proof: ProofStatus::Proven,
            completeness: EvidenceCompleteness::Complete,
            provenance: Box::new([]),
        };
        assert_eq!(
            boundary.proven_external_receiver_shape(),
            None,
            "a non-Go exact external target does not prove Go receiver shape"
        );
        let work = retained_boundary_work(&call, boundary);

        assert_eq!(
            work.nested_entries,
            5usize
                .saturating_add(locator_work.nested_entries.saturating_mul(3))
                .saturating_add(formal_entries),
            "boundary, target, formal, provenance, and all locator payloads are retained"
        );
        assert_eq!(
            work.owned_text_bytes,
            locator_work
                .owned_text_bytes
                .saturating_mul(3)
                .saturating_add(symbol.len())
                .saturating_add(artifact.path().as_str().len())
                .saturating_add(artifact.adapter().name().len())
                .saturating_add(formal_text_bytes),
            "the budget owns every exact-target and formal-contract string"
        );
    }

    #[test]
    fn retained_unmaterialized_external_boundary_work_includes_identity_payload() {
        let call = semantic_call_handle();
        let semantic_call = call
            .procedure()
            .semantics()
            .call_site(call.id())
            .expect("call belongs to its procedure");
        let proof = ExactExternalCallProof::go_package_function("os.Open", 0);
        let target = synthetic_unmaterialized_external(
            "os.Open",
            SemanticLanguage::Standard(Language::Go),
            semantic_call,
            Some(&proof),
            None,
        )
        .expect("canonical Go package call");
        let locator = target.locator().clone();
        let locator_work = semantic_locator_work(&locator);
        let identity_text_bytes = target
            .owner_fqn()
            .len()
            .saturating_add(target.member().len());
        let work = retained_boundary_work(
            &call,
            DispatchBoundary {
                kind: DispatchBoundaryKind::External(Some(locator)),
                external_callee_identity: None,
                exact_external_target: None,
                unmaterialized_external_target: Some(target),
                proof: ProofStatus::Proven,
                completeness: EvidenceCompleteness::Complete,
                provenance: Box::new([]),
            },
        );

        assert_eq!(
            work.nested_entries,
            5usize.saturating_add(locator_work.nested_entries.saturating_mul(3)),
            "boundary, target, provenance, and all locator payloads are retained"
        );
        assert_eq!(
            work.owned_text_bytes,
            locator_work
                .owned_text_bytes
                .saturating_mul(3)
                .saturating_add(identity_text_bytes),
            "the budget owns the target locator, owner, and member strings"
        );
    }

    #[test]
    fn retained_identity_only_external_boundary_work_includes_owner_and_member() {
        let call = semantic_call_handle();
        let owner = "os";
        let member = "Open";
        let work = retained_boundary_work(
            &call,
            DispatchBoundary {
                kind: DispatchBoundaryKind::External(None),
                external_callee_identity: Some(ResolverOwnedExternalCalleeIdentity::new(
                    Language::Go,
                    owner,
                    member,
                )),
                exact_external_target: None,
                unmaterialized_external_target: None,
                proof: ProofStatus::Proven,
                completeness: EvidenceCompleteness::Complete,
                provenance: Box::new([]),
            },
        );

        assert_eq!(
            work.nested_entries, 5,
            "boundary, external identity, provenance handle, relation record, and evidence are retained"
        );
        assert_eq!(
            work.owned_text_bytes,
            owner.len().saturating_add(member.len()),
            "the budget owns the resolver-retained owner and member strings"
        );
    }

    /// The Rust fixture behind the #2596 acceptance. Each function holds one
    /// external call, written in one of the three spellings the issue names.
    const RUST_EXTERNAL_CALL_SOURCE: &str = r#"use std::path::Path;

pub fn scoped(bytes: &[u8]) {
    let _ = std::str::from_utf8(bytes);
}

pub fn imported(text: &str) {
    let _ = Path::new(text);
}

pub fn prelude(text: &str) {
    let _ = String::from(text);
}
"#;

    /// A minted identity as `(owner FQN, member, arity, has_receiver)`, or
    /// `None` when the call reached an external boundary that names no
    /// bindable identity.
    type MintedIdentity = Option<(String, String, u32, bool)>;

    /// The canonical external identity every call in `source` publishes, keyed
    /// by the exact source text of the call.
    fn external_call_identities(
        language: Language,
        rel_path: &str,
        source: &str,
    ) -> Vec<(String, MintedIdentity)> {
        let fixture = AnalyzerFixture::new_for_language(language, &[(rel_path, source)]);
        let file = ProjectFile::new(fixture.project_root(), rel_path);
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("semantic materialization")
            .available_value()
            .cloned()
            .expect("semantic artifact");
        let oracle = fixture.analyzer.semantic_oracle_provider();
        let mut identities = Vec::new();
        for procedure in artifact.procedures() {
            for call in procedure.call_sites() {
                let handle = artifact
                    .procedure_handle(procedure.id())
                    .and_then(|procedure| procedure.call_site_handle(call.id))
                    .expect("scoped call handle");
                let span = procedure
                    .source_mapping(call.source)
                    .expect("call source mapping")
                    .locator
                    .anchor()
                    .span();
                let text = source[span.start_byte() as usize..span.end_byte() as usize].to_owned();
                let mut budget = SemanticBudget::default();
                let outcome = oracle
                    .resolve_call(
                        &handle,
                        &mut SemanticRequest::new(&mut budget, &cancellation),
                    )
                    .expect("external dispatch runs");
                let result = outcome
                    .available_value()
                    .expect("external dispatch retains a result");
                let target = result
                    .boundaries()
                    .iter()
                    .find_map(DispatchBoundary::unmaterialized_external_target)
                    .map(|target| {
                        (
                            target.owner_fqn().to_owned(),
                            target.member().to_owned(),
                            target.arity(),
                            target.has_receiver(),
                        )
                    });
                identities.push((text, target));
            }
        }
        identities.sort();
        identities
    }

    /// #2596: a multi-segment Rust callee publishes the dot-joined canonical
    /// identity an authored `std.str.from_utf8` summary is posted under, and a
    /// `use`-bound single segment reaches the same shape through the file's
    /// import binders.
    ///
    /// `has_receiver` is `false` for both. A Rust scoped path is not lowered as
    /// a call receiver the way a Java qualified static is, so an authored Rust
    /// summary must declare `"has_receiver": false`.
    #[test]
    fn a_qualified_rust_callee_publishes_a_dot_joined_external_identity() {
        let identities =
            external_call_identities(Language::Rust, "lib.rs", RUST_EXTERNAL_CALL_SOURCE);
        assert_eq!(
            identities,
            vec![
                (
                    "Path::new(text)".to_owned(),
                    Some(("std.path.Path".to_owned(), "new".to_owned(), 1, false))
                ),
                // The prelude spelling has no `use` declaration for the import
                // binder to read, so it is deliberately out of scope and names
                // no identity.
                ("String::from(text)".to_owned(), None),
                (
                    "std::str::from_utf8(bytes)".to_owned(),
                    Some(("std.str".to_owned(), "from_utf8".to_owned(), 1, false))
                ),
            ]
        );
    }

    /// The C++ fixture behind the #2606 acceptance. It holds one external call
    /// per qualification shape plus the two workspace-defined controls that
    /// must keep resolving in the workspace.
    const CPP_EXTERNAL_CALL_SOURCE: &str = r#"namespace app {

struct Local {
    static int stat(const char* p) { return 1; }
};

int helper(const char* p) { return 2; }

int run(const char* p) {
    return std::filesystem::exists(p)
        + ns::Type::method(p)
        + ns::f(p)
        + app::Local::stat(p)
        + app::helper(p);
}

}
"#;

    /// #2606: a `::`-qualified C++ callee with no workspace definition
    /// publishes the dot-joined canonical identity an authored
    /// `std.filesystem.exists` summary is posted under.
    ///
    /// The cut takes the last separator, so `ns::Type::method` is owner
    /// `ns.Type` and member `method`, never owner `ns` and member
    /// `Type::method`.
    ///
    /// `has_receiver` is `false` for all of them: C++ lowers a call receiver
    /// only for a `field_expression` target (`obj.method()`), never for a
    /// `qualified_identifier`, so an authored C++ summary for a qualified
    /// callee must declare `"has_receiver": false`.
    ///
    /// A single-segment owner (`ns::f`) names no identity. C++ does not
    /// publish single-segment external owners (#2598) and has no import binder
    /// that could expand one, so such a call keeps the boundary it had.
    #[test]
    fn a_qualified_cpp_callee_publishes_a_dot_joined_external_identity() {
        let identities =
            external_call_identities(Language::Cpp, "app.cpp", CPP_EXTERNAL_CALL_SOURCE);
        assert_eq!(
            identities,
            vec![
                // Defined in this workspace, so it resolves rather than
                // minting an external identity.
                ("app::Local::stat(p)".to_owned(), None),
                ("app::helper(p)".to_owned(), None),
                (
                    "ns::Type::method(p)".to_owned(),
                    Some(("ns.Type".to_owned(), "method".to_owned(), 1, false))
                ),
                // A single-segment owner is out of scope for the same reason
                // Rust's prelude spelling is.
                ("ns::f(p)".to_owned(), None),
                (
                    "std::filesystem::exists(p)".to_owned(),
                    Some(("std.filesystem".to_owned(), "exists".to_owned(), 1, false))
                ),
            ]
        );
    }

    /// #1981: Java type qualifiers are syntactic call objects in the raw IR,
    /// but they are not semantic receivers. The definition resolver expands
    /// both the fully-qualified and explicit-import spellings to the same
    /// canonical owner; instance receivers retain their receiver shape.
    #[test]
    fn java_static_type_qualifiers_normalize_without_cross_binding_instances() {
        let source = r#"import java.net.URLDecoder;
import java.lang.String;
class App {
    static void qualified(String raw) {
        java.net.URLDecoder.decode(raw);
    }
    static void imported(String raw) {
        URLDecoder.decode(raw, "UTF-8");
    }
    static void instance(String raw) {
        raw.trim();
    }
}
"#;
        assert_eq!(
            external_call_identities(Language::Java, "App.java", source),
            vec![
                (
                    "URLDecoder.decode(raw, \"UTF-8\")".to_owned(),
                    Some((
                        "java.net.URLDecoder".to_owned(),
                        "decode".to_owned(),
                        2,
                        false,
                    )),
                ),
                (
                    "java.net.URLDecoder.decode(raw)".to_owned(),
                    Some((
                        "java.net.URLDecoder".to_owned(),
                        "decode".to_owned(),
                        1,
                        false,
                    )),
                ),
                (
                    "raw.trim()".to_owned(),
                    Some(("java.lang.String".to_owned(), "trim".to_owned(), 0, true)),
                ),
            ]
        );
    }

    /// A Java type qualifier is structured proof that one receiverless
    /// external call cannot dispatch dynamically. The absent external body
    /// remains a boundary, while an instance receiver retains open dispatch.
    #[test]
    fn java_resolver_proven_static_external_target_closes_only_the_target_set() {
        let source = r#"import java.net.URLDecoder;
import java.lang.String;
class App {
    static void qualified(String raw) {
        java.net.URLDecoder.decode(raw);
    }
    static void imported(String raw) {
        URLDecoder.decode(raw, "UTF-8");
    }
    static void instance(String raw) {
        raw.trim();
    }
}
"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Java, &[("App.java", source)]);
        let file = ProjectFile::new(fixture.project_root(), "App.java");
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("Java semantic materialization")
            .available_value()
            .cloned()
            .expect("Java semantic artifact");
        let oracle = fixture.analyzer.semantic_oracle_provider();
        let mut observed = Vec::new();
        for procedure in artifact.procedures() {
            for call in procedure.call_sites() {
                let handle = artifact
                    .procedure_handle(procedure.id())
                    .and_then(|procedure| procedure.call_site_handle(call.id))
                    .expect("scoped call handle");
                let span = procedure
                    .source_mapping(call.source)
                    .expect("call source mapping")
                    .locator
                    .anchor()
                    .span();
                let text = source[span.start_byte() as usize..span.end_byte() as usize].to_owned();
                let mut budget = SemanticBudget::default();
                let outcome = oracle
                    .resolve_call(
                        &handle,
                        &mut SemanticRequest::new(&mut budget, &cancellation),
                    )
                    .expect("Java external dispatch runs");
                let complete = matches!(&outcome, SemanticOutcome::Complete { .. });
                let result = outcome
                    .available_value()
                    .expect("Java external dispatch retains a result");
                let resolver_proven_static = result
                    .boundaries()
                    .iter()
                    .filter_map(DispatchBoundary::unmaterialized_external_target)
                    .any(UnmaterializedExternalTarget::resolver_proves_static_call);
                if resolver_proven_static {
                    assert_eq!(
                        result.proven_receiver_shape(),
                        None,
                        "Java static target-set proof must not become Go receiver-shape authority"
                    );
                }
                observed.push((text, complete, result.coverage(), resolver_proven_static));
            }
        }
        observed.sort_by(|left, right| left.0.cmp(&right.0));
        assert_eq!(
            observed,
            vec![
                (
                    "URLDecoder.decode(raw, \"UTF-8\")".to_owned(),
                    true,
                    CandidateCoverage::Exhaustive,
                    true,
                ),
                (
                    "java.net.URLDecoder.decode(raw)".to_owned(),
                    true,
                    CandidateCoverage::Exhaustive,
                    true,
                ),
                (
                    "raw.trim()".to_owned(),
                    false,
                    CandidateCoverage::Open,
                    false,
                ),
            ]
        );
    }

    /// Type-name expansion must fail closed for lexical and import ambiguity.
    /// A workspace type with the same simple name is also not an external
    /// summary owner merely because its requested member is absent.
    #[test]
    fn java_external_static_owner_near_misses_publish_no_identity() {
        let shadowed = r#"import java.net.URLDecoder;
class App {
    static void run(Object URLDecoder, String raw) {
        URLDecoder.decode(raw);
    }
}
"#;
        assert_eq!(
            external_call_identities(Language::Java, "App.java", shadowed),
            vec![("URLDecoder.decode(raw)".to_owned(), None)]
        );

        let ambiguous = r#"import a.URLDecoder;
import b.URLDecoder;
class App {
    static void run(String raw) {
        URLDecoder.decode(raw);
    }
}
"#;
        assert_eq!(
            external_call_identities(Language::Java, "App.java", ambiguous),
            vec![("URLDecoder.decode(raw)".to_owned(), None)]
        );

        let wildcard_ambiguous = r#"import a.*;
import b.*;
class App {
    static void run(String raw) {
        URLDecoder.decode(raw);
    }
}
"#;
        assert_eq!(
            external_call_identities(Language::Java, "App.java", wildcard_ambiguous),
            vec![("URLDecoder.decode(raw)".to_owned(), None)]
        );

        let field_shadowed = r#"import java.net.URLDecoder;
class App {
    Object URLDecoder;
    void run(String raw) {
        URLDecoder.decode(raw);
    }
}
"#;
        assert_eq!(
            external_call_identities(Language::Java, "App.java", field_shadowed),
            vec![("URLDecoder.decode(raw)".to_owned(), None)]
        );

        let local_owner = r#"class URLDecoder { }
class App {
    static void run(String raw) {
        URLDecoder.decode(raw);
    }
}
"#;
        assert_eq!(
            external_call_identities(Language::Java, "App.java", local_owner),
            vec![("URLDecoder.decode(raw)".to_owned(), None)]
        );
    }

    /// The JavaScript fixture behind the #2598 acceptance. Each function holds
    /// one call whose owner carries a single segment -- the whole JS/TS
    /// standard surface -- written in one of the four shapes the issue names.
    const JS_EXTERNAL_CALL_SOURCE: &str = r#"import path from 'path';
import p from 'path';
import { Buffer } from 'buffer';
import { helper } from './helper';
const crypto = require('crypto');

export function joined(a, b) {
    return path.join(a, b);
}

export function aliased(a, b) {
    return p.join(a, b);
}

export function buffered(raw) {
    return Buffer.from(raw);
}

export function relative(raw) {
    return helper.run(raw);
}

export function generated() {
    return crypto.randomUUID();
}

export function parsed(raw) {
    return JSON.parse(raw);
}

export function local(opts, raw) {
    return opts.parse(raw);
}

export function shadowed(raw) {
    const JSON = makeCodec();
    return JSON.parse(raw);
}
"#;

    /// #2598: a single-segment JavaScript owner publishes an external identity
    /// exactly when the file binds it to a package or binds it to nothing, and
    /// the identity carries the module's name rather than the local one.
    ///
    /// `has_receiver` is `true` for every case: unlike a Rust scoped path, a
    /// JS/TS member call *is* lowered with a receiver, so an authored JS/TS
    /// summary must declare `"has_receiver": true`.
    #[test]
    fn a_single_segment_javascript_callee_publishes_its_module_or_global_identity() {
        let identities =
            external_call_identities(Language::JavaScript, "lib.js", JS_EXTERNAL_CALL_SOURCE);
        assert_eq!(
            identities,
            vec![
                // A named import binds a member *of* the module, and that
                // member is the owner: never `buffer`.
                (
                    "Buffer.from(raw)".to_owned(),
                    Some(("Buffer".to_owned(), "from".to_owned(), 1, true))
                ),
                // The same global spelling under a local `const JSON` names
                // that local, so it mints nothing.
                ("JSON.parse(raw)".to_owned(), None),
                // A global nothing in the file binds is its own owner.
                (
                    "JSON.parse(raw)".to_owned(),
                    Some(("JSON".to_owned(), "parse".to_owned(), 1, true))
                ),
                // A CommonJS module-object binding names its module.
                (
                    "crypto.randomUUID()".to_owned(),
                    Some(("crypto".to_owned(), "randomUUID".to_owned(), 0, true))
                ),
                // A relative specifier addresses a workspace file, not a
                // package, so it names no external identity.
                ("helper.run(raw)".to_owned(), None),
                // An unqualified callee has no owner to decide at all.
                ("makeCodec()".to_owned(), None),
                // `opts` is a parameter. The receiver is a runtime value of the
                // enclosing procedure and no authored summary can claim it.
                ("opts.parse(raw)".to_owned(), None),
                // An aliased default import keys under the module it loads, so
                // it publishes the identity `path.join` publishes.
                (
                    "p.join(a, b)".to_owned(),
                    Some(("path".to_owned(), "join".to_owned(), 2, true))
                ),
                (
                    "path.join(a, b)".to_owned(),
                    Some(("path".to_owned(), "join".to_owned(), 2, true))
                ),
            ]
        );
    }

    /// The TypeScript half: one dialect-blind rule, so the same shapes answer
    /// the same way through the TypeScript grammar.
    #[test]
    fn a_single_segment_typescript_callee_publishes_its_module_or_global_identity() {
        let source = r#"import path from 'path';
import * as os from 'os';
import { Buffer } from 'buffer';
const crypto = require('crypto');

export function joined(a: string, b: string): string {
    return path.join(a, b);
}

export function platform(): string {
    return os.platform();
}

export function buffered(raw: string): unknown {
    return Buffer.from(raw);
}

export function generated(): string {
    return crypto.randomUUID();
}

export function parsed(raw: string): unknown {
    return JSON.parse(raw);
}

export function local(opts: { parse(raw: string): unknown }, raw: string): unknown {
    return opts.parse(raw);
}
"#;
        let identities = external_call_identities(Language::TypeScript, "lib.ts", source);
        assert_eq!(
            identities,
            vec![
                (
                    "Buffer.from(raw)".to_owned(),
                    Some(("Buffer".to_owned(), "from".to_owned(), 1, true))
                ),
                (
                    "JSON.parse(raw)".to_owned(),
                    Some(("JSON".to_owned(), "parse".to_owned(), 1, true))
                ),
                (
                    "crypto.randomUUID()".to_owned(),
                    Some(("crypto".to_owned(), "randomUUID".to_owned(), 0, true))
                ),
                ("opts.parse(raw)".to_owned(), None),
                (
                    "os.platform()".to_owned(),
                    Some(("os".to_owned(), "platform".to_owned(), 0, true))
                ),
                (
                    "path.join(a, b)".to_owned(),
                    Some(("path".to_owned(), "join".to_owned(), 2, true))
                ),
            ]
        );
    }

    /// #2713: malformed or generated source can retain more than one static
    /// import for a local owner. Neither the last retained candidate nor any
    /// candidate before it is a proven package identity.
    #[test]
    fn competing_javascript_and_typescript_imports_publish_no_external_identity() {
        for (language, filename, source) in [
            (
                Language::JavaScript,
                "lib.js",
                r#"import api from "pkg-a";
import api from "pkg-b";
export function run(raw) { return api.exec(raw); }
"#,
            ),
            (
                Language::TypeScript,
                "lib.ts",
                r#"import api from "pkg-a";
import api from "pkg-b";
export function run(raw: string): string { return api.exec(raw); }
"#,
            ),
            (
                Language::JavaScript,
                "namespace.js",
                r#"import * as api from "pkg-a";
import * as api from "pkg-b";
export function run(raw) { return api.exec(raw); }
"#,
            ),
            (
                Language::TypeScript,
                "namespace.ts",
                r#"import * as api from "pkg-a";
import * as api from "pkg-b";
export function run(raw: string): string { return api.exec(raw); }
"#,
            ),
        ] {
            assert_eq!(
                external_call_identities(language, filename, source),
                vec![("api.exec(raw)".to_owned(), None)]
            );
        }
    }

    /// The import binder retains a bounded candidate set. Crossing that bound
    /// must not make the last retained package look exact.
    #[test]
    fn truncated_static_import_candidates_publish_no_external_identity() {
        for (language, filename, extension) in [
            (Language::JavaScript, "lib.js", ""),
            (Language::TypeScript, "lib.ts", ": string"),
        ] {
            let mut source = String::new();
            for package in 0..=brokk_bifrost_js_ts::syntax::MAX_STATIC_IMPORT_BINDINGS_PER_NAME {
                source.push_str(&format!("import api from 'pkg-{package}';\n"));
            }
            source.push_str(&format!(
                "export function run(raw{extension}) {{ return api.exec(raw); }}\n"
            ));
            assert_eq!(
                external_call_identities(language, filename, &source),
                vec![("api.exec(raw)".to_owned(), None)]
            );
        }
    }

    /// Ruby lowers every `def` as `ProcedureKind::Method`, including a
    /// top-level one that owns no receiver (#2637). The resolver-proven arm
    /// therefore decides on the declaration path: a file-scope `def` has no
    /// owning class or module and so no override set the proven candidate
    /// list could be missing, while a `def` in a class body does.
    #[test]
    fn file_scope_method_candidate_discharges_a_dispatch_gap_but_a_member_does_not() {
        const SOURCE: &str = r#"def free_target
  "value"
end

class Owner
  def member_target
    "value"
  end
end

def run
  free_target
end
"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Ruby, &[("dispatch.rb", SOURCE)]);
        let file = ProjectFile::new(fixture.project_root(), "dispatch.rb");
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
        let handle_named = |name: &str| {
            artifact
                .procedures()
                .iter()
                .find(|procedure| {
                    procedure
                        .locator()
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some(name)
                })
                .and_then(|procedure| artifact.procedure_handle(procedure.id()))
                .unwrap_or_else(|| panic!("procedure {name} is materialized"))
        };
        let caller = handle_named("run");
        let candidate = |target: ProcedureHandle| {
            vec![
                DispatchCandidate::new(
                    target,
                    ProofStatus::Proven,
                    EvidenceCompleteness::Complete,
                    std::iter::empty(),
                    OracleLimits::default(),
                )
                .expect("an empty dispatch draft fits every positive provenance limit"),
            ]
        };
        let gap = caller
            .semantics()
            .gaps()
            .iter()
            .find(|gap| {
                gap.capability == SemanticCapability::DynamicDispatch
                    && gap.kind == SemanticGapKind::Unknown
            })
            .expect("Ruby publishes an unconditional per-call dynamic-dispatch gap");
        assert_eq!(
            handle_named("free_target").semantics().kind(),
            ProcedureKind::Method,
            "the fixture is only meaningful while Ruby lowers a top-level def as a method"
        );

        let discharges = |candidates: &[DispatchCandidate]| {
            proven_static_target_discharges_gap(
                &caller,
                &CallableTargetResolution::Unknown,
                true,
                candidates,
                &[],
                true,
                DispatchQuality::Complete,
                gap,
            )
        };
        assert!(discharges(&candidate(handle_named("free_target"))));
        assert!(!discharges(&candidate(handle_named("member_target"))));
    }

    #[test]
    fn workspace_semantic_oracle_remains_clone() {
        fn assert_clone<T: Clone>() {}
        assert_clone::<WorkspaceSemanticOracle<'static>>();
    }
}
