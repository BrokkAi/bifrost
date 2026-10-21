//! Bounded point-sensitive heap, alias, and update-oracle materialization.
//!
//! The implementation follows semantic IR edges and effects only. It does not
//! reparse source, infer identities from names, or upgrade allocation-site
//! identities into runtime singletons.

use crate::analyzer::semantic::workspace_oracle::WorkspaceSemanticOracle;

use crate::analyzer::semantic::workspace_oracle::common::Interruption;
use crate::analyzer::semantic::workspace_oracle::common::WorkStager;
use crate::analyzer::semantic::workspace_oracle::common::dedup_evidence;
use crate::analyzer::semantic::workspace_oracle::common::evidence_handle;
use crate::analyzer::semantic::workspace_oracle::common::evidence_quality;
use crate::analyzer::semantic::workspace_oracle::common::internal_contract;
use crate::analyzer::semantic::workspace_oracle::common::value_handle;

use crate::analyzer::semantic::workspace_oracle::value_flow::call_target_refinement_call;
use crate::analyzer::semantic::workspace_oracle::value_flow::constructor_allocation_identity_discharges_gap;

use crate::analyzer::semantic::AbstractLocation;
use crate::analyzer::semantic::AbstractObject;
use crate::analyzer::semantic::AbstractObjectIdentity;
use crate::analyzer::semantic::AccessPath;
use crate::analyzer::semantic::AccessPathAtPoint;
use crate::analyzer::semantic::AccessPathRoot;
use crate::analyzer::semantic::AliasQuery;
use crate::analyzer::semantic::AliasResult;
use crate::analyzer::semantic::CallBinding;
use crate::analyzer::semantic::CallResultHandle;
use crate::analyzer::semantic::CallSiteHandle;
use crate::analyzer::semantic::CandidateCoverage;
use crate::analyzer::semantic::CaptureSource;
use crate::analyzer::semantic::DispatchBoundaryKind;
use crate::analyzer::semantic::DispatchOracle;
use crate::analyzer::semantic::DispatchResult;
use crate::analyzer::semantic::EscapeStatus;
use crate::analyzer::semantic::EvidenceCompleteness;
use crate::analyzer::semantic::FreshObjectPublicationQuery;
use crate::analyzer::semantic::FreshObjectPublicationResult;
use crate::analyzer::semantic::HeapOracle;
use crate::analyzer::semantic::LocationResult;
use crate::analyzer::semantic::MemoryLocationKind;
use crate::analyzer::semantic::ObjectCardinality;
use crate::analyzer::semantic::ObservationPhase;
use crate::analyzer::semantic::OracleContractError;
use crate::analyzer::semantic::PointsToResult;
use crate::analyzer::semantic::ProcedureHandle;
use crate::analyzer::semantic::ProcedurePortHandle;
use crate::analyzer::semantic::ProcedurePortKind;
use crate::analyzer::semantic::ProofStatus;
use crate::analyzer::semantic::SemanticArtifact;
use crate::analyzer::semantic::SemanticCallSite;
use crate::analyzer::semantic::SemanticEffect;
use crate::analyzer::semantic::SemanticGap;
use crate::analyzer::semantic::SemanticGapImpact;
use crate::analyzer::semantic::SemanticGapSubject;
use crate::analyzer::semantic::SemanticOutcome;
use crate::analyzer::semantic::SemanticProviderError;
use crate::analyzer::semantic::SemanticRequest;
use crate::analyzer::semantic::SemanticValueKind;
use crate::analyzer::semantic::SemanticWork;
use crate::analyzer::semantic::StoreAtPoint;
use crate::analyzer::semantic::UpdateEligibility;
use crate::analyzer::semantic::ValueAtPoint;
use crate::analyzer::semantic::ValueFlowKind;
use crate::analyzer::semantic::ValueFlowOracle;
use crate::analyzer::semantic::ValueHandle;
use crate::analyzer::semantic::WeakUpdateReason;
use crate::analyzer::semantic::assignment_transfer;

use crate::analyzer::semantic_model::CompiledProcedureSummary;
use crate::analyzer::semantic_model::CompiledSummaryEffect;
use crate::analyzer::semantic_model::CompiledSummaryExitKind;
use crate::analyzer::semantic_model::CompiledSummaryInput;
use crate::analyzer::semantic_model::CompiledSummaryOutput;
use crate::analyzer::semantic_model::Completeness;
use crate::analyzer::semantic_model::SemanticModelMatchDisposition;
use crate::analyzer::semantic_model::compiled_flow_claims_agree;

use crate::analyzer::usages::CallRelationLimits;
use crate::analyzer::usages::CallRelationService;
use crate::analyzer::usages::UsageProof;
use crate::analyzer::usages::UsageProofAuthority;

use crate::analyzer::AnalyzerQueryScope;
use crate::analyzer::QueryScope;

use crate::hash::HashSet;

pub use brokk_bifrost_semantic::analyzer::semantic::workspace_oracle::heap::*;

use std::sync::Arc;

/// Return the one complete, override-covering summary for a proven external
/// boundary. A summary that declares an input escape also closes the caller's
/// argument-evaluation gap: the external body is absent, but the reviewed
/// summary accounts for the value crossing that boundary.
pub(crate) fn complete_external_summary<'a>(
    oracle: &'a WorkspaceSemanticOracle<'_>,
    dispatch: &DispatchResult,
) -> Option<&'a CompiledProcedureSummary> {
    let [boundary] = dispatch.boundaries() else {
        return None;
    };
    let (DispatchBoundaryKind::External(Some(locator)), Some(target)) =
        (&boundary.kind, boundary.unmaterialized_external_target())
    else {
        return None;
    };
    if locator != target.locator() || !matches!(boundary.proof, ProofStatus::Proven) {
        return None;
    }
    let active = oracle.active_semantic_models()?;
    let matched = active.procedure_summaries_for_external_target(target);
    let summary = match matched.disposition {
        SemanticModelMatchDisposition::Unique => {
            let [selected] = matched.records.as_slice() else {
                return None;
            };
            selected.record
        }
        SemanticModelMatchDisposition::Conflict => {
            let (first, rest) = matched.records.split_first()?;
            (!rest.is_empty()
                && rest
                    .iter()
                    .all(|other| compiled_flow_claims_agree(other.record, first.record)))
            .then_some(first.record)?
        }
        SemanticModelMatchDisposition::Empty => return None,
    };
    (summary.completeness == Completeness::Complete
        && (!target.has_receiver() || summary.covers_overrides))
        .then_some(summary)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn modeled_external_call_gap_discharges_value(
    oracle: &WorkspaceSemanticOracle<'_>,
    procedure: &ProcedureHandle,
    gap: &SemanticGap,
    value: crate::analyzer::semantic::ValueId,
    staged: &mut WorkStager,
    cancellation: &crate::cancellation::CancellationToken,
) -> Result<bool, InterruptionOrProvider> {
    let Some(call_id) = call_target_refinement_call(procedure.semantics(), gap) else {
        return Ok(false);
    };
    let call_row = procedure
        .semantics()
        .call_site(call_id)
        .expect("call-target refinement gap has a validated call site");
    if !call_row
        .receiver
        .into_iter()
        .chain(call_row.arguments.iter().map(|argument| argument.value))
        .any(|actual| actual == value)
    {
        return Ok(false);
    }
    let call = procedure
        .call_site_handle(call_id)
        .expect("validated call site");
    let dispatch_outcome = {
        let mut request = staged.request(cancellation);
        oracle
            .resolve_call(&call, &mut request)
            .map_err(InterruptionOrProvider::Provider)?
    };
    staged.work = staged.work.conservative_add(dispatch_outcome.work());
    if let Some(interruption) = outcome_interruption(&dispatch_outcome) {
        return Err(InterruptionOrProvider::Interruption(interruption));
    }
    let Some(dispatch) = dispatch_outcome.available_value() else {
        return Ok(false);
    };
    let summary = complete_external_summary(oracle, dispatch);
    let Some(summary) = summary else {
        return Ok(false);
    };
    let preserves = complete_external_summary_preserves_receiver(summary, call_row, value);
    let escapes = complete_external_summary_escapes_value(summary, call_row, value);
    Ok(preserves || escapes)
}

/// Return the object identity an activated complete summary assigns to one
/// exact external call result. The ordinary heap trace cannot materialize a
/// body outside the workspace, so it would otherwise retain a symbolic value
/// with open coverage even when the summary proves either a fresh normal result
/// or a receiver-to-return identity.
pub(crate) fn modeled_external_call_result(
    oracle: &WorkspaceSemanticOracle<'_>,
    dispatch: &DispatchResult,
    call_row: &SemanticCallSite,
    procedure: &ProcedureHandle,
) -> Option<ModeledExternalCallResult> {
    let summary = complete_external_summary(oracle, dispatch)?;

    let receiver_identity = summary.transfers.iter().any(|transfer| {
        transfer.exit_kind == CompiledSummaryExitKind::Normal
            && matches!(transfer.input, CompiledSummaryInput::Receiver {})
            && matches!(
                transfer.output,
                CompiledSummaryOutput::NormalReturn {} | CompiledSummaryOutput::Receiver {}
            )
    });
    if receiver_identity {
        let receiver = procedure.value_handle(call_row.receiver?)?;
        return Some(ModeledExternalCallResult::Receiver(receiver));
    }

    let fresh_result = summary.effects.iter().any(|effect| {
        matches!(
            effect,
            CompiledSummaryEffect::Allocation {
                output: CompiledSummaryOutput::NormalReturn {},
                ..
            }
        )
    });
    fresh_result.then_some(ModeledExternalCallResult::Fresh)
}

/// Follow receiver-to-return summaries through one fluent call chain. A
/// receiver result can itself be the return of another modeled call whose
/// normal continuation is represented by a different program point, so the
/// point-indexed heap trace cannot discover the chain by itself. The scan is
/// procedure-local and the visited value set is retained for this query only.
pub(crate) fn modeled_external_receiver_identity(
    oracle: &WorkspaceSemanticOracle<'_>,
    procedure: &ProcedureHandle,
    value: ValueHandle,
    visited: &mut HashSet<crate::analyzer::semantic::ValueId>,
    staged: &mut WorkStager,
    cancellation: &crate::cancellation::CancellationToken,
) -> Result<Option<ValueHandle>, InterruptionOrProvider> {
    if !visited.insert(value.id()) {
        return Ok(None);
    }
    let producers = procedure
        .semantics()
        .call_sites()
        .iter()
        .filter(|call| {
            call.normal_result_values()
                .any(|result| result == value.id())
        })
        .collect::<Vec<_>>();
    let [call_row] = producers.as_slice() else {
        return Ok(None);
    };
    let call = procedure.call_site_handle(call_row.id).ok_or_else(|| {
        InterruptionOrProvider::Provider(SemanticProviderError::internal(
            "modeled receiver identity reached a stale call site",
        ))
    })?;
    let dispatch_outcome = {
        let mut request = staged.request(cancellation);
        oracle
            .resolve_call(&call, &mut request)
            .map_err(InterruptionOrProvider::Provider)?
    };
    staged.work = staged.work.conservative_add(dispatch_outcome.work());
    if let Some(interruption) = outcome_interruption(&dispatch_outcome) {
        return Err(InterruptionOrProvider::Interruption(interruption));
    }
    let Some(dispatch) = dispatch_outcome.available_value() else {
        return Ok(None);
    };
    let Some(modeled) = modeled_external_call_result(oracle, dispatch, call_row, procedure) else {
        return Ok(None);
    };
    match modeled {
        ModeledExternalCallResult::Fresh => Ok(Some(value)),
        ModeledExternalCallResult::Receiver(receiver) => Ok(modeled_external_receiver_identity(
            oracle,
            procedure,
            receiver.clone(),
            visited,
            staged,
            cancellation,
        )?
        .or(Some(receiver))),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn materialize_call_result(
    oracle: &WorkspaceSemanticOracle<'_>,
    query: &ValueAtPoint,
    state: &TraceState,
    inherited_evidence: &EvidenceTrail,
    drafts: &mut Vec<ObjectDraft>,
    limits: crate::analyzer::semantic::OracleLimits,
    staged: &mut WorkStager,
    cancellation: &crate::cancellation::CancellationToken,
) -> Result<Option<CallResultResolution>, InterruptionOrProvider> {
    let procedure = query.point().procedure();
    if cancellation.is_cancelled() {
        return Err(InterruptionOrProvider::Interruption(
            Interruption::Cancelled,
        ));
    }
    let Some(call_ids) = procedure
        .semantics()
        .call_result_site_ids(state.value, state.point)
    else {
        return Ok(None);
    };
    let mut resolution = CallResultResolution {
        ambiguous: call_ids.len() > 1,
        ..CallResultResolution::default()
    };
    for call_id in call_ids {
        if cancellation.is_cancelled() {
            return Err(InterruptionOrProvider::Interruption(
                Interruption::Cancelled,
            ));
        }
        let call_row = procedure.semantics().call_site(*call_id).ok_or_else(|| {
            InterruptionOrProvider::Provider(SemanticProviderError::internal(
                "call-result index reached a stale call site",
            ))
        })?;
        let call_resolution = materialize_one_call_result(
            oracle,
            query,
            state,
            call_row,
            inherited_evidence,
            drafts,
            limits,
            staged,
            cancellation,
        )?;
        resolution.open |= call_resolution.open;
        resolution.truncated |= call_resolution.truncated;
        resolution.ambiguous |= call_resolution.ambiguous;
    }
    Ok(Some(resolution))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn materialize_one_call_result(
    oracle: &WorkspaceSemanticOracle<'_>,
    query: &ValueAtPoint,
    state: &TraceState,
    call_row: &SemanticCallSite,
    inherited_evidence: &EvidenceTrail,
    drafts: &mut Vec<ObjectDraft>,
    limits: crate::analyzer::semantic::OracleLimits,
    staged: &mut WorkStager,
    cancellation: &crate::cancellation::CancellationToken,
) -> Result<CallResultResolution, InterruptionOrProvider> {
    let procedure = query.point().procedure();
    let call = procedure.call_site_handle(call_row.id).ok_or_else(|| {
        InterruptionOrProvider::Provider(SemanticProviderError::internal(
            "call-result trace reached a stale call site",
        ))
    })?;
    let result = value_handle(procedure, state.value).map_err(InterruptionOrProvider::Provider)?;
    let result_row = procedure
        .semantics()
        .value(state.value)
        .expect("value handles are validated at construction");
    let caller_evidence = dedup_evidence(
        inherited_evidence.to_vec().into_iter().chain([
            evidence_handle(procedure, call_row.evidence)
                .map_err(InterruptionOrProvider::Provider)?,
            evidence_handle(procedure, result_row.evidence)
                .map_err(InterruptionOrProvider::Provider)?,
        ]),
    );
    let initial_candidates = drafts.len();
    let mut resolution = CallResultResolution::default();

    let dispatch_outcome = {
        let mut request = staged.request(cancellation);
        oracle
            .resolve_call(&call, &mut request)
            .map_err(InterruptionOrProvider::Provider)?
    };
    staged.work = staged.work.conservative_add(dispatch_outcome.work());
    if let Some(interruption) = outcome_interruption(&dispatch_outcome) {
        return Err(InterruptionOrProvider::Interruption(interruption));
    }
    resolution.open |= outcome_is_open(&dispatch_outcome);
    resolution.ambiguous |= outcome_is_ambiguous(&dispatch_outcome);
    let Some(dispatch) = dispatch_outcome.available_value() else {
        let draft = symbolic_object(procedure, result, caller_evidence)
            .map_err(InterruptionOrProvider::Provider)?;
        push_trace_object(
            &mut *drafts,
            draft.object,
            draft.evidence,
            &state.alternative_quality,
        );
        resolution.open = true;
        return Ok(resolution);
    };
    let modeled_external_result =
        modeled_external_call_result(oracle, dispatch, call_row, procedure);
    resolution.absorb_coverage(dispatch.coverage());
    resolution.open |= !dispatch.boundaries().is_empty();

    if let Some(modeled_external_result) = modeled_external_result {
        let identity_value = match modeled_external_result {
            ModeledExternalCallResult::Fresh => result.clone(),
            ModeledExternalCallResult::Receiver(receiver) => {
                let mut visited = HashSet::default();
                modeled_external_receiver_identity(
                    oracle,
                    procedure,
                    receiver.clone(),
                    &mut visited,
                    staged,
                    cancellation,
                )?
                .unwrap_or(receiver)
            }
        };
        let object = AbstractObject::new(
            AbstractObjectIdentity::Value(identity_value),
            ObjectCardinality::Unknown,
        )
        .map_err(|error| {
            InterruptionOrProvider::Provider(internal_contract(
                "invalid modeled external call-result object",
                error,
            ))
        })?;
        let quality = state.alternative_quality.as_ref().map_or(
            (ProofStatus::Proven, EvidenceCompleteness::Complete),
            |alternative| {
                merge_quality(
                    alternative,
                    &(ProofStatus::Proven, EvidenceCompleteness::Complete),
                )
            },
        );
        push_object_with_quality(drafts, object, caller_evidence.clone(), quality);
        // The summary is selected for the exact resolver-owned target and is
        // complete, so its return identity closes the external boundary for
        // this points-to query.
        resolution.open = false;
        return Ok(resolution);
    }

    for candidate in dispatch.candidates() {
        if cancellation.is_cancelled() {
            return Err(InterruptionOrProvider::Interruption(
                Interruption::Cancelled,
            ));
        }
        let bindings_outcome = {
            let mut request = staged.request(cancellation);
            oracle
                .call_bindings(&call, candidate, query.context(), &mut request)
                .map_err(InterruptionOrProvider::Provider)?
        };
        staged.work = staged.work.conservative_add(bindings_outcome.work());
        if let Some(interruption) = outcome_interruption(&bindings_outcome) {
            return Err(InterruptionOrProvider::Interruption(interruption));
        }
        resolution.open |= outcome_is_open(&bindings_outcome);
        resolution.ambiguous |= outcome_is_ambiguous(&bindings_outcome);
        let Some(bindings) = bindings_outcome.available_value() else {
            resolution.open = true;
            continue;
        };
        resolution.absorb_coverage(bindings.coverage());

        let callee_context = query.context().extended(call.clone(), limits);
        resolution.open |= callee_context.was_truncated();
        let flow_outcome = {
            let mut request = staged.request(cancellation);
            oracle
                .procedure_relations(candidate.target(), &callee_context, &mut request)
                .map_err(InterruptionOrProvider::Provider)?
        };
        staged.work = staged.work.conservative_add(flow_outcome.work());
        if let Some(interruption) = outcome_interruption(&flow_outcome) {
            return Err(InterruptionOrProvider::Interruption(interruption));
        }
        resolution.open |= outcome_is_open(&flow_outcome);
        resolution.ambiguous |= outcome_is_ambiguous(&flow_outcome);
        let Some(flow) = flow_outcome.available_value() else {
            resolution.open = true;
            continue;
        };
        resolution.absorb_coverage(flow.coverage());

        let handle = match CallResultHandle::new(bindings, flow, &result, limits) {
            Ok(handle) => handle,
            Err(OracleContractError::LimitExceeded { .. }) => {
                resolution.truncated = true;
                continue;
            }
            Err(OracleContractError::InvalidAccessRoot(_)) => {
                resolution.open = true;
                continue;
            }
            Err(error) => {
                return Err(InterruptionOrProvider::Provider(internal_contract(
                    "invalid call-result object",
                    error,
                )));
            }
        };
        let mut quality = (candidate.proof().clone(), candidate.completeness().clone());
        for relation in handle.return_relations() {
            quality = merge_quality(
                &quality,
                &(relation.proof.clone(), relation.completeness.clone()),
            );
        }
        let object = AbstractObject::new(
            AbstractObjectIdentity::CallResult(handle),
            ObjectCardinality::Unknown,
        )
        .map_err(|error| {
            InterruptionOrProvider::Provider(internal_contract("invalid call-result object", error))
        })?;
        let quality = state
            .alternative_quality
            .as_ref()
            .map_or(quality.clone(), |alternative| {
                merge_quality(alternative, &quality)
            });
        push_object_with_quality(drafts, object, caller_evidence.clone(), quality);
    }

    if drafts.len() == initial_candidates {
        let draft = symbolic_object(procedure, result, caller_evidence)
            .map_err(InterruptionOrProvider::Provider)?;
        push_trace_object(
            drafts,
            draft.object,
            draft.evidence,
            &state.alternative_quality,
        );
        resolution.open = true;
    }
    Ok(resolution)
}

/// Find semantic call handles for one already-proven source caller and call
/// range. The source-level call relation has selected the caller, so scan only
/// that procedure's call rows instead of rediscovering the call by walking all
/// call sites in the caller artifact for every incoming actual.
pub(crate) fn incoming_semantic_call_handles(
    artifact: &Arc<SemanticArtifact>,
    caller: &crate::analyzer::CodeUnit,
    analyzer: &dyn crate::analyzer::IAnalyzer,
    range: crate::analyzer::Range,
    max_observations: usize,
    staged: &mut WorkStager,
) -> Result<(Vec<CallSiteHandle>, bool), InterruptionOrProvider> {
    let ranges = analyzer.ranges(caller);
    staged.charge_work(SemanticWork {
        source_mappings: ranges.len(),
        nested_entries: ranges.len(),
        ..SemanticWork::default()
    });
    let mut procedures = Vec::new();
    for procedure in artifact.procedures() {
        staged.charge_work(SemanticWork {
            procedures: 1,
            ..SemanticWork::default()
        });
        let span = procedure.locator().anchor().span();
        if ranges.iter().any(|candidate| {
            candidate.start_byte == span.start_byte() as usize
                && candidate.end_byte == span.end_byte() as usize
        }) {
            procedures.push(procedure);
        }
    }
    if procedures.is_empty() {
        return Ok((Vec::new(), false));
    }

    let mut best_width = None;
    let mut calls = Vec::new();
    for procedure in procedures {
        let procedure_handle = artifact
            .procedure_handle(procedure.id())
            .expect("semantic artifact procedure has a scoped handle");
        for semantic_call in procedure.call_sites() {
            staged.charge_work(SemanticWork {
                call_sites: 1,
                source_mappings: 1,
                ..SemanticWork::default()
            });
            let Some(mapping) = procedure.source_mapping(semantic_call.source) else {
                continue;
            };
            let span = mapping.locator.anchor().span();
            let start = span.start_byte() as usize;
            let end = span.end_byte() as usize;
            if start > range.start_byte || range.end_byte > end {
                continue;
            }
            let width = end - start;
            if best_width.is_some_and(|best| width > best) {
                continue;
            }
            if best_width.is_none_or(|best| width < best) {
                best_width = Some(width);
                calls.clear();
            }
            let handle = procedure_handle
                .call_site_handle(semantic_call.id)
                .ok_or_else(|| {
                    InterruptionOrProvider::Provider(SemanticProviderError::internal(
                        "incoming source call has a stale semantic call-site ID",
                    ))
                })?;
            staged
                .admit(SemanticWork {
                    nested_entries: 1,
                    ..SemanticWork::default()
                })
                .map_err(InterruptionOrProvider::Interruption)?;
            calls.push(handle);
        }
    }
    let truncated = calls.len() > max_observations;
    calls.truncate(max_observations);
    Ok((calls, truncated))
}

pub(crate) fn incoming_call_actual_queries(
    oracle: &WorkspaceSemanticOracle<'_>,
    call: &CallSiteHandle,
    target: &ProcedureHandle,
    formal_kind: ProcedurePortKind,
    context: IncomingActualContext<'_>,
    staged: &mut WorkStager,
    cancellation: &crate::cancellation::CancellationToken,
) -> Result<IncomingActualSet, InterruptionOrProvider> {
    let mut result = IncomingActualSet {
        candidates: Vec::new(),
        open: false,
    };
    let candidates = if context.proven_incoming_relation {
        vec![
            super::dispatch::candidate_for_proven_incoming_relation(call, target, *oracle.limits())
                .map_err(InterruptionOrProvider::Provider)?,
        ]
    } else {
        let dispatch_outcome = oracle
            .resolve_call(call, &mut staged.request(cancellation))
            .map_err(InterruptionOrProvider::Provider)?;
        let dispatch_work = dispatch_outcome.work();
        staged.work = staged.work.conservative_add(dispatch_work);
        if let Some(exceeded) = dispatch_outcome.budget_exceeded() {
            return Err(InterruptionOrProvider::Interruption(Interruption::Budget(
                exceeded,
            )));
        }
        if matches!(dispatch_outcome, SemanticOutcome::Cancelled { .. }) {
            return Err(InterruptionOrProvider::Interruption(
                Interruption::Cancelled,
            ));
        }
        result.open |= !dispatch_outcome.is_complete();
        let Some(dispatch) = dispatch_outcome.available_value() else {
            result.open = true;
            return Ok(result);
        };
        result.open |= dispatch.coverage() != CandidateCoverage::Exhaustive;
        dispatch.candidates().to_vec()
    };
    let caller = call.procedure();
    let call_row = caller
        .semantics()
        .call_site(call.id())
        .expect("incoming dispatch retains a live call handle");
    let point = caller.point_handle(call_row.point).ok_or_else(|| {
        InterruptionOrProvider::Provider(SemanticProviderError::internal(
            "incoming call binding has a stale program point",
        ))
    })?;
    let call_context = crate::analyzer::semantic::OracleCallContext::empty();
    let mut matched_callee = false;
    for candidate in &candidates {
        if candidate.target().semantics().locator() != target.semantics().locator() {
            continue;
        }
        let expected_formal = ProcedurePortHandle::new(candidate.target().clone(), formal_kind)
            .map_err(|error| {
                InterruptionOrProvider::Provider(internal_contract(
                    "invalid incoming callee formal port",
                    error,
                ))
            })?;
        matched_callee = true;
        let callee_context = if context.query.calls().last() == Some(call) {
            context.query.clone()
        } else {
            context.query.extended(call.clone(), context.limits)
        };
        result.open |= callee_context.was_truncated();
        result.open |= !matches!(candidate.proof(), ProofStatus::Proven)
            || !matches!(candidate.completeness(), EvidenceCompleteness::Complete);
        let bindings_outcome = oracle
            .call_bindings(
                call,
                candidate,
                &call_context,
                &mut staged.request(cancellation),
            )
            .map_err(InterruptionOrProvider::Provider)?;
        let bindings_work = bindings_outcome.work();
        staged.work = staged.work.conservative_add(bindings_work);
        if let Some(exceeded) = bindings_outcome.budget_exceeded() {
            return Err(InterruptionOrProvider::Interruption(Interruption::Budget(
                exceeded,
            )));
        }
        if matches!(bindings_outcome, SemanticOutcome::Cancelled { .. }) {
            return Err(InterruptionOrProvider::Interruption(
                Interruption::Cancelled,
            ));
        }
        let Some(bindings) = bindings_outcome.available_value() else {
            result.open = true;
            continue;
        };
        let mut candidate_has_actual = false;
        let mut candidate_has_receiver_relation = false;
        let mut open_argument_group_without_selected_mapping = false;
        for binding in bindings.bindings() {
            let mut actuals = Vec::new();
            match binding {
                CallBinding::Receiver {
                    relation: _,
                    actual,
                    formal,
                } if formal == &expected_formal => {
                    candidate_has_actual = true;
                    candidate_has_receiver_relation = true;
                    actuals.push((
                        actual.clone(),
                        candidate.proof().clone(),
                        candidate.completeness().clone(),
                    ));
                }
                CallBinding::ArgumentGroup(group) => {
                    let mut selected_mapping = false;
                    for mapping_candidate in group.mappings() {
                        let mapping = mapping_candidate.value();
                        if mapping.formal() != &expected_formal {
                            continue;
                        }
                        selected_mapping = true;
                        candidate_has_actual = true;
                        candidate_has_receiver_relation |=
                            formal_kind == ProcedurePortKind::Receiver;
                        result.open |= group.coverage() != CandidateCoverage::Exhaustive
                            || !matches!(mapping_candidate.proof(), ProofStatus::Proven)
                            || !matches!(
                                mapping_candidate.completeness(),
                                EvidenceCompleteness::Complete
                            );
                        if !mapping.preserves_reference_identity() {
                            result.open = true;
                            continue;
                        }
                        actuals.push((
                            mapping.actual().value().clone(),
                            mapping_candidate.proof().clone(),
                            mapping_candidate.completeness().clone(),
                        ));
                    }
                    // An open group can omit a mapping for this port even when
                    // its retained rows do not name the selected formal.
                    open_argument_group_without_selected_mapping |=
                        !group.coverage().is_exhaustive() && !selected_mapping;
                }
                CallBinding::ImplicitArgument {
                    relation: _,
                    source,
                    formal,
                    ..
                } if formal == &expected_formal => {
                    candidate_has_actual = true;
                    actuals.push((
                        source.clone(),
                        candidate.proof().clone(),
                        candidate.completeness().clone(),
                    ));
                }
                _ => {}
            }
            for (value, proof, completeness) in actuals {
                let observation = ValueAtPoint::new(
                    value,
                    point.clone(),
                    ObservationPhase::BeforeEffects,
                    call_context.clone(),
                )
                .map_err(|error| {
                    InterruptionOrProvider::Provider(internal_contract(
                        "invalid incoming actual observation",
                        error,
                    ))
                })?;
                result.candidates.push(IncomingActualQuery {
                    observation,
                    proof,
                    completeness,
                    // Keep the context of the formal query in the durable
                    // identity. Incoming edges select possible actuals for
                    // this context-insensitive result, not new object roots.
                    identity_context: context.query.clone(),
                });
            }
        }
        // Whole-call binding coverage also accounts for return, exception,
        // and unrelated formal ports. The selected-port mapping above is the
        // proof needed for this incoming identity query.
        result.open |= !candidate_has_actual;
        result.open |= match formal_kind {
            ProcedurePortKind::Receiver => {
                open_argument_group_without_selected_mapping && !candidate_has_receiver_relation
            }
            ProcedurePortKind::Parameter { .. } => open_argument_group_without_selected_mapping,
            _ => false,
        };
    }
    result.open |= !matched_callee;
    Ok(result)
}

/// Compose a formal parameter/receiver back to its exact incoming actuals
/// through the existing bounded call-relation, dispatch, and call-binding
/// services. This is query-local: every retained site and actual is charged
/// to the semantic budget on the first enumeration; completed bindings are
/// reused without another charge for the lifetime of this query provider.
#[doc(hidden)]
pub fn incoming_actual_queries(
    oracle: &WorkspaceSemanticOracle<'_>,
    procedure: &ProcedureHandle,
    formal_value: crate::analyzer::semantic::ValueId,
    context: &crate::analyzer::semantic::OracleCallContext,
    limits: crate::analyzer::semantic::OracleLimits,
    staged: &mut WorkStager,
    cancellation: &crate::cancellation::CancellationToken,
) -> Result<IncomingActualSet, InterruptionOrProvider> {
    let key = (procedure.durable_key(), formal_value, context.clone());
    if let Some(answer) = oracle
        .incoming_actuals
        .lock()
        .expect("incoming actual memo poisoned")
        .get(&key)
    {
        return Ok(answer.clone());
    }
    let answer = compute_incoming_actual_queries(
        oracle,
        procedure,
        formal_value,
        context,
        limits,
        staged,
        cancellation,
    )?;
    // Only successful enumeration is reusable. Interruptions propagate above
    // without retaining a partial answer or charging a later memo hit.
    oracle
        .incoming_actuals
        .lock()
        .expect("incoming actual memo poisoned")
        .insert(key, answer.clone());
    Ok(answer)
}

pub(crate) fn compute_incoming_actual_queries(
    oracle: &WorkspaceSemanticOracle<'_>,
    procedure: &ProcedureHandle,
    formal_value: crate::analyzer::semantic::ValueId,
    context: &crate::analyzer::semantic::OracleCallContext,
    limits: crate::analyzer::semantic::OracleLimits,
    staged: &mut WorkStager,
    cancellation: &crate::cancellation::CancellationToken,
) -> Result<IncomingActualSet, InterruptionOrProvider> {
    let mut result = IncomingActualSet {
        candidates: Vec::new(),
        open: !context.calls().is_empty() || context.was_truncated(),
    };
    let Some(file) = crate::analyzer::semantic::type_flow::file_for_locator(
        oracle.workspace,
        procedure.semantics().locator(),
    ) else {
        result.open = true;
        return Ok(result);
    };
    let analyzer = oracle.workspace.analyzer();
    let span = procedure.semantics().locator().anchor().span();
    let target_start = span.start_byte() as usize;
    let target_end = span.end_byte() as usize;
    let declarations = analyzer.declarations(&file);
    staged.charge_work(SemanticWork {
        procedures: declarations.len(),
        nested_entries: declarations.len(),
        ..SemanticWork::default()
    });
    let mut matching = Vec::new();
    for declaration in declarations {
        if !declaration.is_callable() {
            continue;
        }
        let ranges = analyzer.ranges(&declaration);
        staged.charge_work(SemanticWork {
            source_mappings: ranges.len(),
            nested_entries: ranges.len(),
            ..SemanticWork::default()
        });
        if ranges
            .iter()
            .any(|range| range.start_byte == target_start && range.end_byte == target_end)
        {
            matching.push(declaration);
        }
    }
    if matching.len() != 1 {
        result.open = true;
        return Ok(result);
    }
    let target = matching
        .pop()
        .expect("one matching callable was checked above");
    let scope = AnalyzerQueryScope::with_cancellation(analyzer, cancellation);
    let sites = CallRelationService::incoming_bounded(
        analyzer,
        scope.token(),
        &target,
        CallRelationLimits {
            max_files: usize::MAX,
            max_source_bytes: usize::MAX,
            max_candidates: limits.call_binding_entries(),
        },
        Some(cancellation),
    );
    staged.charge_work(SemanticWork {
        source_bytes: sites.work.scanned_source_bytes,
        call_sites: sites.sites.len(),
        nested_entries: sites
            .work
            .scanned_files
            .saturating_add(sites.work.examined_candidates),
        ..SemanticWork::default()
    });
    if sites.proof_authority != UsageProofAuthority::Native && sites.sites.is_empty() {
        // Cross-procedure substitution requires exact reverse-call and binding
        // facts. Without a reverse-call row, keep other language adapters'
        // established symbolic formal roots; Rust requires native coverage to
        // make a composed claim.
        let rust_semantics = matches!(
            procedure.artifact().key().language(),
            crate::analyzer::semantic::SemanticLanguage::Standard(crate::analyzer::Language::Rust)
        );
        result.open = rust_semantics;
        return Ok(result);
    }
    result.open |= sites.truncated
        || sites.cancelled
        || sites
            .sites
            .iter()
            .any(|site| site.proof != UsageProof::Proven);
    // These diagnostics report whole-call target resolution, not the native
    // reverse inventory. Exact incoming dispatch and selected formal binding
    // below decide whether that uncertainty affects this identity.
    result.open |= sites.diagnostics.iter().any(|diagnostic| {
        diagnostic.reason_kind.as_deref() != Some("native_call_resolution_incomplete")
    });
    if sites.cancelled || cancellation.is_cancelled() {
        return Err(InterruptionOrProvider::Interruption(
            Interruption::Cancelled,
        ));
    }

    let value_row = procedure
        .semantics()
        .value(formal_value)
        .expect("the formal value belongs to its procedure");
    let formal_kind = match value_row.kind {
        SemanticValueKind::Parameter { ordinal, .. } => ProcedurePortKind::Parameter { ordinal },
        SemanticValueKind::Receiver { .. } => ProcedurePortKind::Receiver,
        _ => return Ok(result),
    };
    let mut caller_artifacts = Vec::new();
    for site in &sites.sites {
        if cancellation.is_cancelled() {
            return Err(InterruptionOrProvider::Interruption(
                Interruption::Cancelled,
            ));
        }
        let artifact = if let Some((_, artifact)) =
            caller_artifacts.iter().find(|(file, _)| file == &site.file)
        {
            Arc::clone(artifact)
        } else {
            let materialized = oracle
                .workspace
                .materialize_program_semantics(&site.file, &mut staged.request(cancellation))
                .map_err(InterruptionOrProvider::Provider)?;
            staged.work = staged.work.conservative_add(materialized.work());
            if let Some(exceeded) = materialized.budget_exceeded() {
                return Err(InterruptionOrProvider::Interruption(Interruption::Budget(
                    exceeded,
                )));
            }
            if matches!(materialized, SemanticOutcome::Cancelled { .. }) {
                return Err(InterruptionOrProvider::Interruption(
                    Interruption::Cancelled,
                ));
            }
            let Some(artifact) = materialized.available_value().cloned() else {
                result.open = true;
                continue;
            };
            // Artifact completeness is file-wide. Exact call handles, dispatch
            // quality, and selected-port binding quality below carry the
            // relevant proof for this incoming edge.
            caller_artifacts.push((site.file.clone(), Arc::clone(&artifact)));
            artifact
        };
        let (calls, calls_truncated) = incoming_semantic_call_handles(
            &artifact,
            &site.caller,
            oracle.workspace.analyzer(),
            site.range,
            limits.source_observations(),
            staged,
        )?;
        result.open |= calls_truncated || calls.is_empty();
        let proven_incoming_relation = !calls_truncated
            && calls.len() == 1
            && site.proof == UsageProof::Proven
            && site.callee == target;
        for call in calls {
            let actuals = incoming_call_actual_queries(
                oracle,
                &call,
                procedure,
                formal_kind,
                IncomingActualContext {
                    query: context,
                    limits,
                    proven_incoming_relation,
                },
                staged,
                cancellation,
            )?;
            result.open |= actuals.open;
            result.candidates.extend(actuals.candidates);
        }
        if cancellation.is_cancelled() {
            return Err(InterruptionOrProvider::Interruption(
                Interruption::Cancelled,
            ));
        }
        /*
         * Keep every failure to locate a semantic call open. A proven source
         * call-relation row is not by itself a semantic dispatch result.
         */
    }
    Ok(result)
}

pub(crate) fn resolve_objects(
    oracle: &WorkspaceSemanticOracle<'_>,
    query: &ValueAtPoint,
    limits: crate::analyzer::semantic::OracleLimits,
    staged: &mut WorkStager,
    cancellation: &crate::cancellation::CancellationToken,
    expansion_depth: usize,
) -> Result<DraftSet<ObjectDraft>, InterruptionOrProvider> {
    let mut active_queries = HashSet::default();
    resolve_objects_with_active_query(
        oracle,
        query,
        limits,
        staged,
        cancellation,
        expansion_depth,
        &mut active_queries,
    )
}

pub(crate) fn resolve_objects_with_active_query(
    oracle: &WorkspaceSemanticOracle<'_>,
    query: &ValueAtPoint,
    limits: crate::analyzer::semantic::OracleLimits,
    staged: &mut WorkStager,
    cancellation: &crate::cancellation::CancellationToken,
    expansion_depth: usize,
    active_queries: &mut HashSet<ValueAtPoint>,
) -> Result<DraftSet<ObjectDraft>, InterruptionOrProvider> {
    if !active_queries.insert(query.clone()) {
        // A bounded call context eventually repeats on a recursive call cycle.
        // Cut that cycle at the repeated semantic observation while keeping
        // coverage open; expanding it again only grows the Rust call stack and
        // cannot add a distinct source observation.
        return Ok(DraftSet {
            candidates: Vec::new(),
            coverage: CandidateCoverage::Open,
            ambiguous: false,
        });
    }
    let result = resolve_objects_inner(
        oracle,
        query,
        limits,
        staged,
        cancellation,
        expansion_depth,
        active_queries,
    );
    assert!(active_queries.remove(query));
    result
}

pub(crate) fn resolve_objects_inner(
    oracle: &WorkspaceSemanticOracle<'_>,
    query: &ValueAtPoint,
    limits: crate::analyzer::semantic::OracleLimits,
    staged: &mut WorkStager,
    cancellation: &crate::cancellation::CancellationToken,
    expansion_depth: usize,
    active_queries: &mut HashSet<ValueAtPoint>,
) -> Result<DraftSet<ObjectDraft>, InterruptionOrProvider> {
    let procedure = query.point().procedure();
    staged.charge_work(SemanticWork {
        procedures: 1,
        values: 1,
        ..SemanticWork::default()
    });
    let runtime_outcome = oracle
        .runtime_refinements_for_procedure(procedure, &mut staged.request(cancellation))
        .map_err(InterruptionOrProvider::Provider)?;
    staged.work = staged.work.conservative_add(runtime_outcome.work());
    match &runtime_outcome {
        SemanticOutcome::Cancelled { .. } => {
            return Err(InterruptionOrProvider::Interruption(
                Interruption::Cancelled,
            ));
        }
        SemanticOutcome::ExceededBudget { exceeded, .. } => {
            return Err(InterruptionOrProvider::Interruption(Interruption::Budget(
                *exceeded,
            )));
        }
        _ => {}
    }
    let runtime_reads = runtime_outcome.available_value();
    let gaps_open = heap_gaps_are_open(procedure, staged, cancellation, |gap| {
        gap.subject == SemanticGapSubject::Procedure
    })
    .map_err(InterruptionOrProvider::Interruption)?;
    let mut open = points_to_capabilities_are_open(procedure) || gaps_open;
    open |= query.context().was_truncated();
    let point_row = procedure
        .semantics()
        .point(query.point().id())
        .ok_or_else(|| {
            InterruptionOrProvider::Provider(SemanticProviderError::internal(
                "program-point handle is stale",
            ))
        })?;
    let initial_limit = match query.phase() {
        ObservationPhase::BeforeEffects => 0,
        ObservationPhase::AfterEffects => point_row.events.len(),
    };
    let mut stack = vec![(
        TraceState {
            value: query.value().id(),
            point: query.point().id(),
            event_limit: initial_limit,
            summary_depth: 0,
            alternative_quality: None,
        },
        EvidenceTrail::default(),
    )];
    let mut visited = HashSet::default();
    let mut drafts = Vec::new();
    let mut truncated = false;
    let mut ambiguous = false;
    let mut abort_user_code = None;
    // Loop membership is a property of the procedure, so the derivation runs at
    // most once per query no matter how many allocations the trace reaches.
    let mut cyclic: Option<Option<CyclicRegions>> = None;

    while let Some((state, inherited_evidence)) = stack.pop() {
        if cancellation.is_cancelled() {
            return Err(InterruptionOrProvider::Interruption(
                Interruption::Cancelled,
            ));
        }
        if !visited.insert(state.clone()) {
            continue;
        }
        staged.charge_work(SemanticWork {
            program_points: 1,
            values: 1,
            nested_entries: 1,
            ..SemanticWork::default()
        });
        let point = procedure.semantics().point(state.point).ok_or_else(|| {
            InterruptionOrProvider::Provider(SemanticProviderError::internal(
                "trace reached a stale program point",
            ))
        })?;
        let mut producer = None;
        let mut producer_alternative_quality = None;
        for (index, event) in point.events[..state.event_limit].iter().enumerate().rev() {
            staged.charge_work(SemanticWork {
                events: 1,
                ..SemanticWork::default()
            });
            if let SemanticEffect::Gap { gap } = event.effect {
                staged.charge_work(SemanticWork {
                    gaps: 1,
                    ..SemanticWork::default()
                });
                let gap = procedure.semantics().gap(gap).ok_or_else(|| {
                    InterruptionOrProvider::Provider(SemanticProviderError::internal(
                        "semantic gap event has a stale gap ID",
                    ))
                })?;
                if !runtime_reads.is_some_and(|reads| reads.discharges(gap.id))
                    && gap_can_open_heap(procedure, gap, &mut abort_user_code)
                    && traced_gap_affects_value(procedure, gap, state.value, staged, cancellation)?
                    && !call_result_materialization_owns_gap(procedure, gap, state.value)
                    && !modeled_external_call_gap_discharges_value(
                        oracle,
                        procedure,
                        gap,
                        state.value,
                        staged,
                        cancellation,
                    )?
                    && !constructor_allocation_identity_discharges_gap(
                        procedure.semantics(),
                        gap,
                        state.value,
                    )
                    && !allocation_owns_modeled_read_partition(procedure, gap, state.value)
                {
                    open = true;
                }
                continue;
            }
            if transfer_stops_identity_trace(&event.effect, state.value) {
                // A producer emits Assignment plus a transfer marker for one
                // identity-separating by-value transfer (e.g. a Go array
                // assignment). The later marker overrides that generic
                // dependence for identity: stop before the reverse scan can
                // follow the duplicate Assignment into the source storage. A
                // move is also a boundary for the moved-from source: after the
                // event neither invalidation contract permits recovering its
                // old object identity through an earlier producer.
                open = true;
                let value = value_handle(procedure, state.value)
                    .map_err(InterruptionOrProvider::Provider)?;
                let evidence = inherited_evidence.to_vec_with(
                    evidence_handle(procedure, event.evidence)
                        .map_err(InterruptionOrProvider::Provider)?,
                );
                let draft = symbolic_object(procedure, value, evidence)
                    .map_err(InterruptionOrProvider::Provider)?;
                push_trace_object(
                    &mut drafts,
                    draft.object,
                    draft.evidence,
                    &state.alternative_quality,
                );
                producer = Some((state.value, index, ProducerEvidence::Fresh));
                break;
            }
            if let SemanticEffect::ValueFlow {
                kind:
                    ValueFlowKind::BackingStoreAlternative {
                        offset: _,
                        allocation,
                    },
                source,
                target,
            } = event.effect
                && target == state.value
            {
                let event_evidence = evidence_handle(procedure, event.evidence)
                    .map_err(InterruptionOrProvider::Provider)?;
                let draft = allocation_object_draft(
                    procedure,
                    query,
                    allocation,
                    &inherited_evidence.to_vec(),
                    event_evidence.clone(),
                    &mut cyclic,
                    staged,
                    cancellation,
                )?;
                let reason: Box<str> = "backing-store alternative arm was not selected".into();
                let quality = (
                    ProofStatus::Unproven(reason.clone()),
                    EvidenceCompleteness::Partial(reason),
                );
                push_object_with_quality(
                    &mut drafts,
                    draft.object,
                    draft.evidence,
                    quality.clone(),
                );
                producer_alternative_quality = Some(quality);
                producer = Some((source, index, ProducerEvidence::Extends(event_evidence)));
                break;
            }
            let source = match event.effect {
                SemanticEffect::Assignment { target, value } if target == state.value => {
                    Some(value)
                }
                SemanticEffect::ValueFlow { source, target, .. } if target == state.value => {
                    Some(source)
                }
                _ => None,
            };
            if let Some(source) = source {
                let evidence = evidence_handle(procedure, event.evidence)
                    .map_err(InterruptionOrProvider::Provider)?;
                producer = Some((source, index, ProducerEvidence::Extends(evidence)));
                break;
            }
            if let SemanticEffect::Allocation { allocation } = event.effect {
                let allocation_result = procedure
                    .semantics()
                    .allocation(allocation)
                    .ok_or_else(|| {
                        InterruptionOrProvider::Provider(SemanticProviderError::internal(
                            "allocation effect has a stale allocation ID",
                        ))
                    })?
                    .result;
                if allocation_result == state.value {
                    let draft = allocation_object_draft(
                        procedure,
                        query,
                        allocation,
                        &inherited_evidence.to_vec(),
                        evidence_handle(procedure, event.evidence)
                            .map_err(InterruptionOrProvider::Provider)?,
                        &mut cyclic,
                        staged,
                        cancellation,
                    )?;
                    push_trace_object(
                        &mut drafts,
                        draft.object,
                        draft.evidence,
                        &state.alternative_quality,
                    );
                    producer = Some((state.value, index, ProducerEvidence::Fresh));
                    break;
                }
            }
            if matches!(
                event.effect,
                SemanticEffect::MemoryLoad { result, .. } if result == state.value
            ) {
                let endpoint = runtime_reads.and_then(|reads| {
                    reads.endpoints.iter().find(|endpoint| {
                        [&endpoint.observation, &endpoint.container_observation]
                            .into_iter()
                            .any(|observation| {
                                observation.value().id() == state.value
                                    && observation.point().id() == state.point
                            })
                    })
                });
                let value = value_handle(procedure, state.value)
                    .map_err(InterruptionOrProvider::Provider)?;
                let evidence = inherited_evidence.to_vec_with(
                    evidence_handle(procedure, event.evidence)
                        .map_err(InterruptionOrProvider::Provider)?,
                );
                let mut memory_path_resolved = false;
                if endpoint.is_none()
                    && let SemanticEffect::MemoryLoad { location, .. } = event.effect
                    && let Some(location) = procedure.semantics().memory_location(location)
                    && let MemoryLocationKind::Field { base, member } = &location.kind
                    && rust_field_identity_is_supported(procedure, member)
                {
                    memory_path_resolved = true;
                    if expansion_depth >= limits.summary_depth() {
                        open = true;
                        truncated = true;
                    } else {
                        let base_value = value_handle(procedure, *base)
                            .map_err(InterruptionOrProvider::Provider)?;
                        let base_point = procedure.point_handle(state.point).ok_or_else(|| {
                            InterruptionOrProvider::Provider(SemanticProviderError::internal(
                                "field load has a stale program point",
                            ))
                        })?;
                        let base_query = ValueAtPoint::new(
                            base_value,
                            base_point,
                            ObservationPhase::BeforeEffects,
                            query.context().clone(),
                        )
                        .map_err(|error| {
                            InterruptionOrProvider::Provider(internal_contract(
                                "invalid Rust field-base query",
                                error,
                            ))
                        })?;
                        let bases = resolve_objects_with_active_query(
                            oracle,
                            &base_query,
                            limits,
                            staged,
                            cancellation,
                            expansion_depth + 1,
                            active_queries,
                        )?;
                        open |= bases.coverage != CandidateCoverage::Exhaustive;
                        if bases.candidates.is_empty() {
                            open = true;
                        }
                        for base in bases.candidates {
                            let quality = (base.proof.clone(), base.completeness.clone());
                            // This field path assumes user Deref/DerefMut returns the same
                            // target for repeated projections from one base object. Per-call
                            // target changes are outside this identity contract.
                            let object = AbstractObject::new(
                                AbstractObjectIdentity::FieldPath {
                                    base: Box::new(base.object.identity().clone()),
                                    member: member.clone(),
                                },
                                base.object.cardinality(),
                            )
                            .map_err(|error| {
                                InterruptionOrProvider::Provider(internal_contract(
                                    "invalid Rust field-path object",
                                    error,
                                ))
                            })?;
                            push_object_with_quality(
                                &mut drafts,
                                object,
                                dedup_evidence(evidence.iter().cloned().chain(base.evidence)),
                                quality,
                            );
                        }
                    }
                }
                if endpoint.is_none()
                    && let SemanticEffect::MemoryLoad { location, .. } = event.effect
                    && let Some(location) = procedure.semantics().memory_location(location)
                    && let MemoryLocationKind::Static { member } = &location.kind
                {
                    memory_path_resolved = true;
                    let member = crate::analyzer::semantic::ScopedSemanticLocator::new(
                        Arc::clone(procedure.artifact()),
                        member.clone(),
                    )
                    .map_err(|error| {
                        InterruptionOrProvider::Provider(internal_contract(
                            "invalid static object identity",
                            error,
                        ))
                    })?;
                    let object = AbstractObject::new(
                        AbstractObjectIdentity::Static(member),
                        ObjectCardinality::Singleton,
                    )
                    .map_err(|error| {
                        InterruptionOrProvider::Provider(internal_contract(
                            "invalid static object",
                            error,
                        ))
                    })?;
                    push_trace_object(
                        &mut drafts,
                        object,
                        evidence.clone(),
                        &state.alternative_quality,
                    );
                }
                open |= endpoint.is_none() && !memory_path_resolved;
                let object = if let Some(endpoint) = endpoint.filter(|endpoint| {
                    endpoint.container_observation.value().id() == state.value
                        && endpoint.container_observation.point().id() == state.point
                }) {
                    AbstractObject::new(
                        AbstractObjectIdentity::RuntimeObject(endpoint.runtime_object.clone()),
                        ObjectCardinality::Singleton,
                    )
                    .map_err(|error| {
                        InterruptionOrProvider::Provider(internal_contract(
                            "invalid runtime object",
                            error,
                        ))
                    })?
                } else {
                    if memory_path_resolved {
                        // The structured static or field-path candidate was
                        // emitted above with its proven identity.
                        producer = Some((state.value, index, ProducerEvidence::Fresh));
                        break;
                    }
                    symbolic_object(procedure, value, evidence.clone())
                        .map_err(InterruptionOrProvider::Provider)?
                        .object
                };
                push_trace_object(
                    &mut drafts,
                    object.clone(),
                    evidence,
                    &state.alternative_quality,
                );
                if let Some(endpoint) = endpoint {
                    let draft = drafts
                        .iter_mut()
                        .find(|draft| draft.object == object)
                        .expect("inserted runtime value");
                    draft.runtime_read =
                        Some(crate::analyzer::semantic::RuntimeReadRelationEvidence {
                            refinement_identity: endpoint.refinement_identity,
                            active_model_set_hash: endpoint.active_model_set_hash.clone(),
                            runtime_profile_digest: endpoint.runtime_profile_digest.clone(),
                            manifest_digest: endpoint.manifest_digest.clone(),
                            shard_id: endpoint.shard_id.clone(),
                            exposure_id: endpoint.exposure_id.clone(),
                            behavior_id: endpoint.behavior_id.clone(),
                        });
                }
                producer = Some((state.value, index, ProducerEvidence::Fresh));
                break;
            }
        }
        if producer.is_none()
            && let Some(resolution) = materialize_call_result(
                oracle,
                query,
                &state,
                &inherited_evidence,
                &mut drafts,
                limits,
                staged,
                cancellation,
            )?
        {
            open |= resolution.open;
            truncated |= resolution.truncated;
            ambiguous |= resolution.ambiguous;
            producer = Some((state.value, state.event_limit, ProducerEvidence::Fresh));
        }
        if let Some((source, event_limit, produced)) = producer {
            if source != state.value {
                if state.summary_depth >= limits.summary_depth() {
                    // Preserve candidates found along other paths but expose
                    // that this producer chain was not fully explored.
                    truncated = true;
                } else {
                    let alternative_quality =
                        producer_alternative_quality.or_else(|| state.alternative_quality.clone());
                    stack.push((
                        TraceState {
                            value: source,
                            point: state.point,
                            event_limit,
                            summary_depth: state.summary_depth + 1,
                            alternative_quality,
                        },
                        match produced {
                            ProducerEvidence::Fresh => EvidenceTrail::default(),
                            ProducerEvidence::Extends(handle) => inherited_evidence.with(handle),
                        },
                    ));
                }
            }
        } else {
            let predecessors = procedure
                .semantics()
                .cfg()
                .predecessor_edges(state.point)
                .map(|(_, edge)| (edge.source_point, edge.evidence))
                .collect::<Vec<_>>();
            staged.charge_work(SemanticWork {
                control_edges: predecessors.len(),
                ..SemanticWork::default()
            });
            if predecessors.is_empty() {
                let value = value_handle(procedure, state.value)
                    .map_err(InterruptionOrProvider::Provider)?;
                let value_row = procedure
                    .semantics()
                    .value(state.value)
                    .expect("value handle is validated");
                let evidence = inherited_evidence.to_vec_with(
                    evidence_handle(procedure, value_row.evidence)
                        .map_err(InterruptionOrProvider::Provider)?,
                );
                if matches!(
                    value_row.kind,
                    SemanticValueKind::Parameter { .. } | SemanticValueKind::Receiver { .. }
                ) {
                    let incoming = incoming_actual_queries(
                        oracle,
                        procedure,
                        state.value,
                        query.context(),
                        limits,
                        staged,
                        cancellation,
                    )?;
                    open |= incoming.open;
                    if incoming.candidates.is_empty() {
                        // Keep the formal port as the symbolic object for
                        // callers outside this workspace. A complete reverse
                        // scan with no internal actuals does not make that
                        // boundary identity incomplete.
                        let draft = symbolic_object(procedure, value, evidence)
                            .map_err(InterruptionOrProvider::Provider)?;
                        push_trace_object(
                            &mut drafts,
                            draft.object,
                            draft.evidence,
                            &state.alternative_quality,
                        );
                    } else if expansion_depth >= limits.summary_depth() {
                        truncated = true;
                        open = true;
                    } else {
                        for actual in incoming.candidates {
                            let actual_points_to = resolve_objects_with_active_query(
                                oracle,
                                &actual.observation,
                                limits,
                                staged,
                                cancellation,
                                expansion_depth + 1,
                                active_queries,
                            )?;
                            open |= actual_points_to.coverage != CandidateCoverage::Exhaustive;
                            truncated |= actual_points_to.coverage == CandidateCoverage::Truncated;
                            ambiguous |= actual_points_to.ambiguous;
                            if actual_points_to.candidates.is_empty() {
                                open = true;
                            }
                            for candidate in actual_points_to.candidates {
                                let quality = merge_quality(
                                    &(actual.proof.clone(), actual.completeness.clone()),
                                    &(candidate.proof.clone(), candidate.completeness.clone()),
                                );
                                let quality = state
                                    .alternative_quality
                                    .as_ref()
                                    .map_or(quality.clone(), |alternative| {
                                        merge_quality(alternative, &quality)
                                    });
                                let object = substitute_object_into_callee(
                                    candidate.object,
                                    procedure,
                                    &actual.identity_context,
                                )
                                .map_err(InterruptionOrProvider::Provider)?;
                                push_object_with_quality(
                                    &mut drafts,
                                    object,
                                    // The points-to arena belongs to this formal's procedure.
                                    // Caller-side call-binding and actual evidence cannot be
                                    // retained here; their proof and completeness travel in
                                    // `actual` and `candidate` quality instead.
                                    evidence.clone(),
                                    quality,
                                );
                            }
                        }
                    }
                } else {
                    open = true;
                    let draft = symbolic_object(procedure, value, evidence)
                        .map_err(InterruptionOrProvider::Provider)?;
                    push_trace_object(
                        &mut drafts,
                        draft.object,
                        draft.evidence,
                        &state.alternative_quality,
                    );
                }
            } else {
                // A single predecessor is the common straight-line case: it takes
                // the trail over instead of copying it.
                let mut inherited_evidence = Some(inherited_evidence);
                let predecessor_count = predecessors.len();
                for (position, (predecessor, edge_evidence)) in predecessors.into_iter().enumerate()
                {
                    let trail = if position + 1 == predecessor_count {
                        inherited_evidence.take()
                    } else {
                        inherited_evidence.clone()
                    }
                    .expect("the trail is taken only by the last predecessor");
                    let event_limit = procedure
                        .semantics()
                        .point(predecessor)
                        .expect("control-flow edges target validated points")
                        .events
                        .len();
                    stack.push((
                        TraceState {
                            value: state.value,
                            point: predecessor,
                            event_limit,
                            summary_depth: state.summary_depth,
                            alternative_quality: state.alternative_quality.clone(),
                        },
                        trail.with(
                            evidence_handle(procedure, edge_evidence)
                                .map_err(InterruptionOrProvider::Provider)?,
                        ),
                    ));
                }
            }
        }
        if drafts.len() > limits.objects_per_value()
            || drafts.len() > limits.provenance_records()
            || drafts
                .iter()
                .map(|draft| draft.evidence.len())
                .sum::<usize>()
                > limits.evidence_handles()
        {
            truncate_object_drafts(&mut drafts, limits);
            truncated = true;
            break;
        }
    }

    Ok(DraftSet {
        candidates: drafts,
        coverage: if truncated {
            CandidateCoverage::Truncated
        } else if open {
            CandidateCoverage::Open
        } else {
            CandidateCoverage::Exhaustive
        },
        ambiguous,
    })
}

pub(crate) fn resolve_locations(
    oracle: &WorkspaceSemanticOracle<'_>,
    query: &AccessPathAtPoint,
    limits: crate::analyzer::semantic::OracleLimits,
    staged: &mut WorkStager,
    cancellation: &crate::cancellation::CancellationToken,
) -> Result<DraftSet<LocationDraft>, InterruptionOrProvider> {
    let procedure = query.point().procedure();
    let objects = if let Some(value) = match query.path().root() {
        AccessPathRoot::Value(value) => Some(value.clone()),
        AccessPathRoot::CallResult(result) => Some(result.result().clone()),
        AccessPathRoot::Allocation(allocation) => procedure
            .semantics()
            .allocation(allocation.id())
            .and_then(|row| procedure.value_handle(row.result)),
        AccessPathRoot::ProcedurePort(_)
        | AccessPathRoot::Static(_)
        | AccessPathRoot::LexicalCell(_)
        | AccessPathRoot::CaptureSlot(_)
        | AccessPathRoot::TypeSummary(_)
        | AccessPathRoot::ModuleObject(_)
        | AccessPathRoot::External(_)
        | AccessPathRoot::RuntimeObject(_)
        | AccessPathRoot::FieldPath { .. }
        | AccessPathRoot::CallSubstitution { .. } => None,
    } {
        let value = ValueAtPoint::new(
            value,
            query.point().clone(),
            query.phase(),
            query.context().clone(),
        )
        .map_err(|error| {
            InterruptionOrProvider::Provider(internal_contract("invalid value-root query", error))
        })?;
        let mut objects = resolve_objects(oracle, &value, limits, staged, cancellation, 0)?;
        if let AccessPathRoot::Allocation(expected) = query.path().root() {
            objects.candidates.retain(|candidate| {
                matches!(
                    candidate.object.identity(),
                    AbstractObjectIdentity::Allocation(actual) if actual == expected
                )
            });
            if objects.candidates.is_empty() {
                objects.coverage = CandidateCoverage::Open;
            }
        }
        if let AccessPathRoot::CallResult(expected) = query.path().root() {
            objects.candidates.retain(|candidate| {
                matches!(
                    candidate.object.identity(),
                    AbstractObjectIdentity::CallResult(actual) if actual == expected
                )
            });
            if objects.candidates.is_empty() {
                objects.coverage = CandidateCoverage::Open;
            }
        }
        objects
    } else {
        staged.charge_work(SemanticWork {
            procedures: 1,
            memory_locations: 1,
            ..SemanticWork::default()
        });
        let gaps_open = heap_gaps_are_open(procedure, staged, cancellation, |_| true)
            .map_err(InterruptionOrProvider::Interruption)?;
        let open =
            location_capabilities_are_open(query) || gaps_open || query.context().was_truncated();
        let evidence = root_evidence(procedure, query.path().root())
            .map_err(InterruptionOrProvider::Provider)?;
        let mut quality = evidence_quality(&evidence);
        if matches!(
            query.path().root(),
            AccessPathRoot::Static(_)
                | AccessPathRoot::CallResult(_)
                | AccessPathRoot::TypeSummary(_)
                | AccessPathRoot::ModuleObject(_)
                | AccessPathRoot::External(_)
                | AccessPathRoot::RuntimeObject(_)
                | AccessPathRoot::CallSubstitution { .. }
        ) {
            quality = (
                ProofStatus::Unproven(
                    "locator root is not backed by a procedure-local memory row".into(),
                ),
                EvidenceCompleteness::Partial(
                    "workspace locator resolution is not yet attached to heap roots".into(),
                ),
            );
        }
        let cardinality = if query.context().was_truncated()
            && matches!(query.path().root(), AccessPathRoot::LexicalCell(_))
        {
            ObjectCardinality::Unknown
        } else {
            candidate_cardinality_for_root(query.path().root())
        };
        let object =
            AbstractObject::new(query.path().root().clone(), cardinality).map_err(|error| {
                InterruptionOrProvider::Provider(internal_contract("invalid access root", error))
            })?;
        DraftSet {
            candidates: vec![ObjectDraft {
                object,
                evidence,
                proof: quality.0,
                completeness: quality.1,
                runtime_read: None,
            }],
            coverage: if open {
                CandidateCoverage::Open
            } else {
                CandidateCoverage::Exhaustive
            },
            ambiguous: false,
        }
    };
    let mut candidates = Vec::new();
    let mut truncated = objects.coverage == CandidateCoverage::Truncated;
    let ambiguous = objects.ambiguous;
    for draft in objects.candidates {
        if cancellation.is_cancelled() {
            return Err(InterruptionOrProvider::Interruption(
                Interruption::Cancelled,
            ));
        }
        staged
            .admit(SemanticWork {
                nested_entries: 1,
                ..SemanticWork::default()
            })
            .map_err(InterruptionOrProvider::Interruption)?;
        let path = AccessPath::bounded(
            draft.object.identity().clone(),
            query.path().selectors().to_vec(),
            query.path().tail(),
            limits,
        )
        .map_err(|error| {
            InterruptionOrProvider::Provider(internal_contract(
                "invalid resolved access path",
                error,
            ))
        })?;
        let location = AbstractLocation::new(draft.object, path).map_err(|error| {
            InterruptionOrProvider::Provider(internal_contract("invalid resolved location", error))
        })?;
        candidates.push(LocationDraft {
            location,
            evidence: draft.evidence,
            proof: draft.proof,
            completeness: draft.completeness,
        });
        if candidates.len() > limits.alias_breadth()
            || candidates.len() > limits.provenance_records()
            || candidates
                .iter()
                .map(|candidate| candidate.evidence.len())
                .sum::<usize>()
                > limits.evidence_handles()
        {
            candidates.truncate(limits.alias_breadth().min(limits.provenance_records()));
            truncated = true;
            break;
        }
    }
    Ok(DraftSet {
        candidates,
        coverage: if truncated {
            CandidateCoverage::Truncated
        } else {
            objects.coverage
        },
        ambiguous,
    })
}

/// Call proofs share exact syntax only while their enclosing escape proof is
/// alive. Dropping this session also drops preparation whose staged charge
/// might later roll back; no unpaid source survives into another heap query.
pub(crate) struct EscapeCallSession<'a> {
    oracle: WorkspaceSemanticOracle<'a>,
    dispatch:
        crate::analyzer::semantic::workspace_oracle::dispatch::PreparedWorkspaceDispatchPool<'a>,
    active_calls: HashSet<crate::analyzer::semantic::CallSiteHandle>,
}

impl EscapeCallSession<'_> {
    fn callee_formal_is_nonpublishing(
        &mut self,
        procedure: &ProcedureHandle,
        formal: &ProcedurePortHandle,
        context: &crate::analyzer::semantic::OracleCallContext,
        staged: &mut WorkStager,
        cancellation: &crate::cancellation::CancellationToken,
    ) -> Result<bool, InterruptionOrProvider> {
        let Some(formal_value) = formal_value_id(procedure, formal.kind()) else {
            return Ok(false);
        };

        let mut copies = Vec::new();
        for point in procedure.semantics().points() {
            if cancellation.is_cancelled() {
                return Err(InterruptionOrProvider::Interruption(
                    Interruption::Cancelled,
                ));
            }
            staged.charge_work(SemanticWork {
                program_points: 1,
                events: point.events.len(),
                ..SemanticWork::default()
            });
            for (event_index, event) in point.events.iter().enumerate() {
                match event.effect {
                    SemanticEffect::Assignment { target, value }
                        if assignment_transfer(&point.events, event_index, value, target)
                            .is_none() =>
                    {
                        copies.push((value, target));
                    }
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Local | ValueFlowKind::BackingStore { .. },
                        source,
                        target,
                    } => copies.push((source, target)),
                    _ => {}
                }
            }
        }

        let mut names = HashSet::default();
        names.insert(formal_value);
        let mut pending = vec![formal_value];
        while let Some(current) = pending.pop() {
            if cancellation.is_cancelled() {
                return Err(InterruptionOrProvider::Interruption(
                    Interruption::Cancelled,
                ));
            }
            staged.charge_work(SemanticWork {
                values: 1,
                ..SemanticWork::default()
            });
            for (source, target) in &copies {
                if *source == current && names.insert(*target) {
                    pending.push(*target);
                }
            }
        }

        for point in procedure.semantics().points() {
            if cancellation.is_cancelled() {
                return Err(InterruptionOrProvider::Interruption(
                    Interruption::Cancelled,
                ));
            }
            staged.charge_work(SemanticWork {
                events: point.events.len(),
                ..SemanticWork::default()
            });
            for event in &point.events {
                match event.effect {
                    SemanticEffect::AggregateInitializer {
                        aggregate, value, ..
                    } => {
                        // Unrefined aggregate operands cannot certify nonpublication.
                        if names.contains(&aggregate) || names.contains(&value) {
                            return Ok(false);
                        }
                    }
                    SemanticEffect::MemoryStore {
                        location, value, ..
                    } => {
                        if procedure
                            .semantics()
                            .is_formal_cell_initialization(point.id, &event.effect)
                        {
                            continue;
                        }
                        let location_uses_formal = procedure
                            .semantics()
                            .memory_location(location)
                            .is_some_and(|location| {
                                names.iter().any(|value| location.kind.uses_value(*value))
                            });
                        if names.contains(&value) || location_uses_formal {
                            return Ok(false);
                        }
                    }
                    SemanticEffect::MemoryLoad { location, .. } => {
                        if procedure
                            .semantics()
                            .memory_location(location)
                            .is_some_and(|location| location.kind.uses_value(formal_value))
                        {
                            // A load is the read-only callback case.
                        }
                    }
                    SemanticEffect::CaptureBind { capture } => {
                        let captures_formal = procedure
                            .semantics()
                            .captures()
                            .iter()
                            .find(|capture_row| capture_row.id == capture)
                            .is_some_and(|capture_row| match capture_row.captured {
                                CaptureSource::Value(value) => names.contains(&value),
                                CaptureSource::Location(location) => procedure
                                    .semantics()
                                    .memory_location(location)
                                    .is_some_and(|location| {
                                        names.iter().any(|value| location.kind.uses_value(*value))
                                    }),
                            });
                        if captures_formal {
                            return Ok(false);
                        }
                    }
                    SemanticEffect::ProcedureReturn { value } | SemanticEffect::Throw { value }
                        if value.is_some_and(|value| names.contains(&value)) =>
                    {
                        return Ok(false);
                    }
                    SemanticEffect::AsyncSuspend { awaited, .. }
                        if awaited.is_some_and(|value| names.contains(&value)) =>
                    {
                        return Ok(false);
                    }
                    SemanticEffect::ValueFlow {
                        kind:
                            ValueFlowKind::Parameter
                            | ValueFlowKind::Receiver
                            | ValueFlowKind::Return
                            | ValueFlowKind::IndexedReturn { .. }
                            | ValueFlowKind::LanguageDefined,
                        source,
                        ..
                    } if names.contains(&source) => return Ok(false),
                    SemanticEffect::CallableCreation { ref callable, .. }
                    | SemanticEffect::CallableReference { ref callable, .. }
                        if callable
                            .bound_receiver
                            .is_some_and(|receiver| names.contains(&receiver)) =>
                    {
                        return Ok(false);
                    }
                    SemanticEffect::Invoke { call_site } => {
                        let Some(call) = procedure.semantics().call_site(call_site) else {
                            return Ok(false);
                        };
                        if !call_names_any(call, &names) {
                            continue;
                        }
                        let Some(call_handle) = procedure.call_site_handle(call_site) else {
                            return Ok(false);
                        };
                        if !self.call_is_nonpublishing(
                            &call_handle,
                            &names,
                            context,
                            staged,
                            cancellation,
                        )? {
                            return Ok(false);
                        }
                    }
                    SemanticEffect::Gap { gap } => {
                        let Some(gap) = procedure.semantics().gap(gap) else {
                            return Ok(false);
                        };
                        let unresolved_effect = gap_impacts_heap(gap)
                            || gap.impacts.contains(SemanticGapImpact::CallEvaluation)
                            || gap.impacts.contains(SemanticGapImpact::ValueFlow);
                        if unresolved_effect
                            && publication_gap_affects_names(procedure, gap, &names)
                        {
                            return Ok(false);
                        }
                    }
                    SemanticEffect::Entry
                    | SemanticEffect::NormalExit
                    | SemanticEffect::ExceptionalExit
                    | SemanticEffect::ProcedureReturn { .. }
                    | SemanticEffect::Throw { .. }
                    | SemanticEffect::AsyncSuspend { .. }
                    | SemanticEffect::Assignment { .. }
                    | SemanticEffect::ValueFlow { .. }
                    | SemanticEffect::ValueUse { .. }
                    | SemanticEffect::Allocation { .. }
                    | SemanticEffect::CallableCreation { .. }
                    | SemanticEffect::CallableReference { .. }
                    | SemanticEffect::CallContinuation { .. }
                    | SemanticEffect::AsyncResume { .. }
                    | SemanticEffect::Synchronization { .. } => {}
                }
            }
        }
        Ok(true)
    }

    fn call_is_nonpublishing(
        &mut self,
        call: &crate::analyzer::semantic::CallSiteHandle,
        names: &HashSet<crate::analyzer::semantic::ValueId>,
        context: &crate::analyzer::semantic::OracleCallContext,
        staged: &mut WorkStager,
        cancellation: &crate::cancellation::CancellationToken,
    ) -> Result<bool, InterruptionOrProvider> {
        if !self.active_calls.insert(call.clone()) {
            return Ok(false);
        }
        let result = (|| {
            let dispatch_outcome = {
                let mut request = staged.request(cancellation);
                self.dispatch
                    .resolve_call(call, &mut request)
                    .map_err(InterruptionOrProvider::Provider)?
            };
            staged.work = staged.work.conservative_add(dispatch_outcome.work());
            if let Some(interruption) = outcome_interruption(&dispatch_outcome) {
                return Err(InterruptionOrProvider::Interruption(interruption));
            }
            let Some(dispatch) = dispatch_outcome.available_value() else {
                return Ok(false);
            };
            if dispatch.coverage() != CandidateCoverage::Exhaustive
                || !dispatch.boundaries().is_empty()
                || dispatch.candidates().len() != 1
            {
                return Ok(false);
            }
            let candidate = &dispatch.candidates()[0];
            if !matches!(candidate.proof(), ProofStatus::Proven)
                || !matches!(candidate.completeness(), EvidenceCompleteness::Complete)
            {
                return Ok(false);
            }
            let bindings_outcome = {
                let mut request = staged.request(cancellation);
                self.oracle
                    .call_bindings(call, candidate, context, &mut request)
                    .map_err(InterruptionOrProvider::Provider)?
            };
            staged.work = staged.work.conservative_add(bindings_outcome.work());
            if let Some(interruption) = outcome_interruption(&bindings_outcome) {
                return Err(InterruptionOrProvider::Interruption(interruption));
            }
            let Some(bindings) = bindings_outcome.available_value() else {
                return Ok(false);
            };
            if bindings.coverage() != CandidateCoverage::Exhaustive {
                return Ok(false);
            }

            let callee_context = context.extended(call.clone(), *self.oracle.limits());
            if callee_context.was_truncated() {
                return Ok(false);
            }
            let flow_outcome = {
                let mut request = staged.request(cancellation);
                self.oracle
                    .procedure_relations(candidate.target(), &callee_context, &mut request)
                    .map_err(InterruptionOrProvider::Provider)?
            };
            staged.work = staged.work.conservative_add(flow_outcome.work());
            if let Some(interruption) = outcome_interruption(&flow_outcome) {
                return Err(InterruptionOrProvider::Interruption(interruption));
            }
            let Some(flow) = flow_outcome.available_value() else {
                return Ok(false);
            };
            if flow.coverage() != CandidateCoverage::Exhaustive {
                return Ok(false);
            }

            let call_row = call
                .procedure()
                .semantics()
                .call_site(call.id())
                .ok_or_else(|| {
                    InterruptionOrProvider::Provider(SemanticProviderError::internal(
                        "escape proof reached a stale call site",
                    ))
                })?;
            let touched = std::iter::once(call_row.callee)
                .chain(call_row.receiver)
                .chain(call_row.arguments.iter().map(|argument| argument.value))
                .filter(|value| names.contains(value))
                .collect::<HashSet<_>>();
            if touched.is_empty() {
                return Ok(true);
            }
            for actual in touched {
                let formals = mapped_formals_for_actual(bindings, actual);
                if formals.is_empty() {
                    return Ok(false);
                }
                for formal in formals {
                    if !self.callee_formal_is_nonpublishing(
                        candidate.target(),
                        &formal,
                        &callee_context,
                        staged,
                        cancellation,
                    )? {
                        return Ok(false);
                    }
                }
            }
            Ok(true)
        })();
        self.active_calls.remove(call);
        result
    }
}

/// Whether the object a resolved location names can be reached under a name
/// this procedure does not control.
///
/// The answer is a copy closure over the procedure's own value flow. An
/// allocation is fresh, so the only way another name can reach it is if this
/// procedure publishes it: by capturing it in a closure, passing it to a call
/// as callee, receiver or argument, storing it into memory, returning it, or
/// throwing it. Each of those hands the reference to code this query does not
/// analyse. A local copy (`alias = box`) is not a publication -- both names
/// stay inside the procedure, and the flow client already tracks them as
/// separate carriers. An invocation is the one exception that can be
/// discharged locally: only an exact dispatch, exact binding, and complete
/// structured callee proof of a read-only formal permits that call partition
/// to remain nonescaping.
///
/// A lexical cell keeps its established rule: it does not escape while no
/// capture names it. Every other identity has no such proof available here, so
/// it may escape.
#[doc(hidden)]
pub fn object_escape_status(
    oracle: &WorkspaceSemanticOracle<'_>,
    identity: &AbstractObjectIdentity,
    context: &crate::analyzer::semantic::OracleCallContext,
    staged: &mut WorkStager,
    cancellation: &crate::cancellation::CancellationToken,
) -> Result<EscapeStatus, InterruptionOrProvider> {
    let allocation = match identity {
        AbstractObjectIdentity::Allocation(allocation) => allocation,
        AbstractObjectIdentity::LexicalCell(location) => {
            let captured = location
                .procedure()
                .semantics()
                .captures()
                .iter()
                .any(|capture| {
                    matches!(
                        capture.captured,
                        CaptureSource::Location(captured) if captured == location.id()
                    )
                });
            return Ok(if captured {
                EscapeStatus::MayEscape
            } else {
                EscapeStatus::DoesNotEscape
            });
        }
        _ => return Ok(EscapeStatus::MayEscape),
    };
    let procedure = allocation.procedure();
    let semantics = procedure.semantics();
    let Some(row) = semantics.allocation(allocation.id()) else {
        return Ok(EscapeStatus::MayEscape);
    };
    if allocation_is_captured(procedure, allocation.id(), row.result) {
        return Ok(EscapeStatus::MayEscape);
    }

    // One pass collects the copy edges, then a worklist closes over them. A
    // repeated pass per name would be quadratic on a large procedure.
    let mut copies: Vec<(
        crate::analyzer::semantic::ValueId,
        crate::analyzer::semantic::ValueId,
    )> = Vec::new();
    for point in semantics.points() {
        staged.charge_work(SemanticWork {
            program_points: 1,
            events: point.events.len(),
            ..SemanticWork::default()
        });
        if cancellation.is_cancelled() {
            return Err(Interruption::Cancelled.into());
        }
        for (event_index, event) in point.events.iter().enumerate() {
            match event.effect {
                SemanticEffect::Assignment { target, value }
                    if assignment_transfer(&point.events, event_index, value, target).is_none() =>
                {
                    copies.push((value, target))
                }
                SemanticEffect::ValueFlow {
                    kind: crate::analyzer::semantic::ValueFlowKind::Local,
                    source,
                    target,
                } => copies.push((source, target)),
                _ => {}
            }
        }
    }
    let mut names = HashSet::default();
    names.insert(row.result);
    let mut pending = vec![row.result];
    while let Some(current) = pending.pop() {
        staged.charge_work(SemanticWork {
            values: 1,
            ..SemanticWork::default()
        });
        for (source, target) in &copies {
            if *source == current && names.insert(*target) {
                pending.push(*target);
            }
        }
    }

    let mut calls = EscapeCallSession {
        oracle: oracle.clone(),
        dispatch: oracle.prepare_workspace_dispatch_pool(),
        active_calls: HashSet::default(),
    };
    for point in semantics.points() {
        staged.charge_work(SemanticWork {
            events: point.events.len(),
            ..SemanticWork::default()
        });
        if cancellation.is_cancelled() {
            return Err(Interruption::Cancelled.into());
        }
        for event in &point.events {
            let published = match event.effect {
                SemanticEffect::MemoryStore { value, .. } => names.contains(&value),
                SemanticEffect::ProcedureReturn { value } | SemanticEffect::Throw { value } => {
                    value.is_some_and(|value| names.contains(&value))
                }
                SemanticEffect::ValueFlow {
                    kind:
                        crate::analyzer::semantic::ValueFlowKind::Return
                        | crate::analyzer::semantic::ValueFlowKind::IndexedReturn { .. }
                        | crate::analyzer::semantic::ValueFlowKind::Parameter
                        | crate::analyzer::semantic::ValueFlowKind::Receiver,
                    source,
                    ..
                } => names.contains(&source),
                SemanticEffect::AsyncSuspend { awaited, .. } => {
                    awaited.is_some_and(|value| names.contains(&value))
                }
                SemanticEffect::Invoke { call_site } => {
                    let Some(call) = semantics.call_site(call_site) else {
                        return Ok(EscapeStatus::MayEscape);
                    };
                    if !call_names_any(call, &names) {
                        false
                    } else {
                        let Some(call_handle) = procedure.call_site_handle(call_site) else {
                            return Ok(EscapeStatus::MayEscape);
                        };
                        !calls.call_is_nonpublishing(
                            &call_handle,
                            &names,
                            context,
                            staged,
                            cancellation,
                        )?
                    }
                }
                _ => false,
            };
            if published {
                return Ok(EscapeStatus::MayEscape);
            }
        }
    }
    Ok(EscapeStatus::DoesNotEscape)
}

impl HeapOracle for WorkspaceSemanticOracle<'_> {
    fn pointees(
        &self,
        value: &ValueAtPoint,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<PointsToResult>, SemanticProviderError> {
        if request.cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: SemanticWork::default(),
            });
        }
        let mut staged = WorkStager::new(request);
        let drafts = match resolve_objects(
            self,
            value,
            *self.limits(),
            &mut staged,
            request.cancellation,
            0,
        ) {
            Ok(drafts) => drafts,
            Err(InterruptionOrProvider::Provider(error)) => {
                request.budget.retain_performed_work(&staged.budget);
                return Err(error);
            }
            Err(InterruptionOrProvider::Interruption(interruption)) => {
                let empty = DraftSet {
                    candidates: Vec::new(),
                    coverage: CandidateCoverage::Open,
                    ambiguous: false,
                };
                let result = materialize_points_to(value, empty, *self.limits())?;
                request.budget.retain_performed_work(&staged.budget);
                return Ok(publish_set_outcome(
                    result,
                    CandidateCoverage::Open,
                    true,
                    false,
                    Some(interruption),
                    staged.work,
                ));
            }
        };
        let coverage = drafts.coverage;
        let ambiguous = drafts.ambiguous;
        let proven_complete = candidates_proven_complete(&drafts.candidates, |candidate| {
            matches!(candidate.proof, ProofStatus::Proven)
                && matches!(candidate.completeness, EvidenceCompleteness::Complete)
        });
        let publication = candidate_publication_work(
            drafts.candidates.len(),
            drafts
                .candidates
                .iter()
                .map(|candidate| candidate.evidence.len())
                .sum(),
        );
        if let Err(interruption) = staged.admit(publication) {
            let empty = DraftSet {
                candidates: Vec::new(),
                coverage: CandidateCoverage::Open,
                ambiguous: false,
            };
            let result = materialize_points_to(value, empty, *self.limits())?;
            request.budget.retain_performed_work(&staged.budget);
            return Ok(publish_set_outcome(
                result,
                CandidateCoverage::Open,
                true,
                false,
                Some(interruption),
                staged.work,
            ));
        }
        let result = materialize_points_to(value, drafts, *self.limits())?;
        *request.budget = staged.budget;
        Ok(publish_set_outcome(
            result,
            coverage,
            proven_complete,
            ambiguous,
            None,
            staged.work,
        ))
    }

    fn locations(
        &self,
        access: &AccessPathAtPoint,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<LocationResult>, SemanticProviderError> {
        if request.cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: SemanticWork::default(),
            });
        }
        let mut staged = WorkStager::new(request);
        let drafts = match resolve_locations(
            self,
            access,
            *self.limits(),
            &mut staged,
            request.cancellation,
        ) {
            Ok(drafts) => drafts,
            Err(InterruptionOrProvider::Provider(error)) => {
                request.budget.retain_performed_work(&staged.budget);
                return Err(error);
            }
            Err(InterruptionOrProvider::Interruption(interruption)) => {
                let empty = DraftSet {
                    candidates: Vec::new(),
                    coverage: CandidateCoverage::Open,
                    ambiguous: false,
                };
                let result = materialize_locations(access, empty, *self.limits())?;
                request.budget.retain_performed_work(&staged.budget);
                return Ok(publish_set_outcome(
                    result,
                    CandidateCoverage::Open,
                    true,
                    false,
                    Some(interruption),
                    staged.work,
                ));
            }
        };
        let coverage = drafts.coverage;
        let ambiguous = drafts.ambiguous;
        let proven_complete = candidates_proven_complete(&drafts.candidates, |candidate| {
            matches!(candidate.proof, ProofStatus::Proven)
                && matches!(candidate.completeness, EvidenceCompleteness::Complete)
        });
        let publication = candidate_publication_work(
            drafts.candidates.len(),
            drafts
                .candidates
                .iter()
                .map(|candidate| candidate.evidence.len())
                .sum(),
        );
        if let Err(interruption) = staged.admit(publication) {
            let empty = DraftSet {
                candidates: Vec::new(),
                coverage: CandidateCoverage::Open,
                ambiguous: false,
            };
            let result = materialize_locations(access, empty, *self.limits())?;
            request.budget.retain_performed_work(&staged.budget);
            return Ok(publish_set_outcome(
                result,
                CandidateCoverage::Open,
                true,
                false,
                Some(interruption),
                staged.work,
            ));
        }
        let result = materialize_locations(access, drafts, *self.limits())?;
        *request.budget = staged.budget;
        Ok(publish_set_outcome(
            result,
            coverage,
            proven_complete,
            ambiguous,
            None,
            staged.work,
        ))
    }

    fn alias(
        &self,
        query: &AliasQuery,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<AliasResult>, SemanticProviderError> {
        if request.cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: SemanticWork::default(),
            });
        }
        let mut staged = WorkStager::new(request);
        let left = resolve_locations(
            self,
            query.left(),
            *self.limits(),
            &mut staged,
            request.cancellation,
        );
        let right = resolve_locations(
            self,
            query.right(),
            *self.limits(),
            &mut staged,
            request.cancellation,
        );
        let (left, right, interruption) = match (left, right) {
            (Ok(left), Ok(right)) => (left, right, None),
            (Err(InterruptionOrProvider::Provider(error)), _)
            | (_, Err(InterruptionOrProvider::Provider(error))) => return Err(error),
            (Err(InterruptionOrProvider::Interruption(interruption)), _) => (
                DraftSet {
                    candidates: Vec::new(),
                    coverage: CandidateCoverage::Open,
                    ambiguous: false,
                },
                DraftSet {
                    candidates: Vec::new(),
                    coverage: CandidateCoverage::Open,
                    ambiguous: false,
                },
                Some(interruption),
            ),
            (_, Err(InterruptionOrProvider::Interruption(interruption))) => (
                DraftSet {
                    candidates: Vec::new(),
                    coverage: CandidateCoverage::Open,
                    ambiguous: false,
                },
                DraftSet {
                    candidates: Vec::new(),
                    coverage: CandidateCoverage::Open,
                    ambiguous: false,
                },
                Some(interruption),
            ),
        };
        let relation = alias_relation(query, &left, &right);
        let evidence = dedup_evidence(
            left.candidates
                .iter()
                .chain(&right.candidates)
                .flat_map(|candidate| candidate.evidence.iter().cloned()),
        );
        let mut evidence = if evidence.is_empty() {
            root_evidence(query.left().point().procedure(), query.left().path().root())?
        } else {
            evidence
        };
        let evidence_truncated = evidence.len() > self.limits().evidence_handles();
        if evidence_truncated {
            evidence.truncate(self.limits().evidence_handles());
        }
        let mut quality = evidence_quality(&evidence);
        if left
            .candidates
            .iter()
            .chain(&right.candidates)
            .any(|candidate| {
                !matches!(candidate.proof, ProofStatus::Proven)
                    || !matches!(candidate.completeness, EvidenceCompleteness::Complete)
            })
        {
            quality = merge_quality(
                &quality,
                &(
                    ProofStatus::Unproven(
                        "alias candidates include an unresolved backing alternative".into(),
                    ),
                    EvidenceCompleteness::Partial(
                        "alias candidates include an unresolved backing alternative".into(),
                    ),
                ),
            );
        }
        if evidence_truncated {
            quality.1 = EvidenceCompleteness::Partial(
                "alias provenance was truncated by the oracle evidence limit".into(),
            );
        }
        let publication = candidate_publication_work(1, evidence.len());
        if let Err(interruption) = staged.admit(publication) {
            return Ok(match interruption {
                Interruption::Budget(exceeded) => SemanticOutcome::ExceededBudget {
                    partial: None,
                    exceeded,
                    work: staged.work,
                },
                Interruption::Cancelled => SemanticOutcome::Cancelled {
                    partial: None,
                    work: staged.work,
                },
            });
        }
        let result = materialize_alias(query, relation, evidence, quality.clone(), *self.limits())?;
        let coverage = if evidence_truncated
            || left.coverage == CandidateCoverage::Truncated
            || right.coverage == CandidateCoverage::Truncated
        {
            CandidateCoverage::Truncated
        } else if left.coverage == CandidateCoverage::Open
            || right.coverage == CandidateCoverage::Open
        {
            CandidateCoverage::Open
        } else {
            CandidateCoverage::Exhaustive
        };
        if interruption.is_none() {
            *request.budget = staged.budget;
        }
        Ok(publish_set_outcome(
            result,
            coverage,
            matches!(quality.0, ProofStatus::Proven)
                && matches!(quality.1, EvidenceCompleteness::Complete),
            left.ambiguous || right.ambiguous,
            interruption,
            staged.work,
        ))
    }

    fn fresh_object_publications(
        &self,
        query: &FreshObjectPublicationQuery,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<FreshObjectPublicationResult>, SemanticProviderError> {
        if request.cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: SemanticWork::default(),
            });
        }
        let mut staged = WorkStager::new(request);
        let drafts = match resolve_fresh_object_publications(
            query,
            *self.limits(),
            &mut staged,
            request.cancellation,
        ) {
            Ok(drafts) => drafts,
            Err(InterruptionOrProvider::Provider(error)) => {
                request.budget.retain_performed_work(&staged.budget);
                return Err(error);
            }
            Err(InterruptionOrProvider::Interruption(interruption)) => {
                let empty = DraftSet {
                    candidates: Vec::new(),
                    coverage: CandidateCoverage::Open,
                    ambiguous: false,
                };
                let result = materialize_fresh_object_publications(query, empty, *self.limits())?;
                request.budget.retain_performed_work(&staged.budget);
                return Ok(publish_set_outcome(
                    result,
                    CandidateCoverage::Open,
                    true,
                    false,
                    Some(interruption),
                    staged.work,
                ));
            }
        };
        let coverage = drafts.coverage;
        let proven_complete = candidates_proven_complete(&drafts.candidates, |candidate| {
            matches!(candidate.proof, ProofStatus::Proven)
                && matches!(candidate.completeness, EvidenceCompleteness::Complete)
        });
        let publication = candidate_publication_work(
            drafts.candidates.len(),
            drafts
                .candidates
                .iter()
                .map(|candidate| candidate.evidence.len())
                .sum(),
        );
        if let Err(interruption) = staged.admit(publication) {
            let result = materialize_fresh_object_publications(query, drafts, *self.limits())?;
            request.budget.retain_performed_work(&staged.budget);
            return Ok(publish_set_outcome(
                result,
                coverage,
                false,
                false,
                Some(interruption),
                staged.work,
            ));
        }
        let result = materialize_fresh_object_publications(query, drafts, *self.limits())?;
        *request.budget = staged.budget;
        Ok(publish_set_outcome(
            result,
            coverage,
            proven_complete,
            false,
            None,
            staged.work,
        ))
    }

    fn update_eligibility(
        &self,
        store: &StoreAtPoint,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<UpdateEligibility>, SemanticProviderError> {
        if request.cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: SemanticWork::default(),
            });
        }
        let mut staged = WorkStager::new(request);
        let drafts = match resolve_locations(
            self,
            store.target(),
            *self.limits(),
            &mut staged,
            request.cancellation,
        ) {
            Ok(drafts) => drafts,
            Err(InterruptionOrProvider::Provider(error)) => {
                request.budget.retain_performed_work(&staged.budget);
                return Err(error);
            }
            Err(InterruptionOrProvider::Interruption(interruption)) => {
                let partial = UpdateEligibility::Weak(
                    [
                        WeakUpdateReason::NonExhaustiveLocations,
                        WeakUpdateReason::NonExhaustiveObjects,
                    ]
                    .into(),
                );
                return Ok(match interruption {
                    Interruption::Budget(exceeded) => SemanticOutcome::ExceededBudget {
                        partial: Some(partial),
                        exceeded,
                        work: staged.work,
                    },
                    Interruption::Cancelled => SemanticOutcome::Cancelled {
                        partial: Some(partial),
                        work: staged.work,
                    },
                });
            }
        };
        let coverage = drafts.coverage;
        let retained_evidence = drafts
            .candidates
            .iter()
            .flat_map(|candidate| candidate.evidence.iter())
            .collect::<HashSet<_>>()
            .len();
        if drafts.candidates.len() == 1
            && (self.limits().provenance_records() < 4
                || retained_evidence.saturating_mul(4) > self.limits().evidence_handles())
        {
            *request.budget = staged.budget;
            return Ok(SemanticOutcome::Unproven {
                partial: UpdateEligibility::Weak(
                    [
                        WeakUpdateReason::TruncatedLocations,
                        WeakUpdateReason::TruncatedObjects,
                        WeakUpdateReason::IncompleteAliasEvidence,
                        WeakUpdateReason::IncompleteEscapeEvidence,
                    ]
                    .into(),
                ),
                work: staged.work,
            });
        }
        let publication = if drafts.candidates.len() == 1 {
            candidate_publication_work(4, retained_evidence.saturating_mul(4))
        } else {
            SemanticWork::default()
        };
        if let Err(interruption) = staged.admit(publication) {
            let partial = UpdateEligibility::Weak(
                [
                    WeakUpdateReason::NonExhaustiveLocations,
                    WeakUpdateReason::NonExhaustiveObjects,
                ]
                .into(),
            );
            return Ok(match interruption {
                Interruption::Budget(exceeded) => SemanticOutcome::ExceededBudget {
                    partial: Some(partial),
                    exceeded,
                    work: staged.work,
                },
                Interruption::Cancelled => SemanticOutcome::Cancelled {
                    partial: Some(partial),
                    work: staged.work,
                },
            });
        }
        // The escape proof is only reachable for a single resolved candidate,
        // and every other shape has already returned weak above, so the walk it
        // costs is never paid for a store that could not be strong anyway.
        let escape = match drafts
            .candidates
            .first()
            .map(|candidate| candidate.location.object().identity())
        {
            Some(identity) => {
                match object_escape_status(
                    self,
                    identity,
                    store.target().context(),
                    &mut staged,
                    request.cancellation,
                ) {
                    Ok(escape) => escape,
                    Err(InterruptionOrProvider::Provider(error)) => {
                        request.budget.retain_performed_work(&staged.budget);
                        return Err(error);
                    }
                    Err(InterruptionOrProvider::Interruption(interruption)) => {
                        let partial = UpdateEligibility::Weak(
                            [WeakUpdateReason::IncompleteEscapeEvidence].into(),
                        );
                        return Ok(match interruption {
                            Interruption::Budget(exceeded) => SemanticOutcome::ExceededBudget {
                                partial: Some(partial),
                                exceeded,
                                work: staged.work,
                            },
                            Interruption::Cancelled => SemanticOutcome::Cancelled {
                                partial: Some(partial),
                                work: staged.work,
                            },
                        });
                    }
                }
            }
            None => EscapeStatus::MayEscape,
        };
        let eligibility = materialize_update(store, drafts, escape, *self.limits())?;
        *request.budget = staged.budget;
        Ok(match coverage {
            CandidateCoverage::Exhaustive => SemanticOutcome::Complete {
                value: eligibility,
                work: staged.work,
            },
            CandidateCoverage::Open => SemanticOutcome::Unknown {
                partial: Some(eligibility),
                work: staged.work,
            },
            CandidateCoverage::Truncated => SemanticOutcome::Unproven {
                partial: eligibility,
                work: staged.work,
            },
        })
    }
}

impl crate::analyzer::semantic::workspace_oracle::WorkspaceSemanticOracle<'_> {
    #[doc(hidden)]
    pub fn incoming_actuals_artifact_bytes(&self) -> u64 {
        self.incoming_actuals.artifact_bytes()
    }
}

#[cfg(test)]
pub(crate) mod tests {

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticEffect;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::ValueFlowKind;

    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::heap::transfer_stops_identity_trace;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::MoveInvalidation;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::TransferKind;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::TransferOperation;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::ValueTransfer;

    #[test]
    fn moves_stop_identity_traces_on_both_sides() {
        let source = brokk_bifrost_analysis::analyzer::semantic::ValueId::new(0);
        let target = brokk_bifrost_analysis::analyzer::semantic::ValueId::new(1);
        for invalidation in [MoveInvalidation::Invalidated, MoveInvalidation::Unknown] {
            let effect = SemanticEffect::ValueFlow {
                kind: ValueFlowKind::Transfer(ValueTransfer {
                    kind: TransferKind::Move { invalidation },
                    operation: TransferOperation::None,
                }),
                source,
                target,
            };
            assert!(transfer_stops_identity_trace(&effect, source));
            assert!(transfer_stops_identity_trace(&effect, target));
        }

        let copy = SemanticEffect::ValueFlow {
            kind: ValueFlowKind::Transfer(ValueTransfer {
                kind: TransferKind::Copy,
                operation: TransferOperation::None,
            }),
            source,
            target,
        };
        assert!(!transfer_stops_identity_trace(&copy, source));
        assert!(transfer_stops_identity_trace(&copy, target));
    }
}
