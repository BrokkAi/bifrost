//! Workspace binding and source projection for spawn-rooted concurrency facts.

use std::sync::Arc;

use super::{ProjectFile, Range, SemanticProcedureValue, WorkspaceAnalyzer};
use crate::analyzer::semantic::{
    AccessPath, AccessPathAtPoint, AccessPathRoot, AccessSelector, AllocationId, CallSiteHandle,
    CallSiteId, CallableTarget, CallableTargetResolution, CandidateCoverage, EvidenceCompleteness,
    ExecutionTiming, FreshObjectPublicationQuery, HeapOracle, IndexSelector,
    IndexedLocationIdentity, MemoryLocationId, MemoryLocationKind, ObjectCardinality,
    ObservationPhase, OracleCallContext, OracleLimits, PreparedWorkspaceDispatchPool,
    ProcedureHandle, ProgramPointId, ProofStatus, ScopedSemanticLocator, SemanticEffect,
    SemanticOutcome, SemanticProviderError, SemanticRequest, SemanticValueKind, SemanticWork,
    ValueAtPoint, ValueFlowKind, ValueHandle, ValueId,
};
use crate::analyzer::semantic_model::{
    ActiveSemanticModelSnapshot, CompiledAtomicOperation, CompiledConcurrencyEffect,
    CompiledLockMode, CompiledSummaryInput, Completeness, ProcedureSummaryDeclarationKey,
    ProcedureSummaryMemberKey, SemanticModelMatchDisposition, SemanticModelMemberTargetDisposition,
    SemanticModelOverlayDisposition, TypeKind, Visibility,
};
use crate::analyzer::{AnalyzerQueryScope, QueryScope};
use brokk_bifrost_core::analyzer::model::{Language, LanguageDialect, StructuredImportPathKind};
use brokk_bifrost_flow::concurrency::{
    CanonicalConcurrencyLocation, ConcurrencyAnswer, ConcurrencyAtomicOperation, ConcurrencyEscape,
    ConcurrencyLockMode, ConcurrencyObjectCardinality, ConcurrencyOpenReason, ConcurrencyOwnership,
    ConcurrencyProvider, ConcurrencySubjectIdentity, ConcurrentAccessConflict,
    ResolvedConcurrencyEffect, ResolvedConcurrencyLocation, ResolvedConcurrencySubject,
    ResolvedMemberDeclaration, field_step_selector,
};
use brokk_bifrost_flow::typestate::TypestateObjectKey;

pub(super) struct WorkspaceConcurrencyProvider<'a> {
    workspace: &'a WorkspaceAnalyzer,
    dispatch_sessions: PreparedWorkspaceDispatchPool<'a>,
    active_models: Option<Arc<ActiveSemanticModelSnapshot>>,
    summaries: Option<brokk_bifrost_flow::typestate::ProductionSemanticSummarySet>,
    /// Declarations already named for a member locator, keyed by its file and
    /// span, so one lookup serves every access repeating it.
    member_identities: std::cell::RefCell<
        crate::hash::HashMap<(String, u32, u32), Option<ResolvedMemberDeclaration>>,
    >,
    /// Whether a callee's receiver binds by reference, keyed by its file and
    /// member name, so one declaration scan serves every call to it.
    receiver_bindings: std::cell::RefCell<crate::hash::HashMap<(String, String), bool>>,
    parameter_bindings:
        std::cell::RefCell<crate::hash::HashMap<(ProcedureHandle, u32), Option<bool>>>,
    backing_parameters: std::cell::RefCell<crate::hash::HashMap<(ProcedureHandle, u32), bool>>,
    reference_free_parameters:
        std::cell::RefCell<crate::hash::HashMap<(ProcedureHandle, u32), bool>>,
    /// Whether a member locator names a field whose payload binds by reference,
    /// keyed by its file and span, so one declaration lookup serves every access
    /// repeating it. `None` is retained when the declaration's type shape is not
    /// enough to prove either storage mode.
    reference_members: std::cell::RefCell<crate::hash::HashMap<(String, u32, u32), Option<bool>>>,
}

impl<'a> WorkspaceConcurrencyProvider<'a> {
    pub(super) fn new(
        workspace: &'a WorkspaceAnalyzer,
        active_models: Option<Arc<ActiveSemanticModelSnapshot>>,
        summaries: Option<brokk_bifrost_flow::typestate::ProductionSemanticSummarySet>,
    ) -> Self {
        Self {
            workspace,
            dispatch_sessions:
                crate::analyzer::semantic::WorkspaceSemanticOracle::with_dispatch_hints(
                    workspace,
                    active_models.clone(),
                    crate::analyzer::semantic::DispatchHints::empty(),
                )
                .prepare_workspace_dispatch_pool(),
            active_models,
            summaries,
            member_identities: std::cell::RefCell::default(),
            receiver_bindings: std::cell::RefCell::default(),
            parameter_bindings: std::cell::RefCell::default(),
            backing_parameters: std::cell::RefCell::default(),
            reference_free_parameters: std::cell::RefCell::default(),
            reference_members: std::cell::RefCell::default(),
        }
    }

    fn actual_input(
        call: &crate::analyzer::semantic::SemanticCallSite,
        input: &CompiledSummaryInput,
    ) -> Option<ValueId> {
        match input {
            CompiledSummaryInput::Receiver {} => call.receiver,
            CompiledSummaryInput::Parameter { ordinal } => call
                .arguments
                .get(usize::try_from(*ordinal).ok()?)
                .map(|argument| argument.value),
        }
    }

    /// Return the one complete source edge that records a deferred receiver's
    /// registration-time snapshot. A marker value is otherwise opaque: this
    /// helper is deliberately narrower than the producer's general capture
    /// flow and rejects competing or non-language-defined edges.
    fn deferred_capture_source(
        procedure: &ProcedureHandle,
        target: ValueId,
        request: &mut SemanticRequest<'_>,
    ) -> Option<(ValueId, ProgramPointId)> {
        let semantics = procedure.semantics();
        let value = semantics.value(target)?;
        if !matches!(&value.kind, SemanticValueKind::LanguageDefined(kind) if kind.as_ref() == "go.defer_capture")
        {
            return None;
        }
        let mut capture = None;
        for point in semantics.points() {
            if request
                .budget
                .charge(SemanticWork {
                    program_points: 1,
                    ..SemanticWork::default()
                })
                .is_err()
            {
                return None;
            }
            for event in &point.events {
                if request
                    .budget
                    .charge(SemanticWork {
                        events: 1,
                        ..SemanticWork::default()
                    })
                    .is_err()
                {
                    return None;
                }
                let SemanticEffect::ValueFlow {
                    kind,
                    source: candidate,
                    target: event_target,
                } = &event.effect
                else {
                    continue;
                };
                if *event_target != target {
                    continue;
                }
                if *kind != ValueFlowKind::LanguageDefined {
                    return None;
                }
                let evidence = semantics.evidence_row(event.evidence)?;
                if evidence.proof != ProofStatus::Proven
                    || evidence.completeness != EvidenceCompleteness::Complete
                {
                    return None;
                }
                if capture.replace((*candidate, point.id)).is_some() {
                    return None;
                }
            }
        }
        let (source, _capture_point) = capture?;

        // The capture edge is emitted on the cleanup route. Resolve the source
        // at the point that evaluated the receiver so a later reassignment of
        // the receiver binding cannot change the deferred snapshot.
        let mut source_point = None;
        for point in semantics.points() {
            if request
                .budget
                .charge(SemanticWork {
                    program_points: 1,
                    ..SemanticWork::default()
                })
                .is_err()
            {
                return None;
            }
            for event in &point.events {
                if request
                    .budget
                    .charge(SemanticWork {
                        events: 1,
                        ..SemanticWork::default()
                    })
                    .is_err()
                {
                    return None;
                }
                let defines_source = match &event.effect {
                    SemanticEffect::Assignment { target, .. }
                    | SemanticEffect::ValueFlow { target, .. } => *target == source,
                    SemanticEffect::MemoryLoad { result, .. } => *result == source,
                    _ => false,
                };
                if !defines_source {
                    continue;
                }
                let evidence = semantics.evidence_row(event.evidence)?;
                if evidence.proof != ProofStatus::Proven
                    || evidence.completeness != EvidenceCompleteness::Complete
                {
                    return None;
                }
                if source_point.replace(point.id).is_some() {
                    return None;
                }
            }
        }
        source_point.map(|point| (source, point))
    }

    /// Prove the selected model's receiver shape from the active declaration
    /// overlay. Method names and summary `has_receiver` are not sufficient:
    /// Go's value and pointer method sets share the same member name.
    fn modeled_pointer_receiver(
        &self,
        summary: &crate::analyzer::semantic_model::CompiledProcedureSummary,
    ) -> Option<bool> {
        let overlay = self
            .active_models
            .as_ref()?
            .semantic_model_overlay()?
            .as_ref();
        let (owner, member) =
            crate::analyzer::semantic::split_qualified_member(&summary.target.symbol)?;
        let owners = overlay.symbols_named(owner);
        if owners.disposition != SemanticModelOverlayDisposition::Unique {
            return None;
        }
        let [owner_symbol] = owners.records.as_slice() else {
            return None;
        };
        if owner_symbol.owner_id.is_some()
            || owner_symbol.qualified_name != owner
            || owner_symbol.language
                != LanguageDialect::Standard(Language::Go).semantic_pack_label()
        {
            return None;
        }
        let methods = overlay.member_target_on_owner(&owner_symbol.id, member);
        if methods.disposition != SemanticModelMemberTargetDisposition::Unique {
            return None;
        }
        let [method] = methods.records.as_slice() else {
            return None;
        };
        if method.language != owner_symbol.language
            || method.name != member
            || !summary.target.has_receiver
            || !method.has_receiver()
            || method.structured_signature().is_none_or(|signature| {
                u32::try_from(signature.parameters.len()).ok()
                    != Some(summary.target.parameter_count)
            })
        {
            return None;
        }
        method.receiver.map(|receiver| receiver.pointer)
    }

    /// Resolve a deferred receiver through its original source only when the
    /// call is an exhaustive external-only synchronization model with an
    /// exact pointer receiver declaration. All other capture routes stay
    /// opaque and therefore open in the caller.
    fn deferred_pointer_receiver_source(
        &self,
        call: &CallSiteHandle,
        row: &crate::analyzer::semantic::SemanticCallSite,
        target: ValueId,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Option<(ValueId, ProgramPointId)>, SemanticProviderError> {
        if row.execution_timing != ExecutionTiming::SameInvocation {
            return Ok(None);
        }
        let semantics = call.procedure().semantics();
        let Some(call_evidence) = semantics.evidence_row(row.evidence) else {
            return Ok(None);
        };
        if call_evidence.proof != ProofStatus::Proven
            || call_evidence.completeness != EvidenceCompleteness::Complete
        {
            return Ok(None);
        }
        let Some((source, point)) =
            Self::deferred_capture_source(call.procedure(), target, request)
        else {
            return Ok(None);
        };
        let ConcurrencyAnswer::Proven(Some(summary)) = self.exact_model_summary(call, request)?
        else {
            return Ok(None);
        };
        if summary.completeness != Completeness::Complete
            || self.modeled_pointer_receiver(summary) != Some(true)
        {
            return Ok(None);
        }
        Ok(Some((source, point)))
    }

    fn canonical_actual(
        &self,
        call: &CallSiteHandle,
        input: &CompiledSummaryInput,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ConcurrencyAnswer<Option<ResolvedConcurrencySubject>>, SemanticProviderError> {
        let row = call
            .procedure()
            .semantics()
            .call_site(call.id())
            .expect("validated call handle resolves");
        let Some(value) = Self::actual_input(row, input) else {
            return Ok(ConcurrencyAnswer::Open {
                partial: None,
                reasons: vec![ConcurrencyOpenReason::UnknownLocation],
            });
        };
        let source = if matches!(input, CompiledSummaryInput::Receiver {}) {
            self.deferred_pointer_receiver_source(call, row, value, request)?
        } else {
            None
        };
        let (value, point, phase) = source.map_or(
            (value, row.point, ObservationPhase::BeforeEffects),
            |(source, point)| (source, point, ObservationPhase::AfterEffects),
        );
        let (canonical, mut reasons) = self
            .canonical_value_at(call.procedure(), point, value, phase, request)?
            .into_parts();
        if canonical.is_none() && reasons.is_empty() {
            reasons.push(ConcurrencyOpenReason::UnknownLocation);
        }
        let subject = ResolvedConcurrencySubject {
            value,
            canonical,
            reasons: reasons.clone(),
            identity: match input {
                CompiledSummaryInput::Receiver {} => ConcurrencySubjectIdentity::Backing,
                CompiledSummaryInput::Parameter { .. } => ConcurrencySubjectIdentity::Value,
            },
        };
        Ok(if reasons.is_empty() {
            ConcurrencyAnswer::Proven(Some(subject))
        } else {
            ConcurrencyAnswer::Open {
                partial: Some(subject),
                reasons,
            }
        })
    }

    fn canonical_value_at(
        &self,
        procedure: &ProcedureHandle,
        point: ProgramPointId,
        value: ValueId,
        phase: ObservationPhase,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ConcurrencyAnswer<Option<CanonicalConcurrencyLocation>>, SemanticProviderError>
    {
        self.resolved_value_at(procedure, point, value, phase, request)
            .map(legacy_canonical_answer)
    }

    fn resolved_value_at(
        &self,
        procedure: &ProcedureHandle,
        point: ProgramPointId,
        value: ValueId,
        phase: ObservationPhase,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ConcurrencyAnswer<ResolvedConcurrencyLocation>, SemanticProviderError> {
        let query = ValueAtPoint::new(
            value_handle(procedure, value)?,
            procedure
                .point_handle(point)
                .expect("validated program point exists"),
            phase,
            OracleCallContext::empty(),
        )
        .map_err(|error| SemanticProviderError::internal(error.to_string()))?;
        let outcome = self
            .workspace
            .semantic_oracle_provider()
            .pointees(&query, request)?;
        let Some(result) = outcome.available_value() else {
            return Ok(open_resolved_location());
        };
        let mut candidates = Vec::new();
        let mut all_singleton = true;
        let mut exhaustive = outcome.is_complete() && result.objects().coverage().is_exhaustive();
        for candidate in result.objects().candidates() {
            if !candidate.is_proven_complete() {
                exhaustive = false;
            }
            let object = candidate.value();
            all_singleton &= object.cardinality() == ObjectCardinality::Singleton;
            if matches!(
                object.identity(),
                AccessPathRoot::CallResult(_)
                    | AccessPathRoot::ProcedurePort(_)
                    | AccessPathRoot::CaptureSlot(_)
                    | AccessPathRoot::RuntimeObject(_)
            ) {
                exhaustive = false;
                continue;
            }
            candidates.push(CanonicalConcurrencyLocation::new(
                TypestateObjectKey::for_object(object).public_canonical_rendering(),
                "object",
            ));
        }
        let cardinality = if all_singleton && candidates.len() == 1 {
            ConcurrencyObjectCardinality::Singleton
        } else if candidates.is_empty() {
            ConcurrencyObjectCardinality::Unknown
        } else {
            ConcurrencyObjectCardinality::Multiple
        };
        let resolved = ResolvedConcurrencyLocation::new(
            candidates,
            exhaustive,
            cardinality,
            ConcurrencyEscape::Unknown,
            ConcurrencyOwnership::Unknown,
        );
        Ok(if exhaustive && !resolved.candidates().is_empty() {
            ConcurrencyAnswer::Proven(resolved)
        } else {
            ConcurrencyAnswer::Open {
                partial: resolved,
                reasons: vec![ConcurrencyOpenReason::AliasSetTruncated],
            }
        })
    }

    fn callback_targets(
        call: &CallSiteHandle,
        input: &CompiledSummaryInput,
    ) -> ConcurrencyAnswer<Vec<ProcedureHandle>> {
        let semantics = call.procedure().semantics();
        let row = semantics
            .call_site(call.id())
            .expect("validated call handle resolves");
        let Some(value) = Self::actual_input(row, input) else {
            return ConcurrencyAnswer::Open {
                partial: Vec::new(),
                reasons: vec![ConcurrencyOpenReason::UnresolvedTarget],
            };
        };
        let mut targets = Vec::new();
        let mut open = false;
        for point in semantics.points() {
            for event in &point.events {
                let callable = match &event.effect {
                    SemanticEffect::CallableCreation { result, callable }
                    | SemanticEffect::CallableReference { result, callable }
                        if *result == value =>
                    {
                        callable
                    }
                    SemanticEffect::ValueFlow {
                        source,
                        target,
                        kind: crate::analyzer::semantic::ValueFlowKind::Local,
                    } if *target == value => {
                        for source_point in semantics.points() {
                            for source_event in &source_point.events {
                                let source_callable = match &source_event.effect {
                                    SemanticEffect::CallableCreation { result, callable }
                                    | SemanticEffect::CallableReference { result, callable }
                                        if result == source =>
                                    {
                                        callable
                                    }
                                    _ => continue,
                                };
                                collect_local_callable_targets(
                                    call.procedure(),
                                    &source_callable.targets,
                                    &mut targets,
                                    &mut open,
                                );
                            }
                        }
                        continue;
                    }
                    _ => continue,
                };
                collect_local_callable_targets(
                    call.procedure(),
                    &callable.targets,
                    &mut targets,
                    &mut open,
                );
            }
        }
        // Sorted by the mount-free procedure wire id, which is the identity
        // the conflict rows publish: a total order that is the same at every
        // workspace root, so the dedup below removes the same duplicates and
        // the callee list arrives in the same order in a base export as in the
        // head. Cached because the key is a digest over the procedure's
        // locator, not a field read.
        targets.sort_by_cached_key(super::semantic::procedure_wire_id);
        targets.dedup();
        if !open && !targets.is_empty() {
            ConcurrencyAnswer::Proven(targets)
        } else {
            ConcurrencyAnswer::Open {
                partial: targets,
                reasons: vec![ConcurrencyOpenReason::UnresolvedTarget],
            }
        }
    }

    fn declaration_has_concurrency_model(
        &self,
        language: &str,
        path: &str,
        member: &str,
        has_receiver: bool,
        parameter_count: u32,
    ) -> bool {
        let Some(active) = self.active_models.as_ref() else {
            return false;
        };
        active
            .active_models()
            .procedure_summaries_for_declaration(ProcedureSummaryDeclarationKey::new(
                language,
                path,
                member,
                has_receiver,
                parameter_count,
            ))
            .records
            .iter()
            .any(|record| !record.concurrency_effects().is_empty())
    }

    fn procedure_has_concurrency_model(&self, procedure: &ProcedureHandle) -> bool {
        let locator = procedure.semantics().locator();
        let Some(member) = locator
            .declaration()
            .segments()
            .last()
            .and_then(|segment| segment.name())
        else {
            return false;
        };
        let mut has_receiver = false;
        let mut parameter_count = 0_u32;
        for value in procedure.semantics().values() {
            match value.kind {
                crate::analyzer::semantic::SemanticValueKind::Receiver { .. } => {
                    has_receiver = true;
                }
                crate::analyzer::semantic::SemanticValueKind::Parameter { .. } => {
                    parameter_count = parameter_count.saturating_add(1);
                }
                _ => {}
            }
        }
        self.declaration_has_concurrency_model(
            locator.language().semantic_pack_label(),
            locator.path().as_str(),
            member,
            has_receiver,
            parameter_count,
        )
    }

    fn declared_target_has_concurrency_model(
        &self,
        procedure: &ProcedureHandle,
        call: &crate::analyzer::semantic::SemanticCallSite,
        target: &CallableTarget,
    ) -> bool {
        match target {
            CallableTarget::Local(target) => procedure
                .artifact()
                .procedure_handle(*target)
                .is_some_and(|target| self.procedure_has_concurrency_model(&target)),
            CallableTarget::External(locator) | CallableTarget::Unmaterialized(locator) => {
                let Some(member) = locator
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                else {
                    return false;
                };
                self.declaration_has_concurrency_model(
                    locator.language().semantic_pack_label(),
                    locator.path().as_str(),
                    member,
                    call.receiver.is_some(),
                    u32::try_from(call.arguments.len())
                        .expect("validated call argument count fits u32"),
                )
            }
        }
    }

    fn exact_model_summary(
        &self,
        call: &CallSiteHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<
        ConcurrencyAnswer<Option<&crate::analyzer::semantic_model::CompiledProcedureSummary>>,
        SemanticProviderError,
    > {
        let semantics = call.procedure().semantics();
        let row = semantics
            .call_site(call.id())
            .expect("validated call handle resolves");
        let evidence = semantics
            .evidence_row(row.target_evidence)
            .expect("validated call target evidence resolves");
        if matches!(
            row.declared_targets,
            CallableTargetResolution::Proven(CallableTarget::Local(_))
        ) && evidence.proof == ProofStatus::Proven
            && evidence.completeness == EvidenceCompleteness::Complete
        {
            // The producer already proved this exact artifact-owned body.
            // The task slice expands it; it has no external summary to bind.
            // Source-level lookup may not index an immediately invoked lambda.
            return Ok(ConcurrencyAnswer::Proven(None));
        }
        let outcome = self.dispatch_sessions.resolve_call(call, request)?;
        let Some(dispatch) = outcome.available_value() else {
            return Ok(ConcurrencyAnswer::Open {
                partial: None,
                reasons: vec![dispatch_open_reason(&outcome)],
            });
        };
        let Some(external_only) =
            complete_exclusive_dispatch_is_external_only(outcome.is_complete(), dispatch)
        else {
            return Ok(ConcurrencyAnswer::Open {
                partial: None,
                reasons: vec![dispatch_open_reason(&outcome)],
            });
        };
        // A complete source-only dispatch has no external procedure summary
        // to consume.
        if !external_only {
            return Ok(ConcurrencyAnswer::Proven(None));
        }
        let mut targets = dispatch
            .boundaries()
            .iter()
            .filter_map(|boundary| {
                if let Some(target) = boundary.exact_external_target() {
                    let (owner, member) =
                        crate::analyzer::semantic::split_qualified_member(target.symbol())?;
                    return Some((
                        target.artifact().language().semantic_pack_label(),
                        owner.to_owned(),
                        member.to_owned(),
                        target.has_receiver(),
                        target.parameter_count(),
                    ));
                }
                let target = boundary.unmaterialized_external_target()?;
                Some((
                    target.language().semantic_pack_label(),
                    target.owner_fqn().to_owned(),
                    target.member().to_owned(),
                    target.has_receiver(),
                    target.arity(),
                ))
            })
            .collect::<Vec<_>>();
        targets.sort();
        targets.dedup();
        let Some(active) = self.active_models.as_ref() else {
            return Ok(ConcurrencyAnswer::Open {
                partial: None,
                reasons: vec![ConcurrencyOpenReason::UnresolvedTarget],
            });
        };
        let [target] = targets.as_slice() else {
            return Ok(ConcurrencyAnswer::Open {
                partial: None,
                reasons: vec![ConcurrencyOpenReason::UnresolvedTarget],
            });
        };
        let matched =
            active
                .active_models()
                .procedure_summaries_for_member(ProcedureSummaryMemberKey::new(
                    target.0, &target.1, &target.2, target.3, target.4,
                ));
        if matched.disposition == SemanticModelMatchDisposition::Conflict {
            return Ok(ConcurrencyAnswer::Open {
                partial: None,
                reasons: vec![ConcurrencyOpenReason::AmbiguousTarget],
            });
        }
        let Some(selected) = matched.records.first() else {
            // Declaration identity does not describe the external body's
            // effects. Only a selected complete summary can certify an empty
            // inventory; absence of that summary leaves the call open.
            return Ok(ConcurrencyAnswer::Open {
                partial: None,
                reasons: vec![ConcurrencyOpenReason::UnresolvedTarget],
            });
        };
        if selected.record.completeness != Completeness::Complete {
            return Ok(ConcurrencyAnswer::Open {
                partial: None,
                reasons: vec![ConcurrencyOpenReason::UnresolvedTarget],
            });
        }
        Ok(ConcurrencyAnswer::Proven(Some(selected.record)))
    }

    fn exact_model_effects(
        &self,
        call: &CallSiteHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ConcurrencyAnswer<Vec<ResolvedConcurrencyEffect>>, SemanticProviderError> {
        let (selected, mut reasons) = self.exact_model_summary(call, request)?.into_parts();
        let mut effects = Vec::new();
        for effect in selected
            .into_iter()
            .flat_map(|summary| &summary.concurrency_effects)
        {
            match self.bind_effect(call, effect, request)? {
                ConcurrencyAnswer::Proven(Some(effect)) => effects.push(effect),
                ConcurrencyAnswer::Proven(None) => {}
                ConcurrencyAnswer::Open {
                    partial: Some(effect),
                    reasons: effect_reasons,
                } => {
                    effects.push(effect);
                    reasons.extend(effect_reasons);
                }
                ConcurrencyAnswer::Open {
                    partial: None,
                    reasons: effect_reasons,
                } => reasons.extend(effect_reasons),
            }
        }
        Ok(if reasons.is_empty() {
            ConcurrencyAnswer::Proven(effects)
        } else {
            ConcurrencyAnswer::Open {
                partial: effects,
                reasons,
            }
        })
    }

    fn bind_effect(
        &self,
        call: &CallSiteHandle,
        effect: &CompiledConcurrencyEffect,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ConcurrencyAnswer<Option<ResolvedConcurrencyEffect>>, SemanticProviderError> {
        let location =
            |answer: ConcurrencyAnswer<Option<ResolvedConcurrencySubject>>,
             mapper: &dyn Fn(ResolvedConcurrencySubject) -> ResolvedConcurrencyEffect| {
                match answer {
                    ConcurrencyAnswer::Proven(Some(location)) => {
                        ConcurrencyAnswer::Proven(Some(mapper(location)))
                    }
                    ConcurrencyAnswer::Proven(None) => ConcurrencyAnswer::Open {
                        partial: None,
                        reasons: vec![ConcurrencyOpenReason::UnknownLocation],
                    },
                    ConcurrencyAnswer::Open {
                        partial: Some(location),
                        reasons,
                    } => {
                        assert_eq!(
                            location.reasons, reasons,
                            "an open subject retains every identity reason"
                        );
                        let global_reasons = reasons
                            .into_iter()
                            .filter(|reason| *reason == ConcurrencyOpenReason::BudgetExhausted)
                            .collect::<Vec<_>>();
                        let effect = mapper(location);
                        if global_reasons.is_empty() {
                            ConcurrencyAnswer::Proven(Some(effect))
                        } else {
                            ConcurrencyAnswer::Open {
                                partial: Some(effect),
                                reasons: global_reasons,
                            }
                        }
                    }
                    ConcurrencyAnswer::Open {
                        partial: None,
                        reasons,
                    } => ConcurrencyAnswer::Open {
                        partial: None,
                        reasons,
                    },
                }
            };
        Ok(match effect {
            CompiledConcurrencyEffect::Unsupported { protocol } => ConcurrencyAnswer::Open {
                partial: None,
                reasons: vec![ConcurrencyOpenReason::UnsupportedSynchronization(
                    protocol.clone().into_boxed_str(),
                )],
            },
            CompiledConcurrencyEffect::TaskSpawn { callable, group } => {
                let (targets, mut reasons) = Self::callback_targets(call, callable).into_parts();
                let group = if let Some(group) = group {
                    match self.canonical_actual(call, group, request)? {
                        ConcurrencyAnswer::Proven(Some(group)) => Some(group),
                        ConcurrencyAnswer::Proven(None) => {
                            reasons.push(ConcurrencyOpenReason::UnknownLocation);
                            None
                        }
                        ConcurrencyAnswer::Open {
                            partial: Some(group),
                            reasons: group_reasons,
                        } => {
                            assert_eq!(
                                group.reasons, group_reasons,
                                "an open task group retains every identity reason"
                            );
                            reasons.extend(group_reasons.into_iter().filter(|reason| {
                                *reason == ConcurrencyOpenReason::BudgetExhausted
                            }));
                            Some(group)
                        }
                        ConcurrencyAnswer::Open {
                            partial: None,
                            reasons: group_reasons,
                        } => {
                            reasons.extend(group_reasons);
                            None
                        }
                    }
                } else {
                    None
                };
                let effect = (!targets.is_empty()).then(|| {
                    let row = call
                        .procedure()
                        .semantics()
                        .call_site(call.id())
                        .expect("owned modeled call");
                    let callable = Self::actual_input(row, callable)
                        .expect("callback targets require an actual callable value");
                    ResolvedConcurrencyEffect::TaskSpawn {
                        callable,
                        targets,
                        group,
                    }
                });
                if reasons.is_empty() {
                    ConcurrencyAnswer::Proven(effect)
                } else {
                    ConcurrencyAnswer::Open {
                        partial: effect,
                        reasons,
                    }
                }
            }
            CompiledConcurrencyEffect::TaskJoin { group } => {
                location(self.canonical_actual(call, group, request)?, &|group| {
                    ResolvedConcurrencyEffect::TaskJoin { group }
                })
            }
            CompiledConcurrencyEffect::LockAcquire { lock, mode } => {
                location(self.canonical_actual(call, lock, request)?, &|lock| {
                    ResolvedConcurrencyEffect::LockAcquire {
                        lock,
                        mode: lock_mode(*mode),
                    }
                })
            }
            CompiledConcurrencyEffect::LockRelease { lock, mode } => {
                location(self.canonical_actual(call, lock, request)?, &|lock| {
                    ResolvedConcurrencyEffect::LockRelease {
                        lock,
                        mode: lock_mode(*mode),
                    }
                })
            }
            CompiledConcurrencyEffect::WaitGroupAdd { group, delta } => {
                location(self.canonical_actual(call, group, request)?, &|group| {
                    ResolvedConcurrencyEffect::WaitGroupAdd {
                        group,
                        delta: exact_integer_input(call, delta),
                    }
                })
            }
            CompiledConcurrencyEffect::WaitGroupDone { group } => {
                location(self.canonical_actual(call, group, request)?, &|group| {
                    ResolvedConcurrencyEffect::WaitGroupDone { group }
                })
            }
            CompiledConcurrencyEffect::WaitGroupWait { group } => {
                location(self.canonical_actual(call, group, request)?, &|group| {
                    ResolvedConcurrencyEffect::WaitGroupWait { group }
                })
            }
            CompiledConcurrencyEffect::Atomic {
                location: input,
                operation,
            } => location(self.canonical_actual(call, input, request)?, &|location| {
                ResolvedConcurrencyEffect::Atomic {
                    location,
                    operation: atomic_operation(*operation),
                }
            }),
        })
    }
}

impl ConcurrencyProvider for WorkspaceConcurrencyProvider<'_> {
    fn summary_behavior_identity(
        &self,
    ) -> Option<crate::analyzer::semantic::IcfgProviderBehaviorIdentity> {
        use crate::analyzer::semantic::IcfgProvider;

        Some(
            crate::analyzer::semantic::WorkspaceIcfgProvider::with_active_semantic_model_snapshot(
                self.workspace,
                self.active_models.clone(),
            )
            .behavior_identity(),
        )
    }

    fn complete_summary(
        &self,
        procedure: &ProcedureHandle,
    ) -> Option<&brokk_bifrost_flow::dataflow::SemanticProcedureSummary> {
        self.summaries.as_ref()?.summary_for(procedure)
    }

    fn procedure_semantics_precharged(&self, procedure: &ProcedureHandle) -> bool {
        self.summaries.as_ref().is_some_and(|summaries| {
            // Projection can omit a target that remains live-resolvable. Only
            // procedures actually present in the fresh closure were scanned.
            summaries.procedure_semantics_precharged() && summaries.summary_for(procedure).is_some()
        })
    }

    fn complete_call_targets(
        &self,
        procedure: &ProcedureHandle,
        call: CallSiteId,
    ) -> Option<&[ProcedureHandle]> {
        self.summaries
            .as_ref()?
            .complete_call_targets(procedure, call)
    }

    fn allocation_is_task_local(
        &self,
        procedure: &ProcedureHandle,
        allocation: AllocationId,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ConcurrencyAnswer<bool>, SemanticProviderError> {
        let semantics = procedure.semantics();
        let allocation = semantics
            .allocation(allocation)
            .expect("validated allocation belongs to its procedure");
        let object = crate::analyzer::semantic::AbstractObject::new(
            AccessPathRoot::Allocation(
                procedure
                    .allocation_handle(allocation.id)
                    .expect("validated allocation retains its handle"),
            ),
            ObjectCardinality::Unknown,
        )
        .map_err(|error| SemanticProviderError::internal(error.to_string()))?;
        let ownership_start = procedure
            .point_handle(allocation.point)
            .expect("validated allocation retains its point");
        let oracle = self.workspace.icfg_provider();
        for exit in [
            semantics.normal_exit_point(),
            semantics.exceptional_exit_point(),
        ] {
            let query = FreshObjectPublicationQuery::new(
                object.clone(),
                ownership_start.clone(),
                procedure
                    .point_handle(exit)
                    .expect("validated procedure retains its exit point"),
                OracleCallContext::empty(),
            )
            .map_err(|error| SemanticProviderError::internal(error.to_string()))?;
            let outcome = oracle.fresh_object_publications(&query, request)?;
            if outcome.budget_exceeded().is_some()
                || matches!(outcome, SemanticOutcome::Cancelled { .. })
            {
                return Ok(ConcurrencyAnswer::Open {
                    partial: false,
                    reasons: vec![ConcurrencyOpenReason::BudgetExhausted],
                });
            }
            let Some(result) = outcome.available_value() else {
                return Ok(ConcurrencyAnswer::Open {
                    partial: false,
                    reasons: vec![ConcurrencyOpenReason::UnknownPublication],
                });
            };
            if !outcome.is_complete()
                || !result.has_exhaustive_proven_inventory()
                || !result.publications().candidates().is_empty()
            {
                return Ok(ConcurrencyAnswer::Open {
                    partial: false,
                    reasons: vec![ConcurrencyOpenReason::UnknownPublication],
                });
            }
        }
        Ok(ConcurrencyAnswer::Proven(true))
    }

    fn may_have_modeled_effects(&self, call: &CallSiteHandle) -> bool {
        // Missing model activation does not establish an unresolved callee's
        // effects. Preserve dispatch uncertainty even without an active pack;
        // exact source targets and absent external summaries are handled below.
        let row = call
            .procedure()
            .semantics()
            .call_site(call.id())
            .expect("validated call handle resolves");
        let retained_targets = self
            .summaries
            .as_ref()
            .and_then(|summaries| summaries.complete_call_targets(call.procedure(), call.id()));
        let Some(retained_targets) = retained_targets else {
            return true;
        };
        if retained_targets
            .iter()
            .any(|target| self.procedure_has_concurrency_model(target))
        {
            return true;
        }
        match &row.declared_targets {
            CallableTargetResolution::Proven(target) => {
                self.declared_target_has_concurrency_model(call.procedure(), row, target)
            }
            CallableTargetResolution::Ambiguous(targets)
            | CallableTargetResolution::Unproven(targets)
            | CallableTargetResolution::ExceededBudget(targets) => targets.iter().any(|target| {
                self.declared_target_has_concurrency_model(call.procedure(), row, target)
            }),
            CallableTargetResolution::Unknown | CallableTargetResolution::Unsupported => false,
        }
    }

    fn resolve_call(
        &self,
        call: &CallSiteHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ConcurrencyAnswer<Vec<ProcedureHandle>>, SemanticProviderError> {
        let outcome = self.dispatch_sessions.resolve_call(call, request)?;
        let partial = outcome
            .available_value()
            .map(|result| {
                result
                    .candidates()
                    .iter()
                    .filter(|candidate| dispatch_candidate_is_exact(candidate))
                    .map(|candidate| candidate.target().clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let proven = outcome.is_complete()
            && outcome.available_value().is_some_and(|result| {
                complete_exclusive_dispatch_is_external_only(true, result).is_some()
            });
        Ok(if proven {
            ConcurrencyAnswer::Proven(partial)
        } else {
            ConcurrencyAnswer::Open {
                partial,
                reasons: vec![dispatch_open_reason(&outcome)],
            }
        })
    }

    fn modeled_call_preserves_ordinary_heap(
        &self,
        call: &CallSiteHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<bool, SemanticProviderError> {
        // `exact_model_summary` admits only a complete external-only dispatch;
        // source-only and mixed/partial calls therefore cannot consume this
        // independent heap-preservation claim.
        Ok(matches!(self.exact_model_summary(call, request)?,
            ConcurrencyAnswer::Proven(Some(summary)) if summary.ordinary_heap_unchanged))
    }

    fn modeled_effects(
        &self,
        call: &CallSiteHandle,
        targets: &ConcurrencyAnswer<Vec<ProcedureHandle>>,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ConcurrencyAnswer<Vec<ResolvedConcurrencyEffect>>, SemanticProviderError> {
        if matches!(targets, ConcurrencyAnswer::Proven(targets) if !targets.is_empty()) {
            // The invocation's stable callable binding can prove a source
            // body even when context-free dispatch cannot name it. Source
            // bodies are expanded by the solver and do not use external models.
            return Ok(ConcurrencyAnswer::Proven(Vec::new()));
        }
        if let ConcurrencyAnswer::Open { reasons, .. } = targets {
            // The workspace resolver's open answer fails the same exhaustive
            // dispatch gate required by model lookup. Reuse that evidence.
            return Ok(ConcurrencyAnswer::Open {
                partial: Vec::new(),
                reasons: reasons.clone(),
            });
        }
        self.exact_model_effects(call, request)
    }

    fn resolved_member_identity(
        &self,
        member: &crate::analyzer::semantic::SemanticLocator,
    ) -> Option<ResolvedMemberDeclaration> {
        let span = member.anchor().span();
        let key = (
            member.path().as_str().to_owned(),
            span.start_byte(),
            span.end_byte(),
        );
        if let Some(cached) = self.member_identities.borrow().get(&key) {
            return cached.clone();
        }
        let resolved = self.name_member_declaration(member);
        self.member_identities
            .borrow_mut()
            .insert(key, resolved.clone());
        resolved
    }

    fn allocation_binds_by_reference(
        &self,
        procedure: &ProcedureHandle,
        allocation: AllocationId,
    ) -> Option<bool> {
        let semantics = procedure.semantics();
        let site = semantics.allocation(allocation)?;
        let mapping = semantics.source_mapping(site.source)?;
        let file = super::witness_projection::locator_file(self.workspace, &mapping.locator);
        let source = self.workspace.analyzer().indexed_source(&file)?;
        crate::analyzer::usages::get_definition::allocation_binds_by_reference_at_offset(
            &file,
            &source,
            mapping.locator.anchor().span().start_byte() as usize,
        )
    }

    fn index_uses_separate_associative_storage(
        &self,
        procedure: &ProcedureHandle,
        location: MemoryLocationId,
    ) -> bool {
        // The Go producer emits Aggregate indexed identity only for a proven
        // map. Map entries are not addressable struct/array storage, so updating
        // an entry cannot overwrite the field slot holding a map descriptor.
        procedure.semantics().locator().language() == LanguageDialect::Standard(Language::Go)
            && matches!(
                procedure
                    .semantics()
                    .memory_location(location)
                    .map(|row| &row.kind),
                Some(MemoryLocationKind::Index {
                    identity: crate::analyzer::semantic::IndexedLocationIdentity::Aggregate,
                    ..
                })
            )
    }

    fn result_binds_by_reference(&self, procedure: &ProcedureHandle, ordinal: u32) -> Option<bool> {
        let locator = procedure.semantics().locator();
        if locator.language() != LanguageDialect::Standard(Language::Go) {
            return None;
        }
        let analyzer = self.workspace.analyzer();
        let file = super::witness_projection::locator_file(self.workspace, locator);
        let declaration = super::dispatch::declaration_at_locator(analyzer, locator, &file)?;
        let span = locator.anchor().span();
        if !declaration.is_function()
            || declaration.is_synthetic()
            || declaration.source() != &file
            || !analyzer.ranges_of(&declaration).into_iter().any(|range| {
                range.start_byte == span.start_byte() as usize
                    && range.end_byte == span.end_byte() as usize
            })
        {
            return None;
        }
        let source = analyzer.indexed_source(&file)?;
        let ordinal = usize::try_from(ordinal).ok()?;
        crate::analyzer::usages::get_definition::result_binds_by_reference_at_ordinal(
            analyzer,
            &file,
            &source,
            &declaration,
            ordinal,
        )
    }

    fn lexical_cell_cardinality(
        &self,
        procedure: &ProcedureHandle,
        binding: ValueId,
    ) -> ConcurrencyObjectCardinality {
        use crate::analyzer::semantic::SemanticValueKind;

        let semantics = procedure.semantics();
        let value = semantics
            .value(binding)
            .expect("validated lexical cell binding exists");
        if matches!(
            value.kind,
            SemanticValueKind::Parameter { .. } | SemanticValueKind::Receiver { .. }
        ) {
            return ConcurrencyObjectCardinality::Singleton;
        }
        if !matches!(value.kind, SemanticValueKind::Local) {
            return ConcurrencyObjectCardinality::Unknown;
        }
        let Some(mapping) = semantics.source_mapping(value.source) else {
            return ConcurrencyObjectCardinality::Unknown;
        };
        let file = super::witness_projection::locator_file(self.workspace, &mapping.locator);
        let Some(source) = self.workspace.analyzer().indexed_source(&file) else {
            return ConcurrencyObjectCardinality::Unknown;
        };
        match crate::analyzer::usages::get_definition::lexical_binding_repeats_at_offset(
            &file,
            &source,
            mapping.locator.anchor().span().start_byte() as usize,
        ) {
            Some(false) => ConcurrencyObjectCardinality::Singleton,
            Some(true) => ConcurrencyObjectCardinality::Multiple,
            None => ConcurrencyObjectCardinality::Unknown,
        }
    }

    fn member_binds_by_reference(
        &self,
        member: &crate::analyzer::semantic::SemanticLocator,
    ) -> Option<bool> {
        let span = member.anchor().span();
        let key = (
            member.path().as_str().to_owned(),
            span.start_byte(),
            span.end_byte(),
        );
        if let Some(cached) = self.reference_members.borrow().get(&key) {
            return *cached;
        }
        let resolved = self.field_binding_mode(member);
        self.reference_members.borrow_mut().insert(key, resolved);
        resolved
    }

    fn receiver_binds_by_reference(&self, procedure: &ProcedureHandle) -> bool {
        let locator = procedure.semantics().locator();
        // Go is the language that copies a receiver. Everything else passes
        // one by reference, so its callees reach the caller's object.
        if locator.language() != LanguageDialect::Standard(Language::Go) {
            return true;
        }
        let Some(member) = locator
            .declaration()
            .segments()
            .last()
            .and_then(|segment| segment.name())
        else {
            return false;
        };
        let key = (locator.path().as_str().to_owned(), member.to_owned());
        if let Some(cached) = self.receiver_bindings.borrow().get(&key) {
            return *cached;
        }
        let resolved = !self.declares_value_receiver(locator, member);
        self.receiver_bindings.borrow_mut().insert(key, resolved);
        resolved
    }

    fn parameter_is_reference_free(&self, procedure: &ProcedureHandle, ordinal: u32) -> bool {
        let key = (procedure.clone(), ordinal);
        if let Some(known) = self.reference_free_parameters.borrow().get(&key) {
            return *known;
        }
        let resolve = || {
            let locator = procedure.semantics().locator();
            if locator.language() != LanguageDialect::Standard(Language::Go) {
                return None;
            }
            let analyzer = self.workspace.analyzer();
            let file = super::witness_projection::locator_file(self.workspace, locator);
            let declaration = super::dispatch::declaration_at_locator(analyzer, locator, &file)?;
            let span = locator.anchor().span();
            if !analyzer.ranges_of(&declaration).into_iter().any(|range| {
                range.start_byte == span.start_byte() as usize
                    && range.end_byte == span.end_byte() as usize
            }) {
                return None;
            }
            let source = analyzer.indexed_source(&file)?;
            crate::analyzer::usages::get_definition::parameter_is_reference_free_at_ordinal(
                analyzer,
                &file,
                &source,
                &declaration,
                usize::try_from(ordinal).ok()?,
            )
        };
        let proven = resolve() == Some(true);
        self.reference_free_parameters
            .borrow_mut()
            .insert(key, proven);
        proven
    }

    fn parameter_binding(&self, procedure: &ProcedureHandle, ordinal: u32) -> Option<bool> {
        let key = (procedure.clone(), ordinal);
        if let Some(cached) = self.parameter_bindings.borrow().get(&key) {
            return *cached;
        }
        let resolve = || {
            let locator = procedure.semantics().locator();
            if locator.language() != LanguageDialect::Standard(Language::Go) {
                return None;
            }
            let analyzer = self.workspace.analyzer();
            let file = super::witness_projection::locator_file(self.workspace, locator);
            let source = analyzer.indexed_source(&file)?;
            let span = locator.anchor().span();
            // Callable source identity includes anonymous function literals. A
            // declaration name neither locates those parameters nor distinguishes
            // equal method names on different receiver types.
            crate::analyzer::usages::get_definition::parameter_binds_by_reference_at_span(
                &file,
                &source,
                span.start_byte() as usize,
                span.end_byte() as usize,
                usize::try_from(ordinal).ok()?,
            )
        };
        let resolved = resolve();
        self.parameter_bindings.borrow_mut().insert(key, resolved);
        resolved
    }

    fn parameter_preserves_backing(&self, procedure: &ProcedureHandle, ordinal: u32) -> bool {
        let key = (procedure.clone(), ordinal);
        if let Some(cached) = self.backing_parameters.borrow().get(&key) {
            return *cached;
        }
        let resolve = || -> Option<bool> {
            let locator = procedure.semantics().locator();
            if locator.language() != LanguageDialect::Standard(Language::Go) {
                return None;
            }
            let file = super::witness_projection::locator_file(self.workspace, locator);
            let source = self.workspace.analyzer().indexed_source(&file)?;
            let span = locator.anchor().span();
            crate::analyzer::usages::get_definition::parameter_preserves_backing_at_span(
                &file,
                &source,
                span.start_byte() as usize,
                span.end_byte() as usize,
                usize::try_from(ordinal).ok()?,
            )
        };
        let resolved = resolve() == Some(true);
        self.backing_parameters.borrow_mut().insert(key, resolved);
        resolved
    }

    fn canonical_location(
        &self,
        procedure: &ProcedureHandle,
        point: ProgramPointId,
        location: MemoryLocationId,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ConcurrencyAnswer<Option<CanonicalConcurrencyLocation>>, SemanticProviderError>
    {
        self.resolved_location(procedure, point, location, request)
            .map(legacy_canonical_answer)
    }

    fn resolved_location(
        &self,
        procedure: &ProcedureHandle,
        point: ProgramPointId,
        location: MemoryLocationId,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ConcurrencyAnswer<ResolvedConcurrencyLocation>, SemanticProviderError> {
        let row = procedure
            .semantics()
            .memory_location(location)
            .expect("validated memory location exists");
        if let MemoryLocationKind::Index {
            base,
            identity: IndexedLocationIdentity::Aggregate,
            ..
        } = row.kind
        {
            let answer = self.resolved_value(procedure, point, base, request)?;
            return Ok(match answer {
                ConcurrencyAnswer::Proven(base) => match base.exact_candidate() {
                    Some(base) => ConcurrencyAnswer::Proven(ResolvedConcurrencyLocation::exact(
                        CanonicalConcurrencyLocation::new(
                            format!("{}/index:aggregate", base.identity),
                            row.kind.label(),
                        ),
                    )),
                    None => open_resolved_location(),
                },
                ConcurrencyAnswer::Open { partial, reasons } => {
                    let partial = partial.exact_candidate().map_or_else(
                        ResolvedConcurrencyLocation::unknown,
                        |base| {
                            ResolvedConcurrencyLocation::exact(CanonicalConcurrencyLocation::new(
                                format!("{}/index:aggregate", base.identity),
                                row.kind.label(),
                            ))
                        },
                    );
                    ConcurrencyAnswer::Open { partial, reasons }
                }
            });
        }
        let point = procedure
            .point_handle(point)
            .expect("validated program point exists");
        let scoped = |locator| {
            ScopedSemanticLocator::new(Arc::clone(procedure.artifact()), locator)
                .map_err(|error| SemanticProviderError::internal(error.to_string()))
        };
        let (root, selectors) = match &row.kind {
            MemoryLocationKind::Field { base, member } => (
                AccessPathRoot::Value(value_handle(procedure, *base)?),
                vec![AccessSelector::Field(scoped(member.clone())?)],
            ),
            MemoryLocationKind::Property { base, key } => (
                AccessPathRoot::Value(value_handle(procedure, *base)?),
                vec![AccessSelector::Property(key.clone())],
            ),
            MemoryLocationKind::Index {
                base,
                index,
                constant_index,
                ..
            } => {
                let selector = match (constant_index, index) {
                    (Some(index), _) => IndexSelector::Constant(*index),
                    (None, Some(index)) => IndexSelector::Exact(value_handle(procedure, *index)?),
                    (None, None) => IndexSelector::Any,
                };
                (
                    AccessPathRoot::Value(value_handle(procedure, *base)?),
                    vec![AccessSelector::Index(selector)],
                )
            }
            // The solver canonicalizes a static itself unless the producer
            // marked the location's identity unresolved, which only happens
            // for a value whose declaring file the producer may not read.
            MemoryLocationKind::Static { member } => {
                return Ok(resolved_static(self.workspace, procedure, location, member));
            }
            MemoryLocationKind::LexicalCell { .. } | MemoryLocationKind::Capture { .. } => {
                unreachable!("the concurrency solver canonicalizes non-heap locations directly")
            }
        };
        let path = AccessPath::exact(root, selectors, OracleLimits::default())
            .map_err(|error| SemanticProviderError::internal(error.to_string()))?;
        let query = AccessPathAtPoint::new(
            path,
            point,
            ObservationPhase::BeforeEffects,
            OracleCallContext::empty(),
        )
        .map_err(|error| SemanticProviderError::internal(error.to_string()))?;
        let outcome = self
            .workspace
            .semantic_oracle_provider()
            .locations(&query, request)?;
        let Some(result) = outcome.available_value() else {
            return Ok(open_resolved_location());
        };
        let mut candidates = Vec::new();
        let mut all_singleton = true;
        let mut exhaustive = outcome.is_complete() && result.locations().coverage().is_exhaustive();
        for candidate in result.locations().candidates() {
            if !candidate.is_proven_complete() {
                exhaustive = false;
            }
            let location = candidate.value();
            all_singleton &= location.object().cardinality() == ObjectCardinality::Singleton;
            let Some(path_identity) = exact_path_identity(location.path()) else {
                exhaustive = false;
                continue;
            };
            let object =
                TypestateObjectKey::for_object(location.object()).public_canonical_rendering();
            candidates.push(CanonicalConcurrencyLocation::new(
                format!("{object}/{path_identity}"),
                row.kind.label(),
            ));
        }
        let cardinality = if all_singleton && candidates.len() == 1 {
            ConcurrencyObjectCardinality::Singleton
        } else if candidates.is_empty() {
            ConcurrencyObjectCardinality::Unknown
        } else {
            ConcurrencyObjectCardinality::Multiple
        };
        let resolved = ResolvedConcurrencyLocation::new(
            candidates,
            exhaustive,
            cardinality,
            ConcurrencyEscape::Unknown,
            ConcurrencyOwnership::Unknown,
        );
        Ok(if exhaustive && !resolved.candidates().is_empty() {
            ConcurrencyAnswer::Proven(resolved)
        } else {
            ConcurrencyAnswer::Open {
                partial: resolved,
                reasons: vec![ConcurrencyOpenReason::AliasSetTruncated],
            }
        })
    }

    fn canonical_value(
        &self,
        procedure: &ProcedureHandle,
        point: ProgramPointId,
        value: ValueId,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ConcurrencyAnswer<Option<CanonicalConcurrencyLocation>>, SemanticProviderError>
    {
        self.canonical_value_at(
            procedure,
            point,
            value,
            ObservationPhase::BeforeEffects,
            request,
        )
    }

    fn resolved_value(
        &self,
        procedure: &ProcedureHandle,
        point: ProgramPointId,
        value: ValueId,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ConcurrencyAnswer<ResolvedConcurrencyLocation>, SemanticProviderError> {
        self.resolved_value_at(
            procedure,
            point,
            value,
            ObservationPhase::BeforeEffects,
            request,
        )
    }

    fn canonical_allocation(
        &self,
        procedure: &ProcedureHandle,
        allocation: AllocationId,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ConcurrencyAnswer<Option<CanonicalConcurrencyLocation>>, SemanticProviderError>
    {
        let allocation = procedure
            .semantics()
            .allocation(allocation)
            .expect("validated allocation exists");
        self.canonical_value_at(
            procedure,
            allocation.point,
            allocation.result,
            ObservationPhase::AfterEffects,
            request,
        )
    }

    fn resolved_allocation(
        &self,
        procedure: &ProcedureHandle,
        allocation: AllocationId,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ConcurrencyAnswer<ResolvedConcurrencyLocation>, SemanticProviderError> {
        let allocation = procedure
            .semantics()
            .allocation(allocation)
            .expect("validated allocation exists");
        self.resolved_value_at(
            procedure,
            allocation.point,
            allocation.result,
            ObservationPhase::AfterEffects,
            request,
        )
    }
}

fn collect_local_callable_targets(
    procedure: &ProcedureHandle,
    resolution: &CallableTargetResolution,
    targets: &mut Vec<ProcedureHandle>,
    open: &mut bool,
) {
    match resolution {
        CallableTargetResolution::Proven(CallableTarget::Local(target)) => targets.push(
            procedure
                .artifact()
                .procedure_handle(*target)
                .expect("validated local callable target exists"),
        ),
        CallableTargetResolution::Proven(_) => *open = true,
        CallableTargetResolution::Ambiguous(candidates)
        | CallableTargetResolution::Unproven(candidates)
        | CallableTargetResolution::ExceededBudget(candidates) => {
            *open = true;
            for target in candidates {
                if let CallableTarget::Local(target) = target {
                    targets.push(
                        procedure
                            .artifact()
                            .procedure_handle(*target)
                            .expect("validated local callable target exists"),
                    );
                }
            }
        }
        CallableTargetResolution::Unknown | CallableTargetResolution::Unsupported => *open = true,
    }
}

fn dispatch_open_reason(
    outcome: &SemanticOutcome<crate::analyzer::semantic::DispatchResult>,
) -> ConcurrencyOpenReason {
    match outcome {
        SemanticOutcome::ExceededBudget { .. } | SemanticOutcome::Cancelled { .. } => {
            ConcurrencyOpenReason::BudgetExhausted
        }
        _ => ConcurrencyOpenReason::UnresolvedTarget,
    }
}

fn dispatch_candidate_is_exact(candidate: &crate::analyzer::semantic::DispatchCandidate) -> bool {
    matches!(candidate.proof(), ProofStatus::Proven)
        && matches!(candidate.completeness(), EvidenceCompleteness::Complete)
}

/// Classify a complete dispatch only when every retained arm is one exact
/// domain. `Some(true)` is external-only and `Some(false)` is source-only;
/// mixed, partial, unresolved, truncated, and empty results return `None`.
fn complete_exclusive_dispatch_is_external_only(
    outcome_complete: bool,
    result: &crate::analyzer::semantic::DispatchResult,
) -> Option<bool> {
    if !outcome_complete
        || result.coverage() != CandidateCoverage::Exhaustive
        || !result.candidates().iter().all(dispatch_candidate_is_exact)
        || !result.boundaries().iter().all(|boundary| {
            matches!(boundary.proof, ProofStatus::Proven)
                // Boundary completeness describes the unavailable body.
                // Exhaustive dispatch and proven target identity answer the
                // separate target-set question; the selected complete model
                // supplies the body's effects.
                && (boundary.exact_external_target().is_some()
                    || boundary.unmaterialized_external_target().is_some())
        })
    {
        return None;
    }
    match (
        result.candidates().is_empty(),
        result.boundaries().is_empty(),
    ) {
        (false, true) => Some(false),
        (true, false) => Some(true),
        // There is no target domain to classify when both are empty, and
        // source plus external arms remain mixed even with complete proofs.
        (true, true) | (false, false) => None,
    }
}

fn value_handle(
    procedure: &ProcedureHandle,
    value: ValueId,
) -> Result<ValueHandle, SemanticProviderError> {
    procedure.value_handle(value).ok_or_else(|| {
        SemanticProviderError::internal("concurrency input names a stale semantic value")
    })
}

/// Resolve one imported package value's occurrence back to its
/// declaration.
///
/// A language adapter that declares no intra-file dependencies cannot read
/// the declaring file, so it stores the occurrence and marks the location
/// unresolved. This provider can see the workspace, and resolving the
/// occurrence is what lets two files naming one variable agree that they
/// name one storage. Without it a cross-package race is not merely missed:
/// the two accesses look disjoint and the run reports itself clean.
///
/// Anything short of exactly one declaration stays open. Several
/// declarations would be a genuine ambiguity, and none means the reference
/// left the workspace.
fn resolved_static(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    location: MemoryLocationId,
    member: &crate::analyzer::semantic::SemanticLocator,
) -> ConcurrencyAnswer<ResolvedConcurrencyLocation> {
    // The declaration is the identity both sides of an import must agree on.
    // A producer that resolved it stored the declaration's own locator, and one
    // that could not stored a use site; resolving either lands on the same
    // declaration, so the two meet.
    let unresolved_by_producer = procedure.semantics().gaps().iter().any(|gap| {
        gap.subject == crate::analyzer::semantic::SemanticGapSubject::MemoryLocation(location)
    });
    let fallback = || {
        if unresolved_by_producer {
            // The stored locator is a use site. Rendering it would claim two
            // occurrences of one variable are different storage.
            open_resolved_location()
        } else {
            ConcurrencyAnswer::Proven(ResolvedConcurrencyLocation::exact(
                CanonicalConcurrencyLocation::new(format!("static:{member:?}"), "static"),
            ))
        }
    };
    let file = super::witness_projection::locator_file(workspace, member);
    let Some(source) = workspace.analyzer().indexed_source(&file) else {
        return fallback();
    };
    let span = member.anchor().span();
    let requests = vec![
        crate::analyzer::usages::get_definition::DefinitionLookupRequest {
            file: file.clone(),
            line: None,
            column: None,
            start_byte: Some(span.start_byte() as usize),
            end_byte: Some(span.end_byte() as usize),
        },
    ];
    let outcomes = crate::analyzer::usages::get_definition::resolve_definition_batch_with_source(
        workspace.analyzer(),
        requests,
        file,
        Arc::from(source),
    );
    let Some(outcome) = outcomes.into_iter().next() else {
        return fallback();
    };
    if outcome.status != crate::analyzer::usages::get_definition::DefinitionLookupStatus::Resolved
        || !outcome.diagnostics.is_empty()
    {
        return fallback();
    }
    let [definition] = outcome.definitions.as_slice() else {
        return fallback();
    };
    ConcurrencyAnswer::Proven(ResolvedConcurrencyLocation::exact(
        CanonicalConcurrencyLocation::new(format!("static:{}", definition.fq_name()), "static"),
    ))
}

impl WorkspaceConcurrencyProvider<'_> {
    /// Name the field declaration one member locator stands for.
    ///
    /// A producer that could type the receiver anchors the member at the
    /// field's declaration; one that could not, such as a capture inside a
    /// spawned closure, anchors it at the use. A definition lookup follows the
    /// use to the declaration, and the declaration names itself. Both sides
    /// then agree, which is what lets their accesses be compared.
    ///
    /// Anything other than exactly one field declaration abstains and leaves
    /// the producer's identity alone. Merging distinct fields would turn a
    /// missed race into a reported one, which is worse than the miss.
    /// Whether any declaration of `member` in the locator's file declares a
    /// value receiver.
    ///
    /// A file can declare one name on more than one receiver type. Answering
    /// from any value receiver keeps the caller's object out of a callee that
    /// might copy it, without resolving which declaration the call reaches. A
    /// name with no receiver at all is not a method and answers `false`.
    fn declares_value_receiver(
        &self,
        locator: &crate::analyzer::semantic::SemanticLocator,
        member: &str,
    ) -> bool {
        let analyzer = self.workspace.analyzer();
        let file = super::witness_projection::locator_file(self.workspace, locator);
        for unit in analyzer.get_declarations(&file) {
            // A Go method's display name carries its owner, as in `box.bump`.
            // Compare the interned last segment so the member is read from
            // structure rather than from the rendered name.
            let declares_member = unit.fq().last().is_some_and(|segment| {
                brokk_bifrost_core::analyzer::fq_name::segment_interner()
                    .resolve(segment)
                    .0
                    == member
            });
            if !unit.is_function() || !declares_member {
                continue;
            }
            for metadata in analyzer.signature_metadata(&unit) {
                let Some(receiver) = metadata.extension_receiver_type_identity() else {
                    continue;
                };
                if !receiver.is_pointer() {
                    return true;
                }
            }
        }
        false
    }

    /// Whether the field a member locator names carries a payload by reference.
    ///
    /// A copy of a struct copies its direct fields, so a write to one cannot
    /// reach the original. A pointer or reference field inside that copy still
    /// addresses one object, so a write through it does. Unknown named types
    /// stay unresolved: a type alias may hide either storage mode.
    fn field_binding_mode(
        &self,
        member: &crate::analyzer::semantic::SemanticLocator,
    ) -> Option<bool> {
        let analyzer = self.workspace.analyzer();
        let file = super::witness_projection::locator_file(self.workspace, member);
        let source = analyzer.indexed_source(&file)?;
        let span = member.anchor().span();
        let mut fields = self
            .resolved_member_identity(member)
            .into_iter()
            .flat_map(|declaration| analyzer.get_definitions(&declaration.name))
            .filter(|unit| unit.is_field())
            .collect::<Vec<_>>();
        if fields.is_empty()
            && let Some(unit) = crate::analyzer::usages::get_definition::declaration_site_at_offset(
                analyzer,
                &file,
                &source,
                span.start_byte() as usize,
            )
        {
            fields.push(unit);
        }
        fields.sort();
        fields.dedup();
        if fields.is_empty() {
            return None;
        }

        let mut binding = None;
        for field in fields {
            let metadata = analyzer.signature_metadata(&field);
            if metadata.is_empty() {
                return None;
            }
            for metadata in metadata {
                let identity = metadata.return_type_identity()?;
                let mode =
                    self.field_type_binding_mode(member.language().language(), &field, identity);
                let mode = mode?;
                if let Some(existing) = binding
                    && existing != mode
                {
                    return None;
                }
                binding = Some(mode);
            }
        }
        binding
    }

    fn field_type_binding_mode(
        &self,
        language: Language,
        field: &crate::analyzer::CodeUnit,
        identity: &brokk_bifrost_core::analyzer::model::StructuredTypeIdentity,
    ) -> Option<bool> {
        if identity.is_pointer() || identity.is_reference() {
            return Some(true);
        }
        if language != Language::Go {
            return None;
        }
        if identity.is_slice() || identity.is_map() {
            return Some(true);
        }
        // A Go array owns its inline element storage.
        if identity.is_array() {
            return Some(false);
        }

        let nominal = identity.nominal_name()?;
        if !nominal.lexical_scope().is_empty() {
            return None;
        }

        // A bare Go type parameter can shadow a same-file nominal type. Keep
        // that field unresolved instead of proving the shadowed type inline.
        match self.field_type_parameter_status(field, identity) {
            Some(false) => {}
            Some(true) | None => return None,
        }

        if nominal.path().len() != 1 {
            return self.modeled_go_nominal_type_binding_mode(field, nominal);
        }
        let [name] = nominal.path() else {
            unreachable!("nominal path length was checked above");
        };

        // A same-file type declaration with structured field children proves a
        // concrete inline struct. A named alias with no such declaration is
        // deliberately left open: its underlying type may be a pointer.
        let analyzer = self.workspace.analyzer();
        let mut candidates = analyzer
            .get_declarations(field.source())
            .into_iter()
            .filter(|unit| unit.is_class() && unit.terminal_name() == name)
            .collect::<Vec<_>>();
        candidates.sort();
        candidates.dedup();
        let [candidate] = candidates.as_slice() else {
            return None;
        };
        analyzer
            .get_members_in_class(candidate)
            .into_iter()
            .any(|member| member.is_field())
            .then_some(false)
    }

    /// Resolve a qualified Go nominal through the importing file's structured
    /// import facts, then consult one exact activated type declaration. A
    /// terminal name alone is deliberately insufficient: two packages may
    /// declare the same type name, and a missing or conflicting model keeps
    /// the storage mode unresolved.
    fn modeled_go_nominal_type_binding_mode(
        &self,
        field: &crate::analyzer::CodeUnit,
        nominal: &brokk_bifrost_core::analyzer::model::StructuredTypeName,
    ) -> Option<bool> {
        let [local_package, type_name] = nominal.path() else {
            return None;
        };
        if local_package.is_empty() || type_name.is_empty() {
            return None;
        }

        let analyzer = self.workspace.analyzer();
        let scope = AnalyzerQueryScope::new(analyzer);
        let token = scope.token();
        let provider = analyzer.import_analysis_provider_for_file(field.source())?;
        let package_paths = provider
            .import_info_of(token, field.source())
            .into_iter()
            .filter(|import| !import.is_wildcard)
            .filter_map(|import| {
                let path = import.path.as_ref()?;
                if path.kind != Some(StructuredImportPathKind::Namespace)
                    || import.local_name() != Some(local_package)
                {
                    return None;
                }
                let rendered = path.render_segments("/");
                (!rendered.is_empty()).then_some(rendered)
            })
            .collect::<Vec<_>>();
        let [package_path] = package_paths.as_slice() else {
            return None;
        };

        let canonical_name = format!("{package_path}.{type_name}");
        let active = self.active_models.as_ref()?;
        let matched = active.active_models().types_named(&canonical_name);
        if matched.disposition != SemanticModelMatchDisposition::Unique {
            return None;
        }
        let [selected] = matched.records.as_slice() else {
            return None;
        };
        let record = selected.record;
        (selected.shard.manifest.language
            == LanguageDialect::Standard(Language::Go).semantic_pack_label()
            && record.name == canonical_name
            && record.type_kind == TypeKind::Struct
            && record.visibility == Visibility::Public)
            .then_some(false)
    }

    /// Return whether a nominal Go field type is an enclosing type parameter.
    ///
    /// Go declarations currently do not persist their type-parameter list in
    /// `SignatureMetadata`, so the AST path is the authoritative fallback.
    fn field_type_parameter_status(
        &self,
        field: &crate::analyzer::CodeUnit,
        identity: &brokk_bifrost_core::analyzer::model::StructuredTypeIdentity,
    ) -> Option<bool> {
        if identity.generic_argument_count().is_some() {
            return Some(false);
        }
        let nominal = identity.nominal_name()?;
        let [name] = nominal.path() else {
            return Some(false);
        };
        if !nominal.lexical_scope().is_empty() {
            return Some(false);
        }

        let analyzer = self.workspace.analyzer();
        if let Some(owner) = analyzer
            .parent_of(field)
            .filter(crate::analyzer::CodeUnit::is_class)
        {
            let metadata = analyzer.signature_metadata(&owner);
            if metadata.iter().any(|metadata| {
                metadata.type_parameters_recorded()
                    && metadata
                        .type_parameters()
                        .iter()
                        .any(|parameter| parameter == name)
            }) {
                return Some(true);
            }
            if !metadata.is_empty()
                && metadata
                    .iter()
                    .all(|metadata| metadata.type_parameters_recorded())
            {
                return Some(false);
            }
        }

        let source = analyzer.indexed_source(field.source())?;
        let tree = crate::analyzer::usages::get_definition::parse_tree_for_language(
            field.source(),
            Language::Go,
            &source,
        )?;
        let field_declaration = analyzer.ranges_of(field).into_iter().find_map(|range| {
            let mut node = tree
                .root_node()
                .named_descendant_for_byte_range(range.start_byte, range.end_byte)?;
            loop {
                if node.kind() == "field_declaration" {
                    if node.has_error() || node.is_missing() {
                        return None;
                    }
                    return Some(node);
                }
                node = node.parent()?;
            }
        })?;
        let mut type_node = field_declaration.child_by_field_name("type")?;
        loop {
            match type_node.kind() {
                "type_identifier" | "identifier" => break,
                "parenthesized_type" | "type_elem" => {
                    type_node = type_node
                        .child_by_field_name("type")
                        .or_else(|| type_node.named_child(0))?;
                }
                _ => return Some(false),
            }
        }
        if type_node.utf8_text(source.as_bytes()).ok()? != name {
            return Some(false);
        }

        let mut ancestor = Some(field_declaration);
        while let Some(node) = ancestor {
            if node.kind() == "type_spec" {
                if node.has_error() || node.is_missing() {
                    return None;
                }
                let Some(type_parameters) = node.child_by_field_name("type_parameters") else {
                    return Some(false);
                };
                if type_parameters.has_error() || type_parameters.is_missing() {
                    return None;
                }
                let mut parameters_cursor = type_parameters.walk();
                let is_parameter = type_parameters
                    .named_children(&mut parameters_cursor)
                    .filter(|parameter| parameter.kind() == "type_parameter_declaration")
                    .any(|parameter| {
                        let mut names_cursor = parameter.walk();
                        parameter
                            .children_by_field_name("name", &mut names_cursor)
                            .any(|name_node| {
                                name_node.utf8_text(source.as_bytes()).ok() == Some(name)
                            })
                    });
                return Some(is_parameter);
            }
            ancestor = node.parent();
        }
        None
    }

    /// Resolve the field declaration behind one member locator, and report
    /// whether that locator anchors at the declaration or at a use of it.
    ///
    /// The two answers come from different lookups and never overlap: a use
    /// resolves as a reference to its definition, and a declaration resolves
    /// only by being one. The solver needs the distinction because a producer
    /// stores the declaration's locator wherever it could type the receiver
    /// and the use's locator wherever it could not.
    fn name_member_declaration(
        &self,
        member: &crate::analyzer::semantic::SemanticLocator,
    ) -> Option<ResolvedMemberDeclaration> {
        let analyzer = self.workspace.analyzer();
        let file = super::witness_projection::locator_file(self.workspace, member);
        let source = analyzer.indexed_source(&file)?;
        let span = member.anchor().span();
        let outcomes =
            crate::analyzer::usages::get_definition::resolve_definition_batch_with_source(
                analyzer,
                vec![
                    crate::analyzer::usages::get_definition::DefinitionLookupRequest {
                        file: file.clone(),
                        line: None,
                        column: None,
                        start_byte: Some(span.start_byte() as usize),
                        end_byte: Some(span.end_byte() as usize),
                    },
                ],
                file.clone(),
                Arc::from(source.clone()),
            );
        let referenced = outcomes.into_iter().next().and_then(|outcome| {
            if outcome.status
                != crate::analyzer::usages::get_definition::DefinitionLookupStatus::Resolved
                || !outcome.diagnostics.is_empty()
            {
                return None;
            }
            let [definition] = outcome.definitions.as_slice() else {
                return None;
            };
            (definition.is_field() || definition.is_function())
                .then(|| (definition.fq_name().to_string(), definition.is_function()))
        });
        if let Some((name, is_callable)) = referenced {
            return Some(ResolvedMemberDeclaration {
                name,
                is_declaration_site: false,
                is_callable,
            });
        }
        if let Some(name) =
            crate::analyzer::usages::get_definition::modeled_method_selection_at_offset(
                analyzer,
                &file,
                &source,
                span.start_byte() as usize,
            )
        {
            return Some(ResolvedMemberDeclaration {
                name,
                is_declaration_site: false,
                is_callable: true,
            });
        }
        crate::analyzer::usages::get_definition::declaration_site_at_offset(
            analyzer,
            &file,
            &source,
            span.start_byte() as usize,
        )
        .filter(|declaration| declaration.is_field() || declaration.is_function())
        .map(|declaration| ResolvedMemberDeclaration {
            name: declaration.fq_name().to_string(),
            is_declaration_site: true,
            is_callable: declaration.is_function(),
        })
    }
}

fn open_resolved_location() -> ConcurrencyAnswer<ResolvedConcurrencyLocation> {
    ConcurrencyAnswer::Open {
        partial: ResolvedConcurrencyLocation::unknown(),
        reasons: vec![ConcurrencyOpenReason::UnknownLocation],
    }
}

fn legacy_canonical_answer(
    answer: ConcurrencyAnswer<ResolvedConcurrencyLocation>,
) -> ConcurrencyAnswer<Option<CanonicalConcurrencyLocation>> {
    match answer {
        ConcurrencyAnswer::Proven(location) => match location.exact_candidate() {
            Some(candidate) => ConcurrencyAnswer::Proven(Some(candidate.clone())),
            None => ConcurrencyAnswer::Open {
                partial: None,
                reasons: vec![ConcurrencyOpenReason::UnknownLocation],
            },
        },
        ConcurrencyAnswer::Open { reasons, .. } => ConcurrencyAnswer::Open {
            partial: None,
            reasons: reasons
                .into_iter()
                .map(|reason| match reason {
                    ConcurrencyOpenReason::AliasSetTruncated => {
                        ConcurrencyOpenReason::UnknownLocation
                    }
                    reason => reason,
                })
                .collect(),
        },
    }
}

/// Name the tail of an exact access path the way the solver names a field step
/// it composes itself.
///
/// The two renderings meet on one location: an access whose base the solver
/// cannot name class-side keeps the answer built here, while its counterpart is
/// recomposed there. Spelling a field with the locator's `Debug` on this side
/// and with the storage digest on that one left the two permanently disjoint.
fn exact_path_identity(path: &AccessPath) -> Option<String> {
    let [selector] = path.selectors() else {
        return Some("root".to_string());
    };
    match selector {
        AccessSelector::Field(field) => Some(field_step_selector(field.locator())),
        AccessSelector::Property(property) => Some(format!("property:{property}")),
        AccessSelector::Index(IndexSelector::Constant(index)) => Some(format!("index:{index}")),
        AccessSelector::Index(IndexSelector::Exact(_) | IndexSelector::Any) => None,
    }
}

fn lock_mode(mode: CompiledLockMode) -> ConcurrencyLockMode {
    match mode {
        CompiledLockMode::Shared => ConcurrencyLockMode::Shared,
        CompiledLockMode::Exclusive => ConcurrencyLockMode::Exclusive,
    }
}

fn atomic_operation(operation: CompiledAtomicOperation) -> ConcurrencyAtomicOperation {
    match operation {
        CompiledAtomicOperation::Load => ConcurrencyAtomicOperation::Load,
        CompiledAtomicOperation::Store => ConcurrencyAtomicOperation::Store,
        CompiledAtomicOperation::ReadModifyWrite => ConcurrencyAtomicOperation::ReadModifyWrite,
    }
}

fn exact_integer_input(call: &CallSiteHandle, input: &CompiledSummaryInput) -> Option<i64> {
    let semantics = call.procedure().semantics();
    let row = semantics.call_site(call.id())?;
    let value = WorkspaceConcurrencyProvider::actual_input(row, input)?;
    let value = semantics.value(value)?;
    match value.kind {
        crate::analyzer::semantic::SemanticValueKind::UnsignedInteger(value) => {
            i64::try_from(value).ok()
        }
        _ => None,
    }
}

#[derive(Debug, Clone)]
pub(super) struct ConcurrentAccessConflictValue {
    pub(super) conflict: ConcurrentAccessConflict,
    pub(super) id: String,
    pub(super) root_procedure_id: String,
    pub(super) file: ProjectFile,
    pub(super) range: Range,
    pub(super) ast_id: Option<String>,
    pub(super) first_file: ProjectFile,
    pub(super) first_range: Range,
    pub(super) second_file: ProjectFile,
    pub(super) second_range: Range,
}

impl ConcurrentAccessConflictValue {
    pub(super) fn file(&self) -> &ProjectFile {
        &self.file
    }
}

pub(super) fn project_conflict(
    workspace: &WorkspaceAnalyzer,
    root: &SemanticProcedureValue,
    conflict: ConcurrentAccessConflict,
) -> ConcurrentAccessConflictValue {
    let source_site = |site: &brokk_bifrost_flow::concurrency::ConcurrentAccessSite| {
        let mapping = site
            .procedure
            .semantics()
            .source_mapping(site.source)
            .expect("validated conflict access has a source mapping");
        let span = mapping.locator.anchor().span();
        (
            super::witness_projection::locator_file(workspace, &mapping.locator),
            Range {
                start_byte: span.start_byte() as usize,
                end_byte: span.end_byte() as usize,
                start_line: span.start().line() as usize + 1,
                end_line: span.end().line() as usize + 1,
            },
        )
    };
    let (first_file, first_range) = source_site(&conflict.first);
    let (second_file, second_range) = source_site(&conflict.second);
    let anchor = conflict_anchor(&conflict);
    let mapping = anchor
        .procedure
        .semantics()
        .source_mapping(anchor.source)
        .expect("validated conflict access has a source mapping");
    let span = mapping.locator.anchor().span();
    let file = super::witness_projection::locator_file(workspace, &mapping.locator);
    let ast_identity = mapping.ast_identity;
    let mut digest = crate::analyzer::semantic::LengthDelimitedDigest::new(
        b"bifrost.code_query.concurrent_access_conflict.v1",
    );
    digest.push(super::semantic::procedure_wire_id(&root.handle).as_bytes());
    digest.push(conflict.location.identity.as_bytes());
    let mut sites = [stable_site(&conflict.first), stable_site(&conflict.second)];
    sites.sort();
    digest.push(sites[0].as_bytes());
    digest.push(sites[1].as_bytes());
    ConcurrentAccessConflictValue {
        conflict,
        id: digest.finish().to_string(),
        root_procedure_id: super::semantic::procedure_wire_id(&root.handle),
        file,
        range: Range {
            start_byte: span.start_byte() as usize,
            end_byte: span.end_byte() as usize,
            start_line: span.start().line() as usize + 1,
            end_line: span.end().line() as usize + 1,
        },
        ast_id: ast_identity.map(|identity| {
            super::super::occurrence_rows::ast_id(identity.content(), identity.node_id())
        }),
        first_file,
        first_range,
        second_file,
        second_range,
    }
}

fn conflict_anchor(
    conflict: &ConcurrentAccessConflict,
) -> &brokk_bifrost_flow::concurrency::ConcurrentAccessSite {
    match (conflict.first.mode, conflict.second.mode) {
        (brokk_bifrost_flow::concurrency::ConcurrentAccessMode::Write, _) => &conflict.first,
        (_, brokk_bifrost_flow::concurrency::ConcurrentAccessMode::Write) => &conflict.second,
        _ => &conflict.first,
    }
}

/// One access site's identity inside a conflict digest.
///
/// The procedure is named by its mount-free wire id rather than by the
/// `SemanticArtifactKey` its durable key folds: that key carries a
/// `WorkspaceMountId` hashed from the absolute workspace root, so a conflict
/// found in the same content at two roots would digest differently and every
/// data-race finding would classify as new under `--diff-base`.
fn stable_site(site: &brokk_bifrost_flow::concurrency::ConcurrentAccessSite) -> String {
    format!(
        "{}:{}:{}",
        super::semantic::procedure_wire_id(&site.procedure),
        site.point.get(),
        site.source.get()
    )
}

#[cfg(test)]
#[allow(clippy::duplicate_mod)]
#[path = "../../../../../test-support/inline_project.rs"]
mod inline_project;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic::{
        DispatchBoundary, DispatchBoundaryKind, DispatchOracle, DispatchResult,
        OracleRelationArena, OracleRelationId, OracleRelationOwner, OracleRelationRecord,
    };
    use crate::analyzer::semantic_model::{
        CatalogOptions, CompilerOptions, SemanticModelActivationEvidence,
        SemanticModelActivationRequest, SemanticModelRuntimeLimits, SemanticModelRuntimeOutcome,
        SemanticPackCatalog, SessionPackSource, SessionPackSourceKind, SourceFormat,
        acquire_active_semantic_models, compile_source,
    };
    use crate::analyzer::{AnalyzerConfig, CodeUnit, Language};
    use crate::cancellation::CancellationToken;
    use semver::Version;

    use super::inline_project::InlineTestProject;

    struct CountingIcfgProvider<'workspace> {
        inner: crate::analyzer::semantic::WorkspaceIcfgProvider<'workspace>,
        call_transfers: std::cell::Cell<usize>,
        behavior: Option<crate::analyzer::semantic::IcfgProviderBehaviorIdentity>,
        publication_unknown: bool,
    }

    impl DispatchOracle for CountingIcfgProvider<'_> {
        fn resolve_call(
            &self,
            call: &CallSiteHandle,
            request: &mut SemanticRequest<'_>,
        ) -> Result<SemanticOutcome<DispatchResult>, SemanticProviderError> {
            self.inner.resolve_call(call, request)
        }
    }

    impl HeapOracle for CountingIcfgProvider<'_> {
        fn pointees(
            &self,
            value: &ValueAtPoint,
            request: &mut SemanticRequest<'_>,
        ) -> Result<SemanticOutcome<crate::analyzer::semantic::PointsToResult>, SemanticProviderError>
        {
            self.inner.pointees(value, request)
        }

        fn locations(
            &self,
            access: &AccessPathAtPoint,
            request: &mut SemanticRequest<'_>,
        ) -> Result<SemanticOutcome<crate::analyzer::semantic::LocationResult>, SemanticProviderError>
        {
            self.inner.locations(access, request)
        }

        fn alias(
            &self,
            query: &crate::analyzer::semantic::AliasQuery,
            request: &mut SemanticRequest<'_>,
        ) -> Result<SemanticOutcome<crate::analyzer::semantic::AliasResult>, SemanticProviderError>
        {
            self.inner.alias(query, request)
        }

        fn fresh_object_publications(
            &self,
            query: &crate::analyzer::semantic::FreshObjectPublicationQuery,
            request: &mut SemanticRequest<'_>,
        ) -> Result<
            SemanticOutcome<crate::analyzer::semantic::FreshObjectPublicationResult>,
            SemanticProviderError,
        > {
            if self.publication_unknown {
                return Ok(SemanticOutcome::Unknown {
                    partial: None,
                    work: crate::analyzer::semantic::SemanticWork::default(),
                });
            }
            self.inner.fresh_object_publications(query, request)
        }

        fn update_eligibility(
            &self,
            store: &crate::analyzer::semantic::StoreAtPoint,
            request: &mut SemanticRequest<'_>,
        ) -> Result<
            SemanticOutcome<crate::analyzer::semantic::UpdateEligibility>,
            SemanticProviderError,
        > {
            self.inner.update_eligibility(store, request)
        }
    }

    impl crate::analyzer::semantic::IcfgProvider for CountingIcfgProvider<'_> {
        fn behavior_identity(&self) -> crate::analyzer::semantic::IcfgProviderBehaviorIdentity {
            self.behavior
                .unwrap_or_else(|| self.inner.behavior_identity())
        }

        fn call_transfers(
            &self,
            caller: &ProcedureHandle,
            call: CallSiteId,
            request: &mut SemanticRequest<'_>,
        ) -> Result<
            SemanticOutcome<crate::analyzer::semantic::CallTransferSet>,
            SemanticProviderError,
        > {
            self.call_transfers
                .set(self.call_transfers.get().saturating_add(1));
            self.inner.call_transfers(caller, call, request)
        }

        fn snapshot(
            &self,
            root: &ProcedureHandle,
            limits: crate::analyzer::semantic::IcfgSnapshotLimits,
            request: &mut SemanticRequest<'_>,
        ) -> Result<SemanticOutcome<crate::analyzer::semantic::IcfgSnapshot>, SemanticProviderError>
        {
            self.inner.snapshot(root, limits, request)
        }
    }

    #[derive(Default)]
    struct CountingSummaryReads(std::cell::Cell<usize>);

    impl brokk_bifrost_flow::dataflow::SummaryReadObserver for CountingSummaryReads {
        fn summary_read(
            &self,
            _identity: &brokk_bifrost_flow::dataflow::ProcedureSummaryIdentity,
            _content: crate::analyzer::semantic::StableDigest,
            _dependencies: &[brokk_bifrost_flow::dataflow::SummaryDependencyKey],
        ) {
            self.0.set(self.0.get().saturating_add(1));
        }
    }

    #[test]
    fn repeated_concurrency_dispatch_reuses_source_and_retains_budget_reasons() {
        use crate::analyzer::semantic::SemanticBudget;

        let source = "package main\nfunc run(cb func()) { cb() }\n";
        let project = InlineTestProject::with_language(Language::Go)
            .file("main.go", source)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut materialization = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &project.file("main.go"),
                &mut SemanticRequest::new(&mut materialization, &cancellation),
            )
            .expect("Go semantics materialize")
            .available_value()
            .expect("Go semantics are available")
            .clone();
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| !procedure.call_sites().is_empty())
            .expect("callback invocation");
        let call = artifact
            .procedure_handle(procedure.id())
            .and_then(|handle| handle.call_site_handle(procedure.call_sites()[0].id))
            .expect("owned callback call");
        let limits = SemanticWork {
            source_bytes: source.len() * 8,
            ..SemanticWork::default_limits()
        };
        let provider = WorkspaceConcurrencyProvider::new(&workspace, None, None);
        let mut budget = SemanticBudget::new(limits).unwrap();
        let mut paid_source = None;
        for _ in 0..32 {
            let answer = provider
                .resolve_call(&call, &mut SemanticRequest::new(&mut budget, &cancellation))
                .unwrap();
            assert!(
                matches!(answer, ConcurrencyAnswer::Open { ref reasons, .. }
                if reasons == &[ConcurrencyOpenReason::UnresolvedTarget]),
                "{answer:?}"
            );
            let modeled = provider
                .exact_model_summary(&call, &mut SemanticRequest::new(&mut budget, &cancellation))
                .unwrap();
            assert!(
                matches!(modeled, ConcurrencyAnswer::Open { ref reasons, .. }
                if reasons == &[ConcurrencyOpenReason::UnresolvedTarget]),
                "{modeled:?}"
            );
            let used = budget.used().source_bytes;
            assert!(used > 0, "the first exact source read must be charged");
            assert_eq!(
                *paid_source.get_or_insert(used),
                used,
                "repeating unresolved dispatch must reuse the paid source without hiding uncertainty"
            );
        }
        cancellation.cancel();
        let cancelled = provider
            .resolve_call(&call, &mut SemanticRequest::new(&mut budget, &cancellation))
            .unwrap();
        assert!(
            matches!(cancelled, ConcurrencyAnswer::Open { ref reasons, .. }
            if reasons == &[ConcurrencyOpenReason::BudgetExhausted]),
            "{cancelled:?}"
        );

        let cancellation = CancellationToken::default();
        let provider = WorkspaceConcurrencyProvider::new(&workspace, None, None);
        let mut low_budget = SemanticBudget::new(SemanticWork {
            source_bytes: 1,
            ..SemanticWork::default_limits()
        })
        .unwrap();
        let limited = provider
            .resolve_call(
                &call,
                &mut SemanticRequest::new(&mut low_budget, &cancellation),
            )
            .unwrap();
        assert!(
            matches!(limited, ConcurrencyAnswer::Open { ref reasons, .. }
            if reasons == &[ConcurrencyOpenReason::BudgetExhausted]),
            "{limited:?}"
        );
        let limited_model = provider
            .exact_model_summary(
                &call,
                &mut SemanticRequest::new(&mut low_budget, &cancellation),
            )
            .unwrap();
        assert!(
            matches!(limited_model, ConcurrencyAnswer::Open { ref reasons, .. }
            if reasons == &[ConcurrencyOpenReason::BudgetExhausted]),
            "{limited_model:?}"
        );
    }

    #[test]
    fn external_declaration_requires_an_explicit_complete_effect_summary() {
        use crate::analyzer::semantic::SemanticBudget;
        use serde_json::json;

        let project = InlineTestProject::with_language(Language::Go)
            .file("main.go", "package main\nimport driver \"example.com/driver\"\nfunc caller() { driver.Open() }\n")
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &project.file("main.go"),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .unwrap()
            .available_value()
            .expect("Go semantics available")
            .clone();
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| !procedure.call_sites().is_empty())
            .expect("caller procedure");
        let call = artifact
            .procedure_handle(procedure.id())
            .unwrap()
            .call_site_handle(procedure.call_sites()[0].id)
            .unwrap();

        let absent = WorkspaceConcurrencyProvider::new(&workspace, None, None);
        let targets = absent
            .resolve_call(&call, &mut SemanticRequest::new(&mut budget, &cancellation))
            .unwrap();
        let effects = absent
            .modeled_effects(
                &call,
                &targets,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .unwrap();
        assert!(
            matches!(effects, ConcurrencyAnswer::Open { ref reasons, .. }
            if reasons == &[ConcurrencyOpenReason::UnresolvedTarget]),
            "{effects:?}"
        );

        for completeness in [None, Some("partial"), Some("complete")] {
            let mut pack_source = json!({
                "schema_version": 2,
                "pack_id": "test.go.external-effect-inventory",
                "version": "1.0.0",
                "producer": {"name": "test", "version": "1.0.0"},
                "language": "go", "ecosystem": "go",
                "compatibility": {"bifrost": ">=0.10.7, <1.0.0", "toolchains": []},
                "provenance": {"source": "synthetic declaration and effects fixture", "revision": "1"},
                "license": "MIT", "completeness": "complete",
                "safety": {"generated_code_only": false, "review_required": false},
                "shards": [{
                    "id": "declarations", "activation": [{}],
                    "payload": {
                        "kind": "declaration_facts",
                        "types": [{
                            "id": "type.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                            "name": "example.com/driver", "type_kind": "module",
                            "visibility": "public", "aliases": ["driver"],
                            "locator": {"kind": "artifact", "path": "driver.go", "symbol": "example.com/driver"}
                        }],
                        "members": [{
                            "id": "member.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                            "owner": "type.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                            "name": "Open", "member_kind": "function", "visibility": "public",
                            "is_static": true, "callable_family_complete": true,
                            "signature": {"parameters": []},
                            "locator": {"kind": "artifact", "path": "driver.go", "symbol": "example.com/driver.Open"}
                        }]
                    }
                }]
            });
            if let Some(completeness) = completeness {
                pack_source["shards"].as_array_mut().unwrap().push(json!({
                    "id": "effects", "activation": [{}],
                    "payload": {"kind": "procedure_summaries", "summaries": [{
                        "id": "driver.open",
                        "target": {"path": "driver.go", "symbol": "example.com/driver.Open()",
                            "has_receiver": false, "parameter_count": 0},
                        "completeness": completeness,
                        "normal_continuation_absent": completeness == "partial",
                        "transfers": [], "effects": [], "concurrency_effects": []
                    }]}
                }));
            }
            let pack = compile_source(
                SourceFormat::Json,
                &serde_json::to_vec(&pack_source).unwrap(),
                &CompilerOptions::default(),
            )
            .unwrap_or_else(|diagnostics| panic!("fixture pack: {diagnostics:#?}"));
            let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
            catalog
                .register_session_pack(
                    &pack,
                    &SessionPackSource {
                        kind: SessionPackSourceKind::Embedded,
                        source_id: "test:external-effect-inventory".to_owned(),
                    },
                )
                .unwrap();
            let activation = acquire_active_semantic_models(
                workspace.analyzer(),
                &catalog,
                None,
                &SemanticModelActivationRequest {
                    bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
                    evidence: vec![SemanticModelActivationEvidence {
                        language: "go".to_owned(),
                        ecosystem: "go".to_owned(),
                        package: None,
                        module: None,
                        toolchain: None,
                        target: None,
                        configuration: None,
                        artifact_sha256: None,
                    }],
                    controls: Vec::new(),
                    limits: SemanticModelRuntimeLimits::default(),
                },
                &cancellation,
            );
            let snapshot = match activation {
                SemanticModelRuntimeOutcome::Ready { snapshot, .. } => snapshot,
                other => panic!("fixture activation: {other:#?}"),
            };
            let provider = WorkspaceConcurrencyProvider::new(&workspace, Some(snapshot), None);
            let mut budget = SemanticBudget::default();
            let targets = provider
                .resolve_call(&call, &mut SemanticRequest::new(&mut budget, &cancellation))
                .unwrap();
            assert!(
                matches!(&targets, ConcurrencyAnswer::Proven(targets) if targets.is_empty()),
                "the fixture must prove external-only dispatch before testing summary absence: {targets:?}"
            );
            assert!(provider.may_have_modeled_effects(&call));
            let summary = provider
                .exact_model_summary(&call, &mut SemanticRequest::new(&mut budget, &cancellation))
                .unwrap();
            let effects = provider
                .modeled_effects(
                    &call,
                    &targets,
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .unwrap();
            if completeness == Some("complete") {
                assert!(
                    matches!(summary, ConcurrencyAnswer::Proven(Some(summary)) if summary.concurrency_effects.is_empty()),
                    "{summary:?}"
                );
                assert!(
                    matches!(effects, ConcurrencyAnswer::Proven(ref effects) if effects.is_empty()),
                    "{effects:?}"
                );
            } else {
                assert!(
                    matches!(summary, ConcurrencyAnswer::Open { ref reasons, .. }
                    if reasons == &[ConcurrencyOpenReason::UnresolvedTarget]),
                    "{summary:?}"
                );
                assert!(
                    matches!(effects, ConcurrencyAnswer::Open { ref reasons, .. }
                    if reasons == &[ConcurrencyOpenReason::UnresolvedTarget]),
                    "{effects:?}"
                );
            }
        }
    }

    #[test]
    fn complete_external_dispatch_does_not_hide_an_unresolved_alternative() {
        let project = InlineTestProject::with_language(Language::TypeScript)
            .file(
                "external.ts",
                r#"import { work } from "third-party";

export function caller() {
    work();
}
"#,
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        });
        let file = project.file("external.ts");
        let cancellation = crate::analyzer::semantic::CancellationToken::default();
        let mut budget = crate::analyzer::semantic::SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("TypeScript semantics materialize")
            .available_value()
            .expect("TypeScript semantics are available")
            .clone();
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| !procedure.call_sites().is_empty())
            .expect("external caller procedure");
        let call = artifact
            .procedure_handle(procedure.id())
            .and_then(|procedure| {
                procedure.call_site_handle(procedure.semantics().call_sites()[0].id)
            })
            .expect("external call handle");
        let oracle = workspace.semantic_oracle_provider();
        let mut dispatch_budget = crate::analyzer::semantic::SemanticBudget::default();
        let dispatch = oracle
            .resolve_call(
                &call,
                &mut SemanticRequest::new(&mut dispatch_budget, &cancellation),
            )
            .expect("external dispatch resolves");
        let source_dispatch = dispatch
            .available_value()
            .expect("external dispatch retains typed boundaries");
        let external_target = source_dispatch
            .boundaries()
            .iter()
            .find_map(|boundary| boundary.unmaterialized_external_target().cloned())
            .expect("fixture retains a structured external target");
        let external_completeness = source_dispatch
            .boundaries()
            .iter()
            .find(|boundary| boundary.unmaterialized_external_target().is_some())
            .map(|boundary| boundary.completeness.clone())
            .expect("external target retains body-availability quality");
        let external_kind = DispatchBoundaryKind::External(Some(external_target.locator().clone()));
        let unresolved_kind = DispatchBoundaryKind::Unresolved;
        let call_row = call
            .procedure()
            .semantics()
            .call_site(call.id())
            .expect("call row");
        let evidence = call
            .procedure()
            .evidence_handle(call_row.target_evidence)
            .expect("call target evidence handle");
        let limits = OracleLimits::default();
        let arena = OracleRelationArena::new(
            OracleRelationOwner::Dispatch(call.clone()),
            vec![
                OracleRelationRecord::dispatch_boundary(
                    external_kind.clone(),
                    std::iter::once(evidence.clone()),
                    limits,
                )
                .expect("external relation record"),
                OracleRelationRecord::dispatch_boundary(
                    unresolved_kind.clone(),
                    std::iter::once(evidence),
                    limits,
                )
                .expect("unresolved relation record"),
            ],
            limits,
        )
        .expect("dispatch relation arena");
        let external_arm = DispatchBoundary {
            kind: external_kind,
            external_callee_identity: None,
            exact_external_target: None,
            unmaterialized_external_target: Some(external_target),
            proof: ProofStatus::Proven,
            // External bodies are unavailable by design, so this is normally
            // Partial even when the target set is exhaustive. The dispatch
            // gate must distinguish those two completeness questions.
            completeness: external_completeness,
            provenance: Box::new([arena
                .handle(OracleRelationId::new(0))
                .expect("external relation handle")]),
        };
        let unresolved_arm = DispatchBoundary {
            kind: unresolved_kind,
            external_callee_identity: None,
            exact_external_target: None,
            unmaterialized_external_target: None,
            proof: ProofStatus::Unproven("alternative is unresolved".into()),
            completeness: EvidenceCompleteness::Partial("alternative is unresolved".into()),
            provenance: Box::new([arena
                .handle(OracleRelationId::new(1))
                .expect("unresolved relation handle")]),
        };
        let external_only = DispatchResult::new(
            &call,
            Vec::new(),
            vec![external_arm.clone()],
            CandidateCoverage::Exhaustive,
            limits,
        )
        .expect("one complete external arm is a valid dispatch");
        assert_eq!(
            complete_exclusive_dispatch_is_external_only(true, &external_only),
            Some(true),
            "one complete external arm is eligible for a modeled summary"
        );
        assert_eq!(
            complete_exclusive_dispatch_is_external_only(false, &external_only),
            None,
            "retained target evidence cannot certify an unfinished dispatch request"
        );
        let mixed = DispatchResult::new(
            &call,
            Vec::new(),
            vec![external_arm, unresolved_arm],
            CandidateCoverage::Open,
            limits,
        )
        .expect("open dispatch retains both typed alternatives");
        assert_eq!(
            complete_exclusive_dispatch_is_external_only(true, &mixed),
            None,
            "a complete external arm cannot hide an unresolved alternative"
        );
    }

    #[test]
    fn complete_source_dispatch_does_not_consume_an_external_summary() {
        let project = InlineTestProject::with_language(Language::TypeScript)
            .file(
                "source.ts",
                r#"function target() {}

export function caller() {
    target();
}
"#,
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        });
        let file = project.file("source.ts");
        let cancellation = crate::analyzer::semantic::CancellationToken::default();
        let mut budget = crate::analyzer::semantic::SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("TypeScript semantics materialize")
            .available_value()
            .expect("TypeScript semantics are available")
            .clone();
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| !procedure.call_sites().is_empty())
            .expect("source caller procedure");
        let call = artifact
            .procedure_handle(procedure.id())
            .and_then(|procedure| {
                procedure.call_site_handle(procedure.semantics().call_sites()[0].id)
            })
            .expect("source call handle");
        let mut dispatch_budget = crate::analyzer::semantic::SemanticBudget::default();
        let dispatch = workspace
            .semantic_oracle_provider()
            .resolve_call(
                &call,
                &mut SemanticRequest::new(&mut dispatch_budget, &cancellation),
            )
            .expect("source dispatch resolves");
        let dispatch = dispatch.available_value().expect("source dispatch answer");
        assert_eq!(
            complete_exclusive_dispatch_is_external_only(true, dispatch),
            Some(false),
            "a complete source-only dispatch has no external summary arm"
        );
        assert!(dispatch.boundaries().is_empty());

        let provider = WorkspaceConcurrencyProvider::new(&workspace, None, None);
        let mut provider_budget = crate::analyzer::semantic::SemanticBudget::default();
        let model_answer = provider
            .exact_model_summary(
                &call,
                &mut SemanticRequest::new(&mut provider_budget, &cancellation),
            )
            .expect("source-only model lookup");
        assert!(
            matches!(model_answer, ConcurrencyAnswer::Proven(None)),
            "source-only dispatch must bypass external summary lookup: {model_answer:?}"
        );
    }

    #[test]
    fn go_qualified_struct_model_requires_exact_import_and_type_name() {
        let project = InlineTestProject::with_language(Language::Go)
            .file(
                "main.go",
                r#"package main

import renamed "sync"
import other "other"

type Holder struct {
    modeled renamed.Mutex
    absent other.Mutex
}
"#,
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        });
        let pack_source = br#"{
          "schema_version": 2,
          "pack_id": "test.go.qualified-struct",
          "version": "1.0.0",
          "producer": {"name": "test", "version": "1.0.0"},
          "language": "go",
          "ecosystem": "go",
          "compatibility": {"bifrost": ">=0.10.7, <1.0.0", "toolchains": []},
          "provenance": {"source": "test", "revision": "1"},
          "license": "MIT",
          "completeness": "complete",
          "safety": {"generated_code_only": false, "review_required": false},
          "shards": [{
            "id": "declarations",
            "activation": [{}],
            "payload": {
              "kind": "declaration_facts",
              "types": [{
                "id": "type.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "name": "sync.Mutex",
                "type_kind": "struct",
                "visibility": "public",
                "is_abstract": false,
                "is_sealed": false,
                "has_explicit_type_terms": false,
                "type_parameters": [],
                "type_parameter_constraints": [],
                "embedded_types": [],
                "hierarchy": [],
                "aliases": [],
                "extension_surfaces": [],
                "locator": {
                  "kind": "artifact",
                  "path": "src/sync/mutex.go",
                  "symbol": "sync.Mutex"
                }
              }]
            }
          }]
        }"#;
        let pack = compile_source(SourceFormat::Json, pack_source, &CompilerOptions::default())
            .unwrap_or_else(|diagnostics| panic!("qualified struct pack failed: {diagnostics:#?}"));
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
            .expect("ephemeral semantic-pack catalog");
        catalog
            .register_session_pack(
                &pack,
                &SessionPackSource {
                    kind: SessionPackSourceKind::Embedded,
                    source_id: "test:go-qualified-struct".to_owned(),
                },
            )
            .expect("register qualified struct pack");
        let activation = acquire_active_semantic_models(
            workspace.analyzer(),
            &catalog,
            None,
            &SemanticModelActivationRequest {
                bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).expect("crate version"),
                evidence: vec![SemanticModelActivationEvidence {
                    language: "go".to_owned(),
                    ecosystem: "go".to_owned(),
                    package: None,
                    module: None,
                    toolchain: None,
                    target: None,
                    configuration: None,
                    artifact_sha256: None,
                }],
                controls: Vec::new(),
                limits: SemanticModelRuntimeLimits::default(),
            },
            &CancellationToken::default(),
        );
        let snapshot = match activation {
            SemanticModelRuntimeOutcome::Ready { snapshot, .. } => snapshot,
            other => panic!("qualified struct model activates: {other:#?}"),
        };

        let analyzer = workspace.analyzer();
        let declarations = analyzer.get_declarations(&project.file("main.go"));
        let field = |name: &str| {
            declarations
                .iter()
                .find(|unit| unit.is_field() && unit.short_name() == format!("Holder.{name}"))
                .cloned()
                .unwrap_or_else(|| panic!("missing Holder.{name} field"))
        };
        let field_identity = |field: &CodeUnit| {
            analyzer
                .signature_metadata(field)
                .into_iter()
                .find_map(|metadata| metadata.return_type_identity().cloned())
                .unwrap_or_else(|| panic!("missing type identity for {}", field.short_name()))
        };
        let provider = WorkspaceConcurrencyProvider::new(&workspace, Some(snapshot), None);
        let modeled = field("modeled");
        let modeled_identity = field_identity(&modeled);
        assert_eq!(
            provider.field_type_binding_mode(Language::Go, &modeled, &modeled_identity),
            Some(false),
            "renamed import resolves to the exact modeled sync.Mutex struct"
        );

        let absent = field("absent");
        let absent_identity = field_identity(&absent);
        assert_eq!(
            provider.field_type_binding_mode(Language::Go, &absent, &absent_identity),
            None,
            "same terminal Mutex from an unavailable package stays unresolved"
        );
    }

    #[test]
    fn go_type_parameter_does_not_use_shadowed_nominal_type_for_inline_proof() {
        let project = InlineTestProject::with_language(Language::Go)
            .file(
                "main.go",
                r#"package main

type T struct { n int }

type Box[T any] struct { value T }

type Holder struct { value T }
"#,
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        });
        let analyzer = workspace.analyzer();
        let declarations = analyzer.get_declarations(&project.file("main.go"));
        let field = |owner: &str| {
            declarations
                .iter()
                .find(|unit| unit.is_field() && unit.short_name() == format!("{owner}.value"))
                .cloned()
                .unwrap_or_else(|| panic!("missing {owner}.value field"))
        };
        let field_identity = |field: &CodeUnit| {
            analyzer
                .signature_metadata(field)
                .into_iter()
                .find_map(|metadata| metadata.return_type_identity().cloned())
                .unwrap_or_else(|| panic!("missing type identity for {}", field.short_name()))
        };
        let provider = WorkspaceConcurrencyProvider::new(&workspace, None, None);
        let generic_field = field("Box");
        let generic_identity = field_identity(&generic_field);
        assert_eq!(
            provider.field_type_binding_mode(Language::Go, &generic_field, &generic_identity),
            None,
            "Box.value uses its enclosing T parameter even though package T is a struct"
        );

        let concrete_field = field("Holder");
        let concrete_identity = field_identity(&concrete_field);
        assert_eq!(
            provider.field_type_binding_mode(Language::Go, &concrete_field, &concrete_identity),
            Some(false),
            "Holder.value resolves the concrete package T struct"
        );
    }

    #[test]
    fn go_allocation_storage_mode_uses_exact_shapes_and_offsets() {
        let project = InlineTestProject::with_language(Language::Go)
            .file(
                "main.go",
                r#"package main

type T struct { n int }
type Alias = T
type Array [2]int
type InlineBeforeShadow struct{}
type ReferenceBeforeShadow []int

func localShadow() {
    type InlineBeforeShadow []int
    type ReferenceBeforeShadow struct{}
    _ = InlineBeforeShadow{}
    _ = ReferenceBeforeShadow{}
}

func generic[T ~map[int]int]() {
    _ = T{}
    _ = struct { n int }{}
    _ = [2]int{}
    _ = &T{}
    _ = new(T)
    _ = make([]int, 2)
    _ = make(map[int]int)
    _ = make(chan int)
    _ = Alias{}
    _ = struct { p *T }{p: &T{}}
}

func concrete() {
    _ = T{}
    _ = Array{}
}
"#,
            )
            .build();
        let file = project.file("main.go");
        let source = std::fs::read_to_string(project.root().join("main.go")).unwrap();
        let mode = |expression: &str| {
            let offset = source
                .find(expression)
                .unwrap_or_else(|| panic!("missing allocation expression {expression:?}"))
                + if expression.starts_with("    _ = ") {
                    "    _ = ".len()
                } else {
                    0
                };
            crate::analyzer::usages::get_definition::allocation_binds_by_reference_at_offset(
                &file, &source, offset,
            )
        };

        let whitespace = source.find("    _ = [2]int{}").unwrap();
        assert_eq!(
            crate::analyzer::usages::get_definition::allocation_binds_by_reference_at_offset(
                &file, &source, whitespace
            ),
            None
        );
        assert_eq!(
            mode("    _ = T{}"),
            None,
            "T is the generic function parameter"
        );
        assert_eq!(mode("    _ = struct { n int }{}"), Some(false));
        assert_eq!(mode("    _ = [2]int{}"), Some(false));
        assert_eq!(mode("    _ = &T{}"), Some(true));
        assert_eq!(mode("    _ = new(T)"), Some(true));
        assert_eq!(mode("    _ = make([]int, 2)"), Some(true));
        assert_eq!(mode("    _ = make(map[int]int)"), Some(true));
        assert_eq!(mode("    _ = make(chan int)"), Some(true));
        assert_eq!(
            mode("    _ = Alias{}"),
            None,
            "type aliases remain unresolved"
        );
        assert_eq!(mode("    _ = struct { p *T }{p: &T{}}"), Some(false));
        assert_eq!(mode("    _ = T{}\n    _ = Array{}"), Some(false));
        assert_eq!(mode("    _ = Array{}"), Some(false));
        assert_eq!(mode("    _ = InlineBeforeShadow{}"), None);
        assert_eq!(mode("    _ = ReferenceBeforeShadow{}"), None);
        assert_eq!(
            crate::analyzer::usages::get_definition::allocation_binds_by_reference_at_offset(
                &file,
                &source,
                source.rfind("&T{}").unwrap(),
            ),
            Some(true),
            "nested pointer allocation uses its own offset"
        );
    }

    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
    struct StableConcurrentSite {
        task: brokk_bifrost_flow::concurrency::TaskId,
        procedure: crate::analyzer::semantic::SemanticLocator,
        source: crate::analyzer::semantic::SemanticLocator,
        mode: brokk_bifrost_flow::concurrency::ConcurrentAccessMode,
        access_kind: &'static str,
    }

    fn stable_site(
        site: &brokk_bifrost_flow::concurrency::ConcurrentAccessSite,
    ) -> StableConcurrentSite {
        let source = site
            .procedure
            .semantics()
            .source_mapping(site.source)
            .unwrap_or_else(|| panic!("site source mapping {:?} is present", site.source));
        StableConcurrentSite {
            task: site.task,
            procedure: site.procedure.semantics().locator().clone(),
            source: source.locator.clone(),
            mode: site.mode,
            access_kind: site.access_kind.label(),
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
    struct StableConcurrentConflict {
        location: CanonicalConcurrencyLocation,
        sites: [StableConcurrentSite; 2],
        task_relation: brokk_bifrost_flow::concurrency::ConcurrentTaskRelation,
        ordering: brokk_bifrost_flow::concurrency::ConcurrentOrdering,
        protection: brokk_bifrost_flow::concurrency::ConcurrentProtection,
        proven: bool,
        exhaustive: bool,
        reasons: Vec<ConcurrencyOpenReason>,
    }

    fn stable_conflict(
        conflict: &brokk_bifrost_flow::concurrency::ConcurrentAccessConflict,
    ) -> StableConcurrentConflict {
        let mut sites = [stable_site(&conflict.first), stable_site(&conflict.second)];
        sites.sort();
        let mut reasons = conflict.reasons.clone();
        reasons.sort();
        reasons.dedup();
        StableConcurrentConflict {
            location: conflict.location.clone(),
            sites,
            task_relation: conflict.task_relation,
            ordering: conflict.ordering,
            protection: conflict.protection,
            proven: conflict.proven,
            exhaustive: conflict.exhaustive,
            reasons,
        }
    }

    fn stable_report(
        report: &brokk_bifrost_flow::concurrency::ConcurrentAccessReport,
    ) -> (Vec<StableConcurrentConflict>, Vec<ConcurrencyOpenReason>) {
        let mut conflicts = report
            .conflicts
            .iter()
            .map(stable_conflict)
            .collect::<Vec<_>>();
        conflicts.sort();
        let mut reasons = report.reasons.clone();
        reasons.sort();
        reasons.dedup();
        (conflicts, reasons)
    }

    #[test]
    fn go_direct_projected_and_retained_summaries_preserve_concurrency_contracts() {
        let project = InlineTestProject::with_language(Language::Go)
            .file(
                "main.go",
                r#"package main

type cell struct { n int }

func makeCell() *cell { return &cell{} }
func dropCell() { c := &cell{}; _ = c.n }
func dropParameter(c *cell) { c = &cell{}; _ = c.n }
func choose(c *cell) *cell { return c }
func chooseFresh(c *cell) *cell { return makeCell() }
func write(c *cell) { c.n = 1 }

func taskLocalWrite() { c := &cell{}; c.n = 1 }
func unknownWrite(c *cell) { c.n = 1 }
func taskLocalAgainstUnknownRoot(c *cell) {
    go taskLocalWrite()
    go unknownWrite(c)
}
func sharedLocalWrite() {
    c := &cell{}
    go write(c)
    c.n = 2
}
func sharedLocalWriteRoot() { go sharedLocalWrite() }

func summarizedChannelPayload() {
    ch := make(chan *cell, 1)
    c := &cell{}
    ch <- c
    go func() { got := <-ch; got.n = 1 }()
    go write(c)
}
func summarizedChannelPayloadRoot() { go summarizedChannelPayload() }
func summarizedChannelValue() {
    ch := make(chan cell, 1)
    c := cell{}
    ch <- c
    go func() { got := <-ch; got.n = 1 }()
    go func() { c.n = 2 }()
}
func summarizedChannelValueRoot() { go summarizedChannelValue() }
func summarySendCell(ch chan *cell, c *cell) { ch <- c }
func summaryReceiveCell(ch chan *cell) {
    got := <-ch
    got.n = 1
}
func summarizedChannelHelperPayload() {
    ch := make(chan *cell, 1)
    c := &cell{}
    summarySendCell(ch, c)
    go summaryReceiveCell(ch)
    go write(c)
}
func summarizedChannelHelperPayloadRoot() { go summarizedChannelHelperPayload() }
func summarySendCellValue(ch chan cell, c cell) { ch <- c }
func summaryReceiveCellValue(ch chan cell) {
    got := <-ch
    got.n = 1
}
func summarizedChannelHelperValue() {
    ch := make(chan cell, 1)
    c := cell{}
    summarySendCellValue(ch, c)
    go summaryReceiveCellValue(ch)
    go func() { c.n = 2 }()
}
func summarizedChannelHelperValueRoot() { go summarizedChannelHelperValue() }
func summarizedChannelBeforeReassignment() {
    ch := make(chan *cell, 1)
    c := &cell{}
    ch <- c
    ch = make(chan *cell, 1)
}

func sharedRoot() {
    dropCell()
    c := makeCell()
    dropParameter(c)
    returned := choose(c)
    write(c)
    go write(returned)
    go write(c)
}

func distinctRoot() {
    c := makeCell()
    returned := chooseFresh(c)
    write(c)
    go write(returned)
    go write(c)
}

type holder struct { items map[int]int }
func writeItems(h *holder) { h.items[0] = 1 }
func readItems(h *holder) { for range h.items {} }
func sharedFieldRoot() {
    h := &holder{items: map[int]int{}}
    writeItems(h)
    readItems(h)
    go writeItems(h)
    go readItems(h)
}
func distinctFieldRoot() {
    first := &holder{items: map[int]int{}}
    second := &holder{items: map[int]int{}}
    writeItems(first)
    readItems(second)
    go writeItems(first)
    go readItems(second)
}

func closeChannel(ch chan struct{}) { close(ch) }
func waitChannel(ch chan struct{}) { <-ch }
func relayChannel(start, finish chan struct{}) { <-start; close(finish) }
func synchronizedChannelRoot() {
    c := &cell{}
    start := make(chan struct{})
    finish := make(chan struct{})
    done := make(chan struct{})
    go func() { c.n = 1; close(start) }()
    go relayChannel(start, finish)
    go func() { <-finish; c.n = 2; close(done) }()
    waitChannel(done)
    _ = c.n
}
func distinctChannelRoot() {
    c := &cell{}
    first := make(chan struct{})
    second := make(chan struct{})
    go func() { c.n = 1; closeChannel(first) }()
    closeChannel(second)
    waitChannel(second)
    _ = c.n
    waitChannel(first)
}

func indirectWrite(target **cell) { *target = &cell{} }
func unsupportedGapRoot() {
    c := &cell{}
    indirectWrite(&c)
    _ = c
}

func recursiveWrite(c *cell, depth int) {
    c.n = 1
    if depth > 0 { recursiveWrite(c, depth-1) }
}
func recursiveAccessRoot() {
    c := &cell{}
    go recursiveWrite(c, 3)
    c.n = 2
}

func recursiveShift(first, second *cell, depth int) {
    first.n = 1
    if depth > 0 { recursiveShift(second, first, depth-1) }
}
func recursiveShiftRoot() {
    first := &cell{}
    second := &cell{}
    go recursiveShift(first, second, 3)
    second.n = 2
}

func recursiveIndex(values []int, index int) {
    values[index] = 1
    if index > 0 { recursiveIndex(values, index-1) }
}
func recursiveIndexRoot() {
    values := make([]int, 2)
    go recursiveIndex(values, 1)
    values[0] = 2
}

func mutualIndexA(values []int, index, depth int) {
    values[index] = 1
    if depth > 0 { mutualIndexB(values, index, depth-1) }
}
func mutualIndexB(values []int, index, depth int) {
    if depth > 0 { mutualIndexA(values, index, depth-1) }
}
func mutualIndexRoot() {
    values := make([]int, 2)
    go mutualIndexA(values, 0, 3)
    values[0] = 2
}

func mutualUnknownIndexRoot(index int) {
    values := make([]int, 2)
    go mutualIndexA(values, index, 3)
    values[0] = 2
}

func mutualDistinctIndexRoot() {
    values := make([]int, 2)
    go mutualIndexA(values, 0, 3)
    go mutualIndexA(values, 1, 3)
}

func mutualChangingIndexA(values []int, index, depth int) {
    values[index] = 1
    if depth > 0 { mutualChangingIndexB(values, index+1, depth-1) }
}
func mutualChangingIndexB(values []int, index, depth int) {
    if depth > 0 { mutualChangingIndexA(values, index, depth-1) }
}
func mutualChangingIndexRoot() {
    values := make([]int, 2)
    go mutualChangingIndexA(values, 0, 3)
    values[1] = 2
}

func mutualReassignedIndexA(values []int, index, depth int) {
    index++
    if depth > 0 { mutualReassignedIndexB(values, index, depth-1) }
}
func mutualReassignedIndexB(values []int, index, depth int) {
    values[index] = 1
    if depth > 0 { mutualReassignedIndexA(values, index, depth-1) }
}
func mutualReassignedIndexRoot() {
    values := make([]int, 2)
    go mutualReassignedIndexA(values, 0, 3)
    values[1] = 2
}

func mutualSliceShiftA(values []int, depth int) {
    values[0] = 1
    if depth > 0 { mutualSliceShiftB(values[1:], depth-1) }
}
func mutualSliceShiftB(values []int, depth int) {
    if depth > 0 { mutualSliceShiftA(values, depth-1) }
}
func mutualSliceShiftRoot() {
    values := make([]int, 2)
    go mutualSliceShiftA(values, 3)
    values[1] = 2
}

func mutualArrayValueA(values [1]cell, depth int) {
    values[0].n = 1
    if depth > 0 { mutualArrayValueB(values, depth-1) }
}
func mutualArrayValueB(values [1]cell, depth int) {
    if depth > 0 { mutualArrayValueA(values, depth-1) }
}
func mutualArrayValueRoot() {
    values := [1]cell{}
    go mutualArrayValueA(values, 3)
    values[0].n = 2
}

func (c *cell) recursivePointerReceiver(depth int) {
    c.n = 1
    if depth > 0 { c.recursivePointerReceiver(depth-1) }
}
func recursivePointerReceiverRoot() {
    c := &cell{}
    go c.recursivePointerReceiver(3)
    c.n = 2
}

func (c cell) recursiveValueReceiver(depth int) {
    c.n = 1
    if depth > 0 { c.recursiveValueReceiver(depth-1) }
}
func recursiveValueReceiverRoot() {
    c := cell{}
    go c.recursiveValueReceiver(3)
    c.n = 2
}

func recursiveResult(c *cell, depth int) *cell {
    c.n = 1
    if depth > 0 { return recursiveResult(c, depth-1) }
    return c
}
func recursiveResultRoot() {
    c := &cell{}
    go recursiveResult(c, 3)
    c.n = 2
}

func recursiveValueResult(c cell, depth int) cell {
    c.n = 1
    if depth > 0 { return recursiveValueResult(c, depth-1) }
    return c
}
func recursiveValueResultRoot() {
    c := cell{}
    go recursiveValueResult(c, 3)
    c.n = 2
}

func recursiveUnanchoredResult(c *cell) *cell {
    c.n = 1
    return recursiveUnanchoredResult(c)
}
func recursiveUnanchoredResultRoot() {
    c := &cell{}
    go recursiveUnanchoredResult(c)
    c.n = 2
}

func recursiveFresh(depth int) {
    c := &cell{}
    c.n = 1
    if depth > 0 { recursiveFresh(depth-1) }
}
func recursiveFreshRoot() { go recursiveFresh(3) }

var recursiveEscaped *cell
func recursivePublished(depth int) {
    c := &cell{}
    recursiveEscaped = c
    if depth > 0 { recursivePublished(depth-1) }
}
func recursivePublishedRoot() { go recursivePublished(3) }

func mutualWrite(c *cell, depth int) {
    c.n = 1
    if depth > 0 { mutualForward(c, depth-1) }
}
func mutualForward(c *cell, depth int) {
    if depth > 0 { mutualWrite(c, depth-1) }
}
func mutualAccessRoot() {
    c := &cell{}
    go mutualWrite(c, 3)
    c.n = 2
}

func mutualResultWrite(c *cell, depth int) *cell {
    c.n = 1
    if depth > 0 { return mutualResultForward(c, depth-1) }
    return c
}
func mutualResultForward(c *cell, depth int) *cell {
    return mutualResultWrite(c, depth)
}
func mutualResultRoot() {
    c := &cell{}
    go mutualResultWrite(c, 3)
    c.n = 2
}

func mutualPairResultWrite(first, second *cell, depth int) (*cell, *cell) {
    first.n = 1
    if depth > 0 {
        returnedFirst, returnedSecond := mutualPairResultForward(first, second, depth-1)
        return returnedFirst, returnedSecond
    }
    return first, second
}
func mutualPairResultForward(first, second *cell, depth int) (*cell, *cell) {
    returnedFirst, returnedSecond := mutualPairResultWrite(first, second, depth)
    return returnedFirst, returnedSecond
}
func mutualPairResultRoot() {
    first := &cell{}
    second := &cell{}
    go mutualPairResultWrite(first, second, 3)
    first.n = 2
}

func mutualMixedResultWrite(c *cell, copied cell, depth int) (*cell, cell) {
    c.n = 1
    if depth > 0 {
        returned, returnedCopy := mutualMixedResultForward(c, copied, depth-1)
        return returned, returnedCopy
    }
    return c, copied
}
func mutualMixedResultForward(c *cell, copied cell, depth int) (*cell, cell) {
    returned, returnedCopy := mutualMixedResultWrite(c, copied, depth)
    return returned, returnedCopy
}
func mutualMixedResultRoot() {
    c := &cell{}
    copied := cell{}
    go mutualMixedResultWrite(c, copied, 3)
    c.n = 2
}

func mutualDirectTupleResultWrite(first, second *cell, depth int) (*cell, *cell) {
    first.n = 1
    if depth > 0 { return mutualDirectTupleResultForward(first, second, depth-1) }
    return first, second
}
func mutualDirectTupleResultForward(first, second *cell, depth int) (*cell, *cell) {
    return mutualDirectTupleResultWrite(first, second, depth)
}
func mutualDirectTupleResultRoot() {
    first := &cell{}
    second := &cell{}
    go mutualDirectTupleResultWrite(first, second, 3)
    first.n = 2
}

type opaquePairTransform func(*cell, *cell) (*cell, *cell)
func mutualOpaqueTupleResultWrite(opaque opaquePairTransform, first, second *cell, depth int) (*cell, *cell) {
    first.n = 1
    if depth > 0 { return mutualOpaqueTupleResultForward(opaque, first, second, depth-1) }
    return first, second
}
func mutualOpaqueTupleResultForward(opaque opaquePairTransform, first, second *cell, depth int) (*cell, *cell) {
    returnedFirst, returnedSecond := mutualOpaqueTupleResultWrite(opaque, first, second, depth)
    return opaque(returnedFirst, returnedSecond)
}
func mutualOpaqueTupleResultRoot(opaque opaquePairTransform) {
    first := &cell{}
    second := &cell{}
    go mutualOpaqueTupleResultWrite(opaque, first, second, 3)
    first.n = 2
}

func mutualSwappedResultWrite(first, second *cell, depth int) (*cell, *cell) {
    first.n = 1
    if depth > 0 {
        returnedFirst, returnedSecond := mutualSwappedResultForward(first, second, depth-1)
        return returnedSecond, returnedFirst
    }
    return first, second
}
func mutualSwappedResultForward(first, second *cell, depth int) (*cell, *cell) {
    returnedFirst, returnedSecond := mutualSwappedResultWrite(first, second, depth)
    return returnedFirst, returnedSecond
}
func mutualSwappedResultRoot() {
    first := &cell{}
    second := &cell{}
    go mutualSwappedResultWrite(first, second, 3)
    first.n = 2
}

func mutualPartiallyUnanchoredResultWrite(c *cell) (*cell, *cell) {
    c.n = 1
    _, second := mutualPartiallyUnanchoredResultForward(c)
    return c, second
}
func mutualPartiallyUnanchoredResultForward(c *cell) (*cell, *cell) {
    _, second := mutualPartiallyUnanchoredResultWrite(c)
    return c, second
}
func mutualPartiallyUnanchoredResultRoot() {
    c := &cell{}
    go mutualPartiallyUnanchoredResultWrite(c)
    c.n = 2
}

func mutualValueResultWrite(c cell, depth int) cell {
    c.n = 1
    if depth > 0 { return mutualValueResultForward(c, depth-1) }
    return c
}
func mutualValueResultForward(c cell, depth int) cell {
    return mutualValueResultWrite(c, depth)
}
func mutualValueResultRoot() {
    c := cell{}
    go mutualValueResultWrite(c, 3)
    c.n = 2
}

func mutualUnanchoredResultWrite(c *cell) *cell {
    c.n = 1
    return mutualUnanchoredResultForward(c)
}
func mutualUnanchoredResultForward(c *cell) *cell {
    return mutualUnanchoredResultWrite(c)
}
func mutualUnanchoredResultRoot() {
    c := &cell{}
    go mutualUnanchoredResultWrite(c)
    c.n = 2
}

func mutualShiftWrite(first, second *cell, depth int) {
    first.n = 1
    if depth > 0 { mutualShiftForward(second, first, depth-1) }
}
func mutualShiftForward(first, second *cell, depth int) {
    if depth > 0 { mutualShiftWrite(first, second, depth-1) }
}
func mutualShiftRoot() {
    first := &cell{}
    second := &cell{}
    go mutualShiftWrite(first, second, 3)
    second.n = 2
}
"#,
            )
            .build();
        let file = project.file("main.go");
        let workspace = project.workspace_analyzer(AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        });
        let cancellation = crate::analyzer::semantic::CancellationToken::default();
        let mut budget = crate::analyzer::semantic::SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("Go semantics materialize")
            .available_value()
            .expect("Go semantics are available")
            .clone();
        let procedure = |name: &str| {
            artifact
                .procedures()
                .iter()
                .find(|procedure| {
                    procedure.kind() == crate::analyzer::semantic::ProcedureKind::Function
                        && procedure.lexical_parent().is_none()
                        && procedure
                            .locator()
                            .declaration()
                            .segments()
                            .last()
                            .and_then(|segment| segment.name())
                            == Some(name)
                })
                .and_then(|procedure| artifact.procedure_handle(procedure.id()))
                .unwrap_or_else(|| panic!("fixture has top-level function {name:?}"))
        };
        let project_summaries = |root: &ProcedureHandle| {
            let provider = workspace.icfg_provider();
            let cancellation = crate::analyzer::semantic::CancellationToken::default();
            let mut budget = crate::analyzer::semantic::SemanticBudget::new(
                crate::analyzer::semantic::SemanticWork::default_limits(),
            )
            .expect("default semantic budgets are positive");
            brokk_bifrost_flow::typestate::project_production_semantic_summaries(
                std::slice::from_ref(root),
                &provider,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("production summaries project")
        };
        let report = |root: &ProcedureHandle,
                      summaries: Option<
            brokk_bifrost_flow::typestate::ProductionSemanticSummarySet,
        >| {
            let provider = WorkspaceConcurrencyProvider::new(&workspace, None, summaries);
            let cancellation = crate::analyzer::semantic::CancellationToken::default();
            let mut budget = crate::analyzer::semantic::SemanticBudget::new(
                crate::analyzer::semantic::SemanticWork::default_limits(),
            )
            .expect("default semantic budgets are positive");
            brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
                &provider,
                root,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("concurrency report computes")
        };
        let repository = brokk_bifrost_flow::dataflow::ProductionSemanticSummaryRepository::new();

        for (root_name, write_name, expected_proven_conflicts) in [
            ("sharedRoot", "write", 1_usize),
            ("distinctRoot", "write", 0_usize),
            ("sharedFieldRoot", "writeItems", 1_usize),
            ("distinctFieldRoot", "writeItems", 0_usize),
            ("taskLocalAgainstUnknownRoot", "taskLocalWrite", 0_usize),
            ("sharedLocalWriteRoot", "sharedLocalWrite", 1_usize),
            (
                "summarizedChannelPayloadRoot",
                "summarizedChannelPayload",
                1_usize,
            ),
            (
                "summarizedChannelValueRoot",
                "summarizedChannelValue",
                0_usize,
            ),
            (
                "summarizedChannelHelperPayloadRoot",
                "summaryReceiveCell",
                1_usize,
            ),
            (
                "summarizedChannelHelperValueRoot",
                "summaryReceiveCellValue",
                0_usize,
            ),
            ("synchronizedChannelRoot", "relayChannel", 0_usize),
            ("distinctChannelRoot", "waitChannel", 1_usize),
            ("unsupportedGapRoot", "indirectWrite", 0_usize),
        ] {
            let root = procedure(root_name);
            let direct = report(&root, None);
            let summaries = project_summaries(&root);
            let write_summary = summaries
                .summary_for(&procedure(write_name))
                .unwrap_or_else(|| {
                    panic!(
                        "{root_name} projection retains {write_name}; summaries={:?}",
                        summaries
                            .summaries()
                            .iter()
                            .map(|summary| summary.key().declaration())
                            .collect::<Vec<_>>()
                    )
                });
            if root_name == "sharedRoot" {
                let call_effects = summaries
                    .summary_for(&root)
                    .expect("projected root summary")
                    .effects()
                    .iter()
                    .filter_map(|effect| match effect.key() {
                        brokk_bifrost_flow::dataflow::SummaryEffectKey::Call {
                            event,
                            callee,
                            witness,
                        } if callee.identity() == write_summary.key().identity() => {
                            Some((*event, *witness))
                        }
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                assert_eq!(
                    call_effects.len(),
                    3,
                    "each source call to one helper remains a distinct summary occurrence"
                );
                assert_eq!(
                    call_effects
                        .iter()
                        .map(|(event, _)| *event)
                        .collect::<std::collections::BTreeSet<_>>()
                        .len(),
                    3,
                    "each source call has a distinct stable event"
                );
                let root_source =
                    brokk_bifrost_flow::dataflow::SummaryProcedureSourceKey::from_locator(
                        root.semantics().locator(),
                    );
                assert!(call_effects.iter().all(|(_, witness)| {
                    witness.is_some_and(|witness| witness.procedure() == root_source)
                }));
                let allocation_summary = summaries
                    .summary_for(&procedure("makeCell"))
                    .expect("shared result projection retains makeCell");
                assert!(
                    allocation_summary.effects().iter().any(|effect| matches!(
                        effect.key(),
                        brokk_bifrost_flow::dataflow::SummaryEffectKey::Concurrency(concurrency)
                            if matches!(
                                concurrency.kind(),
                                brokk_bifrost_flow::dataflow::SummaryConcurrencyEffectKind::Allocation { location }
                                    if matches!(
                                        location.root(),
                                        brokk_bifrost_flow::dataflow::SummaryPort::Heap(_)
                                    ) && location.selectors().is_empty()
                            ) && concurrency.witness().is_some()
                                && effect.evidence().is_complete()
                    )),
                    "projected factory summary must retain its stable source allocation"
                );
                assert!(
                    allocation_summary.effects().iter().any(|effect| matches!(
                        effect.key(),
                        brokk_bifrost_flow::dataflow::SummaryEffectKey::Concurrency(concurrency)
                            if matches!(
                                concurrency.kind(),
                                brokk_bifrost_flow::dataflow::SummaryConcurrencyEffectKind::Publish {
                                    value,
                                    destination,
                                }
                                    if matches!(
                                        value.root(),
                                        brokk_bifrost_flow::dataflow::SummaryPort::Heap(_)
                                    ) && value.selectors().is_empty()
                                        && destination.root()
                                            == &brokk_bifrost_flow::dataflow::SummaryPort::NormalReturn
                                        && destination.selectors().is_empty()
                            ) && concurrency.witness().is_some()
                                && effect.evidence().is_proven()
                                && effect.evidence().is_complete()
                    )),
                    "the exact return publication must retain its allocation and source event"
                );
                for name in ["dropCell", "dropParameter"] {
                    let private_allocation_summary = summaries
                        .summary_for(&procedure(name))
                        .unwrap_or_else(|| panic!("shared projection retains {name}"));
                    assert!(
                        private_allocation_summary.effects().iter().all(|effect| !matches!(
                            effect.key(),
                            brokk_bifrost_flow::dataflow::SummaryEffectKey::Concurrency(concurrency)
                                if matches!(
                                    concurrency.kind(),
                                    brokk_bifrost_flow::dataflow::SummaryConcurrencyEffectKind::Publish { .. }
                                )
                        )),
                        "a fresh allocation used only inside {name} is not published"
                    );
                    assert!(
                        private_allocation_summary.effects().iter().any(|effect| matches!(
                            effect.key(),
                            brokk_bifrost_flow::dataflow::SummaryEffectKey::Concurrency(concurrency)
                                if matches!(
                                    concurrency.kind(),
                                    brokk_bifrost_flow::dataflow::SummaryConcurrencyEffectKind::Unpublished { value }
                                        if matches!(
                                            value.root(),
                                            brokk_bifrost_flow::dataflow::SummaryPort::Heap(_)
                                        ) && value.selectors().is_empty()
                                ) && concurrency.witness().is_some()
                                    && effect.evidence().is_proven()
                                    && effect.evidence().is_complete()
                        )),
                        "a fresh allocation used only inside {name} retains explicit non-publication proof"
                    );
                }
                let different_provider = CountingIcfgProvider {
                    inner: workspace.icfg_provider(),
                    call_transfers: std::cell::Cell::new(0),
                    behavior: Some(
                        crate::analyzer::semantic::IcfgProviderBehaviorIdentity::hash_bytes(
                            b"different-publication-provider",
                        ),
                    ),
                    publication_unknown: false,
                };
                let cancellation = crate::analyzer::semantic::CancellationToken::default();
                let mut budget = crate::analyzer::semantic::SemanticBudget::new(
                    crate::analyzer::semantic::SemanticWork::default_limits(),
                )
                .expect("default semantic budgets are positive");
                let different_summaries =
                    brokk_bifrost_flow::typestate::project_production_semantic_summaries(
                        std::slice::from_ref(&procedure("makeCell")),
                        &different_provider,
                        &mut SemanticRequest::new(&mut budget, &cancellation),
                    )
                    .expect("publication summaries project under a second provider behavior");
                assert_ne!(
                    allocation_summary.key().identity(),
                    different_summaries
                        .summary_for(&procedure("makeCell"))
                        .expect("second projection retains makeCell")
                        .key()
                        .identity(),
                    "an allocation-bearing witnessed leaf retains its provider behavior"
                );
            }
            if root_name == "unsupportedGapRoot" {
                assert!(
                    write_summary.effects().iter().any(|effect| matches!(
                        effect.key(),
                        brokk_bifrost_flow::dataflow::SummaryEffectKey::Concurrency(concurrency)
                            if matches!(
                                concurrency.kind(),
                                brokk_bifrost_flow::dataflow::SummaryConcurrencyEffectKind::Unsupported { protocol }
                                    if protocol.as_ref() == "semantic-gap:assignments"
                            ) && concurrency.witness().is_some()
                                && effect.evidence().is_complete()
                    )),
                    "projected indirect-write summary must retain its exact unsupported effect"
                );
            } else if root_name == "taskLocalAgainstUnknownRoot" {
                assert!(write_summary.effects().iter().any(|effect| matches!(
                    effect.key(),
                    brokk_bifrost_flow::dataflow::SummaryEffectKey::Concurrency(concurrency)
                        if matches!(
                            concurrency.kind(),
                            brokk_bifrost_flow::dataflow::SummaryConcurrencyEffectKind::Unpublished { .. }
                        ) && concurrency.witness().is_some()
                            && effect.evidence().is_proven()
                            && effect.evidence().is_complete()
                )), "the task-local helper must retain its complete empty publication inventory");
            } else if root_name == "sharedLocalWriteRoot" {
                assert!(write_summary.effects().iter().all(|effect| !matches!(
                    effect.key(),
                    brokk_bifrost_flow::dataflow::SummaryEffectKey::Concurrency(concurrency)
                        if matches!(
                            concurrency.kind(),
                            brokk_bifrost_flow::dataflow::SummaryConcurrencyEffectKind::Unpublished { .. }
                        )
                )), "the allocation shared with a nested task must not be classified as unpublished");
            } else if matches!(
                write_name,
                "summarizedChannelPayload"
                    | "summarizedChannelValue"
                    | "summaryReceiveCell"
                    | "summaryReceiveCellValue"
                    | "waitChannel"
                    | "relayChannel"
            ) {
                assert!(
                    write_summary.effects().iter().any(|effect| matches!(
                        effect.key(),
                        brokk_bifrost_flow::dataflow::SummaryEffectKey::Concurrency(concurrency)
                            if matches!(
                                concurrency.kind(),
                                brokk_bifrost_flow::dataflow::SummaryConcurrencyEffectKind::Synchronize { .. }
                            ) && concurrency.witness().is_some()
                                && effect.evidence().is_complete()
                    )),
                    "projected channel helper summary must contain a complete source-backed synchronization effect for {root_name}/{write_name}"
                );
            } else {
                assert!(
                    write_summary.effects().iter().any(|effect| matches!(
                        effect.key(),
                        brokk_bifrost_flow::dataflow::SummaryEffectKey::Concurrency(concurrency)
                            if matches!(
                                concurrency.kind(),
                                brokk_bifrost_flow::dataflow::SummaryConcurrencyEffectKind::Access { .. }
                            ) && concurrency.witness().is_some()
                                && effect.evidence().is_complete()
                    )),
                    "projected {write_name} summary for {root_name} must contain a complete source-backed access effect"
                );
            }
            repository
                .publish_components(summaries.summaries(), summaries.components())
                .expect("projected summary closure publishes");
            let projected = report(&root, Some(summaries));
            let provider = CountingIcfgProvider {
                inner: workspace.icfg_provider(),
                call_transfers: std::cell::Cell::new(0),
                behavior: None,
                publication_unknown: false,
            };
            let cancellation = crate::analyzer::semantic::CancellationToken::default();
            let mut budget = crate::analyzer::semantic::SemanticBudget::new(
                crate::analyzer::semantic::SemanticWork::default_limits(),
            )
            .expect("default semantic budgets are positive");
            let summary_reads = CountingSummaryReads::default();
            let retained = brokk_bifrost_flow::typestate::acquire_production_semantic_summaries(
                std::slice::from_ref(&root),
                &provider,
                &repository,
                &summary_reads,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("retained summary closure is acquired before projection");
            assert_eq!(
                retained.kind(),
                brokk_bifrost_flow::typestate::ProductionSemanticSummaryAcquisitionKind::Retained
            );
            assert_eq!(
                provider.call_transfers.get(),
                0,
                "a retained hit must not project call transfers"
            );
            let retained_summaries = retained.into_summaries();
            assert_eq!(
                summary_reads.0.get(),
                retained_summaries.len(),
                "every consumed retained summary is observed"
            );
            assert!(!retained_summaries.procedure_semantics_precharged());
            assert!(budget.used().nested_entries > 0);
            let retained = report(&root, Some(retained_summaries));

            // Invocation, point, and dense source IDs are solve-local. Compare task
            // topology, source-facing endpoints, and every public completeness/proof field.
            assert_eq!(
                stable_report(&direct),
                stable_report(&projected),
                "direct and freshly projected reports differ for {root_name}"
            );
            assert_eq!(
                stable_report(&direct),
                stable_report(&retained),
                "direct and retained-summary reports differ for {root_name}"
            );
            assert_eq!(
                direct
                    .conflicts
                    .iter()
                    .filter(|conflict| {
                        conflict.proven
                            && conflict.ordering == brokk_bifrost_flow::concurrency::ConcurrentOrdering::Unordered
                            && conflict.protection == brokk_bifrost_flow::concurrency::ConcurrentProtection::Unprotected
                    })
                    .count(),
                expected_proven_conflicts,
                "unexpected direct conflict status for {root_name}"
            );
            assert_eq!(
                projected
                    .conflicts
                    .iter()
                    .filter(|conflict| {
                        conflict.proven
                            && conflict.ordering == brokk_bifrost_flow::concurrency::ConcurrentOrdering::Unordered
                            && conflict.protection == brokk_bifrost_flow::concurrency::ConcurrentProtection::Unprotected
                    })
                    .count(),
                expected_proven_conflicts,
                "unexpected projected conflict status for {root_name}"
            );
            assert_eq!(
                retained
                    .conflicts
                    .iter()
                    .filter(|conflict| {
                        conflict.proven
                            && conflict.ordering == brokk_bifrost_flow::concurrency::ConcurrentOrdering::Unordered
                            && conflict.protection == brokk_bifrost_flow::concurrency::ConcurrentProtection::Unprotected
                    })
                    .count(),
                expected_proven_conflicts,
                "unexpected retained conflict status for {root_name}"
            );
            if root_name == "taskLocalAgainstUnknownRoot" {
                assert!(
                    direct.conflicts.is_empty()
                        && projected.conflicts.is_empty()
                        && retained.conflicts.is_empty(),
                    "a task-local allocation cannot alias an unknown value in a sibling task: direct={direct:#?}, projected={projected:#?}, retained={retained:#?}"
                );
            }
            if root_name == "unsupportedGapRoot" {
                let expected =
                    brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::UnmodeledMemory(
                        "assignments".into(),
                    );
                assert!(
                    direct.reasons.contains(&expected),
                    "direct report: {direct:#?}"
                );
                assert!(
                    projected.reasons.contains(&expected),
                    "projected report: {projected:#?}"
                );
                assert!(
                    retained.reasons.contains(&expected),
                    "retained report: {retained:#?}"
                );
            }
        }

        let reassigned_summaries =
            project_summaries(&procedure("summarizedChannelBeforeReassignment"));
        let reassigned_summary = reassigned_summaries
            .summary_for(&procedure("summarizedChannelBeforeReassignment"))
            .expect("reassigned-channel summary projects");
        assert!(
            reassigned_summary.effects().iter().all(|effect| !matches!(
                effect.key(),
                brokk_bifrost_flow::dataflow::SummaryEffectKey::Concurrency(concurrency)
                    if matches!(
                        concurrency.kind(),
                        brokk_bifrost_flow::dataflow::SummaryConcurrencyEffectKind::Synchronize { .. }
                    )
            )),
            "a later channel assignment must prevent a stable synchronization subject"
        );

        let recursive_root = procedure("recursiveAccessRoot");
        let direct_recursive = report(&recursive_root, None);
        assert!(
            direct_recursive.reasons.contains(
                &brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::RecursiveExpansion
            ),
            "bounded direct recursion retains its omitted activation: {direct_recursive:#?}"
        );
        let recursive_summaries = project_summaries(&recursive_root);
        let recursive_summary = recursive_summaries
            .summary_for(&procedure("recursiveWrite"))
            .expect("recursive helper summary projects");
        assert_eq!(
            recursive_summary
                .recursive_group()
                .expect("self-recursive helper has a summary group")
                .member_count(),
            1
        );
        repository
            .publish_components(
                recursive_summaries.summaries(),
                recursive_summaries.components(),
            )
            .expect("recursive summary closure publishes");
        let projected_recursive = report(&recursive_root, Some(recursive_summaries));
        assert!(
            !projected_recursive.reasons.contains(
                &brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::RecursiveExpansion
            ),
            "exact invariant access recursion reaches its finite summary fixed point: {projected_recursive:#?}"
        );
        assert_eq!(
            projected_recursive
                .conflicts
                .iter()
                .filter(|conflict| conflict.proven && conflict.exhaustive)
                .count(),
            1,
            "the summarized recursive writer races with its parent"
        );

        let provider = CountingIcfgProvider {
            inner: workspace.icfg_provider(),
            call_transfers: std::cell::Cell::new(0),
            behavior: None,
            publication_unknown: false,
        };
        let cancellation = crate::analyzer::semantic::CancellationToken::default();
        let mut budget = crate::analyzer::semantic::SemanticBudget::new(
            crate::analyzer::semantic::SemanticWork::default_limits(),
        )
        .expect("default semantic budgets are positive");
        let summary_reads = CountingSummaryReads::default();
        let retained_recursive =
            brokk_bifrost_flow::typestate::acquire_production_semantic_summaries(
                std::slice::from_ref(&recursive_root),
                &provider,
                &repository,
                &summary_reads,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("recursive summary closure is retained")
            .into_summaries();
        assert_eq!(provider.call_transfers.get(), 0);
        let retained_recursive = report(&recursive_root, Some(retained_recursive));
        assert_eq!(
            stable_report(&projected_recursive),
            stable_report(&retained_recursive),
            "fresh and retained recursive fixed points differ"
        );

        let shifted_root = procedure("recursiveShiftRoot");
        let shifted = report(&shifted_root, Some(project_summaries(&shifted_root)));
        assert!(
            shifted.reasons.contains(
                &brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::RecursiveExpansion
            ),
            "changing the recursively accessed object must remain open: {shifted:#?}"
        );
        assert!(
            shifted.conflicts.iter().all(|conflict| !conflict.proven),
            "an omitted write to the second object cannot become a proven clean fixed point: {shifted:#?}"
        );

        let indexed_root = procedure("recursiveIndexRoot");
        let indexed = report(&indexed_root, Some(project_summaries(&indexed_root)));
        assert!(
            indexed.reasons.contains(
                &brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::RecursiveExpansion
            ),
            "a changing dynamic index must remain open: {indexed:#?}"
        );
        assert!(
            indexed.conflicts.iter().all(|conflict| !conflict.proven),
            "the omitted lower-index write cannot be certified from the first access: {indexed:#?}"
        );

        let mutual_index_root = procedure("mutualIndexRoot");
        let mutual_index_summaries = project_summaries(&mutual_index_root);
        let mutual_index_summary = mutual_index_summaries
            .summary_for(&procedure("mutualIndexA"))
            .expect("mutual index member summary projects");
        assert!(mutual_index_summary.effects().iter().any(|effect| matches!(
            effect.key(),
            brokk_bifrost_flow::dataflow::SummaryEffectKey::Concurrency(concurrency)
                if matches!(
                    concurrency.kind(),
                    brokk_bifrost_flow::dataflow::SummaryConcurrencyEffectKind::Access {
                        location,
                        ..
                    } if location.selectors().iter().any(|selector| matches!(
                        selector,
                        brokk_bifrost_flow::dataflow::SummaryConcurrencyAccessSelector::Index(
                            brokk_bifrost_flow::dataflow::SummaryPort::Parameter(1)
                        )
                    ))
                )
        )));
        repository
            .publish_components(
                mutual_index_summaries.summaries(),
                mutual_index_summaries.components(),
            )
            .expect("invariant-index recursive summary closure publishes");
        let mutual_index = report(&mutual_index_root, Some(mutual_index_summaries));
        assert!(
            !mutual_index.reasons.contains(
                &brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::RecursiveExpansion
            ),
            "a dynamic index forwarded unchanged around the SCC reaches a fixed point: {mutual_index:#?}"
        );
        assert_eq!(
            mutual_index
                .conflicts
                .iter()
                .filter(|conflict| conflict.proven && conflict.exhaustive)
                .count(),
            1,
            "the caller's exact scalar actual must identify the raced element: {mutual_index:#?}"
        );

        let provider = CountingIcfgProvider {
            inner: workspace.icfg_provider(),
            call_transfers: std::cell::Cell::new(0),
            behavior: None,
            publication_unknown: false,
        };
        let cancellation = crate::analyzer::semantic::CancellationToken::default();
        let mut budget = crate::analyzer::semantic::SemanticBudget::new(
            crate::analyzer::semantic::SemanticWork::default_limits(),
        )
        .expect("default semantic budgets are positive");
        let summary_reads = CountingSummaryReads::default();
        let retained_mutual_index =
            brokk_bifrost_flow::typestate::acquire_production_semantic_summaries(
                std::slice::from_ref(&mutual_index_root),
                &provider,
                &repository,
                &summary_reads,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("invariant-index recursive summary closure is retained")
            .into_summaries();
        assert_eq!(provider.call_transfers.get(), 0);
        let retained_mutual_index = report(&mutual_index_root, Some(retained_mutual_index));
        assert_eq!(
            stable_report(&mutual_index),
            stable_report(&retained_mutual_index),
            "fresh and retained invariant-index fixed points differ"
        );

        let unknown_index_root = procedure("mutualUnknownIndexRoot");
        let unknown_index = report(
            &unknown_index_root,
            Some(project_summaries(&unknown_index_root)),
        );
        assert!(
            !unknown_index.reasons.contains(
                &brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::RecursiveExpansion
            ),
            "an unavailable caller scalar does not invalidate the recursive fixed point: {unknown_index:#?}"
        );
        assert!(
            !unknown_index.conflicts.is_empty()
                && unknown_index.conflicts.iter().all(|conflict| {
                    !conflict.proven
                    && conflict.reasons.contains(
                        &brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::UnknownLocation,
                    )
                }),
            "an unavailable caller scalar cannot fabricate an element identity: {unknown_index:#?}"
        );

        let distinct_index_root = procedure("mutualDistinctIndexRoot");
        let distinct_index = report(
            &distinct_index_root,
            Some(project_summaries(&distinct_index_root)),
        );
        assert!(
            distinct_index.reasons.is_empty(),
            "exact scalar actuals should close each recursive invocation independently: {distinct_index:#?}"
        );
        assert!(
            distinct_index.conflicts.is_empty(),
            "different exact scalar actuals must select disjoint elements: {distinct_index:#?}"
        );

        let changing_index_root = procedure("mutualChangingIndexRoot");
        let changing_index = report(
            &changing_index_root,
            Some(project_summaries(&changing_index_root)),
        );
        assert!(
            changing_index.reasons.contains(
                &brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::RecursiveExpansion
            ),
            "an index changed at one SCC edge must remain open: {changing_index:#?}"
        );
        assert!(
            changing_index
                .conflicts
                .iter()
                .all(|conflict| !conflict.proven),
            "the omitted changed-index write cannot be fabricated from the retained access: {changing_index:#?}"
        );

        let reassigned_index_root = procedure("mutualReassignedIndexRoot");
        let reassigned_index = report(
            &reassigned_index_root,
            Some(project_summaries(&reassigned_index_root)),
        );
        assert!(
            reassigned_index.reasons.contains(
                &brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::RecursiveExpansion
            ),
            "an index formal reassigned before an SCC edge must remain open: {reassigned_index:#?}"
        );
        assert!(
            reassigned_index
                .conflicts
                .iter()
                .all(|conflict| !conflict.proven),
            "a reassigned scalar formal cannot fabricate an invariant recursive index: {reassigned_index:#?}"
        );

        let slice_shift_root = procedure("mutualSliceShiftRoot");
        let slice_shift = report(
            &slice_shift_root,
            Some(project_summaries(&slice_shift_root)),
        );
        assert!(
            slice_shift.reasons.contains(
                &brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::RecursiveExpansion
            ),
            "a shifted backing view at one SCC edge must remain open: {slice_shift:#?}"
        );
        assert!(
            slice_shift
                .conflicts
                .iter()
                .all(|conflict| !conflict.proven),
            "an omitted shifted-view write cannot be fabricated from the retained access: {slice_shift:#?}"
        );

        let array_value_root = procedure("mutualArrayValueRoot");
        let array_value = report(
            &array_value_root,
            Some(project_summaries(&array_value_root)),
        );
        assert!(
            array_value.reasons.contains(
                &brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::RecursiveExpansion
            ),
            "an inline array parameter copy must remain open: {array_value:#?}"
        );
        assert!(
            array_value
                .conflicts
                .iter()
                .all(|conflict| !conflict.proven),
            "an inline array copy cannot borrow a descriptor-backing identity: {array_value:#?}"
        );

        let pointer_receiver_root = procedure("recursivePointerReceiverRoot");
        let pointer_receiver = report(
            &pointer_receiver_root,
            Some(project_summaries(&pointer_receiver_root)),
        );
        assert!(
            !pointer_receiver.reasons.contains(
                &brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::RecursiveExpansion
            ),
            "an invariant pointer receiver reaches the access fixed point: {pointer_receiver:#?}"
        );
        assert_eq!(
            pointer_receiver
                .conflicts
                .iter()
                .filter(|conflict| conflict.proven && conflict.exhaustive)
                .count(),
            1,
            "the recursive pointer receiver races with its parent"
        );

        let value_receiver_root = procedure("recursiveValueReceiverRoot");
        let value_receiver = report(
            &value_receiver_root,
            Some(project_summaries(&value_receiver_root)),
        );
        assert!(
            value_receiver.reasons.contains(
                &brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::RecursiveExpansion
            ),
            "a copied receiver cannot inherit the caller's recursive identity: {value_receiver:#?}"
        );
        assert!(
            value_receiver
                .conflicts
                .iter()
                .all(|conflict| !conflict.proven),
            "value-receiver copies must not fabricate a race: {value_receiver:#?}"
        );

        let result_root = procedure("recursiveResultRoot");
        let direct_result = report(&result_root, None);
        assert!(
            direct_result.reasons.contains(
                &brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::RecursiveExpansion
            ),
            "bounded direct recursion retains the omitted result activation: {direct_result:#?}"
        );
        let result_summaries = project_summaries(&result_root);
        repository
            .publish_components(result_summaries.summaries(), result_summaries.components())
            .expect("recursive result summary closure publishes");
        let result = report(&result_root, Some(result_summaries));
        assert!(
            !result.reasons.contains(
                &brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::RecursiveExpansion
            ),
            "a pointer result that returns the invariant recursive input reaches the access fixed point: {result:#?}"
        );
        assert_eq!(
            result
                .conflicts
                .iter()
                .filter(|conflict| conflict.proven && conflict.exhaustive)
                .count(),
            1,
            "the recursive pointer-result writer races with its parent"
        );
        let provider = CountingIcfgProvider {
            inner: workspace.icfg_provider(),
            call_transfers: std::cell::Cell::new(0),
            behavior: None,
            publication_unknown: false,
        };
        let cancellation = crate::analyzer::semantic::CancellationToken::default();
        let mut budget = crate::analyzer::semantic::SemanticBudget::new(
            crate::analyzer::semantic::SemanticWork::default_limits(),
        )
        .expect("default semantic budgets are positive");
        let summary_reads = CountingSummaryReads::default();
        let retained_result = brokk_bifrost_flow::typestate::acquire_production_semantic_summaries(
            std::slice::from_ref(&result_root),
            &provider,
            &repository,
            &summary_reads,
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("recursive result summary closure is retained")
        .into_summaries();
        assert_eq!(provider.call_transfers.get(), 0);
        let retained_result = report(&result_root, Some(retained_result));
        assert_eq!(
            stable_report(&result),
            stable_report(&retained_result),
            "fresh and retained recursive result fixed points differ"
        );

        let value_result_root = procedure("recursiveValueResultRoot");
        let value_result = report(
            &value_result_root,
            Some(project_summaries(&value_result_root)),
        );
        assert!(
            value_result.reasons.contains(
                &brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::RecursiveExpansion
            ),
            "a struct-by-value result cannot inherit the recursive input identity: {value_result:#?}"
        );
        assert!(
            value_result
                .conflicts
                .iter()
                .all(|conflict| !conflict.proven),
            "a value result must not fabricate a race: {value_result:#?}"
        );

        let unanchored_result_root = procedure("recursiveUnanchoredResultRoot");
        let unanchored_result = report(
            &unanchored_result_root,
            Some(project_summaries(&unanchored_result_root)),
        );
        assert!(
            unanchored_result.reasons.contains(
                &brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::RecursiveExpansion
            ),
            "a recursive result equation without a base object proves no identity: {unanchored_result:#?}"
        );
        assert!(
            unanchored_result
                .conflicts
                .iter()
                .all(|conflict| !conflict.proven),
            "an unanchored recursive result must not fabricate a race: {unanchored_result:#?}"
        );

        let fresh_root = procedure("recursiveFreshRoot");
        let fresh_summaries = project_summaries(&fresh_root);
        let fresh_summary = fresh_summaries
            .summary_for(&procedure("recursiveFresh"))
            .expect("recursive fresh helper summary projects");
        assert!(
            fresh_summary.effects().iter().any(|effect| matches!(
                effect.key(),
                brokk_bifrost_flow::dataflow::SummaryEffectKey::Concurrency(concurrency)
                    if matches!(
                        concurrency.kind(),
                        brokk_bifrost_flow::dataflow::SummaryConcurrencyEffectKind::Unpublished { .. }
                    ) && concurrency.witness().is_some()
                        && effect.evidence().is_proven()
                        && effect.evidence().is_complete()
            )),
            "recursive fresh storage retains explicit non-publication proof"
        );
        repository
            .publish_components(fresh_summaries.summaries(), fresh_summaries.components())
            .expect("recursive fresh summary closure publishes");
        let fresh = report(&fresh_root, Some(fresh_summaries));
        assert!(
            !fresh.reasons.contains(
                &brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::RecursiveExpansion
            ),
            "a proven unpublished allocation is fresh in every recursive activation: {fresh:#?}"
        );
        assert!(
            fresh.conflicts.is_empty(),
            "activation-local fresh storage creates no cross-task conflict: {fresh:#?}"
        );
        let provider = CountingIcfgProvider {
            inner: workspace.icfg_provider(),
            call_transfers: std::cell::Cell::new(0),
            behavior: None,
            publication_unknown: false,
        };
        let cancellation = crate::analyzer::semantic::CancellationToken::default();
        let mut budget = crate::analyzer::semantic::SemanticBudget::new(
            crate::analyzer::semantic::SemanticWork::default_limits(),
        )
        .expect("default semantic budgets are positive");
        let summary_reads = CountingSummaryReads::default();
        let retained_fresh = brokk_bifrost_flow::typestate::acquire_production_semantic_summaries(
            std::slice::from_ref(&fresh_root),
            &provider,
            &repository,
            &summary_reads,
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("recursive fresh summary closure is retained")
        .into_summaries();
        assert_eq!(provider.call_transfers.get(), 0);
        let retained_fresh = report(&fresh_root, Some(retained_fresh));
        assert_eq!(
            stable_report(&fresh),
            stable_report(&retained_fresh),
            "fresh and retained unpublished-allocation fixed points differ"
        );

        let published_root = procedure("recursivePublishedRoot");
        let published_summaries = project_summaries(&published_root);
        let published_summary = published_summaries
            .summary_for(&procedure("recursivePublished"))
            .expect("recursive published helper summary projects");
        assert!(
            published_summary.effects().iter().any(|effect| matches!(
                effect.key(),
                brokk_bifrost_flow::dataflow::SummaryEffectKey::Concurrency(concurrency)
                    if matches!(
                        concurrency.kind(),
                        brokk_bifrost_flow::dataflow::SummaryConcurrencyEffectKind::Publish { .. }
                    )
            )),
            "the escaping recursive allocation retains its publication"
        );
        assert!(
            published_summary.effects().iter().all(|effect| !matches!(
                effect.key(),
                brokk_bifrost_flow::dataflow::SummaryEffectKey::Concurrency(concurrency)
                    if matches!(
                        concurrency.kind(),
                        brokk_bifrost_flow::dataflow::SummaryConcurrencyEffectKind::Unpublished { .. }
                    )
            )),
            "a published allocation must not retain non-publication proof"
        );
        let published = report(&published_root, Some(published_summaries));
        assert!(
            published.reasons.contains(
                &brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::RecursiveExpansion
            ),
            "publication prevents treating recursive allocations as activation-local: {published:#?}"
        );

        let mutual_root = procedure("mutualAccessRoot");
        let mutual = report(&mutual_root, Some(project_summaries(&mutual_root)));
        assert!(
            !mutual.reasons.contains(
                &brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::RecursiveExpansion
            ),
            "an invariant two-member access SCC reaches its fixed point: {mutual:#?}"
        );
        assert_eq!(
            mutual
                .conflicts
                .iter()
                .filter(|conflict| conflict.proven && conflict.exhaustive)
                .count(),
            1,
            "the mutually recursive writer races with its parent"
        );

        let mutual_result_root = procedure("mutualResultRoot");
        let mutual_result_forward = procedure("mutualResultForward");
        let [mutual_result_forward_call] = mutual_result_forward.semantics().call_sites() else {
            panic!("mutual result forwarding member has one recursive call")
        };
        let forwarded_result = mutual_result_forward_call
            .normal_result(0)
            .expect("mutual result forwarding call has a pointer result");
        let forward_return_sources = mutual_result_forward
            .semantics()
            .points()
            .iter()
            .flat_map(|point| &point.events)
            .filter_map(|event| match event.effect {
                SemanticEffect::ValueFlow {
                    source,
                    kind: ValueFlowKind::Return | ValueFlowKind::IndexedReturn { ordinal: 0 },
                    ..
                } => Some(source),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(
            !forward_return_sources.is_empty()
                && forward_return_sources
                    .iter()
                    .all(|source| *source == forwarded_result),
            "the forwarding member contributes no independent result base"
        );
        let mutual_result_summaries = project_summaries(&mutual_result_root);
        assert_eq!(
            mutual_result_summaries
                .summary_for(&procedure("mutualResultWrite"))
                .and_then(|summary| summary.recursive_group())
                .expect("mutual pointer-result helpers have a recursive summary group")
                .member_count(),
            2
        );
        repository
            .publish_components(
                mutual_result_summaries.summaries(),
                mutual_result_summaries.components(),
            )
            .expect("mutual pointer-result summary closure publishes");
        let mutual_result = report(&mutual_result_root, Some(mutual_result_summaries));
        assert!(
            !mutual_result.reasons.contains(
                &brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::RecursiveExpansion
            ),
            "an invariant pointer result reaches a two-member access fixed point: {mutual_result:#?}"
        );
        assert_eq!(
            mutual_result
                .conflicts
                .iter()
                .filter(|conflict| conflict.proven && conflict.exhaustive)
                .count(),
            1,
            "the mutually recursive pointer-result writer races with its parent"
        );
        let provider = CountingIcfgProvider {
            inner: workspace.icfg_provider(),
            call_transfers: std::cell::Cell::new(0),
            behavior: None,
            publication_unknown: false,
        };
        let cancellation = crate::analyzer::semantic::CancellationToken::default();
        let mut budget = crate::analyzer::semantic::SemanticBudget::new(
            crate::analyzer::semantic::SemanticWork::default_limits(),
        )
        .expect("default semantic budgets are positive");
        let summary_reads = CountingSummaryReads::default();
        let retained_mutual_result =
            brokk_bifrost_flow::typestate::acquire_production_semantic_summaries(
                std::slice::from_ref(&mutual_result_root),
                &provider,
                &repository,
                &summary_reads,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("mutual pointer-result summary closure is retained")
            .into_summaries();
        assert_eq!(provider.call_transfers.get(), 0);
        let retained_mutual_result = report(&mutual_result_root, Some(retained_mutual_result));
        assert_eq!(
            stable_report(&mutual_result),
            stable_report(&retained_mutual_result),
            "fresh and retained mutual pointer-result fixed points differ"
        );

        let mutual_pair_result_root = procedure("mutualPairResultRoot");
        let mutual_pair_result_summaries = project_summaries(&mutual_pair_result_root);
        repository
            .publish_components(
                mutual_pair_result_summaries.summaries(),
                mutual_pair_result_summaries.components(),
            )
            .expect("mutual two-result summary closure publishes");
        let mutual_pair_result =
            report(&mutual_pair_result_root, Some(mutual_pair_result_summaries));
        assert!(
            !mutual_pair_result.reasons.contains(
                &brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::RecursiveExpansion
            ),
            "two reference result ordinals reach independent component fixed points: {mutual_pair_result:#?}"
        );
        assert_eq!(
            mutual_pair_result
                .conflicts
                .iter()
                .filter(|conflict| conflict.proven && conflict.exhaustive)
                .count(),
            1,
            "the mutually recursive two-result writer races with its parent"
        );
        let provider = CountingIcfgProvider {
            inner: workspace.icfg_provider(),
            call_transfers: std::cell::Cell::new(0),
            behavior: None,
            publication_unknown: false,
        };
        let cancellation = crate::analyzer::semantic::CancellationToken::default();
        let mut budget = crate::analyzer::semantic::SemanticBudget::new(
            crate::analyzer::semantic::SemanticWork::default_limits(),
        )
        .expect("default semantic budgets are positive");
        let summary_reads = CountingSummaryReads::default();
        let retained_mutual_pair_result =
            brokk_bifrost_flow::typestate::acquire_production_semantic_summaries(
                std::slice::from_ref(&mutual_pair_result_root),
                &provider,
                &repository,
                &summary_reads,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("mutual two-result summary closure is retained")
            .into_summaries();
        assert_eq!(provider.call_transfers.get(), 0);
        let retained_mutual_pair_result =
            report(&mutual_pair_result_root, Some(retained_mutual_pair_result));
        assert_eq!(
            stable_report(&mutual_pair_result),
            stable_report(&retained_mutual_pair_result),
            "fresh and retained mutual two-result fixed points differ"
        );

        let direct_tuple_result_root = procedure("mutualDirectTupleResultRoot");
        let direct_tuple_result_summaries = project_summaries(&direct_tuple_result_root);
        repository
            .publish_components(
                direct_tuple_result_summaries.summaries(),
                direct_tuple_result_summaries.components(),
            )
            .expect("direct tuple-result summary closure publishes");
        let direct_tuple_result = report(
            &direct_tuple_result_root,
            Some(direct_tuple_result_summaries),
        );
        assert!(
            !direct_tuple_result.reasons.contains(
                &brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::RecursiveExpansion
            ),
            "direct multi-result calls retain their ordinal mapping: {direct_tuple_result:#?}"
        );
        assert_eq!(
            direct_tuple_result
                .conflicts
                .iter()
                .filter(|conflict| conflict.proven && conflict.exhaustive)
                .count(),
            1,
            "the directly forwarded pointer-result writer races with its parent"
        );
        let provider = CountingIcfgProvider {
            inner: workspace.icfg_provider(),
            call_transfers: std::cell::Cell::new(0),
            behavior: None,
            publication_unknown: false,
        };
        let cancellation = crate::analyzer::semantic::CancellationToken::default();
        let mut budget = crate::analyzer::semantic::SemanticBudget::new(
            crate::analyzer::semantic::SemanticWork::default_limits(),
        )
        .expect("default semantic budgets are positive");
        let summary_reads = CountingSummaryReads::default();
        let retained_direct_tuple_result =
            brokk_bifrost_flow::typestate::acquire_production_semantic_summaries(
                std::slice::from_ref(&direct_tuple_result_root),
                &provider,
                &repository,
                &summary_reads,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("direct tuple-result summary closure is retained")
            .into_summaries();
        assert_eq!(provider.call_transfers.get(), 0);
        let retained_direct_tuple_result = report(
            &direct_tuple_result_root,
            Some(retained_direct_tuple_result),
        );
        assert_eq!(
            stable_report(&direct_tuple_result),
            stable_report(&retained_direct_tuple_result),
            "fresh and retained direct tuple-result fixed points differ"
        );

        let opaque_tuple_result_root = procedure("mutualOpaqueTupleResultRoot");
        let opaque_tuple_result = report(
            &opaque_tuple_result_root,
            Some(project_summaries(&opaque_tuple_result_root)),
        );
        assert!(
            opaque_tuple_result.reasons.contains(
                &brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::RecursiveExpansion
            ),
            "an unresolved tuple transform has no result identity: {opaque_tuple_result:#?}"
        );
        assert!(
            opaque_tuple_result
                .conflicts
                .iter()
                .all(|conflict| !conflict.proven),
            "an opaque tuple result must not fabricate a race: {opaque_tuple_result:#?}"
        );

        let swapped_result_root = procedure("mutualSwappedResultRoot");
        let swapped_result = report(
            &swapped_result_root,
            Some(project_summaries(&swapped_result_root)),
        );
        assert!(
            swapped_result.reasons.contains(
                &brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::RecursiveExpansion
            ),
            "reordered result ordinals are not same-ordinal equations: {swapped_result:#?}"
        );
        assert!(
            swapped_result
                .conflicts
                .iter()
                .all(|conflict| !conflict.proven),
            "reordered result ordinals must not fabricate a race: {swapped_result:#?}"
        );

        let mutual_mixed_result_root = procedure("mutualMixedResultRoot");
        let mutual_mixed_result = report(
            &mutual_mixed_result_root,
            Some(project_summaries(&mutual_mixed_result_root)),
        );
        assert!(
            mutual_mixed_result.reasons.contains(
                &brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::RecursiveExpansion
            ),
            "a value-copy result ordinal keeps the multi-result component open: {mutual_mixed_result:#?}"
        );
        assert!(
            mutual_mixed_result
                .conflicts
                .iter()
                .all(|conflict| !conflict.proven),
            "a mixed value result must not fabricate a race: {mutual_mixed_result:#?}"
        );

        let partially_unanchored_root = procedure("mutualPartiallyUnanchoredResultRoot");
        let partially_unanchored = report(
            &partially_unanchored_root,
            Some(project_summaries(&partially_unanchored_root)),
        );
        assert!(
            partially_unanchored.reasons.contains(
                &brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::RecursiveExpansion
            ),
            "every recursive result ordinal needs its own exact base: {partially_unanchored:#?}"
        );
        assert!(
            partially_unanchored
                .conflicts
                .iter()
                .all(|conflict| !conflict.proven),
            "a partially unanchored result tuple must not fabricate a race: {partially_unanchored:#?}"
        );

        let mutual_value_result_root = procedure("mutualValueResultRoot");
        let mutual_value_result = report(
            &mutual_value_result_root,
            Some(project_summaries(&mutual_value_result_root)),
        );
        assert!(
            mutual_value_result.reasons.contains(
                &brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::RecursiveExpansion
            ),
            "a two-member struct-by-value result cannot inherit caller identity: {mutual_value_result:#?}"
        );
        assert!(
            mutual_value_result
                .conflicts
                .iter()
                .all(|conflict| !conflict.proven),
            "a two-member value result must not fabricate a race: {mutual_value_result:#?}"
        );

        let mutual_unanchored_result_root = procedure("mutualUnanchoredResultRoot");
        let mutual_unanchored_result = report(
            &mutual_unanchored_result_root,
            Some(project_summaries(&mutual_unanchored_result_root)),
        );
        assert!(
            mutual_unanchored_result.reasons.contains(
                &brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::RecursiveExpansion
            ),
            "a two-member result cycle without a base object proves no identity: {mutual_unanchored_result:#?}"
        );
        assert!(
            mutual_unanchored_result
                .conflicts
                .iter()
                .all(|conflict| !conflict.proven),
            "an unanchored two-member result must not fabricate a race: {mutual_unanchored_result:#?}"
        );

        let mutual_shift_root = procedure("mutualShiftRoot");
        let mutual_shift = report(
            &mutual_shift_root,
            Some(project_summaries(&mutual_shift_root)),
        );
        assert!(
            mutual_shift.reasons.contains(
                &brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::RecursiveExpansion
            ),
            "a mutual cycle that changes the accessed object remains open: {mutual_shift:#?}"
        );
        assert!(
            mutual_shift
                .conflicts
                .iter()
                .all(|conflict| !conflict.proven),
            "the omitted second-object write cannot be fabricated from the first cycle: {mutual_shift:#?}"
        );
    }

    #[test]
    fn unpublished_summary_invalidates_when_the_allocation_becomes_published() {
        const PRIVATE_SOURCE: &str = r#"package main

type cell struct { n int }

func recursive(depth int) {
    c := &cell{}
    c.n = 1
    if depth > 0 { recursive(depth-1) }
}

func unknownWrite(c *cell) { c.n = 2 }
func root(c *cell) {
    go recursive(3)
    go unknownWrite(c)
}
"#;
        const PUBLISHED_SOURCE: &str = r#"package main

type cell struct { n int }
var escaped *cell

func recursive(depth int) {
    c := &cell{}
    escaped = c
    c.n = 1
    if depth > 0 { recursive(depth-1) }
}

func unknownWrite(c *cell) { c.n = 2 }
func root(c *cell) {
    go recursive(3)
    go unknownWrite(c)
}
"#;

        let project = InlineTestProject::with_language(Language::Go)
            .file("main.go", PRIVATE_SOURCE)
            .build();
        let file = project.file("main.go");
        let workspace = project.workspace_analyzer(AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        });
        let materialize = |workspace: &WorkspaceAnalyzer| {
            let cancellation = crate::analyzer::semantic::CancellationToken::default();
            let mut budget = crate::analyzer::semantic::SemanticBudget::default();
            workspace
                .materialize_program_semantics(
                    &file,
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .expect("Go semantics materialize")
                .available_value()
                .expect("Go semantics are available")
                .clone()
        };
        let procedure = |artifact: &Arc<crate::analyzer::semantic::SemanticArtifact>,
                         name: &str| {
            artifact
                .procedures()
                .iter()
                .find(|procedure| {
                    procedure.kind() == crate::analyzer::semantic::ProcedureKind::Function
                        && procedure.lexical_parent().is_none()
                        && procedure
                            .locator()
                            .declaration()
                            .segments()
                            .last()
                            .and_then(|segment| segment.name())
                            == Some(name)
                })
                .and_then(|procedure| artifact.procedure_handle(procedure.id()))
                .unwrap_or_else(|| panic!("fixture has top-level function {name:?}"))
        };
        let project_summaries = |workspace: &WorkspaceAnalyzer, root: &ProcedureHandle| {
            let provider = workspace.icfg_provider();
            let cancellation = crate::analyzer::semantic::CancellationToken::default();
            let mut budget = crate::analyzer::semantic::SemanticBudget::new(
                crate::analyzer::semantic::SemanticWork::default_limits(),
            )
            .expect("default semantic budgets are positive");
            brokk_bifrost_flow::typestate::project_production_semantic_summaries(
                std::slice::from_ref(root),
                &provider,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("production summaries project")
        };
        let report =
            |workspace: &WorkspaceAnalyzer,
             root: &ProcedureHandle,
             summaries: brokk_bifrost_flow::typestate::ProductionSemanticSummarySet| {
                let provider = WorkspaceConcurrencyProvider::new(workspace, None, Some(summaries));
                let cancellation = crate::analyzer::semantic::CancellationToken::default();
                let mut budget = crate::analyzer::semantic::SemanticBudget::new(
                    crate::analyzer::semantic::SemanticWork::default_limits(),
                )
                .expect("default semantic budgets are positive");
                brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
                    &provider,
                    root,
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .expect("concurrency report computes")
            };

        let artifact = materialize(&workspace);
        let root = procedure(&artifact, "root");
        let recursive = procedure(&artifact, "recursive");
        let private_summaries = project_summaries(&workspace, &root);
        let private_summary = private_summaries
            .summary_for(&recursive)
            .expect("private recursive summary projects");
        assert!(private_summary.effects().iter().any(|effect| matches!(
            effect.key(),
            brokk_bifrost_flow::dataflow::SummaryEffectKey::Concurrency(concurrency)
                if matches!(
                    concurrency.kind(),
                    brokk_bifrost_flow::dataflow::SummaryConcurrencyEffectKind::Unpublished { .. }
                )
        )));
        let private_report = report(&workspace, &root, private_summaries.clone());
        assert!(
            private_report.reasons.is_empty() && private_report.conflicts.is_empty(),
            "the unpublished recursive allocation stays disjoint from the sibling's unknown object: {private_report:#?}"
        );
        let private_key = private_summary.key().clone();
        let repository = brokk_bifrost_flow::dataflow::ProductionSemanticSummaryRepository::new();
        repository
            .publish_components(
                private_summaries.summaries(),
                private_summaries.components(),
            )
            .expect("private recursive summary closure publishes");

        file.write(PUBLISHED_SOURCE)
            .expect("edit the recursive allocation to publish it");
        let updated_workspace = workspace.update(&std::collections::BTreeSet::from([file.clone()]));
        let updated_artifact = materialize(&updated_workspace);
        let updated_root = procedure(&updated_artifact, "root");
        let updated_recursive = procedure(&updated_artifact, "recursive");
        let provider = updated_workspace.icfg_provider();
        let cancellation = crate::analyzer::semantic::CancellationToken::default();
        let mut budget = crate::analyzer::semantic::SemanticBudget::new(
            crate::analyzer::semantic::SemanticWork::default_limits(),
        )
        .expect("default semantic budgets are positive");
        let summary_reads = CountingSummaryReads::default();
        let updated = brokk_bifrost_flow::typestate::acquire_production_semantic_summaries(
            std::slice::from_ref(&updated_root),
            &provider,
            &repository,
            &summary_reads,
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("updated recursive summary closure projects");
        assert_eq!(
            updated.kind(),
            brokk_bifrost_flow::typestate::ProductionSemanticSummaryAcquisitionKind::Projected,
            "the private summary closure must miss after its source publishes the allocation"
        );
        assert_eq!(summary_reads.0.get(), 0);
        let updated_summaries = updated.into_summaries();
        let updated_summary = updated_summaries
            .summary_for(&updated_recursive)
            .expect("updated recursive summary projects");
        assert_ne!(updated_summary.key(), &private_key);
        assert!(updated_summary.effects().iter().any(|effect| matches!(
            effect.key(),
            brokk_bifrost_flow::dataflow::SummaryEffectKey::Concurrency(concurrency)
                if matches!(
                    concurrency.kind(),
                    brokk_bifrost_flow::dataflow::SummaryConcurrencyEffectKind::Publish { .. }
                )
        )));
        assert!(updated_summary.effects().iter().all(|effect| !matches!(
            effect.key(),
            brokk_bifrost_flow::dataflow::SummaryEffectKey::Concurrency(concurrency)
                if matches!(
                    concurrency.kind(),
                    brokk_bifrost_flow::dataflow::SummaryConcurrencyEffectKind::Unpublished { .. }
                )
        )));

        let fresh_workspace = project.workspace_analyzer(AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        });
        let fresh_artifact = materialize(&fresh_workspace);
        let fresh_root = procedure(&fresh_artifact, "root");
        let fresh_summaries = project_summaries(&fresh_workspace, &fresh_root);
        let updated_report = report(&updated_workspace, &updated_root, updated_summaries.clone());
        let fresh_report = report(&fresh_workspace, &fresh_root, fresh_summaries.clone());
        assert_eq!(
            updated_summaries.summaries(),
            fresh_summaries.summaries(),
            "incremental publication summaries must equal fresh projection"
        );
        assert_eq!(updated_summaries.components(), fresh_summaries.components());
        assert_eq!(
            stable_report(&updated_report),
            stable_report(&fresh_report),
            "incremental publication reports must equal fresh execution"
        );
        assert!(
            updated_report
                .reasons
                .contains(&ConcurrencyOpenReason::RecursiveExpansion)
                && updated_report.conflicts.iter().any(|conflict| {
                    !conflict.proven
                        && conflict
                            .reasons
                            .contains(&ConcurrencyOpenReason::RecursiveExpansion)
                })
                && updated_report
                    .conflicts
                    .iter()
                    .all(|conflict| !conflict.proven),
            "publishing the recursive allocation rejects the private fixed point without fabricating a conflict: {updated_report:#?}"
        );
    }

    #[test]
    fn open_publication_inventory_disqualifies_only_its_allocation_privacy() {
        let project = InlineTestProject::with_language(Language::Go)
            .file(
                "main.go",
                r#"package main

type cell struct { n int }
func makePrivate() *cell { return &cell{} }

func root() {
    first := makePrivate()
    second := &cell{}
    go func() {
        foreign()
        first.n = 1
        second.n = 1
    }()
    first.n = 2
    second.n = 2
}
"#,
            )
            .build();
        let file = project.file("main.go");
        let workspace = project.workspace_analyzer(AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        });
        let cancellation = crate::analyzer::semantic::CancellationToken::default();
        let mut budget = crate::analyzer::semantic::SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("Go semantics materialize")
            .available_value()
            .expect("Go semantics are available")
            .clone();
        let root = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure.kind() == crate::analyzer::semantic::ProcedureKind::Function
                    && procedure.lexical_parent().is_none()
                    && procedure
                        .locator()
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some("root")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("fixture root procedure");
        let projection_provider = CountingIcfgProvider {
            inner: workspace.icfg_provider(),
            call_transfers: std::cell::Cell::new(0),
            behavior: Some(
                crate::analyzer::semantic::IcfgProviderBehaviorIdentity::hash_bytes(
                    b"unknown-publication-provider",
                ),
            ),
            publication_unknown: true,
        };
        let cancellation = crate::analyzer::semantic::CancellationToken::default();
        let mut budget = crate::analyzer::semantic::SemanticBudget::new(
            crate::analyzer::semantic::SemanticWork::default_limits(),
        )
        .expect("default semantic budgets are positive");
        let summaries = brokk_bifrost_flow::typestate::project_production_semantic_summaries(
            std::slice::from_ref(&root),
            &projection_provider,
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("open publication summaries project");
        assert!(
            summaries.summaries().iter().all(|summary| summary.effects().iter().all(
                |effect| !matches!(
                    effect.key(),
                    brokk_bifrost_flow::dataflow::SummaryEffectKey::Concurrency(concurrency)
                        if matches!(
                            concurrency.kind(),
                            brokk_bifrost_flow::dataflow::SummaryConcurrencyEffectKind::Unpublished { .. }
                        )
                )
            )),
            "an unknown publication inventory cannot emit non-publication proof"
        );
        let provider = WorkspaceConcurrencyProvider::new(&workspace, None, Some(summaries));
        let cancellation = crate::analyzer::semantic::CancellationToken::default();
        let mut budget = crate::analyzer::semantic::SemanticBudget::new(
            crate::analyzer::semantic::SemanticWork::default_limits(),
        )
        .expect("default semantic budgets are positive");
        let report = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
            &provider,
            &root,
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("concurrency report computes");
        let conflicts = report
            .conflicts
            .iter()
            .filter(|conflict| {
                conflict.first.mode == brokk_bifrost_flow::concurrency::ConcurrentAccessMode::Write
                    && conflict.second.mode
                        == brokk_bifrost_flow::concurrency::ConcurrentAccessMode::Write
                    && conflict.ordering
                        == brokk_bifrost_flow::concurrency::ConcurrentOrdering::Unordered
                    && conflict.protection
                        == brokk_bifrost_flow::concurrency::ConcurrentProtection::Unprotected
            })
            .collect::<Vec<_>>();
        assert_eq!(
            conflicts.len(),
            2,
            "fixture has two shared fields: {report:#?}"
        );
        assert_eq!(
            conflicts.iter().filter(|conflict| conflict.proven).count(),
            1,
            "the root-local allocation retains its independent privacy proof: {report:#?}"
        );
        let open = conflicts
            .iter()
            .find(|conflict| !conflict.proven)
            .expect("the factory allocation stays open");
        assert!(
            open.reasons.contains(
                &brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::UnresolvedTarget
            ),
            "an open factory publication inventory cannot hide foreign effects: {report:#?}"
        );
    }
}
