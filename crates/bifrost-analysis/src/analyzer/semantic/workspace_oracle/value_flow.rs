//! Bounded value-flow and candidate-specific call-binding materialization.
//!
//! The implementation projects validated semantic IR rows into neutral oracle
//! relations. Java argument conversions delegate to the shared resolver-owned
//! producer through `conversions.rs`; no type interpretation lives here.
//! The remaining projection never reparses source or matches declarations by text,
//! except for one narrow, explicitly named discharge predicate
//! ([`super::external_constant_field_read_discharges_gap`], #2538) composed
//! into the two gap sweeps below: it delegates to `dispatch.rs`'s own
//! source-and-text machinery (already used there to resolve an
//! unmaterialized external *call* target) to prove a specific `FieldMemory`
//! gap is a `static final` read on an external type. Every other relevance
//! and discharge decision in this file stays IR-only. Saved Python defaults
//! additionally consult the provider's captured workspace metadata authority;
//! this file does not scan their source again.
//!
//! The relation pass, [`project_procedure_relations`], takes every answer that
//! does not come from the procedure's own IR from a [`RelationProjectionHost`],
//! so it can run against the workspace at query time or against one file at
//! parse time.

use crate::analyzer::languages::PredeclaredBuiltinQueryStep;

use crate::analyzer::languages::language_support;

use crate::analyzer::semantic::workspace_oracle::common::Interruption;

use crate::analyzer::semantic::workspace_oracle::common::WorkStager;

use crate::analyzer::semantic::workspace_oracle::common::dedup_evidence;

use crate::analyzer::semantic::workspace_oracle::common::evidence_handle;

use crate::analyzer::semantic::workspace_oracle::common::evidence_quality;

use crate::analyzer::semantic::workspace_oracle::common::internal_contract;

use crate::analyzer::semantic::workspace_oracle::common::value_handle;

use crate::analyzer::semantic::workspace_oracle::RuntimeKeyedReadResult;

use crate::analyzer::semantic::workspace_oracle::WorkspaceSemanticOracle;

use crate::analyzer::semantic::AbstractObjectIdentity;

use crate::analyzer::semantic::AccessPath;

use crate::analyzer::semantic::AccessPathRoot;

use crate::analyzer::semantic::AccessSelector;

use crate::analyzer::semantic::BindingOriginIndex;

use crate::analyzer::semantic::CallArgumentEndpoint;

use crate::analyzer::semantic::CallArgumentExpansion;

use crate::analyzer::semantic::CallArgumentMapping;

use crate::analyzer::semantic::CallArgumentMember;

use crate::analyzer::semantic::CallBinding;

use crate::analyzer::semantic::CallBindings;

use crate::analyzer::semantic::CallPassingMode;

use crate::analyzer::semantic::CallableTarget;

use crate::analyzer::semantic::CallableTargetResolution;

use crate::analyzer::semantic::CallerReceiverBinding;

use crate::analyzer::semantic::CandidateCoverage;

use crate::analyzer::semantic::CaptureSource;

use crate::analyzer::semantic::DispatchCandidate;

use crate::analyzer::semantic::EvidenceCompleteness;

use crate::analyzer::semantic::FormalMultiplicity;

use crate::analyzer::semantic::HeapOracle;

use crate::analyzer::semantic::ImplicitArgumentKind;

use crate::analyzer::semantic::IndexSelector;

use crate::analyzer::semantic::MemoryLocationId;

use crate::analyzer::semantic::MemoryLocationKind;

use crate::analyzer::semantic::ObjectCardinality;

use crate::analyzer::semantic::OracleCallContext;

use crate::analyzer::semantic::OracleLimits;

use crate::analyzer::semantic::ProcedureCallBoundary;

use crate::analyzer::semantic::ProcedureHandle;

use crate::analyzer::semantic::ProcedurePortHandle;

use crate::analyzer::semantic::ProcedurePortKind;

use crate::analyzer::semantic::ProcedureReceiverBinding;

use crate::analyzer::semantic::ProgramPointHandle;

use crate::analyzer::semantic::ProgramPointId;

use crate::analyzer::semantic::ScopedSemanticLocator;

use crate::analyzer::semantic::SemanticCapability;

use crate::analyzer::semantic::SemanticEffect;

use crate::analyzer::semantic::SemanticGapDischarge;

use crate::analyzer::semantic::SemanticGapImpact;

use crate::analyzer::semantic::SemanticGapKind;

use crate::analyzer::semantic::SemanticGapSubject;

use crate::analyzer::semantic::SemanticLocator;

use crate::analyzer::semantic::SemanticOutcome;

use crate::analyzer::semantic::SemanticProviderError;

use crate::analyzer::semantic::SemanticRequest;

use crate::analyzer::semantic::SemanticValueKind;

use crate::analyzer::semantic::SemanticWork;

use crate::analyzer::semantic::ValueFlowKind;

use crate::analyzer::semantic::ValueFlowOracle;

use crate::analyzer::semantic::ValueFlowSnapshot;

use crate::analyzer::semantic::ValueId;

use crate::analyzer::semantic::ValueTransfer;

use crate::analyzer::semantic::constructor_call_result;

use crate::analyzer::semantic::gap_certifies_canonical_index_identity;

pub use brokk_bifrost_semantic::analyzer::semantic::workspace_oracle::value_flow::*;

use std::collections::HashMap;

use std::collections::HashSet;

use std::sync::Arc;

impl WorkspaceSemanticOracle<'_> {
    /// Prove that one call result holds exactly one local callable the callee
    /// returned, and materialize that callable's procedure.
    ///
    /// The proof is the callee's own call-binding provenance: the caller result
    /// must be bound to the callee's normal return port, and the unique return
    /// flow feeding that port must derive, through local assignments only,
    /// from one exact callable creation. Every contributing row must carry
    /// proven complete evidence. A second matching return binding, a second
    /// return flow, a competing definition of a value on the derivation chain,
    /// or a callable target that is not one local procedure all refuse the
    /// question instead of picking a callable.
    ///
    /// The answer also carries the creation's structured capture association:
    /// every `CaptureBind` row the callee published for the closure names the
    /// exact environment slot that will observe the value the closure reads.
    /// That association is what lets a consumer keep the escaped environment
    /// connected to the callee's writes without re-deriving the callable's
    /// provenance from syntax.
    pub(crate) fn returned_callable_target(
        &self,
        call: &crate::analyzer::semantic::CallSiteHandle,
        candidate: &DispatchCandidate,
        result: ValueId,
        context: &OracleCallContext,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<Option<LocalCallableTarget>>, SemanticProviderError> {
        if request.cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: SemanticWork::default(),
            });
        }
        let mut staged = WorkStager::new(request);
        let bindings_outcome = self.call_bindings(
            call,
            candidate,
            context,
            &mut staged.request(request.cancellation),
        )?;
        staged.work = staged.work.conservative_add(bindings_outcome.work());
        // This query proves the identity observed on a normal return, not the
        // execution effects of the producer. A retained parent topology can
        // leave spawned work unsupported without changing an unaddressable
        // local callable. Keep the binding outcome open; validate the exact
        // return relation and the immutable local derivation below.
        let (bindings, retained_parent_return) = match bindings_outcome {
            SemanticOutcome::Complete { value, .. } => (value, false),
            SemanticOutcome::Unsupported {
                capability: SemanticCapability::ConcurrentSpawn,
                partial: Some(value),
                ..
            } if value.coverage() == CandidateCoverage::Open => (value, true),
            SemanticOutcome::ExceededBudget { exceeded, .. } => {
                return Ok(returned_callable_interruption(
                    request,
                    staged,
                    Interruption::Budget(exceeded),
                ));
            }
            SemanticOutcome::Cancelled { .. } => {
                return Ok(returned_callable_interruption(
                    request,
                    staged,
                    Interruption::Cancelled,
                ));
            }
            _ => return Ok(returned_callable_refusal(request, &staged)),
        };
        if !retained_parent_return && bindings.coverage() != CandidateCoverage::Exhaustive {
            return Ok(returned_callable_refusal(request, &staged));
        }
        if retained_parent_return {
            if bindings.bindings().iter().any(|binding| {
                matches!(binding, CallBinding::ArgumentGroup(group)
                    if group.coverage() != CandidateCoverage::Exhaustive)
            }) {
                return Ok(returned_callable_refusal(request, &staged));
            }

            // No other return/evaluation omission may be hidden by the typed
            // spawn outcome. Caller-side obligations cannot be discharged by
            // the callee's retained topology either.
            for (procedure, caller) in [(call.procedure(), true), (candidate.target(), false)] {
                for gap in procedure.semantics().gaps() {
                    if request.cancellation.is_cancelled() {
                        return Ok(returned_callable_interruption(
                            request,
                            staged,
                            Interruption::Cancelled,
                        ));
                    }
                    staged.charge_work(SemanticWork {
                        gaps: 1,
                        ..SemanticWork::default()
                    });
                    if (gap.impacts.contains(SemanticGapImpact::CallEvaluation)
                        || gap.impacts.contains(SemanticGapImpact::ReturnTransfer))
                        && (caller
                            || gap.kind != SemanticGapKind::Unsupported
                            || gap.capability != SemanticCapability::ConcurrentSpawn
                            || !procedure.semantics().point(gap.point).is_some_and(|point| {
                                point.events.iter().any(|event| {
                                    matches!(event.effect, SemanticEffect::Invoke { .. })
                                })
                            })
                            || gap.subject != SemanticGapSubject::Point
                            || gap.discharge != SemanticGapDischarge::RetainedControlTopology)
                    {
                        return Ok(returned_callable_refusal(request, &staged));
                    }
                }
            }
        }
        let mut matching_normal_returns = 0usize;
        for binding in bindings.bindings() {
            let CallBinding::NormalReturn {
                formal,
                result: returned,
                ..
            } = binding
            else {
                continue;
            };
            if returned.id() != result
                || !matches!(
                    formal.kind(),
                    ProcedurePortKind::NormalReturn
                        | ProcedurePortKind::IndexedNormalReturn { ordinal: 0 }
                )
            {
                continue;
            }
            matching_normal_returns += 1;
        }
        if matching_normal_returns != 1 {
            return Ok(returned_callable_refusal(request, &staged));
        }
        let callee = candidate.target();
        let semantics = callee.semantics();
        let mut returned_source = None;
        for point in semantics.points() {
            if request.cancellation.is_cancelled() {
                return Ok(returned_callable_interruption(
                    request,
                    staged,
                    Interruption::Cancelled,
                ));
            }
            staged.charge_work(SemanticWork {
                program_points: 1,
                nested_entries: point.events.len(),
                ..SemanticWork::default()
            });
            for event in point.events.iter() {
                let SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Return | ValueFlowKind::IndexedReturn { ordinal: 0 },
                    source,
                    ..
                } = event.effect
                else {
                    continue;
                };
                if !proven_complete(&[evidence_handle(callee, event.evidence)?])
                    || returned_source.replace(source).is_some()
                {
                    return Ok(returned_callable_refusal(request, &staged));
                }
            }
        }
        let Some(returned_source) = returned_source else {
            return Ok(returned_callable_refusal(request, &staged));
        };
        let local_outcome = self.local_callable_target(
            callee,
            returned_source,
            &mut staged.request(request.cancellation),
        )?;
        staged.work = staged.work.conservative_add(local_outcome.work());
        match local_outcome {
            SemanticOutcome::Complete { value, .. } => {
                *request.budget = staged.budget;
                Ok(SemanticOutcome::Complete {
                    value,
                    work: staged.work,
                })
            }
            SemanticOutcome::ExceededBudget { exceeded, .. } => Ok(returned_callable_interruption(
                request,
                staged,
                Interruption::Budget(exceeded),
            )),
            SemanticOutcome::Cancelled { .. } => Ok(returned_callable_interruption(
                request,
                staged,
                Interruption::Cancelled,
            )),
            _ => Ok(returned_callable_refusal(request, &staged)),
        }
    }

    /// Resolve one local callable from a value through unique local
    /// definitions, then validate its exact capture association.
    pub(crate) fn local_callable_target(
        &self,
        procedure: &ProcedureHandle,
        value: ValueId,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<Option<LocalCallableTarget>>, SemanticProviderError> {
        let mut staged = WorkStager::new(request);
        let artifact = procedure.artifact();
        let semantics = procedure.semantics();
        let mut current = value;
        let mut visited: HashSet<ValueId> = HashSet::default();
        loop {
            if !visited.insert(current) {
                return Ok(returned_callable_refusal(request, &staged));
            }
            // A unique local assignment is not exact callable identity when
            // another procedure can rebind that local through shared storage.
            // The closure's own captured values are a separate question.
            for location in semantics.memory_locations() {
                if request.cancellation.is_cancelled() {
                    return Ok(returned_callable_interruption(
                        request,
                        staged,
                        Interruption::Cancelled,
                    ));
                }
                staged.charge_work(SemanticWork {
                    nested_entries: 1,
                    ..SemanticWork::default()
                });
                if matches!(location.kind,
                    MemoryLocationKind::LexicalCell { binding }
                        | MemoryLocationKind::Dereference { address: binding }
                        | MemoryLocationKind::Capture { binding: Some(binding), .. }
                        if binding == current)
                {
                    return Ok(returned_callable_refusal(request, &staged));
                }
            }
            let mut definition: Option<ValueId> = None;
            let mut created: Option<ProcedureHandle> = None;
            let mut created_value: Option<ValueId> = None;
            for point in semantics.points() {
                if request.cancellation.is_cancelled() {
                    return Ok(returned_callable_interruption(
                        request,
                        staged,
                        Interruption::Cancelled,
                    ));
                }
                staged.charge_work(SemanticWork {
                    program_points: 1,
                    nested_entries: point.events.len(),
                    ..SemanticWork::default()
                });
                for event in point.events.iter() {
                    match &event.effect {
                        SemanticEffect::Assignment {
                            target,
                            value: source,
                        }
                        | SemanticEffect::ValueFlow { source, target, .. }
                            if *source == current
                                && semantics.value(*target).is_some_and(|value| {
                                    value.kind == SemanticValueKind::Address
                                }) =>
                        {
                            return Ok(returned_callable_refusal(request, &staged));
                        }
                        SemanticEffect::CaptureBind { capture }
                            if semantics.capture(*capture).is_some_and(|capture| {
                                capture.captured == CaptureSource::Value(current)
                            }) =>
                        {
                            return Ok(returned_callable_refusal(request, &staged));
                        }

                        SemanticEffect::CallableCreation {
                            result: creation,
                            callable,
                        } if *creation == current => {
                            if !proven_complete(&[evidence_handle(procedure, event.evidence)?])
                                || !proven_complete(&[evidence_handle(
                                    procedure,
                                    callable.target_evidence,
                                )?])
                            {
                                return Ok(returned_callable_refusal(request, &staged));
                            }
                            let CallableTargetResolution::Proven(CallableTarget::Local(closure)) =
                                &callable.targets
                            else {
                                return Ok(returned_callable_refusal(request, &staged));
                            };
                            let closure_procedure = artifact.procedure_handle(*closure).ok_or_else(|| {
                                SemanticProviderError::internal(
                                    "returned local callable is absent from its semantic artifact",
                                )
                            })?;
                            if created.is_some() {
                                return Ok(returned_callable_refusal(request, &staged));
                            }
                            created = Some(closure_procedure);
                            created_value = Some(*creation);
                        }
                        SemanticEffect::Assignment {
                            target,
                            value: source,
                        }
                        | SemanticEffect::ValueFlow {
                            kind: ValueFlowKind::Local,
                            source,
                            target,
                        } if *target == current => {
                            if !proven_complete(&[evidence_handle(procedure, event.evidence)?]) {
                                return Ok(returned_callable_refusal(request, &staged));
                            }
                            if definition.is_some_and(|existing| existing != *source) {
                                return Ok(returned_callable_refusal(request, &staged));
                            }
                            definition = Some(*source);
                        }
                        SemanticEffect::ValueFlow {
                            kind: ValueFlowKind::LanguageDefined,
                            source,
                            target,
                        } if *target == current
                            && is_go_assignment_conversion(semantics, *target) =>
                        {
                            if !proven_complete(&[evidence_handle(procedure, event.evidence)?])
                                || definition.is_some_and(|existing| existing != *source)
                            {
                                return Ok(returned_callable_refusal(request, &staged));
                            }
                            definition = Some(*source);
                        }
                        SemanticEffect::ValueFlow { target, .. }
                        | SemanticEffect::MemoryLoad { result: target, .. }
                            if *target == current =>
                        {
                            return Ok(returned_callable_refusal(request, &staged));
                        }
                        // The adapter's operand annotation is not a competing
                        // definition of the value.
                        SemanticEffect::CallableReference { result, .. } if *result == current => {}
                        _ => {}
                    }
                }
            }
            if created.is_some() && definition.is_some() {
                return Ok(returned_callable_refusal(request, &staged));
            }
            if let Some(closure_procedure) = created {
                let creation = created_value.expect("a retained callable records its value");
                let target_semantics = closure_procedure.semantics();
                if target_semantics
                    .gaps()
                    .iter()
                    .any(|gap| gap.capability == SemanticCapability::Captures)
                {
                    return Ok(returned_callable_refusal(request, &staged));
                }
                let mut expected_captures: HashSet<MemoryLocationId> = HashSet::default();
                for location in target_semantics.memory_locations() {
                    if request.cancellation.is_cancelled() {
                        return Ok(returned_callable_interruption(
                            request,
                            staged,
                            Interruption::Cancelled,
                        ));
                    }
                    staged.charge_work(SemanticWork {
                        nested_entries: 1,
                        ..SemanticWork::default()
                    });
                    if let MemoryLocationKind::Capture { lexical_parent, .. } = location.kind {
                        if lexical_parent != procedure.id() {
                            return Ok(returned_callable_refusal(request, &staged));
                        }
                        expected_captures.insert(location.id);
                    }
                }
                let mut captures = Vec::new();
                let mut capture_bindings = Vec::new();
                let mut bound_captures: HashSet<MemoryLocationId> = HashSet::default();
                for row in semantics.captures() {
                    if request.cancellation.is_cancelled() {
                        return Ok(returned_callable_interruption(
                            request,
                            staged,
                            Interruption::Cancelled,
                        ));
                    }
                    staged.charge_work(SemanticWork {
                        nested_entries: 1,
                        ..SemanticWork::default()
                    });
                    if row.target != closure_procedure.id() {
                        continue;
                    }
                    // A row that targets the closure from another creating
                    // value, or without proven complete evidence, makes the
                    // environment association ambiguous. The caller must keep
                    // its refusal rather than trust one storage row.
                    if row.callable != creation
                        || !expected_captures.contains(&row.destination)
                        || !bound_captures.insert(row.destination)
                        || !proven_complete(&[evidence_handle(procedure, row.evidence)?])
                    {
                        return Ok(returned_callable_refusal(request, &staged));
                    }
                    // Retain the source entity and mode, not only the child's
                    // destination slot. Consumers must follow shared-cell state
                    // at invocation rather than freezing the creation value.
                    if let Err(stop) = staged.admit(SemanticWork {
                        captures: 1,
                        nested_entries: 1,
                        owned_text_bytes: match &row.mode {
                            crate::analyzer::semantic::CaptureMode::LanguageDefined(label) => {
                                label.len()
                            }
                            _ => 0,
                        },
                        ..SemanticWork::default()
                    }) {
                        return Ok(returned_callable_interruption(request, staged, stop));
                    }
                    capture_bindings.push(row.clone());
                    captures.push(row.destination);
                }
                if bound_captures != expected_captures {
                    return Ok(returned_callable_refusal(request, &staged));
                }
                let creation = value_handle(procedure, creation)?;
                captures.sort_unstable();
                capture_bindings.sort_unstable_by_key(|row| row.destination);
                *request.budget = staged.budget;
                return Ok(SemanticOutcome::Complete {
                    value: Some(LocalCallableTarget {
                        closure: closure_procedure,
                        creation,
                        captures: captures.into_boxed_slice(),
                        capture_bindings: capture_bindings.into_boxed_slice(),
                    }),
                    work: staged.work,
                });
            }
            let Some(next) = definition else {
                return Ok(returned_callable_refusal(request, &staged));
            };
            current = next;
        }
    }
}

impl RelationProjectionHost for WorkspaceSemanticOracle<'_> {
    fn runtime_refinements(
        &self,
        procedure: &ProcedureHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<RuntimeKeyedReadResult>, SemanticProviderError> {
        self.runtime_refinements_for_procedure(procedure, request)
    }

    /// Prove a lowering-time Go builtin assumption only when the bounded package
    /// declaration lookup authoritatively finds no same-package declaration.
    fn go_builtin_scope_absent(
        &self,
        procedure: &ProcedureHandle,
        builtin: crate::analyzer::semantic::GoPredeclaredBuiltin,
        limit: usize,
        staged: &mut WorkStager,
        cancellation: &crate::CancellationToken,
    ) -> Result<bool, Interruption> {
        let Some(support) = language_support(procedure.artifact().key().language().language())
        else {
            return Ok(false);
        };
        let mut interrupted = None;
        let mut query_step = |step| {
            if matches!(step, PredeclaredBuiltinQueryStep::VisitCandidate)
                && cancellation.is_cancelled()
            {
                interrupted = Some(Interruption::Cancelled);
                return false;
            }
            staged.charge_work(SemanticWork {
                nested_entries: 1,
                ..SemanticWork::default()
            });
            true
        };
        let status = support.predeclared_builtin_shadow_status_limited(
            self.workspace.analyzer(),
            procedure.artifact().key().path().as_str(),
            builtin.name(),
            limit,
            &mut query_step,
        );
        if let Some(stop) = interrupted {
            return Err(stop);
        }
        Ok(status == Some(false))
    }

    /// The catch-binding events of `procedure` whose call cannot throw anything
    /// the bound catch parameter catches, keyed by point and event index.
    ///
    /// A lowering binds a call's thrown value to the catch parameter of the
    /// handler its exceptional continuation reaches, as an `Assignment` and a
    /// local `ValueFlow` at that continuation point. The IR carries no exception
    /// types, so the binding is published for every such call. A language's own
    /// typing rules can prove that a call never throws what the catch clause
    /// catches: a Java callee that declares no `throws` clause cannot deliver a
    /// checked exception. Dropping that binding keeps the parameter's origin the
    /// throws that can reach it, so a field read through the parameter still
    /// observes the thrown object (#2192).
    ///
    /// Fails closed: a language without the proof, an unavailable source, or an
    /// unmapped span refutes nothing.
    fn refuted_catch_bindings(
        &self,
        procedure: &ProcedureHandle,
        request: &SemanticRequest<'_>,
    ) -> Result<HashSet<(ProgramPointId, usize)>, SemanticProviderError> {
        let semantics = procedure.semantics();
        let mut candidates = Vec::new();
        for call in semantics.call_sites() {
            let (Some(thrown), crate::analyzer::semantic::ControlContinuation::Target(point)) =
                (call.thrown, call.exceptional_continuation)
            else {
                continue;
            };
            let Some(row) = semantics.point(point) else {
                continue;
            };
            for (index, event) in row.events.iter().enumerate() {
                let binder = match event.effect {
                    SemanticEffect::Assignment { target, value } if value == thrown => target,
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Local,
                        source,
                        target,
                    } if source == thrown => target,
                    _ => continue,
                };
                candidates.push((call, binder, point, index));
            }
        }
        let mut refuted = HashSet::new();
        if candidates.is_empty() {
            return Ok(refuted);
        }
        let crate::analyzer::LanguageDialect::Standard(language) =
            procedure.artifact().key().language()
        else {
            return Ok(refuted);
        };
        let Some(support) = crate::analyzer::languages::language_support(language) else {
            return Ok(refuted);
        };
        let Some((file, source)) =
            crate::analyzer::semantic::workspace_oracle::exact_source_for_procedure(
                self.workspace,
                procedure,
                request.budget.limits().source_bytes,
            )?
        else {
            return Ok(refuted);
        };
        let span = |mapping| {
            semantics.source_mapping(mapping).map(|mapping| {
                let span = mapping.locator.anchor().span();
                span.start_byte() as usize..span.end_byte() as usize
            })
        };
        let mut answers = HashMap::new();
        for (call, binder, point, index) in candidates {
            let refutes = *answers.entry((call.id, binder)).or_insert_with(|| {
                let Some(call_span) = span(call.source) else {
                    return false;
                };
                let Some(binder_span) =
                    semantics.value(binder).and_then(|value| span(value.source))
                else {
                    return false;
                };
                support.call_cannot_reach_catch_parameter(
                    self.workspace.analyzer(),
                    &file,
                    &source,
                    call_span,
                    binder_span,
                )
            });
            if refutes {
                refuted.insert((point, index));
            }
        }
        Ok(refuted)
    }

    /// Whether the producer's canonical index identity is backed by one exact
    /// base object in this activation.
    ///
    /// The marker proves only the selector. Before discharging its value-flow
    /// gap, independently require the existing heap oracle to close the base
    /// to one proven singleton allocation and require its local copy closure
    /// to contain no secondary binding owner. The local-allocation precheck
    /// keeps this query intra-procedural, so its points-to trace cannot re-enter
    /// `procedure_relations` through a call result. Parameter-backed slices,
    /// aggregate copies, joined bases, cyclic allocations, captures, and
    /// incomplete heap proofs all fail closed.
    #[allow(clippy::too_many_arguments)]
    fn canonical_index_identity_discharged(
        &self,
        procedure: &ProcedureHandle,
        context: &OracleCallContext,
        gap: &crate::analyzer::semantic::SemanticGap,
        bases: &LocalStoreBases,
        staged: &mut WorkStager,
        cancellation: &crate::cancellation::CancellationToken,
    ) -> Result<bool, StrongUpdateStop> {
        if !gap_certifies_canonical_index_identity(
            gap,
            procedure.semantics().points(),
            procedure.semantics().memory_locations(),
            procedure.semantics().values(),
        ) {
            return Ok(false);
        }
        let SemanticGapSubject::MemoryLocation(location) = gap.subject else {
            return Ok(false);
        };
        let Some(MemoryLocationKind::Index { base, .. }) = procedure
            .semantics()
            .memory_location(location)
            .map(|location| &location.kind)
        else {
            return Ok(false);
        };
        let modeled_read_partition = value_traces_to_modeled_read_partition(procedure, *base);
        if !modeled_read_partition
            && (!bases.is_locally_allocated(*base)
                || !bases.canonical_base_has_no_secondary_binding_owner(*base))
        {
            return Ok(false);
        }
        if bases.is_closed_local_array(*base) {
            return Ok(true);
        }
        let point = procedure.point_handle(gap.point).ok_or_else(|| {
            StrongUpdateStop::Provider(SemanticProviderError::internal(
                "canonical-index gap has a stale program point",
            ))
        })?;
        let base = value_handle(procedure, *base).map_err(StrongUpdateStop::Provider)?;
        let observation = crate::analyzer::semantic::ValueAtPoint::new(
            base,
            point,
            crate::analyzer::semantic::ObservationPhase::BeforeEffects,
            context.clone(),
        )
        .map_err(|error| {
            StrongUpdateStop::Provider(internal_contract(
                "invalid canonical-index base observation",
                error,
            ))
        })?;
        let outcome = {
            let mut request = staged.request(cancellation);
            self.pointees(&observation, &mut request)
                .map_err(StrongUpdateStop::Provider)?
        };
        staged.work = staged.work.conservative_add(outcome.work());
        match outcome {
            SemanticOutcome::Complete { value, .. } => {
                let objects = value.objects();
                let [candidate] = objects.candidates() else {
                    return Ok(false);
                };
                Ok(objects.coverage() == CandidateCoverage::Exhaustive
                    && candidate.is_proven_complete()
                    && candidate.value().cardinality() == ObjectCardinality::Singleton
                    && matches!(
                        candidate.value().identity(),
                        AbstractObjectIdentity::Allocation(_)
                    ))
            }
            SemanticOutcome::ExceededBudget { exceeded, .. } => Err(
                StrongUpdateStop::Interruption(Interruption::Budget(exceeded)),
            ),
            SemanticOutcome::Cancelled { .. } => {
                Err(StrongUpdateStop::Interruption(Interruption::Cancelled))
            }
            SemanticOutcome::Ambiguous { .. }
            | SemanticOutcome::Unknown { .. }
            | SemanticOutcome::Unsupported { .. }
            | SemanticOutcome::Unproven { .. } => Ok(false),
        }
    }

    fn external_constant_field_read_discharged(
        &self,
        gap: &crate::analyzer::semantic::SemanticGap,
        procedure: &ProcedureHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<bool, SemanticProviderError> {
        crate::analyzer::semantic::workspace_oracle::external_constant_field_read_discharges_gap(
            gap,
            procedure,
            self.workspace,
            request,
        )
    }

    fn inert_drop_glue_discharged(
        &self,
        gap: &crate::analyzer::semantic::SemanticGap,
        procedure: &ProcedureHandle,
        request: &mut SemanticRequest<'_>,
        inert: &mut Option<bool>,
    ) -> Result<bool, SemanticProviderError> {
        crate::analyzer::semantic::workspace_oracle::inert_drop_glue_discharges_gap(
            gap,
            procedure,
            self.workspace,
            request,
            inert,
        )
    }

    fn residual_conversion_discharged(
        &self,
        gap: &crate::analyzer::semantic::SemanticGap,
        procedure: &ProcedureHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<bool, SemanticProviderError> {
        crate::analyzer::semantic::workspace_oracle::residual_conversion_discharges_gap(
            gap,
            procedure,
            self.workspace,
            request,
        )
    }

    /// Whether the heap oracle certifies this store as a strong update.
    ///
    /// This is the first production consumer of `update_eligibility` (#2444).
    /// The query is demand-driven twice over: the caller only reaches it for a
    /// proven, complete `MemoryStore` whose resolved location is exact, and
    /// this method declines before asking whenever the store's base value is
    /// not locally allocated -- which covers both the shapes that cannot be
    /// certified and the shapes whose points-to trace would re-enter
    /// `procedure_relations`.
    ///
    /// The queried target is built from the store's own memory row, not from
    /// the relation's resolved access path. A certificate is bound to the IR
    /// address it overwrites, while the resolver deliberately rewrites a base
    /// value to the canonical origin it copies from -- `holder` at two
    /// statements resolves to the one allocation, which is what gives the two
    /// stores one carrier in the first place. The certificate covers that
    /// address, so it licenses replacing the facts at the carrier the resolver
    /// produced for it.
    ///
    /// Only a `Complete` outcome licenses the flag. A partial verdict from an
    /// exhausted budget or an open trace is exactly the case where the store
    /// may not have overwritten what a client would otherwise kill.
    #[allow(clippy::too_many_arguments)]
    fn store_holds_strong_update(
        &self,
        procedure: &ProcedureHandle,
        context: &OracleCallContext,
        point: &ProgramPointHandle,
        event_index: usize,
        location: MemoryLocationId,
        stored: ValueId,
        bases: &LocalStoreBases,
        binding_origins: Option<&BindingOriginIndex>,
        staged: &mut WorkStager,
        cancellation: &crate::cancellation::CancellationToken,
    ) -> Result<bool, StrongUpdateStop> {
        let row = procedure
            .semantics()
            .memory_location(location)
            .ok_or_else(|| {
                StrongUpdateStop::Provider(SemanticProviderError::internal(
                    "memory-store effect has a stale location",
                ))
            })?;
        let scoped = |member: &SemanticLocator| {
            ScopedSemanticLocator::new(Arc::clone(procedure.artifact()), member.clone())
                .map_err(|error| internal_contract("invalid store locator", error))
        };
        let (base, root, selectors) = match &row.kind {
            MemoryLocationKind::Property { base, key } => {
                if !bases.is_locally_allocated(*base) {
                    return Ok(false);
                }
                (
                    Some(*base),
                    AccessPathRoot::Value(
                        value_handle(procedure, *base).map_err(StrongUpdateStop::Provider)?,
                    ),
                    vec![AccessSelector::Property(key.clone())],
                )
            }
            MemoryLocationKind::Field { base, member } => {
                if !bases.is_locally_allocated(*base) {
                    return Ok(false);
                }
                (
                    Some(*base),
                    AccessPathRoot::Value(
                        value_handle(procedure, *base).map_err(StrongUpdateStop::Provider)?,
                    ),
                    vec![AccessSelector::Field(
                        scoped(member).map_err(StrongUpdateStop::Provider)?,
                    )],
                )
            }
            MemoryLocationKind::Index {
                base,
                index,
                constant_index,
                ..
            } => {
                // A subscript the analysis cannot pin names a summary cell, and
                // a summary cell can never be strongly updated (#2453).
                let Some(index) = index else {
                    return Ok(false);
                };
                if !bases.is_locally_allocated(*base) {
                    return Ok(false);
                }
                (
                    Some(*base),
                    AccessPathRoot::Value(
                        value_handle(procedure, *base).map_err(StrongUpdateStop::Provider)?,
                    ),
                    vec![AccessSelector::Index(match constant_index {
                        Some(index) => IndexSelector::Constant(*index),
                        None => IndexSelector::Exact(
                            value_handle(procedure, *index).map_err(StrongUpdateStop::Provider)?,
                        ),
                    })],
                )
            }
            MemoryLocationKind::Dereference { address } => {
                let Some(binding_origins) = binding_origins else {
                    return Ok(false);
                };
                let origins = binding_origins.addressed_binding_origins(*address);
                let Some(binding) = origins.unique_binding() else {
                    return Ok(false);
                };
                let Some(cell) = binding_origins.binding_memory_location(binding) else {
                    return Ok(false);
                };
                let handle = procedure.memory_location_handle(cell).ok_or_else(|| {
                    StrongUpdateStop::Provider(SemanticProviderError::internal(
                        "dereference binding origin is a stale lexical cell",
                    ))
                })?;
                (None, AccessPathRoot::LexicalCell(handle), Vec::new())
            }
            MemoryLocationKind::Static { member } => (
                None,
                AccessPathRoot::Static(scoped(member).map_err(StrongUpdateStop::Provider)?),
                Vec::new(),
            ),
            MemoryLocationKind::LexicalCell { .. } => {
                let handle = procedure.memory_location_handle(location).ok_or_else(|| {
                    StrongUpdateStop::Provider(SemanticProviderError::internal(
                        "lexical-cell store names a stale location",
                    ))
                })?;
                (None, AccessPathRoot::LexicalCell(handle), Vec::new())
            }
            MemoryLocationKind::Capture { .. } => {
                let port =
                    ProcedurePortHandle::capture(procedure.clone(), location).map_err(|error| {
                        StrongUpdateStop::Provider(internal_contract("invalid capture port", error))
                    })?;
                (None, AccessPathRoot::CaptureSlot(port), Vec::new())
            }
        };
        let Ok(path) = AccessPath::exact(root, selectors, *self.limits()) else {
            return Ok(false);
        };
        let Ok(store) =
            crate::analyzer::semantic::MemoryStoreHandle::new(point.clone(), event_index)
        else {
            return Ok(false);
        };
        let observe = |value: ValueId| {
            value_handle(procedure, value).and_then(|value| {
                crate::analyzer::semantic::ValueAtPoint::new(
                    value,
                    point.clone(),
                    crate::analyzer::semantic::ObservationPhase::BeforeEffects,
                    context.clone(),
                )
                .map_err(|error| internal_contract("invalid store observation", error))
            })
        };
        let stored = observe(stored).map_err(StrongUpdateStop::Provider)?;
        let base = base
            .map(observe)
            .transpose()
            .map_err(StrongUpdateStop::Provider)?;
        let Ok(target) = crate::analyzer::semantic::AccessPathAtPoint::new(
            path,
            point.clone(),
            crate::analyzer::semantic::ObservationPhase::BeforeEffects,
            context.clone(),
        ) else {
            return Ok(false);
        };
        let Ok(store) = crate::analyzer::semantic::StoreAtPoint::new(store, target, stored, base)
        else {
            return Ok(false);
        };
        let outcome = {
            let mut request = staged.request(cancellation);
            self.update_eligibility(&store, &mut request)
                .map_err(StrongUpdateStop::Provider)?
        };
        staged.work = staged.work.conservative_add(outcome.work());
        match outcome {
            SemanticOutcome::Complete {
                value: crate::analyzer::semantic::UpdateEligibility::Strong(_),
                ..
            } => Ok(true),
            // A shortfall is reported, not swallowed: the snapshot spent this
            // request's budget on the question and must say so.
            SemanticOutcome::ExceededBudget { exceeded, .. } => Err(
                StrongUpdateStop::Interruption(Interruption::Budget(exceeded)),
            ),
            SemanticOutcome::Cancelled { .. } => {
                Err(StrongUpdateStop::Interruption(Interruption::Cancelled))
            }
            _ => Ok(false),
        }
    }
}

impl WorkspaceSemanticOracle<'_> {
    /// The openness of one procedure, computed as the relation projection
    /// computes it, without projecting relations.
    pub fn procedure_openness(
        &self,
        procedure: &ProcedureHandle,
        context: &OracleCallContext,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<ProcedureOpenness>, SemanticProviderError> {
        if request.cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: SemanticWork::default(),
            });
        }
        let mut staged = WorkStager::new(request);
        let runtime_outcome =
            self.runtime_refinements(procedure, &mut staged.request(request.cancellation))?;
        staged.work = staged.work.conservative_add(runtime_outcome.work());
        let interrupted = match &runtime_outcome {
            SemanticOutcome::Cancelled { .. } => Some(Interruption::Cancelled),
            SemanticOutcome::ExceededBudget { exceeded, .. } => {
                Some(Interruption::Budget(*exceeded))
            }
            _ => None,
        };
        if let Some(stop) = interrupted {
            request.budget.retain_performed_work(&staged.budget);
            return Ok(interrupted_openness(stop, staged.work));
        }
        let sweep = sweep_procedure_gaps(
            self,
            procedure,
            context,
            OracleLimits::default(),
            runtime_outcome.available_value(),
            &mut staged,
            request,
        )?;
        if let Some(stop) = sweep.interrupted {
            request.budget.retain_performed_work(&staged.budget);
            return Ok(interrupted_openness(stop, staged.work));
        }
        if request.cancellation.is_cancelled() {
            request.budget.retain_performed_work(&staged.budget);
        } else {
            *request.budget = staged.budget;
        }
        Ok(SemanticOutcome::Complete {
            value: ProcedureOpenness {
                open: value_flow_capabilities_are_open(procedure) || sweep.open,
                relevant_gaps: sweep.relevant_gaps,
            },
            work: staged.work,
        })
    }
}

impl ValueFlowOracle for WorkspaceSemanticOracle<'_> {
    fn procedure_relations(
        &self,
        procedure: &ProcedureHandle,
        context: &OracleCallContext,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<ValueFlowSnapshot>, SemanticProviderError> {
        project_procedure_relations(self, procedure, context, *self.limits(), request)
    }

    fn call_bindings(
        &self,
        call: &crate::analyzer::semantic::CallSiteHandle,
        candidate: &DispatchCandidate,
        context: &OracleCallContext,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<CallBindings>, SemanticProviderError> {
        if request.cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: SemanticWork::default(),
            });
        }
        let mut staged = WorkStager::new(request);
        let initial_work = SemanticWork {
            procedures: 1,
            call_sites: 1,
            nested_entries: 1,
            ..SemanticWork::default()
        };
        if let Err(Interruption::Budget(exceeded)) = staged.admit(initial_work) {
            return Ok(SemanticOutcome::ExceededBudget {
                partial: None,
                exceeded,
                work: initial_work,
            });
        }
        let call_row = call
            .procedure()
            .semantics()
            .call_site(call.id())
            .ok_or_else(|| SemanticProviderError::internal("call-site handle is stale"))?
            .clone();
        let callee = candidate.target();
        let construction =
            constructor_call_result(call.procedure().semantics(), &call_row, callee.semantics());
        let construction_evidence = construction.and_then(|result| {
            call.procedure()
                .semantics()
                .allocations()
                .iter()
                .find(|allocation| allocation.result == result)
                .map(|allocation| allocation.evidence)
        });
        let mut interrupted = None;

        let native_incomplete_source_candidate =
            candidate.unique_incomplete_native_source_reason().is_some();
        debug_assert!(
            !native_incomplete_source_candidate
                || matches!(
                    call.procedure().artifact().key().language(),
                    crate::analyzer::semantic::SemanticLanguage::Standard(
                        crate::analyzer::Language::Java | crate::analyzer::Language::Go
                    )
                )
        );
        let unresolved_call_boundary =
            callee.semantics().properties().call_boundary == ProcedureCallBoundary::Unknown;
        if unresolved_call_boundary && !native_incomplete_source_candidate {
            // Candidate provenance remains attached to the result, while no
            // call-binding relation is minted for an authored boundary that
            // may not be the callable the caller observes.
            let bindings = materialize_call_bindings(
                call,
                candidate,
                context,
                BindingBuild::new(true),
                CandidateCoverage::Open,
                *self.limits(),
            )?;
            if request.cancellation.is_cancelled() {
                return Ok(SemanticOutcome::Cancelled {
                    partial: Some(bindings),
                    work: staged.work,
                });
            }
            *request.budget = staged.budget;
            return Ok(SemanticOutcome::Unknown {
                partial: Some(bindings),
                work: staged.work,
            });
        }

        let mut build =
            BindingBuild::new(unresolved_call_boundary || native_incomplete_source_candidate);
        let caller_abort_user_code = abort_paths_run_user_code(call.procedure().semantics());
        for gap in call.procedure().semantics().gaps() {
            if interrupted.is_some() {
                break;
            }
            if request.cancellation.is_cancelled() {
                interrupted = Some(Interruption::Cancelled);
                break;
            }
            staged.charge_work(SemanticWork {
                gaps: 1,
                ..SemanticWork::default()
            });
            let scoped_to_call = match gap.subject {
                SemanticGapSubject::Procedure => true,
                SemanticGapSubject::Point => gap.point == call_row.point,
                SemanticGapSubject::Value(value) => {
                    call_row.callee == value
                        || call_row.receiver == Some(value)
                        || call_row
                            .arguments
                            .iter()
                            .any(|argument| argument.value == value)
                        || call_row
                            .normal_result_values()
                            .any(|result| result == value)
                        || call_row.thrown == Some(value)
                }
                SemanticGapSubject::CallSite(call_site) => call_site == call.id(),
                SemanticGapSubject::CallContinuation { call_site, .. } => call_site == call.id(),
                SemanticGapSubject::MemoryLocation(_)
                | SemanticGapSubject::Capture(_)
                | SemanticGapSubject::AsyncContinuation { .. } => false,
            };
            let relevant = scoped_to_call
                && (gap.impacts.contains(SemanticGapImpact::CallEvaluation)
                    || gap.impacts.contains(SemanticGapImpact::ValueFlow))
                && call_target_refinement_call(call.procedure().semantics(), gap).is_none()
                && !implicit_abort_gap_is_discharged(gap, caller_abort_user_code);
            build.open |= relevant;
            if relevant {
                build.gap_quality = merge_gap_quality(build.gap_quality, gap);
            }
        }
        let runtime_outcome = self
            .runtime_refinements_for_procedure(callee, &mut staged.request(request.cancellation))?;
        staged.work = staged.work.conservative_add(runtime_outcome.work());
        match &runtime_outcome {
            SemanticOutcome::Cancelled { .. } => interrupted = Some(Interruption::Cancelled),
            SemanticOutcome::ExceededBudget { exceeded, .. } => {
                interrupted = Some(Interruption::Budget(*exceeded))
            }
            _ => {}
        }
        let runtime_reads = runtime_outcome.available_value();
        let callee_abort_user_code = abort_paths_run_user_code(callee.semantics());
        let mut callee_inert_drops = None;
        for gap in callee.semantics().gaps() {
            if interrupted.is_some() {
                break;
            }
            if request.cancellation.is_cancelled() {
                interrupted = Some(Interruption::Cancelled);
                break;
            }
            staged.charge_work(SemanticWork {
                gaps: 1,
                ..SemanticWork::default()
            });
            // Internal callee value-flow gaps belong to the callee snapshot,
            // not to the actual/formal binding partition. Only evaluation and
            // return-transfer gaps can weaken the binding itself.
            let relevant = (gap.impacts.contains(SemanticGapImpact::CallEvaluation)
                || gap.impacts.contains(SemanticGapImpact::ReturnTransfer))
                && !runtime_reads.is_some_and(|reads| reads.discharges(gap.id))
                && call_target_refinement_call(callee.semantics(), gap).is_none()
                && !implicit_abort_gap_is_discharged(gap, callee_abort_user_code)
                && {
                    let before = staged.budget.used();
                    let relevant = {
                        let mut nested = staged.request(request.cancellation);
                        !crate::analyzer::semantic::workspace_oracle::external_constant_field_read_discharges_gap(
                            gap,
                            callee,
                            self.workspace,
                            &mut nested,
                        )? && !crate::analyzer::semantic::workspace_oracle::inert_drop_glue_discharges_gap(
                            gap,
                            callee,
                            self.workspace,
                            &mut nested,
                            &mut callee_inert_drops,
                        )?
                    };
                    staged.work = staged
                        .work
                        .conservative_add(staged.budget.used().saturating_sub(before));
                    relevant
                };
            build.open |= relevant;
            if relevant {
                build.gap_quality = merge_gap_quality(build.gap_quality, gap);
            }
        }

        if let Some(interruption) = interrupted {
            return interrupted_call_bindings(
                call,
                candidate,
                context,
                build,
                interruption,
                staged.work,
                *self.limits(),
            );
        }

        staged.charge_work(SemanticWork {
            values: callee.semantics().values().len(),
            ..SemanticWork::default()
        });

        let call_evidence = evidence_handle(call.procedure(), call_row.evidence)?;
        let callee_evidence = evidence_handle(callee, callee.semantics().evidence())?;
        let default_arguments = callee
            .semantics()
            .values()
            .iter()
            .filter_map(|value| match &value.kind {
                SemanticValueKind::DefaultArgument { ordinal } => {
                    Some((*ordinal, value.id, value.evidence))
                }
                _ => None,
            })
            .map(|(ordinal, value, evidence)| (ordinal, (value, evidence)))
            .collect::<HashMap<_, _>>();
        let mut formals = callee
            .semantics()
            .values()
            .iter()
            .filter_map(|value| match &value.kind {
                SemanticValueKind::Parameter {
                    ordinal,
                    multiplicity,
                    name,
                    passing_mode,
                } => Some((
                    *ordinal,
                    multiplicity.clone(),
                    name.clone(),
                    *passing_mode,
                    value.evidence,
                )),
                _ => None,
            })
            .collect::<Vec<_>>();
        formals.sort_by_key(|(ordinal, _, _, _, _)| *ordinal);

        let caller_receiver_binding = call
            .procedure()
            .semantics()
            .proven_caller_receiver_binding(call.id());
        let mut receiver_needs_actual = call
            .source_receiver_argument_index(callee.semantics())
            .is_some();
        let receiver_formal = callee
            .semantics()
            .values()
            .iter()
            .find(|value| matches!(value.kind, SemanticValueKind::Receiver { .. }));
        let mut bound_formals = std::collections::HashSet::new();
        if interrupted.is_none()
            && !receiver_needs_actual
            && !native_incomplete_source_candidate
            && let Some(receiver_row) = receiver_formal
        {
            // A call that spells no receiver operand can still dispatch on
            // an implicit value or a type qualifier.
            //
            // The first is a constructor call: `new Type(...)` spells no
            // receiver syntax at all (there is no existing object to invoke
            // on), but the call's own `result` names the object it is about
            // to allocate, and that is exactly what the constructor's own
            // `this` binds to (#2574) -- true for any argument count, not
            // only the zero-argument case `allocation_call_is_dischargeable`
            // restricts itself to for its own, different question (whether
            // an *unresolved* dispatch still leaves the allocated identity
            // provable).
            //
            // The second is a bare call between members of one declaring
            // type, which runs on the caller's own `this`. Bind that
            // implicit actual only when the sibling identity is
            // structurally proven; otherwise the missing operand keeps the
            // binding honestly open.
            let (actual, extra_evidence) = match (call_row.receiver, caller_receiver_binding) {
                (Some(_), Some(CallerReceiverBinding::ModuleQualified(_))) => match construction {
                    Some(result) => (
                        Some(result),
                        construction_evidence
                            .map(|evidence| evidence_handle(call.procedure(), evidence))
                            .transpose()?,
                    ),
                    None => (None, None),
                },
                (Some(actual_id), _) => (Some(actual_id), None),
                (None, Some(CallerReceiverBinding::TypeQualified(qualifier)))
                    if callee.semantics().properties().receiver_binding
                        == ProcedureReceiverBinding::Class =>
                {
                    (Some(qualifier), None)
                }
                (None, _) => match construction {
                    Some(result) => (
                        Some(result),
                        construction_evidence
                            .map(|evidence| evidence_handle(call.procedure(), evidence))
                            .transpose()?,
                    ),
                    None => {
                        match implicit_dispatch_receiver_actual(
                            call.procedure(),
                            callee,
                            receiver_row,
                        ) {
                            Some(caller_receiver) => (
                                Some(caller_receiver.id),
                                Some(evidence_handle(call.procedure(), caller_receiver.evidence)?),
                            ),
                            None => (None, None),
                        }
                    }
                },
            };
            if request.cancellation.is_cancelled() {
                interrupted = Some(Interruption::Cancelled);
            } else if let Some(actual_id) = actual {
                let evidence = dedup_evidence(
                    [
                        call_evidence.clone(),
                        evidence_handle(callee, receiver_row.evidence)?,
                    ]
                    .into_iter()
                    .chain(extra_evidence),
                );
                if !proven_complete(&evidence) {
                    build.open = true;
                } else if build.can_retain(std::slice::from_ref(&evidence), 1, *self.limits()) {
                    if let Err(stop) = staged.admit(SemanticWork {
                        values: 2,
                        evidence: evidence.len(),
                        nested_entries: 1,
                        ..SemanticWork::default()
                    }) {
                        interrupted = Some(stop);
                    } else {
                        let relation = build.push_relation(evidence);
                        build.retained_entries += 1;
                        build.bindings.push(CallBindingDraft::Receiver {
                            relation,
                            actual: value_handle(call.procedure(), actual_id)?,
                            formal: ProcedurePortHandle::receiver(callee.clone()).map_err(
                                |error| internal_contract("invalid callee receiver port", error),
                            )?,
                        });
                    }
                } else {
                    build.truncated = true;
                }
            } else {
                build.open = true;
            }
        }

        let java_conversions = if !call_row.arguments.is_empty()
            && call.procedure().artifact().key().language()
                == crate::analyzer::semantic::SemanticLanguage::Standard(
                    crate::analyzer::Language::Java,
                ) {
            let outcome = self.java_call_conversions(
                call,
                candidate,
                &mut staged.request(request.cancellation),
            )?;
            staged.work = staged.work.conservative_add(outcome.work());
            match outcome {
                SemanticOutcome::ExceededBudget { exceeded, .. } => {
                    return interrupted_call_bindings(
                        call,
                        candidate,
                        context,
                        build,
                        Interruption::Budget(exceeded),
                        staged.work,
                        *self.limits(),
                    );
                }
                SemanticOutcome::Cancelled { .. } => {
                    return interrupted_call_bindings(
                        call,
                        candidate,
                        context,
                        build,
                        Interruption::Cancelled,
                        staged.work,
                        *self.limits(),
                    );
                }
                // Conversion uncertainty belongs to the conversion field; it
                // does not open actual-to-formal binding coverage.
                outcome => Some(outcome.available_value().cloned().unwrap_or_default()),
            }
        } else {
            None
        };

        let mut formal_cursor = 0usize;
        let mut positional_width_unknown = false;
        // A source that did not receive a retained mapping may still supply any
        // omitted formal (for example an unresolved spread, dynamic keyword,
        // duplicate, or invalid argument). Defaults are therefore withheld
        // for the whole candidate once one such source is encountered.
        let mut argument_binding_uncertain = false;
        for (source_index, argument) in call_row.arguments.iter().enumerate() {
            if interrupted.is_some() || build.truncated {
                break;
            }
            if request.cancellation.is_cancelled() {
                interrupted = Some(Interruption::Cancelled);
                break;
            }
            staged.charge_work(SemanticWork {
                values: 1,
                nested_entries: 1,
                ..SemanticWork::default()
            });
            let actual = value_handle(call.procedure(), argument.value)?;
            let explicit_receiver = receiver_needs_actual
                && !positional_width_unknown
                && matches!(
                    argument.expansion,
                    CallArgumentExpansion::Direct(
                        crate::analyzer::semantic::ArgumentDomain::Positional
                            | crate::analyzer::semantic::ArgumentDomain::PositionalOrKeyword
                    )
                );
            let selected = if explicit_receiver {
                receiver_needs_actual = false;
                let receiver = receiver_formal.expect("an unbound method has a receiver formal");
                Some((None, &receiver.evidence, false, CallArgumentMember::Whole))
            } else {
                (match &argument.expansion {
                CallArgumentExpansion::Direct(
                    crate::analyzer::semantic::ArgumentDomain::Positional
                    | crate::analyzer::semantic::ArgumentDomain::PositionalOrKeyword,
                ) if !positional_width_unknown => loop {
                    let Some((ordinal, multiplicity, _, passing_mode, evidence)) =
                        formals.get(formal_cursor)
                    else {
                        break None;
                    };
                    match multiplicity {
                        FormalMultiplicity::One => {
                            formal_cursor += 1;
                            if passing_mode.accepts_positional() && !bound_formals.contains(ordinal)
                            {
                                break Some((*ordinal, evidence, false, CallArgumentMember::Whole));
                            }
                        }
                        FormalMultiplicity::Rest(
                            crate::analyzer::semantic::ArgumentDomain::Positional
                            | crate::analyzer::semantic::ArgumentDomain::PositionalOrKeyword,
                        ) if passing_mode.accepts_positional() => {
                            break Some((*ordinal, evidence, true, CallArgumentMember::Whole));
                        }
                        FormalMultiplicity::Rest(_) => formal_cursor += 1,
                    }
                },
                CallArgumentExpansion::Direct(
                    crate::analyzer::semantic::ArgumentDomain::Keyword,
                ) => {
                    let named = argument.keyword.as_deref();
                    let duplicate = named.is_some_and(|actual| {
                        formals.iter().any(|(ordinal, multiplicity, name, _, _)| {
                            matches!(multiplicity, FormalMultiplicity::One)
                                && name.as_deref() == Some(actual)
                                && bound_formals.contains(ordinal)
                        })
                    });
                    if duplicate {
                        None
                    } else {
                        let exact = named.and_then(|actual| {
                            formals
                                .iter()
                                .find(|(ordinal, multiplicity, name, mode, _)| {
                                    matches!(multiplicity, FormalMultiplicity::One)
                                        && name.as_deref() == Some(actual)
                                        && mode.accepts_named()
                                        && !bound_formals.contains(ordinal)
                                })
                        });
                        let rest = || {
                            formals.iter().find(|(_, multiplicity, _, mode, _)| {
                                matches!(
                                    multiplicity,
                                    FormalMultiplicity::Rest(
                                        crate::analyzer::semantic::ArgumentDomain::Keyword
                                            | crate::analyzer::semantic::ArgumentDomain::PositionalOrKeyword
                                    )
                                ) && mode.accepts_named()
                            })
                        };
                        exact
                            .or_else(rest)
                            .map(|(ordinal, multiplicity, _, _, evidence)| {
                                let member = named.map_or(CallArgumentMember::Whole, |name| {
                                    CallArgumentMember::Keyword(name.into())
                                });
                                (
                                    *ordinal,
                                    evidence,
                                    matches!(multiplicity, FormalMultiplicity::Rest(_)),
                                    member,
                                )
                            })
                    }
                }
                CallArgumentExpansion::Direct(
                    crate::analyzer::semantic::ArgumentDomain::LanguageDefined(actual),
                ) => formals
                    .iter()
                    .find_map(
                        |(ordinal, multiplicity, _, _, evidence)| match multiplicity {
                            FormalMultiplicity::Rest(
                                crate::analyzer::semantic::ArgumentDomain::LanguageDefined(
                                    expected,
                                ),
                            ) if expected == actual => {
                                Some((*ordinal, evidence, true, CallArgumentMember::Whole))
                            }
                            FormalMultiplicity::One | FormalMultiplicity::Rest(_) => None,
                        },
                    ),
                CallArgumentExpansion::Spread(
                    crate::analyzer::semantic::ArgumentDomain::Positional
                    | crate::analyzer::semantic::ArgumentDomain::PositionalOrKeyword,
                ) => {
                    positional_width_unknown = true;
                    None
                }
                CallArgumentExpansion::Unclassified
                | CallArgumentExpansion::Spread(_)
                | CallArgumentExpansion::Direct(
                    crate::analyzer::semantic::ArgumentDomain::Positional
                    | crate::analyzer::semantic::ArgumentDomain::PositionalOrKeyword,
                ) => None,
            }).map(|(ordinal, evidence, rest, member)| (Some(ordinal), evidence, rest, member))
            };
            let closure_evidence = vec![call_evidence.clone()];
            let mut relation_evidence = vec![closure_evidence.clone()];
            let mapping = if let Some((ordinal, formal_evidence_id, rest, member)) = selected {
                let mapping_evidence = dedup_evidence([
                    call_evidence.clone(),
                    evidence_handle(callee, *formal_evidence_id)?,
                ]);
                relation_evidence.push(mapping_evidence.clone());
                let (proof, completeness) = if native_incomplete_source_candidate {
                    (candidate.proof().clone(), candidate.completeness().clone())
                } else {
                    evidence_quality(&mapping_evidence)
                };
                if !rest && let Some(ordinal) = ordinal {
                    bound_formals.insert(ordinal);
                }
                let formal = match ordinal {
                    Some(ordinal) => ProcedurePortHandle::parameter(callee.clone(), ordinal),
                    None => ProcedurePortHandle::receiver(callee.clone()),
                }
                .map_err(|error| internal_contract("invalid callee argument port", error))?;
                let mut mapping = CallArgumentMapping::new(
                    source_index as u32,
                    member,
                    CallArgumentEndpoint::Value(actual.clone()),
                    formal,
                    CallPassingMode::Value,
                );
                let mut completeness = completeness;
                if let Some(conversions) = &java_conversions {
                    use crate::analyzer::usages::call_conversion::ConversionUnknown;
                    let value = call
                        .procedure()
                        .semantics()
                        .value(actual.id())
                        .expect("live actual");
                    let source = call
                        .procedure()
                        .semantics()
                        .source_mapping(value.source)
                        .expect("actual source");
                    let span = source.locator.anchor().span();
                    let mut exact = conversions.iter().filter(|conversion| {
                        Some(conversion.formal as u32) == ordinal
                            && conversion.range.start_byte == span.start_byte() as usize
                            && conversion.range.end_byte == span.end_byte() as usize
                    });
                    let conversion = exact
                        .next()
                        .map(|conversion| {
                            if let Some(reason) = &conversion.incomplete_reason
                                && !native_incomplete_source_candidate
                            {
                                completeness = EvidenceCompleteness::Partial(reason.clone().into());
                                build.open = true;
                            } else if conversion.incomplete_reason.is_some() {
                                build.open = true;
                            }
                            conversion.transfer
                        })
                        .unwrap_or(Err(ConversionUnknown::UnresolvedSignature));
                    assert!(
                        exact.next().is_none(),
                        "one conversion for an exact actual/formal pair"
                    );
                    // Typing proves extraction of the primitive on normal
                    // completion, not that the wrapper is non-null.
                    if matches!(
                        conversion,
                        Ok(Some(ValueTransfer {
                            kind: crate::analyzer::semantic::TransferKind::Unboxing,
                            ..
                        }))
                    ) {
                        if !native_incomplete_source_candidate {
                            completeness = EvidenceCompleteness::Partial(
                                "unboxing may throw for a null wrapper".into(),
                            );
                        }
                        build.open = true;
                    }
                    mapping = mapping.with_conversion(conversion);
                }
                Some((mapping_evidence, mapping, proof, completeness))
            } else {
                build.open = true;
                argument_binding_uncertain = true;
                None
            };
            let group_coverage = if mapping.is_some()
                && proven_complete(&closure_evidence)
                && !native_incomplete_source_candidate
            {
                CandidateCoverage::Exhaustive
            } else {
                CandidateCoverage::Open
            };
            let entry_cost = 2 + usize::from(mapping.is_some());
            if !build.can_retain(&relation_evidence, entry_cost, *self.limits()) {
                build.truncated = true;
                break;
            }
            let relation_work = SemanticWork {
                evidence: relation_evidence.iter().map(Vec::len).sum(),
                nested_entries: relation_evidence.len(),
                ..SemanticWork::default()
            };
            if let Err(stop) = staged.admit(relation_work) {
                interrupted = Some(stop);
                break;
            }
            let closure_relation = build.push_relation(closure_evidence);
            let mapping = mapping.map(|(evidence, mapping, proof, completeness)| {
                let relation = build.push_relation(evidence);
                Box::new((relation, mapping, proof, completeness))
            });
            build.retained_entries += entry_cost;
            build.bindings.push(CallBindingDraft::ArgumentGroup {
                closure_relation,
                source: source_index as u32,
                mapping,
                coverage: group_coverage,
            });
        }

        if receiver_needs_actual {
            build.open = true;
            argument_binding_uncertain = true;
        }

        // A default is a saved callee-owned value, not a call expression to
        // execute. Select it only after all syntactic actuals have been
        // mapped: an open argument source could still supply this formal, and
        // an explicit mapping always wins. A source row with incomplete
        // evidence also keeps the candidate open rather than manufacturing a
        // proven implicit edge.
        if interrupted.is_none()
            && !build.truncated
            && !argument_binding_uncertain
            && !native_incomplete_source_candidate
        {
            let python_defaults = callee.artifact().key().language()
                == crate::analyzer::semantic::SemanticLanguage::Standard(
                    crate::analyzer::Language::Python,
                );
            for (ordinal, multiplicity, _, passing_mode, formal_evidence_id) in &formals {
                if !matches!(multiplicity, FormalMultiplicity::One)
                    || bound_formals.contains(ordinal)
                {
                    continue;
                }
                let Some((default_value_id, default_evidence_id)) =
                    default_arguments.get(ordinal).copied()
                else {
                    continue;
                };
                if python_defaults
                    && self.python_saved_default_is_available(callee, *passing_mode) != Some(true)
                {
                    // An unreadable scan or a possibly mutated default leaves
                    // this particular omitted formal unproven. Positional and
                    // keyword-only metadata are checked independently.
                    build.open = true;
                    continue;
                }
                if request.cancellation.is_cancelled() {
                    interrupted = Some(Interruption::Cancelled);
                    break;
                }
                let evidence = dedup_evidence([
                    call_evidence.clone(),
                    evidence_handle(callee, *formal_evidence_id)?,
                    evidence_handle(callee, default_evidence_id)?,
                ]);
                if !proven_complete(&evidence) {
                    build.open = true;
                    continue;
                }
                if !build.can_retain(std::slice::from_ref(&evidence), 1, *self.limits()) {
                    build.truncated = true;
                    break;
                }
                if let Err(stop) = staged.admit(SemanticWork {
                    values: 2,
                    evidence: evidence.len(),
                    nested_entries: 1,
                    ..SemanticWork::default()
                }) {
                    interrupted = Some(stop);
                    break;
                }
                let relation = build.push_relation(evidence);
                build.retained_entries += 1;
                bound_formals.insert(*ordinal);
                build.bindings.push(CallBindingDraft::ImplicitArgument {
                    relation,
                    formal_ordinal: *ordinal,
                    source: value_handle(callee, default_value_id)?,
                    formal: ProcedurePortHandle::parameter(callee.clone(), *ordinal).map_err(
                        |error| internal_contract("invalid callee default parameter port", error),
                    )?,
                    kind: ImplicitArgumentKind::Default,
                });
            }
        }

        // The selected native source candidate can retain a typed normal
        // return relation, but its candidate proof and binding coverage stay
        // incomplete. Exceptional returns still require a complete target.
        if interrupted.is_none() && !build.truncated {
            for (ordinal, result_id) in call_row.normal_results.iter().copied().enumerate() {
                if request.cancellation.is_cancelled() {
                    interrupted = Some(Interruption::Cancelled);
                    break;
                }
                if callee.semantics().properties().construction_return
                    == crate::analyzer::semantic::ConstructionReturn::PreservesAllocation
                    && construction == Some(result_id)
                {
                    continue;
                }
                let Ok(formal) =
                    ProcedurePortHandle::indexed_normal_return(callee.clone(), ordinal as u32)
                else {
                    build.open = true;
                    continue;
                };
                let evidence = dedup_evidence([call_evidence.clone(), callee_evidence.clone()]);
                if !proven_complete(&evidence) {
                    build.open = true;
                    continue;
                }
                if !build.can_retain(std::slice::from_ref(&evidence), 1, *self.limits()) {
                    build.truncated = true;
                    break;
                }
                if let Err(stop) = staged.admit(SemanticWork {
                    values: 1,
                    evidence: evidence.len(),
                    nested_entries: 1,
                    ..SemanticWork::default()
                }) {
                    interrupted = Some(stop);
                    break;
                }
                let relation = build.push_relation(evidence);
                build.retained_entries += 1;
                build.bindings.push(CallBindingDraft::NormalReturn {
                    relation,
                    formal,
                    result: value_handle(call.procedure(), result_id)?,
                });
            }
        }
        if interrupted.is_none() && !build.truncated {
            for (exceptional, result_id) in [(false, call_row.result), (true, call_row.thrown)] {
                if native_incomplete_source_candidate && exceptional {
                    continue;
                }
                let Some(result_id) = result_id else {
                    continue;
                };
                if request.cancellation.is_cancelled() {
                    interrupted = Some(Interruption::Cancelled);
                    break;
                }
                if !exceptional
                    && callee.semantics().properties().construction_return
                        == crate::analyzer::semantic::ConstructionReturn::PreservesAllocation
                    && construction == Some(result_id)
                {
                    // This expression returns the allocated receiver, not the
                    // initializer body's return value. Receiver/member effects
                    // still cross the call, as do exceptional results. A direct
                    // initializer call has no allocation result and keeps its
                    // ordinary return binding.
                    continue;
                }
                let evidence = dedup_evidence([call_evidence.clone(), callee_evidence.clone()]);
                if !proven_complete(&evidence) {
                    build.open = true;
                    continue;
                }
                if !build.can_retain(std::slice::from_ref(&evidence), 1, *self.limits()) {
                    build.truncated = true;
                    break;
                }
                if let Err(stop) = staged.admit(SemanticWork {
                    values: 1,
                    evidence: evidence.len(),
                    nested_entries: 1,
                    ..SemanticWork::default()
                }) {
                    interrupted = Some(stop);
                    break;
                }
                let relation = build.push_relation(evidence);
                build.retained_entries += 1;
                let result = value_handle(call.procedure(), result_id)?;
                if exceptional {
                    build.bindings.push(CallBindingDraft::ExceptionalReturn {
                        relation,
                        formal: ProcedurePortHandle::exceptional_return(callee.clone()),
                        result,
                    });
                } else {
                    build.bindings.push(CallBindingDraft::NormalReturn {
                        relation,
                        formal: ProcedurePortHandle::normal_return(callee.clone()),
                        result,
                    });
                }
            }
        }

        if formals.iter().any(|(ordinal, multiplicity, _, _, _)| {
            matches!(multiplicity, FormalMultiplicity::One) && !bound_formals.contains(ordinal)
        }) {
            build.open = true;
        }
        let coverage = if build.truncated {
            CandidateCoverage::Truncated
        } else if interrupted.is_some() || build.open {
            CandidateCoverage::Open
        } else {
            CandidateCoverage::Exhaustive
        };
        let has_unproven_relation = build.has_unproven_relation;
        let gap_quality = build.gap_quality;
        let quality = merge_relation_quality(gap_quality, has_unproven_relation);
        let bindings =
            materialize_call_bindings(call, candidate, context, build, coverage, *self.limits())?;
        if interrupted.is_none() && request.cancellation.is_cancelled() {
            interrupted = Some(Interruption::Cancelled);
        }
        *request.budget = staged.budget;
        Ok(match interrupted {
            Some(Interruption::Budget(exceeded)) => SemanticOutcome::ExceededBudget {
                partial: Some(bindings),
                exceeded,
                work: staged.work,
            },
            Some(Interruption::Cancelled) => SemanticOutcome::Cancelled {
                partial: Some(bindings),
                work: staged.work,
            },
            None if coverage == CandidateCoverage::Truncated => SemanticOutcome::Unproven {
                partial: bindings,
                work: staged.work,
            },
            None if matches!(quality, Some(GapOutcomeQuality::Unsupported(_))) => {
                let Some(GapOutcomeQuality::Unsupported(capability)) = quality else {
                    unreachable!("guard establishes unsupported gap quality")
                };
                SemanticOutcome::Unsupported {
                    capability,
                    partial: Some(bindings),
                    work: staged.work,
                }
            }
            None if matches!(quality, Some(GapOutcomeQuality::Unknown)) => {
                SemanticOutcome::Unknown {
                    partial: Some(bindings),
                    work: staged.work,
                }
            }
            None if matches!(quality, Some(GapOutcomeQuality::Unproven)) => {
                SemanticOutcome::Unproven {
                    partial: bindings,
                    work: staged.work,
                }
            }
            None if matches!(quality, Some(GapOutcomeQuality::Ambiguous)) => {
                SemanticOutcome::Ambiguous {
                    candidates: bindings,
                    work: staged.work,
                }
            }
            None if coverage == CandidateCoverage::Open => SemanticOutcome::Unknown {
                partial: Some(bindings),
                work: staged.work,
            },
            None => SemanticOutcome::Complete {
                value: bindings,
                work: staged.work,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::value_flow::AccessPathResolution;

    use brokk_bifrost_analysis::analyzer::semantic::oracle::model::AccessPathTail;

    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::value_flow::GapOutcomeQuality;

    use std::collections::HashMap;

    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::value_flow::LoadOrigin;

    use brokk_bifrost_analysis::analyzer::semantic::ids::MemoryLocationId;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::MemoryLocationKind;

    use brokk_bifrost_analysis::analyzer::semantic::capabilities::SemanticCapability;

    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticWork;

    use brokk_bifrost_analysis::analyzer::semantic::ids::ValueId;

    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::value_flow::ValueOriginFacts;

    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::value_flow::merge_relation_quality;

    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::value_flow::resolve_access_path;

    use crate::analyzer::semantic::workspace_oracle::value_flow::*;

    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon("#2835: unproven relation evidence masked stronger typed gap quality")]
    fn typed_gap_quality_dominates_unproven_relation_evidence() {
        assert_eq!(
            merge_relation_quality(
                Some(GapOutcomeQuality::Unsupported(SemanticCapability::Calls)),
                true,
            ),
            Some(GapOutcomeQuality::Unsupported(SemanticCapability::Calls))
        );
        assert_eq!(
            merge_relation_quality(Some(GapOutcomeQuality::Unknown), true),
            Some(GapOutcomeQuality::Unknown)
        );
    }

    #[test]
    #[hardwon("#2835: quality arbitration must retain the unproven relation floor")]
    fn unproven_relation_evidence_keeps_its_existing_quality_floor() {
        assert_eq!(
            merge_relation_quality(None, true),
            Some(GapOutcomeQuality::Unproven)
        );
        assert_eq!(
            merge_relation_quality(Some(GapOutcomeQuality::Ambiguous), true),
            Some(GapOutcomeQuality::Unproven)
        );
        assert_eq!(
            merge_relation_quality(Some(GapOutcomeQuality::Unproven), true),
            Some(GapOutcomeQuality::Unproven)
        );
        assert_eq!(merge_relation_quality(None, false), None);
    }

    #[test]
    #[hardwon("#1407: nested Java/TypeScript access-path cycles did not terminate safely")]
    fn cyclic_load_origins_terminate_with_summary() {
        let first_base = ValueId::new(0);
        let second_base = ValueId::new(1);
        let first_location = MemoryLocationId::new(0);
        let second_location = MemoryLocationId::new(1);
        let locations = [
            MemoryLocationKind::Index {
                base: first_base,
                index: None,
                constant_index: None,
                identity: crate::analyzer::semantic::IndexedLocationIdentity::Element,
            },
            MemoryLocationKind::Index {
                base: second_base,
                index: None,
                constant_index: None,
                identity: crate::analyzer::semantic::IndexedLocationIdentity::Element,
            },
        ];
        let load_origins = HashMap::from([
            (first_base, LoadOrigin::Unique(second_location)),
            (second_base, LoadOrigin::Unique(first_location)),
        ]);

        let draft = resolve_access_path(
            first_location,
            ValueOriginFacts {
                load_origins: &load_origins,
                copied_reference_members: &HashMap::default(),
                binding_origins: None,
            },
            8,
            &crate::CancellationToken::default(),
            |id| locations.get(id.index()),
            |_| None,
            |_| Ok(()),
        )
        .unwrap();
        let AccessPathResolution::Resolved(draft) = draft else {
            panic!("unbudgeted access-path resolution must complete")
        };

        assert!(matches!(draft.root, AccessPathRootDraft::Value(value) if value == second_base));
        assert_eq!(draft.selectors.len(), 2);
        assert_eq!(draft.tail, AccessPathTail::Summary);
    }

    #[test]
    #[hardwon("#1407: ambiguous nested loads must retain the access path as their summary")]
    fn ambiguous_load_origin_summarizes_access_path() {
        let base = ValueId::new(0);
        let locations = [MemoryLocationKind::Index {
            base,
            index: None,
            constant_index: None,
            identity: crate::analyzer::semantic::IndexedLocationIdentity::Element,
        }];
        let load_origins = HashMap::from([(base, LoadOrigin::Ambiguous)]);

        let draft = resolve_access_path(
            MemoryLocationId::new(0),
            ValueOriginFacts {
                load_origins: &load_origins,
                copied_reference_members: &HashMap::default(),
                binding_origins: None,
            },
            8,
            &crate::CancellationToken::default(),
            |id| locations.get(id.index()),
            |_| None,
            |_| Ok(()),
        )
        .unwrap();
        let AccessPathResolution::Resolved(draft) = draft else {
            panic!("unbudgeted access-path resolution must complete")
        };

        assert!(matches!(draft.root, AccessPathRootDraft::Value(value) if value == base));
        assert_eq!(draft.selectors.len(), 1);
        assert_eq!(draft.tail, AccessPathTail::Summary);
    }

    #[test]
    #[hardwon("#5113: visits to existing memory locations were charged against retained rows")]
    fn nested_access_path_work_never_spends_the_memory_location_grant() {
        let first_base = ValueId::new(0);
        let second_base = ValueId::new(1);
        let first_location = MemoryLocationId::new(0);
        let second_location = MemoryLocationId::new(1);
        let locations = [
            MemoryLocationKind::Index {
                base: first_base,
                index: None,
                constant_index: None,
                identity: crate::analyzer::semantic::IndexedLocationIdentity::Element,
            },
            MemoryLocationKind::Index {
                base: second_base,
                index: None,
                constant_index: None,
                identity: crate::analyzer::semantic::IndexedLocationIdentity::Element,
            },
        ];
        let load_origins = HashMap::from([(first_base, LoadOrigin::Unique(second_location))]);
        let mut limits = SemanticWork::default_limits();
        limits.memory_locations = 1;
        let mut budget = crate::analyzer::semantic::SemanticBudget::new(limits).unwrap();

        let resolution = resolve_access_path(
            first_location,
            ValueOriginFacts {
                load_origins: &load_origins,
                copied_reference_members: &HashMap::default(),
                binding_origins: None,
            },
            8,
            &crate::CancellationToken::default(),
            |id| locations.get(id.index()),
            |_| None,
            |work| {
                budget.charge_work(work);
                Ok(())
            },
        )
        .unwrap();

        assert!(matches!(resolution, AccessPathResolution::Resolved(_)));
        assert_eq!(budget.used().memory_locations, 2);
        assert_eq!(budget.root_work_peak().memory_locations, 2);
        assert_eq!(budget.resident().memory_locations, 0);
        assert!(budget.first_refusal().is_none());
    }
}
