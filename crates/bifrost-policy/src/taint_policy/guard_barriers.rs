//! Shared Match/Taint policy guard binding, without a second solver contract.
use super::*;
use crate::definition::{
    TaintGuardBarrierSpec, TaintGuardOperand, TaintGuardPredicate, TaintGuardRelation,
};
use brokk_bifrost_analysis::analyzer::semantic::partial_flow::guard_bindings::{
    CompiledGuardBinding, CompiledGuardBindings, GuardBindingCandidate, GuardBindingDecline,
    GuardBindingProof, GuardBindingReason, GuardInteriorMutability, GuardRemovals,
    GuardStorageExclusivity,
};
use brokk_bifrost_analysis::analyzer::semantic::{
    BarrierObservation, GuardFact, GuardPredicate, IntegerComparison, ReceiverMode,
    SemanticRequest, SemanticValueKind,
};

fn comparison_operands(
    guard: &GuardFact,
    definition: &TaintGuardBarrierSpec,
) -> Option<Vec<ValueId>> {
    let TaintGuardPredicate::Comparison(comparison) = &definition.predicate else {
        return None;
    };
    let equality = |negated: bool| {
        matches!(
            (comparison.relation, negated),
            (TaintGuardRelation::Equality, false) | (TaintGuardRelation::Inequality, true)
        )
    };
    let ordered = |left, right, relation| {
        if comparison.relation != TaintGuardRelation::Ordering {
            return None;
        }
        let left_lesser = matches!(
            relation,
            IntegerComparison::LessThan | IntegerComparison::LessThanOrEqual
        );
        let choose_left = match comparison.operand {
            TaintGuardOperand::Lesser => left_lesser,
            TaintGuardOperand::Greater => !left_lesser,
            TaintGuardOperand::Either => return None,
        };
        Some(vec![if choose_left { left } else { right }])
    };
    match guard.predicate {
        GuardPredicate::ValueEquality {
            left,
            right,
            negated,
        } if equality(negated) => Some(vec![left, right]),
        GuardPredicate::ConstantEquality { negated, .. } if equality(negated) => {
            guard.subject.map(|subject| vec![subject])
        }
        GuardPredicate::ValueOrdering {
            left,
            right,
            relation,
        } => ordered(left, right, relation),
        GuardPredicate::OrderedIntegerComparison { relation, .. }
            if comparison.relation == TaintGuardRelation::Ordering =>
        {
            let subject_lesser = matches!(
                relation,
                IntegerComparison::LessThan | IntegerComparison::LessThanOrEqual
            );
            (matches!(comparison.operand, TaintGuardOperand::Lesser) == subject_lesser)
                .then(|| guard.subject.map(|subject| vec![subject]))
                .flatten()
        }
        _ => None,
    }
}

/// A proof step that failed because the run was cancelled or its budget was
/// spent is operational, not a content-level decline.
fn operational_or(
    request: &brokk_bifrost_analysis::analyzer::semantic::SemanticRequest<'_>,
    content: GuardBindingReason,
) -> GuardBindingReason {
    if request.cancellation.is_cancelled() {
        GuardBindingReason::Cancelled
    } else if request.stop_observed() {
        GuardBindingReason::BudgetExceeded
    } else {
        content
    }
}

impl TaintPolicyCompiler<'_> {
    /// The exact call target must be statically selected. A name-only selector
    /// is nomination, including CodeQL's intentionally broad `contains` rule.
    fn guard_call_resolves(&mut self, call: &CallSiteHandle) -> Result<(), GuardBindingReason> {
        let oracle = WorkspaceSemanticOracle::with_dispatch_hints(
            self.selectors.workspace(),
            self.active_semantic_model_snapshot.clone(),
            DispatchHints::empty(),
        );
        let mut request = self.selectors.semantic_request();
        let dispatch = oracle
            .resolve_call(call, &mut request)
            .map_err(|_| operational_or(&request, GuardBindingReason::MissingCapability))?;
        if request.cancellation.is_cancelled() {
            return Err(GuardBindingReason::Cancelled);
        }
        if !dispatch.is_complete()
            || !dispatch.available_value().is_some_and(|dispatch| {
                dispatch.coverage() == CandidateCoverage::Exhaustive
                    && !dispatch.candidates().is_empty()
                    && dispatch.candidates().iter().all(|candidate| {
                        matches!(candidate.proof(), ProofStatus::Proven)
                            && candidate.completeness() == &EvidenceCompleteness::Complete
                    })
            })
        {
            return Err(operational_or(
                &request,
                GuardBindingReason::UnresolvedSelectedCall,
            ));
        }
        let conversion = oracle
            .call_conversion_may_run_user_code(call, &dispatch, &mut request)
            .map_err(|_| operational_or(&request, GuardBindingReason::MissingCapability))?;
        if conversion.available_value().copied() != Some(false) {
            return Err(GuardBindingReason::MissingCapability);
        }
        Ok(())
    }

    fn guard_call_requirements(
        &mut self,
        procedure: &ProcedureHandle,
        call: &brokk_bifrost_analysis::analyzer::semantic::SemanticCallSite,
        requires: &[crate::definition::TaintSanitizerRequirement],
        selected_results: &[Vec<CallSiteHandle>],
    ) -> Result<bool, GuardBindingReason> {
        for (index, requirement) in requires.iter().enumerate() {
            let operand = sanitizer_operand(call, &requirement.operand)
                .ok_or(GuardBindingReason::AmbiguousOperand)?;
            let mut request = self.selectors.semantic_request();
            let origin = sanitizer_requirement_origin(procedure, operand, call.point, &mut request)
                .map_err(|_| operational_or(&request, GuardBindingReason::AmbiguousDefinition))?;
            let kind = &procedure
                .semantics()
                .value(origin)
                .expect("proven requirement")
                .kind;
            let matched = match &requirement.condition {
                TaintSanitizerCondition::Constant => kind.is_constant(),
                TaintSanitizerCondition::Equals(literal) => {
                    sanitizer_constant_equals(kind, literal, procedure.artifact().key().language())
                        .map_err(|_| GuardBindingReason::MissingCapability)?
                }
                TaintSanitizerCondition::ResultOf(_) => {
                    selected_results[index].iter().any(|selected| {
                        selected.procedure().durable_key() == procedure.durable_key()
                            && procedure
                                .semantics()
                                .call_site(selected.id())
                                .is_some_and(|call| {
                                    call.normal_result_values().any(|value| value == origin)
                                })
                    })
                }
            };
            if !matched {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// One request-local procedure proof for both adapters. `observations`
    /// names the policy's before-effects reads; a final sink's invocation does
    /// not precede its own operand observation.
    pub(super) fn bind_guard_barriers_in(
        &mut self,
        definitions: &[crate::resolved::ResolvedTaintGuardBarrier],
        selectors: &HashMap<&PolicySelectorPath, &ResolvedPolicySelector>,
        procedure: &ProcedureHandle,
        observations: &[ProgramPointId],
    ) -> Result<CompiledGuardBindings, TaintPolicyCompileError> {
        let mut compiled = CompiledGuardBindings::default();
        // A guard needs a branch to hold on, so a procedure without guard facts
        // can neither carry a kill nor need a proof.
        if definitions.is_empty() || procedure.semantics().guard_facts().is_empty() {
            return Ok(compiled);
        }
        self.record_model_content_read();
        let proof = GuardBindingProof::new(procedure, &mut self.selectors.semantic_request());
        let proof = match proof {
            Ok(proof) => proof,
            Err(reason) => {
                compiled
                    .declines
                    .extend(definitions.iter().map(|guard| GuardBindingDecline {
                        id: guard.definition.id.as_str().into(),
                        procedure: procedure.clone(),
                        guard: None,
                        reason,
                    }));
                return Ok(compiled);
            }
        };
        let file = brokk_bifrost_analysis::analyzer::semantic::type_flow::file_for_locator(
            self.selectors.workspace(),
            procedure.semantics().locator(),
        );
        let files = self.selectors.workspace().analyzer().analyzed_files();
        let scope = file
            .as_ref()
            .map(|file| (file, files.as_slice(), procedure));
        let language = match procedure.artifact().key().language() {
            SemanticLanguage::Standard(language) => Some(language),
            _ => None,
        };
        let context = language
            .map(|language| {
                brokk_bifrost_analysis::analyzer::semantic::open_value_type_barrier_context(
                    language,
                    self.selectors.workspace().analyzer(),
                    self.selectors.cancellation(),
                )
            })
            .transpose()
            .map_err(|error| TaintPolicyCompileError::SemanticProvider(error.to_string()))?
            .flatten();
        for authored in definitions {
            let definition = &authored.definition;
            let mut candidates = Vec::new();
            match &definition.predicate {
                TaintGuardPredicate::Comparison(_) => {
                    for guard in procedure.semantics().guard_facts() {
                        if matches!(guard.predicate, GuardPredicate::Opaque { .. }) {
                            compiled.declines.push(GuardBindingDecline {
                                id: definition.id.as_str().into(),
                                procedure: procedure.clone(),
                                guard: Some(guard.id),
                                reason: GuardBindingReason::OpaqueGuard,
                            });
                        }
                        let Some(operands) = comparison_operands(guard, definition) else {
                            continue;
                        };
                        let admission = context
                            .as_deref()
                            .ok_or(GuardBindingReason::MissingCapability)
                            .and_then(|context| {
                                context.guard_comparison_semantics(
                                    procedure,
                                    guard,
                                    &mut self.selectors.semantic_request(),
                                )
                            });
                        if let Err(reason) = admission {
                            compiled.declines.push(GuardBindingDecline {
                                id: definition.id.as_str().into(),
                                procedure: procedure.clone(),
                                guard: Some(guard.id),
                                reason,
                            });
                            continue;
                        }
                        for operand in operands {
                            // A constant side carries no taint. Its absence of a
                            // binding is a definite nonmatch, not an open proof.
                            if procedure
                                .semantics()
                                .value(operand)
                                .is_some_and(|value| value.kind.is_constant())
                            {
                                continue;
                            }
                            candidates.push(GuardBindingCandidate {
                                guard: guard.id,
                                operand,
                                read_point: guard.point,
                                accepts: definition.clean_when,
                            });
                        }
                    }
                }
                TaintGuardPredicate::Call {
                    operand, requires, ..
                } => {
                    let mut selected_results = Vec::new();
                    for (index, requirement) in requires.iter().enumerate() {
                        let mut calls = Vec::new();
                        if matches!(requirement.condition, TaintSanitizerCondition::ResultOf(_)) {
                            let path = crate::definition::sanitizer_requirement_selector_path(
                                authored.selector_path.as_str(),
                                index,
                            );
                            let selector = selectors
                                .iter()
                                .find(|(key, _)| key.as_str() == path)
                                .map(|(_, selector)| *selector)
                                .ok_or_else(|| {
                                    TaintPolicyCompileError::SemanticUnavailable(format!(
                                        "missing guard requirement selector {path}"
                                    ))
                                })?;
                            for selected in self.select_conditional(selector, scope)? {
                                match self.selected_semantic_calls(&selected)? {
                                    SelectedCallSites::One(sites) => {
                                        calls.extend(sites.into_iter().map(|(_, call)| call));
                                    }
                                    SelectedCallSites::Ambiguous { procedures, .. } => {
                                        if procedures.contains(&procedure.durable_key()) {
                                            compiled.declines.push(GuardBindingDecline {
                                                id: definition.id.as_str().into(),
                                                procedure: procedure.clone(),
                                                guard: None,
                                                reason: GuardBindingReason::UnresolvedSelectedCall,
                                            });
                                        }
                                    }
                                    SelectedCallSites::Missing => {}
                                }
                            }
                        }
                        selected_results.push(calls);
                    }
                    let selector = required_selector(selectors, &authored.selector_path)?;
                    for selected in self.select_conditional(selector, scope)? {
                        let sites = match self.selected_semantic_calls(&selected)? {
                            SelectedCallSites::One(sites) => sites,
                            SelectedCallSites::Ambiguous { procedures, .. } => {
                                if procedures.contains(&procedure.durable_key()) {
                                    compiled.declines.push(GuardBindingDecline {
                                        id: definition.id.as_str().into(),
                                        procedure: procedure.clone(),
                                        guard: None,
                                        reason: GuardBindingReason::UnresolvedSelectedCall,
                                    });
                                }
                                continue;
                            }
                            SelectedCallSites::Missing => continue,
                        };
                        for (owner, handle) in sites {
                            if owner.durable_key() != procedure.durable_key() {
                                continue;
                            }
                            let call = procedure
                                .semantics()
                                .call_site(handle.id())
                                .expect("selected guard call");
                            let admission = self.guard_call_resolves(&handle).and_then(|()| {
                                self.guard_call_requirements(
                                    procedure,
                                    call,
                                    requires,
                                    &selected_results,
                                )
                            });
                            if let Err(reason) = admission {
                                compiled.declines.push(GuardBindingDecline {
                                    id: definition.id.as_str().into(),
                                    procedure: procedure.clone(),
                                    guard: None,
                                    reason,
                                });
                                continue;
                            }
                            if admission == Ok(false) {
                                continue;
                            }
                            let Some(operand) = sanitizer_operand(call, operand) else {
                                compiled.declines.push(GuardBindingDecline {
                                    id: definition.id.as_str().into(),
                                    procedure: procedure.clone(),
                                    guard: None,
                                    reason: GuardBindingReason::AmbiguousOperand,
                                });
                                continue;
                            };
                            for guard in procedure.semantics().guard_facts() {
                                let Some(subject) = guard.subject else {
                                    continue;
                                };
                                let matches_result = call
                                    .normal_result_values()
                                    .map(|result| {
                                        proof.tests_call_result(
                                            subject,
                                            guard.point,
                                            result,
                                            &mut self.selectors.semantic_request(),
                                        )
                                    })
                                    .collect::<Result<Vec<_>, _>>();
                                match matches_result {
                                    Err(reason) => compiled.declines.push(GuardBindingDecline {
                                        id: definition.id.as_str().into(),
                                        procedure: procedure.clone(),
                                        guard: Some(guard.id),
                                        reason,
                                    }),
                                    Ok(matches)
                                        if matches.iter().filter(|matched| **matched).count()
                                            == 1 =>
                                    {
                                        if matches!(guard.predicate, GuardPredicate::Truthy { .. })
                                        {
                                            candidates.push(GuardBindingCandidate {
                                                guard: guard.id,
                                                operand,
                                                // Invocation admission anchor; the shared proof
                                                // recovers the operand's exact evaluation event.
                                                read_point: call.point,
                                                accepts: definition.clean_when,
                                            });
                                        } else {
                                            compiled.declines.push(GuardBindingDecline {
                                                id: definition.id.as_str().into(),
                                                procedure: procedure.clone(),
                                                guard: Some(guard.id),
                                                reason: GuardBindingReason::OpaqueGuard,
                                            });
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
            for candidate in candidates {
                let oracle = WorkspaceSemanticOracle::with_dispatch_hints(
                    self.selectors.workspace(),
                    self.active_semantic_model_snapshot.clone(),
                    DispatchHints::empty(),
                );
                let mut request = self.selectors.semantic_request();
                let origins = proof.origins();
                let answer = proof.prove(candidate, observations, &mut request,
                    |binding, request| {
                        let Some(context) = context.as_deref() else { return Ok(GuardInteriorMutability::Unknown) };
                        let observation = BarrierObservation::new(procedure.point_handle(candidate.read_point).expect("candidate read point"), binding, ObservationPhase::BeforeEffects);
                        match context.guard_storage_exclusivity(&observation, request) {
                            GuardStorageExclusivity::Exclusive => {},
                            GuardStorageExclusivity::NotExclusive => return Err(operational_or(request, GuardBindingReason::StorageNotExclusive)),
                            GuardStorageExclusivity::Unknown => return Err(operational_or(request, GuardBindingReason::StorageExclusivityUnknown)),
                        }
                        Ok(context.guard_interior_mutability(&observation, request))
                    },
                    |call, binding, request| {
                        let call = procedure.call_site_handle(call).expect("slice call");
                        let dispatch = oracle.resolve_call(&call, request).map_err(|_| operational_or(request, GuardBindingReason::MissingCapability))?;
                        let Some(targets) = dispatch.available_value().filter(|_| dispatch.is_complete()) else { return Err(operational_or(request, GuardBindingReason::UnresolvedSelectedCall)) };
                        if targets.coverage() != CandidateCoverage::Exhaustive || targets.candidates().is_empty() { return Err(GuardBindingReason::UnresolvedSelectedCall); }
                        let site = procedure.semantics().call_site(call.id()).expect("slice call");
                        let shared_payload = |actual, request: &mut SemanticRequest<'_>| {
                            let Some(context) = context.as_deref() else { return Err(GuardBindingReason::InteriorMutabilityUnknown); };
                            match context.guard_interior_mutability(&BarrierObservation::new(
                                procedure.point_handle(site.point).expect("related shared use point"),
                                actual, ObservationPhase::BeforeEffects), request) {
                                GuardInteriorMutability::Absent => Ok(()),
                                GuardInteriorMutability::Present => Err(operational_or(request, GuardBindingReason::InteriorMutabilityPresent)),
                                GuardInteriorMutability::Unknown => Err(operational_or(request, GuardBindingReason::InteriorMutabilityUnknown)),
                            }
                        };
                        // Explicit argument borrows have the adapter's actual
                        // identity. An implicit receiver additionally requires
                        // every statically selected callee to take shared self.
                        if let Some(receiver) = site.receiver.filter(|value| origins.unique_binding_origin(*value) == Some(binding)) {
                            if !targets.candidates().iter().all(|target| target.target().semantics().values().iter().any(|value| matches!(value.kind, SemanticValueKind::Receiver { mode: ReceiverMode::SharedBorrow, .. }))) {
                                return Err(GuardBindingReason::MutableBorrow);
                            }
                            // A related receiver can wrap the original binding
                            // in a raw capability before the guard. Certify its
                            // actual payload as well as its selected self mode.
                            shared_payload(receiver, request)?;
                        }
                        // A non-Address actual may already be a mutable reference.
                        // Its selected formal must prove the access capability too.
                        let positional = site.arguments.iter().all(|argument| matches!(argument.expansion,
                            brokk_bifrost_analysis::analyzer::semantic::CallArgumentExpansion::Direct(
                                brokk_bifrost_analysis::analyzer::semantic::ArgumentDomain::Positional
                                | brokk_bifrost_analysis::analyzer::semantic::ArgumentDomain::PositionalOrKeyword)));
                        for (index, argument) in site.arguments.iter().enumerate() {
                            if origins.unique_binding_origin(argument.value) != Some(binding) {
                                continue;
                            }
                            let Some(value) = procedure.semantics().value(argument.value) else { return Err(GuardBindingReason::UnknownBorrow) };
                            if value.kind != SemanticValueKind::Address {
                                if !positional { return Err(GuardBindingReason::UnknownBorrow); }
                                let Some(context) = context.as_deref() else { return Err(GuardBindingReason::UnknownBorrow); };
                                for target in targets.candidates() {
                                    let callee = target.target();
                                    if request.cancellation.is_cancelled() { return Err(GuardBindingReason::Cancelled); }
                                    if !request.charge_execution_traversal(callee.semantics().values().len()) { return Err(GuardBindingReason::BudgetExceeded); }
                                    let formal = callee.semantics().values().iter().find(|value| matches!(value.kind,
                                        SemanticValueKind::Parameter { ordinal, .. } if ordinal as usize == index))
                                        .ok_or(GuardBindingReason::UnknownBorrow)?;
                                    context.guard_argument_nonmutating(&BarrierObservation::new(
                                        callee.point_handle(callee.semantics().entry_point()).expect("selected callee entry"),
                                        formal.id, ObservationPhase::BeforeEffects), request)
                                        .map_err(|reason| operational_or(request, reason))?;
                                }
                                continue;
                            }
                            match value.actual_borrow {
                                brokk_bifrost_analysis::analyzer::semantic::ActualBorrowKind::Shared => shared_payload(argument.value, request)?,
                                brokk_bifrost_analysis::analyzer::semantic::ActualBorrowKind::Mutable => return Err(GuardBindingReason::MutableBorrow),
                                brokk_bifrost_analysis::analyzer::semantic::ActualBorrowKind::Raw => return Err(GuardBindingReason::RawAlias),
                                brokk_bifrost_analysis::analyzer::semantic::ActualBorrowKind::Unknown => return Err(GuardBindingReason::UnknownBorrow),
                            }
                        }
                        Ok(())
                    });
                match answer {
                    Ok(binding) => compiled.bindings.push(CompiledGuardBinding {
                        id: definition.id.as_str().into(),
                        removes: GuardRemovals::TaintLabels(
                            definition
                                .removes
                                .iter()
                                .map(|label| Box::<str>::from(label.as_str()))
                                .collect(),
                        ),
                        binding,
                    }),
                    Err(reason) => compiled.declines.push(GuardBindingDecline {
                        id: definition.id.as_str().into(),
                        procedure: procedure.clone(),
                        guard: Some(candidate.guard),
                        reason,
                    }),
                }
            }
        }
        Ok(compiled)
    }

    pub(super) fn record_guard_declines(&mut self, guards: &CompiledGuardBindings) {
        for decline in &guards.declines {
            let path = PolicySelectorPath::new(format!("/analysis/guard_barriers/{}", decline.id))
                .expect("authored guard path");
            let incompleteness = match decline.reason {
                GuardBindingReason::Cancelled => brokk_bifrost_rql::Incompleteness::Operational(
                    brokk_bifrost_rql::DiagnosticExecutionCause::Cancelled,
                ),
                GuardBindingReason::BudgetExceeded => {
                    brokk_bifrost_rql::Incompleteness::Operational(
                        brokk_bifrost_rql::DiagnosticExecutionCause::Budget,
                    )
                }
                GuardBindingReason::GuardSelectorOperational(cause) => {
                    brokk_bifrost_rql::Incompleteness::Operational(cause)
                }
                GuardBindingReason::GuardSelectorResultCap => {
                    brokk_bifrost_rql::Incompleteness::ConfiguredCap
                }
                _ => brokk_bifrost_rql::Incompleteness::Content,
            };
            self.selectors
                .extend_incomplete_taint_selectors(vec![IncompleteTaintSelector {
                    path,
                    message: format!("guard `{}` is undecided: {:?}", decline.id, decline.reason),
                    discovery: Vec::new(),
                    refusal_subjects: Vec::new(),
                    has_non_utf8_refusal: false,
                    refusal_reason: String::new(),
                    truncated: false,
                    incompleteness: vec![incompleteness],
                }]);
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn bind_match_guard_barriers_in(
    workspace: &WorkspaceAnalyzer,
    flow_state: &brokk_bifrost_rql::SemanticFlowResources,
    query_limits: CodeQueryExecutionLimits,
    max_selector_results: usize,
    cancellation: &CancellationToken,
    match_guards: &[crate::resolved::ResolvedMatchGuardBarrier],
    resolved_selectors: &[ResolvedPolicySelector],
    procedure: &ProcedureHandle,
) -> Result<CompiledGuardBindings, String> {
    let active_guards = match_guards
        .iter()
        .filter(|guard| !guard.tokens.is_empty())
        .collect::<Vec<_>>();
    if active_guards.is_empty() {
        return Ok(CompiledGuardBindings::default());
    }
    let definitions = active_guards
        .iter()
        .map(|guard| guard.definition.clone())
        .collect::<Vec<_>>();
    let selectors = resolved_selectors
        .iter()
        .map(|selector| (&selector.path, selector))
        .collect::<HashMap<_, _>>();
    let mut compiler = TaintPolicyCompiler::new(
        workspace,
        flow_state.clone(),
        None,
        query_limits,
        max_selector_results,
        cancellation,
    )
    .with_active_semantic_model_snapshot(workspace.analyzer().active_semantic_model_snapshot());
    let mut compiled = compiler
        .bind_guard_barriers_in(&definitions, &selectors, procedure, &[])
        .map_err(|error| error.to_string())?;
    // This compiler is request-local and is discarded below. Preserve its
    // selector gaps rather than turning partial selection into complete empty.
    for gap in compiler.selectors.take_incomplete_taint_selectors() {
        let reasons = if gap.incompleteness.is_empty() {
            vec![GuardBindingReason::IncompleteGuardSelector]
        } else {
            gap.incompleteness
                .iter()
                .map(|cause| match cause {
                    brokk_bifrost_rql::Incompleteness::Content => {
                        GuardBindingReason::IncompleteGuardSelector
                    }
                    brokk_bifrost_rql::Incompleteness::ConfiguredCap => {
                        GuardBindingReason::GuardSelectorResultCap
                    }
                    brokk_bifrost_rql::Incompleteness::Operational(cause) => {
                        GuardBindingReason::GuardSelectorOperational(*cause)
                    }
                })
                .collect()
        };
        for authored in &definitions {
            let root = authored
                .selector_path
                .as_str()
                .split("/predicate/")
                .next()
                .unwrap_or(authored.selector_path.as_str());
            if gap.path.as_str().starts_with(&format!("{root}/")) {
                for &reason in &reasons {
                    compiled.declines.push(GuardBindingDecline {
                        id: authored.definition.id.as_str().into(),
                        procedure: procedure.clone(),
                        guard: None,
                        reason,
                    });
                }
            }
        }
    }
    for binding in &mut compiled.bindings {
        if let Some(matched) = active_guards
            .iter()
            .find(|guard| guard.definition.definition.id.as_str() == binding.id.as_ref())
        {
            binding.removes = GuardRemovals::ProducerKinds(matched.tokens.clone());
        }
    }
    Ok(compiled)
}

pub(super) fn edge_kills(
    guards: &CompiledGuardBindings,
    sources: brokk_bifrost_flow::value_flow::ValueFlowSourceListId,
    universe: &TaintUniverse,
) -> Result<Vec<ValueFlowEdgeKillSpec>, TaintPolicyCompileError> {
    guards
        .bindings
        .iter()
        .map(|guard| {
            let labels = guard
                .removes
                .taint_labels()
                .iter()
                .map(|label| {
                    SourceClassId::new(label.as_ref())
                        .map_err(|error| TaintPolicyCompileError::Model(error.to_string()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(ValueFlowEdgeKillSpec {
                point: guard
                    .binding
                    .procedure
                    .point_handle(guard.binding.kill.point)
                    .expect("proven guard point"),
                target: guard.binding.kill.target_point,
                kind: guard.binding.kill.kind,
                carrier: ValueFlowCarrier::from(guard.binding.kill.carrier.clone()),
                sources,
                labels: Some(
                    universe
                        .class_set(labels.iter())
                        .map_err(|error| TaintPolicyCompileError::Model(error.to_string()))?,
                ),
            })
        })
        .collect()
}
