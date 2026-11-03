//! Declared effects as facts on the shared execution relation.

use std::cell::RefCell;
use std::convert::Infallible;

use brokk_bifrost_flow::taint::compose::{
    self, BoundSource, CallModel, Callers, Completeness as InventoryCompleteness, ComposeLabels,
    CompositionBudget, CompositionProvider, Dispatch, ExecutionArm, ExecutionArmContext,
    ExecutionDispatch, ExecutionDispatchOutcome, ExecutionEndpointStatus, ExecutionEndpoints,
    ExecutionSource, ExecutionTarget, ExternalTargetIdentity, FallbackPorts, Hop, HopQuality,
    InteriorFlows, InteriorObservation, InteriorSeed, InvocationSite, Invocations, Openness,
    ProcedureEndpoints,
};
use brokk_bifrost_flow::value_flow::{AuthoredArmClosure, DurableCallSiteKey, DurableProcedureKey};

use super::*;
use crate::analyzer::ReadKey;
use crate::analyzer::semantic::partial_flow::ProcedurePartialFlows;
use crate::analyzer::semantic::{
    CandidateCoverage, DispatchBoundaryKind, ExecutionTiming, ProcedureHandle, SemanticBudget,
    SemanticGapKind, SemanticOutcome, SemanticRequest, StructuralNodeIdentity,
};
use crate::analyzer::usages::effects::{
    ProcedureEffectAttribution, project_procedure_effect_report,
};

/// A timing value names its semantic transform, not the path that formed it.
/// In particular, repeating a same-invocation edge is the same function.
#[derive(Debug, Clone, Copy)]
struct EffectLabels;

impl ComposeLabels for EffectLabels {
    type Fact = BoundDeclaredEffect;
    type Function = ExecutionTiming;

    fn identity(&self) -> ExecutionTiming {
        ExecutionTiming::SameEvaluation
    }

    fn then(&self, inner: &ExecutionTiming, outer: &ExecutionTiming) -> ExecutionTiming {
        outer.compose(*inner)
    }

    fn apply(&self, function: &ExecutionTiming, fact: &BoundDeclaredEffect) -> BoundDeclaredEffect {
        let mut effect = fact.clone();
        effect.execution_timing = function.compose(effect.execution_timing);
        effect
    }

    fn intersects(&self, left: &BoundDeclaredEffect, right: &BoundDeclaredEffect) -> bool {
        left.effect_id == right.effect_id
    }
}

#[derive(Clone)]
struct ProcedureInput {
    file: ProjectFile,
    unit: Option<CodeUnit>,
    name: String,
    declaration_only: bool,
}

#[derive(Clone)]
struct CallInput {
    file: ProjectFile,
    range: Range,
    ast: Option<StructuralNodeIdentity>,
}

struct CallAnswer {
    dispatch: ExecutionDispatch<ExecutionTiming>,
    effects: Vec<CallEffectArm>,
    external: Vec<Option<ExternalEffectCallee>>,
    closed: Vec<bool>,
    certainty: EffectCertainty,
    proven_non_callable: bool,
}

/// Created inside one root's consuming capture and dropped with that root.
/// These inventories and projections never cross a query or policy unit.
/// Shared prepared-dispatch hits use the oracle's existing captured reads.
struct ExecutionInputs<'query, 'workspace> {
    analyzer: &'workspace dyn IAnalyzer,
    semantic: &'query mut SemanticQueryContext<'workspace>,
    cache: &'query mut EffectTraversalCache,
    diagnostics: &'query mut Vec<CodeQueryDiagnostic>,
    procedures: HashMap<DurableProcedureKey, ProcedureInput>,
    calls: HashMap<DurableCallSiteKey, CallInput>,
    answers: HashMap<DurableCallSiteKey, CallAnswer>,
    coverage: EffectCoverage,
    reason: Option<EffectReason>,
}

impl ExecutionInputs<'_, '_> {
    fn incomplete(&mut self, reason: EffectReason, coverage: EffectCoverage) {
        self.coverage = self.coverage.meet(coverage);
        self.reason.get_or_insert(reason);
    }

    fn procedure(&mut self, key: &DurableProcedureKey) -> Option<ProcedureHandle> {
        // An empty inventory is still derived from this entire artifact.
        self.analyzer
            .record_read(ReadKey::semantic_artifact(&key.0));
        let file = self.procedures.get(key)?.file.clone();
        let outcome = self.semantic.materialized_outcome(&file)?;
        // Gaps inside validated IR have an owned procedure and point. A
        // partial artifact outcome is the remaining unattributed uncertainty;
        // never hide it by selecting one available procedure from that value.
        match &outcome {
            SemanticOutcome::ExceededBudget { .. } => self.incomplete(
                EffectReason::ProcedureBudgetExhausted,
                EffectCoverage::Truncated,
            ),
            SemanticOutcome::Cancelled { .. } => {
                self.incomplete(EffectReason::DispatchInterrupted, EffectCoverage::Open)
            }
            SemanticOutcome::Unknown { .. }
            | SemanticOutcome::Unproven { .. }
            | SemanticOutcome::Ambiguous { .. }
            | SemanticOutcome::Unsupported {
                capability: SemanticCapability::Calls | SemanticCapability::Procedures,
                ..
            } => self.incomplete(EffectReason::ProcedureUnreadable, EffectCoverage::Open),
            _ => {}
        }
        let artifact = outcome.available_value()?;
        if artifact.key() != &key.0 {
            self.incomplete(EffectReason::ProcedureUnreadable, EffectCoverage::Open);
            return None;
        }
        let handle = artifact.procedure_handle(key.1)?;
        if let Some(input) = self.procedures.get_mut(key)
            && input.unit.is_none()
        {
            input.name = super::super::type_flow::procedure_name(&handle);
        }
        Some(handle)
    }

    fn register_procedure(&mut self, key: DurableProcedureKey, unit: Option<CodeUnit>) {
        self.procedures.entry(key.clone()).or_insert_with(|| {
            let file = unit.as_ref().map_or_else(
                || {
                    ProjectFile::new(
                        self.analyzer.project().root().to_path_buf(),
                        key.0.path().as_path(),
                    )
                },
                |unit| unit.source().clone(),
            );
            ProcedureInput {
                name: unit
                    .as_ref()
                    .map_or_else(|| format!("{:?}", key.1), CodeUnit::fq_name),
                declaration_only: unit.as_ref().is_some_and(|unit| {
                    SignatureMetadata::unit_is_declaration_only(
                        &self.analyzer.signature_metadata(unit),
                    )
                }),
                file,
                unit,
            }
        });
    }

    fn invocations(&mut self, key: &DurableProcedureKey) -> Invocations {
        self.semantic.effect_work.propagation_node_visits = self
            .semantic
            .effect_work
            .propagation_node_visits
            .saturating_add(1);
        let Some(procedure) = self.procedure(key) else {
            self.incomplete(EffectReason::ProcedureUnreadable, EffectCoverage::Open);
            return Invocations {
                sites: Vec::new(),
                coverage: InventoryCompleteness::Incomplete {
                    reason: "procedure artifact is unavailable".into(),
                },
            };
        };
        let input = self.procedures[key].clone();
        let semantics = procedure.semantics();
        if !self.semantic.charge_consumer_traversal(
            &input.file,
            semantics
                .call_sites()
                .len()
                .saturating_add(semantics.gaps().len()),
            "declared-effect invocation inventory",
        ) {
            self.incomplete(EffectReason::DispatchInterrupted, EffectCoverage::Open);
            return Invocations {
                sites: Vec::new(),
                coverage: InventoryCompleteness::Incomplete {
                    reason: "invocation inventory interrupted".into(),
                },
            };
        }
        let mut sites = Vec::new();
        let mut reasons = Vec::new();
        if !input.declaration_only {
            for capability in [SemanticCapability::Procedures, SemanticCapability::Calls] {
                if !procedure.artifact().capabilities().is_available(capability) {
                    reasons.push(format!("unavailable execution capability {capability:?}"));
                }
            }
        }
        for gap in semantics.gaps() {
            // Partial is an adapter-wide support declaration. The selected
            // body's omitted calls are scoped gaps, including Point gaps for
            // unlowered statement bodies. A retained CallSite's value-only
            // gap does not erase its invocation; dispatch answers its targets.
            if (gap.capability == SemanticCapability::Calls
                && !matches!(gap.subject, SemanticGapSubject::CallSite(_)))
                || gap
                    .impacts
                    .contains(crate::analyzer::semantic::SemanticGapImpact::CallEvaluation)
            {
                reasons.push(format!(
                    "{} at {} ({}): {}",
                    gap.capability.label(),
                    gap.subject.label(),
                    gap.kind.label(),
                    gap.detail,
                ));
                if gap.kind == SemanticGapKind::ExceededBudget {
                    self.incomplete(
                        EffectReason::ProcedureBudgetExhausted,
                        EffectCoverage::Truncated,
                    );
                }
            }
        }
        if semantics.call_sites().len() > MAX_CALL_SITES_PER_PROCEDURE {
            reasons.push("procedure call inventory exceeded its bound".to_owned());
            self.incomplete(
                EffectReason::ProcedureBudgetExhausted,
                EffectCoverage::Truncated,
            );
        }
        // Validated IR requires exactly one Invoke event for every call row,
        // at that row's owned program point. Callable creation alone adds no
        // call row. Iterating this index preserves that execution ownership
        // without rescanning every value event in the procedure.
        for call in semantics
            .call_sites()
            .iter()
            .take(MAX_CALL_SITES_PER_PROCEDURE)
        {
            if self.calls.len() >= ProcedureEffectBudget::default().max_edges {
                reasons.push("execution call inventory exceeded its bound".to_owned());
                self.incomplete(
                    EffectReason::ProcedureBudgetExhausted,
                    EffectCoverage::Truncated,
                );
                break;
            }
            let Some(range) = semantic_call_range(semantics, call) else {
                reasons.push(format!("call {:?} has no source mapping", call.id));
                continue;
            };
            let call_key = (key.clone(), call.id);
            self.calls
                .entry(call_key.clone())
                .or_insert_with(|| CallInput {
                    file: input.file.clone(),
                    range,
                    ast: semantics
                        .source_mapping(call.source)
                        .and_then(|source| source.ast_identity),
                });
            self.answer(&call_key);
            if self.answers[&call_key].proven_non_callable {
                // The resolver positively identified a conversion. This is
                // not an invocation with an empty target set.
                continue;
            }
            sites.push(InvocationSite {
                call: call_key,
                source_site: call.id,
                mode: call.invocation_mode,
            });
        }
        if !reasons.is_empty() {
            self.incomplete(EffectReason::ProcedureUnreadable, EffectCoverage::Open);
            record_open_callee(
                self.analyzer,
                &mut self.cache.diagnostic_sources,
                self.diagnostics,
                &input.file,
                input
                    .unit
                    .as_ref()
                    .and_then(|unit| self.analyzer.ranges_of(unit).first().copied()),
                format!("{} invocation inventory: {reasons:?}", input.name),
                Incompleteness::Content,
            );
        }
        Invocations {
            sites,
            coverage: if reasons.is_empty() {
                InventoryCompleteness::Complete
            } else {
                InventoryCompleteness::Incomplete {
                    reason: format!("{reasons:?}").into(),
                }
            },
        }
    }
}

struct EffectProvider<'query, 'workspace> {
    inputs: CaptureScopedMemo<RefCell<ExecutionInputs<'query, 'workspace>>>,
    analyzer: &'workspace dyn IAnalyzer,
}

impl<'query, 'workspace> EffectProvider<'query, 'workspace> {
    fn with_inputs<T>(
        &self,
        read: impl FnOnce(&mut ExecutionInputs<'query, 'workspace>) -> T,
    ) -> T {
        self.inputs
            .read(&memo_attribution(self.analyzer), |inputs| {
                read(&mut inputs.borrow_mut())
            })
    }
}

impl ExecutionInputs<'_, '_> {
    fn answer(&mut self, call: &DurableCallSiteKey) {
        if self.answers.contains_key(call) {
            return;
        }
        let input = self.calls[call].clone();
        let (raw, dispatch_incompleteness) =
            self.cache
                .dispatch_at_source_with_cause(self.semantic, &input.file, input.range);
        let classified = classify_dispatch_arms(self.analyzer, self.cache, &raw);
        let contexts = raw
            .call_contexts
            .iter()
            .enumerate()
            .filter_map(|(index, context)| (context.call.as_ref() == Some(call)).then_some(index))
            .collect::<HashSet<_>>();
        let proven_non_callable = !contexts.is_empty()
            && contexts
                .iter()
                .all(|index| raw.call_contexts[*index].proven_non_callable);
        let residuals = raw
            .call_contexts
            .iter()
            .enumerate()
            .filter(|(index, _)| contexts.contains(index))
            .flat_map(|(_, context)| context.residuals.iter().cloned())
            .collect::<Vec<_>>();
        let mut arms = Vec::new();
        let mut effects = Vec::new();
        let mut external = Vec::new();
        let mut closed = Vec::new();
        let mut missing_target = false;
        for classified in classified
            .iter()
            .filter(|arm| contexts.contains(&arm.call_context))
        {
            let raw_arm = &raw.arms[classified.dispatch_index];
            let target = if let Some(key) = &raw_arm.target_procedure {
                self.register_procedure(key.clone(), classified.callee.clone());
                Some(ExecutionTarget::Procedure(Box::new(key.clone())))
            } else if let (Some(target), Some(boundary)) =
                (&raw_arm.exact_external_target, &raw_arm.boundary)
            {
                Some(ExecutionTarget::External(Box::new(
                    ExternalTargetIdentity::Exact {
                        target: Box::new(target.clone()),
                        boundary: boundary.clone(),
                    },
                )))
            } else if let (Some(target), Some(boundary)) =
                (&raw_arm.unmaterialized_target, &raw_arm.boundary)
            {
                Some(ExecutionTarget::External(Box::new(
                    ExternalTargetIdentity::Unmaterialized {
                        target: Box::new(target.clone()),
                        boundary: boundary.clone(),
                    },
                )))
            } else if let Some(unit) = &classified.callee {
                self.analyzer
                    .ranges_of(unit)
                    .into_iter()
                    .min_by_key(|range| (range.start_byte, range.end_byte))
                    .and_then(|range| {
                        self.semantic
                            .unique_procedure_of_declaration(&DeclarationValue::new(
                                unit.clone(),
                                range,
                            ))
                    })
                    .map(|procedure| {
                        let key = procedure.durable_key();
                        self.register_procedure(key.clone(), Some(unit.clone()));
                        ExecutionTarget::Procedure(Box::new(key))
                    })
            } else {
                None
            };
            let Some(target) = target else {
                missing_target = true;
                self.incomplete(EffectReason::CalleeUnkeyable, EffectCoverage::Open);
                continue;
            };
            let mut effect = classified.effect.clone();
            let mut leaf = classified.external_callee.clone();
            if matches!(target, ExecutionTarget::External(_))
                && leaf.is_none()
                && let Some(key) = &effect.key
            {
                let rust_receiver_closed = effect.complete
                    && key.language == Language::Rust.config_label()
                    && key.has_receiver;
                (effect.lookup, leaf) = external_arm_lookup(
                    self.cache.answer_for(self.analyzer, key),
                    key,
                    rust_receiver_closed,
                );
            }
            match &effect.lookup {
                ArmLookup::Conflict => {
                    self.incomplete(EffectReason::ModelConflict, EffectCoverage::Open)
                }
                ArmLookup::Unkeyable if matches!(target, ExecutionTarget::External(_)) => {
                    self.incomplete(EffectReason::CalleeUnkeyable, EffectCoverage::Open)
                }
                ArmLookup::Unmodeled { analyzable: false }
                    if matches!(target, ExecutionTarget::External(_)) =>
                {
                    self.incomplete(EffectReason::CalleeUnmodeled, EffectCoverage::Open)
                }
                _ => {}
            }
            arms.push(ExecutionArm {
                target,
                function: effect.execution_timing,
                quality: HopQuality::new(effect.proof == EffectProof::Proven, effect.complete),
                timing: effect.execution_timing,
            });
            closed.push(effect.lookup.is_closed_by_summary());
            effects.push(effect);
            external.push(leaf);
        }
        let guarded_closure = !arms.is_empty()
            && raw.coverage != CandidateCoverage::Truncated
            && matches!(residuals.as_slice(), [DispatchBoundaryKind::Unresolved])
            && closed.iter().all(|closed| *closed);
        let inventory_closed =
            raw.coverage.is_exhaustive() && residuals.is_empty() || guarded_closure;
        let certainty = if inventory_closed && arms.len() == 1 && arms[0].quality.proven {
            EffectCertainty::Definite
        } else {
            EffectCertainty::Possible
        };
        let outcome = match raw.outcome {
            "cancelled" => {
                self.incomplete(EffectReason::DispatchInterrupted, EffectCoverage::Open);
                ExecutionDispatchOutcome::Cancelled("dispatch cancelled".into())
            }
            "exceeded_budget" => {
                self.incomplete(EffectReason::DispatchInterrupted, EffectCoverage::Truncated);
                ExecutionDispatchOutcome::Budget("dispatch exceeded budget".into())
            }
            "unsupported" => {
                self.incomplete(EffectReason::DispatchUnsupported, EffectCoverage::Open);
                ExecutionDispatchOutcome::Unsupported("dispatch is unsupported".into())
            }
            _ if missing_target || contexts.is_empty() => {
                self.incomplete(EffectReason::DispatchUnresolved, EffectCoverage::Open);
                ExecutionDispatchOutcome::Unsupported(
                    "IR invocation has no exact source dispatch target".into(),
                )
            }
            _ => ExecutionDispatchOutcome::Complete,
        };
        if !proven_non_callable && (arms.is_empty() || !inventory_closed) {
            self.incomplete(EffectReason::DispatchUnresolved, EffectCoverage::Open);
            record_open_callee(
                self.analyzer,
                &mut self.cache.diagnostic_sources,
                self.diagnostics,
                &input.file,
                Some(input.range),
                format!(
                    "native invocation: outcome={}, coverage={:?}, residuals={residuals:?}, reasons={:?}",
                    raw.outcome, raw.coverage, raw.coverage_reasons
                ),
                dispatch_incompleteness,
            );
        }
        self.answers.insert(
            call.clone(),
            CallAnswer {
                dispatch: ExecutionDispatch {
                    arms,
                    residuals,
                    coverage: raw.coverage,
                    outcome,
                },
                effects,
                external,
                closed,
                certainty,
                proven_non_callable,
            },
        );
    }

    fn endpoints(
        &mut self,
        target: &ExecutionTarget,
        incoming: Option<&ExecutionArmContext>,
    ) -> ExecutionEndpoints<BoundDeclaredEffect> {
        let (effects, status) = match target {
            ExecutionTarget::Procedure(key) => {
                if self.procedure(key).is_none() {
                    self.incomplete(EffectReason::ProcedureUnreadable, EffectCoverage::Open);
                    return ExecutionEndpoints {
                        sources: Vec::new(),
                        status: ExecutionEndpointStatus::Partial("procedure is unavailable".into()),
                        covers_overrides: false,
                    };
                }
                let input = self.procedures[key.as_ref()].clone();
                let model = input
                    .unit
                    .as_ref()
                    .and_then(|unit| self.cache.key_for(self.analyzer, unit))
                    .map(|key| (self.cache.answer_for(self.analyzer, &key), key));
                match model {
                    Some((
                        ModelAnswer::Modeled {
                            effects,
                            complete,
                            covers_overrides,
                            ..
                        },
                        key,
                    )) => {
                        let summary_closed = complete && (covers_overrides || !key.has_receiver);
                        let status = if !input.declaration_only || summary_closed {
                            ExecutionEndpointStatus::Complete
                        } else {
                            self.incomplete(
                                EffectReason::ProcedureUnreadable,
                                EffectCoverage::Open,
                            );
                            ExecutionEndpointStatus::Partial(
                                "declaration has no complete covering summary".into(),
                            )
                        };
                        (effects, status)
                    }
                    Some((ModelAnswer::Conflict, _)) => {
                        self.incomplete(EffectReason::ModelConflict, EffectCoverage::Open);
                        (
                            Vec::new(),
                            ExecutionEndpointStatus::Conflict("active models conflict".into()),
                        )
                    }
                    _ if input.declaration_only => {
                        self.incomplete(EffectReason::ProcedureUnreadable, EffectCoverage::Open);
                        (
                            Vec::new(),
                            ExecutionEndpointStatus::Partial(
                                "declaration has no body or complete summary".into(),
                            ),
                        )
                    }
                    _ => (Vec::new(), ExecutionEndpointStatus::Absent),
                }
            }
            ExecutionTarget::External(_) => {
                let incoming =
                    incoming.expect("external targets are entered through an invocation");
                // Select this arm before cloning its declarations. Cloning
                // the whole call answer here repeats every sibling arm and
                // summary once per target.
                let external = self.answers[&incoming.call].external[incoming.ordinal].clone();
                let conflict = matches!(
                    self.answers[&incoming.call].effects[incoming.ordinal].lookup,
                    ArmLookup::Conflict
                );
                match external {
                    Some(external) if external.basis.is_established() => {
                        (external.declared, ExecutionEndpointStatus::Complete)
                    }
                    Some(external) => {
                        self.incomplete(EffectReason::CalleeUnmodeled, EffectCoverage::Open);
                        (
                            external.declared,
                            ExecutionEndpointStatus::Partial(
                                "external summary is incomplete".into(),
                            ),
                        )
                    }
                    None => {
                        self.incomplete(
                            if conflict {
                                EffectReason::ModelConflict
                            } else {
                                EffectReason::CalleeUnmodeled
                            },
                            EffectCoverage::Open,
                        );
                        (
                            Vec::new(),
                            if conflict {
                                ExecutionEndpointStatus::Conflict("active models conflict".into())
                            } else {
                                ExecutionEndpointStatus::Absent
                            },
                        )
                    }
                }
            }
        };
        ExecutionEndpoints {
            sources: effects
                .into_iter()
                .enumerate()
                .map(|(ordinal, effect)| ExecutionSource {
                    // Source identities are local to this target and query.
                    // Equal effect ids with distinct authored facts must not
                    // collapse before timing and certainty are projected.
                    identity: ordinal.to_string().into(),
                    provenance: effect.summary_id.clone().into(),
                    fact: effect,
                })
                .collect(),
            covers_overrides: matches!(status, ExecutionEndpointStatus::Complete),
            status,
        }
    }
}

impl CompositionProvider for EffectProvider<'_, '_> {
    type Error = Infallible;
    type Fact = BoundDeclaredEffect;
    type Function = ExecutionTiming;

    fn invocations(
        &self,
        procedure: &DurableProcedureKey,
        _: &mut SemanticRequest<'_>,
    ) -> Result<Invocations, Infallible> {
        Ok(self.with_inputs(|inputs| inputs.invocations(procedure)))
    }

    fn execution_dispatch(
        &self,
        call: &DurableCallSiteKey,
        _: &mut SemanticRequest<'_>,
    ) -> Result<ExecutionDispatch<ExecutionTiming>, Infallible> {
        Ok(self.with_inputs(|inputs| {
            inputs.semantic.effect_work.propagation_edge_visits = inputs
                .semantic
                .effect_work
                .propagation_edge_visits
                .saturating_add(1);
            inputs.answer(call);
            inputs.answers[call].dispatch.clone()
        }))
    }

    fn execution_endpoints(
        &self,
        target: &ExecutionTarget,
        incoming: Option<&ExecutionArmContext>,
        _: &mut SemanticRequest<'_>,
    ) -> Result<ExecutionEndpoints<BoundDeclaredEffect>, Infallible> {
        Ok(self.with_inputs(|inputs| inputs.endpoints(target, incoming)))
    }

    fn discharge_execution_residual(
        &self,
        call: &DurableCallSiteKey,
        dispatch: &ExecutionDispatch<ExecutionTiming>,
    ) -> bool {
        self.with_inputs(|inputs| {
            let answer = &inputs.answers[call];
            !dispatch.arms.is_empty()
                && dispatch.coverage != CandidateCoverage::Truncated
                && matches!(
                    dispatch.residuals.as_slice(),
                    [DispatchBoundaryKind::Unresolved]
                )
                && answer.closed.iter().all(|closed| *closed)
        })
    }

    // The execution entry point never requests the value-transfer capability.
    // Keep an accidental crossing explicit instead of fabricating empty flows.
    fn partial_flows(
        &self,
        _: &DurableProcedureKey,
        _: &mut SemanticRequest<'_>,
    ) -> Result<Arc<ProcedurePartialFlows>, Infallible> {
        unimplemented!("declared effects has no value-transfer capability")
    }

    fn interior_flows(
        &self,
        _: &DurableProcedureKey,
        _: &[InteriorSeed],
        _: &[InteriorObservation],
        _: bool,
        _: &mut SemanticRequest<'_>,
    ) -> Result<InteriorFlows, Infallible> {
        unimplemented!("declared effects has no value-transfer capability")
    }

    fn dispatch(
        &self,
        _: &DurableCallSiteKey,
        _: &mut SemanticRequest<'_>,
    ) -> Result<Dispatch, Infallible> {
        unimplemented!("declared effects has no value-transfer capability")
    }

    fn callers(
        &self,
        _: &DurableProcedureKey,
        _: &mut SemanticRequest<'_>,
    ) -> Result<Callers, Infallible> {
        unimplemented!("rooted execution does not enumerate incoming calls")
    }

    fn lexical_parent(
        &self,
        _: &DurableProcedureKey,
        _: &mut SemanticRequest<'_>,
    ) -> Result<Option<DurableProcedureKey>, Infallible> {
        unimplemented!("lexical containment is not an execution edge")
    }

    fn model(&self, _: &DurableCallSiteKey) -> Option<CallModel<ExecutionTiming>> {
        unimplemented!("effects declarations do not replace value transfers")
    }

    fn unmodeled_call_behavior(&self) -> brokk_bifrost_flow::dataflow::UnmodeledCallBehavior {
        unimplemented!("unmodeled effects remain open")
    }

    fn fallback_ports(
        &self,
        _: &DurableCallSiteKey,
        _: &mut SemanticRequest<'_>,
    ) -> Result<FallbackPorts, Infallible> {
        unimplemented!("declared effects has no value-transfer capability")
    }

    fn authored_models(&self) -> Vec<Box<[AuthoredArmClosure]>> {
        unimplemented!("execution declarations carry their own authored provenance")
    }

    fn openness(
        &self,
        _: &DurableProcedureKey,
        _: &mut SemanticRequest<'_>,
    ) -> Result<Openness, Infallible> {
        unimplemented!("execution inventories carry their own coverage")
    }

    fn endpoints(
        &self,
        _: &DurableProcedureKey,
        _: &mut SemanticRequest<'_>,
    ) -> Result<ProcedureEndpoints<BoundDeclaredEffect, ExecutionTiming>, Infallible> {
        unimplemented!("execution declarations have no value carrier")
    }

    fn source_evidence(
        &self,
        _: &BoundSource<BoundDeclaredEffect>,
        _: &mut SemanticRequest<'_>,
    ) -> Result<HopQuality, Infallible> {
        unimplemented!("execution declarations have no value carrier")
    }
}

pub(super) fn admitted(declaration: &DeclarationValue) -> bool {
    use crate::analyzer::languages::{LanguageGraphBackend, language_support_for_hook};
    let language = crate::analyzer::common::language_for_file(declaration.unit.source());
    matches!(language, Language::Rust | Language::Go)
        && language_support_for_hook(language, "reference_plugin").is_some_and(|support| {
            matches!(
                support.reference_plugin().graph,
                LanguageGraphBackend::Native(_)
            )
        })
}

impl ExecutionInputs<'_, '_> {
    #[allow(clippy::too_many_arguments)]
    fn witness_site(
        &mut self,
        call: &DurableCallSiteKey,
        budget: &mut CodeQueryExecutionBudget,
        limits: CodeQueryExecutionLimits,
        cancellation: Option<&CancellationToken>,
        cache_profile: &mut Option<QueryCacheProfile>,
    ) -> Option<String> {
        let input = self.calls[call].clone();
        let facts = self.cache.facts_for_effects(
            self.analyzer,
            self.semantic,
            &input.file,
            budget,
            limits,
            cancellation,
            self.diagnostics,
            cache_profile,
        )?;
        let shape = if let Some(ast) = input.ast {
            if ast.content() != facts.source_identity() {
                return None;
            }
            call_shape_for_call(&facts, &input.file, ast.node_id())
        } else {
            self.cache
                .result_member_call_shapes(self.semantic, &input.file, Some(&facts))
                .and_then(|shapes| shapes.get(&input.range).cloned().flatten())
        }?;
        Some(shape.outcome.site_id)
    }

    fn target_name(
        &self,
        target: &ExecutionTarget,
        call: &DurableCallSiteKey,
        ordinal: usize,
    ) -> String {
        match target {
            ExecutionTarget::Procedure(key) => self.procedures[key.as_ref()].name.clone(),
            ExecutionTarget::External(_) => self.answers[call].effects[ordinal]
                .key
                .as_ref()
                .expect("an external execution target has a canonical model key")
                .display(),
        }
    }
}

/// Each non-policy request reruns this query-local search over stored IR.
/// Cross-request result reuse belongs to the existing policy-unit layer.
#[allow(clippy::too_many_arguments)]
pub(super) fn report(
    semantic: &mut SemanticQueryContext<'_>,
    cache: &mut EffectTraversalCache,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    cache_profile: &mut Option<QueryCacheProfile>,
    declaration: &DeclarationValue,
    root_procedure: Option<&SemanticProcedureValue>,
    identity: &str,
) -> Arc<ProcedureEffectReport> {
    let analyzer = semantic.analyzer();
    // A published snapshot records global Models authority even on a cached
    // negative lookup. With no publication, policy-unit keys carry the existing
    // NO_ACTIVE_MODELS digest; standalone requests retain no composed result.
    let _models = analyzer.active_semantic_models();
    semantic.effect_work.acquisitions = semantic.effect_work.acquisitions.saturating_add(1);
    let name = root_procedure.map_or_else(
        || declaration.unit.fq_name(),
        |procedure| {
            format!(
                "{} ({})",
                declaration.unit.fq_name(),
                procedure.public().procedure_kind
            )
        },
    );
    let root = root_procedure
        .map(|procedure| procedure.handle.clone())
        .or_else(|| semantic.unique_procedure_of_declaration(declaration));
    let Some(root) = root else {
        return Arc::new(project_procedure_effect_report(
            identity,
            &name,
            std::iter::empty(),
            EffectCoverage::Open,
            Some(EffectReason::ProcedureUnreadable),
        ));
    };
    let root_key = root.durable_key();
    // A public procedure row can name a lambda inside this indexed unit.
    // Its enclosing unit supplies presentation and source ownership only;
    // an annotation on that unit is not a declaration on the lambda.
    let root_unit = semantic
        .locator_exactly_names_unit(root.semantics().locator(), &declaration.unit)
        .then(|| declaration.unit.clone());
    let declaration_only = root_unit.as_ref().is_some_and(|unit| {
        SignatureMetadata::unit_is_declaration_only(&analyzer.signature_metadata(unit))
    });
    let provider = EffectProvider {
        inputs: CaptureScopedMemo::new(RefCell::new(ExecutionInputs {
            analyzer,
            semantic,
            cache,
            diagnostics,
            procedures: [(
                root_key.clone(),
                ProcedureInput {
                    file: declaration.unit.source().clone(),
                    unit: root_unit,
                    name: name.clone(),
                    declaration_only,
                },
            )]
            .into_iter()
            .collect(),
            calls: HashMap::default(),
            answers: HashMap::default(),
            coverage: EffectCoverage::Exhaustive,
            reason: None,
        })),
        analyzer,
    };
    let bounds = ProcedureEffectBudget::default();
    let uncancelled = CancellationToken::new();
    let cancellation = cancellation.unwrap_or(&uncancelled);
    let mut traversal_budget = SemanticBudget::default();
    let outcome = compose::search_execution(
        vec![root_key],
        EffectLabels,
        &provider,
        CompositionBudget {
            max_procedures: bounds.max_procedures,
            max_hops: bounds.max_edges,
            max_callers_per_procedure: 0,
        },
        &mut SemanticRequest::new(&mut traversal_budget, cancellation),
    )
    .expect("the execution provider is infallible and requests no value reports");
    provider.with_inputs(|inputs| {
        let work = &mut inputs.semantic.effect_work;
        work.acquired_procedures = work
            .acquired_procedures
            .saturating_add(inputs.procedures.len() as u64);
        work.acquired_edges = work.acquired_edges.saturating_add(
            inputs
                .answers
                .values()
                .map(|answer| answer.dispatch.arms.len() as u64)
                .sum(),
        );
        work.inherited_effect_candidates = work
            .inherited_effect_candidates
            .saturating_add(outcome.reaches.len() as u64);
        for reason in &outcome.incomplete {
            if matches!(reason, compose::Incompleteness::Budget(_)) {
                inputs.incomplete(
                    EffectReason::ProcedureBudgetExhausted,
                    EffectCoverage::Truncated,
                );
            } else if matches!(reason, compose::Incompleteness::Cancelled) {
                inputs.incomplete(EffectReason::DispatchInterrupted, EffectCoverage::Open);
            } else {
                inputs.incomplete(EffectReason::DispatchUnresolved, EffectCoverage::Open);
            }
        }
        let mut effects: HashMap<String, ProcedureEffectAttribution> = HashMap::default();
        for reach in &outcome.reaches {
            let effect = EffectLabels.apply(
                outcome.functions.function(reach.function),
                &outcome.sources[reach.source].fact,
            );
            let depth = reach.hops.len();
            if depth > bounds.max_depth {
                inputs.incomplete(
                    EffectReason::ProcedureBudgetExhausted,
                    EffectCoverage::Truncated,
                );
                continue;
            }
            let mut certainty = effect.certainty;
            let mut witness = Vec::new();
            for hop in reach.hops.iter().rev() {
                let Hop::Invocation {
                    call,
                    ordinal,
                    target,
                    ..
                } = hop
                else {
                    unreachable!("an execution witness contains only invocations");
                };
                let answer = &inputs.answers[call];
                certainty = certainty.meet(answer.certainty);
                debug_assert_eq!(&answer.dispatch.arms[*ordinal].target, target.as_ref());
                let callee_display_name = inputs.target_name(target, call, *ordinal);
                if witness.len() < bounds.max_witness_steps {
                    if let Some(site_id) =
                        inputs.witness_site(call, budget, limits, Some(cancellation), cache_profile)
                    {
                        witness.push(crate::analyzer::usages::effects::EffectWitnessStep {
                            site_id,
                            callee_display_name,
                        });
                    } else {
                        inputs.incomplete(EffectReason::ProcedureUnreadable, EffectCoverage::Open);
                    }
                }
            }
            let attributed = ProcedureEffectAttribution {
                depth,
                certainty,
                timing: effect.timing,
                execution_timing: effect.execution_timing,
                witness_truncated: witness.len() < depth,
                witness,
                pack_id: effect.pack_id,
                model_id: effect.model_id,
                summary_id: effect.summary_id,
            };
            if let Some(existing) = effects.get_mut(&effect.effect_id) {
                existing.merge(attributed);
            } else if effects.len() < bounds.max_effects_per_procedure {
                effects.insert(effect.effect_id, attributed);
            } else {
                inputs.incomplete(
                    EffectReason::EffectBudgetExhausted,
                    EffectCoverage::Truncated,
                );
            }
        }
        if !inputs.coverage.is_exhaustive() {
            let incompleteness = if inputs.coverage == EffectCoverage::Truncated {
                Incompleteness::Operational(DerivationExecutionCause::Budget)
            } else if outcome
                .incomplete
                .iter()
                .any(|reason| matches!(reason, compose::Incompleteness::Cancelled))
            {
                Incompleteness::Operational(DerivationExecutionCause::Cancelled)
            } else {
                Incompleteness::Content
            };
            record_open_callee(
                analyzer,
                &mut inputs.cache.diagnostic_sources,
                inputs.diagnostics,
                declaration.unit.source(),
                Some(declaration.range),
                format!(
                    "{name}: execution coverage={:?}, reason={:?}",
                    inputs.coverage, inputs.reason
                ),
                incompleteness,
            );
        }
        let report = project_procedure_effect_report(
            identity,
            &name,
            effects.iter().map(|(id, effect)| (id.as_str(), effect)),
            inputs.coverage,
            inputs.reason,
        );
        inputs.semantic.effect_work.projected_rows = inputs
            .semantic
            .effect_work
            .projected_rows
            .saturating_add(report.rows.len() as u64);
        Arc::new(report)
    })
}

#[cfg(test)]
mod tests {
    use brokk_bifrost_flow::taint::compose::LabelFunctions;

    use super::*;
    use crate::analyzer::usages::effects::{EffectCertainty, EffectTiming};

    #[test]
    fn invocation_functions_compose_in_path_order_and_converge_on_recursion() {
        use ExecutionTiming::*;
        let timings = [
            SameEvaluation,
            SameInvocation,
            LaterSameTurn,
            AfterSuspension,
            DifferentTask,
            DifferentThread,
            DeferredCallback,
            GeneratorResume,
            CancellationCleanup,
            Unknown,
        ];
        let labels = EffectLabels;
        let mut fact = BoundDeclaredEffect {
            effect_id: "test.marker".to_owned(),
            timing: EffectTiming::Immediate,
            execution_timing: SameEvaluation,
            certainty: EffectCertainty::Definite,
            pack_id: "test.effects".to_owned(),
            model_id: "test.model".to_owned(),
            summary_id: "test.marker".to_owned(),
        };
        for inner in timings {
            for outer in timings {
                let combined = labels.then(&inner, &outer);
                for declared in timings {
                    fact.execution_timing = declared;
                    assert_eq!(
                        labels.apply(&combined, &fact),
                        labels.apply(&outer, &labels.apply(&inner, &fact)),
                        "inner={inner:?}, outer={outer:?}, declared={declared:?}",
                    );
                }
            }
        }
        let mut functions = LabelFunctions::new(labels);
        let synchronous = functions.intern(SameInvocation);
        for _ in 0..32 {
            assert_eq!(functions.then(synchronous, synchronous), synchronous);
        }
    }
}
