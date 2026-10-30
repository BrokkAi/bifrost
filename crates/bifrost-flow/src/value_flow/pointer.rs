//! Query-local pointer-origin propagation over the shared value-flow solver.

use crate::analyzer::semantic::{
    CallBinding, CallBindings, ControlContinuation, ControlEdgeKind, EvidenceCompleteness,
    IcfgProvider, OracleLimits, PointerAccess, PointerAccessWidth, PointerAlias, PointerByteOffset,
    PointerIncompleteReason, PointerInvalidation, PointerInvalidationTarget, PointerOrigin,
    PointerOriginId, PointerOriginKind, PointerRelationStrength, ProcedureHandle, ProcedureId,
    ProcedurePortKind, ProcedureSemantics, ProgramPointHandle, ProgramPointId, ProofStatus,
    ScopeEndAt, ScopeEndFact, SemanticArtifactKey, SemanticBudget, SemanticEffect, SemanticPlace,
    SemanticValueKind, ValueFlowEndpoint, ValueFlowKind, ValueFlowRelation, ValueFlowRelationKind,
    ValueFlowSnapshot, ValueId,
};
use crate::analyzer::{Language, LanguageDialect};
use crate::dataflow::{DataflowRequest, IcfgSolveInput, WitnessRetentionLimits};
use crate::hash::{HashMap, HashSet};

use super::plan::{MAX_VALUE_FLOW_RELATIONS, MAX_VALUE_FLOW_SINKS, MAX_VALUE_FLOW_SOURCES};
use super::{
    ValueFlowCarrier, ValueFlowEdgeKillSpec, ValueFlowEventKey, ValueFlowEventKind, ValueFlowInput,
    ValueFlowObservationPhase, ValueFlowPlan, ValueFlowPlanError, ValueFlowSinkId,
    ValueFlowSinkSpec, ValueFlowSolveError, ValueFlowSourceId, ValueFlowSourceSpec,
    ValueFlowSources, ValueFlowSummaryResult, identity_alias_closure,
    solve_value_flow_summaries_on_snapshot,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PointerBounds {
    InBounds,
    OutOfBounds,
    MayBeOutOfBounds,
    Incomplete(PointerIncompleteReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointerInvalidationWitness {
    pub procedure: ProcedureHandle,
    pub invalidation: PointerInvalidation,
    pub path_status: super::ValueFlowMayStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointerScopeEndWitness {
    pub procedure: ProcedureHandle,
    pub scope_end: ScopeEndFact,
    pub path_status: super::ValueFlowMayStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointerProvenanceOrigin {
    pub procedure: ProcedureHandle,
    pub origin: PointerOrigin,
    pub byte_offset: PointerByteOffset,
    pub strength: PointerRelationStrength,
    pub bounds: PointerBounds,
    pub invalidations_before: Vec<PointerInvalidationWitness>,
    pub scope_ends_before: Vec<PointerScopeEndWitness>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointerProvenanceAccess {
    pub procedure: ProcedureHandle,
    pub access: PointerAccess,
    pub origins: Vec<PointerProvenanceOrigin>,
    pub incomplete_reasons: Vec<PointerIncompleteReason>,
}

/// Query-local pointer facts supplied by a language-specific analyzer after
/// applying active semantic models to persisted structural facts.
#[derive(Debug, Default)]
pub struct PointerProvenanceAdditionalFacts {
    pub origins: Vec<(ProcedureHandle, PointerOrigin)>,
    pub aliases: Vec<(ProcedureHandle, PointerAlias)>,
    pub invalidations: Vec<(ProcedureHandle, PointerInvalidation)>,
}

impl PointerProvenanceAccess {
    pub fn is_complete(&self) -> bool {
        self.incomplete_reasons.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct PointerProvenanceResult {
    accesses: Box<[PointerProvenanceAccess]>,
    flow: ValueFlowSummaryResult,
}

impl PointerProvenanceResult {
    pub fn accesses(&self) -> &[PointerProvenanceAccess] {
        &self.accesses
    }

    pub const fn value_flow(&self) -> &ValueFlowSummaryResult {
        &self.flow
    }

    pub fn is_complete(&self) -> bool {
        self.flow.is_complete()
            && self
                .accesses
                .iter()
                .all(PointerProvenanceAccess::is_complete)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct OriginIdentity {
    procedure: ProcedureKey,
    id: PointerOriginId,
}

type ProcedureKey = (SemanticArtifactKey, ProcedureId);

impl OriginIdentity {
    fn new(procedure: &ProcedureHandle, id: PointerOriginId) -> Self {
        Self {
            procedure: procedure.durable_key(),
            id,
        }
    }
}

#[derive(Debug, Clone)]
struct AliasSeed {
    procedure: ProcedureHandle,
    origin_procedure: ProcedureHandle,
    alias: PointerAlias,
    origin: PointerOrigin,
    identity: OriginIdentity,
    trigger_id: ValueFlowSourceId,
}

#[derive(Debug, Clone)]
enum LifecycleFact {
    Invalidation {
        procedure: ProcedureHandle,
        target: PointerInvalidationTarget,
        row: PointerInvalidation,
        placement: Option<LifecyclePlacement>,
    },
    ScopeEnd {
        procedure: ProcedureHandle,
        origin: Box<OriginIdentity>,
        row: ScopeEndFact,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct LifecyclePlacement {
    procedure: ProcedureHandle,
    point: ProgramPointId,
    observation: usize,
    trigger_alias: usize,
}

#[derive(Debug, Clone, Copy)]
enum SourceMetadata {
    Alias(usize),
    Lifecycle { alias: usize, fact: usize },
}

#[derive(Debug, Clone)]
struct AccessSeed {
    procedure: ProcedureHandle,
    access: PointerAccess,
}

/// A pointer solve plan contains only rows reachable from its discovered
/// procedure closure and is discarded with the query that built it.
#[derive(Debug)]
pub struct PointerProvenancePlan {
    flow: ValueFlowPlan,
    aliases: Box<[AliasSeed]>,
    lifecycle: Box<[LifecycleFact]>,
    sources: HashMap<ValueFlowSourceId, SourceMetadata>,
    sinks: HashMap<ValueFlowSinkId, AccessSeed>,
    placement_observations: Box<[ValueFlowSinkId]>,
    unsupported_procedures: HashSet<(SemanticArtifactKey, ProcedureId)>,
}

impl PointerProvenancePlan {
    pub fn try_new(
        root: ProcedureHandle,
        snapshots: Vec<ValueFlowInput<ValueFlowSnapshot>>,
        bindings: Vec<ValueFlowInput<CallBindings>>,
    ) -> Result<Self, ValueFlowPlanError> {
        Self::try_new_with_additional_facts(
            root,
            snapshots,
            bindings,
            PointerProvenanceAdditionalFacts::default(),
        )
    }

    #[cfg(test)]
    fn try_new_with_additional_invalidations(
        root: ProcedureHandle,
        snapshots: Vec<ValueFlowInput<ValueFlowSnapshot>>,
        bindings: Vec<ValueFlowInput<CallBindings>>,
        additional_invalidations: Vec<(ProcedureHandle, PointerInvalidation)>,
    ) -> Result<Self, ValueFlowPlanError> {
        Self::try_new_with_additional_facts(
            root,
            snapshots,
            bindings,
            PointerProvenanceAdditionalFacts {
                invalidations: additional_invalidations,
                ..PointerProvenanceAdditionalFacts::default()
            },
        )
    }

    pub fn try_new_with_additional_facts(
        root: ProcedureHandle,
        snapshots: Vec<ValueFlowInput<ValueFlowSnapshot>>,
        bindings: Vec<ValueFlowInput<CallBindings>>,
        additional_facts: PointerProvenanceAdditionalFacts,
    ) -> Result<Self, ValueFlowPlanError> {
        let mut procedures = Vec::new();
        let mut seen_procedures = HashSet::default();
        for input in &snapshots {
            let procedure = input.value().procedure().clone();
            if seen_procedures.insert(procedure.durable_key()) {
                procedures.push(procedure);
            }
        }

        let mut additional_origins_by_procedure =
            HashMap::<ProcedureKey, HashMap<PointerOriginId, PointerOrigin>>::default();
        for (procedure, origin) in &additional_facts.origins {
            assert!(
                seen_procedures.contains(&procedure.durable_key()),
                "an injected pointer origin must belong to the discovered procedure closure"
            );
            assert!(procedure.semantics().point(origin.point).is_some());
            let rows = additional_origins_by_procedure
                .entry(procedure.durable_key())
                .or_default();
            assert_eq!(
                origin.id.index(),
                procedure.semantics().pointer_origins().len() + rows.len(),
                "injected pointer origin IDs must extend the procedure's dense origin rows"
            );
            assert!(rows.insert(origin.id, origin.clone()).is_none());
        }

        let mut aliases = Vec::<AliasSeed>::new();
        let mut lifecycle = Vec::<LifecycleFact>::new();
        let mut source_specs = ValueFlowSources::default();
        let mut source_metadata = HashMap::<ValueFlowEventKey, SourceMetadata>::default();
        let mut aliases_by_origin =
            HashMap::<OriginIdentity, Vec<(usize, ValueFlowSourceId)>>::default();

        for procedure in &procedures {
            let semantics = procedure.semantics();
            for alias in semantics.pointer_aliases() {
                let origin = semantics.pointer_origins()[alias.origin.index()].clone();
                let identity = OriginIdentity::new(procedure, origin.id);
                let alias_index = aliases.len();
                let point = procedure
                    .point_handle(alias.point)
                    .expect("validated pointer alias names a live point");
                if source_specs.len() == MAX_VALUE_FLOW_SOURCES {
                    return Err(ValueFlowPlanError::LimitExceeded);
                }
                let key = source_event_key(&point, source_specs.len())?;
                let trigger_id = source_specs.push(ValueFlowSourceSpec::new(
                    key.clone(),
                    point,
                    ValueFlowObservationPhase::AfterEffects,
                    value_carrier(procedure, alias.pointer),
                    ProofStatus::Proven,
                    EvidenceCompleteness::Complete,
                ));
                aliases.push(AliasSeed {
                    procedure: procedure.clone(),
                    origin_procedure: procedure.clone(),
                    alias: alias.clone(),
                    origin,
                    identity: identity.clone(),
                    trigger_id,
                });
                source_metadata.insert(key, SourceMetadata::Alias(alias_index));
                aliases_by_origin
                    .entry(identity)
                    .or_default()
                    .push((alias_index, trigger_id));
            }

            for (owner, alias) in additional_facts
                .aliases
                .iter()
                .filter(|(owner, _)| owner.durable_key() == procedure.durable_key())
            {
                assert!(procedure.semantics().point(alias.point).is_some());
                assert!(procedure.semantics().value(alias.pointer).is_some());
                let origin = procedure
                    .semantics()
                    .pointer_origins()
                    .get(alias.origin.index())
                    .or_else(|| {
                        additional_origins_by_procedure
                            .get(&procedure.durable_key())
                            .and_then(|origins| origins.get(&alias.origin))
                    })
                    .expect("an injected pointer alias names a known origin")
                    .clone();
                assert_eq!(owner.durable_key(), procedure.durable_key());
                let identity = OriginIdentity::new(procedure, origin.id);
                let alias_index = aliases.len();
                let point = procedure
                    .point_handle(alias.point)
                    .expect("injected pointer alias names a live point");
                if source_specs.len() == MAX_VALUE_FLOW_SOURCES {
                    return Err(ValueFlowPlanError::LimitExceeded);
                }
                let key = source_event_key(&point, source_specs.len())?;
                let trigger_id = source_specs.push(ValueFlowSourceSpec::new(
                    key.clone(),
                    point,
                    ValueFlowObservationPhase::AfterEffects,
                    value_carrier(procedure, alias.pointer),
                    ProofStatus::Proven,
                    EvidenceCompleteness::Complete,
                ));
                aliases.push(AliasSeed {
                    procedure: procedure.clone(),
                    origin_procedure: procedure.clone(),
                    alias: alias.clone(),
                    origin,
                    identity: identity.clone(),
                    trigger_id,
                });
                source_metadata.insert(key, SourceMetadata::Alias(alias_index));
                aliases_by_origin
                    .entry(identity)
                    .or_default()
                    .push((alias_index, trigger_id));
            }

            for invalidation in semantics.pointer_invalidations() {
                lifecycle.push(LifecycleFact::Invalidation {
                    procedure: procedure.clone(),
                    target: invalidation.target,
                    row: invalidation.clone(),
                    placement: None,
                });
            }
            let mut stack_origins_by_place =
                HashMap::<SemanticPlace, Vec<PointerOriginId>>::default();
            for origin in semantics.pointer_origins() {
                if let PointerOriginKind::StackPlace { place } = &origin.kind {
                    stack_origins_by_place
                        .entry(place.clone())
                        .or_default()
                        .push(origin.id);
                }
            }
            for scope_end in semantics.scope_ends() {
                for origin in stack_origins_by_place
                    .get(&scope_end.place)
                    .into_iter()
                    .flatten()
                {
                    lifecycle.push(LifecycleFact::ScopeEnd {
                        procedure: procedure.clone(),
                        origin: Box::new(OriginIdentity::new(procedure, *origin)),
                        row: scope_end.clone(),
                    });
                }
            }
        }
        let mut normal_return_facts = HashMap::<ProcedureKey, NormalReturnValueFacts>::default();
        let mut seen_return_aliases = HashSet::default();
        for input in &bindings {
            let call_bindings = input.value();
            if !call_binding_is_proven_complete(call_bindings) {
                continue;
            }
            let call = call_bindings.call();
            let caller = call.procedure();
            let callee = call_bindings.callee();
            let Some(call_site) = caller.semantics().call_site(call.id()) else {
                unreachable!("validated call binding names a live call site");
            };
            let ControlContinuation::Target(continuation) = call_site.normal_continuation else {
                continue;
            };
            let return_facts = normal_return_facts
                .entry(callee.durable_key())
                .or_insert_with(|| normal_return_value_facts(callee));
            for binding in call_bindings.bindings() {
                let CallBinding::NormalReturn { formal, result, .. } = binding else {
                    continue;
                };
                if formal.kind() != ProcedurePortKind::NormalReturn {
                    continue;
                }
                let point = caller
                    .point_handle(continuation)
                    .expect("validated normal continuation names a live point");
                for returned_alias in callee.semantics().pointer_aliases() {
                    if !pointer_alias_reaches_normal_return(callee, returned_alias, return_facts) {
                        continue;
                    }
                    let origin =
                        callee.semantics().pointer_origins()[returned_alias.origin.index()].clone();
                    let identity = OriginIdentity::new(callee, origin.id);
                    if !seen_return_aliases.insert((
                        caller.durable_key(),
                        continuation,
                        result.id(),
                        identity.clone(),
                        returned_alias.byte_offset,
                        returned_alias.strength,
                    )) {
                        continue;
                    }
                    if source_specs.len() == MAX_VALUE_FLOW_SOURCES {
                        return Err(ValueFlowPlanError::LimitExceeded);
                    }
                    let key = source_event_key(&point, source_specs.len())?;
                    let alias_index = aliases.len();
                    let trigger_id = source_specs.push(ValueFlowSourceSpec::new(
                        key.clone(),
                        point.clone(),
                        ValueFlowObservationPhase::AfterEffects,
                        value_carrier(caller, result.id()),
                        ProofStatus::Proven,
                        EvidenceCompleteness::Complete,
                    ));
                    aliases.push(AliasSeed {
                        procedure: caller.clone(),
                        origin_procedure: callee.clone(),
                        alias: PointerAlias {
                            point: continuation,
                            pointer: result.id(),
                            origin: returned_alias.origin,
                            byte_offset: returned_alias.byte_offset,
                            strength: returned_alias.strength,
                            source: call_site.source,
                            evidence: call_site.evidence,
                        },
                        origin,
                        identity: identity.clone(),
                        trigger_id,
                    });
                    source_metadata.insert(key, SourceMetadata::Alias(alias_index));
                    aliases_by_origin
                        .entry(identity)
                        .or_default()
                        .push((alias_index, trigger_id));
                }
            }
        }
        for (procedure, invalidation) in &additional_facts.invalidations {
            assert!(
                seen_procedures.contains(&procedure.durable_key()),
                "an injected pointer invalidation must belong to the discovered procedure closure"
            );
            assert!(procedure.semantics().point(invalidation.point).is_some());
            match invalidation.target {
                PointerInvalidationTarget::Pointer(pointer) => {
                    assert!(procedure.semantics().value(pointer).is_some());
                }
                PointerInvalidationTarget::Origin(origin) => {
                    assert!(
                        procedure
                            .semantics()
                            .pointer_origins()
                            .get(origin.index())
                            .is_some()
                            || additional_origins_by_procedure
                                .get(&procedure.durable_key())
                                .is_some_and(|origins| origins.contains_key(&origin))
                    );
                }
            }
            lifecycle.push(LifecycleFact::Invalidation {
                procedure: procedure.clone(),
                target: invalidation.target,
                row: invalidation.clone(),
                placement: None,
            });
        }

        let mut sink_specs = Vec::<ValueFlowSinkSpec>::new();
        let mut observation_indices = HashMap::default();
        let mut observation_keys = Vec::new();
        let initial_lifecycle_len = lifecycle.len();
        let mut summarized_invalidations = Vec::new();
        let mut seen_placements = HashSet::default();
        let mut alias_indices_by_procedure = HashMap::<ProcedureKey, Vec<usize>>::default();
        for (alias_index, alias) in aliases.iter().enumerate() {
            alias_indices_by_procedure
                .entry(alias.procedure.durable_key())
                .or_default()
                .push(alias_index);
        }
        let mut callees_by_procedure = HashMap::<ProcedureKey, HashSet<ProcedureKey>>::default();
        for input in &bindings {
            let call_bindings = input.value();
            callees_by_procedure
                .entry(call_bindings.call().procedure().durable_key())
                .or_default()
                .insert(call_bindings.callee().durable_key());
        }
        let mut called_procedures_by_caller =
            HashMap::<ProcedureKey, HashSet<ProcedureKey>>::default();
        for (fact_index, fact) in lifecycle.iter().take(initial_lifecycle_len).enumerate() {
            let LifecycleFact::Invalidation {
                procedure,
                target: PointerInvalidationTarget::Pointer(pointer),
                row,
                ..
            } = fact
            else {
                continue;
            };
            if !invalidation_reaches_normal_exit(procedure, row.point) {
                continue;
            }
            let formal_kinds = formal_kinds_reaching_pointer(procedure, *pointer);
            if formal_kinds.is_empty() {
                continue;
            }
            for input in &bindings {
                let call_bindings = input.value();
                if call_bindings.callee() != procedure
                    || !call_binding_is_proven_complete(call_bindings)
                {
                    continue;
                }
                let call = call_bindings.call();
                let caller = call.procedure();
                let call_site = caller
                    .semantics()
                    .call_site(call.id())
                    .expect("validated call binding names a live call site");
                let ControlContinuation::Target(continuation) = call_site.normal_continuation
                else {
                    continue;
                };
                let caller_key = caller.durable_key();
                let called_procedures = called_procedures_by_caller
                    .entry(caller_key.clone())
                    .or_insert_with(|| called_procedure_closure(caller_key, &callees_by_procedure));
                for (formal, actual) in proven_pointer_actuals(call_bindings) {
                    if !formal_kinds.contains(&formal) {
                        continue;
                    }
                    // Origins may come from any callee in the closure. Accept a
                    // placement only when its alias source reaches this caller's
                    // actual pointer observation before the call effects.
                    for origin_procedure in called_procedures.iter() {
                        for alias_index in alias_indices_by_procedure
                            .get(origin_procedure)
                            .into_iter()
                            .flatten()
                            .copied()
                        {
                            let observation = match observation_indices.entry((
                                caller.durable_key(),
                                call_site.point,
                                actual,
                            )) {
                                std::collections::hash_map::Entry::Occupied(entry) => *entry.get(),
                                std::collections::hash_map::Entry::Vacant(entry) => {
                                    if sink_specs.len() == MAX_VALUE_FLOW_SINKS {
                                        return Err(ValueFlowPlanError::LimitExceeded);
                                    }
                                    let point = caller
                                        .point_handle(call_site.point)
                                        .expect("validated call site names a live point");
                                    let key = sink_event_key(&point, sink_specs.len())?;
                                    sink_specs.push(ValueFlowSinkSpec::new(
                                        key.clone(),
                                        point,
                                        ValueFlowObservationPhase::BeforeEffects,
                                        value_carrier(caller, actual),
                                        ProofStatus::Proven,
                                        EvidenceCompleteness::Complete,
                                    ));
                                    let index = observation_keys.len();
                                    observation_keys.push(key);
                                    *entry.insert(index)
                                }
                            };
                            let placement = LifecyclePlacement {
                                procedure: caller.clone(),
                                point: continuation,
                                observation,
                                trigger_alias: alias_index,
                            };
                            if seen_placements.insert((fact_index, placement.clone())) {
                                if summarized_invalidations.len() == MAX_VALUE_FLOW_RELATIONS {
                                    return Err(ValueFlowPlanError::LimitExceeded);
                                }
                                summarized_invalidations.push(LifecycleFact::Invalidation {
                                    procedure: procedure.clone(),
                                    target: PointerInvalidationTarget::Pointer(*pointer),
                                    row: row.clone(),
                                    placement: Some(placement),
                                });
                            }
                        }
                    }
                }
            }
        }
        lifecycle.extend(summarized_invalidations);

        let mut sink_metadata = HashMap::<ValueFlowEventKey, AccessSeed>::default();
        for procedure in &procedures {
            for access in procedure.semantics().pointer_accesses() {
                if sink_specs.len() == MAX_VALUE_FLOW_SINKS {
                    return Err(ValueFlowPlanError::LimitExceeded);
                }
                let point = procedure
                    .point_handle(access.point)
                    .expect("validated pointer access names a live point");
                let key = sink_event_key(&point, sink_specs.len())?;
                sink_specs.push(ValueFlowSinkSpec::new(
                    key.clone(),
                    point,
                    ValueFlowObservationPhase::AfterEffects,
                    value_carrier(procedure, access.pointer),
                    ProofStatus::Proven,
                    EvidenceCompleteness::Complete,
                ));
                sink_metadata.insert(
                    key,
                    AccessSeed {
                        procedure: procedure.clone(),
                        access: access.clone(),
                    },
                );
            }
        }

        let mut edge_kills = Vec::new();
        let mut candidates_by_pointer = HashMap::default();
        for (fact_index, fact) in lifecycle.iter().enumerate() {
            if matches!(
                fact,
                LifecycleFact::Invalidation {
                    placement: Some(_),
                    ..
                }
            ) {
                continue;
            }
            let (procedure, invalidation_target) = match fact {
                LifecycleFact::Invalidation {
                    procedure, target, ..
                } => (procedure, Some(*target)),
                LifecycleFact::ScopeEnd { procedure, .. } => (procedure, None),
            };
            if let Some(PointerInvalidationTarget::Pointer(pointer)) = invalidation_target {
                // Seed the invalidation on the operation's actual pointer
                // value. Alias-origin sources activate it only when they reach
                // that same carrier, including through actual/formal bindings.
                for (alias_index, alias) in aliases.iter().enumerate() {
                    let trigger = alias.trigger_id;
                    append_lifecycle_source(
                        fact,
                        fact_index,
                        alias_index,
                        trigger,
                        pointer,
                        &mut source_specs,
                        &mut source_metadata,
                        &mut edge_kills,
                    )?;
                }
                continue;
            }
            let origin = match fact {
                LifecycleFact::Invalidation {
                    target: PointerInvalidationTarget::Origin(origin),
                    ..
                } => OriginIdentity::new(procedure, *origin),
                LifecycleFact::ScopeEnd { origin, .. } => origin.as_ref().clone(),
                LifecycleFact::Invalidation {
                    target: PointerInvalidationTarget::Pointer(_),
                    ..
                } => unreachable!("pointer invalidations were handled above"),
            };
            let Some(origin_aliases) = aliases_by_origin.get(&origin) else {
                continue;
            };
            for (alias_index, trigger) in origin_aliases {
                let alias = &aliases[*alias_index];
                if alias.procedure.durable_key() != procedure.durable_key() {
                    continue;
                }
                let candidate_key = (procedure.durable_key(), alias.alias.pointer);
                let candidates = candidates_by_pointer
                    .entry(candidate_key)
                    .or_insert_with(|| {
                        let seeds = std::iter::once(alias.alias.pointer).collect();
                        let mut candidates = identity_alias_closure(procedure.semantics(), &seeds)
                            .into_iter()
                            .collect::<Vec<_>>();
                        candidates.sort_unstable();
                        candidates
                    });
                for candidate in candidates.iter().copied() {
                    append_lifecycle_source(
                        fact,
                        fact_index,
                        *alias_index,
                        *trigger,
                        candidate,
                        &mut source_specs,
                        &mut source_metadata,
                        &mut edge_kills,
                    )?;
                }
            }
        }

        let mut unsupported_procedures = HashSet::default();
        let snapshots = snapshots
            .into_iter()
            .map(|input| {
                let (snapshot, status) = input.into_parts();
                let procedure = snapshot.procedure().clone();
                let mut pointer_values = aliases
                    .iter()
                    .filter(|alias| alias.procedure.durable_key() == procedure.durable_key())
                    .map(|alias| alias.alias.pointer)
                    .collect::<HashSet<_>>();
                let seeds = pointer_values.clone();
                pointer_values.extend(identity_alias_closure(procedure.semantics(), &seeds));
                pointer_values.extend(
                    procedure
                        .semantics()
                        .pointer_accesses()
                        .iter()
                        .map(|access| access.pointer),
                );
                pointer_values.extend(lifecycle.iter().filter_map(|fact| match fact {
                    LifecycleFact::Invalidation {
                        procedure: owner,
                        target: PointerInvalidationTarget::Pointer(pointer),
                        ..
                    } if owner.durable_key() == procedure.durable_key() => Some(*pointer),
                    LifecycleFact::Invalidation { .. } | LifecycleFact::ScopeEnd { .. } => None,
                }));
                let identity_projection = snapshot.clone().into_class_identity_projection();
                let retained_relations = identity_projection
                    .relations()
                    .iter()
                    .map(|relation| relation.id.clone())
                    .collect::<HashSet<_>>();
                for relation in snapshot
                    .relations()
                    .iter()
                    .filter(|relation| !retained_relations.contains(&relation.id))
                {
                    if go_pointer_assignment_conversion(relation).is_none()
                        && relation_touches_values(relation, &pointer_values)
                    {
                        unsupported_procedures.insert(procedure.durable_key());
                    }
                }
                ValueFlowInput::new(snapshot, status)
            })
            .collect();
        let flow = ValueFlowPlan::try_new_with_edge_kills(
            root,
            snapshots,
            bindings,
            source_specs,
            sink_specs,
            edge_kills,
        )?;
        let sources = flow
            .sources()
            .map(|(id, source)| {
                let metadata = source_metadata
                    .get(source.key())
                    .copied()
                    .expect("each planned pointer source has query-local metadata");
                (id, metadata)
            })
            .collect();
        let sink_ids = flow
            .sinks()
            .map(|(id, sink)| (sink.key(), id))
            .collect::<HashMap<_, _>>();
        let placement_observations = observation_keys
            .iter()
            .map(|key| {
                *sink_ids
                    .get(key)
                    .expect("each placement observation has a bound sink")
            })
            .collect();
        let observation_keys = observation_keys.into_iter().collect::<HashSet<_>>();
        let sinks = flow
            .sinks()
            .filter(|(_, sink)| !observation_keys.contains(sink.key()))
            .map(|(id, sink)| {
                let seed = sink_metadata
                    .get(sink.key())
                    .expect("each planned pointer access has query-local metadata")
                    .clone();
                (id, seed)
            })
            .collect();
        Ok(Self {
            flow,
            aliases: aliases.into_boxed_slice(),
            lifecycle: lifecycle.into_boxed_slice(),
            sources,
            sinks,
            placement_observations,
            unsupported_procedures,
        })
    }
}

pub fn solve_pointer_provenance_on_snapshot<Provider>(
    provider: &Provider,
    plan: &PointerProvenancePlan,
    input: IcfgSolveInput<'_>,
    limits: OracleLimits,
    semantic_budget: &mut SemanticBudget,
    request: &mut DataflowRequest<'_>,
) -> Result<PointerProvenanceResult, ValueFlowSolveError>
where
    Provider: IcfgProvider + ?Sized,
{
    let flow = solve_value_flow_summaries_on_snapshot(
        provider,
        &plan.flow,
        input,
        limits,
        WitnessRetentionLimits::disabled(),
        semantic_budget,
        request,
    )?;
    Ok(plan.resolve(flow))
}

impl PointerProvenancePlan {
    fn resolve(&self, flow: ValueFlowSummaryResult) -> PointerProvenanceResult {
        let mut ordered_sinks = self.sinks.iter().collect::<Vec<_>>();
        ordered_sinks.sort_unstable_by_key(|(id, _)| **id);
        let mut accesses = ordered_sinks
            .iter()
            .map(|(_, seed)| PointerProvenanceAccess {
                procedure: seed.procedure.clone(),
                access: seed.access.clone(),
                origins: Vec::new(),
                incomplete_reasons: Vec::new(),
            })
            .collect::<Vec<_>>();
        if !self.unsupported_procedures.is_empty() {
            for access in &mut accesses {
                push_reason(
                    &mut access.incomplete_reasons,
                    PointerIncompleteReason::UnsupportedOperation,
                );
            }
        }
        let sink_indices = ordered_sinks
            .iter()
            .enumerate()
            .map(|(index, (id, _))| (**id, index))
            .collect::<HashMap<_, _>>();
        let mut origins_by_access =
            HashMap::<(usize, OriginIdentity, PointerByteOffset), usize>::default();
        let observation_meetings = flow
            .meetings()
            .iter()
            .filter(|meeting| !self.sinks.contains_key(&meeting.sink()))
            .map(|meeting| (meeting.sink(), meeting.source()))
            .collect::<HashSet<_>>();

        for meeting in flow.meetings() {
            let Some(&access_index) = sink_indices.get(&meeting.sink()) else {
                continue;
            };
            let Some(source) = self.sources.get(&meeting.source()).copied() else {
                continue;
            };
            let (alias_index, lifecycle_fact) = match source {
                SourceMetadata::Alias(alias_index) => (alias_index, None),
                SourceMetadata::Lifecycle { alias, fact } => (alias, Some(fact)),
            };
            let seed = &self.aliases[alias_index];
            let result_origin_index = *origins_by_access
                .entry((access_index, seed.identity.clone(), seed.alias.byte_offset))
                .or_insert_with(|| {
                    let bounds = bounds_for(
                        &seed.origin_procedure,
                        &accesses[access_index].procedure,
                        &seed.origin,
                        seed.alias.byte_offset,
                        accesses[access_index].access.width,
                    );
                    if let PointerBounds::Incomplete(reason) = bounds {
                        push_reason(&mut accesses[access_index].incomplete_reasons, reason);
                    }
                    accesses[access_index]
                        .origins
                        .push(PointerProvenanceOrigin {
                            procedure: seed.origin_procedure.clone(),
                            origin: seed.origin.clone(),
                            byte_offset: seed.alias.byte_offset,
                            strength: seed.alias.strength,
                            bounds,
                            invalidations_before: Vec::new(),
                            scope_ends_before: Vec::new(),
                        });
                    accesses[access_index].origins.len() - 1
                });
            let access_point = accesses[access_index].access.point;
            let seed_is_may = seed.alias.strength == PointerRelationStrength::May;
            if seed_is_may {
                push_reason(
                    &mut accesses[access_index].incomplete_reasons,
                    PointerIncompleteReason::AmbiguousAlias,
                );
            }
            let access_procedure = accesses[access_index].procedure.clone();
            let output = &mut accesses[access_index].origins[result_origin_index];
            if seed_is_may || matches!(meeting.may_status(), super::ValueFlowMayStatus::Unproven) {
                output.strength = PointerRelationStrength::May;
            }
            if let Some(fact_index) = lifecycle_fact {
                if lifecycle_is_at_point(
                    &self.lifecycle[fact_index],
                    &access_procedure,
                    access_point,
                ) {
                    continue;
                }
                match &self.lifecycle[fact_index] {
                    LifecycleFact::Invalidation { procedure, row, .. } => {
                        push_invalidation(
                            &mut output.invalidations_before,
                            PointerInvalidationWitness {
                                procedure: procedure.clone(),
                                invalidation: row.clone(),
                                path_status: meeting.may_status(),
                            },
                        );
                    }
                    LifecycleFact::ScopeEnd { procedure, row, .. } => {
                        push_scope_end(
                            &mut output.scope_ends_before,
                            PointerScopeEndWitness {
                                procedure: procedure.clone(),
                                scope_end: row.clone(),
                                path_status: meeting.may_status(),
                            },
                        );
                    }
                }
            }
            for fact in self.lifecycle.iter() {
                let LifecycleFact::Invalidation {
                    procedure,
                    row,
                    placement: Some(placement),
                    ..
                } = fact
                else {
                    continue;
                };
                if placement.trigger_alias == alias_index
                    && observation_meetings.contains(&(
                        self.placement_observations[placement.observation],
                        self.aliases[placement.trigger_alias].trigger_id,
                    ))
                    && placement.procedure == access_procedure
                    && control_reaches(&placement.procedure, placement.point, access_point)
                {
                    push_invalidation(
                        &mut output.invalidations_before,
                        PointerInvalidationWitness {
                            procedure: procedure.clone(),
                            invalidation: row.clone(),
                            path_status: meeting.may_status(),
                        },
                    );
                }
            }
        }

        for access in &mut accesses {
            if !flow.is_complete() {
                push_reason(
                    &mut access.incomplete_reasons,
                    PointerIncompleteReason::AmbiguousAlias,
                );
            }
            if !self.unsupported_procedures.is_empty() {
                push_reason(
                    &mut access.incomplete_reasons,
                    PointerIncompleteReason::UnsupportedOperation,
                );
                for origin in &mut access.origins {
                    origin.strength = PointerRelationStrength::May;
                    origin.bounds =
                        PointerBounds::Incomplete(PointerIncompleteReason::UnsupportedOperation);
                }
            }
            if access.origins.is_empty() {
                push_reason(
                    &mut access.incomplete_reasons,
                    PointerIncompleteReason::AmbiguousOrigin,
                );
                continue;
            }
            let mut distinct_origins = HashSet::default();
            let mut offsets_by_origin =
                HashMap::<OriginIdentity, HashSet<PointerByteOffset>>::default();
            for origin in &access.origins {
                let identity = OriginIdentity::new(&origin.procedure, origin.origin.id);
                distinct_origins.insert(identity.clone());
                offsets_by_origin
                    .entry(identity)
                    .or_default()
                    .insert(origin.byte_offset);
            }
            let ambiguous_origin = distinct_origins.len() > 1;
            let ambiguous_offset = offsets_by_origin.values().any(|offsets| offsets.len() > 1);
            if ambiguous_origin || ambiguous_offset {
                for origin in &mut access.origins {
                    origin.strength = PointerRelationStrength::May;
                }
                if ambiguous_origin {
                    push_reason(
                        &mut access.incomplete_reasons,
                        PointerIncompleteReason::AmbiguousOrigin,
                    );
                }
                if ambiguous_offset {
                    push_reason(
                        &mut access.incomplete_reasons,
                        PointerIncompleteReason::AmbiguousAlias,
                    );
                }
            }
        }

        PointerProvenanceResult {
            accesses: accesses.into_boxed_slice(),
            flow,
        }
    }
}

/// Go emits this descriptor for assignment-context conversions, which retain
/// the pointer's address. Other class-identity-excluded operations stay typed
/// incomplete when they touch a tracked pointer value.
fn go_pointer_assignment_conversion(relation: &ValueFlowRelation) -> Option<(ValueId, ValueId)> {
    let procedure = relation.point.procedure();
    if procedure.semantics().locator().language() != LanguageDialect::Standard(Language::Go)
        || relation.kind != ValueFlowRelationKind::LanguageDefined
    {
        return None;
    }
    let point = procedure
        .semantics()
        .point(relation.point.id())
        .expect("validated relation belongs to a live program point");
    let event = point
        .events
        .get(relation.event_index as usize)
        .expect("validated relation names a live semantic event");
    let SemanticEffect::ValueFlow {
        kind: ValueFlowKind::LanguageDefined,
        source,
        target,
    } = event.effect
    else {
        return None;
    };
    if !matches!(
        procedure.semantics().value(target).map(|value| &value.kind),
        Some(SemanticValueKind::LanguageDefined(name)) if name.as_ref() == "go.assignment_conversion"
    ) {
        return None;
    }
    Some((source, target))
}

fn relation_touches_values(relation: &ValueFlowRelation, values: &HashSet<ValueId>) -> bool {
    [&relation.source, &relation.target].into_iter().any(|endpoint| {
        matches!(endpoint, ValueFlowEndpoint::Value(value) if values.contains(&value.id()))
    })
}

fn invalidation_reaches_normal_exit(procedure: &ProcedureHandle, point: ProgramPointId) -> bool {
    let semantics = procedure.semantics();
    let normal_exit = semantics.normal_exit_point();
    let mut reached = HashSet::default();
    let mut pending = vec![point];
    while let Some(point) = pending.pop() {
        if point == normal_exit {
            return true;
        }
        if !reached.insert(point) {
            continue;
        }
        pending.extend(
            semantics
                .control_edges()
                .iter()
                .filter(|edge| edge.source_point == point)
                .map(|edge| edge.target_point),
        );
    }
    false
}

fn called_procedure_closure(
    root: ProcedureKey,
    callees: &HashMap<ProcedureKey, HashSet<ProcedureKey>>,
) -> HashSet<ProcedureKey> {
    let mut reached = HashSet::default();
    let mut pending = vec![root];
    while let Some(procedure) = pending.pop() {
        if !reached.insert(procedure.clone()) {
            continue;
        }
        pending.extend(callees.get(&procedure).into_iter().flatten().cloned());
    }
    reached
}

struct NormalReturnValueFacts {
    reachable_values: HashSet<ValueId>,
    return_points: Vec<ProgramPointId>,
}

fn normal_return_value_facts(procedure: &ProcedureHandle) -> NormalReturnValueFacts {
    let semantics = procedure.semantics();
    let mut predecessors = HashMap::<ValueId, Vec<ValueId>>::default();
    let mut reachable_values = HashSet::default();
    let mut return_points = Vec::new();
    for point in semantics.points() {
        for event in &point.events {
            match event.effect {
                SemanticEffect::Assignment { target, value } => {
                    predecessors.entry(target).or_default().push(value);
                }
                SemanticEffect::ValueFlow { source, target, .. } => {
                    predecessors.entry(target).or_default().push(source);
                }
                SemanticEffect::ProcedureReturn { value: Some(value) } => {
                    reachable_values.insert(value);
                    return_points.push(point.id);
                }
                _ => {}
            }
        }
    }
    let mut pending = reachable_values.iter().copied().collect::<Vec<_>>();
    while let Some(target) = pending.pop() {
        for source in predecessors.get(&target).into_iter().flatten() {
            if reachable_values.insert(*source) {
                pending.push(*source);
            }
        }
    }
    NormalReturnValueFacts {
        reachable_values,
        return_points,
    }
}

fn pointer_alias_reaches_normal_return(
    procedure: &ProcedureHandle,
    alias: &PointerAlias,
    return_facts: &NormalReturnValueFacts,
) -> bool {
    return_facts.reachable_values.contains(&alias.pointer)
        && return_facts
            .return_points
            .iter()
            .any(|point| control_reaches(procedure, alias.point, *point))
}

fn control_reaches(
    procedure: &ProcedureHandle,
    source: ProgramPointId,
    target: ProgramPointId,
) -> bool {
    let mut reached = HashSet::default();
    let mut pending = vec![source];
    while let Some(point) = pending.pop() {
        if point == target {
            return true;
        }
        if !reached.insert(point) {
            continue;
        }
        pending.extend(
            procedure
                .semantics()
                .control_edges()
                .iter()
                .filter(|edge| edge.source_point == point)
                .map(|edge| edge.target_point),
        );
    }
    false
}

fn formal_kinds_reaching_pointer(
    procedure: &ProcedureHandle,
    pointer: ValueId,
) -> HashSet<ProcedurePortKind> {
    let semantics = procedure.semantics();
    semantics
        .values()
        .iter()
        .filter_map(|value| {
            let kind = match value.kind {
                SemanticValueKind::Parameter { ordinal, .. } => {
                    ProcedurePortKind::Parameter { ordinal }
                }
                SemanticValueKind::Receiver { .. } => ProcedurePortKind::Receiver,
                _ => return None,
            };
            identity_alias_closure(semantics, &std::iter::once(value.id).collect())
                .contains(&pointer)
                .then_some(kind)
        })
        .collect()
}

fn call_binding_is_proven_complete(bindings: &CallBindings) -> bool {
    bindings.coverage().is_exhaustive()
        && matches!(bindings.candidate().proof(), ProofStatus::Proven)
        && matches!(
            bindings.candidate().completeness(),
            EvidenceCompleteness::Complete
        )
}

fn proven_pointer_actuals(bindings: &CallBindings) -> Vec<(ProcedurePortKind, ValueId)> {
    let mut actuals = Vec::new();
    for binding in bindings.bindings() {
        match binding {
            CallBinding::Receiver { actual, formal, .. }
                if formal.kind() == ProcedurePortKind::Receiver =>
            {
                actuals.push((formal.kind(), actual.id()));
            }
            CallBinding::ArgumentGroup(group) if group.coverage().is_exhaustive() => {
                for mapping in group.mappings() {
                    if matches!(mapping.proof(), ProofStatus::Proven)
                        && matches!(mapping.completeness(), EvidenceCompleteness::Complete)
                        && mapping.value().preserves_reference_identity()
                    {
                        actuals.push((
                            mapping.value().formal().kind(),
                            mapping.value().actual().value().id(),
                        ));
                    }
                }
            }
            CallBinding::ImplicitArgument { source, formal, .. }
                if source.procedure() == bindings.call().procedure() =>
            {
                actuals.push((formal.kind(), source.id()));
            }
            CallBinding::Receiver { .. }
            | CallBinding::ArgumentGroup(_)
            | CallBinding::ImplicitArgument { .. }
            | CallBinding::NormalReturn { .. }
            | CallBinding::ExceptionalReturn { .. } => {}
        }
    }
    actuals
}

#[allow(clippy::too_many_arguments)]
fn append_lifecycle_source(
    fact: &LifecycleFact,
    fact_index: usize,
    alias_index: usize,
    trigger: ValueFlowSourceId,
    pointer: ValueId,
    source_specs: &mut ValueFlowSources,
    source_metadata: &mut HashMap<ValueFlowEventKey, SourceMetadata>,
    edge_kills: &mut Vec<ValueFlowEdgeKillSpec>,
) -> Result<(), ValueFlowPlanError> {
    if source_specs.len() == MAX_VALUE_FLOW_SOURCES {
        return Err(ValueFlowPlanError::LimitExceeded);
    }
    let (procedure, point_id, ending_edge) = lifecycle_observation(fact);
    let point = procedure
        .point_handle(point_id)
        .expect("validated lifecycle row names a live point");
    let key = source_event_key(&point, source_specs.len())?;
    let carrier = value_carrier(procedure, pointer);
    let phase = match fact {
        // A point-scoped end is in force on entry to its continuation. Observe
        // it before return/value-transfer effects at that point so the ended
        // pointer can still flow through the transfer to its caller.
        LifecycleFact::ScopeEnd {
            row:
                ScopeEndFact {
                    at: ScopeEndAt::Point(_),
                    ..
                },
            ..
        } => ValueFlowObservationPhase::BeforeEffects,
        LifecycleFact::Invalidation { .. } | LifecycleFact::ScopeEnd { .. } => {
            ValueFlowObservationPhase::AfterEffects
        }
    };
    let trigger = source_specs.intern_list(vec![trigger]);
    let id = source_specs.push(
        ValueFlowSourceSpec::new(
            key.clone(),
            point.clone(),
            phase,
            carrier.clone(),
            ProofStatus::Proven,
            EvidenceCompleteness::Complete,
        )
        .when_sources_reach(trigger),
    );
    source_metadata.insert(
        key,
        SourceMetadata::Lifecycle {
            alias: alias_index,
            fact: fact_index,
        },
    );
    if let Some((end_target, end_kind)) = ending_edge {
        for edge in procedure.semantics().control_edges().iter().filter(|edge| {
            edge.source_point == point_id
                && (edge.target_point != end_target || edge.kind != end_kind)
        }) {
            if edge_kills.len() == MAX_VALUE_FLOW_RELATIONS {
                return Err(ValueFlowPlanError::LimitExceeded);
            }
            edge_kills.push(ValueFlowEdgeKillSpec {
                point: point.clone(),
                target: edge.target_point,
                kind: edge.kind,
                carrier: carrier.clone(),
                sources: source_specs.intern_list(vec![id]),
                labels: None,
            });
        }
    }
    Ok(())
}

fn source_event_key(
    point: &ProgramPointHandle,
    ordinal: usize,
) -> Result<ValueFlowEventKey, ValueFlowPlanError> {
    let ordinal = u32::try_from(ordinal).map_err(|_| ValueFlowPlanError::LimitExceeded)?;
    ValueFlowEventKey::at_point(point, ordinal, ValueFlowEventKind::Source)
        .map_err(ValueFlowPlanError::from)
}

fn sink_event_key(
    point: &ProgramPointHandle,
    ordinal: usize,
) -> Result<ValueFlowEventKey, ValueFlowPlanError> {
    let ordinal = u32::try_from(ordinal).map_err(|_| ValueFlowPlanError::LimitExceeded)?;
    ValueFlowEventKey::at_point(point, ordinal, ValueFlowEventKind::Sink)
        .map_err(ValueFlowPlanError::from)
}

fn lifecycle_is_at_point(
    fact: &LifecycleFact,
    procedure: &ProcedureHandle,
    point: ProgramPointId,
) -> bool {
    let (observation_procedure, observation_point, _) = lifecycle_observation(fact);
    observation_procedure == procedure && observation_point == point
}

fn lifecycle_observation(
    fact: &LifecycleFact,
) -> (
    &ProcedureHandle,
    ProgramPointId,
    Option<(ProgramPointId, ControlEdgeKind)>,
) {
    match fact {
        LifecycleFact::Invalidation { procedure, row, .. } => (procedure, row.point, None),
        LifecycleFact::ScopeEnd { procedure, row, .. } => match row.at {
            ScopeEndAt::Point(point) => (procedure, point, None),
            ScopeEndAt::Edge {
                source_point,
                target_point,
                kind,
            } => (procedure, source_point, Some((target_point, kind))),
        },
    }
}

fn value_carrier(procedure: &ProcedureHandle, value: ValueId) -> ValueFlowCarrier {
    ValueFlowCarrier::for_value(
        procedure
            .value_handle(value)
            .expect("validated pointer row names a live value"),
    )
}

fn bounds_for(
    origin_procedure: &ProcedureHandle,
    access_procedure: &ProcedureHandle,
    origin: &PointerOrigin,
    offset: PointerByteOffset,
    width: PointerAccessWidth,
) -> PointerBounds {
    checked_bounds(
        origin.byte_extent,
        byte_offset(origin_procedure.semantics(), offset),
        access_width(access_procedure.semantics(), width),
    )
}

fn checked_bounds(
    extent: Option<u128>,
    offset: Result<(i128, i128), PointerIncompleteReason>,
    width: Result<u128, PointerIncompleteReason>,
) -> PointerBounds {
    let Some(extent) = extent else {
        return PointerBounds::Incomplete(PointerIncompleteReason::UnknownAllocationExtent);
    };
    let width = match width {
        Ok(width) => width,
        Err(reason) => return PointerBounds::Incomplete(reason),
    };
    let Ok(width) = i128::try_from(width) else {
        return PointerBounds::Incomplete(PointerIncompleteReason::OffsetOverflow);
    };
    let (minimum, maximum) = match offset {
        Ok(offset) => offset,
        Err(reason) => return PointerBounds::Incomplete(reason),
    };
    if minimum > maximum {
        return PointerBounds::Incomplete(PointerIncompleteReason::UnknownLayout);
    }
    if maximum < 0 {
        return PointerBounds::OutOfBounds;
    }
    if minimum < 0 {
        return PointerBounds::MayBeOutOfBounds;
    }
    let Some(minimum_end) = minimum.checked_add(width) else {
        return PointerBounds::Incomplete(PointerIncompleteReason::OffsetOverflow);
    };
    let Some(maximum_end) = maximum.checked_add(width) else {
        return PointerBounds::Incomplete(PointerIncompleteReason::OffsetOverflow);
    };
    let minimum_end = u128::try_from(minimum_end)
        .expect("a non-negative offset plus a non-negative width stays non-negative");
    let maximum_end = u128::try_from(maximum_end)
        .expect("a non-negative offset plus a non-negative width stays non-negative");
    if minimum_end > extent {
        PointerBounds::OutOfBounds
    } else if maximum_end <= extent {
        PointerBounds::InBounds
    } else {
        PointerBounds::MayBeOutOfBounds
    }
}

fn byte_offset(
    semantics: &ProcedureSemantics,
    offset: PointerByteOffset,
) -> Result<(i128, i128), PointerIncompleteReason> {
    match offset {
        PointerByteOffset::Exact(offset) => Ok((offset, offset)),
        PointerByteOffset::Range { minimum, maximum } => Ok((minimum, maximum)),
        PointerByteOffset::Unknown => Err(PointerIncompleteReason::UnknownLayout),
        PointerByteOffset::Value(value) => match semantics.value(value).map(|value| &value.kind) {
            Some(SemanticValueKind::SignedInteger(value)) => Ok((*value, *value)),
            Some(SemanticValueKind::UnsignedInteger(value)) => {
                let value =
                    i128::try_from(*value).map_err(|_| PointerIncompleteReason::OffsetOverflow)?;
                Ok((value, value))
            }
            _ => Err(PointerIncompleteReason::UnknownLayout),
        },
    }
}

fn access_width(
    semantics: &ProcedureSemantics,
    width: PointerAccessWidth,
) -> Result<u128, PointerIncompleteReason> {
    match width {
        PointerAccessWidth::Exact(width) => Ok(width),
        PointerAccessWidth::Unknown => Err(PointerIncompleteReason::UnknownLayout),
        PointerAccessWidth::ValueTimes { value, multiplier } => {
            let Some(value) = semantics.value(value).map(|value| &value.kind) else {
                return Err(PointerIncompleteReason::UnknownLayout);
            };
            let value = match value {
                SemanticValueKind::UnsignedInteger(value) => *value,
                SemanticValueKind::SignedInteger(value) => {
                    u128::try_from(*value).map_err(|_| PointerIncompleteReason::OffsetOverflow)?
                }
                _ => return Err(PointerIncompleteReason::UnknownLayout),
            };
            value
                .checked_mul(multiplier)
                .ok_or(PointerIncompleteReason::OffsetOverflow)
        }
    }
}

fn push_reason(reasons: &mut Vec<PointerIncompleteReason>, reason: PointerIncompleteReason) {
    if !reasons.contains(&reason) {
        reasons.push(reason);
    }
}

fn push_invalidation(
    witnesses: &mut Vec<PointerInvalidationWitness>,
    witness: PointerInvalidationWitness,
) {
    if let Some(existing) = witnesses.iter_mut().find(|existing| {
        existing.procedure == witness.procedure && existing.invalidation == witness.invalidation
    }) {
        if witness.path_status == super::ValueFlowMayStatus::Proven {
            existing.path_status = super::ValueFlowMayStatus::Proven;
        }
    } else {
        witnesses.push(witness);
    }
}

fn push_scope_end(witnesses: &mut Vec<PointerScopeEndWitness>, witness: PointerScopeEndWitness) {
    if let Some(existing) = witnesses.iter_mut().find(|existing| {
        existing.procedure == witness.procedure && existing.scope_end == witness.scope_end
    }) {
        if witness.path_status == super::ValueFlowMayStatus::Proven {
            existing.path_status = super::ValueFlowMayStatus::Proven;
        }
    } else {
        witnesses.push(witness);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic::{
        CancellationToken, IcfgSnapshotLimits, PointerInvalidationCause, SemanticRequest,
    };
    use crate::analyzer::{AnalyzerConfig, Language};
    use crate::dataflow::SolverBudget;
    use crate::inline_project::InlineTestProject;
    use crate::value_flow::{ClosureLimits, discover_closure};

    #[test]
    fn extent_checks_cover_exact_ranges_and_checked_overflow() {
        assert_eq!(
            checked_bounds(Some(8), Ok((4, 4)), Ok(4)),
            PointerBounds::InBounds
        );
        assert_eq!(
            checked_bounds(Some(8), Ok((5, 5)), Ok(4)),
            PointerBounds::OutOfBounds
        );
        assert_eq!(
            checked_bounds(Some(8), Ok((4, 7)), Ok(2)),
            PointerBounds::MayBeOutOfBounds
        );
        assert_eq!(
            checked_bounds(Some(8), Ok((i128::MAX, i128::MAX)), Ok(1)),
            PointerBounds::Incomplete(PointerIncompleteReason::OffsetOverflow)
        );
        assert_eq!(
            checked_bounds(None, Err(PointerIncompleteReason::UnknownLayout), Ok(1)),
            PointerBounds::Incomplete(PointerIncompleteReason::UnknownAllocationExtent)
        );
    }

    #[test]
    fn origins_cross_helper_parameters_returns_and_loop_cycles() {
        let project = InlineTestProject::with_language(Language::Go)
            .file(
                "pointers.go",
                "package fixture\n\
                 func read(pointer *int) int { return *pointer }\n\
                 func readExact(pointer *int) int { return *pointer }\n\
                 func bounce(pointer *int) *int {\n\
                     result := pointer\n\
                     for index := 0; index < 2; index++ { result = pointer }\n\
                     return result\n\
                 }\n\
                 func entry(flag bool) {\n\
                     exact := 0\n\
                     _ = readExact(bounce(&exact))\n\
                     left := 0\n\
                     right := 0\n\
                     var pointer *int\n\
                     if flag { pointer = &left } else { pointer = &right }\n\
                     _ = read(pointer)\n\
                     }\n",
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut semantic_budget = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &project.file("pointers.go"),
                &mut SemanticRequest::new(&mut semantic_budget, &cancellation),
            )
            .expect("Go pointer fixture semantics materialize")
            .available_value()
            .cloned()
            .expect("Go pointer fixture semantics remain available");
        let root = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("entry")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("fixture declares entry");
        let closure = discover_closure(
            &workspace,
            &root,
            ClosureLimits { max_procedures: 32 },
            &mut semantic_budget,
            &cancellation,
        )
        .expect("fixture call closure resolves");
        let closure_binding_count = closure.bindings.len();
        let plan =
            PointerProvenancePlan::try_new(root.clone(), closure.snapshots, closure.bindings)
                .expect("pointer plan builds over the discovered closure");
        let provider = workspace.icfg_provider();
        let icfg = provider
            .snapshot(
                &root,
                IcfgSnapshotLimits::default(),
                &mut SemanticRequest::new(&mut semantic_budget, &cancellation),
            )
            .expect("fixture ICFG materializes");
        let input = IcfgSolveInput::from_outcome(&icfg).expect("ICFG snapshot is available");
        let mut solver_budget = SolverBudget::default();
        let result = solve_pointer_provenance_on_snapshot(
            &provider,
            &plan,
            input,
            OracleLimits::default(),
            &mut semantic_budget,
            &mut DataflowRequest::new(&mut solver_budget, &cancellation),
        )
        .expect("pointer provenance solve succeeds");
        let read_access = result
            .accesses()
            .iter()
            .find(|access| {
                access
                    .procedure
                    .semantics()
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("read")
            })
            .expect("read helper has one dereference access");
        assert_eq!(
            read_access.origins.len(),
            2,
            "both branch origins reach read; aliases={:?}, sources={:?}, sinks={:?}, procedures={:?}, bindings={}, meetings={:?}, complete={}",
            plan.aliases
                .iter()
                .map(|seed| (
                    seed.procedure.id().get(),
                    seed.alias.pointer.get(),
                    seed.origin.id.get(),
                    seed.origin.kind.clone(),
                ))
                .collect::<Vec<_>>(),
            plan.sources
                .iter()
                .map(|(id, source)| (id.get(), *source))
                .collect::<Vec<_>>(),
            plan.sinks
                .iter()
                .map(|(id, seed)| (
                    id.get(),
                    seed.procedure.id().get(),
                    seed.procedure
                        .semantics()
                        .locator()
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name()),
                    seed.access.pointer.get()
                ))
                .collect::<Vec<_>>(),
            closure
                .procedures
                .iter()
                .map(|procedure| {
                    procedure
                        .semantics()
                        .locator()
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                })
                .collect::<Vec<_>>(),
            closure_binding_count,
            result
                .value_flow()
                .meetings()
                .iter()
                .map(|meeting| (meeting.source().get(), meeting.sink().get()))
                .collect::<Vec<_>>(),
            result.value_flow().is_complete(),
        );
        assert_ne!(
            read_access.origins[0].origin.id, read_access.origins[1].origin.id,
            "both branch alternatives keep their distinct origin identities"
        );
        assert!(
            read_access
                .origins
                .iter()
                .all(|origin| origin.strength == PointerRelationStrength::May)
        );
        assert!(read_access.origins.iter().all(|origin| {
            origin.bounds
                == PointerBounds::Incomplete(PointerIncompleteReason::UnknownAllocationExtent)
        }));
        let exact_access = result
            .accesses()
            .iter()
            .find(|access| {
                access
                    .procedure
                    .semantics()
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("readExact")
            })
            .expect("readExact helper has one dereference access");
        assert_eq!(exact_access.origins.len(), 1);
        assert_eq!(
            exact_access.origins[0].strength,
            PointerRelationStrength::Must
        );
    }

    #[test]
    fn helper_pointer_invalidation_reaches_only_later_caller_accesses() {
        let project = InlineTestProject::with_language(Language::Go)
            .file(
                "pointer_lifetime.go",
                "package fixture\n\
                 func release(pointer *int) {}\n\
                 func after() {\n\
                     value := 0\n\
                     pointer := &value\n\
                     release(pointer)\n\
                     _ = *pointer\n\
                 }\n\
                 func before() {\n\
                     value := 0\n\
                     pointer := &value\n\
                     _ = *pointer\n\
                     release(pointer)\n\
                 }\n",
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut semantic_budget = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &project.file("pointer_lifetime.go"),
                &mut SemanticRequest::new(&mut semantic_budget, &cancellation),
            )
            .expect("Go helper fixture semantics materialize")
            .available_value()
            .cloned()
            .expect("Go helper fixture semantics remain available");
        let provider = workspace.icfg_provider();

        for (root_name, should_have_witness) in [("after", true), ("before", false)] {
            let root = artifact
                .procedures()
                .iter()
                .find(|procedure| {
                    procedure
                        .locator()
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some(root_name)
                })
                .and_then(|procedure| artifact.procedure_handle(procedure.id()))
                .expect("fixture declares each access-order root");
            let closure = discover_closure(
                &workspace,
                &root,
                ClosureLimits { max_procedures: 16 },
                &mut semantic_budget,
                &cancellation,
            )
            .expect("helper call closure resolves");
            let release = closure
                .procedures
                .iter()
                .find(|procedure| {
                    procedure
                        .semantics()
                        .locator()
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some("release")
                })
                .expect("discovered closure includes release helper");
            let pointer = release
                .semantics()
                .values()
                .iter()
                .find(|value| {
                    matches!(
                        &value.kind,
                        SemanticValueKind::Parameter { name: Some(name), .. }
                            if name.as_ref() == "pointer"
                    )
                })
                .map(|value| value.id)
                .expect("release has its pointer formal");
            let source = release
                .semantics()
                .source_mappings()
                .first()
                .expect("release has source evidence")
                .id;
            let evidence = release
                .semantics()
                .evidence_rows()
                .first()
                .expect("release has proof evidence")
                .id;
            // Go has no explicit deallocator. Inject the same typed IR fact a
            // language producer emits for a helper that frees this parameter,
            // while keeping actual/formal mapping and caller CFG real.
            let invalidation = PointerInvalidation {
                point: release.semantics().normal_exit_point(),
                target: PointerInvalidationTarget::Pointer(pointer),
                cause: PointerInvalidationCause::Deallocated,
                strength: PointerRelationStrength::Must,
                source,
                evidence,
            };
            let plan = PointerProvenancePlan::try_new_with_additional_invalidations(
                root.clone(),
                closure.snapshots,
                closure.bindings,
                vec![(release.clone(), invalidation)],
            )
            .expect("pointer plan includes the helper deallocation fact");
            let icfg = provider
                .snapshot(
                    &root,
                    IcfgSnapshotLimits::default(),
                    &mut SemanticRequest::new(&mut semantic_budget, &cancellation),
                )
                .expect("caller/helper ICFG materializes");
            let input = IcfgSolveInput::from_outcome(&icfg).expect("ICFG snapshot is available");
            let mut solver_budget = SolverBudget::default();
            let result = solve_pointer_provenance_on_snapshot(
                &provider,
                &plan,
                input,
                OracleLimits::default(),
                &mut semantic_budget,
                &mut DataflowRequest::new(&mut solver_budget, &cancellation),
            )
            .expect("helper invalidation solve succeeds");
            let access = result
                .accesses()
                .iter()
                .find(|access| access.procedure == root)
                .expect("caller has one dereference access");
            assert!(
                !access.origins.is_empty(),
                "caller access resolves its origin"
            );
            let has_invalidation_witness = access
                .origins
                .iter()
                .any(|origin| !origin.invalidations_before.is_empty());
            assert_eq!(
                has_invalidation_witness, should_have_witness,
                "helper deallocation witness expectation for caller {root_name}"
            );
        }
    }
}
