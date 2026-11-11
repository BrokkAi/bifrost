//! Query-lifetime ordered local events for a typestate client.
//!
//! This is a view of one decoded procedure. Calls and their continuations are
//! kept separate from point events: the IR does not assign a point-event
//! ordinal to a call stage. A client must bind those stages with its call
//! bindings before composing protocol transitions.

use crate::analyzer::WorkspaceAnalyzer;
use crate::analyzer::semantic::partial_flow::PartialFlowPort;
use crate::analyzer::semantic::{
    CallBinding, CallBindings, CallSiteHandle, CandidateCoverage, ControlContinuation, ControlEdge,
    ControlEdgeHandle, DispatchResult, DropFact, EvidenceCompleteness, HeapOracle, MoveOutFact,
    ObservationPhase, ProcedureHandle, ProcedureSemanticsParts, ProgramPointId, ProofStatus,
    SemanticCallSite, SemanticEffect, SemanticEvent, SemanticOutcome, SemanticProviderError,
    SemanticValueKind, ValueAtPoint, procedure_parts_retained_bytes,
};
use crate::analyzer::workspace_authority::{
    OwnedMemoCapability, ReplayingMemo, ReplayingMemoEntry, workspace_memo_attribution,
};
use crate::composition::{CompositionMemoBudget, LocalTransferDiscovery, admit_composition_entry};
use crate::hash::HashMap;
use crate::taint::compose::{
    CallHandoff, CallHandoffExit, CallObjectContinuity, DispatchCandidate, HopQuality,
};
use crate::taint::compose::{Endpoint, ObjectAnchorSite};
use crate::value_flow::DurableProcedureKey;
use crate::value_flow::ValueFlowProvider;

use super::{
    BoundTypestateSubject, CallSubjectMapSelection, CallSubjectMapping, CompiledProtocol,
    ProtocolEventOccurrence, ProtocolObservationPhase, TypestateAliasGuard,
    TypestateBindingContext, TypestateBindingMultiplicity, TypestateBindingPlan,
    TypestateBindingQuality, TypestateComposeFunction, TypestateComposeStep, TypestateSubjectId,
    TypestateUncertainty, call_subject_map,
};

const MAX_LOCAL_PATHS: usize = 1_024;
const MAX_LOCAL_VISITS: usize = 4_096;

type BypassKey = (
    DurableProcedureKey,
    TypestateBindingContext,
    Option<PartialFlowPort>,
);
type OrderedEntry<T> = std::sync::Arc<ReplayingMemoEntry<T, crate::analyzer::ReadKey>>;
type OrderedMemo<K, V> =
    ReplayingMemo<std::cell::RefCell<std::collections::HashMap<K, OrderedEntry<V>>>>;

#[derive(Clone)]
struct CallBypass {
    exits: HashMap<ProgramPointId, (TypestateComposeFunction, HopQuality)>,
}

#[derive(Debug, Clone, Copy)]
pub struct OrderedEvent<'a> {
    pub point: ProgramPointId,
    pub ordinal: usize,
    pub event: &'a SemanticEvent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallPlacement {
    BeforeCall,
    AfterNormalReturn(ControlContinuation),
    AfterExceptionalReturn(ControlContinuation),
}

#[derive(Debug, Clone, Copy)]
pub struct OrderedCallStage<'a> {
    pub call: &'a SemanticCallSite,
    pub placement: CallPlacement,
}

/// All local rows needed to attach protocol events to a single procedure.
/// The caller owns `parts` only for this query, so no workspace-scale graph
/// survives the request.
#[derive(Debug)]
pub struct OrderedProcedure<'a> {
    pub events: Vec<OrderedEvent<'a>>,
    pub call_stages: Vec<OrderedCallStage<'a>>,
    pub edges: &'a [ControlEdge],
    pub drops: &'a [DropFact],
    pub moves: &'a [MoveOutFact],
}

pub fn project_ordered_procedure(parts: &ProcedureSemanticsParts) -> OrderedProcedure<'_> {
    let events = parts
        .points
        .iter()
        .flat_map(|point| {
            point
                .events
                .iter()
                .enumerate()
                .map(move |(ordinal, event)| OrderedEvent {
                    point: point.id,
                    ordinal,
                    event,
                })
        })
        .collect();
    let call_stages = parts
        .call_sites
        .iter()
        .flat_map(|call| {
            [
                CallPlacement::BeforeCall,
                CallPlacement::AfterNormalReturn(call.normal_continuation),
                CallPlacement::AfterExceptionalReturn(call.exceptional_continuation),
            ]
            .map(|placement| OrderedCallStage { call, placement })
        })
        .collect();
    OrderedProcedure {
        events,
        call_stages,
        edges: &parts.control_edges,
        drops: &parts.drops,
        moves: &parts.move_outs,
    }
}

/// Decoded procedure rows and demanded port relations for one policy query.
/// Neither map survives the query; the read ledger still records the whole
/// semantic artifact for each procedure read from the store.
pub struct TypestateOrderedRelations<'a> {
    workspace: &'a WorkspaceAnalyzer,
    discovery: std::rc::Rc<crate::composition::WorkspaceCompositionDiscovery<'a>>,
    attribution: OwnedMemoCapability,
    memo_budget: std::rc::Rc<CompositionMemoBudget>,
    protocol: &'a CompiledProtocol,
    subject: TypestateSubjectId,
    bindings: &'a TypestateBindingPlan,
    parts: OrderedMemo<DurableProcedureKey, Option<ProcedureSemanticsParts>>,
    inert_drops: OrderedMemo<DurableProcedureKey, bool>,
    bypasses: OrderedMemo<BypassKey, HashMap<ProgramPointId, CallBypass>>,
    relations: HashMap<
        (
            DurableProcedureKey,
            TypestateBindingContext,
            PartialFlowPort,
            PartialFlowPort,
        ),
        (TypestateComposeFunction, HopQuality),
    >,
}

pub(crate) struct OrderedHandoffQuery<'a> {
    pub call: &'a CallSiteHandle,
    pub dispatch: &'a SemanticOutcome<DispatchResult>,
    pub bindings: &'a CallBindings,
    pub candidate: &'a DispatchCandidate,
    pub subject: &'a BoundTypestateSubject,
    pub exit: CallHandoffExit,
    pub tracked_formal: Option<(&'a DurableProcedureKey, &'a PartialFlowPort)>,
}

pub(crate) struct OrderedHandoff {
    pub handoff: CallHandoff<TypestateComposeFunction>,
    pub mapping: CallSubjectMapping,
    pub discharge_eligible: bool,
}

impl<'a> TypestateOrderedRelations<'a> {
    fn inert_drops(
        &mut self,
        procedure: &ProcedureHandle,
        request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
    ) -> Result<bool, SemanticProviderError> {
        let key = procedure.durable_key();
        let entry = self.inert_drops.read(
            &self.attribution.capability(),
            |memo, capture| -> Result<_, SemanticProviderError> {
                if let Some(entry) = memo.borrow().get(&key).cloned() {
                    return Ok(entry);
                }
                let entry = capture.try_build_weighted(|| {
                    let inert = self
                        .workspace
                        .semantic_oracle_provider()
                        .procedure_drops_proven_inert(procedure, request)?;
                    Ok::<_, SemanticProviderError>((inert, std::mem::size_of::<bool>()))
                })?;
                Ok(admit_composition_entry(
                    memo,
                    &key,
                    entry,
                    &self.memo_budget,
                    request.stop_observed(),
                ))
            },
        )?;
        Ok(*entry)
    }

    fn parts(
        &self,
        procedure: &ProcedureHandle,
        request: Option<&crate::analyzer::semantic::SemanticRequest<'_>>,
    ) -> Result<
        brokk_bifrost_core::analyzer::memo_attribution::ReplayedMemoValue<
            Option<ProcedureSemanticsParts>,
            crate::analyzer::ReadKey,
        >,
        SemanticProviderError,
    > {
        let key = procedure.durable_key();
        self.parts.read(
            &self.attribution.capability(),
            |memo, capture| -> Result<_, SemanticProviderError> {
                if let Some(entry) = memo.borrow().get(&key).cloned() {
                    return Ok(entry);
                }
                let entry = capture.try_build_weighted(|| {
                    let parts = self.workspace.stored_semantic_ir_procedure(procedure)?;
                    let bytes = std::mem::size_of::<Option<ProcedureSemanticsParts>>()
                        + parts.as_ref().map_or(0, procedure_parts_retained_bytes);
                    Ok::<_, SemanticProviderError>((parts, bytes))
                })?;
                Ok(admit_composition_entry(
                    memo,
                    &key,
                    entry,
                    &self.memo_budget,
                    request.is_some_and(|request| request.stop_observed()),
                ))
            },
        )
    }

    pub(crate) fn new(
        workspace: &'a WorkspaceAnalyzer,
        discovery: std::rc::Rc<crate::composition::WorkspaceCompositionDiscovery<'a>>,
        protocol: &'a CompiledProtocol,
        bindings: &'a TypestateBindingPlan,
        subject: TypestateSubjectId,
        memo_budget: std::rc::Rc<CompositionMemoBudget>,
    ) -> Self {
        Self {
            workspace,
            discovery,
            attribution: workspace_memo_attribution(workspace),
            memo_budget,
            protocol,
            bindings,
            subject,
            parts: ReplayingMemo::new(std::cell::RefCell::new(std::collections::HashMap::new())),
            inert_drops: ReplayingMemo::new(std::cell::RefCell::new(
                std::collections::HashMap::new(),
            )),
            bypasses: ReplayingMemo::new(std::cell::RefCell::new(std::collections::HashMap::new())),
            relations: HashMap::default(),
        }
    }

    pub fn between_ports(
        &mut self,
        procedure: &ProcedureHandle,
        context: &TypestateBindingContext,
        from: &PartialFlowPort,
        to: &PartialFlowPort,
        request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
    ) -> Result<(TypestateComposeFunction, HopQuality), SemanticProviderError> {
        let inert_drops = self.inert_drops(procedure, request)?;
        let key = (
            procedure.durable_key(),
            context.clone(),
            from.clone(),
            to.clone(),
        );
        let parts_entry = self.parts(procedure, Some(request))?;
        let Some(parts) = parts_entry.as_ref() else {
            return Ok((
                TypestateComposeFunction::incomplete(TypestateUncertainty::IncompleteAnalysis),
                HopQuality::UNCERTAIN,
            ));
        };
        if let Some(relation) = self.relations.get(&key) {
            return Ok(relation.clone());
        }
        let mut solve = OrderedRelationCache::new(
            parts,
            procedure.clone(),
            context.clone(),
            self.bindings,
            self.protocol,
            self.subject,
            inert_drops,
        );
        let relation = solve.between_ports(from, to);
        if !request.stop_observed() {
            self.relations.insert(key, relation.clone());
        }
        Ok(relation)
    }

    /// Reachability of one local segment. A call point ends the segment;
    /// its continuation is entered only through a separate call handoff.
    pub fn locally_reaches(
        &mut self,
        procedure: &ProcedureHandle,
        from: &PartialFlowPort,
        to: &PartialFlowPort,
    ) -> Result<bool, SemanticProviderError> {
        let parts_entry = self.parts(procedure, None)?;
        let Some(parts) = parts_entry.as_ref() else {
            return Ok(false);
        };
        let solve = OrderedRelationCache::new(
            parts,
            procedure.clone(),
            TypestateBindingContext::root(),
            self.bindings,
            self.protocol,
            self.subject,
            false,
        );
        let (Some(start), Some(end)) = (solve.port_point(from), solve.port_point(to)) else {
            return Ok(false);
        };
        Ok(local_cfg_reaches(
            &parts.call_sites,
            &parts.control_edges,
            &HashMap::default(),
            start,
            end,
        ))
    }

    /// One object segment, stopping before any intervening call. An absent
    /// relation is not an incomplete path: the search enters the matching
    /// call continuation through its separate handoff.
    pub fn object_segment(
        &mut self,
        procedure: &ProcedureHandle,
        context: &TypestateBindingContext,
        tracked_formal: Option<&PartialFlowPort>,
        endpoints: (&Endpoint, &Endpoint),
        activation_edge: Option<&ControlEdgeHandle>,
        request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
    ) -> Result<Option<(TypestateComposeFunction, HopQuality)>, SemanticProviderError> {
        let (from, to) = endpoints;
        let inert_drops = self.inert_drops(procedure, request)?;
        let key = procedure.durable_key();
        let parts_entry = self.parts(procedure, Some(request))?;
        let Some(parts) = parts_entry.as_ref() else {
            return Ok(None);
        };
        let mut solve = OrderedRelationCache::new(
            parts,
            procedure.clone(),
            context.clone(),
            self.bindings,
            self.protocol,
            self.subject,
            inert_drops,
        );
        let bypass_key = (key.clone(), context.clone(), tracked_formal.cloned());
        let bypass_entry = self.bypasses.read(
            &self.attribution.capability(),
            |memo, capture| -> Result<_, SemanticProviderError> {
                if let Some(entry) = memo.borrow().get(&bypass_key).cloned() {
                    return Ok(entry);
                }
                let entry = capture.try_build_weighted(|| {
                    let computed = call_bypasses(
                        BypassQuery {
                            workspace: self.workspace,
                            discovery: self.discovery.as_ref(),
                            procedure,
                            parts,
                            context,
                            subject: self
                                .bindings
                                .subject(self.subject)
                                .expect("selected subject exists"),
                            subject_id: self.subject,
                            bindings: self.bindings,
                            protocol: self.protocol,
                            tracked_formal,
                        },
                        request,
                    )?;
                    let bytes = std::mem::size_of::<HashMap<ProgramPointId, CallBypass>>()
                        + computed.capacity() * std::mem::size_of::<(ProgramPointId, CallBypass)>()
                        + computed
                            .values()
                            .map(|bypass| {
                                bypass.exits.capacity()
                                    * std::mem::size_of::<(
                                        ProgramPointId,
                                        (TypestateComposeFunction, HopQuality),
                                    )>()
                            })
                            .sum::<usize>();
                    Ok::<_, SemanticProviderError>((computed, bytes))
                })?;
                Ok(admit_composition_entry(
                    memo,
                    &bypass_key,
                    entry,
                    &self.memo_budget,
                    request.stop_observed(),
                ))
            },
        )?;
        solve.call_bypasses = (*bypass_entry).clone();
        let point = |endpoint: &Endpoint| match endpoint {
            Endpoint::Port(port) => solve.port_point(port),
            Endpoint::Object(anchor) => match anchor.site {
                ObjectAnchorSite::ProgramPoint(point) => Some(point),
                ObjectAnchorSite::CallSite(call) => parts
                    .call_sites
                    .get(usize::try_from(call.get()).expect("call ID fits usize"))
                    .map(|site| site.point),
                ObjectAnchorSite::NormalExit => solve.port_point(&PartialFlowPort::NormalReturn),
                ObjectAnchorSite::ExceptionalExit => {
                    solve.port_point(&PartialFlowPort::ExceptionalReturn)
                }
            },
            _ => None,
        };
        let (Some(start), Some(end)) = (point(from), point(to)) else {
            return Ok(None);
        };
        let (start, activation_quality) = if let Some(edge) = activation_edge {
            let row = edge
                .procedure()
                .semantics()
                .control_edge(edge.id())
                .expect("validated activation edge resolves");
            assert_eq!(edge.procedure(), procedure);
            assert_eq!(start, row.source_point);
            let evidence = edge
                .procedure()
                .semantics()
                .evidence_row(row.evidence)
                .expect("validated activation edge has evidence");
            (
                row.target_point,
                HopQuality::new(
                    matches!(evidence.proof, ProofStatus::Proven),
                    matches!(evidence.completeness, EvidenceCompleteness::Complete),
                ),
            )
        } else {
            (start, HopQuality::CERTAIN)
        };
        if !local_cfg_reaches(
            &parts.call_sites,
            &parts.control_edges,
            &solve.call_bypasses,
            start,
            end,
        ) {
            return Ok(None);
        }
        let (mut function, quality) = solve.between(start, end);
        if !activation_quality.proven {
            function = TypestateComposeFunction::unproven_hop_loss().then(function);
        }
        let mut quality = activation_quality.conjoin(quality);
        if let Endpoint::Port(PartialFlowPort::CallResult { call, .. }) = from {
            let (stage, stage_quality) =
                solve.call_stage(*call, ProtocolObservationPhase::AfterNormalReturn);
            function = stage.then(function);
            quality = quality.conjoin(stage_quality);
        } else if let Endpoint::Port(PartialFlowPort::CallThrown { call }) = from {
            let (stage, stage_quality) =
                solve.call_stage(*call, ProtocolObservationPhase::AfterExceptionalReturn);
            function = stage.then(function);
            quality = quality.conjoin(stage_quality);
        }
        if let Endpoint::Port(
            PartialFlowPort::CallReceiver { call } | PartialFlowPort::CallArgument { call, .. },
        ) = to
        {
            let (stage, stage_quality) =
                solve.call_stage(*call, ProtocolObservationPhase::BeforeCall);
            function = function.then(stage);
            quality = quality.conjoin(stage_quality);
        }
        Ok(Some((function, quality)))
    }

    pub(crate) fn handoffs(
        &mut self,
        query: OrderedHandoffQuery<'_>,
        request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
    ) -> Result<Vec<OrderedHandoff>, SemanticProviderError> {
        let OrderedHandoffQuery {
            call,
            dispatch,
            bindings,
            candidate,
            subject,
            exit,
            tracked_formal,
        } = query;
        // Only a tracked formal of the procedure that makes this call is a
        // formal here.
        let current_formal = tracked_formal
            .and_then(|(owner, port)| (owner == &call.procedure().durable_key()).then_some(port));
        let mut reference_certified = std::collections::HashSet::new();
        let receiver_continuity_certified =
            if let Some(site) = call.procedure().semantics().call_site(call.id()) {
                if let Some(actual) = site.receiver {
                    selected_receiver_binding(
                        MoveBindingQuery {
                            discovery: self.discovery.as_ref(),
                            procedure: call.procedure(),
                            call: site,
                            context: bindings.context(),
                            subject,
                            tracked_formal: current_formal,
                            actual,
                        },
                        request,
                    )?
                } else {
                    CallObjectContinuity::Unknown
                }
            } else {
                CallObjectContinuity::Unknown
            };
        let site = call
            .procedure()
            .semantics()
            .call_site(call.id())
            .expect("a selected call is in its procedure");
        for binding in bindings.bindings() {
            let CallBinding::ArgumentGroup(group) = binding else {
                continue;
            };
            for mapping in group.mappings() {
                let actual = mapping.value().actual().value().id();
                if selected_reference_binding(
                    MoveBindingQuery {
                        discovery: self.discovery.as_ref(),
                        procedure: call.procedure(),
                        call: site,
                        context: bindings.context(),
                        subject,
                        tracked_formal: current_formal,
                        actual,
                    },
                    request,
                )? {
                    reference_certified.insert(actual);
                }
            }
        }
        let mut handoffs = Vec::new();
        for mut binding in crate::composition::project_call_handoffs(
            call,
            bindings,
            candidate,
            &reference_certified,
            receiver_continuity_certified,
        )
        .map_err(SemanticProviderError::internal)?
        .iter()
        .filter(|binding| binding.exit == exit)
        .cloned()
        {
            let (actual, formal) = candidate
                .arguments
                .get(binding.argument_index)
                .expect("a selected handoff indexes its candidate");
            if matches!(actual, PartialFlowPort::CallReceiver { .. }) {
                let mode = bindings
                    .callee()
                    .semantics()
                    .values()
                    .iter()
                    .find_map(|value| match value.kind {
                        SemanticValueKind::Receiver { mode, .. } => Some(mode),
                        _ => None,
                    });
                // The declaration chooses a proof; it does not supply one.
                // Unknown leaves other languages' existing receiver evidence.
                binding.continuity = match mode {
                    Some(
                        crate::analyzer::semantic::ReceiverMode::SharedBorrow
                        | crate::analyzer::semantic::ReceiverMode::MutableBorrow,
                    ) if binding.continuity == CallObjectContinuity::Reference => {
                        CallObjectContinuity::Reference
                    }
                    Some(crate::analyzer::semantic::ReceiverMode::Owned)
                        if binding.continuity == CallObjectContinuity::Move =>
                    {
                        CallObjectContinuity::Move
                    }
                    Some(crate::analyzer::semantic::ReceiverMode::Unknown) | None => {
                        binding.continuity
                    }
                    _ => CallObjectContinuity::Unknown,
                };
            }
            let site = call
                .procedure()
                .semantics()
                .call_site(call.id())
                .expect("a selected call is in its procedure");
            if binding.continuity == CallObjectContinuity::Unknown
                && matches!(actual, PartialFlowPort::CallArgument { .. })
                && let Some(value) =
                    crate::analyzer::semantic::partial_flow::call_input_value(site, actual)
                && selected_move_binding(
                    MoveBindingQuery {
                        discovery: self.discovery.as_ref(),
                        procedure: call.procedure(),
                        call: site,
                        context: bindings.context(),
                        subject,
                        tracked_formal: current_formal,
                        actual: value,
                    },
                    request,
                )?
            {
                binding.continuity = CallObjectContinuity::Move;
            }
            let object_map =
                crate::analyzer::semantic::partial_flow::call_input_value(site, actual)
                    .and_then(|value| call.procedure().value_handle(value))
                    .zip(call.procedure().point_handle(site.point))
                    .map(|(value, point)| {
                        ValueAtPoint::new(
                            value,
                            point,
                            ObservationPhase::BeforeEffects,
                            bindings.context().clone(),
                        )
                    })
                    .transpose()
                    .map_err(|error| SemanticProviderError::internal(error.to_string()))?;
            let points = match object_map.as_ref() {
                Some(query)
                    if !super::call_map::exact_formal_reborrow(query, actual, tracked_formal) =>
                {
                    Some(
                        self.workspace
                            .semantic_oracle_provider()
                            .pointees(query, request)?,
                    )
                }
                _ => None,
            };
            // The owned-origin shortcut is formal-only. A tracked formal owned
            // by another procedure refuses it; it never falls back to a
            // root-origin proof in selected_move_binding.
            let exact_owned_origin = match current_formal {
                Some(_)
                    if binding.continuity == CallObjectContinuity::Move
                        && matches!(actual, PartialFlowPort::CallReceiver { .. }) =>
                {
                    receiver_continuity_certified == CallObjectContinuity::Move
                }
                Some(formal)
                    if binding.continuity == CallObjectContinuity::Move
                        && matches!(actual, PartialFlowPort::CallArgument { .. }) =>
                {
                    if let Some(value) =
                        crate::analyzer::semantic::partial_flow::call_input_value(site, actual)
                    {
                        selected_move_binding(
                            MoveBindingQuery {
                                discovery: self.discovery.as_ref(),
                                procedure: call.procedure(),
                                call: site,
                                context: bindings.context(),
                                subject,
                                tracked_formal: Some(formal),
                                actual: value,
                            },
                            request,
                        )?
                    } else {
                        false
                    }
                }
                _ => false,
            };
            let discharge_eligible = binding.quality.is_certain()
                && binding.continuity == CallObjectContinuity::Reference;
            let mapping = call_subject_map(
                dispatch,
                bindings,
                CallSubjectMapSelection {
                    call: &call.durable_key(),
                    callee: &candidate.procedure,
                    context: bindings.context(),
                    port_query: object_map.as_ref(),
                    port_objects: points.as_ref().and_then(SemanticOutcome::available_value),
                    continuity: binding.continuity,
                    tracked_formal,
                    exact_owned_origin,
                },
                subject,
                actual,
                formal,
            );
            let (mut map_function, map_quality) = mapping.compose();
            if !binding.quality.proven {
                map_function = TypestateComposeFunction::unproven_hop_loss().then(map_function);
            }
            binding.quality = binding.quality.conjoin(map_quality);
            handoffs.push(OrderedHandoff {
                mapping,
                discharge_eligible,
                handoff: CallHandoff {
                    binding,
                    // The provider composes the callee through the shared search,
                    // including nested calls, after this subject map is known.
                    function: map_function,
                },
            });
        }
        Ok(handoffs)
    }
}

/// Demand-driven, query-lifetime local path relations for one procedure.
/// Repeated points and exhausted bounds yield an incomplete alternative, so
/// this solve never certifies a closed path after losing a possible arm.
pub struct OrderedRelationCache<'a> {
    parts: &'a ProcedureSemanticsParts,
    procedure: ProcedureHandle,
    context: TypestateBindingContext,
    bindings: &'a TypestateBindingPlan,
    protocol: &'a CompiledProtocol,
    subject: TypestateSubjectId,
    ordered: OrderedProcedure<'a>,
    inert_drops: bool,
    call_bypasses: HashMap<ProgramPointId, CallBypass>,
    relations: HashMap<(ProgramPointId, ProgramPointId), (TypestateComposeFunction, HopQuality)>,
}

impl<'a> OrderedRelationCache<'a> {
    pub fn new(
        parts: &'a ProcedureSemanticsParts,
        procedure: ProcedureHandle,
        context: TypestateBindingContext,
        bindings: &'a TypestateBindingPlan,
        protocol: &'a CompiledProtocol,
        subject: TypestateSubjectId,
        inert_drops: bool,
    ) -> Self {
        assert_eq!(
            parts.id,
            procedure.id(),
            "ordered rows and handle name one procedure"
        );
        Self {
            parts,
            procedure,
            context,
            bindings,
            protocol,
            subject,
            ordered: project_ordered_procedure(parts),
            inert_drops,
            call_bypasses: HashMap::default(),
            relations: HashMap::default(),
        }
    }

    fn port_point(&self, port: &PartialFlowPort) -> Option<ProgramPointId> {
        match port {
            PartialFlowPort::Receiver
            | PartialFlowPort::Parameter { .. }
            | PartialFlowPort::Capture { .. } => self
                .parts
                .points
                .iter()
                .find(|point| {
                    point
                        .events
                        .iter()
                        .any(|event| matches!(event.effect, SemanticEffect::Entry))
                })
                .map(|point| point.id),
            PartialFlowPort::NormalReturn | PartialFlowPort::IndexedNormalReturn { .. } => self
                .parts
                .points
                .iter()
                .find(|point| {
                    point
                        .events
                        .iter()
                        .any(|event| matches!(event.effect, SemanticEffect::NormalExit))
                })
                .map(|point| point.id),
            PartialFlowPort::ExceptionalReturn => self
                .parts
                .points
                .iter()
                .find(|point| {
                    point
                        .events
                        .iter()
                        .any(|event| matches!(event.effect, SemanticEffect::ExceptionalExit))
                })
                .map(|point| point.id),
            PartialFlowPort::CallReceiver { call } | PartialFlowPort::CallArgument { call, .. } => {
                self.parts
                    .call_sites
                    .get(usize::try_from(call.get()).expect("call ID fits usize"))
                    .map(|site| site.point)
            }
            PartialFlowPort::CallResult { call, .. } => self
                .parts
                .call_sites
                .get(usize::try_from(call.get()).expect("call ID fits usize"))?
                .normal_continuation
                .target(),
            PartialFlowPort::CallThrown { call } => self
                .parts
                .call_sites
                .get(usize::try_from(call.get()).expect("call ID fits usize"))?
                .exceptional_continuation
                .target(),
            PartialFlowPort::Heap { root, .. } => self.port_point(root),
            PartialFlowPort::CaptureOut { .. } => None,
        }
    }

    fn call_stage(
        &self,
        call_id: crate::analyzer::semantic::CallSiteId,
        phase: ProtocolObservationPhase,
    ) -> (TypestateComposeFunction, HopQuality) {
        let call = self
            .procedure
            .call_site_handle(call_id)
            .expect("a projected call port names its procedure's call");
        let mut events: Vec<_> = self
            .bindings
            .event_bindings_at_call_site_all_contexts(&call)
            .filter(|binding| {
                binding.subject() == self.subject
                    && binding.site().context() == &self.context
                    && self.protocol.event(binding.event()).is_some_and(|event| {
                        event.observation().occurrence
                            == ProtocolEventOccurrence::Endpoint { phase }
                    })
            })
            .collect();
        events.sort_unstable_by_key(|event| (event.order(), event.id()));
        let mut uncertain = false;
        let steps = events
            .into_iter()
            .map(|event| {
                if event.condition().is_some() {
                    uncertain = true;
                    TypestateComposeStep::Incomplete(TypestateUncertainty::IncompleteAnalysis)
                } else {
                    TypestateComposeStep::Event(event.id())
                }
            })
            .collect();
        (
            TypestateComposeFunction::choice([steps]),
            HopQuality::from_uncertain(uncertain),
        )
    }

    pub fn between_ports(
        &mut self,
        from: &PartialFlowPort,
        to: &PartialFlowPort,
    ) -> (TypestateComposeFunction, HopQuality) {
        match (self.port_point(from), self.port_point(to)) {
            (Some(from_point), Some(to_point)) => {
                let (mut function, mut quality) = self.between(from_point, to_point);
                if let PartialFlowPort::CallResult { call, .. } = from {
                    let (stage, stage_quality) =
                        self.call_stage(*call, ProtocolObservationPhase::AfterNormalReturn);
                    function = stage.then(function);
                    quality = quality.conjoin(stage_quality);
                } else if let PartialFlowPort::CallThrown { call } = from {
                    let (stage, stage_quality) =
                        self.call_stage(*call, ProtocolObservationPhase::AfterExceptionalReturn);
                    function = stage.then(function);
                    quality = quality.conjoin(stage_quality);
                }
                if let PartialFlowPort::CallReceiver { call }
                | PartialFlowPort::CallArgument { call, .. } = to
                {
                    let (stage, stage_quality) =
                        self.call_stage(*call, ProtocolObservationPhase::BeforeCall);
                    function = function.then(stage);
                    quality = quality.conjoin(stage_quality);
                }
                (function, quality)
            }
            _ => (
                TypestateComposeFunction::incomplete(TypestateUncertainty::IncompleteAnalysis),
                HopQuality::UNCERTAIN,
            ),
        }
    }

    pub fn between(
        &mut self,
        from: ProgramPointId,
        to: ProgramPointId,
    ) -> (TypestateComposeFunction, HopQuality) {
        if let Some(cached) = self.relations.get(&(from, to)) {
            return cached.clone();
        }
        assert!(self.procedure.point_handle(from).is_some());
        assert!(self.procedure.point_handle(to).is_some());

        struct Path {
            point: ProgramPointId,
            seen: Vec<ProgramPointId>,
            function: TypestateComposeFunction,
        }

        let mut pending = vec![Path {
            point: from,
            seen: Vec::new(),
            function: TypestateComposeFunction::identity(),
        }];
        let mut paths = Vec::new();
        let mut incomplete = false;
        let mut visits = 0;
        while let Some(mut path) = pending.pop() {
            visits += 1;
            if visits > MAX_LOCAL_VISITS || paths.len() >= MAX_LOCAL_PATHS {
                incomplete = true;
                break;
            }
            if path.seen.contains(&path.point) {
                incomplete = true;
                continue;
            }
            path.seen.push(path.point);
            let handle = self
                .procedure
                .point_handle(path.point)
                .expect("an edge of one procedure names its point");
            let mut events: Vec<_> = self
                .bindings
                .event_bindings_at_program_point_all_contexts(&handle)
                .filter(|event| {
                    event.subject() == self.subject && event.site().context() == &self.context
                })
                .collect();
            events.sort_unstable_by_key(|event| (event.order(), event.id()));
            for event in events {
                if event.condition().is_some() {
                    incomplete = true;
                    path.function = path.function.then(TypestateComposeFunction::incomplete(
                        TypestateUncertainty::IncompleteAnalysis,
                    ));
                } else {
                    path.function = path
                        .function
                        .then(TypestateComposeFunction::event(event.id()));
                }
            }
            if (!self.inert_drops
                && self
                    .ordered
                    .drops
                    .iter()
                    .any(|drop| drop.point == path.point))
                || self
                    .ordered
                    .moves
                    .iter()
                    .any(|moved| moved.point == path.point)
            {
                incomplete = true;
                path.function = path.function.then(TypestateComposeFunction::incomplete(
                    TypestateUncertainty::IncompleteAnalysis,
                ));
            }
            if path.point == to {
                paths.push(path.function);
                continue;
            }
            if self.ordered.call_stages.iter().any(|stage| {
                stage.call.point == path.point && stage.placement == CallPlacement::BeforeCall
            }) {
                let Some(_) = self.call_bypasses.get(&path.point) else {
                    // An exact object handoff owns this call boundary.
                    continue;
                };
            }
            for edge in self
                .ordered
                .edges
                .iter()
                .filter(|edge| edge.source_point == path.point)
            {
                let mut function = path.function.clone();
                if let Some(bypass) = self.call_bypasses.get(&path.point) {
                    let Some((effect, quality)) = bypass.exits.get(&edge.target_point) else {
                        continue;
                    };
                    function = function.then(effect.clone());
                    if !quality.is_certain() {
                        incomplete = true;
                        function = function.then(TypestateComposeFunction::incomplete(
                            TypestateUncertainty::IncompleteAnalysis,
                        ));
                    }
                }
                pending.push(Path {
                    point: edge.target_point,
                    seen: path.seen.clone(),
                    function,
                });
            }
        }
        incomplete |= paths.is_empty();
        if incomplete {
            paths.push(TypestateComposeFunction::incomplete(
                TypestateUncertainty::IncompleteAnalysis,
            ));
        }
        let result = (
            TypestateComposeFunction::choice_functions(paths),
            HopQuality::from_uncertain(incomplete),
        );
        self.relations.insert((from, to), result.clone());
        result
    }
}

fn local_cfg_reaches(
    calls: &[SemanticCallSite],
    edges: &[ControlEdge],
    bypasses: &HashMap<ProgramPointId, CallBypass>,
    start: ProgramPointId,
    end: ProgramPointId,
) -> bool {
    let mut pending = vec![start];
    let mut seen = std::collections::HashSet::new();
    let call_points: std::collections::HashSet<_> = calls.iter().map(|call| call.point).collect();
    while let Some(point) = pending.pop() {
        if !seen.insert(point) {
            continue;
        }
        if point == end {
            return true;
        }
        if call_points.contains(&point) && !bypasses.contains_key(&point) {
            continue;
        }
        pending.extend(
            edges
                .iter()
                .filter(|edge| edge.source_point == point)
                .map(|edge| edge.target_point),
        );
    }
    false
}

/// The selected return class is independent of this ordinary call boundary.
/// This certificate also requires one unconverted local read of an effectively
/// immutable binding initialized exactly once from that return value.
fn root_result_move_into_actual(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    context: &crate::analyzer::semantic::OracleCallContext,
    subject: &BoundTypestateSubject,
    actual: crate::analyzer::semantic::ValueId,
    request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
) -> Result<bool, SemanticProviderError> {
    use crate::analyzer::semantic::{AccessPathRoot, ValueFlowKind};
    let AccessPathRoot::CallResult(root) = subject.object().identity() else {
        return Ok(false);
    };
    if root.result().procedure() != procedure
        || root.caller_context() != context
        || procedure.artifact().key().language()
            != crate::analyzer::LanguageDialect::Standard(crate::analyzer::Language::Rust)
    {
        return Ok(false);
    }
    let semantics = procedure.semantics();
    // Both origin scans below read the complete procedure event inventory.
    // Charge it before scanning; a refused or cancelled read cannot certify
    // a move and must not become a stable query-local proof.
    if request.cancellation.is_cancelled() {
        return Ok(false);
    }
    let event_count = semantics
        .points()
        .iter()
        .map(|point| point.events.len())
        .fold(0usize, usize::saturating_add);
    let work = crate::analyzer::semantic::SemanticWork {
        events: event_count.saturating_mul(2),
        ..Default::default()
    };
    if request.budget.check_admission(work).is_err() {
        return Ok(false);
    }
    request.budget.charge_work(work);
    let mut reads = semantics
        .points()
        .iter()
        .flat_map(|point| &point.events)
        .filter_map(|event| match event.effect {
            SemanticEffect::ValueFlow {
                kind,
                source,
                target,
            } if target == actual => Some((kind, source, event.evidence)),
            _ => None,
        });
    let Some((kind, local, evidence)) = reads.next() else {
        return Ok(false);
    };
    if kind != ValueFlowKind::Local
        || !semantics
            .evidence_row(evidence)
            .is_some_and(|e| e.proof.establishes_complete_evidence(&e.completeness))
        || reads.next().is_some()
        || !semantics
            .value(local)
            .is_some_and(|value| value.kind == SemanticValueKind::Local)
    {
        return Ok(false);
    }
    let mut writes = semantics.points().iter().flat_map(|point| &point.events)
        .filter(|event| matches!(event.effect, SemanticEffect::Assignment { target, .. } if target == local));
    let Some(write) = writes.next() else {
        return Ok(false);
    };
    if writes.next().is_some()
        || !matches!(write.effect, SemanticEffect::Assignment { value, .. } if value == root.result().id())
        || !semantics
            .evidence_row(write.evidence)
            .is_some_and(|e| e.proof.establishes_complete_evidence(&e.completeness))
    {
        return Ok(false);
    }
    let Some(support) =
        crate::analyzer::languages::language_support(crate::analyzer::Language::Rust)
    else {
        return Ok(false);
    };
    if request.cancellation.is_cancelled() || request.budget.refusal_count() > 0 {
        return Ok(false);
    }
    Ok(
        support.ownership_class_of_call_result(workspace, root.callee(), request)?
            == crate::analyzer::languages::SelectedCallResultOwnership::Move,
    )
}

/// A formal-entry summary may consume its own formal, independently of any
/// caller. A single filtered Parameter edge is insufficient: inspect every
/// origin of the actual and every write to the formal before accepting it.
fn formal_ownership_into_actual(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    tracked_formal: Option<&PartialFlowPort>,
    actual: crate::analyzer::semantic::ValueId,
    request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
) -> Result<Option<crate::analyzer::languages::SelectedCallResultOwnership>, SemanticProviderError>
{
    use crate::analyzer::semantic::{SemanticIncompleteSubject, ValueFlowKind};
    let Some(PartialFlowPort::Parameter { ordinal }) = tracked_formal else {
        return Ok(None);
    };
    let language = procedure.artifact().key().language().language();
    let semantics = procedure.semantics();
    let mut formals = semantics.values().iter().filter(|value| {
        matches!(value.kind, SemanticValueKind::Parameter {
            ordinal: candidate,
            multiplicity: crate::analyzer::semantic::FormalMultiplicity::One,
            ..
        } if candidate == *ordinal)
    });
    let Some(formal) = formals.next() else {
        return Ok(None);
    };
    if formals.next().is_some() || request.stop_observed() {
        return Ok(None);
    }
    let event_count = semantics
        .points()
        .iter()
        .map(|point| point.events.len())
        .fold(0usize, usize::saturating_add);
    let work = crate::analyzer::semantic::SemanticWork {
        events: event_count.saturating_add(semantics.incomplete_facts().len()),
        ..Default::default()
    };
    if request.budget.check_admission(work).is_err() {
        return Ok(None);
    }
    request.budget.charge_work(work);
    let mut origin = None;
    let mut origin_count = 0;
    let mut formal_write = false;
    for event in semantics.points().iter().flat_map(|point| &point.events) {
        match event.effect {
            SemanticEffect::ValueFlow { target, .. }
            | SemanticEffect::Assignment { target, .. }
                if target == actual =>
            {
                origin_count += 1;
                origin = Some(event);
            }
            _ => {}
        }
        formal_write |= matches!(event.effect,
            SemanticEffect::Assignment { target, .. } if target == formal.id);
    }
    let Some(origin) = origin else {
        return Ok(None);
    };
    if origin_count != 1
        || !matches!(origin.effect, SemanticEffect::ValueFlow {
            kind: ValueFlowKind::Parameter,
            source,
            target,
        } if source == formal.id && target == actual)
        || !semantics
            .evidence_row(origin.evidence)
            .is_some_and(|evidence| {
                evidence
                    .proof
                    .establishes_complete_evidence(&evidence.completeness)
            })
        || formal_write
        || semantics
            .incomplete_facts()
            .iter()
            .any(|fact| match fact.subject {
                SemanticIncompleteSubject::Procedure => true,
                SemanticIncompleteSubject::Value(value) => value == actual,
                _ => false,
            })
    {
        return Ok(None);
    }
    let Some(support) = crate::analyzer::languages::language_support(language) else {
        return Ok(None);
    };
    let class =
        support.ownership_class_of_formal(workspace, procedure, *ordinal, actual, request)?;
    Ok((!request.stop_observed()).then_some(class))
}

pub(crate) struct MoveBindingQuery<'a, 'w> {
    pub(crate) discovery: &'a crate::composition::WorkspaceCompositionDiscovery<'w>,
    pub(crate) procedure: &'a ProcedureHandle,
    pub(crate) call: &'a SemanticCallSite,
    pub(crate) context: &'a crate::analyzer::semantic::OracleCallContext,
    pub(crate) subject: &'a BoundTypestateSubject,
    pub(crate) tracked_formal: Option<&'a PartialFlowPort>,
    pub(crate) actual: crate::analyzer::semantic::ValueId,
}

fn selected_move_binding(
    query: MoveBindingQuery<'_, '_>,
    request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
) -> Result<bool, SemanticProviderError> {
    let MoveBindingQuery {
        discovery,
        procedure,
        call,
        context,
        subject,
        tracked_formal,
        actual,
    } = query;
    let Some(site) = procedure.call_site_handle(call.id) else {
        return Ok(false);
    };
    let dispatch = discovery.resolve_call(&site, request)?;
    let Some(targets) = dispatch.available_value() else {
        return Ok(false);
    };
    let [target] = targets.candidates() else {
        return Ok(false);
    };
    let bindings = discovery.call_bindings(&site, target, context, request)?;
    let Some(selected) = bindings.available_value() else {
        return Ok(false);
    };
    if selected.context() != context
        || !exact_selected_value_binding(&dispatch, &bindings, selected, &site, actual, |_| true)
    {
        return Ok(false);
    }
    let formal_identity = if let Some(PartialFlowPort::Parameter { ordinal }) = tracked_formal {
        let Some(mapping) = selected.bindings().iter().find_map(|binding| {
            let CallBinding::ArgumentGroup(group) = binding else {
                return None;
            };
            group
                .mappings()
                .iter()
                .find(|mapping| mapping.value().actual().value().id() == actual)
                .map(|mapping| mapping.value())
        }) else {
            return Ok(false);
        };
        let crate::analyzer::semantic::ProcedurePortKind::Parameter {
            ordinal: target_ordinal,
        } = mapping.formal().kind()
        else {
            return Ok(false);
        };
        if !matches!(mapping.conversion(), Some(Ok(None))) {
            // A recorded nonidentity or failed conversion cannot be replaced
            // by a type-level certificate about an ordinary bare formal.
            if mapping.conversion().is_some() {
                return Ok(false);
            }
            let Some(support) =
                crate::analyzer::languages::language_support(crate::analyzer::Language::Rust)
            else {
                return Ok(false);
            };
            if support.identity_conversion_between_formals(
                discovery.workspace(),
                procedure,
                *ordinal,
                mapping.formal().procedure(),
                target_ordinal,
                request,
            )? != crate::analyzer::languages::SelectedIdentityConversion::Identity
                || request.stop_observed()
            {
                return Ok(false);
            }
        }
        true
    } else {
        // The root-result path retains its established conversion predicate.
        exact_selected_value_binding(&dispatch, &bindings, selected, &site, actual, |mapping| {
            mapping.preserves_reference_identity()
        })
    };
    if !formal_identity {
        return Ok(false);
    }
    move_origin_into_actual(
        discovery.workspace(),
        procedure,
        context,
        subject,
        tracked_formal,
        actual,
        request,
    )
}

/// One selected Value-mode reference handoff. Source shape, destination
/// shape, whole-value conversion, and the evaluated referent are separate.
fn selected_reference_binding(
    query: MoveBindingQuery<'_, '_>,
    request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
) -> Result<bool, SemanticProviderError> {
    let MoveBindingQuery {
        discovery,
        procedure,
        call,
        context,
        subject,
        tracked_formal,
        actual,
    } = query;
    if call.invocation_mode != crate::analyzer::semantic::CallInvocationMode::Ordinary
        || !call.execution_timing.is_synchronous()
        || call.receiver == Some(actual)
        || call
            .arguments
            .iter()
            .filter(|argument| argument.value == actual)
            .count()
            != 1
        || context.was_truncated()
        || !subject.quality().is_definitive()
        || crate::composition::moved_into_call(procedure, call, actual)
        || request.stop_observed()
    {
        return Ok(false);
    }
    let Some(site) = procedure.call_site_handle(call.id) else {
        return Ok(false);
    };
    let dispatch = discovery.resolve_call(&site, request)?;
    let Some(targets) = dispatch.available_value() else {
        return Ok(false);
    };
    let [target] = targets.candidates() else {
        return Ok(false);
    };
    let bindings = discovery.call_bindings(&site, target, context, request)?;
    let Some(selected) = bindings.available_value() else {
        return Ok(false);
    };
    if selected.context() != context
        || !exact_selected_value_binding(&dispatch, &bindings, selected, &site, actual, |_| true)
    {
        return Ok(false);
    }
    let mut mappings = selected.bindings().iter().filter_map(|binding| {
        let CallBinding::ArgumentGroup(group) = binding else {
            return None;
        };
        group
            .mappings()
            .iter()
            .find(|mapping| mapping.value().actual().value().id() == actual)
            .map(|mapping| mapping.value())
    });
    let Some(mapping) = mappings.next() else {
        return Ok(false);
    };
    if mappings.next().is_some() {
        return Ok(false);
    }
    let crate::analyzer::semantic::ProcedurePortKind::Parameter {
        ordinal: target_ordinal,
    } = mapping.formal().kind()
    else {
        return Ok(false);
    };
    let Some(support) = crate::analyzer::languages::language_support(
        procedure.artifact().key().language().language(),
    ) else {
        return Ok(false);
    };
    // A successful typed mapping may supply this premise. Go currently has
    // no such producer, so its selected formal-to-formal hook must prove it.
    let (source_identity, modeled_formal_reference) = if let Some(PartialFlowPort::Parameter {
        ordinal,
    }) = tracked_formal
    {
        let conversion = match mapping.conversion() {
            Some(Ok(None)) => true,
            None => {
                support.identity_conversion_between_formals(
                    discovery.workspace(),
                    procedure,
                    *ordinal,
                    mapping.formal().procedure(),
                    target_ordinal,
                    request,
                )? == crate::analyzer::languages::SelectedIdentityConversion::Identity
            }
            _ => false,
        };
        (
            conversion
                && formal_ownership_into_actual(
                    discovery.workspace(),
                    procedure,
                    tracked_formal,
                    actual,
                    request,
                )? == Some(crate::analyzer::languages::SelectedCallResultOwnership::Reference),
            false,
        )
    } else {
        let Some(origin) = selected_call_result_origin(
            discovery, procedure, call, context, subject, actual, request,
        )?
        else {
            return Ok(false);
        };
        // Go's direct pointer annotation is a category and conversion proof;
        // the evaluated instance is checked independently below.
        let preserves_reference_identity = mapping.preserves_reference_identity();
        match origin {
            SelectedCallResultOrigin::Local { callee, ordinal } => (
                preserves_reference_identity
                    && support.identity_conversion_from_call_result(
                        discovery.workspace(),
                        &callee,
                        ordinal,
                        mapping.formal().procedure(),
                        target_ordinal,
                        request,
                    )? == crate::analyzer::languages::SelectedIdentityConversion::Identity,
                false,
            ),
            SelectedCallResultOrigin::Modeled(external) => {
                let joined = preserves_reference_identity
                    && support.identity_conversion_from_modeled_call_result(
                        discovery.workspace(),
                        &external,
                        mapping.formal().procedure(),
                        target_ordinal,
                        request,
                    )? == crate::analyzer::languages::SelectedIdentityConversion::Identity;
                (joined, joined)
            }
        }
    };
    if !source_identity
        || (!modeled_formal_reference
            && support.ownership_class_of_formal(
                discovery.workspace(),
                mapping.formal().procedure(),
                target_ordinal,
                actual,
                request,
            )? != crate::analyzer::languages::SelectedCallResultOwnership::Reference)
        || request.stop_observed()
    {
        return Ok(false);
    }
    exact_call_actual_pointee(
        discovery, procedure, call, context, subject, actual, request,
    )
}

/// A conservative closed origin chain. Requiring one writer globally for
/// each link is stronger than requiring one reaching writer at this call: it
/// rejects joins and loops without treating an unseen path as an identity
/// copy. Assignment rows must have their matching affirmative Local flow.
enum SelectedCallResultOrigin {
    Local { callee: ProcedureHandle, ordinal: u32 },
    Modeled(Box<brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::heap::ModeledFreshCallResultOrigin>),
}

enum SelectedCallResultCandidate {
    Local(ProcedureHandle),
    Modeled(Box<brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::heap::ModeledFreshCallResultOrigin>),
}

fn identity_preserving_origin_edge(
    kind: crate::analyzer::semantic::ValueFlowKind,
    static_reference_result: bool,
) -> bool {
    matches!(kind, crate::analyzer::semantic::ValueFlowKind::Local)
        || (matches!(
            kind,
            crate::analyzer::semantic::ValueFlowKind::ByValueCapture
        ) && static_reference_result)
}

fn selected_call_result_origin(
    discovery: &crate::composition::WorkspaceCompositionDiscovery<'_>,
    procedure: &ProcedureHandle,
    call: &SemanticCallSite,
    context: &crate::analyzer::semantic::OracleCallContext,
    subject: &BoundTypestateSubject,
    actual: crate::analyzer::semantic::ValueId,
    request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
) -> Result<Option<SelectedCallResultOrigin>, SemanticProviderError> {
    use crate::analyzer::semantic::{
        AccessPathRoot, SemanticGapImpact, SemanticGapSubject, SemanticIncompleteSubject,
    };
    let modeled_value = match subject.object().identity() {
        AccessPathRoot::Value(value) if value.procedure() == procedure => Some(value.clone()),
        AccessPathRoot::Allocation(allocation) if allocation.procedure() == procedure => procedure
            .semantics()
            .allocation(allocation.id())
            .and_then(|row| procedure.value_handle(row.result)),
        _ => None,
    };
    let (producer_call, result, origin) = match subject.object().identity() {
        AccessPathRoot::CallResult(root) => {
            if root.result().procedure() != procedure
                || root.caller_context() != context
                || !root.binding_relation().record().is_proven_complete()
                || root.return_relations().is_empty()
                || !root.return_relations().iter().all(|relation| {
                    relation.proof == ProofStatus::Proven
                        && relation.completeness == EvidenceCompleteness::Complete
                })
            {
                return Ok(None);
            }
            (
                root.call().clone(),
                root.result().clone(),
                SelectedCallResultCandidate::Local(root.callee().clone()),
            )
        }
        _ if modeled_value.is_some() => {
            let value = modeled_value.expect("matched modeled result root has a value");
            let mut calls = procedure.semantics().call_sites().iter().filter(|site| {
                site.normal_result_values()
                    .any(|result| result == value.id())
            });
            let (Some(site), None) = (calls.next(), calls.next()) else {
                return Ok(None);
            };
            let Some(call_handle) = procedure.call_site_handle(site.id) else {
                return Ok(None);
            };
            let Some(witness) = discovery.modeled_fresh_call_result_origin(
                &call_handle,
                &value,
                context,
                request,
            )?
            else {
                return Ok(None);
            };
            if witness.call != call_handle
                || witness.result != value
                || &witness.caller_context != context
            {
                return Ok(None);
            }
            (
                call_handle,
                value,
                SelectedCallResultCandidate::Modeled(Box::new(witness)),
            )
        }
        _ => return Ok(None),
    };
    let producer = procedure
        .semantics()
        .call_site(producer_call.id())
        .expect("a call-result root names a call in its procedure");
    let Some(ordinal) = producer
        .normal_result_values()
        .position(|value| value == result.id())
        .and_then(|ordinal| u32::try_from(ordinal).ok())
    else {
        return Ok(None);
    };
    if producer.id == call.id
        || !matches!(producer.normal_continuation, ControlContinuation::Target(_))
        || !producer.execution_timing.is_synchronous()
    {
        return Ok(None);
    }
    // The selected Fresh witness can carry only this producer's call-target
    // refinement question to the joined language proof below. It does not
    // answer any other artifact gap or change the local-callee path.
    let modeled_origin_authority = match &origin {
        SelectedCallResultCandidate::Modeled(witness) => {
            witness.call == producer_call
                && witness.call.procedure() == procedure
                && witness.result == result
                && witness.result.procedure() == procedure
                && witness.ordinal == ordinal
                && &witness.caller_context == context
                && witness.proves_complete_fresh_result()
                && witness.dispatch.is_complete()
                && witness.dispatch.available_value().is_some_and(|selected| {
                    selected.coverage() == CandidateCoverage::Exhaustive
                        && selected.candidates().is_empty()
                        && matches!(selected.boundaries(), [boundary]
                            if boundary.unmaterialized_external_target() == Some(&witness.target)
                                && boundary.proof == ProofStatus::Proven)
                })
                && !request.stop_observed()
        }
        SelectedCallResultCandidate::Local(_) => false,
    };
    // Prove local dispatch and its normal-return binding before deciding
    // whether that same call's target-refinement gap is still open.
    let origin = match origin {
        SelectedCallResultCandidate::Local(callee) => {
            let dispatch = discovery.resolve_call(&producer_call, request)?;
            let Some(targets) = dispatch.available_value() else {
                return Ok(None);
            };
            let [target] = targets.candidates() else {
                return Ok(None);
            };
            let bindings = discovery.call_bindings(&producer_call, target, context, request)?;
            let Some(selected) = bindings.available_value() else {
                return Ok(None);
            };
            if selected.context() != context
                || !exact_selected_call_binding(&dispatch, &bindings, selected, &producer_call)
                || selected.callee() != &callee
                || !selected.bindings().iter().any(|binding| {
                    matches!(binding,
                    CallBinding::NormalReturn { relation, result: bound, .. }
                        if bound.id() == result.id()
                            && relation.record().is_proven_complete())
                })
            {
                return Ok(None);
            }
            SelectedCallResultOrigin::Local { callee, ordinal }
        }
        SelectedCallResultCandidate::Modeled(witness) => {
            if witness.ordinal != ordinal {
                return Ok(None);
            }
            SelectedCallResultOrigin::Modeled(witness)
        }
    };
    if procedure.semantics().gaps().iter().any(|gap| {
        (gap.impacts.contains(crate::analyzer::semantic::SemanticGapImpact::ReturnTransfer)
            || gap.impacts.contains(crate::analyzer::semantic::SemanticGapImpact::CallEvaluation)
            || gap.impacts.contains(crate::analyzer::semantic::SemanticGapImpact::ValueFlow))
            && matches!(gap.subject,
                crate::analyzer::semantic::SemanticGapSubject::CallSite(id)
                    | crate::analyzer::semantic::SemanticGapSubject::CallContinuation { call_site: id, .. }
                    if id == producer.id)
            && !((modeled_origin_authority || matches!(&origin, SelectedCallResultOrigin::Local { .. }))
                && matches!(gap.kind,
                    crate::analyzer::semantic::SemanticGapKind::Unknown
                        | crate::analyzer::semantic::SemanticGapKind::Unproven)
                && crate::analyzer::semantic::workspace_oracle::call_target_refinement_call(
                    procedure.semantics(), gap,
                ) == Some(producer.id))
    }) {
        return Ok(None);
    }
    let semantics = procedure.semantics();
    // A deferred by-value capture freezes its source at registration. A later
    // write cannot change that copy unless control can reach registration again.
    let mut capture_points = semantics.points().iter().filter(|point| {
        point.events.iter().any(|event| {
            matches!(event.effect,
                SemanticEffect::ValueFlow { target, .. }
                    if target == actual && semantics.value(target).is_some_and(|value|
                        value.kind.is_language_defined("go.defer_capture")))
        })
    });
    let capture_point = capture_points.next().map(|point| point.id);
    if capture_points.next().is_some() {
        return Ok(None);
    }
    // Only a deferred by-value capture of `actual` asks the language to prove
    // its static type. Every other call-result origin skips that proof, its
    // reads and its execution dependence.
    let static_reference_result = match capture_point.and_then(|_| {
        crate::analyzer::languages::language_support(
            procedure.artifact().key().language().language(),
        )
    }) {
        Some(support) => support.captured_value_static_type_is_reference(
            discovery.workspace(),
            procedure,
            actual,
            result.id(),
            request,
        )?,
        None => false,
    };
    let capture_predecessors = if let Some(point) = capture_point {
        use crate::analyzer::semantic::cfg_algorithms::{
            CfgAlgorithmBudget, CfgAlgorithmRequest, reverse_reachability,
        };
        let reach_work = crate::analyzer::semantic::SemanticWork {
            program_points: semantics.points().len(),
            control_edges: semantics.control_edges().len(),
            ..Default::default()
        };
        if request.budget.check_admission(reach_work).is_err() {
            return Ok(None);
        }
        request.budget.charge_work(reach_work);
        let mut budget = CfgAlgorithmBudget::default();
        let Ok(reaching) = reverse_reachability(
            semantics,
            point,
            &mut CfgAlgorithmRequest::new(&mut budget, request.cancellation),
        ) else {
            return Ok(None);
        };
        Some(reaching)
    } else {
        None
    };
    let reaches_capture = |point| {
        capture_predecessors
            .as_ref()
            .is_none_or(|reaching| reaching.contains(semantics, point))
    };
    // Writer discovery and reaching definitions matter only for a
    // deferred capture; without one every write is admitted below.
    let mut by_event = std::collections::HashMap::new();
    let mut reaching_writes = std::collections::HashSet::new();
    if let Some(capture) = capture_point {
        // A point can precede registration while its earlier writes have been
        // overwritten. Follow possible value-flow sources, then track writes of
        // just those values across CFG edges.
        let discovery_work = crate::analyzer::semantic::SemanticWork {
            events: semantics
                .points()
                .iter()
                .map(|point| point.events.len())
                .sum(),
            ..Default::default()
        };
        if request.budget.check_admission(discovery_work).is_err() {
            return Ok(None);
        }
        request.budget.charge_work(discovery_work);
        let mut sources = std::collections::HashMap::<_, Vec<_>>::new();
        for point in semantics.points() {
            for event in &point.events {
                if let SemanticEffect::ValueFlow { source, target, .. } = event.effect {
                    sources.entry(target).or_default().push(source);
                }
            }
        }
        let mut walked_values = std::collections::HashSet::from([actual]);
        let mut pending = vec![actual];
        while let Some(value) = pending.pop() {
            for &source in sources.get(&value).into_iter().flatten() {
                if walked_values.insert(source) {
                    pending.push(source);
                }
            }
        }
        let mut writes = Vec::new();
        let mut by_value = std::collections::HashMap::<_, Vec<usize>>::new();
        for point in semantics.points() {
            for (index, event) in point.events.iter().enumerate() {
                let target = match event.effect {
                    SemanticEffect::Assignment { target, .. }
                    | SemanticEffect::ValueFlow { target, .. } => Some(target),
                    SemanticEffect::MemoryLoad { result, .. } => Some(result),
                    _ => None,
                };
                if let Some(target) = target.filter(|target| walked_values.contains(target)) {
                    let id = writes.len();
                    writes.push((point.id, index, target));
                    by_value.entry(target).or_default().push(id);
                    by_event.insert((point.id, index), id);
                }
            }
        }
        use crate::analyzer::semantic::cfg_algorithms::{
            CfgAlgorithmBudget, CfgAlgorithmRequest, GenKillFacts, reaching_definitions,
        };
        let words = semantics
            .points()
            .len()
            .saturating_mul(writes.len().div_ceil(64));
        let preparation = crate::analyzer::semantic::SemanticWork {
            events: writes.len().saturating_add(words.saturating_mul(4)),
            ..Default::default()
        };
        if request.budget.check_admission(preparation).is_err() {
            return Ok(None);
        }
        request.budget.charge_work(preparation);
        let mut facts = GenKillFacts::new(semantics.points().len(), writes.len());
        for point in semantics.points() {
            let mut last = std::collections::HashMap::new();
            for (index, _) in point.events.iter().enumerate() {
                if let Some(&id) = by_event.get(&(point.id, index)) {
                    last.insert(writes[id].2, id);
                }
            }
            for (value, id) in last {
                for &old in &by_value[&value] {
                    facts.record_killed(point.id.index(), old);
                }
                facts.record_generated(point.id.index(), id);
            }
        }
        let mut budget = CfgAlgorithmBudget::default();
        let Ok(reaching) = reaching_definitions(
            semantics,
            semantics.entry_point(),
            &facts,
            &mut CfgAlgorithmRequest::new(&mut budget, request.cancellation),
        ) else {
            return Ok(None);
        };
        let used = budget.used();
        let solve_work = crate::analyzer::semantic::SemanticWork {
            program_points: used.node_visits,
            control_edges: used.edge_visits,
            ..Default::default()
        };
        if request.budget.check_admission(solve_work).is_err() {
            return Ok(None);
        }
        request.budget.charge_work(solve_work);
        reaching_writes.extend(reaching.reaching_in(capture.index()));
        let capture_row = semantics.point(capture).expect("capture point exists");
        let capture_event = capture_row
            .events
            .iter()
            .position(|event| {
                matches!(event.effect, SemanticEffect::ValueFlow { target, .. }
                    if target == actual && semantics.value(target).is_some_and(|value|
                        value.kind.is_language_defined("go.defer_capture")))
            })
            .expect("capture point has capture event");
        for index in 0..=capture_event {
            if let Some(&id) = by_event.get(&(capture, index)) {
                reaching_writes.retain(|old| writes[*old].2 != writes[id].2);
                reaching_writes.insert(id);
            }
        }
        // Assignment and its immediately paired flow form one write. Both
        // events must be checked when that flow is the reaching definition.
        for &id in &reaching_writes.clone() {
            let (point, index, target) = writes[id];
            if index > 0
                && let Some(&previous) = by_event.get(&(point, index - 1))
                && writes[previous].2 == target
                && matches!(
                    semantics.point(point).unwrap().events[index - 1].effect,
                    SemanticEffect::Assignment { .. }
                )
            {
                reaching_writes.insert(previous);
            }
        }
    }
    let reaches_write = |point, index| {
        capture_point.is_none()
            || by_event
                .get(&(point, index))
                .is_some_and(|id| reaching_writes.contains(id))
    };
    let event_count = semantics
        .points()
        .iter()
        .map(|point| point.events.len())
        .sum::<usize>();
    let work = crate::analyzer::semantic::SemanticWork {
        events: semantics
            .incomplete_facts()
            .len()
            .saturating_add(semantics.gaps().len()),
        ..Default::default()
    };
    if request.budget.check_admission(work).is_err() {
        return Ok(None);
    }
    request.budget.charge_work(work);
    let mut accepted_conversions = std::collections::HashSet::new();
    let mut checked_conversions = std::collections::HashSet::new();
    if let SelectedCallResultOrigin::Local { callee, ordinal } = &origin {
        for point in semantics.points() {
            if !reaches_capture(point.id) {
                continue;
            }
            for event in &point.events {
                if let SemanticEffect::ValueFlow {
                    kind: crate::analyzer::semantic::ValueFlowKind::LanguageDefined,
                    source,
                    target: converted,
                } = &event.effect
                {
                    if *source != result.id()
                        || !checked_conversions.insert(*converted)
                        || !semantics.value(*converted).is_some_and(|value| {
                            matches!(&value.kind,
                            crate::analyzer::semantic::SemanticValueKind::LanguageDefined(name)
                            if name.as_ref() == "go.assignment_conversion")
                        })
                    {
                        continue;
                    }
                    let mut targets = semantics
                        .points()
                        .iter()
                        .flat_map(|point| point.events.iter())
                        .filter_map(|event| match event.effect {
                            SemanticEffect::ValueFlow {
                                kind: crate::analyzer::semantic::ValueFlowKind::Local,
                                source,
                                target,
                            } if source == *converted => Some(target),
                            _ => None,
                        });
                    if let (Some(target), None) = (targets.next(), targets.next())
                        && let Some(support) = crate::analyzer::languages::language_support(
                            procedure.artifact().key().language().language(),
                        )
                        && support.assignment_conversion_preserves_identity(
                            discovery.workspace(),
                            procedure,
                            *converted,
                            target,
                            callee,
                            *ordinal,
                            request,
                        )?
                    {
                        accepted_conversions.insert((result.id(), *converted));
                    }
                }
            }
        }
    }
    let mut current = actual;
    let mut seen = std::collections::HashSet::new();
    loop {
        if !seen.insert(current) || request.stop_observed() {
            return Ok(None);
        }
        if semantics.incomplete_facts().iter().any(|fact| matches!(fact.subject,
            SemanticIncompleteSubject::Procedure)
            || matches!(fact.subject, SemanticIncompleteSubject::Value(value) if value == current))
            || semantics.gaps().iter().any(|gap| {
                (gap.impacts.contains(SemanticGapImpact::ValueFlow)
                    || gap.impacts.contains(SemanticGapImpact::CallEvaluation)
                    || gap.impacts.contains(SemanticGapImpact::ReturnTransfer))
                    && (matches!(gap.subject, SemanticGapSubject::Procedure)
                        || matches!(gap.subject, SemanticGapSubject::Value(value) if value == current)
                        || matches!(gap.subject, SemanticGapSubject::Point))
            })
        {
            return Ok(None);
        }
        let scan = crate::analyzer::semantic::SemanticWork {
            events: event_count,
            ..Default::default()
        };
        if request.budget.check_admission(scan).is_err() {
            return Ok(None);
        }
        request.budget.charge_work(scan);
        let mut source = None;
        let mut flow_count = 0;
        for point in semantics.points() {
            if !reaches_capture(point.id) {
                continue;
            }
            for (index, event) in point.events.iter().enumerate() {
                if matches!(
                    event.effect,
                    SemanticEffect::Assignment { .. }
                        | SemanticEffect::ValueFlow { .. }
                        | SemanticEffect::MemoryLoad { .. }
                ) && !reaches_write(point.id, index)
                {
                    continue;
                }
                let complete = semantics
                    .evidence_row(event.evidence)
                    .is_some_and(|evidence| {
                        evidence
                            .proof
                            .establishes_complete_evidence(&evidence.completeness)
                    });
                match event.effect {
                    SemanticEffect::ValueFlow {
                        kind,
                        source: value,
                        target,
                    } if target == current
                        && complete
                        && (identity_preserving_origin_edge(kind, static_reference_result)
                            || accepted_conversions.contains(&(value, target))) =>
                    {
                        flow_count += 1;
                        source = Some(value);
                    }
                    SemanticEffect::Assignment { target, value } if target == current => {
                        let paired = point.events.get(index + 1).is_some_and(|next| {
                            matches!(next.effect, SemanticEffect::ValueFlow {
                                kind, source, target: t
                            } if source == value && t == target
                                && identity_preserving_origin_edge(kind, static_reference_result))
                        });
                        if !complete || !paired {
                            return Ok(None);
                        }
                    }
                    SemanticEffect::ValueFlow { target, .. } if target == current => {
                        return Ok(None);
                    }
                    SemanticEffect::MemoryLoad { result, .. } if result == current => {
                        return Ok(None);
                    }
                    _ => {}
                }
            }
        }
        if current == result.id() {
            if flow_count != 0 || source.is_some() {
                return Ok(None);
            }
            break;
        }
        if flow_count != 1 {
            return Ok(None);
        }
        current = source.expect("one whole identity flow has a source");
    }
    if let SelectedCallResultOrigin::Local { .. } = &origin {
        // The walk answers with one value id. The rows it counted while
        // following edges are scratch and must not stay on the ledger (#10530).
        let mark = request.budget.scratch_mark();
        let closed = crate::analyzer::semantic::closed_value_origin_at_capture(
            procedure,
            actual,
            |value| value == result.id(),
            |kind, source, target| {
                if identity_preserving_origin_edge(*kind, static_reference_result)
                    || accepted_conversions.contains(&(source, target))
                {
                    crate::analyzer::semantic::ClosedOriginEdge::Follow
                } else {
                    crate::analyzer::semantic::ClosedOriginEdge::Refuse
                }
            },
            reaches_write,
            request.cancellation,
            |work| {
                request.budget.admit(work).map_err(
                    crate::analyzer::semantic::workspace_oracle::common::Interruption::Budget,
                )
            },
        )
        .ok()
        .flatten();
        request.budget.release_scratch_since(&mark);
        if closed != Some(result.id()) {
            return Ok(None);
        }
    }
    Ok((!request.stop_observed()).then_some(origin))
}

/// One selected receiver and its written actual share a single certificate
/// across handoff projection and bypass. The selected adjustment determines
/// which object continuity proof is required at this call and context.
fn selected_receiver_binding(
    query: MoveBindingQuery<'_, '_>,
    request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
) -> Result<CallObjectContinuity, SemanticProviderError> {
    use crate::analyzer::semantic::{MemberReceiverPreparation as Preparation, ReceiverMode};
    use CallObjectContinuity::{Move, Reference, Unknown};
    let MoveBindingQuery {
        discovery,
        procedure,
        call,
        context,
        subject,
        tracked_formal,
        actual,
    } = query;
    if call.receiver != Some(actual)
        || call.invocation_mode != crate::analyzer::semantic::CallInvocationMode::Ordinary
        || !call.execution_timing.is_synchronous()
        || context.was_truncated()
        || !subject.quality().is_definitive()
        || request.stop_observed()
    {
        return Ok(Unknown);
    }
    let Some(site) = procedure.call_site_handle(call.id) else {
        return Ok(Unknown);
    };
    let dispatch = discovery.resolve_call(&site, request)?;
    let Some(targets) = dispatch.available_value() else {
        return Ok(Unknown);
    };
    let [target] = targets.candidates() else {
        return Ok(Unknown);
    };
    let bindings = discovery.call_bindings(&site, target, context, request)?;
    let Some(selected) = bindings.available_value() else {
        return Ok(Unknown);
    };
    let language = procedure.artifact().key().language().language();
    let preparation = target.member_receiver_preparation();
    if selected.context() != context
        || !exact_selected_call_binding(&dispatch, &bindings, selected, &site)
        || target.receiver_owner_relation()
            != crate::analyzer::semantic::ReceiverOwnerRelation::Direct
    {
        return Ok(Unknown);
    }
    let mut receivers = selected.bindings().iter().filter_map(|binding| {
        let CallBinding::Receiver {
            relation,
            actual: bound,
            formal,
        } = binding
        else {
            return None;
        };
        (bound.id() == actual
            && relation.record().is_proven_complete()
            && formal.kind() == crate::analyzer::semantic::ProcedurePortKind::Receiver)
            .then_some(formal)
    });
    let Some(formal) = receivers.next() else {
        return Ok(Unknown);
    };
    if receivers.next().is_some() {
        return Ok(Unknown);
    }
    let Some(support) = crate::analyzer::languages::language_support(language) else {
        return Ok(Unknown);
    };
    if request.stop_observed() {
        return Ok(Unknown);
    }
    let declared_mode = selected
        .callee()
        .semantics()
        .values()
        .iter()
        .find_map(|value| match value.kind {
            SemanticValueKind::Receiver { mode, .. } => Some(mode),
            _ => None,
        });
    match preparation {
        Some(Preparation::Reference | Preparation::AddressOfPlace) => {
            if language == crate::analyzer::Language::Rust {
                if declared_mode != Some(ReceiverMode::SharedBorrow)
                    || (preparation == Some(Preparation::AddressOfPlace)
                        && !rust_written_receiver_is_place(procedure, actual, request))
                {
                    return Ok(Unknown);
                }
            } else if !support.selected_method_has_pointer_receiver(
                discovery.workspace(),
                formal.procedure(),
                request,
            )? || (preparation == Some(Preparation::AddressOfPlace)
                && !procedure
                    .semantics()
                    .value(actual)
                    .is_some_and(|value| value.kind == SemanticValueKind::Address))
            {
                return Ok(Unknown);
            }
            Ok(
                if exact_call_actual_pointee(
                    discovery, procedure, call, context, subject, actual, request,
                )? {
                    Reference
                } else {
                    Unknown
                },
            )
        }
        Some(Preparation::ByValue)
            if language == crate::analyzer::Language::Rust
                && declared_mode == Some(ReceiverMode::Owned) =>
        {
            // The existing selected-origin proof follows one unconverted
            // receiver-place read and requires the source type's Copy absence.
            Ok(
                if move_origin_into_actual(
                    discovery.workspace(),
                    procedure,
                    context,
                    subject,
                    tracked_formal,
                    actual,
                    request,
                )? && !request.stop_observed()
                {
                    Move
                } else {
                    Unknown
                },
            )
        }
        _ => Ok(Unknown),
    }
}

/// Identify a consumed Rust receiver for an authored after-return event.
/// The same selected handoff and subject map used by composition must prove
/// the exact pre-call object in this query's call context.
pub fn selected_owned_receiver_event_object(
    discovery: &crate::composition::WorkspaceCompositionDiscovery<'_>,
    procedure: &ProcedureHandle,
    call: &CallSiteHandle,
    context: &crate::analyzer::semantic::OracleCallContext,
    request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
) -> Result<
    Option<(
        crate::analyzer::semantic::AbstractObject,
        TypestateBindingQuality,
    )>,
    SemanticProviderError,
> {
    if procedure.artifact().key().language()
        != crate::analyzer::LanguageDialect::Standard(crate::analyzer::Language::Rust)
    {
        return Ok(None);
    }
    let site = procedure
        .semantics()
        .call_site(call.id())
        .expect("selected receiver event names a call");
    let Some(actual) = site.receiver else {
        return Ok(None);
    };
    let observation = ValueAtPoint::new(
        procedure.value_handle(actual).expect("receiver is a value"),
        procedure
            .point_handle(site.point)
            .expect("call has a point"),
        ObservationPhase::BeforeEffects,
        context.clone(),
    )
    .expect("receiver and point share a procedure");
    let points = discovery
        .workspace()
        .semantic_oracle_provider()
        .pointees(&observation, request)?;
    let Some(result) = points.available_value() else {
        return Ok(None);
    };
    let [candidate] = result.objects().candidates() else {
        return Ok(None);
    };
    if !points.is_complete()
        || result.objects().coverage() != CandidateCoverage::Exhaustive
        || !candidate.is_proven_complete()
        || request.stop_observed()
    {
        return Ok(None);
    }
    let quality = TypestateBindingQuality::new(
        candidate.proof().clone(),
        candidate.completeness().clone(),
        TypestateBindingMultiplicity::new(CandidateCoverage::Exhaustive, 1)
            .expect("one exact receiver object has valid multiplicity"),
    );
    let subject =
        BoundTypestateSubject::receiver_event_probe(candidate.value().clone(), quality.clone());
    if selected_receiver_binding(
        MoveBindingQuery {
            discovery,
            procedure,
            call: site,
            context,
            subject: &subject,
            tracked_formal: None,
            actual,
        },
        request,
    )? != CallObjectContinuity::Move
    {
        return Ok(None);
    }
    let dispatch = discovery.resolve_call(call, request)?;
    let Some(targets) = dispatch.available_value() else {
        return Ok(None);
    };
    let [target] = targets.candidates() else {
        return Ok(None);
    };
    let binding_outcome = discovery.call_bindings(call, target, context, request)?;
    let Some(bindings) = binding_outcome.available_value() else {
        return Ok(None);
    };
    if !exact_selected_call_binding(&dispatch, &binding_outcome, bindings, call) {
        return Ok(None);
    }
    let from = PartialFlowPort::CallReceiver { call: call.id() };
    let to = PartialFlowPort::Receiver;
    let call_key = call.durable_key();
    let callee_key = bindings.callee().durable_key();
    let (_, map_quality) = call_subject_map(
        &dispatch,
        bindings,
        CallSubjectMapSelection {
            call: &call_key,
            callee: &callee_key,
            context,
            port_query: Some(&observation),
            port_objects: Some(result),
            continuity: CallObjectContinuity::Move,
            tracked_formal: None,
            exact_owned_origin: false,
        },
        &subject,
        &from,
        &to,
    )
    .compose();
    Ok((map_quality.is_certain() && !request.stop_observed())
        .then_some((candidate.value().clone(), quality)))
}

/// An autoref uses the written operand's place. The exact pointee proof below
/// establishes the object; this association establishes that the operand was
/// a proven place read rather than a temporary or an unrecorded conversion.
fn rust_written_receiver_is_place(
    procedure: &ProcedureHandle,
    actual: crate::analyzer::semantic::ValueId,
    request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
) -> bool {
    use crate::analyzer::semantic::ValueFlowKind;
    let semantics = procedure.semantics();
    let work = crate::analyzer::semantic::SemanticWork {
        events: semantics
            .points()
            .iter()
            .map(|point| point.events.len())
            .sum(),
        ..Default::default()
    };
    if request.budget.check_admission(work).is_err() {
        return false;
    }
    request.budget.charge_work(work);
    let mut associations = semantics
        .points()
        .iter()
        .flat_map(|point| &point.events)
        .filter(|event| {
            matches!(event.effect,
            SemanticEffect::ValueFlow { target, .. }
                | SemanticEffect::Assignment { target, .. } if target == actual)
        });
    let Some(association) = associations.next() else {
        return false;
    };
    associations.next().is_none()
        && matches!(association.effect,
            SemanticEffect::ValueFlow { kind: ValueFlowKind::Local | ValueFlowKind::Parameter | ValueFlowKind::Receiver, source, target }
                if target == actual && semantics.value(source).is_some_and(|value|
                    matches!(value.kind, SemanticValueKind::Local | SemanticValueKind::Parameter { .. } | SemanticValueKind::Receiver { .. })))
        && semantics
            .evidence_row(association.evidence)
            .is_some_and(|evidence| {
                evidence
                    .proof
                    .establishes_complete_evidence(&evidence.completeness)
            })
        && !request.stop_observed()
}

fn exact_call_actual_pointee(
    discovery: &crate::composition::WorkspaceCompositionDiscovery<'_>,
    procedure: &ProcedureHandle,
    call: &SemanticCallSite,
    context: &crate::analyzer::semantic::OracleCallContext,
    subject: &BoundTypestateSubject,
    actual: crate::analyzer::semantic::ValueId,
    request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
) -> Result<bool, SemanticProviderError> {
    let observation = ValueAtPoint::new(
        procedure
            .value_handle(actual)
            .expect("selected call actual is a value"),
        procedure
            .point_handle(call.point)
            .expect("selected call point exists"),
        ObservationPhase::BeforeEffects,
        context.clone(),
    )
    .expect("selected call actual and point share a procedure");
    let Ok(Some(expected)) =
        crate::analyzer::semantic::workspace_oracle::heap::rehome_object_at_point(
            subject.object().clone(),
            &observation,
        )
    else {
        return Ok(false);
    };
    let points = discovery
        .workspace()
        .semantic_oracle_provider()
        .pointees(&observation, request)?;
    let Some(objects) = points.available_value().map(|points| points.objects()) else {
        return Ok(false);
    };
    Ok(points.is_complete()
        && objects.coverage() == CandidateCoverage::Exhaustive
        && matches!(objects.candidates(), [object]
            if object.is_proven_complete()
                && object.value() == &expected)
        && !request.stop_observed())
}

fn exact_selected_value_binding(
    dispatch: &crate::analyzer::semantic::SemanticOutcome<DispatchResult>,
    binding_outcome: &crate::analyzer::semantic::SemanticOutcome<CallBindings>,
    bindings: &CallBindings,
    call: &CallSiteHandle,
    actual: crate::analyzer::semantic::ValueId,
    identity_conversion: impl Fn(&crate::analyzer::semantic::CallArgumentMapping) -> bool,
) -> bool {
    if !exact_selected_call_binding(dispatch, binding_outcome, bindings, call) {
        return false;
    }
    let mut matches = 0;
    for binding in bindings.bindings() {
        let CallBinding::ArgumentGroup(group) = binding else {
            continue;
        };
        for mapping in group.mappings() {
            if mapping.value().actual().value().id() != actual {
                continue;
            }
            if !group.coverage().is_exhaustive()
                || !group.closure_relation().record().is_proven_complete()
                || !mapping.is_proven_complete()
                || mapping.value().member() != &crate::analyzer::semantic::CallArgumentMember::Whole
                || mapping.value().mode() != crate::analyzer::semantic::CallPassingMode::Value
                || !identity_conversion(mapping.value())
            {
                return false;
            }
            matches += 1;
        }
    }
    matches == 1
}

pub(crate) fn exact_selected_call_binding(
    dispatch: &crate::analyzer::semantic::SemanticOutcome<DispatchResult>,
    binding_outcome: &crate::analyzer::semantic::SemanticOutcome<CallBindings>,
    bindings: &CallBindings,
    call: &CallSiteHandle,
) -> bool {
    let Some(targets) = dispatch.available_value() else {
        return false;
    };
    let [target] = targets.candidates() else {
        return false;
    };
    if !dispatch.is_complete()
        || targets.coverage() != CandidateCoverage::Exhaustive
        || !targets.boundaries().is_empty()
        || target.proof() != &ProofStatus::Proven
        || target.completeness() != &EvidenceCompleteness::Complete
        || !binding_outcome.is_complete()
        || bindings.coverage() != CandidateCoverage::Exhaustive
        || bindings.call() != call
        || bindings.candidate() != target
    {
        return false;
    }
    true
}

fn move_origin_into_actual(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    context: &crate::analyzer::semantic::OracleCallContext,
    subject: &BoundTypestateSubject,
    tracked_formal: Option<&PartialFlowPort>,
    actual: crate::analyzer::semantic::ValueId,
    request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
) -> Result<bool, SemanticProviderError> {
    if let Some(formal) = tracked_formal {
        Ok(
            formal_ownership_into_actual(workspace, procedure, Some(formal), actual, request)?
                == Some(crate::analyzer::languages::SelectedCallResultOwnership::Move),
        )
    } else {
        root_result_move_into_actual(workspace, procedure, context, subject, actual, request)
    }
}

/// Calls without an exact object handoff leave the object in the caller.
/// A formal-entry summary cannot certify disjointness from another formal;
/// that caller-specific fact is deliberately absent from the summary.
struct BypassQuery<'a, 'w> {
    workspace: &'a WorkspaceAnalyzer,
    discovery: &'a crate::composition::WorkspaceCompositionDiscovery<'w>,
    procedure: &'a ProcedureHandle,
    parts: &'a ProcedureSemanticsParts,
    context: &'a TypestateBindingContext,
    subject: &'a BoundTypestateSubject,
    subject_id: TypestateSubjectId,
    bindings: &'a TypestateBindingPlan,
    protocol: &'a CompiledProtocol,
    tracked_formal: Option<&'a PartialFlowPort>,
}

pub(crate) fn exact_parameter_origin(
    procedure: &ProcedureHandle,
    actual: crate::analyzer::semantic::ValueId,
) -> Option<u32> {
    match procedure.semantics().value(actual)?.kind {
        SemanticValueKind::Parameter { ordinal, .. } => Some(ordinal),
        _ => None,
    }
}

fn guarded_local_bypass(
    query: &BypassQuery<'_, '_>,
    call: &SemanticCallSite,
    request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
) -> Result<Option<CallBypass>, SemanticProviderError> {
    macro_rules! reject {
        ($reason:expr) => {{ return Ok(None) }};
    }
    let Some(
        first @ PartialFlowPort::Parameter {
            ordinal: first_ordinal,
        },
    ) = query.tracked_formal
    else {
        reject!("not parameter");
    };
    let Some(site) = query.procedure.call_site_handle(call.id) else {
        reject!("no call handle");
    };
    let dispatch = query.discovery.resolve_call(&site, request)?;
    let Some(targets) = dispatch.available_value() else {
        reject!("no dispatch")
    };
    let [target] = targets.candidates() else {
        reject!("not unique dispatch")
    };
    let bindings_outcome =
        query
            .discovery
            .call_bindings(&site, target, query.context.runtime(), request)?;
    let Some(selected) = bindings_outcome.available_value() else {
        reject!("no bindings")
    };
    if !exact_selected_call_binding(&dispatch, &bindings_outcome, selected, &site) {
        reject!("inexact selected bindings");
    }
    let candidate = crate::composition::composition_candidate(
        &site,
        target.target().durable_key(),
        selected,
        None,
        None,
        None,
    )
    .map_err(SemanticProviderError::internal)?;
    let handoffs = crate::composition::project_call_handoffs(
        &site,
        selected,
        &candidate,
        &std::collections::HashSet::new(),
        CallObjectContinuity::Unknown,
    )
    .map_err(SemanticProviderError::internal)?;
    let mut exits: HashMap<_, (TypestateComposeFunction, HopQuality)> =
        [call.normal_continuation, call.exceptional_continuation]
            .into_iter()
            .filter_map(|continuation| continuation.target())
            .map(|point| {
                (
                    point,
                    (TypestateComposeFunction::identity(), HopQuality::CERTAIN),
                )
            })
            .collect();
    if exits.is_empty() {
        reject!("no exits")
    }
    let mut saw_interference = false;
    for (port, actual) in call
        .receiver
        .into_iter()
        .map(|value| (PartialFlowPort::CallReceiver { call: call.id }, value))
        .chain(call.arguments.iter().enumerate().map(|(index, argument)| {
            (
                PartialFlowPort::CallArgument {
                    call: call.id,
                    ordinal: u32::try_from(index).expect("call argument index fits u32"),
                },
                argument.value,
            )
        }))
    {
        let origin = if let Some(ordinal) = exact_parameter_origin(query.procedure, actual) {
            Some(ordinal)
        } else if let PartialFlowPort::CallArgument { ordinal, .. } = port {
            let language = query.procedure.artifact().key().language().language();
            match crate::analyzer::languages::language_support_for_hook(
                language,
                "direct_formal_referent_at_call",
            ) {
                Some(support) => support.direct_formal_referent_at_call(
                    query.workspace,
                    query.procedure,
                    call,
                    ordinal,
                    request,
                )?,
                None => None,
            }
        } else {
            None
        };
        let Some(ordinal) = origin else {
            reject!("not exact second formal")
        };
        if ordinal == *first_ordinal {
            reject!("first formal passed")
        }
        let mut selected_handoffs = handoffs.iter().filter(|handoff| {
            candidate
                .arguments
                .get(handoff.argument_index)
                .is_some_and(|(bound, _)| bound == &port)
        });
        let Some(handoff) = selected_handoffs.next() else {
            reject!("no selected handoff")
        };
        if selected_handoffs.any(|other| other.argument_index != handoff.argument_index)
            || handoff.continuity != CallObjectContinuity::Reference
            || !handoff.quality.is_certain()
        {
            reject!("inexact reference handoff");
        }
        let mut events = query
            .bindings
            .event_templates_at_call_site_all_contexts(&site)
            .filter(|event| {
                event.site().context() == query.context
                    && event.subject() == query.subject_id
                    && event.selected_operand().is_some_and(|selected| {
                        selected.call() == &site
                            && selected.partial_flow_port() == port
                            && selected.selected_target() == Some(&candidate.procedure)
                    })
            })
            .filter(|event| {
                query.protocol.event(event.event()).is_some_and(|event| {
                    matches!(
                        event.observation().occurrence,
                        ProtocolEventOccurrence::Endpoint { .. }
                    )
                })
            });
        let Some(event) = events.next() else {
            reject!("no selected local event")
        };
        if events.next().is_some() || event.condition().is_some() {
            reject!("ambiguous or conditional event")
        }
        let ProtocolEventOccurrence::Endpoint { phase } = query
            .protocol
            .event(event.event())
            .expect("bound event exists in the protocol")
            .observation()
            .occurrence
        else {
            unreachable!();
        };
        if phase == ProtocolObservationPhase::AtMatch {
            reject!("at-match event")
        }
        let second = PartialFlowPort::Parameter { ordinal };
        let guard = TypestateAliasGuard::new(query.procedure.durable_key(), first.clone(), second);
        let alias = TypestateComposeFunction::event(event.id());
        for (point, (function, _)) in &mut exits {
            let applies = match phase {
                ProtocolObservationPhase::BeforeCall => true,
                ProtocolObservationPhase::AfterNormalReturn => {
                    Some(*point) == call.normal_continuation.target()
                }
                ProtocolObservationPhase::AfterExceptionalReturn => {
                    Some(*point) == call.exceptional_continuation.target()
                }
                ProtocolObservationPhase::AtMatch => {
                    unreachable!("at-match events do not enter a call bypass")
                }
            };
            *function = function.clone().then(TypestateComposeFunction::guarded(
                guard.clone(),
                TypestateComposeFunction::identity(),
                if applies {
                    alias.clone()
                } else {
                    TypestateComposeFunction::identity()
                },
            ));
        }
        saw_interference = true;
    }
    Ok(saw_interference.then_some(CallBypass { exits }))
}

/// Return (exact subject transport, proven disjointness) for a call input.
/// Unknown aliases establish neither property.
pub(crate) fn call_actual_continuity(
    workspace: &WorkspaceAnalyzer,
    query: MoveBindingQuery<'_, '_>,
    request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
) -> Result<(bool, bool), SemanticProviderError> {
    let MoveBindingQuery {
        discovery,
        procedure,
        call,
        context,
        subject,
        tracked_formal,
        actual,
    } = query;
    let formal_value = match tracked_formal {
        Some(PartialFlowPort::Parameter { ordinal }) => procedure.semantics().values().iter()
            .find_map(|value| matches!(value.kind, SemanticValueKind::Parameter { ordinal: actual, .. } if actual == *ordinal).then_some(value.id)),
        _ => None,
    };
    let oracle = workspace.semantic_oracle_provider();
    let selected_receiver_witness_required = crate::analyzer::languages::language_support(
        procedure.artifact().key().language().language(),
    )
    .is_some_and(|support| support.requires_selected_receiver_witness());
    if call.receiver == Some(actual)
        && selected_receiver_binding(
            MoveBindingQuery {
                discovery,
                procedure,
                call,
                context,
                subject,
                tracked_formal,
                actual,
            },
            request,
        )? != CallObjectContinuity::Unknown
    {
        return Ok((true, false));
    }
    let mut value = actual;
    let address = procedure
        .semantics()
        .value(actual)
        .is_some_and(|row| row.kind == SemanticValueKind::Address)
        && !(call.receiver == Some(actual) && selected_receiver_witness_required);
    if address {
        let mut associations = procedure.semantics().points().iter()
                    .flat_map(|point| &point.events)
                    .filter(|event| matches!(event.effect, SemanticEffect::Assignment { target, .. } if target == actual));
        match (associations.next(), associations.next()) {
            (Some(event), None)
                if procedure
                    .semantics()
                    .evidence_row(event.evidence)
                    .is_some_and(|evidence| {
                        evidence
                            .proof
                            .establishes_complete_evidence(&evidence.completeness)
                    }) =>
            {
                let SemanticEffect::Assignment { value: source, .. } = event.effect else {
                    unreachable!()
                };
                value = source;
            }
            _ => {
                return Ok((false, false));
            }
        }
    }
    if formal_value == Some(value)
        && (address
            || selected_reference_binding(
                MoveBindingQuery {
                    discovery,
                    procedure,
                    call,
                    context,
                    subject,
                    tracked_formal,
                    actual,
                },
                request,
            )?
            || selected_move_binding(
                MoveBindingQuery {
                    discovery,
                    procedure,
                    call,
                    context,
                    subject,
                    tracked_formal,
                    actual,
                },
                request,
            )?)
    {
        return Ok((true, false));
    }
    if selected_reference_binding(
        MoveBindingQuery {
            discovery,
            procedure,
            call,
            context,
            subject,
            tracked_formal,
            actual,
        },
        request,
    )? {
        return Ok((true, false));
    }
    if tracked_formal.is_some()
        && selected_move_binding(
            MoveBindingQuery {
                discovery,
                procedure,
                call,
                context,
                subject,
                tracked_formal,
                actual,
            },
            request,
        )?
    {
        // A whole temporary with one exact Parameter origin moves the
        // tracked formal too; direct ValueId equality is not required.
        return Ok((true, false));
    }
    if tracked_formal.is_some() {
        return Ok((false, false));
    }
    let observation = ValueAtPoint::new(
        procedure
            .value_handle(value)
            .expect("call actual is a procedure value"),
        procedure
            .point_handle(call.point)
            .expect("call point belongs to procedure"),
        ObservationPhase::BeforeEffects,
        context.clone(),
    )
    .expect("call actual and point share a procedure");
    let answer = oracle.pointees(&observation, request)?;
    let Some(points) = answer.available_value() else {
        return Ok((false, false));
    };
    let objects = points.objects();
    if !answer.is_complete()
        || objects.coverage() != CandidateCoverage::Exhaustive
        || !objects
            .candidates()
            .iter()
            .all(|candidate| candidate.is_proven_complete())
    {
        return Ok((false, false));
    }
    if matches!(objects.candidates(), [candidate] if candidate.value() == subject.object()) {
        // A singleton allocation site does not establish object continuity:
        // passing a Copy value creates a distinct object at that site.
        if address
            || (tracked_formal.is_none()
                && crate::composition::moved_into_call(procedure, call, actual))
            || selected_move_binding(
                MoveBindingQuery {
                    discovery,
                    procedure,
                    call,
                    context,
                    subject,
                    tracked_formal,
                    actual,
                },
                request,
            )?
        {
            return Ok((true, false));
        }
        return Ok((false, false));
    }
    Ok((
        false,
        objects
            .candidates()
            .iter()
            .all(|candidate| candidate.value() != subject.object()),
    ))
}

fn call_bypasses(
    query: BypassQuery<'_, '_>,
    request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
) -> Result<HashMap<ProgramPointId, CallBypass>, SemanticProviderError> {
    let BypassQuery {
        workspace,
        discovery,
        procedure,
        parts,
        context,
        subject,
        subject_id,
        bindings,
        protocol,
        tracked_formal,
    } = query;
    let mut bypasses = HashMap::default();
    for call in &parts.call_sites {
        let mut disjoint = true;
        let mut exact_handoff = false;
        for actual in call
            .receiver
            .into_iter()
            .chain(call.arguments.iter().map(|argument| argument.value))
        {
            let (exact, separate) = call_actual_continuity(
                workspace,
                MoveBindingQuery {
                    discovery,
                    procedure,
                    call,
                    context: context.runtime(),
                    subject,
                    tracked_formal,
                    actual,
                },
                request,
            )?;
            exact_handoff |= exact;
            disjoint &= separate;
            if exact_handoff {
                break;
            }
        }
        if !exact_handoff {
            if !disjoint
                && let Some(guarded) = guarded_local_bypass(
                    &BypassQuery {
                        workspace,
                        discovery,
                        procedure,
                        parts,
                        context,
                        subject,
                        subject_id,
                        bindings,
                        protocol,
                        tracked_formal,
                    },
                    call,
                    request,
                )?
            {
                bypasses.insert(call.point, guarded);
                continue;
            }
            let quality = HopQuality::from_uncertain(!disjoint);
            let function = if disjoint {
                TypestateComposeFunction::identity()
            } else {
                TypestateComposeFunction::unproven_hop_loss()
            };
            let exits = [call.normal_continuation, call.exceptional_continuation]
                .into_iter()
                .filter_map(|continuation| continuation.target())
                .map(|target| (target, (function.clone(), quality)))
                .collect();
            bypasses.insert(call.point, CallBypass { exits });
        }
    }
    Ok(bypasses)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic::{CancellationToken, SemanticBudget, SemanticRequest};

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9432: Java selected constructor result could not certify a workspace formal handoff"
    )]
    fn java_modeled_constructor_handoff_uses_selected_formal() {
        use crate::analyzer::semantic::{OracleCallContext, ValueAtPoint};
        use crate::analyzer::semantic_model::{
            CatalogOptions, CompilerOptions, SemanticModelActivationControl,
            SemanticModelActivationEvidence, SemanticModelActivationRequest,
            SemanticModelControlAction, SemanticModelControlScope, SemanticModelOverlayDisposition,
            SemanticModelPackSelector, SemanticModelRuntimeLimits, SemanticModelRuntimeOutcome,
            SemanticPackCatalog, SessionPackSource, SessionPackSourceKind, SourceFormat,
            acquire_active_semantic_models, compile_source,
        };
        use crate::composition::WorkspaceCompositionDiscovery;
        use crate::value_flow::{ValueFlowCache, WorkspaceValueFlowProvider};

        let source = "import com.example.res.Handle;\nimport com.example.res.Other;\nclass App {\n  static void accept(Handle h) {}\n  static void acceptOther(Other h) {}\n  static void run() { accept(new Handle()); acceptOther(new Handle()); Variant.accept(new Handle()); }\n}\n";
        let project = crate::inline_project::InlineTestProject::with_language(
            crate::analyzer::Language::Java,
        )
        .file("App.java", source)
        .file(
            "Variant.java",
            "import com.example.other.Handle;\nclass Variant { static void accept(Handle h) {} }\n",
        )
        .build();
        let workspace = project.workspace_analyzer(crate::analyzer::AnalyzerConfig::default());
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let compiled = compile_source(
            SourceFormat::Json,
            include_bytes!("../../tests/fixtures/9432-java-handle.json"),
            &CompilerOptions::default(),
        )
        .unwrap();
        catalog
            .register_session_pack(
                &compiled,
                &SessionPackSource {
                    kind: SessionPackSourceKind::Embedded,
                    source_id: "test:9432-java-handle".into(),
                },
            )
            .unwrap();
        let variant = compile_source(
            SourceFormat::Json,
            include_bytes!("../../tests/fixtures/9432-java-handle-variant.json"),
            &CompilerOptions::default(),
        )
        .unwrap();
        catalog
            .register_session_pack(
                &variant,
                &SessionPackSource {
                    kind: SessionPackSourceKind::Embedded,
                    source_id: "test:9432-java-handle-variant".into(),
                },
            )
            .unwrap();
        let mut activation = SemanticModelActivationRequest {
            approximate_standard_libraries: Vec::new(),
            bifrost_version: env!("CARGO_PKG_VERSION").parse().unwrap(),
            evidence: vec![SemanticModelActivationEvidence {
                language: "java".into(),
                ecosystem: "maven".into(),
                package: None,
                module: None,
                toolchain: None,
                target: None,
                configuration: None,
                artifact_sha256: None,
            }],
            controls: vec![SemanticModelActivationControl {
                scope: SemanticModelControlScope::Workspace,
                action: SemanticModelControlAction::Enable,
                selector: SemanticModelPackSelector {
                    pack_id: "test.9432.java-handle".into(),
                    version: None,
                    manifest_digest: None,
                },
            }],
            limits: SemanticModelRuntimeLimits::default(),
        };
        activation.controls.push(SemanticModelActivationControl {
            scope: SemanticModelControlScope::Workspace,
            action: SemanticModelControlAction::Enable,
            selector: SemanticModelPackSelector {
                pack_id: "test.9432.java-handle-variant".into(),
                version: None,
                manifest_digest: None,
            },
        });
        let cancellation = CancellationToken::default();
        let activated = acquire_active_semantic_models(
            workspace.analyzer(),
            &catalog,
            None,
            &activation,
            &cancellation,
        );
        assert!(
            matches!(activated, SemanticModelRuntimeOutcome::Ready { .. }),
            "{activated:?}"
        );
        let mut budget = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &project.file("App.java"),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .unwrap()
            .available_value()
            .cloned()
            .expect("Java semantics materializes");
        let handles = artifact
            .procedures()
            .iter()
            .map(|row| artifact.procedure_handle(row.id()).unwrap())
            .collect::<Vec<_>>();
        let call_text = |call: &CallSiteHandle| {
            let span =
                crate::analyzer::semantic::workspace_oracle::dispatch::exact_call_range(call)
                    .unwrap();
            source
                .get(span.start_byte..span.end_byte)
                .unwrap()
                .to_owned()
        };
        let calls = handles
            .iter()
            .flat_map(|procedure| {
                procedure
                    .semantics()
                    .call_sites()
                    .iter()
                    .map(move |row| procedure.call_site_handle(row.id).unwrap())
            })
            .collect::<Vec<_>>();
        let consumer = calls
            .iter()
            .find(|call| call_text(call) == "accept(new Handle())")
            .expect("workspace consumer call");
        let site = consumer
            .procedure()
            .semantics()
            .call_site(consumer.id())
            .unwrap();
        let actual = site.arguments.first().expect("one actual").value;
        let observation = ValueAtPoint::new(
            consumer.procedure().value_handle(actual).unwrap(),
            consumer.procedure().point_handle(site.point).unwrap(),
            ObservationPhase::BeforeEffects,
            OracleCallContext::empty(),
        )
        .unwrap();
        let objects = workspace
            .semantic_oracle_provider()
            .pointees(
                &observation,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .unwrap();
        let [object] = objects.available_value().unwrap().objects().candidates() else {
            panic!("one exact constructor object: {objects:?}");
        };
        let subject = BoundTypestateSubject::receiver_event_probe(
            object.value().clone(),
            TypestateBindingQuality::proven_unique(),
        );
        let discovery = WorkspaceCompositionDiscovery::new(
            &workspace,
            WorkspaceValueFlowProvider::new(&workspace, ValueFlowCache::default()),
        );
        let dispatch = discovery
            .resolve_call(
                consumer,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .unwrap();
        let [candidate] = dispatch.available_value().unwrap().candidates() else {
            panic!("one workspace candidate: {dispatch:?}");
        };
        let bindings = discovery
            .call_bindings(
                consumer,
                candidate,
                &OracleCallContext::empty(),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .unwrap();
        let selected = bindings
            .available_value()
            .expect("selected workspace binding");
        let mapping = selected
            .bindings()
            .iter()
            .find_map(|binding| {
                let CallBinding::ArgumentGroup(group) = binding else {
                    return None;
                };
                group.mappings().first().map(|mapping| mapping.value())
            })
            .expect("one argument mapping");
        let conversion = mapping.conversion();
        assert!(matches!(conversion, Some(Ok(None))), "{conversion:?}");
        use crate::analyzer::semantic::{TransferKind, TransferOperation, ValueTransfer};
        use crate::analyzer::usages::call_conversion::ConversionUnknown;
        assert!(
            !mapping
                .clone()
                .with_conversion(Ok(Some(ValueTransfer {
                    kind: TransferKind::Copy,
                    operation: TransferOperation::None,
                })))
                .preserves_reference_identity()
        );
        assert!(
            !mapping
                .clone()
                .with_conversion(Err(ConversionUnknown::UnresolvedTargetType))
                .preserves_reference_identity()
        );
        assert!(
            selected_reference_binding(
                MoveBindingQuery {
                    discovery: &discovery,
                    procedure: consumer.procedure(),
                    call: site,
                    context: selected.context(),
                    subject: &subject,
                    tracked_formal: None,
                    actual,
                },
                &mut SemanticRequest::new(&mut budget, &cancellation)
            )
            .unwrap()
        );
        let other = calls
            .iter()
            .find(|call| call_text(call) == "acceptOther(new Handle())")
            .expect("different formal consumer call");
        let other_site = other.procedure().semantics().call_site(other.id()).unwrap();
        let other_actual = other_site.arguments.first().unwrap().value;
        let other_observation = ValueAtPoint::new(
            other.procedure().value_handle(other_actual).unwrap(),
            other.procedure().point_handle(other_site.point).unwrap(),
            ObservationPhase::BeforeEffects,
            OracleCallContext::empty(),
        )
        .unwrap();
        let other_objects = workspace
            .semantic_oracle_provider()
            .pointees(
                &other_observation,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .unwrap();
        let [other_object] = other_objects
            .available_value()
            .unwrap()
            .objects()
            .candidates()
        else {
            panic!("one exact second constructor object: {other_objects:?}");
        };
        let other_subject = BoundTypestateSubject::receiver_event_probe(
            other_object.value().clone(),
            TypestateBindingQuality::proven_unique(),
        );
        let other_dispatch = discovery
            .resolve_call(other, &mut SemanticRequest::new(&mut budget, &cancellation))
            .unwrap();
        let [other_candidate] = other_dispatch.available_value().unwrap().candidates() else {
            panic!("one other workspace candidate: {other_dispatch:?}");
        };
        let other_bindings = discovery
            .call_bindings(
                other,
                other_candidate,
                &OracleCallContext::empty(),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .unwrap();
        let other_mapping = other_bindings
            .available_value()
            .unwrap()
            .bindings()
            .iter()
            .find_map(|binding| {
                let CallBinding::ArgumentGroup(group) = binding else {
                    return None;
                };
                group.mappings().first().map(|mapping| mapping.value())
            })
            .expect("other formal mapping");
        assert!(matches!(other_mapping.conversion(), Some(Err(_))));
        assert!(
            !selected_reference_binding(
                MoveBindingQuery {
                    discovery: &discovery,
                    procedure: other.procedure(),
                    call: other_site,
                    context: selected.context(),
                    subject: &other_subject,
                    tracked_formal: None,
                    actual: other_actual,
                },
                &mut SemanticRequest::new(&mut budget, &cancellation)
            )
            .unwrap()
        );
        let alternate = calls
            .iter()
            .find(|call| call_text(call) == "Variant.accept(new Handle())")
            .expect("alternate-provider workspace call");
        let alternate_dispatch = discovery
            .resolve_call(
                alternate,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .unwrap();
        let [alternate_candidate] = alternate_dispatch.available_value().unwrap().candidates()
        else {
            panic!("alternate-provider workspace target not selected: {alternate_dispatch:?}");
        };
        assert_eq!(
            alternate_candidate.target.artifact().key().path().as_str(),
            "Variant.java"
        );
        let alternate_bindings = discovery
            .call_bindings(
                alternate,
                alternate_candidate,
                &OracleCallContext::empty(),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .unwrap();
        let selected_alternate = alternate_bindings
            .available_value()
            .expect("selected alternate-provider binding");
        let alternate_mapping = selected_alternate
            .bindings()
            .iter()
            .find_map(|binding| {
                let CallBinding::ArgumentGroup(group) = binding else {
                    return None;
                };
                group.mappings().first().map(|mapping| mapping.value())
            })
            .expect("alternate-provider formal mapping");
        assert!(
            matches!(
                alternate_mapping.conversion(),
                Some(Err(ConversionUnknown::UnsupportedConversion))
            ),
            "{:?}",
            alternate_mapping.conversion()
        );
        assert!(!alternate_mapping.preserves_reference_identity());
        let selected_overlay = workspace.analyzer().semantic_model_overlay().unwrap();
        let selected_other_provider =
            selected_overlay.symbols_with_id("type.other-provider-handle");
        let [selected_other_provider] = selected_other_provider.records.as_slice() else {
            panic!("one active alternate Handle provider: {selected_other_provider:?}");
        };
        assert_eq!(
            selected_other_provider.qualified_name,
            "com.example.other.Handle"
        );
        assert_eq!(
            selected_other_provider.provenance.pack_id,
            "test.9432.java-handle-variant"
        );
        let selected_original_provider = selected_overlay.symbols_with_id("type.handle");
        let [selected_original_provider] = selected_original_provider.records.as_slice() else {
            panic!("one active constructor Handle provider: {selected_original_provider:?}");
        };
        assert_eq!(
            selected_original_provider.name,
            selected_other_provider.name
        );
        assert_ne!(
            selected_original_provider.provenance.pack_digest,
            selected_other_provider.provenance.pack_digest
        );
        let alternate_site = alternate
            .procedure()
            .semantics()
            .call_site(alternate.id())
            .unwrap();
        let alternate_actual = alternate_site
            .arguments
            .first()
            .expect("alternate actual")
            .value;
        let alternate_observation = ValueAtPoint::new(
            alternate
                .procedure()
                .value_handle(alternate_actual)
                .unwrap(),
            alternate
                .procedure()
                .point_handle(alternate_site.point)
                .unwrap(),
            ObservationPhase::BeforeEffects,
            OracleCallContext::empty(),
        )
        .unwrap();
        let alternate_objects = workspace
            .semantic_oracle_provider()
            .pointees(
                &alternate_observation,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .unwrap();
        let [alternate_object] = alternate_objects
            .available_value()
            .unwrap()
            .objects()
            .candidates()
        else {
            panic!("one exact alternate-provider constructor object: {alternate_objects:?}");
        };
        let alternate_subject = BoundTypestateSubject::receiver_event_probe(
            alternate_object.value().clone(),
            TypestateBindingQuality::proven_unique(),
        );
        assert!(
            !selected_reference_binding(
                MoveBindingQuery {
                    discovery: &discovery,
                    procedure: alternate.procedure(),
                    call: alternate_site,
                    context: selected_alternate.context(),
                    subject: &alternate_subject,
                    tracked_formal: None,
                    actual: alternate_actual,
                },
                &mut SemanticRequest::new(&mut budget, &cancellation)
            )
            .unwrap()
        );
        let mut duplicate_activation = activation.clone();
        duplicate_activation.evidence[0].configuration = Some("variant".into());
        let duplicate_runtime = acquire_active_semantic_models(
            workspace.analyzer(),
            &catalog,
            None,
            &duplicate_activation,
            &cancellation,
        );
        assert!(
            matches!(duplicate_runtime, SemanticModelRuntimeOutcome::Ready { .. }),
            "{duplicate_runtime:?}"
        );
        let duplicate_overlay = workspace.analyzer().semantic_model_overlay().unwrap();
        let same_fqn = duplicate_overlay.symbols_with_id("type.handle");
        assert_eq!(
            same_fqn.disposition,
            SemanticModelOverlayDisposition::Conflict
        );
        let [first, second] = same_fqn.records.as_slice() else {
            panic!("same-FQN variants must conflict: {same_fqn:?}");
        };
        assert_eq!(first.qualified_name, second.qualified_name);
        assert_eq!(first.qualified_name, "com.example.res.Handle");
        assert_ne!(first.provenance.pack_digest, second.provenance.pack_digest);
        assert!(first.provenance.ambiguous && second.provenance.ambiguous);
    }

    #[test]
    fn void_helper_continuation_reaches_the_next_object_call() {
        let project = crate::inline_project::InlineTestProject::with_language(
            crate::analyzer::Language::TypeScript,
        )
        .file(
            "main.ts",
            "function helper(_x: object) {}\nexport function root() { const x = {}; helper(x); helper(x); }\n",
        )
        .build();
        let workspace = project.workspace_analyzer(crate::analyzer::AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let artifact = workspace
            .materialize_program_semantics(
                &project.file("main.ts"),
                &mut SemanticRequest::new(&mut SemanticBudget::default(), &cancellation),
            )
            .unwrap()
            .available_value()
            .cloned()
            .unwrap();
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
                    == Some("root")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .unwrap();
        let calls = root.semantics().call_sites();
        assert_eq!(calls.len(), 2);
        let start = calls[0].normal_continuation.target().unwrap();
        assert!(local_cfg_reaches(
            calls,
            root.semantics().control_edges(),
            &HashMap::default(),
            start,
            calls[1].point,
        ));
        assert!(
            !local_cfg_reaches(
                calls,
                root.semantics().control_edges(),
                &HashMap::default(),
                calls[0].point,
                calls[1].point,
            ),
            "the local relation must not bypass the helper handoff"
        );
    }
}
