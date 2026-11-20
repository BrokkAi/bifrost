//! One query-local proof of an authored branch guard. Origin graphs nominate
//! bindings; only the shared CFG reaching-definition solve certifies a version.
//! Consumers translate the proven edge into their existing source/label kills.

use std::collections::{HashMap, HashSet};

use super::rules::GuardEdgeKill;
use crate::analyzer::semantic::binding_initialization::{
    BindingDefinitions, BindingEventKey, BindingInitializationEvent, binding_write_target,
};
use crate::analyzer::semantic::cfg_algorithms::{
    self, CfgAlgorithmBudget, CfgAlgorithmRequest, DenseBidirectionalGraph, ReachingSets,
};
use crate::analyzer::semantic::{
    ActualBorrowKind, BindingOriginIndex, CaptureSource, GuardId, MemoryLocationKind,
    ProcedureHandle, ProgramPointId, SemanticEffect, SemanticRequest, SemanticValueKind,
    ValueFlowEndpoint, ValueFlowKind, ValueId,
};

/// An affirmative type proof is independent of Copy, Drop, and let mutability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardInteriorMutability {
    Absent,
    Present,
    Unknown,
}

/// Query-only storage form. Exclusive additionally needs the shared proof's
/// nonescape inventory; a readonly referent is not exclusive owned storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardStorageExclusivity {
    Exclusive,
    NotExclusive,
    Unknown,
}

/// A failed proof never carries a kill. These causes survive adapter transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardBindingReason {
    OpaqueGuard,
    UnprovenComparisonSemantics,
    IncompleteGuardSelector,
    GuardSelectorResultCap,
    GuardSelectorOperational(
        brokk_bifrost_core::analyzer::derivation_cause::DerivationExecutionCause,
    ),
    UnresolvedSelectedCall,
    AmbiguousOperand,
    MissingAcceptingEdge,
    AmbiguousDefinition,
    ChangedDefinition,
    UnknownBorrow,
    MutableBorrow,
    RawAlias,
    Capture,
    InteriorMutabilityPresent,
    InteriorMutabilityUnknown,
    StorageNotExclusive,
    StorageExclusivityUnknown,
    MissingCapability,
    IncompleteUses,
    BudgetExceeded,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GuardEstablishment {
    ParameterEntry(ValueId),
    Event(BindingEventKey),
}

/// A nomination after policy predicate and requirements have matched.
#[derive(Debug, Clone, Copy)]
pub struct GuardBindingCandidate {
    pub guard: GuardId,
    pub operand: ValueId,
    pub read_point: ProgramPointId,
    pub accepts: bool,
}

/// Exact per-procedure binding proof. No source-list IDs or solver state.
#[derive(Debug, Clone)]
pub struct GuardBinding {
    pub procedure: ProcedureHandle,
    pub guard: GuardId,
    pub operand: ValueId,
    pub read_point: ProgramPointId,
    pub establishment: GuardEstablishment,
    pub accepts: bool,
    pub kill: GuardEdgeKill,
}

/// Opaque producer-owned removal token carried through shared guard bindings.
#[derive(Debug, Clone)]
pub struct GuardRemovalToken {
    producer_id: &'static str,
    payload: std::sync::Arc<dyn std::any::Any + Send + Sync>,
}

impl GuardRemovalToken {
    pub fn new<T: Send + Sync + 'static>(producer_id: &'static str, payload: T) -> Self {
        Self {
            producer_id,
            payload: std::sync::Arc::new(payload),
        }
    }

    pub const fn producer_id(&self) -> &'static str {
        self.producer_id
    }

    pub fn downcast<T: 'static>(&self, producer_id: &str) -> Option<&T> {
        (self.producer_id == producer_id)
            .then(|| self.payload.downcast_ref::<T>())
            .flatten()
    }
}

/// Producer-owned closed vocabulary for Match `:guard-barriers :removes`.
pub trait GuardRemovalVocabulary: Send + Sync {
    fn producer_id(&self) -> &'static str;
    fn resolve(&self, name: &str) -> Option<GuardRemovalToken>;
    fn names(&self) -> Vec<&'static str>;
}

/// Resolved removals carried by a compiled guard binding.
#[derive(Debug, Clone)]
pub enum GuardRemovals {
    TaintLabels(Box<[Box<str>]>),
    ProducerKinds(Box<[GuardRemovalToken]>),
}

impl GuardRemovals {
    pub fn taint_labels(&self) -> &[Box<str>] {
        match self {
            Self::TaintLabels(labels) => labels,
            Self::ProducerKinds(_) => &[],
        }
    }

    pub fn producer_kinds(&self) -> &[GuardRemovalToken] {
        match self {
            Self::ProducerKinds(tokens) => tokens,
            Self::TaintLabels(_) => &[],
        }
    }
}

/// Authored identity/labels decorate the same proof for Match and Taint.
#[derive(Debug, Clone)]
pub struct CompiledGuardBinding {
    pub id: Box<str>,
    pub removes: GuardRemovals,
    pub binding: GuardBinding,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardBindingDecline {
    pub id: Box<str>,
    pub procedure: ProcedureHandle,
    pub guard: Option<GuardId>,
    pub reason: GuardBindingReason,
}

#[derive(Debug, Clone, Default)]
pub struct CompiledGuardBindings {
    pub bindings: Vec<CompiledGuardBinding>,
    pub declines: Vec<GuardBindingDecline>,
}

/// The proof's shared CFG solve and ordered establishments, retained only for
/// this procedure in this request. No process or policy-product cache is added.
pub struct GuardBindingProof<'a> {
    procedure: &'a ProcedureHandle,
    origins: BindingOriginIndex,
    operand_predecessors: HashMap<ValueId, Result<(ValueId, BindingEventKey), GuardBindingReason>>,
    events: Vec<BindingInitializationEvent>,
    definitions: BindingDefinitions,
    reaching: ReachingSets,
    dominance: cfg_algorithms::Dominators<ProgramPointId>,
}

impl<'a> GuardBindingProof<'a> {
    pub fn new(
        procedure: &'a ProcedureHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Self, GuardBindingReason> {
        let ir = procedure.semantics();
        if request.cancellation.is_cancelled() {
            return Err(GuardBindingReason::Cancelled);
        }
        let mut events = Vec::new();
        let mut operand_predecessors = HashMap::new();
        for value in ir.values() {
            if matches!(
                value.kind,
                SemanticValueKind::Parameter { .. } | SemanticValueKind::Receiver { .. }
            ) {
                events.push(BindingInitializationEvent {
                    event: events.len(),
                    binding: value.id,
                    establishes: true,
                    key: BindingEventKey {
                        point: ir.entry_point(),
                        event_index: u32::MAX,
                        source: value.source,
                    },
                });
            }
        }
        for point in ir.points() {
            if !request.charge_execution_traversal(point.events.len()) {
                return Err(GuardBindingReason::BudgetExceeded);
            }
            for (index, event) in point.events.iter().enumerate() {
                if request.cancellation.is_cancelled() {
                    return Err(GuardBindingReason::Cancelled);
                }
                let predecessor = match event.effect {
                    SemanticEffect::Assignment { target, value } => Some((target, Ok(value))),
                    SemanticEffect::ValueFlow {
                        target,
                        source,
                        kind,
                    } => Some((
                        target,
                        if matches!(
                            kind,
                            ValueFlowKind::Local
                                | ValueFlowKind::AddressOf
                                | ValueFlowKind::Parameter
                                | ValueFlowKind::Receiver
                        ) {
                            Ok(source)
                        } else {
                            Err(GuardBindingReason::AmbiguousOperand)
                        },
                    )),
                    _ => None,
                };
                if let Some((target, predecessor)) = predecessor {
                    let predecessor = predecessor.map(|source| {
                        (
                            source,
                            BindingEventKey {
                                point: point.id,
                                event_index: index as u32,
                                source: event.source,
                            },
                        )
                    });
                    operand_predecessors
                        .entry(target)
                        .and_modify(|prior| {
                            if *prior != predecessor {
                                *prior = Err(GuardBindingReason::AmbiguousOperand);
                            }
                        })
                        .or_insert(predecessor);
                }
                let Some(binding) = binding_write_target(&event.effect) else {
                    continue;
                };
                if !ir
                    .value(binding)
                    .is_some_and(|value| value.kind.is_binding())
                {
                    continue;
                }
                // Lowering's adjacent Local row repeats the Assignment writer.
                if matches!(
                    event.effect,
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Local | ValueFlowKind::AddressOf,
                        ..
                    }
                ) && index > 0
                    && matches!(point.events[index - 1].effect,
                        SemanticEffect::Assignment { target, .. } if target == binding)
                {
                    continue;
                }
                events.push(BindingInitializationEvent {
                    event: events.len(),
                    binding,
                    establishes: true,
                    key: BindingEventKey {
                        point: point.id,
                        event_index: index as u32,
                        source: event.source,
                    },
                });
            }
        }
        // The solve uses the final ordered writer of each point, while
        // definition_at still has all events for before-event observations.
        let mut last = std::collections::HashMap::new();
        for event in &events {
            last.insert((event.key.point, event.binding), *event);
        }
        let mut final_events = last.into_values().collect::<Vec<_>>();
        final_events.sort_by_key(|event| event.event);
        let definitions = BindingDefinitions::build(ir, &final_events);
        let solve_cells = definitions.dense_solve_cells(ir);
        if !request.charge_execution_traversal(solve_cells.div_ceil(8)) {
            return Err(GuardBindingReason::BudgetExceeded);
        }
        let facts = definitions.gen_kill(ir);
        let remaining = request.budget.remaining();
        let mut budget =
            CfgAlgorithmBudget::uniform(remaining.events.saturating_add(remaining.control_edges));
        let dominated = cfg_algorithms::dominators(
            ir,
            ir.entry_point(),
            &mut CfgAlgorithmRequest::new(&mut budget, request.cancellation),
        );
        let solved = cfg_algorithms::reaching_definitions(
            ir,
            ir.entry_point(),
            &facts,
            &mut CfgAlgorithmRequest::new(&mut budget, request.cancellation),
        );
        if request.cancellation.is_cancelled() {
            return Err(GuardBindingReason::Cancelled);
        }
        if !request.charge_execution_traversal(
            budget
                .used()
                .node_visits
                .saturating_add(budget.used().edge_visits),
        ) {
            return Err(GuardBindingReason::BudgetExceeded);
        }
        let reaching = solved.map_err(|_| GuardBindingReason::BudgetExceeded)?;
        let dominance = dominated.map_err(|_| GuardBindingReason::BudgetExceeded)?;
        Ok(Self {
            procedure,
            origins: BindingOriginIndex::new(procedure),
            operand_predecessors,
            events,
            definitions,
            reaching,
            dominance,
        })
    }

    fn definition_at(
        &self,
        binding: ValueId,
        point: ProgramPointId,
        event_index: usize,
    ) -> Result<GuardEstablishment, GuardBindingReason> {
        // Same-point writes precede the observation in semantic event order.
        if let Some(event) = self.events.iter().rev().find(|event| {
            event.binding == binding
                && event.key.point == point
                && event.key.event_index != u32::MAX
                && (event.key.event_index as usize) < event_index
        }) {
            return Ok(GuardEstablishment::Event(event.key));
        }
        let mut reaching = self
            .reaching
            .reaching_in(point.index())
            .filter(|definition| {
                *definition < self.definitions.events().len()
                    && self.definitions.binding(*definition) == binding
            })
            .map(|definition| &self.events[self.definitions.events()[definition]]);
        let first = reaching
            .next()
            .ok_or(GuardBindingReason::AmbiguousDefinition)?;
        if reaching.next().is_some()
            || !self
                .dominance
                .dominates(self.procedure.semantics(), first.key.point, point)
        {
            return Err(GuardBindingReason::AmbiguousDefinition);
        }
        Ok(if first.key.event_index == u32::MAX {
            GuardEstablishment::ParameterEntry(binding)
        } else {
            GuardEstablishment::Event(first.key)
        })
    }

    /// Nomination cannot cross derivations such as concatenation or a call:
    /// only exact local identity and explicit address creation preserve a read.
    fn nominated_binding(
        &self,
        operand: ValueId,
        request: &mut SemanticRequest<'_>,
    ) -> Result<(ValueId, BindingEventKey), GuardBindingReason> {
        let ir = self.procedure.semantics();
        let mut value = operand;
        let mut seen = HashSet::new();
        let mut read = None;
        loop {
            if request.cancellation.is_cancelled() {
                return Err(GuardBindingReason::Cancelled);
            }
            if !request.charge_execution_traversal(1) {
                return Err(GuardBindingReason::BudgetExceeded);
            }
            if !seen.insert(value) {
                return Err(GuardBindingReason::AmbiguousOperand);
            }
            if ir.value(value).is_some_and(|value| value.kind.is_binding()) {
                return Ok((value, read.ok_or(GuardBindingReason::AmbiguousOperand)?));
            }
            let (predecessor, key) = self
                .operand_predecessors
                .get(&value)
                .copied()
                .ok_or(GuardBindingReason::AmbiguousOperand)??;
            // The innermost identity edge reads the binding. Later arguments
            // and outer address/copy events cannot move that read forward.
            read = Some(key);
            value = predecessor;
        }
    }

    /// Resolve only exact stored identities through the same reaching owner.
    /// General value dependence is never evidence that a guard tests a result.
    pub fn tests_call_result(
        &self,
        subject: ValueId,
        point: ProgramPointId,
        result: ValueId,
        request: &mut SemanticRequest<'_>,
    ) -> Result<bool, GuardBindingReason> {
        let ir = self.procedure.semantics();
        let mut pending = vec![(subject, point, usize::MAX)];
        let mut seen = HashSet::new();
        while let Some((value, point, bound)) = pending.pop() {
            if request.cancellation.is_cancelled() {
                return Err(GuardBindingReason::Cancelled);
            }
            if !request.charge_execution_traversal(1) {
                return Err(GuardBindingReason::BudgetExceeded);
            }
            if !seen.insert((value, point, bound)) {
                return Err(GuardBindingReason::AmbiguousDefinition);
            }
            if value == result {
                continue;
            }
            if !ir.value(value).is_some_and(|value| value.kind.is_binding()) {
                return Ok(false);
            }
            let GuardEstablishment::Event(key) = self.definition_at(value, point, bound)? else {
                return Ok(false);
            };
            let event =
                &ir.point(key.point).expect("definition point").events[key.event_index as usize];
            let source = match event.effect {
                SemanticEffect::Assignment { value, .. } => value,
                SemanticEffect::ValueFlow {
                    source,
                    kind: ValueFlowKind::Local | ValueFlowKind::Transfer(_),
                    ..
                } => source,
                _ => return Err(GuardBindingReason::AmbiguousDefinition),
            };
            // The copy reads `source` at its own event, not at the end of the point.
            pending.push((source, key.point, key.event_index as usize));
        }
        Ok(true)
    }

    /// The binding-origin index this proof already built for its procedure.
    pub fn origins(&self) -> &BindingOriginIndex {
        &self.origins
    }

    fn address_origins(
        &self,
        address: ValueId,
        request: &mut SemanticRequest<'_>,
    ) -> Result<(HashSet<ValueId>, bool), GuardBindingReason> {
        let ir = self.procedure.semantics();
        let mut pending = vec![address];
        let mut visited = HashSet::new();
        let mut bindings = HashSet::new();
        let mut complete = true;
        while let Some(value) = pending.pop() {
            if request.cancellation.is_cancelled() {
                return Err(GuardBindingReason::Cancelled);
            }
            if !request.charge_execution_traversal(1) {
                return Err(GuardBindingReason::BudgetExceeded);
            }
            if !visited.insert(value) {
                continue;
            }
            let Some(kind) = ir.value(value).map(|v| &v.kind) else {
                complete = false;
                continue;
            };
            if value != address && kind.is_binding() {
                bindings.insert(value);
                continue;
            }
            let mut has_pred = false;
            for pred in self.origins.value_predecessors(value) {
                has_pred = true;
                pending.push(pred);
            }
            if !has_pred {
                complete = false;
            }
        }
        let complete = complete && !bindings.is_empty();
        Ok((bindings, complete))
    }

    pub fn prove(
        &self,
        candidate: GuardBindingCandidate,
        _observations: &[ProgramPointId],
        request: &mut SemanticRequest<'_>,
        mut interior: impl FnMut(
            ValueId,
            &mut SemanticRequest<'_>,
        ) -> Result<GuardInteriorMutability, GuardBindingReason>,
        mut nonmutating_call: impl FnMut(
            crate::analyzer::semantic::CallSiteId,
            ValueId,
            &mut SemanticRequest<'_>,
        ) -> Result<(), GuardBindingReason>,
    ) -> Result<GuardBinding, GuardBindingReason> {
        let ir = self.procedure.semantics();
        if request.cancellation.is_cancelled() {
            return Err(GuardBindingReason::Cancelled);
        }
        let guard = ir
            .guard_facts()
            .iter()
            .find(|guard| guard.id == candidate.guard)
            .ok_or(GuardBindingReason::OpaqueGuard)?;
        let edge = if candidate.accepts {
            guard.true_edge
        } else {
            guard.false_edge
        }
        .and_then(|edge| ir.control_edge(edge))
        .ok_or(GuardBindingReason::MissingAcceptingEdge)?;
        let (binding, read) = self.nominated_binding(candidate.operand, request)?;
        let read_point = read.point;
        let read_event = read.event_index as usize;
        let establishment = self.definition_at(binding, read_point, read_event)?;
        if self.definition_at(binding, guard.point, usize::MAX)? != establishment {
            return Err(GuardBindingReason::ChangedDefinition);
        }
        // This is the accepting slice. A later assignment creates an unguarded
        // definition; ordinary value flow supplies its fresh facts independently.
        let mut slice = HashSet::new();
        let mut pending = vec![edge.target_point];
        while let Some(point) = pending.pop() {
            if request.cancellation.is_cancelled() {
                return Err(GuardBindingReason::Cancelled);
            }
            if !request.charge_execution_traversal(1) {
                return Err(GuardBindingReason::BudgetExceeded);
            }
            if !slice.insert(point) {
                continue;
            }
            pending.extend(ir.successors(point).map(|(_, successor)| successor));
        }
        // Edge kills also enter callees and returned values. A local sink
        // cannot bound the stability proof for those later observations, so
        // retain the complete accepting slice, including outgoing call effects.
        let accepting_points = slice.clone();
        // A stored verdict describes the operand at its selected read. Check
        // every route from that read to the branch, before trusting the verdict.
        // Restrict the interval to points that can reach this branch so unrelated
        // earlier paths do not invalidate the proof.
        if read_point != guard.point {
            let mut to_guard = HashSet::new();
            let mut pending = vec![guard.point];
            while let Some(point) = pending.pop() {
                if request.cancellation.is_cancelled() {
                    return Err(GuardBindingReason::Cancelled);
                }
                if !request.charge_execution_traversal(1) {
                    return Err(GuardBindingReason::BudgetExceeded);
                }
                if to_guard.insert(point) && point != read_point {
                    pending.extend(ir.predecessors(point).map(|(_, predecessor)| predecessor));
                }
            }
            let mut interval = HashSet::new();
            let mut pending = vec![read_point];
            while let Some(point) = pending.pop() {
                if request.cancellation.is_cancelled() {
                    return Err(GuardBindingReason::Cancelled);
                }
                if !request.charge_execution_traversal(1) {
                    return Err(GuardBindingReason::BudgetExceeded);
                }
                if to_guard.contains(&point) && interval.insert(point) && point != guard.point {
                    pending.extend(ir.successors(point).map(|(_, successor)| successor));
                }
            }
            slice.extend(interval);
        }
        match interior(binding, request)? {
            GuardInteriorMutability::Absent => {}
            GuardInteriorMutability::Present => {
                return Err(GuardBindingReason::InteriorMutabilityPresent);
            }
            GuardInteriorMutability::Unknown => {
                return Err(GuardBindingReason::InteriorMutabilityUnknown);
            }
        }
        // Exclusive inline storage also requires a complete nonescape
        // inventory. An omitted address/capture effect before validation could
        // have made the local globally reachable. Call-site gaps still have
        // represented actuals and are checked through selected formals below.
        // Callable-reference gaps duplicate that dispatch frontier; other
        // point/value/capture omissions have no such inventory.
        for gap in ir.logical_gaps() {
            if request.cancellation.is_cancelled() {
                return Err(GuardBindingReason::Cancelled);
            }
            if !request.charge_execution_traversal(1) {
                return Err(GuardBindingReason::BudgetExceeded);
            }
            let represented_call = (gap.base.capability
                == crate::analyzer::semantic::SemanticCapability::CallableReferences
                || matches!(
                    gap.base.subject,
                    crate::analyzer::semantic::SemanticGapSubject::CallSite(_)
                ))
                && !gap
                    .base
                    .impacts
                    .contains(crate::analyzer::semantic::SemanticGapImpact::CallEvaluation);
            if !gap.base.is_implicit_drop_omission() && !represented_call {
                return Err(GuardBindingReason::StorageExclusivityUnknown);
            }
        }
        // Index identity edges once; a worklist follows each alias edge at
        // most once instead of rescanning every event for each chain link.
        let mut alias_edges = HashMap::<ValueId, Vec<(ValueId, Option<GuardBindingReason>)>>::new();
        let mut accepting_addresses = HashSet::new();
        let mut call_uses = HashMap::<ValueId, Vec<ProgramPointId>>::new();
        for point in ir.points() {
            for event in &point.events {
                if request.cancellation.is_cancelled() {
                    return Err(GuardBindingReason::Cancelled);
                }
                if !request.charge_execution_traversal(1) {
                    return Err(GuardBindingReason::BudgetExceeded);
                }
                let target = match event.effect {
                    SemanticEffect::Assignment { target, .. }
                    | SemanticEffect::ValueFlow { target, .. } => Some(target),
                    SemanticEffect::MemoryLoad { result, .. } => Some(result),
                    _ => None,
                };
                if accepting_points.contains(&point.id)
                    && let Some(target) = target
                    && ir
                        .value(target)
                        .is_some_and(|value| value.kind == SemanticValueKind::Address)
                {
                    accepting_addresses.insert(target);
                }

                match event.effect {
                    SemanticEffect::Assignment { target, value } => {
                        alias_edges.entry(value).or_default().push((target, None));
                    }
                    SemanticEffect::ValueFlow {
                        source,
                        target,
                        kind,
                    } => {
                        let step = if kind == ValueFlowKind::LanguageDefined
                            || ir.value(target).is_some_and(|value| {
                                matches!(value.kind, SemanticValueKind::LanguageDefined(_))
                            }) {
                            Some((
                                target,
                                Some(
                                    if ir.value(target).is_some_and(|value| {
                                        value.actual_borrow == ActualBorrowKind::Raw
                                    }) {
                                        GuardBindingReason::RawAlias
                                    } else {
                                        GuardBindingReason::UnknownBorrow
                                    },
                                ),
                            ))
                        } else if matches!(
                            kind,
                            ValueFlowKind::Local
                                | ValueFlowKind::AddressOf
                                | ValueFlowKind::Parameter
                                | ValueFlowKind::Receiver
                                | ValueFlowKind::Transfer(_)
                        ) {
                            Some((target, None))
                        } else {
                            None
                        };
                        if let Some(step) = step {
                            alias_edges.entry(source).or_default().push(step);
                        }
                    }
                    SemanticEffect::AggregateInitializer {
                        aggregate, value, ..
                    } => {
                        alias_edges
                            .entry(value)
                            .or_default()
                            .push((aggregate, None));
                    }
                    SemanticEffect::MemoryLoad {
                        result, location, ..
                    } => {
                        let base = match ir.memory_location(location).map(|location| &location.kind)
                        {
                            Some(
                                MemoryLocationKind::Field { base, .. }
                                | MemoryLocationKind::Property { base, .. }
                                | MemoryLocationKind::Index { base, .. },
                            ) => Some(*base),
                            Some(MemoryLocationKind::Dereference { address }) => Some(*address),
                            Some(MemoryLocationKind::LexicalCell { binding }) => Some(*binding),
                            _ => None,
                        };
                        if let Some(base) = base {
                            alias_edges.entry(base).or_default().push((result, None));
                        }
                    }
                    SemanticEffect::MemoryStore {
                        location, value, ..
                    } => {
                        let container =
                            match ir.memory_location(location).map(|location| &location.kind) {
                                Some(
                                    MemoryLocationKind::Field { base, .. }
                                    | MemoryLocationKind::Property { base, .. }
                                    | MemoryLocationKind::Index { base, .. },
                                ) => Some(*base),
                                Some(MemoryLocationKind::Dereference { address }) => Some(*address),
                                _ => None,
                            };
                        if let Some(container) = container {
                            alias_edges
                                .entry(value)
                                .or_default()
                                .push((container, None));
                        }
                    }
                    SemanticEffect::Invoke { call_site } => {
                        if let Some(call) = ir.call_site(call_site) {
                            for source in call
                                .receiver
                                .into_iter()
                                .chain(call.arguments.iter().map(|arg| arg.value))
                            {
                                call_uses.entry(source).or_default().push(call.point);
                                for target in call.normal_result_values() {
                                    if request.cancellation.is_cancelled() {
                                        return Err(GuardBindingReason::Cancelled);
                                    }
                                    if !request.charge_execution_traversal(1) {
                                        return Err(GuardBindingReason::BudgetExceeded);
                                    }
                                    alias_edges.entry(source).or_default().push((target, None));
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        // A reference can arrive as a parameter or call result, without any
        // local Address value. Trace store addresses back to the guarded
        // binding as well as checking explicit address introductions below.
        let mut store_roots = Vec::new();
        for point in ir
            .points()
            .iter()
            .filter(|point| slice.contains(&point.id) || point.id == guard.point)
        {
            for (index, event) in point.events.iter().enumerate() {
                if point.id == read_point && read_point != guard.point && index <= read_event {
                    continue;
                }
                if request.cancellation.is_cancelled() {
                    return Err(GuardBindingReason::Cancelled);
                }
                if !request.charge_execution_traversal(1) {
                    return Err(GuardBindingReason::BudgetExceeded);
                }
                if let SemanticEffect::MemoryStore { location, .. } = event.effect {
                    match ir.memory_location(location).map(|location| &location.kind) {
                        Some(
                            MemoryLocationKind::Field { base, .. }
                            | MemoryLocationKind::Property { base, .. }
                            | MemoryLocationKind::Index { base, .. },
                        ) => store_roots.push(*base),
                        Some(MemoryLocationKind::Dereference { address }) => {
                            store_roots.push(*address)
                        }
                        _ => {}
                    }
                }
            }
        }
        if !store_roots.is_empty() {
            let mut call_inputs = HashMap::<ValueId, Vec<ValueId>>::new();
            for call in ir.call_sites() {
                for result in call.normal_result_values() {
                    for input in call
                        .receiver
                        .into_iter()
                        .chain(call.arguments.iter().map(|argument| argument.value))
                    {
                        if request.cancellation.is_cancelled() {
                            return Err(GuardBindingReason::Cancelled);
                        }
                        if !request.charge_execution_traversal(1) {
                            return Err(GuardBindingReason::BudgetExceeded);
                        }
                        call_inputs.entry(result).or_default().push(input);
                    }
                }
            }
            let mut visited = HashSet::new();
            while let Some(value) = store_roots.pop() {
                if request.cancellation.is_cancelled() {
                    return Err(GuardBindingReason::Cancelled);
                }
                if !request.charge_execution_traversal(1) {
                    return Err(GuardBindingReason::BudgetExceeded);
                }
                if !visited.insert(value) {
                    continue;
                }
                if value == binding {
                    return Err(GuardBindingReason::MutableBorrow);
                }
                store_roots.extend(self.origins.value_predecessors(value));
                store_roots.extend(call_inputs.get(&value).into_iter().flatten().copied());
            }
        }
        for value in ir
            .values()
            .iter()
            .filter(|value| value.kind == SemanticValueKind::Address)
        {
            let (bindings, complete) = self.address_origins(value.id, request)?;
            if !bindings.contains(&binding) {
                continue;
            }
            // An earlier mutable/raw borrow can escape into a container or
            // implicit cleanup as well as a represented call. Its absence of
            // later explicit uses is not a nonescape certificate.
            if value.actual_borrow != ActualBorrowKind::Shared {
                return Err(GuardBindingReason::StorageNotExclusive);
            }
            if !complete {
                return Err(GuardBindingReason::UnknownBorrow);
            }
            let mut aliases = HashSet::from([value.id]);
            let mut pending = vec![value.id];
            while let Some(source) = pending.pop() {
                for step in alias_edges.get(&source).into_iter().flatten() {
                    if request.cancellation.is_cancelled() {
                        return Err(GuardBindingReason::Cancelled);
                    }
                    if !request.charge_execution_traversal(1) {
                        return Err(GuardBindingReason::BudgetExceeded);
                    }
                    let (target, reason) = *step;
                    if let Some(reason) = reason {
                        return Err(reason);
                    }
                    if aliases.insert(target) {
                        pending.push(target);
                    }
                }
            }
            for alias in &aliases {
                for point in call_uses.get(alias).into_iter().flatten() {
                    if request.cancellation.is_cancelled() {
                        return Err(GuardBindingReason::Cancelled);
                    }
                    if !request.charge_execution_traversal(1) {
                        return Err(GuardBindingReason::BudgetExceeded);
                    }
                    if accepting_addresses.contains(&value.id) && accepting_points.contains(point) {
                        return Err(GuardBindingReason::StorageNotExclusive);
                    }
                }
            }
        }
        // Local bindings stop unique_binding_origin, but do not stop a
        // reference capability. Follow the indexed identity edges through them.
        let mut binding_aliases = HashSet::from([binding]);
        let mut pending = vec![binding];
        while let Some(value) = pending.pop() {
            for step in alias_edges.get(&value).into_iter().flatten() {
                if request.cancellation.is_cancelled() {
                    return Err(GuardBindingReason::Cancelled);
                }
                if !request.charge_execution_traversal(1) {
                    return Err(GuardBindingReason::BudgetExceeded);
                }
                let (target, _) = *step;
                if binding_aliases.insert(target) {
                    pending.push(target);
                }
            }
        }
        // Capturing a local alias or an aggregate carries the capability as
        // surely as capturing the original binding. Zero-argument closure calls
        // need not expose that capability as a receiver or actual argument.
        for capture in ir.captures() {
            if request.cancellation.is_cancelled() {
                return Err(GuardBindingReason::Cancelled);
            }
            if !request.charge_execution_traversal(1) {
                return Err(GuardBindingReason::BudgetExceeded);
            }
            let related = match capture.captured {
                CaptureSource::Value(value) => binding_aliases.contains(&value),
                CaptureSource::Location(location) => {
                    match ir.memory_location(location).map(|location| &location.kind) {
                        Some(MemoryLocationKind::LexicalCell { binding }) => {
                            binding_aliases.contains(binding)
                        }
                        Some(
                            MemoryLocationKind::Field { base, .. }
                            | MemoryLocationKind::Property { base, .. }
                            | MemoryLocationKind::Index { base, .. },
                        ) => binding_aliases.contains(base),
                        Some(MemoryLocationKind::Dereference { address }) => {
                            binding_aliases.contains(address)
                        }
                        _ => false,
                    }
                }
            };
            if related {
                return Err(GuardBindingReason::Capture);
            }
        }
        // The selected predicate must not mutate the value after inspecting
        // it either. Check every related local binding, so the callback checks
        // each corresponding receiver and formal rather than only the original.
        for call in ir
            .call_sites()
            .iter()
            .filter(|call| slice.contains(&call.point) || call.point == candidate.read_point)
        {
            let mut checked = HashSet::new();
            for value in call
                .receiver
                .into_iter()
                .chain(call.arguments.iter().map(|argument| argument.value))
            {
                if !binding_aliases.contains(&value) {
                    continue;
                }
                if request.cancellation.is_cancelled() {
                    return Err(GuardBindingReason::Cancelled);
                }
                if !request.charge_execution_traversal(1) {
                    return Err(GuardBindingReason::BudgetExceeded);
                }
                let local = self
                    .origins
                    .unique_binding_origin(value)
                    .ok_or(GuardBindingReason::UnknownBorrow)?;
                if checked.insert(local) {
                    nonmutating_call(call.id, local, request)?;
                }
            }
        }
        if request.cancellation.is_cancelled() {
            return Err(GuardBindingReason::Cancelled);
        }
        if request.stop_observed() {
            return Err(GuardBindingReason::BudgetExceeded);
        }
        Ok(GuardBinding {
            procedure: self.procedure.clone(),
            guard: guard.id,
            operand: candidate.operand,
            read_point,
            establishment,
            accepts: candidate.accepts,
            kill: GuardEdgeKill {
                point: guard.point,
                target_point: edge.target_point,
                kind: edge.kind,
                carrier: ValueFlowEndpoint::for_value(
                    self.procedure
                        .value_handle(binding)
                        .expect("proven binding"),
                ),
            },
        })
    }
}
