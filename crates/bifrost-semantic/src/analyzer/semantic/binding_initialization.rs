//! Binding initialization transfer facts over the semantic IR.
//!
//! Callers project binding reads and establishments, then use the same gen/kill
//! solve for ordinary reaching relations and initialization. Completeness and
//! language-specific refinements belong to the caller.

use crate::analyzer::semantic::cfg_algorithms::{GenKillFacts, ReachingSets};
use crate::analyzer::semantic::{
    MoveInvalidation, MoveOutFact, MoveOutState, ProcedureSemantics, ProgramPointId,
    SemanticEffect, SemanticEvent, SemanticPlace, SemanticValue, SemanticValueKind,
    SourceMappingId, TransferKind, ValueFlowKind, ValueId, ValueUseKind,
};
use brokk_bifrost_core::hash::{HashMap, HashSet};

/// Borrowed procedure facts available both during lowering and after publication.
pub trait BindingInitializationIr {
    fn entry_point(&self) -> ProgramPointId;
    fn point_count(&self) -> usize;
    fn values(&self) -> &[SemanticValue];
    fn events_at(&self, point: ProgramPointId) -> &[SemanticEvent];
    fn point_events(&self) -> impl Iterator<Item = (ProgramPointId, &[SemanticEvent])> {
        (0..self.point_count()).map(|index| {
            let point = ProgramPointId::try_from_index(index).expect("dense procedure points");
            (point, self.events_at(point))
        })
    }
    fn move_outs(&self) -> &[MoveOutFact];
    /// Positive declaration evidence, at the declaration's execution point.
    /// Unknown binding producers provide no certificate.
    fn uninitialized_declarations(&self) -> &[(ProgramPointId, ValueId)] {
        &[]
    }
    fn value(&self, binding: ValueId) -> Option<&SemanticValue> {
        self.values().get(binding.index())
    }
}

impl BindingInitializationIr for ProcedureSemantics {
    fn entry_point(&self) -> ProgramPointId {
        self.entry_point()
    }
    fn point_count(&self) -> usize {
        self.points().len()
    }
    fn values(&self) -> &[SemanticValue] {
        self.values()
    }
    fn events_at(&self, point: ProgramPointId) -> &[SemanticEvent] {
        &self.points()[point.index()].events
    }
    fn move_outs(&self) -> &[MoveOutFact] {
        self.move_outs()
    }
}

/// Identity of an event in its owning procedure's IR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BindingEventKey {
    pub point: ProgramPointId,
    pub event_index: u32,
    pub source: SourceMappingId,
}

/// A projected binding read or establishment. The caller owns the dense event id.
#[derive(Debug, Clone, Copy)]
pub struct BindingInitializationEvent {
    pub event: usize,
    pub key: BindingEventKey,
    pub binding: ValueId,
    pub establishes: bool,
}

/// Direct IR writes that can populate a binding, independent of source syntax.
/// Callers distinguish binding values from temporary expression results.
pub fn binding_write_target(effect: &SemanticEffect) -> Option<ValueId> {
    match effect {
        SemanticEffect::Assignment { target, .. }
        | SemanticEffect::ValueFlow { target, .. }
        | SemanticEffect::MemoryLoad { result: target, .. }
        | SemanticEffect::CallableCreation { result: target, .. }
        | SemanticEffect::CallableReference { result: target, .. } => Some(*target),
        _ => None,
    }
}

/// Binding invalidated by an IR move or unbind.
pub fn invalidated_binding(effect: &SemanticEffect) -> Option<ValueId> {
    match effect {
        SemanticEffect::ValueFlow {
            kind: ValueFlowKind::Transfer(transfer),
            source,
            ..
        } if matches!(transfer.kind, TransferKind::Move { .. }) => Some(*source),
        SemanticEffect::ValueUse {
            kind: ValueUseKind::Unbind,
            value,
        } => Some(*value),
        _ => None,
    }
}

/// Shared reaching definitions and ordered initialization transitions.
pub struct BindingDefinitions {
    /// Definition id -> event id.
    events: Vec<usize>,
    /// Definition id -> the dense program point index it is generated at.
    points: Vec<usize>,
    /// Definition id -> subject.
    bindings: Vec<ValueId>,
    /// A synthetic fact that reaches every executable point after entry.
    reachable: usize,
    full_moves: HashSet<(ProgramPointId, SourceMappingId, ValueId, ValueId)>,
    initialized_by_binding: HashMap<ValueId, usize>,
    last_initialized_by_point: HashMap<(usize, ValueId), bool>,
    /// Legacy may-uninitialized over-approximation for flow's existing query.
    /// These facts are not affirmative emptiness evidence and never authorize
    /// the definite proof, whose initialized facts start true for all bindings.
    uninitialized_by_binding: HashMap<ValueId, usize>,
    /// Last initialization transition within each point, in semantic order.
    last_uninitialized_by_point: HashMap<(usize, ValueId), bool>,
}

impl BindingDefinitions {
    /// Establishment event ids, indexed by the shared solve's definition ids.
    pub fn events(&self) -> &[usize] {
        &self.events
    }

    /// Binding named by one establishment definition.
    pub fn binding(&self, definition: usize) -> ValueId {
        self.bindings[definition]
    }

    pub fn build(
        procedure: &impl BindingInitializationIr,
        events: &[BindingInitializationEvent],
    ) -> Self {
        let mut definitions = Self {
            events: Vec::new(),
            points: Vec::new(),
            bindings: Vec::new(),
            reachable: 0,
            full_moves: procedure
                .move_outs()
                .iter()
                .filter(|moved| {
                    moved.state_after == MoveOutState::Uninitialized
                        && matches!(moved.place, SemanticPlace::LocalBinding(_))
                })
                .map(|moved| {
                    (
                        moved.point,
                        moved.source,
                        moved.source_value,
                        moved.target_value,
                    )
                })
                .collect(),
            initialized_by_binding: HashMap::default(),
            last_initialized_by_point: HashMap::default(),
            uninitialized_by_binding: HashMap::default(),
            last_uninitialized_by_point: HashMap::default(),
        };
        for event in events {
            if !event.establishes {
                continue;
            }
            definitions.events.push(event.event);
            definitions.points.push(event.key.point.index());
            definitions.bindings.push(event.binding);
        }
        definitions.reachable = definitions.events.len();
        let observed_bindings = events
            .iter()
            .map(|event| event.binding)
            .collect::<HashSet<_>>();
        for value in procedure.values() {
            if observed_bindings.contains(&value.id) && value.kind.is_binding() {
                let definition =
                    definitions.reachable + 1 + definitions.uninitialized_by_binding.len();
                definitions
                    .uninitialized_by_binding
                    .insert(value.id, definition);
            }
        }

        for binding in definitions.uninitialized_by_binding.keys() {
            definitions.initialized_by_binding.insert(
                *binding,
                definitions.reachable
                    + 1
                    + definitions.uninitialized_by_binding.len()
                    + definitions.initialized_by_binding.len(),
            );
        }
        let projected_establishments = events
            .iter()
            .filter(|event| event.establishes)
            .map(|event| (event.key, event.binding))
            .collect::<HashMap<_, _>>();
        for (point, point_events) in procedure.point_events() {
            for (event_index, event) in point_events.iter().enumerate() {
                let key = BindingEventKey {
                    point,
                    event_index: event_index as u32,
                    source: event.source,
                };
                if let Some(binding) = projected_establishments.get(&key)
                    && definitions.uninitialized_by_binding.contains_key(binding)
                {
                    definitions
                        .last_uninitialized_by_point
                        .insert((point.index(), *binding), false);
                }
                if let Some(binding) = invalidated_binding(&event.effect)
                    && definitions.uninitialized_by_binding.contains_key(&binding)
                {
                    definitions
                        .last_uninitialized_by_point
                        .insert((point.index(), binding), true);
                }
            }
        }
        // The definite proof starts every binding initialized, regardless of
        // its value kind. Only explicit declarations and full moves clear it.
        for (point, binding) in procedure.uninitialized_declarations() {
            definitions
                .last_initialized_by_point
                .insert((point.index(), *binding), false);
        }
        // Preserve the original may-uninitialized transitions. A separate
        // synthetic may-initialized fact distinguishes joins without killing
        // the establishment identities used by ordinary reaching relations.
        for (point, events) in procedure.point_events() {
            for (event_index, event) in events.iter().enumerate() {
                let key = BindingEventKey {
                    point,
                    event_index: event_index as u32,
                    source: event.source,
                };
                if let Some(binding) = projected_establishments.get(&key) {
                    definitions
                        .last_initialized_by_point
                        .insert((point.index(), *binding), true);
                }
                if let Some(binding) = definitions.full_move_source(point, event) {
                    definitions
                        .last_initialized_by_point
                        .insert((point.index(), binding), false);
                }
            }
        }
        definitions
    }

    /// Logical cells across gen, kill, IN and OUT matrices, before allocation.
    /// Saturation forces an overlarge shape to fail its caller's work budget.
    pub fn dense_solve_cells(&self, procedure: &impl BindingInitializationIr) -> usize {
        let definitions = self
            .reachable
            .saturating_add(1)
            .saturating_add(self.uninitialized_by_binding.len())
            .saturating_add(self.initialized_by_binding.len());
        procedure
            .point_count()
            .saturating_mul(definitions)
            .saturating_mul(4)
    }

    pub fn gen_kill(&self, procedure: &impl BindingInitializationIr) -> GenKillFacts {
        let entry = procedure.entry_point().index();
        let mut facts = GenKillFacts::new(
            procedure.point_count(),
            self.reachable
                + 1
                + self.uninitialized_by_binding.len()
                + self.initialized_by_binding.len(),
        );
        facts.record_generated(entry, self.reachable);
        for (binding, definition) in &self.uninitialized_by_binding {
            let value = procedure
                .value(*binding)
                .expect("read binding belongs to procedure");
            if value.kind == SemanticValueKind::Local
                && self.last_uninitialized_by_point.get(&(entry, *binding)) != Some(&false)
            {
                facts.record_generated(entry, *definition);
            }
        }
        for (definition, point) in self.points.iter().copied().enumerate() {
            facts.record_generated(point, definition);
            for (other, subject) in self.bindings.iter().enumerate() {
                if other != definition && *subject == self.bindings[definition] {
                    facts.record_killed(point, other);
                }
            }
        }
        for ((point, binding), uninitialized) in &self.last_uninitialized_by_point {
            let definition = self.uninitialized_by_binding[binding];
            if *uninitialized {
                facts.record_generated(*point, definition);
            } else {
                facts.record_killed(*point, definition);
            }
        }
        for (binding, definition) in &self.initialized_by_binding {
            // A declaration or full move at entry overrides the default seed.
            if self.last_initialized_by_point.get(&(entry, *binding)) != Some(&false) {
                facts.record_generated(entry, *definition);
            }
        }
        for ((point, binding), initialized) in &self.last_initialized_by_point {
            let Some(definition) = self.initialized_by_binding.get(binding) else {
                continue;
            };
            if *initialized {
                facts.record_generated(*point, *definition);
            } else {
                facts.record_killed(*point, *definition);
            }
        }
        facts
    }

    pub fn uninitialized_before_event(
        &self,
        procedure: &impl BindingInitializationIr,
        events: &[BindingInitializationEvent],
        reaching: &ReachingSets,
    ) -> HashMap<usize, bool> {
        let projected_events = events
            .iter()
            .map(|event| (event.key, (event.event, event.establishes, event.binding)))
            .collect::<HashMap<_, _>>();
        let mut facts = HashMap::default();
        for (point, point_events) in procedure.point_events() {
            let index = point.index();
            if point != procedure.entry_point() && !reaching.reaches_in(index, self.reachable) {
                continue;
            }
            let mut state_at_point = HashMap::<ValueId, bool>::default();
            for (event_index, semantic_event) in point_events.iter().enumerate() {
                let key = BindingEventKey {
                    point,
                    event_index: event_index as u32,
                    source: semantic_event.source,
                };
                if let Some(&(event, establishes, binding)) = projected_events.get(&key) {
                    let uninitialized = *state_at_point.entry(binding).or_insert_with(|| {
                        let definition = self.uninitialized_by_binding[&binding];
                        (point == procedure.entry_point()
                            && procedure
                                .value(binding)
                                .is_some_and(|value| value.kind == SemanticValueKind::Local))
                            || reaching.reaches_in(index, definition)
                    });
                    facts.insert(event, uninitialized);
                    if establishes {
                        state_at_point.insert(binding, false);
                    }
                }
                if let Some(binding) = invalidated_binding(&semantic_event.effect)
                    && self.uninitialized_by_binding.contains_key(&binding)
                {
                    state_at_point.insert(binding, true);
                }
            }
        }
        facts
    }
    fn full_move_source(&self, point: ProgramPointId, event: &SemanticEvent) -> Option<ValueId> {
        let SemanticEffect::ValueFlow {
            source,
            target,
            kind: ValueFlowKind::Transfer(transfer),
        } = event.effect
        else {
            return None;
        };
        (matches!(
            transfer.kind,
            TransferKind::Move {
                invalidation: MoveInvalidation::Invalidated
            }
        ) && self
            .full_moves
            .contains(&(point, event.source, source, target)))
        .then_some(source)
    }

    /// Whether every represented path leaves the whole binding without a value
    /// before this event. Completeness of control and partial-place writes is
    /// the caller's obligation. Unknown/full-move evidence is never assumed.
    pub fn definitely_uninitialized_before_event(
        &self,
        procedure: &impl BindingInitializationIr,
        event: BindingInitializationEvent,
        reaching: &ReachingSets,
    ) -> bool {
        let Some(definition) = self.initialized_by_binding.get(&event.binding) else {
            return false;
        };
        if event.key.point != procedure.entry_point()
            && !reaching.reaches_in(event.key.point.index(), self.reachable)
        {
            return false;
        }
        let mut initialized = event.key.point == procedure.entry_point()
            || reaching.reaches_in(event.key.point.index(), *definition);
        if procedure
            .uninitialized_declarations()
            .contains(&(event.key.point, event.binding))
        {
            initialized = false;
        }
        let effects = procedure.events_at(event.key.point);
        // Same-point writes precede the selected event in semantic order.
        for effect in effects.iter().take(event.key.event_index as usize) {
            if binding_write_target(&effect.effect) == Some(event.binding) {
                initialized = true;
            }
            if self.full_move_source(event.key.point, effect) == Some(event.binding) {
                initialized = false;
            }
        }
        !initialized
    }
}
