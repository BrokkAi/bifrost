//! Temporal identity of procedure-local bindings at guard points.
//!
//! A static predecessor walk can say that a temporary was once copied from a
//! local binding, but it cannot say that the binding has not been overwritten
//! since that copy.  This analysis keeps only the bindings that are still
//! current at each CFG point.  Alternatives meet by intersection: a
//! provenance absent from one incoming path is not a proof at the join.

use std::collections::VecDeque;

use super::correlations::{
    CorrelationError, open_bindings, produced_value, unknown_write_bindings,
};
use crate::analyzer::semantic::{
    CancellationToken, GuardPredicate, ProcedureHandle, ProgramPoint, ProgramPointId,
    SemanticBudget, SemanticEffect, SemanticValueKind, SemanticWork, ValueFlowKind, ValueId,
};
use crate::hash::{HashMap, HashSet};

/// The still-current lexical binding for each supported guard subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct GuardBindings {
    by_guard: Vec<Option<ValueId>>,
    exits: Vec<Option<State>>,
}

impl GuardBindings {
    pub(super) fn binding_for_guard(&self, guard_index: usize) -> Option<ValueId> {
        self.by_guard.get(guard_index).copied().flatten()
    }

    pub(super) fn binding_at_point(
        &self,
        point: ProgramPointId,
        subject: ValueId,
    ) -> Option<ValueId> {
        self.exits
            .get(point.index())
            .and_then(Option::as_ref)
            .and_then(|state| state.current.get(&subject))
            .copied()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct State {
    /// A value is mapped only when it is known to equal the current value in
    /// one lexical binding.  Missing entries are deliberately unproven.
    current: HashMap<ValueId, ValueId>,
}

impl State {
    fn entry(bindings: &HashSet<ValueId>) -> Self {
        Self {
            current: bindings
                .iter()
                .copied()
                .map(|binding| (binding, binding))
                .collect(),
        }
    }

    fn clear_value(&mut self, value: ValueId) {
        self.current.remove(&value);
    }

    fn invalidate_binding(&mut self, binding: ValueId) {
        self.current
            .retain(|value, origin| *value == binding || *origin != binding);
        self.current.insert(binding, binding);
    }

    fn copy(&mut self, source: ValueId, target: ValueId) {
        if source == target {
            return;
        }
        if let Some(&binding) = self.current.get(&source) {
            self.current.insert(target, binding);
        } else {
            self.current.remove(&target);
        }
    }

    fn intersect(&mut self, other: &Self) -> bool {
        let before = self.current.len();
        self.current.retain(|value, binding| {
            other
                .current
                .get(value)
                .is_some_and(|other_binding| other_binding == binding)
        });
        before != self.current.len()
    }

    fn size(&self) -> usize {
        self.current.len()
    }
}

/// Derive the binding that each supported guard subject still equals.
///
/// The result is indexed by the procedure's validated `guard_facts()` order.
/// A missing entry means that the subject was never an identity read, was
/// overwritten, or did not survive every incoming CFG path.
pub(super) fn derive(
    procedure: &ProcedureHandle,
    budget: &mut SemanticBudget,
    cancellation: &CancellationToken,
) -> Result<GuardBindings, CorrelationError> {
    check_cancelled(cancellation)?;
    let semantics = procedure.semantics();
    let bindings = semantics
        .values()
        .iter()
        .filter(|value| is_binding_kind(&value.kind))
        .map(|value| value.id)
        .collect::<HashSet<_>>();
    check_cancelled(cancellation)?;
    charge_entries(budget, bindings.len().saturating_add(1))?;
    let open = open_bindings(semantics);
    check_cancelled(cancellation)?;
    charge_entries(budget, open.len().saturating_add(1))?;

    let entry = semantics.entry_point();
    let point_count = semantics.points().len();
    check_cancelled(cancellation)?;
    charge_entries(budget, point_count.saturating_mul(3).saturating_add(1))?;
    let mut incoming = vec![None::<State>; point_count];
    let mut exits = vec![None::<State>; point_count];
    incoming[entry.index()] = Some(State::entry(&bindings));
    let mut queued = vec![false; point_count];
    queued[entry.index()] = true;
    check_cancelled(cancellation)?;
    charge_entries(budget, 1)?;
    let mut worklist = VecDeque::from([entry]);

    while let Some(point_id) = worklist.pop_front() {
        check_cancelled(cancellation)?;
        queued[point_id.index()] = false;
        let incoming_state = incoming[point_id.index()]
            .as_ref()
            .expect("a scheduled binding-refinement point is reachable");
        charge_entries(budget, incoming_state.size().saturating_add(1))?;
        let mut state = incoming_state.clone();
        transfer_point(
            semantics,
            point_id,
            &bindings,
            &open,
            &mut state,
            budget,
            cancellation,
        )?;
        charge_entries(budget, state.size().saturating_add(1))?;
        exits[point_id.index()] = Some(state.clone());

        for (_edge_id, edge) in semantics.successor_edges(point_id) {
            check_cancelled(cancellation)?;
            charge_edges(budget, 1)?;
            let target = edge.target_point.index();
            let changed = if let Some(existing) = &mut incoming[target] {
                charge_entries(
                    budget,
                    existing
                        .size()
                        .saturating_add(state.size())
                        .saturating_add(1),
                )?;
                existing.intersect(&state)
            } else {
                charge_entries(budget, state.size().saturating_add(1))?;
                incoming[target] = Some(state.clone());
                true
            };
            if changed && !queued[target] {
                queued[target] = true;
                worklist.push_back(edge.target_point);
            }
        }
    }

    check_cancelled(cancellation)?;
    let guard_count = semantics.guard_facts().len();
    charge_entries(budget, guard_count.saturating_add(1))?;
    let mut by_guard = Vec::with_capacity(guard_count);
    for guard in semantics.guard_facts() {
        check_cancelled(cancellation)?;
        charge_entries(budget, 1)?;
        let subject = match guard.predicate {
            GuardPredicate::InstanceOf { value, .. }
            | GuardPredicate::ExactClass { value, .. }
            | GuardPredicate::HasMember { value, .. }
            | GuardPredicate::Truthy { value } => Some(value),
            GuardPredicate::NullComparison { .. } => guard.subject,
            GuardPredicate::ConstantBoolean { .. }
            | GuardPredicate::ConstantEquality { .. }
            | GuardPredicate::Opaque { .. } => None,
        };
        let binding = subject
            .and_then(|subject| exits[guard.point.index()].as_ref()?.current.get(&subject))
            .copied();
        by_guard.push(binding);
    }

    Ok(GuardBindings { by_guard, exits })
}

fn transfer_point(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    point_id: ProgramPointId,
    bindings: &HashSet<ValueId>,
    open: &HashSet<ValueId>,
    state: &mut State,
    budget: &mut SemanticBudget,
    cancellation: &CancellationToken,
) -> Result<(), CorrelationError> {
    let point = semantics
        .point(point_id)
        .expect("a validated binding-refinement point remains live");
    charge_entries(budget, point.events.len().saturating_add(1))?;
    for (event_index, event) in point.events.iter().enumerate() {
        check_cancelled(cancellation)?;
        match &event.effect {
            SemanticEffect::Assignment { target, value } => {
                if bindings.contains(target) {
                    state.invalidate_binding(*target);
                } else {
                    state.copy(*value, *target);
                }
            }
            SemanticEffect::ValueFlow {
                kind,
                source,
                target,
            } => {
                if is_assignment_transfer_marker(point, event_index, *source, *target) {
                    continue;
                }
                if bindings.contains(target) {
                    state.invalidate_binding(*target);
                } else if is_identity_flow(*kind) {
                    state.copy(*source, *target);
                } else {
                    state.clear_value(*target);
                }
            }
            effect => {
                for value in unknown_write_bindings(effect, semantics, open) {
                    if bindings.contains(&value) {
                        state.invalidate_binding(value);
                    } else {
                        state.clear_value(value);
                    }
                }
                if let Some(result) = produced_value(effect) {
                    if bindings.contains(&result) {
                        state.invalidate_binding(result);
                    } else {
                        state.clear_value(result);
                    }
                }
            }
        }
    }
    Ok(())
}

fn is_binding_kind(kind: &SemanticValueKind) -> bool {
    matches!(
        kind,
        SemanticValueKind::Local
            | SemanticValueKind::Parameter { .. }
            | SemanticValueKind::Receiver { .. }
    )
}

fn is_identity_flow(kind: ValueFlowKind) -> bool {
    matches!(
        kind,
        ValueFlowKind::Local | ValueFlowKind::Parameter | ValueFlowKind::Receiver
    )
}

fn is_assignment_transfer_marker(
    point: &ProgramPoint,
    event_index: usize,
    source: ValueId,
    target: ValueId,
) -> bool {
    event_index > 0
        && matches!(
            &point.events[event_index - 1].effect,
            SemanticEffect::Assignment {
                target: previous_target,
                value: previous_value,
            } if *previous_target == target && *previous_value == source
        )
}

fn check_cancelled(cancellation: &CancellationToken) -> Result<(), CorrelationError> {
    if cancellation.is_cancelled() {
        return Err(CorrelationError::Cancelled {
            timed_out: cancellation.is_timed_out(),
        });
    }
    Ok(())
}

fn charge_entries(budget: &mut SemanticBudget, count: usize) -> Result<(), CorrelationError> {
    if count == 0 {
        return Ok(());
    }
    budget.charge(SemanticWork {
        nested_entries: count,
        ..SemanticWork::default()
    })?;
    Ok(())
}

fn charge_edges(budget: &mut SemanticBudget, count: usize) -> Result<(), CorrelationError> {
    if count == 0 {
        return Ok(());
    }
    budget.charge(SemanticWork {
        control_edges: count,
        ..SemanticWork::default()
    })?;
    Ok(())
}
