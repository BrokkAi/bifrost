//! Temporal identity of procedure-local bindings at guard points.
//!
//! A static predecessor walk can say that a temporary was once copied from a
//! local binding, but it cannot say that the binding has not been overwritten
//! since that copy.  This analysis keeps only the bindings that are still
//! current at each CFG point.  Alternatives meet by intersection: a
//! provenance absent from one incoming path is not a proof at the join.
//!
//! Only a guard-subject query can observe the result, so state is carried for
//! the values such a query can name and for the values that copy into one.
//! Every other value would carry state that nothing reads.

use std::collections::VecDeque;

use super::correlations::{
    CorrelationError, open_bindings, produced_value, unknown_write_bindings,
};
use crate::analyzer::WorkspaceAnalyzer;
use crate::analyzer::semantic::{
    CancellationToken, GuardFact, GuardPredicate, ProcedureHandle, ProcedureSemantics,
    ProgramPoint, ProgramPointId, SemanticBudget, SemanticEffect, SemanticValueKind, SemanticWork,
    TypeFlowAdapter, ValueFlowKind, ValueId,
};
use crate::hash::{HashMap, HashSet};

/// The still-current lexical binding for each supported guard subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct GuardBindings {
    by_guard: Vec<Option<ValueId>>,
    /// Exit state at the points a query may name.  See [`queried_points`].
    exits: HashMap<ProgramPointId, State>,
    /// The values a query may name.  See [`queried_values`].
    queried: HashSet<ValueId>,
    /// The points a query may name.  See [`queried_points`].
    retained: HashSet<ProgramPointId>,
}

impl GuardBindings {
    pub(super) fn binding_for_guard(&self, guard_index: usize) -> Option<ValueId> {
        self.by_guard.get(guard_index).copied().flatten()
    }

    /// The binding one adapter-supplied subject still equals at a point.
    ///
    /// The subject must be one [`queried_values`] admits and the point one
    /// [`queried_points`] admits.  Anything else carries no state, so
    /// answering it would silently report "not proven" for a value this
    /// analysis never tracked.
    pub(super) fn binding_at_point(
        &self,
        point: ProgramPointId,
        subject: ValueId,
    ) -> Option<ValueId> {
        assert!(
            self.queried.contains(&subject),
            "a binding query names a guard subject or an adapter refinement subject"
        );
        assert!(
            self.retained.contains(&point),
            "a binding query names a guard point or a normal continuation"
        );
        self.exits
            .get(&point)
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
    fn entry(bindings: &HashSet<ValueId>, tracked: &HashSet<ValueId>) -> Self {
        Self {
            current: bindings
                .iter()
                .copied()
                .filter(|binding| tracked.contains(binding))
                .map(|binding| (binding, binding))
                .collect(),
        }
    }

    fn clear_value(&mut self, value: ValueId) {
        self.current.remove(&value);
    }

    fn invalidate_binding(&mut self, binding: ValueId, tracked: &HashSet<ValueId>) {
        if !tracked.contains(&binding) {
            // Every origin this map records is a tracked binding, because the
            // entry state and this method are the only places that install
            // one, so an untracked binding is nobody's origin.
            debug_assert!(
                self.current.values().all(|origin| *origin != binding),
                "an untracked binding is not the origin of a tracked value"
            );
            return;
        }
        self.current
            .retain(|value, origin| *value == binding || *origin != binding);
        self.current.insert(binding, binding);
    }

    fn copy(&mut self, source: ValueId, target: ValueId, tracked: &HashSet<ValueId>) {
        if source == target || !tracked.contains(&target) {
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
///
/// `nested_entries` is charged for retained state alone: the entries stored
/// per point for the fixpoint, the entries kept in the exit map at a queried
/// point, and the per-procedure indexes. The copy a visit works on is
/// transient and is not charged; the propagation that makes those visits is
/// charged one `control_edges` unit per edge traversal.
pub(super) fn derive(
    workspace: &WorkspaceAnalyzer,
    adapter: &dyn TypeFlowAdapter,
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
    let queried = queried_values(workspace, adapter, procedure, budget, cancellation)?;
    let tracked = tracked_values(semantics, &bindings, &queried, budget, cancellation)?;
    let open = open_bindings(semantics);
    check_cancelled(cancellation)?;
    charge_entries(budget, open.len().saturating_add(1))?;

    let entry = semantics.entry_point();
    let point_count = semantics.points().len();
    let retained = queried_points(semantics, budget, cancellation)?;
    check_cancelled(cancellation)?;
    charge_entries(budget, point_count.saturating_mul(2).saturating_add(1))?;
    let mut incoming = vec![None::<State>; point_count];
    let mut exits = HashMap::<ProgramPointId, State>::default();
    incoming[entry.index()] = Some(State::entry(&bindings, &tracked));
    let mut queued = vec![false; point_count];
    queued[entry.index()] = true;
    check_cancelled(cancellation)?;
    charge_entries(budget, 1)?;
    let mut worklist = VecDeque::from([entry]);

    while let Some(point_id) = worklist.pop_front() {
        check_cancelled(cancellation)?;
        queued[point_id.index()] = false;
        // The visit's working copy is transient: it is charged only where it
        // becomes retained state, below and at the exit map.
        let mut state = incoming[point_id.index()]
            .as_ref()
            .expect("a scheduled binding-refinement point is reachable")
            .clone();
        transfer_point(
            semantics,
            point_id,
            &bindings,
            &tracked,
            &open,
            &mut state,
            cancellation,
        )?;
        if retained.contains(&point_id) {
            let previous = exits.get(&point_id).map_or(0, State::size);
            charge_entries(budget, state.size().saturating_sub(previous))?;
            exits.insert(point_id, state.clone());
        }

        for (_edge_id, edge) in semantics.successor_edges(point_id) {
            check_cancelled(cancellation)?;
            charge_edges(budget, 1)?;
            let target = edge.target_point.index();
            let changed = if let Some(existing) = &mut incoming[target] {
                // Intersection only removes entries, so this join retains
                // nothing new and charges nothing new.
                existing.intersect(&state)
            } else {
                charge_entries(budget, state.size())?;
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
        let subject = guard_predicate_subject(guard);
        let binding = subject
            .and_then(|subject| exits.get(&guard.point)?.current.get(&subject))
            .copied();
        by_guard.push(binding);
    }

    Ok(GuardBindings {
        by_guard,
        exits,
        queried,
        retained,
    })
}

fn transfer_point(
    semantics: &ProcedureSemantics,
    point_id: ProgramPointId,
    bindings: &HashSet<ValueId>,
    tracked: &HashSet<ValueId>,
    open: &HashSet<ValueId>,
    state: &mut State,
    cancellation: &CancellationToken,
) -> Result<(), CorrelationError> {
    let point = semantics
        .point(point_id)
        .expect("a validated binding-refinement point remains live");
    for (event_index, event) in point.events.iter().enumerate() {
        check_cancelled(cancellation)?;
        match &event.effect {
            SemanticEffect::Assignment { target, value } => {
                if bindings.contains(target) {
                    state.invalidate_binding(*target, tracked);
                } else {
                    state.copy(*value, *target, tracked);
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
                    state.invalidate_binding(*target, tracked);
                } else if is_identity_flow(*kind) {
                    state.copy(*source, *target, tracked);
                } else {
                    state.clear_value(*target);
                }
            }
            effect => {
                for value in unknown_write_bindings(effect, semantics, open) {
                    if bindings.contains(&value) {
                        state.invalidate_binding(value, tracked);
                    } else {
                        state.clear_value(value);
                    }
                }
                if let Some(result) = produced_value(effect) {
                    if bindings.contains(&result) {
                        state.invalidate_binding(result, tracked);
                    } else {
                        state.clear_value(result);
                    }
                }
            }
        }
    }
    Ok(())
}

/// The value one guard fact tests directly, when the predicate names one.
fn guard_predicate_subject(guard: &GuardFact) -> Option<ValueId> {
    match guard.predicate {
        GuardPredicate::InstanceOf { value, .. }
        | GuardPredicate::ExactClass { value, .. }
        | GuardPredicate::HasMember { value, .. }
        | GuardPredicate::Truthy { value } => Some(value),
        GuardPredicate::NullComparison { .. } => guard.subject,
        GuardPredicate::ConstantBoolean { .. }
        | GuardPredicate::ConstantEquality { .. }
        | GuardPredicate::Opaque { .. } => None,
    }
}

/// Every value a consumer of this analysis may ask about.
///
/// Two kinds of query exist.  A guard fact asks for the binding its own
/// predicate subject equals.  An adapter asks for the binding one call's
/// actual argument equals, through `call_guard_narrowing` or
/// `normal_return_type_constraints`; `TypeFlowAdapter::refinement_subjects`
/// states which values those two can name.
fn queried_values(
    workspace: &WorkspaceAnalyzer,
    adapter: &dyn TypeFlowAdapter,
    procedure: &ProcedureHandle,
    budget: &mut SemanticBudget,
    cancellation: &CancellationToken,
) -> Result<HashSet<ValueId>, CorrelationError> {
    let semantics = procedure.semantics();
    let mut queried = HashSet::default();
    for guard in semantics.guard_facts() {
        check_cancelled(cancellation)?;
        charge_entries(budget, 1)?;
        if let Some(subject) = guard.subject {
            queried.insert(subject);
        }
        if let Some(subject) = guard_predicate_subject(guard) {
            queried.insert(subject);
        }
    }
    let subjects = adapter.refinement_subjects(workspace, procedure);
    charge_entries(budget, subjects.len().saturating_add(1))?;
    for subject in subjects {
        check_cancelled(cancellation)?;
        queried.insert(subject);
    }
    Ok(queried)
}

/// The points whose exit state a query may name: every guard point, and
/// every normal continuation a return contract can constrain.
fn queried_points(
    semantics: &ProcedureSemantics,
    budget: &mut SemanticBudget,
    cancellation: &CancellationToken,
) -> Result<HashSet<ProgramPointId>, CorrelationError> {
    let mut points = HashSet::default();
    for guard in semantics.guard_facts() {
        check_cancelled(cancellation)?;
        charge_entries(budget, 1)?;
        points.insert(guard.point);
    }
    for call in semantics.call_sites() {
        check_cancelled(cancellation)?;
        charge_entries(budget, 1)?;
        if let Some(normal) = call.normal_continuation.target() {
            points.insert(normal);
        }
    }
    Ok(points)
}

/// The queried values together with every value that copies into one.
///
/// The transfer function reads the state of a copy's source to write the
/// state of its target, so a value outside this closure can never change the
/// answer at a queried value and needs no state.  The closure ignores CFG
/// order on purpose: taking every copy event in the procedure over-covers any
/// one path through it.
fn tracked_values(
    semantics: &ProcedureSemantics,
    bindings: &HashSet<ValueId>,
    queried: &HashSet<ValueId>,
    budget: &mut SemanticBudget,
    cancellation: &CancellationToken,
) -> Result<HashSet<ValueId>, CorrelationError> {
    let mut sources_of = HashMap::<ValueId, Vec<ValueId>>::default();
    for point in semantics.points() {
        check_cancelled(cancellation)?;
        charge_entries(budget, point.events.len().saturating_add(1))?;
        for (event_index, event) in point.events.iter().enumerate() {
            let (source, target) = match &event.effect {
                SemanticEffect::Assignment { target, value } => (*value, *target),
                SemanticEffect::ValueFlow {
                    kind,
                    source,
                    target,
                } => {
                    if !is_identity_flow(*kind)
                        || is_assignment_transfer_marker(point, event_index, *source, *target)
                    {
                        continue;
                    }
                    (*source, *target)
                }
                _ => continue,
            };
            if source == target || bindings.contains(&target) {
                continue;
            }
            sources_of.entry(target).or_default().push(source);
        }
    }
    let mut tracked = queried.clone();
    let mut pending = queried.iter().copied().collect::<Vec<_>>();
    while let Some(target) = pending.pop() {
        check_cancelled(cancellation)?;
        charge_entries(budget, 1)?;
        let Some(sources) = sources_of.get(&target) else {
            continue;
        };
        charge_entries(budget, sources.len())?;
        for &source in sources {
            if tracked.insert(source) {
                pending.push(source);
            }
        }
    }
    Ok(tracked)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic::{
        CancellationToken, ProcedureHandle, SemanticBudget, SemanticRequest, type_flow_adapter,
    };
    use crate::analyzer::{AnalyzerConfig, Language, WorkspaceAnalyzer};
    use crate::inline_project::InlineTestProject;

    const SOURCE: &str = concat!(
        "class Thing:\n",
        "    pass\n",
        "\n",
        "def check(flag, spare):\n",
        "    idle = spare\n",
        "    if isinstance(flag, Thing):\n",
        "        return idle\n",
        "    return None\n",
    );

    fn derive_check() -> (WorkspaceAnalyzer, ProcedureHandle, GuardBindings) {
        let project = InlineTestProject::with_language(Language::Python)
            .file("app.py", SOURCE)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &project.file("app.py"),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("the fixture materializes")
            .available_value()
            .cloned()
            .expect("the fixture stays available");
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("check")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("the fixture declares `check`");
        let adapter = type_flow_adapter(Language::Python).expect("Python has a type-flow adapter");
        let bindings = derive(&workspace, adapter, &procedure, &mut budget, &cancellation)
            .expect("binding refinement completes within the default budget");
        (workspace, procedure, bindings)
    }

    fn parameter(procedure: &ProcedureHandle, name: &str) -> ValueId {
        procedure
            .semantics()
            .values()
            .iter()
            .find(|value| {
                matches!(
                    &value.kind,
                    SemanticValueKind::Parameter { name: Some(actual), .. } if actual.as_ref() == name
                )
            })
            .map(|value| value.id)
            .unwrap_or_else(|| panic!("the fixture declares the parameter `{name}`"))
    }

    #[test]
    fn a_guard_subject_still_refines_to_its_lexical_binding() {
        let (_workspace, procedure, bindings) = derive_check();
        let guard = bindings
            .binding_for_guard(0)
            .expect("the `isinstance` guard subject is still the parameter it was read from");
        assert_eq!(guard, parameter(&procedure, "flag"));
    }

    #[test]
    fn a_value_that_reaches_no_guard_subject_carries_no_state() {
        let (_workspace, procedure, bindings) = derive_check();
        let spare = parameter(&procedure, "spare");
        for state in bindings.exits.values() {
            assert!(
                !state.current.contains_key(&spare),
                "an unqueried parameter is not tracked: {state:?}"
            );
            assert!(
                state.current.values().all(|binding| *binding != spare),
                "an unqueried parameter is nobody's origin: {state:?}"
            );
        }
        assert!(
            !bindings.queried.contains(&spare),
            "an unqueried parameter is not a query subject"
        );
    }
}
