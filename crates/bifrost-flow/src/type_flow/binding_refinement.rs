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
    CorrelationError, admit_set_entry, charge_edges, charge_entries, check_cancelled,
    correlation_event_candidate, open_bindings_from_copy_graph, produced_value, record_entry_work,
    tested_boolean_bindings_from_copy_graph, unknown_write_bindings,
};
use super::is_assignment_transfer_marker;
use crate::analyzer::WorkspaceAnalyzer;
use crate::analyzer::semantic::{
    BindingOriginIndex, CancellationToken, GuardFact, GuardPredicate, ProcedureHandle,
    ProcedureSemantics, ProgramPointId, SemanticBudget, SemanticEffect, SemanticValueKind,
    SemanticWork, TypeFlowAdapter, ValueFlowKind, ValueId,
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
    /// Values on a structured identity path from a boolean literal to a guard
    /// that correlation analysis can refine. This reuses the copy graph the
    /// binding analysis already built instead of rescanning every event.
    correlation_bindings: Vec<ValueId>,
    /// Every local whose storage an opaque effect can replace. Correlation
    /// refinement consumes the same inventory, so retain it with the copy
    /// graph result instead of rescanning the procedure's events.
    open_bindings: HashSet<ValueId>,
    /// Every local/parameter/receiver binding in deterministic order.
    data_bindings: Vec<ValueId>,
    /// Event indices that can replace a data or boolean component, grouped by
    /// dense program-point index.
    correlation_events: Vec<Vec<usize>>,
}

impl GuardBindings {
    pub(super) fn census(&self) -> crate::analyzer::semantic::SemanticWork {
        crate::analyzer::semantic::SemanticWork {
            nested_entries: self.by_guard.len()
                + self.exits.len()
                + self.exits.values().map(State::size).sum::<usize>()
                + self.queried.len()
                + self.retained.len()
                + self.correlation_bindings.len()
                + self.open_bindings.len()
                + self.data_bindings.len()
                + self.correlation_events.len()
                + self.correlation_events.iter().map(Vec::len).sum::<usize>(),
            ..Default::default()
        }
    }

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

    pub(super) fn correlation_bindings(&self) -> &[ValueId] {
        &self.correlation_bindings
    }

    pub(super) fn open_bindings(&self) -> &HashSet<ValueId> {
        &self.open_bindings
    }

    pub(super) fn data_bindings(&self) -> &[ValueId] {
        &self.data_bindings
    }

    pub(super) fn correlation_events(&self) -> &[Vec<usize>] {
        &self.correlation_events
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
        super::copy_tracked_value(&mut self.current, source, target, tracked);
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
/// charged one `control_edges` unit per edge traversal. The cache derivation
/// scope refunds scratch on every returned outcome and admits only the result census.
pub(super) fn derive(
    workspace: &WorkspaceAnalyzer,
    adapter: &dyn TypeFlowAdapter,
    procedure: &ProcedureHandle,
    budget: &mut SemanticBudget,
    cancellation: &CancellationToken,
) -> Result<GuardBindings, CorrelationError> {
    check_cancelled(Some(cancellation))?;
    let semantics = procedure.semantics();
    let binding_origins = BindingOriginIndex::new(procedure);
    let bindings = semantics
        .values()
        .iter()
        .filter(|value| value.kind.is_binding())
        .map(|value| value.id)
        .collect::<HashSet<_>>();
    check_cancelled(Some(cancellation))?;
    charge_entries(budget, bindings.len().saturating_add(1))?;
    let queried = queried_values(workspace, adapter, procedure, budget, cancellation)?;
    let TrackedValues {
        values: tracked,
        reverse_copies,
        forward_copies,
        address_sources,
        correlation_events,
    } = tracked_values(semantics, &bindings, &queried, budget, cancellation)?;
    let correlation_bindings = tested_boolean_bindings_from_copy_graph(
        semantics,
        &reverse_copies,
        &forward_copies,
        budget,
        Some(cancellation),
    )?;
    let open =
        open_bindings_from_copy_graph(semantics, &bindings, &reverse_copies, &address_sources);
    check_cancelled(Some(cancellation))?;
    charge_entries(budget, open.len().saturating_add(1))?;

    let entry = semantics.entry_point();
    let point_count = semantics.points().len();
    let retained = queried_points(semantics, budget, cancellation)?;
    check_cancelled(Some(cancellation))?;
    charge_entries(budget, point_count.saturating_mul(2).saturating_add(1))?;
    let mut incoming = vec![None::<State>; point_count];
    let mut exits = HashMap::<ProgramPointId, State>::default();
    let entry_state = State::entry(&bindings, &tracked);
    charge_entries(budget, entry_state.size())?;
    incoming[entry.index()] = Some(entry_state);
    let mut queued = vec![false; point_count];
    queued[entry.index()] = true;
    check_cancelled(Some(cancellation))?;
    charge_entries(budget, 1)?;
    let mut worklist = VecDeque::from([entry]);
    let transfer = TransferContext {
        semantics,
        bindings: &bindings,
        tracked: &tracked,
        open: &open,
        binding_origins: &binding_origins,
        cancellation,
    };

    while let Some(point_id) = worklist.pop_front() {
        check_cancelled(Some(cancellation))?;
        queued[point_id.index()] = false;
        // The visit's working copy is transient: it is charged only where it
        // becomes retained state, below and at the exit map.
        let mut state = incoming[point_id.index()]
            .as_ref()
            .expect("a scheduled binding-refinement point is reachable")
            .clone();
        transfer_point(&transfer, point_id, &mut state)?;
        if retained.contains(&point_id) {
            let previous = exits.get(&point_id).map_or(0, State::size);
            charge_entries(budget, state.size().saturating_sub(previous))?;
            budget.release_admission(SemanticWork {
                nested_entries: previous.saturating_sub(state.size()),
                ..SemanticWork::default()
            });
            exits.insert(point_id, state.clone());
        }

        for (_edge_id, edge) in semantics.successor_edges(point_id) {
            check_cancelled(Some(cancellation))?;
            charge_edges(budget, 1)?;
            let target = edge.target_point.index();
            let changed = if let Some(existing) = &mut incoming[target] {
                // Intersection only removes entries, so this join retains
                // nothing new and charges nothing new.
                let previous = existing.size();
                let changed = existing.intersect(&state);
                budget.release_admission(SemanticWork {
                    nested_entries: previous - existing.size(),
                    ..SemanticWork::default()
                });
                changed
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

    check_cancelled(Some(cancellation))?;
    let guard_count = semantics.guard_facts().len();
    charge_entries(budget, guard_count.saturating_add(1))?;
    let mut by_guard = Vec::with_capacity(guard_count);
    for guard in semantics.guard_facts() {
        check_cancelled(Some(cancellation))?;
        record_entry_work(budget, 1);
        let subject = guard_predicate_subject(guard);
        let binding = subject
            .and_then(|subject| exits.get(&guard.point)?.current.get(&subject))
            .copied();
        by_guard.push(binding);
    }

    let mut data_bindings = bindings.into_iter().collect::<Vec<_>>();
    data_bindings.sort_unstable();
    Ok(GuardBindings {
        by_guard,
        exits,
        queried,
        retained,
        correlation_bindings,
        open_bindings: open,
        data_bindings,
        correlation_events,
    })
}

#[derive(Clone, Copy)]
struct TransferContext<'a> {
    semantics: &'a ProcedureSemantics,
    bindings: &'a HashSet<ValueId>,
    tracked: &'a HashSet<ValueId>,
    open: &'a HashSet<ValueId>,
    binding_origins: &'a BindingOriginIndex,
    cancellation: &'a CancellationToken,
}

fn transfer_point(
    context: &TransferContext<'_>,
    point_id: ProgramPointId,
    state: &mut State,
) -> Result<(), CorrelationError> {
    let TransferContext {
        semantics,
        bindings,
        tracked,
        open,
        binding_origins,
        cancellation,
    } = *context;
    let point = semantics
        .point(point_id)
        .expect("a validated binding-refinement point remains live");
    for (event_index, event) in point.events.iter().enumerate() {
        check_cancelled(Some(cancellation))?;
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
            SemanticEffect::MemoryStore {
                location, value, ..
            } if semantics
                .memory_location(*location)
                .is_some_and(|location| {
                    matches!(
                        location.kind,
                        crate::analyzer::semantic::MemoryLocationKind::Dereference { .. }
                    )
                }) =>
            {
                let address = match semantics.memory_location(*location).map(|row| &row.kind) {
                    Some(crate::analyzer::semantic::MemoryLocationKind::Dereference {
                        address,
                    }) => *address,
                    _ => unreachable!("the guard above selected a dereference store"),
                };
                let origins = binding_origins.addressed_binding_origins(address);
                if let Some(binding) = origins.unique_binding() {
                    if bindings.contains(&binding) {
                        state.invalidate_binding(binding, tracked);
                        state.copy(*value, binding, tracked);
                    }
                } else {
                    for binding in
                        unknown_write_bindings(&event.effect, semantics, open, binding_origins)
                    {
                        if bindings.contains(&binding) {
                            state.invalidate_binding(binding, tracked);
                        } else {
                            state.clear_value(binding);
                        }
                    }
                }
                if let Some(result) = produced_value(&event.effect) {
                    if bindings.contains(&result) {
                        state.invalidate_binding(result, tracked);
                    } else {
                        state.clear_value(result);
                    }
                }
            }
            effect => {
                for value in unknown_write_bindings(effect, semantics, open, binding_origins) {
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
        | GuardPredicate::OrderedIntegerComparison { .. }
        | GuardPredicate::OrderedFloatComparison { .. }
        | GuardPredicate::NanComparison { .. }
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
        check_cancelled(Some(cancellation))?;
        record_entry_work(budget, 1);
        if let Some(subject) = guard.subject {
            admit_set_entry(budget, &mut queried, subject)?;
        }
        if let Some(subject) = guard_predicate_subject(guard) {
            admit_set_entry(budget, &mut queried, subject)?;
        }
    }
    let subjects = adapter.refinement_subjects(workspace, procedure);
    charge_entries(budget, subjects.len().saturating_add(1))?;
    for subject in subjects {
        check_cancelled(Some(cancellation))?;
        admit_set_entry(budget, &mut queried, subject)?;
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
        check_cancelled(Some(cancellation))?;
        record_entry_work(budget, 1);
        admit_set_entry(budget, &mut points, guard.point)?;
    }
    for call in semantics.call_sites() {
        check_cancelled(Some(cancellation))?;
        record_entry_work(budget, 1);
        if let Some(normal) = call.normal_continuation.target() {
            admit_set_entry(budget, &mut points, normal)?;
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
struct TrackedValues {
    values: HashSet<ValueId>,
    reverse_copies: HashMap<ValueId, Vec<ValueId>>,
    forward_copies: HashMap<ValueId, Vec<ValueId>>,
    address_sources: HashSet<ValueId>,
    correlation_events: Vec<Vec<usize>>,
}

fn tracked_values(
    semantics: &ProcedureSemantics,
    bindings: &HashSet<ValueId>,
    queried: &HashSet<ValueId>,
    budget: &mut SemanticBudget,
    cancellation: &CancellationToken,
) -> Result<TrackedValues, CorrelationError> {
    let mut sources_of = HashMap::<ValueId, Vec<ValueId>>::default();
    let mut correlation_sources_of = HashMap::<ValueId, Vec<ValueId>>::default();
    let mut correlation_targets_of = HashMap::<ValueId, Vec<ValueId>>::default();
    let mut address_sources = HashSet::default();
    charge_entries(budget, semantics.points().len())?;
    let mut correlation_events = vec![Vec::new(); semantics.points().len()];
    for point in semantics.points() {
        check_cancelled(Some(cancellation))?;
        record_entry_work(budget, point.events.len().saturating_add(1));
        for (event_index, event) in point.events.iter().enumerate() {
            if correlation_event_candidate(&event.effect) {
                charge_entries(budget, 1)?;
                correlation_events[point.id.index()].push(event_index);
            }
            match &event.effect {
                SemanticEffect::Assignment { target, value }
                | SemanticEffect::ValueFlow {
                    source: value,
                    target,
                    ..
                } if semantics
                    .value(*target)
                    .is_some_and(|target| target.kind == SemanticValueKind::Address) =>
                {
                    admit_set_entry(budget, &mut address_sources, *value)?;
                }
                _ => {}
            }
            let (source, target, binding_copy) = match &event.effect {
                SemanticEffect::Assignment { target, value } => (*value, *target, true),
                SemanticEffect::ValueFlow {
                    kind,
                    source,
                    target,
                } => {
                    if !kind.preserves_runtime_class() {
                        continue;
                    }
                    (
                        *source,
                        *target,
                        is_identity_flow(*kind)
                            && !is_assignment_transfer_marker(point, event_index, *source, *target),
                    )
                }
                _ => continue,
            };
            if source == target {
                continue;
            }
            charge_entries(budget, 2)?;
            correlation_sources_of
                .entry(target)
                .or_default()
                .push(source);
            correlation_targets_of
                .entry(source)
                .or_default()
                .push(target);
            if bindings.contains(&target) || !binding_copy {
                continue;
            }
            charge_entries(budget, 1)?;
            sources_of.entry(target).or_default().push(source);
        }
    }
    let tracked = super::tracked_copy_sources(&sources_of, queried.clone(), budget, cancellation)?;
    Ok(TrackedValues {
        values: tracked,
        reverse_copies: correlation_sources_of,
        forward_copies: correlation_targets_of,
        address_sources,
        correlation_events,
    })
}

fn is_identity_flow(kind: ValueFlowKind) -> bool {
    matches!(
        kind,
        ValueFlowKind::Local | ValueFlowKind::Parameter | ValueFlowKind::Receiver
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic::{
        CancellationToken, ProcedureHandle, SemanticBudget, SemanticRequest, SemanticWork,
        type_flow_adapter,
    };
    use crate::analyzer::{AnalyzerConfig, Language, WorkspaceAnalyzer};
    use crate::inline_project::InlineTestProject;
    use crate::type_flow::correlations::analyze_correlations_with_boolean_bindings;
    use brokk_bifrost_test_macros::hardwon;

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
    #[hardwon(
        "#3124+#3129+#3152: 271660e00562: sparse refinement state must retain the queried guard subject binding"
    )]
    fn a_guard_subject_still_refines_to_its_lexical_binding() {
        let (_workspace, procedure, bindings) = derive_check();
        let guard = bindings
            .binding_for_guard(0)
            .expect("the `isinstance` guard subject is still the parameter it was read from");
        assert_eq!(guard, parameter(&procedure, "flag"));
    }

    #[test]
    fn correlation_reuses_the_binding_event_inventory() {
        let source = concat!(
            "def correlate(condition):\n",
            "    flag = False\n",
            "    value = []\n",
            "    if condition:\n",
            "        flag = True\n",
            "        value = {}\n",
            "    if flag:\n",
            "        return value.index\n",
            "    return None\n",
        );
        let project = InlineTestProject::with_language(Language::Python)
            .file("app.py", source)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &project.file("app.py"),
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
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
                    == Some("correlate")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("the fixture declares `correlate`");
        let adapter = type_flow_adapter(Language::Python).expect("Python has a type-flow adapter");
        let mut derivation_budget = SemanticBudget::default();
        let bindings = derive(
            &workspace,
            adapter,
            &procedure,
            &mut derivation_budget,
            &cancellation,
        )
        .expect("binding refinement completes");
        assert!(
            !bindings.correlation_bindings().is_empty(),
            "the literal-backed flag activates correlation"
        );

        let mut correlation_budget = SemanticBudget::new(SemanticWork {
            events: 1,
            ..SemanticWork::default_limits()
        })
        .expect("the event limit is positive");
        analyze_correlations_with_boolean_bindings(
            &procedure,
            bindings.correlation_bindings(),
            bindings.data_bindings(),
            bindings.open_bindings(),
            bindings.correlation_events(),
            &mut correlation_budget,
            Some(&cancellation),
        )
        .expect("correlation consumes the prepared event inventory");
        assert_eq!(
            correlation_budget.used().events,
            0,
            "correlation does not rescan semantic events"
        );
    }
}
